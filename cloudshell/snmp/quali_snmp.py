"""
This package contains classes and utility functions to work with SNMP in Quali shells.

This package assumes that its users are familiar with SNMP basics but are not necessarily
professionals. Thus the operations and terminology are not always by the book but reflects the
needs of Quali SNMP users.
"""
from collections import OrderedDict
import time
import re

import os
from pysnmp.hlapi import UsmUserData, usmNoAuthProtocol, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, \
    usmNoPrivProtocol, usmDESPrivProtocol, usm3DESEDEPrivProtocol, usmAesCfb128Protocol, usmAesCfb192Protocol, \
    usmAesCfb256Protocol
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.error import PySnmpError
from pysnmp.smi import builder, view
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
from cloudshell.snmp.snmp_parameters import SNMPParameters, SNMPV3Parameters, SNMPV2ReadParameters


class QualiSnmpError(PySnmpError):
    pass


# Original class QualiMibTable(OrderedDict). Inheritance was changed because serialization does not work correctly.
class QualiMibTable(dict):
    """ Represents MIB table.

    Note that this class inherits from OrderedDict so all dict operations are supported.
    """

    def __init__(self, name, *args, **kwargs):
        """ Create ordered dictionary to hold the MIB table.

        MIB table representation:
        {index: {attribute: value, ...}...}

        :param name: MIB table name.
        """

        super(QualiMibTable, self).__init__(*args, **kwargs)
        self._name = name
        self._prefix = name[:-len('Table')]

    def get_rows(self, *indexes):
        """
        :param indexes: list of requested indexes.
        :return: a partial table containing only the requested rows.
        """

        return QualiMibTable(self._name, OrderedDict((i, v) for i, v in self.items() if
                                                     i in indexes))

    def get_columns(self, *names):
        """
        :param names: list of requested columns names.
        :return: a partial table containing only the requested columns.
        """

        names = [self._prefix + n for n in names]
        return QualiMibTable(self._name, OrderedDict((i, {n: v for n, v in values.items() if
                                                          n in names}) for
                                                     i, values in self.items()))

    def filter_by_column(self, name, *values):
        """
        :param name: column name.
        :param values: list of requested values.
        :return: a partial table containing only the rows that has one of the requested values in
            the requested column.
        """

        name = self._prefix + name
        return QualiMibTable(self._name, OrderedDict((i, _values) for i, _values in self.items() if
                                                     _values[name] in values))

    def sort_by_column(self, name):
        """
        :param name: column name.
        :return: the same table sorted by the value in the requested column.
        """

        column = self.get_columns(name)
        name = self._prefix + name
        return QualiMibTable(self._name, sorted(column.items(), key=lambda t: int(t[1][name])))


class QualiSnmp(object):
    """ A wrapper class around PySNMP.

    :todo: use pysnmp.hlapi, do we really need to import symbols? see
        pysnmp.sourceforge.net/examples/hlapi/asyncore/sync/manager/cmdgen/table-operations.html
    """

    var_binds = ()

    """ raw output from PySNMP command. """
    AUTH_PROTOCOL_MAP = {SNMPV3Parameters.AUTH_NO_AUTH: usmNoAuthProtocol,
                         SNMPV3Parameters.AUTH_MD5: usmHMACMD5AuthProtocol,
                         SNMPV3Parameters.AUTH_SHA: usmHMACSHAAuthProtocol}

    PRIV_PROTOCOL_MAP = {SNMPV3Parameters.PRIV_NO_PRIV: usmNoPrivProtocol,
                         SNMPV3Parameters.PRIV_DES: usmDESPrivProtocol,
                         SNMPV3Parameters.PRIV_3DES: usm3DESEDEPrivProtocol,
                         SNMPV3Parameters.PRIV_AES128: usmAesCfb128Protocol,
                         SNMPV3Parameters.PRIV_AES192: usmAesCfb192Protocol,
                         SNMPV3Parameters.PRIV_AES256: usmAesCfb256Protocol}

    def __init__(self, snmp_parameters, logger, snmp_error_values=None):
        """ Initialize SNMP environment.
        :param SNMPParameters snmp_parameters: snmp parameters
        """
        self._snmp_errors = None
        snmp_error_values = snmp_error_values or []
        self.set_snmp_errors(snmp_error_values)
        self.cmd_gen = cmdgen.CommandGenerator()
        self.mib_builder = self.cmd_gen.snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder
        self.mib_viewer = view.MibViewController(self.mib_builder)
        self.mib_path = builder.DirMibSource(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mibs'))
        self.logger = logger
        self.is_read_only = False
        self.target = None
        self.security = None

        self.initialize_snmp(snmp_parameters)
        self.mib_builder.setMibSources(self.mib_path)

    def set_snmp_errors(self, snmp_errors):
        self._snmp_errors = {pattern: re.compile(pattern, re.IGNORECASE) for pattern in snmp_errors}

    def initialize_snmp(self, snmp_parameters):
        """Create snmp, using provided version user details or community name

        :param SNMPV3Parameters snmp_parameters: snmp parameters

        """

        self.logger.info('QualiSnmp Creating SNMP Handler')
        ip = snmp_parameters.ip
        if ':' in ip:
            ip = ip.split(':')[0]
        self.target = cmdgen.UdpTransportTarget((ip, snmp_parameters.port))
        if isinstance(snmp_parameters, SNMPV3Parameters):
            snmp_v3_param = snmp_parameters
            """:type: SNMPV3Parameters"""
            self.security = UsmUserData(userName=snmp_v3_param.snmp_user,
                                        authKey=snmp_v3_param.snmp_password or None,
                                        privKey=snmp_v3_param.snmp_private_key or None,
                                        authProtocol=self.AUTH_PROTOCOL_MAP.get(snmp_v3_param.auth_protocol,
                                                                                usmNoAuthProtocol),
                                        privProtocol=self.PRIV_PROTOCOL_MAP.get(snmp_v3_param.private_key_protocol,
                                                                                usmNoPrivProtocol))
            self.logger.info('Snmp v3 handler created')
        else:
            if isinstance(snmp_parameters, SNMPV2ReadParameters):
                self.is_read_only = True
            snmp_v2_param = snmp_parameters
            """:type: SNMPV2Parameters"""
            self.security = cmdgen.CommunityData(snmp_v2_param.snmp_community)
            self.logger.info('Snmp v2 handler created')
        self._test_snmp_agent()

    def _test_snmp_agent(self, retries_count=3, sleep_length=1):
        """
        Validate snmp agent and connectivity attributes, raise Exception if snmp agent is invalid
        """

        result = None
        exception_message = 'Snmp connection failed, check host IP and snmp attributes'
        for retry in range(retries_count):
            try:
                result = self.get(('SNMPv2-MIB', 'sysObjectID', '0'))
                break
            except Exception as e:
                self.logger.error('Snmp agent validation failed')
                self.logger.exception(e)
                exception_message = e.message
                time.sleep(sleep_length)

        if not result:
            raise Exception('Snmp attributes or host IP are not valid\n{0}'.format(exception_message))

    def update_mib_sources(self, mib_folder_path):
        """Add specified path to the Pysnmp mib sources, which will be used to translate snmp responses.

        :param mib_folder_path: string path
        """

        builder.DirMibSource(mib_folder_path)
        mib_sources = (builder.DirMibSource(mib_folder_path),) + self.mib_builder.getMibSources()
        self.mib_builder.setMibSources(*mib_sources)

    def load_mib(self, mib_list):
        """ Load all MIBs provided in incoming mib_list one by one

        :param mib_list: List of MIB names, for example: ['CISCO-PRODUCTS-MIB', 'CISCO-ENTITY-VENDORTYPE-OID-MIB']
        """

        if isinstance(mib_list, str):
            mib_list = [mib_list]

        for mib in mib_list:
            self.mib_builder.loadModules(mib)

    def get(self, *oids):
        """ Get/Bulk get operation for scalars.

        :param oids: list of oids to get. oid can be full dotted OID or (MIB, OID name, [index]).
            For example, the OID to get sysContact can by any of the following:
            ('SNMPv2-MIB', 'sysContact', 0)
            ('SNMPv2-MIB', 'sysContact')
            '1.3.6.1.2.1.1.4.0'
            '1.3.6.1.2.1.1.4'
        :return: a dictionary of <oid, value>
        """

        object_identities = []
        for oid in oids:
            if type(oid) is list or type(oid) is tuple:
                oid_0 = list(oid)
                if len(oid_0) == 2:
                    oid_0.append(0)
                object_identities.append(ObjectIdentity(*oid_0))
            else:
                oid_0 = oid if oid.endswith('.0') else oid + '.0'
                object_identities.append(ObjectIdentity(oid_0))

        self._command(self.cmd_gen.getCmd, *object_identities)

        oid_2_value = OrderedDict()
        for var_bind in self.var_binds:
            mib_name, oid_value, suffix = self._translate_var_bind(var_bind)
            oid_2_value[mib_name] = oid_value

        return oid_2_value

    def _translate_var_bind(self, var_bind):
        mod_name, mib_name, suffix = self.mib_viewer.getNodeLocation(var_bind[0])
        oid_value = str(var_bind[1].prettyPrint())
        if oid_value.lower().startswith("0x"):
            oid_value = str(var_bind[1])
        self._check_result_for_errors(oid_value)
        return mib_name, oid_value, suffix

    def set(self, oids):
        """SNMP Set operation.

        :param oids: list of oids to set. oid can be full dotted OID or (MIB, OID name, [index]).
            For example, the OID to get sysContact can by any of the following:
            ('SNMPv2-MIB', 'sysContact', 0)
            '1.3.6.1.2.1.1.4.0'
            snmp.set([(("CISCO-CONFIG-COPY-MIB", "ccCopyProtocol", 10), 1),
                      (("CISCO-CONFIG-COPY-MIB", "ccCopySourceFileType", 10), 1),
                      (("CISCO-CONFIG-COPY-MIB", "ccCopyDestFileType", 10), 3),
                      (("CISCO-CONFIG-COPY-MIB", "ccCopyServerAddress", 10), "10.212.95.180"),
                      (("CISCO-CONFIG-COPY-MIB", "ccCopyFileName", 10), "test_snmp_running_config_save"),
                      (("CISCO-CONFIG-COPY-MIB", "ccCopyVrfName", 10), "management"),
                      (("CISCO-CONFIG-COPY-MIB", "ccCopyEntryRowStatus", 10), 4)])
        """

        if self.is_read_only:
            raise Exception(self.__class__.__name__, "SNMP Read Community doesn't support snmp set command")

        object_identities = []
        for oid in oids:
            if type(oid) is list or type(oid) is tuple:
                oid_0 = list(oid)
                if len(oid_0) < 2:
                    raise Exception(self.__class__.__name__, "Missing oid or value data")

                if type(oid[0]) is list or type(oid[0]) is tuple:
                    if (len(oid_0[0])) < 3:
                        raise Exception(self.__class__.__name__, "Missing oid index")
                object_identities.append(ObjectType(ObjectIdentity(*oid_0[0]), oid[1]))
            else:
                raise Exception(self.__class__.__name__, "Wrong oids parameter")

        self._command(self.cmd_gen.setCmd, *object_identities)

    def get_table_field(self, *oids):
        """ Get/Bulk get operation for columnar entries.
        Returns exact value from table for specified oids

        :param ois: list of oids to get. oid can be full dotted OID or (MIB, OID name, [index]).
        For example, the OID to get sysContact can by any of the following:
        ('SNMPv2-MIB', 'sysContact', 0)
        ('SNMPv2-MIB', 'sysContact')
        '1.3.6.1.2.1.1.4.0'
        '1.3.6.1.2.1.1.4'
        :return: a dictionary of <oid, value>
        """

        object_identities = []
        for oid in oids:
            if type(oid) is list or type(oid) is tuple:
                oid_0 = list(oid)
                object_identities.append(ObjectIdentity(*oid_0))
            else:
                oid_0 = oid
                object_identities.append(ObjectIdentity(oid_0))

        self._command(self.cmd_gen.getCmd, *object_identities)

        oid_2_value = OrderedDict()
        for var_bind in self.var_binds:
            mib_name, oid_value, suffix = self._translate_var_bind(var_bind)
            oid_2_value[mib_name] = oid_value

        return oid_2_value

    def _check_result_for_errors(self, value):
        for pattern, compiled_pattern in self._snmp_errors.iteritems():
            if re.search(compiled_pattern, value):
                self.logger.debug('Snmp value contain errors, {}'.format(pattern))
                raise Exception(self.__class__.__name__, 'Snmp value contain errors, {}'.format(pattern))

    def get_property(self, snmp_module_name, property_name, index, return_type='str'):
        """ Get SNMP value from specified MIB and property name.

        :param snmp_module_name: MIB name, like 'IF-MIB'
        :param property_name: map of required property and it's default type, i.e. 'ifDescr'
        :param str index: index of the required element, i.e. '1' or '1.2.3.0'
        :param return_type: type of the output we expect to get in response, i.e. 'int'
        :return: string
        """

        self.logger.debug(
            '\tReading \'{0}\'.{1} value from \'{2}\' ...'.format(property_name, index, snmp_module_name))

        if isinstance(index, str):
            index_list = index.split('.')
        else:
            index_list = [index]
        try:
            snmp_request = (snmp_module_name, property_name) + tuple(index_list)
            return_value = self.get(snmp_request).values()[0].strip(' \t\n\r')
            if 'int' in return_type:
                return_value = int(return_value)
        except Exception as e:
            self.logger.error(e.args)
            if return_type == 'int':
                return_value = 0
            else:
                return_value = ''
        self.logger.debug('\tDone.')
        return return_value

    def get_properties(self, snmp_mib_name, index, properties_map):
        """ Get SNMP table from specified MIB and map of properties.

        :param snmp_mib_name: MIB name 'IF-MIB'
        :param index: index of the required element '1'
        :param properties_map: map of required property and it's default type, i.e. {'ifDescr': 'str', 'ifMtu': 'int'}
        :return: QualiMibTable
        """

        result = QualiMibTable(snmp_mib_name)
        result[index] = {}
        for command_key, command_type in properties_map.iteritems():
            result[index][command_key] = self.get_property(snmp_mib_name, command_key, index, command_type)
        return result

    def get_table(self, snmp_module_name, table_name):
        """ Get SNMP table from specified MIB and table name.

        :param snmp_module_name: MIB name
        :param table_name: table name
        :return: QualiMibTable
        """

        self.logger.debug('\tReading \'{0}\' table from \'{1}\' ...'.format(table_name, snmp_module_name))
        try:
            ret_value = self.walk((snmp_module_name, table_name))
        except Exception as e:
            self.logger.error(e.args)
            ret_value = QualiMibTable(table_name)
        self.logger.debug('\tDone.')
        return ret_value

    def next(self, oid):
        """ Get next for a scalar.

        :param oid: oid to getnext.
        :return: a pair of (next oid, value)
        """

        self._command(self.cmd_gen.nextCmd, ObjectIdentity(*oid), )

        var_bind = self.var_binds[0][0]
        mib_name, value, suffix = self._translate_var_bind(var_bind)

        return mib_name, value

    def walk(self, oid, *indexes):
        """ Walk through the given table OID.

        :param oid: oid of the table to walk through.
        :param indices: only walk through the requested indices.
        :return: a dictionary of <index, <attribute, value>>
        """

        self._command(self.cmd_gen.nextCmd, ObjectIdentity(*oid))

        oid_2_value = QualiMibTable(oid[1])
        for var_bind in self.var_binds:
            mibName, mib_value, suffix = self._translate_var_bind(var_bind[0])
            # We want table index to be numeric if possible.
            if str(suffix).isdigit():
                # Single index like 1, 2, 3... - treat as int
                index = int(str(suffix))
            else:
                # Triple or more index (like IPv4 in IP-Table) - treat as str.
                index = str(suffix)
            if not oid_2_value.get(index):
                oid_2_value[index] = {'suffix': str(suffix)}

            oid_2_value[index][mibName] = mib_value
            # self.logger.debug('{0}'.format(oid_2_value))

        if indexes:
            oid_2_value = oid_2_value.get_rows(*indexes)

        return oid_2_value

    #
    # Private methods.
    #

    def _command(self, cmd, *oids):
        """ Execute provided command with provided oids

        :param cmd: command to execute, i.e get
        :param oids: request oids, '1.3.6.1.2.1.1.2'
        """

        error_indication, error_status, error_index, self.var_binds = cmd(self.security,
                                                                          self.target,
                                                                          *oids)
        # Check for errors
        if error_indication:
            raise PySnmpError(error_indication)
        if error_status:
            raise PySnmpError(error_status)
