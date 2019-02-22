import os
import time

from pyasn1.type import univ
from pysnmp.proto.errind import requestTimedOut
from pysnmp.smi import builder

from cloudshell.snmp.core.domain.quali_mib_table import QualiMibTable
from cloudshell.snmp.core.snmp_response_reader import SnmpResponseReader


class ReadSnmpService(object):
    DEFAULT_GET_BULK_REPETITIONS = 25
    WALK_RETRY_COUNT = 2

    def __init__(self, snmp_engine, context_id, context_name, logger, retries=1, get_bulk_flag=False):
        self._snmp_engine = snmp_engine
        self._logger = logger
        self._context_id = context_id
        self._context_name = context_name
        self._retries = retries
        self._get_bulk_flag = get_bulk_flag
        path_to_mibs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", 'mibs')
        self.update_mib_sources(path_to_mibs)

    def update_mib_sources(self, mib_folder_path):
        """Add specified path to the Pysnmp mib sources, which will be used to translate snmp responses.

        :param mib_folder_path: string path
        """

        mib_builder = self._snmp_engine.msgAndPduDsp.mibInstrumController.mibBuilder
        builder.DirMibSource(mib_folder_path)
        mib_sources = (builder.DirMibSource(mib_folder_path),) + mib_builder.getMibSources()
        mib_builder.setMibSources(*mib_sources)

    def load_mib(self, mib_list):
        """ Load all MIBs provided in incoming mib_list one by one

        :param mib_list: List of MIB names, for example: ['CISCO-PRODUCTS-MIB', 'CISCO-ENTITY-VENDORTYPE-OID-MIB']
        """

        mib_builder = self._snmp_engine.msgAndPduDsp.mibInstrumController.mibBuilder
        if isinstance(mib_list, str):
            mib_list = [mib_list]

        for mib in mib_list:
            mib_builder.loadModules(mib)

    def get(self, snmp_oid):
        """ Get snmp operation. Load appropriate oid value from the device.

        :param snmp_oid: Single SnmpMibOid or SnmpRawOid object.
            For example, an object to get sysContact can by any of the following:
            SnmpMibOid('SNMPv2-MIB', 'sysContact', 0)
            SnmpMibOid('SNMPv2-MIB', 'sysContact')
            SnmpRawOid('1.3.6.1.2.1.1.4.0')
        :return: SnmpResponse
        """

        # ToDo do we really need to check index and set it to 0 it if it's None?
        if hasattr(snmp_oid, "index") and not snmp_oid.index:
            snmp_oid.index = 0
        oid = snmp_oid.get_object_type(self._snmp_engine)[0]

        service = self._create_response_service()
        service.send_get_var_binds(oid=oid)

        self._start_dispatcher()

        self._check_error(service.cb_ctx, service.result)

        result = None
        if service.result:
            result = list(service.result)[-1]

        return result

    def get_list(self, snmp_oid_list):
        """ Get snmp operation. Load list of appropriate oid values from the device.

        :param snmp_oid_list: List of SnmpMibOid or SnmpRawOid objects.
            For example, an object to get sysContact can by any of the following:
            [SnmpMibOid('SNMPv2-MIB', 'sysContact'), SnmpRawOid('1.3.6.1.2.1.1.4.0')]

        :return: SnmpResponse
        """
        result_list = []

        request_list = []
        for oid in snmp_oid_list:
            if hasattr(oid, "index") and not oid.index:
                oid.index = 0

            service = self._create_response_service()
            service.send_get_var_binds(oid=oid.get_object_type(self._snmp_engine))
            request_list.append(service)

        self._start_dispatcher()

        for request_result in request_list:
            self._check_error(request_result.cb_ctx, request_result.result)

            if request_result.result:
                result_list.extend(request_result.result)

        return result_list

    def walk(self, snmp_oid_obj, stop_oid=None, get_subtree=True, retry_count=2,
             get_bulk_flag=None, get_bulk_repetitions=DEFAULT_GET_BULK_REPETITIONS):
        response = self._walk(snmp_oid_obj, stop_oid=stop_oid, get_subtree=get_subtree, retry_count=retry_count,
                              get_bulk_flag=get_bulk_flag, get_bulk_repetitions=get_bulk_repetitions)
        return list(response)

    def _walk(self, snmp_oid_obj, stop_oid=None, get_subtree=True, retry_count=2,
              get_bulk_flag=None, get_bulk_repetitions=DEFAULT_GET_BULK_REPETITIONS):
        if self._get_bulk_flag and get_bulk_flag is not None:
            get_bulk = get_bulk_flag
        else:
            get_bulk = self._get_bulk_flag

        start_oid = univ.ObjectIdentifier(snmp_oid_obj.get_oid(self._snmp_engine))
        if stop_oid:
            stop_oid = univ.ObjectIdentifier(stop_oid.get_oid(self._snmp_engine))
        elif get_subtree:
            _stop_oid = "{}{}".format(str(start_oid)[:-1], int(str(start_oid)[-1:]) + 1)
            stop_oid = univ.ObjectIdentifier(_stop_oid)
        cb_ctx = {
            'total': 0,
            'count': 0,
            'errors': 0,
            'is_snmp_timeout': False,
            'iteration': 0,
            'reqTime': time.time(),
            '': True,
            'retries': retry_count,
            'lastOID': start_oid
        }
        service = self._create_response_service(cb_ctx=cb_ctx,
                                                get_bulk_flag=get_bulk,
                                                get_bulk_repetitions=get_bulk_repetitions,
                                                retry_count=retry_count)

        if get_bulk:
            service.send_bulk_var_binds(start_oid, stop_oid)
        else:
            service.send_walk_var_binds(start_oid, stop_oid)

        self._start_dispatcher()

        self._check_error(service.cb_ctx, service.result)

        return service.result

    def get_table(self, snmp_oid_obj, retry_count=WALK_RETRY_COUNT, get_bulk_flag=None,
                  get_bulk_repetitions=DEFAULT_GET_BULK_REPETITIONS):
        table_name = snmp_oid_obj.get_object_type(snmp_engine=self._snmp_engine)[0].getMibSymbol()[1]

        result_list = self._walk(snmp_oid_obj, get_subtree=True, retry_count=retry_count,
                                 get_bulk_flag=get_bulk_flag, get_bulk_repetitions=get_bulk_repetitions)

        result_dict = QualiMibTable.create_from_list(table_name, result_list)

        return result_dict

    def _create_response_service(self, cb_ctx=None, retry_count=0, get_bulk_flag=False,
                                 get_bulk_repetitions=None):
        return SnmpResponseReader(snmp_engine=self._snmp_engine,
                                  logger=self._logger,
                                  cb_ctx=cb_ctx,
                                  context_id=self._context_id,
                                  context_name=self._context_name,
                                  get_bulk_flag=get_bulk_flag,
                                  get_bulk_repetitions=get_bulk_repetitions,
                                  retry_count=retry_count)

    def _start_dispatcher(self):
        try:
            self._snmp_engine.transportDispatcher.runDispatcher()
        except Exception as e:
            self._logger.debug("Error retrieving snmp response ", exc_info=1)
            pass

    def _check_error(self, cb_ctx, result):
        if cb_ctx.get("is_snmp_timeout") and not result:
            exception = requestTimedOut
            self._logger.error(str(exception))
            raise exception
