import os
import time

from pyasn1.type import univ
from pysnmp.proto.errind import requestTimedOut
from pysnmp.smi import builder

from cloudshell.snmp.core.domain.quali_mib_table import QualiMibTable
from cloudshell.snmp.core.domain.snmp_response import SnmpResponse
from cloudshell.snmp.core.snmp_errors import ReadSNMPException
from cloudshell.snmp.core.snmp_response_reader import SnmpResponseReader


class SnmpService(object):
    DEFAULT_GET_BULK_REPETITIONS = 25
    WALK_RETRY_COUNT = 2

    def __init__(
        self,
        snmp_engine,
        context_id,
        context_name,
        logger,
        retries=1,
        get_bulk_flag=False,
    ):
        self._snmp_engine = snmp_engine
        self._logger = logger
        self._context_id = context_id
        self._context_name = context_name
        self._retries = retries
        self._get_bulk_flag = get_bulk_flag
        path_to_mibs = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "mibs"
        )
        self.update_mib_file_sources(path_to_mibs)

    def update_mib_file_sources(self, mib_folder_path):
        """Add specified path to the Pysnmp mib sources, which will be used to translate snmp responses.

        :param mib_folder_path: string path to mibs
        """

        mib_builder = self._snmp_engine.msgAndPduDsp.mibInstrumController.mibBuilder
        builder.DirMibSource(mib_folder_path)
        mib_sources = (
            builder.DirMibSource(mib_folder_path),
        ) + mib_builder.getMibSources()
        mib_builder.setMibSources(*mib_sources)

    def load_mib_oids(self, mib_list):
        """Load all MIBs provided in incoming mib_list one by one

        :param mib_list: List of MIB names, for example: ['CISCO-PRODUCTS-MIB', 'CISCO-ENTITY-VENDORTYPE-OID-MIB']
        """

        mib_builder = self._snmp_engine.msgAndPduDsp.mibInstrumController.mibBuilder
        if isinstance(mib_list, str):
            mib_list = [mib_list]

        for mib in mib_list:
            mib_builder.loadModules(mib)

    def set(self, snmp_set_oids):
        """SNMP Set operation. Set appropriate oid value on the device

        :param snmp_set_oids: list or single SnmpSetMibName and/or SnmpSetRawOid object to set.
            For example, to set sysContact:
            snmp_obj = SnmpSetMibName(mib_name="SNMPv2-MIB", mib_id="sysContact", index=0, value="Owner")
            or
            snmp_obj = SnmpSetRawOid(oid="1.3.6.1.2.1.1.4.0", value="Owner)
            then
            set(snmp_obj)

            2 Example, set mib table row:
            set([SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyProtocol", 10, 1),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopySourceFileType", 10, 1),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyDestFileType", 10, 3),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyServerAddress", 10, "10.10.95.180"),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyFileName", 10, "test_snmp_running_config_save"),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyVrfName", 10, "management"),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyEntryRowStatus", 10, 4)])

        :rtype: list of SnmpResponse
        """

        snmp_set_oids_list = snmp_set_oids
        if not isinstance(snmp_set_oids_list, (list, tuple)):
            snmp_set_oids_list = [snmp_set_oids]
        object_types = []
        for snmp_set_obj in snmp_set_oids_list:
            object_types.append(snmp_set_obj.get_object_type(self._snmp_engine))

        service = self._create_response_service()

        service.send_set_var_binds(object_types)

        self._start_dispatcher()

        self._check_error(service.cb_ctx, service.result)

        return service.result

    def get_property(self, snmp_oid):
        response = SnmpResponse(
            str(snmp_oid.get_oid(self._snmp_engine)),
            None,
            snmp_engine=self._snmp_engine,
            logger=self._logger,
        )
        try:
            return self.get(snmp_oid) or response
        except ReadSNMPException as e:
            self._logger.debug(e, exc_info=True)

        return response

    def get(self, snmp_oid):
        """ Get snmp operation. Load appropriate oid value from the device.

        :param snmp_oid: Single SnmpMibOid or SnmpRawOid object.
            For example, an object to get sysContact can by any of the following:
            SnmpMibOid('SNMPv2-MIB', 'sysContact', 0)
            SnmpMibOid('SNMPv2-MIB', 'sysContact')
            SnmpRawOid('1.3.6.1.2.1.1.4.0')
        :return: SnmpResponse
        """

        oid = snmp_oid.get_oid(self._snmp_engine)
        if hasattr(oid, "index") and not oid.index:
            oid.index = 0

        service = self._create_response_service()
        service.send_get_var_binds(oid=oid)

        self._start_dispatcher()

        self._check_error(service.cb_ctx, service.result)

        result = None
        if service.result:
            result = list(service.result)[-1]

        return result

    def get_next(self, snmp_oid):
        """ Get snmp operation. Load appropriate oid value from the device.

        :param snmp_oid: Single SnmpMibOid or SnmpRawOid object.
            For example, an object to get sysContact can by any of the following:
            SnmpMibOid('SNMPv2-MIB', 'sysContact', 0)
            SnmpMibOid('SNMPv2-MIB', 'sysContact')
            SnmpRawOid('1.3.6.1.2.1.1.4.0')
        :return: list of SnmpResponse
        """

        oid = snmp_oid.get_oid(self._snmp_engine)

        service = self._create_response_service()
        stop_oid = "{}{}".format(str(oid)[:-1], int(str(oid)[-1:]) + 1)
        stop_oid = univ.ObjectIdentifier(stop_oid)
        service.send_walk_var_binds(oid=oid, stop_oid=stop_oid)
        # service.send_walk_var_binds(oid=oid, stop_oid=stop_oid, cb_fun=service.cb_fun)

        self._start_dispatcher()

        self._check_error(service.cb_ctx, service.result)

        if service.result:
            return list(service.result)
        # result = []
        # if service.result:
        #     for response in service.result:
        #         if response.mib_id == snmp_oid.mib_id \
        #                 and snmp_oid.index in response.index:
        #             result.append(response)
        # return result

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

    def walk(
        self,
        snmp_oid_obj,
        stop_oid=None,
        get_subtree=True,
        retry_count=2,
        get_bulk_flag=None,
        get_bulk_repetitions=DEFAULT_GET_BULK_REPETITIONS,
    ):
        response = self._walk(
            snmp_oid_obj,
            stop_oid=stop_oid,
            get_subtree=get_subtree,
            retry_count=retry_count,
            get_bulk_flag=get_bulk_flag,
            get_bulk_repetitions=get_bulk_repetitions,
        )
        return list(response)

    def _walk(
        self,
        snmp_oid_obj,
        stop_oid=None,
        get_subtree=True,
        retry_count=2,
        get_bulk_flag=None,
        get_bulk_repetitions=DEFAULT_GET_BULK_REPETITIONS,
    ):
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
            "total": 0,
            "count": 0,
            "errors": 0,
            "is_snmp_timeout": False,
            "iteration": 0,
            "reqTime": time.time(),
            "": True,
            "retries": retry_count,
            "lastOID": start_oid,
        }
        service = self._create_response_service(
            cb_ctx=cb_ctx,
            get_bulk_flag=get_bulk,
            get_bulk_repetitions=get_bulk_repetitions,
            retry_count=retry_count,
        )

        if get_bulk:
            service.send_bulk_var_binds(start_oid, stop_oid)
        else:
            service.send_walk_var_binds(start_oid, stop_oid)

        self._start_dispatcher()

        self._check_error(service.cb_ctx, service.result)

        return service.result

    def get_table(
        self,
        snmp_oid_obj,
        retry_count=WALK_RETRY_COUNT,
        get_bulk_flag=None,
        get_bulk_repetitions=DEFAULT_GET_BULK_REPETITIONS,
    ):
        table_name = snmp_oid_obj.get_object_type(snmp_engine=self._snmp_engine)[
            0
        ].getMibSymbol()[1]

        result_list = self._walk(
            snmp_oid_obj,
            get_subtree=True,
            retry_count=retry_count,
            get_bulk_flag=get_bulk_flag,
            get_bulk_repetitions=get_bulk_repetitions,
        )

        result_dict = QualiMibTable.create_from_list(table_name, result_list)

        return result_dict

    def _create_response_service(
        self, cb_ctx=None, retry_count=0, get_bulk_flag=False, get_bulk_repetitions=None
    ):
        return SnmpResponseReader(
            snmp_engine=self._snmp_engine,
            logger=self._logger,
            cb_ctx=cb_ctx,
            context_id=self._context_id,
            context_name=self._context_name,
            get_bulk_flag=get_bulk_flag,
            get_bulk_repetitions=get_bulk_repetitions,
            retry_count=retry_count,
        )

    def _start_dispatcher(self):
        try:
            self._snmp_engine.transportDispatcher.runDispatcher()
        except Exception as e:
            self._logger.debug("Error retrieving snmp response ", exc_info=1)
            raise

    def _check_error(self, cb_ctx, result):
        if cb_ctx.get("is_snmp_timeout") and not result:
            exception = requestTimedOut
            self._logger.error(str(exception))
            raise exception