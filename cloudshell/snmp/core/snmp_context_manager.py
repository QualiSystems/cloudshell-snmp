from cloudshell.snmp.core.snmp_service import SnmpService


class SnmpContextManager(object):
    def __init__(
        self,
        snmp_engine,
        v3_context_engine_id,
        v3_context_name,
        logger,
        get_bulk_flag=False,
        is_snmp_read_only=False,
    ):
        self._snmp_engine = snmp_engine
        self._is_snmp_read_only = is_snmp_read_only
        self._v3_context_engine_id = v3_context_engine_id
        self._v3_context = v3_context_name
        self._logger = logger
        self._get_bulk_flag = get_bulk_flag

    def __enter__(self):
        snmp_service = SnmpService(
            snmp_engine=self._snmp_engine,
            context_id=self._v3_context_engine_id,
            context_name=self._v3_context,
            get_bulk_flag=self._get_bulk_flag,
            is_snmp_read_only=self._is_snmp_read_only,
            logger=self._logger,
        )
        return snmp_service

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._snmp_engine.transportDispatcher:
            self._snmp_engine.transportDispatcher.closeDispatcher()
