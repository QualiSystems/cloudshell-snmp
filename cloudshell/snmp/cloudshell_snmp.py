from pysnmp.entity import engine, config

from cloudshell.snmp.core.tools.snmp_context import SnmpContext
from cloudshell.snmp.core.tools.snmp_security import SnmpSecurity
from cloudshell.snmp.core.tools.snmp_trasnport import SnmpTransport
from cloudshell.snmp.core.tools.snmp_constants import SNMP_RETRIES_COUNT, SNMP_TIMEOUT
from cloudshell.snmp.core.snmp_context_manager import SnmpContextManager


class Snmp(object):
    def __init__(self, logger, snmp_parameters, v3_context_engine_id=None, v3_context_name=""):
        self._v3_context_engine_id = v3_context_engine_id
        self._v3_context_name = v3_context_name
        self._logger = logger
        self._snmp_engine = None
        self._snmp_parameters = snmp_parameters

    def get_snmp_service(self, snmp_timeout=SNMP_TIMEOUT, snmp_retry_count=SNMP_RETRIES_COUNT):
        snmp_engine = self._get_snmp_engine(snmp_timeout, snmp_retry_count)
        snmp_context = SnmpContext(self._v3_context_engine_id, self._v3_context_name)
        get_bulk_flag = self._snmp_parameters.snmp_version > 0
        return SnmpContextManager(snmp_engine=snmp_engine,
                                  v3_context_engine_id=snmp_context.context_engine_id,
                                  v3_context_name=snmp_context.context_name,
                                  logger=self._logger,
                                  get_bulk_flag=get_bulk_flag
                                  )

    def _get_snmp_engine(self, snmp_timeout, snmp_retry_count):
        snmp_engine = engine.SnmpEngine()

        config.addTargetParams(snmp_engine, 'pms', self._snmp_parameters.user, self._snmp_parameters.security,
                               self._snmp_parameters.snmp_version)
        transport = SnmpTransport(snmp_parameters=self._snmp_parameters, logger=self._logger)
        transport.add_udp_endpoint(snmp_engine, snmp_timeout, snmp_retry_count)
        security = SnmpSecurity(snmp_parameters=self._snmp_parameters, logger=self._logger)
        security.add_security(snmp_engine)

        return snmp_engine
