from pysnmp.entity import config, engine

from cloudshell.snmp.core.snmp_context_manager import SnmpContextManager
from cloudshell.snmp.core.tools.snmp_constants import SNMP_RETRIES_COUNT, SNMP_TIMEOUT
from cloudshell.snmp.core.tools.snmp_context import SnmpContext
from cloudshell.snmp.core.tools.snmp_parameters_helper import SnmpParametersConverter
from cloudshell.snmp.core.tools.snmp_security import SnmpSecurity
from cloudshell.snmp.core.tools.snmp_trasnport import SnmpTransport


class Snmp(object):
    def __init__(self, timeout=SNMP_TIMEOUT, retry_count=SNMP_RETRIES_COUNT):
        self._snmp_timeout = timeout
        self._snmp_retry_count = retry_count

    def get_snmp_service(self, snmp_parameters, logger):
        """Get SNMP service.

        :param cloudshell.snmp.snmp_parameters.SnmpV2Parameters snmp_parameters:
        :param logging.Logger logger:
        """
        pysnmp_params = SnmpParametersConverter(snmp_parameters)
        snmp_engine = self._get_snmp_engine(pysnmp_params, logger)
        snmp_context = SnmpContext(
            snmp_parameters.context_engine_id, snmp_parameters.context_name
        )
        get_bulk_flag = pysnmp_params.version > 0
        return SnmpContextManager(
            snmp_engine=snmp_engine,
            v3_context_engine_id=snmp_context.context_engine_id,
            v3_context_name=snmp_context.context_name,
            logger=logger,
            get_bulk_flag=get_bulk_flag,
            is_snmp_read_only=pysnmp_params.is_read_only,
        )

    def _get_snmp_engine(self, pysnmp_params, logger):
        """Get SNMP engine.

        :param cloudshell.snmp.core.tools.snmp_parameters_helper.SnmpParametersConverter pysnmp_params:  # noqa: E501
        """
        snmp_engine = engine.SnmpEngine()
        config.addTargetParams(
            snmp_engine,
            "pms",
            pysnmp_params.user,
            pysnmp_params.security,
            pysnmp_params.version,
        )
        transport = SnmpTransport(
            snmp_parameters=pysnmp_params.snmp_parameters, logger=logger
        )
        transport.add_udp_endpoint(
            snmp_engine, self._snmp_timeout, self._snmp_retry_count
        )
        security = SnmpSecurity(py_snmp_params=pysnmp_params, logger=logger)
        security.add_security(snmp_engine)

        return snmp_engine
