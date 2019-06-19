from pysnmp.entity import engine, config

from cloudshell.snmp.core.tools.snmp_parameters_helper import SnmpParametersConverter
from cloudshell.snmp.core.tools.snmp_context import SnmpContext
from cloudshell.snmp.core.tools.snmp_security import SnmpSecurity
from cloudshell.snmp.core.tools.snmp_trasnport import SnmpTransport
from cloudshell.snmp.core.tools.snmp_constants import SNMP_RETRIES_COUNT, SNMP_TIMEOUT
from cloudshell.snmp.core.snmp_context_manager import SnmpContextManager


class Snmp(object):
    def __init__(self, v3_context_engine_id=None, v3_context_name="", timeout=SNMP_TIMEOUT,
                 retry_count=SNMP_RETRIES_COUNT):
        self._v3_context_engine_id = v3_context_engine_id
        self._v3_context_name = v3_context_name
        self._snmp_engine = None
        self._snmp_timeout = timeout
        self._snmp_retry_count = retry_count

    def get_snmp_service(self, snmp_parameters, logger):
        """

        :param cloudshell.snmp.snmp_parameters.SnmpParameters snmp_parameters:
        :param logging.Logger logger:
        :return:
        """
        py_snmp_params = SnmpParametersConverter(snmp_parameters)
        snmp_engine = self._get_snmp_engine(py_snmp_params, logger)
        snmp_context = SnmpContext(self._v3_context_engine_id, self._v3_context_name)
        get_bulk_flag = py_snmp_params.version > 0
        return SnmpContextManager(snmp_engine=snmp_engine,
                                  v3_context_engine_id=snmp_context.context_engine_id,
                                  v3_context_name=snmp_context.context_name,
                                  logger=logger,
                                  get_bulk_flag=get_bulk_flag
                                  )

    def _get_snmp_engine(self, py_snmp_params, logger):
        """
        :param cloudshell.snmp.core.tools.snmp_parameters_helper.SnmpParametersConverter py_snmp_params:
        :return:
        """
        snmp_engine = engine.SnmpEngine()
        config.addTargetParams(snmp_engine,
                               'pms',
                               py_snmp_params.user,
                               py_snmp_params.security,
                               py_snmp_params.version)
        transport = SnmpTransport(snmp_parameters=py_snmp_params.snmp_parameters,
                                  logger=logger)
        transport.add_udp_endpoint(snmp_engine,
                                   self._snmp_timeout,
                                   self._snmp_retry_count)
        security = SnmpSecurity(py_snmp_params=py_snmp_params,
                                logger=logger)
        security.add_security(snmp_engine)

        return snmp_engine
