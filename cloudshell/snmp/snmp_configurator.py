from abc import ABC, abstractmethod
from functools import lru_cache

from cloudshell.snmp.cloudshell_snmp import Snmp
from cloudshell.snmp.snmp_parameters import SnmpParametersHelper


class SnmpConfigurator(object):
    """
    Create snmp service, according to resource config values
    """

    def __init__(self, resource_config, logger, api, snmp=None):
        """
        :param cloudshell.shell.standards.resource_config_generic_models.GenericSnmpConfig resource_config:
        :param logging.Logger logger:
        :param cloudshell.api.cloudshell_api.CloudShellAPISession api:
        :param snmp:
        """
        self.resource_config = resource_config
        self._logger = logger
        self._api = api
        # use like a container
        self._snmp = snmp or Snmp()
        self._snmp_parameters_helper = SnmpParametersHelper(resource_config, api)

    @property
    def _snmp_parameters(self):
        return self._snmp_parameters_helper.get_snmp_parameters()

    def get_service(self):
        """
        Enable/Disable snmp
        :return:
        :rtype: SnmpContextManager
        """
        return self._snmp.get_snmp_service(self._snmp_parameters, self._logger)


class EnableDisableSnmpFlowInterface(ABC):
    @abstractmethod
    def enable_snmp(self):
        pass

    @abstractmethod
    def disable_snmp(self):
        pass


class EnableDisableSnmpManager(object):
    """
    Context manager to enable/disable snmp
    """

    def __init__(self, enable_disable_flow, snmp_configurator):
        """
        :param EnableDisableSnmpFlowInterface enable_disable_flow:
        :param SnmpConfigurator snmp_configurator:
        """
        self._enable_disable_flow = enable_disable_flow
        self._snmp_configurator = snmp_configurator

    @lru_cache()
    def _snmp_manager(self):
        return self._snmp_configurator.get_service()

    def __enter__(self):
        """
        :return:
        """
        if str(self._snmp_configurator.resource_config.enable_snmp).lower() == 'true':
            self._enable_disable_flow.enable_snmp()
        return self._snmp_manager.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Disable snmp service
        :param exc_type:
        :param exc_val:
        :param exc_tb:
        :return:
        """
        if str(self._snmp_configurator.resource_config.disable_snmp).lower() == 'false':
            self._enable_disable_flow.disable_snmp()
        self._snmp_manager.__exit__(exc_type, exc_val, exc_tb)

# class EnableDisableSnmpConfigurator(SnmpConfigurator, ABC):
#
#     @abstractmethod
#     def _enable_snmp_flow(self):
#         """
#         :rtype: CommandFlow
#         """
#         pass
#
#     @abstractmethod
#     def _disable_snmp_flow(self):
#         """
#         :rtype: CommandFlow
#         """
#         pass
#
#     def get_service(self):
#         return EnabelDisableSnmpManager(self._enable_snmp_flow(), self._disable_snmp_flow(), self._snmp,
#                                         self._snmp_parameters,
#                                         self._logger)
