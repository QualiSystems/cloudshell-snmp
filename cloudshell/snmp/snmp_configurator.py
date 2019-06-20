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
        self._resource_config = resource_config
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


class CommandFlow(ABC):
    @abstractmethod
    def execute(self):
        pass


class EnabelDisableSnmpManager(object):
    """
    Context manager to enable/disable snmp
    """

    def __init__(self, enable_flow, disable_flow, snmp, snmp_parameters, logger):
        """
        :param CommandFlow enable_flow:
        :param CommandFlow disable_flow:
        :param cloudshell.snmp.cloudshell_snmp.Snmp snmp:
        :param snmp_parameters:
        :param logger:
        :return:
        """
        self._enable_flow = enable_flow
        self._disable_flow = disable_flow
        self._snmp = snmp
        self._snmp_parameters = snmp_parameters
        self._logger = logger

    @property
    @lru_cache()
    def _snmp_manager(self):
        return self._snmp.get_snmp_service(self._snmp_parameters, self._logger)

    def __enter__(self):
        """
        Execute enable flow and create snmp service
        :return:
        :rtype: QualiSnmp
        """

        self._enable_flow.execute()
        return self._snmp_manager.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Disable snmp service
        :param exc_type:
        :param exc_val:
        :param exc_tb:
        :return:
        """
        self._disable_flow.execute()
        self._snmp_manager.__exit__(exc_type, exc_val, exc_tb)


class EnableDisableSnmpConfigurator(SnmpConfigurator, ABC):

    @abstractmethod
    def _enable_snmp_flow(self):
        """
        :rtype: CommandFlow
        """
        pass

    @abstractmethod
    def _disable_snmp_flow(self):
        """
        :rtype: CommandFlow
        """
        pass

    def get_service(self):
        return EnabelDisableSnmpManager(self._enable_snmp_flow(), self._disable_snmp_flow(), self._snmp,
                                        self._snmp_parameters,
                                        self._logger)
