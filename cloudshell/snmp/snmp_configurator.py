from abc import ABCMeta, abstractmethod

from cloudshell.snmp.cloudshell_snmp import Snmp
from cloudshell.snmp.snmp_parameters import SnmpParametersHelper

ABC = ABCMeta("ABC", (object,), {"__slots__": ()})


class SnmpConfigurator(object):
    """Create snmp service, according to resource config values."""

    def __init__(self, resource_config, logger, snmp=None):
        """Create snmp service, according to resource config values.

        :param cloudshell.shell.standards.resource_config_generic_models.GenericSnmpConfig resource_config:  # noqa: E501
        :param logging.Logger logger:
        :param snmp:
        """
        self.resource_config = resource_config
        self._logger = logger
        # use like a container
        self._snmp = snmp or Snmp()
        self._snmp_parameters_helper = SnmpParametersHelper(resource_config)

    @property
    def _snmp_parameters(self):
        return self._snmp_parameters_helper.get_snmp_parameters()

    def get_service(self):
        """Enable/Disable snmp.

        :rtype: SnmpContextManager
        """
        return self._snmp.get_snmp_service(self._snmp_parameters, self._logger)


class EnableDisableSnmpFlowInterface(ABC):
    @abstractmethod
    def enable_snmp(self, snmp_parameters):
        """Enable SNMP.

        :param cloudshell.snmp.snmp_parameters.SnmpParameters snmp_parameters:
        """
        pass

    @abstractmethod
    def disable_snmp(self, snmp_parameters):
        """Disable SNMP.

        :param cloudshell.snmp.snmp_parameters.SnmpParameters snmp_parameters:
        """
        pass


class EnableDisableSnmpManager(object):
    """Context manager to enable/disable snmp."""

    def __init__(
        self,
        enable_disable_flow,
        snmp_parameters,
        snmp,
        logger,
        enable=True,
        disable=True,
    ):
        """Context manager to enable/disable snmp.

        :param EnableDisableSnmpFlowInterface enable_disable_flow:
        :param cloudshell.snmp.snmp_parameters.SnmpParameters snmp_parameters:
        :param cloudshell.snmp.cloudshell_snmp.Snmp snmp:
        :param logging.Logger logger:
        :param bool enable:
        :disable bool disable:
        """
        self._enable_disable_flow = enable_disable_flow
        self._snmp_parameters = snmp_parameters
        self._logger = logger
        self._snmp_manager = snmp.get_snmp_service(self._snmp_parameters, self._logger)
        self._enable = enable
        self._disable = disable

    def __enter__(self):
        if self._enable:
            self._logger.debug("Calling enable snmp flow")
            self._enable_disable_flow.enable_snmp(self._snmp_parameters)
        return self._snmp_manager.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Disable snmp service."""
        if self._disable:
            self._logger.debug("Calling disable snmp flow")
            self._enable_disable_flow.disable_snmp(self._snmp_parameters)
        self._snmp_manager.__exit__(exc_type, exc_val, exc_tb)


class EnableDisableSnmpConfigurator(SnmpConfigurator, ABC):
    def __init__(self, enable_disable_snmp_flow, resource_config, logger):
        """Enable Disable SNMP Configurator.

        :param EnableDisableSnmpFlowInterface enable_disable_snmp_flow:
        :param resource_config:
        :param logger:
        """
        super(EnableDisableSnmpConfigurator, self).__init__(resource_config, logger)
        self._enable_disable_snmp_flow = enable_disable_snmp_flow

    def get_service(self):
        enable = self.resource_config.enable_snmp.lower() == str(True).lower()
        disable = self.resource_config.disable_snmp.lower() == str(True).lower()
        return EnableDisableSnmpManager(
            self._enable_disable_snmp_flow,
            self._snmp_parameters,
            self._snmp,
            self._logger,
            enable,
            disable,
        )
