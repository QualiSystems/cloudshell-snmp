from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cloudshell.snmp.cloudshell_snmp import Snmp
from cloudshell.snmp.snmp_parameters import (
    SnmpParameters,
    get_snmp_parameters_from_config,
)
from cloudshell.snmp.types import SNMPConfigProtocol

if TYPE_CHECKING:
    from logging import Logger

    from cloudshell.snmp.cloudshell_snmp import SnmpContextManager


class SnmpConfigurator:
    """Create snmp service, according to resource config values."""

    def __init__(
        self, snmp_parameters: SnmpParameters, logger: Logger, snmp: Snmp = None
    ):
        """Create snmp service, according to resource config values."""
        self._logger = logger
        # use like a container
        self._snmp = snmp or Snmp()
        self._snmp_parameters = snmp_parameters

    def get_service(self) -> SnmpContextManager:
        """Enable/Disable snmp.

        :rtype: SnmpContextManager
        """
        return self._snmp.get_snmp_service(self._snmp_parameters, self._logger)

    @classmethod
    def from_config(cls, conf: SNMPConfigProtocol, logger: Logger) -> SnmpConfigurator:
        """Create SnmpConfigurator from config."""
        snmp_parameters = get_snmp_parameters_from_config(conf)
        return cls(snmp_parameters, logger)


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


class EnableDisableSnmpManager:
    """Context manager to enable/disable snmp."""

    def __init__(
        self,
        enable_disable_flow: EnableDisableSnmpFlowInterface,
        snmp_parameters: SnmpParameters,
        snmp_service: SnmpContextManager,
        logger: Logger,
        enable: bool = True,
        disable: bool = True,
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
        self._snmp_manager = snmp_service
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


class EnableDisableSnmpConfigurator:
    def __init__(
        self,
        enable_disable_snmp_flow: EnableDisableSnmpFlowInterface,
        snmp_parameters: SnmpParameters,
        enable_snmp: bool,
        disable_snmp: bool,
        logger: Logger,
    ):
        """Enable Disable SNMP Configurator."""
        assert enable_disable_snmp_flow, "Enable Disable Snmp Flow class can't be empty"
        assert snmp_parameters, "SnmpParameters can't be empty"

        self._logger = logger
        self._enable_disable_snmp_flow = enable_disable_snmp_flow
        self._snmp_parameters = snmp_parameters
        self._snmp_configurator = SnmpConfigurator(
            snmp_parameters=snmp_parameters, logger=logger
        )
        self._enable_disable_snmp_flow = enable_disable_snmp_flow
        self._enable_snmp = enable_snmp
        self._disable_snmp = disable_snmp

    def get_service(self):
        return EnableDisableSnmpManager(
            enable_disable_flow=self._enable_disable_snmp_flow,
            snmp_parameters=self._snmp_parameters,
            snmp_service=self._snmp_configurator.get_service(),
            logger=self._logger,
            enable=self._enable_snmp,
            disable=self._disable_snmp,
        )

    @classmethod
    def from_config(
        cls,
        enable_disable_snmp_flow: EnableDisableSnmpFlowInterface,
        conf: SNMPConfigProtocol,
        logger: Logger,
    ) -> EnableDisableSnmpConfigurator:
        """Create Enable Disable Snmp Configurator from config."""
        snmp_parameters = get_snmp_parameters_from_config(conf)
        return cls(
            enable_disable_snmp_flow=enable_disable_snmp_flow,
            snmp_parameters=snmp_parameters,
            logger=logger,
            enable_snmp=conf.enable_snmp,
            disable_snmp=conf.disable_snmp,
        )
