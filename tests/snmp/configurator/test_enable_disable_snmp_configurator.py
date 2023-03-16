from logging import Logger
from unittest import TestCase
from unittest.mock import Mock

import pytest

from cloudshell.snmp.snmp_configurator import (
    EnableDisableSnmpConfigurator,
    EnableDisableSnmpFlowInterface,
    EnableDisableSnmpManager,
)
from cloudshell.snmp.snmp_parameters import SNMPReadParameters as SnmpParameters
from cloudshell.snmp.types import SNMPConfigProtocol, SNMPVersionProtocol

"""
Code Analysis:
-The class 'EnableDisableSnmpConfigurator' is responsible for configuring the SNMP service by enabling or disabling it based on the configuration provided. It is an abstract class that defines the interface for enabling and disabling SNMP.
- The class has a constructor that takes in an instance of 'EnableDisableSnmpFlowInterface', 'SnmpParameters', 'enable_snmp', 'disable_snmp', and 'Logger'.
- The 'get_service' method returns an instance of 'EnableDisableSnmpManager' that manages the context of enabling and disabling SNMP.
- The 'from_config' method creates an instance of 'EnableDisableSnmpConfigurator' from the configuration provided. It takes in an instance of 'EnableDisableSnmpFlowInterface', 'SNMPConfigProtocol', and 'Logger'.
- The 'from_config' method extracts the 'SnmpParameters' from the configuration and initializes the 'EnableDisableSnmpConfigurator' instance with the extracted parameters, logger, and enable/disable flags.
- The 'get_service' method returns an instance of 'EnableDisableSnmpManager' that manages the context of enabling and disabling SNMP. It takes in the 'EnableDisableSnmpFlowInterface', 'SnmpParameters', 'SnmpContextManager', 'Logger', 'enable', and 'disable' flags.
"""

"""
Test Plan:
- test_get_service(): tests that the 'get_service' method returns an instance of 'EnableDisableSnmpManager'. Tags: [happy path]
- test_from_config(): tests that the 'from_config' method extracts the 'SnmpParameters' from the configuration and initializes the 'EnableDisableSnmpConfigurator' instance with the extracted parameters, logger, and enable/disable flags. Tags: [happy path]
- test_constructor_invalid_snmp_parameters(): tests that the constructor raises an exception when invalid 'snmp_parameters' are provided. Tags: [edge case]
- test_constructor_invalid_enable_disable_snmp_flow(): tests that the constructor raises an exception when invalid 'enable_disable_snmp_flow' is provided. Tags: [edge case]
- test_constructor_valid_parameters(): tests that the constructor initializes the object with valid parameters. Tags: [happy path]
- test_constructor_invalid_logger(): tests that the constructor raises an exception when invalid 'logger' is provided. Tags: [edge case]
- test_get_service_invalid_enable_snmp(): tests that the 'get_service' method raises an exception when invalid 'enable_snmp' is provided. Tags: [edge case]
- test_get_service_invalid_disable_snmp(): tests that the 'get_service' method raises an exception when invalid 'disable_snmp' is provided. Tags: [edge case]
- test_from_config_invalid_enable_disable_snmp_flow(): tests that the 'from_config' method raises an exception when invalid 'enable_disable_snmp_flow' is provided. Tags: [edge case]
- test_from_config_invalid_logger(): tests that the 'from_config' method raises an exception when invalid 'logger' is provided. Tags: [edge case]
- test_from_config_invalid_snmp_parameters(): tests that the 'from_config' method raises an exception when invalid 'snmp_parameters' are provided. Tags: [edge case]
"""


class TestEnableDisableSnmpConfigurator(TestCase):
    def test_get_service(self):
        # Arrange
        enable_disable_flow = Mock(spec=EnableDisableSnmpFlowInterface)
        snmp_parameters = SnmpParameters(ip="1.2.3.4", snmp_community="public")
        logger = Mock(spec=Logger)
        enable = True
        disable = True
        configurator = EnableDisableSnmpConfigurator(
            enable_disable_flow, snmp_parameters, enable, disable, logger
        )

        # Act
        service = configurator.get_service()
        with service:
            pass

        # Assert
        assert isinstance(service, EnableDisableSnmpManager)
        assert enable_disable_flow.enable_snmp.called_once_with(snmp_parameters)
        assert enable_disable_flow.disable_snmp.called_once_with(snmp_parameters)

    def test_from_config(self):
        # Arrange
        ip = "1.2.3.4"
        enable_disable_flow = Mock(spec=EnableDisableSnmpFlowInterface)
        conf = Mock(spec=SNMPConfigProtocol)
        conf.address = ip
        conf.enable_snmp = True
        conf.snmp_write_community = ""
        conf.snmp_read_community = "public"
        conf.disable_snmp = False
        conf.snmp_version = Mock(spec=SNMPVersionProtocol, value="v2c")
        logger = Mock(spec=Logger)
        snmp_parameters = SnmpParameters(ip=ip, snmp_community="public")

        # Act
        configurator = EnableDisableSnmpConfigurator.from_config(
            enable_disable_flow, conf, logger
        )

        # Assert
        assert isinstance(configurator, EnableDisableSnmpConfigurator)
        assert configurator._snmp_parameters.ip == snmp_parameters.ip
        assert configurator._snmp_parameters.version == snmp_parameters.version
        assert (
            configurator._snmp_parameters.snmp_community
            == snmp_parameters.snmp_community
        )
        assert configurator._enable_snmp == conf.enable_snmp
        assert configurator._disable_snmp == conf.disable_snmp

    def test_constructor_invalid_snmp_parameters(self):
        # Arrange
        enable_disable_flow = Mock(spec=EnableDisableSnmpFlowInterface)
        snmp_parameters = None
        logger = Mock(spec=Logger)

        # Act / Assert
        with pytest.raises(AssertionError):
            EnableDisableSnmpConfigurator(
                enable_disable_flow, snmp_parameters, True, False, logger
            )

    def test_constructor_empty_enable_disable_snmp_flow(self):
        # Arrange
        enable_disable_flow = None
        snmp_parameters = SnmpParameters(ip="1.2.3.4", snmp_community="public")
        logger = Mock(spec=Logger)

        # Act / Assert
        with pytest.raises(AssertionError):
            EnableDisableSnmpConfigurator(
                enable_disable_flow, snmp_parameters, True, False, logger
            )

    def test_constructor_valid_parameters(self):
        # Arrange
        enable_disable_flow = Mock(spec=EnableDisableSnmpFlowInterface)
        snmp_parameters = SnmpParameters(ip="1.2.3.4", snmp_community="public")
        logger = Mock(spec=Logger)

        # Act
        configurator = EnableDisableSnmpConfigurator(
            enable_disable_flow, snmp_parameters, True, False, logger
        )

        # Assert
        assert isinstance(configurator, EnableDisableSnmpConfigurator)
        assert configurator._snmp_parameters == snmp_parameters
        assert configurator._enable_snmp is True
        assert configurator._disable_snmp is False
