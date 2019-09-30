import sys
from unittest import TestCase

from cloudshell.snmp.snmp_configurator import EnableDisableSnmpConfigurator

if sys.version_info >= (3, 0):
    from unittest.mock import Mock, patch
else:
    from mock import Mock, patch


class TestSNMPConfiguratorInit(TestCase):
    @patch("cloudshell.snmp.snmp_configurator.Snmp")
    @patch("cloudshell.snmp.snmp_configurator.SnmpParametersHelper")
    def test_enable_disable_snmp_configurator_init(
        self, smp_params_helper_mock, snmp_mock
    ):
        resource_config = Mock()
        resource_config.enable_snmp = "True"
        resource_config.disable_snmp = "True"
        logger = Mock()
        enable_disable_flow = Mock()

        config = EnableDisableSnmpConfigurator(
            enable_disable_flow, resource_config, logger
        )
        config.get_service()

        smp_params_helper_mock.assert_called_once()
        snmp_mock.assert_called_once()

        with config.get_service():
            pass

        enable_disable_flow.enable_snmp.assert_called_once()
        enable_disable_flow.disable_snmp.assert_called_once()
