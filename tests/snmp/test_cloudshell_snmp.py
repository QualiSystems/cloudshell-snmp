import sys
from unittest import TestCase

from cloudshell.snmp.cloudshell_snmp import Snmp
from cloudshell.snmp.core.tools.snmp_constants import SNMP_RETRIES_COUNT, SNMP_TIMEOUT

if sys.version_info >= (3, 0):
    from unittest.mock import Mock, patch
else:
    from mock import Mock, patch


class TestSNMP(TestCase):
    def test_snmp_init_without_params(self):
        # Act
        snmp = Snmp()

        # Assert
        self.assertEqual(snmp._snmp_timeout, SNMP_TIMEOUT)
        self.assertEqual(snmp._snmp_retry_count, SNMP_RETRIES_COUNT)

    def test_snmp_init_with_params(self):
        # Assign
        timeout = 1
        retries = 2

        # Act
        snmp = Snmp(timeout=timeout, retry_count=retries)

        # Assert
        self.assertEqual(snmp._snmp_timeout, timeout)
        self.assertEqual(snmp._snmp_retry_count, retries)

    @patch("cloudshell.snmp.cloudshell_snmp.SnmpContextManager")
    @patch("cloudshell.snmp.cloudshell_snmp.SnmpContext")
    @patch("cloudshell.snmp.cloudshell_snmp.SnmpParametersConverter")
    @patch("cloudshell.snmp.cloudshell_snmp.Snmp._get_snmp_engine")
    def test_get_snmp_service(
        self, mock_get_engine, mock_params_converter, mock_context, mock_context_manager
    ):
        logger = Mock()
        snmp_params = Mock()
        snmp = Snmp()
        mock_params_converter.return_value.version = 0

        snmp.get_snmp_service(snmp_parameters=snmp_params, logger=logger)

        mock_params_converter.assert_called_once_with(snmp_params)
        mock_get_engine.assert_called_once_with(
            mock_params_converter.return_value, logger
        )
        mock_context.assert_called_once_with(
            snmp_params.context_engine_id, snmp_params.context_name
        )
        mock_context_manager.assert_called_once_with(
            snmp_engine=mock_get_engine.return_value,
            v3_context_engine_id=mock_context.return_value.context_engine_id,
            v3_context_name=mock_context.return_value.context_name,
            logger=logger,
            get_bulk_flag=False,
            is_snmp_read_only=mock_params_converter.return_value.is_read_only,
        )

    @patch("cloudshell.snmp.cloudshell_snmp.SnmpContextManager")
    @patch("cloudshell.snmp.cloudshell_snmp.SnmpContext")
    @patch("cloudshell.snmp.cloudshell_snmp.SnmpParametersConverter")
    @patch("cloudshell.snmp.cloudshell_snmp.Snmp._get_snmp_engine")
    def test_get_snmp_service_with_get_bulk(
        self, mock_get_engine, mock_params_converter, mock_context, mock_context_manager
    ):
        logger = Mock()
        snmp_params = Mock()
        snmp = Snmp()
        mock_params_converter.return_value.version = 1

        snmp.get_snmp_service(snmp_parameters=snmp_params, logger=logger)

        mock_params_converter.assert_called_once_with(snmp_params)
        mock_get_engine.assert_called_once_with(
            mock_params_converter.return_value, logger
        )
        mock_context.assert_called_once_with(
            snmp_params.context_engine_id, snmp_params.context_name
        )
        mock_context_manager.assert_called_once_with(
            snmp_engine=mock_get_engine.return_value,
            v3_context_engine_id=mock_context.return_value.context_engine_id,
            v3_context_name=mock_context.return_value.context_name,
            logger=logger,
            get_bulk_flag=True,
            is_snmp_read_only=mock_params_converter.return_value.is_read_only,
        )

    @patch("cloudshell.snmp.cloudshell_snmp.SnmpSecurity")
    @patch("cloudshell.snmp.cloudshell_snmp.SnmpTransport")
    @patch("cloudshell.snmp.cloudshell_snmp.engine")
    @patch("cloudshell.snmp.cloudshell_snmp.config")
    def test_get_snmp_engine(
        self, mock_config, mock_engine, mock_transport, mock_security
    ):
        logger = Mock()
        pysnmp_params = Mock()
        snmp = Snmp()

        snmp._get_snmp_engine(logger=logger, pysnmp_params=pysnmp_params)

        mock_engine.SnmpEngine.assert_called_once_with()
        mock_config.addTargetParams.assert_called_once_with(
            mock_engine.SnmpEngine.return_value,
            "pms",
            pysnmp_params.user,
            pysnmp_params.security,
            pysnmp_params.version,
        )
        mock_transport.assert_called_once_with(
            snmp_parameters=pysnmp_params.snmp_parameters, logger=logger
        )
        mock_transport.return_value.add_udp_endpoint.assert_called_once_with(
            mock_engine.SnmpEngine.return_value,
            snmp._snmp_timeout,
            snmp._snmp_retry_count,
        )
        mock_security.assert_called_once_with(
            py_snmp_params=pysnmp_params, logger=logger
        )
        mock_security.return_value.add_security.assert_called_once_with(
            mock_engine.SnmpEngine.return_value
        )
