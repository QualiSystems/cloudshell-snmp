from logging import Logger
from unittest import TestCase
from unittest.mock import Mock, patch

import pytest

from cloudshell.snmp.core.snmp_context_manager import SnmpContextManager
from cloudshell.snmp.core.snmp_engine import QualiSnmpEngine
from cloudshell.snmp.core.snmp_msg_pdu_dsp import QualiMsgAndPduDispatcher
from cloudshell.snmp.core.snmp_service import SnmpService
from cloudshell.snmp.core.tools.snmp_json_mib import JsonMib

"""
Code Analysis:
-The SnmpContextManager class is responsible for managing SNMP contexts.
- It takes in several parameters during initialization, including the SNMP engine, context engine ID, context name, logger, get_bulk_flag, and is_snmp_read_only.
- The __enter__ method returns the result of the get_service method, which creates a new SnmpService object with the parameters passed during initialization.
- The get_service method creates a new SnmpService object with the parameters passed during initialization and returns it.
- The __exit__ method is responsible for cleaning up after the context is exited. It closes the transportDispatcher and destroys any JSON MIBs that were created.
- The main functionality of the class is to provide a context manager for creating and managing SNMP services.
- The main methods of the class are __enter__, get_service, and __exit__.
- The main fields of the class are _snmp_engine, _is_snmp_read_only, _v3_context_engine_id, _v3_context, _logger, and _get_bulk_flag.
"""

"""
Test Plan:
- test_create_snmp_context_manager_valid_params(): tests creating a SnmpContextManager object with valid parameters. Tags: [happy path]
- test_enter_exit_context_manager_no_errors(): tests entering and exiting the context manager without any errors. Tags: [happy path]
- test_enter_exit_context_manager_with_errors(): tests entering and exiting the context manager with errors or exceptions. Tags: [edge case]
- test_create_snmp_context_manager_empty_params(): tests creating a SnmpContextManager object with empty parameters. Tags: [edge case]
- test_exit_closes_transport_dispatcher(): tests that the __exit__ method closes the transportDispatcher. Tags: [general behavior]
- test_exit_destroys_json_mibs(): tests that the __exit__ method destroys any JSON MIBs. Tags: [general behavior]
- test_logger_behavior(): tests the behavior of the logger object passed during initialization. Tags: [general behavior]
- test_create_snmp_context_manager_invalid_params(): tests creating a SnmpContextManager object with invalid parameters. Tags: [edge case]
- test_get_service_valid_params(): tests calling the get_service method and receiving a valid SnmpService object. Tags: [happy path]
- test_get_service_invalid_params(): tests calling the get_service method with invalid parameters. Tags: [edge case]
- test_get_service_returns_snmp_service(): tests that the get_service method creates and returns a valid SnmpService object. Tags: [happy path]
"""


class TestSnmpContextManager(TestCase):
    def test_create_snmp_context_manager_valid_params(self):
        logger = Mock(spec=Logger)
        snmp_engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=logger
        )
        v3_context_engine_id = "test_id"
        v3_context_name = "test_name"
        logger = "test_logger"
        get_bulk_flag = True
        is_snmp_read_only = False

        with SnmpContextManager(
            snmp_engine,
            v3_context_engine_id,
            v3_context_name,
            logger,
            get_bulk_flag,
            is_snmp_read_only,
        ) as snmp_context:
            assert isinstance(snmp_context, SnmpService)

    def test_enter_exit_context_manager_no_errors(self):
        logger = Mock(spec=Logger)
        snmp_engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=logger
        )
        v3_context_engine_id = "test_id"
        v3_context_name = "test_name"
        logger = "test_logger"
        get_bulk_flag = True
        is_snmp_read_only = False

        with SnmpContextManager(
            snmp_engine,
            v3_context_engine_id,
            v3_context_name,
            logger,
            get_bulk_flag,
            is_snmp_read_only,
        ):
            pass

    def test_enter_exit_context_manager_with_errors(self):
        logger = Mock(spec=Logger)
        snmp_engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=logger
        )
        v3_context_engine_id = "test_id"
        v3_context_name = "test_name"
        logger = "test_logger"
        get_bulk_flag = True
        is_snmp_read_only = False

        with pytest.raises(Exception):
            with SnmpContextManager(
                snmp_engine,
                v3_context_engine_id,
                v3_context_name,
                logger,
                get_bulk_flag,
                is_snmp_read_only,
            ):
                raise Exception("Test Exception")

    def test_create_snmp_context_manager_empty_params(self):
        with pytest.raises(TypeError):
            SnmpContextManager()

    @patch("cloudshell.snmp.core.snmp_context_manager.SnmpService")
    def test_exit_closes_transport_dispatcher(self, snmp_service_mock):
        snmp_engine_mock = Mock()
        mib_builder_mock = Mock()
        snmp_engine_mock.mib_builder = mib_builder_mock
        mib_mock = Mock(spec=JsonMib)
        mib_builder_mock.json_mib_parser.json_mibs = {"test_mib": mib_mock}
        transport_dispatcher_mock = Mock()
        snmp_engine_mock.transportDispatcher = transport_dispatcher_mock

        with SnmpContextManager(
            snmp_engine_mock, "test_id", "test_name", "test_logger"
        ):
            pass

        transport_dispatcher_mock.closeDispatcher.assert_called_once()

    @patch("cloudshell.snmp.core.snmp_context_manager.SnmpService")
    def test_exit_destroys_json_mibs(self, snmp_service_mock):
        snmp_engine_mock = Mock()
        mib_builder_mock = Mock()
        snmp_engine_mock.mib_builder = mib_builder_mock
        mib_mock = Mock(spec=JsonMib)
        mib_builder_mock.json_mib_parser.json_mibs = {"test_mib": mib_mock}

        with SnmpContextManager(
            snmp_engine_mock, "test_id", "test_name", "test_logger"
        ):
            pass

        assert mib_mock.json_mib_destroy.call_count == 1
