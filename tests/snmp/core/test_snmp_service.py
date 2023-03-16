from unittest import TestCase
from unittest.mock import Mock, create_autospec, patch

from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject
from cloudshell.snmp.core.snmp_engine import QualiSnmpEngine
from cloudshell.snmp.core.snmp_msg_pdu_dsp import QualiMsgAndPduDispatcher
from cloudshell.snmp.core.snmp_service import SnmpService


@patch("cloudshell.snmp.core.snmp_service.SnmpService._create_response_service")
class TestSNMPService(TestCase):
    def setUp(self):
        self.snmp_engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=Mock()
        )
        self.snmp_engine.transportDispatcher = Mock()
        context_id = Mock()
        context_name = Mock()
        logger = Mock()
        self.snmp_service = SnmpService(
            snmp_engine=self.snmp_engine,
            context_id=context_id,
            context_name=context_name,
            logger=logger,
            retries=1,
            get_bulk_flag=False,
            is_snmp_read_only=True,
        )

    def test_get(self, response_service):
        expected_response = Mock()
        response_service.return_value.result = [expected_response]
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.get(oid)
        assert response, expected_response

    def test_set(self, response_service):
        expected_response = Mock()
        response_service.return_value.result = [expected_response]
        self.snmp_service._is_snmp_read_only = False
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.set([oid, oid])
        assert response, expected_response

    def test_get_property(self, response_service):
        expected_response = Mock()
        response_service.return_value.result = [expected_response]
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.get_property(oid)
        assert response, expected_response

    def test_get_property_bad_response(self, response_service):
        expected_response = None
        response_service.return_value.result = [expected_response]
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.get_property(oid)
        assert response, ""

    @patch("cloudshell.snmp.core.snmp_service.univ")
    def test_walk(self, univ, response_service):
        univ.ObjectIdentifier.return_value = 2
        expected_response = [Mock(), Mock(), Mock()]
        response_service.return_value.result = expected_response
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.walk(oid)
        assert response, expected_response

    @patch("cloudshell.snmp.core.snmp_service.QualiMibTable")
    @patch("cloudshell.snmp.core.snmp_service.univ")
    def test_get_multiple_columns(self, univ, mib_table, response_service):
        univ.ObjectIdentifier.return_value = 2
        expected_response = [Mock(), Mock(), Mock()]
        mib_table.create_from_list.return_value = expected_response
        response_service.return_value.result = expected_response
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.get_multiple_columns([oid])
        assert response, expected_response
