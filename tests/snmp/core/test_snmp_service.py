import sys
from unittest import TestCase

from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject
from cloudshell.snmp.core.snmp_service import SnmpService

if sys.version_info >= (3, 0):
    from unittest.mock import Mock, create_autospec, patch
else:
    from mock import Mock, create_autospec, patch


@patch("cloudshell.snmp.core.snmp_service.builder")
@patch("cloudshell.snmp.core.snmp_service.SnmpService._create_response_service")
class TestSNMPService(TestCase):
    def set_up(
        self,
        builder,
    ):
        builder.DirMibSource.return_value = "some_path/here/1"
        self.snmp_engine = Mock()
        mib_instrum_controller = self.snmp_engine.msgAndPduDsp.mibInstrumController
        mib_instrum_controller.mibBuilder.getMibSources.return_value = (
            "some_path/here/2",
        )
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

    def test_get(self, response_service, builder):
        expected_response = Mock()
        response_service.return_value.result = [expected_response]
        self.set_up(builder)
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.get(oid)
        assert response, expected_response

    def test_set(self, response_service, builder):
        expected_response = Mock()
        response_service.return_value.result = [expected_response]
        self.set_up(builder)
        self.snmp_service._is_snmp_read_only = False
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.set([oid, oid])
        assert response, expected_response

    def test_get_property(self, response_service, builder):
        expected_response = Mock()
        response_service.return_value.result = [expected_response]
        self.set_up(builder)
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.get_property(oid)
        assert response, expected_response

    def test_get_property_bad_response(self, response_service, builder):
        expected_response = None
        response_service.return_value.result = [expected_response]
        self.set_up(builder)
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.get_property(oid)
        assert response, ""

    @patch("cloudshell.snmp.core.snmp_service.univ")
    def test_walk(self, univ, response_service, builder):
        univ.ObjectIdentifier.return_value = 2
        expected_response = [Mock(), Mock(), Mock()]
        response_service.return_value.result = expected_response
        self.set_up(builder)
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.walk(oid)
        assert response, expected_response

    @patch("cloudshell.snmp.core.snmp_service.QualiMibTable")
    @patch("cloudshell.snmp.core.snmp_service.univ")
    def test_get_multiple_columns(self, univ, mib_table, response_service, builder):
        univ.ObjectIdentifier.return_value = 2
        expected_response = [Mock(), Mock(), Mock()]
        mib_table.create_from_list.return_value = expected_response
        response_service.return_value.result = expected_response
        self.set_up(builder)
        oid = create_autospec(SnmpMibObject)
        response = self.snmp_service.get_multiple_columns([oid])
        assert response, expected_response
