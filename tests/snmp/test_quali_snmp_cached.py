from unittest import TestCase

from mock import patch, MagicMock

from cloudshell.snmp.quali_snmp_cached import QualiSnmpCached
from cloudshell.snmp.snmp_parameters import SNMPV3Parameters


class TestQualiSnmpInit(TestCase):
    SNMP_V3_PARAMS = SNMPV3Parameters(ip="localhost", snmp_user="user", snmp_password="pass",
                                      snmp_private_key="priv_key")

    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    @patch("cloudshell.snmp.quali_snmp.QualiSnmp.initialize_snmp")
    def set_up(self, init_mock, cmdgen_mock, view_mock):
        self._logger = MagicMock()
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        self._cmdgen_mock = cmdgen_mock
        cmdgen_mock.CommandGenerator().getCmd.return_value = "", "", "", [["view", result]]
        cmdgen_mock.CommandGenerator().nextCmd.return_value = "", "", "", [[["view", result]]]
        cmdgen_mock.CommandGenerator().setCmd.return_value = "", "", "", [["view", result]]

        view_mock.MibViewController().getNodeLocation.return_value = ("SNMPv2-MIB", "sysDescr", "0")

        return QualiSnmpCached(snmp_parameters=self.SNMP_V3_PARAMS, logger=self._logger)

    def test_get_cached(self):
        # Setup
        quali_snmp = self.set_up()
        oid = "1.2.3.4"

        # Act
        with patch('__builtin__.super') as super_mock:
            quali_snmp.get(oid)
            result = quali_snmp.get(oid)

        # Assert
        self.assertIsNotNone(result)
        super_mock.return_value.get.assert_called_once_with(oid)

    def test_walk_cached(self):
        # Setup
        quali_snmp = self.set_up()
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        quali_snmp.var_binds = [[["view", result]]]

        # Act
        with patch('__builtin__.super') as super_mock:
            quali_snmp.walk(("SNMPv2-MIB", "sysDescr"))
            response = quali_snmp.walk(("SNMPv2-MIB", "sysDescr"))

        # Assert
        super_mock.assert_called_with(QualiSnmpCached, quali_snmp)
        super_mock.return_value.walk.assert_called_once_with(("SNMPv2-MIB", "sysDescr"))
        self.assertIsNotNone(response)
        first_element = response.get(0)
        self.assertIsNotNone(first_element)
        self.assertIsNotNone(first_element.get("sysDescr"))
