from unittest import TestCase
from mock import MagicMock, patch

import cloudshell.snmp.quali_snmp as quali_snmp

from cloudshell.snmp.snmp_parameters import SNMPV3Parameters


def return_community(community):
    return community


class TestQualiSnmpInit(TestCase):
    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    def set_up(self, cmdgen_mock, view_mock):
        self._logger = MagicMock()
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        cmdgen_mock.CommandGenerator().getCmd.return_value = "", "", "", [["view", result]]
        cmdgen_mock.CommandGenerator().nextCmd.return_value = "", "", "", [[["view", result]]]
        cmdgen_mock.CommandGenerator().setCmd.return_value = "", "", "", [["view", result]]

        view_mock.MibViewController().getNodeLocation.return_value = ("SNMPv2-MIB", "sysDescr", "0")

        snmp_v3_params = SNMPV3Parameters(ip="localhost", snmp_user="user", snmp_password="pass",
                                          snmp_private_key="priv_key")
        return quali_snmp.QualiSnmp(snmp_parameters=snmp_v3_params, logger=self._logger)

    def test_get(self):
        # Setup
        quali_snmp = self.set_up()

        # Act
        result = quali_snmp.get()

        # Assert
        self.assertIsNotNone(result)

    def test_walk(self):
        # Setup
        quali_snmp = self.set_up()

        # Act
        result = quali_snmp.walk(("SNMPv2-MIB", "sysDescr"))

        # Assert
        self.assertIsNotNone(result)
        first_element = result.get(0)
        self.assertIsNotNone(first_element)
        self.assertIsNotNone(first_element.get("sysDescr"))

    def test_set(self):
        # Setup
        quali_snmp = self.set_up()

        # Act
        quali_snmp.set([(("CISCO-CONFIG-COPY-MIB", "ccCopyProtocol", 10), 1)])
