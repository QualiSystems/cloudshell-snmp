from unittest import TestCase
from mock import MagicMock, patch

import cloudshell.snmp.quali_snmp as quali_snmp

from cloudshell.snmp.snmp_parameters import SNMPV3Parameters


def return_community(community):
    return community


class TestQualiSnmpInit(TestCase):
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

        snmp_v3_params = SNMPV3Parameters(ip="localhost", snmp_user="user", snmp_password="pass",
                                          snmp_private_key="priv_key")
        return quali_snmp.QualiSnmp(snmp_parameters=snmp_v3_params, logger=self._logger)

    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    @patch("cloudshell.snmp.quali_snmp.QualiSnmp.initialize_snmp")
    def test_snmp_init(self, init_mock, cmdgen_mock, view_mock):
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        cmdgen_mock.CommandGenerator().getCmd.return_value = "", "", "", [["view", result]]

        snmp_v3_params = SNMPV3Parameters(ip="localhost", snmp_user="user", snmp_password="pass",
                                          snmp_private_key="priv_key")
        quali_snmp.QualiSnmp(snmp_parameters=snmp_v3_params, logger=MagicMock())

        init_mock.assert_called_once_with(snmp_v3_params)

    @patch("cloudshell.snmp.quali_snmp.ObjectIdentity")
    @patch("cloudshell.snmp.quali_snmp.QualiSnmp._command")
    def test_get(self, cmd_mock, obj_id_mock):
        # Setup
        quali_snmp = self.set_up()

        # Act
        result = quali_snmp.get("1.2.3.4")

        # Assert
        self.assertIsNotNone(result)
        cmd_mock.assert_called_once_with(self._cmdgen_mock.CommandGenerator().getCmd, obj_id_mock.return_value)

    @patch("cloudshell.snmp.quali_snmp.QualiSnmp.get")
    def test_get_property(self, get_mock):
        # Setup
        quali_snmp = self.set_up()
        mib = "SNMPv2-MIB"
        mib_property = "sysDescr"
        index = "1"

        # Act
        result = quali_snmp.get_property(mib, mib_property, index)

        # Assert
        self.assertIsNotNone(result)
        get_mock.assert_called_once_with((mib, mib_property, index))

    @patch("cloudshell.snmp.quali_snmp.QualiSnmp.walk")
    def test_get_table(self, walk_mock):
        # Setup
        quali_snmp = self.set_up()
        mib = "SNMPv2-MIB"
        mib_property = "system"

        # Act
        result = quali_snmp.get_table(mib, mib_property)

        # Assert
        self.assertIsNotNone(result)
        walk_mock.assert_called_once_with((mib, mib_property))

    @patch("cloudshell.snmp.quali_snmp.ObjectIdentity")
    @patch("cloudshell.snmp.quali_snmp.QualiSnmp._command")
    def test_walk(self, cmd_mock, obj_id_mock):
        # Setup
        quali_snmp = self.set_up()
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        quali_snmp.var_binds = [[["view", result]]]

        # Act
        result = quali_snmp.walk(("SNMPv2-MIB", "sysDescr"))

        # Assert
        self.assertIsNotNone(result)
        first_element = result.get(0)
        self.assertIsNotNone(first_element)
        self.assertIsNotNone(first_element.get("sysDescr"))
        cmd_mock.assert_called_once_with(self._cmdgen_mock.CommandGenerator().nextCmd, obj_id_mock.return_value)

    @patch("cloudshell.snmp.quali_snmp.ObjectType")
    @patch("cloudshell.snmp.quali_snmp.QualiSnmp._command")
    def test_set(self, cmd_mock, obj_type_mock):
        # Setup
        quali_snmp = self.set_up()

        # Act
        quali_snmp.set([(("CISCO-CONFIG-COPY-MIB", "ccCopyProtocol", 10), 1)])

        # Assert
        cmd_mock.assert_called_once_with(self._cmdgen_mock.CommandGenerator().setCmd, obj_type_mock.return_value)
