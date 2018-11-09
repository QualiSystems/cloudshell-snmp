from unittest import TestCase
from mock import MagicMock, patch

import cloudshell.snmp.quali_snmp as quali_snmp

from cloudshell.snmp.snmp_parameters import SNMPV3Parameters, SNMPV2ReadParameters


def return_community(community):
    return community


class TestQualiSnmpInit(TestCase):
    SNMP_V3_PARAMS = SNMPV3Parameters(ip="localhost", snmp_user="user", snmp_password="pass",
                                      snmp_private_key="priv_key")
    SNMP_V2_PARAMS = SNMPV2ReadParameters(ip="localhost", snmp_read_community="test")

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

        return quali_snmp.QualiSnmp(snmp_parameters=self.SNMP_V3_PARAMS, logger=self._logger)

    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    @patch("cloudshell.snmp.quali_snmp.QualiSnmp.initialize_snmp")
    def test_snmp_init(self, init_mock, cmdgen_mock, view_mock):
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        cmdgen_mock.CommandGenerator().getCmd.return_value = "", "", "", [["view", result]]

        quali_snmp.QualiSnmp(snmp_parameters=self.SNMP_V3_PARAMS, logger=MagicMock())

        init_mock.assert_called_once_with(self.SNMP_V3_PARAMS)

    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    @patch("cloudshell.snmp.quali_snmp.UsmUserData")
    @patch("cloudshell.snmp.quali_snmp.QualiSnmp._test_snmp_agent")
    def test_snmp_initialize_v3(self, test_mock, usm_mock, cmdgen_mock, view_mock):
        # Setup
        view_mock.MibViewController().getNodeLocation.return_value = ("SNMPv2-MIB", "sysDescr", "0")

        # Act
        quali_snmp.QualiSnmp(snmp_parameters=self.SNMP_V3_PARAMS, logger=MagicMock())

        # Assert
        test_mock.assert_called_once()
        cmdgen_mock.UdpTransportTarget.assert_called_once_with((self.SNMP_V3_PARAMS.ip, self.SNMP_V3_PARAMS.port))
        usm_mock.assert_called_once_with(userName=self.SNMP_V3_PARAMS.snmp_user,
                                         authKey=self.SNMP_V3_PARAMS.snmp_password,
                                         privKey=self.SNMP_V3_PARAMS.snmp_private_key,
                                         authProtocol=self.SNMP_V3_PARAMS.auth_protocol,
                                         privProtocol=self.SNMP_V3_PARAMS.private_key_protocol)

    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    @patch("cloudshell.snmp.quali_snmp.QualiSnmp._test_snmp_agent")
    def test_snmp_initialize_v2(self, test_mock, cmdgen_mock, view_mock):
        # Setup
        view_mock.MibViewController().getNodeLocation.return_value = ("SNMPv2-MIB", "sysDescr", "0")

        # Act
        quali_snmp.QualiSnmp(snmp_parameters=self.SNMP_V2_PARAMS, logger=MagicMock())

        # Assert
        test_mock.assert_called_once()
        cmdgen_mock.UdpTransportTarget.assert_called_once_with((self.SNMP_V2_PARAMS.ip, self.SNMP_V2_PARAMS.port))
        cmdgen_mock.CommunityData.assert_called_once_with(self.SNMP_V2_PARAMS.snmp_community)

    @patch("cloudshell.snmp.quali_snmp.QualiSnmp.get")
    def test_snmp_agent_test(self, get_mock):
        # Setup
        quali_snmp = self.set_up()
        expected_call_params = ('SNMPv2-MIB', 'sysObjectID', '0')

        # Act
        quali_snmp._test_snmp_agent()

        # Assert
        get_mock.assert_called_once_with(expected_call_params)

    @patch("cloudshell.snmp.quali_snmp.ObjectIdentity")
    def test_get(self, obj_id_mock):
        # Setup
        quali_snmp = self.set_up()
        oid = MagicMock()

        # Act
        quali_snmp._command(self._cmdgen_mock.CommandGenerator().getCmd, oid)

        # Assert
        self.assertIsNotNone(quali_snmp.var_binds)
        self._cmdgen_mock.CommandGenerator().getCmd.assert_called_once_with(quali_snmp.security, quali_snmp.target, oid)

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

    def test_command(self, get_mock):
        # Setup
        quali_snmp = self.set_up()
        mib = "SNMPv2-MIB"
        mib_property = "sysDescr"
        index = "1"

        # Act
        result = quali_snmp._command(mib, mib_property, index)

        # Assert
        self.assertIsNotNone(result)
