from unittest import TestCase
from mock import MagicMock, patch

import cloudshell.snmp.quali_snmp as quali_snmp

from pysnmp.entity.rfc3413.oneliner import cmdgen
from cloudshell.snmp.snmp_parameters import SNMPV3Parameters, SNMPV2ReadParameters, SNMPV2WriteParameters


def return_community(community):
    return community


class TestQualiSnmpInit(TestCase):
    def setUp(self):
        self._logger = MagicMock()

    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    def test_quali_snmp_init_with_SNMPV3_params(self, cmdgen_mock, view_mock):
        # Setup
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        cmdgen_mock.CommandGenerator().getCmd.return_value = "", "", "", [["view", result]]
        ip = "localhost"
        snmp_user = "user"
        snmp_password = "pass"
        snmp_private_key = "priv_key"

        view_mock.MibViewController().getNodeLocation.return_value = ("SNMPv2-MIB", "sysDescr", "0")

        # Act
        snmp_v3_params = SNMPV3Parameters(ip=ip, snmp_user=snmp_user, snmp_password=snmp_password,
                                          snmp_private_key=snmp_private_key, auth_protocol=SNMPV3Parameters.AUTH_MD5)
        test_quali_snmp = quali_snmp.QualiSnmp(snmp_parameters=snmp_v3_params, logger=self._logger)

        # Assert
        self.assertIsNotNone(test_quali_snmp.security)
        self.assertTrue(snmp_user == test_quali_snmp.security.userName)
        self.assertTrue(snmp_password == test_quali_snmp.security.authKey)
        self.assertTrue(snmp_private_key == test_quali_snmp.security.privKey)

    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    def test_quali_snmp_init_with_SNMPV2_read_params(self, cmdgen_mock, view_mock):
        # Setup
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        cmdgen_mock.CommandGenerator().getCmd.return_value = "", "", "", [["view", result]]
        cmdgen_mock.CommunityData = lambda x: cmdgen.CommunityData(x)
        ip = "localhost"
        snmp_read_community = 'public'

        view_mock.MibViewController().getNodeLocation.return_value = ("SNMPv2-MIB", "sysDescr", "0")

        # Act
        snmp_v2_read_params = SNMPV2ReadParameters(ip=ip, snmp_read_community=snmp_read_community)
        test_quali_snmp = quali_snmp.QualiSnmp(snmp_parameters=snmp_v2_read_params, logger=self._logger)

        # Assert
        self.assertIsNotNone(test_quali_snmp.security)
        self.assertTrue(test_quali_snmp.security.communityName == snmp_read_community)
        self.assertTrue(test_quali_snmp.is_read_only)

    @patch("cloudshell.snmp.quali_snmp.view")
    @patch("cloudshell.snmp.quali_snmp.cmdgen")
    def test_quali_snmp_init_with_SNMPV2_write_params(self, cmdgen_mock, view_mock):
        # Setup
        result = MagicMock()
        result.prettyPrint.return_value = "response"
        cmdgen_mock.CommandGenerator().getCmd.return_value = "", "", "", [["view", result]]
        cmdgen_mock.CommunityData = lambda x: cmdgen.CommunityData(x)
        ip = "localhost"
        snmp_write_community = 'private'

        view_mock.MibViewController().getNodeLocation.return_value = ("SNMPv2-MIB", "sysDescr", "0")

        # Act
        snmp_v2_read_params = SNMPV2WriteParameters(ip=ip, snmp_write_community=snmp_write_community)
        test_quali_snmp = quali_snmp.QualiSnmp(snmp_parameters=snmp_v2_read_params, logger=self._logger)

        # Assert
        self.assertIsNotNone(test_quali_snmp.security)
        self.assertTrue(test_quali_snmp.security.communityName == snmp_write_community)
        self.assertFalse(test_quali_snmp.is_read_only)

    @patch("cloudshell.snmp.quali_snmp.QualiSnmp.get")
    def test_snmp_v2_parameters_snmp_initialize(self, get_mock):
        get_mock.return_value = "result"
        snmp_v2_read_parameters = SNMPV2ReadParameters(ip="192.168.42.25", snmp_read_community="Cisco")
        snmp = quali_snmp.QualiSnmp(snmp_parameters=snmp_v2_read_parameters, logger=self._logger)
        snmp.get_property("SNMPv2-MIB", "sysDescr", "0")
        get_mock.assert_called()

    @patch("cloudshell.snmp.quali_snmp.QualiSnmp.get")
    def test_snmp_v3_parameters_snmp_initializ(self, get_mock):
        get_mock.return_value = "result"
        test_scenario = []
        for key in ["AES-128", "AES-192", "AES-256", "DES", "3DES-EDE"]:
            for auth in ["SHA", "MD5"]:
                test_scenario.append(SNMPV3Parameters(ip="172.16.1.74",
                                                      snmp_user="test_{}_{}".format(auth.lower(),
                                                                                    key.lower().replace("ede",
                                                                                                        "").replace(
                                                                                        "-", "")),
                                                      snmp_password="test",
                                                      snmp_private_key="temp",
                                                      auth_protocol=auth, private_key_protocol=key))
        for scenario in test_scenario:
            snmp = quali_snmp.QualiSnmp(snmp_parameters=scenario, logger=self._logger)
            snmp.get_property("SNMPv2-MIB", "sysDescr", "0")

        get_mock.assert_called()
