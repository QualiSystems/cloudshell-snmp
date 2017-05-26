from unittest import TestCase
from mock import MagicMock, patch

import cloudshell.snmp.quali_snmp as quali_snmp

from pysnmp.entity.rfc3413.oneliner import cmdgen
from cloudshell.snmp.snmp_parameters import SNMPV3Parameters, SNMPV2ReadParameters, SNMPV2WriteParameters


def return_community(community):
    return community


@patch("cloudshell.snmp.quali_snmp.view")
@patch("cloudshell.snmp.quali_snmp.cmdgen")
class TestQualiSnmpInit(TestCase):
    def setUp(self):
        self._logger = MagicMock()

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
                                          snmp_private_key=snmp_private_key)
        test_quali_snmp = quali_snmp.QualiSnmp(snmp_parameters=snmp_v3_params, logger=self._logger)

        # Assert
        self.assertIsNotNone(test_quali_snmp.security)
        self.assertTrue(snmp_user == test_quali_snmp.security.userName)
        self.assertTrue(snmp_password == test_quali_snmp.security.authKey)
        self.assertTrue(snmp_private_key == test_quali_snmp.security.privKey)

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
