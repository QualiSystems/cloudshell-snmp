from unittest import TestCase
from unittest.mock import Mock

import pytest

from cloudshell.snmp.snmp_parameters import (
    SnmpParameters,
    SNMPReadParameters,
    SNMPV3Parameters,
    SNMPWriteParameters,
    get_snmp_parameters_from_config,
)
from cloudshell.snmp.types import SNMPConfigProtocol


class TestSNMPParametersInit(TestCase):
    IP = "localhost"
    SNMP_WRITE_COMMUNITY = "private"
    SNMP_READ_COMMUNITY = "public"
    SNMP_USER = "admin"
    SNMP_PASSWORD = "S3c@sw0rd"
    SNMP_PRIVATE_KEY = "S3c@tw0rd"

    def test_snmp_v2_write_parameters(self):
        snmp_v2_write_parameters = SNMPWriteParameters(
            ip=self.IP, snmp_community=self.SNMP_WRITE_COMMUNITY
        )

        self.assertIs(self.IP, snmp_v2_write_parameters.ip)
        self.assertIs(
            self.SNMP_WRITE_COMMUNITY, snmp_v2_write_parameters.snmp_community
        )

    def test_snmp_v2_read_parameters(self):
        snmp_v2_read_parameters = SNMPReadParameters(
            ip=self.IP, snmp_community=self.SNMP_READ_COMMUNITY
        )

        self.assertTrue(snmp_v2_read_parameters.ip == self.IP)
        self.assertTrue(
            snmp_v2_read_parameters.snmp_community == self.SNMP_READ_COMMUNITY
        )

    def test_snmp_v3_parameters(self):
        snmp_v3_parameters = SNMPV3Parameters(
            ip=self.IP,
            snmp_user=self.SNMP_USER,
            snmp_password=self.SNMP_PASSWORD,
            snmp_private_key=self.SNMP_PRIVATE_KEY,
        )

        self.assertTrue(snmp_v3_parameters.ip == self.IP)
        self.assertTrue(snmp_v3_parameters.snmp_user == self.SNMP_USER)
        self.assertTrue(snmp_v3_parameters.snmp_password == self.SNMP_PASSWORD)
        self.assertTrue(snmp_v3_parameters.snmp_private_key == self.SNMP_PRIVATE_KEY)

    def test_snmp_v3_parameters_validate_no_user(self):
        assert_regex = self.assertRaisesRegex

        with assert_regex(Exception, "SNMPv3 user is not defined"):
            SNMPV3Parameters(Mock(), "", Mock(), Mock()).validate()

    def test_snmp_v3_parameters_validate_unknown_auth_protocol(self):
        auth_protocol = "test_auth_protocol"
        assert_regex = self.assertRaisesRegex

        with assert_regex(
            Exception, f"Unknown Authentication Protocol {auth_protocol}"
        ):
            SNMPV3Parameters(
                Mock(), "test_user", Mock(), Mock(), Mock(), auth_protocol
            ).validate()

    def test_snmp_v3_parameters_validate_unknown_priv_protocol(self):
        priv_protocol = "test_priv_protocol"
        assert_regex = self.assertRaisesRegex

        with assert_regex(Exception, f"Unknown Privacy Protocol {priv_protocol}"):
            SNMPV3Parameters(
                Mock(),
                "test_user",
                Mock(),
                Mock(),
                Mock(),
                SNMPV3Parameters.AUTH_MD5,
                priv_protocol,
            ).validate()

    def test_snmp_v3_parameters_validate_no_auth_priv(self):
        auth_proto = SNMPV3Parameters.AUTH_NO_AUTH
        priv_protocol = SNMPV3Parameters.PRIV_3DES
        assert_regex = self.assertRaisesRegex

        with assert_regex(
            Exception, f"{priv_protocol} cannot be used with {auth_proto}"
        ):
            SNMPV3Parameters(
                Mock(), "test_user", Mock(), Mock(), Mock(), auth_proto, priv_protocol
            ).validate()

    def test_snmp_v3_parameters_validate_auth_no_password(self):
        auth_proto = SNMPV3Parameters.AUTH_MD5
        priv_protocol = SNMPV3Parameters.PRIV_NO_PRIV
        assert_regex = self.assertRaisesRegex

        with assert_regex(
            Exception,
            "SNMPv3 Password has to be specified for Authentication Protocol {}".format(
                auth_proto
            ),
        ):
            SNMPV3Parameters(
                Mock(), "test_user", "", Mock(), Mock(), auth_proto, priv_protocol
            ).validate()

    def test_snmp_v3_parameters_validate_priv_no_priv_key(self):
        auth_proto = SNMPV3Parameters.AUTH_MD5
        priv_protocol = SNMPV3Parameters.PRIV_3DES
        assert_regex = self.assertRaisesRegex

        with assert_regex(
            Exception,
            "SNMPv3 Private key has to be specified for Privacy Protocol {}".format(
                priv_protocol
            ),
        ):
            SNMPV3Parameters(
                Mock(), "test_user", Mock(), "", Mock(), auth_proto, priv_protocol
            ).validate()

    def test_snmp_v3_parameters_get_valid(self):
        auth_proto = SNMPV3Parameters.AUTH_NO_AUTH
        priv_protocol = SNMPV3Parameters.PRIV_NO_PRIV
        valid_instance = SNMPV3Parameters(
            Mock(), "tets_user", Mock(), Mock(), Mock(), auth_proto, priv_protocol
        ).get_valid()
        self.assertEqual(valid_instance.snmp_password, "")
        self.assertEqual(valid_instance.snmp_private_key, "")

    def test_snmp_v1_read(self):
        conf = Mock(spec=SNMPConfigProtocol)
        conf.address = "192.168.0.1"
        conf.snmp_version = Mock(value="1")
        conf.snmp_read_community = "public"
        conf.snmp_write_community = ""

        result = get_snmp_parameters_from_config(conf)
        assert isinstance(result, SNMPReadParameters)
        assert result.version == SnmpParameters.SnmpVersion.V1
        assert result.snmp_community == "public"
        assert result.is_read_only

    def test_snmp_v2_write(self):
        conf = Mock(spec=SNMPConfigProtocol)
        conf.address = "192.168.0.1"
        conf.snmp_version = Mock(value="2")
        conf.snmp_read_community = "public"
        conf.snmp_write_community = "private"
        result = get_snmp_parameters_from_config(conf)
        assert isinstance(result, SNMPWriteParameters)
        assert result.version == SnmpParameters.SnmpVersion.V2
        assert result.snmp_community == "private"
        assert not result.is_read_only

    def test_snmp_v3(self):
        conf = Mock(spec=SNMPConfigProtocol)
        conf.address = "192.168.0.1"
        conf.snmp_version = Mock(value="3")
        conf.snmp_v3_user = "user"
        conf.snmp_v3_password = "password"
        conf.snmp_v3_private_key = "private_key"
        conf.snmp_v3_auth_protocol = Mock(value="MD5")
        conf.snmp_v3_priv_protocol = Mock(value="AES-128")
        result = get_snmp_parameters_from_config(conf)
        assert isinstance(result, SNMPV3Parameters)
        assert result.version == SnmpParameters.SnmpVersion.V3
        assert result.snmp_user == "user"
        assert result.snmp_password == "password"
        assert result.snmp_private_key == "private_key"
        assert result.snmp_auth_protocol == SNMPV3Parameters.AUTH_MD5
        assert result.snmp_private_key_protocol == SNMPV3Parameters.PRIV_AES128
        assert not result.is_read_only

    def test_snmp_unknown_version(self):
        conf = Mock(spec=SNMPConfigProtocol)
        conf.address = "192.168.0.1"
        conf.snmp_version = Mock(value="5")
        with pytest.raises(Exception, match="Unknown SNMP version 5"):
            get_snmp_parameters_from_config(conf)

    def test_snmp_ip_invalid(self):
        conf = Mock(spec=SNMPConfigProtocol)
        conf.address = ""
        conf.snmp_read_community = "public"
        conf.snmp_write_community = "private"
        conf.snmp_version = Mock(value="1")
        with pytest.raises(Exception, match="SNMP host is not defined"):
            get_snmp_parameters_from_config(conf)

    def test_snmp_community_invalid(self):
        conf = Mock(spec=SNMPConfigProtocol)
        conf.address = "1.2.3.4"
        conf.snmp_read_community = ""
        conf.snmp_write_community = ""
        conf.snmp_version = Mock(value="1")
        with pytest.raises(Exception, match="SNMP community is not defined"):
            get_snmp_parameters_from_config(conf)
