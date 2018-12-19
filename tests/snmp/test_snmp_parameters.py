from unittest import TestCase

from mock import Mock

from cloudshell.snmp.snmp_parameters import SNMPV3Parameters, SNMPV2ReadParameters, SNMPV2WriteParameters


class TestSNMPParametersInit(TestCase):
    IP = "localhost"
    SNMP_WRITE_COMMUNITY = "private"
    SNMP_READ_COMMUNITY = "public"
    SNMP_USER = "admin"
    SNMP_PASSWORD = "S3c@sw0rd"
    SNMP_PRIVATE_KEY = "S3c@tw0rd"

    def test_snmp_v2_write_parameters(self):
        snmp_v2_write_parameters = SNMPV2WriteParameters(ip=self.IP,
                                                         snmp_write_community=self.SNMP_WRITE_COMMUNITY)

        self.assertIs(self.IP, snmp_v2_write_parameters.ip)
        self.assertIs(self.SNMP_WRITE_COMMUNITY, snmp_v2_write_parameters.snmp_community)

    def test_snmp_v2_read_parameters(self):
        snmp_v2_read_parameters = SNMPV2ReadParameters(ip=self.IP, snmp_read_community=self.SNMP_READ_COMMUNITY)

        self.assertTrue(snmp_v2_read_parameters.ip == self.IP)
        self.assertTrue(snmp_v2_read_parameters.snmp_community == self.SNMP_READ_COMMUNITY)

    def test_snmp_v3_parameters(self):
        snmp_v3_parameters = SNMPV3Parameters(ip=self.IP, snmp_user=self.SNMP_USER,
                                              snmp_password=self.SNMP_PASSWORD,
                                              snmp_private_key=self.SNMP_PRIVATE_KEY)

        self.assertTrue(snmp_v3_parameters.ip == self.IP)
        self.assertTrue(snmp_v3_parameters.snmp_user == self.SNMP_USER)
        self.assertTrue(snmp_v3_parameters.snmp_password == self.SNMP_PASSWORD)
        self.assertTrue(snmp_v3_parameters.snmp_private_key == self.SNMP_PRIVATE_KEY)

    def test_snmp_v3_parameters_validate_no_user(self):
        with self.assertRaisesRegexp(Exception, 'SNMPv3 user is not defined'):
            SNMPV3Parameters(Mock(), '', Mock(), Mock()).validate()

    def test_snmp_v3_parameters_validate_unknown_auth_protocol(self):
        auth_protocol = 'test_auth_protocol'
        with self.assertRaisesRegexp(Exception, 'Unknown Authentication Protocol {}'.format(auth_protocol)):
            SNMPV3Parameters(Mock(), 'test_user', Mock(), Mock(), Mock(), auth_protocol).validate()

    def test_snmp_v3_parameters_validate_unknown_priv_protocol(self):
        priv_protocol = 'test_priv_protocol'
        with self.assertRaisesRegexp(Exception, 'Unknown Privacy Protocol {}'.format(priv_protocol)):
            SNMPV3Parameters(Mock(), 'test_user', Mock(), Mock(), Mock(), SNMPV3Parameters.AUTH_MD5,
                             priv_protocol).validate()

    def test_snmp_v3_parameters_validate_no_auth_priv(self):
        auth_proto = SNMPV3Parameters.AUTH_NO_AUTH
        priv_protocol = SNMPV3Parameters.PRIV_3DES
        with self.assertRaisesRegexp(Exception, '{} cannot be used with {}'.format(priv_protocol, auth_proto)):
            SNMPV3Parameters(Mock(), 'test_user', Mock(), Mock(), Mock(), auth_proto,
                             priv_protocol).validate()

    def test_snmp_v3_parameters_validate_auth_no_password(self):
        auth_proto = SNMPV3Parameters.AUTH_MD5
        priv_protocol = SNMPV3Parameters.PRIV_NO_PRIV
        with self.assertRaisesRegexp(Exception,
                                     'SNMPv3 Password has to be specified for Authentication Protocol {}'.format(
                                         auth_proto)):
            SNMPV3Parameters(Mock(), 'test_user', '', Mock(), Mock(), auth_proto,
                             priv_protocol).validate()

    def test_snmp_v3_parameters_validate_priv_no_priv_key(self):
        auth_proto = SNMPV3Parameters.AUTH_MD5
        priv_protocol = SNMPV3Parameters.PRIV_3DES
        with self.assertRaisesRegexp(Exception,
                                     'SNMPv3 Private key has to be specified for Privacy Protocol {}'.format(
                                         priv_protocol)):
            SNMPV3Parameters(Mock(), 'test_user', Mock(), '', Mock(), auth_proto,
                             priv_protocol).validate()

    def test_snmp_v3_parameters_get_valid(self):
        auth_proto = SNMPV3Parameters.AUTH_NO_AUTH
        priv_protocol = SNMPV3Parameters.PRIV_NO_PRIV
        valid_instance = SNMPV3Parameters(Mock(), 'tets_user', Mock(), Mock(), Mock(), auth_proto,
                                          priv_protocol).get_valid()
        self.assertEqual(valid_instance.snmp_password, '')
        self.assertEqual(valid_instance.snmp_private_key, '')
