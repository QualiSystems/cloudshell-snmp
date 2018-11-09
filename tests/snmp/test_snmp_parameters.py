from unittest import TestCase
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
