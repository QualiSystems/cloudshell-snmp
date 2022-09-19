import unittest
from unittest.mock import Mock

from pysnmp.entity import engine

from cloudshell.snmp.core.domain.snmp_response import SnmpResponse


class TestSnmpResponse(unittest.TestCase):
    def setUp(self):
        self._engine = engine.SnmpEngine()

    def test_snmp_response(self):
        oid = "1.3.6.1.2.1.1.1.0"
        mib_oid = "sysDescr"
        mib_name = "SNMPv2-MIB"
        value = "Some Value"
        snmp_response = SnmpResponse(
            oid=oid, value=value, snmp_engine=self._engine, logger=Mock()
        )
        self.assertEqual(str(snmp_response.oid), oid)
        self.assertEqual(snmp_response.mib_id, mib_oid)
        self.assertEqual(snmp_response.index, "0")
        self.assertEqual(snmp_response.mib_name, mib_name)
        self.assertEqual(snmp_response.raw_value, value)
        self.assertEqual(snmp_response.value, value)
        self.assertEqual(snmp_response.safe_value, value)
