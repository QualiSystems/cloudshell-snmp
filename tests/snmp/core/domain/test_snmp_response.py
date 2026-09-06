import unittest
from unittest.mock import Mock

from pysnmp.proto import rfc1902

from cloudshell.snmp.core.domain.snmp_response import SnmpResponse
from cloudshell.snmp.core.snmp_engine import QualiSnmpEngine
from cloudshell.snmp.core.snmp_msg_pdu_dsp import QualiMsgAndPduDispatcher
from cloudshell.snmp.core.snmp_service import SnmpService


class TestSnmpResponse(unittest.TestCase):
    def setUp(self):
        self._engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=Mock()
        )

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

    def test_malformed_textual_convention_renders_raw(self):
        """Payloads violating a TC size constraint must render as raw ASCII.

        pysnmp 7 resolve_with_mib force-assigns the wire payload into the MIB
        type bypassing constraints; without the fallback a malformed
        DateAndTime (entPhysicalMfgDate) renders through the DISPLAY-HINT as
        garbage. pysnmp 4 rendered the raw octets - keep that behavior.
        """
        # loads the bundled JSON MIBs (ENTITY-MIB) into the engine
        SnmpService(self._engine, None, "", Mock())
        oid = "1.3.6.1.2.1.47.1.1.1.1.17.2"  # entPhysicalMfgDate.2

        for payload, expected in ((b"0" * 16, "0000000000000000"), (b"NA", "NA")):
            response = SnmpResponse(
                oid=oid,
                value=rfc1902.OctetString(payload),
                snmp_engine=self._engine,
                logger=Mock(),
            )
            self.assertEqual(response.safe_value, expected)
            self.assertEqual(response.mib_id, "entPhysicalMfgDate")

        # a well-formed DateAndTime must still render via the DISPLAY-HINT
        well_formed = SnmpResponse(
            oid=oid,
            value=rfc1902.OctetString(bytes([0x07, 0xE8, 1, 2, 3, 4, 5, 6])),
            snmp_engine=self._engine,
            logger=Mock(),
        )
        self.assertEqual(well_formed.safe_value, "2024-1-2,3:4:5.6")
