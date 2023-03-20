import os
import unittest
from unittest.mock import Mock

from cloudshell.snmp.core.snmp_engine import QualiSnmpEngine
from cloudshell.snmp.core.snmp_mib_builder import QualiMibBuilder
from cloudshell.snmp.core.snmp_msg_pdu_dsp import QualiMsgAndPduDispatcher
from cloudshell.snmp.core.tools.mib_builder_helper import QualiDirMibSource


class TestQualiMibBuilder(unittest.TestCase):
    def test_load_mib_symbols(self):
        mib_builder = QualiMibBuilder()
        mib_builder.load_mib_symbols("mib_name", "sym_name")
        self.assertEqual(mib_builder.mibSymbols, {})
        self.assertEqual(mib_builder.json_mib_parser.json_mibs, {})

    def test_get_mib_symbol(self):
        mib_builder = QualiMibBuilder()
        mib_builder.get_mib_symbol("mib_name", "sym_name")
        self.assertEqual(mib_builder.mibSymbols, {})
        self.assertEqual(mib_builder.json_mib_parser.json_mibs, {})

    def test_load_mib_types(self):
        snmp_engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=Mock()
        )
        mib_name = "ASN1"
        mib_type = "ObjectIdentifier"
        mib_builder = snmp_engine.mib_builder
        result = mib_builder.load_mib_types(mib_name, mib_type)
        self.assertEqual(mib_builder.mibSymbols.get("ASN1", {}).get(mib_type), result)

    def test_importSymbols(self):
        snmp_engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=Mock()
        )
        mib_name = "SNMPv2-MIB"
        mib_record = "sysDescr"
        oid = (1, 3, 6, 1, 2, 1, 1, 1)
        mib_builder = snmp_engine.mib_builder
        result = mib_builder.importSymbols(mib_name, mib_record)
        self.assertEqual(result[0].name, oid)
        self.assertEqual(result[0].label, mib_record)

    def test_load_module(self):
        snmp_engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=Mock()
        )
        mib_name = "IF-MIB"
        mib_record = "ifTable"
        mib_builder = snmp_engine.mib_builder
        path_to_mibs = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "..",
            "..",
            "..",
            "cloudshell",
            "snmp",
            "mibs",
        )
        path_to_add = QualiDirMibSource(path_to_mibs)
        mib_sources = (path_to_add,) + mib_builder.getMibSources()
        mib_builder.setMibSources(*mib_sources)
        path_to_add.preload(mib_builder)
        mib_builder.loadModule(mib_name)
        mib_builder.importSymbols(mib_name, mib_record)
        self.assertTrue(mib_builder.mibSymbols.get(mib_name))
        self.assertTrue(mib_builder.mibSymbols.get(mib_name).get(mib_record))
