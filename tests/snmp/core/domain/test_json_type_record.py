import unittest

from cloudshell.snmp.core.domain.snmp_json_record import JsonMibType


class TestJsonMibTypeRecord(unittest.TestCase):
    def test_json_mib_type_record(self):
        mib_type_record = JsonMibType(
            mib_name="mib_name",
            mib_data={
                "name": "PhysicalIndex",
                "class": "textualconvention",
                "type": {
                    "type": "Integer32",
                    "class": "type",
                    "constraints": {"range": [{"min": 1, "max": 2147483647}]},
                },
                "displayhint": "d",
                "status": "current",
            },
        )
        self.assertEqual(mib_type_record.mib_name, "mib_name")
        self.assertEqual(mib_type_record.mib_record, "PhysicalIndex")
        self.assertEqual(mib_type_record.mib_type, "textualconvention")
        self.assertEqual(mib_type_record.mib_type_display_hint, "d")
        self.assertEqual(mib_type_record.mib_type_class, "Integer32")
        self.assertEqual(
            mib_type_record.mib_type_constraints,
            {"range": [{"min": 1, "max": 2147483647}]},
        )
        self.assertEqual(mib_type_record.mib_node_status, "current")
