import unittest

from cloudshell.snmp.core.domain.snmp_json_record import JsonMibRecord


class TestJsonMibRecord(unittest.TestCase):
    """Test the JSON MIB record class."""

    def test_json_mib_record(self):
        """Test the JSON MIB record class."""
        record = JsonMibRecord(
            "mib_name",
            {
                "name": "mib_record",
                "class": "class",
                "nodetype": "nodetype",
                "syntax": {"type": "type", "constraints": "constraints"},
                "status": "status",
                "default": "default",
                "maxaccess": "readonly",
                "augmention": "augmention",
                "units": "units",
                "oid": "1.1.1.1",
            },
        )
        self.assertEqual(record.mib_name, "mib_name")
        self.assertEqual(record.mib_record, "mib_record")
        self.assertEqual(record.mib_type, "class")
        self.assertEqual(record.mib_node_type, "nodetype")
        self.assertEqual(record.mib_node_syntax_type, "type")
        self.assertEqual(record.mib_node_syntax_constraint, "constraints")
        self.assertEqual(record.mib_node_status, "status")
        self.assertEqual(record.mib_node_default, "default")
        self.assertEqual(record.mib_node_access, "readonly")
        self.assertEqual(record.mib_node_augmentation, "augmention")
        self.assertEqual(record.mib_node_units, "units")

    def test_json_mib_record_oid_tuple(self):
        """Test the JSON MIB record class."""
        record = JsonMibRecord(
            "mib_name",
            {
                "name": "mib_record",
                "oid": "1.1.1.1.11.1",
            },
        )
        self.assertEqual(record.oid_tuple, (1, 1, 1, 1, 11, 1))
