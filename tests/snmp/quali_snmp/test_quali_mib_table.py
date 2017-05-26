from unittest import TestCase
from cloudshell.snmp.quali_snmp import QualiMibTable


class TestQualiMibTableInit(TestCase):
    def setUp(self):
        self.table = QualiMibTable("entPhysicalTable")
        self.table[0] = {}
        self.table[1] = {}
        self.table[2] = {}
        self.table[3] = {}
        self.table[0]["entPhysicalClass"] = "port"
        self.table[1]["entPhysicalClass"] = "port"
        self.table[2]["entPhysicalClass"] = "port"
        self.table[3]["entPhysicalClass"] = "port"
        self.table[0]["entPhysicalParentRelPos"] = 1
        self.table[1]["entPhysicalParentRelPos"] = 2
        self.table[2]["entPhysicalParentRelPos"] = 3
        self.table[3]["entPhysicalParentRelPos"] = 4

    def test_filter_by_column(self):
        self.assertIsNotNone(self.table.filter_by_column("Class", "port"))
        self.assertIsInstance(self.table.filter_by_column("Class", "port"), QualiMibTable)

    def test_sort_by_column(self):
        self.assertIsNotNone(self.table.sort_by_column("ParentRelPos"))
        self.assertIsInstance(self.table.sort_by_column("ParentRelPos"), QualiMibTable)

    def test_get_rows(self):
        self.assertIsNotNone(self.table.get_rows(1))
        self.assertIsInstance(self.table.get_rows(1), QualiMibTable)

    def test_get_columns(self):
        self.assertIsNotNone(self.table.get_columns("Class"))
        self.assertIsInstance(self.table.get_columns("Class"), QualiMibTable)