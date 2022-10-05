from collections import defaultdict

from pyasn1.type.univ import ObjectIdentifier
from pysnmp.smi.builder import DirMibSource
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType


class QualiDirMibSource(DirMibSource):
    def read_json(self, mib_name):
        return self._getData(f"{mib_name}.json", "r")


class MibBuilderHelper:
    def __init__(self, mib_builder):
        self._mib_builder = mib_builder
        self._snmp_object_type_map = defaultdict(dict)
        self._snmp_object_map = {}

    def get_obj_identity(self, oid):
        object_identity = self.get_object(oid)
        if object_identity is None:
            object_identity = ObjectIdentity(oid)
        return object_identity

    def get_obj_type(self, object_identity, value):
        object_type = ObjectType(object_identity, value)
        if not object_type.isFullyResolved():
            if isinstance(value, ObjectIdentifier):
                self.get_object(str(value))
        return object_type

    def get_object(self, oid):
        target_oid = str(oid)
        return next(
            (
                value.load_mib_symbol(target_oid)
                for mib, value in self._mib_builder.json_mib_parser.json_mibs.items()
                if target_oid in value.mib_symbols
            ),
            None,
        )
