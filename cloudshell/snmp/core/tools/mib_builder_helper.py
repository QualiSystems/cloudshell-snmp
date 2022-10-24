import os
from collections import defaultdict

from pyasn1.type.univ import ObjectIdentifier
from pysnmp.smi.builder import DirMibSource
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType


class QualiDirMibSource(DirMibSource):
    def read_json(self, mib_name):
        return self._getData(f"{mib_name}.json", "r")

    def preload(self, mib_builder):
        for file in os.listdir(self._srcName):
            if file.endswith(".json"):
                mib_builder.json_mib_parser.load_json_mib(file.replace(".json", ""))


class MibBuilderHelper:
    def __init__(self, mib_builder):
        self._mib_builder = mib_builder
        self._snmp_object_type_map = defaultdict(dict)
        self._snmp_object_map = {}
        self._loaded_symbols = []

    def get_obj_identity(self, oid):
        self.get_object(oid)
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
        if target_oid in self._loaded_symbols:
            return
        mib = self._mib_builder.json_mib_parser.guess_mib_by_oid(target_oid)
        while not mib:
            target_oid = target_oid[: target_oid.rfind(".")]
            if target_oid in self._loaded_symbols:
                return
            mib = self._mib_builder.json_mib_parser.guess_mib_by_oid(target_oid)
            self._loaded_symbols.append(target_oid)

        mib_object = self._mib_builder.json_mib_parser.json_mibs.get(mib)
        mib_object.load_mib_symbol(target_oid)
        mib_object.load_mib_type(target_oid)
        self._loaded_symbols.append(target_oid)
