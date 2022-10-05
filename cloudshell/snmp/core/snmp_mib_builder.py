import json
from collections import defaultdict

from pysnmp.smi import builder
from pysnmp.smi.error import MibLoadError, MibNotFoundError


class JsonMibRecord:
    def __init__(self, mib_name, mib_data):
        self.mib_name = mib_name
        self._mib_data = mib_data
        self.mib_record = mib_data.get("name")
        self.mib_type = mib_data.get("class")
        self.oid = mib_data.get("oid")

    @property
    def oid_tuple(self):
        return tuple(int(x) for x in self.oid.split("."))


class JsonMib:
    def __init__(self, mib_builder, mib_name, mib_json, mib_parser):
        self.mib_name = mib_name
        self.mib_json = mib_json
        self._mib_builder = mib_builder
        self._snmp_object_types = mib_json.pop("imports")
        self._mib_parser = mib_parser
        self._snmp_object_type_map = None
        self._snmp_object_map = defaultdict(JsonMibRecord)

    @property
    def snmp_object_type_map(self):
        if not self._snmp_object_type_map:
            self._snmp_object_type_map = self._update_object_map()
        return self._snmp_object_type_map

    @property
    def mib_symbols(self):
        if not self._snmp_object_map:
            self.build_map(self.mib_name, self.mib_json)
        return self._snmp_object_map

    def _update_object_map(self):
        snmp_object_type_map = {}
        for key, values in self._snmp_object_types.items():
            if "class" == key and values == "imports":
                continue
            for value in values:
                snmp_object_type_map[value.lower().replace("-", "")] = {
                    key: value.title().replace("-", "")
                }
            if not self._mib_builder.mibSymbols.get(key):
                self._mib_parser.load_json_mib(key)
                snmp_object_type_map.update(
                    self._mib_parser.json_mibs[key].snmp_object_type_map
                )
        return snmp_object_type_map

    def build_map(self, mib_name, mib_json):
        for key, values in mib_json.items():
            data = JsonMibRecord(mib_name, values)
            self._snmp_object_map[values.get("oid")] = data
            self._snmp_object_map[f"{key}"] = data

    def _get_snmp_object(self, obj_type):
        mib = self.snmp_object_type_map.get(obj_type.lower())
        return self._load_import(*list(mib.items())[0])

    def _load_import(self, mib, symbol):
        snmp_mib = self._mib_builder.mibSymbols.get(mib)
        if not snmp_mib:
            snmp_mib = self._mib_builder.mibSymbols.get(mib)
        return snmp_mib.get(symbol)

    def load_mib_symbol(self, request_oid):
        snmp_data = self.mib_symbols.get(request_oid)
        if snmp_data:
            snmp_name = snmp_data.mib_record
            mib_name = snmp_data.mib_name
            obj_type = snmp_data.mib_type
            obj = self._get_snmp_object(obj_type)
            oid = snmp_data.oid_tuple
            initialized_obj = obj(oid)
            data = {snmp_name: initialized_obj}
            if not self._mib_builder.mibSymbols.get(mib_name, {}).get(snmp_name):
                self._mib_builder.exportSymbols(mib_name, **data)


class JsonMibParser:
    def __init__(self, mib_builder):
        self._mib_builder = mib_builder
        self.json_mibs = {}

    def load_json_mib(self, mib_name):
        for mib_source in self._mib_builder.getMibSources():
            try:
                json_data, path = mib_source.read_json(mib_name)
            except (IOError, AttributeError):
                continue
            if json_data:
                try:
                    data = json.loads(json_data)
                except json.decoder.JSONDecodeError:
                    raise MibLoadError(mib_name)
                mib = JsonMib(self._mib_builder, mib_name, data, self)
                self.json_mibs[mib_name] = mib
                return
        raise MibNotFoundError(mib_name)


class QualiMibBuilder(builder.MibBuilder):
    def __init__(self):
        super().__init__()
        self.json_mib_parser = JsonMibParser(self)

    def importSymbols(self, modName, *symNames, **userCtx):
        json_mib = self.json_mib_parser.json_mibs.get(modName)
        if json_mib:
            for symName in symNames:
                if symName in json_mib.mib_symbols:
                    json_mib.load_mib_symbol(symName)

        return super().importSymbols(modName, *symNames, **userCtx)

    def loadModule(self, modName, **userCtx):
        try:
            return super().loadModule(modName, **userCtx)
        except MibNotFoundError:
            self.json_mib_parser.load_json_mib(modName)
