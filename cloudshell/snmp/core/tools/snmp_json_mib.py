from collections import defaultdict
from contextlib import suppress
from functools import lru_cache
from threading import Thread

from pyasn1.type.constraint import (
    ConstraintsUnion,
    SingleValueConstraint,
    ValueRangeConstraint,
    ValueSizeConstraint,
)
from pyasn1.type.namedval import NamedValues

from cloudshell.snmp.core.domain.snmp_json_record import JsonMibRecord, JsonMibType
from cloudshell.snmp.core.snmp_errors import TranslateSNMPException


class JsonMib:
    TEXTUAL_CONVENTION = "textualconvention"
    TEXT_MIB_TYPE_MAP = {
        "integer": "Integer32",
        "object identifier": "ObjectIdentifier",
        "octet string": "OctetString",
    }

    OBJECT_TYPE_NODE_MAP = {
        "scalar": "MibScalar",
        "row": "MibTableRow",
        "table": "MibTable",
        "column": "MibTableColumn",
    }

    def __init__(self, mib_builder, mib_name, mib_json, mib_parser):
        self.mib_name = mib_name
        self.mib_json = mib_json
        self._mib_builder = mib_builder
        self._snmp_object_types = {}
        if mib_json:
            self._snmp_object_types = mib_json.pop("imports")
        self._mib_parser = mib_parser
        self._snmp_object_type_map = None
        self._snmp_object_map = defaultdict(JsonMibRecord)
        self._snmp_table_map = defaultdict(list)
        self._snmp_type_map = defaultdict(JsonMibType)
        self._thread = Thread(
            name=mib_name, target=self._build_map, args=(mib_name, mib_json)
        )
        self._thread.start()

    @property
    def snmp_object_type_map(self):
        if not self._snmp_object_type_map:
            self._snmp_object_type_map = self._update_object_map()
        return self._snmp_object_type_map

    @property
    def mib_types(self):
        self._thread.join()
        return self._snmp_type_map

    @property
    def mib_symbols(self):
        self._thread.join()
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
                json_mib = self._mib_parser.json_mibs.get(key)
                if not json_mib:
                    self._mib_parser.load_json_mib(key)
                    json_mib = self._mib_parser.json_mibs.get(key)
                snmp_object_type_map.update(json_mib.snmp_object_type_map)
        return snmp_object_type_map

    def json_mib_destroy(self):
        with suppress(Exception):
            self._thread.join(0)

    def _build_map(self, mib_name, mib_json):
        for key, values in mib_json.items():
            data = JsonMibRecord(mib_name, values)
            if data.mib_type == self.TEXTUAL_CONVENTION:
                self._snmp_type_map[data.mib_record.lower()] = JsonMibType(
                    mib_name, values
                )
                continue
            elif data.mib_node_type == "table":
                self._snmp_table_map[f"{key}".lower()] = []
                self._snmp_table_map[data.oid] = []
            if key:
                self._snmp_object_map[f"{key}".lower()] = data
            if data.oid:
                self._snmp_object_map[data.oid] = data

        for table in self._snmp_table_map:
            item = self._snmp_object_map.get(table)
            if item and item.oid:
                result = [
                    oid
                    for oid in self._snmp_object_map
                    if oid.startswith(f"{item.oid}.")
                ]
                self._snmp_table_map[table] = result
                self._snmp_table_map[item.oid] = result

    def _get_snmp_object(self, obj_type, snmp_data_record=None):
        if obj_type.lower() in self.TEXT_MIB_TYPE_MAP:
            obj_type = self.TEXT_MIB_TYPE_MAP.get(obj_type.lower(), "").lower()
        data = list(self.snmp_object_type_map.get(obj_type.lower(), {}).items())
        mib = self._mib_parser.guess_mib_by_oid(obj_type)
        if not data:
            self._mib_builder.load_mib_types(mib, obj_type)
            data = list(self.snmp_object_type_map.get(obj_type.lower(), {}).items())
        if not data and mib:
            result = self._mib_builder.get_mib_symbol(mib, obj_type)
            if result:
                return result

        mib, sym_name = data[0]
        if snmp_data_record and "objecttype" == sym_name.lower():
            sym_name = self.OBJECT_TYPE_NODE_MAP.get(snmp_data_record.mib_node_type)
        return self._load_import(mib, sym_name)

    def _load_import(self, mib, symbol):
        snmp_mib = self._mib_builder.mibSymbols.get(mib)
        if not snmp_mib:
            if mib == self.mib_name:
                self.load_mib_type(symbol)
            else:
                self._mib_builder.load_mib_types(mib, symbol)
            snmp_mib = self._mib_builder.mibSymbols.get(mib)
        result = next(
            (obj for name, obj in snmp_mib.items() if symbol.lower() == name.lower()),
            None,
        )
        if not result:
            self._mib_builder.load_mib_types(mib, symbol)
            result = next(
                (
                    obj
                    for name, obj in snmp_mib.items()
                    if symbol.lower() == name.lower()
                ),
                None,
            )
        return result

    def load_mib_type(self, request):
        snmp_name = request.lower()
        snmp_data = self.mib_types.get(snmp_name)
        if not snmp_data:
            return
        mib_name = snmp_data.mib_name
        obj = self._create_snmp_object(snmp_data)
        self._snmp_object_type_map[snmp_name] = {mib_name: snmp_name}
        self._snmp_object_type_map[snmp_name] = {mib_name: request}
        mib = self._mib_builder.mibSymbols.get(mib_name)
        if not mib:
            self._mib_builder.mibSymbols[mib_name] = {request: obj}
        else:
            mib[request] = obj

    @lru_cache()
    def _get_snmp_data(self, snmp_name):
        return self.mib_symbols.get(snmp_name.lower())

    def load_mib_symbol(self, request_oid):
        snmp_data = self._get_snmp_data(request_oid)
        if not snmp_data:
            return
        mib = self._mib_builder.mibSymbols.get(self.mib_name, {})
        if mib.get(snmp_data.mib_record):
            return
        snmp_name = snmp_data.mib_record
        mib_name = snmp_data.mib_name
        obj_type = snmp_data.mib_type
        obj = self._get_snmp_object(obj_type, snmp_data)
        oid = snmp_data.oid_tuple
        if snmp_data.mib_node_syntax_type:
            syntax = self._prepare_node_syntax(snmp_data)

            initialized_obj = obj(oid, syntax)
            if snmp_data.mib_node_units:
                initialized_obj.setUnits(snmp_data.mib_node_units)
        else:
            initialized_obj = obj(oid)
        data = {snmp_name: initialized_obj}
        self._update_index_names(initialized_obj, snmp_data)
        if snmp_data.mib_node_augmentation:
            self._set_augmentation(snmp_data.mib_node_augmentation, initialized_obj)
        self._mib_builder.exportSymbols(mib_name, **data)
        parent_oid = snmp_data.oid[: snmp_data.oid.rfind(".")]
        parent_mib = self._mib_parser.guess_mib_by_oid(parent_oid)
        if parent_mib:
            if parent_mib == self.mib_name:
                self.load_mib_symbol(parent_oid)
            else:
                parent_mib_obj = self._mib_parser.json_mibs.get(parent_mib)
                if parent_mib_obj:
                    parent_oid_obj = parent_mib_obj.mib_symbols.get(parent_oid)
                    if parent_oid_obj:
                        parent_oid = parent_oid_obj.mib_record
                        self._mib_builder.importSymbols(parent_mib, parent_oid, **{})
        if snmp_data.mib_node_type == "table":
            self._load_child_nodes(snmp_data.mib_record)

    def _prepare_node_syntax(self, snmp_data):
        if snmp_data.mib_node_syntax_type:
            syntax_type = self._get_snmp_object(snmp_data.mib_node_syntax_type)
            syntax = syntax_type()
            if snmp_data.mib_node_syntax_constraint:
                syntax.subtype(
                    subtypeSpec=self._get_constraints(
                        snmp_data.mib_node_syntax_constraint
                    )
                )
                enum = snmp_data.mib_node_syntax_constraint.get(
                    "enumeration", {}
                ) or snmp_data.mib_node_syntax_constraint.get("bits", {})
                if enum:
                    syntax = syntax.clone(namedValues=NamedValues(**enum))
            if snmp_data.mib_node_default:
                def_data = snmp_data.mib_node_default.get("default", {})
                data_type = def_data.get("format")
                data = def_data.get("value")
                if data_type == "decimal":
                    data = int(def_data.get("value"))
                elif data_type == "enum":
                    data = def_data.get("value")
                elif data_type == "oid":
                    data = tuple(int(x) for x in def_data.get("value")[1:-1].split(","))
                if data:
                    syntax = syntax.clone(data)
                else:
                    syntax = syntax.clone()
            return syntax

    def _set_augmentation(self, node_augmentation, initialized_obj):
        augm_object = node_augmentation.get("object")
        augm_mib = node_augmentation.get("module")
        augm_target = node_augmentation.get("name")
        augm_obj = self._mib_builder.importSymbols(augm_mib, augm_object)
        if not augm_obj:
            raise TranslateSNMPException("Augmentation object not found")
        augm_obj[0].registerAugmentions((augm_mib, augm_target))
        initialized_obj.setIndexNames(*augm_obj[0].getIndexNames())
        return augm_obj

    def _get_constraints(self, constraints_dict):
        constraints_data = None
        constraints = constraints_dict.get("range", [])
        for constraint in constraints:
            return ValueRangeConstraint(
                int(constraint.get("min")), int(constraint.get("max"))
            )
        size = constraints_dict.get("size", [])
        for constraint in size:
            return ValueSizeConstraint(
                int(constraint.get("min")), int(constraint.get("max"))
            )
        enum = constraints_dict.get("enumeration", {}) or constraints_dict.get(
            "bits", {}
        )
        if enum:
            return SingleValueConstraint(*list(enum.values()))
        return constraints_data

    def _create_snmp_object(self, snmp_data):
        snmp_mib_type = JsonMibType(snmp_data.mib_name, snmp_data.mib_data)
        obj_type_name = snmp_mib_type.mib_type
        obj_type_class_name = snmp_mib_type.mib_type_class
        obj_type = self._get_snmp_object(obj_type_name)
        obj_type_class = self._get_snmp_object(obj_type_class_name)
        constraints = self._get_constraints(snmp_mib_type.mib_type_constraints)
        class_attrs = {}
        if snmp_data.mib_node_status:
            class_attrs["status"] = snmp_data.mib_node_status
        if snmp_mib_type.mib_type_display_hint:
            class_attrs["displayHint"] = snmp_mib_type.mib_type_display_hint
        if constraints:
            class_attrs["subtypeSpec"] = obj_type_class.subtypeSpec + constraints
        enum = snmp_mib_type.mib_type_constraints.get(
            "enumeration", {}
        ) or snmp_mib_type.mib_type_constraints.get("bits", {})
        if enum:
            class_attrs["subtypeSpec"] = obj_type_class.subtypeSpec + ConstraintsUnion(
                constraints
            )
            class_attrs["namedValues"] = NamedValues(**enum)
        return type(snmp_data.mib_record, (obj_type, obj_type_class), class_attrs)

    def _load_child_nodes(self, oid):
        child_list = self._snmp_table_map.get(oid.lower())
        for key in child_list:
            self.load_mib_symbol(key)

    def _update_index_names(self, initialized_obj, snmp_data):
        data = []
        for index_data in snmp_data.mib_indexes:
            index = index_data.get("implied")
            mib_name = index_data.get("module")
            symbol = index_data.get("object")
            if index is not None and mib_name and symbol:
                data.append((index, mib_name, symbol))
        if data:
            initialized_obj.setIndexNames(*data)
        if snmp_data.mib_node_status and self._mib_builder.loadTexts:
            initialized_obj = initialized_obj.setStatus(
                snmp_data.mib_node_status.lower()
            )
        if snmp_data.mib_node_access:
            initialized_obj = initialized_obj.setMaxAccess(
                snmp_data.mib_node_access.replace("-", "")
            )
        return initialized_obj
