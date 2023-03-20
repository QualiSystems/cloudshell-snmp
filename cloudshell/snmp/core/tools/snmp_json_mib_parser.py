import json

from pysnmp.smi.error import MibLoadError, MibNotFoundError

from cloudshell.snmp.core.tools.snmp_json_mib import JsonMib


class JsonMibParser:
    def __init__(self, mib_builder):
        self._mib_builder = mib_builder
        self.json_mibs = {}

    def load_json_mib(self, mib_name):
        for mib_source in self._mib_builder.getMibSources():
            try:
                json_data, path = mib_source.read_json(mib_name)
            except (OSError, AttributeError):
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

    def guess_mib_by_oid(self, oid):
        for mib in self.json_mibs.values():
            if oid in mib.mib_symbols or oid.lower() in mib.mib_types:
                return mib.mib_name
        for mib_name, mib_symbols in self._mib_builder.mibSymbols.items():
            if any(x for x in mib_symbols if x and x.lower() == oid.lower()):
                return mib_name
        return None
