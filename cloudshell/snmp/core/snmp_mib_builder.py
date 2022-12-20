from pysnmp.smi import builder
from pysnmp.smi.error import MibNotFoundError

from cloudshell.snmp.core.tools.snmp_json_mib_parser import JsonMibParser


class QualiMibBuilder(builder.MibBuilder):
    def __init__(self):
        super().__init__()
        self.json_mib_parser = JsonMibParser(self)

    def load_mib_symbols(self, mib_name, *sym_names):
        json_mib = self.json_mib_parser.json_mibs.get(mib_name)
        if json_mib:
            for sym_name in sym_names:
                if not self.mibSymbols.get(mib_name, {}).get(sym_name):
                    json_mib.load_mib_symbol(sym_name)
                    json_mib.load_mib_type(sym_name)

    def get_mib_symbol(self, mib_name, sym_name):
        mib = self.mibSymbols.get(mib_name, {})
        if mib:
            symbol = next(
                (
                    symbol
                    for name, symbol in mib.items()
                    if name.lower() == sym_name.lower()
                ),
                None,
            )
            if symbol:
                return symbol

    def load_mib_types(self, mib_name, sym_name, **user_ctx):
        mib = self.mibSymbols.get(mib_name, {})
        if mib:
            symbol = next(
                (
                    symbol
                    for name, symbol in mib.items()
                    if name.lower() == sym_name.lower()
                ),
                None,
            )
            if symbol:
                return symbol
        json_mib = self.json_mib_parser.json_mibs.get(mib_name)
        if not mib and not json_mib:
            self.loadModule(mib_name, **user_ctx)
            mib = self.mibSymbols.get(mib_name, {})
            json_mib = self.json_mib_parser.json_mibs.get(mib_name)
        if json_mib:
            if sym_name not in mib and any(
                x for x in json_mib.mib_types if x and x.lower() == sym_name.lower()
            ):
                json_mib.load_mib_type(sym_name)

    def importSymbols(self, modName, *symNames, **userCtx):
        if modName in self.json_mib_parser.json_mibs:
            self.load_mib_symbols(modName, *symNames)

        return super().importSymbols(modName, *symNames, **userCtx)

    def loadModule(self, modName, **userCtx):
        if modName in self.json_mib_parser.json_mibs:
            return
        try:
            return super().loadModule(modName, **userCtx)
        except MibNotFoundError:
            self.json_mib_parser.load_json_mib(modName)
