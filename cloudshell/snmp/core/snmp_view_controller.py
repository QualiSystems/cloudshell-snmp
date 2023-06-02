from collections import OrderedDict
from copy import copy
from threading import Lock

from pysnmp.smi.error import NoSuchObjectError, SmiError

classTypes = (type,)
instanceTypes = (object,)


class QualiViewController:
    def __init__(self, mib_builder, logger):
        self.mib_builder = mib_builder
        self.mibBuilder = mib_builder
        self.last_build_id = -1
        self._mibSymbolsIdx = OrderedDict()
        self._logger = logger
        self._lock = Lock()

    def index_mib(self):
        if self.last_build_id == self.mib_builder.lastBuildId:
            return

        (MibScalarInstance,) = self.mib_builder.importSymbols(
            "SNMPv2-SMI", "MibScalarInstance"
        )

        with self._lock:
            if self.last_build_id == self.mib_builder.lastBuildId:
                return
            self._mibSymbolsIdx.clear()

            def _sort_fun(x, b=self.mib_builder):
                if b.moduleID in b.mibSymbols[x]:
                    m = b.mibSymbols[x][b.moduleID]
                    r = m.getRevisions()
                    if r:
                        return r[0]

                return "1970-01-01 00:00"

            mod_names = list(self.mib_builder.mibSymbols.keys())
            mod_names.sort(key=_sort_fun)

            for modName in [""] + mod_names:
                self._mibSymbolsIdx[modName] = mibMod = {
                    "oidToLabelIdx": {},
                    "labelToOidIdx": {},
                    "varToNameIdx": {},
                    "typeToModIdx": {},
                    "oidToModIdx": {},
                }

                if not modName:
                    glob_mib_mod = mibMod
                    continue

                for n, v in copy(self.mib_builder.mibSymbols[modName]).items():
                    if n == self.mib_builder.moduleID:
                        continue
                    if isinstance(v, classTypes):
                        if n in mibMod["typeToModIdx"]:
                            raise SmiError(
                                "Duplicate SMI type %s::%s, has %s"
                                % (modName, n, mibMod["typeToModIdx"][n])
                            )
                        glob_mib_mod["typeToModIdx"][n] = modName
                        mibMod["typeToModIdx"][n] = modName
                    elif isinstance(v, instanceTypes):
                        if isinstance(v, MibScalarInstance):
                            continue
                        if n in mibMod["varToNameIdx"]:
                            raise SmiError(
                                "Duplicate MIB variable %s::%s has %s"
                                % (modName, n, mibMod["varToNameIdx"][n])
                            )
                        glob_mib_mod["varToNameIdx"][n] = v.name
                        mibMod["varToNameIdx"][n] = v.name
                        glob_mib_mod["oidToModIdx"][v.name] = modName
                        mibMod["oidToModIdx"][v.name] = modName
                        glob_mib_mod["oidToLabelIdx"][v.name] = (n,)
                        mibMod["oidToLabelIdx"][v.name] = (n,)
                    else:
                        raise SmiError(f"Unexpected object {modName}::{n}")

            oidToLabelIdx = self._mibSymbolsIdx[""]["oidToLabelIdx"]
            labelToOidIdx = self._mibSymbolsIdx[""]["labelToOidIdx"]
            prevOid = ()
            baseLabel = ()
            for key in oidToLabelIdx.keys():
                keydiff = len(key) - len(prevOid)
                if keydiff > 0:
                    if prevOid:
                        if keydiff == 1:
                            baseLabel = oidToLabelIdx[prevOid]
                        else:
                            baseLabel += key[-keydiff:-1]
                    else:
                        baseLabel = ()
                elif keydiff < 0:
                    baseLabel = ()
                    keyLen = len(key)
                    i = keyLen - 1
                    while i:
                        k = key[:i]
                        if k in oidToLabelIdx:
                            baseLabel = oidToLabelIdx[k]
                            if i != keyLen - 1:
                                baseLabel += key[i:-1]
                            break
                        i -= 1
                oidToLabelIdx[key] = baseLabel + oidToLabelIdx[key]
                labelToOidIdx[oidToLabelIdx[key]] = key
                prevOid = key

            for mibMod in self._mibSymbolsIdx.values():
                for oid in mibMod["oidToLabelIdx"].keys():
                    data = oidToLabelIdx.get(oid)
                    if not data:
                        mib_name = self.mib_builder.json_mib_parser.guess_mib_name(oid)
                        if not mib_name:
                            raise Exception(f"Could not find MIB for OID: {oid}")
                        json_mib = self.mib_builder.json_mib_parser.json_mibs.get(
                            mib_name
                        )
                        json_mib.load_mib_symbol(oid)
                        json_mib.load_mib_type(oid)
                        sym = json_mib.mib_symbols.get(oid) or json_mib.mib_types.get(
                            oid
                        )
                        data = sym.mib_record

                    mibMod["oidToLabelIdx"][oid] = data
                    mibMod["labelToOidIdx"][oidToLabelIdx[oid]] = oid

            self.last_build_id = self.mib_builder.lastBuildId

    def getOrderedModuleName(self, index):
        self.index_mib()
        modNames = self._mibSymbolsIdx.keys()
        if modNames:
            return modNames[index]
        raise SmiError("No modules loaded at %s" % self)

    def getFirstModuleName(self):
        return self.getOrderedModuleName(0)

    def getLastModuleName(self):
        return self.getOrderedModuleName(-1)

    def getNextModuleName(self, modName):
        self.index_mib()
        try:
            return self._mibSymbolsIdx.nextKey(modName)
        except KeyError:
            raise SmiError(f"No module next to {modName} at {self}")

    def _getOidLabel(self, nodeName, oidToLabelIdx, labelToOidIdx):
        """getOidLabel(nodeName) -> (oid, label, suffix)."""
        if not nodeName:
            return nodeName, nodeName, ()
        if nodeName in labelToOidIdx:
            return labelToOidIdx[nodeName], nodeName, ()
        if nodeName in oidToLabelIdx:
            return nodeName, oidToLabelIdx[nodeName], ()
        if len(nodeName) < 2:
            return nodeName, nodeName, ()
        oid, label, suffix = self._getOidLabel(
            nodeName[:-1], oidToLabelIdx, labelToOidIdx
        )
        suffix = suffix + nodeName[-1:]
        resLabel = label + tuple([str(x) for x in suffix])
        if resLabel in labelToOidIdx:
            return labelToOidIdx[resLabel], resLabel, ()
        resOid = oid + suffix
        if resOid in oidToLabelIdx:
            return resOid, oidToLabelIdx[resOid], ()
        return oid, label, suffix

    def getNodeNameByOid(self, nodeName, modName=""):
        self.index_mib()
        if modName in self._mibSymbolsIdx:
            mibMod = self._mibSymbolsIdx[modName]
        else:
            raise SmiError(f"No module {modName} at {self}")
        oid, label, suffix = self._getOidLabel(
            nodeName, mibMod["oidToLabelIdx"], mibMod["labelToOidIdx"]
        )
        if oid == label:
            raise NoSuchObjectError(
                str="Can't resolve node name {}::{} at {}".format(
                    modName, nodeName, self
                )
            )
        return oid, label, suffix

    def getNodeNameByDesc(self, nodeName, modName=""):
        self.index_mib()
        if modName in self._mibSymbolsIdx:
            mibMod = self._mibSymbolsIdx[modName]
        else:
            raise SmiError(f"No module {modName} at {self}")
        if nodeName in mibMod["varToNameIdx"]:
            oid = mibMod["varToNameIdx"][nodeName]
        else:
            raise NoSuchObjectError(
                str=f"No such symbol {modName}::{nodeName} at {self}"
            )
        return self.getNodeNameByOid(oid, modName)

    def getNodeName(self, nodeName, modName=""):
        try:
            return self.getNodeNameByOid(nodeName, modName)
        except NoSuchObjectError:
            oid, label, suffix = self.getNodeNameByDesc(nodeName[0], modName)
            return self.getNodeNameByOid(oid + suffix + nodeName[1:], modName)

    def getOrderedNodeName(self, index, modName=""):
        self.index_mib()
        if modName in self._mibSymbolsIdx:
            mibMod = self._mibSymbolsIdx[modName]
        else:
            raise SmiError(f"No module {modName} at {self}")
        if not mibMod["oidToLabelIdx"]:
            raise NoSuchObjectError(
                str=f"No variables at MIB module {modName} at {self}"
            )
        try:
            oid, label = mibMod["oidToLabelIdx"].items()[index]
        except KeyError:
            raise NoSuchObjectError(
                str="No symbol at position %s in MIB module %s at %s"
                % (index, modName, self)
            )
        return oid, label, ()

    def getFirstNodeName(self, modName=""):
        return self.getOrderedNodeName(0, modName)

    def getLastNodeName(self, modName=""):
        return self.getOrderedNodeName(-1, modName)

    def getNextNodeName(self, nodeName, modName=""):
        oid, label, suffix = self.getNodeName(nodeName, modName)
        try:
            return self.getNodeName(
                self._mibSymbolsIdx[modName]["oidToLabelIdx"].nextKey(oid) + suffix,
                modName,
            )
        except KeyError:
            raise NoSuchObjectError(
                str=f"No name next to {modName}::{nodeName} at {self}"
            )

    def getParentNodeName(self, nodeName, modName=""):
        oid, label, suffix = self.getNodeName(nodeName, modName)
        if len(oid) < 2:
            raise NoSuchObjectError(
                str=f"No parent name for {modName}::{nodeName} at {self}"
            )
        return oid[:-1], label[:-1], oid[-1:] + suffix

    def getNodeLocation(self, nodeName, modName=""):
        oid, label, suffix = self.getNodeName(nodeName, modName)
        return self._mibSymbolsIdx[""]["oidToModIdx"][oid], label[-1], suffix

    # MIB type management

    def getTypeName(self, typeName, modName=""):
        self.index_mib()
        if modName in self._mibSymbolsIdx:
            mibMod = self._mibSymbolsIdx[modName]
        else:
            raise SmiError(f"No module {modName} at {self}")
        if typeName in mibMod["typeToModIdx"]:
            m = mibMod["typeToModIdx"][typeName]
        else:
            raise NoSuchObjectError(str=f"No such type {modName}::{typeName} at {self}")
        return m, typeName

    def getOrderedTypeName(self, index, modName=""):
        self.index_mib()
        if modName in self._mibSymbolsIdx:
            mibMod = self._mibSymbolsIdx[modName]
        else:
            raise SmiError(f"No module {modName} at {self}")
        if not mibMod["typeToModIdx"]:
            raise NoSuchObjectError(str=f"No types at MIB module {modName} at {self}")
        t = mibMod["typeToModIdx"].keys()[index]
        return mibMod["typeToModIdx"][t], t

    def getFirstTypeName(self, modName=""):
        return self.getOrderedTypeName(0, modName)

    def getLastTypeName(self, modName=""):
        return self.getOrderedTypeName(-1, modName)

    def getNextType(self, typeName, modName=""):
        m, t = self.getTypeName(typeName, modName)
        try:
            return self._mibSymbolsIdx[m]["typeToModIdx"].nextKey(t)
        except KeyError:
            raise NoSuchObjectError(
                str=f"No type next to {modName}::{typeName} at {self}"
            )
