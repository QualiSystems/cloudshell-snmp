from pysnmp.hlapi.varbinds import CommandGeneratorVarBinds
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType


class SnmpResponse(ObjectType):
    def __init__(self, oid, value, snmp_engine, logger):
        self._raw_oid = oid
        self._snmp_mib_translator = CommandGeneratorVarBinds.getMibViewController(snmp_engine)
        self._logger = logger
        self._mib_id = None
        self._mib_name = None
        self._index = None
        self._raw_value = value
        super(SnmpResponse, self).__init__(ObjectIdentity(self._raw_oid), self._raw_value)

    @property
    def raw_value(self):
        return self._raw_value

    @property
    def oid(self):
        if not self.isFullyResolved():
            self.resolveWithMib(self._snmp_mib_translator)
        return self[0].getOid()

    @property
    def mib_name(self):
        if not self._mib_name:
            self._get_oid()
        return self._mib_name

    @property
    def mib_id(self):
        if not self._mib_id:
            self._get_oid()
        return self._mib_id

    @property
    def index(self):
        if not self._index:
            self._get_oid()
        return self._index

    @property
    def value(self):
        if not self.isFullyResolved():
            self.resolveWithMib(self._snmp_mib_translator)
        value = str(self[1].prettyPrint())
        if value.lower().startswith("0x"):
            value = str(self._raw_value)
        return value

    def _get_oid(self):
        if not self.isFullyResolved():
            self.resolveWithMib(self._snmp_mib_translator)
        oid = self[0].getMibSymbol()
        self._mib_name = oid[0]
        self._mib_id = oid[1]
        if isinstance(oid[-1], tuple):
            self._index = ".".join(map(lambda x: x.prettyPrint(), oid[-1]))

    def __str__(self):
        return self.value
