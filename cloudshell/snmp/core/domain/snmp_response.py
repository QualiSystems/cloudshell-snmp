from pysnmp.error import PySnmpError
from pysnmp.hlapi.varbinds import CommandGeneratorVarBinds
from pysnmp.smi.error import SmiError
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType

from cloudshell.snmp.core.snmp_errors import TranslateSNMPException


class SnmpResponse(object):
    def __init__(self, oid, value, snmp_engine, logger):
        self._raw_oid = oid
        self._snmp_mib_translator = CommandGeneratorVarBinds.getMibViewController(
            snmp_engine
        )
        self._logger = logger
        self._mib_id = None
        self._mib_name = None
        self._index = None
        self._raw_value = value
        self._object_id = ObjectIdentity(self._raw_oid)
        self._object_type = ObjectType(self._object_id, self._raw_value)

    @property
    def _object_identity(self):
        if not self._object_id.isFullyResolved():
            self._object_id.resolveWithMib(self._snmp_mib_translator)
        return self._object_id

    @property
    def object_type(self):
        if not self._object_type.isFullyResolved():
            self._object_type.resolveWithMib(self._snmp_mib_translator)
        return self._object_type

    @property
    def raw_value(self):
        return self._raw_value

    @property
    def oid(self):
        return self._object_identity.getOid()

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
    def safe_value(self):
        result = ""
        try:
            result = self.value or ""
        except TranslateSNMPException:
            pass

        return result

    @property
    def value(self):
        try:
            if self._raw_value is None or not self.object_type:
                return
            if hasattr(self.object_type[1], "prettyPrint"):
                value = self.object_type[1].prettyPrint()
            else:
                value = str(self.object_type[1])
            if value.lower().startswith("0x"):
                value = str(self._raw_value)
            return value
        except (PySnmpError, SmiError):
            raise TranslateSNMPException("Error parsing snmp response")

    def _get_oid(self):
        oid = self._object_identity.getMibSymbol()
        self._mib_name = oid[0]
        self._mib_id = oid[1]
        if isinstance(oid[-1], tuple):
            self._index = ".".join(map(lambda x: x.prettyPrint(), oid[-1]))

    def __str__(self):
        return self.safe_value

    def __repr__(self):
        return self.__str__()
