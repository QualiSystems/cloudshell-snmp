from __future__ import annotations

from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import OctetString
from pysnmp.error import PySnmpError
from pysnmp.hlapi.varbinds import CommandGeneratorVarBinds
from pysnmp.smi.error import SmiError

from cloudshell.snmp.core.snmp_errors import TranslateSNMPException


class SnmpResponse:
    def __init__(self, oid, value, snmp_engine, logger):
        self._raw_oid = oid
        self._engine = snmp_engine
        # prefer the engine's QualiViewController (pysnmp-4-identical semantics);
        # fall back to pysnmp's cache helper only for foreign engines
        self._snmp_mib_translator = getattr(
            snmp_engine, "mib_view", None
        ) or CommandGeneratorVarBinds.get_mib_view_controller(snmp_engine.cache)
        self._logger = logger
        self._mib_id = None
        self._mib_name = None
        self._index = None
        self._raw_value = value
        self._object_id = snmp_engine.build_helper.get_obj_identity(self._raw_oid)
        self._object_type = snmp_engine.build_helper.get_obj_type(
            self._object_id, self._raw_value
        )

    @property
    def _object_identity(self):
        if not self._object_id.is_fully_resolved():
            self._object_id.resolve_with_mib(self._snmp_mib_translator)
        return self._object_id

    @property
    def object_type(self):
        if not self._object_type.is_fully_resolved():
            self._object_type.resolve_with_mib(self._snmp_mib_translator)
        return self._object_type

    @property
    def raw_value(self):
        return self._raw_value

    @property
    def oid(self):
        return self._object_identity.get_oid()

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
            resolved = self.object_type[1]
            if self._violates_octet_string_constraint(resolved):
                # pysnmp 7 resolve_with_mib force-assigns the wire payload into
                # the MIB type bypassing size constraints, so a malformed
                # octet-string (e.g. a 16-byte DateAndTime) would render
                # through the DISPLAY-HINT as garbage. pysnmp 4 left such
                # values as plain OctetString - reproduce that: raw ASCII if
                # printable, otherwise the 0x... path below.
                value = OctetString(resolved.asOctets()).prettyPrint()
            elif hasattr(resolved, "prettyPrint"):
                value = resolved.prettyPrint()
            else:
                value = str(resolved)
            if value.lower().startswith("0x"):
                value = str(self._raw_value)
            return value
        except (PySnmpError, SmiError, PyAsn1Error):
            raise TranslateSNMPException("Error parsing snmp response")

    @staticmethod
    def _violates_octet_string_constraint(resolved):
        """Detect a constraint-violating OctetString TextualConvention.

        True when the payload violates the type's size constraint,
        in which case the DISPLAY-HINT would misrender it.
        """
        if not isinstance(resolved, OctetString):
            return False
        # only TextualConventions render via DISPLAY-HINT
        if not getattr(resolved, "displayHint", None):
            return False
        subtype_spec = getattr(resolved, "subtypeSpec", None)
        if not subtype_spec:
            return False
        try:
            subtype_spec(resolved.asOctets())
        except PyAsn1Error:
            return True
        except Exception:
            return False
        return False

    def _get_oid(self):
        oid = self._object_identity.get_mib_symbol()
        self._mib_name = oid[0]
        self._mib_id = oid[1]
        if isinstance(oid[-1], tuple):
            self._index = ".".join([x.prettyPrint() for x in oid[-1]])

    def __str__(self):
        return self.safe_value

    def __repr__(self):
        return self.__str__()
