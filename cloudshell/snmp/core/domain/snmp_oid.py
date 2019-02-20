from abc import abstractmethod

from pysnmp.hlapi.varbinds import CommandGeneratorVarBinds
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType


class BaseSnmpOid(object):
    @abstractmethod
    def get_oid(self, snmp_engine):
        pass


class SnmpRawOid(BaseSnmpOid):
    def __init__(self, oid, asn_mib_sources=None, custom_mib_sources=None):
        self._oid = oid
        self._asn_mib_sources = asn_mib_sources
        self._custom_mib_sources = custom_mib_sources
        self._object_identity = None

    def _create_object_identity(self):
        self._object_identity = ObjectIdentity(self._oid)
        if self._asn_mib_sources:
            self._object_identity.addAsn1MibSource(self._asn_mib_sources)
        if self._custom_mib_sources:
            self._object_identity.addMibSource(self._custom_mib_sources)

    def get_oid(self, snmp_engine):
        self._create_object_identity()
        self._object_identity.resolveWithMib(CommandGeneratorVarBinds().getMibViewController(snmpEngine=snmp_engine))
        return self._object_identity


class SnmpMibOid(BaseSnmpOid):
    def __init__(self, mib_name, mib_id, index=None, asn_mib_sources=None, custom_mib_sources=None):
        self._mib_name = mib_name
        self._mib_id = mib_id
        self.index = index
        self._asn_mib_sources = asn_mib_sources
        self._custom_mib_sources = custom_mib_sources
        self._object_identity = None

    def _create_object_identity(self):
        self._object_identity = ObjectIdentity(*(self._mib_name, self._mib_id))
        if self.index is not None:
            self._object_identity = ObjectIdentity(*(self._mib_name, self._mib_id, self.index))
        if self._asn_mib_sources:
            self._object_identity.addAsn1MibSource(self._asn_mib_sources)
        if self._custom_mib_sources:
            self._object_identity.addMibSource(self._custom_mib_sources)

    def get_oid(self, snmp_engine):
        if not self._object_identity:
            self._create_object_identity()
            self._object_identity.resolveWithMib(CommandGeneratorVarBinds().getMibViewController(snmpEngine=snmp_engine))
        return self._object_identity


class SnmpSetRawOid(SnmpRawOid):
    def __init__(self, oid, value, asn_mib_sources=None, custom_mib_sources=None):
        super(SnmpSetRawOid, self).__init__(oid, asn_mib_sources, custom_mib_sources)
        self.value = value

    def get_oid(self, snmp_engine):
        self._create_object_identity()
        object_type = ObjectType(self._object_identity, self.value)
        object_type.resolveWithMib(CommandGeneratorVarBinds().getMibViewController(snmpEngine=snmp_engine))
        return object_type


class SnmpSetMibName(SnmpMibOid):
    def __init__(self, mib_name, mib_id, index, value, asn_mib_sources=None, custom_mib_sources=None):
        super(SnmpSetMibName, self).__init__(mib_name, mib_id, index, asn_mib_sources, custom_mib_sources)
        self.value = value

    def get_oid(self, snmp_engine):
        self._create_object_identity()
        object_type = ObjectType(self._object_identity, self.value)
        object_type.resolveWithMib(CommandGeneratorVarBinds().getMibViewController(snmpEngine=snmp_engine))
        return object_type
