from abc import abstractmethod

from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType


class BaseSnmpOid:
    def __init__(self, asn_mib_sources=None, custom_mib_sources=None):
        self._asn_mib_sources = asn_mib_sources
        self._custom_mib_sources = custom_mib_sources
        self._mib_oid = None
        self._oid = None
        self.value = None

    @abstractmethod
    def _create_object_identity(self):
        pass

    @abstractmethod
    def get_oid(self, snmp_engine):
        pass

    @abstractmethod
    def get_object_type(self, snmp_engine):
        pass


class SnmpRawOid(BaseSnmpOid):
    def __init__(self, oid, asn_mib_sources=None, custom_mib_sources=None):
        super().__init__(asn_mib_sources, custom_mib_sources)
        self._oid = oid

    def _create_object_identity(self):
        object_identity = ObjectIdentity(self._oid)
        if self._asn_mib_sources:
            object_identity.addAsn1MibSource(self._asn_mib_sources)
        if self._custom_mib_sources:
            object_identity.addMibSource(self._custom_mib_sources)
        return object_identity

    def get_oid(self, snmp_engine):
        return self._oid

    def get_object_type(self, snmp_engine):
        mib_view = snmp_engine.mib_view
        object_identity = self._create_object_identity()
        object_identity.resolveWithMib(mib_view)
        object_type = ObjectType(object_identity)
        object_type.resolveWithMib(mib_view)
        return object_type


class SnmpMibObject(BaseSnmpOid):
    def __init__(
        self,
        mib_name,
        object_name,
        index=None,
        asn_mib_sources=None,
        custom_mib_sources=None,
    ):
        super().__init__(asn_mib_sources, custom_mib_sources)
        self._mib_name = mib_name
        self._object_name = object_name
        self.index = index
        self._asn_mib_sources = asn_mib_sources
        self._custom_mib_sources = custom_mib_sources
        self._object_identity = None

    @property
    def mib_name(self):
        return self._mib_name

    @property
    def object_name(self):
        return self._object_name

    def _create_object_identity(self):
        object_identity = ObjectIdentity(*(self._mib_name, self._object_name))
        if self.index is not None:
            object_identity = ObjectIdentity(
                *(
                    (self._mib_name, self._object_name)
                    + tuple(str(self.index).split("."))
                )
            )
        if self._asn_mib_sources:
            object_identity.addAsn1MibSource(self._asn_mib_sources)
        if self._custom_mib_sources:
            object_identity.addMibSource(self._custom_mib_sources)
        return object_identity

    def get_oid(self, snmp_engine):
        return self.get_object_type(snmp_engine)[0].getOid()

    def get_object_type(self, snmp_engine):
        mib_view = snmp_engine.mib_view
        object_identity = self._create_object_identity()
        object_identity.resolveWithMib(mib_view)
        object_type = ObjectType(object_identity)
        object_type.resolveWithMib(mib_view)
        return object_type


class SnmpSetRawOid(SnmpRawOid):
    def __init__(self, oid, value, asn_mib_sources=None, custom_mib_sources=None):
        super().__init__(oid, asn_mib_sources, custom_mib_sources)
        self.value = value

    def get_object_type(self, snmp_engine):
        mib_view = snmp_engine.mib_view
        object_identity = self._create_object_identity()
        object_type = ObjectType(object_identity, self.value)
        object_type.resolveWithMib(mib_view)
        return object_type


class SnmpSetMibName(SnmpMibObject):
    def __init__(
        self,
        mib_name,
        mib_id,
        index,
        value,
        asn_mib_sources=None,
        custom_mib_sources=None,
    ):
        super().__init__(mib_name, mib_id, index, asn_mib_sources, custom_mib_sources)
        self.value = value
        self._mib_oid = (self._mib_name, self._object_name)

    def get_object_type(self, snmp_engine):
        mib_view = snmp_engine.mib_view
        object_identity = self._create_object_identity()
        object_type = ObjectType(object_identity, self.value)
        object_type.resolveWithMib(mib_view)
        return object_type
