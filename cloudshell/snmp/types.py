from __future__ import annotations

from typing_extensions import Protocol


class SNMPVersionProtocol(Protocol):
    # some str enum
    @property
    def value(self) -> str:
        ...


class SnmpV3AuthProtocol(Protocol):
    # some str enum
    @property
    def value(self) -> str:
        ...


class SnmpV3PrivProtocol(Protocol):
    # some str enum
    @property
    def value(self) -> str:
        ...


class SNMPConfigProtocol(Protocol):
    address: str
    snmp_read_community: str
    snmp_write_community: str
    snmp_v3_user: str
    snmp_v3_password: str
    snmp_v3_private_key: str
    snmp_v3_auth_protocol: SnmpV3AuthProtocol
    snmp_v3_priv_protocol: SnmpV3PrivProtocol
    snmp_version: SNMPVersionProtocol
    enable_snmp: bool
    disable_snmp: bool
