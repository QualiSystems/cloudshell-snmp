from pysnmp.hlapi import (
    usm3DESEDEPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from cloudshell.snmp.snmp_parameters import SNMPV3Parameters

SNMP_RETRIES_COUNT = 2
MAX_BULK_REPETITIONS = 25
SNMP_TIMEOUT = 1000
SNMP_DEFAULT_PORT = 161

AUTH_PROTOCOL_MAP = {
    SNMPV3Parameters.AUTH_NO_AUTH: usmNoAuthProtocol,
    SNMPV3Parameters.AUTH_MD5: usmHMACMD5AuthProtocol,
    SNMPV3Parameters.AUTH_SHA: usmHMACSHAAuthProtocol,
}

PRIV_PROTOCOL_MAP = {
    SNMPV3Parameters.PRIV_NO_PRIV: usmNoPrivProtocol,
    SNMPV3Parameters.PRIV_DES: usmDESPrivProtocol,
    SNMPV3Parameters.PRIV_3DES: usm3DESEDEPrivProtocol,
    SNMPV3Parameters.PRIV_AES128: usmAesCfb128Protocol,
    SNMPV3Parameters.PRIV_AES192: usmAesCfb192Protocol,
    SNMPV3Parameters.PRIV_AES256: usmAesCfb256Protocol,
}
