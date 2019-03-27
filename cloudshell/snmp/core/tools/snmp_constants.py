from pysnmp.hlapi import usmNoPrivProtocol, usmDESPrivProtocol, usm3DESEDEPrivProtocol, usmAesCfb128Protocol, \
    usmAesCfb192Protocol, usmAesCfb256Protocol, usmNoAuthProtocol, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol

SNMP_RETRIES_COUNT = 2

MAX_BULK_REPETITIONS = 25

SNMP_TIMEOUT = 1000

SNMP_DEFAULT_PORT = 161

AUTH_PROTOCOL_MAP = {"No Authentication Protocol": usmNoAuthProtocol, "MD5": usmHMACMD5AuthProtocol,
                     "SHA": usmHMACSHAAuthProtocol}

PRIV_PROTOCOL_MAP = {"No Privacy Protocol": usmNoPrivProtocol, "DES": usmDESPrivProtocol,
                     "3DES-EDE": usm3DESEDEPrivProtocol,
                     "AES-128": usmAesCfb128Protocol, "AES-192": usmAesCfb192Protocol,
                     "AES-256": usmAesCfb256Protocol}
