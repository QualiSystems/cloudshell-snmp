from pysnmp.hlapi import usmNoPrivProtocol, usmDESPrivProtocol, usm3DESEDEPrivProtocol, usmAesCfb128Protocol, \
    usmAesCfb192Protocol, usmAesCfb256Protocol, usmNoAuthProtocol, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol


class SNMPParameters(object):
    def __init__(self, ip, port=161):
        self.ip = ip
        self.port = port


class SNMPV2WriteParameters(SNMPParameters):
    def __init__(self, ip, snmp_write_community, port=161):
        """
        Represents parameters for an SMNPV2 connection
        :param str ip: The device IP
        :param str snmp_write_community: SNMP Write community
        :param int port: SNMP port to use
        """
        SNMPParameters.__init__(self, ip=ip, port=port)
        self.snmp_community = snmp_write_community


class SNMPV2ReadParameters(SNMPParameters):
    def __init__(self, ip, snmp_read_community, port=161):
        """
        Represents parameters for an SMNPV2 connection
        :param str ip: The device IP
        :param str snmp_read_community: SNMP Read community
        :param int port: SNMP port to use
        """
        SNMPParameters.__init__(self, ip=ip, port=port)
        self.snmp_community = snmp_read_community


class SNMPV3Parameters(SNMPParameters):
    AUTH_PROTOCOL_MAP = {"No Authentication Protocol": usmNoAuthProtocol, "MD5": usmHMACMD5AuthProtocol,
                         "SHA": usmHMACSHAAuthProtocol}

    PRIV_PROTOCOL_MAP = {"No Privacy Protocol": usmNoPrivProtocol, "DES": usmDESPrivProtocol,
                         "3DES-EDE": usm3DESEDEPrivProtocol,
                         "AES-128": usmAesCfb128Protocol, "AES-192": usmAesCfb192Protocol,
                         "AES-256": usmAesCfb256Protocol}

    def __init__(self, ip, snmp_user, snmp_password,
                 snmp_private_key, port=161, auth_protocol="SHA",
                 private_key_protocol="AES-128"):
        """
        Represents parameters for an SMNPV3 connection
        :param str ip: The device IP
        :param str snmp_user: SNMP user
        :param str snmp_password: SNMP Password
        :param str snmp_private_key: Private key
        :param int port: SNMP port to use
        :param auth_protocol: Auth protocol to use
        :param private_key_protocol: Private key protocol
        """
        SNMPParameters.__init__(self, ip=ip, port=port)
        self.snmp_user = snmp_user
        self.snmp_password = snmp_password
        self.snmp_private_key = snmp_private_key
        self.auth_protocol = self.AUTH_PROTOCOL_MAP[auth_protocol]
        self.private_key_protocol = self.PRIV_PROTOCOL_MAP[private_key_protocol]
