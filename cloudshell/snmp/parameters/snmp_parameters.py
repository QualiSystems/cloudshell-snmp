from abc import abstractproperty

from cloudshell.snmp.core.tools.snmp_constants import AUTH_PROTOCOL_MAP, PRIV_PROTOCOL_MAP


class SnmpParameters(object):
    class SnmpVersion:
        V1 = 0
        V2 = 1
        V3 = 3

    def __init__(self, ip, port=161):
        self.ip = ip
        self.port = port

    @abstractproperty
    def security(self):
        pass

    @abstractproperty
    def user(self):
        pass

    @abstractproperty
    def snmp_version(self):
        pass


class SNMPV2Parameters(SnmpParameters):
    def __init__(self, ip, snmp_community, version, port=161):
        """
        Represents parameters for an SMNPV2 connection
        :param str ip: The device IP
        :param str snmp_community: SNMP Read community
        :param int port: SNMP port to use
        """
        SnmpParameters.__init__(self, ip=ip, port=port)
        self._version = version
        self.snmp_community = snmp_community

    @property
    def security(self):
        return 'noAuthNoPriv'

    @property
    def user(self):
        return 'agt'

    @property
    def snmp_version(self):
        version = SnmpParameters.SnmpVersion.V1
        if "2" in self._version:
            version = SnmpParameters.SnmpVersion.V2
        return version


class SNMPV3Parameters(SnmpParameters):
    def __init__(self, ip, snmp_user, snmp_password, snmp_private_key, port=161,
                 auth_protocol="No Authentication Protocol",
                 private_key_protocol="No Privacy Protocol"):
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
        super(SNMPV3Parameters, self).__init__(ip, port)
        self.snmp_user = snmp_user
        self.snmp_password = snmp_password
        self.snmp_private_key = snmp_private_key
        self.auth_protocol = AUTH_PROTOCOL_MAP[auth_protocol]
        self.private_key_protocol = PRIV_PROTOCOL_MAP[private_key_protocol]

        if snmp_private_key is None and snmp_password is None:
            self._sec_level = 'noAuthNoPriv'
        elif snmp_private_key is None:
            self._sec_level = 'authNoPriv'
        else:
            self._sec_level = 'authPriv'

    @property
    def security(self):
        return self._sec_level

    def user(self):
        return self.snmp_user

    @property
    def snmp_version(self):
        return SnmpParameters.SnmpVersion.V3
