from abc import abstractproperty


class SnmpParameters(object):
    class SnmpVersion:
        def __init__(self):
            pass

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

    def validate(self):
        if not self.ip:
            raise Exception('SNMP host is not defined')
        if not self.port:
            raise Exception('SNMP port is not defined')


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
    AUTH_NO_AUTH = "No Authentication Protocol"
    AUTH_MD5 = "MD5"
    AUTH_SHA = "SHA"

    PRIV_NO_PRIV = "No Privacy Protocol"
    PRIV_DES = "DES"
    PRIV_3DES = "3DES-EDE"
    PRIV_AES128 = "AES-128"
    PRIV_AES192 = "AES-192"
    PRIV_AES256 = "AES-256"

    PROHIBITED_PROTOCOL_COMBINATIONS = [()]

    def __init__(self, ip, snmp_user, snmp_password, snmp_private_key, port=161,
                 auth_protocol=AUTH_NO_AUTH,
                 private_key_protocol=PRIV_NO_PRIV):
        """
        Represents parameters for an SMNPV3 connection
        :param str ip: The device IP
        :param str snmp_user: SNMP user
        :param str snmp_password: SNMP Password
        :param str snmp_private_key: Private key
        :param int port: SNMP port to use
        :param auth_protocol: a constant of SnmpAuthProtocol class that defines Auth protocol to use
        :param private_key_protocol: a constant of SnmpPrivProtocol class that defines what Private protocol to use
        """
        super(SNMPV3Parameters, self).__init__(ip, port)
        self.snmp_user = snmp_user
        self.snmp_password = snmp_password
        self.snmp_private_key = snmp_private_key
        self.auth_protocol = auth_protocol
        self.private_key_protocol = private_key_protocol

        if snmp_private_key is None and snmp_password is None:
            self._sec_level = 'noAuthNoPriv'
        elif snmp_password and snmp_private_key is None:
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

    def validate(self):
        """
        Validate
        """
        super(SNMPV3Parameters, self).validate()

        if not self.snmp_user:
            raise Exception('SNMPv3 user is not defined')

        if self.auth_protocol not in [self.AUTH_NO_AUTH, self.AUTH_MD5, self.AUTH_SHA]:
            raise Exception('Unknown Authentication Protocol {}'.format(self.auth_protocol))
        if self.private_key_protocol not in [self.PRIV_NO_PRIV, self.PRIV_DES, self.PRIV_3DES, self.PRIV_AES128,
                                             self.PRIV_AES192, self.PRIV_AES256]:
            raise Exception('Unknown Privacy Protocol {}'.format(self.private_key_protocol))

        if self.auth_protocol == self.AUTH_NO_AUTH and self.private_key_protocol != self.PRIV_NO_PRIV:
            raise Exception('{} cannot be used with {}'.format(self.private_key_protocol, self.auth_protocol))

        if self.auth_protocol != self.AUTH_NO_AUTH and not self.snmp_password:
            raise Exception('SNMPv3 Password has to be specified for Authentication Protocol {}'.format(
                                self.auth_protocol))

        if self.private_key_protocol != self.PRIV_NO_PRIV and not self.snmp_private_key:
            raise Exception('SNMPv3 Private key has to be specified for Privacy Protocol {}'.format(
                                self.private_key_protocol))

    def get_valid(self):
        self.validate()
        if self.private_key_protocol == self.PRIV_NO_PRIV:
            self.snmp_private_key = ''
        if self.auth_protocol == self.AUTH_NO_AUTH:
            self.snmp_password = ''
        return self
