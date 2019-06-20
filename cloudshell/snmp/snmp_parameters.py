from backports.functools_lru_cache import lru_cache


class SnmpParameters(object):
    def __init__(self, ip, port=161, context_engine_id=None, context_name=""):
        self.ip = ip
        self.port = port
        self.context_engine_id = context_engine_id
        self.context_name = context_name

    def validate(self):
        if not self.ip:
            raise Exception('SNMP host is not defined')
        if not self.port:
            raise Exception('SNMP port is not defined')


class SNMPV1Parameters(SnmpParameters):
    def __init__(self, ip, snmp_community, port=161, context_engine_id=None, context_name=""):
        """
        Represents parameters for an SMNPV2 connection
        :param str ip: The device IP
        :param str snmp_community: SNMP Read community
        :param int port: SNMP port to use
        """
        super(SNMPV1Parameters, self).__init__(ip,
                                               port,
                                               context_engine_id=context_engine_id,
                                               context_name=context_name)
        self.snmp_community = snmp_community


class SNMPV2Parameters(SNMPV1Parameters):
    def __init__(self, ip, snmp_community, port=161, context_engine_id=None, context_name=""):
        """
        Represents parameters for an SMNPV2 connection
        :param str ip: The device IP
        :param str snmp_community: SNMP Read community
        :param int port: SNMP port to use
        """
        super(SNMPV2Parameters, self).__init__(ip,
                                               snmp_community,
                                               port,
                                               context_engine_id=context_engine_id,
                                               context_name=context_name)


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

    def __init__(self, ip, snmp_user, snmp_password, snmp_private_key, port=161,
                 auth_protocol=AUTH_NO_AUTH,
                 private_key_protocol=PRIV_NO_PRIV,
                 context_engine_id=None, context_name=""):
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
        super(SNMPV3Parameters, self).__init__(ip,
                                               port,
                                               context_engine_id=context_engine_id,
                                               context_name=context_name)
        self.snmp_user = snmp_user
        self.snmp_password = snmp_password
        self.snmp_private_key = snmp_private_key
        self.auth_protocol = auth_protocol
        self.private_key_protocol = private_key_protocol

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


class SnmpParametersHelper(object):
    def __init__(self, resource_config, api):
        """

        :type resource_config: cloudshell.shell.standards.resource_config_generic_models.GenericSnmpConfig
        """

        self._resource_config = resource_config
        self._api = api

    @property
    @lru_cache()
    def _get_v3_password(self):
        return self._api.DecryptPassword(self._resource_config.snmp_v3_password).Value

    @property
    @lru_cache()
    def _get_read_community(self):
        return self._api.DecryptPassword(self._resource_config.snmp_read_community).Value

    @property
    @lru_cache()
    def _get_write_community(self):
        return self._api.DecryptPassword(self._resource_config.snmp_write_community).Value

    def get_snmp_parameters(self):
        """

        """
        if "3" in self._resource_config.snmp_version:
            return SNMPV3Parameters(ip=self._resource_config.address,
                                    snmp_user=self._resource_config.snmp_v3_user,
                                    snmp_password=self._get_v3_password(),
                                    snmp_private_key=self._resource_config.snmp_v3_private_key,
                                    auth_protocol=self._resource_config.snmp_v3_auth_protocol,
                                    private_key_protocol=self._resource_config.snmp_v3_priv_protocol)
        elif "1" in self._resource_config.snmp_version:
            return SNMPV1Parameters(self._resource_config.address,
                                    self._get_write_community() or self._get_read_community())
        else:
            return SNMPV2Parameters(self._resource_config.address,
                                    self._get_write_community() or self._get_read_community())
