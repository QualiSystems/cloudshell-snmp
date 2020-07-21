import warnings


class SnmpParameters(object):
    class SnmpVersion:
        def __init__(self):
            pass

        V1 = "1"
        V2 = "2"
        V3 = "3"

    def __init__(self, ip, port=161, context_engine_id=None, context_name=""):
        self.ip = ip
        self.port = port
        self.context_engine_id = context_engine_id
        self.context_name = context_name
        self.version = None
        self.is_read_only = None

    def validate(self):
        if not self.ip:
            raise Exception("SNMP host is not defined")
        if not self.port:
            raise Exception("SNMP port is not defined")


class SNMPReadParameters(SnmpParameters):
    def __init__(
        self,
        ip,
        snmp_community,
        version=SnmpParameters.SnmpVersion.V2,
        port=161,
        context_engine_id=None,
        context_name="",
    ):
        """Represents parameters for an SMNPV2 connection.

        :param str ip: The device IP
        :param str snmp_community: SNMP Read community
        :param int port: SNMP port to use
        """
        super(SNMPReadParameters, self).__init__(
            ip, port, context_engine_id=context_engine_id, context_name=context_name
        )
        self.snmp_community = snmp_community
        self.is_read_only = True
        self.version = version


class SNMPWriteParameters(SNMPReadParameters):
    def __init__(
        self,
        ip,
        snmp_community,
        version=SnmpParameters.SnmpVersion.V2,
        port=161,
        context_engine_id=None,
        context_name="",
    ):
        """Represents parameters for an SMNPV2 connection.

        :param str ip: The device IP
        :param str snmp_community: SNMP Read community
        :param int port: SNMP port to use
        """
        super(SNMPWriteParameters, self).__init__(
            ip, snmp_community, version, port, context_engine_id, context_name
        )
        self.is_read_only = False


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

    def __init__(
        self,
        ip,
        snmp_user,
        snmp_password,
        snmp_private_key,
        port=161,
        auth_protocol=AUTH_NO_AUTH,
        private_key_protocol=PRIV_NO_PRIV,
        context_engine_id=None,
        context_name="",
    ):
        """Represents parameters for an SMNPV3 connection.

        :param str ip: The device IP
        :param str snmp_user: SNMP user
        :param str snmp_password: SNMP Password
        :param str snmp_private_key: Private key
        :param int port: SNMP port to use
        :param auth_protocol: a constant of SnmpAuthProtocol class that defines
            Auth protocol to use
        :param private_key_protocol: a constant of SnmpPrivProtocol class that defines
            what Private protocol to use
        """
        super(SNMPV3Parameters, self).__init__(
            ip, port, context_engine_id=context_engine_id, context_name=context_name
        )
        self.is_read_only = False
        self.version = SnmpParameters.SnmpVersion.V3
        self.snmp_user = snmp_user
        self.snmp_password = snmp_password
        self.snmp_private_key = snmp_private_key
        self.snmp_auth_protocol = auth_protocol
        self.snmp_private_key_protocol = private_key_protocol

    # For backward compatibility auth_protocol and private_key_protocol
    @property
    def auth_protocol(self):
        warnings.warn(
            "auth_protocol is obsolete please use snmp_auth_protocol field instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.snmp_auth_protocol

    @auth_protocol.setter
    def auth_protocol(self, value):
        warnings.warn(
            "auth_protocol is obsolete please use snmp_auth_protocol field instead",
            DeprecationWarning,
            stacklevel=2,
        )
        self.snmp_auth_protocol = value

    @property
    def private_key_protocol(self):
        warnings.warn(
            "private_key_protocol is obsolete please "
            "use snmp_private_key_protocol "
            "field instead",
            DeprecationWarning,
            stacklevel=2,
        )

        return self.snmp_private_key_protocol

    @private_key_protocol.setter
    def private_key_protocol(self, value):
        warnings.warn(
            "private_key_protocol is obsolete please "
            "use snmp_private_key_protocol "
            "field instead",
            DeprecationWarning,
            stacklevel=2,
        )
        self.snmp_private_key_protocol = value

    def validate(self):
        super(SNMPV3Parameters, self).validate()

        if not self.snmp_user:
            raise Exception("SNMPv3 user is not defined")

        if self.auth_protocol not in [self.AUTH_NO_AUTH, self.AUTH_MD5, self.AUTH_SHA]:
            raise Exception(
                "Unknown Authentication Protocol {}".format(self.auth_protocol)
            )
        if self.private_key_protocol not in [
            self.PRIV_NO_PRIV,
            self.PRIV_DES,
            self.PRIV_3DES,
            self.PRIV_AES128,
            self.PRIV_AES192,
            self.PRIV_AES256,
        ]:
            raise Exception(
                "Unknown Privacy Protocol {}".format(self.private_key_protocol)
            )

        if (
            self.auth_protocol == self.AUTH_NO_AUTH
            and self.private_key_protocol != self.PRIV_NO_PRIV
        ):
            raise Exception(
                "{} cannot be used with {}".format(
                    self.private_key_protocol, self.auth_protocol
                )
            )

        if self.auth_protocol != self.AUTH_NO_AUTH and not self.snmp_password:
            raise Exception(
                "SNMPv3 Password has to be specified for Authentication "
                "Protocol {}".format(self.auth_protocol)
            )

        if self.private_key_protocol != self.PRIV_NO_PRIV and not self.snmp_private_key:
            raise Exception(
                "SNMPv3 Private key has to be specified for Privacy Protocol {}".format(
                    self.private_key_protocol
                )
            )

    def get_valid(self):
        self.validate()
        if self.private_key_protocol == self.PRIV_NO_PRIV:
            self.snmp_private_key = ""
        if self.auth_protocol == self.AUTH_NO_AUTH:
            self.snmp_password = ""
        return self


class SnmpParametersHelper(object):
    def __init__(self, resource_config):
        """SNMP Parameter Helper.

        :type resource_config: cloudshell.shell.standards.resource_config_generic_models.GenericSnmpConfig  # noqa E501
        """
        self._resource_config = resource_config

    def get_snmp_parameters(self):
        if "3" in self._resource_config.snmp_version:
            return SNMPV3Parameters(
                ip=self._resource_config.address,
                snmp_user=self._resource_config.snmp_v3_user,
                snmp_password=self._resource_config.snmp_v3_password,
                snmp_private_key=self._resource_config.snmp_v3_private_key,
                auth_protocol=self._resource_config.snmp_v3_auth_protocol,
                private_key_protocol=self._resource_config.snmp_v3_priv_protocol,
            )
        else:
            version = SnmpParameters.SnmpVersion.V2
            if "1" in self._resource_config.snmp_version:
                version = SnmpParameters.SnmpVersion.V1

            community = self._resource_config.snmp_write_community
            if community:
                return SNMPWriteParameters(
                    self._resource_config.address, community, version=version
                )
            community = self._resource_config.snmp_read_community
            return SNMPReadParameters(
                self._resource_config.address, community, version=version
            )
