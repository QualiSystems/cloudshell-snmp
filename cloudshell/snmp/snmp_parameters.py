from cloudshell.snmp.types import SNMPConfigProtocol


class SnmpParameters:
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
        super().__init__(
            ip, port, context_engine_id=context_engine_id, context_name=context_name
        )
        self.snmp_community = snmp_community
        self.is_read_only = True
        self.version = version

    def validate(self):
        super().validate()
        if not self.snmp_community:
            raise Exception("SNMP community is not defined")


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
        super().__init__(
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
        snmp_auth_protocol=AUTH_NO_AUTH,
        snmp_private_key_protocol=PRIV_NO_PRIV,
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
        super().__init__(
            ip, port, context_engine_id=context_engine_id, context_name=context_name
        )
        self.is_read_only = False
        self.version = SnmpParameters.SnmpVersion.V3
        self.snmp_user = snmp_user
        self.snmp_password = snmp_password
        self.snmp_private_key = snmp_private_key
        self.snmp_auth_protocol = snmp_auth_protocol
        self.snmp_private_key_protocol = snmp_private_key_protocol

    def validate(self):
        super().validate()

        if not self.snmp_user:
            raise Exception("SNMPv3 user is not defined")

        if self.snmp_auth_protocol not in [
            self.AUTH_NO_AUTH,
            self.AUTH_MD5,
            self.AUTH_SHA,
        ]:
            raise Exception(
                f"Unknown Authentication Protocol {self.snmp_auth_protocol}"
            )
        if self.snmp_private_key_protocol not in [
            self.PRIV_NO_PRIV,
            self.PRIV_DES,
            self.PRIV_3DES,
            self.PRIV_AES128,
            self.PRIV_AES192,
            self.PRIV_AES256,
        ]:
            raise Exception(
                f"Unknown Privacy Protocol {self.snmp_private_key_protocol}"
            )

        if (
            self.snmp_auth_protocol == self.AUTH_NO_AUTH
            and self.snmp_private_key_protocol != self.PRIV_NO_PRIV
        ):
            raise Exception(
                "{} cannot be used with {}".format(
                    self.snmp_private_key_protocol, self.snmp_auth_protocol
                )
            )

        if self.snmp_auth_protocol != self.AUTH_NO_AUTH and not self.snmp_password:
            raise Exception(
                "SNMPv3 Password has to be specified for Authentication "
                "Protocol {}".format(self.snmp_auth_protocol)
            )

        if (
            self.snmp_private_key_protocol != self.PRIV_NO_PRIV
            and not self.snmp_private_key
        ):
            raise Exception(
                "SNMPv3 Private key has to be specified for Privacy Protocol {}".format(
                    self.snmp_private_key_protocol
                )
            )

    def get_valid(self):
        self.validate()
        if self.snmp_private_key_protocol == self.PRIV_NO_PRIV:
            self.snmp_private_key = ""
        if self.snmp_auth_protocol == self.AUTH_NO_AUTH:
            self.snmp_password = ""
        return self


def get_snmp_parameters_from_config(conf: SNMPConfigProtocol) -> SnmpParameters:
    """Generate SNMP parameters from resource config."""
    snmp_params = None
    if "3" in conf.snmp_version.value:
        snmp_params = SNMPV3Parameters(
            ip=conf.address,
            snmp_user=conf.snmp_v3_user,
            snmp_password=conf.snmp_v3_password,
            snmp_private_key=conf.snmp_v3_private_key,
            snmp_auth_protocol=conf.snmp_v3_auth_protocol.value,
            snmp_private_key_protocol=conf.snmp_v3_priv_protocol.value,
        )
    elif "2" in conf.snmp_version.value or "1" in conf.snmp_version.value:
        version = SnmpParameters.SnmpVersion.V2
        if "1" in conf.snmp_version.value:
            version = SnmpParameters.SnmpVersion.V1

        community = conf.snmp_write_community
        if community:
            snmp_params = SNMPWriteParameters(conf.address, community, version=version)
        else:
            community = conf.snmp_read_community
            snmp_params = SNMPReadParameters(conf.address, community, version=version)
    if not snmp_params:
        raise Exception(f"Unknown SNMP version {conf.snmp_version.value}")
    snmp_params.validate()
    return snmp_params
