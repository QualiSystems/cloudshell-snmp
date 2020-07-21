class SnmpParametersConverter(object):
    DEFAULT_USER = "agt"
    NO_AUTH_NO_PRIV = "noAuthNoPriv"
    AUTH_NO_PRIV = "authNoPriv"
    AUTH_PRIV = "authPriv"

    class PySnmpVersion:
        V1 = 0
        V2 = 1
        V3 = 3

    def __init__(self, snmp_parameters):
        self.snmp_parameters = snmp_parameters
        self._security = None
        self._user = None
        self._version = None

    @property
    def is_read_only(self):
        return self.snmp_parameters.is_read_only

    @property
    def security(self):
        if not self._security:
            self._get_security()
        return self._security

    @property
    def version(self):
        if not self._version:
            if "3" in self.snmp_parameters.version:
                self._version = SnmpParametersConverter.PySnmpVersion.V3
            elif "2" in self.snmp_parameters.version:
                self._version = SnmpParametersConverter.PySnmpVersion.V2
            else:
                self._version = SnmpParametersConverter.PySnmpVersion.V1

        return self._version

    @property
    def user(self):
        if not self._user:
            self._user = self.DEFAULT_USER
            if hasattr(self.snmp_parameters, "snmp_user"):
                self._user = self.snmp_parameters.snmp_user
        return self._user

    def _get_security(self):
        if "3" in self.snmp_parameters.version:
            if (
                self.snmp_parameters.snmp_private_key is None
                and self.snmp_parameters.snmp_password is None
            ):
                self._security = self.NO_AUTH_NO_PRIV
            elif (
                self.snmp_parameters.snmp_password
                and self.snmp_parameters.snmp_private_key is None
            ):
                self._security = self.AUTH_NO_PRIV
            else:
                self._security = self.AUTH_PRIV
        else:
            self._security = self.NO_AUTH_NO_PRIV
