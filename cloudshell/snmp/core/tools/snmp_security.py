from pysnmp.entity import config


class SnmpSecurity(object):
    def __init__(self, snmp_parameters, logger):
        self._snmp_parameters = snmp_parameters
        self._logger = logger

    def add_security(self, snmp_engine):
        if hasattr(self._snmp_parameters, "snmp_password"):
            config.addV3User(
                snmp_engine, self._snmp_parameters.snmp_user,
                self._snmp_parameters.snmp_auth_protocol, self._snmp_parameters.snmp_password,
                self._snmp_parameters.snmp_priv_protocol, self._snmp_parameters.snmp_v3_priv_key
            )
        else:
            config.addV1System(
                snmp_engine, self._snmp_parameters.user, self._snmp_parameters.snmp_community
            )
