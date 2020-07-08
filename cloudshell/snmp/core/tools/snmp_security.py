from pysnmp.entity import config

from cloudshell.snmp.core.tools.snmp_constants import (
    AUTH_PROTOCOL_MAP,
    PRIV_PROTOCOL_MAP,
)


class SnmpSecurity(object):
    def __init__(self, py_snmp_params, logger):
        self._py_snmp_params = py_snmp_params
        self._logger = logger

    def add_security(self, snmp_engine):
        if hasattr(self._py_snmp_params.snmp_parameters, "snmp_password"):
            auth_protocol = AUTH_PROTOCOL_MAP.get(
                self._py_snmp_params.snmp_parameters.snmp_auth_protocol
            )
            priv_protocol = PRIV_PROTOCOL_MAP.get(
                self._py_snmp_params.snmp_parameters.snmp_private_key_protocol
            )
            config.addV3User(
                snmpEngine=snmp_engine,
                userName=self._py_snmp_params.user,
                authProtocol=auth_protocol,
                authKey=self._py_snmp_params.snmp_parameters.snmp_password,
                privProtocol=priv_protocol,
                privKey=self._py_snmp_params.snmp_parameters.snmp_private_key,
            )
        else:
            config.addV1System(
                snmp_engine,
                self._py_snmp_params.user,
                self._py_snmp_params.snmp_parameters.snmp_community,
            )
