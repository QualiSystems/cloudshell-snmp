import socket
from ipaddress import IPv6Address, ip_address

from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.entity import config

from cloudshell.snmp.core.snmp_errors import InitializeSNMPException
from cloudshell.snmp.core.tools.snmp_constants import SNMP_RETRIES_COUNT, SNMP_TIMEOUT


class SnmpTransport(object):
    def __init__(self, snmp_parameters, logger):
        self._snmp_parameters = snmp_parameters
        self._logger = logger

    def add_udp_endpoint(
        self,
        snmp_engine,
        snmp_timeout=SNMP_TIMEOUT,
        snmp_retry_count=SNMP_RETRIES_COUNT,
    ):
        if self._snmp_parameters.ip:
            try:
                agent_udp_endpoint = socket.getaddrinfo(
                    self._snmp_parameters.ip,
                    self._snmp_parameters.port,
                    socket.AF_INET,
                    socket.SOCK_DGRAM,
                    socket.IPPROTO_UDP,
                )[0][4][:2]
            except socket.gaierror:
                raise InitializeSNMPException(
                    "Failed to validate {} hostname".format(self._snmp_parameters.ip),
                    self._logger,
                )
        else:
            raise InitializeSNMPException(
                "Failed to validate {} hostname".format(self._snmp_parameters.ip),
                self._logger,
            )

        ip = ip_address(u"{}".format(self._snmp_parameters.ip))
        if isinstance(ip, IPv6Address):
            config.addSocketTransport(
                snmp_engine,
                udp6.domainName,
                udp6.Udp6SocketTransport().openClientMode(),
            )
            config.addTargetAddr(
                snmp_engine,
                "tgt",
                udp6.domainName,
                agent_udp_endpoint,
                "pms",
                snmp_timeout,
                snmp_retry_count,
            )
        else:
            config.addSocketTransport(
                snmp_engine, udp.domainName, udp.UdpSocketTransport().openClientMode()
            )
            config.addTargetAddr(
                snmp_engine,
                "tgt",
                udp.domainName,
                agent_udp_endpoint,
                "pms",
                snmp_timeout,
                snmp_retry_count,
            )
