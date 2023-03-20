import socket
from ipaddress import IPv6Address, ip_address

from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.entity import config

from cloudshell.snmp.core.snmp_errors import InitializeSNMPException
from cloudshell.snmp.core.tools.snmp_constants import SNMP_RETRIES_COUNT, SNMP_TIMEOUT


class SnmpTransport:
    def __init__(self, snmp_parameters, logger):
        self._snmp_parameters = snmp_parameters
        self._logger = logger

    def add_udp_endpoint(
        self,
        snmp_engine,
        snmp_timeout=SNMP_TIMEOUT,
        snmp_retry_count=SNMP_RETRIES_COUNT,
    ):
        """Add UDP/IPv4 or UDP/IPv6 transport endpoint to SNMP engine.

        :param snmp_engine: SNMP engine instance
        :param snmp_timeout: SNMP timeout
        :param snmp_retry_count: SNMP retry count
        """
        if self._snmp_parameters.ip:
            try:
                agent_udp_endpoint = socket.getaddrinfo(
                    self._snmp_parameters.ip,
                    self._snmp_parameters.port,
                    0,
                    socket.SOCK_DGRAM,
                    socket.IPPROTO_UDP,
                )[-1][4][:2]
            except socket.gaierror:
                raise InitializeSNMPException(
                    f"Failed to validate {self._snmp_parameters.ip} hostname",
                    self._logger,
                )
        else:
            raise InitializeSNMPException(
                f"Failed to validate {self._snmp_parameters.ip} hostname",
                self._logger,
            )
        # fmt: off
        ip = ip_address(f"{agent_udp_endpoint[0]}")
        # fmt: on
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
