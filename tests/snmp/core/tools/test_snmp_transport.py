import unittest
from unittest.mock import Mock

from pysnmp.entity import engine
from pysnmp.entity.rfc3413.config import getTargetAddr

from cloudshell.snmp.core.tools.snmp_trasnport import SnmpTransport
from cloudshell.snmp.snmp_parameters import SNMPReadParameters


class TestSnmpTransport(unittest.TestCase):
    def setUp(self):
        self._engine = engine.SnmpEngine()

    def test_snmp_transport_with_ipv4(self):
        ip = "127.0.0.1"
        snmp_community = "public"
        snmp_parameters = SNMPReadParameters(ip=ip, snmp_community=snmp_community)
        transport = SnmpTransport(snmp_parameters, Mock())
        transport.add_udp_endpoint(self._engine, 10, 10)
        snmp_data = getTargetAddr(self._engine, "tgt")
        snmp_ip, snmp_port = snmp_data[1]
        assert snmp_ip == snmp_parameters.ip
        assert snmp_port == snmp_parameters.port

    def test_snmp_transport_with_hostname(self):
        hostname = "localhost"
        ipv6 = "::1"
        ip = "127.0.0.1"
        snmp_community = "public"
        snmp_parameters = SNMPReadParameters(ip=hostname, snmp_community=snmp_community)
        transport = SnmpTransport(snmp_parameters, Mock())
        transport.add_udp_endpoint(self._engine, 10, 10)
        snmp_data = getTargetAddr(self._engine, "tgt")
        snmp_ip = snmp_data[1][0]
        snmp_port = snmp_data[1][1]
        assert snmp_ip == ip or snmp_ip == ipv6
        assert snmp_port == snmp_parameters.port

    def test_snmp_transport_with_ipv6(self):
        ipv6 = "::1"
        snmp_community = "public"
        snmp_parameters = SNMPReadParameters(ip=ipv6, snmp_community=snmp_community)
        transport = SnmpTransport(snmp_parameters, Mock())
        transport.add_udp_endpoint(self._engine, 10, 10)
        snmp_data = getTargetAddr(self._engine, "tgt")
        snmp_ip = snmp_data[1][0]
        snmp_port = snmp_data[1][1]
        assert snmp_ip == snmp_parameters.ip
        assert snmp_port == snmp_parameters.port
