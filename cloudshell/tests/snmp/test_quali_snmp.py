from unittest import TestCase
import mock
from pyasn1.type.constraint import ConstraintsIntersection, ValueSizeConstraint
from pysnmp.proto.rfc1902 import ObjectName
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
#from mock import MagicMock as DisplayString
from cloudshell.snmp.quali_snmp import QualiSnmp
from mock import MagicMock
from mock import patch


class TestEricssonConfigurationOperations(TestCase):
    def _get_handler(self):
        var_binds = [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString(
            'Juniper Networks, Inc. srx220h-poe internet router, kernel JUNOS 12.1R6.5 #0: 2013-04-18 05:12:18 UTC     builder@rementh.juniper.net:/volume/build/junos/12.1/release/12.1R6.5/obj-octeon/junos/bsd/kernels/JSRXNLE/kernel Build date: 2013-04-18 06:40:26 UT',
            subtypeSpec=ConstraintsIntersection(ConstraintsIntersection(
                ConstraintsIntersection(ConstraintsIntersection(), ValueSizeConstraint(0, 65535)),
                ValueSizeConstraint(0, 255)), ValueSizeConstraint(0, 255))))]

        with patch.object(QualiSnmp, '_test_snmp_agent', return_value=''):
            snmp = QualiSnmp(ip='10.10.10.10', logger=MagicMock(), snmp_community='test')

        snmp._command = MagicMock(return_value=None)
        snmp.var_binds = var_binds
        return snmp

    def test_get_returns_correct_data(self):
        snmp_handler = self._get_handler()
        response = snmp_handler.get('1.3.6.1.2.1.1.4')
        self.assertIsNotNone(response)
