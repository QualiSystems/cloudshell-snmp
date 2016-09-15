import unittest
from mock import Mock
from cloudshell.snmp.command_context_snmp_helpers import get_snmp_parameters_from_command_context
from cloudshell.snmp.snmp_parameters import SNMPV2Parameters, SNMPV3Parameters


class MyTestCase(unittest.TestCase):

    def test_it_creates_SNMPV3_instance_if_snmp_version_attribute_is_V3(self):
        # Arrange
        context = Mock()
        context.resource = Mock()
        context.resource.attributes = { 'SNMP Version' : '3', 'SNMP User' : 'something',
                                        'SNMP Password' : 'secret', 'SNMP Private Key' : 'key' }

        # Act
        result = get_snmp_parameters_from_command_context(context)

        # Assert
        self.assertIsInstance(result, SNMPV3Parameters)

    def test_it_creates_SNMPV2_instance_if_snmp_version_attribute_is_V2(self):
        # Arrange
        context = Mock()
        context.resource = Mock()
        context.resource.attributes = { 'SNMP Version' : '2', 'SNMP Read Community' : 'something' }

        # Act
        result = get_snmp_parameters_from_command_context(context)

        # Assert
        self.assertIsInstance(result, SNMPV2Parameters)

    def test_it_returns_an_intelligible_error_message_if_missing_a_mandatory_attribute(self):
        # Arrange
        context = Mock()
        context.resource = Mock()
        context.resource.attributes = { 'SNMP Version' : '2' }

        # Act + Assert
        self.assertRaisesRegexp(ValueError, 'SNMP Read Community', get_snmp_parameters_from_command_context, context )


if __name__ == '__main__':
    unittest.main()
