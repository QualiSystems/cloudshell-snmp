from cloudshell.snmp.snmp_parameters import SNMPV3Parameters, SNMPV2Parameters

__author__ = 'CoYe'

def get_snmp_parameters_from_command_context(command_context):
    """
    :param ResourceCommandContext command_context: command context
    :return:
    """
    snmp_version = get_and_validate_att(command_context,'SNMP Version')
    ip = command_context.resource.address

    if '3' in snmp_version:
        return SNMPV3Parameters(
            ip=ip,
            snmp_user=get_and_validate_att(command_context, 'SNMP User'),
            snmp_password=get_and_validate_att(command_context, 'SNMP Password'),
            snmp_private_key=get_and_validate_att(command_context, 'SNMP Private Key')
        )
    else:
        return SNMPV2Parameters(
            ip=ip,
            snmp_community=get_and_validate_att(command_context, 'SNMP Read Community'))


def get_and_validate_att(command_context, attribute_name):
    if attribute_name not in command_context.resource.attributes:
        raise ValueError('The resource does not have the mandatory {attribute_name} attribute defined'
                        .format(attribute_name=attribute_name))

    return command_context.resource.attributes[attribute_name]