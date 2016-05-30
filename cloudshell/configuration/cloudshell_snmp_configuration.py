from cloudshell.snmp.quali_snmp import QualiSnmp
from cloudshell.shell.core.context_utils import get_attribute_by_name_wrapper, get_resource_address

QUALISNMP_INIT_PARAMS = {'ip': get_resource_address,
                         'snmp_version': get_attribute_by_name_wrapper('SNMP Version'),
                         'snmp_user': get_attribute_by_name_wrapper('SNMP V3 User'),
                         'snmp_password': get_attribute_by_name_wrapper('SNMP V3 Password'),
                         'snmp_community': get_attribute_by_name_wrapper('SNMP Read Community'),
                         'snmp_private_key': get_attribute_by_name_wrapper('SNMP V3 Private Key')}


def create_snmp_handler():
    kwargs = {}
    for key, value in QUALISNMP_INIT_PARAMS.iteritems():
        if callable(value):
            kwargs[key] = value()
    return QualiSnmp(**kwargs)


SNMP_HANDLER = create_snmp_handler
