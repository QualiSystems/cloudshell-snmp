from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmDESPrivProtocol



# SNMP_HANDLER = QualiSnmp
# SNMP_HANDLER.kwargs = {'SNMP Version': get_attribute_by_name_wrapper('SNMP Version'),
#                        'SNMP User': get_attribute_by_name_wrapper('SNMP User'),
#                        'SNMP Password': get_attribute_by_name_wrapper('SNMP Password'),
#                        'SNMP Read Community': get_attribute_by_name_wrapper('SNMP Read Community'),
#                        'SNMP Private key': get_attribute_by_name_wrapper('SNMP Private Key'),
#                        'ResourceAddress': get_resource_address}
SNMP_DEFAULT_PORT = 161
SNMP_PRIV_PROTOCOL = usmDESPrivProtocol
SNMP_AUTH_PROTOCOL = usmHMACSHAAuthProtocol

