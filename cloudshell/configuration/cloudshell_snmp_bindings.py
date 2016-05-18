import cloudshell.configuration.cloudshell_snmp_configuration as config
import inject

"""SNMP HANDLER binding key"""
SNMP_HANDLER = 'snmp_handler'


def bindings(binder):
    """
    Binding for snmp handler
    :param binder: The Binder object for binding creation
    :type binder: inject.Binder
    """

    try:
        binder.bind_to_provider(SNMP_HANDLER, config.SNMP_HANDLER)
    except inject.InjectorException:
        pass
