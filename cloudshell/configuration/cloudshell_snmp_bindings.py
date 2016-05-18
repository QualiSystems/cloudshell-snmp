import cloudshell.configuration.cloudshell_snmp_configuration as config
from cloudshell.configuration.cloudshell_snmp_binding_keys import SNMP_HANDLER
import inject


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
