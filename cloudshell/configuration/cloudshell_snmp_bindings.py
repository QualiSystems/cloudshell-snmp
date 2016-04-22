import cloudshell.configuration.cloudshell_snmp_configuration as config
import inject


def bindings(binder):
    """
    Binding for snmp handler
    :param binder: The Binder object for binding creation
    :type binder: inject.Binder
    """

    _SNMP_HANDLER_NAME = 'snmp_handler'
    try:
        binder.bind_to_provider(_SNMP_HANDLER_NAME, config.SNMP_HANDLER)
    except inject.InjectorException:
        pass