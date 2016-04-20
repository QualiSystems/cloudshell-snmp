from cloudshell.snmp.quali_snmp import QualiSnmp
import inject


def bindings(binder):
    """
    Binding for snmp handler
    :param binder: The Binder object for binding creation
    :type binder: inject.Binder

    """

    _SNMP_HANDLER_NAME = 'snmp_handler'
    try:
        binder.bind_to_provider(_SNMP_HANDLER_NAME, QualiSnmp)
    except inject.InjectorException:
        pass
