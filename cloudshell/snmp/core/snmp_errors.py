

class GeneralSNMPException(Exception):
    """
    Basic Snmp exception
    """
    pass


class ReadSNMPException(GeneralSNMPException):
    """
    Snmp response read exception
    """
    pass


class InitializeSNMPException(Exception):
    """
    Snmp initialize exception
    """
    pass


class TranslateSNMPException(GeneralSNMPException):
    """
    Snmp response read exception
    """
    pass
