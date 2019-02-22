

class SNMPException(Exception):
    """
    Basic Snmp exception
    """
    pass


class ReadSNMPException(SNMPException):
    """
    Snmp response read exception
    """
    pass


class InitializeSNMPException(Exception):
    """
    Snmp initialize exception
    """
    pass
