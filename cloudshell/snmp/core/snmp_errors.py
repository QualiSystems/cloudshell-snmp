class GeneralSNMPException(Exception):
    """Basic Snmp exception."""


class ReadSNMPException(GeneralSNMPException):
    """Snmp response read exception."""


class InitializeSNMPException(Exception):
    """Snmp initialize exception."""


class TranslateSNMPException(GeneralSNMPException):
    """Snmp response read exception."""
