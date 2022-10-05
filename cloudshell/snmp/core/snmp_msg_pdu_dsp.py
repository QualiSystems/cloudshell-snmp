from pysnmp.proto.rfc3412 import MsgAndPduDispatcher
from pysnmp.smi import instrum

from cloudshell.snmp.core.snmp_mib_builder import QualiMibBuilder


class QualiMsgAndPduDispatcher(MsgAndPduDispatcher):
    def __init__(self):
        mib_controller = instrum.MibInstrumController(QualiMibBuilder())
        super().__init__(mibInstrumController=mib_controller)
