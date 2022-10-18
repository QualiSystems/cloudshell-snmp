from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi.varbinds import CommandGeneratorVarBinds

from cloudshell.snmp.core.tools.mib_builder_helper import MibBuilderHelper


class QualiSnmpEngine(SnmpEngine):
    def __init__(self, snmp_engine_id=None, max_msg_size=65507, msg_pdu_dsp=None):
        super().__init__(
            snmpEngineID=snmp_engine_id,
            maxMessageSize=max_msg_size,
            msgAndPduDsp=msg_pdu_dsp,
        )
        self.build_helper = MibBuilderHelper(self.getMibBuilder())
        self.mib_view = CommandGeneratorVarBinds.getMibViewController(self)
