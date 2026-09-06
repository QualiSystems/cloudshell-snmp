from pysnmp.entity.engine import SnmpEngine

from cloudshell.snmp.core.snmp_view_controller import QualiViewController
from cloudshell.snmp.core.tools.mib_builder_helper import MibBuilderHelper


class QualiSnmpEngine(SnmpEngine):
    MIB_VIEW_CONTROLLER = "mibViewController"

    def __init__(
        self, logger, snmp_engine_id=None, max_msg_size=65507, msg_pdu_dsp=None
    ):
        super().__init__(
            snmpEngineID=snmp_engine_id,
            maxMessageSize=max_msg_size,
            msgAndPduDsp=msg_pdu_dsp,
        )
        self._logger = logger
        self._mib_view = None

    @property
    def mib_builder(self):
        return self.get_mib_builder()

    @property
    def build_helper(self):
        return MibBuilderHelper(self.mib_builder)

    @property
    def mib_view(self):
        if not self._mib_view:
            self._mib_view = QualiViewController(self.mib_builder, self._logger)
            # pysnmp 7 CommandGeneratorVarBinds.get_mib_view_controller reads the
            # raw engine.cache key, while set_user_context prefixes keys with "__" -
            # plant the controller directly or MIB resolution silently falls back
            # to a fresh default MibViewController.
            self.cache[self.MIB_VIEW_CONTROLLER] = self._mib_view
        return self._mib_view
