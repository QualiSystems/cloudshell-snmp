from pyasn1.type import univ


class SnmpContext(object):
    def __init__(self, v3_context_engine_id=None, v3_context_name=""):
        self._v3_context_engine_id = v3_context_engine_id
        self._v3_context_name = v3_context_name

    @property
    def context_engine_id(self):
        if self._v3_context_engine_id:
            if self._v3_context_engine_id[2:] == "0x":
                self._v3_context_engine_id = univ.OctetString(
                    hexValue=self._v3_context_engine_id[2:]
                )
            else:
                self._v3_context_engine_id = univ.OctetString(
                    self._v3_context_engine_id
                )
        return self._v3_context_engine_id

    @property
    def context_name(self):
        if self._v3_context_name:
            if self._v3_context_name[:2] == "0x":
                self._v3_context_name = univ.OctetString(
                    hexValue=self._v3_context_name[2:]
                )
            else:
                self._v3_context_name = univ.OctetString(self._v3_context_name)
        return self._v3_context_name
