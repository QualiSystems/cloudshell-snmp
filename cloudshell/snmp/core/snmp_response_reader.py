import time

from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.proto import rfc1902, rfc1905
from pysnmp.proto.errind import RequestTimedOut

from cloudshell.snmp.core.domain.snmp_response import SnmpResponse
from cloudshell.snmp.core.snmp_errors import ReadSNMPException


class SnmpResponseReader(object):
    TAGS_TO_SKIP = [
        rfc1905.NoSuchObject.tagSet,
        rfc1905.NoSuchInstance.tagSet,
        rfc1905.EndOfMibView.tagSet,
    ]

    def __init__(
        self,
        snmp_engine,
        logger,
        cb_ctx=None,
        context_id=None,
        context_name="",
        get_bulk_flag=False,
        get_bulk_repetitions=25,
        retry_count=2,
    ):
        self._snmp_engine = snmp_engine
        self._context_id = context_id
        self._context_name = context_name
        self._get_bulk_flag = get_bulk_flag
        self._get_bulk_repetitions = get_bulk_repetitions
        self._retry_count = retry_count
        self._stop_oid = None
        self._logger = logger
        self.cb_ctx = cb_ctx or {
            "is_snmp_timeout": False,
            "reqTime": time.time(),
            "": True,
            "retries": self._retry_count,
        }
        self.result = set()

    def cb_fun(
        self,
        snmp_engine,
        send_request_handle,
        error_indication,
        error_status,
        error_index,
        var_bind_table,
        cb_ctx,
    ):
        if error_status and error_status != 2 or error_indication:
            message = "Remote SNMP error {}".format(
                error_indication or error_status.prettyPrint()
            )
            self._logger.error(message)
            raise ReadSNMPException(message)
        stop_flag = self._parse_var_binds(var_bind_table=var_bind_table)
        return not stop_flag

    def cb_walk_fun(
        self,
        snmp_engine,
        send_request_handle,
        error_indication,
        error_status,
        error_index,
        var_bind_table,
        cb_ctx,
    ):
        if self.cb_ctx["is_snmp_timeout"] and self._get_bulk_flag:
            self.cb_ctx["get_bulk_flag"] = True
            self.cb_ctx["is_snmp_timeout"] = False

        if isinstance(error_indication, RequestTimedOut):
            bulk_half_rep_flag = self.cb_ctx.get("get_bulk_retry_half_repetitions_flag")
            if not bulk_half_rep_flag:
                self.cb_ctx["get_bulk_retry_half_repetitions_flag"] = True
            else:
                self.cb_ctx["get_bulk_flag"] = False
            self.cb_ctx["is_snmp_timeout"] = True

        get_bulk_flag = self.cb_ctx.get("get_bulk_flag", self._get_bulk_flag)
        if error_indication and not self.cb_ctx["retries"]:
            self._logger.debug("SNMP Engine error: %s" % error_indication)
            return
        # SNMPv1 response may contain noSuchName error *and* SNMPv2c exception,
        # so we ignore noSuchName error here
        if error_status and error_status != 2 or error_indication:
            self._logger.debug(
                "Remote SNMP error %s"
                % (error_indication or error_status.prettyPrint())
            )
            if self.cb_ctx["retries"]:
                try:
                    next_oid = var_bind_table[-1][0][0]
                except IndexError:
                    next_oid = self.cb_ctx["lastOID"]
                else:
                    self._logger.debug("Failed OID: %s" % next_oid)
                # fuzzy logic of walking a broken OID
                if len(next_oid) < 4:
                    pass
                if not self.cb_ctx.get("is_snmp_timeout"):
                    if (
                        self._retry_count - self.cb_ctx["retries"]
                    ) * 10 / self._retry_count > 5:
                        next_oid = next_oid[:-2] + (next_oid[-2] + 1,)
                    elif next_oid[-1]:
                        next_oid = next_oid[:-1] + (next_oid[-1],)
                    else:
                        next_oid = next_oid[:-2] + (next_oid[-2] + 1, 0)

                self.cb_ctx["retries"] -= 1
                self.cb_ctx["lastOID"] = next_oid

                self._logger.debug(
                    "Retrying with OID %s (%s retries left)..."
                    % (next_oid, self.cb_ctx["retries"])
                )

                get_bulk_repetitions = self._get_bulk_repetitions
                half_bulk_repetitions_flag = self.cb_ctx.get(
                    "get_bulk_retry_half_repetitions_flag"
                )
                if half_bulk_repetitions_flag:
                    get_bulk_repetitions = self._get_bulk_repetitions // 2

                # initiate another SNMP walk iteration
                if get_bulk_flag:
                    self._send_bulk_var_binds(
                        oid=next_oid, get_bulk_repetitions=get_bulk_repetitions
                    )
                else:
                    self._send_walk_var_binds(oid=next_oid)

            return

        if self._retry_count != self.cb_ctx["retries"]:
            self.cb_ctx["retries"] += 1

        if var_bind_table and var_bind_table[-1] and var_bind_table[-1][0]:
            self.cb_ctx["lastOID"] = var_bind_table[-1][0][0]

        stop_flag = self._parse_var_binds(var_bind_table=var_bind_table)
        return not stop_flag

    def _parse_var_binds(self, var_bind_table):
        stop_flag = False
        if not var_bind_table:
            return False
        for var_bind_row in var_bind_table:
            if isinstance(var_bind_row, tuple):
                var_bind_row = [var_bind_row]
            if not isinstance(var_bind_row, list):
                self._logger.debug(
                    "Failed to parse snmp response, unknown type: '{}'".format(
                        type(var_bind_row)
                    )
                )
            for oid, value in var_bind_row:
                stop_flag = self._parse_response(oid, value)
                if stop_flag:
                    break
        return stop_flag

    def _parse_response(self, oid, value):
        if (
            self._stop_oid and oid >= self._stop_oid
        ) or value.tagSet in self.TAGS_TO_SKIP:
            return True

        elif value.tagSet == rfc1902.Integer32.tagSet:
            value = rfc1902.Integer32(value)

        elif value.tagSet == rfc1902.Unsigned32.tagSet:
            value = rfc1902.Unsigned32(value)

        elif value.tagSet == rfc1902.Bits.tagSet:
            value = rfc1902.OctetString(value)

        response = SnmpResponse(
            oid, value, snmp_engine=self._snmp_engine, logger=self._logger
        )
        self.result.add(response)
        return False

    def send_walk_var_binds(self, oid, stop_oid=None, cb_fun=None):
        if stop_oid and not self._stop_oid:
            self._stop_oid = stop_oid

        self._send_walk_var_binds(oid, cb_fun)

    def _send_walk_var_binds(self, oid, cb_fun=None):
        cmd_gen = cmdgen.NextCommandGenerator()
        if not cb_fun:
            cb_fun = self.cb_walk_fun

        cmd_gen.sendVarBinds(
            self._snmp_engine,
            "tgt",
            self._context_id,
            self._context_name,
            [(oid, None)],
            cb_fun,
            self.cb_ctx,
        )

    def send_bulk_var_binds(self, oid, stop_oid=None, get_bulk_repetitions=None):
        if stop_oid and not self._stop_oid:
            self._stop_oid = stop_oid
        self._send_bulk_var_binds(oid, get_bulk_repetitions)

    def _send_bulk_var_binds(self, oid, get_bulk_repetitions=None):
        cmd_gen = cmdgen.BulkCommandGenerator()

        cmd_gen.sendVarBinds(
            self._snmp_engine,
            "tgt",
            self._context_id,
            self._context_name,
            0,
            get_bulk_repetitions or self._get_bulk_repetitions,
            [(oid, None)],
            self.cb_walk_fun,
            self.cb_ctx,
        )

    def send_get_var_binds(self, oid, stop_oid=None):
        cmd_gen = cmdgen.GetCommandGenerator()
        if stop_oid and not self._stop_oid:
            self._stop_oid = stop_oid

        cmd_gen.sendVarBinds(
            self._snmp_engine,
            "tgt",
            self._context_id,
            self._context_name,
            [(oid, None)],
            self.cb_fun,
            self.cb_ctx,
        )

    def send_set_var_binds(self, oids):
        cmd_gen = cmdgen.SetCommandGenerator()

        cmd_gen.sendVarBinds(
            self._snmp_engine,
            "tgt",
            self._context_id,
            self._context_name,
            oids,
            self.cb_fun,
            self.cb_ctx,
        )
