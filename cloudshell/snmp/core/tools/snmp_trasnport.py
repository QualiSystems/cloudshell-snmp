import asyncio
import socket
from ipaddress import IPv6Address, ip_address

from pysnmp.carrier.asyncio.dgram import udp, udp6
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.entity import config
from pysnmp.error import PySnmpError

from cloudshell.snmp.core.snmp_errors import InitializeSNMPException
from cloudshell.snmp.core.tools.snmp_constants import SNMP_RETRIES_COUNT, SNMP_TIMEOUT


class QualiAsyncioDispatcher(AsyncioDispatcher):
    """Asyncio transport dispatcher with pysnmp 4 style run-loop semantics.

    pysnmp 7 run_dispatcher(timeout) runs the event loop until the safety
    timeout and then closes the transports, so every request would block for
    the full safety window and the engine would die after the first call.
    run_until_jobs_done() instead stops the loop as soon as all outstanding
    request jobs completed - like pysnmp 4 runDispatcher() did.
    """

    def __init__(self, *args, **kwargs):
        if "loop" not in kwargs:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                pass
            else:
                raise InitializeSNMPException(
                    "cloudshell-snmp drives its own event loop and cannot be "
                    "used from within a running asyncio event loop"
                )
            loop = asyncio.new_event_loop()
            # transports created later must land on this same loop
            asyncio.set_event_loop(loop)
            kwargs["loop"] = loop
        super().__init__(*args, **kwargs)
        self._running_until_jobs_done = False
        self._safety_timer = None
        self._max_wait = None

    def run_until_jobs_done(self, max_wait):
        """Run the event loop until all pending jobs complete.

        max_wait is a per-request safety net (seconds): the timer is re-armed
        on every job start/finish, so long multi-request walks are not cut
        off, while a wedged request cannot hang the loop forever.
        """
        if self.loop.is_running():
            raise PySnmpError("Event loop is already running")
        if not self.jobs_are_pending():
            return
        self._max_wait = max_wait
        self._running_until_jobs_done = True
        self._arm_safety_timer()
        try:
            self.loop.run_forever()
        finally:
            self._running_until_jobs_done = False
            self._cancel_safety_timer()

    def job_started(self, jobId, count=1):
        super().job_started(jobId, count)
        if self._running_until_jobs_done:
            self._arm_safety_timer()

    def job_finished(self, jobId, count=1):
        super().job_finished(jobId, count)
        if self._running_until_jobs_done:
            self._arm_safety_timer()
            # The deferral is mandatory: the retry path calls job_finished and
            # then job_started for the retransmit within the same callback
            # chain - stopping synchronously here would end the loop before
            # the retransmit (or a walk re-issue) is registered.
            self.loop.call_soon(self._maybe_stop)

    def _maybe_stop(self):
        if self._running_until_jobs_done and not self.jobs_are_pending():
            self.loop.stop()

    def _arm_safety_timer(self):
        self._cancel_safety_timer()
        self._safety_timer = self.loop.call_later(self._max_wait, self._on_safety_wait)

    def _cancel_safety_timer(self):
        if self._safety_timer is not None:
            self._safety_timer.cancel()
            self._safety_timer = None

    def _on_safety_wait(self):
        self._safety_timer = None
        self.loop.stop()

    def close_dispatcher(self):
        self._cancel_safety_timer()
        super().close_dispatcher()
        if not self.loop.is_running() and not self.loop.is_closed():
            # let the transports' close callbacks run, then close our loop
            try:
                self.loop.run_until_complete(asyncio.sleep(0))
                self.loop.run_until_complete(asyncio.sleep(0))
            except Exception:
                pass
            self.loop.close()


class SnmpTransport:
    def __init__(self, snmp_parameters, logger):
        self._snmp_parameters = snmp_parameters
        self._logger = logger

    def add_udp_endpoint(
        self,
        snmp_engine,
        snmp_timeout=SNMP_TIMEOUT,
        snmp_retry_count=SNMP_RETRIES_COUNT,
    ):
        """Add UDP/IPv4 or UDP/IPv6 transport endpoint to SNMP engine.

        :param snmp_engine: SNMP engine instance
        :param snmp_timeout: SNMP timeout, in 1/100 sec
        :param snmp_retry_count: SNMP retry count
        """
        if self._snmp_parameters.ip:
            try:
                agent_udp_endpoint = socket.getaddrinfo(
                    self._snmp_parameters.ip,
                    self._snmp_parameters.port,
                    0,
                    socket.SOCK_DGRAM,
                    socket.IPPROTO_UDP,
                )[-1][4][:2]
            except socket.gaierror:
                raise InitializeSNMPException(
                    f"Failed to validate {self._snmp_parameters.ip} hostname",
                    self._logger,
                )
        else:
            raise InitializeSNMPException(
                f"Failed to validate {self._snmp_parameters.ip} hostname",
                self._logger,
            )

        # register our dispatcher BEFORE config.add_transport - otherwise
        # pysnmp auto-installs a stock AsyncioDispatcher without our
        # run_until_jobs_done semantics
        if snmp_engine.transport_dispatcher is None:
            snmp_engine.register_transport_dispatcher(QualiAsyncioDispatcher())
        dispatcher_loop = snmp_engine.transport_dispatcher.loop

        # fmt: off
        ip = ip_address(f"{agent_udp_endpoint[0]}")
        # fmt: on
        if isinstance(ip, IPv6Address):
            config.add_transport(
                snmp_engine,
                udp6.DOMAIN_NAME,
                udp6.Udp6AsyncioTransport(loop=dispatcher_loop).open_client_mode(),
            )
            config.add_target_address(
                snmp_engine,
                "tgt",
                udp6.DOMAIN_NAME,
                agent_udp_endpoint,
                "pms",
                snmp_timeout,
                snmp_retry_count,
            )
        else:
            config.add_transport(
                snmp_engine,
                udp.DOMAIN_NAME,
                udp.UdpAsyncioTransport(loop=dispatcher_loop).open_client_mode(),
            )
            config.add_target_address(
                snmp_engine,
                "tgt",
                udp.DOMAIN_NAME,
                agent_udp_endpoint,
                "pms",
                snmp_timeout,
                snmp_retry_count,
            )

        # let SnmpService size its dispatcher safety window from the actual
        # per-request deadline: timeout (1/100 sec) x (retries + 1)
        snmp_engine.quali_request_deadline = (snmp_timeout / 100.0) * (
            snmp_retry_count + 1
        )
