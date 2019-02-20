import time

from cloudshell.snmp.core.services.read_snmp_service import ReadSnmpService


class WriteSnmpService(ReadSnmpService):
    def set(self, snmp_set_oids):
        """SNMP Set operation. Set appropriate oid value on the device

        :param snmp_set_oids: list or single SnmpSetMibName and/or SnmpSetRawOid object to set.
            For example, to set sysContact:
            snmp_obj = SnmpSetMibName(mib_name="SNMPv2-MIB", mib_id="sysContact", index=0, value="Owner")
            or
            snmp_obj = SnmpSetRawOid(oid="1.3.6.1.2.1.1.4.0", value="Owner)
            then
            set(snmp_obj)

            2 Example, set mib table row:
            set([SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyProtocol", 10, 1),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopySourceFileType", 10, 1),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyDestFileType", 10, 3),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyServerAddress", 10, "10.10.95.180"),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyFileName", 10, "test_snmp_running_config_save"),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyVrfName", 10, "management"),
                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyEntryRowStatus", 10, 4)])

        :rtype: list of SnmpResponse
        """
        snmp_set_oids_list = snmp_set_oids
        if not isinstance(snmp_set_oids_list, (list, tuple)):
            snmp_set_oids_list = [snmp_set_oids]
        object_identities = []
        for snmp_set_obj in snmp_set_oids_list:
            object_identities.append(snmp_set_obj.get_oid(self._snmp_engine))

        cb_ctx = {
            'is_snmp_timeout': False,
            'reqTime': time.time(),
            '': True,
        }
        service = self._create_response_service()

        service.send_set_var_binds(object_identities)

        self._start_dispatcher()

        self._check_error(service.cb_ctx, service.result)

        return service.result
