import pickle

from cloudshell.snmp.quali_snmp import QualiSnmp


class QualiSnmpCached(QualiSnmp):
    def __init__(self, *args, **kwargs):
        self._snmp_cache = {}
        self._cache_changed = False
        super(QualiSnmpCached, self).__init__(*args, **kwargs)

    def override_cache_from_file(self, file_path):
        self.logger.debug('Reading cache from file {}'.format(file_path))
        try:
            with open(file_path, 'rb') as ff:
                self._snmp_cache = pickle.load(ff)
        except:
            raise Exception(self.__class__.__name__, 'Cannot open file {}'.format(file_path))

    def save_cache_to_file(self, file_path):
        self.logger.debug('Save cache to file {}'.format(file_path))
        with open(file_path, 'wb') as ff:
            pickle.dump(self._snmp_cache, ff, pickle.HIGHEST_PROTOCOL)

    def save_cache_to_file_if_changed(self, file_path):
        if self._cache_changed:
            self.save_cache_to_file(file_path)

    def walk(self, oid, *indexes):
        if oid in self._snmp_cache:
            self.logger.debug('Reading OID \"{}\" from cache'.format(oid))
            oid_2_value = self._snmp_cache[oid]
        else:
            self.logger.debug('Send SNMP request to the device, OID \"{}\"'.format(oid))
            oid_2_value = super(QualiSnmpCached, self).walk(oid)
            self._snmp_cache[oid] = oid_2_value
            self._cache_changed = True
        if indexes:
            oid_2_value = oid_2_value.get_rows(*indexes)
        return oid_2_value

    def get(self, *oids):
        if oids in self._snmp_cache:
            self.logger.debug('Reading OIDS \"{}\" from cache'.format(oids))
            result = self._snmp_cache[oids]
        else:
            self.logger.debug('Send SNMP request to the device, OIDS \"{}\"'.format(oids))
            result = super(QualiSnmpCached, self).get(*oids)
            self._cache_changed = True
            self._snmp_cache[oids] = result
        return result
