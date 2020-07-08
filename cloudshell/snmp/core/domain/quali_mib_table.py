from collections import OrderedDict


class QualiMibTable(dict):
    """Represents MIB table.

    Note that this class inherits from OrderedDict so all dict operations are supported.
    """

    def __init__(self, name, *args, **kwargs):
        """Create ordered dictionary to hold the MIB table.

        MIB table representation:
        {index: {attribute: value, ...}...}

        :param name: MIB table name.
        """
        super(QualiMibTable, self).__init__(*args, **kwargs)
        self._name = name

    def get_rows(self, *indexes):
        """Get rows.

        :param indexes: list of requested indexes.
        :return: a partial table containing only the requested rows.
        """
        return QualiMibTable(
            self._name, OrderedDict((i, v) for i, v in self.items() if i in indexes)
        )

    def get_columns(self, *names):
        """Get columns.

        :param names: list of requested columns names.
        :return: a partial table containing only the requested columns.
        """
        return QualiMibTable(
            self._name,
            OrderedDict(
                (i, {n: v for n, v in values.items() if n in names})
                for i, values in self.items()
            ),
        )

    def filter_by_column(self, name, *values):
        """Filter by column.

        :param name: column name.
        :param values: list of requested values.
        :return: a partial table containing only the rows that has one of the
            requested values in the requested column.
        """
        return QualiMibTable(
            self._name,
            OrderedDict(
                (i, _values) for i, _values in self.items() if _values[name] in values
            ),
        )

    def sort_by_column(self, name):
        """Sort by column.

        :param name: column name.
        :return: the same table sorted by the value in the requested column.
        """
        column = self.get_columns(name)
        return QualiMibTable(
            self._name, sorted(column.items(), key=lambda t: int(t[1][name]))
        )

    @staticmethod
    def create_from_list(name, response_list):
        mib_table = QualiMibTable(name)
        for item in response_list:
            entry = mib_table.get(item.index)
            if not entry:
                entry = {}
                mib_table[item.index] = entry
            entry[item.mib_id] = item
        return mib_table
