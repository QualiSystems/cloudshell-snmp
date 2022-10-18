class JsonMibRecord:
    def __init__(self, mib_name, mib_data):
        self.mib_name = mib_name
        self.mib_data = mib_data
        self.mib_record = mib_data.get("name")
        self.mib_type = mib_data.get("class")
        self.mib_node_type = mib_data.get("nodetype")
        self.mib_node_syntax = mib_data.get("syntax", {})
        self.mib_node_syntax_type = self.mib_node_syntax.get("type")
        self.mib_node_syntax_constraint = self.mib_node_syntax.get("constraints")
        self.mib_node_status = mib_data.get("status")
        self.mib_node_default = mib_data.get("default")
        self.mib_node_access = mib_data.get("maxaccess")
        self.mib_node_augmentation = mib_data.get("augmention")
        self.mib_node_units = mib_data.get("units")
        self.oid = mib_data.get("oid")
        self.mib_indexes = mib_data.get("indices", [])

    @property
    def oid_tuple(self):
        return tuple(int(x) for x in self.oid.split("."))


class JsonMibType(JsonMibRecord):
    def __init__(self, mib_name, mib_data):
        super().__init__(mib_name, mib_data)
        self.mib_type_display_hint = self.mib_data.get("displayhint")
        self.mib_type_data = self.mib_data.get("type", {})
        self.mib_type_class = self.mib_type_data.get("type")
        self.mib_type_constraints = self.mib_type_data.get("constraints", {})
