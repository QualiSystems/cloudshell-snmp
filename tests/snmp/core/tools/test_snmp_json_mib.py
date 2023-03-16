import json
import os
from unittest import TestCase
from unittest.mock import Mock

import pytest
from pysnmp.smi.error import MibNotFoundError

from cloudshell.snmp.core.domain.snmp_json_record import JsonMibRecord, JsonMibType
from cloudshell.snmp.core.snmp_engine import QualiSnmpEngine
from cloudshell.snmp.core.snmp_msg_pdu_dsp import QualiMsgAndPduDispatcher
from cloudshell.snmp.core.tools.mib_builder_helper import QualiDirMibSource
from cloudshell.snmp.core.tools.snmp_json_mib import JsonMib

"""
Code Analysis:
--The JsonMib class is responsible for parsing and storing SNMP MIB data in JSON format.
- It takes in a MIB builder, MIB name, MIB JSON data, and MIB parser as parameters during initialization.
- It creates a thread to build a map of the MIB data, which is stored in various dictionaries.
- The snmp_object_type_map property returns a dictionary mapping SNMP object types to their corresponding MIB nodes.
- The mib_types property returns a dictionary mapping textual conventions to their corresponding MIB types.
- The mib_symbols property returns a dictionary mapping MIB symbols to their corresponding JSON MibRecord objects.
- The json_mib_destroy method stops the thread used to build the MIB map.
- The _build_map method is responsible for building the MIB map by iterating through the JSON data and creating MibRecord objects for each node.
- The _get_snmp_object method returns the SNMP object corresponding to a given object type.
- The load_mib_type method loads a new MIB type into the MIB builder.
- The remaining methods are helper methods used in building the MIB map or creating SNMP objects.
"""

"""
Test Plan:
- test_successful_parsing_and_mapping_of_mib_data(): tests that the MIB data can be successfully parsed and mapped. Tags: [happy path]
- test_initialization_with_empty_mib_json_data(): tests that the JsonMib class can be initialized with empty MIB JSON data. Tags: [edge case]
- test_retrieval_of_snmp_object_type_map_before_mib_data_is_fully_parsed(): tests that the SNMP object type map cannot be retrieved before MIB data is fully parsed. Tags: [edge case]
- test_ability_to_load_new_mib_types_into_the_mib_builder(): tests that new MIB types can be loaded into the MIB builder. Tags: [general behavior]
- test_creation_of_snmp_objects_based_on_mib_data(): tests that SNMP objects can be created based on MIB data. Tags: [general behavior]
- test_retrieval_of_snmp_object_type_with_invalid_object_type(): tests that an invalid SNMP object type cannot be retrieved. Tags: [edge case]
- test_ability_to_destroy_the_thread_used_to_build_the_mib_map(): tests that the thread used to build the MIB map can be destroyed. Tags: [general behavior]
- test_initialization_with_valid_parameters(): tests that the JsonMib class can be initialized with valid parameters. Tags: [happy path]
"""


class TestJsonMib(TestCase):
    def setUp(self):
        snmp_engine = QualiSnmpEngine(
            msg_pdu_dsp=QualiMsgAndPduDispatcher(), logger=Mock()
        )
        self.mib_builder = snmp_engine.mib_builder
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "..",
            "..",
            "..",
            "cloudshell",
            "snmp",
            "mibs",
        )
        path_to_add = QualiDirMibSource(path)
        mib_sources = (path_to_add,) + self.mib_builder.getMibSources()
        self.mib_builder.setMibSources(*mib_sources)
        path_to_add.preload(self.mib_builder)

    def test_successful_parsing_and_mapping_of_mib_data(self):
        # Arrange
        mib_builder = None
        mib_name = "test_mib"
        mib_json = {
            "imports": {},
            "test_node": {
                "oid": "1.3.6.1.4.1.12345.1.1",
                "syntax": {
                    "type": "INTEGER",
                    "class": "type",
                },
                "nodetype": "scalar",
                "maxaccess": "read-only",
                "status": "current",
                "description": "Test node description",
            },
        }
        mib_parser = None

        # Act
        json_mib = JsonMib(mib_builder, mib_name, mib_json, mib_parser)
        json_mib.mib_types["INTEGER"] = Mock()

        # Assert
        result = json_mib.mib_symbols["test_node"]
        assert isinstance(result, JsonMibRecord)
        assert result.oid == "1.3.6.1.4.1.12345.1.1"
        assert result.mib_node_syntax_type == "INTEGER"
        assert result.mib_node_access == "read-only"
        assert result.mib_node_status == "current"

    def test_initialization_with_empty_mib_json_data(self):
        # Arrange
        mib_builder = None
        mib_name = "test_mib"
        mib_json = {}
        mib_parser = None

        # Act
        json_mib = JsonMib(mib_builder, mib_name, mib_json, mib_parser)

        # Assert
        assert json_mib.mib_symbols == {}

    def test_retrieval_of_snmp_object_type_map_before_mib_data_is_fully_parsed(self):
        # Arrange
        mib_name = "test_mib"
        mib_json = {
            "imports": {
                "class": "Imports",
                "imports": ["SNMPv2-SMI", "SNMPv2-TC", "SNMPv2-CONF"],
            }
        }
        json_mib = JsonMib(
            self.mib_builder, mib_name, mib_json, self.mib_builder.json_mib_parser
        )

        # Act/Assert
        with pytest.raises(MibNotFoundError):
            json_mib.snmp_object_type_map

    def test_ability_to_load_new_mib_types_into_the_mib_builder(self):
        # Arrange
        mib_name = "IF-MIB"
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "..",
            "..",
            "..",
            "cloudshell",
            "snmp",
            "mibs",
            f"{mib_name}.json",
        )
        mib_json = json.load(open(path))
        json_mib = JsonMib(
            self.mib_builder, mib_name, mib_json, self.mib_builder.json_mib_parser
        )

        # Act
        self.mib_builder.loadModule("IF-MIB")
        json_mib.load_mib_type("interfaceindex")
        result = json_mib.mib_types.get("interfaceindex")

        # Assert
        assert isinstance(result, JsonMibType)
        assert result.mib_node_status == "current"
        assert result.mib_name == mib_name
        assert result.mib_type_class == "Integer32"

    def test_retrieval_of_snmp_object_type_with_invalid_object_type(self):
        # Arrange
        mib_name = "test_mib"
        mib_json = {}
        json_mib = JsonMib(
            self.mib_builder, mib_name, mib_json, self.mib_builder.json_mib_parser
        )

        # Act/Assert
        with pytest.raises(TypeError):
            json_mib._get_snmp_object("invalid_type")

    def test_ability_to_destroy_the_thread_used_to_build_the_mib_map(self):
        # Arrange
        mib_builder = None
        mib_name = "test_mib"
        mib_json = {}
        mib_parser = None
        json_mib = JsonMib(mib_builder, mib_name, mib_json, mib_parser)

        # Act
        json_mib.json_mib_destroy()

        # Assert
        assert not json_mib._thread.is_alive()

    def test_initialization_with_valid_parameters(self):
        # Arrange
        mib_builder = None
        mib_name = "test_mib"
        mib_json = {}
        mib_parser = None

        # Act
        json_mib = JsonMib(mib_builder, mib_name, mib_json, mib_parser)

        # Assert
        assert json_mib.mib_name == "test_mib"
