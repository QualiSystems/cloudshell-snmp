# Cloudshell SNMP

[![Build status](https://github.com/QualiSystems/cloudshell-snmp/workflows/CI/badge.svg?branch=master)](https://github.com/QualiSystems/cloudshell-snmp/actions?query=branch%3Amaster)
[![codecov](https://codecov.io/gh/QualiSystems/cloudshell-snmp/branch/master/graph/badge.svg)](https://codecov.io/gh/QualiSystems/cloudshell-snmp)
[![PyPI version](https://shields.io/pypi/v/cloudshell-snmp)](https://pypi.org/project/cloudshell-snmp)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)

<p align="center">
<img src="https://github.com/QualiSystems/devguide_source/raw/master/logo.png"></img>
</p>

## Overview
The cloudshell-snmp open source Python package provides an easy-to-use interface for SNMP access and communication to a networking devices.

**Note:** We use tox and pre-commit for testing. For details, see [Services description](https://github.com/QualiSystems/cloudshell-package-repo-template#description-of-services).

## Installation
```bash
pip install cloudshell-snmp
```

### Contributing 

We welcome community ideas and contributions, so if you have any feedback or would like to request enhancements, feel free to create an **Issue** in the repository. 

#### Contributing code

1. Fork the repository. 

2. Make the code change. Make sure the tests pass. Add unit tests to cover any new behavior. We do require that the coverage does not decrease with the new code.

3. Submit a **Pull Request**.

## Usage

### Key components

CloudShell SNMP offers the following key features: 
* `SnmpMibOid` and `SnmpRawOid` - entities used to build a request
* `SnmpResponse`and `QualiMibTable` - types of objects we recieve in response from all communication methods (get, walk, get_table, etc.)
* **snmp service** allows CloudShell SNMP to communicate with target device.
<br>*CloudShell SNMP uses the `with` statement to establish a connection to the device.*

CloudShell SNMP is highly modular and implements many programming interfaces. 

### SNMP service
**snmp service** is the service that manages communication with the device. Allowing you to `set`, `get`, `walk` and `get_table` to/from the device.
Additionally it allows you to add more snmp MIB files by running `update_mib_sources` method
Most communication methods requires you to pass either `SnmpMibOid` or `SnmpRawOid`, 
i.e: `SnmpMibOid('SNMPv2-MIB', 'sysContact', 0)` or `SnmpRawOid('1.3.6.1.2.1.1.4.0')`
And in the result most of the commands return single or list of `SnmpResponse`, except get_table, since it returns table like dictionary: `QualiMibTable`.

**Example - Executing 'update_mib_sources' and 'set' command**

```python
from cloudshell.logging.qs_logger import get_qs_logger
from cloudshell.snmp.cloudshell_snmp import Snmp
from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject, SnmpSetMibName
from cloudshell.snmp.snmp_parameters import SNMPWriteParameters

snmp_params = SNMPWriteParameters(ip, community, "v2")
logger.info("started")

snmp_handler = Snmp()

with snmp_handler.get_snmp_service(snmp_parameters=snmp_params, logger=logger) as snmp_service:
    snmp_service.update_mib_sources("D:\\cisco\\mibs")
    set_id = 1 # Represents a row id, should be incremented.
    response = snmp_service.set([SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyProtocol", set_id, 1),
                                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopySourceFileType", set_id, 3),
                                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyDestFileType", set_id, 1),
                                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyServerAddress", set_id, "192.168.105.3"),
                                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyFileName", set_id, "test_snmp_running_config_save"),
                                 SnmpSetMibName("CISCO-CONFIG-COPY-MIB", "ccCopyEntryRowStatus", set_id, 4)])
```

**Example - Executing 'get', 'get_next', 'get_list' and 'get_property' command**

```python
from cloudshell.logging.qs_logger import get_qs_logger
from cloudshell.snmp.cloudshell_snmp import Snmp
from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject, SnmpSetMibName
from cloudshell.snmp.snmp_parameters import SNMPWriteParameters

snmp_params = SNMPWriteParameters(ip, community, "v2")
logger.info("started")

snmp_handler = Snmp()

with snmp_handler.get_snmp_service(snmp_parameters=snmp_params, logger=logger) as snmp_service:
    response = snmp_service.get_property(SnmpMibObject("SNMPv2-MIB", "sysDescr", 0))  # Retruns empty SnmpResponse in case get command failed to retrieve data
    response = snmp_service.get(SnmpMibObject("SNMPv2-MIB", "sysDescr", 0))  # Raises an exception in case requested oid is not found
    response = snmp_service.get_next(SnmpMibObject("SNMPv2-MIB", "sysDescr", 0))  # same as get
    response = snmp_service.get_list(SnmpMibObject("SNMPv2-MIB", "sysDescr", 0))  # same as get


```

**Example - Executing 'walk' and 'get_table' command**

```python
from cloudshell.logging.qs_logger import get_qs_logger
from cloudshell.snmp.cloudshell_snmp import Snmp
from cloudshell.snmp.core.domain.snmp_oid import SnmpMibObject, SnmpSetMibName
from cloudshell.snmp.snmp_parameters import SNMPWriteParameters

snmp_params = SNMPWriteParameters(ip, community, "v2")
logger.info("started")

snmp_handler = Snmp()

with snmp_handler.get_snmp_service(snmp_parameters=snmp_params, logger=logger) as snmp_service:
    response = snmp_service.walk(SnmpMibObject('IF-MIB', 'ifTable'))  # Retruns empty SnmpResponse in case get command failed to retrieve data
    response = snmp_service.get_table(SnmpMibObject('IF-MIB', 'ifTable'))  # Raises an exception in case requested oid is not found
```
