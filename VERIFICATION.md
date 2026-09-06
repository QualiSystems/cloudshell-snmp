# pysnmp 7 migration - live self-verification

Date: 2026-09-06. Environment: Windows 11, Python 3.13, pysnmp 7.1.29, pyasn1 0.6.4,
cryptography 50.0.1. Target: snmpsim-command-responder on 127.0.0.1:1612 serving
`public.snmprec` (copy of the parity-harness data file), v2c community `public` plus a
v3 USM user `simuser` (authPriv, SHA / AES-128). Unit suite: `pytest tests` = **72 passed**.

| # | Check | Result |
|---|-------|--------|
| a | v2c `get_property(SnmpMibObject("SNMPv2-MIB", "sysDescr", 0))` | PASS - `'Cisco Controller'`, `mib_id=sysDescr`, `index=0`, 0.22 s |
| b | Full `walk` of ifTable (`1.3.6.1.2.1.2.2`) | PASS - 100 var-binds, **5 rows** (indices 1-5) |
| b' | Independent count: raw pysnmp `next_cmd` lexicographic walk of the same subtree | PASS - **100 var-binds, same 5 row indices** -> no silent truncation vs the library walk |
| c | `get_table` of entPhysicalTable (`1.3.6.1.2.1.47.1.1.1`) | PASS - QualiMibTable with **2 rows**, keys `['1', '8']` |
| d | Dead host `127.0.0.1:9`, timeout=300 cs (3 s), retries=1 | PASS - `get` raised `ReadSNMPException` ("No SNMP response received before timeout") after **6.7 s**; `walk(retry_count=0)` raised `pysnmp.proto.errind.requestTimedOut` after **6.8 s**. Both ~ timeout x (retries+1) = 6 s + timer granularity, NOT the safety window - proves `run_until_jobs_done` + deferred `job_finished` stop works |
| e | Two sequential requests on separate `get_snmp_service` contexts | PASS - both returned `sysName='Cisco_70:a9:24'`; `close_dispatcher` (which also closes the private event loop) does not poison the next engine |
| f | SNMPv3 authPriv (SHA / AES-128) `get_property` of sysDescr | PASS - `'Cisco Controller'` in 0.21 s; proves the cryptography-backed USM priv path |

Notes and gotchas surfaced during verification:

- **The undeclared-cryptography trap is real and silent-ish**: the snmpsim venv initially
  lacked `cryptography`; the simulator accepted the encrypted request but the exchange
  failed with client-side `DecryptionError: Ciphering services not available or ciphertext
  is broken` - not an ImportError anywhere. This is exactly why cloudshell-snmp 6.0
  declares `cryptography>=43` explicitly.
- snmpsim selects the data file by v3 **context name** - check (f) uses
  `context_name="public"`. This is a simulator artifact, not a product requirement.
- cryptography 50.x warns that CFB mode moves to `hazmat.decrepit` in 49.0 semantics
  (`CryptographyDeprecationWarning` from pysnmp's `rfc3826/priv/aes.py`). Functional
  today; a future cryptography release may break pysnmp 7.1.x AES until pysnmp updates
  its import. Watch this at dependency-bump time.
- The timeout error contract preserved exactly as in 5.x: `walk`/`get_table` raise
  `errind.requestTimedOut` (what cloudshell-snmp-autoload catches); `get` raises
  `ReadSNMPException`, which `get_property` swallows into an empty `SnmpResponse`.
