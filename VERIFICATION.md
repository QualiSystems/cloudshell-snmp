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

## Parity-gate follow-up: malformed TextualConvention rendering (2026-09-06)

The 143-device parity gate initially reported 140/143 byte-identical; the 3 diffs (rec067,
rec068, rec114) were all one pattern - `entPhysicalMfgDate` (SNMPv2-TC `DateAndTime`,
SIZE(8|11)) with malformed vendor payloads (16 ASCII `0` bytes on PaloAlto, `NA` on
Force10). pysnmp 7's `ObjectType.resolve_with_mib` force-assigns the wire payload into the
MIB type bypassing size constraints, so the DISPLAY-HINT rendered garbage
(`12336-48-48,...` / `20033`) where pysnmp 4 left raw ASCII.

Mitigation in `SnmpResponse.value`: when the resolved value is an OctetString-based
TextualConvention (has a DISPLAY-HINT) whose raw octets violate the type's `subtypeSpec`,
render the plain octets exactly as pysnmp 4 did (raw ASCII if printable, existing 0x/raw
path otherwise). Well-formed values keep going through `prettyPrint` untouched.

Proof:

- Unit test `test_malformed_textual_convention_renders_raw`: `b"0"*16` ->
  `'0000000000000000'`, `b"NA"` -> `'NA'`, well-formed 8-byte payload still renders
  `'2024-1-2,3:4:5.6'` via the hint. Full suite: **73 passed**.
- Parity re-check against the responder serving all 143 recordings on 127.0.0.1:1611:
  `walk_device.py` output for **rec067, rec068, rec114 all byte-identical** to
  `snmp-parity-harness/goldens/` -> gate now 143/143.
