# AGENTS.md — pyzk_wl10 Project Documentation

## Project Overview

This is a fork of `fananimi/pyzk` that adds support for **ZK WL10 / AK3750** fingerprint attendance terminals. The device uses a reverse-engineered protocol (tested against AK3750WIFI_TFT firmware "Ver 6.60 May 19 2023").

**Repository root**: `/home/informatica/zk2`

## Device Protocol Summary

### Read Path (already existed in fork)
- **Bulk read users**: `CMD=9 (USERTEMP_RRQ)` with empty payload → `CMD_PREPARE_DATA=1500` + 12B section header + N × 72B records
- **Bulk read attendance**: `CMD=13 (ATTLOG_RRQ)` with empty payload → `CMD_PREPARE_DATA=1500` + 12B section header + N × 22B records
- Uses raw socket (`_wl10_read_raw_command`) because standard buffered read truncates responses

### Write Path (implemented in this fork)
| Operation | Command | Payload | Response |
|-----------|---------|---------|----------|
| Write user | `CMD=8 (USER_WRQ)` | 72B (`HB8s24s4sx7sx24s`) | `ACK_OK=2000` |
| Delete user | `CMD=18 (DELETE_USER)` | 2B `pack('<h', uid)` | `ACK_OK=2000`¹ |
| Reboot | `CMD=2 (CMD_RESTART)` | empty | `ACK_OK=2000` |
| Housekeeping | `CMD=1013 (REFRESHDATA)` | empty | `ACK_OK=2000` |

¹ Device returns `ACK_OK` but **does not persist deletion** on tested firmware (Ver 6.60). Method provided for firmwares where it works.

### Record Layouts
- **User (72B)**: `uid(u16) | priv(u8) | pwd(8B) | name(24B) | card(u32) | pad | gid(7B) | pad | user_id(24B)`
- **Attendance (22B)**: `uid(u16) | user_id(6B) | reserved(4B) | flag(u8) | ts(u32 LE) | status(u8) | reserved(4B)`
- Timestamp encoding: `(Y%100)*12*31*86400 + (M-1)*31*86400 + (D-1)*86400 + h*3600 + m*60 + s`

## Code Structure

```
/home/informatica/zk2/
├── listar_marcaciones.py          # CLI: dump attendance with filters
├── wl10_probe_write.py            # One-off probe script for reverse-engineering write protocol
├── check_device.py                # Portable Windows diagnostic script (test UIDs > 999)
├── test_wl10_write.py             # Live-device E2E test for wl10_set_user/delete_user
├── test_runner_wl10.py            # Live-device test runner (uid <= 1000, user_id >= 9999, no overwrite, no delete)
├── README.md                       # Full protocol docs
├── AGENTS.md                       # This file
└── pyzk_wl10/
    └── zk/
        ├── __init__.py
        ├── attendance.py           # Attendance dataclass + ZK timestamp decode
        ├── base.py                 # Main ZK class (2160 lines)
        ├── const.py                # Protocol constants (CMD_*, WL10_*_RECORD_SIZE)
        ├── exception.py            # ZKErrorConnection, ZKErrorResponse, ZKNetworkError
        ├── finger.py               # Fingerprint template class
        ├── user.py                 # User dataclass + 72B/28B pack helpers
        └── tests/
            ├── conftest.py
            ├── helpers.py          # Fixtures + pack_user_record / pack_bulk_response
            ├── test_const.py
            ├── test_decode_time.py
            ├── test_parse_attendance.py
            ├── test_parse_users.py
            ├── test_scan_user_id.py
            ├── test_set_user.py    # 20 tests: wl10_set_user / wl10_delete_user + guards
            ├── test_socket_mss.py  # TCP MSS / chunking tests
            ├── test_strip_header.py
            ├── test_wl10_raw_drain.py  # Raw socket drain / framing tests
            ├── test_wl10_reboot.py     # wl10_reboot guards + ACK handling
            └── test_wl10_resilience.py # Dedup, missing-user, truncated-read resilience
```

## Key Classes & Methods

### `zk.base.ZK` (main class)
**Constructor**: `ZK(ip, port=4370, timeout=15, password=0, ommit_ping=True, force_udp=False, wl10=True, verbose=False, encoding='UTF-8')`

**Public API (WL10-specific)**:
- `wl10_get_users()` → `list[User]`
- `wl10_get_attendance()` → `list[Attendance]`
- `wl10_set_user(uid=None, name='', privilege=0, password='', group_id='', user_id='', card=0)` → `bool`
- `wl10_delete_user(uid=0, user_id='')` → `bool`
- `wl10_reboot()` → `bool` — reboots the device via `CMD_RESTART` over raw TCP path; marks connection closed on success

**Internal WL10 helpers** (prefixed `_wl10_`):
- `_wl10_read_sizes(self)` — query device capacities (user/attlog counts)
- `_wl10_read_raw_command(cmd)` — raw socket send + full recv (does NOT update `__session_id`/`__reply_id`)
- `_wl10_read_bulk_data(cmd, function_code)` — raw bulk read with fallback to buffered
- `_wl10_extract_tcp_payloads(raw)` — strip TCP framing, concat ZK payloads
- `_wl10_strip_header(raw, record_size)` — strip 12B section header, return `(records_bytes, count)`
- `_wl10_bulk_is_complete(raw, record_size)` — check whether a bulk read is complete
- `_wl10_build_users_map(users)` — build `{uid: User}` lookup for attendance enrichment
- `_wl10_parse_users(raw)` / `_wl10_parse_attendance(raw, users_map)`
- `_wl10_decode_user_record(rec)` — decode a single 72B user record
- `_wl10_scan_user_id(rec)` — scan user_id field handling null-terminator
- `_wl10_read_ack()` — read simple ACK (dsize=8), return `(cmd, rid)` and **synchronizes `__reply_id`**
- `_wl10_refresh_data()` — send `CMD_REFRESHDATA` to settle device state between operations

### `zk.const` — Protocol constants
```python
CMD_CONNECT=1000, CMD_USER_WRQ=8, CMD_USERTEMP_RRQ=9, CMD_ATTLOG_RRQ=13,
CMD_DELETE_USER=18, CMD_REFRESHDATA=1013, CMD_PREPARE_DATA=1500,
CMD_ACK_OK=2000, CMD_ACK_ERROR=2001, CMD_ACK_UNAUTH=2005,
WL10_USER_RECORD_SIZE=72, WL10_ATT_RECORD_SIZE=22,
USER_DEFAULT=0, USER_ADMIN=14
```

## Usage Example

```python
from zk import ZK

zk = ZK('<DEVICE_IP>', timeout=20, ommit_ping=True, force_udp=False, wl10=True)
zk.connect()

# Read
users = zk.wl10_get_users()
attendance = zk.wl10_get_attendance()

# Write (NEW)
zk.wl10_set_user(uid=1000, name='Alice', privilege=0, user_id='999950', card=0)
zk.wl10_set_user(uid=1001, name='Bob', privilege=14, user_id='999951')  # ADMIN

# Delete (returns True but may not persist on this firmware)
zk.wl10_delete_user(uid=1000)

# Reboot the device (connection becomes unusable after this)
zk.wl10_reboot()

zk.disconnect()
```

## Test Suite

Run all tests:
```bash
cd /home/informatica/zk2
python3 -m pytest pyzk_wl10/zk/tests/ -v
```

**91 tests total**:
- 39 original parser/fixture tests
- 20 write/delete tests (`test_set_user.py`):
  - 2 guards (`wl10=False`, `tcp=False`)
  - 3 payload format (72B, privilege clamp, admin passthrough)
  - 2 ACK handling (error, no response)
  - 4 `__reply_id` sync (after write OK, ACK_ERROR, consecutive writes, delete)
  - 5 delete guards + payload + sync
  - 4 reboot guards + ACK handling (`test_wl10_reboot.py`)
- 32 additional tests: socket MSS/chunking, raw drain/framing, strip header, resilience (dedup, missing-user, truncated-read)

## Probe Script (One-off)

```bash
python3 wl10_probe_write.py <DEVICE_IP> --verbose
```

Features:
- Reads baseline users via CMD=9 (raw)
- Writes USER (priv=0) + ADMIN (priv=14) via CMD=8 + 72B
- Readback verification
- Deletes via CMD=18 + `pack('<h', uid)`
- Deletion verification
- Structured report with PASS/FAIL summary

## Live-Device E2E Test

```bash
python3 test_wl10_write.py <DEVICE_IP> --verbose
```

Validates `wl10_set_user` / `wl10_delete_user` / `wl10_reboot` against a real device. Includes finally/disconnect cleanup. Excluded from ruff linting (live-device probe script).

## Live-Device Test Runner

```bash
python3 test_runner_wl10.py <DEVICE_IP> <DEVICE_IP> --verbose
```

Read-only baseline → picks free uids (≤ 1000, avoiding existing) + free user_ids (≥ 9999) → writes 2 test users (regular + admin) → read-back verification → NO delete. Hard constraints: no overwrite, no delete, test users left on device.

## Known Limitations

1. **Max uid = 1000** on AK3750 Ver 6.60 — device rejects uid > 1000 with `ACK_ERROR`. This is a firmware limitation. Use uids ≤ 1000 (avoiding existing users) and set `user_id` (badge string) to values ≥ 9999 for test isolation.
2. **Delete persists on tested devices** (<DEVICE_IP>, <DEVICE_IP>) — contrary to earlier belief. `wl10_delete_user` uses `pack('<H', uid)` (unsigned short) to support uids up to 65535.
3. **Concurrent writes require `refresh_data()` between calls** — the `__reply_id` sync in `_wl10_read_raw_command` keeps the client in sync with the device's incrementing reply_id after bulk reads. Without it, writes after `wl10_get_users()` fail with `ACK_ERROR`.
4. **No fingerprint/template write support** — only basic user records.
5. **Badge/user_id limited to 6 chars (max 999999)** due to 24B ASCII field.
6. **`_wl10_read_sizes()` returns False** on this firmware — device capacities cannot be queried.

## Common Commands

```bash
# Run all tests
python3 -m pytest pyzk_wl10/zk/tests/ -v

# Run specific test file
python3 -m pytest pyzk_wl10/zk/tests/test_set_user.py -v

# Probe live device
python3 wl10_probe_write.py <DEVICE_IP> --verbose

# Live-device test runner (write + verify, no delete)
python3 test_runner_wl10.py <DEVICE_IP> <DEVICE_IP> --verbose

# CLI dump attendance
python3 listar_marcaciones.py <DEVICE_IP> --since 2026-07-01 --csv
```

## Git History

```
3f18251  test: add live-device E2E test script for wl10_set_user/delete_user
4390227  fix: replace .encode('hex') with codecs.encode() in base.py
b36f3d3  feat: test UIDs > 999 + portable Windows diagnostic script
bf9acdc  docs: use uid 1000/1001 in wl10 write docstring examples
ad47549  fix: dedupe duplicate WL10 attendance records
194f573  feat: retry truncated WL10 bulk reads (users/attendance)
5b385ce  fix: restore broken_header reconstruction in __recieve_chunk
6b021dd  refactor: wl10_probe_write.py unused unpack + noqa + style
b51b0b2  refactor: tests sweep — unused imports, dead locals, import sort
1fe381c  refactor: listar_marcaciones.py dead locals + import sort
dbf2df4  refactor: base.py style cleanup (lint fixes + dead code)
504dd6f  chore: expand ruff ignores for base.py legacy
4b7b68e  refactor: modernize zk model classes (attendance/user/finger)
fabd71c  chore: add ruff config + clean encoding decls in zk package
b3ce60e  chore: ignore .omo/ OpenCode agent workspace
210f4ea  feat: implement wl10_set_user + wl10_delete_user (with reply_id sync fix)
3a227f7  test: add pytest fixtures + 39 tests for WL10 parsers
f4f4b70  Fix WL10/AK3750 record parsing to match real on-wire format
fc44280  Initial commit: pyzk WL10 fork
```

## Key Files for Future Work

| File | Purpose |
|------|---------|
| `pyzk_wl10/zk/base.py:1221` | `wl10_set_user` implementation |
| `pyzk_wl10/zk/base.py:1307` | `wl10_delete_user` implementation |
| `pyzk_wl10/zk/base.py:1358` | `wl10_reboot` implementation |
| `pyzk_wl10/zk/base.py:1157` | `_wl10_read_ack` — **critical**: syncs `__reply_id` |
| `pyzk_wl10/zk/tests/test_set_user.py` | 20 comprehensive tests |
| `pyzk_wl10/zk/tests/test_wl10_reboot.py` | 4 reboot guard + ACK tests |
| `pyzk_wl10/zk/tests/test_wl10_resilience.py` | Dedup, missing-user, truncated-read tests |
| `wl10_probe_write.py` | Live device probe reference |
| `test_wl10_write.py` | Live-device E2E test script |
| `test_runner_wl10.py` | Live-device test runner (uid ≤ 1000, user_id ≥ 9999, no overwrite/delete) |
| `check_device.py` | Portable Windows diagnostic (UIDs > 999) |
| `README.md` | Full protocol documentation |

## Critical Implementation Notes for Future Agents

1. **Never break the read path** — `wl10_get_users` / `wl10_get_attendance` must remain unchanged.
2. **`__reply_id` must be synchronized** after every raw write AND after every bulk read — `_wl10_read_raw_command` now syncs `__reply_id` from the `CMD_ACK_OK`/`CMD_ACK_ERROR` packet in the bulk response stream. `_wl10_read_ack` returns `(cmd, rid)` for write/delete ACKs. Callers must update `self._ZK__reply_id = ack_rid`.
3. **Use raw TCP path for writes** — `__send_command` doesn't work with WL10 bulk responses.
4. **Badge pool**: Use 999950–999999 for test users (6-char limit).
5. **Privilege values**: `0 = USER_DEFAULT`, `14 = USER_ADMIN`. Anything else clamps to `0`.
6. **Refresh_data() required** between bulk operations to settle device state.
7. **`__session_id` is NOT updated** by `_wl10_read_raw_command` — bulk-read `CMD_DATA` packets have garbled sid bytes 4-7; updating from them corrupts the session.

---

*Generated for pyzk_wl10 fork — commit 853852b (docs: sync AGENTS.md to current state)*