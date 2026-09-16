# AGENTS.md — pyzk_wl10 Project Documentation

## Project Overview

Fork of `fananimi/pyzk` adding **ZK WL10 / AK3750** fingerprint attendance
terminal support via a reverse-engineered TCP protocol. Tested against
AK3750WIFI_TFT firmware "Ver 6.60 May 19 2023". Pure Python, stdlib-only
runtime, ~3700 LOC. **Repository root**: `/home/informatica/Dev/zkteco/zk2`.

**Before touching `base.py`'s WL10 read/write paths, read
`specs/wl10_reengineering_review.md`** — the adversarial review and dated
addendum are historical evidence, not proof that every risk is closed. The
current implementation has focused offline coverage, but live-device support
remains operation- and evidence-gated.

## Device Protocol Summary

### Read Path (pre-existing in fork)
- **Bulk read users**: `CMD=9 (USERTEMP_RRQ)` empty payload → `CMD_PREPARE_DATA=1500` + 12B section header + N × 72B records
- **Bulk read attendance**: `CMD=13 (ATTLOG_RRQ)` empty payload → `CMD_PREPARE_DATA=1500` + 12B section header + N × 22B records
- Uses raw socket (`_wl10_read_raw_command`) — the standard buffered read truncates these responses

### Write Path (fork-added)
| Operation | Command | Payload | Response |
|-----------|---------|---------|----------|
| Write user | `CMD=8 (USER_WRQ)` | 72B `HB8s24s4sB7sx24s` | `ACK_OK=2000` |
| Delete user | `CMD=18 (DELETE_USER)` | 2B `pack('<H', uid)` | `ACK_OK=2000` |
| Reboot | `CMD=1004 (CMD_RESTART)` | empty | `ACK_OK=2000` |
| Housekeeping | `CMD=1013 (REFRESHDATA)` | empty | `ACK_OK=2000` |

Deletion **persists** on tested devices.

### Record Layouts
- **User (72B)**: `uid(u16) | priv(u8) | pwd(8B) | name(24B) | card(u32) | verify_mode(u8) | gid(7B) | pad | user_id(24B)`
- **Attendance (22B)**: `uid(u16) | user_id(6B) | reserved(4B) | flag(u8) | ts(u32 LE) | status(u8) | reserved(4B)`
- Timestamp: `(Y%100)*12*31*86400 + (M-1)*31*86400 + (D-1)*86400 + h*3600 + m*60 + s`

## Code Structure

```
/home/informatica/Dev/zkteco/zk2/
├── listar_marcaciones.py          # CLI: dump attendance w/ --since/--until/--csv
├── wl10_probe_read.py             # Read-only raw capture probe; new output dir required
├── wl10_probe_write.py            # One-off protocol probe (write+verify+delete)
├── check_device.py                # Portable Windows read-only diagnostic (users + attendance, ES labels)
├── test_wl10_write.py             # Live-device E2E (set_user/delete_user)
├── test_runner_wl10.py            # Read-only by default; explicit one-write mode
├── README.md                      # Full protocol docs
├── AGENTS.md                      # This file
├── specs/
│   └── wl10_reengineering_review.md  # Historical review plus sanitized 2026-09-10 device addendum
└── pyzk_wl10/
    └── zk/
        ├── base.py                # class ZK (2449 lines — the monolith)
        ├── const.py               # Protocol constants (CMD_*, WL10_*_SIZE, WL10_VERIFY_*)
        ├── user.py / attendance.py / finger.py / exception.py
        └── tests/                 # 208 collected offline tests (see pyzk_wl10/zk/tests/AGENTS.md)
```

## Key API — `zk.base.ZK`

**Constructor** (base.py L91): `ZK(ip, port=4370, timeout=60, password=0, force_udp=False, ommit_ping=False, verbose=False, encoding='UTF-8', wl10=False, tcp_maxseg=None, gap_timeout=1)`
- WL10 requires TCP: `force_udp=False` + `wl10=True`
- `tcp_maxseg` sets TCP_MAXSEG before connect (fixes PMTUD blackhole on low-MTU VPN routes); also auto-set to 1200 by the resilience path on persistent no-ACK (see below)
- `gap_timeout` sets the per-attempt inter-chunk silence gap (base.py `_wl10_read_raw_command`); gaps grow 1×/2×/4× across the 3 drain attempts, clamped by `timeout`. Default `1` (LAN behavior preserved). `None` is normalized to `1` (CLIs pass `None` via argparse default — a raw `None` would break the arithmetic)

**General WL10 resilience mode** (applies to ALL wl10 devices, LAN + VPN — no per-IP config):
- `_wl10_read_raw_command` (base.py L838+) drains until either (a) a **terminal ACK** is detected in the TCP stream (`_wl10_scan_for_terminal_ack`: framed packet, `dsize>=8`, `pcmd in (CMD_ACK_OK=2000, CMD_ACK_ERROR=2001)`) → ends drain early (LAN: same-tick ACK, faster than old 1s wait), or (b) adaptive silence fallback: per-attempt gap `min(gap_timeout * 2**attempt, __timeout)` (1s → 2s → 4s with defaults). `__reply_id` is synced from the ACK rid even on `CMD_ACK_ERROR`; `__session_id` is NEVER updated from bulk packets.
- On 3 incomplete bulk attempts with **no terminal ACK observed** and `tcp_maxseg` unset, `_wl10_get_users`/`_wl10_get_attendance` auto-escalate: set `tcp_maxseg=1200`, `_wl10_reconnect()`, and retry up to **3 clamped recovery cycles** (each bounded by `min(__timeout, 5)`; break on a complete bulk). The multi-cycle loop handles flapping tunnels (observed ~50% up/down duty on the Bella Vista VPN) where a single recovery attempt is a coin flip. LAN devices complete attempt 1 (ACK arrives) → never reach escalation → zero behavior change.
- `_wl10_reconnect()` (base.py L806) — private recovery: marks `is_connect=False`, temporarily sets `ommit_ping=True` (ICMP may be blocked even when TCP is recoverable), calls `connect()` for a fresh handshake (resets `__session_id`/`__reply_id`). Deliberately does NOT use `disconnect()` (that sends `CMD_EXIT` first and can fail on a broken VPN). `__create_socket` closes the old socket before creating the replacement (fd-leak fix).

**Public WL10 API** (line refs in `pyzk_wl10/zk/base.py`):
- `wl10_get_users()` L1423 → `list[User]`; updates `next_uid`/`next_user_id` from the parsed table
- `wl10_get_attendance()` L1438 → `list[Attendance]`
- `wl10_set_user(uid=None, name='', privilege=0, password='', group_id='', user_id='', card=0, verify_mode=1)` L1510 → `bool`; compatibility signature, but `uid=None` is rejected before socket I/O; explicit uid and badge are required
- `wl10_delete_user(uid=0, user_id='')` L1605 → `bool`; preflights template slots and current users
- `wl10_reboot()` L1662 → `bool` — marks connection closed on success

**Native dispatch in WL10 mode**: `get_users()` → `wl10_get_users()`, `set_user()` → `wl10_set_user()`, `delete_user()` → `wl10_delete_user()`, `refresh_data()` → `_wl10_refresh_data()`, and `restart()` → `wl10_reboot()`.
**Internal helpers** (`pyzk_wl10/zk/base.py`): `_wl10_get_users` L1086, `_wl10_get_attendance` L1161, `_wl10_parse_users` L1243, `_wl10_parse_attendance` L1354, `_wl10_read_sizes` L598, `_wl10_scan_for_terminal_ack` L763, `_wl10_reconnect` L806, `_wl10_read_raw_command` L838 (ACK-terminated drain + adaptive silence fallback; syncs `__reply_id` from terminal ACK; does NOT sync `__session_id`), `_wl10_read_ack` L1446 (syncs `__reply_id`), `_wl10_refresh_data` L1487.

## Usage

```python
from zk import ZK

zk = ZK('<DEVICE_IP>', timeout=20, ommit_ping=True, wl10=True)
zk.connect()
users = zk.wl10_get_users()
attendance = zk.wl10_get_attendance()

zk.wl10_set_user(uid=1000, name='Alice', privilege=0, user_id='999950', card=0)
zk.wl10_set_user(uid=8, name='Bob', privilege=14, user_id='999951')  # ADMIN example; use only after live gates
zk.wl10_delete_user(uid=1000)
zk.wl10_reboot()          # connection becomes unusable after this
zk.disconnect()
```

## Test Suite

```bash
python3 -m pytest pyzk_wl10/zk/tests/ --collect-only -q  # 208 collected
python3 -m pytest pyzk_wl10/zk/tests/ -q                 # 208 passed, offline
```

**HAZARD**: a bare `pytest` from the repo root also collects live-device
scripts (`test_wl10_write.py`, `test_runner_wl10.py` match `test_*.py`) and
tries to hit real hardware. Always pass the explicit `pyzk_wl10/zk/tests/` path.
Test conventions: `pyzk_wl10/zk/tests/AGENTS.md`.

## Live-Device Scripts — NEVER IN CI

All take a device IP and touch real hardware. Never run casually or in CI:
- `wl10_probe_read.py IP --output-dir DIR [--timeout N --tcp-maxseg N --gap-timeout N]` — read-only raw capture; output directory is required and must not already exist
- `test_runner_wl10.py IP [--write-one --uid UID --user-id BADGE --evidence-json FILE --read-gate-json FILE]` — read-only by default; `--write-one` permits exactly one explicit write and leaves residue; no delete/cleanup/retry
- `listar_marcaciones.py IP [--since ... --csv --tcp-maxseg N --gap-timeout N]` — dump attendance
- `wl10_probe_write.py IP --verbose` — legacy writes/deletes real users; prohibited unless separately authorized
- `check_device.py` — Windows read-only diagnostic (users + attendance, ES labels)
- `test_wl10_write.py IP --verbose` — live E2E; prohibited unless separately authorized

## Known Limitations

1. **Max uid = 1000** on AK3750 Ver 6.60; WL10 writes require an explicit `uid` in 1..1000.
2. **Badge/user_id is required for WL10 writes**, must be an explicit non-empty value, and is a 6-character ASCII field (test pool `999950`–`999999`). The compatibility `uid=None` signature is fail-closed: it raises before any socket I/O; never rely on automatic allocation.
3. **Template-slot safety is mandatory**: records with `priv=0x31` (49) are tracked in `_wl10_template_uids`, excluded from user results, and rejected as write/delete targets. The write/delete preflight reads the table first and fails closed on read failure, template collision, or uncertain outcome.
4. **WL10 mutation ordering**: native `get_users`, `set_user`, `delete_user`, `refresh_data`, and `restart` dispatch to `wl10_*`/raw WL10 paths when `self.wl10` is true. Writes/deletes perform preflight, raw `REFRESHDATA`, exactly one mutation, and no automatic retry or cleanup on unknown outcome.
5. **No fingerprint/template write support** — basic user records only.
6. **`_wl10_read_sizes()` returns False** on this firmware — capacities not queryable.
7. **Attendance `uid=0` records are skipped; deduplication includes the flag byte.**
8. **Historical review bugs are not all proven fixed**: current tests cover the audited parser/dispatch/guard paths, but no blanket claim is made that every historical finding is fixed or live-certified. The historical `uid=None` overwrite scenario is blocked by the current guard.
9. **M4 data-model limitation**: a record with no name but a valid uid may display as `NN-<uid>`; this is device data, not proof of a missing name.

## WL10 support matrix

| Mode | Supported operations | Evidence status |
|---|---|---|
| Offline | pytest collection and suite; fake-socket/parser/dispatch/runner/probe tests | **Validated**: 208 collected and 208 passed |
| Read-only live | `wl10_probe_read.py` with a new output directory; `test_runner_wl10.py` default mode | **Partially characterized on a VPN-tested device**: the VPN profile completed with a summary and complete users/attendance reads, but `template_uids` was empty, so the template gate failed; not certified |
| One-write live | `test_runner_wl10.py --write-one --uid ... --user-id ... --evidence-json ... --read-gate-json ...` | **Not validated**: Task 6 overall gate FAILED; Task 7 remains blocked |
| Prohibited | delete, reboot, power, time, clear, door, enable/disable; legacy mutation scripts | **Not exercised on the VPN-tested device** |
| Unverified | any live operation lacking identity/completeness/parser/template/baseline evidence; raw packet capture without capability | **Unverified on the VPN-tested device**; the successful VPN read-only capture is not certified because the template gate failed |

Task 6 status (2026-09-10): the default profile remains incomplete after the wrapper timeout, with no summary; the VPN profile succeeded with a summary and complete users/attendance reads. Identity, complete reads, parser, and baseline consistency within the VPN profile passed; the empty `template_uids` set failed its gate. Overall Task 6 remains FAILED, and Task 7 write remains blocked.

No destructive operation was exercised on the VPN-tested device; no write was performed.

## Commands

```bash
python3 -m pytest pyzk_wl10/zk/tests/ --collect-only -q
python3 -m pytest pyzk_wl10/zk/tests/ -q
python3 wl10_probe_read.py <DEVICE_IP> --output-dir /path/to/new-capture --timeout 20
python3 test_runner_wl10.py <DEVICE_IP>                 # read-only default
python3 test_runner_wl10.py <DEVICE_IP> --write-one --uid 8 --user-id 999950 --evidence-json /path/to/new-evidence.json --read-gate-json /path/to/read-gate.json  # explicit single write only after gates
```

## Contribution traceability

Protocol-changing agents own one work-unit commit with code and tests together. Commits require contiguous `Agent-Role`, `Agent-Id`, and `Verification` trailers. Concurrent edits to `base.py` are prohibited. Raw device evidence is private and must never be committed or copied into prompts.

## Critical Implementation Notes

1. **Never break the read path** — `wl10_get_users` / `wl10_get_attendance` must stay unchanged unless a protocol work unit updates code and tests together.
2. **`__reply_id` must be synced** after every raw write and bulk read. `_wl10_read_raw_command` syncs it from the terminal ACK; write/delete ACKs come from `_wl10_read_ack`.
3. **Use the raw TCP path for WL10 writes** — `__send_command` does not handle WL10 bulk responses.
4. **Badge pool**: 999950–999999 for test users; production badges need explicit review.
5. **Privilege**: `0 = USER_DEFAULT`, `14 = USER_ADMIN`; other values clamp to `0`. `verify_mode` clamps to supported WL10 modes.
6. **`refresh_data()` is part of the WL10 mutation sequence**, not a substitute for preflight.
7. **`__session_id` is not updated from bulk `CMD_DATA` packets.**
8. **Never use `uid=None` for WL10 writes; pass an explicit uid and badge.**
9. **Inter-chunk drain gap** is `min(gap_timeout * 2**attempt, self.__timeout)` across three attempts; `TCP_MAXSEG` setup tolerates unsupported platforms.
