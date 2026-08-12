# AGENTS.md — pyzk_wl10 Project Documentation

## Project Overview

Fork of `fananimi/pyzk` adding **ZK WL10 / AK3750** fingerprint attendance
terminal support via a reverse-engineered TCP protocol. Tested against
AK3750WIFI_TFT firmware "Ver 6.60 May 19 2023". Pure Python, stdlib-only
runtime, ~4700 LOC. **Repository root**: `/home/informatica/zk2`.

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

Deletion **persists** on tested devices (<DEVICE_IP>, <DEVICE_IP>).

### Record Layouts
- **User (72B)**: `uid(u16) | priv(u8) | pwd(8B) | name(24B) | card(u32) | verify_mode(u8) | gid(7B) | pad | user_id(24B)`
- **Attendance (22B)**: `uid(u16) | user_id(6B) | reserved(4B) | flag(u8) | ts(u32 LE) | status(u8) | reserved(4B)`
- Timestamp: `(Y%100)*12*31*86400 + (M-1)*31*86400 + (D-1)*86400 + h*3600 + m*60 + s`

## Code Structure

```
/home/informatica/zk2/
├── listar_marcaciones.py          # CLI: dump attendance w/ --since/--csv
├── wl10_probe_write.py            # One-off protocol probe (write+verify+delete)
├── check_device.py                # Portable Windows diagnostic (UIDs > 999)
├── test_wl10_write.py             # Live-device E2E (set_user/delete_user/reboot)
├── test_runner_wl10.py            # Live-device runner (uid<=1000, user_id>=9999, no overwrite/delete)
├── README.md                      # Full protocol docs
├── AGENTS.md                      # This file
└── pyzk_wl10/
    └── zk/
        ├── base.py                # class ZK (2204 lines — the monolith)
        ├── const.py               # Protocol constants (CMD_*, WL10_*_SIZE, WL10_VERIFY_*)
        ├── user.py / attendance.py / finger.py / exception.py
        └── tests/                 # 91 offline tests (see pyzk_wl10/zk/tests/AGENTS.md)
```

## Key API — `zk.base.ZK`

**Constructor** (base.py L91): `ZK(ip, port=4370, timeout=60, password=0, force_udp=False, ommit_ping=False, verbose=False, encoding='UTF-8', wl10=False, tcp_maxseg=None, gap_timeout=1)`
- WL10 requires TCP: `force_udp=False` + `wl10=True`
- `tcp_maxseg` sets TCP_MAXSEG before connect (fixes PMTUD blackhole on low-MTU VPN routes); also auto-set to 1200 by the resilience path on persistent no-ACK (see below)
- `gap_timeout` sets the per-attempt inter-chunk silence gap (base.py `_wl10_read_raw_command`); gaps grow 1×/2×/4× across the 3 drain attempts, clamped by `timeout`. Default `1` (LAN behavior preserved). `None` is normalized to `1` (CLIs pass `None` via argparse default — a raw `None` would break the `min(gap_timeout * 2**attempt, __timeout)` arithmetic)

**General WL10 resilience mode** (applies to ALL wl10 devices, LAN + VPN — no per-IP config):
- `_wl10_read_raw_command` (base.py L799+) drains until either (a) a **terminal ACK** is detected in the TCP stream (`_wl10_scan_for_terminal_ack`: framed packet, `dsize>=8`, `pcmd in (CMD_ACK_OK=2000, CMD_ACK_ERROR=2001)`) → ends drain early (LAN: same-tick ACK, faster than old 1s wait), or (b) adaptive silence fallback: per-attempt gap `min(gap_timeout * 2**attempt, __timeout)` (1s → 2s → 4s with defaults). `__reply_id` is synced from the ACK rid even on `CMD_ACK_ERROR`; `__session_id` is NEVER updated from bulk packets.
- On 3 incomplete bulk attempts with **no terminal ACK observed** and `tcp_maxseg` unset, `_wl10_get_users`/`_wl10_get_attendance` auto-escalate: set `tcp_maxseg=1200`, `_wl10_reconnect()`, and retry up to **3 clamped recovery cycles** (each bounded by `min(__timeout, 5)`; break on a complete bulk). The multi-cycle loop handles flapping tunnels (observed ~50% up/down duty on the Bella Vista VPN) where a single recovery attempt is a coin flip. LAN devices complete attempt 1 (ACK arrives) → never reach escalation → zero behavior change.
- `_wl10_reconnect()` (base.py L777) — private recovery: marks `is_connect=False`, temporarily sets `ommit_ping=True` (ICMP may be blocked even when TCP is recoverable), calls `connect()` for a fresh handshake (resets `__session_id`/`__reply_id`). Deliberately does NOT use `disconnect()` (that sends `CMD_EXIT` first and can fail on a broken VPN). `__create_socket` closes the old socket before creating the replacement (fd-leak fix).

**Public WL10 API** (line refs in `pyzk_wl10/zk/base.py`):
- `wl10_get_users()` L1177 → `list[User]`
- `wl10_get_attendance()` L1185 → `list[Attendance]`
- `wl10_set_user(uid=None, name='', privilege=0, password='', group_id='', user_id='', card=0, verify_mode=1)` L1257 → `bool`
- `wl10_delete_user(uid=0, user_id='')` L1351 → `bool`
- `wl10_reboot()` L1402 → `bool` — marks connection closed on success

**Internal helpers** (`pyzk_wl10/zk/base.py`): `_wl10_read_sizes` L564, `_wl10_scan_for_terminal_ack` L733, `_wl10_reconnect` L777, `_wl10_read_raw_command` L799 (ACK-terminated drain + adaptive silence fallback; syncs `__reply_id` from terminal ACK; does NOT sync `__session_id`), `_wl10_parse_users` L1001, `_wl10_parse_attendance` L1112, `_wl10_read_ack` L1193 (syncs `__reply_id`), `_wl10_refresh_data` L1234.

## Usage

```python
from zk import ZK

zk = ZK('<DEVICE_IP>', timeout=20, ommit_ping=True, wl10=True)
zk.connect()
users = zk.wl10_get_users()
attendance = zk.wl10_get_attendance()

zk.wl10_set_user(uid=1000, name='Alice', privilege=0, user_id='999950', card=0)
zk.wl10_set_user(uid=1001, name='Bob', privilege=14, user_id='999951')  # ADMIN
zk.wl10_delete_user(uid=1000)
zk.wl10_reboot()          # connection becomes unusable after this
zk.disconnect()
```

## Test Suite

```bash
python3 -m pytest pyzk_wl10/zk/tests/ -q     # 91 passed
```

**HAZARD**: a bare `pytest` from the repo root collects the live-device
scripts (`test_wl10_write.py`, `test_runner_wl10.py` match `test_*.py`) —
always run with the explicit `pyzk_wl10/zk/tests/` path. Test conventions:
`pyzk_wl10/zk/tests/AGENTS.md`.

## Live-Device Scripts — NEVER IN CI

All take a device IP and touch real hardware. Never run casually or in CI:
- `listar_marcaciones.py IP [--since ... --csv --tcp-maxseg N --gap-timeout N]` — dump attendance (VPN-tuned flags)
- `wl10_probe_write.py IP --verbose` — writes/deletes real users
- `check_device.py` — Windows diagnostic, UIDs > 999
- `test_wl10_write.py IP --verbose` — live E2E (excluded from ruff)
- `test_runner_wl10.py IP1 IP2 --verbose` — writes 2 test users, NO delete

## Known Limitations

1. **Max uid = 1000** on AK3750 Ver 6.60 — device rejects uid > 1000 with `ACK_ERROR`. Use uids ≤ 1000 and user_id ≥ 9999 for test isolation.
2. **Delete persists** on tested devices. `wl10_delete_user` uses `pack('<H', uid)` (unsigned short) for uids up to 65535.
3. **Concurrent writes need `refresh_data()` between calls** — without `__reply_id` sync, writes after `wl10_get_users()` fail with `ACK_ERROR`.
4. **No fingerprint/template write support** — basic user records only.
5. **Badge/user_id limited to 6 chars** (max 999999, 24B ASCII field).
6. **`_wl10_read_sizes()` returns False** on this firmware — capacities not queryable.

## Commands

```bash
python3 -m pytest pyzk_wl10/zk/tests/ -q                          # offline suite (106)
python3 -m pytest pyzk_wl10/zk/tests/test_set_user.py -v          # single file
python3 listar_marcaciones.py <DEVICE_IP> --since 2026-07-01 --csv
python3 listar_marcaciones.py <DEVICE_IP> --since 2026-07-01 --tcp-maxseg 1200 --gap-timeout 3   # VPN path (manual overrides; resilience auto-applies without flags)
```

## Critical Implementation Notes

1. **Never break the read path** — `wl10_get_users` / `wl10_get_attendance` must stay unchanged.
2. **`__reply_id` must be synced** after every raw write AND bulk read. `_wl10_read_raw_command` syncs it from the ACK packet in the bulk stream; write/delete ACKs come from `_wl10_read_ack` → set `self._ZK__reply_id = ack_rid`.
3. **Use the raw TCP path for writes** — `__send_command` doesn't work with WL10 bulk responses.
4. **Badge pool**: 999950–999999 for test users (6-char limit).
5. **Privilege**: `0 = USER_DEFAULT`, `14 = USER_ADMIN`; anything else clamps to `0`. `verify_mode` must be in `WL10_VERIFY_MODES` (default 1 = fingerprint) or it clamps.
6. **`refresh_data()` required** between bulk operations to settle device state.
7. **`__session_id` is NOT updated** by `_wl10_read_raw_command` — bulk `CMD_DATA` packets have garbled sid bytes 4-7; updating from them corrupts the session.
8. **Inter-chunk drain gap = `min(gap_timeout * 2**attempt, self.__timeout)`** (base.py `_wl10_read_raw_command`) — grows 1×/2×/4× across the 3 drain attempts (VPN path tolerates jitter); LAN devices end on the terminal ACK in the same tick, so the gap is never exercised. `setsockopt(TCP_MAXSEG)` is wrapped in `try/except OSError` (Windows: option unsupported, bpo-23302).
