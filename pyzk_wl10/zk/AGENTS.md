# AGENTS.md — pyzk_wl10/zk (the `zk` package)

Scope: the `ZK` class and wire protocol layer. Repo overview, commands, and
limitations live in `../../AGENTS.md` — don't duplicate them here.

## Layout

| File | Lines | Contents |
|------|-------|----------|
| `base.py` | 2204 | `class ZK` — session, raw TCP read/write, WL10 bulk + write path |
| `const.py` | 137 | Wire constants: CMD_*, record sizes, WL10_VERIFY_* |
| `user.py` | 40 | `User` dataclass + `repack29` L30 / `repack73` L33 |
| `attendance.py` | 31 | `Attendance` dataclass + ZK timestamp decode |
| `finger.py` | 49 | Fingerprint template class |
| `exception.py` | 14 | ZKErrorConnection / ZKErrorResponse / ZKNetworkError |

## ZK constructor (base.py L91)

`ZK(ip, port=4370, timeout=60, password=0, force_udp=False, ommit_ping=False, verbose=False, encoding='UTF-8', wl10=False, tcp_maxseg=None)`
- WL10 requires TCP: `force_udp=False` (sets `self.tcp`) + `wl10=True`
- `tcp_maxseg` → TCP_MAXSEG in `__create_socket` L135 (PMTUD blackhole workaround)

## Public WL10 API (base.py)

| Method | Line | Notes |
|--------|------|-------|
| `wl10_get_users()` | 1177 | bulk read CMD=9 → `list[User]` |
| `wl10_get_attendance()` | 1185 | bulk read CMD=13 → `list[Attendance]` |
| `wl10_set_user(...)` | 1257 | CMD=8, 72B; has `verify_mode` param (default 1 = fingerprint) |
| `wl10_delete_user(uid, user_id)` | 1351 | CMD=18, `pack('<H', uid)`; persists on device |
| `wl10_reboot()` | 1402 | CMD=1004 (CMD_RESTART); marks connection closed on ACK_OK |

## Internal helpers (base.py)

- `_wl10_read_sizes` L564 — device capacities (returns False on this firmware)
- `_wl10_read_raw_command` L724 — raw socket send+recv; **syncs `__reply_id`**, NOT `__session_id`
- `_wl10_parse_users` L1001 / `_wl10_parse_attendance` L1112
- `_wl10_read_ack` L1193 — returns `(cmd, rid)`; caller MUST set `self._ZK__reply_id = ack_rid`
- `_wl10_refresh_data` L1234 — sends CMD_REFRESHDATA between operations

## Protocol constants (const.py)

`CMD_USER_WRQ=8, CMD_USERTEMP_RRQ=9, CMD_ATTLOG_RRQ=13, CMD_DELETE_USER=18, CMD_DELETE_USERTEMP=19, CMD_CONNECT=1000, CMD_RESTART=1004, CMD_REFRESHDATA=1013, CMD_PREPARE_DATA=1500, CMD_ACK_OK=2000, CMD_ACK_ERROR=2001, CMD_ACK_UNAUTH=2005, USER_DEFAULT=0, USER_ADMIN=14, WL10_USER_RECORD_SIZE=72, WL10_ATT_RECORD_SIZE=22`
- `WL10_VERIFY_MODES` L132, `WL10_VERIFY_DEFAULT=1` L137 (fingerprint)

## Pack formats

- User write (72B): `pack('HB8s24s4sB7sx24s', uid, privilege, pwd, name_pad24, card_u32_le, verify_mode, gid7, user_id24)`
- Delete: `pack('<H', uid)`
- Attendance record (22B): `uid(u16) | user_id(6B) | reserved(4B) | flag(u8) | ts(u32 LE) | status(u8) | reserved(4B)`
- Timestamp: `(Y%100)*12*31*86400 + (M-1)*31*86400 + (D-1)*86400 + h*3600 + m*60 + s`

## Rules

1. `__reply_id` synced after every raw write AND bulk read (`self._ZK__reply_id = ack_rid`).
2. `__session_id` NEVER updated from bulk reads — garbled sid bytes 4-7 corrupt the session.
3. `wl10_set_user`: privilege clamps to 0 unless 0/14; verify_mode clamps to default unless in `WL10_VERIFY_MODES`; payload must be exactly 72B or `ZKErrorResponse`.
4. Never change the read path (`wl10_get_users` / `wl10_get_attendance`).
