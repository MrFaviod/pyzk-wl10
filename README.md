# pyzk_wl10 — pyzk fork for ZK WL10 / AK3750 devices

A fork of [`fananimi/pyzk`](https://github.com/fananimi/pyzk) that adds
support for the **WL10** (and its sibling **AK3750**) family of ZK
fingerprint-attendance terminals. Reverse-engineered against an
`AK3750WIFI_TFT` reporting firmware `Ver 6.60 May 19 2023`.

## What was wrong

The previous fork in this repo tried to *guess* the on-wire record
layouts by trying every plausible record size (8 / 16 / 24 / 28 / 40
bytes) and offset combination, then kept the one that produced the
**most** records. This heuristic is wrong: on the WL10 the device sends
**22-byte** attendance records, but the previous fork misidentified them
as 22 bytes only by accident and ended up reporting the wrong totals
(1028 records where the device actually stores 543).

The user record layout was similarly wrong: the previous code read
`uid` as 4 bytes at offset 0 and the `name` at offset 19, when in fact
the device uses the **standard pyzk 72-byte layout** with `uid` as 2
bytes at offset 0 and `name` at offset 11.



### Bulk response framing

Every bulk response (user table, attendance log, fingerprint table, …)
is framed as:

```
4 bytes  outer header      size of the section header + records
                           (does NOT include the 4 bytes itself)
4 bytes  device field      a constant like 0x00009fb0 in our captures;
                           reserved / unused
4 bytes  section header    byte count of the records section,
                           i.e. record_count * record_size
N*M bytes records
```

The outer header is `len(payload) - 8` (it doesn't include the device
field that follows it). The first 8 bytes are the same for both user
and attendance responses on the AK3750.

### User records — 72 bytes (STANDARD pyzk layout)

The WL10 uses the **same** 72-byte layout as the upstream pyzk library,
which is also what the Wireshark `zk6.lua` dissector documents:

| Offset | Size | Field             | Notes                            |
|-------:|-----:|-------------------|----------------------------------|
|   0-1  |   2  | `uid`             | `uint16` LE                      |
|   2    |   1  | `privilege`       | `0` = user, `14` = admin         |
|   3-10 |   8  | `password`        |                                  |
|  11-34 |  24  | `name`            | ASCII, NUL-padded                |
|  35-38 |   4  | `card`            | `uint32` LE                      |
|   39   |   1  | _padding_         |                                  |
|  40-46 |   7  | `group_id`        |                                  |
|   47   |   1  | _padding_         |                                  |
|  48-71 |  24  | `user_id` / badge | ASCII, NUL-padded                |

Some AK3750 firmwares emit one or two extra **"linking" records** with
no name, in which the `user_id` field at offsets 48-71 holds garbage
and the actual badge number lives somewhere in offsets 2-15. The parser
detects these by the empty name and falls back to scanning the whole
72-byte record for a 3-5 digit numeric string.

### Attendance records — 22 bytes (WL10-specific)

| Offset | Size | Field        | Notes                            |
|-------:|-----:|--------------|----------------------------------|
|   0-1  |   2  | `uid`        | `uint16` LE, device-internal     |
|   2-7  |   6  | `user_id`    | ASCII, NUL-padded (= the badge)  |
|   8-11 |   4  | _reserved_   | zero                             |
|   12   |   1  | `flag`       | always `0x01` on the observed FW |
|  13-16 |   4  | `timestamp`  | `uint32` LE, ZK format           |
|   17   |   1  | `status`     | `0` = In, `1` = Out             |
|  18-21 |   4  | _reserved_   | zero                             |

The ZK timestamp is the custom encoding: `(Y%100)*12*31*86400 +
(M-1)*31*86400 + (D-1)*86400 + h*3600 + m*60 + s` decoded back into a
`datetime` — see `pyzk.attendance.Attendance` for the reference.

### Read strategy

The standard pyzk buffered read (`CMD_DATA_WRRQ` 1503) does **not**
work against the AK3750 firmware: the device sends the data in a
single TCP packet whose length field under-reports the actual payload,
so the buffered reader truncates the response. We therefore prefer the
**raw socket read** (`_wl10_read_raw_command`), which drains the socket
until the device stops sending, and only fall back to the standard
buffered read if that yields nothing.

### Write strategy

The existing fork already implemented the **bulk read** (CMD=9 / USERTEMP_RRQ
via raw socket).  What was missing was the write path; this is implemented
by **CMD=8 (CMD_USER_WRQ)** with a 72-byte payload in the same
`HB8s24s4sx7sx24s` layout used for reads.  The device responds with a
simple ACK (CMD_ACK_OK=2000) — no buffered write sequence is needed.

| Operation      | Command              | Payload           | Response               | Status     |
|----------------|----------------------|-------------------|------------------------|------------|
| Write user     | CMD=8 (USER_WRQ)     | 72-byte record    | ACK_OK=2000            | **New**    |
| Delete user    | CMD=18 (DELETE_USER) | `pack('<H', uid)` | ACK_OK=2000 | **New** |
| Bulk read      | CMD=9 (USERTEMP_RRQ) | (empty) | PREPARE_DATA=1500+N*72 | Existing |
| Housekeeping   | CMD=1013 REFRESHDATA | (empty) | ACK_OK | Existing |

Deletion is confirmed to return ACK_OK on the AK3750, but persistence depends on
firmware. The method is not part of the read-only probe or safe runner.

Writes (and the existing bulk reads) go through the raw TCP path rather
than `__send_command`, because the standard buffered protocol does not
work with this firmware.

## Usage

```python
from zk import ZK

zk = ZK('<DEVICE_IP>', timeout=20, ommit_ping=True, force_udp=False,
        wl10=True)
zk.connect()

users = zk.wl10_get_users()         # list[User]
attendance = zk.wl10_get_attendance()  # list[Attendance]

# Write a new user (privilege 0 = USER_DEFAULT, 14 = USER_ADMIN)
zk.wl10_set_user(uid=1000, name='Alice', privilege=0,
                 user_id='999950', card=0)

# Delete a user (may return True but still leave the user on some FW)
zk.wl10_delete_user(uid=1000)

print(f'{len(users)} users, {len(attendance)} attendance records')
zk.disconnect()
```

The original non-WL10 API (`get_users()`, `get_attendance()`) also
works; when `wl10=True` the constructor routes through the WL10
parser.

## CLI

`listar_marcaciones.py <ip> [--since YYYY-MM-DD] [--until YYYY-MM-DD]
[--csv] [--password N] [--port N]`

```
$ python3 listar_marcaciones.py <DEVICE_IP> --since 2026-07-01
   Badge | Nombre                         | Fecha/Hora             | Status | Punch
--------------------------------------------------------------------------------
     138 | Apellido, Nombre A        | 2026-07-01 14:05:38    | 1      | 0
     209 | Apellido, Nombre B                  | 2026-07-01 15:24:53    | 1      | 0
     134 | Apellido, Nombre C        | 2026-07-01 15:26:32    | 1      | 0
     ...
```

## Files

```
.
├── listar_marcaciones.py   # CLI tool to dump attendance records
├── wl10_probe_read.py      # read-only raw capture; new output dir required
├── test_runner_wl10.py     # read-only default; write requires a fresh read gate
├── pyzk_wl10/              # the library
│   └── zk/
│       ├── __init__.py
│       ├── attendance.py
│       ├── base.py         # ZK class + WL10 read/write methods
│       ├── const.py        # protocol constants
│       ├── exception.py
│       ├── finger.py
│       ├── user.py
│       └── tests/          # 208 offline pytest tests
│           ├── conftest.py
│           ├── helpers.py
│           └── test_*.py
```
## Safe operation contract

`wl10_probe_read.py IP --output-dir DIR` is read-only and requires a new
output directory. It binds captures and `summary.json` to an opened directory
fd and refuses symlinked or replaced parents.

`test_runner_wl10.py IP` is read-only by default. `--write-one` requires one
literal IP, explicit UID and badge, a collision-safe `--evidence-json`, and a
fresh `--read-gate-json` proving identity, complete users and attendance,
parser success, template set presence, and baseline consistency. It performs
exactly one write and one readback; there is no retry, delete, reboot, or
cleanup. Evidence records disconnect failure as failure.

```bash
python3 test_runner_wl10.py IP --write-one --uid 8 --user-id 999950 --evidence-json /path/to/new-evidence.json --read-gate-json /path/to/read-gate.json
```

Task 6 did not validate the target device, so no write was performed and no
live success is inferred.
## Offline verification

```bash
python3 -m pytest pyzk_wl10/zk/tests/ --collect-only -q  # 208 collected
python3 -m pytest pyzk_wl10/zk/tests/ -q                 # offline suite
python3 wl10_probe_read.py --help
python3 test_runner_wl10.py --help
```
## Changelog vs the original fork

* **Replaced** the "guess-the-format-by-trying-six-candidates" parser
  with the verified 72-byte / 22-byte layouts documented above.
* **Replaced** the buggy raw socket reader (which used to corrupt
  `__session_id` / `__reply_id` and break subsequent commands) with a
  read-only version that just strips the TCP framing and returns the
  ZK payload.
* **Fixed** the user-record parser to use the standard 72-byte layout
  instead of the bogus custom layout (uid at offset 8, name at offset
  19, etc.) it had before.
* **Added** `_wl10_scan_user_id` to recover the badge number from
  "linking" records that the firmware emits in addition to the regular
  user records.
* **Added** `_decode_zk_time` (a public alias of `__decode_time` that the WL10 parser can call without name-mangling).
* **Added** 10 unit tests for the new write/delete methods; at that point, the offline suite contained 199 tests.
* **Updated** `const.WL10_ATT_RECORD_SIZE` from `28` to `22`.
* **Added** `wl10_set_user` and `wl10_delete_user` — the write path
  reverse-engineered from the AK3750 firmware.  CMD=8 (USER_WRQ) with
  72-byte payload writes the user; CMD=18 (DELETE_USER) deletes it
  (persistence depends on FW version).
* **Added** 10 unit tests for the new write/delete methods, bringing
  the historical total at that point to 49 tests.
