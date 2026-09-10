# AGENTS.md — pyzk_wl10/zk/tests (offline test suite)

Scope: conventions for the 199-test offline suite. Repo context:
`../../../AGENTS.md`. Library API: `../AGENTS.md`.

## Run

```bash
python3 -m pytest pyzk_wl10/zk/tests/ --collect-only -q  # 199 collected
python3 -m pytest pyzk_wl10/zk/tests/ -q                 # 199 passed, offline, no hardware
```

**HAZARD**: bare `pytest` from the repo root ALSO collects the live-device
scripts (`test_wl10_write.py`, `test_runner_wl10.py` match `test_*.py`) and
tries to hit real hardware. Always pass the explicit `pyzk_wl10/zk/tests/` path.

## Conventions

- **No real network**: tests monkeypatch `socket.socket` to fake the device.
- Tests poke name-mangled internals, e.g. `self._ZK__reply_id`, to assert ACK/session sync.
- Binary fixtures in `fixtures/` (9 × .bin): `user_normal_72.bin`, `user_empty_72.bin`, `user_linking_72.bin`, `bulk_users.bin`, `att_valid_22.bin`, `att_old_22.bin`, `att_zero_ts_22.bin`, `att_no_uid_22.bin`, `bulk_attendance.bin`.

## Fixtures & helpers

- `conftest.py` (46L): fixtures `zk_class` L23, `zk_instance` L29, `const_module` L44
- `helpers.py` (67L): `pack_user_record(...)` L24, `pack_attendance_record(...)` L41, `pack_bulk_response(records_bytes, record_size)` L50, `encode_zk_time(dt)` L60

## Per-file inventory (199 total)

| File | Tests | Covers |
|------|-------|--------|
| test_cli_listar.py | 3 | CLI arg parsing / listar_marcaciones |
| test_const.py | 4 | constant values and WL10 method surface |
| test_decode_time.py | 7 | timestamp decode |
| test_live_runner_wl10.py | 19 | read-only default; explicit single-write gates; evidence safety |
| test_parse_attendance.py | 10 | 22B record parse, uid=0 filtering, flag-aware dedup |
| test_parse_users.py | 11 | 72B user parse, template slots, badge preservation |
| test_scan_user_id.py | 8 | user_id scan / null-terminator |
| test_set_user.py | 50 | WL10 set/delete guards, preflight, payload, ACK, reply sync |
| test_socket_mss.py | 7 | TCP MSS / socket lifecycle |
| test_strip_header.py | 9 | section header variants and reply-id wrap |
| test_wl10_dispatch.py | 6 | native get/set/delete/refresh/restart WL10 dispatch |
| test_wl10_probe_read.py | 14 | read-only probe allowlist, capture, redaction, fail-closed guards |
| test_wl10_raw_drain.py | 13 | raw socket drain / framing / ACK termination |
| test_wl10_reboot.py | 9 | reboot guards, refresh ordering, ACK handling |
| test_wl10_resilience.py | 29 | completeness, dedup, missing-user, truncation, reconnect escalation |

## Adding a test

1. Create `test_<area>.py` in this directory (default pytest collection).
2. Use `zk_instance` / `zk_class` fixtures from conftest; monkeypatch the socket.
3. Build wire bytes with helpers.py; assert on `_ZK__reply_id` / `_ZK__session_id` when testing sync.
4. Never open a real socket here — live-device tests are standalone scripts at the repo root.
5. Verify: `python3 -m pytest pyzk_wl10/zk/tests/test_<area>.py -q`
