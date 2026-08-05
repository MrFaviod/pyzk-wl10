#!/usr/bin/env python3
"""
Live-device test runner for WL10/AK3750 terminals.

TESTING RULES (hard constraints):
  - user_id (badge) >= 9999 only — never touch real users (badges < 9999)
  - uid (internal 2-byte ID) <= 1000 — firmware limit on AK3750 Ver 6.60
  - NO overwrite: skip any uid or user_id that already exists on the device
  - NO delete: nothing is removed; test users are left on the device
  - Read-only safety checks before any write

Usage:
    python3 test_runner_wl10.py 192.168.120.80
    python3 test_runner_wl10.py 192.168.130.107
    python3 test_runner_wl10.py 192.168.120.80 --verbose
"""
import argparse
import os
import sys
from contextlib import suppress

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pyzk_wl10'))

from zk import ZK, const  # noqa: E402
from zk.exception import ZKErrorResponse  # noqa: E402

# uid (internal 2-byte ID) constraints:
#   - Device firmware (AK3750 Ver 6.60) rejects uid > 1000 with ACK_ERROR.
#   - Real users typically occupy uids 1-6; we start at 7 to avoid collisions.
#   - The script also checks the live baseline, so collisions are doubly prevented.
UID_MIN = 7        # avoid common admin/real-user uids
UID_MAX = 1000      # firmware hard limit

# user_id (badge string) constraints:
#   - User rule: test users must have badge >= 9999 to avoid real users.
#   - Device field is 24B but convention limits to 6 chars (max 999999).
USER_ID_MIN = 9999
USER_ID_MAX = 999999
TEST_USER_ID_START = 999950  # safe zone, 6 chars, >= USER_ID_MIN
ADMIN_USER_ID_START = 999951


def find_free_uid(existing_uids, start=UID_MIN, ceiling=UID_MAX):
    """Find the first free uid >= start that does not collide with existing users."""
    uid = start
    while uid <= ceiling:
        if uid not in existing_uids:
            return uid
        uid += 1
    return None


def find_free_user_id(existing_user_ids, start=TEST_USER_ID_START,
                      floor=USER_ID_MIN, ceiling=USER_ID_MAX):
    """Find the first free user_id >= start that does not collide with existing badges."""
    uid_num = max(start, floor)
    while uid_num <= ceiling:
        badge = str(uid_num)
        if badge not in existing_user_ids:
            return badge
        uid_num += 1
    return None


def run_tests(ip, verbose=False):
    """Run write/verify tests on a single device. Returns True if all pass."""
    print(f"{'=' * 60}")
    print(f"  WL10 Live Test Runner — {ip}")
    print(f"{'=' * 60}")
    print()

    zk = ZK(ip, timeout=20, ommit_ping=True, force_udp=False, wl10=True, verbose=verbose)

    results = []
    test_users_written = []

    try:
        zk.connect()
        print(f"[OK] Connected: {zk.get_device_name()} ({zk.get_platform()})")
        print(f"     Firmware: {zk.get_firmware_version()}")
        print(f"     Serial:   {zk.get_serialnumber()}")
        print()

        # --- Phase 1: Read-only baseline ---
        print("[1/4] Reading baseline users (read-only)...")
        baseline_users = zk.wl10_get_users()
        baseline_uids = {u.uid for u in baseline_users}
        baseline_user_ids = {u.user_id for u in baseline_users}
        print(f"      Baseline: {len(baseline_users)} users")
        real_uids = sorted(u for u in baseline_uids if u < UID_MIN)
        test_uids = sorted(u for u in baseline_uids if u >= UID_MIN)
        print(f"      Real uids (< {UID_MIN}): {real_uids}")
        if test_uids:
            print(f"      Test uids (>= {UID_MIN}): {test_uids}")
        print()

        # --- Phase 2: Pick free uids + user_ids (no overwrite) ---
        print(f"[2/4] Selecting free uid (<={UID_MAX}) and user_id (>={USER_ID_MIN})...")
        regular_uid = find_free_uid(baseline_uids)
        admin_uid = find_free_uid(baseline_uids | {regular_uid} if regular_uid else baseline_uids)

        if regular_uid is not None and admin_uid == regular_uid:
            admin_uid = find_free_uid(baseline_uids | {regular_uid}, start=regular_uid + 1)

        regular_user_id = find_free_user_id(baseline_user_ids, start=TEST_USER_ID_START)
        admin_user_id = find_free_user_id(
            baseline_user_ids | {regular_user_id} if regular_user_id else baseline_user_ids,
            start=ADMIN_USER_ID_START,
        )

        if regular_uid is None or admin_uid is None:
            print(f"      [FAIL] No free uids available in range {UID_MIN}-{UID_MAX}")
            return False
        if regular_user_id is None or admin_user_id is None:
            print(f"      [FAIL] No free user_ids available >= {USER_ID_MIN}")
            return False

        print(f"      Regular: uid={regular_uid}, user_id='{regular_user_id}'")
        print(f"      Admin:   uid={admin_uid}, user_id='{admin_user_id}'")
        print()

        # --- Phase 3: Write tests (no overwrite: confirmed free above) ---
        regular_name = f"TestReg {regular_uid}"
        admin_name = f"TestAdm {admin_uid}"

        # Test A: regular user
        print(f"[3/4] Writing regular user (uid={regular_uid}, user_id='{regular_user_id}', priv=USER)...")
        try:
            ok = zk.wl10_set_user(
                uid=regular_uid,
                name=regular_name,
                privilege=const.USER_DEFAULT,
                user_id=regular_user_id,
                card=0,
            )
            results.append(('write_regular', ok))
            print(f"      [{'OK' if ok else 'FAIL'}] wl10_set_user returned {ok}")
            test_users_written.append(regular_uid)
        except ZKErrorResponse as e:
            results.append(('write_regular', False))
            print(f"      [FAIL] {e}")
        print()

        # Test B: admin user
        print(f"[3/4] Writing admin user (uid={admin_uid}, user_id='{admin_user_id}', priv=ADMIN)...")
        try:
            ok = zk.wl10_set_user(
                uid=admin_uid,
                name=admin_name,
                privilege=const.USER_ADMIN,
                user_id=admin_user_id,
                card=0,
            )
            results.append(('write_admin', ok))
            print(f"      [{'OK' if ok else 'FAIL'}] wl10_set_user returned {ok}")
            test_users_written.append(admin_uid)
        except ZKErrorResponse as e:
            results.append(('write_admin', False))
            print(f"      [FAIL] {e}")
        print()

        # --- Phase 4: Verify (read-back, no delete) ---
        print("[4/4] Verifying writes (read-back)...")
        try:
            after_users = zk.wl10_get_users()
        except ZKErrorResponse as e:
            results.append(('readback', False))
            print(f"      [FAIL] readback failed: {e}")
            after_users = []

        after_uids = {u.uid for u in after_users}
        for label, uid, expected_name, expected_priv, expected_user_id in [
            ('regular', regular_uid, regular_name, const.USER_DEFAULT, regular_user_id),
            ('admin', admin_uid, admin_name, const.USER_ADMIN, admin_user_id),
        ]:
            if uid in after_uids:
                user = next((u for u in after_users if u.uid == uid), None)
                if user:
                    name_ok = user.name == expected_name
                    priv_ok = user.privilege == expected_priv
                    uid_ok = user.user_id == expected_user_id
                    passed = name_ok and priv_ok and uid_ok
                    results.append((f'verify_{label}', passed))
                    print(f"      [{'OK' if passed else 'WARN'}] uid={uid} "
                          f"name='{user.name}'(exp '{expected_name}') "
                          f"priv={user.privilege}(exp {expected_priv}) "
                          f"user_id='{user.user_id}'(exp '{expected_user_id}')")
            else:
                results.append((f'verify_{label}', False))
                print(f"      [FAIL] uid={uid} NOT found after write")
        print()

        # --- Summary ---
        print(f"{'─' * 60}")
        print("  SUMMARY")
        print(f"{'─' * 60}")
        passed = sum(1 for _, ok in results if ok)
        total = len(results)
        for label, ok in results:
            print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        print()
        print(f"  {passed}/{total} checks passed")
        if test_users_written:
            print(f"  Test users LEFT on device (no delete): {test_users_written}")
        print(f"{'─' * 60}")
        return passed == total

    except Exception as e:  # noqa: BLE001  # report and continue
        print(f"[ERROR] {e}")
        import traceback  # noqa: PLC0415
        traceback.print_exc()
        return False
    finally:
        with suppress(Exception):
            zk.disconnect()
            print("Disconnected")


def main():
    ap = argparse.ArgumentParser(description='WL10 live-device test runner')
    ap.add_argument('ips', nargs='+', help='One or more device IPs to test')
    ap.add_argument('--verbose', action='store_true', help='Verbose socket output')
    args = ap.parse_args()

    overall = True
    for ip in args.ips:
        ok = run_tests(ip, verbose=args.verbose)
        overall = overall and ok
        print()

    sys.exit(0 if overall else 1)


if __name__ == '__main__':
    main()
