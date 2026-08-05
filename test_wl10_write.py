#!/usr/bin/env python3
"""
Test wl10_set_user and wl10_delete_user against a live device.

This script tests the actual implementation in pyzk_wl10/zk/base.py,
not the standalone protocol implementation in wl10_probe_write.py.

Usage:
    python3 test_wl10_write.py 192.168.180.201
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pyzk_wl10'))

from zk import ZK, const
from zk.exception import ZKErrorResponse


def test_write_delete(ip):
    """Test write and delete operations on a live device."""
    print(f"Connecting to {ip}...")
    zk = ZK(ip, timeout=20, ommit_ping=True, force_udp=False, wl10=True, verbose=True)

    try:
        zk.connect()
        print(f"✓ Connected to {zk.get_device_name()} ({zk.get_platform()})")
        print(f"  Firmware: {zk.get_firmware_version()}")
        print(f"  Serial: {zk.get_serialnumber()}")
        print()

        # Read baseline
        print("Reading baseline users...")
        baseline_users = zk.wl10_get_users()
        print(f"  Baseline: {len(baseline_users)} users")
        baseline_uids = {u.uid for u in baseline_users}
        print()

        # Test 1: Write a regular user
        test_uid_1 = 1000
        test_name_1 = "Test User Regular"
        test_user_id_1 = "999950"

        print(f"Test 1: Writing regular user (uid={test_uid_1}, name='{test_name_1}', priv=0)...")
        try:
            result = zk.wl10_set_user(
                uid=test_uid_1,
                name=test_name_1,
                privilege=const.USER_DEFAULT,
                user_id=test_user_id_1,
                card=0
            )
            if result:
                print("  ✓ Write returned True")
            else:
                print("  ✗ Write returned False")
        except ZKErrorResponse as e:
            print(f"  ✗ Write failed: {e}")
            return False
        print()

        # Verify write
        print("Verifying write (reading users)...")
        users_after_write = zk.wl10_get_users()
        new_uids = {u.uid for u in users_after_write} - baseline_uids
        if test_uid_1 in new_uids:
            print(f"  ✓ User {test_uid_1} found after write")
            # Find the user and check details
            user = next((u for u in users_after_write if u.uid == test_uid_1), None)
            if user:
                print(f"    Name: {user.name}")
                print(f"    Privilege: {user.privilege}")
                print(f"    User ID: {user.user_id}")
        else:
            print(f"  ✗ User {test_uid_1} NOT found after write")
            print(f"    New UIDs: {new_uids}")
        print()

        # Test 2: Write an admin user
        test_uid_2 = 1001
        test_name_2 = "Test User Admin"
        test_user_id_2 = "999951"

        print(f"Test 2: Writing admin user (uid={test_uid_2}, name='{test_name_2}', priv=14)...")
        try:
            result = zk.wl10_set_user(
                uid=test_uid_2,
                name=test_name_2,
                privilege=const.USER_ADMIN,
                user_id=test_user_id_2,
                card=0
            )
            if result:
                print("  ✓ Write returned True")
            else:
                print("  ✗ Write returned False")
        except ZKErrorResponse as e:
            print(f"  ✗ Write failed: {e}")
            return False
        print()

        # Verify admin write
        print("Verifying admin write...")
        users_after_admin = zk.wl10_get_users()
        admin_uids = {u.uid for u in users_after_admin} - baseline_uids
        if test_uid_2 in admin_uids:
            print(f"  ✓ Admin user {test_uid_2} found after write")
            user = next((u for u in users_after_admin if u.uid == test_uid_2), None)
            if user:
                print(f"    Name: {user.name}")
                print(f"    Privilege: {user.privilege} (expected 14)")
                if user.privilege != const.USER_ADMIN:
                    print(f"  ⚠ WARNING: Privilege is {user.privilege}, expected {const.USER_ADMIN}")
        else:
            print(f"  ✗ Admin user {test_uid_2} NOT found after write")
        print()

        # Test 3: Delete the regular user
        print(f"Test 3: Deleting regular user (uid={test_uid_1})...")
        try:
            result = zk.wl10_delete_user(uid=test_uid_1)
            if result:
                print("  ✓ Delete returned True")
            else:
                print("  ✗ Delete returned False")
        except ZKErrorResponse as e:
            print(f"  ✗ Delete failed: {e}")
        print()

        # Verify delete
        print("Verifying delete...")
        users_after_delete = zk.wl10_get_users()
        remaining_uids = {u.uid for u in users_after_delete}
        if test_uid_1 not in remaining_uids:
            print(f"  ✓ User {test_uid_1} successfully deleted")
        else:
            print(f"  ⚠ User {test_uid_1} still present (expected on Ver 6.60 firmware)")
        print()

        # Test 4: Delete the admin user
        print(f"Test 4: Deleting admin user (uid={test_uid_2})...")
        try:
            result = zk.wl10_delete_user(uid=test_uid_2)
            if result:
                print("  ✓ Delete returned True")
            else:
                print("  ✗ Delete returned False")
        except ZKErrorResponse as e:
            print(f"  ✗ Delete failed: {e}")
        print()

        # Final state
        print("Final state:")
        final_users = zk.wl10_get_users()
        print(f"  Total users: {len(final_users)}")
        final_uids = {u.uid for u in final_users}
        test_users_remaining = final_uids & {test_uid_1, test_uid_2}
        if test_users_remaining:
            print(f"  ⚠ Test users still present: {test_users_remaining}")
            print("    (This is expected on Ver 6.60 firmware - delete ACKs but doesn't persist)")
        else:
            print("  ✓ All test users removed")
        print()

        return True

    except Exception as e:  # noqa: BLE001  # intentional: report E2E test failure and continue
        print(f"✗ Error: {e}")
        import traceback  # noqa: PLC0415  # lazy: only imported on failure path
        traceback.print_exc()
        return False
    finally:
        try:
            zk.disconnect()
            print("Disconnected")
        except Exception:  # noqa: BLE001  # intentional: cleanup must not mask the result
            pass


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 test_wl10_write.py <ip>")
        sys.exit(1)

    ip = sys.argv[1]
    success = test_write_delete(ip)
    sys.exit(0 if success else 1)
