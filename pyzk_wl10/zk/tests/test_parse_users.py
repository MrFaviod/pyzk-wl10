import os

from helpers import FIXTURES_DIR, pack_bulk_response, pack_user_record

from zk.const import USER_ADMIN, WL10_USER_RECORD_SIZE


class TestParseUsers:
    """Test _wl10_parse_users and _wl10_decode_user_record."""

    def test_decode_normal(self, zk_instance):
        rec = pack_user_record(
            uid=5, privilege=USER_ADMIN, password=b'secret',
            name=b'Apellido, Nombre A',
            card=12345, group_id=b'1', user_id=b'101')
        user = zk_instance._wl10_decode_user_record(rec)
        assert user is not None
        assert user.uid == 5
        assert user.name == 'Apellido, Nombre A'
        assert user.privilege == USER_ADMIN
        assert user.password == 'secret'
        assert user.card == 12345
        assert user.group_id == '1'
        assert user.user_id == '101'

    def test_decode_linking_record(self, zk_instance):
        path = os.path.join(FIXTURES_DIR, 'user_linking_72.bin')
        with open(path, 'rb') as f:
            rec = f.read()
        user = zk_instance._wl10_decode_user_record(rec)
        assert user is not None
        # uid should be 7 (from pack_user_record)
        assert user.uid == 7
        # The fallback should have picked up '102' from the scan
        assert user.user_id == '102', \
            f'Expected user_id=102, got {user.user_id!r}'

    def test_decode_all_zeros(self, zk_instance):
        rec = b'\x00' * 72
        user = zk_instance._wl10_decode_user_record(rec)
        assert user is None

    def test_decode_no_name_but_uid(self, zk_instance):
        rec = pack_user_record(
            uid=12, name=b'', user_id=b'500')
        user = zk_instance._wl10_decode_user_record(rec)
        assert user is not None
        assert user.uid == 12
        assert user.name == 'NN-500'

    def test_parse_users_single(self, zk_instance):
        rec = pack_user_record(
            uid=5, name=b'Alice', user_id=b'100')
        raw = pack_bulk_response(rec, WL10_USER_RECORD_SIZE)
        users = zk_instance._wl10_parse_users(raw)
        assert len(users) == 1
        assert users[0].name == 'Alice'

    def test_parse_users_dedup(self, zk_instance):
        rec = pack_user_record(
            uid=5, name=b'Alice', user_id=b'100')
        raw = pack_bulk_response(rec * 2, WL10_USER_RECORD_SIZE)
        users = zk_instance._wl10_parse_users(raw)
        assert len(users) == 1, 'Should deduplicate by uid'

    def test_parse_users_empty(self, zk_instance):
        assert zk_instance._wl10_parse_users(b'') == []

    def test_nameless_records_are_not_users(self, zk_instance):
        """Ghost records must not be reported as people.

        The firmware interleaves sidecar records (fingerprint/linking
        storage) with the real user table. They carry a uid and often a
        scannable badge but no name, and the library used to synthesize
        ``NN-<badge>`` users for them — which inflates the user list and
        turns template storage into a delete/write target. They are kept
        out of the user list and reported separately instead.
        """
        real = pack_user_record(uid=5, name=b'Apellido, Nombre A', user_id=b'101')
        ghost = pack_user_record(uid=7, name=b'', user_id=b'102')
        raw = pack_bulk_response(real + ghost, WL10_USER_RECORD_SIZE)

        users = zk_instance._wl10_parse_users(raw)

        assert [user.uid for user in users] == [5]
        assert zk_instance._wl10_sidecar_uids == {7}

    def test_a_table_of_only_nameless_records_has_no_users(self, zk_instance):
        ghost = pack_user_record(uid=7, name=b'', user_id=b'102')
        raw = pack_bulk_response(ghost, WL10_USER_RECORD_SIZE)

        assert zk_instance._wl10_parse_users(raw) == []
        assert zk_instance._wl10_sidecar_uids == {7}

    def test_a_named_record_wins_over_its_sidecar_twin(self, zk_instance):
        """A uid may appear twice; the named record is the person."""
        ghost = pack_user_record(uid=7, name=b'', user_id=b'102')
        real = pack_user_record(uid=7, name=b'Real', user_id=b'102')
        raw = pack_bulk_response(ghost + real, WL10_USER_RECORD_SIZE)

        users = zk_instance._wl10_parse_users(raw)

        assert [user.name for user in users] == ['Real']
        assert zk_instance._wl10_sidecar_uids == {7}

    def test_template_slots_are_sidecars_not_users(self, zk_instance):
        """priv=0x31 storage is excluded, and the sidecar set starts clean."""
        slot = pack_user_record(uid=3, name=b'', user_id=b'101', privilege=0x31)
        raw = pack_bulk_response(slot, WL10_USER_RECORD_SIZE)

        assert zk_instance._wl10_parse_users(raw) == []
        assert zk_instance._wl10_template_uids == {3}
        assert zk_instance._wl10_sidecar_uids == set()

    def test_decode_template_slot_returns_none(self, zk_instance):
        # Fingerprint-template slots are interleaved in the user table with
        # privilege byte 0x31 (49). They must never be parsed as users.
        rec = pack_user_record(uid=3, privilege=0x31)
        assert zk_instance._wl10_decode_user_record(rec) is None

    def test_parse_users_skips_template_slots(self, zk_instance):
        real = pack_user_record(uid=5, name=b'Alice', user_id=b'100')
        slot = pack_user_record(uid=3, privilege=0x31)
        raw = pack_bulk_response(real + slot, WL10_USER_RECORD_SIZE)
        users = zk_instance._wl10_parse_users(raw)
        assert [u.uid for u in users] == [5]

    def test_parse_tracks_template_uids_and_resets_on_empty_table(self, zk_instance):
        real = pack_user_record(uid=5, name=b'Alice', user_id=b'100')
        slots = pack_user_record(uid=3, privilege=0x31) + pack_user_record(uid=7, privilege=0x31)
        users = zk_instance._wl10_parse_users(
            pack_bulk_response(real + slots, WL10_USER_RECORD_SIZE))
        assert [u.uid for u in users] == [5]
        assert zk_instance._wl10_template_uids == {3, 7}

        assert zk_instance._wl10_parse_users(
            pack_bulk_response(b'', WL10_USER_RECORD_SIZE)) == []
        assert zk_instance._wl10_template_uids == set()

    def test_decode_alphanumeric_badge_preserved(self, zk_instance):
        # A user with an alphanumeric badge (user_id='AB12') and a name that
        # contains digits ('Juan 123') must keep the badge as-is. The scan
        # fallback must NOT kick in just because user_id is non-numeric.
        rec = pack_user_record(
            uid=10, name=b'Juan 123', user_id=b'AB12')
        user = zk_instance._wl10_decode_user_record(rec)
        assert user is not None
        assert user.user_id == 'AB12'
