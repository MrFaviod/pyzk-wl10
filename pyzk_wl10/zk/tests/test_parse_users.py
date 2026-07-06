import os
from helpers import FIXTURES_DIR, pack_user_record, pack_bulk_response
from zk.user import User
from zk.const import USER_ADMIN, USER_DEFAULT, WL10_USER_RECORD_SIZE


class TestParseUsers:
    """Test _wl10_parse_users and _wl10_decode_user_record."""

    def test_decode_normal(self, zk_instance):
        rec = pack_user_record(
            uid=5, privilege=USER_ADMIN, password=b'secret',
            name=b'Rivarola Enciso, Juan A',
            card=12345, group_id=b'1', user_id=b'138')
        user = zk_instance._wl10_decode_user_record(rec)
        assert user is not None
        assert user.uid == 5
        assert user.name == 'Rivarola Enciso, Juan A'
        assert user.privilege == USER_ADMIN
        assert user.password == 'secret'
        assert user.card == 12345
        assert user.group_id == '1'
        assert user.user_id == '138'

    def test_decode_linking_record(self, zk_instance):
        path = os.path.join(FIXTURES_DIR, 'user_linking_72.bin')
        with open(path, 'rb') as f:
            rec = f.read()
        user = zk_instance._wl10_decode_user_record(rec)
        assert user is not None
        # uid should be 7 (from pack_user_record)
        assert user.uid == 7
        # The fallback should have picked up '209' from the scan
        assert user.user_id == '209', \
            f'Expected user_id=209, got {user.user_id!r}'

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