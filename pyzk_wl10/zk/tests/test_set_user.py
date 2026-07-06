"""Tests for wl10_set_user and wl10_delete_user.

These tests verify guard clauses, privilege clamping, and payload
construction.  Full end-to-end tests require a live device.
"""
from struct import pack
from unittest.mock import MagicMock
import pytest

from zk.const import WL10_USER_RECORD_SIZE, USER_DEFAULT, USER_ADMIN
from zk.exception import ZKErrorResponse


SAMPLE_RECORD_SIZE = 72


class TestWl10SetUserGuard:
    """Guard clauses — no network needed."""

    def test_rejects_non_wl10(self, zk_instance):
        zk_instance.wl10 = False
        with pytest.raises(ZKErrorResponse, match='Not in WL10 mode'):
            zk_instance.wl10_set_user(uid=1, user_id='999950')

    def test_rejects_udp(self, zk_instance):
        zk_instance.tcp = False
        with pytest.raises(ZKErrorResponse, match='WL10 write requires TCP'):
            zk_instance.wl10_set_user(uid=1, user_id='999950')


class TestWl10SetUserPayload:
    """Verify the on-wire payload format (no ACK read needed)."""

    def build_zk(self):
        """Create a ZK instance and patch the socket + ACK reader."""
        import sys
        from zk.base import ZK
        inst = object.__new__(ZK)
        inst.wl10 = True
        inst.verbose = False
        inst.encoding = 'UTF-8'
        inst.tcp = True
        inst.is_connect = True
        inst._ZK__session_id = 12345
        inst._ZK__reply_id = 6789
        inst.next_uid = 1
        inst.next_user_id = '1'
        # Patch socket — capture TCP frames for inspection
        inst._ZK__sock = MagicMock()
        # Mock _wl10_read_ack to return ACK_OK
        from zk import const
        inst._wl10_read_ack = MagicMock(return_value=const.CMD_ACK_OK)
        # Mock refresh_data so it doesn't call __send_command (which
        # expects a real socket).  We're testing the payload only.
        inst.refresh_data = MagicMock(return_value=True)
        return inst, inst._ZK__sock

    def _first_send_payload(self, sock):
        """Return the command_string from the very first socket.send call
        (the user write, not the subsequent refresh_data call)."""
        assert sock.send.call_count >= 1
        sent = sock.send.call_args_list[0][0][0]
        return sent[16:]  # skip TCP top (8) + ZK header (8)

    def test_payload_72_bytes(self):
        inst, sock = self.build_zk()
        result = inst.wl10_set_user(
            uid=42, name='Alice', privilege=USER_DEFAULT,
            password='pw', group_id='2', user_id='999950', card=999)
        assert result is True
        payload = self._first_send_payload(sock)
        assert len(payload) == WL10_USER_RECORD_SIZE, \
            f'Expected {WL10_USER_RECORD_SIZE}B, got {len(payload)}B'
        uid_dec, priv_dec = pack('<H', 42)[0], payload[2]
        from struct import unpack
        uid_dec, priv_dec = unpack('<HB', payload[:3])
        assert uid_dec == 42
        assert priv_dec == USER_DEFAULT
        uid_str = payload[48:72].rstrip(b'\x00').decode()
        assert uid_str == '999950'

    def test_privilege_clamp_to_default(self):
        inst, sock = self.build_zk()
        inst.wl10_set_user(uid=1, privilege=1, user_id='999951')
        payload = self._first_send_payload(sock)
        priv_dec = payload[2]
        assert priv_dec == USER_DEFAULT, 'Privilege should be clamped to 0'

    def test_privilege_admin_passthrough(self):
        inst, sock = self.build_zk()
        inst.wl10_set_user(uid=1, privilege=USER_ADMIN, user_id='999952')
        payload = self._first_send_payload(sock)
        priv_dec = payload[2]
        assert priv_dec == USER_ADMIN, f'Expected {USER_ADMIN}, got {priv_dec}'


class TestWl10SetUserResponse:
    """Verify ACK response handling."""

    def test_ack_error_raises(self):
        from zk.base import ZK
        from zk import const
        inst = object.__new__(ZK)
        inst.wl10 = True
        inst.verbose = False
        inst.encoding = 'UTF-8'
        inst.tcp = True
        inst._ZK__session_id = 12345
        inst._ZK__reply_id = 6789
        inst.next_uid = 1
        inst.next_user_id = '1'
        inst._ZK__sock = MagicMock()
        inst._wl10_read_ack = MagicMock(return_value=const.CMD_ACK_ERROR)
        with pytest.raises(ZKErrorResponse, match='ACK_ERROR'):
            inst.wl10_set_user(uid=1, user_id='999950')

    def test_no_response_raises(self):
        from zk.base import ZK
        from zk import const
        inst = object.__new__(ZK)
        inst.wl10 = True
        inst.verbose = False
        inst.encoding = 'UTF-8'
        inst.tcp = True
        inst._ZK__session_id = 12345
        inst._ZK__reply_id = 6789
        inst.next_uid = 1
        inst.next_user_id = '1'
        inst._ZK__sock = MagicMock()
        inst._wl10_read_ack = MagicMock(return_value=0)
        with pytest.raises(ZKErrorResponse, match='No response'):
            inst.wl10_set_user(uid=1, user_id='999950')


class TestWl10DeleteUser:
    """Guard clauses for delete_user."""

    def test_rejects_non_wl10(self, zk_instance):
        zk_instance.wl10 = False
        with pytest.raises(ZKErrorResponse, match='Not in WL10 mode'):
            zk_instance.wl10_delete_user(uid=1)

    def test_rejects_udp(self, zk_instance):
        zk_instance.tcp = False
        with pytest.raises(ZKErrorResponse, match='WL10 delete requires TCP'):
            zk_instance.wl10_delete_user(uid=1)

    def test_no_uid_no_user_id_returns_false(self):
        """When uid=0 and user_id='' we skip (no lookup), return False."""
        from zk.base import ZK
        inst = object.__new__(ZK)
        inst.wl10 = True
        inst.verbose = False
        inst.encoding = 'UTF-8'
        inst.tcp = True
        result = inst.wl10_delete_user(uid=0)
        assert result is False
