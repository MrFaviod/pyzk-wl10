"""Tests for wl10_set_user and wl10_delete_user.

These tests verify guard clauses, privilege clamping, payload
construction, ACK response handling and reply_id synchronization.
Full end-to-end tests require a live device (see wl10_probe_write.py).
"""
from struct import pack, unpack
from unittest.mock import MagicMock
import pytest

from zk.base import ZK
from zk import const
from zk.const import WL10_USER_RECORD_SIZE, USER_DEFAULT, USER_ADMIN
from zk.exception import ZKErrorResponse


def _build_wl10_zk(ack_cmd=const.CMD_ACK_OK, ack_rid=100):
    """Build a mock-backed ZK instance for write/delete tests.

    Parameters:
        ack_cmd: command field that the mocked _wl10_read_ack returns.
        ack_rid: reply_id that the mocked _wl10_read_ack returns — used
                 to verify that wl10_set_user/wl10_delete_user
                 synchronise self.__reply_id after each operation.
    """
    inst = object.__new__(ZK)
    inst.wl10 = True
    inst.verbose = False
    inst.encoding = 'UTF-8'
    inst.tcp = True
    inst.is_connect = True
    inst._ZK__session_id = 12345
    inst._ZK__reply_id = 6789
    inst._ZK__timeout = 5
    inst.next_uid = 1
    inst.next_user_id = '1'
    # Mocked socket — captures TCP frames for inspection
    inst._ZK__sock = MagicMock()
    # Mocked ACK reader — new signature returns (cmd, rid) tuple
    inst._wl10_read_ack = MagicMock(return_value=(ack_cmd, ack_rid))
    # Mocked refresh_data so it doesn't call __send_command (which
    # expects a real socket).  We're testing our own raw path only.
    inst.refresh_data = MagicMock(return_value=True)
    return inst


def _first_send_payload(sock):
    """Return the command_string from the very first socket.send call
    (the user write, not the subsequent refresh_data call)."""
    assert sock.send.call_count >= 1
    sent = sock.send.call_args_list[0][0][0]
    return sent[16:]  # skip TCP top (8) + ZK header (8)


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

    def test_payload_72_bytes(self):
        inst = _build_wl10_zk()
        result = inst.wl10_set_user(
            uid=42, name='Alice', privilege=USER_DEFAULT,
            password='pw', group_id='2', user_id='999950', card=999)
        assert result is True
        payload = _first_send_payload(inst._ZK__sock)
        assert len(payload) == WL10_USER_RECORD_SIZE, \
            f'Expected {WL10_USER_RECORD_SIZE}B, got {len(payload)}B'
        uid_dec, priv_dec = unpack('<HB', payload[:3])
        assert uid_dec == 42
        assert priv_dec == USER_DEFAULT
        uid_str = payload[48:72].rstrip(b'\x00').decode()
        assert uid_str == '999950'

    def test_privilege_clamp_to_default(self):
        inst = _build_wl10_zk()
        inst.wl10_set_user(uid=1, privilege=1, user_id='999951')
        payload = _first_send_payload(inst._ZK__sock)
        assert payload[2] == USER_DEFAULT, 'Privilege should be clamped to 0'

    def test_privilege_admin_passthrough(self):
        inst = _build_wl10_zk()
        inst.wl10_set_user(uid=1, privilege=USER_ADMIN, user_id='999952')
        payload = _first_send_payload(inst._ZK__sock)
        assert payload[2] == USER_ADMIN, f'Expected {USER_ADMIN}, got {payload[2]}'


class TestWl10SetUserResponse:
    """Verify ACK response handling and reply_id synchronization."""

    def test_ack_error_raises(self):
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_ERROR, ack_rid=200)
        with pytest.raises(ZKErrorResponse, match='ACK_ERROR'):
            inst.wl10_set_user(uid=1, user_id='999950')

    def test_no_response_raises(self):
        inst = _build_wl10_zk(ack_cmd=0, ack_rid=0)
        with pytest.raises(ZKErrorResponse, match='No response'):
            inst.wl10_set_user(uid=1, user_id='999950')

    def test_reply_id_synchronised_after_write(self):
        """Critical: after a successful write, __reply_id must be updated
        from the ACK so that two consecutive writes don't desync."""
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_OK, ack_rid=4242)
        assert inst._ZK__reply_id == 6789
        inst.wl10_set_user(uid=1, user_id='999950')
        assert inst._ZK__reply_id == 4242, \
            f'Expected 4242, got {inst._ZK__reply_id}'

    def test_reply_id_synchronised_after_ack_error(self):
        """Even on ACK_ERROR the reply_id must be updated so the next
        command uses the correct sequence number."""
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_ERROR, ack_rid=7777)
        assert inst._ZK__reply_id == 6789
        try:
            inst.wl10_set_user(uid=1, user_id='999950')
        except ZKErrorResponse:
            pass
        assert inst._ZK__reply_id == 7777, \
            f'Expected 7777, got {inst._ZK__reply_id}'

    def test_consecutive_writes_use_incrementing_reply_id(self):
        """Simulate two writes in a row and verify the second command
        carries a different reply_id derived from the first ACK."""
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_OK, ack_rid=6790)
        # First write — sets __reply_id to 6790
        inst.wl10_set_user(uid=1, name='A', user_id='999950')
        first_sent = inst._ZK__sock.send.call_args_list[0][0][0]
        first_rid_in_wire = unpack('<4H', first_sent[8:16])[3]
        # Second write — should embed rid = 6790 + 1 = 6791
        inst._wl10_read_ack.return_value = (const.CMD_ACK_OK, 6791)
        inst.wl10_set_user(uid=2, name='B', user_id='999951')
        second_sent = inst._ZK__sock.send.call_args_list[1][0][0]
        second_rid_in_wire = unpack('<4H', second_sent[8:16])[3]
        # The next command embeds (current __reply_id) + 1
        assert second_rid_in_wire == 6791, \
            f'Expected second rid=6791, got {second_rid_in_wire}'


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
        inst = _build_wl10_zk()
        result = inst.wl10_delete_user(uid=0)
        assert result is False

    def test_reply_id_synchronised_after_delete(self):
        """Delete must also synchronise reply_id for subsequent commands."""
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_OK, ack_rid=5555)
        assert inst._ZK__reply_id == 6789
        inst.wl10_delete_user(uid=1)
        assert inst._ZK__reply_id == 5555, \
            f'Expected 5555, got {inst._ZK__reply_id}'

    def test_ack_error_returns_false(self):
        """ACK_ERROR on delete should return False (not raise)."""
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_ERROR, ack_rid=9001)
        result = inst.wl10_delete_user(uid=1)
        assert result is False
        # reply_id must still be updated
        assert inst._ZK__reply_id == 9001

    def test_delete_payload_format(self):
        """Verify the delete command_string is pack('<h', uid) — 2 bytes."""
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_OK, ack_rid=100)
        inst.wl10_delete_user(uid=42)
        payload = _first_send_payload(inst._ZK__sock)
        assert len(payload) == 2
        assert unpack('<h', payload)[0] == 42
