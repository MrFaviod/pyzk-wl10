"""Tests for wl10_reboot.

Rebooting a WL10 device must use the raw TCP path (not the buffered
``__send_command`` used by the standard ``restart()``) because the WL10
firmware does not respond to the buffered sequence — same reason the
write/delete/refresh operations use the raw path.
"""
from struct import pack, unpack
from unittest.mock import MagicMock
import pytest

from zk.base import ZK
from zk import const
from zk.exception import ZKErrorResponse


def _build_wl10_zk(ack_cmd=const.CMD_ACK_OK, ack_rid=100):
    """Build a mock-backed ZK instance for reboot tests."""
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
    inst._ZK__sock = MagicMock()
    inst._wl10_read_ack = MagicMock(return_value=(ack_cmd, ack_rid))
    return inst


def _first_send_frame(sock):
    """Return the full TCP frame from the LAST socket.send call.

    ``wl10_reboot`` sends a refresh_data command first (to settle device
    state) and then the actual CMD_RESTART frame — the reboot is the
    last one sent.
    """
    assert sock.send.call_count >= 1
    return sock.send.call_args_list[-1][0][0]


class TestWl10RebootGuard:
    """Guard clauses — no network needed."""

    def test_rejects_non_wl10(self, zk_instance):
        zk_instance.wl10 = False
        with pytest.raises(ZKErrorResponse, match='Not in WL10 mode'):
            zk_instance.wl10_reboot()

    def test_rejects_udp(self, zk_instance):
        zk_instance.tcp = False
        with pytest.raises(ZKErrorResponse, match='WL10 reboot requires TCP'):
            zk_instance.wl10_reboot()


class TestWl10RebootPayload:
    """Verify the on-wire frame (no ACK read needed)."""

    def test_payload_empty_restart_cmd(self):
        inst = _build_wl10_zk()
        inst.wl10_reboot()
        frame = _first_send_frame(inst._ZK__sock)
        # Frame layout: TCP top (8B: magic1, magic2, dsize) + ZK header (16B+)
        magic1, magic2, dsize = unpack('<HHI', frame[:8])
        assert magic1 == const.MACHINE_PREPARE_DATA_1
        assert magic2 == const.MACHINE_PREPARE_DATA_2
        cmd, chk, sid, rid = unpack('<HHHH', frame[8:16])
        assert cmd == const.CMD_RESTART, \
            f'Expected CMD_RESTART ({const.CMD_RESTART}), got {cmd}'
        assert sid == 12345
        assert len(frame) == 8 + 8, \
            f'Expected empty payload (16B frame), got {len(frame)}B'

class TestWl10RebootResponse:
    """Verify ACK response handling and reply_id synchronization."""

    def test_ack_ok_returns_true_and_disconnects(self):
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_OK, ack_rid=4242)
        assert inst.is_connect is True
        assert inst.wl10_reboot() is True
        assert inst.is_connect is False, \
            'Device reboots — connection must be marked closed'
        assert inst.next_uid == 1, 'next_uid must reset after reboot'
        assert inst._ZK__reply_id == 4242, \
            f'Expected 4242, got {inst._ZK__reply_id}'

    def test_ack_error_raises(self):
        inst = _build_wl10_zk(ack_cmd=const.CMD_ACK_ERROR, ack_rid=200)
        with pytest.raises(ZKErrorResponse, match='ACK_ERROR'):
            inst.wl10_reboot()

    def test_no_response_raises(self):
        inst = _build_wl10_zk(ack_cmd=0, ack_rid=0)
        with pytest.raises(ZKErrorResponse, match='No response'):
            inst.wl10_reboot()
