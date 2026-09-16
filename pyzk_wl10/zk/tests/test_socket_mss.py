"""Tests for TCP MSS override (tcp_maxseg) in ZK socket creation.

Regression test for a low-MTU VPN route: the path to the tested device
has a low MTU and drops large fragmented packets
(PMTUD blackhole).  Users (432B) fit in one packet, but attendance bulk
responses (up to ~3200B) exceed the MTU and never arrive -> timeout.
Forcing TCP_MAXSEG=1200 makes the device's segments fit the path MTU.
"""
import socket as _socket
from unittest.mock import MagicMock

import zk.base as base_module
from zk.base import ZK


def test_ping_uses_argv_without_shell(monkeypatch):
    import subprocess

    seen = {}
    monkeypatch.setattr(subprocess, 'call', lambda args, **kwargs: seen.update(args=args, kwargs=kwargs) or 0)
    zk = _build_zk()
    zk.helper = base_module.ZK_helper('127.0.0.1;echo pwned')
    assert zk.helper.test_ping() is True
    assert seen['args'] == ['ping', '-c', '1', '-W', '5', '127.0.0.1;echo pwned']
    assert seen['kwargs']['shell'] is False

def _build_zk(tcp_maxseg=None, force_udp=False):
    inst = object.__new__(ZK)
    inst.tcp = not force_udp
    inst.wl10 = True
    inst.verbose = False
    inst.encoding = 'UTF-8'
    inst.is_connect = False
    inst._ZK__address = ('203.0.113.10', 4370)
    inst._ZK__timeout = 5
    inst._ZK__session_id = 0
    inst._ZK__reply_id = 0
    inst._ZK__password = 0
    inst._ZK__data_recv = None
    inst._ZK__data = None
    inst.tcp_maxseg = tcp_maxseg
    inst.helper = None
    return inst


class TestSocketCreation:
    def test_socket_created_tcp_when_tcp_mode(self):
        zk = _build_zk()
        zk._ZK__create_socket()
        assert zk._ZK__sock is not None
        assert zk._ZK__sock.family == _socket.AF_INET
        assert zk._ZK__sock.type == _socket.SOCK_STREAM
        zk._ZK__sock.close()

    def test_socket_created_udp_when_udp_mode(self):
        zk = _build_zk(force_udp=True)
        zk._ZK__create_socket()
        assert zk._ZK__sock is not None
        assert zk._ZK__sock.type == _socket.SOCK_DGRAM
        zk._ZK__sock.close()

    def test_tcp_maxseg_none_does_not_set_mss(self, monkeypatch):
        """tcp_maxseg=None (default) must not set TCP_MAXSEG."""
        zk = _build_zk()
        seen = []
        real_setsockopt = _socket.socket.setsockopt

        class ProbeSocket(_socket.socket):
            def setsockopt(self, *args):
                seen.append(args)
                return real_setsockopt(self, *args)

        monkeypatch.setattr(base_module, 'socket', ProbeSocket)
        zk._ZK__create_socket()
        mss_calls = [a for a in seen if len(a) >= 2 and a[1] == _socket.TCP_MAXSEG]
        assert mss_calls == [], f'TCP_MAXSEG should not be set, got {mss_calls}'
        zk._ZK__sock.close()

    def test_tcp_maxseg_sets_setsockopt(self, monkeypatch):
        """tcp_maxseg=1200 must call setsockopt(IPPROTO_TCP, TCP_MAXSEG, 1200)."""
        zk = _build_zk(tcp_maxseg=1200)
        seen = []
        real_setsockopt = _socket.socket.setsockopt

        class ProbeSocket(_socket.socket):
            def setsockopt(self, *args):
                seen.append(args)
                return real_setsockopt(self, *args)

        monkeypatch.setattr(base_module, 'socket', ProbeSocket)
        zk._ZK__create_socket()
        assert any(
            args[0] == _socket.IPPROTO_TCP
            and args[1] == _socket.TCP_MAXSEG
            and args[2] == 1200
            for args in seen
        ), f'expected setsockopt(IPPROTO_TCP, TCP_MAXSEG, 1200) in {seen}'
        zk._ZK__sock.close()


class TestSetsockoptSafety:
    """Windows safety: Winsock has no TCP_MAXSEG (bpo-23302), so
    setsockopt(IPPROTO_TCP, TCP_MAXSEG, ...) raises OSError and must be
    swallowed by __create_socket — while still applying on platforms that
    support it."""

    def test_tcp_maxseg_setsockopt_oserror_is_swallowed(self, monkeypatch):
        """setsockopt raising OSError (Windows) must not propagate out of
        __create_socket; the socket must still be created."""
        zk = _build_zk(tcp_maxseg=1200)
        real_setsockopt = _socket.socket.setsockopt

        class FailingSocket(_socket.socket):
            def setsockopt(self, *args):
                if len(args) >= 3 and args[1] == _socket.TCP_MAXSEG:
                    raise OSError('TCP_MAXSEG not supported')
                return real_setsockopt(self, *args)

        monkeypatch.setattr(base_module, 'socket', FailingSocket)
        zk._ZK__create_socket()  # must not raise
        assert zk._ZK__sock is not None
        zk._ZK__sock.close()

    def test_tcp_maxseg_setsockopt_success_still_applies(self, monkeypatch):
        """On platforms where TCP_MAXSEG exists, setsockopt must still be
        called exactly once with (IPPROTO_TCP, TCP_MAXSEG, 1200)."""
        zk = _build_zk(tcp_maxseg=1200)
        seen = []
        real_setsockopt = _socket.socket.setsockopt

        class RecordingSocket(_socket.socket):
            def setsockopt(self, *args):
                seen.append(args)
                return real_setsockopt(self, *args)

        monkeypatch.setattr(base_module, 'socket', RecordingSocket)
        zk._ZK__create_socket()
        assert seen == [(_socket.IPPROTO_TCP, _socket.TCP_MAXSEG, 1200)], \
            f'expected exactly one setsockopt(IPPROTO_TCP, TCP_MAXSEG, 1200), got {seen}'
        zk._ZK__sock.close()


class TestSocketTeardown:
    """__create_socket must close the previous socket before creating a new
    one so reconnects don't leak file descriptors."""

    def test_create_socket_closes_old_socket(self, monkeypatch):
        """A pre-existing ``__sock`` (MagicMock) must be closed exactly once
        and replaced by the freshly created socket."""
        zk = _build_zk()
        old_sock = MagicMock()
        zk._ZK__sock = old_sock

        new_sock = MagicMock()

        def fake_socket(*_args, **_kwargs):
            return new_sock

        monkeypatch.setattr(base_module, 'socket', fake_socket)
        zk._ZK__create_socket()
        assert old_sock.close.called
        assert old_sock.close.call_count == 1
        assert zk._ZK__sock is new_sock
        assert zk._ZK__sock is not old_sock
