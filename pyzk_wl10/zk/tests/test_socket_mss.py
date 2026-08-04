"""Tests for TCP MSS override (tcp_maxseg) in ZK socket creation.

Regression test for the 192.168.110.152 case: the route to that device
(via site-to-site VPN) has a low MTU and drops large fragmented packets
(PMTUD blackhole).  Users (432B) fit in one packet, but attendance bulk
responses (up to ~3200B) exceed the MTU and never arrive -> timeout.
Forcing TCP_MAXSEG=1200 makes the device's segments fit the path MTU.
"""
import socket as _socket

import zk.base as base_module
from zk.base import ZK


def _build_zk(tcp_maxseg=None, force_udp=False):
    inst = object.__new__(ZK)
    inst.tcp = not force_udp
    inst.wl10 = True
    inst.verbose = False
    inst.encoding = 'UTF-8'
    inst.is_connect = False
    inst._ZK__address = ('192.168.110.152', 4370)
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
