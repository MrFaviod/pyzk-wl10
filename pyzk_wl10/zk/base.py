import codecs
import sys
import time
from datetime import datetime
from socket import AF_INET, IPPROTO_TCP, SOCK_DGRAM, SOCK_STREAM, TCP_MAXSEG, socket, timeout
from struct import error as StructError, pack, unpack

from . import const
from .attendance import Attendance
from .exception import ZKErrorConnection, ZKErrorResponse, ZKNetworkError
from .finger import Finger
from .user import User


def safe_cast(val, to_type, default=None):
    try:
        return to_type(val)
    except (ValueError, TypeError):
        return default


def make_commkey(key, session_id, ticks=50):
    key = int(key)
    session_id = int(session_id)
    k = 0
    for i in range(32):
        if (key & (1 << i)):  # noqa: SIM108  # bit-twiddling reads clearer as if/else
            k = (k << 1 | 1)
        else:
            k = k << 1
    k += session_id
    k = pack(b'I', k)
    k = unpack(b'BBBB', k)
    k = pack(
        b'BBBB',
        k[0] ^ ord('Z'),
        k[1] ^ ord('K'),
        k[2] ^ ord('S'),
        k[3] ^ ord('O'))
    k = unpack(b'HH', k)
    k = pack(b'HH', k[1], k[0])
    B = 0xff & ticks
    k = unpack(b'BBBB', k)
    k = pack(
        b'BBBB',
        k[0] ^ B,
        k[1] ^ B,
        B,
        k[3] ^ B)
    return k


class ZK_helper:
    def __init__(self, ip, port=4370):
        self.address = (ip, port)
        self.ip = ip
        self.port = port

    def test_ping(self):
        import platform  # noqa: PLC0415  # lazy import: only needed for ping
        import subprocess  # noqa: PLC0415  # lazy import: only needed for ping
        ping_str = "-n 1" if platform.system().lower() == "windows" else "-c 1 -W 5"
        args = "ping " + " " + ping_str + " " + self.ip
        need_sh = platform.system().lower() != "windows"
        return subprocess.call(args,  # noqa: S603  # ip comes from the caller's own config, not untrusted input
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               shell=need_sh) == 0

    def test_tcp(self):
        self.client = socket(AF_INET, SOCK_STREAM)
        self.client.settimeout(10)
        res = self.client.connect_ex(self.address)
        self.client.close()
        return res

    def test_udp(self):
        self.client = socket(AF_INET, SOCK_DGRAM)
        self.client.settimeout(10)


class ZK:
    """Main ZK device client.

    Supports both the standard pyzk protocol (ZEM500/ZEM600/iClock/...)
    and the WL10/AK3750 family. The latter is opt-in via
    ``wl10=True``; see the README and the :class:`_wl10_*` methods
    below for the protocol details.
    """

    def __init__(self, ip, port=4370, timeout=60, password=0, force_udp=False, ommit_ping=False, verbose=False, encoding='UTF-8', wl10=False, tcp_maxseg=None, gap_timeout=1):
        User.encoding = encoding
        self.__address = (ip, port)
        self.__sock = socket(AF_INET, SOCK_DGRAM)
        self.__sock.settimeout(timeout)
        self.__timeout = timeout
        self.__password = password
        self.__session_id = 0
        self.__reply_id = const.USHRT_MAX - 1
        self.__data_recv = None
        self.__data = None

        self.is_connect = False
        self.is_enabled = True
        self.helper = ZK_helper(ip, port)
        self.force_udp = force_udp
        self.ommit_ping = ommit_ping
        self.verbose = verbose
        self.encoding = encoding
        self.tcp = not force_udp
        self.users = 0
        self.fingers = 0
        self.records = 0
        self.dummy = 0
        self.cards = 0
        self.fingers_cap = 0
        self.users_cap = 0
        self.rec_cap = 0
        self.faces = 0
        self.faces_cap = 0
        self.fingers_av = 0
        self.users_av = 0
        self.rec_av = 0
        self.next_uid = 1
        self.next_user_id = '1'
        self.user_packet_size = 28
        self.end_live_capture = False
        self.wl10 = wl10
        self._wl10_template_uids = set()
        self.tcp_maxseg = tcp_maxseg
        # Normalize None -> 1: CLIs pass gap_timeout=None (argparse
        # default) explicitly, which would otherwise poison the drain's
        # adaptive-gap arithmetic with a TypeError.
        self.gap_timeout = 1 if gap_timeout is None else gap_timeout
        self.platform = ''

    def __nonzero__(self):
        return self.is_connect

    def __create_socket(self):
        if getattr(self, '_ZK__sock', None) is not None:
            try:
                self.__sock.close()
            except OSError:
                pass
        if self.tcp:
            self.__sock = socket(AF_INET, SOCK_STREAM)
            self.__sock.settimeout(self.__timeout)
            if self.tcp_maxseg:
                try:
                    self.__sock.setsockopt(IPPROTO_TCP, TCP_MAXSEG, self.tcp_maxseg)
                except OSError:
                    pass  # e.g. Windows: TCP_MAXSEG not supported (bpo-23302)
            self.__sock.connect_ex(self.__address)
        else:
            self.__sock = socket(AF_INET, SOCK_DGRAM)
            self.__sock.settimeout(self.__timeout)

    def __create_tcp_top(self, packet):
        length = len(packet)
        top = pack('<HHI', const.MACHINE_PREPARE_DATA_1, const.MACHINE_PREPARE_DATA_2, length)
        return top + packet

    def __create_header(self, command, command_string, session_id, reply_id):
        buf = pack('<4H', command, 0, session_id, reply_id) + command_string
        buf = unpack(f'8B{len(command_string)}B', buf)
        checksum = unpack('H', self.__create_checksum(buf))[0]
        reply_id += 1
        if reply_id >= const.USHRT_MAX:
            reply_id -= const.USHRT_MAX
        buf = pack('<4H', command, checksum, session_id, reply_id)
        return buf + command_string

    def __create_checksum(self, p):
        length = len(p)
        checksum = 0
        while length > 1:
            checksum += unpack('H', pack('BB', p[0], p[1]))[0]
            p = p[2:]
            if checksum > const.USHRT_MAX:
                checksum -= const.USHRT_MAX
            length -= 2
        if length:
            checksum = checksum + p[-1]
        while checksum > const.USHRT_MAX:
            checksum -= const.USHRT_MAX
        checksum = ~checksum
        while checksum < 0:
            checksum += const.USHRT_MAX
        return pack('H', checksum)

    def __test_tcp_top(self, packet):
        if len(packet) <= 8:
            return 0
        tcp_header = unpack('<HHI', packet[:8])
        if tcp_header[0] == const.MACHINE_PREPARE_DATA_1 and tcp_header[1] == const.MACHINE_PREPARE_DATA_2:
            return tcp_header[2]
        return 0

    def __send_command(self, command, command_string=b'', response_size=8):
        if command not in [const.CMD_CONNECT, const.CMD_AUTH] and not self.is_connect:
            raise ZKErrorConnection("instance are not connected.")
        buf = self.__create_header(command, command_string, self.__session_id, self.__reply_id)
        try:
            if self.tcp:
                top = self.__create_tcp_top(buf)
                self.__sock.send(top)
                self.__tcp_data_recv = self.__sock.recv(response_size + 8)
                self.__tcp_length = self.__test_tcp_top(self.__tcp_data_recv)
                if self.__tcp_length == 0:
                    raise ZKNetworkError("TCP packet invalid")
                self.__header = unpack('<4H', self.__tcp_data_recv[8:16])
                self.__data_recv = self.__tcp_data_recv[8:]
            else:
                self.__sock.sendto(buf, self.__address)
                self.__data_recv = self.__sock.recv(response_size)
                self.__header = unpack('<4H', self.__data_recv[:8])
        except Exception as e:
            raise ZKNetworkError(str(e))

        self.__response = self.__header[0]
        self.__reply_id = self.__header[3]
        self.__data = self.__data_recv[8:]
        if self.__response in [const.CMD_ACK_OK, const.CMD_PREPARE_DATA, const.CMD_DATA]:
            return {
                'status': True,
                'code': self.__response
            }
        return {
            'status': False,
            'code': self.__response
        }

    def __ack_ok(self):
        buf = self.__create_header(const.CMD_ACK_OK, b'', self.__session_id, const.USHRT_MAX - 1)
        try:
            if self.tcp:
                top = self.__create_tcp_top(buf)
                self.__sock.send(top)
            else:
                self.__sock.sendto(buf, self.__address)
        except Exception as e:
            raise ZKNetworkError(str(e))

    def __get_data_size(self):
        response = self.__response
        if response == const.CMD_PREPARE_DATA:
            size = unpack('I', self.__data[:4])[0]
            return size
        else:
            return 0

    def __reverse_hex(self, hex):
        data = ''
        for i in reversed(range(len(hex) / 2)):
            data += hex[i * 2:(i * 2) + 2]
        return data

    def __decode_time(self, t):
        t = unpack("<I", t)[0]
        second = t % 60
        t = t // 60
        minute = t % 60
        t = t // 60
        hour = t % 24
        t = t // 24
        day = t % 31 + 1
        t = t // 31
        month = t % 12 + 1
        t = t // 12
        year = t + 2000
        d = datetime(year, month, day, hour, minute, second)
        return d

    @staticmethod
    def _decode_zk_time(value):
        """Decode a ZK 4-byte timestamp (uint32) to a :class:`datetime`.

        Returns ``None`` for value 0 or for out-of-range dates.
        Public alias of the private ``__decode_time`` so the WL10
        parser can use it without name-mangling.
        """
        if not value:
            return None
        second = value % 60
        value //= 60
        minute = value % 60
        value //= 60
        hour = value % 24
        value //= 24
        day = value % 31 + 1
        value //= 31
        month = value % 12 + 1
        value //= 12
        year = value + 2000
        try:
            return datetime(year, month, day, hour, minute, second)
        except (ValueError, OverflowError):
            return None

    def __decode_timehex(self, timehex):
        year, month, day, hour, minute, second = unpack("6B", timehex)
        year += 2000
        d = datetime(year, month, day, hour, minute, second)
        return d

    def __encode_time(self, t):
        d = (
            ((t.year % 100) * 12 * 31 + ((t.month - 1) * 31) + t.day - 1) *
            (24 * 60 * 60) + (t.hour * 60 + t.minute) * 60 + t.second
        )
        return d

    def connect(self):
        self.end_live_capture = False
        if not self.ommit_ping and not self.helper.test_ping():
            raise ZKNetworkError(f"can't reach device (ping {self.__address[0]})")
        if not self.force_udp and self.helper.test_tcp() == 0:
            self.user_packet_size = 72
        self.__create_socket()
        self.__session_id = 0
        self.__reply_id = const.USHRT_MAX - 1
        if self.wl10 and self.tcp:
            # Flapping VPN: a single blocking CMD_CONNECT attempt is a coin
            # flip (~50% up/down duty on the Bella Vista tunnel). Retry with
            # a clamped per-attempt timeout so a dead tunnel fails fast;
            # LAN devices reply on attempt 1 and never exercise the loop.
            old_timeout = self.__timeout
            try:
                for attempt in range(3):
                    self.__timeout = min(self.__timeout, 5)
                    try:
                        cmd_response = self.__send_command(const.CMD_CONNECT)
                        break
                    except ZKNetworkError:
                        if attempt == 2:
                            raise
                        self.__create_socket()
                        self.__session_id = 0
                        self.__reply_id = const.USHRT_MAX - 1
            finally:
                self.__timeout = old_timeout
        else:
            cmd_response = self.__send_command(const.CMD_CONNECT)
        self.__session_id = self.__header[2]
        if cmd_response.get('code') == const.CMD_ACK_UNAUTH:
            if self.verbose:
                print("try auth")
            command_string = make_commkey(self.__password, self.__session_id)
            cmd_response = self.__send_command(const.CMD_AUTH, command_string)
        if cmd_response.get('status'):
            self.is_connect = True
            try:
                self.platform = self.get_platform()
            except Exception:
                self.platform = ''
            try:
                device_name = self.get_device_name()
            except Exception:
                device_name = ''
            if 'WL10' in device_name or 'AK3750' in self.platform or self.wl10:
                self.wl10 = True
                if self.verbose:
                    print("Detected WL10/AK3750 platform - using WL10 mode")
            return self
        else:
            if cmd_response["code"] == const.CMD_ACK_UNAUTH:
                raise ZKErrorResponse("Unauthenticated")
            if self.verbose:
                print("connect err response {} ".format(cmd_response["code"]))
            raise ZKErrorResponse("Invalid response: Can't connect")

    def disconnect(self):
        cmd_response = self.__send_command(const.CMD_EXIT)
        if cmd_response.get('status'):
            self.is_connect = False
            if self.__sock:
                self.__sock.close()
            return True
        else:
            raise ZKErrorResponse("can't disconnect")

    def enable_device(self):
        cmd_response = self.__send_command(const.CMD_ENABLEDEVICE)
        if cmd_response.get('status'):
            self.is_enabled = True
            return True
        else:
            raise ZKErrorResponse("Can't enable device")

    def disable_device(self):
        cmd_response = self.__send_command(const.CMD_DISABLEDEVICE)
        if cmd_response.get('status'):
            self.is_enabled = False
            return True
        else:
            raise ZKErrorResponse("Can't disable device")

    def get_firmware_version(self):
        cmd_response = self.__send_command(const.CMD_GET_VERSION, b'', 1024)
        if cmd_response.get('status'):
            firmware_version = self.__data.split(b'\x00')[0]
            return firmware_version.decode()
        else:
            raise ZKErrorResponse("Can't read firmware version")

    def get_serialnumber(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'~SerialNumber\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            serialnumber = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            serialnumber = serialnumber.replace(b'=', b'')
            return serialnumber.decode()
        else:
            raise ZKErrorResponse("Can't read serial number")

    def get_platform(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'~Platform\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            platform = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            platform = platform.replace(b'=', b'')
            return platform.decode()
        else:
            raise ZKErrorResponse("Can't read platform name")

    def get_mac(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'MAC\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            mac = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            return mac.decode()
        else:
            raise ZKErrorResponse("can't read mac address")

    def get_device_name(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'~DeviceName\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            device = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            return device.decode()
        else:
            return ""

    def get_face_version(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'ZKFaceVersion\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            response = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            return safe_cast(response, int, 0) if response else 0
        else:
            return None

    def get_fp_version(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'~ZKFPVersion\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            response = self.__data.split(b'=', 1)[-1].split(b'\x00')[0]
            response = response.replace(b'=', b'')
            return safe_cast(response, int, 0) if response else 0
        else:
            raise ZKErrorResponse("can't read fingerprint version")

    def _clear_error(self, command_string=b''):
        # __send_command has side effects (mutates __response/__reply_id); the
        # return dict is intentionally discarded here
        self.__send_command(const.CMD_ACK_ERROR, command_string, 1024)
        self.__send_command(const.CMD_ACK_UNKNOWN, command_string, 1024)
        self.__send_command(const.CMD_ACK_UNKNOWN, command_string, 1024)
        self.__send_command(const.CMD_ACK_UNKNOWN, command_string, 1024)

    def get_extend_fmt(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'~ExtendFmt\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            fmt = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
            return safe_cast(fmt, int, 0) if fmt else 0
        else:
            self._clear_error(command_string)
            return None

    def get_user_extend_fmt(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'~UserExtFmt\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            fmt = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
            return safe_cast(fmt, int, 0) if fmt else 0
        else:
            self._clear_error(command_string)
            return None

    def get_face_fun_on(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'FaceFunOn\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            response = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
            return safe_cast(response, int, 0) if response else 0
        else:
            self._clear_error(command_string)
            return None

    def get_compat_old_firmware(self):
        command = const.CMD_OPTIONS_RRQ
        command_string = b'CompatOldFirmware\x00'
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            response = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
            return safe_cast(response, int, 0) if response else 0
        else:
            self._clear_error(command_string)
            return None

    def get_network_params(self):
        ip = self.__address[0]
        mask = b''
        gate = b''
        cmd_response = self.__send_command(const.CMD_OPTIONS_RRQ, b'IPAddress\x00', 1024)
        if cmd_response.get('status'):
            ip = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
        cmd_response = self.__send_command(const.CMD_OPTIONS_RRQ, b'NetMask\x00', 1024)
        if cmd_response.get('status'):
            mask = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
        cmd_response = self.__send_command(const.CMD_OPTIONS_RRQ, b'GATEIPAddress\x00', 1024)
        if cmd_response.get('status'):
            gate = (self.__data.split(b'=', 1)[-1].split(b'\x00')[0])
        return {'ip': ip.decode(), 'mask': mask.decode(), 'gateway': gate.decode()}

    def get_pin_width(self):
        command = const.CMD_GET_PINWIDTH
        command_string = b' P'
        response_size = 9
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            width = self.__data.split(b'\x00')[0]
            return bytearray(width)[0]
        else:
            raise ZKErrorResponse("can't get pin width")

    def free_data(self):
        command = const.CMD_FREE_DATA
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("can't free data")

    def read_sizes(self):
        if self.wl10 and self._wl10_read_sizes():
            return
        # Fall through to standard method if WL10 mode failed
        command = const.CMD_GET_FREE_SIZES
        response_size = 1024
        cmd_response = self.__send_command(command, b'', response_size)
        if cmd_response.get('status'):
            if self.verbose:
                print(codecs.encode(self.__data, 'hex'))
            if len(self.__data) >= 80:
                fields = unpack('20i', self.__data[:80])
                self.users = fields[4]
                self.fingers = fields[6]
                self.records = fields[8]
                self.dummy = fields[10]
                self.cards = fields[12]
                self.fingers_cap = fields[14]
                self.users_cap = fields[15]
                self.rec_cap = fields[16]
                self.fingers_av = fields[17]
                self.users_av = fields[18]
                self.rec_av = fields[19]
                self.__data = self.__data[80:]
            if len(self.__data) >= 12:
                fields = unpack('3i', self.__data[:12])
                self.faces = fields[0]
                self.faces_cap = fields[2]
            return True
        else:
            raise ZKErrorResponse("can't read sizes")

    def _wl10_read_sizes(self):
        """Try to read device sizes in WL10 mode.
        Uses direct CMD_GET_FREE_SIZES (50) command."""
        try:
            command = const.CMD_GET_FREE_SIZES
            response_size = 1024
            cmd_response = self.__send_command(command, b'', response_size)
            if cmd_response.get('status') and len(self.__data) >= 80:
                fields = unpack('20i', self.__data[:80])
                self.users = fields[4]
                self.fingers = fields[6]
                self.records = fields[8]
                self.dummy = fields[10]
                self.cards = fields[12]
                self.fingers_cap = fields[14]
                self.users_cap = fields[15]
                self.rec_cap = fields[16]
                self.fingers_av = fields[17]
                self.users_av = fields[18]
                self.rec_av = fields[19]
                return True
        except Exception:
            pass
        return False

    def unlock(self, time=3):
        command = const.CMD_UNLOCK
        command_string = pack("I", int(time) * 10)
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Can't open door")

    def __str__(self):
        proto = "tcp" if self.tcp else "udp"
        return (
            f"ZK {proto}://{self.__address[0]}:{self.__address[1]} "
            f"users[{self.user_packet_size}]:{self.users}/{self.users_cap} "
            f"fingers:{self.fingers}/{self.fingers_cap}, "
            f"records:{self.records}/{self.rec_cap} "
            f"faces:{self.faces}/{self.faces_cap}"
        )

    def restart(self):
        command = const.CMD_RESTART
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            self.is_connect = False
            self.next_uid = 1
            return True
        else:
            raise ZKErrorResponse("can't restart device")

    def get_time(self):
        command = const.CMD_GET_TIME
        response_size = 1032
        cmd_response = self.__send_command(command, b'', response_size)
        if cmd_response.get('status'):
            return self.__decode_time(self.__data[:4])
        else:
            raise ZKErrorResponse("can't get time")

    def set_time(self, timestamp):
        command = const.CMD_SET_TIME
        command_string = pack(b'I', self.__encode_time(timestamp))
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("can't set time")

    def poweroff(self):
        command = const.CMD_POWEROFF
        command_string = b''
        response_size = 1032
        cmd_response = self.__send_command(command, command_string, response_size)
        if cmd_response.get('status'):
            self.is_connect = False
            self.next_uid = 1
            return True
        else:
            raise ZKErrorResponse("can't poweroff")

    def refresh_data(self):
        if self.wl10:
            return self._wl10_refresh_data()
        command = const.CMD_REFRESHDATA
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("can't refresh data")

    def test_voice(self, index=0):
        command = const.CMD_TESTVOICE
        command_string = pack("I", index)
        cmd_response = self.__send_command(command, command_string)
        return bool(cmd_response.get('status'))

    # ================== WL10 / AK3750 Specific Methods ==================
    #
    # The WL10 (and its sibling AK3750) platform differs from the
    # standard pyzk protocol in two ways, observed by reverse
    # engineering against AK3750WIFI_TFT firmware "Ver 6.60 May 19 2023":
    #
    # * Bulk responses are framed with a 4-byte section header at the
    #   start (the 4-byte outer header is already stripped by the TCP
    #   layer). The section header holds the byte size of the records
    #   section that follows; for N records of M bytes it equals N * M.
    #
    # * User records use the standard 72-byte pyzk layout (NOT a custom
    #   one as the previous fork claimed):
    #     0-1   uid (uint16 LE)
    #     2     privilege (uint8)        -- 0=user, 14=admin
    #     3-10  password (8 bytes)
    #     11-34 name (24 bytes, ASCII, null-terminated)
    #     35-38 card (uint32 LE)
    #     39    padding
    #     40-46 group_id (7 bytes)
    #     47    padding
    #     48-71 user_id / badge (24 bytes, ASCII, null-terminated)
    #
    # * Attendance records are 22 bytes long, NOT 8/16/28/40:
    #     0-1   uid (uint16 LE)
    #     2-7   user_id (6 bytes, ASCII, null-terminated)
    #     8-11  reserved (zeros)
    #     12    flag (always 0x01 on the observed firmwares)
    #     13-16 timestamp (uint32 LE, ZK format)
    #     17    status (0=Check-In, 1=Check-Out, 2..5=other states)
    #     18-21 reserved (zeros)
    #
    # The previous implementation guessed record layouts from a small
    # set of candidates and picked whichever produced the most records,
    # which produced the wrong totals (1028 records instead of 543, and
    # 1001 instead of 1058). The implementation below uses the actual
    # documented layout.

    @staticmethod
    def _wl10_extract_tcp_payloads(raw_data):
        """Concatenate the ZK payloads carried in a stream of TCP packets.

        Each TCP packet is framed as
        ``MACHINE_PREPARE_DATA_1, MACHINE_PREPARE_DATA_2, length``
        (8 bytes) followed by a ZK header (8 bytes) and ``length - 8``
        bytes of payload. The function walks the byte stream and
        extracts every payload it finds.
        """
        payload = b''
        pos = 0
        while pos < len(raw_data) - 8:
            magic1, magic2, dsize = unpack('<HHI', raw_data[pos:pos + 8])
            if (magic1 == const.MACHINE_PREPARE_DATA_1
                    and magic2 == const.MACHINE_PREPARE_DATA_2
                    and 0 < dsize <= len(raw_data) - pos):
                zk_data = raw_data[pos + 16:pos + 8 + dsize]
                payload += zk_data
                pos += 8 + dsize
            else:
                pos += 1
        return payload

    @staticmethod
    def _wl10_scan_for_terminal_ack(raw_data):
        """Walk the framed TCP stream and return the LAST terminal ACK.

        WL10 frames every ZK packet as
        ``MACHINE_PREPARE_DATA_1 | MACHINE_PREPARE_DATA_2 | dsize``
        (8 bytes) followed by an 8-byte ZK header whose first uint16 is
        the command code. A bulk response ends with one terminal ACK
        (``CMD_ACK_OK`` or ``CMD_ACK_ERROR``); draining can stop as
        soon as a complete terminal ACK is present.

        Oracle (bg_58bcb925) verdict: drain termination is an
        *optimization*, not the sole completion condition — incomplete
        bulks still rely on the silence fallback + declared-length
        check. ACK_ERROR terminates draining but is NOT success. We
        record the last valid ACK (single terminal ACK in normal
        traffic) for reply-id synchronization.

        Returns ``(pcmd, rid)`` for the last valid framed terminal ACK,
        or ``None`` when no terminal ACK is present. A frame is a valid
        ACK candidate when: magic matches, ``dsize >= 8``, the full
        frame is present, and ``pcmd`` is ``CMD_ACK_OK`` (2000) or
        ``CMD_ACK_ERROR`` (2001). Never treats ``CMD_PREPARE_DATA``
        (1500) or ``CMD_DATA`` (1501) as terminal — their sid bytes
        are bulk-checksum data, not session state, and must not corrupt
        the session (see ``__session_id`` note in ``_wl10_read_raw_command``).
        """
        last_ack = None
        pos = 0
        while pos + 16 <= len(raw_data):
            magic1, magic2, dsize = unpack('<HHI', raw_data[pos:pos + 8])
            if (magic1 == const.MACHINE_PREPARE_DATA_1
                    and magic2 == const.MACHINE_PREPARE_DATA_2
                    and dsize >= 8
                    and dsize <= len(raw_data) - pos - 8):
                pcmd, _ck, _sid, rid = unpack(
                    '<4H', raw_data[pos + 8:pos + 16])
                if pcmd in (const.CMD_ACK_OK, const.CMD_ACK_ERROR):
                    last_ack = (pcmd, rid)
                pos += 8 + dsize
            else:
                pos += 1
        return last_ack

    def _wl10_reconnect(self):
        """Re-handshake after a broken WL10 connection.

        Oracle (bg_58bcb925): the existing :meth:`disconnect` sends
        ``CMD_EXIT`` first and only closes the socket on success, which
        fails on a broken VPN link and would block recovery. This helper
        instead marks the connection down, skips ping (ICMP may be
        unavailable even when TCP recovery is possible — see the
        Fortinet/Ubiquiti route notes), and lets :meth:`connect`
        perform a fresh handshake.

        ``__create_socket`` closes the old socket before re-creating,
        so no file descriptor leaks.

        The handshake is clamped to a short timeout: ``connect()`` blocks
        ``self.__timeout`` (e.g. 15s) per ``__send_command`` call on a
        broken link, and the MSS-escalation path can call this in a loop.
        Clamping bounds the worst-case recovery cost; ``__create_socket``
        re-applies the clamped value to the new socket, and the original
        timeout is restored afterwards.
        """
        self.is_connect = False
        old_ommit_ping = self.ommit_ping
        old_timeout = self.__timeout
        self.ommit_ping = True
        self.__timeout = min(self.__timeout, 5)
        try:
            self.connect()
        finally:
            self.__timeout = old_timeout
            self.ommit_ping = old_ommit_ping

    def _wl10_read_raw_command(self, command_code):
        """Send a command and read the entire response via raw recv.

        Resilient drain (Oracle bg_58bcb925 — general WL10 mode, no
        per-IP special-casing):

        - **ACK-terminated**: after each ``recv`` we scan the accumulated
          stream for a complete framed ``CMD_ACK_OK`` /
          ``CMD_ACK_ERROR`` packet and break the inner drain loop as soon
          as one is present. On a healthy LAN the terminal ACK lands in
          the first chunk, so the drain ends *faster* than the historical
          hard 1s silence timeout; over a jittery VPN the drain waits for
          the ACK that signals "device done", which removes the gap-based
          truncation that used to discard late-arriving segments.
        - **Adaptive silence fallback**: when no terminal ACK is observed
          (older firmware hedge), we stop on a silence timeout that grows
          across the existing three attempts — ``gap_timeout``,
          ``2 * gap_timeout``, ``4 * gap_timeout`` — each clamped by
          ``self.__timeout``. The default ``gap_timeout`` is one second,
          preserving LAN behaviour; a caller may raise it via the
          ``gap_timeout`` kwarg / ``--gap-timeout`` CLI flag for known
          slow links.
        - **Declared-length completeness** is checked by the caller via
          :meth:`_wl10_bulk_is_complete`; this method only drains.

        Bookkeeping mirroring the pre-resilience behavior:

        - ``__reply_id`` IS updated from the terminal ACK's rid (the
          device advances its reply_id by one per command and echoes it
          back, so the client must track it to stay in sync). Updated
          even when the extracted payload is empty or the ACK is
          ``CMD_ACK_ERROR`` (per Oracle: ERROR still advances rid).
        - ``__session_id`` is deliberately NOT updated: bulk reads
          contain three ZK packets (``CMD_PREPARE_DATA``, ``CMD_DATA``,
          ``CMD_ACK_OK``) and the middle one's header bytes 4-7 are
          bulk-checksum data, not a real sid/rid. Updating
          ``__session_id`` from that garbled value corrupts the session.
        - ``self._wl10_last_ack`` stores the last observed terminal ACK
          as ``(pcmd, rid)`` so bulk callers can decide whether to
          escalate MSS (no terminal ACK across all retries implies
          PMTUD blackhole — segments never arrived).
        """
        if not self.tcp:
            return b''

        # Instances built via object.__new__ in tests may lack attrs set
        # via __init__; provide safe defaults so the drain works without
        # a full constructor round-trip. None (CLI argparse default)
        # normalizes to the 1s default too — __init__ already does this,
        # but fixtures bypass the constructor.
        self.gap_timeout = getattr(self, 'gap_timeout', 1) or 1
        self.tcp_maxseg = getattr(self, 'tcp_maxseg', None)
        self._wl10_last_ack = None

        for attempt in range(3):
            buf = self.__create_header(command_code, b'', self.__session_id, self.__reply_id)
            top = self.__create_tcp_top(buf)
            try:
                self.__sock.send(top)
            except Exception as e:
                if self.verbose:
                    print(f'  [raw] send error: {e}')
                return b''

            all_raw = b''
            # First chunk: bounded by min(__timeout, 10) so a dead
            # device doesn't pay the full timeout per attempt. Oracle:
            # making every initial read wait the full timeout slows
            # dead-device recovery unnecessarily.
            self.__sock.settimeout(min(self.__timeout, 10))
            # Silence fallback grows across attempts, clamped by the
            # connection timeout. Attempt 1 = gap_timeout (default 1 =
            # historical LAN behaviour); 2 = 2x; 3 = 4x.
            silence_gap = min(self.gap_timeout * (2 ** attempt),
                              self.__timeout)
            try:
                while True:
                    chunk = self.__sock.recv(65536)
                    if not chunk:
                        break
                    all_raw += chunk
                    # If a complete terminal ACK is now present, stop
                    # draining — the device signaled end-of-response.
                    last_ack = self._wl10_scan_for_terminal_ack(all_raw)
                    if last_ack is not None:
                        self._wl10_last_ack = last_ack
                        break
                    # Otherwise wait up to the adaptive silence gap for
                    # the next chunk / ACK.
                    self.__sock.settimeout(silence_gap)
            except timeout:
                pass
            except Exception as e:
                if self.verbose:
                    print(f'  [raw] recv error: {e}')
            finally:
                self.__sock.settimeout(self.__timeout)

            if all_raw:
                payload = self._wl10_extract_tcp_payloads(all_raw)
                if self.verbose:
                    print(f'  [raw] cmd={command_code} attempt={attempt + 1} '
                          f'raw={len(all_raw)} payload={len(payload)} '
                          f'ack={self._wl10_last_ack}')
                # If we saw a terminal ACK, sync __reply_id from it and
                # return — done regardless of payload size (the device
                # told us it finished, possibly with an error).
                if self._wl10_last_ack is not None:
                    _pcmd, rid = self._wl10_last_ack
                    self.__reply_id = rid
                    if self.verbose:
                        print(f'  [raw] synced reply_id={rid} from '
                              f'cmd={self._wl10_last_ack[0]}')
                    return payload
                # No terminal ACK: accept any payload >= 8 (the
                # silence fallback found *something*); otherwise retry.
                if payload and len(payload) >= 8:
                    return payload
                if self.verbose:
                    print('  [raw] payload too small / no ACK, retrying')

        return b''

    def _wl10_read_bulk_data(self, command_code, function_code=0):
        """Read a bulk response from the WL10/AK3750 device.

        The standard pyzk buffered read (``read_with_buffer``) does not
        work reliably against this firmware: the device sends the
        data in a single TCP packet whose length field under-reports
        the actual payload, so the buffered reader truncates the
        response. We therefore prefer the raw socket read, which
        drains the socket until the device stops sending.

        The returned buffer still has the 4-byte section header at the
        start; callers strip it before parsing records.
        """
        if not self.wl10:
            raise ZKErrorResponse('Not in WL10 mode')

        # --- Strategy 1: raw socket read (the one that works) ---
        if self.tcp:
            try:
                data = self._wl10_read_raw_command(command_code)
                if data and len(data) >= 4:
                    if self.verbose:
                        print(f'  [wl10_bulk] strategy=raw len={len(data)}')
                    return data
            except Exception as e:
                if self.verbose:
                    print(f'  [wl10_bulk] strategy=raw failed: {e}')

        # --- Strategy 2: standard buffered read (fallback, UDP only) ---
        # Deliberately gated to the UDP path. This firmware under-reports
        # the payload length in a single TCP packet, so read_with_buffer
        # truncates on TCP AND blocks self.__timeout per call on a broken
        # link (it sends via __send_command). For TCP/WL10 the raw read
        # above is the only reliable path; running this fallback on TCP
        # just burns seconds of blocking time before returning b''.
        if not self.tcp:
            try:
                data, _size = self.read_with_buffer(
                    command_code, function_code, 0)
                if data and len(data) >= 4:
                    if self.verbose:
                        print(f'  [wl10_bulk] strategy=buffered len={len(data)}')
                    return data
            except Exception as e:
                if self.verbose:
                    print(f'  [wl10_bulk] strategy=buffered failed: {e}')

        return b''

    @staticmethod
    def _wl10_strip_header(raw_data, record_size):
        """Strip the WL10 framing header and return ``(records, n)``.

        The observed layout (reverse engineered from AK3750WIFI_TFT
        firmware "Ver 6.60 May 19 2023") is::

            4 bytes  outer header  (size of section header + records,
                                    NOT including itself nor the
                                    device field that follows)
            4 bytes  device field  (a constant like 0x00009fb0 in our
                                    captures; reserved/unused by us)
            4 bytes  section header (byte count of the records
                                    section, i.e. record_count *
                                    record_size)
            N*M bytes records

        Returns ``(records_bytes, declared_record_count)``.
        """
        if not raw_data or len(raw_data) < 12:
            return raw_data, len(raw_data) // record_size

        outer = unpack('I', raw_data[:4])[0]
        section = unpack('I', raw_data[8:12])[0]

        # The standard 12-byte layout: section header at offset 8
        # holds the byte count of the records that follow.
        if (section == len(raw_data) - 12
                and section % record_size == 0):
            return raw_data[12:], section // record_size

        # Variant: section header at offset 4 (4-byte form, e.g. when
        # the read_with_buffer path returns the section header at the
        # start).
        if len(raw_data) >= 8:
            section4 = unpack('I', raw_data[4:8])[0]
            if (section4 == len(raw_data) - 8
                    and section4 % record_size == 0):
                return raw_data[8:], section4 // record_size

        # Last resort: the first 4 bytes are a record count.
        if outer <= (len(raw_data) - 4) // record_size:
            return raw_data[4:], outer

        return raw_data, len(raw_data) // record_size

    @staticmethod
    def _wl10_bulk_is_complete(raw_data, record_size):
        """Return True if a bulk response is not truncated.

        The WL10 framing (12-byte header + N*M records) announces the
        record section size in the header. On unstable links the device
        can stop sending before the full body arrives; ``_wl10_strip_header``
        then falls back to interpreting the outer field as a record
        count and silently drops the missing tail. This gate detects the
        mismatch so the caller can retry instead of accepting a partial
        table::

            True  - header's declared section == bytes actually received
            False - fewer bytes than announced (truncated) or no data
        """
        if not raw_data or len(raw_data) < 12:
            return False

        section = unpack('I', raw_data[8:12])[0]
        if section == len(raw_data) - 12 and section % record_size == 0:
            return True

        # Variant: section header at offset 4 (buffered read path).
        if len(raw_data) >= 8:
            section4 = unpack('I', raw_data[4:8])[0]
            if section4 == len(raw_data) - 8 and section4 % record_size == 0:
                return True

        return False

    def _wl10_get_users(self):
        """Read and parse the user table from the device.

        Resilient bulk read (Oracle bg_58bcb925 — general WL10 mode):

        - Retries truncated reads (``free_data`` + short backoff between
          attempts) instead of returning a partial table, which used to
          happen silently on unstable links (Bella Vista vpn-device).
        - If all three attempts return an incomplete bulk AND none of
          them observed a terminal ACK (no ``CMD_ACK_OK`` /
          ``CMD_ACK_ERROR`` in the drained bytes — segments never
          arrived, a classic PMTUD blackhole), and the caller did not
          opt out via an explicit ``tcp_maxseg``, reconnect once with
          an automatic MSS of 1200 and retry the bulk a single extra
          time. Self-configuring; LAN devices that drain cleanly never
          reach this path.
        """
        last_raw = b''
        saw_ack = False
        for attempt in range(3):
            if attempt > 0:
                # Settle the device between bulk reads; the AK3750
                # firmware often needs CMD_FREE_DATA before it will
                # service the next bulk command.
                try:  # noqa: SIM105  # keep exception visible for retry semantics
                    self.free_data()
                except Exception:
                    pass
                time.sleep(0.5)
            raw = self._wl10_read_bulk_data(const.CMD_USERTEMP_RRQ, const.FCT_USER)
            if self._wl10_bulk_is_complete(raw, const.WL10_USER_RECORD_SIZE):
                return self._wl10_parse_users(raw)
            last_raw = raw
            if getattr(self, '_wl10_last_ack', None) is not None:
                saw_ack = True
            if self.verbose:
                print(f'  [wl10_users] truncated/empty bulk (attempt {attempt + 1}), retrying')

        # MSS escalation: PMTUD blackhole recovery for degraded VPN paths.
        # Only when every prior attempt drained without a terminal ACK
        # (segments dropped before reaching us) and the caller did not
        # already set tcp_maxseg. Reconnect with MSS=1200 and retry a few
        # clamped cycles: on a flapping tunnel a single recovery attempt
        # is a coin flip, and each cycle is bounded by the clamp below.
        if not saw_ack and self.tcp and not getattr(self, 'tcp_maxseg', None):
            if self.verbose:
                print('  [wl10_users] no terminal ACK seen across 3 attempts; '
                      'reconnecting with MSS=1200 (PMTUD recovery)')
            for _ in range(3):
                try:
                    self.tcp_maxseg = 1200
                    self._wl10_reconnect()
                    # Clamp the retry handshake+bulk so a half-broken VPN can't
                    # block __timeout (e.g. 15s) per __send_command call here —
                    # free_data and the buffered drain both stall on a broken
                    # link, and the recovery window closes before it completes.
                    old_timeout = self.__timeout
                    self.__timeout = min(self.__timeout, 5)
                    try:
                        self.free_data()
                        raw = self._wl10_read_bulk_data(
                            const.CMD_USERTEMP_RRQ, const.FCT_USER)
                    finally:
                        self.__timeout = old_timeout
                    if self._wl10_bulk_is_complete(raw, const.WL10_USER_RECORD_SIZE):
                        return self._wl10_parse_users(raw)
                    last_raw = raw
                except Exception as e:
                    if self.verbose:
                        print(f'  [wl10_users] MSS recovery failed: {e}')

        raise ZKErrorResponse(
            f'Cannot read a complete user table from the device '
            f'(got {len(last_raw)} bytes after 3 attempts)')

    def _wl10_get_attendance(self):
        """Read and parse the attendance log from the device.

        Users are read first so that we can resolve names / badges for
        every attendance record even if the second read disrupts the
        socket (which happens on some AK3750 firmwares).

        PMTUD recovery mirrors :meth:`_wl10_get_users`: when every
        attempt drained without a terminal ACK the device's bulk
        segments never reached us, so we reconnect with MSS=1200 and
        retry once. See :meth:`_wl10_get_users` for the full rationale.
        """
        users = self._wl10_get_users()
        users_map = self._wl10_build_users_map(users)

        # After the user bulk read the device sometimes needs a
        # CMD_FREE_DATA + small pause before it will service the
        # next bulk command. Try them in sequence with retries.
        raw = b''
        saw_ack = False
        for _ in range(3):
            try:  # noqa: SIM105  # keep exception visible for the loop's retry semantics
                self.free_data()
            except Exception:
                pass
            raw = self._wl10_read_bulk_data(const.CMD_ATTLOG_RRQ, const.FCT_ATTLOG)
            if (raw and len(raw) >= 8
                    and self._wl10_bulk_is_complete(raw, const.WL10_ATT_RECORD_SIZE)):
                break
            if getattr(self, '_wl10_last_ack', None) is not None:
                saw_ack = True

        # MSS escalation (PMTUD blackhole recovery — see _wl10_get_users).
        # A few clamped recovery cycles instead of one: on a flapping
        # tunnel (observed on the Bella Vista VPN) a single attempt is a
        # coin flip; each cycle is bounded by the clamp below.
        if (not self._wl10_bulk_is_complete(raw, const.WL10_ATT_RECORD_SIZE)
                and not saw_ack and self.tcp
                and not getattr(self, 'tcp_maxseg', None)):
            if self.verbose:
                print('  [wl10_att] no terminal ACK seen across 3 attempts; '
                      'reconnecting with MSS=1200 (PMTUD recovery)')
            for _ in range(3):
                try:
                    self.tcp_maxseg = 1200
                    self._wl10_reconnect()
                    # Clamp (see _wl10_get_users): free_data + the buffered
                    # drain block self.__timeout per call on a broken link.
                    old_timeout = self.__timeout
                    self.__timeout = min(self.__timeout, 5)
                    try:
                        self.free_data()
                        raw = self._wl10_read_bulk_data(
                            const.CMD_ATTLOG_RRQ, const.FCT_ATTLOG)
                    finally:
                        self.__timeout = old_timeout
                    if self._wl10_bulk_is_complete(raw, const.WL10_ATT_RECORD_SIZE):
                        break
                except Exception as e:
                    if self.verbose:
                        print(f'  [wl10_att] MSS recovery failed: {e}')

        if not self._wl10_bulk_is_complete(raw, const.WL10_ATT_RECORD_SIZE):
            raise ZKErrorResponse(
                f'Cannot read a complete attendance log from the device '
                f'(got {len(raw)} bytes after 3 attempts)')

        return self._wl10_parse_attendance(raw, users_map)

    @staticmethod
    def _wl10_build_users_map(users):
        """Index a list of :class:`User` objects by uid and user_id."""
        users_map = {}
        for u in users:
            if not u or u.uid is None:
                continue
            entry = {'name': u.name or '', 'badge': u.user_id or str(u.uid), 'uid': u.uid}
            if u.user_id:
                users_map[u.user_id] = entry
            users_map[str(u.uid)] = entry
        return users_map

    def _wl10_parse_users(self, raw_data):
        """Parse the user table and retain fingerprint-template slot UIDs."""
        self._wl10_template_uids = set()
        records, n_declared = self._wl10_strip_header(
            raw_data, const.WL10_USER_RECORD_SIZE)
        if not records:
            return []

        rec_size = const.WL10_USER_RECORD_SIZE
        n = min(n_declared, len(records) // rec_size)
        users = []
        seen = set()
        for i in range(n):
            rec = records[i * rec_size:(i + 1) * rec_size]
            uid = unpack('<H', rec[:2])[0]
            if uid and rec[2] == 0x31:
                self._wl10_template_uids.add(uid)
            user = self._wl10_decode_user_record(rec)
            if user is None or user.uid in seen:
                continue
            seen.add(user.uid)
            users.append(user)

        if self.verbose:
            print(f'  [wl10_users] parsed {len(users)} users from {n} records')
        return users

    def _wl10_decode_user_record(self, rec):
        """Decode a single 72-byte user record using the standard layout.

        Layout (matches the upstream pyzk 72-byte user format and the
        Wireshark ``zk6.lua`` dissector):
            0-1   uid (uint16 LE)
            2     privilege (uint8)            0=user, 14=admin
            3-10  password (8 bytes)
            11-34 name (24 bytes, ASCII)
            35-38 card (uint32 LE)
            39    padding
            40-46 group_id (7 bytes)
            47    padding
            48-71 user_id / badge (24 bytes, ASCII)

        Some AK3750 firmwares emit a "linking" record (a sidecar to
        the user table that links a user to a fingerprint template)
        which carries the user_id at a non-standard offset. When the
        standard fields are empty, we scan the whole record for a
        plausible 3-5 digit numeric string to use as the user_id.

        Returns ``None`` for empty records. Records with a valid uid
        but no name get a synthetic ``NN-<uid>`` placeholder.
        """
        uid = unpack('<H', rec[0:2])[0]
        privilege = rec[2]
        if privilege == 0x31:
            # Fingerprint-template slot (priv=0x31) interleaved in the
            # user table — never a real user record.
            return None
        password = rec[3:11].split(b'\x00', 1)[0].decode(self.encoding, errors='ignore')
        name = rec[11:35].split(b'\x00', 1)[0].decode(self.encoding, errors='ignore').strip()
        card = unpack('<I', rec[35:39])[0]
        group_id = rec[40:47].split(b'\x00', 1)[0].decode(self.encoding, errors='ignore')
        user_id = rec[48:72].split(b'\x00', 1)[0].decode(self.encoding, errors='ignore').strip()

        # Linking-record fallback: if the record has no name (it's a
        # fingerprint sidecar rather than a full user record), the
        # standard user_id field at bytes 48-71 holds garbage. Scan
        # the whole record for a 3-5 digit numeric user_id that
        # appears in one of the secondary offsets used by linking
        # records. Only trigger on a missing name — an alphanumeric
        # (non-numeric) badge is legitimate and must be preserved, not
        # overwritten by a digit run found elsewhere in the record.
        if not name:
            fallback = self._wl10_scan_user_id(rec)
            if fallback:
                user_id = fallback

        if not user_id:
            user_id = str(uid) if uid else ''

        if not name:
            if not uid:
                return None
            name = f'NN-{user_id}'

        return User(uid, name, privilege, password, group_id, user_id, card)

    @staticmethod
    def _wl10_scan_user_id(rec):
        """Scan a 72-byte record for a 3-5 digit ASCII user_id.

        Used as a fallback when the standard ``user_id`` field is
        empty (the device emitted a "linking" record instead of a
        full user record).
        """
        for off in range(len(rec) - 3):
            length = 0
            for end in range(off, min(off + 6, len(rec))):
                if 0x30 <= rec[end] <= 0x39:
                    length += 1
                else:
                    break
            if 3 <= length <= 5:
                # Ensure the character after the run is a null or
                # outside the digit range (boundary check) so we
                # don't pick up partial numbers from the binary
                # header.
                after = rec[off + length] if off + length < len(rec) else 0
                if after in (0, 0x20) or after < 0x30 or after > 0x39:
                    return rec[off:off + length].decode('ascii')
        return ''

    def _wl10_parse_attendance(self, raw_data, users_map=None):
        """Parse the attendance log from a WL10 device.

        The 4-byte section header is stripped first; the remaining
        bytes are interpreted as 22-byte records using the WL10 layout
        documented in the module docstring of this class.
        """
        records, n_declared = self._wl10_strip_header(
            raw_data, const.WL10_ATT_RECORD_SIZE)
        if not records:
            return []

        rec_size = const.WL10_ATT_RECORD_SIZE
        n = min(n_declared, len(records) // rec_size)
        attendances = []
        seen = set()
        now_year = datetime.now().year
        min_year = 2020
        max_year = now_year + 1

        for i in range(n):
            rec = records[i * rec_size:(i + 1) * rec_size]
            uid = unpack('<H', rec[0:2])[0]
            if uid == 0:
                # uid=0 marks a punch whose user was deleted from the
                # device — an orphan record, not a valid attendance.
                continue
            user_id_raw = rec[2:8].split(b'\x00', 1)[0].decode('ascii', errors='ignore')
            ts = unpack('<I', rec[13:17])[0]
            status = rec[17]

            dt = self._decode_zk_time(ts) if ts else None
            if dt is None or not (min_year <= dt.year <= max_year):
                # Skip records with invalid or out-of-range timestamps
                # (e.g. 0x00000000 from a freshly-formatted device, or
                # future-dated records from clock drift).
                continue

            # Some WL10 firmwares (e.g. Bella Vista vpn-device) emit every
            # attendance record twice. Collapse identical punches while
            # keeping distinct ones (different status/time is NOT a dup).
            key = (user_id_raw, ts, status, rec[12])
            if key in seen:
                continue
            seen.add(key)

            name = ''
            badge = user_id_raw or str(uid)
            if users_map:
                # Try user_id first (it's the actual badge number that
                # employees use to clock in), then fall back to uid.
                # A missing entry (partial user table) falls back to the
                # raw badge instead of crashing.
                for key in (user_id_raw, str(uid)) if user_id_raw else (str(uid),):
                    info = users_map.get(key)
                    if not info:
                        continue
                    name = info.get('name', '') or name
                    badge = info.get('badge', badge) or badge
                    break

            attendances.append(Attendance(badge, dt, status, 0, uid, name, badge))

        if self.verbose:
            print(f'  [wl10_att] parsed {len(attendances)} records from {n} candidate records')
        return attendances

    # --- Public API ----------------------------------------------------

    def wl10_get_users(self):
        """Public wrapper around :meth:`_wl10_get_users`."""
        if not self.wl10:
            raise ZKErrorResponse('Not in WL10 mode. Call with wl10=True')
        users = self._wl10_get_users()
        self.users = len(users)
        max_uid = max((u.uid for u in users), default=0)
        max_uid += 1
        self.next_uid = max_uid
        self.next_user_id = str(max_uid)
        while any(u.user_id == self.next_user_id for u in users):
            max_uid += 1
            self.next_user_id = str(max_uid)
        return users

    def wl10_get_attendance(self):
        """Public wrapper around :meth:`_wl10_get_attendance`."""
        if not self.wl10:
            raise ZKErrorResponse('Not in WL10 mode. Call with wl10=True')
        attendances = self._wl10_get_attendance()
        self.records = len(attendances)
        return attendances

    def _wl10_read_ack(self):
        """Read a simple ACK response from the device via raw recv.

        ACK responses have ``dsize=8`` (only the ZK header, no body),
        unlike bulk-read responses where ``dsize >= 16``.  The helper
        ``_wl10_extract_tcp_payloads`` requires ``dsize >= 16`` and
        therefore returns empty for ACKs, so we parse the response here.

        Returns ``(cmd, reply_id)`` where ``cmd`` is the command field
        of the ZK header and ``reply_id`` is the echoed reply_id
        (valid for ACK_OK / ACK_ERROR responses).  Returns ``(0, 0)``
        on failure.

        The caller should update ``self.__reply_id`` from the returned
        value so that subsequent commands stay in sync with the device —
        without this, chaining two writes without an intervening
        ``refresh_data()`` used to send a stale ``reply_id`` and the
        device would respond with ``ACK_ERROR``.
        """
        raw = b''
        self.__sock.settimeout(min(self.__timeout, 5))
        try:
            while True:
                chunk = self.__sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
                self.__sock.settimeout(1)
        except timeout:
            pass
        finally:
            self.__sock.settimeout(self.__timeout)

        if len(raw) < 16:
            return 0, 0
        _, _, dsize = unpack('<HHI', raw[:8])
        if dsize < 8:
            return 0, 0
        cmd, _cksum, _sid, rid = unpack('<4H', raw[8:16])
        return cmd, rid

    def _wl10_refresh_data(self):
        """Send CMD_REFRESHDATA via raw TCP path and wait for ACK.

        The standard ``refresh_data()`` uses ``__send_command`` which
        doesn't work reliably with WL10 bulk responses.  This helper
        uses the raw TCP path instead.
        """
        buf = self.__create_header(const.CMD_REFRESHDATA, b'',
                                   self.__session_id, self.__reply_id)
        top = self.__create_tcp_top(buf)
        try:
            self.__sock.send(top)
        except Exception as e:
            if self.verbose:
                print(f'  [wl10_refresh] send error: {e}')
            return False

        cmd, ack_rid = self._wl10_read_ack()
        if cmd:
            self.__reply_id = ack_rid
            return cmd == const.CMD_ACK_OK
        return False

    def wl10_set_user(self, uid=None, name='', privilege=0, password='',
                      group_id='', user_id='', card=0,
                      verify_mode=const.WL10_VERIFY_DEFAULT):
        """Write one explicitly identified user, failing closed on uncertainty."""
        if not self.wl10:
            raise ZKErrorResponse('Not in WL10 mode. Call with wl10=True')
        if not self.tcp:
            raise ZKErrorResponse('WL10 write requires TCP mode')
        if uid is None:
            raise ZKErrorResponse(
                'uid is required in WL10 mode; automatic allocation is unsafe')
        try:
            uid = int(uid)
        except (TypeError, ValueError, OverflowError):
            raise ZKErrorResponse(f'invalid uid: {uid}')
        try:
            card = int(card)
        except (TypeError, ValueError, OverflowError):
            raise ZKErrorResponse(f'invalid card: {card}')
        if not user_id:
            raise ZKErrorResponse('user_id (badge) is required')
        if not 1 <= uid <= 1000:
            raise ZKErrorResponse(f'uid out of range (1..1000): {uid}')
        if not 0 <= card <= 0xFFFFFFFF:
            raise ZKErrorResponse(f'card out of range (0..0xFFFFFFFF): {card}')

        try:
            if privilege not in (const.USER_DEFAULT, const.USER_ADMIN):
                privilege = const.USER_DEFAULT
            privilege = int(privilege)
            if verify_mode not in const.WL10_VERIFY_MODES:
                verify_mode = const.WL10_VERIFY_DEFAULT
            verify_mode = int(verify_mode)
            name_raw = name.encode(self.encoding, errors='ignore')
            if len(name_raw) > 24:
                name_raw = name_raw[:24]
                while name_raw:
                    try:
                        name_raw.decode(self.encoding)
                        break
                    except UnicodeDecodeError:
                        name_raw = name_raw[:-1]
            command_string = pack(
                'HB8s24s4sB7sx24s', uid, privilege,
                password.encode(self.encoding, errors='ignore'),
                name_raw.ljust(24, b'\x00'), pack('<I', card), verify_mode,
                group_id.encode(), user_id.encode())
        except (AttributeError, TypeError, ValueError, OverflowError,
                UnicodeError, StructError) as e:
            raise ZKErrorResponse(f'Invalid user data: {e}')
        if len(command_string) != const.WL10_USER_RECORD_SIZE:
            raise ZKErrorResponse(
                f'User record must be {const.WL10_USER_RECORD_SIZE}B, '
                f'got {len(command_string)}B')

        self._wl10_get_users()
        self._wl10_assert_user_slot_safe(uid)
        if not self._wl10_refresh_data():
            raise ZKErrorResponse('Failed to refresh data before write')
        buf = self.__create_header(const.CMD_USER_WRQ, command_string,
                                   self.__session_id, self.__reply_id)
        try:
            self.__sock.send(self.__create_tcp_top(buf))
        except Exception as e:
            raise ZKErrorResponse(f'Failed to send user: {e}')
        cmd, ack_rid = self._wl10_read_ack()
        if cmd:
            self.__reply_id = ack_rid
            if cmd == const.CMD_ACK_OK:
                self._wl10_refresh_data()
                if self.next_uid == uid:
                    self.next_uid += 1
                if self.next_user_id == user_id:
                    self.next_user_id = str(self.next_uid)
                return True
            msg = {const.CMD_ACK_ERROR: 'ACK_ERROR',
                   const.CMD_ACK_UNAUTH: 'UNAUTH'}.get(cmd, f'UNKNOWN({cmd})')
            raise ZKErrorResponse(f'Device rejected write: {msg}')
        try:
            observed = self._wl10_get_users()
        except Exception:
            raise ZKErrorResponse(
                'No response from device; write outcome is unknown')
        wire_name = name_raw.decode(self.encoding, errors='ignore').strip()
        if any(user.uid == uid and user.user_id == user_id
               and user.privilege == privilege and user.card == card
               and user.name == wire_name for user in observed):
            return True
        raise ZKErrorResponse('No response from device; write outcome is unknown')

    def _wl10_assert_user_slot_safe(self, uid):
        if uid in getattr(self, '_wl10_template_uids', set()):
            raise ZKErrorResponse(
                f'uid {uid} is reserved for fingerprint templates')

    def wl10_delete_user(self, uid=0, user_id=''):
        """Delete one user after a read-only baseline preflight."""
        if not self.wl10:
            raise ZKErrorResponse('Not in WL10 mode. Call with wl10=True')
        if not self.tcp:
            raise ZKErrorResponse('WL10 delete requires TCP mode')
        if uid == 0 and not user_id:
            return False
        if uid:
            try:
                uid = int(uid)
            except (TypeError, ValueError):
                raise ZKErrorResponse(f'invalid uid: {uid}')
            if not 1 <= uid <= 1000:
                raise ZKErrorResponse(f'uid out of range (1..1000): {uid}')
        elif not user_id:
            raise ZKErrorResponse('user_id (badge) is required')

        baseline = self._wl10_get_users()
        self._wl10_assert_user_slot_safe(uid) if uid else None
        if not uid:
            matches = [user for user in baseline if user.user_id == str(user_id)]
            if not matches:
                return False
            uid = matches[0].uid
        else:
            matches = [user for user in baseline if user.uid == uid]
            if not matches:
                return False
        self._wl10_assert_user_slot_safe(uid)
        if not self._wl10_refresh_data():
            raise ZKErrorResponse('Failed to refresh data before delete')

        buf = self.__create_header(const.CMD_DELETE_USER, pack('<H', uid),
                                   self.__session_id, self.__reply_id)
        try:
            self.__sock.send(self.__create_tcp_top(buf))
        except Exception as e:
            raise ZKErrorResponse(f'Failed to send delete: {e}')
        cmd, ack_rid = self._wl10_read_ack()
        if cmd:
            self.__reply_id = ack_rid
            if cmd == const.CMD_ACK_OK:
                self._wl10_refresh_data()
                if uid == (self.next_uid - 1):
                    self.next_uid = uid
                return True
            return False
        try:
            remaining = self._wl10_get_users()
        except Exception:
            raise ZKErrorResponse(
                'No response from device; delete outcome is unknown')
        if not any(user.uid == uid for user in remaining):
            return True
        raise ZKErrorResponse('No response from device; delete outcome is unknown')

    def wl10_reboot(self):
        """Reboot using one raw command and fail closed on unknown outcome."""
        if not self.wl10:
            raise ZKErrorResponse('Not in WL10 mode. Call with wl10=True')
        if not self.tcp:
            raise ZKErrorResponse('WL10 reboot requires TCP mode')
        if not self._wl10_refresh_data():
            raise ZKErrorResponse('Failed to refresh data before reboot')
        buf = self.__create_header(const.CMD_RESTART, b'',
                                   self.__session_id, self.__reply_id)
        try:
            self.__sock.send(self.__create_tcp_top(buf))
        except Exception as e:
            raise ZKErrorResponse(f'Failed to send reboot: {e}')
        cmd, ack_rid = self._wl10_read_ack()
        if cmd:
            self.__reply_id = ack_rid
            if cmd == const.CMD_ACK_OK:
                self.is_connect = False
                self.next_uid = 1
                return True
            raise ZKErrorResponse(f'Device rejected reboot: {cmd} (ACK_ERROR)')
        self.is_connect = False
        raise ZKErrorResponse('No response from device; reboot outcome is unknown')


    # ================== End WL10 Specific Methods ==================

    def set_user(self, uid=None, name='', privilege=0, password='', group_id='', user_id='', card=0):
        if self.wl10:
            return self.wl10_set_user(uid=uid, name=name, privilege=privilege,
                                      password=password, group_id=group_id,
                                      user_id=user_id, card=card)
        command = const.CMD_USER_WRQ
        if uid is None:
            uid = self.next_uid
            if not user_id:
                user_id = self.next_user_id
        if not user_id:
            user_id = str(uid)
        if privilege not in [const.USER_DEFAULT, const.USER_ADMIN]:
            privilege = const.USER_DEFAULT
        privilege = int(privilege)
        if self.user_packet_size == 28:
            if not group_id:
                group_id = 0
            try:
                command_string = pack('HB5s8sIxBHI', uid, privilege, password.encode(self.encoding, errors='ignore'), name.encode(self.encoding, errors='ignore'), card, int(group_id), 0, int(user_id))
            except Exception as e:
                if self.verbose:
                    print(f"s_h Error pack: {e}")
                if self.verbose:
                    print(f"Error pack: {sys.exc_info()[0]}")
                raise ZKErrorResponse("Can't pack user")
        else:
            name_pad = name.encode(self.encoding, errors='ignore').ljust(24, b'\x00')[:24]
            card_str = pack('<I', int(card))[:4]
            command_string = pack('HB8s24s4sx7sx24s', uid, privilege, password.encode(self.encoding, errors='ignore'), name_pad, card_str, group_id.encode(), user_id.encode())
        response_size = 1024
        cmd_response = self.__send_command(command, command_string, response_size)
        if self.verbose:
            print(f"Response: {cmd_response}")
        if not cmd_response.get('status'):
            raise ZKErrorResponse("Can't set user")
        self.refresh_data()
        if self.next_uid == uid:
            self.next_uid += 1
        if self.next_user_id == user_id:
            self.next_user_id = str(self.next_uid)

    def save_user_template(self, user, fingers=None):
        if fingers is None:
            fingers = []
        if not isinstance(user, User):
            users = self.get_users()
            tusers = list(filter(lambda x: x.uid == user, users))
            if len(tusers) == 1:
                user = tusers[0]
            else:
                tusers = list(filter(lambda x: x.user_id == str(user), users))
                if len(tusers) == 1:
                    user = tusers[0]
                else:
                    raise ZKErrorResponse("Can't find user")
        if isinstance(fingers, Finger):
            fingers = [fingers]
        fpack = b""
        table = b""
        fnum = 0x10
        tstart = 0
        for finger in fingers:
            tfp = finger.repack_only()
            table += pack("<bHbI", 2, user.uid, fnum + finger.fid, tstart)
            tstart += len(tfp)
            fpack += tfp
        upack = user.repack29() if self.user_packet_size == 28 else user.repack73()
        head = pack("III", len(upack), len(table), len(fpack))
        packet = head + upack + table + fpack
        self._send_with_buffer(packet)
        command = 110
        command_string = pack('<IHH', 12, 0, 8)
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise ZKErrorResponse("Can't save utemp")
        self.refresh_data()

    def _send_with_buffer(self, buffer):
        MAX_CHUNK = 1024
        size = len(buffer)
        self.free_data()
        command = const.CMD_PREPARE_DATA
        command_string = pack('I', size)
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise ZKErrorResponse("Can't prepare data")
        remain = size % MAX_CHUNK
        packets = (size - remain) // MAX_CHUNK
        start = 0
        for _wlk in range(packets):
            self.__send_chunk(buffer[start:start + MAX_CHUNK])
            start += MAX_CHUNK
        if remain:
            self.__send_chunk(buffer[start:start + remain])

    def __send_chunk(self, command_string):
        command = const.CMD_DATA
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Can't send chunk")

    def delete_user_template(self, uid=0, temp_id=0, user_id=''):
        if self.tcp and user_id:
            command = 134
            command_string = pack('<24sB', str(user_id), temp_id)
        cmd_response = self.__send_command(command, command_string)
        return bool(cmd_response.get('status'))
        if not uid:
            users = self.get_users()
            users = list(filter(lambda x: x.user_id == str(user_id), users))
            if not users:
                return False
            uid = users[0].uid
        command = const.CMD_DELETE_USERTEMP
        command_string = pack('hb', uid, temp_id)
        cmd_response = self.__send_command(command, command_string)
        return bool(cmd_response.get('status'))

    def delete_user(self, uid=0, user_id=''):
        if self.wl10:
            return self.wl10_delete_user(uid=uid, user_id=user_id)
        if not uid:
            users = self.get_users()
            users = list(filter(lambda x: x.user_id == str(user_id), users))
            if not users:
                return False
            uid = users[0].uid
        command = const.CMD_DELETE_USER
        command_string = pack('<H', uid)
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise ZKErrorResponse("Can't delete user")
        self.refresh_data()
        if uid == (self.next_uid - 1):
            self.next_uid = uid

    def get_user_template(self, uid, temp_id=0, user_id=''):
        if not uid:
            users = self.get_users()
            users = list(filter(lambda x: x.user_id == str(user_id), users))
            if not users:
                return False
            uid = users[0].uid
        for _retries in range(3):
            command = 88
            command_string = pack('hb', uid, temp_id)
            response_size = 1024 + 8
            self.__send_command(command, command_string, response_size)
            data = self.__recieve_chunk()
            if data is not None:
                resp = data[:-1]
                if resp[-6:] == b'\x00\x00\x00\x00\x00\x00':
                    resp = resp[:-6]
                return Finger(uid, temp_id, 1, resp)
            if self.verbose:
                print("retry get_user_template")
        else:  # noqa: PLW0120  # else = retries exhausted (loop exits via return)
            if self.verbose:
                print("Can't read/find finger")
            return None

    def get_templates(self):
        self.read_sizes()
        if self.fingers == 0:
            return []
        templates = []
        templatedata, size = self.read_with_buffer(const.CMD_DB_RRQ, const.FCT_FINGERTMP)
        if size < 4:
            if self.verbose:
                print("WRN: no user data")
            return []
        total_size = unpack('i', templatedata[0:4])[0]
        if self.verbose:
            print("get template total size {}, size {} len {}".format(total_size, size, len(templatedata)))
        templatedata = templatedata[4:]
        while total_size:
            size, uid, fid, valid = unpack('HHbb', templatedata[:6])
            template = unpack(f"{size - 6}s", templatedata[6:size])[0]
            finger = Finger(uid, fid, valid, template)
            if self.verbose:
                print(finger)
            templates.append(finger)
            templatedata = templatedata[size:]
            total_size -= size
        return templates

    def get_users(self):
        if self.wl10:
            users = self._wl10_get_users()
            return users
        self.read_sizes()
        if self.users == 0:
            self.next_uid = 1
            self.next_user_id = '1'
            return []
        users = []
        max_uid = 0
        userdata, size = self.read_with_buffer(const.CMD_USERTEMP_RRQ, const.FCT_USER)
        if self.verbose:
            print("user size {} (= {})".format(size, len(userdata)))
        if size <= 4:
            print("WRN: missing user data")
            return []
        total_size = unpack("I", userdata[:4])[0]
        self.user_packet_size = total_size / self.users
        if self.user_packet_size not in [28, 72] and self.verbose:
            print(f"WRN packet size would be  {self.user_packet_size}")
        userdata = userdata[4:]
        if self.user_packet_size == 28:
            while len(userdata) >= 28:
                uid, privilege, password, name, card, group_id, timezone, user_id = unpack('<HB5s8sIxBhI', userdata.ljust(28, b'\x00')[:28])
                max_uid = max(max_uid, uid)
                password = (password.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
                name = (name.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
                group_id = str(group_id)
                user_id = str(user_id)
                if not name:
                    name = f"NN-{user_id}"
                user = User(uid, name, privilege, password, group_id, user_id, card)
                users.append(user)
                if self.verbose:
                    print("[6]user:", uid, privilege, password, name, card, group_id, timezone, user_id)
                userdata = userdata[28:]
        else:
            while len(userdata) >= 72:
                uid, privilege, password, name, card, group_id, user_id = unpack('<HB8s24sIx7sx24s', userdata.ljust(72, b'\x00')[:72])
                password = (password.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
                name = (name.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
                group_id = (group_id.split(b'\x00')[0]).decode(self.encoding, errors='ignore').strip()
                user_id = (user_id.split(b'\x00')[0]).decode(self.encoding, errors='ignore')
                max_uid = max(max_uid, uid)
                if not name:
                    name = f"NN-{user_id}"
                user = User(uid, name, privilege, password, group_id, user_id, card)
                users.append(user)
                userdata = userdata[72:]
        max_uid += 1
        self.next_uid = max_uid
        self.next_user_id = str(max_uid)
        while True:
            if any(u for u in users if u.user_id == self.next_user_id):
                max_uid += 1
                self.next_user_id = str(max_uid)
            else:
                break
        return users

    def cancel_capture(self):
        command = const.CMD_CANCELCAPTURE
        cmd_response = self.__send_command(command)
        return bool(cmd_response.get('status'))

    def verify_user(self):
        command = const.CMD_STARTVERIFY
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Cant Verify")

    def reg_event(self, flags):
        command = const.CMD_REG_EVENT
        command_string = pack("I", flags)
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise ZKErrorResponse(f"cant' reg events {flags}")

    def set_sdk_build_1(self):
        command = const.CMD_OPTIONS_WRQ
        command_string = b"SDKBuild=1"
        cmd_response = self.__send_command(command, command_string)
        return bool(cmd_response.get('status'))

    def enroll_user(self, uid=0, temp_id=0, user_id=''):
        command = const.CMD_STARTENROLL
        done = False
        if not user_id:
            users = self.get_users()
            users = list(filter(lambda x: x.uid == uid, users))
            if len(users) >= 1:
                user_id = users[0].user_id
            else:
                return False
        if self.tcp:
            command_string = pack('<24sbb', str(user_id).encode(), temp_id, 1)
        else:
            command_string = pack('<Ib', int(user_id), temp_id)
        self.cancel_capture()
        cmd_response = self.__send_command(command, command_string)
        if not cmd_response.get('status'):
            raise ZKErrorResponse(f"Cant Enroll user #{uid} [{temp_id}]")
        self.__sock.settimeout(60)
        attempts = 3
        while attempts:
            if self.verbose:
                print(f"A:{attempts} esperando primer regevent")
            data_recv = self.__sock.recv(1032)
            self.__ack_ok()
            if self.verbose:
                print(codecs.encode(data_recv, 'hex'))
            if self.tcp:
                if len(data_recv) > 16:
                    res = unpack("H", data_recv.ljust(24, b"\x00")[16:18])[0]
                    if self.verbose:
                        print(f"res {res}")
                    if res in (0, 6, 4):
                        if self.verbose:
                            print("posible timeout  o reg Fallido")
                        break
            elif len(data_recv) > 8:
                res = unpack("H", data_recv.ljust(16, b"\x00")[8:10])[0]
                if self.verbose:
                    print(f"res {res}")
                if res in (6, 4):
                        if self.verbose:
                            print("posible timeout")
                        break
            if self.verbose:
                print(f"A:{attempts} esperando 2do regevent")
            data_recv = self.__sock.recv(1032)
            self.__ack_ok()
            if self.verbose:
                print(codecs.encode(data_recv, 'hex'))
            if self.tcp:
                if len(data_recv) > 8:
                    res = unpack("H", data_recv.ljust(24, b"\x00")[16:18])[0]
                    if self.verbose:
                        print(f"res {res}")
                    if res in (6, 4):
                        if self.verbose:
                            print("posible timeout  o reg Fallido")
                        break
                    elif res == 0x64:
                        if self.verbose:
                            print("ok, continue?")
                        attempts -= 1
            elif len(data_recv) > 8:
                res = unpack("H", data_recv.ljust(16, b"\x00")[8:10])[0]
                if self.verbose:
                    print(f"res {res}")
                if res in (6, 4):
                    if self.verbose:
                        print("posible timeout  o reg Fallido")
                    break
                elif res == 0x64:
                    if self.verbose:
                        print("ok, continue?")
                    attempts -= 1
        if attempts == 0:
            data_recv = self.__sock.recv(1032)
            self.__ack_ok()
            if self.verbose:
                print(codecs.encode(data_recv, 'hex'))
            if self.tcp:
                res = unpack("H", data_recv.ljust(24, b"\x00")[16:18])[0]
            else:
                res = unpack("H", data_recv.ljust(16, b"\x00")[8:10])[0]
            if self.verbose:
                print(f"res {res}")
            if res == 5:  # noqa: SIM102  # nested for readability
                if self.verbose:
                    print("finger duplicate")
            if res in (6, 4):  # noqa: SIM102  # nested for readability
                if self.verbose:
                    print("posible timeout")
            if res == 0:
                size = unpack("H", data_recv.ljust(16, b"\x00")[10:12])[0]
                pos = unpack("H", data_recv.ljust(16, b"\x00")[12:14])[0]
                if self.verbose:
                    print("enroll ok", size, pos)
                done = True
        self.__sock.settimeout(self.__timeout)
        self.reg_event(0)
        self.cancel_capture()
        self.verify_user()
        return done

    def live_capture(self, new_timeout=10):
        was_enabled = self.is_enabled
        users = self.get_users()
        self.cancel_capture()
        self.verify_user()
        if not self.is_enabled:
            self.enable_device()
        if self.verbose:
            print("start live_capture")
        self.reg_event(const.EF_ATTLOG)
        self.__sock.settimeout(new_timeout)
        self.end_live_capture = False
        while not self.end_live_capture:
            try:
                if self.verbose:
                    print("esperando event")
                data_recv = self.__sock.recv(1032)
                self.__ack_ok()
                if self.tcp:
                    header = unpack('HHHH', data_recv[8:16])
                    data = data_recv[16:]
                else:
                    header = unpack('<4H', data_recv[:8])
                    data = data_recv[8:]
                if header[0] != const.CMD_REG_EVENT:
                    if self.verbose:
                        print(f"not event! {header[0]:x}")
                    continue
                if not len(data):
                    if self.verbose:
                        print("empty")
                    continue
                while len(data) >= 12:
                    if len(data) == 12:
                        user_id, status, punch, timehex = unpack('<IBB6s', data)
                        data = data[12:]
                    elif len(data) == 32:
                        user_id, status, punch, timehex = unpack('<24sBB6s', data[:32])
                        data = data[32:]
                    elif len(data) == 36:
                        user_id, status, punch, timehex, _other = unpack('<24sBB6s4s', data[:36])
                        data = data[36:]
                    elif len(data) >= 52:
                        user_id, status, punch, timehex, _other = unpack('<24sBB6s20s', data[:52])
                        data = data[52:]
                    if isinstance(user_id, int):
                        user_id = str(user_id)
                    else:
                        user_id = (user_id.split(b'\x00')[0]).decode(errors='ignore')
                    timestamp = self.__decode_timehex(timehex)
                    tuser = list(filter(lambda x: x.user_id == user_id, users))
                    uid = int(user_id) if not tuser else tuser[0].uid
                    yield Attendance(user_id, timestamp, status, punch, uid)
            except timeout:
                if self.verbose:
                    print("time out")
                yield None
            except (KeyboardInterrupt, SystemExit):
                if self.verbose:
                    print("break")
                break
        if self.verbose:
            print("exit gracefully")
        self.__sock.settimeout(self.__timeout)
        self.reg_event(0)
        if not was_enabled:
            self.disable_device()

    def clear_data(self):
        command = const.CMD_CLEAR_DATA
        command_string = ''
        cmd_response = self.__send_command(command, command_string)
        if cmd_response.get('status'):
            self.next_uid = 1
            return True
        else:
            raise ZKErrorResponse("can't clear data")

    def __recieve_tcp_data(self, data_recv, size):
        data = []
        tcp_length = self.__test_tcp_top(data_recv)
        if self.verbose:
            print("tcp_length {}, size {}".format(tcp_length, size))
        if tcp_length <= 0:
            if self.verbose:
                print("Incorrect tcp packet")
            return None, b""
        if (tcp_length - 8) < size:
            if self.verbose:
                print("tcp length too small... retrying")
            resp, bh = self.__recieve_tcp_data(data_recv, tcp_length - 8)
            data.append(resp)
            size -= len(resp)
            if self.verbose:
                print("new tcp DATA packet to fill misssing {}".format(size))
            data_recv = bh + self.__sock.recv(size + 16)
            if self.verbose:
                print("new tcp DATA starting with {} bytes".format(len(data_recv)))
            resp, bh = self.__recieve_tcp_data(data_recv, size)
            data.append(resp)
            if self.verbose:
                print("for misssing {} recieved {} with extra {}".format(size, len(resp), len(bh)))
            return b''.join(data), bh
        recieved = len(data_recv)
        if self.verbose:
            print("recieved {}, size {}".format(recieved, size))
        response = unpack('HHHH', data_recv[8:16])[0]
        if recieved >= (size + 32):
            if response == const.CMD_DATA:
                resp = data_recv[16: size + 16]
                if self.verbose:
                    print("resp complete len {}".format(len(resp)))
                return resp, data_recv[size + 16:]
            else:
                if self.verbose:
                    print("incorrect response!!! {}".format(response))
                return None, b""
        else:
            if self.verbose:
                print("try DATA incomplete (actual valid {})".format(recieved - 16))
            data.append(data_recv[16: size + 16])
            size -= recieved - 16
            broken_header = b""
            if size < 0:
                broken_header = data_recv[size:]
                if self.verbose:
                    print("broken", codecs.encode(broken_header, 'hex'))
            if size > 0:
                data_recv = self.__recieve_raw_data(size)
                data.append(data_recv)
            return b''.join(data), broken_header

    def __recieve_raw_data(self, size):
        data = []
        if self.verbose:
            print("expecting {} bytes raw data".format(size))
        while size > 0:
            data_recv = self.__sock.recv(size)
            recieved = len(data_recv)
            if self.verbose:
                print("partial recv {}".format(recieved))
            if recieved < 100 and self.verbose:
                print("   recv {}".format(codecs.encode(data_recv, 'hex')))
            data.append(data_recv)
            size -= recieved
            if self.verbose:
                print("still need {}".format(size))
        return b''.join(data)

    def __recieve_chunk(self):
        if self.__response == const.CMD_DATA:
            if self.tcp:
                if self.verbose:
                    print("_rc_DATA! is {} bytes, tcp length is {}".format(len(self.__data), self.__tcp_length))
                if len(self.__data) < (self.__tcp_length - 8):
                    need = (self.__tcp_length - 8) - len(self.__data)
                    if self.verbose:
                        print("need more data: {}".format(need))
                    more_data = self.__recieve_raw_data(need)
                    return b''.join([self.__data, more_data])
                else:
                    if self.verbose:
                        print("Enough data")
                    return self.__data
            else:
                if self.verbose:
                    print("_rc len is {}".format(len(self.__data)))
                return self.__data
        elif self.__response == const.CMD_PREPARE_DATA:
            data = []
            size = self.__get_data_size()
            if self.verbose:
                print("recieve chunk: prepare data size is {}".format(size))
            if self.tcp:
                if len(self.__data) >= (8 + size):
                    data_recv = self.__data[8:]
                else:
                    data_recv = self.__data[8:] + self.__sock.recv(size + 32)
                resp, broken_header = self.__recieve_tcp_data(data_recv, size)
                data.append(resp)
                if len(broken_header) < 16:  # noqa: SIM108  # functional: rebuild data_recv from leftover bytes; keep explicit
                    data_recv = broken_header + self.__sock.recv(16)
                else:
                    data_recv = broken_header
                if len(data_recv) < 16:
                    if self.verbose:
                        print(f"trying to complete broken ACK {len(data_recv)} /16")
                        print(codecs.encode(data_recv, 'hex'))
                    data_recv += self.__sock.recv(16 - len(data_recv))
                if not self.__test_tcp_top(data_recv):
                    if self.verbose:
                        print("invalid chunk tcp ACK OK")
                    return None
                response = unpack('HHHH', data_recv[8:16])[0]
                if response == const.CMD_ACK_OK:
                    if self.verbose:
                        print("chunk tcp ACK OK!")
                    return b''.join(data)
                if self.verbose:
                    print(f"bad response {data_recv}")
                    print(codecs.encode(data, 'hex'))
                return None

                return resp
            while True:
                data_recv = self.__sock.recv(1024 + 8)
                response = unpack('<4H', data_recv[:8])[0]
                if self.verbose:
                    print("# packet response is: {}".format(response))
                if response == const.CMD_DATA:
                    data.append(data_recv[8:])
                    size -= 1024
                elif response == const.CMD_ACK_OK:
                    break
                else:
                    if self.verbose:
                        print("broken!")
                    break
                if self.verbose:
                    print(f"still needs {size}")
            return b''.join(data)
        else:
            if self.verbose:
                print(f"invalid response {self.__response}")
            return None

    def __read_chunk(self, start, size):
        for _retries in range(3):
            command = 1504
            command_string = pack('<ii', start, size)
            response_size = size + 32 if self.tcp else 1024 + 8
            self.__send_command(command, command_string, response_size)
            data = self.__recieve_chunk()
            if data is not None:
                return data
        else:  # noqa: PLW0120  # else = retries exhausted (loop exits via return)
            raise ZKErrorResponse(f"can't read chunk {start}:[{size}]")

    def read_with_buffer(self, command, fct=0, ext=0):
        MAX_CHUNK = 0xFFC0 if self.tcp else 16 * 1024
        command_string = pack('<bhii', 1, command, fct, ext)
        if self.verbose:
            print("rwb cs", command_string)
        response_size = 1024
        data = []
        start = 0
        cmd_response = self.__send_command(1503, command_string, response_size)
        if not cmd_response.get('status'):
            raise ZKErrorResponse("RWB Not supported")
        if cmd_response['code'] == const.CMD_DATA:
            if self.tcp:
                if self.verbose:
                    print("DATA! is {} bytes, tcp length is {}".format(len(self.__data), self.__tcp_length))
                if len(self.__data) < (self.__tcp_length - 8):
                    need = (self.__tcp_length - 8) - len(self.__data)
                    if self.verbose:
                        print("need more data: {}".format(need))
                    more_data = self.__recieve_raw_data(need)
                    return b''.join([self.__data, more_data]), len(self.__data) + len(more_data)
                else:
                    if self.verbose:
                        print("Enough data")
                    size = len(self.__data)
                    return self.__data, size
            else:
                size = len(self.__data)
                return self.__data, size
        size = unpack('I', self.__data[1:5])[0]
        if self.verbose:
            print(f"size fill be {size}")
        remain = size % MAX_CHUNK
        packets = (size - remain) // MAX_CHUNK
        if self.verbose:
            print("rwb: #{} packets of max {} bytes, and extra {} bytes remain".format(packets, MAX_CHUNK, remain))
        for _wlk in range(packets):
            data.append(self.__read_chunk(start, MAX_CHUNK))
            start += MAX_CHUNK
        if remain:
            data.append(self.__read_chunk(start, remain))
            start += remain
        self.free_data()
        if self.verbose:
            print(f"_read w/chunk {start} bytes")
        return b''.join(data), start

    def get_attendance(self):
        # Save original mode for restoration
        saved_wl10 = self.wl10

        if self.wl10:
            # Try WL10 method first
            attendances = self._wl10_get_attendance()
            if attendances:
                self.records = len(attendances)
                return attendances
            # WL10 returned empty - temporarily switch to standard method
            if self.verbose:
                print("WL10 attendance returned empty, trying standard method...")
            self.wl10 = False

        try:
            self.read_sizes()
        except Exception as e:
            if self.verbose:
                print(f"read_sizes failed: {e}")
            self.wl10 = saved_wl10
            return []

        if self.records == 0:
            self.wl10 = saved_wl10
            return []
        users = self.get_users()
        if self.verbose:
            print(users)
        attendances = []
        attendance_data, size = self.read_with_buffer(const.CMD_ATTLOG_RRQ)
        if size < 4:
            if self.verbose:
                print("WRN: no attendance data")
            return []
        total_size = unpack("I", attendance_data[:4])[0]
        record_size = total_size / self.records
        if self.verbose:
            print("record_size is ", record_size)
        attendance_data = attendance_data[4:]
        if record_size == 8:
            while len(attendance_data) >= 8:
                uid, status, timestamp, punch = unpack('HB4sB', attendance_data.ljust(8, b'\x00')[:8])
                if self.verbose:
                    print(codecs.encode(attendance_data[:8], 'hex'))
                attendance_data = attendance_data[8:]
                tuser = list(filter(lambda x: x.uid == uid, users))
                user_id = str(uid) if not tuser else tuser[0].user_id
                timestamp = self.__decode_time(timestamp)
                attendance = Attendance(user_id, timestamp, status, punch, uid)
                attendances.append(attendance)
        elif record_size == 16:
            while len(attendance_data) >= 16:
                user_id, timestamp, status, punch, _reserved, _workcode = unpack('<I4sBB2sI', attendance_data.ljust(16, b'\x00')[:16])
                user_id = str(user_id)
                if self.verbose:
                    print(codecs.encode(attendance_data[:16], 'hex'))
                attendance_data = attendance_data[16:]
                tuser = list(filter(lambda x: x.user_id == user_id, users))
                if not tuser:
                    if self.verbose:
                        print("no uid {}", user_id)
                    uid = str(user_id)
                    tuser = list(filter(lambda x: x.uid == user_id, users))
                    if not tuser:
                        uid = str(user_id)
                    else:
                        uid = tuser[0].uid
                        user_id = tuser[0].user_id
                else:
                    uid = tuser[0].uid
                timestamp = self.__decode_time(timestamp)
                attendance = Attendance(user_id, timestamp, status, punch, uid)
                attendances.append(attendance)
        else:
            while len(attendance_data) >= 40:
                uid, user_id, status, timestamp, punch, _space = unpack('<H24sB4sB8s', attendance_data.ljust(40, b'\x00')[:40])
                if self.verbose:
                    print(codecs.encode(attendance_data[:40], 'hex'))
                user_id = (user_id.split(b'\x00')[0]).decode(errors='ignore')
                timestamp = self.__decode_time(timestamp)

                attendance = Attendance(user_id, timestamp, status, punch, uid)
                attendances.append(attendance)
                attendance_data = attendance_data[40:]
        # Restore saved mode
        self.wl10 = saved_wl10
        return attendances

    def clear_attendance(self):
        command = const.CMD_CLEAR_ATTLOG
        cmd_response = self.__send_command(command)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Can't clear response")
