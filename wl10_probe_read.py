#!/usr/bin/env python3
"""Read-only WL10 protocol capture probe."""

import argparse
import hashlib
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "pyzk_wl10"))
from zk import ZK, const  # noqa: E402
from zk.exception import ZKErrorResponse  # noqa: E402


READ_METHODS = (
    "get_device_name", "get_platform", "get_firmware_version", "get_serialnumber",
    "get_mac", "get_face_version", "get_fp_version", "get_extend_fmt",
    "get_user_extend_fmt", "get_face_fun_on", "get_compat_old_firmware",
    "get_network_params", "get_pin_width", "get_time", "read_sizes",
)
_ALLOWED_SEND = {
    const.CMD_CONNECT, const.CMD_AUTH, const.CMD_EXIT, const.CMD_OPTIONS_RRQ,
    const.CMD_GET_VERSION, const.CMD_GET_PINWIDTH, const.CMD_GET_TIME, const.CMD_GET_FREE_SIZES,
    const.CMD_FREE_DATA, const.CMD_ACK_ERROR, const.CMD_ACK_UNKNOWN,
}
_ALLOWED_RAW = {const.CMD_USERTEMP_RRQ, const.CMD_ATTLOG_RRQ}


def _open_output_dir(path):
    absolute = os.path.abspath(os.fspath(path))
    components = absolute.split(os.sep)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = os.open(os.sep, flags)
    try:
        for component in components[1:-1]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        os.mkdir(components[-1], 0o700, dir_fd=current_fd)
        output_fd = os.open(components[-1], flags, dir_fd=current_fd)
    except BaseException:
        os.close(current_fd)
        raise
    os.close(current_fd)
    return output_fd


def _write_exclusive(parent_or_path, basename_or_data, data=None):
    if data is None:
        path = os.fspath(parent_or_path)
        basename = os.path.basename(path)
        parent_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return _write_exclusive(parent_fd, basename, basename_or_data)
        finally:
            os.close(parent_fd)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(basename_or_data, flags, 0o600, dir_fd=parent_or_path)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


class CapturingZK(ZK):
    """ZK client constrained to the probe's read-only command allowlist."""

    def __init__(self, *args, capture_dir=None, capture_dir_fd=None, **kwargs):
        kwargs["ommit_ping"] = True
        super().__init__(*args, **kwargs)
        self._capture_dir = Path(capture_dir) if capture_dir else None
        self._capture_dir_fd = capture_dir_fd
        if self._capture_dir_fd is None and self._capture_dir is not None:
            self._capture_dir_fd = os.open(self._capture_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._capture_seq = {const.CMD_USERTEMP_RRQ: 0, const.CMD_ATTLOG_RRQ: 0}
        self._captures = []
        self._parser_counts = {}
        self._skip_connect_metadata = False

    def connect(self):
        self._skip_connect_metadata = True
        try:
            return super().connect()
        finally:
            self._skip_connect_metadata = False

    def get_device_name(self):
        if self._skip_connect_metadata:
            return ""
        return super().get_device_name()

    def get_platform(self):
        if self._skip_connect_metadata:
            return ""
        return super().get_platform()

    def _ZK__send_command(self, command, command_string=b"", response_size=8):
        if command not in _ALLOWED_SEND:
            raise ZKErrorResponse(f"command {command} not allowed in read-only probe")
        return super()._ZK__send_command(command, command_string, response_size)

    def wl10_set_user(self, *args, **kwargs):
        raise ZKErrorResponse('not allowed in read-only probe')

    def wl10_delete_user(self, *args, **kwargs):
        raise ZKErrorResponse('not allowed in read-only probe')

    def wl10_reboot(self, *args, **kwargs):
        raise ZKErrorResponse('not allowed in read-only probe')

    def _wl10_refresh_data(self, *args, **kwargs):
        raise ZKErrorResponse('not allowed in read-only probe')

    def _wl10_read_ack(self, *args, **kwargs):
        raise ZKErrorResponse('not allowed in read-only probe')

    def refresh_data(self, *args, **kwargs):
        raise ZKErrorResponse('not allowed in read-only probe')

    def _wl10_read_raw_command(self, command_code):
        if command_code not in _ALLOWED_RAW:
            raise ZKErrorResponse(f"command {command_code} not allowed in read-only probe")
        payload = super()._wl10_read_raw_command(command_code)
        if not hasattr(self, "_capture_dir_fd"):
            self._capture_dir_fd = self._capture_dir
        if self._capture_dir_fd is None:
            return payload
        if isinstance(self._capture_dir_fd, Path):
            self._capture_dir_fd = os.open(self._capture_dir_fd, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._capture_seq[command_code] += 1
        filename = f"cmd_{command_code:02d}_{self._capture_seq[command_code]:03d}.bin"
        _write_exclusive(self._capture_dir_fd, filename, payload)
        ack = getattr(self, "_wl10_last_ack", None)
        self._captures.append({
            "command": command_code, "filename": filename, "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "ack": {"command": ack[0], "reply_id": ack[1]} if ack else None,
        })
        return payload

    def _wl10_parse_users(self, raw_data):
        records, declared = self._wl10_strip_header(raw_data, const.WL10_USER_RECORD_SIZE)
        users = super()._wl10_parse_users(raw_data)
        self._parser_counts["users"] = {
            "declared": declared, "candidate": len(records) // const.WL10_USER_RECORD_SIZE,
            "accepted": len(users),
        }
        return users

    def _wl10_parse_attendance(self, raw_data, users_map=None):
        records, declared = self._wl10_strip_header(raw_data, const.WL10_ATT_RECORD_SIZE)
        attendance = super()._wl10_parse_attendance(raw_data, users_map)
        self._parser_counts["attendance"] = {
            "declared": declared, "candidate": len(records) // const.WL10_ATT_RECORD_SIZE,
            "accepted": len(attendance),
        }
        return attendance


def _status(value):
    if isinstance(value, dict):
        return {"status": "ok", "type": "dict", "fields": len(value), "keys": sorted(value)}
    return {"status": "ok", "type": type(value).__name__}


def _error(exc):
    return {"status": "error", "type": type(exc).__name__, "message": str(exc)}


def _aggregate(items, parser_counts):
    uids = [getattr(item, "uid", None) for item in items]
    uids = [uid for uid in uids if isinstance(uid, int)]
    counts = dict(parser_counts or {})
    counts.setdefault("accepted", len(items))
    return {"status": "ok", "complete": True, "count": len(items),
            "min_uid": min(uids) if uids else None, "max_uid": max(uids) if uids else None,
            "parser_counts": counts}


def _bulk_error(exc):
    return {"status": "error", "complete": False, "type": type(exc).__name__, "message": str(exc)}


def build_parser():
    parser = argparse.ArgumentParser(description="Read-only WL10 protocol capture probe")
    parser.add_argument("ip", help="Device IP")
    parser.add_argument("--output-dir", required=True, type=Path, help="New directory for raw captures and summary")
    parser.add_argument("--port", type=int, default=4370)
    parser.add_argument("--password", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--tcp-maxseg", type=int, default=None)
    parser.add_argument("--gap-timeout", type=int, default=None)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        print(f"ERROR: invalid IP address: {args.ip}", file=sys.stderr)
        return 2
    try:
        output_fd = _open_output_dir(args.output_dir)
    except OSError as exc:
        print(f"ERROR: cannot create output directory: {exc}", file=sys.stderr)
        return 2
    summary = {
        "schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(), "ended_utc": None,
        "constructor": {"ip": args.ip, "port": args.port, "password_configured": bool(args.password),
                        "timeout": args.timeout, "tcp_maxseg": args.tcp_maxseg, "gap_timeout": args.gap_timeout},
        "operations": {}, "users": {"status": "not_run"}, "attendance": {"status": "not_run"},
        "template_uids": [], "captures": [], "disconnect": {"status": "not_run"}, "outcome": "error",
    }
    zk = None
    exit_code = 1
    try:
        zk = CapturingZK(args.ip, port=args.port, password=args.password, timeout=args.timeout,
                         wl10=True, tcp_maxseg=args.tcp_maxseg, gap_timeout=args.gap_timeout,
                         capture_dir=args.output_dir, capture_dir_fd=output_fd)
        try:
            zk.connect()
            summary["operations"]["connect"] = {"status": "ok"}
        except Exception as exc:
            summary["operations"]["connect"] = _error(exc)
        else:
            for name in READ_METHODS:
                try:
                    summary["operations"][name] = _status(getattr(zk, name)())
                except Exception as exc:
                    summary["operations"][name] = _error(exc)
            try:
                users = zk.wl10_get_users()
                summary["users"] = _aggregate(users, zk._parser_counts.get("users"))
            except Exception as exc:
                summary["users"] = _bulk_error(exc)
            try:
                attendance = zk.wl10_get_attendance()
                summary["attendance"] = _aggregate(attendance, zk._parser_counts.get("attendance"))
            except Exception as exc:
                summary["attendance"] = _bulk_error(exc)
            summary["template_uids"] = sorted(getattr(zk, "_wl10_template_uids", ()))
            exit_code = int(any(item.get("status") == "error" for item in summary["operations"].values())
                            or summary["users"].get("status") != "ok"
                            or summary["attendance"].get("status") != "ok")
    except Exception as exc:
        summary["operations"]["probe"] = _error(exc)
    finally:
        if zk is not None:
            try:
                zk.disconnect()
                summary["disconnect"] = {"status": "ok"}
            except Exception as exc:
                summary["disconnect"] = _error(exc)
                exit_code = 1
        summary["captures"] = list(getattr(zk, "_captures", ()))
        summary["ended_utc"] = datetime.now(timezone.utc).isoformat()
        summary["outcome"] = "ok" if exit_code == 0 else "error"
        try:
            _write_exclusive(output_fd, "summary.json", (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode())
        except OSError as exc:
            print(f"ERROR: cannot write summary: {exc}", file=sys.stderr)
            exit_code = 1
        os.close(output_fd)
    console = {
        "outcome": summary["outcome"],
        "users": {key: summary["users"].get(key) for key in ("status", "complete", "count")},
        "attendance": {key: summary["attendance"].get(key) for key in ("status", "complete", "count")},
        "captures": len(summary["captures"]),
    }
    print(json.dumps(console, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
