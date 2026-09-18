#!/usr/bin/env python3
"""Read-only WL10 protocol capture probe."""

import argparse
import hashlib
import ipaddress
import json
import os
import struct
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
    const.CMD_DATA_WRRQ,
}
# Raw reads allowed on the wire. CMD_DB_RRQ (7) is deliberately absent: a
# direct CMD 7 with an empty body returned terminal ACK_OK and zero payload
# on all three authorized WL10s. The template table is read through
# CMD_DATA_WRRQ (1503) instead, and only with the exact body below.
_ALLOWED_RAW = {const.CMD_USERTEMP_RRQ, const.CMD_ATTLOG_RRQ}
_ALLOWED_RAW_REQUESTS = {
    (const.CMD_DATA_WRRQ, struct.pack('<bhii', 1, const.CMD_DB_RRQ, const.FCT_FINGERTMP, 0)),
}
# Raw chunk command used only by the internal template-chunk flow. It is not
# a generic read API: the request body must be exactly ``pack('<ii', start,
# size)`` with a non-negative start and a positive size within one chunk.
_RAW_CHUNK_COMMAND = 1504
_MAX_RAW_CHUNK = 0xFFC0

# Per-user/per-finger template command. Reachable only through the bounded
# scan below: the uid must be a successfully parsed real user, the fid must be
# 0..9, and reserved `_wl10_template_uids` slots are never probed.
_RAW_USER_TEMPLATE_COMMAND = 88
_MAX_RAW_FID = 9
# Logical operation name carried in the capture metadata for a wire command.
_WIRE_LOGICAL = {const.CMD_DATA_WRRQ: const.CMD_DB_RRQ}


def _raw_chunk_range(command_string):
    """Return ``(start, size)`` for a bounded chunk request, else ``None``."""
    if len(command_string) != 8:
        return None
    start, size = struct.unpack('<ii', command_string)
    if start < 0 or size <= 0 or size > _MAX_RAW_CHUNK:
        return None
    return start, size

SIZE_COUNTERS = (
    'users', 'fingers', 'records', 'cards',
    'users_cap', 'users_av', 'fingers_cap', 'fingers_av',
    'rec_cap', 'rec_av', 'faces', 'faces_cap',
)


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
        self._capture_seq = {const.CMD_DB_RRQ: 0, const.CMD_DATA_WRRQ: 0, _RAW_CHUNK_COMMAND: 0,
                             const.CMD_USERTEMP_RRQ: 0, const.CMD_ATTLOG_RRQ: 0}
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

    def _wl10_read_raw_command(self, command_code, command_string=b''):
        request = (command_code, command_string)
        if request not in _ALLOWED_RAW_REQUESTS \
                and not (command_code in _ALLOWED_RAW and not command_string):
            raise ZKErrorResponse(
                f"command {command_code} with a {len(command_string)}-byte body "
                "not allowed in read-only probe")
        return self._record_capture(
            command_code, super()._wl10_read_raw_command(command_code, command_string))

    def _wl10_parse_users(self, raw_data):
        records, declared = self._wl10_strip_header(raw_data, const.WL10_USER_RECORD_SIZE)
        users = super()._wl10_parse_users(raw_data)
        self._parser_counts["users"] = {
            "declared": declared, "candidate": len(records) // const.WL10_USER_RECORD_SIZE,
            "accepted": len(users),
        }
        return users

    def _wl10_read_user_template(self, uid, fid):
        """Read one user's template, only for a real user and fid 0..9.

        There is no generic command API here. The uid must have come from
        the successfully parsed real-user table, and reserved
        ``_wl10_template_uids`` slots are never probed because they are
        template storage, not people.
        """
        known = getattr(self, "_known_user_uids", None)
        reserved = getattr(self, "_wl10_template_uids", set())
        if uid not in known or uid in reserved \
                or not isinstance(fid, int) or isinstance(fid, bool) \
                or not 0 <= fid <= _MAX_RAW_FID:
            raise ZKErrorResponse(
                f"user template read uid={uid!r} fid={fid!r} is not a known "
                "real user and finger index, not allowed in read-only probe")
        # The reply_id the request will carry, and the one the device
        # answers with. A device that processes the command advances its
        # counter; one that merely refuses does not. Both are protocol
        # counters, never payload bytes.
        request_rid = getattr(self, "_ZK__reply_id", None)
        if request_rid is not None:
            request_rid &= 0xFFFF
        try:
            payload = super()._wl10_read_user_template(uid, fid)
        except ZKErrorResponse:
            # An unclassified status is diagnostic evidence: record the
            # status and the protocol lengths, never any payload byte.
            observed = getattr(self, "_wl10_last_data_response", None) or {}
            self._captures.append({
                "command": _RAW_USER_TEMPLATE_COMMAND,
                "wire_command": _RAW_USER_TEMPLATE_COMMAND,
                "uid": uid,
                "fid": fid,
                "status": "error",
                "wire_status": observed.get("status"),
                "payload_len": observed.get("payload_len"),
                "request_rid": request_rid,
                "rid": observed.get("rid"),
            })
            raise
        # Command 88 returns a fingerprint template, which is a biometric
        # identifier. Unlike the bulk captures it is recorded as metadata
        # only: no cmd_88 binary file is ever created for it.
        template = bytes(payload.template) if payload is not None else b''
        observed = getattr(self, "_wl10_last_data_response", None) or {}
        self._captures.append({
            "command": _RAW_USER_TEMPLATE_COMMAND,
            "wire_command": _RAW_USER_TEMPLATE_COMMAND,
            "uid": uid,
            "fid": fid,
            "status": "present" if payload is not None else "absent",
            "size": len(template),
            "sha256": hashlib.sha256(template).hexdigest(),
            # For a present read this is the announcement frame's rid; the
            # prepared body's terminal ACK advances it further.
            "request_rid": request_rid,
            "rid": observed.get("rid"),
        })
        return payload

    def _wl10_read_announced_chunk(self, start, size):
        """Read one bounded template chunk, only inside the announced range.

        ``start``/``size`` must describe a chunk inside the table the device
        announced and no larger than one max chunk. This is not a generic
        arbitrary read: with no validated announcement, or outside its
        bounds, the request is refused before any socket send.
        """
        chunk_range = _raw_chunk_range(struct.pack("<ii", start, size))
        announced = getattr(self, "_wl10_announced_total", None)
        if chunk_range is None or announced is None \
                or chunk_range[0] + chunk_range[1] > announced:
            raise ZKErrorResponse(
                f"chunk read start={start} size={size} outside the announced "
                "template range is not allowed in read-only probe")
        payload = super()._wl10_read_announced_chunk(start, size)
        return self._record_capture(
            _RAW_CHUNK_COMMAND, payload, read={"start": start, "size": size})

    def _record_capture(self, command_code, payload, read=None):
        """Persist one response and its non-sensitive metadata."""
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
        capture = {
            "command": _WIRE_LOGICAL.get(command_code, command_code),
            "wire_command": command_code,
            "filename": filename, "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "ack": {"command": ack[0], "reply_id": ack[1]} if ack else None,
        }
        if read is not None:
            # Non-sensitive range metadata only; never the request bytes.
            capture["read"] = read
        self._captures.append(capture)
        return payload

    def _wl10_parse_announcement(self, raw_data):
        total = super()._wl10_parse_announcement(raw_data)
        # Remember the validated announcement so the raw chunk guard can
        # bound every 1504 request to the table the device announced.
        self._wl10_announced_total = total
        return total

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


def _user_template_summary(per_uid):
    """Summarize per-user template reads without bytes, marks or identities.

    Emits only a total count, per-UID count plus present fid list, and
    ``(uid, fid, valid, size)`` with a per-template SHA-256. Names, badges,
    template bytes and ``Finger.mark`` never leave the process.
    """
    entries = []
    users = {}
    for uid in sorted(per_uid):
        fingers = per_uid[uid]
        present = []
        for finger in fingers:
            template = bytes(finger.template)
            entries.append({
                "uid": finger.uid, "fid": finger.fid, "valid": finger.valid,
                "size": len(template), "sha256": hashlib.sha256(template).hexdigest(),
            })
            present.append(finger.fid)
        users[str(uid)] = {"count": len(fingers), "present_fids": sorted(present)}
    return {"status": "ok", "complete": True, "count": len(entries),
            "per_uid": users, "entries": entries}


def _template_summary(templates):
    """Summarize templates without serializing bytes or Finger.mark.

    Emits only: total count, per-UID counts, ``(uid, fid, valid, size)``
    metadata, a per-template SHA-256 and a size histogram. Template
    bytes and ``Finger.mark`` never leave the process.
    """
    entries = []
    per_uid = {}
    histogram = {}
    total_bytes = 0
    for finger in templates:
        template = bytes(finger.template)
        entries.append({
            "uid": finger.uid, "fid": finger.fid, "valid": finger.valid,
            "size": len(template), "sha256": hashlib.sha256(template).hexdigest(),
        })
        per_uid[str(finger.uid)] = per_uid.get(str(finger.uid), 0) + 1
        histogram[str(len(template))] = histogram.get(str(len(template)), 0) + 1
        total_bytes += len(template)
    return {"status": "ok", "complete": True, "count": len(entries),
            "total_bytes": total_bytes, "per_uid": per_uid, "entries": entries,
            "size_histogram": histogram}


def _read_sizes_summary(zk):
    """Read the non-sensitive size counters needed for analysis."""
    return {name: getattr(zk, name, None) for name in SIZE_COUNTERS}


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


def _stream_summary(zk):
    """Report whether the read session is still in sync.

    A failed chunk read leaves announced bytes unread, so the session is
    unsafe for any later read. Surfacing it lets the summary distinguish
    "the device reported nothing" from "the read desynchronized".
    """
    return {"safe": bool(getattr(zk, "_wl10_stream_safe", True))}


def _failed(entry):
    """A read that ran and did not succeed. "skipped" is a deliberate omission."""
    return entry.get("status") not in ("ok", "skipped")


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
    parser.add_argument("--skip-template-table", action="store_true",
                        help="Skip the standard FCT_FINGERTMP table read and report it "
                             "as skipped. Use it for a per-user fingerprint sweep: on "
                             "this firmware the standard table fetch has been observed "
                             "leaving a device answering every later template read with "
                             "ACK_ERROR until it was restarted.")
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
        "templates": {"status": "not_run"}, "sizes": {},
        "user_templates": {"status": "not_run"},
        "stream": {"safe": True},
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
            summary["sizes"] = _read_sizes_summary(zk)
            try:
                users = zk.wl10_get_users()
                summary["users"] = _aggregate(users, zk._parser_counts.get("users"))
                # Nameless sidecar records the firmware interleaves with the
                # real table. They are template / linking storage, kept out
                # of the user list, and listing them here keeps them
                # auditable without dressing them up as people.
                summary["users"]["sidecars"] = sorted(
                    getattr(zk, "_wl10_sidecar_uids", ()))
                # The per-user template scan needs the real uids; reserved
                # interleaved template slots are never probed.
                zk._known_user_uids = {user.uid for user in users}
            except Exception as exc:
                summary["users"] = _bulk_error(exc)
            try:
                attendance = zk.wl10_get_attendance()
                summary["attendance"] = _aggregate(attendance, zk._parser_counts.get("attendance"))
            except Exception as exc:
                summary["attendance"] = _bulk_error(exc)
            try:
                uids = sorted(getattr(zk, "_known_user_uids", ()))
                summary["user_templates"] = _user_template_summary(
                    zk.wl10_scan_user_templates(uids))
            except Exception as exc:
                summary["user_templates"] = _bulk_error(exc)
            try:
                if args.skip_template_table:
                    summary["templates"] = {
                        "status": "skipped", "complete": None, "count": None}
                else:
                    summary["templates"] = _template_summary(zk.wl10_get_templates())
            except Exception as exc:
                summary["templates"] = _bulk_error(exc)
            summary["template_uids"] = sorted(getattr(zk, "_wl10_template_uids", ()))
            summary["stream"] = _stream_summary(zk)
            exit_code = int(any(item.get("status") == "error" for item in summary["operations"].values())
                            or _failed(summary["users"])
                            or _failed(summary["attendance"])
                            or _failed(summary["templates"])
                            or _failed(summary["user_templates"])
                            or not summary["stream"]["safe"])
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
        "templates": {key: summary["templates"].get(key) for key in ("status", "complete", "count")},
        "user_templates": {key: summary["user_templates"].get(key) for key in ("status", "complete", "count")},
        "stream": summary.get("stream", {"safe": True}),
        "captures": len(summary["captures"]),
    }
    print(json.dumps(console, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
