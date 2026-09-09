#!/usr/bin/env python3
"""Read-only WL10 protocol capture probe."""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "pyzk_wl10"))
from zk import ZK, const  # noqa: E402

READ_METHODS = (
    "get_device_name", "get_platform", "get_firmware_version", "get_serialnumber",
    "get_mac", "get_face_version", "get_fp_version", "get_extend_fmt",
    "get_user_extend_fmt", "get_face_fun_on", "get_compat_old_firmware",
    "get_network_params", "get_pin_width", "get_time", "read_sizes",
)


class CapturingZK(ZK):
    """ZK client that persists only CMD 9/13 application payloads."""

    def __init__(self, *args, capture_dir=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._capture_dir = Path(capture_dir) if capture_dir else None
        self._capture_seq = {const.CMD_USERTEMP_RRQ: 0, const.CMD_ATTLOG_RRQ: 0}
        self._captures = []

    def _wl10_read_raw_command(self, command_code):
        payload = super()._wl10_read_raw_command(command_code)
        if command_code not in self._capture_seq or self._capture_dir is None:
            return payload
        self._capture_seq[command_code] += 1
        filename = f"cmd_{command_code:02d}_{self._capture_seq[command_code]:03d}.bin"
        (self._capture_dir / filename).write_bytes(payload)
        ack = getattr(self, "_wl10_last_ack", None)
        self._captures.append({
            "command": command_code, "filename": filename, "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "ack": {"command": ack[0], "reply_id": ack[1]} if ack else None,
        })
        return payload


def _status(value):
    if isinstance(value, dict):
        return {"status": "ok", "type": "dict", "fields": len(value), "keys": sorted(value)}
    return {"status": "ok", "type": type(value).__name__}


def _error(exc):
    return {"status": "error", "type": type(exc).__name__, "message": str(exc)}


def _aggregate(items):
    uids = [getattr(item, "uid", None) for item in items]
    uids = [uid for uid in uids if isinstance(uid, int)]
    return {"status": "ok", "complete": True, "count": len(items),
            "min_uid": min(uids) if uids else None, "max_uid": max(uids) if uids else None}


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
    if args.output_dir.exists() or args.output_dir.is_symlink():
        print(f"ERROR: output directory already exists: {args.output_dir}", file=sys.stderr)
        return 2
    args.output_dir.mkdir(parents=True)
    summary = {
        "schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(), "ended_utc": None,
        "constructor": {"ip": args.ip, "port": args.port, "password": args.password,
                        "timeout": args.timeout, "tcp_maxseg": args.tcp_maxseg, "gap_timeout": args.gap_timeout},
        "operations": {}, "users": {"status": "not_run"}, "attendance": {"status": "not_run"},
        "template_uids": [], "captures": [], "disconnect": {"status": "not_run"}, "outcome": "error",
    }
    zk = None
    exit_code = 1
    try:
        zk = CapturingZK(args.ip, port=args.port, password=args.password, timeout=args.timeout,
                         wl10=True, tcp_maxseg=args.tcp_maxseg, gap_timeout=args.gap_timeout,
                         capture_dir=args.output_dir)
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
                summary["users"] = _aggregate(zk.wl10_get_users())
            except Exception as exc:
                summary["users"] = _bulk_error(exc)
            try:
                summary["attendance"] = _aggregate(zk.wl10_get_attendance())
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
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"outcome": summary["outcome"], "users": summary["users"],
                      "attendance": summary["attendance"], "captures": len(summary["captures"])}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
