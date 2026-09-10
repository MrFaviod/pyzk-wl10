#!/usr/bin/env python3
"""Safe WL10 live runner: read-only by default, one explicit write when asked."""
import argparse
import errno
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pyzk_wl10'))

from zk import ZK, const  # noqa: E402

UID_MIN, UID_MAX = 7, 1000
USER_ID_MIN, USER_ID_MAX = 999950, 999999
TEST_USER_ID_START = USER_ID_MIN


def find_free_uid(existing_uids, start=UID_MIN, ceiling=UID_MAX, forbidden=()):
    blocked = set(existing_uids) | set(forbidden)
    return next((uid for uid in range(start, ceiling + 1) if uid not in blocked), None)


def find_free_user_id(existing_user_ids, start=TEST_USER_ID_START,
                      floor=USER_ID_MIN, ceiling=USER_ID_MAX):
    return next((str(value) for value in range(max(start, floor), ceiling + 1)
                 if str(value) not in existing_user_ids), None)


def _valid_uid(value):
    return bool(re.fullmatch(r'[0-9]+', value or '')) and UID_MIN <= int(value) <= UID_MAX


def _valid_badge(value):
    return bool(re.fullmatch(r'[0-9]{6}', value or '')) and USER_ID_MIN <= int(value) <= USER_ID_MAX


def _user_badge(user):
    return str(getattr(user, 'badge', '') or getattr(user, 'user_id', ''))


def _baseline(users, templates):
    uids = sorted(int(user.uid) for user in users)
    badges = sorted(_user_badge(user) for user in users if _user_badge(user))
    digest = hashlib.sha256(json.dumps({'uids': uids, 'badges': badges}, separators=(',', ':')).encode()).hexdigest()
    return {'count': len(users), 'uid_count': len(set(uids)), 'badge_count': len(set(badges)),
            'template_count': len(templates), 'hash': digest}


def _same_user(user, uid, badge):
    return (int(user.uid) == uid and str(user.user_id) == badge and
            getattr(user, 'name', '') == f'RE110-{uid}' and
            int(user.privilege) == const.USER_DEFAULT and int(getattr(user, 'card', 0)) == 0)


def _open_evidence_parent(path):
    absolute = os.path.abspath(os.fspath(path))
    components = absolute.split(os.sep)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = os.open(os.sep, flags)
    try:
        for component in components[1:-1]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
    except Exception:
        os.close(current_fd)
        raise
    return current_fd, components[-1]


def _write_evidence(parent_fd, basename, evidence):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(basename, flags, 0o600, dir_fd=parent_fd)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(evidence, stream, indent=2, sort_keys=True)
        stream.write('\n')


def _preflight_evidence(path):
    parent_fd, basename = _open_evidence_parent(path)
    try:
        try:
            os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), path)
        if not os.access('.', os.W_OK | os.X_OK, dir_fd=parent_fd):
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
    except Exception:
        os.close(parent_fd)
        raise
    return parent_fd, basename
def _load_read_gate(path, target_ip):
    try:
        with open(path, encoding='utf-8') as stream:
            gate = json.load(stream)
        captured = datetime.fromisoformat(gate['captured_utc'])
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise ValueError(f'invalid --read-gate-json: {exc}') from exc
    age = (datetime.now(timezone.utc) - captured.astimezone(timezone.utc)).total_seconds()
    if gate.get('schema') != 1 or gate.get('target_ip') != target_ip:
        raise ValueError('read gate target/schema mismatch')
    if age < 0 or age > 3600:
        raise ValueError('read gate is stale')
    required = (
        gate.get('identity', {}).get('status') == 'ok',
        gate.get('users', {}).get('status') == 'ok',
        gate.get('users', {}).get('complete') is True,
        gate.get('users', {}).get('parser_success') is True,
        gate.get('attendance', {}).get('status') == 'ok',
        gate.get('attendance', {}).get('complete') is True,
        gate.get('attendance', {}).get('parser_success') is True,
        gate.get('templates', {}).get('present') is True,
        gate.get('baseline', {}).get('consistent') is True,
    )
    if not all(required):
        raise ValueError('read gate does not prove complete successful baseline')
    return gate


def _parser():
    parser = argparse.ArgumentParser(
        description='WL10 runner; safe read-only default. --write-one performs one residue-preserving write.')
    parser.add_argument('ips', nargs='+', help='device IP address')
    parser.add_argument('--verbose', action='store_true', help='show ZK transport diagnostics')
    parser.add_argument('--write-one', action='store_true',
                        help='enable exactly one regular-user write; residue is left on the device')
    parser.add_argument('--uid', help='explicit UID (7..1000), required with --write-one')
    parser.add_argument('--user-id', help='explicit six-digit badge (999950..999999), required with --write-one')
    parser.add_argument('--evidence-json', help='sanitized evidence path; required with --write-one, never overwritten')
    parser.add_argument('--read-gate-json', help='Task-6 success authorization; required with --write-one')
    return parser


def _validate_args(args):
    for ip in args.ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError('--ips must contain literal IP addresses') from exc
    if not args.write_one and args.evidence_json:
        raise ValueError('--evidence-json requires --write-one')
    if not args.write_one and any(value is not None for value in (args.uid, args.user_id, args.read_gate_json)):
        raise ValueError('--uid, --user-id, and --read-gate-json require --write-one')
    if args.write_one:
        if len(args.ips) != 1:
            raise ValueError('--write-one requires exactly one IP')
        missing = [name for name, value in (('--uid', args.uid), ('--user-id', args.user_id),
                                              ('--evidence-json', args.evidence_json),
                                              ('--read-gate-json', args.read_gate_json)) if not value]
        if missing:
            raise ValueError('write mode requires ' + ', '.join(missing))
        if not _valid_uid(args.uid):
            raise ValueError('--uid must be 7..1000')
        if not _valid_badge(args.user_id):
            raise ValueError('--user-id must be a six-digit badge in 999950..999999')
        args._read_gate = _load_read_gate(args.read_gate_json, args.ips[0])
        try:
            args._evidence_parent_fd, args._evidence_basename = _preflight_evidence(args.evidence_json)
        except OSError as exc:
            raise ValueError(f'--evidence-json unavailable: {exc.strerror}') from exc

def _run_one(ip, args):
    uid = int(args.uid) if args.uid else None
    badge = args.user_id
    result = False
    evidence = {'outcome': 'failure', 'stage': 'connect', 'candidate': None}
    if args.write_one:
        evidence['candidate'] = {'uid': uid, 'user_id': badge}
    zk = None
    try:
        zk = ZK(ip, timeout=20, ommit_ping=True, force_udp=False, wl10=True, verbose=args.verbose)
        try:
            zk.connect()
            users = zk.wl10_get_users()
            templates = set(getattr(zk, '_wl10_template_uids', set()))
            evidence['baseline'] = _baseline(users, templates)
            occupied_uids = {int(user.uid) for user in users}
            occupied_badges = {_user_badge(user) for user in users if _user_badge(user)}

            if not args.write_one:
                candidate_uid = find_free_uid(occupied_uids, forbidden=templates)
                candidate_badge = find_free_user_id(occupied_badges)
                if candidate_uid is None or candidate_badge is None:
                    raise ValueError('no free synthetic candidate')
                evidence.update(outcome='success', stage='read-only',
                                candidate={'uid': candidate_uid, 'user_id': candidate_badge})
                print(f'[OK] read-only baseline; candidate uid={candidate_uid} badge={candidate_badge}; no write performed')
                result = True
            else:
                if uid in occupied_uids or badge in occupied_badges or uid in templates:
                    raise ValueError('requested candidate is occupied or reserved')

                evidence['stage'] = 'fresh-baseline'
                users = zk.wl10_get_users()
                templates = set(getattr(zk, '_wl10_template_uids', set()))
                evidence['fresh_baseline'] = _baseline(users, templates)
                occupied_uids = {int(user.uid) for user in users}
                occupied_badges = {_user_badge(user) for user in users if _user_badge(user)}
                if uid in occupied_uids or badge in occupied_badges or uid in templates:
                    raise ValueError('requested candidate changed during preflight')

                evidence['stage'] = 'write'
                if not zk.wl10_set_user(uid=uid, user_id=badge, name=f'RE110-{uid}',
                                         privilege=const.USER_DEFAULT, card=0):
                    raise RuntimeError('write rejected')

                evidence['stage'] = 'readback'
                readback = zk.wl10_get_users()
                matches = [user for user in readback if _same_user(user, uid, badge)]
                evidence['readback'] = {
                    'status': 'match' if len(matches) == 1 else 'mismatch',
                    'count': len(matches),
                    'hash': _baseline(readback, getattr(zk, '_wl10_template_uids', set()))['hash'],
                }
                if len(matches) != 1:
                    raise ValueError('readback mismatch')
                evidence['outcome'] = 'success'
                print(f'[OK] wrote and verified uid={uid} badge={badge}; residue left on device')
                result = True
        except Exception as exc:
            evidence['error'] = type(exc).__name__
            print(f'[FAIL] stage={evidence["stage"]} type={type(exc).__name__}')
        finally:
            try:
                if zk is not None:
                    zk.disconnect()
            except Exception as exc:
                evidence['disconnect'] = 'error'
                evidence['error'] = type(exc).__name__
                evidence['outcome'] = 'failure'
                evidence['stage'] = 'disconnect'
                result = False
            if args.evidence_json:
                try:
                    _write_evidence(args._evidence_parent_fd, args._evidence_basename, evidence)
                except OSError as exc:
                    print(f'[FAIL] evidence write type={type(exc).__name__}')
                    result = False
    finally:
        if args.evidence_json:
            os.close(args._evidence_parent_fd)
    return result

def main(argv=None):
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        _validate_args(args)
    except ValueError as exc:
        print(f'[FAIL] {exc}', file=sys.stderr)
        return 2
    overall = True
    for ip in args.ips:
        args.ip = ip
        overall = _run_one(ip, args) and overall
    return 0 if overall else 1


if __name__ == '__main__':
    sys.exit(main())
