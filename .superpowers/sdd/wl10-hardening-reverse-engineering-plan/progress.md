# SDD ledger — plan: /home/informatica/.omp/agent/sessions/-Dev-zkteco-zk2/2026-09-09T17-33-34-909Z_01a0873b-713d-7289-9060-7a07989fe888/local/wl10-hardening-reverse-engineering-plan.md

Merge base: e19b1cd7bdc748ea984f7af23ab99da9b2de3116
Branch: reengineering
Workspace: normal dirty checkout; inherited working tree remains authoritative per approved plan.
Pre-existing generated archive: pyzk_wl10_tests.tar.gz; must remain untracked and untouched.

Task 1: completed; fix rounds 1-2 completed
Agent: BaselineCurator
Base hash: e19b1cd7bdc748ea984f7af23ab99da9b2de3116
Head hash: 3da9b32
Files: AGENTS.md; pyzk_wl10/zk/base.py; pyzk_wl10/zk/tests/test_parse_attendance.py; pyzk_wl10/zk/tests/test_parse_users.py; pyzk_wl10/zk/tests/test_set_user.py; pyzk_wl10/zk/tests/test_strip_header.py; pyzk_wl10/zk/tests/test_wl10_dispatch.py; pyzk_wl10/zk/tests/test_wl10_resilience.py; specs/wl10_reengineering_review.md
Report: /home/informatica/Dev/zkteco/zk2/.superpowers/sdd/wl10-hardening-reverse-engineering-plan/task-1-report.md
Verification: python3 -m pytest pyzk_wl10/zk/tests/ -q — 139 passed in 3.57s; exact nine-file allowlist; sanitized spec excludes raw hexdump/device identifiers; archive untracked; real Git trailers verified
Reviewer verdict: fix rounds addressed traceability, baseline verification, and raw-evidence containment findings
Rollback boundary: 3da9b32

Task 2: completed; fix rounds 1-3 completed
Agent: WL10SafetyFixer
Base hash: 3da9b32f77cc8222c53f3a2f0eacbccc79a6d4ef
Head hash: 4d731570c5105dbece78497c6d4329cb0b3dc9ab
Files: pyzk_wl10/zk/base.py; pyzk_wl10/zk/tests/test_parse_users.py; pyzk_wl10/zk/tests/test_set_user.py; pyzk_wl10/zk/tests/test_wl10_reboot.py
Report: /home/informatica/Dev/zkteco/zk2/.superpowers/sdd/wl10-hardening-reverse-engineering-plan/task-2-report.md
Verification: focused Task 2 suite — 70 passed; raw CMD_REFRESHDATA ordering asserted; all post-3da9b32 commits have parseable Agent-Role, Agent-Id, Verification trailers
Reviewer verdict: approved; functional ordering and trailer re-reviews passed
Rollback boundary: 4d731570c5105dbece78497c6d4329cb0b3dc9ab

Task 3: completed
Agent: DispatchFixer
Base hash: 4d731570c5105dbece78497c6d4329cb0b3dc9ab
Head hash: c97a2d7335de756891cd860414114177a035057e
Files: pyzk_wl10/zk/base.py; pyzk_wl10/zk/tests/test_wl10_dispatch.py; pyzk_wl10/zk/tests/test_const.py
Report: /home/informatica/Dev/zkteco/zk2/.superpowers/sdd/wl10-hardening-reverse-engineering-plan/task-3-report.md
Verification: focused dispatch suite — 19 passed; real Git trailers parse
Reviewer verdict: approved; no issues
Rollback boundary: c97a2d7335de756891cd860414114177a035057e

Task 4: completed; fix rounds 1-3 completed; all scoped reviews passed
Agents: ReadProbeBuilder; FinalFixer; RawMutationGateFixer
Base hash: c97a2d7335de756891cd860414114177a035057e
Head hash: 9a460edf33512dbabfe8b748f921319763ffe40b
Files: wl10_probe_read.py; pyzk_wl10/zk/tests/test_wl10_probe_read.py
Reports: task-4-report.md; review-ce4929a..b14b2c3.diff; review-b14b2c3..9a460ed.diff
Verification: focused 14 passed; offline 180 passed; --help exit 0; 2-file stats; contiguous trailers; raw-gate re-review PASS
Reviewer verdict: security, contract, housekeeping, and raw mutation paths addressed; no new issue
Rollback boundary: 9a460edf33512dbabfe8b748f921319763ffe40b

Task 5: completed; all scoped reviews passed; final blockers closed
Agents: LiveRunnerHardener; LiveRunnerFixer; EvidenceReservationFixer; EvidencePathHardener; RetainedEvidenceParentFixer; FinalFixer; DocsPolisher
Base hash: e5690a4c2e49084e00337595e252f03584f81b0a
Head hash: 325989a5a5015c431abada1e1ee8934b02ad0415
Files: test_runner_wl10.py; pyzk_wl10/zk/tests/test_live_runner_wl10.py; pyzk_wl10/zk/base.py; pyzk_wl10/zk/tests/test_socket_mss.py; wl10_probe_read.py; pyzk_wl10/zk/tests/test_wl10_probe_read.py; README.md; AGENTS.md
Reports: task-5-report.md; final review package review-e19b1cd..325989a.diff
Verification: final controller rerun — focused runner 16 passed; focused probe 25 passed; offline 208 passed; both CLI helps exit 0; git diff --check clean; every commit e19b1cd..HEAD has parseable contiguous Agent-Role/Agent-Id/Verification trailers; archive only untracked item
Final review: security PASS; correctness PASS with prior P3 README/count and read-gate documentation fixes applied; unsigned local read-gate is an accepted informational limitation under the approved plan
Final blockers fixed: missing b14 trailers, shell ping injection, probe output-dir TOCTOU, executable write gate bypass, disconnect evidence truth; README/AGENTS examples aligned
Task 6 remains failed after the recovered VPN characterization below; Task 7 write remains blocked; no live write operation was run

Task 6: read-only characterization completed for the VPN profile; overall gate FAILED; Task 7 blocked
Agent: DeviceOperator110152 / Task6DocsReconciler
Target: <DEVICE_IP>
Evidence root: `.superpowers/sdd/wl10-hardening-reverse-engineering-plan/evidence/110152`
Default command: `python3 /home/informatica/Dev/zkteco/zk2/wl10_probe_read.py <DEVICE_IP> --output-dir <evidence>/default --timeout 20`; UTC 01:55:22–01:57:22; wrapper timeout/interrupted; no probe exit; 5 capture files; no summary; users/attendance/identity/templates/parser/capture aggregate unavailable; mutation observed false
Default SHA-256: cmd_09_001.bin=005f057892da47849a982647215065a25cc1fbf1727377e7abd48298f04d8dc6; cmd_09_002.bin=005f057892da47849a982647215065a25cc1fbf1727377e7abd48298f04d8dc6; cmd_13_001.bin=b6f59fbbfb03ee482a941683ab267d59ecb46ee668a1fa64ecd445b946e2d4f5; cmd_13_002.bin=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; cmd_13_003.bin=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
VPN profile command: `python3 /home/informatica/Dev/zkteco/zk2/wl10_probe_read.py <DEVICE_IP> --output-dir <evidence>/vpn1200 --timeout 20 --tcp-maxseg 1200 --gap-timeout 3`; UTC 04:57:04–04:57:12; exit 0; summary outcome `ok`; `connect`, `get_device_name`, `get_platform`, and `get_firmware_version` statuses `ok`; mutation observed false
VPN users: status `ok`, complete `true`, count `8`; parser declared/candidate/accepted=`8/8/8`. VPN attendance: status `ok`, complete `true`, count `48`; parser declared/candidate/accepted=`813/813/48`.
VPN captures: command 9, 588 B, SHA-256 `005f057892da47849a982647215065a25cc1fbf1727377e7abd48298f04d8dc6`, ACK command `2000`, reply ids `31/32` across duplicate payloads; command 13, 17898 B, SHA-256 `a390aaf026069ae3e93a1c91ba95fddebd61d7f4bc673b67d6aa33bb0e7fcc54`, ACK command `2000`, reply id `34`; duplicate command-9 payload SHA is deduplicated for capture counting; no user total is inferred beyond the summary count
VPN summary SHA-256: `9793f7973370047e321ca0e45096e86a95f4027c4d2fef92e4445ea17060995d`; `template_uids=[]`; transport capture unavailable because `CAP_NET_RAW` was unavailable
Safety: no listar_marcaciones.py, check_device.py, mutation runner, or Task 7 write; raw payloads withheld
Gate: identity PASS; complete users/attendance PASS; parser PASS; baseline consistency PASS within the VPN profile; template UID set FAIL because empty; overall Task 6 gate FAILED; Task 7 remains blocked
Rollback mapping: b14b2c3→6a86636; 9a460ed→b4d61cd; fc64860→3b3b3d4; c9b53f4→d9278c1; b1af44e→6a21114; e5690a4→344b00a; b070388→fbe4d72; 61a6344→06c5a09; prior FinalFixer 2419f6f→837f538; DocsPolisher→325989a
Deferred informational: local read-gate JSON is unsigned; upgrade to signed provenance only if threat model includes local filesystem compromise or untrusted operators
Rollback boundary: 325989a5015c431abada1e1ee8934b02ad0415