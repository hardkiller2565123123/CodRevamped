# 1.44 integration, 2026-10-04

Target: D:\unlock\Modern Warfare\Call of Duty Modern Warfare (1.44)
Active metadata: 1.44.0.10435696.
Exact PE fingerprint: 61671CE8 / 22C1BA00 / 06D429F8.

Rebuilt and deployed existing shared backend and lightweight version proxy.
Preserved previous target binaries in codrevamped-backup-*.
Retained current worktree changes, including the release-CRT Debug DLL settings.

Fixed missing proxy integration of existing Auth3 trust for this fingerprint.
The diagnostics profile in game/1.44addressess.h already identifies the
294-byte response key at RVA 0708E2B0. The proxy now uses this location only
for the exact 1.44 fingerprint and compares the entire original key before
writing the local server public key. The 1.20 profile remains unchanged;
unsupported builds are still rejected. No auth/fence/menu success is forced.

Runtime verified AUTH3-PROFILE build=1.44 and AUTH3-TRUST PATCHED at 0708E2B0.
Client now reaches prod.umbrella.demonware.net / LSG token exchange. Current
server returns UMBRELLA_STOCK_NAMED_V15 with mintedDwAuthTicketV67. Requests
match the issued Auth3 server ticket. It then retries without any attributed
TCP lobby connection; UDP/3074 is not evidence of lobby progress.

Added fingerprint-scoped use of existing exact-text Safe Mode prompt handler;
runtime log confirms handlers=2/2 and IDNO with settings preserved.
Retail 1.44 remains outside older-build OS/launcher compatibility hooks.

Builds pass, but the existing DCQoS test suite does NOT pass: its line 74
expects an empty JSON request to be rejected, while the current shared
implementation accepts a nonempty legacy string. Reconcile contract/tests
before claiming regression coverage. No test failure was hidden or relaxed.

Main menu is NOT verified. Next investigation is the exact 1.44 Umbrella
response parser and transition after HTTP 200; avoid speculative global
response changes that would regress other versions.
