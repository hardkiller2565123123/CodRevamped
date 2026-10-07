# Steam retail integration — 2026-10-05

## In-process parser research and response corrections

External process reads were denied, but the already-loaded project DLL can
inspect its own readable image pages. Added opt-in `SteamRetailParserProbe.inl`,
scoped to this exact fingerprint. It copies only bounded code windows and
RIP-relative references, skips guarded/uncommitted pages, and never patches
code/state or changes memory protections. Raw captures are in the retail
folder's `steam_retail_parser.log` and timestamped backups. Decode with
`tools/tests/decode-retail-probe.py` (pefile + capstone).

Confirmed loaded-code routines:

- `6CBB960`: login response validation, invokes `6CBAF00` for title data.
- `6CACC30`: title needs userID, accountType, username, sessionID, titleID,
  clientID, crossplayEnabled, sessionKey (33-byte string buffer/base64 to
  24 bytes), loginTicket. Optional lsgEndpoint and loginTicketIssueTime are read.
- `6CAC5C0`: Umbrella needs unoID, unoUsername, umbrellaID, accessExpiresIn,
  refreshExpiresIn, accessToken, refreshToken, accounts array.
- `6CAD0F0`: UNO needs accountType, unoID, and `userName` (capital N).
- `6CBBEC1`: after those objects pass, rejects a zero issued-at timestamp.

V2 response added missing title fields using existing local server ticket/key.
Live client advanced from title-data failure to Umbrella-data failure, proving
the title change was accepted. V3 added captured Umbrella/UNO fields; client
advanced to a truncated missing-response-data error. Full parser capture
identifies that next branch as missing Login Ticket Issued at Timestamp.
V4 adds numeric uint32 `title.loginTicketIssueTime`; runtime result pending.
V4 runtime subsequently confirmed acceptance: native lobby DNS, TCP 3074 hello,
and 153-byte 0x82 client challenge. Menu is still not established.

The shared lobby transcript incorrectly hard-coded advertised versions 210/220;
retail advertises 220/231. Store/hash the received 20-byte hello remainder.
Retail also consumes the login response's sessionKey directly rather than
expanding it with Auth3's public-SPKI key. An exact client-proof check confirmed
this: `directLoginSessionKey proofMatch=YES`, followed by native 0x83 acceptance
and valid HMAC/decryption of the client's secure 0x85 request. No proof bypass.
Old builds retain their SPKI-derived path. Retail public-SPKI scanning was also
enabled, though the verified direct-key path does not require that candidate.

Current next blocker is service 38 task 8, first decoded secure request, which
the backend returns as explicit unsupported failure. Its request schema and
callback semantics need identification before adding any success handler.
Changes are scoped to Steam retail 22824864, not old build response contracts.

Both builds succeed. Synthetic TLS loopback contract test passes for types,
buffer limits, shared identity, 24-byte key/ticket binding, and fresh timestamp.
`test-steam-title-contract.py` trusts the local CA (pre-3.13 strictness), never
uses real credentials or external servers. This is NOT proof of reaching menu.
`start-steam-retail-test.ps1` now archives DLL/logs, stops only exact retail
test paths, verifies deployment hash, and restores launch environment variables.


## Latest result (supersedes the pre-login boundary below)

Extended the existing exact-text Safe Mode/recommended-settings handlers to
this precise Steam fingerprint. Rebuilt and deployed; runtime confirmed both
prompts were declined while preserving settings. The hidden bootstrapper child
(PID 7248) then requested the keylist and reached
`wz-steam-loginservice.prod.demonware.net/v1/login/`, titleID 6000.
The existing local response returns HTTP 200, but subsequent requests report:
`Failed to load title data from login service response.` (code 20).
This is an observed response-contract failure, not menu completion.

`tools/tests/inspect-steam-title.py` performs read-only exact-build PE inspection.
The disk contains that error string and title/titleID strings, but no matching
plain RIP-relative LEA references were found in disk executable sections.
Live process inspection was denied by Windows (error 5). No workaround for that
access restriction or speculative response-field change was applied.
Need a permitted parser disassembly/decompilation referencing the exact error
string to establish the required title-data fields and types. Computer Use's
required node_repl runtime was not available in this session. Game audio was
verified muted; menu remains unverified.

## Earlier startup tests

Target: `D:\SteamLibrary\steamapps\common\Call of Duty Modern Warfare\ModernWarfare.exe`.
Steam app 2000950, installed build 22824864. PE fingerprint:
`69DD404E / 21679200 / 06E4931C`.

- Added exact build identification to the existing universal backend; no older
  auth/manifest RVAs or forced game-state transitions were applied.
- Extended opt-in background hiding/game-session muting to this fingerprint.
  Background mode now skips creating the proxy console entirely.
- Both Debug builds succeeded. Existing retail DLL/server were backed up to a
  timestamped `codrevamped-backup-*` directory before deployment.
- Server started hidden (PID 14588 during testing). No new client HTTP/login
  request reached it in these runs.
- Direct launch with our DLL exits before login. Repeating with process-local
  SteamAppId/SteamGameId=2000950 also exited, code 0.
- Logging observed first-chance C0000096 in dynamically allocated memory shortly
  before exit. This is not proof of an unhandled crash or its root cause.
- Exact-retail opt-in `CODREVAMPED_RETAIL_IAT_ONLY=1` skips WS2 export hooks,
  retains DNS IAT hooks, and also exited code 0. Seven game-only audio sessions
  were verified muted in this test; main window handle was zero.
- Combining IAT-only with `CODREVAMPED_RETAIL_NO_VEH=1` (no first-chance logger)
  also exited code 0. These experimental flags are process-local, not defaults.

The existing bootstrapper log revealed the normal game launch includes an extra
argument. Launched the unmodified `bootstrapper.exe` with the same process-local
background/IAT-only/no-VEH flags instead of copying or inventing that argument.
Its child (PID 22868) remained running beyond the earlier direct-launch exit
point. Seven game-only audio sessions verified muted, main window handle zero;
no HTTP/login request reached the server during the observation period. This
narrows the direct-launch problem but does not establish rendered menu progress.

Main menu NOT reached. Remaining boundary is retail startup before backend
requests, not an established missing server route. Hidden-window effects and
Steam-mediated launch have not been ruled out. Do not patch security
checks or infer menu success from process creation. No game EXE changes made.
