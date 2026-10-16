# Steam retail integration — 2026-10-05

## 2026-10-13 fresh retail test

Follow-up: user reports Checking for updates. The initial test's explicit
127.0.0.1 bind is suspect: server UDP diagnostics received its own type-31 and
type-21 replies, with both client and server using port 3074. A specific local
bind can capture replies intended for the game's wildcard-bound socket.
Restored the project's default 0.0.0.0 server binding (PID 35688) and relaunched
retail visibly via bootstrap PID 34268. This is a controlled launch correction,
not proof that update-content or menu initialization is fixed. DNS redirection
still targets localhost. The earlier server PID 25176 was stopped by exact path.
Retest at 00:52:25: client source port is now 3833, discovery proceeds from
request=0 to request=3, and the repeated discovery/self-reply loop is absent
during observation. Game PID 34860 remains responding with six unmuted audio
sessions. No fresh login follows yet; title-screen progression is unverified.

The user finished the separate 1.20 session. Confirmed no game/server process
remained before rebuilding both Debug targets (exit 0). Backed up and deployed
the current backend and DLL; server deployment SHA-256 matched the build.
Started loopback-only server PID 25176 and visible retail game PID 33436 via
bootstrapper. All six game audio sessions were verified unmuted.

The offline retail/legacy contract test passes, including publisher metadata
SHA-1 checks. Both Raven store HTTP regression requests pass on the new server.
Those two HTTP requests are test traffic, NOT game progress. As of 00:50 the
game has requested the keylist and STUN, but no fresh login/secure task request
is present. Requested that the user advance the title screen; no menu success
is established. The Computer Use skill's required node_repl tool is unavailable.

PublisherContent is absent in this retail installation. Existing backend code
therefore still falls back to the 1.20-signed manifest and placeholder numbered
Raven objects. These are unverified retail content, not a completed 8.69 backend.
The client's local manifest trust replacement is explicitly MW120-only; do not
describe the fallback manifest as retail-verified. No new trust patch was made.

## 2026-10-12 continuation (supersedes historical blockers below)

The October 9 runtime logs already reach authenticated secure tasks and Raven
publisher metadata for `1_manifest_{patch,comms}_pc_8.69.txt` and
`unified_large_playlist_tu69.aggr`. Service 38/task 8 is no longer the current
boundary. The user reports the frontend remains at Checking for updates.

Inspected the supplied `CodRevampedRuntimeDump/ModernWarfare_runtime_dump.exe`
read-only. Its mapped PE base is `0x7FF755230000`; string RVAs include
`objectID=0x717B7E8` and `manifestver=0x70032C8`. The dump still contains
obfuscated control flow; presence of these strings alone does not establish
required metadata fields. No EXE patch or guessed objectID was applied.

Found a concrete current-source mismatch: REST publisher metadata advertises
the 17-byte neutral store body, while the HTTP handler used the larger legacy
store layout for Raven `store_v2.json`. Added a shared RetailStoreBody and
scoped the HTTP correction to Raven's two store objects, preserving the older
Infinity Ward store routes. Built client and backend successfully. Backed up
and deployed both. `test-retail-publisher-http.py` passes against the running
loopback server for both objects, including exact bytes and Content-Length.

Fresh hidden run: game PID 17732, server launch PID 21152. Six game audio
sessions verified muted. At the initial check, the client had fetched the
keylist but had not issued login traffic. HTTP test requests must not be
mistaken for game progress. Requested visible/manual title-screen testing;
no menu success is established. No unrelated 1.30 proxy edits were changed.

`inspect-retail-dump.py` supports bounded read-only disassembly, string xrefs,
and direct-jump following. It does not modify the dump or IDA database.

Follow-up: the initial hidden run DID proceed to login after the first check.
At 15:58:04, secure request service 80/task 245 carried the complete payload
`17 08 08 00 00 00 0A 04 36 30 30 30 10 10 00`: context `6000`, maximum 16.
The existing semantic handler hard-coded `5800` and rejected it; ReplayDW
fallback also returned `task-parameters-invalid`. Updated the context guard to
accept `6000` only when the exact Steam retail fingerprint is detected. The
existing bounds/duplicate-field/malformed-request validation is unchanged.
Backend builds successfully, but this balance fix is NOT deployed: stopping
the running server PID 21152 returned Access is denied. User was asked to close
it. Do not report the new balance response as runtime-verified yet.

User now wants visible game with audio. Added `-VisibleWithAudio` to the test
launcher (background=0, hide-window=0); server remains hidden. Visible launches
have intermittently exited; a running process alone does not verify frontend.

### Subsequent deployment and structured-profile research

After the user closed the elevated server, deployed the balance-context fix.
Runtime at 16:03:16 confirmed service 80/task 245 now uses the semantic
`getBalancesV3` reply, not ReplayDW `task-parameters-invalid`.

Repeated structured-profile requests led to a second dump-confirmed contract:
`6CCE080` parses `usersStructuredData[]`, `6CCE192` reads each user's `items[]`,
`6CCE275` reads `payload` as a string, and `6CCE293` requires `errorCode`.
The caller at `1F02E129` sets R8B=1, selecting the encoded branch. `6CCE250`
calls decoder `6C6FF90`, which uses the base64 decode table at `7173B40`.
The old response's direct `structuredData` object was not this contract.

Exact Steam retail now receives items containing base64-encoded profile JSON
and numeric errorCode=0. Other builds retain their previous response shape.
The first test used plain JSON in payload; the subsequent caller trace found
and corrected the encoding before the latest deployment. Never infer that
the first structure-only test proved successful client parsing.

Added `iw8_retail_contract_test.cpp`: retail and legacy balance contexts,
invalid context/count/truncated requests, retail profile envelope, unchanged
legacy profile shape. Compiled and passed; its emitted profile also passed
Python's strict base64 decoding and JSON parsing. Backend builds successfully.
Latest test server PID 7976, bootstrap PID 17864. Menu remains unverified.

The inner profile consumer also requires `hasPlayed` to be an array:
string xref `1D081B05` reaches `6D46550`, calling the same array reader
`6C82E10`. Changed only retail to an empty array; old builds keep the bool.
Scalar seasonRank and battlepassOwned readers were inspected separately and
do not use this array reader. Regression test plus strict base64/JSON checks
pass with hasPlayed=[].

Final deployment in this continuation: server PID 21452, bootstrap PID 25604.
Server deployment hash verified. The visible game has six audio sessions,
all verified unmuted. Latest run reaches secure requests and both Raven store
downloads; the prior repeated profile requests are no longer evident during
the observed interval. Frontend/menu has NOT been visually verified. A user
screenshot was requested; Computer Use's required node_repl tool is unavailable.
Do not equate a responding window or completed backend request with menu success.

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
