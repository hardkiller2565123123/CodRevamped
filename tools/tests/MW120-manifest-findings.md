# Exact 1.20 manifest investigation

## Authorized local-trust experiment

The user subsequently authorized a patch specifically for local manifests.
CODREVAMPED_MW120_LOCAL_MANIFESTS=1 now opts both processes into locally signed
empty inventories. The proxy replaces only the 270-byte manifest RSA public
key at RVA 02416200, after exact build, executable-name and stock-key checks.
The executable on disk, verifier code, parser, and game state stay unchanged.
RSA-PSS/SHA256 uses an 8-byte salt and signs the native 0xDC00C-byte structure.
Runtime confirmation, 2026-10-02 03:24:34 local: the stock patch probe reached
ready=1 version=1 status=1 detail=0 (previously version=32765 status=3 detail=48).
mw2019_redirect.log confirms the local key write and restored memory protection.
The EXE SHA256 remains 68FB1CBCB2924182724004039DE55A4C50152BB6561803C4898B7930B38132F0.
Next observed missing pieces: unified_large_playlist_tu19.aggr,
contentCreatorList.txt, and service80/task69 inventory. Main menu unverified.
OpenSSL verified the generated signature and rejected a modified payload.
The private key is local under ignored artifacts/build; only public data and
the signed manifest are included in source. Both client and server builds
and the protocol tests passed. Runtime/menu success is not implied.
Use tools/tests/start-mw120-local-manifests.ps1 after deploying both binaries.
Close both processes and launch without the environment variable to disable.
Historical findings below describe the preceding unsigned experiment.

Executable: game_dx12_ship_replay.exe, PE timestamp 5E9BAF80.

Confirmed backend fixes:
- Reply to unsupported tasks with BD_SERVICE_NOT_AVAILABLE (108); dropping
  replies corrupts FIFO task correspondence. No fabricated successes.
- CCS metadata requires nonzero objectID and base64 SHA-1 (28 characters).
  A 32-character hex checksum overflows its strcpy_s destination (29 bytes),
  causing fast-fail c0000409, parameter 5.
- Both manifest files subsequently downloaded over stock HTTPS (586 bytes).

The empty unsigned manifest experiment FAILED with stock error 48. It is now
disabled unless CODREVAMPED_IW8_TEST_UNSIGNED_MANIFEST=1 is explicitly set.
Do not represent these test manifests as official content or a working fix.

Exact executable evidence (RVAs):
- 01052958 calls manifest parser wrapper 01053300.
- 01052977 hashes 0xDC00C bytes of parsed manifest data.
- 010529AE calls signature verifier 01038500 with hash and signature.
- 010529B6 tests its result; success jumps to 01052A20.
- Failure records error bit 0x1000000000000 and sets patch status 3,
  detail 48, version 0x7FFD. This matches runtime and the user's screenshot.
- OpenIW8 online_patchsystem.cpp is NOT an exact match here: its published
  implementation reports signature failure without this fatal branch.

Headless verification of the decrypted PE (no UI or executable writes):
- RVA 01038524 selects sha256; 01038559 loads a 270-byte DER key from
  RVA 02416200; 01038560 calls its importer at RVA 02056C00.
- The DER is an RSA public-key sequence containing only a 2048-bit modulus
  and exponent 65537 (header 3082010a0282010100, tail 0203010001).
  This key has no private exponent and cannot sign replacement manifests.
- RVA 010385D5 calls the verification routine at RVA 02056870 with a
  256-byte signature and 32-byte hash. Success requires both return code
  zero and output status one at 010385E6..010385EF.
- Literal full manifest filenames and PEM private-key headers were absent
  in a raw PE scan. Parser field names are present; this limited scan does
  not prove absence of compressed or differently encoded embedded assets.
- Reproduce bounded disassembly with tools/tests/inspect-mw120-pe.py,
  passing the exact game executable, RVA 1038500 and --size 152.
- Running only against localhost does not remove the client-side signature
  requirement. Decryption exposes verification code, not a signing key.

Needed for the requested no-client-patches approach:
- Genuine signed 1_manifest_patch_pc_8.19.txt
- Genuine signed 1_manifest_comms_pc_8.19.txt
- Any files referenced by those manifests, matching their hashes.

No matching loose files found under D:\unlock or D:\projects\Call of duty.
The 1.20 data0/data1.dcache files were empty before the experiment. The test
downloads may now be cached; preserve those files rather than deleting user data.
Main menu has NOT been reached or verified. Current game visibility and audio
are enabled at the user's request.
