# 1.16 folder startup test (2026-10-03)

Target: D:\unlock\Modern Warfare\Call of Duty Modern Warfare (1.16)\ModernWarfare.exe
PE timestamp 5DAF7AF7, image size 168C6E00, entry point 02B53550.
The folder's .build.info says 1.01.0.7199386PL; the folder name alone is not
proof of executable/assets version agreement. Preserve the existing files.
The active CASC build config 26d7724bb63f1326dd474a7aa93ed6ab additionally
identifies release_7199386_10_21v1_no_exe_dll_fixship. Another config identifies
release_7204640_10_21_v1_exe_signed_ship. No 1.16 build metadata was found in
these records. This discrepancy needs resolution before claiming 1.16 support.

Confirmed compatibility bug fixed in MW2019RedirectProxy.cpp:
CompatRtlGetVersion rejected the size=8 call seen during startup. A native
RtlGetVersion probe on this host, with an allocated 512-byte buffer, succeeds
for size values 8, 276 and 284. The adapter now calls the native implementation
and preserves its result before adjusting the reported OS version.

Both Debug targets built. Updated DLL and server copied into the target folder;
previous binaries preserved in a compat-backup-* directory there. No files
were removed and neither our DLL nor server was intentionally disabled.

Game still exits with code 0 after about 4 seconds, before D3D12 initialization
or observed backend requests. Diagnostic startup sampler ends in ntdll;
this is not proof of the root cause and no successful launch/menu is claimed.
The server initially required elevation; the user removed that requirement.
Retest launched RevampedIW8Server successfully (PID 18600), with TCP listeners
visible via netstat. Game still exits code 0 before contacting the backend.
Bounded passive dynamic-export logging now preserves returned addresses and
LastError, recording at most 128 lookups in the 1.16 startup log. The latest
run resolves through GetLogicalProcessorInformation, RtlCaptureContext and
RtlCaptureStackBackTrace; those breadcrumbs alone do not identify the cause.
A temporary native-OS-version reporting test retained our DLL and server but
also exited code 0. Its opt-in code was removed after the negative test.
Passive debug-event capture also exited code 0. An exit-breakpoint experiment
changed the outcome to 80000003 without hitting the expected callback, so it
is inconclusive and must not be treated as the normal startup failure.
Do not reuse the 1.20 manifest key RVA or native-state addresses for this build.
