// Private DW-build Windows startup compatibility.
//
// The Replay CRT constructor privately maps gdi32.dll and invokes
// GdiDllInitialize. Current Windows routes that export through loader-owned
// dispatch state, which is absent in a private image. The 2026-10-04 DW crash
// dump confirms a null call from this constructor before the first game frame.
// Normal Windows DLL loading supplies GDI initialization; this optional private
// copy is unnecessary. The existing Replay proxy skips the same constructor.
//
// The compiler resolves this verified native identity and derives its complete
// replacement range from the PE unwind family. No RVA/layout table or runtime
// code patch is needed. This source is included only in the frozen DW build.
extern "C" void func_1403061A0() {
}
