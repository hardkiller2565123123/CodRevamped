// Private DW executable integration; compiled and linked by the frozen-source
// workflow. Native bindings are link-time identities, never runtime patches.
#include "com_debugstates.h"
#include "replay_dvar.h"
#include "con_dvar_names.h"

extern "C" {
bool DW_LocalBackend_IsEnabled();
void DW_HostMigration_Frame();
void replay_rva_015ae0b0(int); // Con_DrawConsole, exact Replay implementation
bool replay_rva_015b0ef0(int); // Con_IsActive
uintptr_t replay_rva_012aa180(void*); // CL_Keys_ClearField
extern unsigned char replay_rva_0eea60d0[]; // native console field
extern int replay_rva_0eea2b80; // autocomplete choice
extern unsigned char replay_rva_0eea2b40; // autocomplete active
extern unsigned replay_rva_0eef1284; // client-zero key catchers
extern unsigned replay_rva_0eea60dc[2]; // console field dimensions
extern unsigned replay_rva_0461b674[2]; // native console dimensions
extern int replay_rva_0eea60e4; // console field fixed-size flag
extern unsigned char replay_rva_0ee9e18c; // full console output
extern void* replay_rva_12d36330; // native game HWND
__declspec(dllimport) short __stdcall GetAsyncKeyState(int);
__declspec(dllimport) void* __stdcall GetForegroundWindow();
}

// CL_Keys_ConsoleKey proves the native 16-byte buffer layout and client-zero
// base. GScr_AddDebugCommand originally selects the NEXT buffer instead.
struct conCommandBuffer_t {
    char* data;
    int capacity;
    int size;
};
static_assert(sizeof(conCommandBuffer_t) == 16);
static_assert(offsetof(conCommandBuffer_t, size) == 12);
extern "C" conCommandBuffer_t replay_rva_0d216d70[];

namespace {
cmd_function_s s_toggleCommand{};
bool s_registered = false;
bool s_visibilitySet = false;
bool s_f7Held = false;
bool s_graveHeld = false;
bool s_graveToggled = false;
// Translation and immediate Cbuf submission are main-thread-only. Keep this
// scratch space off the event stack; no allocation or large stack probe needed.
char s_translation[4096];

// The native event handler and the render-thread fallback share this latch.
// Holding grave, including Windows key repeat, must toggle only once.
bool Con_ClaimGravePress() {
    if (!(GetAsyncKeyState(0xc0) & 0x8000)) {
        s_graveToggled = false;
        return true;
    }
    if (s_graveToggled) return false;
    s_graveToggled = true;
    return true;
}

uintptr_t Con_ToggleNative() {
    // Exact Replay Con_ToggleConsole behavior, recovered from its instructions.
    replay_rva_012aa180(replay_rva_0eea60d0);
    if (replay_rva_0eea2b80 >= 0 && replay_rva_0eea2b40) {
        replay_rva_0eea2b80 = -1;
        replay_rva_0eea2b40 = 0;
    }
    replay_rva_0eef1284 ^= 1u;
    replay_rva_0eea60dc[0] = replay_rva_0461b674[0];
    replay_rva_0eea60dc[1] = replay_rva_0461b674[1];
    replay_rva_0eea60e4 = 1;
    replay_rva_0ee9e18c = 0;
    return replay_rva_0461b674[0];
}

bool Equal(const char* text, unsigned length, const char* other) {
    unsigned i = 0;
    for (; i < length && other[i]; ++i)
        if (text[i] != other[i]) return false;
    return i == length && other[i] == 0;
}

bool Space(char c) { return c == ' ' || c == '\t' || c == '\v' || c == '\f'; }

// Match the proxy's translation rules without introducing STL allocation or
// new CRT dependencies. Values, quoted strings, comments and command boundaries
// remain intact. Reject the whole command on overflow; never execute a prefix.
bool Translate(const char* input, char (&output)[4096]) {
    unsigned position = 0, used = 0, tokenIndex = 0;
    bool dvarCommand = false;
    while (input[position]) {
        if (position >= sizeof(output) - 1) return false;
        const unsigned start = position;
        const char c = input[position];
        const char* replacement = nullptr;
        if (c == ';' || c == '\n' || c == '\r') {
            tokenIndex = 0;
            dvarCommand = false;
            ++position;
        } else if (Space(c)) {
            ++position;
        } else if (c == '/' && input[position + 1] == '/') {
            while (input[position] && input[position] != '\n' && input[position] != '\r') {
                if (++position >= sizeof(output) - 1) return false;
            }
        } else {
            if (c == '"') {
                ++position;
                while (input[position]) {
                    if (position >= sizeof(output) - 1) return false;
                    if (input[position] == '\\' && input[position + 1]) {
                        position += 2;
                        continue;
                    }
                    if (input[position++] == '"') break;
                }
            } else {
                while (input[position] && !Space(input[position]) &&
                       input[position] != ';' && input[position] != '\n' && input[position] != '\r') {
                    if (++position >= sizeof(output) - 1) return false;
                }
                const unsigned length = position - start;
                if (tokenIndex == 0) {
                    dvarCommand = Equal(input + start, length, "set") ||
                        Equal(input + start, length, "seta") || Equal(input + start, length, "setu") ||
                        Equal(input + start, length, "sets") || Equal(input + start, length, "toggle") ||
                        Equal(input + start, length, "reset");
                    if (Equal(input + start, length, "noclip") ||
                        Equal(input + start, length, "mw_noclip")) replacement = "cmd noclip";
                    else if (Equal(input + start, length, "mw_setpos")) replacement = "cmd mw_setpos";
                }
                if ((tokenIndex == 0 && !dvarCommand) || (tokenIndex == 1 && dvarCommand)) {
                    for (const auto& entry : dvardb::kEntries) {
                        if (Equal(input + start, length, entry.name)) {
                            replacement = entry.token;
                            break;
                        }
                    }
                }
            }
            ++tokenIndex;
        }
        if (replacement) {
            for (unsigned i = 0; replacement[i]; ++i) {
                if (used >= sizeof(output) - 1) return false;
                output[used++] = replacement[i];
            }
        } else {
            for (unsigned i = start; i < position; ++i) {
                if (used >= sizeof(output) - 1) return false;
                output[used++] = input[i];
            }
        }
    }
    output[used] = 0;
    return true;
}

void Con_ToggleDeveloper_f() {
    Con_ToggleNative();
}

void Con_UpdateDeveloperInput(int client) {
    if (client != 0 || !Sys_IsMainThread()) return;
    if (!s_registered) {
        Cmd_AddCommandInternal("dw_console", Con_ToggleDeveloper_f, &s_toggleCommand);
        s_registered = true;
        Com_Printf(16, "Developer console: grave/tilde or F7; Shift+F7 toggles full output.\n");
    }
    if (!s_visibilitySet) {
        if (auto* hidden = Dvar_FindVarByName("NRNSMTPL")) {
            DvarValue value{};
            value.enabled = false;
            Dvar_SetVariant(hidden, &value, 0);
            s_visibilitySet = true;
        }
    }
    // LUI can consume grave before the native console branch. Poll both keys
    // while focused; the native toggle replacements deduplicate grave presses.
    // Character input, editing, history and autocomplete stay native.
    const bool held = (GetAsyncKeyState(0x76) & 0x8000) != 0;
    const bool graveHeld = (GetAsyncKeyState(0xc0) & 0x8000) != 0;
    if (!graveHeld) s_graveToggled = false;
    const bool focused = GetForegroundWindow() == replay_rva_12d36330;
    if (focused && held && !s_f7Held) {
        if (GetAsyncKeyState(0x10) & 0x8000) {
            if (!replay_rva_015b0ef0(client)) Con_ToggleNative();
            replay_rva_0ee9e18c = !replay_rva_0ee9e18c;
        } else {
            Con_ToggleNative();
        }
    }
    if (focused && graveHeld && !s_graveHeld && Con_ClaimGravePress())
        Con_ToggleNative();
    s_f7Held = held;
    s_graveHeld = graveHeld;
}
}

extern "C" uintptr_t func_1415B18C0() {
    if (DW_LocalBackend_IsEnabled() && !Con_ClaimGravePress())
        return replay_rva_0461b674[0];
    return Con_ToggleNative();
}

extern "C" void func_1415B1930() {
    // Stock Shift+grave normally selects full output instead of closing the
    // console. In DW, both legends on this key mean a regular console toggle.
    if (DW_LocalBackend_IsEnabled() && (GetAsyncKeyState(0xc0) & 0x8000)) {
        if (Con_ClaimGravePress()) Con_ToggleNative();
    } else {
        replay_rva_0ee9e18c = !replay_rva_0ee9e18c;
    }
}

// ScrPlace_EndFrame runs after UI workers in both the no-game-mode main
// menu and game views. Keep input and draw submission on that common path.
extern "C" const void* replay_rva_0eeb0c58; // cls.consoleFont, native Con_CheckResize
extern "C" void Con_DeveloperFrame() {
    if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread()) return;
    DW_HostMigration_Frame();
    Con_UpdateDeveloperInput(0);
    if (replay_rva_0eeb0c58 && replay_rva_015b0ef0(0))
        replay_rva_015ae0b0(0);
}

// Source replacement of GScr_AddDebugCommand; no detour or injected DLL.
// Preserve the native debugger buffer for other callers. The developer console
// submits client zero on the main thread and must append to client zero's Cbuf.
extern "C" uintptr_t func_1415C1C20(int client, const char* text) {
    if (!text || client < 0 || client > 1) return 0;
    const bool console = client == 0 && DW_LocalBackend_IsEnabled() && Sys_IsMainThread();
    if (console) {
        if (!Translate(text, s_translation)) {
            Com_Printf(16, "Developer console: command exceeds translation buffer.\n");
            return 0;
        }
        text = s_translation;
    }
    unsigned length = 0;
    while (text[length]) ++length;
    Sys_EnterCriticalSection(35);
    auto& buffer = replay_rva_0d216d70[console ? 0 : client + 1];
    if (buffer.data && buffer.capacity > 0 && buffer.size >= 0 &&
        buffer.size < buffer.capacity && length < unsigned(buffer.capacity - buffer.size)) {
        for (unsigned i = 0; i <= length; ++i) buffer.data[buffer.size + i] = text[i];
        buffer.size += int(length);
    } else {
        Com_Printf(16, "Cbuf_AddText: overflow (adding '%s')\n", text);
    }
    Sys_LeaveCriticalSection(35);
    return 0;
}
