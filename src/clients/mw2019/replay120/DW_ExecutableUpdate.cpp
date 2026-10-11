#include "com_debugstates.h"
#include "DW_LocalConfig.h"
#include "DW_UpdateHelper.h" // Generated from the freshly compiled static helper.

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    void DW_LocalPlatform_RecordStage(const char *);
    int func_1420838B0(void *);                    // lua_gettop
    int func_142089FB0(void *, const char *, ...); // luaL_error
    void func_1413E9BE0(void *, const char *);     // Dvar_SetString_Internal
    void Dvar_SetBool_Internal(void *, bool);
    extern void *gl_151895EB0;
    extern void *gl_151895EA8;
    extern uint8_t gl_14E5C0944; // Sys_CheckQuitRequest native deferred shutdown flag.
    extern uint8_t gl_14F05AC00;
    void *func_1416702D0();
    unsigned func_141660390();
    void func_14165E6D0(unsigned, void *);
    void func_140C859F0(void *, unsigned, void (*)(unsigned, void *), void *);
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) void *__stdcall CreateThread(
        void *, size_t, unsigned long(__stdcall *)(void *), void *, unsigned long, unsigned long *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) unsigned long __stdcall WaitForSingleObject(void *, unsigned long);
}

namespace
{
    struct Startup
    {
        unsigned long size;
        wchar_t *reserved, *desktop, *title;
        unsigned long x, y, width, height, charsX, charsY, attribute, flags;
        unsigned short show, reservedSize;
        void *reservedBytes, *input, *output, *error;
    };

    struct Process
    {
        void *process, *thread;
        unsigned long pid, tid;
    };

    static_assert(sizeof(Startup) == 104);
    static_assert(sizeof(Process) == 24);
    using File = void *(__stdcall *)(const wchar_t *,
                                     unsigned long,
                                     unsigned long,
                                     void *,
                                     unsigned long,
                                     unsigned long,
                                     void *);
    using IO = int(__stdcall *)(void *, void *, unsigned long, unsigned long *, void *);
    using Launch = int(__stdcall *)(const wchar_t *,
                                    wchar_t *,
                                    void *,
                                    void *,
                                    int,
                                    unsigned long,
                                    void *,
                                    const wchar_t *,
                                    Startup *,
                                    Process *);
    using ExitCode = int(__stdcall *)(void *, unsigned long *);
    using Event = void *(__stdcall *)(void *, int, int, const wchar_t *);
    using ModuleName = unsigned long(__stdcall *)(void *, wchar_t *, unsigned long);
    using Pid = unsigned long(__stdcall *)();
    using Ticks = unsigned long long(__stdcall *)();
    void *s_kernel;
    wchar_t s_exe[1024]{}, s_helper[1060]{}, s_directory[1024]{}, s_eventName[80]{};
    // 0 unstarted, 1 checking, 10 current, 20 staged, 30 unknown, 40 failed.
    unsigned s_state = 0, s_reported = 0;
    bool s_restartRequested = false, s_restarting = false;
    void *s_apply = nullptr, *s_ready = nullptr;
    unsigned long long s_handoffDeadline = 0;

    bool append(wchar_t *out, unsigned capacity, const wchar_t *part)
    {
        unsigned at = 0;
        while (at < capacity && out[at])
            ++at;
        for (unsigned i = 0; part[i]; ++i)
        {
            if (at + 1 >= capacity)
                return false;
            out[at++] = part[i];
        }
        out[at] = 0;
        return true;
    }

    bool spawn(const wchar_t *mode, const wchar_t *extra, Process &process)
    {
        wchar_t command[2400]{};
        if (!append(command, 2400, L"\"") || !append(command, 2400, s_helper) ||
            !append(command, 2400, L"\" ") || !append(command, 2400, mode) ||
            !append(command, 2400, L" \"") || !append(command, 2400, s_exe) ||
            !append(command, 2400, L"\" ") || !append(command, 2400, extra))
            return false;
        auto create = reinterpret_cast<Launch>(GetProcAddress(s_kernel, "CreateProcessW"));
        Startup startup{};
        startup.size = sizeof(startup);
        return create && create(s_helper,
                                command,
                                nullptr,
                                nullptr,
                                0,
                                0x08000000,
                                nullptr,
                                s_directory,
                                &startup,
                                &process);
    }

    unsigned long __stdcall check(void *)
    {
        unsigned result = 40;
        s_kernel = LoadLibraryA("kernel32.dll");
        if (!s_kernel)
            goto finished;
        {
            auto name =
                reinterpret_cast<ModuleName>(GetProcAddress(s_kernel, "GetModuleFileNameW"));
            auto file = reinterpret_cast<File>(GetProcAddress(s_kernel, "CreateFileW"));
            auto write = reinterpret_cast<IO>(GetProcAddress(s_kernel, "WriteFile"));
            auto read = reinterpret_cast<IO>(GetProcAddress(s_kernel, "ReadFile"));
            auto code = reinterpret_cast<ExitCode>(GetProcAddress(s_kernel, "GetExitCodeProcess"));
            if (!name || !file || !write || !read || !code)
                goto finished;
            unsigned long count = name(nullptr, s_exe, 1024);
            if (!count || count >= 1024)
                goto finished;
            append(s_helper, 1060, s_exe);
            append(s_helper, 1060, L".updater.exe");
            append(s_directory, 1024, s_exe);
            while (count && s_directory[count - 1] != L'\\')
                --count;
            if (!count)
                goto finished;
            s_directory[count] = 0;
            // Reuse only an exact byte match to the helper embedded in this
            // game release. A helper left by an older release is regenerated.
            bool same = true;
            void *existing = file(s_helper, 0x80000000, 1, nullptr, 3, 0x80, nullptr);
            if (existing == reinterpret_cast<void *>(~uintptr_t{0}))
                same = false;
            else
            {
                uint8_t buffer[4096];
                for (unsigned at = 0; same && at < sizeof(s_dwUpdateHelper);)
                {
                    unsigned wanted = sizeof(buffer);
                    if (wanted > sizeof(s_dwUpdateHelper) - at)
                        wanted = sizeof(s_dwUpdateHelper) - at;
                    unsigned long got = 0;
                    same = read(existing, buffer, wanted, &got, nullptr) && got == wanted;
                    for (unsigned i = 0; same && i < wanted; ++i)
                        same = buffer[i] == s_dwUpdateHelper[at + i];
                    at += wanted;
                }
                unsigned long extra = 0;
                same = same && read(existing, buffer, 1, &extra, nullptr) && !extra;
                CloseHandle(existing);
            }
            if (!same)
            {
                void *output = file(s_helper, 0x40000000, 0, nullptr, 2, 0x80000080, nullptr);
                if (output == reinterpret_cast<void *>(~uintptr_t{0}))
                    goto finished;
                unsigned long written = 0;
                const bool ok = write(output,
                                      const_cast<uint8_t *>(s_dwUpdateHelper),
                                      sizeof(s_dwUpdateHelper),
                                      &written,
                                      nullptr) &&
                                written == sizeof(s_dwUpdateHelper);
                CloseHandle(output);
                if (!ok)
                    goto finished;
            }
            Process process{};
            if (!spawn(L"--prepare", DW_LocalConfig_WideHost(), process))
                goto finished;
            CloseHandle(process.thread);
            // Blocking work belongs to this worker, never the game frame.
            if (WaitForSingleObject(process.process, 12 * 60 * 1000) == 0)
            {
                unsigned long exit = 40;
                if (code(process.process, &exit) && (exit == 10 || exit == 20 || exit == 30))
                    result = exit;
            }
            CloseHandle(process.process);
        }
    finished:
        __atomic_store_n(&s_state, result, __ATOMIC_RELEASE);
        return 0;
    }

    unsigned state()
    {
        unsigned current = __atomic_load_n(&s_state, __ATOMIC_ACQUIRE);
        if (!current && __atomic_compare_exchange_n(
                            &s_state, &current, 1U, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        {
            void *worker = CreateThread(nullptr, 0, check, nullptr, 0, nullptr);
            if (worker)
                CloseHandle(worker);
            else
                __atomic_store_n(&s_state, 40U, __ATOMIC_RELEASE);
            current = 1;
        }
        return current;
    }
} // namespace

extern "C" void DW_ExecutableUpdate_Frame()
{
    if (!DW_LocalBackend_IsEnabled())
        return;
    const unsigned current = state();
    if (current != s_reported)
    {
        if (!s_reported)
            DW_LocalPlatform_RecordStage("DW_EXE_UPDATE client revision 2");
        s_reported = current;
        DW_LocalPlatform_RecordStage(
            current == 1    ? "DW_EXE_UPDATE checking"
            : current == 10 ? "DW_EXE_UPDATE current"
            : current == 20 ? "DW_EXE_UPDATE verified replacement staged; restart required"
            : current == 30 ? "DW_EXE_UPDATE unknown executable; no patch applied"
                            : "DW_EXE_UPDATE failed; installed executable unchanged; inspect "
                              ".update/result.log");
    }
    if (s_restartRequested && !s_restarting && current == 20)
    {
        s_restartRequested = false;
        auto event = reinterpret_cast<Event>(GetProcAddress(s_kernel, "CreateEventW"));
        auto pid = reinterpret_cast<Pid>(GetProcAddress(s_kernel, "GetCurrentProcessId"));
        auto ticks = reinterpret_cast<Ticks>(GetProcAddress(s_kernel, "GetTickCount64"));
        if (!event || !pid || !ticks)
            return;
        char ascii[100]{};
        Com_sprintf(ascii, sizeof(ascii), "Local\\ReplayUpdate-%lu", pid());
        for (unsigned i = 0; ascii[i]; ++i)
            s_eventName[i] = ascii[i];
        s_ready = event(nullptr, 1, 0, s_eventName);
        if (!s_ready)
            return;
        Com_sprintf(ascii, sizeof(ascii), "%lu Local\\ReplayUpdate-%lu", pid(), pid());
        wchar_t extra[100]{};
        for (unsigned i = 0; ascii[i]; ++i)
            extra[i] = ascii[i];
        Process process{};
        if (spawn(L"--apply", extra, process))
        {
            CloseHandle(process.thread);
            s_apply = process.process;
            s_restarting = true;
            s_handoffDeadline = ticks() + 30000;
        }
        else
        {
            CloseHandle(s_ready);
            s_ready = nullptr;
        }
    }
    if (s_restarting)
    {
        if (WaitForSingleObject(s_ready, 0) == 0)
        {
            // The native deferred shutdown saves configuration and drains the
            // game. The updater holds this exact process until it has exited.
            DW_LocalPlatform_RecordStage("DW_EXE_UPDATE restart handoff acknowledged");
            gl_14E5C0944 = 1;
            s_restarting = false;
            CloseHandle(s_ready);
            CloseHandle(s_apply);
            s_ready = s_apply = nullptr;
        }
        else if (WaitForSingleObject(s_apply, 0) == 0 ||
                 reinterpret_cast<Ticks>(GetProcAddress(s_kernel, "GetTickCount64"))() >=
                     s_handoffDeadline)
        {
            DW_LocalPlatform_RecordStage(
                "DW_EXE_UPDATE restart handoff failed; game remains running");
            CloseHandle(s_ready);
            CloseHandle(s_apply);
            s_ready = s_apply = nullptr;
            s_restarting = false;
        }
    }
}

// Original target-build getter: [this + 0xA5 + patchType * 100].
extern "C" uint8_t func_141053520(const uint8_t *streamer, int patchType)
{
    const uint8_t native = streamer[165 + static_cast<int64_t>(patchType) * 100];
    if (!DW_LocalBackend_IsEnabled() || patchType != 0 || native == 3 || native == 4)
        return native;
    const unsigned update = state();
    if (update == 0 || update == 1)
        return 0; // Native checking/downloading state.
    if (update == 20 && (native == 1 || native == 2))
        return 2; // COMPLETE_RESTART
    return native;
}

extern "C" int func_141B117B0(void *lua)
{
    if (func_1420838B0(lua))
        return func_142089FB0(lua, "USAGE: Fences.PatchRestart()");
    if (DW_LocalBackend_IsEnabled() && state() == 20)
        s_restartRequested = true;
    else
    {
        func_1413E9BE0(gl_151895EB0, "LUA_MENU/PATCH_UPDATE_SUCCESS");
        Dvar_SetBool_Internal(gl_151895EA8, true);
    }
    return 0;
}

// The shipped ui/utils/fencepatch.lua confirmation sets the restart dvar
// directly. Com_Frame consumes it and calls this native platform restart entry.
// Keep the entire original platform request for non-updater restarts.
extern "C" void func_14165E530()
{
    if (DW_LocalBackend_IsEnabled() && state() == 20)
    {
        s_restartRequested = true;
        return;
    }
    if (!gl_14F05AC00)
    {
        gl_14F05AC00 = 1;
        void *service = func_1416702D0();
        const unsigned account = func_141660390();
        func_140C859F0(service, account, func_14165E6D0, nullptr);
    }
}
