#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <array>

namespace
{
    constexpr std::uint32_t kMW120Timestamp = 0x5E9BAF80u;
    constexpr std::uint32_t kMW120ImageSize = 0x1324B000u;
    constexpr std::uint32_t kMW120EntryPoint = 0x021CDC10u;

    constexpr std::uintptr_t kSignInStateRva = 0x0E5C0730u;
    constexpr std::uintptr_t kDwLogonHsmRva = 0x0F493960u;
    constexpr std::uintptr_t kFrontendSceneRva = 0x0C4EBEB0u;
    constexpr std::uintptr_t kOnlineServicesFenceRva = 0x0C26A6F0u;
    constexpr std::uintptr_t kOnlineSyncFenceRva = 0x0C26A700u;
    constexpr std::uintptr_t kOnlineFenceFlagsRva = 0x0C26A6D3u;
    constexpr std::uintptr_t kPatchStreamerRva = 0x041E3A70u;

    // 1.20 functions already identified from the stock OnlineStorage/playerdata path.
    // These are RVAs from image base 0x140000000, so ASLR is handled by adding the
    // live module base at runtime.
    struct FenceTarget
    {
        std::uintptr_t rva;
        const char* name;
        volatile LONG hits;
        volatile LONG64 lastTick;
        volatile LONG64 lastRcx;
        volatile LONG64 lastRdx;
        volatile LONG64 lastR8;
        volatile LONG64 lastR9;
    };

    std::array<FenceTarget, 7> g_targets{{
        { 0x012A7A60u, "ONLINE_STORAGE_REQUEST_DEFAULT_STATS", 0, 0, 0, 0, 0, 0 },
        { 0x012A8360u, "ONLINE_STORAGE_DEFAULT_STATS_CALLBACK", 0, 0, 0, 0, 0, 0 },
        { 0x012A8450u, "ONLINE_STORAGE_DEFAULT_STATS_INSTALL", 0, 0, 0, 0, 0, 0 },
        { 0x012A3B50u, "PLAYERDATA_RESET_HANDLER", 0, 0, 0, 0, 0, 0 },
        { 0x012A4190u, "PLAYERDATA_NATIVE_STATS_INIT", 0, 0, 0, 0, 0, 0 },
        { 0x0129ED70u, "DEFAULT_STATS_INIT_COMMAND", 0, 0, 0, 0, 0, 0 },
        { 0x012A1C00u, "PLAYERDATA_AVAILABLE_EVENT", 0, 0, 0, 0, 0, 0 },
    }};

    struct GuardPage
    {
        std::uintptr_t page;
        DWORD baseProtect;
        bool armed;
    };

    std::array<GuardPage, 7> g_guardPages{};
    std::size_t g_guardPageCount = 0;
    std::uintptr_t g_imageBase = 0;
    PVOID g_veh = nullptr;
    ULONGLONG g_startTick = 0;
    volatile LONG g_stop = 0;

    bool ReadLiveFingerprint(
        std::uint32_t& timestamp,
        std::uint32_t& imageSize,
        std::uint32_t& entryPoint) noexcept;

    // Guard faults are per-thread.  Re-arm after one instruction so the guarded
    // instruction can execute normally without changing the game's code bytes.
    __declspec(thread) std::uintptr_t g_rearmPage = 0;

    std::uintptr_t PageBase(std::uintptr_t address) noexcept
    {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const auto size = static_cast<std::uintptr_t>(si.dwPageSize ? si.dwPageSize : 0x1000u);
        return address & ~(size - 1u);
    }

    bool IsExecutableProtection(DWORD protect) noexcept
    {
        protect &= 0xFFu;
        return protect == PAGE_EXECUTE ||
               protect == PAGE_EXECUTE_READ ||
               protect == PAGE_EXECUTE_READWRITE ||
               protect == PAGE_EXECUTE_WRITECOPY;
    }

    void WriteFenceLog(const char* text) noexcept
    {
        if (!text)
            return;

        wchar_t path[32768]{};
        if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path))))
            return;

        wchar_t* slash = wcsrchr(path, L'\\');
        if (!slash)
            return;

        slash[1] = L'\0';
        wcscat_s(path, L"mw2019_frontend_fence.log");

        HANDLE file = CreateFileW(
            path,
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
            CloseHandle(file);
        }

        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (output && output != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteConsoleA(output, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        }

        OutputDebugStringA(text);
    }

    void FencePrint(const char* format, ...) noexcept
    {
        if (!format)
            return;

        char body[2048]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(body, sizeof(body), _TRUNCATE, format, args);
        va_end(args);

        SYSTEMTIME now{};
        GetLocalTime(&now);

        char line[2300]{};
        _snprintf_s(
            line,
            sizeof(line),
            _TRUNCATE,
            "[FRONTEND-FENCE %02u:%02u:%02u.%03u +%llums] %s\r\n",
            static_cast<unsigned>(now.wHour),
            static_cast<unsigned>(now.wMinute),
            static_cast<unsigned>(now.wSecond),
            static_cast<unsigned>(now.wMilliseconds),
            static_cast<unsigned long long>(g_startTick ? GetTickCount64() - g_startTick : 0),
            body);

        WriteFenceLog(line);
    }

    void WriteNativeStateLog(const char* text) noexcept
    {
        if (!text)
            return;

        wchar_t path[32768]{};
        if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path))))
            return;

        wchar_t* slash = wcsrchr(path, L'\\');
        if (!slash)
            return;

        slash[1] = L'\0';
        wcscat_s(path, L"mw2019_120_native_state.log");

        HANDLE file = CreateFileW(
            path,
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
            CloseHandle(file);
        }

        OutputDebugStringA(text);
    }

    void NativeStatePrint(const char* format, ...) noexcept
    {
        if (!format)
            return;

        char body[2048]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(body, sizeof(body), _TRUNCATE, format, args);
        va_end(args);

        SYSTEMTIME now{};
        GetLocalTime(&now);

        char line[2300]{};
        _snprintf_s(
            line,
            sizeof(line),
            _TRUNCATE,
            "[MW120-NATIVE %02u:%02u:%02u.%03u +%llums] %s\r\n",
            static_cast<unsigned>(now.wHour),
            static_cast<unsigned>(now.wMinute),
            static_cast<unsigned>(now.wSecond),
            static_cast<unsigned>(now.wMilliseconds),
            static_cast<unsigned long long>(g_startTick ? GetTickCount64() - g_startTick : 0),
            body);

        WriteNativeStateLog(line);
    }

    void DeleteSiblingLog(const wchar_t* name) noexcept
    {
        if (!name)
            return;

        wchar_t path[32768]{};
        if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path))))
            return;

        wchar_t* slash = wcsrchr(path, L'\\');
        if (!slash)
            return;

        slash[1] = L'\0';
        wcscat_s(path, name);
        DeleteFileW(path);
    }

    template <typename T>
    bool ReadGameValue(std::uintptr_t rva, T& value) noexcept
    {
        if (!g_imageBase)
            return false;

        __try
        {
            std::memcpy(&value, reinterpret_cast<const void*>(g_imageBase + rva), sizeof(T));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::memset(&value, 0, sizeof(T));
            return false;
        }
    }

    struct NativeStateSnapshot
    {
        std::int32_t signInState;
        std::int32_t dwState;
        std::int32_t dwDepth;
        std::int32_t dwStack0;
        std::int32_t dwStack1;
        std::int32_t frontendScene;
        std::array<std::int32_t, 3> onlineServicesFence;
        std::array<std::int32_t, 12> onlineSyncFence;
        std::array<std::uint8_t, 6> onlineFenceFlags;
        std::uint8_t patchActive;
        std::uint8_t patchPhase;
        std::uint8_t patchReady;
        std::uint16_t patchVersion;
        std::uint8_t patchStatus;
        std::uint8_t patchLifecycle;
        std::uint32_t patchDetail;
    };

    bool CaptureNativeState(NativeStateSnapshot& state) noexcept
    {
        std::memset(&state, 0, sizeof(state));

        bool ok = true;
        ok = ReadGameValue(kSignInStateRva, state.signInState) && ok;
        ok = ReadGameValue(kDwLogonHsmRva + 0x0Cu, state.dwState) && ok;
        ok = ReadGameValue(kDwLogonHsmRva + 0x84u, state.dwDepth) && ok;
        ok = ReadGameValue(kDwLogonHsmRva + 0x10u, state.dwStack0) && ok;
        ok = ReadGameValue(kDwLogonHsmRva + 0x14u, state.dwStack1) && ok;
        ok = ReadGameValue(kFrontendSceneRva, state.frontendScene) && ok;
        ok = ReadGameValue(kOnlineServicesFenceRva, state.onlineServicesFence) && ok;
        ok = ReadGameValue(kOnlineSyncFenceRva, state.onlineSyncFence) && ok;
        ok = ReadGameValue(kOnlineFenceFlagsRva, state.onlineFenceFlags) && ok;
        ok = ReadGameValue(kPatchStreamerRva + 77u, state.patchActive) && ok;
        ok = ReadGameValue(kPatchStreamerRva + 78u, state.patchPhase) && ok;
        ok = ReadGameValue(kPatchStreamerRva + 79u, state.patchReady) && ok;
        ok = ReadGameValue(kPatchStreamerRva + 80u, state.patchVersion) && ok;
        ok = ReadGameValue(kPatchStreamerRva + 165u, state.patchStatus) && ok;
        ok = ReadGameValue(kPatchStreamerRva + 166u, state.patchLifecycle) && ok;
        ok = ReadGameValue(kPatchStreamerRva + 168u, state.patchDetail) && ok;
        return ok;
    }

    void PrintNativeState(const NativeStateSnapshot& state, const char* reason) noexcept
    {
        NativeStatePrint(
            "%s signIn=%d dwState=%d dwDepth=%d dwStack=[%d,%d] frontendScene=%d "
            "onlineServices=[%d,%d,%d] sync0=[%d,%d,%d] sync1=[%d,%d,%d] "
            "sync2=[%d,%d,%d] sync3=[%d,%d,%d] flags=%02X-%02X-%02X-%02X-%02X-%02X "
            "patch=[active=%u phase=%u ready=%u version=%u status=%u lifecycle=%u detail=%u]",
            reason ? reason : "STATE",
            state.signInState,
            state.dwState,
            state.dwDepth,
            state.dwStack0,
            state.dwStack1,
            state.frontendScene,
            state.onlineServicesFence[0],
            state.onlineServicesFence[1],
            state.onlineServicesFence[2],
            state.onlineSyncFence[0],
            state.onlineSyncFence[1],
            state.onlineSyncFence[2],
            state.onlineSyncFence[3],
            state.onlineSyncFence[4],
            state.onlineSyncFence[5],
            state.onlineSyncFence[6],
            state.onlineSyncFence[7],
            state.onlineSyncFence[8],
            state.onlineSyncFence[9],
            state.onlineSyncFence[10],
            state.onlineSyncFence[11],
            state.onlineFenceFlags[0],
            state.onlineFenceFlags[1],
            state.onlineFenceFlags[2],
            state.onlineFenceFlags[3],
            state.onlineFenceFlags[4],
            state.onlineFenceFlags[5],
            static_cast<unsigned>(state.patchActive),
            static_cast<unsigned>(state.patchPhase),
            static_cast<unsigned>(state.patchReady),
            static_cast<unsigned>(state.patchVersion),
            static_cast<unsigned>(state.patchStatus),
            static_cast<unsigned>(state.patchLifecycle),
            static_cast<unsigned>(state.patchDetail));
    }

    DWORD RunPassiveNativeStateProbe() noexcept
    {
        DeleteSiblingLog(L"mw2019_120_native_state.log");
        NativeStatePrint(
            "fingerprint timestamp=0x%08X imageSize=0x%08X entryPoint=0x%08X",
            kMW120Timestamp,
            kMW120ImageSize,
            kMW120EntryPoint);
        NativeStatePrint(
            "probe=read-only-v1 durationMs=180000 intervalMs=500 clientStateWrites=off pageGuards=off");

        NativeStateSnapshot previous{};
        bool havePrevious = false;
        const ULONGLONG probeStart = GetTickCount64();

        while (InterlockedCompareExchange(&g_stop, 0, 0) == 0 &&
               GetTickCount64() - probeStart < 180000ull)
        {
            NativeStateSnapshot current{};
            if (!CaptureNativeState(current))
            {
                NativeStatePrint("probe stopped reason=state-read-failed");
                return 0;
            }

            if (!havePrevious || std::memcmp(&current, &previous, sizeof(current)) != 0)
            {
                PrintNativeState(current, havePrevious ? "CHANGE" : "INITIAL");
                previous = current;
                havePrevious = true;
            }

            Sleep(500);
        }

        if (havePrevious)
            PrintNativeState(previous, "FINAL");
        NativeStatePrint("probe stopped reason=duration-complete");
        return 0;
    }

    BOOL CALLBACK HideOwnWindowCallback(HWND window, LPARAM processIdValue) noexcept
    {
        DWORD ownerProcessId = 0;
        GetWindowThreadProcessId(window, &ownerProcessId);
        if (ownerProcessId == static_cast<DWORD>(processIdValue) && IsWindowVisible(window))
            ShowWindow(window, SW_HIDE);
        return TRUE;
    }

    DWORD WINAPI HideOwnWindowsWorker(LPVOID) noexcept
    {
        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;
        if (!ReadLiveFingerprint(timestamp, imageSize, entryPoint) ||
            timestamp != kMW120Timestamp ||
            imageSize != kMW120ImageSize ||
            entryPoint != kMW120EntryPoint)
        {
            return 0;
        }

        const DWORD processId = GetCurrentProcessId();
        while (InterlockedCompareExchange(&g_stop, 0, 0) == 0)
        {
            EnumWindows(HideOwnWindowCallback, static_cast<LPARAM>(processId));
            if (HWND console = GetConsoleWindow(); console && IsWindowVisible(console))
                ShowWindow(console, SW_HIDE);
            Sleep(250);
        }
        return 0;
    }

    bool ReadLiveFingerprint(
        std::uint32_t& timestamp,
        std::uint32_t& imageSize,
        std::uint32_t& entryPoint) noexcept
    {
        const auto base = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
        if (!base)
            return false;

        __try
        {
            const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;

            timestamp = nt->FileHeader.TimeDateStamp;
            imageSize = nt->OptionalHeader.SizeOfImage;
            entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    GuardPage* FindGuardPage(std::uintptr_t page) noexcept
    {
        for (std::size_t i = 0; i < g_guardPageCount; ++i)
        {
            if (g_guardPages[i].page == page)
                return &g_guardPages[i];
        }
        return nullptr;
    }

    bool RearmGuardPage(std::uintptr_t page) noexcept
    {
        GuardPage* guard = FindGuardPage(page);
        if (!guard)
            return false;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const SIZE_T pageSize = si.dwPageSize ? si.dwPageSize : 0x1000u;

        DWORD oldProtect = 0;
        const BOOL ok = VirtualProtect(
            reinterpret_cast<void*>(guard->page),
            pageSize,
            guard->baseProtect | PAGE_GUARD,
            &oldProtect);

        guard->armed = ok != FALSE;
        return ok != FALSE;
    }

    LONG CALLBACK FrontendFenceVeh(PEXCEPTION_POINTERS pointers) noexcept
    {
        if (!pointers || !pointers->ExceptionRecord || !pointers->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        const DWORD code = pointers->ExceptionRecord->ExceptionCode;
        auto* context = pointers->ContextRecord;

        if (code == STATUS_GUARD_PAGE_VIOLATION)
        {
            const std::uintptr_t rip = static_cast<std::uintptr_t>(context->Rip);
            const std::uintptr_t page = PageBase(rip);

            if (!FindGuardPage(page))
                return EXCEPTION_CONTINUE_SEARCH;

            // PAGE_GUARD is one-shot.  Let the current instruction execute, take a
            // single-step trap, and re-arm the page there.
            g_rearmPage = page;
            context->EFlags |= 0x100u;

            for (auto& target : g_targets)
            {
                if (rip != g_imageBase + target.rva)
                    continue;

                InterlockedIncrement(&target.hits);
                InterlockedExchange64(&target.lastTick, static_cast<LONG64>(GetTickCount64()));
                InterlockedExchange64(&target.lastRcx, static_cast<LONG64>(context->Rcx));
                InterlockedExchange64(&target.lastRdx, static_cast<LONG64>(context->Rdx));
                InterlockedExchange64(&target.lastR8, static_cast<LONG64>(context->R8));
                InterlockedExchange64(&target.lastR9, static_cast<LONG64>(context->R9));
                break;
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (code == STATUS_SINGLE_STEP && g_rearmPage)
        {
            const std::uintptr_t page = g_rearmPage;
            g_rearmPage = 0;
            context->EFlags &= ~0x100u;
            RearmGuardPage(page);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool InstallReadOnlyGuards() noexcept
    {
        g_imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!g_imageBase)
            return false;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const SIZE_T pageSize = si.dwPageSize ? si.dwPageSize : 0x1000u;

        for (const auto& target : g_targets)
        {
            const std::uintptr_t address = g_imageBase + target.rva;
            MEMORY_BASIC_INFORMATION mbi{};

            if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi) ||
                mbi.State != MEM_COMMIT ||
                !IsExecutableProtection(mbi.Protect))
            {
                FencePrint(
                    "target=%s rva=0x%llX validation=FAILED protect=0x%08lX",
                    target.name,
                    static_cast<unsigned long long>(target.rva),
                    static_cast<unsigned long>(mbi.Protect));
                continue;
            }

            const std::uintptr_t page = PageBase(address);
            if (!FindGuardPage(page))
            {
                if (g_guardPageCount >= g_guardPages.size())
                    continue;

                g_guardPages[g_guardPageCount++] = {
                    page,
                    static_cast<DWORD>(mbi.Protect & ~PAGE_GUARD),
                    false
                };
            }

            FencePrint(
                "target=%s rva=0x%llX address=0x%llX validation=OK",
                target.name,
                static_cast<unsigned long long>(target.rva),
                static_cast<unsigned long long>(address));
        }

        if (!g_guardPageCount)
            return false;

        g_veh = AddVectoredExceptionHandler(1, FrontendFenceVeh);
        if (!g_veh)
            return false;

        std::size_t armed = 0;
        for (std::size_t i = 0; i < g_guardPageCount; ++i)
        {
            DWORD oldProtect = 0;
            if (VirtualProtect(
                    reinterpret_cast<void*>(g_guardPages[i].page),
                    pageSize,
                    g_guardPages[i].baseProtect | PAGE_GUARD,
                    &oldProtect))
            {
                g_guardPages[i].armed = true;
                ++armed;
            }
        }

        FencePrint(
            "tracer=MW120-readonly-v1 mechanism=PAGE_GUARD targets=%zu pages=%zu armed=%zu stateWrites=off codeBytesTouched=none",
            g_targets.size(),
            g_guardPageCount,
            armed);

        return armed != 0;
    }

    void RemoveReadOnlyGuards() noexcept
    {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const SIZE_T pageSize = si.dwPageSize ? si.dwPageSize : 0x1000u;

        for (std::size_t i = 0; i < g_guardPageCount; ++i)
        {
            DWORD oldProtect = 0;
            VirtualProtect(
                reinterpret_cast<void*>(g_guardPages[i].page),
                pageSize,
                g_guardPages[i].baseProtect,
                &oldProtect);
            g_guardPages[i].armed = false;
        }

        if (g_veh)
        {
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = nullptr;
        }
    }

    const FenceTarget& Target(std::size_t index) noexcept
    {
        return g_targets[index];
    }

    const char* OnlineStorageState() noexcept
    {
        if (Target(2).hits > 0)
            return "INSTALLED";
        if (Target(1).hits > 0)
            return "CALLBACK_SEEN_WAITING_INSTALL";
        if (Target(0).hits > 0)
            return "REQUESTED_WAITING_CALLBACK";
        return "NOT_REACHED";
    }

    const char* PlayerDataState() noexcept
    {
        if (Target(6).hits > 0)
            return "AVAILABLE_EVENT_SEEN";
        if (Target(4).hits > 0)
            return "NATIVE_INIT_SEEN_WAITING_AVAILABLE_EVENT";
        if (Target(3).hits > 0)
            return "RESET_HANDLER_SEEN";
        return "NOT_REACHED";
    }

    const char* LastMilestone() noexcept
    {
        LONG64 newest = 0;
        const char* name = "NONE";

        for (const auto& target : g_targets)
        {
            const LONG64 tick = target.lastTick;
            if (tick > newest)
            {
                newest = tick;
                name = target.name;
            }
        }

        return name;
    }

    DWORD WINAPI FrontendFenceWorker(LPVOID) noexcept
    {
        // Let the proxy DLL's normal RedirectWorker finish opening the console and
        // installing its compatibility/network hooks first.
        Sleep(3000);

        g_startTick = GetTickCount64();
        g_imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));

        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;

        if (!ReadLiveFingerprint(timestamp, imageSize, entryPoint))
        {
            NativeStatePrint("disabled reason=fingerprint-read-failed");
            return 0;
        }

        if (timestamp != kMW120Timestamp ||
            imageSize != kMW120ImageSize ||
            entryPoint != kMW120EntryPoint)
        {
            NativeStatePrint(
                "disabled reason=not-IW8-1.20 timestamp=0x%08X imageSize=0x%08X entryPoint=0x%08X",
                timestamp,
                imageSize,
                entryPoint);
            return 0;
        }

        // PAGE_GUARD tracing is intentionally opt-in. Guarding six executable
        // pages during normal startup can repeatedly fault on unrelated hot
        // instructions that share those pages and delay the stock online flow.
        // Normal runs use only passive reads of exact 1.20 state globals.
        wchar_t traceEnabled[8]{};
        if (!GetEnvironmentVariableW(
                L"CODREVAMPED_MW120_FENCE_TRACE",
                traceEnabled,
                static_cast<DWORD>(std::size(traceEnabled))) ||
            traceEnabled[0] != L'1')
        {
            return RunPassiveNativeStateProbe();
        }

        DeleteSiblingLog(L"mw2019_frontend_fence.log");
        FencePrint(
            "fingerprint timestamp=0x%08X imageSize=0x%08X entryPoint=0x%08X",
            timestamp,
            imageSize,
            entryPoint);

        if (!InstallReadOnlyGuards())
        {
            FencePrint("disabled reason=no-guard-pages-installed");
            return 0;
        }

        std::array<LONG, 7> reportedHits{};
        ULONGLONG nextSummary = 0;

        // Two minutes is enough to cover the entire "Connecting to Online Services"
        // phase from the supplied traces.  The game is not modified when the tracer
        // stops; guarded pages are restored to their original protection.
        while (InterlockedCompareExchange(&g_stop, 0, 0) == 0 &&
               GetTickCount64() - g_startTick < 120000ull)
        {
            for (std::size_t i = 0; i < g_targets.size(); ++i)
            {
                const LONG hits = g_targets[i].hits;
                if (hits == reportedHits[i])
                    continue;

                reportedHits[i] = hits;
                FencePrint(
                    "HIT name=%s hits=%ld rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX",
                    g_targets[i].name,
                    static_cast<long>(hits),
                    static_cast<unsigned long long>(g_targets[i].lastRcx),
                    static_cast<unsigned long long>(g_targets[i].lastRdx),
                    static_cast<unsigned long long>(g_targets[i].lastR8),
                    static_cast<unsigned long long>(g_targets[i].lastR9));
            }

            const ULONGLONG elapsed = GetTickCount64() - g_startTick;
            if (elapsed >= nextSummary)
            {
                nextSummary = elapsed + 2000ull;

                FencePrint(
                    "SUMMARY onlineStorage=%s playerData=%s statsNativeInit=%s resetHandler=%s playerdataAvailable=%s last=%s",
                    OnlineStorageState(),
                    PlayerDataState(),
                    Target(4).hits > 0 ? "SEEN" : "NOT_SEEN",
                    Target(3).hits > 0 ? "SEEN" : "NOT_SEEN",
                    Target(6).hits > 0 ? "SEEN" : "NOT_SEEN",
                    LastMilestone());
            }

            Sleep(50);
        }

        FencePrint(
            "FINAL onlineStorage=%s playerData=%s statsNativeInit=%s resetHandler=%s playerdataAvailable=%s last=%s",
            OnlineStorageState(),
            PlayerDataState(),
            Target(4).hits > 0 ? "SEEN" : "NOT_SEEN",
            Target(3).hits > 0 ? "SEEN" : "NOT_SEEN",
            Target(6).hits > 0 ? "SEEN" : "NOT_SEEN",
            LastMilestone());

        RemoveReadOnlyGuards();
        FencePrint("tracer stopped; original page protections restored");
        return 0;
    }

    struct FrontendFenceAutoStart
    {
        FrontendFenceAutoStart() noexcept
        {
            HANDLE thread = CreateThread(nullptr, 0, FrontendFenceWorker, nullptr, 0, nullptr);
            if (thread)
                CloseHandle(thread);

            wchar_t hideRequested[8]{};
            if (GetEnvironmentVariableW(
                    L"CODREVAMPED_MW120_HIDE_WINDOW",
                    hideRequested,
                    static_cast<DWORD>(std::size(hideRequested))) &&
                hideRequested[0] == L'1')
            {
                HANDLE hideThread = CreateThread(nullptr, 0, HideOwnWindowsWorker, nullptr, 0, nullptr);
                if (hideThread)
                    CloseHandle(hideThread);
            }
        }
    };

    // version.dll is loaded at process startup.  The worker itself sleeps before
    // touching game pages, so this constructor only queues the tracer thread.
    FrontendFenceAutoStart g_frontendFenceAutoStart;
}
