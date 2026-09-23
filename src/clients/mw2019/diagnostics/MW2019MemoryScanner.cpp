#include "MW2019MemoryScanner.hpp"
#include "MW2019Shared.hpp"
#include "MW2019NetworkBlocker.hpp"
#include "../game/IW8144Compat.h"

#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdarg>
#include <cwchar>
#include <intrin.h>
#include <process.h>
#include <cerrno>
#include <vector>
#include <algorithm>

namespace mw2019_network
{
    void SetCustomServer(const char* host) noexcept;
    void GetCustomServer(char* out, std::size_t outCount) noexcept;
}

namespace
{
    template <typename T, size_t N> constexpr size_t CountOf(const T (&)[N]) noexcept { return N; }

    enum class ResolveKind { None, CallRel32At0, RipRel32At2, RipRel32At2Plus1, RipRel32At3 };

    struct Signature
    {
        const char* name;
        const char* pattern;
        ResolveKind resolve;
        std::uintptr_t address;
    };

    Signature g_signatures[] = {
        {"luaL_openlib", "48 89 5C 24 ? 55 56 41 56 48 83 EC ? 48 8B 41", ResolveKind::None, 0},
        {"lua_pushboolean", "E8 ? ? ? ? EB ? 85 D2 78", ResolveKind::CallRel32At0, 0},
        {"lua_pushstring", "48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 48 8B D9 48 85 D2 75 ? 48 8B 41", ResolveKind::None, 0},
        {"lua_remove", "4C 8B C1 85 D2 7E ? 8D 42 ? 48 63 D0 48 8B 41 ? 48 8B 49", ResolveKind::None, 0},
        {"lua_remove_v146", "4C 8B C1 85 D2 7E ? 48 8B 41 ? 48 8B 49", ResolveKind::None, 0},
        {"lua_getfield", "48 89 5C 24 ? 57 48 83 EC ? 4D 8B D0 48 8B D9 E8 ? ? ? ? 48 8B F8 49 C7 C0 ? ? ? ? 90 49 FF C0 43 80 3C 02 ? 75 ? 49 8B D2 48 8B CB E8 ? ? ? ? 48 B9 ? ? ? ? ? ? ? ? 4C 8D 44 24 ? 48 0B C1 48 8B D7 48 8B CB 48 89 44 24 ? E8 ? ? ? ? 48 85 C0", ResolveKind::None, 0},
        {"LUI_luaVM", "48 8B 05 ? ? ? ? 45 33 C0 44 8B 4C 24 ? 48 89 44 24 ? 48 8B 5C 24", ResolveKind::RipRel32At3, 0},
        {"LuaShared_PCall", "E8 ? ? ? ? 8B F8 85 C0 74 ? 4C 8D 44 24", ResolveKind::CallRel32At0, 0},
        {"Dvar_RegisterBool", "E8 ? ? ? ? 48 8B F0 F6 46", ResolveKind::CallRel32At0, 0},
        {"Dvar_FindVarByName", "E8 ? ? ? ? 48 8B CB 48 63 50", ResolveKind::CallRel32At0, 0},
        {"Dvar_RegisterString", nullptr, ResolveKind::None, 0},
        {"Cmd_Exec_Internal", nullptr, ResolveKind::None, 0},
        {"Content_DoWeHaveContentPack", nullptr, ResolveKind::None, 0},
        {"Live_OnlineServicesFence_GetState", nullptr, ResolveKind::None, 0},
        {"Live_SyncOnlineDataFence_GetState", nullptr, ResolveKind::None, 0},
        {"LUI_CoD_LuaCall_IsBattleNetAuthReady", nullptr, ResolveKind::None, 0},
        {"LUI_CoD_LuaCall_IsConnectedToGameServer", nullptr, ResolveKind::None, 0},
        {"LUI_CoD_LuaCall_ShouldBeInOnlineArea", nullptr, ResolveKind::None, 0},
        {"LUI_CoD_LuaCall_OfflineDataFetched", nullptr, ResolveKind::None, 0},
        {"OnlineErrorManager_GetFenceState", nullptr, ResolveKind::None, 0},
        {"OnlineErrorManager_IsMpNotAllowed", nullptr, ResolveKind::None, 0},
        {"s_OnlineServicesFenceData_state", nullptr, ResolveKind::None, 0},
        {"LUI_OpenMenu", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 41 8B F1 41 8B D8", ResolveKind::None, 0},
        {"s_isContentEnumerationFinished", "80 3D ? ? ? ? ? 74 ? 48 89 7C 24", ResolveKind::RipRel32At2Plus1, 0},
        {"unk_XUIDCheck1", "48 8D 1D ? ? ? ? 40 88 35", ResolveKind::RipRel32At3, 0},
        {"GamerProfile_SetDataByName", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B F1 0F 29 74 24", ResolveKind::None, 0},
        {"CL_PlayerData_GetDDLBuffer", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B E9 49 63 F8", ResolveKind::None, 0},
        {"DB_LoadXFile", "E8 ? ? ? ? 8B F8 33 ED 40 38 B3", ResolveKind::CallRel32At0, 0},
        {"DB_FindXAssetHeader", "E8 ? ? ? ? 44 8B C5 8D 4D", ResolveKind::CallRel32At0, 0},
        {"CL_GetLocalClientSignInState", "E8 ? ? ? ? 85 C0 7F ? 8B CB", ResolveKind::CallRel32At0, 0},
        {"Live_IsUserSignedInToDemonware", "E8 ? ? ? ? 83 4F ? ? 48 8D 0D", ResolveKind::CallRel32At0, 0},
        {"dwGetLogOnStatus", "40 53 48 83 EC ? 48 63 C1 BA ? ? ? ? 48 69 D8", ResolveKind::None, 0},
        {"R_EndFrame", "48 83 EC ? E8 ? ? ? ? 48 8B 15 ? ? ? ? 45 33 D2", ResolveKind::None, 0},
        {"s_luaInFrontend", "0F B6 05 ? ? ? ? 75", ResolveKind::RipRel32At3, 0},
        {"unk_BNetClass", "83 3D ? ? ? ? ? 74 ? B8 ? ? ? ? C3", ResolveKind::RipRel32At2, 0},
        {"unk_IsUserSignedInToBNet", "40 53 48 83 EC ? 48 8B DA E8 ? ? ? ? 83 38 ? 75 ? E8 ? ? ? ? 84 C0", ResolveKind::None, 0},
        {"unk_SignInState", "83 3D ? ? ? ? ? 7E ? 33 C9", ResolveKind::RipRel32At2, 0},
    };

    struct V99RelCallHit
    {
        std::uintptr_t callsite;
        std::uintptr_t target;
    };

    Signature* FindSignature(const char* name) noexcept;
    bool InstallLUIOpenMenuTraceHook() noexcept;
    bool InstallBuild357GameWindowDispatch() noexcept;
    bool IsExecutableProtect(DWORD protect) noexcept;
    bool GetMainImageRange(std::uintptr_t& baseOut, std::uintptr_t& endOut) noexcept;
    bool V99FunctionBounds(std::uintptr_t address, std::uintptr_t& beginOut, std::uintptr_t& endOut) noexcept;
    void V99LogPreCallBranchCandidates(std::uintptr_t callsite, std::uintptr_t ownerBegin, std::uintptr_t ownerEnd, std::uintptr_t moduleBase) noexcept;
    unsigned V99CollectRel32CallsInRegion(std::uintptr_t scanStart, std::uintptr_t scanEnd, const std::uintptr_t* targets, unsigned targetCount, V99RelCallHit* outHits, unsigned outCapacity) noexcept;
    void Build378ArmTransitionTrace(const char* label) noexcept;
    void V99MenuBacktraceScan() noexcept;
    void V99PrintMenuStatus() noexcept;
    void V99Append(const char* format, ...) noexcept;
    void V100PrintFrontendStatus(const char* reason = "manual") noexcept;
    void V100ArmFrontendTrace(unsigned seconds = 45) noexcept;
    void V100StopFrontendTrace(const char* reason) noexcept;
    void V100ConnectingXrefScan() noexcept;
    void V100ScheduleManualMenuSnapshots(const char* menuName) noexcept;
    void V100Snapshot(const char* reason) noexcept;
    void V100TraceWindowMessage(UINT msg, WPARAM wParam, LPARAM lParam) noexcept;
    void V100FrontendTraceTick(unsigned long long uptimeMs) noexcept;
    void V100Append(const char* format, ...) noexcept;
    bool Build374PostMenuMessage(WPARAM id) noexcept;

    volatile LONG g_scanBusy = 0;
    unsigned long long g_lastAutoScan = 0;
    bool g_firstAutoDone = false;
    unsigned g_autoAttempts = 0;
    bool g_completionLogged = false;

    bool g_buildGateLogged = false;
    unsigned long long g_lastDvarPass = 0;
    unsigned g_dvarPasses = 0;
    unsigned long long g_firstOfflineDvarPassAt = 0;
    bool g_luaMenuHookInstalled = false;
    void* g_luaOpenLibTrampoline = nullptr;
    PVOID g_crashVeh = nullptr;
    volatile LONG g_crashLogCount = 0;
    // Build372: 0x43E5D70 is called as (controller, StatsSource, StatsGroup).
    // The stock caller deliberately passes RCX=0 for controller 0. The protected
    // entry begins with a deliberate-looking null read through RDI, so never do
    // file I/O or stack walking for this exception inside VEH.
    volatile LONG g_mpProtectedEntryExceptionCount = 0;
    LONG g_mpProtectedEntryLastLogged = 0;
    bool g_luiOpenTraceHookInstalled = false;
    void* g_luiOpenTraceTrampoline = nullptr;
    volatile LONG g_luiOpenTraceCount = 0;

    // Build378: short, user-armed transition trace. This stays completely idle
    // until `trace mp` / `trace wz` is issued, then records only the next 20s
    // of LUI_OpenMenu activity and native callers.
    volatile LONG g_transitionTraceArmed = 0;
    unsigned long long g_transitionTraceDeadlineMs = 0;
    char g_transitionTraceLabel[32]{};

    // V100: focused frontend-transition / Connecting-state observer.  This is
    // command-armed only and never changes a frontend, menu, auth, or input value.
    struct V100UiMarkerAddress
    {
        std::uintptr_t address = 0;
        bool utf16 = false;
        bool imageBacked = false;
    };
    V100UiMarkerAddress g_v100ConnectingMarkers[32]{};
    unsigned g_v100ConnectingMarkerCount = 0;
    volatile LONG g_v100FrontendTraceArmed = 0;
    unsigned long long g_v100FrontendTraceDeadlineMs = 0;
    unsigned long long g_v100FrontendTraceNextSampleMs = 0;
    unsigned long long g_v100FrontendTraceLastHeartbeatMs = 0;
    int g_v100LastFrontend = -999;
    int g_v100LastMarkerLive = -999;
    HWND g_v100LastForeground = nullptr;
    HWND g_v100LastFocus = nullptr;
    HWND g_v100LastActive = nullptr;
    HWND g_v100LastCapture = nullptr;
    unsigned long long g_v100ManualSnapshotStartMs = 0;
    unsigned g_v100ManualSnapshotMask = 0;
    char g_v100ManualSnapshotMenu[64]{};
    bool g_ddlTraceHookInstalled = false;
    bool g_arxanSafeDiagnosticHooksRestored = false;
    bool g_luaOpenLibRestoredAfterQuiet = false;
    volatile LONG g_luaOpenLibActiveCalls = 0;
    volatile LONG g_luaOverrideRegistrationCount = 0;
    unsigned long long g_lastLuaOverrideActivityMs = 0;
    void* g_ddlTraceTrampoline = nullptr;
    volatile LONG g_ddlTraceCount = 0;
    volatile LONG g_ddlOfflineGroupCalls[8]{};
    volatile LONG g_ddlOfflineGroupSuccess[8]{};
    unsigned long long g_lastMpStateSnapshot = 0;
    unsigned g_mpStateSnapshotCount = 0;
    bool g_identitySnapshotDumped = false;
    bool g_crashPathSnapshotDumped = false;
    bool g_identityPrereqsLogged = false;
    bool g_profilePrereqsLogged = false;
    bool g_deepDiscoveryDone = false;
    bool g_luaWrapperDiscoveryDone = false;
    bool g_legacy120StatsAnchorDiscoveryDone = false;

    // Legacy LAN/debug route helpers remain compiled for comparison only.
    // Build372 never polls the F-keys and never forces those menus.
    HWND g_gameWindow = nullptr;
    WNDPROC g_originalGameWndProc = nullptr;
    HWND g_build374WindowCandidate = nullptr;
    unsigned long long g_build374WindowCandidateArea = 0;
    bool g_build374ReadyLogged = false;
    bool g_build384FrontendTraceAutoArmed = false;

    // Build385: passive memory-diff trace. We intentionally avoid PAGE_GUARD,
    // hardware breakpoints and write hooks because those can interfere with the
    // game's own exception/protection flow. Instead we snapshot writable state
    // owned by ModernWarfare.exe plus the live Lua VM allocation and report only
    // bytes that actually change during the short frontend transition window.
    struct Build385WatchSpan
    {
        std::uintptr_t base = 0;
        std::size_t size = 0;
        std::vector<unsigned char> snapshot;
        std::vector<unsigned char> warmupPageChanges;
        std::vector<unsigned char> activePages;
        unsigned long changes = 0;
    };
    std::vector<Build385WatchSpan>& Build385WatchSpans()
    {
        static auto* value = new std::vector<Build385WatchSpan>();
        return *value;
    }
    bool g_build385MemoryTraceArmed = false;
    unsigned long long g_build385MemoryTraceDeadlineMs = 0;
    unsigned long long g_build385MemoryTraceWarmupUntilMs = 0;
    unsigned long long g_build385LastMemoryScanMs = 0;
    unsigned long long g_build388LastWarmupScanMs = 0;
    unsigned long g_build385LoggedChanges = 0;
    bool g_build385WarmupComplete = false;
    constexpr unsigned long kBuild385MaxLoggedChanges = 600;

    // Build390: use visible frontend text as passive state markers. We do not
    // modify these strings or authentication state; their appearance simply
    // timestamps the stock transition so the memory diff can be correlated
    // with Connecting/Loading/Failure screens.
    unsigned long long g_build390LastUiMarkerScanMs = 0;
    bool g_build390ConnectingSeen = false;
    bool g_build390LoadingAssetsSeen = false;
    bool g_build390ConnectionFailedSeen = false;
    bool g_build390UnableOnlineSeen = false;
    void* g_build390LuaVmForMarkers = nullptr;

    // Build391: locate localization-token strings once, then watch settled writable
    // memory for pointers to those tokens. This is passive tracing only; it does
    // not alter authentication or service state.
    struct Build391TokenAddress
    {
        const char* label = nullptr;
        const char* token = nullptr;
        std::uintptr_t address = 0;
    };
    std::vector<Build391TokenAddress>& Build391TokenAddresses()
    {
        static auto* value = new std::vector<Build391TokenAddress>();
        return *value;
    }

    std::vector<std::uintptr_t>& Build391SeenPointerRefs()
    {
        static auto* value = new std::vector<std::uintptr_t>();
        return *value;
    }
    bool g_build391TokensLocated = false;
    unsigned long long g_build391LastPointerScanMs = 0;

    bool g_build379CfgAuditDone = false;
    constexpr UINT kBuild357MenuMessage = WM_APP + 0x369;
    bool g_f1WasDown = false;
    bool g_f2WasDown = false;
    bool g_f3WasDown = false;
    bool g_f4WasDown = false;
    bool g_f5WasDown = false;
    bool g_hotkeyHelpLogged = false;

    // Build373: Retail/Steam Lua-dump driven menu command console.
    // No F-key polling is re-enabled. Commands are read from the existing OS console
    // and marshalled to the game window thread before touching LUI.
    volatile LONG g_build373ConsoleThreadStarted = 0;
    volatile LONG g_build373RawMenuPending = 0;
    char g_build373RawMenu[128]{};
    constexpr WPARAM kBuild373RawMenuRoute = 0x1000;

    // Steam 1.69 live command discovery/runner. Command nodes are discovered
    // passively from writable ModernWarfare.exe data pages and executed through
    // the game's own Engine.ExecNow Lua bridge on the game window thread.
    constexpr UINT kBuild169ExecMessage = WM_APP + 0x36A;
    volatile LONG g_build169ExecPending = 0;
    char g_build169ExecText[512]{};
    SRWLOCK g_build169CommandLock = SRWLOCK_INIT;

    struct Build169DiscoveredCommand
    {
        char name[96]{};
        std::uintptr_t node = 0;
        std::uintptr_t callback = 0;
    };

    std::vector<Build169DiscoveredCommand>& Build169Commands()
    {
        static auto* value = new std::vector<Build169DiscoveredCommand>();
        return *value;
    }

    unsigned g_build169LastAutoCommandCount = 0;

    // Forward declarations used by the live command scanner.
    bool IsReadable(DWORD protect);
    bool IsExecutableProtect(DWORD protect) noexcept;
    bool GetMainImageRange(std::uintptr_t& baseOut, std::uintptr_t& endOut) noexcept;
    void Build169ScanCommandsInternal(bool verbose) noexcept;
    bool Build169QueueExec(const char* command) noexcept;

    struct CapturedLuaWrapper
    {
        const char* obfuscatedName;
        const char* friendlyName;
        std::uintptr_t original;
    };

    CapturedLuaWrapper g_capturedLuaWrappers[] = {
        {"BGAAHHAGAC", "IsDemoBuild", 0},
        {"JBIHDJBH",   "IsBattleNetAuthReady", 0},
        {"BJGAADIDFH", "IsBattleNetLanOnly", 0},
        {"DHEJECBEE",  "IsConnectedToGameServer", 0},
        {"CEGDBDIIIE", "IsGameModeAllowed", 0},
        {"DBEGJIECGB", "IsGameModeAvailable", 0},
        {"CFHBIHABCB", "IsPremiumPlayer", 0},
        {"ECFHDAEIDA", "IsPremiumPlayerReady", 0},
    };


    void LogCrashPointerQwords(const char* regName, std::uintptr_t value) noexcept
    {
        if (!regName || value < 0x10000ull)
            return;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(value), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            return;

        __try
        {
            const auto* q = reinterpret_cast<const std::uint64_t*>(value);
            mw2019_diag::Log(
                "[CRASH-MEM] reg=%s ptr=%p q0=%016llX q1=%016llX q2=%016llX q3=%016llX q4=%016llX q5=%016llX q6=%016llX q7=%016llX\r\n",
                regName, reinterpret_cast<void*>(value),
                static_cast<unsigned long long>(q[0]), static_cast<unsigned long long>(q[1]),
                static_cast<unsigned long long>(q[2]), static_cast<unsigned long long>(q[3]),
                static_cast<unsigned long long>(q[4]), static_cast<unsigned long long>(q[5]),
                static_cast<unsigned long long>(q[6]), static_cast<unsigned long long>(q[7]));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log("[CRASH-MEM] reg=%s ptr=%p unreadable code=0x%08lX\r\n",
                regName, reinterpret_cast<void*>(value), GetExceptionCode());
        }
    }

    LONG CALLBACK CrashTraceVeh(EXCEPTION_POINTERS* ep) noexcept
    {
        if (!ep || !ep->ExceptionRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        const DWORD code = ep->ExceptionRecord->ExceptionCode;
        if (code != EXCEPTION_ACCESS_VIOLATION &&
            code != EXCEPTION_ILLEGAL_INSTRUCTION &&
            code != EXCEPTION_STACK_OVERFLOW &&
            code != EXCEPTION_IN_PAGE_ERROR)
            return EXCEPTION_CONTINUE_SEARCH;

        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const auto at = reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
        constexpr std::uintptr_t kKnownImageSize = 0x21679200ull;
        const bool inGameImage =
            base && at >= base && at < base + kKnownImageSize;
        const unsigned long long rva =
            inGameImage ? static_cast<unsigned long long>(at - base) : 0ull;

        // Ignore faults raised by our scanner/CRT/system modules. We only need
        // ModernWarfare.exe exceptions for the Local-MP transition.
        if (!inGameImage || rva == 0x767DD4ull)
            return EXCEPTION_CONTINUE_SEARCH;

#if defined(_M_X64)
        // Build372: the stock caller at 0x347212A sets:
        //   ECX = controller index (0 is valid), EDX = StatsSource::OFFLINE (1),
        //   R8D = StatsGroup (0..7), then calls 0x43E5D70.
        // The target's protected entry begins with bytes 23 27 (`and esp,[rdi]`)
        // while RDI is zero in the observed context. Treat this as a protection/
        // exception-dispatch candidate, not as a null controller object.
        //
        // IMPORTANT: stay completely silent here. Build371 performed logging and
        // stack walking before the game's later exception handlers got a chance
        // to process the fault. We only increment our own DLL counter and continue
        // searching; the worker thread will log later *only if execution survives*.
        if (rva == 0x43E5D70ull &&
            ep->ContextRecord &&
            ep->ContextRecord->Rdx == 1 &&
            ep->ContextRecord->R8 < 8)
        {
            InterlockedIncrement(&g_mpProtectedEntryExceptionCount);
            return EXCEPTION_CONTINUE_SEARCH;
        }
#endif

        const LONG index = InterlockedIncrement(&g_crashLogCount);
        if (index > 16)
            return EXCEPTION_CONTINUE_SEARCH;

#if defined(_M_X64)
        CONTEXT* c = ep->ContextRecord;
        mw2019_diag::Log(
            "[CRASH-CANDIDATE] index=%ld thread=%lu code=0x%08lX address=%p rva=0x%llX rip=%p rsp=%p rbp=%p rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p r8=%p r9=%p\r\n",
            index, GetCurrentThreadId(), code, ep->ExceptionRecord->ExceptionAddress, rva,
            c ? reinterpret_cast<void*>(c->Rip) : nullptr,
            c ? reinterpret_cast<void*>(c->Rsp) : nullptr,
            c ? reinterpret_cast<void*>(c->Rbp) : nullptr,
            c ? reinterpret_cast<void*>(c->Rax) : nullptr,
            c ? reinterpret_cast<void*>(c->Rbx) : nullptr,
            c ? reinterpret_cast<void*>(c->Rcx) : nullptr,
            c ? reinterpret_cast<void*>(c->Rdx) : nullptr,
            c ? reinterpret_cast<void*>(c->Rsi) : nullptr,
            c ? reinterpret_cast<void*>(c->Rdi) : nullptr,
            c ? reinterpret_cast<void*>(c->R8) : nullptr,
            c ? reinterpret_cast<void*>(c->R9) : nullptr);

        if (c)
        {
            LogCrashPointerQwords("RAX", static_cast<std::uintptr_t>(c->Rax));
            LogCrashPointerQwords("RBX", static_cast<std::uintptr_t>(c->Rbx));
            LogCrashPointerQwords("RCX", static_cast<std::uintptr_t>(c->Rcx));
            LogCrashPointerQwords("RDX", static_cast<std::uintptr_t>(c->Rdx));
            LogCrashPointerQwords("RSI", static_cast<std::uintptr_t>(c->Rsi));
            LogCrashPointerQwords("RDI", static_cast<std::uintptr_t>(c->Rdi));
            LogCrashPointerQwords("R8", static_cast<std::uintptr_t>(c->R8));
            LogCrashPointerQwords("R9", static_cast<std::uintptr_t>(c->R9));
            LogCrashPointerQwords("R10", static_cast<std::uintptr_t>(c->R10));
            LogCrashPointerQwords("R11", static_cast<std::uintptr_t>(c->R11));
        }

        if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR)
        {
            const ULONG_PTR kind = ep->ExceptionRecord->NumberParameters > 0
                ? ep->ExceptionRecord->ExceptionInformation[0] : static_cast<ULONG_PTR>(~0ull);
            const ULONG_PTR fault = ep->ExceptionRecord->NumberParameters > 1
                ? ep->ExceptionRecord->ExceptionInformation[1] : 0;
            const char* op = kind == 0 ? "read" : (kind == 1 ? "write" : (kind == 8 ? "execute" : "unknown"));
            mw2019_diag::Log(
                "[CRASH-ACCESS] index=%ld operation=%s kind=%llu faultAddress=%p\r\n",
                index, op, static_cast<unsigned long long>(kind), reinterpret_cast<void*>(fault));
        }

        if (c)
        {
            __try
            {
                const auto* ip = reinterpret_cast<const unsigned char*>(c->Rip);
                char hexLine[1024]{};
                int pos = sprintf_s(hexLine, "[CRASH-BYTES] rva=0x%llX bytes=", rva);
                for (int i = -16; i < 48 && pos > 0 && pos < static_cast<int>(sizeof(hexLine) - 4); ++i)
                    pos += sprintf_s(hexLine + pos, sizeof(hexLine) - static_cast<size_t>(pos), "%02X ", ip[i]);
                if (pos > 0)
                    strcat_s(hexLine, "\r\n");
                mw2019_diag::Log("%s", hexLine);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                mw2019_diag::Log("[CRASH-BYTES] unavailable code=0x%08lX\r\n", GetExceptionCode());
            }

            __try
            {
                const auto* stack = reinterpret_cast<const std::uintptr_t*>(c->Rsp);
                for (int i = 0; i < 32; ++i)
                {
                    const std::uintptr_t value = stack[i];
                    const unsigned long long stackRva =
                        (base && value >= base && value < base + kKnownImageSize)
                            ? static_cast<unsigned long long>(value - base)
                            : 0ull;
                    if (stackRva)
                    {
                        mw2019_diag::Log("[CRASH-STACK] +0x%03X value=%p gameRva=0x%llX\r\n",
                            i * static_cast<int>(sizeof(std::uintptr_t)),
                            reinterpret_cast<void*>(value),
                            stackRva);

                        __try
                        {
                            const auto* codePtr = reinterpret_cast<const unsigned char*>(value);
                            char stackBytes[512]{};
                            int bpos = sprintf_s(stackBytes, "[CRASH-STACK-BYTES] gameRva=0x%llX bytes=", stackRva);
                            for (int b = -16; b < 32 && bpos > 0 && bpos < static_cast<int>(sizeof(stackBytes) - 4); ++b)
                                bpos += sprintf_s(stackBytes + bpos, sizeof(stackBytes) - static_cast<size_t>(bpos), "%02X ", codePtr[b]);
                            if (bpos > 0)
                                strcat_s(stackBytes, "\r\n");
                            mw2019_diag::Log("%s", stackBytes);
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {}
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                mw2019_diag::Log("[CRASH-STACK] unavailable code=0x%08lX\r\n", GetExceptionCode());
            }
        }
#else
        mw2019_diag::Log("[CRASH-CANDIDATE] index=%ld thread=%lu code=0x%08lX address=%p rva=0x%llX\r\n",
            index, GetCurrentThreadId(), code, ep->ExceptionRecord->ExceptionAddress, rva);
#endif
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void InstallCrashTraceVehLate() noexcept
    {
        if (g_crashVeh)
            return;

        // Register after the game has finished its startup/protection work and
        // after all of our known game .text hooks are stock. Passing First=0
        // appends us to the current VEH chain, so already-registered game
        // protection handlers get the first chance to consume intentional faults.
        g_crashVeh = AddVectoredExceptionHandler(0, &CrashTraceVeh);
        if (!g_crashVeh)
            mw2019_diag::Log("[ERROR] crash recorder registration failed\r\n");
    }

    struct LuaReg
    {
        const char* name;
        int (*func)(void*);
    };

    using LuaOpenLibFn = void (*)(void*, const char*, const LuaReg*, std::uint32_t);
    using LuaPushBooleanFn = void (*)(void*, int);

    int LuaReturnTrue(void* vm) noexcept
    {
        Signature* push = FindSignature("lua_pushboolean");
        if (!push || !push->address || !vm)
            return 0;

        __try
        {
            reinterpret_cast<LuaPushBooleanFn>(push->address)(vm, 1);
            return 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    bool IsForcedMenuLuaName(const char* libName, const char* fnName) noexcept
    {
        if (!libName || !fnName || _stricmp(libName, "Engine") != 0)
            return false;

        static const char* const kNames[] = {
            "BGAAHHAGAC", // IsDemoBuild
            "JBIHDJBH",   // IsBattleNetAuthReady
            "BJGAADIDFH", // IsBattleNetLanOnly
            "DHEJECBEE",  // IsConnectedToGameServer
            "CEGDBDIIIE", // IsGameModeAllowed
            "DBEGJIECGB", // IsGameModeAvailable
            "CFHBIHABCB", // IsPremiumPlayer
            "ECFHDAEIDA"  // IsPremiumPlayerReady
        };

        for (const char* name : kNames)
            if (_stricmp(fnName, name) == 0)
                return true;
        return false;
    }

    void CaptureLuaWrapper(const char* libName, const char* fnName, int (*fn)(void*)) noexcept
    {
        if (!libName || !fnName || !fn || _stricmp(libName, "Engine") != 0)
            return;

        const auto address = reinterpret_cast<std::uintptr_t>(fn);
        for (auto& wrapper : g_capturedLuaWrappers)
        {
            if (_stricmp(wrapper.obfuscatedName, fnName) != 0)
                continue;

            if (!wrapper.original)
                wrapper.original = address;
            return;
        }
    }

    // Build372 compile fix: MSVC C2712 forbids __try in a function frame that
    // owns C++ objects requiring unwinding. Keep the SEH-heavy hook body free of
    // RAII objects, and track active calls in a tiny outer SEH wrapper instead.
    // __finally guarantees the counter is decremented even if the body returns
    // through one of its guarded fallback paths.
    void LuaOpenLibHookBody(void* vm, const char* libName, const LuaReg* regs, std::uint32_t nup) noexcept
    {
        auto original = reinterpret_cast<LuaOpenLibFn>(g_luaOpenLibTrampoline);
        if (!original)
            return;

        if (!regs || !libName)
        {
            original(vm, libName, regs, nup);
            return;
        }

        std::size_t count = 0;
        __try
        {
            while (count < 1024 && regs[count].name)
                ++count;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            original(vm, libName, regs, nup);
            return;
        }

        if (!count)
        {
            original(vm, libName, regs, nup);
            return;
        }

        LuaReg* copy = static_cast<LuaReg*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LuaReg) * (count + 1)));
        if (!copy)
        {
            original(vm, libName, regs, nup);
            return;
        }

        __try
        {
            memcpy(copy, regs, sizeof(LuaReg) * count);
            unsigned replaced = 0;
            for (std::size_t i = 0; i < count; ++i)
            {
                if (IsForcedMenuLuaName(libName, copy[i].name))
                {
                    // Build355: save the real current-Retail wrapper before replacing it.
                    // The old 1.44 AddressBook resolved auth/profile state by following
                    // these wrappers, which is much more reliable than blind whole-EXE scans.
                    CaptureLuaWrapper(libName, copy[i].name, copy[i].func);
copy[i].func = &LuaReturnTrue;
                    ++replaced;
                }
            }

            original(vm, libName, copy, nup);
            if (replaced)
            {
                g_lastLuaOverrideActivityMs = GetTickCount64();
                InterlockedIncrement(&g_luaOverrideRegistrationCount);
}
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log("[LUA-MENU] guarded registration fault code=0x%08lX; falling back to stock table\r\n", GetExceptionCode());
            original(vm, libName, regs, nup);
        }

        HeapFree(GetProcessHeap(), 0, copy);
    }

    void LuaOpenLibHook(void* vm, const char* libName, const LuaReg* regs, std::uint32_t nup) noexcept
    {
        InterlockedIncrement(&g_luaOpenLibActiveCalls);
        __try
        {
            LuaOpenLibHookBody(vm, libName, regs, nup);
        }
        __finally
        {
            InterlockedDecrement(&g_luaOpenLibActiveCalls);
        }
    }

    bool InstallLuaMenuHook() noexcept
    {
        if (g_luaMenuHookInstalled)
            return true;

        Signature* openLib = FindSignature("luaL_openlib");
        Signature* pushBool = FindSignature("lua_pushboolean");
        if (!openLib || !openLib->address || !pushBool || !pushBool->address)
            return false;

        constexpr std::size_t kPatchSize = 13;
        unsigned char original[kPatchSize]{};
        __try { memcpy(original, reinterpret_cast<const void*>(openLib->address), kPatchSize); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

        unsigned char* trampoline = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!trampoline)
            return false;

        memcpy(trampoline, original, kPatchSize);
        std::size_t pos = kPatchSize;
        trampoline[pos++] = 0x48; trampoline[pos++] = 0xB8;
        *reinterpret_cast<std::uint64_t*>(trampoline + pos) = static_cast<std::uint64_t>(openLib->address + kPatchSize);
        pos += 8;
        trampoline[pos++] = 0xFF; trampoline[pos++] = 0xE0;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(openLib->address), kPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        unsigned char patch[kPatchSize]{};
        patch[0] = 0x48; patch[1] = 0xB8;
        *reinterpret_cast<std::uint64_t*>(patch + 2) = reinterpret_cast<std::uint64_t>(&LuaOpenLibHook);
        patch[10] = 0xFF; patch[11] = 0xE0; patch[12] = 0x90;

        memcpy(reinterpret_cast<void*>(openLib->address), patch, kPatchSize);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(openLib->address), kPatchSize);
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(openLib->address), kPatchSize, oldProtect, &ignored);

        g_luaOpenLibTrampoline = trampoline;
        g_luaMenuHookInstalled = true;

        return true;
    }


    using LUIOpenMenuFn = void (*)(int, const char*, int, int, int);


    using LuaGetFieldFn = void (*)(void*, int, const char*);
    using LuaPushStringFn = void (*)(void*, const char*);
    using LuaRemoveFn = void (*)(void*, int);
    using LuaPCallFn = int (*)(void*, int, int);

    bool Build372ExecNow(void* luaVm, const char* command) noexcept
    {
        if (!luaVm || !command || !*command)
            return false;

        Signature* getField = FindSignature("lua_getfield");
        Signature* pushString = FindSignature("lua_pushstring");
        Signature* remove = FindSignature("lua_remove");
        Signature* remove146 = FindSignature("lua_remove_v146");
        Signature* pcall = FindSignature("LuaShared_PCall");

        const std::uintptr_t removeAddress =
            (remove && remove->address) ? remove->address :
            ((remove146 && remove146->address) ? remove146->address : 0);

        if (!getField || !getField->address ||
            !pushString || !pushString->address ||
            !removeAddress ||
            !pcall || !pcall->address)
        {
            mw2019_diag::Log(
                "[LAN-EXEC] unavailable getfield=%p pushstring=%p remove=%p pcall=%p cmd='%s'\r\n",
                getField ? reinterpret_cast<void*>(getField->address) : nullptr,
                pushString ? reinterpret_cast<void*>(pushString->address) : nullptr,
                reinterpret_cast<void*>(removeAddress),
                pcall ? reinterpret_cast<void*>(pcall->address) : nullptr,
                command);
            return false;
        }

        // Mirrors the old IW8 Game::Cbuf_AddText bridge:
        // Engine.DAGFFDGFII == ExecNow.
        __try
        {
            const auto luaGetField = reinterpret_cast<LuaGetFieldFn>(getField->address);
            const auto luaPushString = reinterpret_cast<LuaPushStringFn>(pushString->address);
            const auto luaRemove = reinterpret_cast<LuaRemoveFn>(removeAddress);
            const auto luaPCall = reinterpret_cast<LuaPCallFn>(pcall->address);

            luaGetField(luaVm, -10002, "Engine");
            luaGetField(luaVm, -1, "DAGFFDGFII");
            luaRemove(luaVm, -2);
            luaPushString(luaVm, command);
            const int result = luaPCall(luaVm, 1, 1);

            return result == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log(
                "[LAN-EXEC] ExecNow fault code=0x%08lX cmd='%s'\r\n",
                GetExceptionCode(), command);
            return false;
        }
    }

    void Build372BootstrapSystemLink(void* luaVm) noexcept
    {

        static const char* const commands[] = {
            "set onlinegame 0",
            "set systemlink 1",
            "set ui_netSource 1",
            "set xblive_privatematch 1",
            "set xblive_rankedmatch 1",
            "set xblive_loggedin 1"
        };

        unsigned ok = 0;
        for (const char* cmd : commands)
            ok += Build372ExecNow(luaVm, cmd) ? 1u : 0u;

        mw2019_diag::Log("[MENU] LAN bootstrap applied=%u/%u\r\n",
            ok, static_cast<unsigned>(CountOf(commands)));
    }

    struct Build373RetailMenuRoute
    {
        const char* alias;
        const char* menuName;
        const char* luaAsset;
        bool bootstrapSystemLink;
    };

    // Menu-type names are candidates inferred from the CURRENT Retail/Steam Lua
    // asset basenames captured by Build371 (lua_dump_23584_pass1.txt), not 1.20.
    // The raw command exists specifically so a registration name can be corrected
    // at runtime without another rebuild.
    const Build373RetailMenuRoute g_build373RetailMenuRoutes[] = {
        {"revamped",    "ServerBrowser",      "ui/frontend/serverbrowser.lua",                 true},
        {"lanbrowser",  "ServerBrowser",      "ui/frontend/serverbrowser.lua",                 true},
        {"browser",     "ServerBrowser",      "ui/frontend/serverbrowser.lua",                 false},
        {"systemlink",  "SystemLinkLobby",    "ui/frontend/systemlinklobby.lua",               true},
        {"mp",          "MPMainMenu",         "ui/frontend/mp/mpmainmenu.lua",                 false},
        {"main",        "MainMenu",           "ui/frontend/mainmenu.lua",                      false},
        {"offline",     "MainMenuOffline",    "ui/frontend/mainmenuoffline.lua",               false},
        {"public",      "MPPublicLobby",      "ui/frontend/mp/mppubliclobby.lua",              false},
        {"private",     "PrivateMatchLobby",  "ui/frontend/mp/privatematchlobby.lua",          false},
        {"play",        "MPPlayMenu",         "ui/frontend/mp/mpplaymenu.lua",                 false},
        {"playlists",   "PlaylistMenu",       "ui/frontend/mp/playlistmenu.lua",               false},
        {"weapons",     "MPWeaponMenu",       "ui/frontend/mpweaponmenu.lua",                  false},
        {"operators",   "MPOperatorMenu",     "ui/frontend/mpoperatormenu.lua",                false},
        {"barracks",    "MPBarracksMenu",     "ui/frontend/mpbarracksmenu.lua",                false},
        {"store",       "MPStoreMenu",        "ui/frontend/mpstoremenu.lua",                   false},
        {"battlepass",  "BattlePassMenu",     "ui/frontend/battlepassmenu.lua",                false},
        {"combatrecord", "CombatRecord",      "ui/frontend/combatrecord.lua",                  false},
        {"leaderboard", "LeaderboardMenu",    "ui/frontend/mp/leaderboardmenu.lua",            false},
        {"tournament",  "ArenaTournament",    "ui/frontend/mp/arenatournament.lua",            false},
        {"trials",      "TrialsMP",           "ui/frontend/mp/trialsmp.lua",                   false},
        {"br",          "BRMainMenu",         "ui/frontend/mp/brmainmenu.lua",                 false},
        {"warzone",     "WZMainMenu",         "ui/frontend/wzmainmenu.lua",                    false},
        {"coop",        "CPMainMenu",         "ui/frontend/cp/cpmainmenu.lua",                 false},
        {"social",      "SocialMenu",         "ui/widgets/socialmenu.lua",                     false},
        {"options",     "OptionsMenu",        "ui/widgets/optionsmenu.lua",                    false},
        {"account",     "CODAccountSettings", "ui/frontend/codaccountsettings.lua",            false},
        {"challenges",  "ChallengeMenu",      "ui/frontend/challengemenu.lua",                 false},
        {"clan",        "ClanMembersScreen",  "ui/frontend/clanmembersscreen.lua",             false},
        {"regiments",   "ManageRegimentMenu", "ui/frontend/manageregimentmenu.lua",            false},
    };

    const Build373RetailMenuRoute* Build373MenuRouteFromId(WPARAM id) noexcept
    {
        const unsigned routeId = static_cast<unsigned>(id);
        if (routeId < 1 || routeId > CountOf(g_build373RetailMenuRoutes))
            return nullptr;
        return &g_build373RetailMenuRoutes[routeId - 1];
    }

    const Build373RetailMenuRoute* Build373FindMenuRoute(const char* alias) noexcept
    {
        if (!alias || !*alias)
            return nullptr;
        for (const auto& route : g_build373RetailMenuRoutes)
        {
            if (_stricmp(route.alias, alias) == 0)
                return &route;
        }
        return nullptr;
    }

    WPARAM Build373MenuRouteId(const Build373RetailMenuRoute* route) noexcept
    {
        if (!route)
            return 0;
        return static_cast<WPARAM>((route - g_build373RetailMenuRoutes) + 1);
    }

    LRESULT CALLBACK Build357GameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) noexcept
    {
        V100TraceWindowMessage(msg, wParam, lParam);
        if (msg == kBuild169ExecMessage)
        {
            char command[sizeof(g_build169ExecText)]{};
            if (InterlockedCompareExchange(&g_build169ExecPending, 1, 1) == 1)
            {
                strncpy_s(command, g_build169ExecText, _TRUNCATE);
                InterlockedExchange(&g_build169ExecPending, 0);
            }

            if (!command[0])
                return 0;

            Signature* luaVmSig = FindSignature("LUI_luaVM");
            void* luaVm = nullptr;
            if (luaVmSig && luaVmSig->address)
            {
                __try { luaVm = *reinterpret_cast<void**>(luaVmSig->address); }
                __except (EXCEPTION_EXECUTE_HANDLER) { luaVm = nullptr; }
            }

            if (!luaVm)
            {
                mw2019_diag::Log("[CMD] '%s' not run: Lua/ExecNow is not ready yet\r\n", command);
                return 0;
            }

            const bool ok = Build372ExecNow(luaVm, command);
            mw2019_diag::Log("[CMD] exec %s: %s\r\n", ok ? "OK" : "FAILED", command);
            return 0;
        }

        if (msg == kBuild357MenuMessage)
        {
            char rawMenuName[128]{};
            const Build373RetailMenuRoute* route = nullptr;
            const char* menuName = nullptr;
            bool bootstrapSystemLink = false;

            if (wParam == kBuild373RawMenuRoute)
            {
                if (InterlockedCompareExchange(&g_build373RawMenuPending, 1, 1) == 1)
                {
                    strncpy_s(rawMenuName, g_build373RawMenu, _TRUNCATE);
                    InterlockedExchange(&g_build373RawMenuPending, 0);
                    menuName = rawMenuName;
                }
            }
            else
            {
                route = Build373MenuRouteFromId(wParam);
                if (route)
                {
                    menuName = route->menuName;
                    bootstrapSystemLink = route->bootstrapSystemLink;
                }
            }

            Signature* openSig = FindSignature("LUI_OpenMenu");
            void* luaVm = nullptr;
            Signature* luaVmSig = FindSignature("LUI_luaVM");
            if (luaVmSig && luaVmSig->address)
            {
                __try { luaVm = *reinterpret_cast<void**>(luaVmSig->address); }
                __except (EXCEPTION_EXECUTE_HANDLER) { luaVm = nullptr; }
            }

            if (!menuName || !*menuName || !openSig || !openSig->address || !luaVm)
            {
                mw2019_diag::Log("[MENU] %s not ready (LUI unresolved)\r\n",
                    (menuName && *menuName) ? menuName : "<invalid>");
                return 0;
            }

            if (bootstrapSystemLink)
            {
                Build372BootstrapSystemLink(luaVm);
                Sleep(50);
            }

            // If the passive LUI trace hook is active, call its trampoline so this
            // does not recursively re-enter our trace hook. Build348 proved these
            // arguments are sufficient to open MainMenuOffline on this Retail build.
            auto openFn = reinterpret_cast<LUIOpenMenuFn>(openSig->address);

            __try
            {
                openFn(0, menuName, 0, 0, 1);
                mw2019_diag::Log("[MENU] %s call returned\r\n", menuName);
                if (iw8_144::IsExactBuild(GetModuleHandleW(nullptr)))
                    V100Snapshot("menu-call-returned");
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                mw2019_diag::Log("[MENU] %s fault code=0x%08lX\r\n", menuName, GetExceptionCode());
            }
            return 0;
        }

        if (msg == WM_NCDESTROY && hwnd == g_gameWindow)
        {
            WNDPROC original = g_originalGameWndProc;
            const LRESULT result = original
                ? CallWindowProcW(original, hwnd, msg, wParam, lParam)
                : DefWindowProcW(hwnd, msg, wParam, lParam);
            g_gameWindow = nullptr;
            g_originalGameWndProc = nullptr;
            return result;
        }

        return g_originalGameWndProc
            ? CallWindowProcW(g_originalGameWndProc, hwnd, msg, wParam, lParam)
            : DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    BOOL CALLBACK Build357FindGameWindow(HWND hwnd, LPARAM) noexcept
    {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != GetCurrentProcessId())
            return TRUE;
        if (!IsWindow(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr || !IsWindowVisible(hwnd))
            return TRUE;
        RECT rc{};
        if (!GetClientRect(hwnd, &rc))
            return TRUE;
        const unsigned long long width = rc.right > rc.left
            ? static_cast<unsigned long long>(rc.right - rc.left) : 0ull;
        const unsigned long long height = rc.bottom > rc.top
            ? static_cast<unsigned long long>(rc.bottom - rc.top) : 0ull;
        const unsigned long long area = width * height;
        if (area > g_build374WindowCandidateArea)
        {
            g_build374WindowCandidateArea = area;
            g_build374WindowCandidate = hwnd;
        }
        return TRUE;
    }

    bool Build373PureServerEmu144() noexcept
    {
        return iw8_144::IsExactBuild(GetModuleHandleW(nullptr)) && iw8_144::IsPureServerEmulationMode();
    }

    void V99Append(const char* format, ...) noexcept
    {
        // V101: no dedicated trace files. V99 diagnostics are emitted by their
        // existing mw2019_diag::Log calls directly to the CMD console.
        (void)format;
    }

    void V100Append(const char* format, ...) noexcept
    {
        // V101: frontend tracing is console-only. No v100/v101 trace files are
        // created; callers that matter now emit directly through Log().
        (void)format;
    }


    bool V100ReadableProtect(DWORD protect) noexcept
    {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS))
            return false;
        const DWORD p = protect & 0xFFu;
        return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
               p == PAGE_EXECUTE_WRITECOPY;
    }

    bool V100ReadFrontendState(void*& vmOut, int& frontendOut) noexcept
    {
        vmOut = nullptr;
        frontendOut = -1;
        Signature* vmSig = FindSignature("LUI_luaVM");
        Signature* frontendSig = FindSignature("s_luaInFrontend");
        if (vmSig && vmSig->address)
        {
            SIZE_T got = 0;
            ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(vmSig->address),
                &vmOut, sizeof(vmOut), &got);
            if (got != sizeof(vmOut)) vmOut = nullptr;
        }
        if (frontendSig && frontendSig->address)
        {
            unsigned char value = 0;
            SIZE_T got = 0;
            if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(frontendSig->address),
                    &value, sizeof(value), &got) && got == sizeof(value))
                frontendOut = value ? 1 : 0;
        }
        return vmOut != nullptr || frontendOut >= 0;
    }

    bool V100MarkerStillPresent(const V100UiMarkerAddress& marker) noexcept
    {
        static const char kText[] = "Connecting to Online Services";
        if (!marker.address)
            return false;
        if (!marker.utf16)
        {
            char bytes[sizeof(kText)]{};
            SIZE_T got = 0;
            return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(marker.address),
                       bytes, sizeof(kText) - 1, &got) &&
                   got == sizeof(kText) - 1 &&
                   memcmp(bytes, kText, sizeof(kText) - 1) == 0;
        }

        wchar_t wide[CountOf(kText)]{};
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(marker.address),
                wide, (sizeof(kText) - 1) * sizeof(wchar_t), &got) ||
            got != (sizeof(kText) - 1) * sizeof(wchar_t))
            return false;
        for (std::size_t i = 0; i < sizeof(kText) - 1; ++i)
        {
            if (wide[i] != static_cast<wchar_t>(static_cast<unsigned char>(kText[i])))
                return false;
        }
        return true;
    }

    void V100AddMarker(std::uintptr_t address, bool utf16, bool imageBacked) noexcept
    {
        if (!address || g_v100ConnectingMarkerCount >= CountOf(g_v100ConnectingMarkers))
            return;
        for (unsigned i = 0; i < g_v100ConnectingMarkerCount; ++i)
        {
            if (g_v100ConnectingMarkers[i].address == address &&
                g_v100ConnectingMarkers[i].utf16 == utf16)
                return;
        }
        g_v100ConnectingMarkers[g_v100ConnectingMarkerCount++] = {address, utf16, imageBacked};
    }

    void V100ScanRangeForConnecting(std::uintptr_t begin, std::uintptr_t end, bool imageBacked) noexcept
    {
        static const char kText[] = "Connecting to Online Services";
        if (!begin || end <= begin)
            return;
        constexpr std::size_t kPage = 0x1000;
        unsigned char bytes[kPage + 128]{};
        for (std::uintptr_t cursor = begin; cursor < end && g_v100ConnectingMarkerCount < CountOf(g_v100ConnectingMarkers); )
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) || !mbi.RegionSize)
                break;
            const auto regionBegin = (std::max)(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const auto regionEnd = (std::min)(end, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
            if (mbi.State == MEM_COMMIT && V100ReadableProtect(mbi.Protect) && regionEnd > regionBegin)
            {
                for (std::uintptr_t at = regionBegin; at < regionEnd; )
                {
                    const std::size_t n = static_cast<std::size_t>((std::min)(regionEnd - at, static_cast<std::uintptr_t>(kPage)));
                    SIZE_T got = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(at), bytes, n, &got) && got)
                    {
                        for (std::size_t i = 0; i + sizeof(kText) - 1 <= got; ++i)
                        {
                            if (memcmp(bytes + i, kText, sizeof(kText) - 1) == 0)
                                V100AddMarker(at + i, false, imageBacked);
                        }
                        for (std::size_t i = 0; i + (sizeof(kText) - 1) * 2 <= got; ++i)
                        {
                            bool match = true;
                            for (std::size_t j = 0; j < sizeof(kText) - 1; ++j)
                            {
                                if (bytes[i + j * 2] != static_cast<unsigned char>(kText[j]) || bytes[i + j * 2 + 1] != 0)
                                { match = false; break; }
                            }
                            if (match)
                                V100AddMarker(at + i, true, imageBacked);
                        }
                    }
                    at += n ? n : kPage;
                }
            }
            const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= cursor) break;
            cursor = next;
        }
    }

    void V100LocateConnectingMarkers() noexcept
    {
        g_v100ConnectingMarkerCount = 0;
        const auto started = GetTickCount64();
        std::uintptr_t imageBase = 0, imageEnd = 0;
        if (GetMainImageRange(imageBase, imageEnd))
        {
            // Scan only PE data sections for the literal.  Do not sweep the full
            // 500+ MiB image or all process heaps during a live frontend test.
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(imageBase);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(imageBase + dos->e_lfanew);
            const auto* sections = IMAGE_FIRST_SECTION(nt);
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            {
                char name[9]{};
                memcpy(name, sections[i].Name, 8);
                if (_stricmp(name, ".rdata") != 0 && _stricmp(name, ".data") != 0)
                    continue;
                const auto begin = imageBase + sections[i].VirtualAddress;
                const auto size = (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
                V100ScanRangeForConnecting(begin, begin + size, true);
            }
        }

        void* vm = nullptr;
        int frontend = -1;
        V100ReadFrontendState(vm, frontend);
        if (vm)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(vm, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT && V100ReadableProtect(mbi.Protect))
            {
                std::size_t size = mbi.RegionSize;
                if (size > 32ull * 1024ull * 1024ull)
                    size = 32ull * 1024ull * 1024ull;
                V100ScanRangeForConnecting(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress),
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + size, false);
            }
        }

        const auto elapsed = GetTickCount64() - started;
        mw2019_diag::Log("[V100-FRONT] marker scan complete hits=%u elapsedMs=%llu frontend=%d vm=%p\r\n",
            g_v100ConnectingMarkerCount, static_cast<unsigned long long>(elapsed), frontend, vm);
        V100Append("[V100-FRONT] MARKER_SCAN hits=%u elapsedMs=%llu frontend=%d vm=%p\r\n",
            g_v100ConnectingMarkerCount, static_cast<unsigned long long>(elapsed), frontend, vm);
        for (unsigned i = 0; i < g_v100ConnectingMarkerCount; ++i)
        {
            std::uintptr_t base = 0, end = 0;
            GetMainImageRange(base, end);
            const auto rva = (base && g_v100ConnectingMarkers[i].address >= base && g_v100ConnectingMarkers[i].address < end)
                ? g_v100ConnectingMarkers[i].address - base : 0;
            V100Append("[V100-FRONT] MARKER index=%u addr=%p rva=%s0x%llX encoding=%s imageBacked=%s\r\n",
                i, reinterpret_cast<void*>(g_v100ConnectingMarkers[i].address), rva ? "" : "n/a-",
                static_cast<unsigned long long>(rva), g_v100ConnectingMarkers[i].utf16 ? "UTF16" : "ASCII",
                g_v100ConnectingMarkers[i].imageBacked ? "yes" : "no");
        }
    }

    int V100CountLiveConnectingMarkers() noexcept
    {
        int live = 0;
        for (unsigned i = 0; i < g_v100ConnectingMarkerCount; ++i)
            live += V100MarkerStillPresent(g_v100ConnectingMarkers[i]) ? 1 : 0;
        return live;
    }

    void V100Snapshot(const char* reason) noexcept
    {
        void* vm = nullptr;
        int frontend = -1;
        V100ReadFrontendState(vm, frontend);
        const int liveMarkers = V100CountLiveConnectingMarkers();
        HWND foreground = GetForegroundWindow();
        HWND focus = GetFocus();
        HWND active = GetActiveWindow();
        HWND capture = GetCapture();
        const auto now = GetTickCount64();
        const DWORD threadId = GetCurrentThreadId();
        mw2019_diag::Log(
            "[V101-FRONT] SNAP reason=%s t=%llums tid=%lu vm=%p frontend=%d foreground=%p focus=%p active=%p capture=%p gameWindow=%p broadConnectingStringScan=OFF\r\n",
            reason ? reason : "snapshot", static_cast<unsigned long long>(now), static_cast<unsigned long>(threadId),
            vm, frontend, foreground, focus, active, capture, g_gameWindow);
    }

    void V100PrintFrontendStatus(const char* reason) noexcept
    {
        // V101 deliberately avoids the old 2s heap marker scan. The useful
        // frontend/Lua state is sampled directly from already-seeded exact RVAs.
        V100Snapshot(reason ? reason : "frontstatus");
    }

    void V100ArmFrontendTrace(unsigned seconds) noexcept
    {
        if (seconds < 5) seconds = 5;
        if (seconds > 300) seconds = 300;
        // V101: never run the old broad Connecting-string scan here. It took
        // ~2 seconds in V100 and can itself perturb startup timing.
        InstallBuild357GameWindowDispatch();
        const auto now = GetTickCount64();
        g_v100FrontendTraceDeadlineMs = now + static_cast<unsigned long long>(seconds) * 1000ull;
        g_v100FrontendTraceNextSampleMs = now;
        g_v100FrontendTraceLastHeartbeatMs = 0;
        g_v100LastFrontend = -999;
        g_v100LastMarkerLive = -999;
        g_v100LastForeground = nullptr;
        g_v100LastFocus = nullptr;
        g_v100LastActive = nullptr;
        g_v100LastCapture = nullptr;
        InterlockedExchange(&g_v100FrontendTraceArmed, 1);
        mw2019_diag::Log("[V101-FRONT] armed %us CMD_ONLY broadMarkerScan=OFF stateWrites=off menuForcing=off\r\n", seconds);
        V100Snapshot("arm");
    }


    void V100StopFrontendTrace(const char* reason) noexcept
    {
        if (InterlockedExchange(&g_v100FrontendTraceArmed, 0) != 0)
        {
            mw2019_diag::Log("[V101-FRONT] stopped%s%s t=%llums\r\n", reason && *reason ? ": " : "", reason && *reason ? reason : "",
                static_cast<unsigned long long>(GetTickCount64()));
        }
        g_v100FrontendTraceDeadlineMs = 0;
    }

    const char* V100WindowMessageName(UINT msg) noexcept
    {
        switch (msg)
        {
        case WM_SETFOCUS: return "WM_SETFOCUS";
        case WM_KILLFOCUS: return "WM_KILLFOCUS";
        case WM_ACTIVATE: return "WM_ACTIVATE";
        case WM_ACTIVATEAPP: return "WM_ACTIVATEAPP";
        case WM_LBUTTONDOWN: return "WM_LBUTTONDOWN";
        case WM_LBUTTONUP: return "WM_LBUTTONUP";
        case WM_KEYDOWN: return "WM_KEYDOWN";
        case WM_KEYUP: return "WM_KEYUP";
        default: return nullptr;
        }
    }

    void V100TraceWindowMessage(UINT msg, WPARAM wParam, LPARAM lParam) noexcept
    {
        if (InterlockedCompareExchange(&g_v100FrontendTraceArmed, 0, 0) == 0)
            return;
        const char* name = V100WindowMessageName(msg);
        if (!name)
            return;
        if ((msg == WM_KEYDOWN || msg == WM_KEYUP) && wParam != VK_ESCAPE && wParam != VK_RETURN && wParam != VK_SPACE)
            return;
        mw2019_diag::Log("[V101-INPUT] t=%llu tid=%lu msg=%s wParam=0x%llX lParam=0x%llX foreground=%p focus=%p active=%p\r\n",
            static_cast<unsigned long long>(GetTickCount64()), static_cast<unsigned long>(GetCurrentThreadId()), name,
            static_cast<unsigned long long>(wParam), static_cast<unsigned long long>(lParam),
            GetForegroundWindow(), GetFocus(), GetActiveWindow());
    }

    void V100ScheduleManualMenuSnapshots(const char* menuName) noexcept
    {
        strncpy_s(g_v100ManualSnapshotMenu, menuName && *menuName ? menuName : "<unknown>", _TRUNCATE);
        g_v100ManualSnapshotStartMs = GetTickCount64();
        g_v100ManualSnapshotMask = 0;
        V100Snapshot("menu-before-dispatch");
    }

    void V100FrontendTraceTick(unsigned long long) noexcept
    {
        const auto now = GetTickCount64();
        if (g_v100ManualSnapshotStartMs)
        {
            static const unsigned offsets[] = {16, 80, 250, 1000, 3000};
            for (unsigned i = 0; i < CountOf(offsets); ++i)
            {
                const unsigned bit = 1u << i;
                if ((g_v100ManualSnapshotMask & bit) || now < g_v100ManualSnapshotStartMs + offsets[i])
                    continue;
                g_v100ManualSnapshotMask |= bit;
                char reason[128]{};
                _snprintf_s(reason, CountOf(reason), _TRUNCATE, "menu-%s-plus-%ums", g_v100ManualSnapshotMenu, offsets[i]);
                V100Snapshot(reason);
            }
            if (g_v100ManualSnapshotMask == ((1u << CountOf(offsets)) - 1u))
                g_v100ManualSnapshotStartMs = 0;
        }

        if (InterlockedCompareExchange(&g_v100FrontendTraceArmed, 0, 0) == 0)
            return;
        if (g_v100FrontendTraceDeadlineMs && now >= g_v100FrontendTraceDeadlineMs)
        {
            V100StopFrontendTrace("window complete");
            return;
        }
        if (now < g_v100FrontendTraceNextSampleMs)
            return;
        g_v100FrontendTraceNextSampleMs = now + 100ull;

        void* vm = nullptr;
        int frontend = -1;
        V100ReadFrontendState(vm, frontend);
        const int liveMarkers = V100CountLiveConnectingMarkers();
        HWND foreground = GetForegroundWindow();
        HWND focus = GetFocus();
        HWND active = GetActiveWindow();
        HWND capture = GetCapture();
        const bool changed = frontend != g_v100LastFrontend || liveMarkers != g_v100LastMarkerLive ||
            foreground != g_v100LastForeground || focus != g_v100LastFocus || active != g_v100LastActive || capture != g_v100LastCapture;
        const bool heartbeat = !g_v100FrontendTraceLastHeartbeatMs || now - g_v100FrontendTraceLastHeartbeatMs >= 2000ull;
        if (changed || heartbeat)
        {
            mw2019_diag::Log("[V101-FRONT] SAMPLE t=%llu changed=%s vm=%p frontend=%d foreground=%p focus=%p active=%p capture=%p gameWindow=%p\r\n",
                static_cast<unsigned long long>(now), changed ? "YES" : "no", vm, frontend,
                foreground, focus, active, capture, g_gameWindow);
            g_v100FrontendTraceLastHeartbeatMs = now;
            g_v100LastFrontend = frontend;
            g_v100LastMarkerLive = liveMarkers;
            g_v100LastForeground = foreground;
            g_v100LastFocus = focus;
            g_v100LastActive = active;
            g_v100LastCapture = capture;
        }
    }

    bool V100RipRefTarget(std::uintptr_t at, std::uintptr_t& targetOut, std::size_t& lengthOut) noexcept
    {
        targetOut = 0;
        lengthOut = 0;
        unsigned char b[8]{};
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(at), b, sizeof(b), &got) || got < 7)
            return false;
        if ((b[0] == 0x48 || b[0] == 0x4C) && (b[1] == 0x8D || b[1] == 0x8B || b[1] == 0x3B) && (b[2] & 0xC7) == 0x05)
        {
            std::int32_t rel = 0;
            memcpy(&rel, b + 3, sizeof(rel));
            lengthOut = 7;
            targetOut = at + 7 + rel;
            return true;
        }
        return false;
    }

    void V100ConnectingXrefScan() noexcept
    {
        // V100 proved the visible text is runtime/Lua heap data, not an
        // image-backed literal. Re-running that broad scan costs ~2 seconds and
        // perturbs the exact startup timing we are trying to measure.
        mw2019_diag::Log("[V110-XREF] Connecting literal scan disabled: runtime/Lua-only text. V110 read-only SessionService completion branch trace is active; V109 broad owner ancestry is disabled.\r\n");
    }


    void V99PrintMenuStatus() noexcept
    {
        mw2019_scanner::ScanNow("V99 menu status");
        Signature* vmSig = FindSignature("LUI_luaVM");
        Signature* frontendSig = FindSignature("s_luaInFrontend");
        Signature* openSig = FindSignature("LUI_OpenMenu");
        void* vm = nullptr;
        int frontend = -1;
        if (vmSig && vmSig->address)
        {
            __try { vm = *reinterpret_cast<void**>(vmSig->address); }
            __except (EXCEPTION_EXECUTE_HANDLER) { vm = nullptr; }
        }
        if (frontendSig && frontendSig->address)
        {
            __try { frontend = *reinterpret_cast<const unsigned char*>(frontendSig->address) ? 1 : 0; }
            __except (EXCEPTION_EXECUTE_HANDLER) { frontend = -1; }
        }
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const auto openRva = (base && openSig && openSig->address >= base) ? openSig->address - base : 0;
        mw2019_diag::Log(
            "[V99-STATUS] luaVm=%p inFrontend=%d LUI_OpenMenu=%p rva=0x%llX traceArmed=%s events=%ld normalStateForcing=OFF\r\n",
            vm, frontend, openSig ? reinterpret_cast<void*>(openSig->address) : nullptr,
            static_cast<unsigned long long>(openRva),
            InterlockedCompareExchange(&g_transitionTraceArmed, 0, 0) ? "YES" : "no",
            InterlockedCompareExchange(&g_luiOpenTraceCount, 0, 0));
        V99Append(
            "[V99-STATUS] luaVm=%p inFrontend=%d LUI_OpenMenu=%p rva=0x%llX traceArmed=%s events=%ld normalStateForcing=OFF\r\n",
            vm, frontend, openSig ? reinterpret_cast<void*>(openSig->address) : nullptr,
            static_cast<unsigned long long>(openRva),
            InterlockedCompareExchange(&g_transitionTraceArmed, 0, 0) ? "YES" : "no",
            InterlockedCompareExchange(&g_luiOpenTraceCount, 0, 0));
        if (iw8_144::IsExactBuild(GetModuleHandleW(nullptr)))
            iw8_144::PrintStatus();
    }

    bool V992ExplicitManualOpenAlias(const Build373RetailMenuRoute* route) noexcept
    {
        if (!route || !route->menuName || !*route->menuName)
            return false;

        // V99.2 TEST-ONLY escape hatch. The previous V99 command accidentally
        // routed through QueueFrontendMenu(), which correctly refuses forcing in
        // PURE EMULATION mode. An explicit /menuopen command must be different:
        // marshal the known alias to the already-existing game-window dispatcher
        // and invoke the stock LUI_OpenMenu entry only because the user requested
        // this test. Nothing in normal runtime calls this helper.
        const WPARAM id = Build373MenuRouteId(route);
        if (!id)
            return false;

        V100ScheduleManualMenuSnapshots(route->menuName);
        mw2019_diag::Log(
            "[V99.2-MENU] EXPLICIT TEST dispatch alias=%s menu=%s routeId=%llu normalRuntimeMenuForcing=OFF\r\n",
            route->alias, route->menuName, static_cast<unsigned long long>(id));
        V99Append(
            "[V99.2-MENU] EXPLICIT_TEST dispatch alias=%s menu=%s routeId=%llu normalRuntimeMenuForcing=OFF\r\n",
            route->alias, route->menuName, static_cast<unsigned long long>(id));

        if (!Build374PostMenuMessage(id))
        {
            mw2019_diag::Log("[V99.2-MENU] dispatcher not ready; explicit test was NOT sent\r\n");
            V99Append("[V99.2-MENU] EXPLICIT_TEST dispatch_failed alias=%s\r\n", route->alias);
            return false;
        }

        mw2019_diag::Log("[V99.2-MENU] explicit test posted to game window thread; watch for [V99-MENU][TRACE] and [MENU] call returned/fault\r\n");
        V99Append("[V99.2-MENU] EXPLICIT_TEST posted alias=%s\r\n", route->alias);
        return true;
    }

    void Build373PrintMenuHelp() noexcept
    {
        if (Build373PureServerEmu144())
        {
            mw2019_diag::Log("[SERVER-EMU144] LOGIN EMULATION research console (normal runtime read-only; /source3 0|1 is an explicit manual test write)\r\n");
            mw2019_diag::Log("[AUTH] authscan             - rescan Battle.net/Demonware/UNO login strings + xrefs\r\n");
            mw2019_diag::Log("[AUTH] authstatus           - print pure-emulation + transport status\r\n");
            mw2019_diag::Log("[AUTH] offsets              - print only known login/auth correlation RVAs\r\n");
            mw2019_diag::Log("[TEST] source3              - print V97 Source3/task status (read-only)\r\n");
            mw2019_diag::Log("[TEST] source3 1            - TEST ONLY: call stock setter for controller 0 -> 1\r\n");
            mw2019_diag::Log("[TEST] source3 0            - restore controller 0 Source3 -> 0 after test\r\n");
            mw2019_diag::Log("[V99]  menustatus           - print Lua/frontend/menu target readiness\r\n");
            mw2019_diag::Log("[V99]  menuxrefs            - static 3-level reverse scan from LUI_OpenMenu\r\n");
            mw2019_diag::Log("[V99]  menutrace [label]    - hook LUI_OpenMenu for the next 20s and log callers\r\n");
            mw2019_diag::Log("[V99.2] menuopen <alias>     - TEST ONLY: explicitly dispatch a known stock frontend menu\r\n");
            mw2019_diag::Log("[V99.2] frontend [alias]     - TEST ONLY shorthand; default alias=main\r\n");
            mw2019_diag::Log("[V99]  aliases              - main offline mp play private public weapons operators store battlepass warzone br coop social options\r\n");
            mw2019_diag::Log("[V106] frontstatus          - snapshot frontend/Lua/window focus state (no broad marker scan)\r\n");
            mw2019_diag::Log("[V106] fronttrace [seconds] - restart/extend console-only frontend trace (AUTO-ARMED at startup)\r\n");
            mw2019_diag::Log("[V106] frontstop            - stop auto frontend trace\r\n");
            mw2019_diag::Log("[V106] connectxrefs         - legacy literal xref helper; runtime Lua text is not image-backed\r\n");
            mw2019_diag::Log("[NET]  netstatus | server <host>\r\n");
            mw2019_diag::Log("[INFO] automatic menu/frontend state forcing remains OFF; V99 menu opens occur only when you type the test command\r\n");
            return;
        }
        mw2019_diag::Log("[CMD] cmdscan                 - rescan and print registered game commands\r\n");
        mw2019_diag::Log("[CMD] commands                - list cached command names\r\n");
        mw2019_diag::Log("[CMD] cmdfind <text>          - filter cached command names\r\n");
        mw2019_diag::Log("[CMD] cmdrun <id> [args]      - execute a discovered command by number\r\n");
        mw2019_diag::Log("[CMD] exec <raw command>      - execute raw text through Engine.ExecNow\r\n");
        mw2019_diag::Log("[SCAN] offsetscan              - late/manual full IW8 offset scan\r\n");
        mw2019_diag::Log("[SCAN] offsets                 - print current exact/scanned address catalog\r\n");
        mw2019_diag::Log("[LUA] luascan                  - narrow late Lua/LUI frontend scan\r\n");
        mw2019_diag::Log("[LUA] luastatus                - print LUI VM/frontend readiness\r\n");
        mw2019_diag::Log("[DVAR] blades                  - reapply offline + online-blade selectors\r\n");
        mw2019_diag::Log("[HOOK] signin144               - arm only sign-in/status hooks\r\n");
        mw2019_diag::Log("[HOOK] content144              - arm only local content ownership hook\r\n");
        mw2019_diag::Log("[HOOK] lui144                  - arm only LUI frontend gate hooks\r\n");
        mw2019_diag::Log("[HOOK] patch144                - scan/arm optional patch/time hooks\r\n");
        mw2019_diag::Log("[HOOK] hooks144                - arm all late 1.44 groups\r\n");
        mw2019_diag::Log(
            "[MENU] aliases: revamped mp play private public weapons operators barracks playlists battlepass store "
            "warzone br coop tournament trials combatrecord leaderboard social lanbrowser browser systemlink\r\n");
        mw2019_diag::Log("[MENU] raw: menu raw <ExactLUIName>\r\n");
        mw2019_diag::Log("[NET] server <host> | netstatus\r\n");
    }

    void DetachBuild374GameWindowDispatch() noexcept
    {
        if (g_gameWindow && g_originalGameWndProc && IsWindow(g_gameWindow))
        {
            const auto current = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(g_gameWindow, GWLP_WNDPROC));
            if (current == &Build357GameWndProc)
                SetWindowLongPtrW(g_gameWindow, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(g_originalGameWndProc));
        }
        g_gameWindow = nullptr;
        g_originalGameWndProc = nullptr;
    }

    bool InstallBuild357GameWindowDispatch() noexcept
    {
        g_build374WindowCandidate = nullptr;
        g_build374WindowCandidateArea = 0;
        EnumWindows(&Build357FindGameWindow, 0);
        HWND target = g_build374WindowCandidate;
        if (!target)
        {
            if (g_gameWindow && IsWindow(g_gameWindow))
                target = g_gameWindow;
            else
                return false;
        }
        if (target == g_gameWindow && g_originalGameWndProc && IsWindow(target))
        {
            const auto current = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(target, GWLP_WNDPROC));
            if (current == &Build357GameWndProc)
                return true;
        }
        if (g_gameWindow && target != g_gameWindow)
            DetachBuild374GameWindowDispatch();
        g_gameWindow = target;
        SetLastError(0);
        const LONG_PTR old = SetWindowLongPtrW(g_gameWindow, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&Build357GameWndProc));
        if (!old)
        {
            const DWORD err = GetLastError();
            g_gameWindow = nullptr;
            g_originalGameWndProc = nullptr;
            if (err)
                mw2019_diag::Log("[MENU] window dispatcher error=%lu\r\n", err);
            return false;
        }
        g_originalGameWndProc = reinterpret_cast<WNDPROC>(old);
        return true;
    }

    bool Build374PostMenuMessage(WPARAM id) noexcept
    {
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            if (!InstallBuild357GameWindowDispatch())
                continue;
            if (PostMessageW(g_gameWindow, kBuild357MenuMessage, id, 0))
                return true;
            DetachBuild374GameWindowDispatch();
        }
        return false;
    }

    bool Build169QueueExec(const char* command) noexcept
    {
        if (!command || !*command)
            return false;

        if (InterlockedCompareExchange(&g_build169ExecPending, 1, 0) != 0)
        {
            mw2019_diag::Log("[CMD] previous game command is still pending\r\n");
            return false;
        }

        strncpy_s(g_build169ExecText, command, _TRUNCATE);
        if (!InstallBuild357GameWindowDispatch() ||
            !PostMessageW(g_gameWindow, kBuild169ExecMessage, 0, 0))
        {
            InterlockedExchange(&g_build169ExecPending, 0);
            mw2019_diag::Log("[CMD] game window/ExecNow dispatcher is not ready yet\r\n");
            return false;
        }

        mw2019_diag::Log("[CMD] queued: %s\r\n", command);
        return true;
    }

    bool Build373QueueRawMenu(const char* menuName) noexcept
    {
        if (!menuName || !*menuName)
            return false;

        // Exact 1.44: an arbitrary raw menu name previously caused the process to
        // disappear immediately after the request.  Keep raw names as discovery
        // input only; known aliases below are marshalled onto an existing LUI
        // callback thread before LUI_OpenMenu is called.
        if (iw8_144::IsExactBuild(GetModuleHandleW(nullptr)))
        {
            mw2019_diag::Log("[MENU144] raw direct-open disabled in safe profile: '%s'\r\n", menuName);
            mw2019_diag::Log("[MENU144] use 'menus' then a known alias (offline, mp, warzone, main, etc.)\r\n");
            return false;
        }

        if (InterlockedCompareExchange(&g_build373RawMenuPending, 1, 0) != 0)
        {
            mw2019_diag::Log("[MENU] previous raw request still pending\r\n");
            return false;
        }
        strncpy_s(g_build373RawMenu, menuName, _TRUNCATE);
        mw2019_diag::Log("[MENU] request raw -> %s\r\n", menuName);
        if (!Build374PostMenuMessage(kBuild373RawMenuRoute))
        {
            InterlockedExchange(&g_build373RawMenuPending, 0);
            mw2019_diag::Log("[MENU] dispatcher not ready; try again after READY\r\n");
            return false;
        }
        return true;
    }

    bool Build373QueueAlias(const char* alias) noexcept
    {
        const auto* route = Build373FindMenuRoute(alias);
        if (!route)
            return false;

        // Exact 1.44 normal-runtime path: preserve the pure-emulation guard.
        // This path is intentionally NOT allowed to force a menu while the stock
        // frontend state machine is still deciding what to do.
        if (iw8_144::IsExactBuild(GetModuleHandleW(nullptr)))
        {
            mw2019_diag::Log("[MENU144] request %s -> %s\r\n", alias, route->menuName);
            const bool queued = iw8_144::QueueFrontendMenu(route->menuName);
            if (!queued)
                mw2019_diag::Log("[MENU144] %s was not queued by the normal pure-emulation path\r\n", alias);
            return queued;
        }

        // Build379: transition tracing is automatic for the routes that can enter
        // the stock online-services gate. Manual trace commands remain available.
        if (_stricmp(alias, "mp") == 0 ||
            _stricmp(alias, "play") == 0 ||
            _stricmp(alias, "private") == 0 ||
            _stricmp(alias, "public") == 0 ||
            _stricmp(alias, "warzone") == 0 ||
            _stricmp(alias, "br") == 0)
        {
            char traceLabel[32]{};
            sprintf_s(traceLabel, "auto-%s", alias);
            Build378ArmTransitionTrace(traceLabel);
        }

        const WPARAM id = Build373MenuRouteId(route);
        mw2019_diag::Log("[MENU] request %s -> %s\r\n", alias, route->menuName);
        if (!Build374PostMenuMessage(id))
        {
            mw2019_diag::Log("[MENU] %s dispatcher not ready; try again after READY\r\n", alias);
            return true;
        }
        return true;
    }

    char* Build373TrimCommand(char* text) noexcept
    {
        if (!text) return text;
        while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') ++text;
        char* end = text + strlen(text);
        while (end > text && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
            *--end = '\0';
        return text;
    }

    void Build378StopTransitionTrace(const char* reason) noexcept
    {
        if (InterlockedExchange(&g_transitionTraceArmed, 0) != 0)
        {
            mw2019_diag::Log("[TRACE] stopped%s%s\r\n",
                (reason && *reason) ? ": " : "",
                (reason && *reason) ? reason : "");
        }
        g_transitionTraceDeadlineMs = 0;
        g_transitionTraceLabel[0] = '\0';
    }

    void Build378ArmTransitionTrace(const char* label) noexcept
    {
        if (!InstallLUIOpenMenuTraceHook())
        {
            mw2019_diag::Log("[TRACE] LUI_OpenMenu hook not ready; wait for READY and retry\r\n");
            return;
        }
        strncpy_s(g_transitionTraceLabel, (label && *label) ? label : "manual", _TRUNCATE);
        g_transitionTraceDeadlineMs = GetTickCount64() + 20000ull;
        InterlockedExchange(&g_luiOpenTraceCount, 0);
        InterlockedExchange(&g_transitionTraceArmed, 1);
        mw2019_diag::Log("[V99-TRACE] armed '%s' for 20s. Trigger the natural transition or use /menuopen <alias>.\r\n",
            g_transitionTraceLabel);
        V99Append("[V99-TRACE] armed label=%s deadlineMs=%llu normalStateForcing=OFF\r\n",
            g_transitionTraceLabel, static_cast<unsigned long long>(g_transitionTraceDeadlineMs));
    }

    void Build378TraceStatus() noexcept
    {
        const bool armed = InterlockedCompareExchange(&g_transitionTraceArmed, 0, 0) != 0;
        if (!armed)
        {
            mw2019_diag::Log("[TRACE] idle\r\n");
            return;
        }
        const auto now = GetTickCount64();
        const auto left = (g_transitionTraceDeadlineMs > now) ? (g_transitionTraceDeadlineMs - now) : 0ull;
        mw2019_diag::Log("[TRACE] armed '%s' remaining=%llums events=%ld\r\n",
            g_transitionTraceLabel[0] ? g_transitionTraceLabel : "manual",
            static_cast<unsigned long long>(left),
            InterlockedCompareExchange(&g_luiOpenTraceCount, 0, 0));
    }

    bool Build169WritableDataProtect(DWORD protect) noexcept
    {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS))
            return false;
        const DWORD p = protect & 0xFF;
        return p == PAGE_READWRITE || p == PAGE_WRITECOPY;
    }

    bool Build169ExecutableAddress(std::uintptr_t address) noexcept
    {
        if (!address) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        return VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT && IsExecutableProtect(mbi.Protect);
    }

    bool Build169CopyCommandName(
        std::uintptr_t address,
        std::uintptr_t imageBase,
        std::uintptr_t imageEnd,
        char* out,
        std::size_t outSize) noexcept
    {
        if (!out || outSize < 2 || address < imageBase || address >= imageEnd)
            return false;
        out[0] = '\0';

        __try
        {
            std::size_t i = 0;
            for (; i + 1 < outSize && i < 95; ++i)
            {
                const unsigned char c = *reinterpret_cast<const unsigned char*>(address + i);
                if (c == 0)
                {
                    if (i < 2)
                        return false;
                    out[i] = '\0';
                    return true;
                }

                const bool allowed =
                    (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '_' || c == '-' || c == '+' || c == '.' ||
                    c == '?' || c == '/' || c == '\\';
                if (!allowed)
                    return false;
                out[i] = static_cast<char>(c);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return false;
    }

    bool Build169ReadCommandNodeFields(
        std::uintptr_t address,
        std::uintptr_t* next,
        std::uintptr_t* namePtr,
        std::uintptr_t* callback) noexcept
    {
        if (!address || !next || !namePtr || !callback)
            return false;

        __try
        {
            const auto* q = reinterpret_cast<const std::uintptr_t*>(address);
            *next = q[0];
            *namePtr = q[1];
            *callback = q[4];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void Build169ScanCommandsInternal(bool verbose) noexcept
    {
        std::uintptr_t base = 0, end = 0;
        if (!GetMainImageRange(base, end))
        {
            if (verbose) mw2019_diag::Log("[CMD] main image is not ready\r\n");
            return;
        }

        std::vector<Build169DiscoveredCommand> found;
        found.reserve(256);

        std::uintptr_t cursor = base;
        while (cursor < end && found.size() < 1024)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) || !mbi.RegionSize)
                break;

            const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto regionEndRaw = regionBase + mbi.RegionSize;
            const auto scanStart = regionBase < base ? base : regionBase;
            const auto scanEnd = regionEndRaw > end ? end : regionEndRaw;

            if (mbi.State == MEM_COMMIT &&
                Build169WritableDataProtect(mbi.Protect) &&
                scanEnd > scanStart + 40)
            {
                const auto first = (scanStart + 7ull) & ~7ull;
                for (std::uintptr_t at = first; at + 40 <= scanEnd; at += 8)
                {
                    std::uintptr_t next = 0;
                    std::uintptr_t namePtr = 0;
                    std::uintptr_t callback = 0;
                    if (!Build169ReadCommandNodeFields(at, &next, &namePtr, &callback))
                        continue;

                    if (namePtr < base || namePtr >= end ||
                        callback < base || callback >= end ||
                        (next && (next < base || next >= end)))
                        continue;
                    if (!Build169ExecutableAddress(callback))
                        continue;

                    char name[96]{};
                    if (!Build169CopyCommandName(namePtr, base, end, name, sizeof(name)))
                        continue;

                    // Command registration nodes are linked records. Requiring a
                    // plausible next node (or null tail) removes most unrelated
                    // data structures that also contain a string + code pointer.
                    if (next)
                    {
                        MEMORY_BASIC_INFORMATION nextMbi{};
                        if (!VirtualQuery(reinterpret_cast<const void*>(next), &nextMbi, sizeof(nextMbi)) ||
                            nextMbi.State != MEM_COMMIT ||
                            !Build169WritableDataProtect(nextMbi.Protect))
                            continue;
                    }

                    const bool duplicate = std::any_of(
                        found.begin(), found.end(),
                        [at](const Build169DiscoveredCommand& item) { return item.node == at; });
                    if (duplicate)
                        continue;

                    Build169DiscoveredCommand item{};
                    strncpy_s(item.name, name, _TRUNCATE);
                    item.node = at;
                    item.callback = callback;
                    found.push_back(item);
                }
            }

            if (regionEndRaw <= cursor)
                break;
            cursor = regionEndRaw;
        }

        std::sort(
            found.begin(), found.end(),
            [](const Build169DiscoveredCommand& a, const Build169DiscoveredCommand& b)
            {
                const int byName = _stricmp(a.name, b.name);
                return byName == 0 ? a.node < b.node : byName < 0;
            });

        AcquireSRWLockExclusive(&g_build169CommandLock);
        Build169Commands() = found;
        ReleaseSRWLockExclusive(&g_build169CommandLock);

        const unsigned count = static_cast<unsigned>(found.size());
        if (verbose || count != g_build169LastAutoCommandCount)
        {
            g_build169LastAutoCommandCount = count;
            mw2019_diag::Log("[CMD] live Steam command scan found %u candidates\r\n", count);
        }

        if (verbose)
        {
            for (std::size_t i = 0; i < found.size(); ++i)
            {
                mw2019_diag::Log(
                    "[CMD] [%03zu] %-40s callback=%p node=%p\r\n",
                    i + 1,
                    found[i].name,
                    reinterpret_cast<void*>(found[i].callback),
                    reinterpret_cast<void*>(found[i].node));
            }
            if (found.empty())
                mw2019_diag::Log("[CMD] no command nodes are registered yet; run cmdscan again after the frontend appears\r\n");
        }
    }

    bool Build169ContainsNoCase(const char* text, const char* needle) noexcept
    {
        if (!needle || !*needle) return true;
        if (!text || !*text) return false;
        const std::size_t needleLen = strlen(needle);
        for (const char* p = text; *p; ++p)
        {
            if (_strnicmp(p, needle, needleLen) == 0)
                return true;
        }
        return false;
    }

    void Build169PrintCommands(const char* filter) noexcept
    {
        AcquireSRWLockShared(&g_build169CommandLock);
        const auto& commands = Build169Commands();
        unsigned shown = 0;
        for (std::size_t i = 0; i < commands.size(); ++i)
        {
            if (filter && *filter && !Build169ContainsNoCase(commands[i].name, filter))
                continue;
            mw2019_diag::Log("[CMD] [%03zu] %s\r\n", i + 1, commands[i].name);
            ++shown;
        }
        ReleaseSRWLockShared(&g_build169CommandLock);

        if (filter && *filter)
            mw2019_diag::Log("[CMD] listed %u command(s) matching '%s'\r\n", shown, filter);
        else
            mw2019_diag::Log("[CMD] listed %u command(s)\r\n", shown);
    }

    bool Build169CommandByIndex(unsigned oneBasedIndex, Build169DiscoveredCommand& out) noexcept
    {
        if (!oneBasedIndex)
            return false;
        bool ok = false;
        AcquireSRWLockShared(&g_build169CommandLock);
        const auto& commands = Build169Commands();
        const std::size_t index = static_cast<std::size_t>(oneBasedIndex - 1);
        if (index < commands.size())
        {
            out = commands[index];
            ok = true;
        }
        ReleaseSRWLockShared(&g_build169CommandLock);
        return ok;
    }

    DWORD WINAPI Build373MenuConsoleThread(LPVOID) noexcept
    {
        HANDLE input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (input == INVALID_HANDLE_VALUE)
        {
            mw2019_diag::Log("[ERROR] console input unavailable err=%lu\r\n", GetLastError());
            InterlockedExchange(&g_build373ConsoleThreadStarted, 0);
            return 0;
        }
        char buffer[512]{};
        for (;;)
        {
            DWORD read = 0;
            if (!ReadConsoleA(input, buffer, static_cast<DWORD>(sizeof(buffer) - 1), &read, nullptr)) break;
            if (!read) continue;
            buffer[read < sizeof(buffer) ? read : sizeof(buffer) - 1] = '\0';
            char* line = Build373TrimCommand(buffer);
            if (!line || !*line) continue;
            while (*line == '/') line = Build373TrimCommand(line + 1);

            if (_stricmp(line, "help") == 0 || _stricmp(line, "cmdhelp") == 0)
            {
                Build373PrintMenuHelp();
                continue;
            }
            if (Build373PureServerEmu144())
            {
                if (_stricmp(line, "authscan") == 0 || _stricmp(line, "scan") == 0)
                {
                    mw2019_diag::RunServerEmuAuthScan();
                    continue;
                }
                if (_stricmp(line, "authstatus") == 0 || _stricmp(line, "status") == 0)
                {
                    iw8_144::PrintStatus();
                    mw2019_diag::PrintServerEmuNetworkStatus();
                    continue;
                }
                if (_stricmp(line, "offsets") == 0 || _stricmp(line, "authoffsets") == 0)
                {
                    iw8_144::PrintOffsets();
                    continue;
                }
                if (_stricmp(line, "source3") == 0 || _stricmp(line, "source3status") == 0)
                {
                    mw2019_diag::PrintSource3TestStatus();
                    continue;
                }
                if (_strnicmp(line, "source3 ", 8) == 0 || _strnicmp(line, "source3test ", 12) == 0)
                {
                    char* valueText = Build373TrimCommand(line + (_strnicmp(line, "source3test ", 12) == 0 ? 12 : 8));
                    if (!valueText || (strcmp(valueText, "0") != 0 && strcmp(valueText, "1") != 0))
                    {
                        mw2019_diag::Log("[V97-TEST] usage: /source3 1 to force controller-0 Source3 to 1 for testing; /source3 0 to restore\r\n");
                    }
                    else
                    {
                        const unsigned value = static_cast<unsigned>(valueText[0] - '0');
                        const bool ok = mw2019_diag::SetSource3TestValue(value);
                        mw2019_diag::Log("[V97-TEST] /source3 %u -> %s (TEST ONLY; normal runtime state forcing remains OFF)\r\n",
                            value, ok ? "OK" : "FAILED");
                    }
                    continue;
                }
                if (_stricmp(line, "menustatus") == 0 || _stricmp(line, "v99status") == 0)
                {
                    V99PrintMenuStatus();
                    continue;
                }
                if (_stricmp(line, "frontstatus") == 0 || _stricmp(line, "v100status") == 0)
                {
                    V100PrintFrontendStatus("frontstatus");
                    continue;
                }
                if (_stricmp(line, "frontstop") == 0)
                {
                    V100StopFrontendTrace("console command");
                    continue;
                }
                if (_stricmp(line, "connectxrefs") == 0 || _stricmp(line, "connectingxrefs") == 0)
                {
                    V100ConnectingXrefScan();
                    continue;
                }
                if (_stricmp(line, "fronttrace") == 0 || _strnicmp(line, "fronttrace ", 11) == 0)
                {
                    unsigned seconds = 45;
                    if (_strnicmp(line, "fronttrace ", 11) == 0)
                    {
                        char* value = Build373TrimCommand(line + 11);
                        const int parsed = value ? atoi(value) : 0;
                        if (parsed > 0) seconds = static_cast<unsigned>(parsed);
                    }
                    V100ArmFrontendTrace(seconds);
                    continue;
                }
                if (_stricmp(line, "menuxrefs") == 0 || _stricmp(line, "menubacktrace") == 0 || _stricmp(line, "menugraph") == 0)
                {
                    mw2019_scanner::ScanNow("V99 menu reverse scan");
                    V99MenuBacktraceScan();
                    continue;
                }
                if (_strnicmp(line, "menutrace", 9) == 0)
                {
                    char* label = Build373TrimCommand(line + 9);
                    mw2019_scanner::ScanNow("V99 menu trace");
                    Build378ArmTransitionTrace((label && *label) ? label : "v99-menu");
                    V99Append("[V99-TRACE] armed label=%s windowMs=20000 normalStateForcing=OFF\r\n",
                        (label && *label) ? label : "v99-menu");
                    continue;
                }
                if (_stricmp(line, "aliases") == 0 || _stricmp(line, "menualiases") == 0 || _stricmp(line, "menuopen list") == 0)
                {
                    mw2019_diag::Log("[V99-MENU] aliases: main offline mp play private public weapons operators barracks playlists store battlepass warzone br coop social options account challenges clan regiments\r\n");
                    continue;
                }
                if (_strnicmp(line, "menuopen ", 9) == 0 || _strnicmp(line, "menutest ", 9) == 0)
                {
                    char* alias = Build373TrimCommand(line + 9);
                    const auto* route = Build373FindMenuRoute(alias);
                    if (!route)
                    {
                        mw2019_diag::Log("[V99-MENU] unknown alias '%s'; use /aliases\r\n", alias ? alias : "");
                        continue;
                    }
                    mw2019_scanner::ScanNow("V99 test menu open");
                    Build378ArmTransitionTrace("v99-menuopen");
                    mw2019_diag::Log("[V99-MENU] TEST ONLY request alias=%s menu=%s asset=%s normalRuntimeMenuForcing=OFF\r\n",
                        route->alias, route->menuName, route->luaAsset);
                    V99Append("[V99-MENU] TEST_ONLY request alias=%s menu=%s asset=%s normalRuntimeMenuForcing=OFF\r\n",
                        route->alias, route->menuName, route->luaAsset);
                    const bool queued = iw8_144::IsExactBuild(GetModuleHandleW(nullptr))
                        ? V992ExplicitManualOpenAlias(route)
                        : Build373QueueAlias(route->alias);
                    mw2019_diag::Log("[V99.2-MENU] TEST ONLY open alias=%s -> %s\r\n",
                        route->alias, queued ? "DISPATCHED" : "FAILED");
                    V99Append("[V99.2-MENU] TEST_ONLY open alias=%s result=%s\r\n",
                        route->alias, queued ? "DISPATCHED" : "FAILED");
                    continue;
                }
                if (_stricmp(line, "menuopen") == 0 || _stricmp(line, "menutest") == 0)
                {
                    mw2019_diag::Log("[V99-MENU] usage: /menuopen <alias>; use /aliases for known safe names\r\n");
                    continue;
                }
                if (_stricmp(line, "frontend") == 0 || _strnicmp(line, "frontend ", 9) == 0)
                {
                    char* alias = (_stricmp(line, "frontend") == 0) ? nullptr : Build373TrimCommand(line + 9);
                    if (!alias || !*alias) alias = const_cast<char*>("main");
                    const auto* route = Build373FindMenuRoute(alias);
                    if (!route)
                    {
                        mw2019_diag::Log("[V99-MENU] unknown frontend alias '%s'; use /aliases\r\n", alias);
                        continue;
                    }
                    mw2019_scanner::ScanNow("V99 frontend test open");
                    Build378ArmTransitionTrace("v99-frontend-test");
                    mw2019_diag::Log("[V99-MENU] TEST ONLY /frontend alias=%s -> %s normalRuntimeMenuForcing=OFF\r\n",
                        route->alias, route->menuName);
                    V99Append("[V99-MENU] TEST_ONLY frontend alias=%s menu=%s\r\n", route->alias, route->menuName);
                    const bool dispatched = iw8_144::IsExactBuild(GetModuleHandleW(nullptr))
                        ? V992ExplicitManualOpenAlias(route)
                        : Build373QueueAlias(route->alias);
                    mw2019_diag::Log("[V99.2-MENU] /frontend alias=%s -> %s\r\n",
                        route->alias, dispatched ? "DISPATCHED" : "FAILED");
                    continue;
                }
                if (_stricmp(line, "netstatus") == 0)
                {
                    char host[256]{};
                    mw2019_network::GetCustomServer(host, CountOf(host));
                    mw2019_diag::Log("[NET] mode=Revamped server-emulation server=%s\r\n",
                        host[0] ? host : "127.0.0.1");
                    mw2019_diag::PrintServerEmuNetworkStatus();
                    continue;
                }
                if (_strnicmp(line, "server ", 7) == 0)
                {
                    char* host = Build373TrimCommand(line + 7);
                    if (!host || !*host)
                        mw2019_diag::Log("[NET] usage: server <hostname-or-ip>\r\n");
                    else
                    {
                        mw2019_network::SetCustomServer(host);
                        mw2019_diag::Log("[NET] Revamped server set to %s\r\n", host);
                    }
                    continue;
                }

                mw2019_diag::Log("[CMD] login-emulation mode: unknown command '%s'. Type help.\r\n", line);
                continue;
            }
            if (_stricmp(line, "offsetscan") == 0 || _stricmp(line, "scanoffsets") == 0)
            {
                mw2019_scanner::ScanAllNow("manual offset scan");
                mw2019_scanner::PrintAddresses();
                continue;
            }
            if (_stricmp(line, "luascan") == 0 || _stricmp(line, "scanlua") == 0)
            {
                mw2019_scanner::ScanNow("manual Lua/frontend scan");
                const auto vmGlobal = mw2019_scanner::GetAddress("LUI_luaVM");
                const auto frontend = mw2019_scanner::GetAddress("s_luaInFrontend");
                const auto openMenu = mw2019_scanner::GetAddress("LUI_OpenMenu");
                void* vm = nullptr;
                int inFrontend = -1;
                __try
                {
                    if (vmGlobal) vm = *reinterpret_cast<void**>(vmGlobal);
                    if (frontend) inFrontend = *reinterpret_cast<unsigned char*>(frontend) ? 1 : 0;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    vm = nullptr;
                    inFrontend = -1;
                }
                mw2019_diag::Log("[LUA] vmGlobal=%p vm=%p s_luaInFrontend=%p state=%d LUI_OpenMenu=%p\r\n",
                    reinterpret_cast<void*>(vmGlobal), vm, reinterpret_cast<void*>(frontend), inFrontend,
                    reinterpret_cast<void*>(openMenu));
                continue;
            }
            if (_stricmp(line, "luastatus") == 0 || _stricmp(line, "lua") == 0)
            {
                const auto vmGlobal = mw2019_scanner::GetAddress("LUI_luaVM");
                const auto frontend = mw2019_scanner::GetAddress("s_luaInFrontend");
                const auto openMenu = mw2019_scanner::GetAddress("LUI_OpenMenu");
                void* vm = nullptr;
                int inFrontend = -1;
                __try
                {
                    if (vmGlobal) vm = *reinterpret_cast<void**>(vmGlobal);
                    if (frontend) inFrontend = *reinterpret_cast<unsigned char*>(frontend) ? 1 : 0;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    vm = nullptr;
                    inFrontend = -1;
                }
                mw2019_diag::Log("[LUA] vmGlobal=%p vm=%p s_luaInFrontend=%p state=%d LUI_OpenMenu=%p\r\n",
                    reinterpret_cast<void*>(vmGlobal), vm, reinterpret_cast<void*>(frontend), inFrontend,
                    reinterpret_cast<void*>(openMenu));
                if (iw8_144::IsExactBuild(GetModuleHandleW(nullptr)))
                    iw8_144::PrintStatus();
                continue;
            }
            if (_stricmp(line, "offsets") == 0 || _stricmp(line, "addrs") == 0)
            {
                mw2019_scanner::PrintAddresses();
                continue;
            }
            if (_stricmp(line, "blades") == 0 || _stricmp(line, "dvarscan") == 0)
            {
                if (Build373PureServerEmu144())
                {
                    mw2019_diag::Log("[SERVER-EMU144] blocked: dvar/blade writes are disabled in PURE EMULATION mode\r\n");
                    continue;
                }
                if (iw8_144::IsExactBuild(GetModuleHandleW(nullptr)))
                {
                    // On exact 1.44 never call Dvar_FindVarByName from this
                    // console/helper thread. Queue the selector pass through the
                    // already-installed LUI gate detours so lookups execute on a game-owned UI thread.
                    iw8_144::RequestFrontendSelectorPass();
                }
                else
                {
                    mw2019_scanner::ScanNow("manual blade selector pass");
                    (void)mw2019_scanner::ApplyFrontendBladeSelectors(true);
                }
                continue;
            }
            if (_stricmp(line, "signin144") == 0 || _stricmp(line, "auth144") == 0)
            {
                if (Build373PureServerEmu144()) mw2019_diag::Log("[SERVER-EMU144] blocked: sign-in truth hooks are disabled\r\n");
                else iw8_144::EnableSignInHooks();
                continue;
            }
            if (_stricmp(line, "content144") == 0)
            {
                if (Build373PureServerEmu144()) mw2019_diag::Log("[SERVER-EMU144] blocked: content truth hooks are disabled\r\n");
                else iw8_144::EnableContentHook();
                continue;
            }
            if (_stricmp(line, "lui144") == 0 || _stricmp(line, "frontend144") == 0)
            {
                if (Build373PureServerEmu144()) mw2019_diag::Log("[SERVER-EMU144] blocked: LUI truth hooks are disabled\r\n");
                else iw8_144::EnableLuiHooks();
                continue;
            }
            if (_stricmp(line, "patch144") == 0)
            {
                if (Build373PureServerEmu144()) mw2019_diag::Log("[SERVER-EMU144] blocked: patch/time truth hooks are disabled\r\n");
                else iw8_144::EnablePatchHooks();
                continue;
            }
            if (_stricmp(line, "hooks144") == 0 || _stricmp(line, "fences144") == 0)
            {
                if (Build373PureServerEmu144()) mw2019_diag::Log("[SERVER-EMU144] blocked: offline/client truth hook bundle is disabled\r\n");
                else iw8_144::EnableLateOfflineHooks();
                continue;
            }
            if (_stricmp(line, "cmdscan") == 0 || _stricmp(line, "scancommands") == 0)
            {
                mw2019_scanner::ScanNow("manual command scan");
                Build169ScanCommandsInternal(true);
                continue;
            }
            if (_stricmp(line, "commands") == 0 || _stricmp(line, "cmdlist") == 0)
            {
                Build169ScanCommandsInternal(false);
                Build169PrintCommands(nullptr);
                continue;
            }
            if (_strnicmp(line, "cmdfind ", 8) == 0)
            {
                char* filter = Build373TrimCommand(line + 8);
                Build169ScanCommandsInternal(false);
                Build169PrintCommands(filter);
                continue;
            }
            if (_strnicmp(line, "exec ", 5) == 0)
            {
                if (Build373PureServerEmu144())
                {
                    mw2019_diag::Log("[SERVER-EMU144] blocked: exec is disabled in PURE EMULATION mode\r\n");
                    continue;
                }
                char* command = Build373TrimCommand(line + 5);
                if (!command || !*command)
                    mw2019_diag::Log("[CMD] usage: exec <raw command>\r\n");
                else
                    Build169QueueExec(command);
                continue;
            }
            if (_strnicmp(line, "cmdrun ", 7) == 0)
            {
                if (Build373PureServerEmu144())
                {
                    mw2019_diag::Log("[SERVER-EMU144] blocked: cmdrun is disabled in PURE EMULATION mode\r\n");
                    continue;
                }
                char* indexText = Build373TrimCommand(line + 7);
                char* endText = nullptr;
                const unsigned long commandIndex = strtoul(indexText, &endText, 10);
                if (endText == indexText || commandIndex == 0)
                {
                    mw2019_diag::Log("[CMD] usage: cmdrun <id> [args]\r\n");
                    continue;
                }

                Build169DiscoveredCommand discovered{};
                if (!Build169CommandByIndex(static_cast<unsigned>(commandIndex), discovered))
                {
                    mw2019_diag::Log("[CMD] id %lu is not in the current list; run cmdscan\r\n", commandIndex);
                    continue;
                }

                char* args = Build373TrimCommand(endText);
                char command[512]{};
                if (args && *args)
                    _snprintf_s(command, sizeof(command), _TRUNCATE, "%s %s", discovered.name, args);
                else
                    strncpy_s(command, discovered.name, _TRUNCATE);

                Build169QueueExec(command);
                continue;
            }

            if (_stricmp(line, "menus") == 0 || _stricmp(line, "menuhelp") == 0)
            {
                Build373PrintMenuHelp();
                continue;
            }
            if (_strnicmp(line, "trace", 5) == 0 && Build373PureServerEmu144())
            {
                mw2019_diag::Log("[SERVER-EMU144] blocked: LUI transition tracing hooks are disabled in PURE EMULATION mode\r\n");
                continue;
            }
            if (_stricmp(line, "trace stop") == 0)
            {
                Build378StopTransitionTrace("manual");
                continue;
            }
            if (_stricmp(line, "trace status") == 0)
            {
                Build378TraceStatus();
                continue;
            }
            if (_stricmp(line, "trace mp") == 0)
            {
                Build378ArmTransitionTrace("mp");
                continue;
            }
            if (_stricmp(line, "trace wz") == 0 || _stricmp(line, "trace warzone") == 0)
            {
                Build378ArmTransitionTrace("wz");
                continue;
            }
            if (_stricmp(line, "trace start") == 0 || _stricmp(line, "trace") == 0)
            {
                Build378ArmTransitionTrace("manual");
                continue;
            }
            if (_stricmp(line, "netstatus") == 0)
            {
                char host[256]{};
                mw2019_network::GetCustomServer(host, CountOf(host));
                mw2019_diag::Log("[NET] mode=Revamped isolation=%s server=%s\r\n",
                    mw2019_network::IsEnabled() ? "ON" : "OFF", host[0] ? host : "127.0.0.1");
                continue;
            }
            if (_strnicmp(line, "server ", 7) == 0)
            {
                char* host = Build373TrimCommand(line + 7);
                if (!host || !*host)
                    mw2019_diag::Log("[NET] usage: server <hostname-or-ip>\r\n");
                else
                {
                    mw2019_network::SetCustomServer(host);
                    mw2019_diag::Log("[NET] Revamped server set to %s\r\n", host);
                }
                continue;
            }
            if (_strnicmp(line, "menu raw ", 9) == 0)
            {
                if (Build373PureServerEmu144())
                {
                    mw2019_diag::Log("[SERVER-EMU144] blocked: forced menu routing is disabled in PURE EMULATION mode\r\n");
                    continue;
                }
                char* raw = Build373TrimCommand(line + 9);
                if (!raw || !*raw) mw2019_diag::Log("[MENU] usage: menu raw <ExactLUIName>\r\n");
                else Build373QueueRawMenu(raw);
                continue;
            }
            if (_strnicmp(line, "menu ", 5) == 0)
            {
                if (Build373PureServerEmu144())
                {
                    mw2019_diag::Log("[SERVER-EMU144] blocked: forced menu routing is disabled in PURE EMULATION mode\r\n");
                    continue;
                }
                char* alias = Build373TrimCommand(line + 5);
                if (!Build373QueueAlias(alias))
                {
                    mw2019_diag::Log("[MENU] unknown alias '%s'; trying raw name\r\n", alias);
                    Build373QueueRawMenu(alias);
                }
                continue;
            }
            if (Build373PureServerEmu144() && Build373FindMenuRoute(line))
            {
                mw2019_diag::Log("[SERVER-EMU144] blocked: forced menu routing is disabled in PURE EMULATION mode\r\n");
                continue;
            }
            if (Build373QueueAlias(line)) continue;
            mw2019_diag::Log("[CMD] unknown command '%s'. Type help.\r\n", line);
        }
        CloseHandle(input);
        InterlockedExchange(&g_build373ConsoleThreadStarted, 0);
        return 0;
    }

    unsigned __stdcall Build373MenuConsoleThreadCrt(void*) noexcept
    {
        return static_cast<unsigned>(Build373MenuConsoleThread(nullptr));
    }

    void StartBuild373MenuConsole() noexcept
    {
        if (InterlockedCompareExchange(&g_build373ConsoleThreadStarted, 1, 0) != 0) return;

        errno = 0;
        const std::uintptr_t rawThread = _beginthreadex(nullptr, 0, &Build373MenuConsoleThreadCrt, nullptr, 0, nullptr);
        HANDLE thread = reinterpret_cast<HANDLE>(rawThread);
        if (!thread)
        {
            const int crtError = errno;
            const DWORD winError = GetLastError();
            mw2019_diag::Log("[ERROR] menu console thread failed crt_errno=%d winerr=%lu\r\n", crtError, winError);
            InterlockedExchange(&g_build373ConsoleThreadStarted, 0);
            return;
        }
        CloseHandle(thread);
        mw2019_diag::Log("[CMD] menu console thread started via CRT-safe _beginthreadex\r\n");
    }

    void PollBuild357LanHotkeys() noexcept
    {
        if (!InstallBuild357GameWindowDispatch())
            return;

        if (!g_hotkeyHelpLogged)
        {
            g_hotkeyHelpLogged = true;
            mw2019_diag::Log(
                "[LAN-HOTKEY] Build372 debug menu routes disabled\r\n");
        }

        struct KeyRoute { int vk; bool* wasDown; WPARAM id; const char* label; };
        KeyRoute routes[] = {
            { VK_F1, &g_f1WasDown, 1, "LAN bootstrap + ServerBrowser" },
            { VK_F2, &g_f2WasDown, 2, "ServerBrowser only" },
            { VK_F3, &g_f3WasDown, 3, "MPMainMenu" },
            { VK_F4, &g_f4WasDown, 4, "SystemLinkLobby" },
            { VK_F5, &g_f5WasDown, 5, "old openmenu menu_systemlink_lobby path" },
        };

        for (auto& route : routes)
        {
            const bool down = (GetAsyncKeyState(route.vk) & 0x8000) != 0;
            if (down && !*route.wasDown)
            {
                mw2019_diag::Log("[LAN-HOTKEY] key request -> %s\r\n", route.label);
                if (!PostMessageW(g_gameWindow, kBuild357MenuMessage, route.id, 0))
                    mw2019_diag::Log("[LAN-HOTKEY] PostMessage failed menu=%s err=%lu\r\n", route.label, GetLastError());
            }
            *route.wasDown = down;
        }
    }

    void LUIOpenMenuTraceHook(
        int localClientNum,
        const char* menuName,
        int isPopup,
        int isModal,
        int isExclusive) noexcept
    {
        auto original = reinterpret_cast<LUIOpenMenuFn>(g_luiOpenTraceTrampoline);
        if (!original)
            return;

        if (InterlockedCompareExchange(&g_transitionTraceArmed, 0, 0) != 0)
        {
            const auto now = GetTickCount64();
            if (g_transitionTraceDeadlineMs && now >= g_transitionTraceDeadlineMs)
            {
                Build378StopTransitionTrace("20s window complete");
            }
            else
            {
                const LONG n = InterlockedIncrement(&g_luiOpenTraceCount);
                if (n <= 96)
                {
                    const char* safeName = menuName ? menuName : "<null>";
                    const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
                    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
                    const auto callerRva = (base && caller >= base) ? (caller - base) : 0;

                    void* frames[8]{};
                    const USHORT frameCount = RtlCaptureStackBackTrace(1, static_cast<ULONG>(CountOf(frames)), frames, nullptr);
                    char stackText[512]{};
                    size_t used = 0;
                    for (USHORT i = 0; i < frameCount && used + 32 < CountOf(stackText); ++i)
                    {
                        const auto frame = reinterpret_cast<std::uintptr_t>(frames[i]);
                        if (!base || frame < base)
                            continue;
                        const auto rva = frame - base;
                        const int wrote = _snprintf_s(stackText + used, CountOf(stackText) - used, _TRUNCATE,
                            "%s%llX", used ? "," : "", static_cast<unsigned long long>(rva));
                        if (wrote <= 0) break;
                        used += static_cast<size_t>(wrote);
                    }

                    mw2019_diag::Log(
                        "[V99-MENU][TRACE:%s] #%ld LUI_OpenMenu name='%s' client=%d popup=%d modal=%d exclusive=%d callerRVA=0x%llX stackRVA=[%s]\r\n",
                        g_transitionTraceLabel[0] ? g_transitionTraceLabel : "manual",
                        n, safeName, localClientNum, isPopup, isModal, isExclusive,
                        static_cast<unsigned long long>(callerRva), stackText);
                    V99Append(
                        "[V99-MENU][TRACE:%s] #%ld LUI_OpenMenu name='%s' client=%d popup=%d modal=%d exclusive=%d callerRVA=0x%llX stackRVA=[%s]\r\n",
                        g_transitionTraceLabel[0] ? g_transitionTraceLabel : "manual",
                        n, safeName, localClientNum, isPopup, isModal, isExclusive,
                        static_cast<unsigned long long>(callerRva), stackText);
                }
            }
        }

        original(localClientNum, menuName, isPopup, isModal, isExclusive);
    }

    bool InstallLUIOpenMenuTraceHook() noexcept
    {
        if (g_luiOpenTraceHookInstalled)
            return true;

        Signature* openSig = FindSignature("LUI_OpenMenu");
        if (!openSig || !openSig->address)
            return false;

        constexpr std::size_t kPatchSize = 15;
        unsigned char originalBytes[kPatchSize]{};
        __try { memcpy(originalBytes, reinterpret_cast<const void*>(openSig->address), kPatchSize); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

        unsigned char* trampoline = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!trampoline)
            return false;

        memcpy(trampoline, originalBytes, kPatchSize);
        std::size_t pos = kPatchSize;
        trampoline[pos++] = 0x48; trampoline[pos++] = 0xB8;
        *reinterpret_cast<std::uint64_t*>(trampoline + pos) =
            static_cast<std::uint64_t>(openSig->address + kPatchSize);
        pos += 8;
        trampoline[pos++] = 0xFF; trampoline[pos++] = 0xE0;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(openSig->address), kPatchSize,
                PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        unsigned char patch[kPatchSize]{};
        patch[0] = 0x48; patch[1] = 0xB8;
        *reinterpret_cast<std::uint64_t*>(patch + 2) =
            reinterpret_cast<std::uint64_t>(&LUIOpenMenuTraceHook);
        patch[10] = 0xFF; patch[11] = 0xE0;
        patch[12] = 0x90; patch[13] = 0x90; patch[14] = 0x90;

        memcpy(reinterpret_cast<void*>(openSig->address), patch, kPatchSize);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(openSig->address), kPatchSize);
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(openSig->address), kPatchSize, oldProtect, &ignored);

        g_luiOpenTraceTrampoline = trampoline;
        g_luiOpenTraceHookInstalled = true;
        return true;
    }


    using CLPlayerDataGetDDLBufferFn = bool (*)(void*, int, int, int);

    void LogDDLContextRaw(const char* tag, void* context) noexcept
    {
        if (!tag || !context)
            return;

        __try
        {
            const auto* q = reinterpret_cast<const std::uint64_t*>(context);
            mw2019_diag::Log(
                "[DDL-CONTEXT] %s ptr=%p q0=%016llX q1=%016llX q2=%016llX q3=%016llX q4=%016llX q5=%016llX q6=%016llX q7=%016llX\r\n",
                tag, context,
                static_cast<unsigned long long>(q[0]), static_cast<unsigned long long>(q[1]),
                static_cast<unsigned long long>(q[2]), static_cast<unsigned long long>(q[3]),
                static_cast<unsigned long long>(q[4]), static_cast<unsigned long long>(q[5]),
                static_cast<unsigned long long>(q[6]), static_cast<unsigned long long>(q[7]));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log("[DDL-CONTEXT] %s ptr=%p read fault code=0x%08lX\r\n",
                tag, context, GetExceptionCode());
        }
    }

    bool CLPlayerDataGetDDLBufferTraceHook(
        void* context,
        int controllerIndex,
        int statsSource,
        int statsGroup) noexcept
    {
        auto original = reinterpret_cast<CLPlayerDataGetDDLBufferFn>(g_ddlTraceTrampoline);
        if (!original)
            return false;

        const LONG index = InterlockedIncrement(&g_ddlTraceCount);
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const auto returnAddress = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
        const unsigned long long returnRva =
            (base && returnAddress >= base && returnAddress < base + 0x21679200ull)
                ? static_cast<unsigned long long>(returnAddress - base) : 0ull;

        bool result = false;
        bool faulted = false;
        DWORD faultCode = 0;

        __try
        {
            result = original(context, controllerIndex, statsSource, statsGroup);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            faulted = true;
            faultCode = GetExceptionCode();
            result = false;
        }

        if (statsSource == 1 && statsGroup >= 0 && statsGroup < 8)
        {
            InterlockedIncrement(&g_ddlOfflineGroupCalls[statsGroup]);
            if (result)
                InterlockedIncrement(&g_ddlOfflineGroupSuccess[statsGroup]);
        }

        if ((statsSource == 1 && statsGroup >= 0 && statsGroup < 16) || index <= 128)
        {
            mw2019_diag::Log(
                "[DDL-CALL] index=%ld thread=%lu callerRva=0x%llX context=%p controller=%d source=%d group=%d result=%d fault=%d code=0x%08lX\r\n",
                index, GetCurrentThreadId(), returnRva, context,
                controllerIndex, statsSource, statsGroup,
                result ? 1 : 0, faulted ? 1 : 0, faultCode);

            if (context)
                LogDDLContextRaw(result ? "after-success" : "after-fail", context);
        }

        return result;
    }

    bool InstallCLPlayerDataDDLTraceHook() noexcept
    {
        if (g_ddlTraceHookInstalled)
            return true;

        Signature* sig = FindSignature("CL_PlayerData_GetDDLBuffer");
        if (!sig || !sig->address)
            return false;

        constexpr std::size_t kPatchSize = 15;
        unsigned char original[kPatchSize]{};
        __try
        {
            memcpy(original, reinterpret_cast<const void*>(sig->address), kPatchSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        unsigned char* trampoline = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!trampoline)
            return false;

        memcpy(trampoline, original, kPatchSize);
        std::size_t pos = kPatchSize;
        trampoline[pos++] = 0x48; trampoline[pos++] = 0xB8;
        *reinterpret_cast<std::uint64_t*>(trampoline + pos) =
            static_cast<std::uint64_t>(sig->address + kPatchSize);
        pos += 8;
        trampoline[pos++] = 0xFF; trampoline[pos++] = 0xE0;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(sig->address), kPatchSize,
                PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

        unsigned char patch[kPatchSize]{};
        patch[0] = 0x48; patch[1] = 0xB8;
        *reinterpret_cast<std::uint64_t*>(patch + 2) =
            reinterpret_cast<std::uint64_t>(&CLPlayerDataGetDDLBufferTraceHook);
        patch[10] = 0xFF; patch[11] = 0xE0;
        patch[12] = 0x90; patch[13] = 0x90; patch[14] = 0x90;

        memcpy(reinterpret_cast<void*>(sig->address), patch, kPatchSize);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(sig->address), kPatchSize);
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(sig->address), kPatchSize, oldProtect, &ignored);

        g_ddlTraceTrampoline = trampoline;
        g_ddlTraceHookInstalled = true;
        mw2019_diag::Log(
            "[DDL-TRACE] CL_PlayerData_GetDDLBuffer hook ACTIVE address=%p trampoline=%p\r\n",
            reinterpret_cast<void*>(sig->address), trampoline);
        return true;
    }




    // Build372 compile-order forward declarations.
    // Implementations are defined later in this translation unit.
    bool IsReadable(DWORD protect);
    bool IsExecutableProtect(DWORD protect) noexcept;
    bool GetMainImageRange(std::uintptr_t& baseOut, std::uintptr_t& endOut) noexcept;
    bool GetRuntimeFunctionBounds(
        std::uintptr_t pc,
        std::uintptr_t& beginOut,
        std::uintptr_t& endOut) noexcept;
    void ArxanBytesHex(
        const void* data,
        std::size_t size,
        char* out,
        std::size_t outSize) noexcept
    {
        if (!out || !outSize)
            return;

        out[0] = '\0';
        if (!data || !size)
            return;

        const auto* p = static_cast<const unsigned char*>(data);
        std::size_t pos = 0;

        __try
        {
            for (std::size_t i = 0; i < size && pos + 3 < outSize; ++i)
            {
                const int wrote = _snprintf_s(
                    out + pos,
                    outSize - pos,
                    _TRUNCATE,
                    "%02X",
                    p[i]);

                if (wrote <= 0)
                    break;

                pos += static_cast<std::size_t>(wrote);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            out[0] = '\0';
        }
    }

    bool RestoreGameTextHookFromTrampoline(
        const char* label,
        const char* signatureName,
        void* trampoline,
        std::size_t patchSize,
        bool& installedFlag) noexcept
    {
        if (!installedFlag)
            return true;

        Signature* sig = FindSignature(signatureName);
        if (!sig || !sig->address || !trampoline || !patchSize)
        {
            mw2019_diag::Log(
                "[ARXAN-SAFE] cannot restore %s target=%s addr=%p trampoline=%p size=%zu\r\n",
                label ? label : "?",
                signatureName ? signatureName : "?",
                sig ? reinterpret_cast<void*>(sig->address) : nullptr,
                trampoline,
                patchSize);
            return false;
        }

        unsigned char before[32]{};
        unsigned char original[32]{};
        if (patchSize > sizeof(before))
            return false;

        __try
        {
            memcpy(before, reinterpret_cast<const void*>(sig->address), patchSize);
            memcpy(original, trampoline, patchSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log(
                "[ARXAN-SAFE] restore read fault %s code=0x%08lX\r\n",
                label ? label : "?",
                GetExceptionCode());
            return false;
        }

        char beforeHex[96]{};
        char originalHex[96]{};
        ArxanBytesHex(before, patchSize, beforeHex, sizeof(beforeHex));
        ArxanBytesHex(original, patchSize, originalHex, sizeof(originalHex));

        DWORD oldProtect = 0;
        if (!VirtualProtect(
                reinterpret_cast<void*>(sig->address),
                patchSize,
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            mw2019_diag::Log(
                "[ARXAN-SAFE] VirtualProtect restore failed %s err=%lu\r\n",
                label ? label : "?",
                GetLastError());
            return false;
        }

        __try
        {
            memcpy(reinterpret_cast<void*>(sig->address), original, patchSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DWORD ignored = 0;
            VirtualProtect(reinterpret_cast<void*>(sig->address), patchSize, oldProtect, &ignored);
            mw2019_diag::Log(
                "[ARXAN-SAFE] restore write fault %s code=0x%08lX\r\n",
                label ? label : "?",
                GetExceptionCode());
            return false;
        }

        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<void*>(sig->address),
            patchSize);

        DWORD ignored = 0;
        VirtualProtect(
            reinterpret_cast<void*>(sig->address),
            patchSize,
            oldProtect,
            &ignored);

        unsigned char after[32]{};
        bool verified = false;
        __try
        {
            memcpy(after, reinterpret_cast<const void*>(sig->address), patchSize);
            verified = memcmp(after, original, patchSize) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            verified = false;
        }

        installedFlag = false;

        if (!verified)
            mw2019_diag::Log("[ERROR] stock .text restore verification failed: %s\r\n",
                label ? label : "?");

        return verified;
    }

    unsigned CountCapturedOfflineLuaWrappers() noexcept
    {
        unsigned found = 0;
        for (const auto& wrapper : g_capturedLuaWrappers)
            if (wrapper.original)
                ++found;
        return found;
    }

    void RestorePersistentGameTextHooksForArxan(unsigned long long uptimeMs) noexcept
    {
        if (g_arxanSafeDiagnosticHooksRestored)
            return;
        const unsigned wrappers = CountCapturedOfflineLuaWrappers();
        if (wrappers < CountOf(g_capturedLuaWrappers) || uptimeMs < 25000)
            return;
        // Build374 never installs the old LUI/DDL diagnostic detours.
        g_arxanSafeDiagnosticHooksRestored = true;
    }

    void RestoreLuaOpenLibAfterQuietWindow(unsigned long long uptimeMs) noexcept
    {
        (void)uptimeMs;
        if (g_luaOpenLibRestoredAfterQuiet ||
            !g_arxanSafeDiagnosticHooksRestored ||
            !g_luaMenuHookInstalled)
            return;
        if (g_dvarPasses < 2 || !g_lastLuaOverrideActivityMs || g_luaOverrideRegistrationCount < 2)
            return;
        const unsigned long long now = GetTickCount64();
        const unsigned long long quietMs = now >= g_lastLuaOverrideActivityMs
            ? now - g_lastLuaOverrideActivityMs : 0ull;
        if (quietMs < 20000ull || InterlockedCompareExchange(&g_luaOpenLibActiveCalls, 0, 0) != 0)
            return;
        const bool ok = RestoreGameTextHookFromTrampoline(
            "luaL_openlib quiet restore", "luaL_openlib", g_luaOpenLibTrampoline, 13, g_luaMenuHookInstalled);
        if (ok)
        {
            g_luaOpenLibRestoredAfterQuiet = true;
            InstallCrashTraceVehLate();
        }
        else
        {
            mw2019_diag::Log("[ERROR] failed to restore luaL_openlib after quiet window\r\n");
        }
    }

    bool IsReadable(DWORD protect)
    {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        const DWORD p = protect & 0xFF;
        return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    bool ParsePattern(const char* text, unsigned char* bytes, unsigned char* mask, std::size_t& length)
    {
        length = 0;
        while (text && *text && length < 96)
        {
            while (*text == ' ') ++text;
            if (!*text) break;
            if (*text == '?')
            {
                bytes[length] = 0; mask[length] = 0; ++length;
                while (*text == '?') ++text;
            }
            else
            {
                unsigned value = 0;
                if (sscanf_s(text, "%2x", &value) != 1) return false;
                bytes[length] = static_cast<unsigned char>(value); mask[length] = 1; ++length;
                if (text[0]) ++text;
                if (text[0]) ++text;
                continue;
            }
            while (*text && *text != ' ') ++text;
        }
        return length != 0;
    }

    const unsigned char* FindPattern(const unsigned char* start, std::size_t size, const char* pattern)
    {
        unsigned char bytes[96]{}, mask[96]{};
        std::size_t len = 0;
        if (!ParsePattern(pattern, bytes, mask, len) || size < len) return nullptr;

        std::size_t anchor = 0;
        while (anchor < len && !mask[anchor]) ++anchor;
        if (anchor == len) return start;

        for (std::size_t i = 0; i + len <= size; ++i)
        {
            if (start[i + anchor] != bytes[anchor]) continue;
            bool ok = true;
            for (std::size_t j = 0; j < len; ++j)
            {
                if (mask[j] && start[i + j] != bytes[j]) { ok = false; break; }
            }
            if (ok) return start + i;
        }
        return nullptr;
    }

    std::uintptr_t Resolve(std::uintptr_t match, ResolveKind kind)
    {
        __try
        {
            switch (kind)
            {
            case ResolveKind::CallRel32At0:
                return match + 5 + *reinterpret_cast<const std::int32_t*>(match + 1);
            case ResolveKind::RipRel32At2:
                return match + 7 + *reinterpret_cast<const std::int32_t*>(match + 2);
            case ResolveKind::RipRel32At2Plus1:
                return match + 8 + *reinterpret_cast<const std::int32_t*>(match + 2);
            case ResolveKind::RipRel32At3:
                return match + 7 + *reinterpret_cast<const std::int32_t*>(match + 3);
            default:
                return match;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return match; }
    }

    std::uintptr_t ScanOne(const char* pattern)
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return 0;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            const auto* sec = IMAGE_FIRST_SECTION(nt);
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            {
                if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                auto sectionStart = base + sec[i].VirtualAddress;
                auto sectionSize = static_cast<std::size_t>(sec[i].Misc.VirtualSize);
                std::uintptr_t cur = sectionStart;
                const std::uintptr_t end = sectionStart + sectionSize;
                while (cur < end)
                {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi))) break;
                    const auto regionStart = (cur > reinterpret_cast<std::uintptr_t>(mbi.BaseAddress)) ? cur : reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                    const auto regionEnd0 = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                    const auto regionEnd = regionEnd0 < end ? regionEnd0 : end;
                    if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect) && regionEnd > regionStart)
                    {
                        if (const auto* hit = FindPattern(reinterpret_cast<const unsigned char*>(regionStart), static_cast<std::size_t>(regionEnd - regionStart), pattern))
                            return reinterpret_cast<std::uintptr_t>(hit);
                    }
                    if (regionEnd <= cur) break;
                    cur = regionEnd;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return 0;
    }


    void LogCodeWindow(const char* tag, std::uintptr_t address, std::uintptr_t base) noexcept
    {
        if (!address || !base) return;
        __try
        {
            const unsigned long long rva = static_cast<unsigned long long>(address - base);
            char line[1024]{};
            int pos = sprintf_s(line, "[DEEP-%s] rva=0x%llX address=%p bytes=",
                tag ? tag : "CODE", rva, reinterpret_cast<void*>(address));
            const auto* p = reinterpret_cast<const unsigned char*>(address);
            for (int i = -32; i < 64 && pos > 0 && pos < static_cast<int>(sizeof(line) - 4); ++i)
                pos += sprintf_s(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02X ", p[i]);
            if (pos > 0)
                strcat_s(line, "\r\n");
            mw2019_diag::Log("%s", line);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    void ScanCallsitesTo(const char* name, std::uintptr_t target) noexcept
    {
        if (!target) return;
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return;

        unsigned hits = 0;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            const auto* sec = IMAGE_FIRST_SECTION(nt);
            for (unsigned s = 0; s < nt->FileHeader.NumberOfSections && hits < 32; ++s)
            {
                if (!(sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                const auto start = base + sec[s].VirtualAddress;
                const auto size = static_cast<std::size_t>(sec[s].Misc.VirtualSize);
                const auto* p = reinterpret_cast<const unsigned char*>(start);
                for (std::size_t i = 0; i + 5 <= size && hits < 32; ++i)
                {
                    if (p[i] != 0xE8) continue;
                    const auto at = start + i;
                    const auto dst = at + 5 + *reinterpret_cast<const std::int32_t*>(at + 1);
                    if (dst != target) continue;
                    ++hits;
                    mw2019_diag::Log("[DEEP-CALLSITE] target=%s targetRva=0x%llX callRva=0x%llX\r\n",
                        name ? name : "<unknown>",
                        static_cast<unsigned long long>(target - base),
                        static_cast<unsigned long long>(at - base));
                    LogCodeWindow("CALLSITE", at, base);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        mw2019_diag::Log("[DEEP-CALLSITE] target=%s hits=%u\r\n", name ? name : "<unknown>", hits);
    }

    void ScanRipXrefsTo(const char* name, std::uintptr_t target) noexcept
    {
        if (!target) return;
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return;

        unsigned hits = 0;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            const auto* sec = IMAGE_FIRST_SECTION(nt);
            for (unsigned s = 0; s < nt->FileHeader.NumberOfSections && hits < 48; ++s)
            {
                if (!(sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                const auto start = base + sec[s].VirtualAddress;
                const auto size = static_cast<std::size_t>(sec[s].Misc.VirtualSize);
                const auto* p = reinterpret_cast<const unsigned char*>(start);

                for (std::size_t i = 0; i + 8 <= size && hits < 48; ++i)
                {
                    std::size_t dispOff = 0;
                    std::size_t instLen = 0;

                    if ((p[i] == 0x48 || p[i] == 0x4C) &&
                        (p[i + 1] == 0x8B || p[i + 1] == 0x8D || p[i + 1] == 0x89) &&
                        (p[i + 2] & 0xC7) == 0x05)
                    {
                        dispOff = 3;
                        instLen = 7;
                    }
                    else if ((p[i] == 0x80 || p[i] == 0x83) && (p[i + 1] & 0xC7) == 0x3D)
                    {
                        dispOff = 2;
                        instLen = (p[i] == 0x80) ? 7 : 7;
                    }
                    else if ((p[i] == 0x0F && p[i + 1] == 0xB6 && (p[i + 2] & 0xC7) == 0x05))
                    {
                        dispOff = 3;
                        instLen = 7;
                    }
                    else
                    {
                        continue;
                    }

                    const auto at = start + i;
                    const auto dst = at + instLen + *reinterpret_cast<const std::int32_t*>(at + dispOff);
                    if (dst != target) continue;

                    ++hits;
                    mw2019_diag::Log("[DEEP-XREF] target=%s targetRva=0x%llX xrefRva=0x%llX\r\n",
                        name ? name : "<unknown>",
                        static_cast<unsigned long long>(target - base),
                        static_cast<unsigned long long>(at - base));
                    LogCodeWindow("XREF", at, base);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        mw2019_diag::Log("[DEEP-XREF] target=%s hits=%u\r\n", name ? name : "<unknown>", hits);
    }

    void ScanBNetAuthMagic() noexcept
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return;

        const unsigned char magic[] = { 0xF0, 0x30, 0x52, 0x79 };
        unsigned hits = 0;

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            const auto* sec = IMAGE_FIRST_SECTION(nt);
            for (unsigned s = 0; s < nt->FileHeader.NumberOfSections && hits < 32; ++s)
            {
                if (!(sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                const auto start = base + sec[s].VirtualAddress;
                const auto size = static_cast<std::size_t>(sec[s].Misc.VirtualSize);
                const auto* p = reinterpret_cast<const unsigned char*>(start);

                for (std::size_t i = 0; i + sizeof(magic) <= size && hits < 32; ++i)
                {
                    if (memcmp(p + i, magic, sizeof(magic)) != 0) continue;
                    ++hits;
                    const auto at = start + i;
                    mw2019_diag::Log("[DEEP-BNET-MAGIC] hit=%u rva=0x%llX\r\n",
                        hits, static_cast<unsigned long long>(at - base));
                    LogCodeWindow("BNETMAGIC", at, base);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        mw2019_diag::Log("[DEEP-BNET-MAGIC] total=%u\r\n", hits);
    }


    bool IsExecutableProtect(DWORD protect) noexcept
    {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS))
            return false;
        const DWORD p = protect & 0xFF;
        return p == PAGE_EXECUTE ||
               p == PAGE_EXECUTE_READ ||
               p == PAGE_EXECUTE_READWRITE ||
               p == PAGE_EXECUTE_WRITECOPY;
    }

    bool GetMainImageRange(std::uintptr_t& baseOut, std::uintptr_t& endOut) noexcept
    {
        baseOut = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        endOut = 0;
        if (!baseOut) return false;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(baseOut);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                baseOut + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
            endOut = baseOut + static_cast<std::uintptr_t>(nt->OptionalHeader.SizeOfImage);
            return endOut > baseOut;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void ScanMappedExecCallsitesTo(const char* name, std::uintptr_t target) noexcept
    {
        if (!target) return;

        std::uintptr_t base = 0, end = 0;
        if (!GetMainImageRange(base, end)) return;

        unsigned hits = 0;
        std::uintptr_t cursor = base;
        while (cursor < end && hits < 64)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t scanStart = regionBase < base ? base : regionBase;
            const std::uintptr_t scanEnd = regionEndRaw > end ? end : regionEndRaw;

            if (mbi.State == MEM_COMMIT &&
                IsExecutableProtect(mbi.Protect) &&
                scanEnd > scanStart)
            {
                __try
                {
                    const auto* p = reinterpret_cast<const unsigned char*>(scanStart);
                    const std::size_t size = static_cast<std::size_t>(scanEnd - scanStart);
                    for (std::size_t i = 0; i + 5 <= size && hits < 64; ++i)
                    {
                        if (p[i] != 0xE8) continue;
                        const auto at = scanStart + i;
                        const auto dst = at + 5 +
                            *reinterpret_cast<const std::int32_t*>(at + 1);
                        if (dst != target) continue;

                        ++hits;
                        mw2019_diag::Log(
                            "[MAPPED-CALLSITE] target=%s targetRva=0x%llX callRva=0x%llX protect=0x%08lX\r\n",
                            name ? name : "<unknown>",
                            static_cast<unsigned long long>(target - base),
                            static_cast<unsigned long long>(at - base),
                            mbi.Protect);
                        LogCodeWindow("MAPPED-CALLSITE", at, base);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            if (regionEndRaw <= cursor) break;
            cursor = regionEndRaw;
        }

        mw2019_diag::Log("[MAPPED-CALLSITE] target=%s hits=%u\r\n",
            name ? name : "<unknown>", hits);
    }

    bool V99FunctionBounds(std::uintptr_t address, std::uintptr_t& beginOut, std::uintptr_t& endOut) noexcept
    {
        beginOut = endOut = 0;
        if (!address)
            return false;
        DWORD64 imageBase = 0;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(static_cast<DWORD64>(address), &imageBase, nullptr);
        if (!rf || !imageBase || rf->EndAddress <= rf->BeginAddress)
            return false;
        beginOut = static_cast<std::uintptr_t>(imageBase + rf->BeginAddress);
        endOut = static_cast<std::uintptr_t>(imageBase + rf->EndAddress);
        return address >= beginOut && address < endOut;
    }

    bool V99VectorContains(const std::vector<std::uintptr_t>& values, std::uintptr_t value) noexcept
    {
        return std::find(values.begin(), values.end(), value) != values.end();
    }

    void V99LogPreCallBranchCandidates(std::uintptr_t callsite, std::uintptr_t ownerBegin,
        std::uintptr_t ownerEnd, std::uintptr_t moduleBase) noexcept
    {
        if (!callsite || !ownerBegin || callsite <= ownerBegin || !moduleBase)
            return;

        const auto start = (callsite - ownerBegin > 0xA0u) ? callsite - 0xA0u : ownerBegin;
        struct Candidate { std::uintptr_t site; std::uintptr_t target; std::uintptr_t predicate; };
        Candidate candidates[6]{};
        unsigned count = 0;

        __try
        {
            for (auto at = start; at < callsite; ++at)
            {
                const auto* p = reinterpret_cast<const unsigned char*>(at);
                std::uintptr_t branchTarget = 0;
                std::size_t branchLen = 0;
                if (p[0] >= 0x70 && p[0] <= 0x7F && at + 2 <= callsite)
                {
                    const auto rel = static_cast<std::int8_t>(p[1]);
                    branchLen = 2;
                    branchTarget = at + branchLen + rel;
                }
                else if (p[0] == 0x0F && p[1] >= 0x80 && p[1] <= 0x8F && at + 6 <= callsite)
                {
                    std::int32_t rel = 0;
                    memcpy(&rel, p + 2, sizeof(rel));
                    branchLen = 6;
                    branchTarget = at + branchLen + rel;
                }
                else
                {
                    continue;
                }

                // Prefer branches that stay inside the owning state-machine function.
                if (branchTarget < ownerBegin || branchTarget >= ownerEnd)
                    continue;

                std::uintptr_t predicate = 0;
                const auto predStart = (at - ownerBegin > 0x38u) ? at - 0x38u : ownerBegin;
                for (auto q = predStart; q + 5 <= at; ++q)
                {
                    const auto* b = reinterpret_cast<const unsigned char*>(q);
                    if (b[0] != 0xE8)
                        continue;
                    std::int32_t rel = 0;
                    memcpy(&rel, b + 1, sizeof(rel));
                    predicate = q + 5 + rel;
                }

                if (count < CountOf(candidates))
                {
                    candidates[count++] = { at, branchTarget, predicate };
                }
                else
                {
                    for (unsigned move = 1; move < CountOf(candidates); ++move)
                        candidates[move - 1] = candidates[move];
                    candidates[CountOf(candidates) - 1] = { at, branchTarget, predicate };
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return;
        }

        // Keep only the closest candidates to the eventual LUI_OpenMenu call.
        const unsigned beginIndex = count > 4 ? count - 4 : 0;
        for (unsigned i = beginIndex; i < count; ++i)
        {
            const auto& c = candidates[i];
            const auto branchRva = c.site >= moduleBase ? c.site - moduleBase : 0;
            const auto targetRva = c.target >= moduleBase ? c.target - moduleBase : 0;
            const auto predRva = c.predicate >= moduleBase ? c.predicate - moduleBase : 0;
            mw2019_diag::Log(
                "[V99-BRANCH] callRva=0x%llX branchRva=0x%llX branchTargetRva=0x%llX nearestPredicateCallRva=0x%llX classification=CANDIDATE_PRE_MENU_GATE readOnly=yes\r\n",
                static_cast<unsigned long long>(callsite - moduleBase),
                static_cast<unsigned long long>(branchRva),
                static_cast<unsigned long long>(targetRva),
                static_cast<unsigned long long>(predRva));
            V99Append(
                "[V99-BRANCH] callRva=0x%llX branchRva=0x%llX branchTargetRva=0x%llX nearestPredicateCallRva=0x%llX classification=CANDIDATE_PRE_MENU_GATE readOnly=yes\r\n",
                static_cast<unsigned long long>(callsite - moduleBase),
                static_cast<unsigned long long>(branchRva),
                static_cast<unsigned long long>(targetRva),
                static_cast<unsigned long long>(predRva));
            LogCodeWindow("V99-MENU-BRANCH", c.site, moduleBase);
        }
    }

    // Keep SEH isolated from std::vector/std::string/logging code. MSVC rejects
    // __try in a function that requires C++ object unwinding (C2712).
    // This helper is POD-only and just snapshots matching rel32 CALL sites.
    unsigned V99CollectRel32CallsInRegion(
        std::uintptr_t scanStart,
        std::uintptr_t scanEnd,
        const std::uintptr_t* targets,
        unsigned targetCount,
        V99RelCallHit* outHits,
        unsigned outCapacity) noexcept
    {
        if (!scanStart || scanEnd <= scanStart || !targets || !targetCount || !outHits || !outCapacity)
            return 0;

        unsigned hitCount = 0;
        __try
        {
            const auto* bytes = reinterpret_cast<const unsigned char*>(scanStart);
            const auto size = static_cast<std::size_t>(scanEnd - scanStart);
            for (std::size_t i = 0; i + 5 <= size && hitCount < outCapacity; ++i)
            {
                if (bytes[i] != 0xE8)
                    continue;

                std::int32_t rel = 0;
                memcpy(&rel, bytes + i + 1, sizeof(rel));
                const auto callsite = scanStart + i;
                const auto target = callsite + 5 + rel;

                bool wanted = false;
                for (unsigned t = 0; t < targetCount; ++t)
                {
                    if (targets[t] == target)
                    {
                        wanted = true;
                        break;
                    }
                }
                if (!wanted)
                    continue;

                outHits[hitCount++] = { callsite, target };
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return hitCount;
        }
        return hitCount;
    }

    void V99MenuBacktraceScan() noexcept
    {
        Signature* openSig = FindSignature("LUI_OpenMenu");
        if (!openSig || !openSig->address)
        {
            mw2019_diag::Log("[V99-XREF] LUI_OpenMenu unresolved; run /menustatus then retry\r\n");
            V99Append("[V99-XREF] ABORT reason=LUI_OpenMenu_unresolved\r\n");
            return;
        }

        std::uintptr_t base = 0, end = 0;
        if (!GetMainImageRange(base, end))
        {
            mw2019_diag::Log("[V99-XREF] main image range unavailable\r\n");
            return;
        }

        std::vector<std::uintptr_t> frontier;
        frontier.push_back(openSig->address);
        std::vector<std::uintptr_t> allOwners;
        unsigned totalEdges = 0;
        mw2019_diag::Log(
            "[V99-XREF] BEGIN target=LUI_OpenMenu targetRva=0x%llX depth=3 mode=STATIC_DIRECT_CALL_REVERSE readOnly=yes\r\n",
            static_cast<unsigned long long>(openSig->address - base));
        V99Append(
            "\r\n[V99-XREF] BEGIN target=LUI_OpenMenu targetRva=0x%llX depth=3 mode=STATIC_DIRECT_CALL_REVERSE readOnly=yes\r\n",
            static_cast<unsigned long long>(openSig->address - base));

        for (unsigned depth = 0; depth < 3 && !frontier.empty(); ++depth)
        {
            std::vector<std::uintptr_t> next;
            unsigned depthEdges = 0;
            std::uintptr_t cursor = base;
            while (cursor < end && depthEdges < 96)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) || !mbi.RegionSize)
                    break;
                const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto regionEndRaw = regionBase + mbi.RegionSize;
                const auto scanStart = regionBase < base ? base : regionBase;
                const auto scanEnd = regionEndRaw > end ? end : regionEndRaw;

                if (mbi.State == MEM_COMMIT && IsExecutableProtect(mbi.Protect) && scanEnd > scanStart)
                {
                    std::uintptr_t targets[32]{};
                    const unsigned targetCount = static_cast<unsigned>(
                        frontier.size() < CountOf(targets) ? frontier.size() : CountOf(targets));
                    for (unsigned i = 0; i < targetCount; ++i)
                        targets[i] = frontier[i];

                    V99RelCallHit hits[96]{};
                    const unsigned capacity = 96u - depthEdges;
                    const unsigned hitCount = V99CollectRel32CallsInRegion(
                        scanStart, scanEnd, targets, targetCount, hits, capacity);

                    for (unsigned i = 0; i < hitCount && depthEdges < 96; ++i)
                    {
                        const auto callsite = hits[i].callsite;
                        const auto target = hits[i].target;
                        std::uintptr_t ownerBegin = 0, ownerEnd = 0;
                        const bool haveOwner = V99FunctionBounds(callsite, ownerBegin, ownerEnd);
                        ++depthEdges;
                        ++totalEdges;
                        mw2019_diag::Log(
                            "[V99-XREF] depth=%u edge=%u targetRva=0x%llX callRva=0x%llX owner=%s0x%llX..0x%llX protect=0x%08lX\r\n",
                            depth, depthEdges,
                            static_cast<unsigned long long>(target - base),
                            static_cast<unsigned long long>(callsite - base),
                            haveOwner ? "" : "UNKNOWN/",
                            static_cast<unsigned long long>(haveOwner ? ownerBegin - base : 0),
                            static_cast<unsigned long long>(haveOwner ? ownerEnd - base : 0),
                            mbi.Protect);
                        V99Append(
                            "[V99-XREF] depth=%u edge=%u targetRva=0x%llX callRva=0x%llX owner=%s0x%llX..0x%llX\r\n",
                            depth, depthEdges,
                            static_cast<unsigned long long>(target - base),
                            static_cast<unsigned long long>(callsite - base),
                            haveOwner ? "" : "UNKNOWN/",
                            static_cast<unsigned long long>(haveOwner ? ownerBegin - base : 0),
                            static_cast<unsigned long long>(haveOwner ? ownerEnd - base : 0));

                        LogCodeWindow("V99-MENU-CALLSITE", callsite, base);
                        if (haveOwner)
                        {
                            V99LogPreCallBranchCandidates(callsite, ownerBegin, ownerEnd, base);
                            if (!V99VectorContains(allOwners, ownerBegin))
                                allOwners.push_back(ownerBegin);
                            if (!V99VectorContains(next, ownerBegin) && next.size() < 32)
                                next.push_back(ownerBegin);
                        }
                    }
                }

                if (regionEndRaw <= cursor)
                    break;
                cursor = regionEndRaw;
            }

            mw2019_diag::Log("[V99-XREF] DEPTH_COMPLETE depth=%u targets=%zu edges=%u nextOwners=%zu\r\n",
                depth, frontier.size(), depthEdges, next.size());
            V99Append("[V99-XREF] DEPTH_COMPLETE depth=%u targets=%zu edges=%u nextOwners=%zu\r\n",
                depth, frontier.size(), depthEdges, next.size());
            frontier.swap(next);
        }

        mw2019_diag::Log(
            "[V99-XREF] COMPLETE totalEdges=%u uniqueOwnerFunctions=%zu next=arm_/menutrace_then_compare_natural_vs_/menuopen readOnly=yes\r\n",
            totalEdges, allOwners.size());
        V99Append(
            "[V99-XREF] COMPLETE totalEdges=%u uniqueOwnerFunctions=%zu next=arm_menutrace_then_compare_natural_vs_menuopen readOnly=yes\r\n",
            totalEdges, allOwners.size());
    }

    void ScanMappedRipXrefsTo(const char* name, std::uintptr_t target) noexcept
    {
        if (!target) return;

        std::uintptr_t base = 0, end = 0;
        if (!GetMainImageRange(base, end)) return;

        unsigned hits = 0;
        std::uintptr_t cursor = base;
        while (cursor < end && hits < 96)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t scanStart = regionBase < base ? base : regionBase;
            const std::uintptr_t scanEnd = regionEndRaw > end ? end : regionEndRaw;

            if (mbi.State == MEM_COMMIT &&
                IsExecutableProtect(mbi.Protect) &&
                scanEnd > scanStart)
            {
                __try
                {
                    const auto* p = reinterpret_cast<const unsigned char*>(scanStart);
                    const std::size_t size = static_cast<std::size_t>(scanEnd - scanStart);

                    for (std::size_t i = 0; i + 8 <= size && hits < 96; ++i)
                    {
                        std::size_t dispOff = 0;
                        std::size_t instLen = 0;

                        if ((p[i] == 0x48 || p[i] == 0x4C) &&
                            (p[i + 1] == 0x8B || p[i + 1] == 0x8D || p[i + 1] == 0x89) &&
                            (p[i + 2] & 0xC7) == 0x05)
                        {
                            dispOff = 3; instLen = 7;
                        }
                        else if ((p[i] == 0x80 || p[i] == 0x83) &&
                                 (p[i + 1] & 0xC7) == 0x3D)
                        {
                            dispOff = 2; instLen = 7;
                        }
                        else if (p[i] == 0x0F && p[i + 1] == 0xB6 &&
                                 (p[i + 2] & 0xC7) == 0x05)
                        {
                            dispOff = 3; instLen = 7;
                        }
                        else
                        {
                            continue;
                        }

                        const auto at = scanStart + i;
                        const auto dst = at + instLen +
                            *reinterpret_cast<const std::int32_t*>(at + dispOff);
                        if (dst != target) continue;

                        ++hits;
                        mw2019_diag::Log(
                            "[MAPPED-XREF] target=%s targetRva=0x%llX xrefRva=0x%llX protect=0x%08lX\r\n",
                            name ? name : "<unknown>",
                            static_cast<unsigned long long>(target - base),
                            static_cast<unsigned long long>(at - base),
                            mbi.Protect);
                        LogCodeWindow("MAPPED-XREF", at, base);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            if (regionEndRaw <= cursor) break;
            cursor = regionEndRaw;
        }

        mw2019_diag::Log("[MAPPED-XREF] target=%s hits=%u\r\n",
            name ? name : "<unknown>", hits);
    }



    bool GetRuntimeFunctionBounds(
        std::uintptr_t pc,
        std::uintptr_t& beginOut,
        std::uintptr_t& endOut) noexcept
    {
        beginOut = 0;
        endOut = 0;
        if (!pc)
            return false;

#if defined(_M_X64)
        DWORD64 imageBase = 0;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(
            static_cast<DWORD64>(pc),
            &imageBase,
            nullptr);

        if (!rf || !imageBase)
            return false;

        beginOut =
            static_cast<std::uintptr_t>(imageBase + rf->BeginAddress);
        endOut =
            static_cast<std::uintptr_t>(imageBase + rf->EndAddress);

        return beginOut &&
               endOut > beginOut &&
               pc >= beginOut &&
               pc < endOut;
#else
        return false;
#endif
    }

    void LogRuntimeFunctionMap(
        const char* tag,
        std::uintptr_t pc,
        bool dumpCalls) noexcept
    {
        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base || !pc)
            return;

        std::uintptr_t begin = 0;
        std::uintptr_t end = 0;
        if (!GetRuntimeFunctionBounds(pc, begin, end))
        {
            mw2019_diag::Log(
                "[FUNC-MAP] tag=%s pc=%p pcRva=0x%llX unwind=NONE\r\n",
                tag ? tag : "?",
                reinterpret_cast<void*>(pc),
                static_cast<unsigned long long>(pc - base));
            return;
        }

        const std::size_t size =
            static_cast<std::size_t>(end - begin);

        mw2019_diag::Log(
            "[FUNC-MAP] tag=%s pcRva=0x%llX beginRva=0x%llX endRva=0x%llX size=0x%zX\r\n",
            tag ? tag : "?",
            static_cast<unsigned long long>(pc - base),
            static_cast<unsigned long long>(begin - base),
            static_cast<unsigned long long>(end - base),
            size);

        LogCodeWindow("FUNC-BEGIN", begin, base);

        if (!dumpCalls || size == 0 || size > 0x20000)
            return;

        unsigned callIndex = 0;
        __try
        {
            for (std::uintptr_t at = begin;
                 at + 5 <= end && callIndex < 96;
                 ++at)
            {
                if (*reinterpret_cast<const unsigned char*>(at) != 0xE8)
                    continue;

                const auto rel =
                    *reinterpret_cast<const std::int32_t*>(at + 1);
                const std::uintptr_t target = at + 5 + rel;

                if (target < base ||
                    target >= base + 0x21679200ull)
                {
                    continue;
                }

                ++callIndex;
                mw2019_diag::Log(
                    "[FUNC-CALL] tag=%s index=%u callRva=0x%llX targetRva=0x%llX\r\n",
                    tag ? tag : "?",
                    callIndex,
                    static_cast<unsigned long long>(at - base),
                    static_cast<unsigned long long>(target - base));

                if (callIndex <= 24)
                    LogCodeWindow("FUNC-CALL-TARGET", target, base);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log(
                "[FUNC-CALL] tag=%s scan fault code=0x%08lX count=%u\r\n",
                tag ? tag : "?",
                GetExceptionCode(),
                callIndex);
        }
    }

    void LogBuild372MpDependencySnapshot() noexcept
    {
        static bool s_done = false;
        if (s_done ||
            !g_luaOpenLibRestoredAfterQuiet ||
            !g_arxanSafeDiagnosticHooksRestored)
        {
            return;
        }

        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return;

        s_done = true;
        mw2019_diag::Log(
            "[MP-DEPS] Build372 immediate READ-ONLY dependency snapshot BEGIN; all known diagnostic/menu game .text hooks are stock\r\n");
        mw2019_diag::Log(
            "[MP-DEPS] stock caller 0x347212A passes (ECX=controller, EDX=StatsSource, R8D=StatsGroup); RCX=0 means controller 0 and is expected\r\n");

        // These RVAs were proven against this exact Retail image by Build363/369.
        // RtlLookupFunctionEntry gives us the enclosing unwind function, then the
        // existing mapper records bounded direct E8 edges without modifying code.
        LogRuntimeFunctionMap("B372-stock-mp-caller", base + 0x347212Aull, true);
        LogRuntimeFunctionMap("B372-mp-first-fault", base + 0x43E5D70ull, true);
        LogRuntimeFunctionMap("B372-mp-first-fault-neighbor", base + 0x43E67C0ull, true);
        LogRuntimeFunctionMap("B372-mp-second-fault-thunk", base + 0x3AB45B0ull, true);
        LogRuntimeFunctionMap("B372-mp-second-fault-jump-target", base + 0x3713110ull, true);
        LogRuntimeFunctionMap("B372-stats-init-mp", base + 0x346F116ull, true);
        LogRuntimeFunctionMap("B372-playerdata-available", base + 0x346AEB3ull, true);

        LogCodeWindow("B372-MP-CALLSITE", base + 0x347212Aull, base);
        LogCodeWindow("B372-MP-FIRST-FAULT", base + 0x43E5D70ull, base);
        LogCodeWindow("B372-MP-FIRST-FAULT-NEIGHBOR", base + 0x43E67C0ull, base);
        LogCodeWindow("B372-MP-SECOND-FAULT", base + 0x3AB45B0ull, base);

        static const char* const names[] = {
            "CL_PlayerData_GetDDLBuffer",
            "GamerProfile_SetDataByName",
            "Live_IsUserSignedInToDemonware",
            "dwGetLogOnStatus",
            "CL_GetLocalClientSignInState",
            "unk_IsUserSignedInToBNet",
            "unk_SignInState",
            "unk_BNetClass",
        };

        for (const char* name : names)
        {
            Signature* sig = FindSignature(name);
            mw2019_diag::Log(
                "[MP-DEPS-SIG] %-32s %s address=%p rva=0x%llX\r\n",
                name,
                (sig && sig->address) ? "FOUND" : "MISSING",
                (sig && sig->address) ? reinterpret_cast<void*>(sig->address) : nullptr,
                (sig && sig->address)
                    ? static_cast<unsigned long long>(sig->address - base)
                    : 0ull);

            if (sig && sig->address &&
                (strcmp(name, "CL_PlayerData_GetDDLBuffer") == 0 ||
                 strcmp(name, "Live_IsUserSignedInToDemonware") == 0 ||
                 strcmp(name, "dwGetLogOnStatus") == 0))
            {
                LogRuntimeFunctionMap(name, sig->address, true);
            }
        }

        mw2019_diag::Log(
            "[MP-DEPS] Build372 immediate READ-ONLY dependency snapshot END\r\n");
    }

    struct Legacy120AnchorTarget
    {
        const char* name;
        const char* text;
        std::uintptr_t address;
        unsigned xrefs;
    };

    std::uintptr_t FindMappedAsciiAnchor(const char* needle) noexcept
    {
        if (!needle || !*needle)
            return 0;

        const std::size_t needleLen = strlen(needle);
        if (!needleLen)
            return 0;

        std::uintptr_t base = 0, end = 0;
        if (!GetMainImageRange(base, end))
            return 0;

        std::uintptr_t cursor = base;
        while (cursor < end)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t scanStart = regionBase < base ? base : regionBase;
            const std::uintptr_t scanEnd = regionEndRaw > end ? end : regionEndRaw;

            if (mbi.State == MEM_COMMIT &&
                IsReadable(mbi.Protect) &&
                scanEnd > scanStart &&
                static_cast<std::size_t>(scanEnd - scanStart) >= needleLen)
            {
                __try
                {
                    const auto* p = reinterpret_cast<const unsigned char*>(scanStart);
                    const std::size_t size =
                        static_cast<std::size_t>(scanEnd - scanStart);

                    const unsigned char first =
                        static_cast<unsigned char>(needle[0]);
                    std::size_t off = 0;
                    while (off + needleLen <= size)
                    {
                        const void* hit = memchr(p + off, first, size - off);
                        if (!hit)
                            break;

                        const auto* at =
                            static_cast<const unsigned char*>(hit);
                        const std::size_t index =
                            static_cast<std::size_t>(at - p);

                        if (index + needleLen <= size &&
                            memcmp(at, needle, needleLen) == 0)
                        {
                            return scanStart + index;
                        }

                        off = index + 1;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            if (regionEndRaw <= cursor)
                break;
            cursor = regionEndRaw;
        }

        return 0;
    }

    void ScanMappedExecXrefsToLegacy120Anchors(
        Legacy120AnchorTarget* targets,
        std::size_t targetCount) noexcept
    {
        if (!targets || !targetCount)
            return;

        std::uintptr_t base = 0, end = 0;
        if (!GetMainImageRange(base, end))
            return;

        std::uintptr_t cursor = base;
        while (cursor < end)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t scanStart = regionBase < base ? base : regionBase;
            const std::uintptr_t scanEnd = regionEndRaw > end ? end : regionEndRaw;

            if (mbi.State == MEM_COMMIT &&
                IsExecutableProtect(mbi.Protect) &&
                scanEnd > scanStart)
            {
                __try
                {
                    const auto* p =
                        reinterpret_cast<const unsigned char*>(scanStart);
                    const std::size_t size =
                        static_cast<std::size_t>(scanEnd - scanStart);

                    for (std::size_t i = 0; i + 8 <= size; ++i)
                    {
                        std::size_t dispOff = 0;
                        std::size_t instLen = 0;

                        // Common RIP-relative LEA/MOV forms used for strings/globals.
                        if ((p[i] == 0x48 || p[i] == 0x4C) &&
                            (p[i + 1] == 0x8B ||
                             p[i + 1] == 0x8D ||
                             p[i + 1] == 0x89) &&
                            (p[i + 2] & 0xC7) == 0x05)
                        {
                            dispOff = 3;
                            instLen = 7;
                        }
                        else if ((p[i] == 0x80 || p[i] == 0x83) &&
                                 (p[i + 1] & 0xC7) == 0x3D)
                        {
                            dispOff = 2;
                            instLen = 7;
                        }
                        else if (p[i] == 0x0F &&
                                 p[i + 1] == 0xB6 &&
                                 (p[i + 2] & 0xC7) == 0x05)
                        {
                            dispOff = 3;
                            instLen = 7;
                        }
                        else
                        {
                            continue;
                        }

                        const std::uintptr_t at = scanStart + i;
                        const std::uintptr_t dst =
                            at + instLen +
                            *reinterpret_cast<const std::int32_t*>(
                                at + dispOff);

                        for (std::size_t t = 0; t < targetCount; ++t)
                        {
                            if (!targets[t].address ||
                                dst != targets[t].address ||
                                targets[t].xrefs >= 32)
                            {
                                continue;
                            }

                            ++targets[t].xrefs;
                            mw2019_diag::Log(
                                "[1.20-ANCHOR-XREF] name=%s stringRva=0x%llX xref=%u xrefRva=0x%llX protect=0x%08lX\r\n",
                                targets[t].name,
                                static_cast<unsigned long long>(
                                    targets[t].address - base),
                                targets[t].xrefs,
                                static_cast<unsigned long long>(at - base),
                                mbi.Protect);
                            LogCodeWindow("1.20-ANCHOR-XREF", at, base);

                            char funcTag[96]{};
                            sprintf_s(
                                funcTag,
                                "%s-xref%u",
                                targets[t].name,
                                targets[t].xrefs);
                            LogRuntimeFunctionMap(
                                funcTag,
                                at,
                                targets[t].xrefs == 1);
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            if (regionEndRaw <= cursor)
                break;
            cursor = regionEndRaw;
        }

        for (std::size_t i = 0; i < targetCount; ++i)
        {
            mw2019_diag::Log(
                "[1.20-ANCHOR-SUMMARY] name=%s address=%p rva=0x%llX xrefs=%u\r\n",
                targets[i].name,
                reinterpret_cast<void*>(targets[i].address),
                targets[i].address && base
                    ? static_cast<unsigned long long>(
                        targets[i].address - base)
                    : 0ull,
                targets[i].xrefs);
        }
    }

    void LogLocalMpTransitionDirectCalls() noexcept
    {
        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return;

        // This is the stock Local-MP transition window seen in Build361.
        const std::uintptr_t start = base + 0x3472000ull;
        const std::uintptr_t end = base + 0x3472900ull;
        unsigned calls = 0;

        mw2019_diag::Log(
            "[MP-CALLMAP] scanning stock Local-MP transition rva=0x3472000..0x3472900\r\n");

        __try
        {
            for (std::uintptr_t at = start;
                 at + 5 <= end && calls < 96;
                 ++at)
            {
                if (*reinterpret_cast<const unsigned char*>(at) != 0xE8)
                    continue;

                const auto rel =
                    *reinterpret_cast<const std::int32_t*>(at + 1);
                const std::uintptr_t target = at + 5 + rel;

                if (target < base ||
                    target >= base + 0x21679200ull)
                {
                    continue;
                }

                ++calls;
                mw2019_diag::Log(
                    "[MP-CALLMAP] index=%u callRva=0x%llX targetRva=0x%llX\r\n",
                    calls,
                    static_cast<unsigned long long>(at - base),
                    static_cast<unsigned long long>(target - base));

                // Dump only a bounded number of windows so logging itself does not
                // starve the frontend.
                if (calls <= 40)
                    LogCodeWindow("MP-CALLMAP-TARGET", target, base);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log(
                "[MP-CALLMAP] scan fault code=0x%08lX after %u calls\r\n",
                GetExceptionCode(), calls);
        }

        mw2019_diag::Log("[MP-CALLMAP] complete calls=%u\r\n", calls);
    }

    void RunLegacy120StatsAnchorDiscovery() noexcept
    {
        if (g_legacy120StatsAnchorDiscoveryDone)
            return;

        g_legacy120StatsAnchorDiscoveryDone = true;

        mw2019_diag::Log(
            "[1.20-GUIDE] Build372 source-guided Retail stats/profile + unwind-function discovery BEGIN\r\n");
        mw2019_diag::Log(
            "[1.20-GUIDE] Build361 proved CL_PlayerData_GetDDLBuffer succeeds for OFFLINE groups 0..7; looking for the surrounding LiveStorage/profile initialization state\r\n");

        Legacy120AnchorTarget anchors[] = {
            {"playerdata_available",
             "playerdata_available", 0, 0},
            {"stats_init_mp",
             "exec mp/stats_init.cfg", 0, 0},
            {"stats_init_coop",
             "exec mp/stats_init_coop.cfg", 0, 0},
            {"stats_init_privatematch",
             "exec mp/stats_init_privatematch.cfg", 0, 0},
            {"mpdata",
             "mpdata", 0, 0},

            // Profile/login anchors from the older IW8 source/decomp. These let
            // us recover the CURRENT Retail profile-login function family from
            // strings instead of copying any old RVA.
            {"gamerprofile_login_timing",
             "GamerProfile_LogInProfile took %ims", 0, 0},
            {"controller_signed_in_local",
             "Controller #%i signed in locally from state %i", 0, 0},
            {"changing_platform_id",
             "Changing PlatformId(%u) from (%zu) to (%zu).", 0, 0},
            {"changing_platform_username",
             "Changing platform username(%u) from (%s) to (%s).", 0, 0},

            // LiveStorage/offline-playerdata state anchors.
            {"offline_stats_version",
             "Offline stats file version of %i differs from expected version of %i for controller %i; clearing stats", 0, 0},
            {"stats_read_finished",
             "LiveStorage_ReadStats_Platform - finished reading all stats groups", 0, 0},
            {"stats_bad_state",
             "Not saving stats: they're in a bad state (cont %i)", 0, 0},
            {"fresh_start_not_ready",
             "Cannot do fresh start because we have not downloaded stats or read them from a save device.", 0, 0},
            {"ensure_stats_online",
             "LiveStorage_EnsureWeHaveStats_Online() blocking on stats download.", 0, 0},
        };

        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));

        for (auto& anchor : anchors)
        {
            anchor.address = FindMappedAsciiAnchor(anchor.text);
            mw2019_diag::Log(
                "[1.20-ANCHOR] name=%s found=%d address=%p rva=0x%llX text='%s'\r\n",
                anchor.name,
                anchor.address ? 1 : 0,
                reinterpret_cast<void*>(anchor.address),
                anchor.address && base
                    ? static_cast<unsigned long long>(
                        anchor.address - base)
                    : 0ull,
                anchor.text);
        }

        // One executable-memory walk handles every anchor at once. This is much
        // cheaper than the old repeated full-image scans.
        ScanMappedExecXrefsToLegacy120Anchors(
            anchors, CountOf(anchors));

        // Map all direct calls in the exact Local-MP transition function family.
        LogLocalMpTransitionDirectCalls();

        // Use the x64 unwind metadata to establish whether our two crash RVAs
        // are normal functions, protected thunks, or PCs inside a larger function.
        const std::uintptr_t imageBase =
            reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (imageBase)
        {
            LogRuntimeFunctionMap("stock-mp-caller", imageBase + 0x347212Aull, true);
            LogRuntimeFunctionMap("mp-first-fault", imageBase + 0x43E5D70ull, true);
            LogRuntimeFunctionMap("mp-second-fault-thunk", imageBase + 0x3AB45B0ull, true);
            LogRuntimeFunctionMap("mp-second-fault-jump-target", imageBase + 0x3713110ull, true);
            LogRuntimeFunctionMap("stats-init-mp-xref-region", imageBase + 0x346F116ull, true);
            LogRuntimeFunctionMap("playerdata-available-xref-region", imageBase + 0x346AEB3ull, true);
        }

        // Explicitly record the known current Retail stats/profile entry points.
        static const char* const related[] = {
            "CL_PlayerData_GetDDLBuffer",
            "GamerProfile_SetDataByName",
            "Live_IsUserSignedInToDemonware",
            "dwGetLogOnStatus",
            "CL_GetLocalClientSignInState",
            "unk_IsUserSignedInToBNet",
            "unk_SignInState",
            "unk_BNetClass",
        };

        for (const char* name : related)
        {
            Signature* sig = FindSignature(name);
            mw2019_diag::Log(
                "[1.20-RELATION] %-32s %s address=%p rva=0x%llX\r\n",
                name,
                (sig && sig->address) ? "FOUND" : "MISSING",
                (sig && sig->address)
                    ? reinterpret_cast<void*>(sig->address)
                    : nullptr,
                (sig && sig->address && base)
                    ? static_cast<unsigned long long>(
                        sig->address - base)
                    : 0ull);
        }

        mw2019_diag::Log(
            "[1.20-GUIDE] Build372 discovery END; old absolute addresses were NOT used or called\r\n");
    }

    void ScanMappedConstant(const char* name, const void* needle, std::size_t needleSize) noexcept
    {
        if (!needle || !needleSize) return;

        std::uintptr_t base = 0, end = 0;
        if (!GetMainImageRange(base, end)) return;

        unsigned hits = 0;
        std::uintptr_t cursor = base;
        while (cursor < end && hits < 64)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t scanStart = regionBase < base ? base : regionBase;
            const std::uintptr_t scanEnd = regionEndRaw > end ? end : regionEndRaw;

            if (mbi.State == MEM_COMMIT &&
                IsReadable(mbi.Protect) &&
                scanEnd > scanStart &&
                static_cast<std::size_t>(scanEnd - scanStart) >= needleSize)
            {
                __try
                {
                    const auto* p = reinterpret_cast<const unsigned char*>(scanStart);
                    const std::size_t size = static_cast<std::size_t>(scanEnd - scanStart);
                    for (std::size_t i = 0; i + needleSize <= size && hits < 64; ++i)
                    {
                        if (memcmp(p + i, needle, needleSize) != 0) continue;
                        ++hits;
                        const auto at = scanStart + i;
                        mw2019_diag::Log(
                            "[MAPPED-CONST] name=%s hit=%u rva=0x%llX protect=0x%08lX\r\n",
                            name ? name : "<unknown>", hits,
                            static_cast<unsigned long long>(at - base),
                            mbi.Protect);
                        if (IsExecutableProtect(mbi.Protect))
                            LogCodeWindow("MAPPED-CONST", at, base);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            if (regionEndRaw <= cursor) break;
            cursor = regionEndRaw;
        }

        mw2019_diag::Log("[MAPPED-CONST] name=%s total=%u\r\n",
            name ? name : "<unknown>", hits);
    }

    void DumpIdentityNeighborhood() noexcept
    {
        Signature* xuid = FindSignature("unk_XUIDCheck1");
        if (!xuid || !xuid->address) return;

        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        mw2019_diag::Log("[IDENTITY-NEIGHBORHOOD] centerRva=0x%llX center=%p\r\n",
            static_cast<unsigned long long>(xuid->address - base),
            reinterpret_cast<void*>(xuid->address));

        __try
        {
            const auto start = xuid->address - 0x100;
            for (std::size_t off = 0; off < 0x200; off += 0x20)
            {
                const auto* q = reinterpret_cast<const std::uint64_t*>(start + off);
                mw2019_diag::Log(
                    "[IDENTITY-QWORD] rva=0x%llX %016llX %016llX %016llX %016llX\r\n",
                    static_cast<unsigned long long>(start + off - base),
                    static_cast<unsigned long long>(q[0]),
                    static_cast<unsigned long long>(q[1]),
                    static_cast<unsigned long long>(q[2]),
                    static_cast<unsigned long long>(q[3]));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log("[IDENTITY-NEIGHBORHOOD] read fault code=0x%08lX\r\n",
                GetExceptionCode());
        }
    }

    bool IsAddressInMainImage(std::uintptr_t address) noexcept
    {
        std::uintptr_t base = 0, end = 0;
        return GetMainImageRange(base, end) && address >= base && address < end;
    }

    void AnalyzeLuaWrapperDirectTargets(const CapturedLuaWrapper& wrapper) noexcept
    {
        if (!wrapper.original || !IsAddressInMainImage(wrapper.original))
            return;

        std::uintptr_t base = 0, end = 0;
        if (!GetMainImageRange(base, end))
            return;

        mw2019_diag::Log(
            "[LUA-AUTH-ANALYZE] wrapper=%s obfuscated=%s rva=0x%llX BEGIN\r\n",
            wrapper.friendlyName, wrapper.obfuscatedName,
            static_cast<unsigned long long>(wrapper.original - base));
        LogCodeWindow("LUA-AUTH-WRAPPER", wrapper.original, base);

        unsigned calls = 0;
        unsigned globals = 0;
        __try
        {
            const auto* p = reinterpret_cast<const unsigned char*>(wrapper.original);
            constexpr std::size_t kWindow = 0x280;
            for (std::size_t i = 0; i + 8 <= kWindow; ++i)
            {
                const auto at = wrapper.original + i;

                if (p[i] == 0xE8)
                {
                    const auto dst = at + 5 + *reinterpret_cast<const std::int32_t*>(at + 1);
                    if (dst >= base && dst < end)
                    {
                        ++calls;
                        mw2019_diag::Log(
                            "[LUA-AUTH-CALL] wrapper=%s callRva=0x%llX targetRva=0x%llX target=%p\r\n",
                            wrapper.friendlyName,
                            static_cast<unsigned long long>(at - base),
                            static_cast<unsigned long long>(dst - base),
                            reinterpret_cast<void*>(dst));
                        LogCodeWindow("LUA-AUTH-CALLEE", dst, base);

                        // In the 1.44 source CL_GetLocalClientSignInState and
                        // unk_IsUserSignedInToBNet were exactly 0x20 bytes apart.
                        // Do not patch this guess; simply log the neighbor as a high-value
                        // current-Retail candidate for the next comparison.
                        const auto plus20 = dst + 0x20;
                        if (plus20 < end)
                        {
                            mw2019_diag::Log(
                                "[AUTH-PAIR-CANDIDATE] wrapper=%s baseTargetRva=0x%llX neighborPlus20Rva=0x%llX\r\n",
                                wrapper.friendlyName,
                                static_cast<unsigned long long>(dst - base),
                                static_cast<unsigned long long>(plus20 - base));
                            LogCodeWindow("AUTH-PAIR-PLUS20", plus20, base);
                        }
                    }
                    continue;
                }

                std::size_t dispOff = 0;
                std::size_t instLen = 0;
                if ((p[i] == 0x48 || p[i] == 0x4C) &&
                    (p[i + 1] == 0x8B || p[i + 1] == 0x8D || p[i + 1] == 0x89) &&
                    (p[i + 2] & 0xC7) == 0x05)
                {
                    dispOff = 3; instLen = 7;
                }
                else if ((p[i] == 0x80 || p[i] == 0x83 || p[i] == 0xC6) &&
                         (p[i + 1] & 0xC7) == 0x05)
                {
                    dispOff = 2; instLen = 7;
                }
                else if (p[i] == 0x0F && p[i + 1] == 0xB6 &&
                         (p[i + 2] & 0xC7) == 0x05)
                {
                    dispOff = 3; instLen = 7;
                }
                else
                {
                    continue;
                }

                const auto dst = at + instLen + *reinterpret_cast<const std::int32_t*>(at + dispOff);
                if (dst >= base && dst < end)
                {
                    ++globals;
                    mw2019_diag::Log(
                        "[LUA-AUTH-GLOBAL] wrapper=%s insnRva=0x%llX targetRva=0x%llX target=%p\r\n",
                        wrapper.friendlyName,
                        static_cast<unsigned long long>(at - base),
                        static_cast<unsigned long long>(dst - base),
                        reinterpret_cast<void*>(dst));
                    __try
                    {
                        const auto q0 = *reinterpret_cast<const std::uint64_t*>(dst);
                        const auto q1 = *reinterpret_cast<const std::uint64_t*>(dst + 8);
                        mw2019_diag::Log(
                            "[LUA-AUTH-GLOBAL-VALUE] wrapper=%s targetRva=0x%llX q0=%016llX q1=%016llX\r\n",
                            wrapper.friendlyName,
                            static_cast<unsigned long long>(dst - base),
                            static_cast<unsigned long long>(q0),
                            static_cast<unsigned long long>(q1));
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log(
                "[LUA-AUTH-ANALYZE] wrapper=%s guarded fault code=0x%08lX\r\n",
                wrapper.friendlyName, GetExceptionCode());
        }

        mw2019_diag::Log(
            "[LUA-AUTH-ANALYZE] wrapper=%s calls=%u globals=%u END\r\n",
            wrapper.friendlyName, calls, globals);
    }

    bool HaveCoreCapturedAuthWrappers() noexcept
    {
        bool authReady = false;
        bool connected = false;
        bool lanOnly = false;
        for (const auto& wrapper : g_capturedLuaWrappers)
        {
            if (!wrapper.original) continue;
            if (_stricmp(wrapper.friendlyName, "IsBattleNetAuthReady") == 0) authReady = true;
            if (_stricmp(wrapper.friendlyName, "IsConnectedToGameServer") == 0) connected = true;
            if (_stricmp(wrapper.friendlyName, "IsBattleNetLanOnly") == 0) lanOnly = true;
        }
        return authReady && connected && lanOnly;
    }

    void RunLuaWrapperAuthDiscovery() noexcept
    {
        if (g_luaWrapperDiscoveryDone || !HaveCoreCapturedAuthWrappers())
            return;

        g_luaWrapperDiscoveryDone = true;
        mw2019_diag::Log(
            "[LUA-AUTH-DISCOVERY] Build356 lightweight current-Retail wrapper analysis BEGIN\r\n");

        for (const auto& wrapper : g_capturedLuaWrappers)
        {
            if (!wrapper.original) continue;
            // These are the highest-value wrappers from the old AddressBook relationship.
            if (_stricmp(wrapper.friendlyName, "IsBattleNetAuthReady") == 0 ||
                _stricmp(wrapper.friendlyName, "IsBattleNetLanOnly") == 0 ||
                _stricmp(wrapper.friendlyName, "IsConnectedToGameServer") == 0 ||
                _stricmp(wrapper.friendlyName, "IsGameModeAllowed") == 0 ||
                _stricmp(wrapper.friendlyName, "IsGameModeAvailable") == 0)
            {
                AnalyzeLuaWrapperDirectTargets(wrapper);
                // Build356 menu-first: do NOT sweep the whole executable here.
                // The direct wrapper targets are the useful old-source relationship,
                // while full-image caller scans delayed the first offline-menu dvar pass.
            }
        }

        mw2019_diag::Log(
            "[LUA-AUTH-DISCOVERY] Build356 lightweight wrapper analysis END; no derived candidate was patched\r\n");
    }

    void RunDeepAuthDiscovery() noexcept
    {
        if (g_deepDiscoveryDone)
            return;
        g_deepDiscoveryDone = true;

        mw2019_diag::Log("[DEEP] Build355 mapped-runtime auth/profile discovery BEGIN\r\n");

        const char* const callTargets[] = {
            "Live_IsUserSignedInToDemonware",
            "dwGetLogOnStatus",
            "GamerProfile_SetDataByName",
            "DB_FindXAssetHeader"
        };
        for (const char* name : callTargets)
        {
            Signature* sig = FindSignature(name);
            if (sig && sig->address)
                ScanCallsitesTo(name, sig->address);
        }

        const char* const dataTargets[] = {
            "unk_XUIDCheck1",
            "s_isContentEnumerationFinished",
            "LUI_luaVM",
            "s_luaInFrontend"
        };
        for (const char* name : dataTargets)
        {
            Signature* sig = FindSignature(name);
            if (sig && sig->address)
                ScanRipXrefsTo(name, sig->address);
        }

        // Build354: PE section flags are unreliable for IW8's unpacked/Arxan runtime
        // pages. Repeat discovery over the actual committed executable mappings.
        for (const char* name : callTargets)
        {
            Signature* sig = FindSignature(name);
            if (sig && sig->address)
                ScanMappedExecCallsitesTo(name, sig->address);
        }

        for (const char* name : dataTargets)
        {
            Signature* sig = FindSignature(name);
            if (sig && sig->address)
                ScanMappedRipXrefsTo(name, sig->address);
        }

        const auto runtimeBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (runtimeBase)
        {
            // The reproducible Local-MP fault is called directly from 0x347212A.
            // Find every current-runtime caller rather than assuming that is the only one.
            ScanMappedExecCallsitesTo("LocalMP_crash_target_43E5D70",
                runtimeBase + 0x43E5D70ull);
        }

        constexpr std::uint32_t kBnetMagic = 0x795230F0u;
        constexpr std::uint64_t kXuidMagic = 0x11CB1243B8D7C31Eull;
        ScanMappedConstant("BNetAuthMagic_795230F0", &kBnetMagic, sizeof(kBnetMagic));
        ScanMappedConstant("GuardedXuidMagic_11CB1243B8D7C31E", &kXuidMagic, sizeof(kXuidMagic));
        DumpIdentityNeighborhood();

        ScanBNetAuthMagic();

        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (base)
        {
            static const std::uintptr_t kCrashNeighborhoods[] = {
                0x43E5D70ull, 0x43E67C0ull, 0x347212Full, 0x34726D5ull,
                0x3472712ull, 0x2C1868Eull, 0x2DBA1A4ull, 0x3262480ull
            };
            for (const auto rva : kCrashNeighborhoods)
                LogCodeWindow("CRASH-PATH", base + rva, base);

            // Wider caller context around the exact rel32 call at 0x347212A.
            static const std::uintptr_t kCallerWindows[] = {
                0x3472080ull, 0x34720E0ull, 0x3472140ull, 0x34721A0ull
            };
            for (const auto rva : kCallerWindows)
                LogCodeWindow("LOCALMP-CALLER-WIDE", base + rva, base);
        }

        mw2019_diag::Log("[DEEP] Build355 mapped-runtime auth/profile discovery END\r\n");
    }


    bool IsCurrentRetailSteamImage() noexcept
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return false;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

            // Exact fingerprint from the working Retail Steam test supplied with Build343.
            return nt->FileHeader.TimeDateStamp == 0x69DD404E &&
                   nt->OptionalHeader.SizeOfImage == 0x21679200;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    Signature* FindSignature(const char* name) noexcept
    {
        if (!name) return nullptr;
        for (auto& sig : g_signatures)
            if (_stricmp(sig.name, name) == 0) return &sig;
        return nullptr;
    }

    bool PatchReturnEax(const char* name, std::uint32_t value) noexcept
    {
        Signature* sig = FindSignature(name);
        if (!sig || !sig->address) return false;

        const unsigned char patch[6] = {
            0xB8,
            static_cast<unsigned char>(value & 0xFF),
            static_cast<unsigned char>((value >> 8) & 0xFF),
            static_cast<unsigned char>((value >> 16) & 0xFF),
            static_cast<unsigned char>((value >> 24) & 0xFF),
            0xC3
        };

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(sig->address), sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            mw2019_diag::Log("[MENU-PATCH] VirtualProtect failed target=%s address=%p error=%lu\r\n",
                name, reinterpret_cast<void*>(sig->address), GetLastError());
            return false;
        }

        __try
        {
            memcpy(reinterpret_cast<void*>(sig->address), patch, sizeof(patch));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DWORD ignored = 0;
            VirtualProtect(reinterpret_cast<void*>(sig->address), sizeof(patch), oldProtect, &ignored);
            mw2019_diag::Log("[MENU-PATCH] write fault target=%s address=%p code=0x%08lX\r\n",
                name, reinterpret_cast<void*>(sig->address), GetExceptionCode());
            return false;
        }

        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(sig->address), sizeof(patch));
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(sig->address), sizeof(patch), oldProtect, &ignored);

        mw2019_diag::Log("[MENU-PATCH] %s => return %u address=%p\r\n",
            name, value, reinterpret_cast<void*>(sig->address));
        return true;
    }

    struct DvarBoolView
    {
        const char* name;               // 0x00
        std::uint32_t checksum;         // 0x08
        std::uint32_t pad0C;            // 0x0C
        const char* description;        // 0x10
        std::uint32_t flags;            // 0x18
        std::uint8_t level;             // 0x1C
        std::uint8_t type;              // 0x1D
        bool modified;                  // 0x1E
        std::uint8_t pad1F;             // 0x1F
        std::uint16_t hashNext;         // 0x20
        std::uint8_t pad22[6];          // 0x22
        union { bool enabled; std::uint64_t qword; } current; // 0x28
        std::uint8_t currentPad[8];      // 0x30
        union { bool enabled; std::uint64_t qword; } latched; // 0x38
        std::uint8_t latchedPad[8];      // 0x40
        union { bool enabled; std::uint64_t qword; } reset;   // 0x48
    };

    bool SetBoolDvar(const char* obfuscatedName, const char* friendlyName, bool value) noexcept
    {
        Signature* findSig = FindSignature("Dvar_FindVarByName");
        if (!findSig || !findSig->address || !obfuscatedName) return false;

        using FindFn = void* (*)(const char*);
        auto fn = reinterpret_cast<FindFn>(findSig->address);
        void* raw = nullptr;
        __try
        {
            raw = fn(obfuscatedName);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log("[DVAR] lookup fault name=%s code=0x%08lX\r\n",
                friendlyName ? friendlyName : obfuscatedName, GetExceptionCode());
            return false;
        }

        if (!raw) return false;

        auto* dvar = reinterpret_cast<DvarBoolView*>(raw);
        __try
        {
            dvar->current.enabled = value;
            dvar->latched.enabled = value;
            dvar->reset.enabled = value;
            dvar->modified = true;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log("[DVAR] write fault name=%s ptr=%p code=0x%08lX\r\n",
                friendlyName ? friendlyName : obfuscatedName, raw, GetExceptionCode());
            return false;
        }
    }


    void LogBoolDvarState(const char* obfuscatedName, const char* friendlyName) noexcept
    {
        Signature* findSig = FindSignature("Dvar_FindVarByName");
        if (!findSig || !findSig->address || !obfuscatedName)
            return;

        using FindFn = void* (*)(const char*);
        auto fn = reinterpret_cast<FindFn>(findSig->address);
        void* raw = nullptr;
        __try { raw = fn(obfuscatedName); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log("[MP-STATE-DVAR] %s lookup fault code=0x%08lX\r\n",
                friendlyName ? friendlyName : obfuscatedName, GetExceptionCode());
            return;
        }

        if (!raw)
        {
            mw2019_diag::Log("[MP-STATE-DVAR] %-28s key=%s MISSING\r\n",
                friendlyName ? friendlyName : obfuscatedName, obfuscatedName);
            return;
        }

        __try
        {
            auto* dvar = reinterpret_cast<DvarBoolView*>(raw);
            mw2019_diag::Log(
                "[MP-STATE-DVAR] %-28s key=%s ptr=%p current=%d latched=%d reset=%d modified=%d type=%u flags=0x%08X\r\n",
                friendlyName ? friendlyName : obfuscatedName,
                obfuscatedName, raw,
                dvar->current.enabled ? 1 : 0,
                dvar->latched.enabled ? 1 : 0,
                dvar->reset.enabled ? 1 : 0,
                dvar->modified ? 1 : 0,
                static_cast<unsigned>(dvar->type),
                dvar->flags);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            mw2019_diag::Log("[MP-STATE-DVAR] %s read fault ptr=%p code=0x%08lX\r\n",
                friendlyName ? friendlyName : obfuscatedName, raw, GetExceptionCode());
        }
    }

    void LogMPStateSnapshot(unsigned long long uptimeMs) noexcept
    {
        if (!IsCurrentRetailSteamImage() || g_dvarPasses < 1)
            return;
        if (g_mpStateSnapshotCount >= 12)
            return;
        if (g_lastMpStateSnapshot && uptimeMs - g_lastMpStateSnapshot < 5000)
            return;

        g_lastMpStateSnapshot = uptimeMs;
        ++g_mpStateSnapshotCount;

        void* luaVm = nullptr;
        int frontend = -1;
        int contentFinished = -1;
        std::uint64_t xuidGuard = 0;

        Signature* luaVmSig = FindSignature("LUI_luaVM");
        Signature* frontendSig = FindSignature("s_luaInFrontend");
        Signature* contentSig = FindSignature("s_isContentEnumerationFinished");
        Signature* xuidSig = FindSignature("unk_XUIDCheck1");

        if (luaVmSig && luaVmSig->address)
        {
            __try { luaVm = *reinterpret_cast<void**>(luaVmSig->address); }
            __except (EXCEPTION_EXECUTE_HANDLER) { luaVm = nullptr; }
        }
        if (frontendSig && frontendSig->address)
        {
            __try { frontend = *reinterpret_cast<const unsigned char*>(frontendSig->address) ? 1 : 0; }
            __except (EXCEPTION_EXECUTE_HANDLER) { frontend = -1; }
        }
        if (contentSig && contentSig->address)
        {
            __try { contentFinished = *reinterpret_cast<const unsigned char*>(contentSig->address) ? 1 : 0; }
            __except (EXCEPTION_EXECUTE_HANDLER) { contentFinished = -1; }
        }
        if (xuidSig && xuidSig->address)
        {
            __try { xuidGuard = *reinterpret_cast<const std::uint64_t*>(xuidSig->address); }
            __except (EXCEPTION_EXECUTE_HANDLER) { xuidGuard = 0; }
        }

        int dwSignedIn = -1;
        int dwStatus = -1;
        Signature* live = FindSignature("Live_IsUserSignedInToDemonware");
        if (live && live->address)
        {
            using LiveFn = bool (*)(int);
            __try { dwSignedIn = reinterpret_cast<LiveFn>(live->address)(0) ? 1 : 0; }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                dwSignedIn = -2;
                mw2019_diag::Log("[MP-STATE] Live_IsUserSignedInToDemonware probe fault code=0x%08lX\r\n",
                    GetExceptionCode());
            }
        }

        Signature* logon = FindSignature("dwGetLogOnStatus");
        if (logon && logon->address)
        {
            using LogonFn = int (*)(int);
            __try { dwStatus = reinterpret_cast<LogonFn>(logon->address)(0); }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                dwStatus = -2;
                mw2019_diag::Log("[MP-STATE] dwGetLogOnStatus probe fault code=0x%08lX\r\n",
                    GetExceptionCode());
            }
        }

        if (g_mpStateSnapshotCount == 1)
        {
            static const char* const prereqNames[] = {
                "GamerProfile_SetDataByName",
                "CL_PlayerData_GetDDLBuffer",
                "CL_GetLocalClientSignInState",
                "Live_IsUserSignedInToDemonware",
                "dwGetLogOnStatus",
                "unk_BNetClass",
                "unk_IsUserSignedInToBNet",
                "unk_SignInState",
                "s_isContentEnumerationFinished",
                "unk_XUIDCheck1"
            };
            for (const char* name : prereqNames)
            {
                Signature* sig = FindSignature(name);
                mw2019_diag::Log(
                    "[MP-PREREQ-SIG] %-32s %s address=%p\r\n",
                    name,
                    (sig && sig->address) ? "FOUND" : "MISSING",
                    (sig && sig->address) ? reinterpret_cast<void*>(sig->address) : nullptr);
            }
        }

        mw2019_diag::Log(
            "[MP-STATE] snapshot=%u uptimeMs=%llu luaVM=%p frontend=%d contentFinished=%d xuidGuard=%016llX dwSignedIn=%d dwStatus=%d ddlHook=%d ddlCalls=%ld diagnosticCleanup=%d\r\n",
            g_mpStateSnapshotCount, uptimeMs, luaVm, frontend, contentFinished,
            static_cast<unsigned long long>(xuidGuard), dwSignedIn, dwStatus,
            g_ddlTraceHookInstalled ? 1 : 0, g_ddlTraceCount,
            g_arxanSafeDiagnosticHooksRestored ? 1 : 0);

        for (int group = 0; group < 8; ++group)
        {
            mw2019_diag::Log(
                "[MP-STATE-DDL] source=OFFLINE(1) group=%d calls=%ld success=%ld fail=%ld\r\n",
                group,
                g_ddlOfflineGroupCalls[group],
                g_ddlOfflineGroupSuccess[group],
                g_ddlOfflineGroupCalls[group] - g_ddlOfflineGroupSuccess[group]);
        }

        static const struct { const char* key; const char* name; } dvars[] = {
            {"MPSSOTQQPM", "force_offline_enabled"},
            {"LSTQOKLTRN", "force_offline_menus"},
            {"LMMRONPQMO", "lui_force_online_menus"},
            {"MTSTMKPMRM", "ui_onlineRequired"},
            {"RLSPOOTTT", "com_checkIfGameModeInstalled"},
            {"MROLPRPTPO", "com_force_premium"},
            {"LPNMMPKRL", "com_lan_lobby_enabled"},
            {"LTOQRQMMLQ", "online_lan_cross_play"},
            {"MLNMPQOON", "cg_viewedSplashScreen"},
        };
        for (const auto& d : dvars)
            LogBoolDvarState(d.key, d.name);

        if (!g_identitySnapshotDumped)
        {
            g_identitySnapshotDumped = true;
            DumpIdentityNeighborhood();
        }

        if (!g_crashPathSnapshotDumped)
        {
            g_crashPathSnapshotDumped = true;
            const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            if (base)
            {
                static const std::uintptr_t paths[] = {
                    0x43E1F10ull,
                    0x43E5D70ull,
                    0x43E67C0ull,
                    0x347212Aull,
                    0x3472771ull,
                    0x3AB45B0ull,
                    0x3713110ull,
                    0x2DBA1A4ull,
                    0x3262480ull,
                };
                for (const auto rva : paths)
                    LogCodeWindow("MP-PIPELINE", base + rva, base);
            }
        }
    }


    void ApplyKnownLocalIdentityPrereqs() noexcept
    {
        if (!IsCurrentRetailSteamImage())
            return;

        bool changed = false;
        Signature* content = FindSignature("s_isContentEnumerationFinished");
        Signature* xuidCheck = FindSignature("unk_XUIDCheck1");

        if (content && content->address)
        {
            __try
            {
                auto* value = reinterpret_cast<unsigned char*>(content->address);
                if (*value == 0)
                {
                    *value = 1;
                    changed = true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (xuidCheck && xuidCheck->address)
        {
            constexpr std::uint64_t kLocalXuid = 0x12345678ull;
            constexpr std::uint64_t kXuidMagic = 0x11CB1243B8D7C31Eull;
            constexpr std::uint64_t kGuardedXuid = kXuidMagic | (kLocalXuid * kLocalXuid);

            __try
            {
                auto* value = reinterpret_cast<std::uint64_t*>(xuidCheck->address);
                if (*value != kGuardedXuid)
                {
                    *value = kGuardedXuid;
                    changed = true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (!g_identityPrereqsLogged &&
            ((content && content->address) || (xuidCheck && xuidCheck->address)))
        {
            g_identityPrereqsLogged = true;
        }
        (void)changed;
    }


    void ApplyKnownProfilePrereqs() noexcept
    {
        if (!IsCurrentRetailSteamImage())
            return;

        Signature* profileSig = FindSignature("GamerProfile_SetDataByName");
        if (!profileSig || !profileSig->address)
            return;

        using SetProfileFn = void (*)(int, const char*, float);
        auto fn = reinterpret_cast<SetProfileFn>(profileSig->address);

        bool ok = true;
        __try
        {
            fn(0, "acceptedEULA", 1.0f);
            fn(0, "hasEverPlayed_MainMenu", 1.0f);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = false;
            mw2019_diag::Log(
                "[PROFILE] GamerProfile_SetDataByName fault address=%p code=0x%08lX\r\n",
                reinterpret_cast<void*>(profileSig->address),
                GetExceptionCode());
        }

        if (!g_profilePrereqsLogged)
            g_profilePrereqsLogged = true;
        (void)ok;
    }

    void ApplyOfflineFrontendState(unsigned long long uptimeMs) noexcept
    {
        // Build345: Build344 proved that blindly returning DW_LIVE_CONNECTED while all
        // external endpoints are blocked can leave IW8 in a contradictory auth state.
        // Keep network isolation, but route the UI through the game's own demo/LAN Lua
        // gates exactly like the older working IW8 client did.
        if (!IsCurrentRetailSteamImage())
        {
            if (!g_buildGateLogged && uptimeMs >= 12000)
            {
                g_buildGateLogged = true;
                mw2019_diag::Log("[MENU-PATCH] exact Retail Steam fingerprint not matched; menu writes DISABLED\r\n");
            }
            return;
        }

        if (uptimeMs >= 10000)
        {
            // luaL_openlib must stay active because Retail can re-register the
            // Engine table later. Build367 proved removing it regresses back to
            // Connecting to Online Services.
            if (!g_luaOpenLibRestoredAfterQuiet)
                InstallLuaMenuHook();

            // Build374 keeps LUI_OpenMenu and CL_PlayerData_GetDDLBuffer stock.
            ApplyKnownLocalIdentityPrereqs();
        }

        void* luaVmValue = nullptr;
        Signature* luaVmSig = FindSignature("LUI_luaVM");
        if (luaVmSig && luaVmSig->address)
        {
            __try { luaVmValue = *reinterpret_cast<void**>(luaVmSig->address); }
            __except (EXCEPTION_EXECUTE_HANDLER) { luaVmValue = nullptr; }
        }

        // Do not mutate dvars until the LUI VM is alive. Build344 was changing state while
        // the frontend was still booting. Once live, apply the known offline selectors
        // conservatively and only a handful of times.
        if (!luaVmValue)
            return;

        ApplyKnownProfilePrereqs();

        if (g_dvarPasses >= 6)
            return;
        if (g_lastDvarPass && uptimeMs - g_lastDvarPass < 10000)
            return;

        g_lastDvarPass = uptimeMs;
        ++g_dvarPasses;
        if (!g_firstOfflineDvarPassAt)
            g_firstOfflineDvarPassAt = uptimeMs;

        unsigned found = 0;
        found += SetBoolDvar("MPSSOTQQPM", "force_offline_enabled", true) ? 1u : 0u;
        found += SetBoolDvar("LSTQOKLTRN", "force_offline_menus", true) ? 1u : 0u;
        found += SetBoolDvar("LMMRONPQMO", "lui_force_online_menus", false) ? 1u : 0u;
        found += SetBoolDvar("MTSTMKPMRM", "ui_onlineRequired", false) ? 1u : 0u;
        found += SetBoolDvar("RLSPOOTTT", "com_checkIfGameModeInstalled", false) ? 1u : 0u;
        found += SetBoolDvar("MROLPRPTPO", "com_force_premium", true) ? 1u : 0u;
        found += SetBoolDvar("LPNMMPKRL", "com_lan_lobby_enabled", true) ? 1u : 0u;
        found += SetBoolDvar("LTOQRQMMLQ", "online_lan_cross_play", true) ? 1u : 0u;

        (void)found;
    }

    bool Build383FrontendSelectorsReady() noexcept
    {
        if (!IsCurrentRetailSteamImage())
            return false;

        Signature* findSig = FindSignature("Dvar_FindVarByName");
        using FindFn = void* (*)(const char*);
        FindFn findFn = (findSig && findSig->address)
            ? reinterpret_cast<FindFn>(findSig->address)
            : nullptr;
        if (!findFn)
            return false;

        struct RequiredBool
        {
            const char* key;
            bool expected;
        };

        static const RequiredBool required[] = {
            {"MPSSOTQQPM", true},   // force_offline_enabled
            {"LSTQOKLTRN", true},   // force_offline_menus
            {"LMMRONPQMO", false},  // lui_force_online_menus
            {"MTSTMKPMRM", false},  // ui_onlineRequired
            {"RLSPOOTTT", false},   // com_checkIfGameModeInstalled
            {"LPNMMPKRL", true},    // com_lan_lobby_enabled
            {"LTOQRQMMLQ", true},   // online_lan_cross_play
            {"MLNMPQOON", false},   // cg_viewedSplashScreen: preserve normal splash
        };

        for (const auto& item : required)
        {
            void* raw = nullptr;
            __try { raw = findFn(item.key); }
            __except (EXCEPTION_EXECUTE_HANDLER) { raw = nullptr; }
            if (!raw)
                return false;

            bool current = false;
            __try { current = reinterpret_cast<DvarBoolView*>(raw)->current.enabled; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
            if (current != item.expected)
                return false;
        }

        return true;
    }

    void Build379AuditCfgAndFrontendState(void* luaVm) noexcept
    {
        if (g_build379CfgAuditDone || !luaVm || !IsCurrentRetailSteamImage())
            return;

        g_build379CfgAuditDone = true;
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));

        struct CfgEntry
        {
            const char* name;
            const char* command;
        };

        static const CfgEntry cfgs[] = {
            {"stats_init_mp",           "exec mp/stats_init.cfg"},
            {"stats_init_coop",         "exec mp/stats_init_coop.cfg"},
            {"stats_init_privatematch", "exec mp/stats_init_privatematch.cfg"},
        };

        mw2019_diag::Log("[CFG] one-shot Retail CFG audit BEGIN\r\n");
        for (const auto& cfg : cfgs)
        {
            const auto anchor = FindMappedAsciiAnchor(cfg.command);
            mw2019_diag::Log(
                "[CFG] %-24s asset-ref=%s rva=0x%llX command='%s'\r\n",
                cfg.name,
                anchor ? "FOUND" : "MISSING",
                static_cast<unsigned long long>((anchor && base) ? (anchor - base) : 0ull),
                cfg.command);

            // Build382: READ-ONLY audit. Do NOT execute stats_init*.cfg here.
            // Build379 proved those execs mutate frontend selectors during startup
            // (ui_onlineRequired/lui_force_online_menus/etc.) and regress the
            // previously working Build374 MP menu path back into Connecting to
            // Online Services. Presence of the Retail command/asset reference is
            // all this audit is allowed to verify.
            mw2019_diag::Log(
                "[CFG] %-24s audit=%s (read-only; not executed)\r\n",
                cfg.name,
                anchor ? "OK" : "MISSING");
        }

        struct BoolAudit
        {
            const char* key;
            const char* name;
            int expected; // -1 = informational only
        };

        // These are the known frontend/local selectors we have been tracking on
        // CURRENT Retail. Audit once; do not rewrite them here.
        static const BoolAudit dvars[] = {
            {"MPSSOTQQPM", "force_offline_enabled",        -1},
            {"LSTQOKLTRN", "force_offline_menus",          -1},
            {"LMMRONPQMO", "lui_force_online_menus",       -1},
            {"MTSTMKPMRM", "ui_onlineRequired",            -1},
            {"RLSPOOTTT", "com_checkIfGameModeInstalled", -1},
            {"MROLPRPTPO", "com_force_premium",            -1},
            {"LPNMMPKRL", "com_lan_lobby_enabled",         1},
            {"LTOQRQMMLQ", "online_lan_cross_play",        1},
            {"MLNMPQOON", "cg_viewedSplashScreen",         0},
        };

        Signature* findSig = FindSignature("Dvar_FindVarByName");
        using FindFn = void* (*)(const char*);
        FindFn findFn = (findSig && findSig->address)
            ? reinterpret_cast<FindFn>(findSig->address)
            : nullptr;

        mw2019_diag::Log("[CFG] frontend dvar audit BEGIN\r\n");
        for (const auto& item : dvars)
        {
            void* raw = nullptr;
            if (findFn)
            {
                __try { raw = findFn(item.key); }
                __except (EXCEPTION_EXECUTE_HANDLER) { raw = nullptr; }
            }

            if (!raw)
            {
                mw2019_diag::Log("[CFG] %-28s MISSING key=%s\r\n", item.name, item.key);
                continue;
            }

            __try
            {
                auto* dvar = reinterpret_cast<DvarBoolView*>(raw);
                const int current = dvar->current.enabled ? 1 : 0;
                const char* state = (item.expected < 0)
                    ? "INFO"
                    : (current == item.expected ? "OK" : "UNEXPECTED");
                mw2019_diag::Log(
                    "[CFG] %-28s current=%d latched=%d reset=%d status=%s\r\n",
                    item.name,
                    current,
                    dvar->latched.enabled ? 1 : 0,
                    dvar->reset.enabled ? 1 : 0,
                    state);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                mw2019_diag::Log("[CFG] %-28s READ-FAULT\r\n", item.name);
            }
        }

        Signature* frontendSig = FindSignature("s_luaInFrontend");
        int frontend = -1;
        if (frontendSig && frontendSig->address)
        {
            __try { frontend = *reinterpret_cast<unsigned char*>(frontendSig->address) ? 1 : 0; }
            __except (EXCEPTION_EXECUTE_HANDLER) { frontend = -1; }
        }

        char customServer[256]{};
        mw2019_network::GetCustomServer(customServer, CountOf(customServer));
        mw2019_diag::Log(
            "[CFG] runtime luaVM=%p frontend=%d network=REVAMPED-ISOLATION customServer=%s\r\n",
            luaVm, frontend, customServer[0] ? customServer : "127.0.0.1");
        mw2019_diag::Log("[CFG] one-shot Retail CFG audit END\r\n");
    }

    void AppendScannerLog(const char* text)
    {
        wchar_t path[32768]{};
        if (!mw2019_diag::BuildOutputPath(L"scanner\\memory_scanner.log", path, CountOf(path))) return;
        HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) { DWORD w{}; WriteFile(h, text, static_cast<DWORD>(strlen(text)), &w, nullptr); CloseHandle(h); }
    }
}


    bool Build385ReadableProtect(DWORD protect) noexcept
    {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS))
            return false;
        const DWORD p = protect & 0xFFu;
        return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
               p == PAGE_EXECUTE_WRITECOPY;
    }

    bool Build385WritableProtect(DWORD protect) noexcept
    {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS))
            return false;
        const DWORD p = protect & 0xFFu;
        return p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    bool Build385ReadMemory(std::uintptr_t address, void* out, std::size_t size) noexcept
    {
        if (!address || !out || !size)
            return false;
        SIZE_T bytesRead = 0;
        return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                                 out, size, &bytesRead) != FALSE && bytesRead == size;
    }

    bool Build385AddWatchSpan(std::uintptr_t base, std::size_t size) noexcept
    {
        if (!base || !size)
            return false;
        // Keep snapshots bounded. PE writable sections are normally modest; the
        // Lua allocation is capped below before reaching this helper.
        if (size > 64ull * 1024ull * 1024ull)
            return false;
        for (const auto& old : Build385WatchSpans())
        {
            const auto oldEnd = old.base + old.size;
            const auto newEnd = base + size;
            if (base < oldEnd && old.base < newEnd)
                return false;
        }
        Build385WatchSpan span{};
        span.base = base;
        span.size = size;
        try
        {
            span.snapshot.resize(size);
            const std::size_t pages = (size + 0xFFFu) / 0x1000u;
            span.warmupPageChanges.assign(pages, 0);
            span.activePages.assign(pages, 1);
        }
        catch (...) { return false; }
        if (!Build385ReadMemory(base, span.snapshot.data(), size))
            return false;
        try { Build385WatchSpans().emplace_back(std::move(span)); }
        catch (...) { return false; }
        return true;
    }

    void Build385AddMainModuleWritableSections() noexcept
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return;

        IMAGE_DOS_HEADER dos{};
        if (!Build385ReadMemory(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
            return;

        IMAGE_NT_HEADERS64 nt{};
        const auto ntAddress = base + static_cast<std::uintptr_t>(dos.e_lfanew);
        if (!Build385ReadMemory(ntAddress, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE)
            return;

        const auto sectionTable = ntAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
        for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
        {
            IMAGE_SECTION_HEADER sec{};
            if (!Build385ReadMemory(sectionTable + static_cast<std::uintptr_t>(i) * sizeof(sec), &sec, sizeof(sec)))
                break;
            if ((sec.Characteristics & IMAGE_SCN_MEM_WRITE) == 0)
                continue;
            std::size_t size = static_cast<std::size_t>(sec.Misc.VirtualSize);
            if (!size)
                size = static_cast<std::size_t>(sec.SizeOfRawData);
            if (!size)
                continue;
            const auto start = base + sec.VirtualAddress;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(start), &mbi, sizeof(mbi)) ||
                mbi.State != MEM_COMMIT || !Build385ReadableProtect(mbi.Protect))
                continue;
            Build385AddWatchSpan(start, size);
        }
    }

    void Build388AddSettledPrivateWritableMemory(void* luaVm) noexcept
    {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const auto minAddr = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const auto maxAddr = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        std::uintptr_t luaRegionBase = 0;
        std::uintptr_t luaRegionEnd = 0;
        if (luaVm)
        {
            MEMORY_BASIC_INFORMATION luaMbi{};
            if (VirtualQuery(luaVm, &luaMbi, sizeof(luaMbi)))
            {
                luaRegionBase = reinterpret_cast<std::uintptr_t>(luaMbi.BaseAddress);
                luaRegionEnd = luaRegionBase + luaMbi.RegionSize;
            }
        }

        constexpr std::size_t kMaxRegion = 8ull * 1024ull * 1024ull;
        constexpr std::size_t kMaxTotal = 192ull * 1024ull * 1024ull;
        std::size_t total = 0;

        for (std::uintptr_t cursor = minAddr; cursor < maxAddr; )
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) || !mbi.RegionSize)
                break;

            const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto next = base + mbi.RegionSize;
            if (next <= cursor)
                break;
            cursor = next;

            if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || !Build385WritableProtect(mbi.Protect))
                continue;
            const DWORD p = mbi.Protect & 0xFFu;
            if (p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY)
                continue;
            if (mbi.RegionSize < 0x1000 || mbi.RegionSize > kMaxRegion)
                continue;
            if (luaRegionBase && base < luaRegionEnd && luaRegionBase < next)
                continue; // known Lua allocator region is intentionally excluded
            if (total + mbi.RegionSize > kMaxTotal)
                continue;
            if (Build385AddWatchSpan(base, static_cast<std::size_t>(mbi.RegionSize)))
                total += static_cast<std::size_t>(mbi.RegionSize);
        }
    }

    void Build385AddLuaVmAllocation(void* luaVm) noexcept
    {
        if (!luaVm)
            return;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(luaVm, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
            !Build385ReadableProtect(mbi.Protect))
            return;
        auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        std::size_t size = mbi.RegionSize;
        // The VM often lives in a larger heap reservation. A 16 MiB cap gives us
        // broad Lua/frontend state coverage without turning the trace into a RAM copy loop.
        if (size > 16ull * 1024ull * 1024ull)
            size = 16ull * 1024ull * 1024ull;
        Build385AddWatchSpan(base, size);
    }

    void Build385ArmMemoryTrace(void* luaVm) noexcept
    {
        (void)luaVm;
        if (g_build385MemoryTraceArmed)
            return;
        Build385WatchSpans().clear();
        g_build385LoggedChanges = 0;
        g_build385WarmupComplete = false;
        g_build390LastUiMarkerScanMs = 0;
        g_build390ConnectingSeen = false;
        g_build390LoadingAssetsSeen = false;
        g_build390ConnectionFailedSeen = false;
        g_build390UnableOnlineSeen = false;
        g_build390LuaVmForMarkers = luaVm;
        Build391TokenAddresses().clear();
        Build391SeenPointerRefs().clear();
        g_build391TokensLocated = false;
        g_build391LastPointerScanMs = 0;

        // Build388: capture settled private writable process state, but exclude the
        // known Lua VM allocation. Warmup identifies pages that churn continuously;
        // the active pass watches only pages that were stable before the user click.
        Build385AddMainModuleWritableSections();
        Build388AddSettledPrivateWritableMemory(luaVm);

        std::size_t total = 0;
        for (const auto& span : Build385WatchSpans())
            total += span.size;

        const auto now = GetTickCount64();
        g_build385MemoryTraceArmed = !Build385WatchSpans().empty();
        g_build385MemoryTraceWarmupUntilMs = now + 5000ull;
        g_build385MemoryTraceDeadlineMs = now + 65000ull; // 5s warmup + 60s capture
        g_build385LastMemoryScanMs = 0;
        g_build388LastWarmupScanMs = 0;
        mw2019_diag::Log(
            "[MEMTRACE] WARMUP 5s spans=%zu bytes=%zu (private writable + MW image; Lua heap excluded). Do not click yet.\r\n",
            Build385WatchSpans().size(), total);
    }

    void Build385StopMemoryTrace(const char* reason) noexcept
    {
        if (!g_build385MemoryTraceArmed)
            return;
        g_build385MemoryTraceArmed = false;
        g_build385WarmupComplete = false;
        unsigned long totalChanges = 0;
        for (const auto& span : Build385WatchSpans())
            totalChanges += span.changes;
        mw2019_diag::Log("[MEMTRACE] stopped%s%s logged=%lu total-page-events=%lu\r\n",
            (reason && *reason) ? ": " : "", (reason && *reason) ? reason : "",
            g_build385LoggedChanges, totalChanges);
        Build385WatchSpans().clear();
    }


    bool Build390MatchAscii(const unsigned char* data, std::size_t size, const char* text) noexcept
    {
        if (!data || !text)
            return false;
        const std::size_t n = strlen(text);
        if (!n || size < n)
            return false;
        for (std::size_t i = 0; i + n <= size; ++i)
        {
            if (memcmp(data + i, text, n) == 0)
                return true;
        }
        return false;
    }

    bool Build390MatchUtf16(const unsigned char* data, std::size_t size, const char* text) noexcept
    {
        if (!data || !text)
            return false;
        const std::size_t n = strlen(text);
        if (!n || size < n * 2)
            return false;
        for (std::size_t i = 0; i + n * 2 <= size; ++i)
        {
            bool match = true;
            for (std::size_t j = 0; j < n; ++j)
            {
                if (data[i + j * 2] != static_cast<unsigned char>(text[j]) || data[i + j * 2 + 1] != 0)
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return true;
        }
        return false;
    }

    void Build390ScanUiMarkers(unsigned long long now) noexcept
    {
        if (!g_build385MemoryTraceArmed || !g_build385WarmupComplete)
            return;
        if (g_build390LastUiMarkerScanMs && now - g_build390LastUiMarkerScanMs < 1500ull)
            return;
        g_build390LastUiMarkerScanMs = now;

        struct Marker
        {
            const char* label;
            const char* text;
            bool* seen;
        };
        Marker markers[] = {
            {"CONNECTING", "Connecting to Online Services", &g_build390ConnectingSeen},
            {"LOADING_ASSETS", "Loading Assets", &g_build390LoadingAssetsSeen},
            {"CONNECTION_FAILED", "CONNECTION FAILED", &g_build390ConnectionFailedSeen},
            {"UNABLE_ONLINE", "Unable to access online services", &g_build390UnableOnlineSeen},
        };

        bool allSeen = true;
        for (const auto& marker : markers)
            allSeen = allSeen && *marker.seen;
        if (allSeen)
            return;

        constexpr std::size_t page = 0x1000;
        unsigned char current[page];
        const auto scanRange = [&](std::uintptr_t base, std::size_t size) noexcept
        {
            for (std::size_t off = 0; off < size; off += page)
            {
                const std::size_t n = (std::min)(page, size - off);
                const auto addr = base + off;
                if (!Build385ReadMemory(addr, current, n))
                    continue;

                for (auto& marker : markers)
                {
                    if (*marker.seen)
                        continue;
                    if (Build390MatchAscii(current, n, marker.text) || Build390MatchUtf16(current, n, marker.text))
                    {
                        *marker.seen = true;
                        mw2019_diag::Log(
                            "[UIMARK] t=%llums state=%s text='%s' page=%p\r\n",
                            static_cast<unsigned long long>(now), marker.label, marker.text,
                            reinterpret_cast<void*>(addr));
                    }
                }
            }
        };

        for (const auto& span : Build385WatchSpans())
            scanRange(span.base, span.size);

        // The broad diff deliberately excludes the noisy Lua allocator, but UI
        // strings are often materialized there. Search its live allocation only
        // for these exact marker texts so we get the state timestamp without
        // reintroducing Lua-heap diff spam.
        if (g_build390LuaVmForMarkers)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(g_build390LuaVmForMarkers, &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT && Build385ReadableProtect(mbi.Protect))
            {
                std::size_t n = mbi.RegionSize;
                if (n > 16ull * 1024ull * 1024ull)
                    n = 16ull * 1024ull * 1024ull;
                scanRange(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), n);
            }
        }
    }

    void Build391CollectTokenInRange(const char* label, const char* token,
                                      std::uintptr_t base, std::size_t size) noexcept
    {
        if (!label || !token || !base || !size)
            return;
        constexpr std::size_t page = 0x1000;
        unsigned char current[page];
        const std::size_t tokenLen = strlen(token);
        if (!tokenLen || tokenLen >= page)
            return;

        for (std::size_t off = 0; off < size; off += page)
        {
            const std::size_t n = (std::min)(page, size - off);
            if (!Build385ReadMemory(base + off, current, n))
                continue;
            for (std::size_t i = 0; i + tokenLen <= n; ++i)
            {
                if (memcmp(current + i, token, tokenLen) != 0)
                    continue;
                const auto found = base + off + i;
                bool duplicate = false;
                for (const auto& item : Build391TokenAddresses())
                {
                    if (item.address == found)
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                {
                    Build391TokenAddresses().push_back({label, token, found});
                    mw2019_diag::Log("[UITOKEN] label=%s token='%s' addr=%p\r\n",
                                     label, token, reinterpret_cast<void*>(found));
                }
            }
        }
    }

    void Build391LocateUiTokens() noexcept
    {
        if (g_build391TokensLocated)
            return;
        g_build391TokensLocated = true;

        struct TokenDef { const char* label; const char* token; };
        const TokenDef tokens[] = {
            {"CONNECTION_FAILED", "menu/connection_failed"},
            {"CONTENT_NOT_AVAILABLE", "menu/content_not_available"},
            {"AUTH_ERROR", "An authentication function returned an error"},
            {"CONNECTION_TYPE", "lua_menu/connection_type"},
        };

        // Search the exact settled writable spans already selected for tracing.
        for (const auto& span : Build385WatchSpans())
        {
            for (const auto& t : tokens)
                Build391CollectTokenInRange(t.label, t.token, span.base, span.size);
        }

        // The Retail Lua dump shows connection localization tokens in the Lua-side
        // memory neighborhood. Search the VM allocation separately even though the
        // broad diff excludes it for noise reasons.
        if (g_build390LuaVmForMarkers)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(g_build390LuaVmForMarkers, &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT && Build385ReadableProtect(mbi.Protect))
            {
                std::size_t n = mbi.RegionSize;
                if (n > 32ull * 1024ull * 1024ull)
                    n = 32ull * 1024ull * 1024ull;
                for (const auto& t : tokens)
                    Build391CollectTokenInRange(t.label, t.token,
                        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), n);
            }
        }

        mw2019_diag::Log("[UITOKEN] discovery complete count=%zu\r\n",
                         Build391TokenAddresses().size());
    }

    bool Build391AlreadySawRef(std::uintptr_t ref) noexcept
    {
        return std::find(Build391SeenPointerRefs().begin(),
                         Build391SeenPointerRefs().end(), ref) != Build391SeenPointerRefs().end();
    }

    void Build391ScanTokenPointerRefs(unsigned long long now) noexcept
    {
        if (!g_build385MemoryTraceArmed || !g_build385WarmupComplete)
            return;
        if (!g_build391TokensLocated)
            Build391LocateUiTokens();
        if (Build391TokenAddresses().empty())
            return;
        if (g_build391LastPointerScanMs && now - g_build391LastPointerScanMs < 250ull)
            return;
        g_build391LastPointerScanMs = now;

        constexpr std::size_t page = 0x1000;
        alignas(8) unsigned char current[page];
        unsigned loggedThisPass = 0;
        for (const auto& span : Build385WatchSpans())
        {
            for (std::size_t off = 0; off < span.size; off += page)
            {
                const std::size_t pageIndex = off / page;
                if (pageIndex >= span.activePages.size() || !span.activePages[pageIndex])
                    continue;
                const std::size_t n = (std::min)(page, span.size - off);
                const auto pageAddr = span.base + off;
                if (!Build385ReadMemory(pageAddr, current, n))
                    continue;

                for (std::size_t j = 0; j + sizeof(std::uintptr_t) <= n; j += sizeof(std::uintptr_t))
                {
                    std::uintptr_t value = 0;
                    memcpy(&value, current + j, sizeof(value));
                    for (const auto& token : Build391TokenAddresses())
                    {
                        if (value != token.address)
                            continue;
                        const auto ref = pageAddr + j;
                        if (Build391AlreadySawRef(ref))
                            continue;
                        Build391SeenPointerRefs().push_back(ref);
                        mw2019_diag::Log(
                            "[UIREF] t=%llums label=%s ref=%p -> token=%p ('%s')\r\n",
                            static_cast<unsigned long long>(now), token.label,
                            reinterpret_cast<void*>(ref), reinterpret_cast<void*>(token.address),
                            token.token);
                        if (++loggedThisPass >= 64)
                            return;
                    }
                }
            }
        }
    }

    void Build385TickMemoryTrace() noexcept
    {
        if (!g_build385MemoryTraceArmed)
            return;
        const auto now = GetTickCount64();
        if (g_build385MemoryTraceDeadlineMs && now >= g_build385MemoryTraceDeadlineMs)
        {
            Build385StopMemoryTrace("60s active window complete");
            return;
        }

        // Build388 warmup: sample repeatedly and classify continuously-changing
        // pages as noise. Only pages that remain mostly stable become active.
        if (!g_build385WarmupComplete)
        {
            constexpr std::size_t page = 0x1000;
            if (!g_build388LastWarmupScanMs || now - g_build388LastWarmupScanMs >= 500ull)
            {
                g_build388LastWarmupScanMs = now;
                for (auto& span : Build385WatchSpans())
                {
                    for (std::size_t off = 0, pageIndex = 0; off < span.size; off += page, ++pageIndex)
                    {
                        const std::size_t n = (std::min)(page, span.size - off);
                        unsigned char current[page];
                        if (!Build385ReadMemory(span.base + off, current, n))
                            continue;
                        if (memcmp(current, span.snapshot.data() + off, n) != 0)
                        {
                            if (pageIndex < span.warmupPageChanges.size() && span.warmupPageChanges[pageIndex] < 255)
                                ++span.warmupPageChanges[pageIndex];
                            memcpy(span.snapshot.data() + off, current, n);
                        }
                    }
                }
            }

            if (now < g_build385MemoryTraceWarmupUntilMs)
                return;

            std::size_t activePages = 0;
            std::size_t noisyPages = 0;
            for (auto& span : Build385WatchSpans())
            {
                span.changes = 0;
                for (std::size_t i = 0; i < span.activePages.size(); ++i)
                {
                    // Zero or one change during five seconds is considered settled.
                    const bool active = i < span.warmupPageChanges.size() && span.warmupPageChanges[i] <= 1;
                    span.activePages[i] = active ? 1 : 0;
                    if (active) ++activePages; else ++noisyPages;
                }
            }

            // Build389: warmup classification is not itself a valid active baseline.
            // Pages that never changed during warmup may still contain the 0xFF
            // sentinel from allocation. Re-read every active page NOW so the first
            // active comparison starts from real process memory rather than the
            // sentinel. This prevents the entire detail budget being consumed at
            // one timestamp before the user can click MP/Co-op.
            constexpr std::size_t baselinePage = 0x1000;
            std::size_t baselinedPages = 0;
            std::size_t baselineReadFailures = 0;
            for (auto& span : Build385WatchSpans())
            {
                for (std::size_t off = 0; off < span.size; off += baselinePage)
                {
                    const std::size_t pageIndex = off / baselinePage;
                    if (pageIndex >= span.activePages.size() || !span.activePages[pageIndex])
                        continue;
                    const std::size_t n = (std::min)(baselinePage, span.size - off);
                    unsigned char current[baselinePage];
                    if (!Build385ReadMemory(span.base + off, current, n))
                    {
                        span.activePages[pageIndex] = 0;
                        ++baselineReadFailures;
                        if (activePages) --activePages;
                        ++noisyPages;
                        continue;
                    }
                    memcpy(span.snapshot.data() + off, current, n);
                    ++baselinedPages;
                }
            }

            g_build385LoggedChanges = 0;
            g_build385WarmupComplete = true;
            g_build385LastMemoryScanMs = now;
            mw2019_diag::Log(
                "[MEMTRACE] ACTIVE 60s stablePages=%zu noisyPages=%zu baselined=%zu readFail=%zu. UI-token pointer trace enabled; click Multiplayer once, then Co-op after rollback.\r\n",
                activePages, noisyPages, baselinedPages, baselineReadFailures);
            return;
        }

        Build390ScanUiMarkers(now);
        Build391ScanTokenPointerRefs(now);

        if (g_build385LastMemoryScanMs && now - g_build385LastMemoryScanMs < 250ull)
            return;
        g_build385LastMemoryScanMs = now;
        const auto moduleBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        constexpr std::size_t page = 0x1000;
        for (auto& span : Build385WatchSpans())
        {
            for (std::size_t off = 0; off < span.size; off += page)
            {
                const std::size_t pageIndex = off / page;
                if (pageIndex >= span.activePages.size() || !span.activePages[pageIndex])
                    continue;
                const std::size_t n = (std::min)(page, span.size - off);
                const auto addr = span.base + off;
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(addr), &mbi, sizeof(mbi)) ||
                    mbi.State != MEM_COMMIT || !Build385ReadableProtect(mbi.Protect))
                    continue;
                bool different = false;
                std::size_t first = 0;
                unsigned char current[page];
                if (!Build385ReadMemory(addr, current, n))
                    continue;
                for (std::size_t j = 0; j < n; ++j)
                {
                    if (current[j] != span.snapshot[off + j])
                    {
                        different = true;
                        first = j;
                        break;
                    }
                }
                if (!different)
                    continue;

                ++span.changes;
                if (g_build385LoggedChanges < kBuild385MaxLoggedChanges)
                {
                    const std::size_t sampleStart = first > 4 ? first - 4 : 0;
                    const std::size_t sampleCount = (std::min)(std::size_t(16), n - sampleStart);
                    char beforeHex[16 * 3 + 1]{};
                    char afterHex[16 * 3 + 1]{};
                    std::size_t bp = 0, ap = 0;
                    for (std::size_t j = 0; j < sampleCount && bp + 4 < sizeof(beforeHex) && ap + 4 < sizeof(afterHex); ++j)
                    {
                        bp += static_cast<std::size_t>(sprintf_s(beforeHex + bp, sizeof(beforeHex) - bp, "%02X ", span.snapshot[off + sampleStart + j]));
                        ap += static_cast<std::size_t>(sprintf_s(afterHex + ap, sizeof(afterHex) - ap, "%02X ", current[sampleStart + j]));
                    }
                    const auto absolute = addr + first;
                    const bool inExe = moduleBase && absolute >= moduleBase;
                    const auto rva = inExe ? static_cast<unsigned long long>(absolute - moduleBase) : 0ull;
                    mw2019_diag::Log(
                        "[MEMTRACE] t=%llums addr=%p%s%llX page=%p +0x%zX old=[%s] new=[%s]\r\n",
                        static_cast<unsigned long long>(now), reinterpret_cast<void*>(absolute),
                        inExe ? " rva=0x" : " ext=0x", rva,
                        reinterpret_cast<void*>(addr), first, beforeHex, afterHex);
                    ++g_build385LoggedChanges;
                }
                memcpy(span.snapshot.data() + off, current, n);
            }
        }
    }

namespace mw2019_scanner
{
    void Initialize() noexcept
    {
        // V106: auto-arm the lightweight frontend/read-only slot50 timeline immediately. This is
        // intentionally done before the intro and performs no image/heap scan.
        const auto now = GetTickCount64();
        g_v100FrontendTraceDeadlineMs = 0;
        g_v100FrontendTraceNextSampleMs = now;
        g_v100FrontendTraceLastHeartbeatMs = 0;
        g_v100LastFrontend = -999;
        g_v100LastMarkerLive = -999;
        InterlockedExchange(&g_v100FrontendTraceArmed, 1);
        mw2019_diag::Log("[V111.1-AUTO] SessionService completion hardware execution watch AUTO_ARM=ON RETRY_SIGNATURES=ON targets={gate:0x4642C90,installerCall:0x4642CE8,successWriter:0x46417FF} V109BroadAncestry=OFF functionDetours=OFF int3=OFF codeWrites=OFF stateWrites=off\r\n");
        mw2019_diag::Log("[V112.1-AUTO] passive post-connected Source3 correlation AUTO_ARM=ON WAIT_FOR_V111_RESTORE=ON observers={resultFetch:V98,statusCommit:V103,altRoute:V103,primary:V97,setter:V97} hardwareBreakpoints=0 debugRegistersTouchedByV112=NO noNewDetours=yes int3=OFF stateWrites=off\r\n");
        mw2019_diag::Log("[V113-AUTO] connected-owner continuation trace AUTO_ARM=ON WAIT_FOR_V111_RESTORE=ON WAIT_FOR_V103=ON preCommitWatch={0x4531538} postCommitWatch={slot50:0x2B59C00,firstLocalJcc,firstLocalCall} hotResultFetchBreakpoint=OFF noNewDetours=yes int3=OFF stateWrites=off\r\n");
    }

    void ScanNow(const char* reason) noexcept
    {
        (void)reason;
        if (InterlockedCompareExchange(&g_scanBusy, 1, 0) != 0)
            return;

        // Small frontend/Lua set used by command execution and dvar reapply.
        static const char* const required[] = {
            "luaL_openlib",
            "lua_pushboolean",
            "lua_pushstring",
            "lua_remove",
            "lua_remove_v146",
            "lua_getfield",
            "LUI_luaVM",
            "LuaShared_PCall",
            "Dvar_FindVarByName",
            "LUI_OpenMenu",
            "s_luaInFrontend",
            "s_isContentEnumerationFinished",
            "unk_XUIDCheck1",
            "GamerProfile_SetDataByName"
        };

        for (const char* name : required)
        {
            Signature* sig = FindSignature(name);
            if (!sig || sig->address || !sig->pattern || !*sig->pattern)
                continue;
            const auto match = ScanOne(sig->pattern);
            if (match)
                sig->address = Resolve(match, sig->resolve);
        }

        InterlockedExchange(&g_scanBusy, 0);
    }

    void ScanAllNow(const char* reason) noexcept
    {
        if (InterlockedCompareExchange(&g_scanBusy, 1, 0) != 0)
        {
            mw2019_diag::Log("[SCAN] another scan is already active\r\n");
            return;
        }

        mw2019_diag::Log("[SCAN] full late offset scan begin reason=%s\r\n",
            (reason && *reason) ? reason : "manual");
        unsigned foundNow = 0;
        for (auto& sig : g_signatures)
        {
            if (sig.address || !sig.pattern || !*sig.pattern)
                continue;
            const auto match = ScanOne(sig.pattern);
            if (!match)
                continue;
            sig.address = Resolve(match, sig.resolve);
            if (sig.address)
                ++foundNow;
        }
        InterlockedExchange(&g_scanBusy, 0);
        mw2019_diag::Log("[SCAN] full late offset scan complete foundNow=%u\r\n", foundNow);
    }

    // Build374 continuous/graph/MP-state scanner runtime retained only for the
    // generic research path. Exact 1.44 uses its own lightweight Tick loop.
    void Tick(unsigned long long uptimeMs) noexcept
    {
        // V101 samples from the first runtime ticks so intro-skip/TLS/frontend
        // timing cannot occur before the trace is armed.
        V100FrontendTraceTick(uptimeMs);

        // Install the window/input observer as soon as a game window exists,
        // including during the intro. This is lightweight and does not scan.
        if (uptimeMs >= 500)
        {
            static unsigned long long v101EarlyObserverAttempt = 0;
            if (uptimeMs - v101EarlyObserverAttempt >= 500)
            {
                v101EarlyObserverAttempt = uptimeMs;
                InstallBuild357GameWindowDispatch();
                if (InstallLUIOpenMenuTraceHook() &&
                    InterlockedCompareExchange(&g_transitionTraceArmed, 0, 0) == 0)
                {
                    strncpy_s(g_transitionTraceLabel, "v101-auto", _TRUNCATE);
                    g_transitionTraceDeadlineMs = 0;
                    InterlockedExchange(&g_luiOpenTraceCount, 0);
                    InterlockedExchange(&g_transitionTraceArmed, 1);
                    mw2019_diag::Log("[V101-AUTO] early LUI trace armed CMD_ONLY uptimeMs=%llu\r\n", uptimeMs);
                }
            }
        }

        if (uptimeMs < 10000)
            return;
        StartBuild373MenuConsole();

        // V101: once the lightweight frontend symbols/window become available,
        // attach the existing menu/input observers automatically. No user command
        // is needed and no menu/state is forced.
        if (Build373PureServerEmu144())
        {
            static unsigned long long v101LastObserverAttempt = 0;
            const auto now = GetTickCount64();
            if (now - v101LastObserverAttempt >= 1000ull)
            {
                v101LastObserverAttempt = now;
                ScanNow("V101 auto observer bootstrap");
                const bool wndReady = InstallBuild357GameWindowDispatch();
                const bool luiReady = InstallLUIOpenMenuTraceHook();
                if (luiReady && InterlockedCompareExchange(&g_transitionTraceArmed, 0, 0) == 0)
                {
                    strncpy_s(g_transitionTraceLabel, "v101-auto", _TRUNCATE);
                    g_transitionTraceDeadlineMs = 0;
                    InterlockedExchange(&g_luiOpenTraceCount, 0);
                    InterlockedExchange(&g_transitionTraceArmed, 1);
                    mw2019_diag::Log("[V101-AUTO] LUI_OpenMenu trace armed indefinitely CMD_ONLY; gameWindowDispatch=%s\r\n", wndReady ? "ready" : "waiting");
                }
            }
        }
        if (InterlockedCompareExchange(&g_transitionTraceArmed, 0, 0) != 0 &&
            g_transitionTraceDeadlineMs && GetTickCount64() >= g_transitionTraceDeadlineMs)
        {
            Build378StopTransitionTrace("20s window complete");
        }
        if (!g_firstAutoDone || (g_autoAttempts < 10 && uptimeMs - g_lastAutoScan >= 10000))
        {
            g_firstAutoDone = true;
            g_lastAutoScan = uptimeMs;
            ++g_autoAttempts;
            ScanNow("startup");
        }
        RestorePersistentGameTextHooksForArxan(uptimeMs);
        RestoreLuaOpenLibAfterQuietWindow(uptimeMs);
        ApplyOfflineFrontendState(uptimeMs);
        Build385TickMemoryTrace();

        if (g_build374ReadyLogged)
            return;

        Signature* openSig = FindSignature("LUI_OpenMenu");
        Signature* luaVmSig = FindSignature("LUI_luaVM");
        Signature* frontendSig = FindSignature("s_luaInFrontend");
        void* luaVm = nullptr;
        int frontend = -1;
        if (luaVmSig && luaVmSig->address)
        {
            __try { luaVm = *reinterpret_cast<void**>(luaVmSig->address); }
            __except (EXCEPTION_EXECUTE_HANDLER) { luaVm = nullptr; }
        }
        if (frontendSig && frontendSig->address)
        {
            __try { frontend = *reinterpret_cast<unsigned char*>(frontendSig->address) ? 1 : 0; }
            __except (EXCEPTION_EXECUTE_HANDLER) { frontend = -1; }
        }

        static unsigned stableReadyChecks = 0;
        static unsigned long long lastReadyCheck = 0;
        if (uptimeMs - lastReadyCheck >= 750)
        {
            lastReadyCheck = uptimeMs;
            const bool readyNow =
                openSig && openSig->address &&
                luaVm &&
                frontend == 1 &&
                Build383FrontendSelectorsReady() &&
                InstallBuild357GameWindowDispatch();

            if (readyNow)
                ++stableReadyChecks;
            else
                stableReadyChecks = 0;
        }

        if (stableReadyChecks >= 2)
        {
            Build379AuditCfgAndFrontendState(luaVm);
            if (!g_build384FrontendTraceAutoArmed)
            {
                Build378ArmTransitionTrace("auto-frontend");
                g_build384FrontendTraceAutoArmed =
                    InterlockedCompareExchange(&g_transitionTraceArmed, 0, 0) != 0;
            }
            Build385ArmMemoryTrace(luaVm);
            g_build374ReadyLogged = true;
            mw2019_diag::Log(
                "[READY] MW2019 generic frontend stable. UI-token pointer trace + memory trace active.\r\n");
        }
    }

    void StartConsole() noexcept
    {
        StartBuild373MenuConsole();
        if (Build373PureServerEmu144())
            mw2019_diag::Log("[CMD] V113 TRACE ON: V112.1 passive correlation retained. V113 watches only the low-frequency connected return 0x4531538 before commit, then one-shot traces the first local branch/call and exact slot50 target 0x2B59C00. Hot resultFetch breakpoint remains OFF; no Source3/menu/fence writes or broad scans. Commands: authstatus | source3 [0|1] | menustatus | menuxrefs | menutrace | menuopen <alias> | frontend [alias] | frontstatus | fronttrace [sec] | frontstop | connectxrefs | offsets | netstatus | server <host> | help\r\n");
        else
            mw2019_diag::Log(
                "[CMD] console ready: luascan | luastatus | menus | menu <alias> | blades | signin144 | content144 | lui144 | patch144 | hooks144 | cmdscan | commands | cmdfind <text> | cmdrun <id> | exec <raw> | offsetscan | offsets\r\n");
    }

    void ScanCommands() noexcept
    {
        Build169ScanCommandsInternal(false);
    }

    void SeedAddress(const char* name, std::uintptr_t address) noexcept
    {
        if (!name || !*name || !address)
            return;
        Signature* sig = FindSignature(name);
        if (!sig)
            return;
        sig->address = address;
    }

    std::uintptr_t GetAddress(const char* name) noexcept
    {
        Signature* sig = FindSignature(name);
        return sig ? sig->address : 0;
    }

    void PrintAddresses() noexcept
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        unsigned resolved = 0;
        unsigned total = 0;
        for (const auto& sig : g_signatures)
        {
            ++total;
            if (sig.address)
            {
                ++resolved;
                const auto rva = (base && sig.address >= base) ? (sig.address - base) : 0;
                mw2019_diag::Log("[OFFSET] %-42s = %p rva=0x%llX\r\n",
                    sig.name,
                    reinterpret_cast<void*>(sig.address),
                    static_cast<unsigned long long>(rva));
            }
            else
            {
                mw2019_diag::Log("[OFFSET] %-42s = MISSING\r\n", sig.name);
            }
        }
        mw2019_diag::Log("[OFFSET] resolved=%u/%u\r\n", resolved, total);
    }

    bool SetBool(const char* keyOrName, const char* friendlyName, bool value) noexcept
    {
        if (!keyOrName || !*keyOrName)
            return false;
        return SetBoolDvar(keyOrName, friendlyName, value);
    }

    unsigned ApplyFrontendBladeSelectors(bool verbose) noexcept
    {
        struct Entry { const char* token; const char* label; bool value; };
        static const Entry entries[] = {
            {"MPSSOTQQPM", "force_offline_enabled", true},
            {"LSTQOKLTRN", "force_offline_menus", false},
            {"LMMRONPQMO", "lui_force_online_menus", true},
            {"MTSTMKPMRM", "ui_onlineRequired", false},
            {"RLSPOOTTT", "com_checkIfGameModeInstalled", false},
            {"LPNMMPKRL", "com_lan_lobby_enabled", true},
            {"LTOQRQMMLQ", "online_lan_cross_play", true},
            {"LLOKQOSPPP", "xblive_loggedin", true},
            {"LTSNLQNRKO", "onlinegame", true},
            {"MROLPRPTPO", "com_force_premium", true},
            {"NOSONNPTLM", "online_auth_skip_auth", true},
            {"MNMLRKRSSL", "enable_cod_account", true},
            {"online_store_catalog_fence_enabled", "online_store_catalog_fence_enabled", false},
            {"LNKTTMTOMR", "lui_tournament_allow_warzone_players", false},
            {"LOQQOSNQKN", "wz_private_match_enabled", true},
            {"wz_enable_blades_refresh", "wz_enable_blades_refresh", true},
            {"LKSKPKTOON", "text_chat_enabled", true},
            {"NQPKQNMQSR", "display_ng_blade_enabled", true},
            {"LKSTRMKTML", "checkReleaseDLC", true},
            {"challenge_summary_test", "challenge_summary_test", true},
            {"LKQRNQSSQS", "online_challenge_fence_enabled", false},
            {"LQKTNLONLP", "mp_private_match_enabled", true},
            {"LOMSTMNPRR", "mp_trials_enabled", true}
        };

        if (!GetAddress("Dvar_FindVarByName"))
        {
            if (verbose)
                mw2019_diag::Log("[DVAR] Dvar_FindVarByName is not ready; use offsetscan after the frontend starts\r\n");
            return 0;
        }

        unsigned found = 0;
        for (const auto& entry : entries)
        {
            bool ok = SetBoolDvar(entry.token, entry.label, entry.value);
            if (!ok && _stricmp(entry.token, entry.label) != 0)
                ok = SetBoolDvar(entry.label, entry.label, entry.value);
            if (ok)
            {
                ++found;
                if (verbose)
                    mw2019_diag::Log("[DVAR] %-38s = %s\r\n", entry.label, entry.value ? "true" : "false");
            }
            else if (verbose)
            {
                mw2019_diag::Log("[DVAR] %-38s = MISSING\r\n", entry.label);
            }
        }
        if (verbose)
            mw2019_diag::Log("[DVAR] blade/offline selector pass matched=%u/%u\r\n",
                found, static_cast<unsigned>(CountOf(entries)));
        return found;
    }
}
