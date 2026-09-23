#include "BetaOffline.h"

#include "../T9Addresses.h"
#include "../../../../shared/common/utils/pattern_scan.hpp"
#include "../../../../shared/runtime/StoragePaths.h"

#include <Windows.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>

namespace
{
    constexpr std::uintptr_t kBuildIdRva = 0x011017B0u;
    constexpr std::uintptr_t kLegacyAlphaMarkerRva = 0x02602E18u;
    constexpr std::uint32_t kLegacyAlphaMarkerValue = 0x5F1B8329u;

    constexpr std::uint32_t kStateLayout208A = 0x8348B74Eu;
    constexpr std::uint32_t kStateLayout216 = 0xB8ECE9C1u;
    constexpr std::uint32_t kStateLayout208B = 0xE9CC1D0Eu;

    // These are the same live T9 signatures recovered from the supplied
    // Season 2 helper. The helper itself contains multi-build handling, so for
    // the Beta we use them only as runtime discovery candidates and refuse to
    // call/write anything unless every required target validates.
    constexpr const char* kRuntimeBootstrapA =
        "48 85 C9 0F 84 ?? ?? ?? ?? 48 89 5C 24 ?? 57 48 83 EC 60 0F 57 C0 "
        "44 0F B6 CA 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 41 8B F8 48 8B D9 "
        "0F 11 44 24 ?? 0F 11 44 24 ?? 48 85 01 0F 84 ?? ?? ?? ??";

    constexpr const char* kRuntimeBootstrapB =
        "48 85 C9 0F 84 ?? ?? ?? ?? 4C 8B DC 56 57 48 83 EC ?? 0F 57 C0 "
        "44 0F B6 CA 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 41 8B F0 48 8B F9 "
        "0F 11 44 24 ?? 0F 11 44 24 ?? 48 85 01 0F 84 ?? ?? ?? ??";

    constexpr const char* kEnableFlagAPattern =
        "80 3D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B 3F 48 8B C8 "
        "48 0F 45 3D ?? ?? ?? ?? E8 ?? ?? ?? ??";

    constexpr const char* kEnableFlagBPattern =
        "80 3D ?? ?? ?? ?? ?? 75 58 33 C9 48 89 5C 24 ??";

    constexpr const char* kPreModeResetPattern =
        "40 53 56 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? "
        "48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 4D 8B F8";

    constexpr const char* kPrepareFrontendModePattern =
        "48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 54 41 56 41 57 "
        "48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? "
        "48 33 C4 48 89 45 27 0F B6 FA 48 63 D9 8B 05 ?? ?? ?? ??";

    constexpr const char* kSetSessionStatePattern =
        "40 53 48 83 EC 20 8B D9 89 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? "
        "8B CB E8 ?? ?? ?? ??";

    constexpr const char* kSetGameModePattern =
        "8B 05 ?? ?? ?? ?? 8B D0 33 D1 83 E2 0F 33 C2 "
        "89 05 ?? ?? ?? ?? C3";

    constexpr const char* kGetMapContextCallsitePattern =
        "E8 ?? ?? ?? ?? 48 8B D7 8B C8 E8 ?? ?? ?? ?? 48 8B 7C 24 ?? "
        "E8 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ??";

    constexpr const char* kSetMapCallsitePattern =
        "E8 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ?? 84 C0 74 13 8B CB "
        "E8 ?? ?? ?? ?? 8B C8 BA ?? ?? ?? ??";

    constexpr const char* kSetGametypeThunkPattern =
        "E9 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 45 33 C0 B2 01 "
        "48 83 C4 28 E9 ?? ?? ?? ??";

    constexpr const char* kOfflineStateMarkerPattern = "2C 08 4E 3C AC 67 D3 78";

    constexpr const char* kRuntimeContextSlotPattern =
        "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 01 75 ?? "
        "48 8B 0F 8D 68 ?? 44 8B F8 48 85 C9";

    constexpr const char* kRuntimeReadyFlagPattern =
        "38 ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 ?? 4F B6 E2 AE 25 2E C1 17";

    using RuntimeBootstrapFn = void(__fastcall*)(void*, bool, bool);
    using PreModeResetFn = void(__fastcall*)(int, int, const char*);
    using PrepareFrontendModeFn = void(__fastcall*)(int);
    using SetSessionStateFn = void(__fastcall*)(int);
    using SetGameModeFn = void(__fastcall*)(int);
    using GetMapContextFn = unsigned int(__fastcall*)(int);
    using SetMapFn = void(__fastcall*)(unsigned int, const char*);
    using SetGametypeFn = void(__fastcall*)(const char*, bool);

    struct Addresses
    {
        std::uintptr_t base{};
        DWORD imageSize{};
        RuntimeBootstrapFn runtimeBootstrap{};
        PreModeResetFn preModeReset{};
        PrepareFrontendModeFn prepareFrontendMode{};
        SetSessionStateFn setSessionState{};
        SetGameModeFn setGameMode{};
        GetMapContextFn getMapContext{};
        SetMapFn setMap{};
        SetGametypeFn setGametype{};
        std::uintptr_t enableFlagA{};
        std::uintptr_t enableFlagB{};
        std::uintptr_t offlineStateRootSlot{};
        std::uintptr_t runtimeContextSlot{};
        std::uintptr_t runtimeReadyFlag{};
    };

    Addresses g_addresses{};
    std::mutex g_logMutex;
    std::atomic_bool g_maintenanceStarted{ false };
    std::uint32_t g_lastBuildId = 0;
    std::uintptr_t g_lastRoot = 0;
    std::uint32_t g_lastUnsupportedBuildId = 0;

    std::filesystem::path LogDirectory()
    {
        const auto dir = storage_paths::Logs() / L"t9_beta";
        storage_paths::EnsureDirectory(dir);
        return dir;
    }

    void Log(const char* fmt, ...)
    {
        char message[2048]{};
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(message, sizeof(message), fmt, ap);
        va_end(ap);
        message[sizeof(message) - 1] = '\0';

        std::lock_guard<std::mutex> lock(g_logMutex);
        std::ofstream out(LogDirectory() / L"offline_frontend.log", std::ios::app);
        if (out)
            out << message << '\n';
        std::printf("[T9-BETA-OFFLINE] %s\n", message);
    }

    bool ReadFingerprint(DWORD& timestamp, DWORD& imageSize, DWORD& entryRva)
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return false;

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return false;
            timestamp = nt->FileHeader.TimeDateStamp;
            imageSize = nt->OptionalHeader.SizeOfImage;
            entryRva = nt->OptionalHeader.AddressOfEntryPoint;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool IsExactBeta()
    {
        DWORD timestamp = 0, imageSize = 0, entryRva = 0;
        return ReadFingerprint(timestamp, imageSize, entryRva) &&
            timestamp == t9_addresses::BetaFingerprint.timestamp &&
            imageSize == t9_addresses::BetaFingerprint.imageSize &&
            entryRva == t9_addresses::BetaFingerprint.entryPointRva;
    }

    bool IsInsideImage(std::uintptr_t address, std::size_t size = 1)
    {
        if (!address || !g_addresses.base || !g_addresses.imageSize || !size)
            return false;
        const auto end = g_addresses.base + g_addresses.imageSize;
        return address >= g_addresses.base && address < end && size <= end - address;
    }

    bool IsReadable(std::uintptr_t address, std::size_t size = 1)
    {
        if (!IsInsideImage(address, size))
            return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
            return false;
        const DWORD p = mbi.Protect & 0xFFu;
        const bool readable = p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
            p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        if (!readable)
            return false;
        const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return size <= regionEnd - address;
    }

    bool IsExecutable(std::uintptr_t address)
    {
        if (!IsInsideImage(address))
            return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
            return false;
        const DWORD p = mbi.Protect & 0xFFu;
        return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    template <typename T>
    bool SafeRead(std::uintptr_t address, T& out)
    {
        if (!IsReadable(address, sizeof(T)))
            return false;
        SIZE_T got = 0;
        return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), &out, sizeof(T), &got) && got == sizeof(T);
    }

    template <typename T>
    bool SafeWrite(std::uintptr_t address, const T& value)
    {
        if (!IsReadable(address, sizeof(T)))
            return false;
        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;
        SIZE_T wrote = 0;
        const BOOL ok = WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), &value, sizeof(T), &wrote);
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &ignored);
        return ok && wrote == sizeof(T);
    }

    std::uintptr_t ResolveRel32(std::uintptr_t instruction, std::size_t displacementOffset, std::size_t instructionLength)
    {
        std::int32_t displacement = 0;
        if (!SafeRead(instruction + displacementOffset, displacement))
            return 0;
        return instruction + instructionLength + static_cast<std::intptr_t>(displacement);
    }

    std::uintptr_t Find(const char* name, const char* pattern)
    {
        const auto address = utils::pattern_scan::find_first(nullptr, pattern);
        if (!address)
        {
            Log("resolve miss: %s", name);
            return 0;
        }
        Log("resolve hit: %s rva=0x%llX", name,
            static_cast<unsigned long long>(address - g_addresses.base));
        return address;
    }

    bool ResolveOfflineStateRootSlot()
    {
        const auto marker = Find("OfflineState.marker", kOfflineStateMarkerPattern);
        if (!marker || marker < g_addresses.base + 3)
            return false;

        const auto floor = marker > g_addresses.base + 0x2000 ? marker - 0x2000 : g_addresses.base;
        for (auto cursor = marker - 2; cursor >= floor + 3; --cursor)
        {
            unsigned char op[3]{};
            if (!SafeRead(cursor, op))
                continue;
            if (op[0] == 0x48 && op[1] == 0x89 && op[2] == 0x05)
            {
                g_addresses.offlineStateRootSlot = ResolveRel32(cursor, 3, 7);
                return g_addresses.offlineStateRootSlot != 0;
            }
        }
        return false;
    }

    bool ResolveAddresses()
    {
        g_addresses = {};
        g_addresses.base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!g_addresses.base || !IsExactBeta())
            return false;
        g_addresses.imageSize = t9_addresses::BetaFingerprint.imageSize;

        auto bootstrap = Find("RuntimeBootstrap.primary", kRuntimeBootstrapA);
        if (!bootstrap)
            bootstrap = Find("RuntimeBootstrap.fallback", kRuntimeBootstrapB);
        g_addresses.runtimeBootstrap = reinterpret_cast<RuntimeBootstrapFn>(bootstrap);

        const auto flagA = Find("EnableFlagA.locator", kEnableFlagAPattern);
        g_addresses.enableFlagA = flagA ? ResolveRel32(flagA, 2, 7) : 0;
        const auto flagB = Find("EnableFlagB.locator", kEnableFlagBPattern);
        g_addresses.enableFlagB = flagB ? ResolveRel32(flagB, 2, 7) : 0;

        g_addresses.preModeReset = reinterpret_cast<PreModeResetFn>(Find("PreModeReset", kPreModeResetPattern));
        g_addresses.prepareFrontendMode = reinterpret_cast<PrepareFrontendModeFn>(Find("PrepareFrontendMode", kPrepareFrontendModePattern));
        g_addresses.setSessionState = reinterpret_cast<SetSessionStateFn>(Find("SetSessionState", kSetSessionStatePattern));
        g_addresses.setGameMode = reinterpret_cast<SetGameModeFn>(Find("SetGameMode", kSetGameModePattern));

        const auto mapContextCallsite = Find("GetMapContext.callsite", kGetMapContextCallsitePattern);
        g_addresses.getMapContext = reinterpret_cast<GetMapContextFn>(mapContextCallsite ? ResolveRel32(mapContextCallsite, 1, 5) : 0);
        const auto setMapCallsite = Find("SetMap.callsite", kSetMapCallsitePattern);
        g_addresses.setMap = reinterpret_cast<SetMapFn>(setMapCallsite ? ResolveRel32(setMapCallsite, 1, 5) : 0);
        const auto gametypeThunk = Find("SetGametype.thunk", kSetGametypeThunkPattern);
        g_addresses.setGametype = reinterpret_cast<SetGametypeFn>(gametypeThunk ? ResolveRel32(gametypeThunk, 1, 5) : 0);

        (void)ResolveOfflineStateRootSlot();

        const auto context = Find("RuntimeContextSlot.locator", kRuntimeContextSlotPattern);
        g_addresses.runtimeContextSlot = context ? ResolveRel32(context, 3, 7) : 0;
        const auto ready = Find("RuntimeReadyFlag.locator", kRuntimeReadyFlagPattern);
        g_addresses.runtimeReadyFlag = ready ? ResolveRel32(ready, 2, 6) : 0;

        const bool required =
            g_addresses.runtimeBootstrap &&
            g_addresses.preModeReset &&
            g_addresses.prepareFrontendMode &&
            g_addresses.setSessionState &&
            g_addresses.setGameMode &&
            g_addresses.getMapContext &&
            g_addresses.setMap &&
            g_addresses.setGametype &&
            g_addresses.enableFlagA &&
            g_addresses.enableFlagB &&
            g_addresses.runtimeContextSlot &&
            g_addresses.runtimeReadyFlag;

        if (!required)
        {
            Log("resolver incomplete: Beta does not expose the full Season-2-style offline target set yet");
            return false;
        }

        const bool valid =
            IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.runtimeBootstrap)) &&
            IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.preModeReset)) &&
            IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.prepareFrontendMode)) &&
            IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setSessionState)) &&
            IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setGameMode)) &&
            IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.getMapContext)) &&
            IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setMap)) &&
            IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setGametype)) &&
            IsReadable(g_addresses.enableFlagA) &&
            IsReadable(g_addresses.enableFlagB) &&
            IsReadable(g_addresses.runtimeContextSlot, sizeof(std::uintptr_t)) &&
            IsReadable(g_addresses.runtimeReadyFlag);

        if (!valid)
        {
            Log("resolver validation failed: at least one candidate has unexpected memory protection");
            return false;
        }

        Log("resolver complete offline_root=%s", g_addresses.offlineStateRootSlot ? "yes" : "no");
        return true;
    }

    bool ResolveWithRetry()
    {
        constexpr unsigned kAttempts = 3;
        for (unsigned attempt = 1; attempt <= kAttempts; ++attempt)
        {
            Log("resolver attempt %u/%u", attempt, kAttempts);
            if (ResolveAddresses())
                return true;
            if (attempt != kAttempts)
                Sleep(2500);
        }
        return false;
    }

    void ForceEnableFlags()
    {
        std::uint32_t marker = 0;
        if (SafeRead(g_addresses.base + kLegacyAlphaMarkerRva, marker) && marker == kLegacyAlphaMarkerValue)
        {
            Log("enable flags skipped: legacy Alpha marker detected");
            return;
        }
        const std::uint8_t one = 1;
        const bool a = SafeWrite(g_addresses.enableFlagA, one);
        const bool b = SafeWrite(g_addresses.enableFlagB, one);
        Log("enable flags A=%u B=%u", a ? 1u : 0u, b ? 1u : 0u);
    }

    bool SetMapAndGametype()
    {
        __try
        {
            const unsigned int context = g_addresses.getMapContext(0);
            g_addresses.setMap(context, "mp_moscow");
            g_addresses.setGametype("dm", true);
            Log("map/gametype applied map=mp_moscow gametype=dm context=%u", context);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log("map/gametype call fault code=0x%08lX", static_cast<unsigned long>(GetExceptionCode()));
            return false;
        }
    }

    bool ApplyMultiplayerMode()
    {
        __try
        {
            // Match the confirmed helper's initial multiplayer ordering.
            const bool mapOk = SetMapAndGametype();
            g_addresses.prepareFrontendMode(11);
            g_addresses.setSessionState(1);
            g_addresses.setGameMode(1);
            ForceEnableFlags();
            Log("multiplayer offline mode applied map_ok=%u", mapOk ? 1u : 0u);
            return mapOk;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log("multiplayer mode call fault code=0x%08lX", static_cast<unsigned long>(GetExceptionCode()));
            return false;
        }
    }

    bool ReadExternal(std::uintptr_t address, void* out, std::size_t size)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!address || !out || !size || !VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
            return false;
        const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (size > regionEnd - address)
            return false;
        SIZE_T got = 0;
        return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), out, size, &got) && got == size;
    }

    bool WriteExternal32(std::uintptr_t address, std::uint32_t value)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!address || !VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
            return false;
        const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (sizeof(value) > regionEnd - address)
            return false;
        const DWORD p = mbi.Protect & 0xFFu;
        const bool writable = p == PAGE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        if (!writable)
            return false;
        SIZE_T wrote = 0;
        return WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), &value, sizeof(value), &wrote) && wrote == sizeof(value);
    }

    void NormalizeOfflineState()
    {
        if (!g_addresses.offlineStateRootSlot || !IsReadable(g_addresses.offlineStateRootSlot, sizeof(std::uintptr_t)))
            return;

        std::uintptr_t root = 0;
        if (!SafeRead(g_addresses.offlineStateRootSlot, root) || !root)
            return;

        std::uint32_t buildId = 0;
        if (!SafeRead(g_addresses.base + kBuildIdRva, buildId))
            return;

        if (root != g_lastRoot || buildId != g_lastBuildId)
        {
            g_lastRoot = root;
            g_lastBuildId = buildId;
            Log("offline state root=0x%llX build_id=0x%08X", static_cast<unsigned long long>(root), buildId);
        }

        std::int32_t count = 0;
        std::uintptr_t array = 0;
        std::size_t stride = 0, fieldA = 0, fieldB = 0, fieldC = 0;

        if (buildId == kStateLayout208A || buildId == kStateLayout208B)
        {
            if (!ReadExternal(root + 8, &count, sizeof(count)) || !ReadExternal(root + 16, &array, sizeof(array)))
                return;
            stride = 208; fieldA = 20; fieldB = 72; fieldC = 76;
        }
        else if (buildId == kStateLayout216)
        {
            if (!ReadExternal(root + 16, &count, sizeof(count)) || !ReadExternal(root + 24, &array, sizeof(array)))
                return;
            stride = 216; fieldA = 36; fieldB = 80; fieldC = 84;
        }
        else
        {
            if (g_lastUnsupportedBuildId != buildId)
            {
                g_lastUnsupportedBuildId = buildId;
                Log("offline state layout unknown for build_id=0x%08X; no state-array writes applied", buildId);
            }
            return;
        }

        if (!array || count <= 0 || count > 256)
            return;

        for (std::int32_t i = 0; i < count; ++i)
        {
            const auto entry = array + static_cast<std::uintptr_t>(i) * stride;
            (void)WriteExternal32(entry + fieldA, 0);
            (void)WriteExternal32(entry + fieldB, 2);
            (void)WriteExternal32(entry + fieldC, 3);
        }
    }

    bool WaitForRuntimeAndBootstrap()
    {
        constexpr DWORD kTimeoutMs = 45000;
        const ULONGLONG start = GetTickCount64();
        std::uint8_t last = 0xFF;
        while (GetTickCount64() - start < kTimeoutMs)
        {
            NormalizeOfflineState();
            std::uint8_t ready = 0;
            if (SafeRead(g_addresses.runtimeReadyFlag, ready))
            {
                if (ready != last)
                {
                    Log("runtime ready flag=%u", static_cast<unsigned int>(ready));
                    last = ready;
                }
                if (ready == 1)
                    break;
            }
            Sleep(150);
        }

        std::uint8_t ready = 0;
        if (!SafeRead(g_addresses.runtimeReadyFlag, ready) || ready != 1)
        {
            Log("runtime ready timeout; falling back to recovered Beta network handoff");
            return false;
        }

        std::uintptr_t context = 0;
        if (!SafeRead(g_addresses.runtimeContextSlot, context) || !context)
        {
            Log("runtime context null; falling back to recovered Beta network handoff");
            return false;
        }

        __try
        {
            g_addresses.runtimeBootstrap(reinterpret_cast<void*>(context), true, false);
            g_addresses.preModeReset(0, 0, "");
            Log("runtime bootstrap complete context=0x%llX", static_cast<unsigned long long>(context));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log("runtime bootstrap fault code=0x%08lX", static_cast<unsigned long>(GetExceptionCode()));
            return false;
        }
    }

    DWORD WINAPI MaintenanceThread(LPVOID)
    {
        Log("maintenance=start automatic state normalization; no mode hotkeys");
        for (;;)
        {
            NormalizeOfflineState();
            Sleep(50);
        }
    }

    void StartMaintenance()
    {
        if (g_maintenanceStarted.exchange(true, std::memory_order_acq_rel))
            return;
        HANDLE thread = CreateThread(nullptr, 0, &MaintenanceThread, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
        else
            g_maintenanceStarted.store(false, std::memory_order_release);
    }
}

namespace beta_offline
{
    bool TryActivate()
    {
        if (!IsExactBeta())
            return false;

        Log("attempt=start exact Open Beta fingerprint confirmed");
        if (!ResolveWithRetry())
        {
            Log("attempt=skip reason=live_signature_set_not_resolved");
            return false;
        }

        if (!ApplyMultiplayerMode())
        {
            Log("attempt=skip reason=multiplayer_mode_failed");
            return false;
        }

        if (!WaitForRuntimeAndBootstrap())
        {
            Log("attempt=skip reason=runtime_bootstrap_failed");
            return false;
        }

        StartMaintenance();
        Log("attempt=success frontend=offline_multiplayer normal_navigation_expected=1");
        return true;
    }
}
