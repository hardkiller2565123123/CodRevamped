#include "Season2Support.h"

#include "../T9Addresses.h"
#include "../../../../shared/common/utils/pattern_scan.hpp"
#include "../../../../shared/patches/Win11Patch.h"
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
#include <string>

namespace
{
    constexpr DWORD kSeason2Timestamp = t9_addresses::Season2Fingerprint.timestamp;
    constexpr DWORD kSeason2ImageSize = t9_addresses::Season2Fingerprint.imageSize;
    constexpr DWORD kSeason2EntryRva = t9_addresses::Season2Fingerprint.entryPointRva;

    constexpr std::uintptr_t kBuildIdRva = 0x011017B0u;
    constexpr std::uintptr_t kLegacyAlphaMarkerRva = 0x02602E18u;
    constexpr std::uint32_t kLegacyAlphaMarkerValue = 0x5F1B8329u;

    constexpr std::uint32_t kStateLayout208A = 0x8348B74Eu;
    constexpr std::uint32_t kStateLayout216 = 0xB8ECE9C1u;
    constexpr std::uint32_t kStateLayout208B = 0xE9CC1D0Eu;

    // Exact patterns reconstructed from the supplied Season 2 discord_game_sdk.dll.
    // These are intentionally kept in the Season 2 build implementation rather
    // than Common/Patches because they are T9 build knowledge.
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

    constexpr const char* kSetUsernamePattern =
        "48 89 5C 24 ?? 57 48 83 EC 20 48 8B D9 4C 8B C2 "
        "BA ?? ?? ?? ?? 48 81 C1 ?? ?? ?? ??";

    constexpr const char* kGetUserContextCallsitePattern =
        "E8 ?? ?? ?? ?? 48 8B E8 33 C0 48 89 85 ?? ?? ?? ?? 48 8D 4D 10 "
        "48 89 85 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ??";

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

    constexpr const char* kDvarGetBoolPattern =
        "83 79 ?? 01 8B 41 ?? 48 89 5C 24 ??";

    constexpr const char* kDvarPointerSlotPattern =
        "48 8B 0D ?? ?? ?? ?? 41 0F 28 F2 F3 0F 5E F0 "
        "C7 44 24 ?? ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 28 FE "
        "44 0F 28 C6 F3 0F 59 3D ?? ?? ?? ?? 44 0F 28 CE "
        "F3 0F 59 35 ?? ?? ?? ??";

    constexpr const char* kOfflineStateMarkerPattern =
        "2C 08 4E 3C AC 67 D3 78";

    constexpr const char* kRuntimeContextSlotPattern =
        "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 01 75 ?? "
        "48 8B 0F 8D 68 ?? 44 8B F8 48 85 C9";

    constexpr const char* kRuntimeReadyFlagPattern =
        "38 ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 ?? 4F B6 E2 AE 25 2E C1 17";

    constexpr const char* kCbufAddTextPattern =
        "48 89 5C 24 08 57 48 83 EC 30 45 33 C0 48 63 F9 48 8B DA "
        "48 8D 4C 24 ?? 41 8D 50 ??";

    using RuntimeBootstrapFn = void(__fastcall*)(void*, bool, bool);
    using PreModeResetFn = void(__fastcall*)(int, int, const char*);
    using GetUserContextFn = void*(__fastcall*)(int);
    using SetUsernameFn = void(__fastcall*)(void*, const char*);
    using PrepareFrontendModeFn = void(__fastcall*)(int);
    using SetSessionStateFn = void(__fastcall*)(int);
    using SetGameModeFn = void(__fastcall*)(int);
    using GetMapContextFn = unsigned int(__fastcall*)(int);
    using SetMapFn = void(__fastcall*)(unsigned int, const char*);
    using SetGametypeFn = void(__fastcall*)(const char*, bool);
    using CbufAddTextFn = void(__fastcall*)(int, const char*);

    struct Addresses
    {
        std::uintptr_t base{};
        DWORD imageSize{};

        RuntimeBootstrapFn runtimeBootstrap{};
        PreModeResetFn preModeReset{};
        GetUserContextFn getUserContext{};
        SetUsernameFn setUsername{};
        PrepareFrontendModeFn prepareFrontendMode{};
        SetSessionStateFn setSessionState{};
        SetGameModeFn setGameMode{};
        GetMapContextFn getMapContext{};
        SetMapFn setMap{};
        SetGametypeFn setGametype{};
        CbufAddTextFn cbufAddText{};

        std::uintptr_t enableFlagA{};
        std::uintptr_t enableFlagB{};
        std::uintptr_t dvarGetBool{};
        std::uintptr_t dvarPointerSlot{};
        std::uintptr_t offlineStateRootSlot{};
        std::uintptr_t runtimeContextSlot{};
        std::uintptr_t runtimeReadyFlag{};
    };

    Addresses g_addresses{};
    std::atomic_bool g_started{ false };
    std::atomic_bool g_resolved{ false };
    std::atomic<std::uintptr_t> g_originalDvarPointer{ 0 };
    std::atomic_bool g_dvarTrapRepaired{ false };
    PVOID g_dvarTrapVeh = nullptr;
    std::mutex g_logMutex;
    std::uint32_t g_lastBuildId = 0;
    std::uintptr_t g_lastStateRoot = 0;

    std::filesystem::path LogDirectory()
    {
        const auto dir = storage_paths::Logs() / L"t9_s2";
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
        const auto path = LogDirectory() / L"season2_support.log";
        std::ofstream out(path, std::ios::app);
        if (out)
            out << message << '\n';

        std::printf("[T9-S2] %s\n", message);
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

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                return false;
            }

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

    bool IsInsideImage(std::uintptr_t address, std::size_t size = 1)
    {
        if (!address || !g_addresses.base || !g_addresses.imageSize || !size)
            return false;

        const auto end = g_addresses.base + g_addresses.imageSize;
        return address >= g_addresses.base &&
               address < end &&
               size <= end - address;
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
        const bool readable = p == PAGE_READONLY || p == PAGE_READWRITE ||
            p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READ ||
            p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
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
        return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    template <typename T>
    bool SafeRead(std::uintptr_t address, T& out)
    {
        if (!IsReadable(address, sizeof(T)))
            return false;

        SIZE_T got = 0;
        return ReadProcessMemory(
                   GetCurrentProcess(),
                   reinterpret_cast<const void*>(address),
                   &out,
                   sizeof(T),
                   &got) &&
               got == sizeof(T);
    }

    template <typename T>
    bool SafeWrite(std::uintptr_t address, const T& value)
    {
        if (!IsInsideImage(address, sizeof(T)))
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
        {
            return false;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_READWRITE, &oldProtect))
            return false;

        SIZE_T wrote = 0;
        const BOOL ok = WriteProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<void*>(address),
            &value,
            sizeof(T),
            &wrote);

        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &ignored);
        return ok && wrote == sizeof(T);
    }

    bool IsReadableExternal(std::uintptr_t address, std::size_t size)
    {
        if (!address || !size)
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
        {
            return false;
        }

        const DWORD p = mbi.Protect & 0xFFu;
        const bool readable = p == PAGE_READONLY || p == PAGE_READWRITE ||
            p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READ ||
            p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        if (!readable)
            return false;

        const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return address <= regionEnd && size <= regionEnd - address;
    }

    LONG CALLBACK Season2DvarTrapVeh(PEXCEPTION_POINTERS info)
    {
        if (!info || !info->ExceptionRecord || !info->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        const auto dvarGetBool = g_addresses.dvarGetBool;
        const auto original = g_originalDvarPointer.load(std::memory_order_acquire);
        if (!dvarGetBool || !original)
            return EXCEPTION_CONTINUE_SEARCH;

        const auto* record = info->ExceptionRecord;
        auto* context = info->ContextRecord;
        if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
            reinterpret_cast<std::uintptr_t>(record->ExceptionAddress) != dvarGetBool ||
            static_cast<std::uintptr_t>(context->Rip) != dvarGetBool ||
            static_cast<std::uintptr_t>(context->Rcx) != 1)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // The supplied discord_game_sdk.dll deliberately writes pointer value 1
        // into this dvar slot, then repairs RCX from its RtlDispatchException
        // hook. CodRevamped does not need that recurring exception as its own
        // frontend tick is independent. Repair this single compatibility trap,
        // restore the real slot, and let Dvar_GetBool continue normally.
        context->Rcx = static_cast<DWORD64>(original);
        // Do not call VirtualProtect/WriteProcessMemory from inside the VEH.
        // The normal Season 2 worker repairs the global slot immediately after
        // this one exception has been allowed to resume.
        g_dvarTrapRepaired.store(true, std::memory_order_release);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    bool InstallDvarTrapCompatibility()
    {
        if (!g_addresses.dvarGetBool || !g_addresses.dvarPointerSlot)
        {
            Log("dvar trap compatibility unavailable: target or slot unresolved");
            return false;
        }

        std::uintptr_t current = 0;
        if (!SafeRead(g_addresses.dvarPointerSlot, current))
        {
            Log("dvar trap compatibility unavailable: slot unreadable");
            return false;
        }

        if (current != 1 && IsReadableExternal(current, 0x28))
        {
            g_originalDvarPointer.store(current, std::memory_order_release);
            Log("captured original Dvar pointer=0x%llX", static_cast<unsigned long long>(current));
        }
        else if (current == 1)
        {
            // If the supplied Season 2 discord proxy reached DiscordCreate
            // before our worker, recover the pointer it saved at its known
            // g_OriginalDvarPointer slot. Guard this with its export RVA so an
            // unrelated official Discord SDK is never treated as this helper.
            const auto helper = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"discord_game_sdk.dll"));
            const auto discordCreate = helper
                ? reinterpret_cast<std::uintptr_t>(GetProcAddress(reinterpret_cast<HMODULE>(helper), "DiscordCreate"))
                : 0;
            constexpr std::uintptr_t kHelperDiscordCreateRva = 0x43D0u;
            constexpr std::uintptr_t kHelperOriginalDvarPointerRva = 0x11DD8u;

            std::uintptr_t helperOriginal = 0;
            if (helper && discordCreate == helper + kHelperDiscordCreateRva &&
                IsReadableExternal(helper + kHelperOriginalDvarPointerRva, sizeof(helperOriginal)))
            {
                SIZE_T got = 0;
                if (ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(helper + kHelperOriginalDvarPointerRva),
                        &helperOriginal,
                        sizeof(helperOriginal),
                        &got) &&
                    got == sizeof(helperOriginal) && IsReadableExternal(helperOriginal, 0x28))
                {
                    g_originalDvarPointer.store(helperOriginal, std::memory_order_release);
                    Log("recovered original Dvar pointer from supplied discord helper=0x%llX",
                        static_cast<unsigned long long>(helperOriginal));
                }
            }

            if (!g_originalDvarPointer.load(std::memory_order_acquire))
            {
                Log("dvar pointer slot already contains trap value 1 and helper original pointer was unavailable; leaving trap handler unarmed");
                return false;
            }
        }
        else
        {
            Log("dvar pointer slot contains unexpected value=0x%llX; leaving trap handler unarmed",
                static_cast<unsigned long long>(current));
            return false;
        }

        g_dvarTrapVeh = AddVectoredExceptionHandler(1, &Season2DvarTrapVeh);
        Log("dvar trap compatibility VEH installed=%u", g_dvarTrapVeh ? 1u : 0u);
        return g_dvarTrapVeh != nullptr;
    }

    void RepairDvarSlotIfTrapped()
    {
        const auto original = g_originalDvarPointer.load(std::memory_order_acquire);
        if (!original || !g_addresses.dvarPointerSlot)
            return;

        std::uintptr_t current = 0;
        if (SafeRead(g_addresses.dvarPointerSlot, current) && current == 1)
        {
            if (SafeWrite(g_addresses.dvarPointerSlot, original))
            {
                if (!g_dvarTrapRepaired.exchange(true, std::memory_order_acq_rel))
                {
                    Log("repaired supplied-helper Dvar trap before execution slot=0x%llX original=0x%llX",
                        static_cast<unsigned long long>(g_addresses.dvarPointerSlot - g_addresses.base),
                        static_cast<unsigned long long>(original));
                }
            }
        }
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

    void LogResolvedAddress(const char* name, std::uintptr_t address, bool executable)
    {
        if (!address)
            return;
        Log("resolved: %s rva=0x%llX valid=%u", name,
            static_cast<unsigned long long>(address - g_addresses.base),
            executable ? (IsExecutable(address) ? 1u : 0u) : (IsReadable(address) ? 1u : 0u));
    }

    bool ResolveOfflineStateRootSlot()
    {
        const auto marker = Find("offline_state_marker", kOfflineStateMarkerPattern);
        if (!marker || marker < g_addresses.base + 3)
            return false;

        // The original helper searches backward from marker-2 for the preceding
        // `48 89 05 disp32` store and resolves its RIP-relative destination.
        const auto floor = marker > g_addresses.base + 0x2000
            ? marker - 0x2000
            : g_addresses.base;

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
        if (!g_addresses.base)
            return false;

        DWORD timestamp = 0;
        DWORD entryRva = 0;
        if (!ReadFingerprint(timestamp, g_addresses.imageSize, entryRva) ||
            timestamp != kSeason2Timestamp ||
            g_addresses.imageSize != kSeason2ImageSize ||
            entryRva != kSeason2EntryRva)
        {
            return false;
        }

        auto runtimeBootstrap = Find("RuntimeBootstrap.primary", kRuntimeBootstrapA);
        if (!runtimeBootstrap)
            runtimeBootstrap = Find("RuntimeBootstrap.fallback", kRuntimeBootstrapB);
        g_addresses.runtimeBootstrap = reinterpret_cast<RuntimeBootstrapFn>(runtimeBootstrap);

        const auto flagAInstruction = Find("EnableFlagA.locator", kEnableFlagAPattern);
        g_addresses.enableFlagA = flagAInstruction ? ResolveRel32(flagAInstruction, 2, 7) : 0;

        const auto flagBInstruction = Find("EnableFlagB.locator", kEnableFlagBPattern);
        g_addresses.enableFlagB = flagBInstruction ? ResolveRel32(flagBInstruction, 2, 7) : 0;

        g_addresses.preModeReset = reinterpret_cast<PreModeResetFn>(
            Find("PreModeReset", kPreModeResetPattern));
        g_addresses.setUsername = reinterpret_cast<SetUsernameFn>(
            Find("SetUsername", kSetUsernamePattern));

        const auto userContextCallsite = Find("GetUserContext.callsite", kGetUserContextCallsitePattern);
        g_addresses.getUserContext = reinterpret_cast<GetUserContextFn>(
            userContextCallsite ? ResolveRel32(userContextCallsite, 1, 5) : 0);

        g_addresses.prepareFrontendMode = reinterpret_cast<PrepareFrontendModeFn>(
            Find("PrepareFrontendMode", kPrepareFrontendModePattern));
        g_addresses.setSessionState = reinterpret_cast<SetSessionStateFn>(
            Find("SetSessionState", kSetSessionStatePattern));
        g_addresses.setGameMode = reinterpret_cast<SetGameModeFn>(
            Find("SetGameMode", kSetGameModePattern));

        const auto mapContextCallsite = Find("GetMapContext.callsite", kGetMapContextCallsitePattern);
        g_addresses.getMapContext = reinterpret_cast<GetMapContextFn>(
            mapContextCallsite ? ResolveRel32(mapContextCallsite, 1, 5) : 0);

        const auto setMapCallsite = Find("SetMap.callsite", kSetMapCallsitePattern);
        g_addresses.setMap = reinterpret_cast<SetMapFn>(
            setMapCallsite ? ResolveRel32(setMapCallsite, 1, 5) : 0);

        const auto gametypeThunk = Find("SetGametype.thunk", kSetGametypeThunkPattern);
        g_addresses.setGametype = reinterpret_cast<SetGametypeFn>(
            gametypeThunk ? ResolveRel32(gametypeThunk, 1, 5) : 0);

        g_addresses.dvarGetBool = Find("DvarGetBool", kDvarGetBoolPattern);
        const auto dvarSlotInstruction = Find("DvarPointerSlot.locator", kDvarPointerSlotPattern);
        g_addresses.dvarPointerSlot = dvarSlotInstruction
            ? ResolveRel32(dvarSlotInstruction, 3, 7)
            : 0;

        (void)ResolveOfflineStateRootSlot();

        const auto runtimeContextInstruction = Find("RuntimeContextSlot.locator", kRuntimeContextSlotPattern);
        g_addresses.runtimeContextSlot = runtimeContextInstruction
            ? ResolveRel32(runtimeContextInstruction, 3, 7)
            : 0;

        const auto readyInstruction = Find("RuntimeReadyFlag.locator", kRuntimeReadyFlagPattern);
        g_addresses.runtimeReadyFlag = readyInstruction
            ? ResolveRel32(readyInstruction, 2, 6)
            : 0;

        g_addresses.cbufAddText = reinterpret_cast<CbufAddTextFn>(
            Find("Cbuf_AddText", kCbufAddTextPattern));

        LogResolvedAddress("RuntimeBootstrap", reinterpret_cast<std::uintptr_t>(g_addresses.runtimeBootstrap), true);
        LogResolvedAddress("EnableFlagA", g_addresses.enableFlagA, false);
        LogResolvedAddress("EnableFlagB", g_addresses.enableFlagB, false);
        LogResolvedAddress("PreModeReset", reinterpret_cast<std::uintptr_t>(g_addresses.preModeReset), true);
        LogResolvedAddress("GetUserContext", reinterpret_cast<std::uintptr_t>(g_addresses.getUserContext), true);
        LogResolvedAddress("SetUsername", reinterpret_cast<std::uintptr_t>(g_addresses.setUsername), true);
        LogResolvedAddress("PrepareFrontendMode", reinterpret_cast<std::uintptr_t>(g_addresses.prepareFrontendMode), true);
        LogResolvedAddress("SetSessionState", reinterpret_cast<std::uintptr_t>(g_addresses.setSessionState), true);
        LogResolvedAddress("SetGameMode", reinterpret_cast<std::uintptr_t>(g_addresses.setGameMode), true);
        LogResolvedAddress("GetMapContext", reinterpret_cast<std::uintptr_t>(g_addresses.getMapContext), true);
        LogResolvedAddress("SetMap", reinterpret_cast<std::uintptr_t>(g_addresses.setMap), true);
        LogResolvedAddress("SetGametype", reinterpret_cast<std::uintptr_t>(g_addresses.setGametype), true);
        LogResolvedAddress("DvarGetBool", g_addresses.dvarGetBool, true);
        LogResolvedAddress("DvarPointerSlot", g_addresses.dvarPointerSlot, false);
        LogResolvedAddress("OfflineStateRootSlot", g_addresses.offlineStateRootSlot, false);
        LogResolvedAddress("RuntimeContextSlot", g_addresses.runtimeContextSlot, false);
        LogResolvedAddress("RuntimeReadyFlag", g_addresses.runtimeReadyFlag, false);
        LogResolvedAddress("Cbuf_AddText", reinterpret_cast<std::uintptr_t>(g_addresses.cbufAddText), true);

        // These are the minimum targets used by the recovered offline path.
        const bool required =
            g_addresses.runtimeBootstrap &&
            g_addresses.preModeReset &&
            g_addresses.getUserContext &&
            g_addresses.setUsername &&
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
            Log("resolver incomplete: required Season 2 targets are missing; no game calls/writes will run");
            return false;
        }

        if (!IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.runtimeBootstrap)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.preModeReset)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.getUserContext)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setUsername)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.prepareFrontendMode)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setSessionState)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setGameMode)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.getMapContext)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setMap)) ||
            !IsExecutable(reinterpret_cast<std::uintptr_t>(g_addresses.setGametype)) ||
            !IsReadable(g_addresses.enableFlagA) ||
            !IsReadable(g_addresses.enableFlagB) ||
            !IsReadable(g_addresses.runtimeContextSlot, sizeof(std::uintptr_t)) ||
            !IsReadable(g_addresses.runtimeReadyFlag))
        {
            Log("resolver validation failed: one or more recovered targets have the wrong memory protection");
            return false;
        }

        return true;
    }

    bool ResolveWithRetry()
    {
        // The uploaded Season 2 EXE keeps large protected/encrypted code regions
        // on disk. The supplied discord DLL resolves these signatures only from
        // the live process. Use the existing early Win11 observation as a useful
        // handoff signal when available, then make only a few full-image passes.
        constexpr DWORD kWin11ObservationTimeoutMs = 15000;
        const ULONGLONG waitStart = GetTickCount64();
        while (!patches::win11::IsArmed() &&
               GetTickCount64() - waitStart < kWin11ObservationTimeoutMs)
        {
            Sleep(25);
        }

        Log("Win11 early profile observed=%u active=%s",
            patches::win11::IsArmed() ? 1u : 0u,
            patches::win11::ActiveProfileName());

        // Give the game a short quiet window after its exception/filter setup.
        Sleep(1000);

        constexpr unsigned kAttempts = 3;
        for (unsigned attempt = 1; attempt <= kAttempts; ++attempt)
        {
            Log("resolver attempt %u/%u", attempt, kAttempts);
            if (ResolveAddresses())
                return true;
            if (attempt != kAttempts)
                Sleep(5000);
        }
        return false;
    }

    void ForceRecoveredEnableFlags()
    {
        std::uint32_t marker = 0;
        if (SafeRead(g_addresses.base + kLegacyAlphaMarkerRva, marker) &&
            marker == kLegacyAlphaMarkerValue)
        {
            Log("enable flags skipped: legacy Alpha marker detected");
            return;
        }

        const std::uint8_t one = 1;
        const bool a = SafeWrite(g_addresses.enableFlagA, one);
        const bool b = SafeWrite(g_addresses.enableFlagB, one);
        Log("enable flags: A=%u B=%u", a ? 1u : 0u, b ? 1u : 0u);
    }

    bool SetMapAndGametype(const char* map, const char* gametype)
    {
        if (!map || !gametype)
            return false;

        unsigned int context = 0;
        __try
        {
            context = g_addresses.getMapContext(0);
            g_addresses.setMap(context, map);
            g_addresses.setGametype(gametype, true);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log("exception while setting map/gametype map=%s gametype=%s", map, gametype);
            return false;
        }
    }

    enum class Mode
    {
        Zombies = 0,
        Multiplayer = 1,
        Campaign = 2
    };

    bool ApplyInitialMode(Mode mode)
    {
        __try
        {
            if (mode == Mode::Zombies)
            {
                g_addresses.prepareFrontendMode(11);
                g_addresses.setSessionState(1);
                g_addresses.setGameMode(0);
                ForceRecoveredEnableFlags();
                const bool mapOk = SetMapAndGametype("zm_silver", "zclassic");
                Log("initial mode=Zombies map=zm_silver gametype=zclassic map_ok=%u", mapOk ? 1u : 0u);
                return true;
            }

            if (mode == Mode::Multiplayer)
            {
                // Match the supplied helper startup path exactly: initial --multiplayer uses `dm`.
                const bool mapOk = SetMapAndGametype("mp_moscow", "dm");
                g_addresses.prepareFrontendMode(11);
                g_addresses.setSessionState(1);
                g_addresses.setGameMode(1);
                ForceRecoveredEnableFlags();
                Log("initial mode=Multiplayer map=mp_moscow gametype=dm map_ok=%u", mapOk ? 1u : 0u);
                return true;
            }

            g_addresses.prepareFrontendMode(10);
            g_addresses.setSessionState(1);
            g_addresses.setGameMode(2);
            ForceRecoveredEnableFlags();
            Log("initial mode=Campaign");
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log("exception while applying initial mode=%d", static_cast<int>(mode));
            return false;
        }
    }

    Mode CommandLineMode()
    {
        const char* commandLine = GetCommandLineA();
        if (commandLine && std::strstr(commandLine, "--zombies"))
            return Mode::Zombies;
        if (commandLine && std::strstr(commandLine, "--multiplayer"))
            return Mode::Multiplayer;
        return Mode::Campaign;
    }

    void ApplyRecoveredUsername()
    {
        __try
        {
            void* context = g_addresses.getUserContext(0);
            if (!context)
            {
                Log("username skipped: user context is null");
                return;
            }
            g_addresses.setUsername(context, "Player1");
            Log("username applied: Player1");
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log("exception while applying recovered username");
        }
    }

    void NormalizeOfflineState()
    {
        if (!g_addresses.offlineStateRootSlot || !IsReadable(g_addresses.offlineStateRootSlot, sizeof(std::uintptr_t)))
            return;

        std::uintptr_t root = 0;
        if (!SafeRead(g_addresses.offlineStateRootSlot, root) || !root)
            return;

        // The root itself may live on a game heap rather than inside the EXE,
        // so use ReadProcessMemory directly after VirtualQuery validation.
        auto readExternal = [](std::uintptr_t address, void* out, std::size_t size) -> bool
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!address || !out || !size ||
                !VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) ||
                mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
            {
                return false;
            }
            const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (size > regionEnd - address)
                return false;
            SIZE_T got = 0;
            return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), out, size, &got) && got == size;
        };

        auto writeExternal32 = [](std::uintptr_t address, std::uint32_t value) -> bool
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!address ||
                !VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) ||
                mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
            {
                return false;
            }
            const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (sizeof(value) > regionEnd - address)
                return false;

            const DWORD protection = mbi.Protect & 0xFFu;
            const bool writable = protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
                protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
            if (!writable)
                return false;

            SIZE_T wrote = 0;
            return WriteProcessMemory(
                       GetCurrentProcess(),
                       reinterpret_cast<void*>(address),
                       &value,
                       sizeof(value),
                       &wrote) &&
                   wrote == sizeof(value);
        };

        std::uint32_t buildId = 0;
        if (!SafeRead(g_addresses.base + kBuildIdRva, buildId))
            return;

        if (buildId != g_lastBuildId || root != g_lastStateRoot)
        {
            g_lastBuildId = buildId;
            g_lastStateRoot = root;
            Log("offline state root=0x%llX build_id=0x%08X",
                static_cast<unsigned long long>(root), buildId);
        }

        std::int32_t count = 0;
        std::uintptr_t array = 0;
        std::size_t stride = 0;
        std::size_t fieldA = 0;
        std::size_t fieldB = 0;
        std::size_t fieldC = 0;

        if (buildId == kStateLayout208A || buildId == kStateLayout208B)
        {
            if (!readExternal(root + 8, &count, sizeof(count)) ||
                !readExternal(root + 16, &array, sizeof(array)))
                return;
            stride = 208;
            fieldA = 20;
            fieldB = 72;
            fieldC = 76;
        }
        else if (buildId == kStateLayout216)
        {
            if (!readExternal(root + 16, &count, sizeof(count)) ||
                !readExternal(root + 24, &array, sizeof(array)))
                return;
            stride = 216;
            fieldA = 36;
            fieldB = 80;
            fieldC = 84;
        }
        else
        {
            return;
        }

        if (!array || count <= 0 || count > 256)
            return;

        for (std::int32_t i = 0; i < count; ++i)
        {
            const auto entry = array + static_cast<std::uintptr_t>(i) * stride;
            (void)writeExternal32(entry + fieldA, 0);
            (void)writeExternal32(entry + fieldB, 2);
            (void)writeExternal32(entry + fieldC, 3);
        }
    }

    bool WaitForReadyAndBootstrap()
    {
        constexpr DWORD kReadyTimeoutMs = 120000;
        const ULONGLONG start = GetTickCount64();
        std::uint8_t last = 0xFF;

        while (GetTickCount64() - start < kReadyTimeoutMs)
        {
            RepairDvarSlotIfTrapped();
            NormalizeOfflineState();

            std::uint8_t ready = 0;
            if (SafeRead(g_addresses.runtimeReadyFlag, ready))
            {
                if (ready != last)
                {
                    Log("runtime ready flag=%u", static_cast<unsigned>(ready));
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
            Log("runtime ready wait timed out; bootstrap not called");
            return false;
        }

        std::uintptr_t context = 0;
        if (!SafeRead(g_addresses.runtimeContextSlot, context) || !context)
        {
            Log("runtime context slot is null; bootstrap not called");
            return false;
        }

        __try
        {
            g_addresses.runtimeBootstrap(reinterpret_cast<void*>(context), true, false);
            g_addresses.preModeReset(0, 0, "");
            Log("runtime bootstrap completed context=0x%llX", static_cast<unsigned long long>(context));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log("exception while calling runtime bootstrap");
            return false;
        }
    }

    void RunFrontendMaintenanceLoop()
    {
        Log("frontend maintenance active: automatic offline state normalization; mode hotkeys disabled");
        for (;;)
        {
            RepairDvarSlotIfTrapped();
            NormalizeOfflineState();
            Sleep(50);
        }
    }
}

namespace season2_support
{
    bool IsExactSeason2()
    {
        DWORD timestamp = 0;
        DWORD imageSize = 0;
        DWORD entryRva = 0;
        return ReadFingerprint(timestamp, imageSize, entryRva) &&
               timestamp == kSeason2Timestamp &&
               imageSize == kSeason2ImageSize &&
               entryRva == kSeason2EntryRva;
    }

    bool StartRecoveredClient()
    {
        if (!IsExactSeason2())
            return false;

        if (g_started.exchange(true, std::memory_order_acq_rel))
            return true;

        HANDLE thread = CreateThread(nullptr, 0, &RecoveredClientThread, nullptr, 0, nullptr);
        if (!thread)
        {
            g_started.store(false, std::memory_order_release);
            return false;
        }
        CloseHandle(thread);
        return true;
    }

    DWORD WINAPI RecoveredClientThread(LPVOID)
    {
        Log("exact profile confirmed timestamp=0x%08X image=0x%08X entry=0x%08X",
            kSeason2Timestamp, kSeason2ImageSize, kSeason2EntryRva);
        Log("source behavior: supplied discord_game_sdk.dll; live runtime signatures required because protected EXE is not plaintext on disk");

        if (!ResolveWithRetry())
        {
            Log("Season 2 resolver failed after retry window; no recovered offline writes/calls were applied");
            return 1;
        }

        g_resolved.store(true, std::memory_order_release);
        Log("all required recovered Season 2 targets resolved and validated");

        // The supplied Season 2 discord proxy deliberately turns a valid dvar
        // pointer into 1 later in startup and expects its own exception hook to
        // repair it. Capture the real pointer while it is still valid so our
        // version.dll can safely coexist with that proxy during migration.
        (void)InstallDvarTrapCompatibility();

        ApplyRecoveredUsername();
        (void)ApplyInitialMode(CommandLineMode());
        (void)WaitForReadyAndBootstrap();
        RunFrontendMaintenanceLoop();
        return 0;
    }
}
