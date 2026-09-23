#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "../../../shared/core/CoreRuntime.h"
#include "../../../shared/compat/games/common/GameTypes.h"
#include "../game/T9Addresses.h"
#include "../game/ColdWarPatches.h"
#include "../game/alpha/AlphaSupport.h"
#include "../game/beta/BetaSupport.h"
#include "../../../shared/patches/Win11Patch.h"
#include "../../../shared/runtime/CrashDiagnostics.h"
#include "../../../shared/runtime/scanner/UniversalScanner.h"
#include "../../../shared/runtime/network/UniversalLan.h"
#include "../../../shared/runtime/ClientIdentity.h"

namespace
{
    enum class ColdWarIniLaunchMode
    {
        OfflineLan,
        OnlinePassthrough
    };

    struct ColdWarIniSelection
    {
        ColdWarIniLaunchMode mode = ColdWarIniLaunchMode::OfflineLan;
        int offline = 0;
        int online = 0;
        wchar_t path[MAX_PATH]{};
    };

    bool BuildColdWarIniPath(wchar_t (&path)[MAX_PATH]) noexcept
    {
        path[0] = L'\0';
        const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (!length || length >= MAX_PATH)
            return false;

        wchar_t* slash = wcsrchr(path, L'\\');
        wchar_t* slashAlt = wcsrchr(path, L'/');
        if (!slash || (slashAlt && slashAlt > slash))
            slash = slashAlt;

        if (slash)
            *(slash + 1) = L'\0';
        else
            path[0] = L'\0';

        return wcscat_s(path, L"CodRevamped.ini") == 0;
    }

    void EnsureDefaultColdWarIni(const wchar_t* path) noexcept
    {
        if (!path || !*path || GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
            return;

        HANDLE file = CreateFileW(
            path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;

        static constexpr char contents[] =
            "; CodRevamped Cold War startup selector\r\n"
            "; Set exactly ONE option to 1.\r\n"
            "; offline=1 -> CodRevamped Offline/LAN client\r\n"
            "; online=1  -> normal Cold War online passthrough (no offline/network patches)\r\n"
            "; If both are 0 or both are 1, Offline/LAN is used as the safe default.\r\n"
            "\r\n"
            "[ColdWar]\r\n"
            "offline=0\r\n"
            "online=0\r\n";

        DWORD written = 0;
        WriteFile(file, contents, static_cast<DWORD>(sizeof(contents) - 1), &written, nullptr);
        CloseHandle(file);
    }

    ColdWarIniSelection LoadColdWarIniSelection() noexcept
    {
        ColdWarIniSelection selection{};
        if (!BuildColdWarIniPath(selection.path))
            return selection;

        EnsureDefaultColdWarIni(selection.path);
        selection.offline = GetPrivateProfileIntW(
            L"ColdWar", L"offline", 0, selection.path);
        selection.online = GetPrivateProfileIntW(
            L"ColdWar", L"online", 0, selection.path);

        if (selection.online == 1 && selection.offline != 1)
            selection.mode = ColdWarIniLaunchMode::OnlinePassthrough;
        return selection;
    }

    bool ReadImage(games::ExecutableInfo& out) noexcept
    {
        out = {};
        out.module = GetModuleHandleW(nullptr);
        if (!out.module)
            return false;

        __try
        {
            const auto base = reinterpret_cast<const unsigned char*>(out.module);
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;

            out.timestamp = nt->FileHeader.TimeDateStamp;
            out.imageSize = nt->OptionalHeader.SizeOfImage;
            out.entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
            GetModuleFileNameW(nullptr, out.executableName, MAX_PATH);
            const wchar_t* slash = wcsrchr(out.executableName, L'\\');
            if (slash)
                memmove(out.executableName, slash + 1, (wcslen(slash + 1) + 1) * sizeof(wchar_t));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool IsFingerprint(const games::ExecutableInfo& image, const t9_addresses::Fingerprint& fp) noexcept
    {
        return image.timestamp == fp.timestamp &&
               image.imageSize == fp.imageSize &&
               (!fp.entryPointRva || image.entryPointRva == fp.entryPointRva);
    }

    DWORD WINAPI Bootstrap(LPVOID) noexcept
    {
        games::ExecutableInfo image{};
        if (!ReadImage(image))
            return 1;

        games::GameKind kind = games::GameKind::Unknown;
        if (IsFingerprint(image, t9_addresses::AlphaFingerprint))
            kind = games::GameKind::Alpha;
        else if (IsFingerprint(image, t9_addresses::BetaFingerprint))
            kind = games::GameKind::Beta;
        else if (image.timestamp == 0x60368381u && image.imageSize == 0x1DDC8000u && image.entryPointRva == 0x0CBD66A0u)
            kind = games::GameKind::S2;
        else if (IsFingerprint(image, t9_addresses::RetailFingerprint))
            kind = games::GameKind::Retail;
        else
        {
            // A future Steam retail update must never be treated as the legacy
            // Open Beta simply because its fingerprint changed.  Route unknown
            // modern T9 builds through Retail first; InitializeRetail will reject
            // stale RVAs safely and the fallback scanner below will capture the
            // new executable without applying guessed writes.
            kind = games::GameKind::Retail;
        }

        const ColdWarIniSelection iniSelection = LoadColdWarIniSelection();
        if (iniSelection.mode == ColdWarIniLaunchMode::OnlinePassthrough)
        {
            core_runtime::SetStartupMode(core_runtime::StartupMode::OnlineResearch);
            OutputDebugStringW(
                L"[CODREVAMPED] CodRevamped.ini selected ONLINE passthrough; standalone Cold War client patches are disabled.\n");
            return 0;
        }

        core_runtime::SetActiveGame(kind);

        if (kind == games::GameKind::Alpha || kind == games::GameKind::Beta)
        {
            const ULONGLONG start = GetTickCount64();
            while (!patches::win11::HasApplied() && GetTickCount64() - start < 10000ull)
                Sleep(1);

            if (!patches::win11::HasApplied())
                return 0;

            Sleep(2000);
            core_runtime::InitializeConsole();
            core_runtime::StartCommandConsole();
            crash_diagnostics::InstallVectoredOnly();

            if (kind == games::GameKind::Alpha)
            {
                alpha_support::Initialize();
                return 0;
            }

            // v7: Open Beta is re-enabled only as a Retail-style focused
            // scanner/direct-camo research target. Do NOT start the legacy Beta
            // recovered frontend/Lua/state bootstrap; that entire path remains
            // compiled but dormant while we discover this build's equivalent
            // addresses automatically.
            core_runtime::SetStartupMode(core_runtime::StartupMode::OfflineLan);
            core_runtime::InstallEarlyNetworkBlocker();
            core_runtime::SetModuleBase();
            core_runtime::InitializeBetaFocusedResearch();
            return 0;
        }

        core_runtime::SetStartupMode(core_runtime::StartupMode::OfflineLan);
        core_runtime::InstallEarlyNetworkBlocker();
        universal_lan::Initialize(kind);
        core_runtime::InitializeConsole();
        core_runtime::SetModuleBase();

        if (kind == games::GameKind::Retail)
        {
            if (!core_runtime::InitializeRetail())
            {
                // New/changed retail executable: never apply stale RVAs. The
                // release scanner is limited to Offline/LAN + custom-camo targets.
                core_runtime::StartCommandConsole();
                core_runtime::StartReadOnlyScanner();
                std::printf("[UPDATE-SCAN] Unknown Retail fingerprint; focused Offline/LAN + camo scanner active.\n");
                return 0;
            }
            // v47.94: keep the standalone path consistent with GameManager.
            // Do not touch the T9 controller/user object from bootstrap; apply
            // the saved name later via /username once the frontend is live.
            std::printf("[IDENTITY] Startup T9 profile write deferred for crash safety; use /username after frontend readiness if needed.\n");
            return 0;
        }

        core_runtime::StartCommandConsole();
        std::printf("[RELEASE] Broad address/Lua scanner disabled for this Cold War build.\n");
        return 0;
    }
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        core_runtime::SetSelfModule(module);

        // Cold War owns the Cold War Win11 profiles. No IW8/T8/T10 router is
        // linked into this DLL.
        coldwar_patches::InitializeEarly();

        HANDLE thread = CreateThread(nullptr, 0, Bootstrap, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
    }
    return TRUE;
}
