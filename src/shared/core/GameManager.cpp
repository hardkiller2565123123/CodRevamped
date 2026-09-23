#include "GameManager.h"
#include "CoreRuntime.h"
#include "../compat/game/Dvar.h"
#include "../compat/startup/AlphaSupport.h"
#include "../runtime/LogPaths.h"
#include "../../clients/mw2019/game/IW8Module.h"
#include "../../clients/mw2019/game/IW8Addresses.h"
#include "../../clients/mw2019/game/IW8LegacyBridge.h"
#include "../../clients/coldwar/game/T9Addresses.h"
#include "../../clients/coldwar/game/season2/Season2Support.h"
#include "../compat/network/UniversalLan.h"
#include "../../clients/bo4/game/T8Module.h"
#include "../compat/games/t10/T10Module.h"
#include "../compat/scanner/UniversalScanner.h"
#include "../compat/universal/ClientIdentity.h"
#include <array>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <string>


namespace
{
    games::ExecutableInfo g_image{};
    game_manager::BuildProfile g_profile{};
    DWORD g_mainThreadId = 0;
    volatile LONG g_alphaHotkeyThreadStarted = 0;

    bool RecoverAlphaFrontend()
    {
        if (alpha_support::EnterFrontend())
            return true;

        // Recovery fallback: clear the current session first, then retry the
        // alpha-specific frontend-ready + SetScreen path.  This is deliberately
        // repeatable so F1 can be used whenever the legacy frontend gets stuck.
        alpha_support::Disconnect();
        Sleep(125);
        return alpha_support::EnterFrontend();
    }

    bool RecoverAlphaZombies()
    {
        // SwitchZombies writes the validated legacy Alpha mode state and
        // disconnects. Follow it with the same frontend recovery path so F2
        // works both as a mode switch and as a way out of a failed transition.
        const bool modeOk = alpha_support::SwitchZombies();
        Sleep(125);
        const bool frontendOk = RecoverAlphaFrontend();
        return modeOk && frontendOk;
    }

    DWORD WINAPI AlphaRecoveryHotkeyThread(LPVOID)
    {
        std::printf(
            "[ALPHA-HOTKEY] F1=Force Frontend  F2=Force Zombies\n");

        for (;;)
        {
            if (GetAsyncKeyState(VK_F1) & 1)
            {
                std::printf(
                    "[ALPHA-HOTKEY] F1 -> frontend recovery\n");
                const bool ok = RecoverAlphaFrontend();
                std::printf(
                    "[ALPHA-HOTKEY] frontend recovery %s\n",
                    ok ? "OK" : "FAILED");
            }

            if (GetAsyncKeyState(VK_F2) & 1)
            {
                std::printf(
                    "[ALPHA-HOTKEY] F2 -> zombies recovery\n");
                const bool ok = RecoverAlphaZombies();
                std::printf(
                    "[ALPHA-HOTKEY] zombies recovery %s\n",
                    ok ? "OK" : "FAILED");
            }

            Sleep(30);
        }
    }

    void StartAlphaRecoveryHotkeys()
    {
        if (InterlockedCompareExchange(
            &g_alphaHotkeyThreadStarted, 1, 0) != 0)
            return;

        HANDLE thread = CreateThread(
            nullptr, 0, AlphaRecoveryHotkeyThread, nullptr, 0, nullptr);
        if (!thread)
        {
            InterlockedExchange(&g_alphaHotkeyThreadStarted, 0);
            std::printf(
                "[ALPHA-HOTKEY] FAILED to create recovery hotkey thread\n");
            return;
        }

        CloseHandle(thread);
    }

    constexpr int kButtonOffline = 1001;
    constexpr int kButtonOnline = 1002;

    struct StartupSelectorState
    {
        core_runtime::StartupMode mode =
            core_runtime::StartupMode::OfflineLan;
        bool chosen = false;
    };

    bool IsLegacyAlphaImage(const games::ExecutableInfo& image)
    {
        return
            image.timestamp == t9_addresses::AlphaFingerprint.timestamp &&
            image.imageSize == t9_addresses::AlphaFingerprint.imageSize &&
            image.entryPointRva == t9_addresses::AlphaFingerprint.entryPointRva;
    }

    bool IsOpenBetaImage(const games::ExecutableInfo& image)
    {
        return
            image.timestamp == t9_addresses::BetaFingerprint.timestamp &&
            image.imageSize == t9_addresses::BetaFingerprint.imageSize &&
            image.entryPointRva == t9_addresses::BetaFingerprint.entryPointRva;
    }

    bool IsSeason2Image(const games::ExecutableInfo& image)
    {
        return
            image.timestamp == t9_addresses::Season2Fingerprint.timestamp &&
            image.imageSize == t9_addresses::Season2Fingerprint.imageSize &&
            image.entryPointRva == t9_addresses::Season2Fingerprint.entryPointRva;
    }

    LRESULT CALLBACK StartupSelectorWndProc(
        HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        auto* state = reinterpret_cast<StartupSelectorState*>(
            GetWindowLongPtrW(hwnd, GWLP_USERDATA));

        if (message == WM_NCCREATE)
        {
            const auto* create =
                reinterpret_cast<const CREATESTRUCTW*>(lParam);
            SetWindowLongPtrW(
                hwnd, GWLP_USERDATA,
                reinterpret_cast<LONG_PTR>(create->lpCreateParams));
            return TRUE;
        }

        if (message == WM_COMMAND && state)
        {
            const int id = LOWORD(wParam);
            if (id == kButtonOffline || id == kButtonOnline)
            {
                state->mode =
                    id == kButtonOnline
                    ? core_runtime::StartupMode::OnlineResearch
                    : core_runtime::StartupMode::OfflineLan;
                state->chosen = true;
                DestroyWindow(hwnd);
                return 0;
            }
        }

        if (message == WM_CLOSE && state)
        {
            // Closing the selector defaults to the normal safe client mode.
            state->mode = core_runtime::StartupMode::OfflineLan;
            state->chosen = true;
            DestroyWindow(hwnd);
            return 0;
        }

        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    core_runtime::StartupMode ShowStartupModeSelector()
    {
        StartupSelectorState state{};

        const wchar_t* className = L"T9ClientStartupSelector";
        WNDCLASSW wc{};
        wc.lpfnWndProc = StartupSelectorWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = className;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground =
            reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        RegisterClassW(&wc);

        HWND window = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
            className,
            L"T9 Client Startup",
            WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT,
            470, 210,
            nullptr, nullptr,
            wc.hInstance,
            &state);

        if (!window)
            return core_runtime::StartupMode::OfflineLan;

        CreateWindowExW(
            0, L"STATIC",
            L"Choose how this Cold War instance should start.\n"
            L"Public DNS and public network endpoints stay blocked in BOTH modes.",
            WS_CHILD | WS_VISIBLE,
            24, 22, 410, 52,
            window, nullptr, wc.hInstance, nullptr);

        CreateWindowExW(
            0, L"BUTTON",
            L"Offline / LAN",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            35, 92, 180, 48,
            window,
            reinterpret_cast<HMENU>(
                static_cast<INT_PTR>(kButtonOffline)),
            wc.hInstance, nullptr);

        CreateWindowExW(
            0, L"BUTTON",
            L"Online Research",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            250, 92, 180, 48,
            window,
            reinterpret_cast<HMENU>(
                static_cast<INT_PTR>(kButtonOnline)),
            wc.hInstance, nullptr);

        ShowWindow(window, SW_SHOW);
        UpdateWindow(window);
        SetForegroundWindow(window);

        MSG msg{};
        while (!state.chosen &&
            GetMessageW(&msg, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        UnregisterClassW(className, wc.hInstance);
        return state.mode;
    }

    HANDLE SuspendMainThreadForSelector()
    {
        if (!g_mainThreadId ||
            g_mainThreadId == GetCurrentThreadId())
            return nullptr;

        HANDLE thread = OpenThread(
            THREAD_SUSPEND_RESUME |
            THREAD_QUERY_INFORMATION,
            FALSE,
            g_mainThreadId);

        if (!thread)
            return nullptr;

        if (SuspendThread(thread) ==
            static_cast<DWORD>(-1))
        {
            CloseHandle(thread);
            return nullptr;
        }

        return thread;
    }

    void ResumeHeldMainThread(HANDLE thread)
    {
        if (!thread)
            return;
        ResumeThread(thread);
        CloseHandle(thread);
    }

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
        bool created = false;
        bool conflict = false;
        bool noSelection = false;
        wchar_t path[MAX_PATH]{};
    };

    bool BuildColdWarIniPath(wchar_t (&path)[MAX_PATH])
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

    bool CreateDefaultColdWarIni(const wchar_t* path)
    {
        if (!path || !*path)
            return false;

        HANDLE file = CreateFileW(
            path,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file == INVALID_HANDLE_VALUE)
            return GetLastError() == ERROR_FILE_EXISTS ||
                   GetLastError() == ERROR_ALREADY_EXISTS;

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
        const BOOL ok = WriteFile(
            file,
            contents,
            static_cast<DWORD>(sizeof(contents) - 1),
            &written,
            nullptr);
        CloseHandle(file);
        return ok && written == sizeof(contents) - 1;
    }

    ColdWarIniSelection LoadColdWarIniSelection()
    {
        ColdWarIniSelection selection{};
        if (!BuildColdWarIniPath(selection.path))
        {
            selection.noSelection = true;
            return selection;
        }

        const DWORD attributes = GetFileAttributesW(selection.path);
        if (attributes == INVALID_FILE_ATTRIBUTES)
            selection.created = CreateDefaultColdWarIni(selection.path);

        selection.offline = GetPrivateProfileIntW(
            L"ColdWar", L"offline", 0, selection.path);
        selection.online = GetPrivateProfileIntW(
            L"ColdWar", L"online", 0, selection.path);

        const bool offlineEnabled = selection.offline == 1;
        const bool onlineEnabled = selection.online == 1;
        selection.conflict = offlineEnabled && onlineEnabled;
        selection.noSelection = !offlineEnabled && !onlineEnabled;

        // Preserve the current client behavior as the safe fallback. Only an
        // unambiguous online=1/offline=0 selection disables CodRevamped's T9
        // runtime and lets the original online game startup pass through.
        selection.mode =
            onlineEnabled && !offlineEnabled
                ? ColdWarIniLaunchMode::OnlinePassthrough
                : ColdWarIniLaunchMode::OfflineLan;
        return selection;
    }

    constexpr std::array<game_manager::BuildProfile, 7> kProfiles{ {
        { games::GameKind::Retail, "T9 Retail", t9_addresses::RetailFingerprint.timestamp, t9_addresses::RetailFingerprint.imageSize, false },
        { games::GameKind::Alpha,  "T9 June 4 Alpha", t9_addresses::AlphaFingerprint.timestamp, t9_addresses::AlphaFingerprint.imageSize, true },
        { games::GameKind::S2,     "S2", 0, 0, true },
        { games::GameKind::Beta,   "T9 Open Beta (focused scanner)", t9_addresses::BetaFingerprint.timestamp, t9_addresses::BetaFingerprint.imageSize, true },
        { games::GameKind::IW8,    "IW8 / MW2019", 0, 0, true },
        { games::GameKind::T8,     "T8 / Black Ops 4", 0, 0, true },
        { games::GameKind::T10,    "T10 / Black Ops 6", 0, 0, true },
    } };

    bool ContainsNoCase(const wchar_t* text, const wchar_t* needle)
    {
        if (!text || !needle) return false;
        wchar_t copy[MAX_PATH]{};
        wcsncpy_s(copy, text, _TRUNCATE);
        _wcslwr_s(copy);
        wchar_t wanted[64]{};
        wcsncpy_s(wanted, needle, _TRUNCATE);
        _wcslwr_s(wanted);
        return wcsstr(copy, wanted) != nullptr;
    }

    bool ReadExecutableInfo(games::ExecutableInfo& out)
    {
        out = {};
        out.module = GetModuleHandleW(nullptr);
        if (!out.module) return false;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(out.module);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const unsigned char*>(out.module) + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
            out.timestamp = nt->FileHeader.TimeDateStamp;
            out.imageSize = nt->OptionalHeader.SizeOfImage;
            out.entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
            GetModuleFileNameW(nullptr, out.executableName, MAX_PATH);
            const wchar_t* slash = wcsrchr(out.executableName, L'\\');
            if (slash) memmove(out.executableName, slash + 1, (wcslen(slash + 1) + 1) * sizeof(wchar_t));
            return out.imageSize != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    game_manager::BuildProfile SelectProfile(const games::ExecutableInfo& image)
    {
        games::IW8Module iw8{};
        if (iw8.Matches(image))
        {
            auto profile =
                kProfiles[4];

            const auto variant =
                games::IW8Module::DetectVariant(
                    image);

            profile.name =
                games::IW8Module::VariantName(
                    variant);

            return profile;
        }

        if (IsLegacyAlphaImage(image))
            return kProfiles[1];
        if (IsOpenBetaImage(image))
            return kProfiles[3];
        if (image.timestamp == t9_addresses::RetailFingerprint.timestamp &&
            image.imageSize == t9_addresses::RetailFingerprint.imageSize)
            return kProfiles[0];
        if (IsSeason2Image(image) ||
            ContainsNoCase(image.executableName, L"s2_") ||
            ContainsNoCase(image.executableName, L"s2sp") ||
            ContainsNoCase(image.executableName, L"s2mp"))
            return kProfiles[2];
        games::T8Module t8{};
        if (t8.Matches(image))
            return kProfiles[5];
        games::T10Module t10{};
        if (t10.Matches(image))
        {
            auto profile = kProfiles[6];
            profile.name =
                games::T10Module::VariantName(
                    games::T10Module::DetectVariant(image));
            return profile;
        }
        if (ContainsNoCase(image.executableName, L"blackopscoldwar") || ContainsNoCase(image.executableName, L"t9"))
        {
            // Steam retail updates keep the retail release path even when the
            // fingerprint changes. InitializeRetail() will reject stale RVAs and
            // the focused release scanner will relocate only Offline/LAN + camo
            // targets. Never misclassify a new retail build as the old Open Beta.
            auto profile = kProfiles[0];
            profile.name = "T9 Retail (update scan)";
            return profile;
        }
        return {};
    }

    DWORD InitializeSelectedBuild()
    {
        core_runtime::SetActiveGame(g_profile.kind);
        universal_scanner::SetGame(g_profile.kind);
        std::string identityLoad;
        client_identity::Load(identityLoad);
        std::printf("[IDENTITY] %s\n", identityLoad.c_str());
        std::printf("[BUILD] Selected %s profile (timestamp=0x%08lX image=0x%08lX exe=%ls).\n",
            g_profile.name, g_image.timestamp, g_image.imageSize, g_image.executableName);

        switch (g_profile.kind)
        {
        case games::GameKind::Retail:
            if (!core_runtime::InitializeRetail())
            {
                // Never terminate the game just because the executable changed.
                // Keep stale RVAs disabled and collect a fresh update report.
                core_runtime::StartCommandConsole();
                core_runtime::StartReadOnlyScanner();
                std::printf("[UPDATE-SCAN] Retail initialization did not validate; focused Offline/LAN + camo relocation scan armed.\n");
                return 0;
            }
            std::printf(
                "[UPDATE-SCAN] Focused Offline/LAN + camo address profile active; broad function/Lua research is disabled.\n");
            // v47.94: do not call LiveUser_GetUserDataForController from the
            // bootstrap worker. s_inited proved unreliable as a readiness gate
            // on this Retail build, and this early identity application was the
            // remaining post-InitializeRetail game-side call. The persistent
            // name is already loaded; /username <name> can apply it later after
            // the frontend is actually live.
            std::printf("[IDENTITY] Startup T9 profile write deferred for crash safety; saved identity remains loaded. Use /username after the frontend is live if needed.\n");
            return 0;
        case games::GameKind::Alpha:
        {
            std::printf("[ALPHA] Scanner-only profile selected; optional legacy controls are managed through GameManager.\n");
            // AlphaSupport::Initialize() is a void initializer in the current
            // interface. The recovery entry points perform their own validation,
            // so initialize support first and then arm the recovery hotkeys.
            alpha_support::Initialize();
            StartAlphaRecoveryHotkeys();
            core_runtime::StartCommandConsole();
            std::printf("[RELEASE] Alpha broad address/Lua scanner disabled; existing playable support kept.\n");
            return 0;
        }
        case games::GameKind::S2:
        {
            std::printf("[S2] Existing Season 2 playable support selected; broad address/Lua scanner disabled for release.\n");
            if (!season2_support::StartRecoveredClient())
                std::printf("[S2] Recovered client did not start because exact Season 2 validation failed.\n");
            core_runtime::StartCommandConsole();
            return 0;
        }
        case games::GameKind::Beta:
            // v7 intentionally does NOT revive the old BetaSupport/BetaResearch
            // frontend/Lua/state implementation. The exact Beta now uses the
            // same narrow self-relocating address/direct-camo research style as
            // Retail so we can learn the build without speculative game calls.
            std::printf("[BETA] Open Beta focused scanner profile selected; legacy Beta runtime remains disabled.\n");
            return core_runtime::InitializeBetaFocusedResearch() ? 0 : 1;
        case games::GameKind::IW8:
        {
            games::IW8Module iw8{};
            return iw8.Initialize(g_image);
        }
        case games::GameKind::T8:
        {
            games::T8Module t8{};
            return t8.Initialize(g_image);
        }
        case games::GameKind::T10:
        {
            games::T10Module t10{};
            return t10.Initialize(g_image);
        }
        default:
            std::printf("[BUILD] Unknown executable; no game-specific writes or hooks installed.\n");
            core_runtime::StartReadOnlyScanner();
            return 0;
        }
    }

    DWORD BootstrapIW8Early()
    {
        // IW8 must never pass through T9 gameplay/frontend hooks.  The shared
        // public DNS/connect/sendto safety blocker is intentionally installed
        // here as well so MW2019 gets the same network isolation policy.
        core_runtime::InitializeConsole();
        core_runtime::RecordStartupStage("console-ready-iw8");

        core_runtime::SetModuleBase();
        core_runtime::RecordStartupStage("module-base-ready-iw8");

        core_runtime::InstallEarlyNetworkBlocker();
        core_runtime::RecordStartupStage("public-network-blocker-installed-iw8");
        universal_lan::Initialize(games::GameKind::IW8);
        core_runtime::RecordStartupStage("universal-lan-ready-iw8");

        std::printf(
            "[BOOTSTRAP] IW8 detected before T9 initialization. "
            "Public DNS/network blocker ACTIVE; Cold War-specific gameplay/frontend hooks skipped.\n");

        g_profile = SelectProfile(g_image);
        core_runtime::SetActiveGame(g_profile.kind);
        core_runtime::RecordStartupStage(
            "profile-selected",
            g_profile.name);

        // Do not bind GameManager to a specific IW8Variant enumerator name.
        // The IW8 module owns variant naming and older/newer headers do not all
        // expose a Steam167 enum member. Detect 1.67 through the module's public
        // variant-name API instead.
        const auto iw8Variant =
            games::IW8Module::DetectVariant(g_image);
        const char* iw8VariantName =
            games::IW8Module::VariantName(iw8Variant);
        const bool isSteam167 =
            iw8VariantName &&
            (std::strstr(iw8VariantName, "1.67") != nullptr ||
                std::strstr(iw8VariantName, "167") != nullptr);

        if (isSteam167)
        {
            static bool legacyStarted = false;
            if (!legacyStarted)
            {
                legacyStarted = true;
                std::printf(
                    "[IW8] Starting full legacy 1.67 core outside DllMain.\n");
                CodRevamped_IW8Legacy_Attach(167);
            }
        }

        return InitializeSelectedBuild();
    }

    DWORD WINAPI BootstrapThread(LPVOID)
    {
        core_runtime::RecordStartupStage("bootstrap-enter");

        // Build262: identify IW8 before any T9-specific selector/network/hook
        // behavior. Runtime base comes from GetModuleHandle, so ASLR is handled.
        if (ReadExecutableInfo(g_image))
        {
            games::IW8Module iw8{};
            if (iw8.Matches(g_image))
            {
                core_runtime::RecordStartupStage(
                    "iw8-supported-build-detected-early");
                return BootstrapIW8Early();
            }
            games::T8Module t8{};
            if (t8.Matches(g_image))
            {
                core_runtime::InitializeConsole();
                core_runtime::SetModuleBase();
                core_runtime::InstallEarlyNetworkBlocker();
                universal_lan::Initialize(games::GameKind::T8);
                g_profile = SelectProfile(g_image);
                return InitializeSelectedBuild();
            }

            games::T10Module t10{};
            if (t10.Matches(g_image))
            {
                // BO6 must be allowed to complete its normal platform launch.
                // This profile is research/scanner-only and deliberately does
                // not install the offline public-network/auth blocker.
                core_runtime::InitializeConsole();
                core_runtime::SetModuleBase();
                g_profile = SelectProfile(g_image);
                return InitializeSelectedBuild();
            }
        }

        // v47.93: choose the Cold War client path from CodRevamped.ini in the
        // game/executable directory. The file is generated automatically on the
        // first launch with offline=0 and online=0. An unambiguous online=1
        // selection is a true passthrough path: no T9 network blocker, offline
        // frontend, LAN bridge, scanners, or other CodRevamped game patches are
        // installed. Everything else preserves the existing Offline/LAN default.
        const ColdWarIniSelection iniSelection = LoadColdWarIniSelection();
        if (iniSelection.mode == ColdWarIniLaunchMode::OnlinePassthrough)
        {
            core_runtime::SetStartupMode(core_runtime::StartupMode::OnlineResearch);
            core_runtime::RecordStartupStage(
                "mode-online-passthrough",
                "CodRevamped.ini online=1 offline=0; T9 runtime bypassed");
            OutputDebugStringW(
                L"[CODREVAMPED] CodRevamped.ini selected ONLINE passthrough; Cold War client patches are disabled.\n");
            return 0;
        }

        core_runtime::SetStartupMode(core_runtime::StartupMode::OfflineLan);
        core_runtime::RecordStartupStage("mode-offline-lan");

        core_runtime::InstallEarlyNetworkBlocker();
        core_runtime::RecordStartupStage("public-network-blocker-installed-t9");

        log_paths::EnsureAll();
        core_runtime::InitializeConsole();
        core_runtime::RecordStartupStage("console-ready");
        std::printf(
            "[MODE-INI] %ls  offline=%d online=%d%s%s -> OFFLINE/LAN\n",
            iniSelection.path[0] ? iniSelection.path : L"CodRevamped.ini",
            iniSelection.offline,
            iniSelection.online,
            iniSelection.created ? " (created)" : "",
            iniSelection.conflict
                ? " (both enabled; safe default)"
                : (iniSelection.noSelection ? " (neither enabled; safe default)" : ""));
        core_runtime::SetModuleBase();
        core_runtime::RecordStartupStage("module-base-ready");

        // Do not delay or suspend the game here.  The Retail initializer runs on
        // this bootstrap worker and performs its own readiness checks while the
        // native game/Steam launch path continues normally.

        if (!ReadExecutableInfo(g_image))
        {
            std::printf("[BUILD] Failed to read executable metadata.\n");
            return 1;
        }

        g_profile = SelectProfile(g_image);
        core_runtime::RecordStartupStage("profile-selected", g_profile.name);

        // Initialize the shared LAN layer for the actual detected Cold War build.
        // Unknown/new Steam retail fingerprints are deliberately routed to Retail
        // above so StartReadOnlyScanner() remains active after Steam launches it.
        if (g_profile.kind != games::GameKind::Beta)
        {
            universal_lan::Initialize(
                g_profile.kind == games::GameKind::Unknown
                    ? games::GameKind::Retail
                    : g_profile.kind);
        }
        else
        {
            std::printf("[BETA] Universal LAN runtime hooks are intentionally deferred until the focused scanner resolves/validates the Beta layout.\n");
        }

        std::printf("[BOOTSTRAP] Cold War release mode: Offline/LAN + custom camos.\n");
        std::printf("[BOOTSTRAP] Broad Lua/GSC/function research disabled.\n");

        const DWORD result = InitializeSelectedBuild();

        core_runtime::RecordStartupStage(
            result == 0 ? "bootstrap-complete" : "bootstrap-failed");
        std::printf("[BOOTSTRAP] Game-specific initialization returned %lu.\n", result);
        return result;
    }
}

namespace game_manager
{
    void SetMainThreadId(DWORD threadId)
    {
        g_mainThreadId = threadId;
    }

    void Start(HMODULE)
    {
        HANDLE thread = CreateThread(nullptr, 0, BootstrapThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    const BuildProfile& ActiveProfile() { return g_profile; }
    const games::ExecutableInfo& ActiveImage() { return g_image; }
}
