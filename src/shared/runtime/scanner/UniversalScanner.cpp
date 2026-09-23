#include "UniversalScanner.h"
#include "AdvancedAnalysisScanner.h"
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
#include "../../../clients/mw2019/game/IW8ResearchScanner.h"
#include "../../../clients/mw2019/game/IW8Module.h"
#include "../../../clients/bo4/game/T8Scanner.h"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <atomic>
#include <cstdio>
#include <sstream>

namespace universal_scanner
{
    namespace
    {
        std::atomic_int g_game{ static_cast<int>(games::GameKind::Unknown) };
        std::atomic_bool g_running{ false };
        std::atomic_bool g_completed{ false };

        Profile ResolveProfile()
        {
            const auto game = static_cast<games::GameKind>(g_game.load());
            switch (game)
            {
            case games::GameKind::Retail: return Profile::T9Retail;
            case games::GameKind::Beta: return Profile::T9Beta;
            case games::GameKind::Alpha: return Profile::T9Alpha;
            case games::GameKind::S2: return Profile::S2_Generic;
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
            case games::GameKind::T8: return Profile::T8_BO4;
            case games::GameKind::IW8:
            {
                games::ExecutableInfo info{};
                info.module = GetModuleHandleW(nullptr);
                wchar_t path[MAX_PATH]{};
                GetModuleFileNameW(nullptr, path, MAX_PATH);
                const wchar_t* slash = wcsrchr(path, L'\\');
                wcsncpy_s(info.executableName, slash ? slash + 1 : path, _TRUNCATE);
                if (info.module)
                {
                    const auto base = reinterpret_cast<std::uintptr_t>(info.module);
                    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
                    if (dos->e_magic == IMAGE_DOS_SIGNATURE)
                    {
                        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
                        if (nt->Signature == IMAGE_NT_SIGNATURE)
                        {
                            info.timestamp = nt->FileHeader.TimeDateStamp;
                            info.imageSize = nt->OptionalHeader.SizeOfImage;
                            info.entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
                        }
                    }
                }
                return games::IW8Module::DetectVariant(info) == games::IW8Variant::Legacy144
                    ? Profile::IW8_144 : Profile::IW8_169;
            }
#endif
            default: return Profile::Unknown;
            }
        }

        DWORD WINAPI Worker(LPVOID)
        {
            std::string message;
            RunAll(message);
            std::printf("[UNIVERSAL-SCAN] %s\n", message.c_str());
            std::fflush(stdout);
            return 0;
        }
    }

    void SetGame(games::GameKind game) { g_game.store(static_cast<int>(game)); }
    Profile ActiveProfile() { return ResolveProfile(); }

    const char* ProfileName(Profile profile)
    {
        switch (profile)
        {
        case Profile::T9Retail: return "T9 Retail";
        case Profile::T9Beta: return "T9 Beta";
        case Profile::T9Alpha: return "T9 Alpha";
        case Profile::IW8_169: return "IW8 MW2019 1.69";
        case Profile::IW8_144: return "IW8 MW2019 1.44";
        case Profile::T8_BO4: return "T8 Black Ops 4";
        case Profile::S2_Generic: return "S2 generic";
        default: return "Unknown";
        }
    }

    void StartAutomatic()
    {
        const auto game = static_cast<games::GameKind>(g_game.load());
        if (game == games::GameKind::Retail || game == games::GameKind::Beta)
        {
            std::printf("[RELEASE] Broad universal/Lua/function scanner disabled for Cold War; focused release scanner only.\n");
            std::fflush(stdout);
            return;
        }
        if (g_running.exchange(true)) return;
        HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        else g_running.store(false);
    }

    bool RunFunctions(std::string& message)
    {
        const bool ok = scanner::RunAdvancedAnalysisPass();
        message = ok ? "function/caller/xref analysis complete" : "function analysis failed";
        return ok;
    }

    bool RunLua(std::string& message)
    {
        const auto p = ResolveProfile();
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
        if (p == Profile::IW8_169 || p == Profile::IW8_144)
            return iw8_research::Run(iw8_research::ScanMode::LuaLui, message);
        if (p == Profile::T8_BO4)
            return t8_scanner::Run(t8_scanner::Mode::Lua, message);
#endif
        message = "Lua pass is handled by this game's native profile/runtime dumper";
        return true;
    }

    bool RunFrontend(std::string& message)
    {
        const auto p = ResolveProfile();
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
        if (p == Profile::IW8_169 || p == Profile::IW8_144)
            return iw8_research::Run(iw8_research::ScanMode::Frontend, message);
        if (p == Profile::T8_BO4)
            return t8_scanner::Run(t8_scanner::Mode::Frontend, message);
#endif
        message = "frontend pass is handled by the generic function/xref analysis plus game profile";
        return true;
    }

    bool RunAll(std::string& message)
    {
        g_running.store(true);
        const auto profile = ResolveProfile();
        std::printf("[UNIVERSAL-SCAN] profile=%s starting function/caller/xref scan...\n", ProfileName(profile));
        std::fflush(stdout);

        std::string functionMessage;
        const bool functionOk = RunFunctions(functionMessage);

        bool specialOk = true;
        std::string specialMessage;
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
        if (profile == Profile::IW8_169 || profile == Profile::IW8_144)
        {
            specialOk = iw8_research::Run(iw8_research::ScanMode::All, specialMessage);
        }
        else if (profile == Profile::T8_BO4)
        {
            specialOk = t8_scanner::Run(t8_scanner::Mode::All, specialMessage);
        }
        else
#endif
        {
            specialMessage = "game-specific runtime scanner remains active through its profile";
        }

        g_completed.store(functionOk && specialOk);
        g_running.store(false);
        std::ostringstream out;
        out << "profile=" << ProfileName(profile)
            << " functions=" << (functionOk ? "complete" : "failed")
            << " specialized=" << (specialOk ? "complete" : "failed")
            << " -- dump complete";
        message = out.str();
        return functionOk && specialOk;
    }

    void PrintStatus()
    {
        std::printf("[UNIVERSAL-SCAN] profile=%s running=%s complete=%s\n",
            ProfileName(ResolveProfile()),
            g_running.load() ? "yes" : "no",
            g_completed.load() ? "yes" : "no");
        std::fflush(stdout);
    }
}
