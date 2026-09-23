#include "BO4Entry.h"

#include "BlackoutBetaResearch.h"
#include "T8BuildProfile.h"
#include "T8FullBridge.h"
#include "T8Runtime.h"
#include "T8Scanner.h"
#include "../../../shared/common/runtime/Addressing.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

// The original Multiplayer Beta unlocker/decompiler probe is part of the BO4
// static project. It is research data for the same version.dll, not a proxy DLL.
#include "MultiplayerBetaResearch.inl"

namespace
{
    std::atomic_bool g_betaBootstrapStarted{ false };
    std::atomic_bool g_fullClientAttached{ false };

    void EnsureConsole()
    {
        bool available = GetConsoleWindow() != nullptr;
        if (!available && AttachConsole(ATTACH_PARENT_PROCESS))
            available = true;
        if (!available && AllocConsole())
            available = true;
        if (!available)
            return;

        FILE* stream = nullptr;
        freopen_s(&stream, "CONOUT$", "w", stdout);
        freopen_s(&stream, "CONOUT$", "w", stderr);
        freopen_s(&stream, "CONIN$", "r", stdin);

        std::wstring title = L"CodRevamped - BO4 / T8 - ";
        switch (t8_build::Active())
        {
        case t8_addresses::Build::MultiplayerBetaAug2018: title += L"Multiplayer Beta"; break;
        case t8_addresses::Build::BlackoutBetaSep2018: title += L"Blackout Beta"; break;
        case t8_addresses::Build::LatestBnet: title += L"Retail"; break;
        default: title += L"Unknown"; break;
        }
        SetConsoleTitleW(title.c_str());
    }

    void WriteFamilyProfileMarker()
    {
        const auto build = t8_build::Active();
        const auto& set = t8_build::ActiveAddressSet();
        const auto pe = t8_build::ReadPeFingerprint();

        std::error_code ec;
        std::filesystem::create_directories(t8_build::LogFolder(build), ec);
        const std::filesystem::path path =
            std::filesystem::path(t8_build::LogFolder(build)) / "family_profile.log";

        std::ofstream out(path, std::ios::app);
        if (!out)
            return;

        out << "profile=" << t8_build::Key(build) << "\n"
            << "label=" << set.fingerprint->label << "\n"
            << "runtime_model=RETAIL_BO4_SHARED_BASE\n"
            << "single_output=version.dll\n"
            << "timestamp=0x" << std::hex << std::uppercase << pe.timestamp << "\n"
            << "image_size=0x" << pe.imageSize << "\n"
            << "entry_rva=0x" << pe.entryPointRva << "\n"
            << "address_entries=" << std::dec << set.namedCount << "\n"
            << "retail_map_entries=" << set.retailMapCount << "\n"
            << "full_client_address_map=" << (set.fullClientAddressMapComplete ? "complete" : "partial") << "\n";
    }

    DWORD WINAPI BetaSharedBootstrap(LPVOID)
    {
        EnsureConsole();
        WriteFamilyProfileMarker();

        std::printf(
            "\n=========================================\n"
            "CodRevamped - BO4 Shared T8 Family\n"
            "=========================================\n"
            "[T8] profile=%s\n"
            "[T8] Retail BO4 is the common implementation base.\n"
            "[T8] Beta differences live in fingerprint/address/patch tables.\n"
            "[T8] output=version.dll (no dxgi client/proxy).\n",
            t8_build::Key(t8_build::Active()));

        std::string runtimeMessage;
        const bool runtimeOk = t8_runtime::Initialize(runtimeMessage);
        std::printf("[T8] shared runtime %s: %s\n", runtimeOk ? "ready" : "failed", runtimeMessage.c_str());

        std::string scanMessage;
        t8_scanner::Run(t8_scanner::Mode::All, scanMessage);

        if (!t8_build::FullClientAddressMapComplete())
        {
            std::printf(
                "[T8] Beta-safe startup: retail Shield entry/TLS bootstrap is disabled while "
                "the beta address map is partial. Stock entry/TLS callbacks are untouched; "
                "shared runtime/scanner/research remains active.\n");
        }

        if (t8_build::IsMultiplayerBeta())
        {
            std::printf("[T8-MP-BETA] starting original-unlocker recovery scanner inside shared BO4 runtime.\n");
            t8_mp_beta::StartAutomatic();
        }
        else if (t8_build::IsBlackoutBeta())
        {
            std::printf("[T8-BLACKOUT] starting Blackout research inside shared BO4 runtime.\n");
            t8_blackout_beta::StartAutomatic();
        }

        return 0;
    }

    void StartBetaBootstrapOnce()
    {
        bool expected = false;
        if (!g_betaBootstrapStarted.compare_exchange_strong(expected, true))
            return;

        HANDLE thread = CreateThread(nullptr, 0, &BetaSharedBootstrap, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
        else
            g_betaBootstrapStarted.store(false);
    }
}

namespace bo4_entry
{
    bool IsMultiplayerBetaSupported()
    {
        return t8_build::IsMultiplayerBeta();
    }

    bool IsBlackoutBetaSupported()
    {
        return t8_build::IsBlackoutBeta();
    }

    void StartMultiplayerBetaResearch()
    {
        if (t8_build::IsMultiplayerBeta())
            t8_mp_beta::StartAutomatic();
    }

    void ProcessAttach()
    {
        if (!t8_build::IsBlackOps4Process())
            return;

        const auto build = t8_build::Active();

        // Make the global _g literal profile-aware only while this BO4 client is
        // active. Other game clients continue using Common's normal preferred-VA
        // translation because they never install this callback.
        codrevamped::address::set_preferred_resolver(&t8_build::TranslatePreferredAddress);

        // Retail keeps the recovered Shield entry/TLS bootstrap. The 2018 beta
        // executables do NOT use it until their full address map is complete.
        // EarlyAttach patches the game entry point and TLS callbacks; doing that
        // with the partial beta map can terminate the beta before the passive
        // research worker finishes (the console appears briefly, then closes).
        // Keep beta startup stock and run only the read-only profile/scanner path.
        if (build == t8_addresses::Build::LatestBnet)
        {
            g_fullClientAttached.store(CodRevamped_T8Shield_EarlyAttach());
        }
        else
        {
            g_fullClientAttached.store(false);
            StartBetaBootstrapOnce();
        }
    }

    void ProcessDetach()
    {
        if (g_fullClientAttached.exchange(false))
            CodRevamped_T8Shield_PreDestroy();

        codrevamped::address::clear_preferred_resolver();
    }

    void StartBlackoutBetaDedicated()
    {
        if (t8_build::IsBlackoutBeta())
            StartBetaBootstrapOnce();
    }

    void StartMultiplayerBetaDedicated()
    {
        if (t8_build::IsMultiplayerBeta())
            StartBetaBootstrapOnce();
    }
}
