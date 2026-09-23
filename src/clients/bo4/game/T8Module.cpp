#include "T8Module.h"
#include "T8BuildProfile.h"
#include "T8FullBridge.h"
#include "T8Runtime.h"
#include "T8Scanner.h"
#include "BlackoutBetaResearch.h"
#include "BO4Entry.h"
#include "../../../shared/runtime/scanner/UniversalScanner.h"
#include "../../../shared/runtime/ClientIdentity.h"
#include "../../../shared/core/CoreRuntime.h"

#include <cwchar>
#include <cstdio>
#include <string>

namespace
{
    bool IsT8Name(const wchar_t* n)
    {
        if (!n)
            return false;

        wchar_t s[MAX_PATH]{};
        wcsncpy_s(s, n, _TRUNCATE);
        _wcslwr_s(s);

        return
            wcsstr(s, L"blackops4.exe") != nullptr ||
            wcsstr(s, L"blackops4") != nullptr ||
            wcsstr(s, L"t8") != nullptr;
    }
}

namespace games
{
    GameKind T8Module::Kind() const noexcept
    {
        return GameKind::T8;
    }

    const char* T8Module::Name() const noexcept
    {
        return "T8 / Black Ops 4";
    }

    bool T8Module::Matches(const ExecutableInfo& image) const noexcept
    {
        return IsT8Name(image.executableName);
    }

    DWORD T8Module::Initialize(const ExecutableInfo&) noexcept
    {
        const auto build = t8_build::Active();
        const auto& set = t8_build::ActiveAddressSet();

        std::printf(
            "\n=========================================\n"
            "T8 / Black Ops 4 - CodRevamped\n"
            "=========================================\n"
            "[T8] profile=%s label=%s\n"
            "[T8] Retail BO4 is the shared implementation base for all T8 builds.\n"
            "[T8] Build-specific differences are isolated to fingerprints, RVAs, and validated patch bytes.\n",
            t8_build::Key(build), set.fingerprint->label);

        core_runtime::InitializeConsole();
        core_runtime::StartCommandConsole();

        std::string adapterMessage;
        const bool adapterOk = t8_runtime::Initialize(adapterMessage);
        std::printf("[T8] shared adapter %s: %s\n", adapterOk ? "ready" : "read-only", adapterMessage.c_str());

        std::string addressScan;
        t8_scanner::Run(t8_scanner::Mode::All, addressScan);

        universal_scanner::SetGame(GameKind::T8);
        universal_scanner::StartAutomatic();

        std::string identity;
        client_identity::ApplyForGame(GameKind::T8, identity);
        std::printf("[T8] identity: %s\n", identity.c_str());

        if (build == t8_addresses::Build::LatestBnet)
        {
            std::printf("[T8] Full Shield component loader is active from early process attach.\n");
        }
        else
        {
            std::printf(
                "[T8] Full retail component source is compiled for this beta too; "
                "address-dependent hooks remain gated until its central beta RVA map is complete.\n");

            if (build == t8_addresses::Build::MultiplayerBetaAug2018)
                bo4_entry::StartMultiplayerBetaResearch();
            else if (build == t8_addresses::Build::BlackoutBetaSep2018)
                t8_blackout_beta::StartAutomatic();
        }

        return 0;
    }
}
