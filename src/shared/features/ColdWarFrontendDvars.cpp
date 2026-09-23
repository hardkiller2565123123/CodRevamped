#include "ColdWarFrontendDvars.h"
#include "../core/CoreRuntime.h"
#include "../runtime/LogPaths.h"
#include "../../clients/coldwar/game/T9Dvar.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

namespace coldwar_frontend_dvars
{
    namespace
    {
        std::atomic_bool g_workerStarted{ false };
        std::atomic_bool g_applied{ false };
        std::atomic_uint g_successCount{ 0 };
        std::atomic_uint g_failureCount{ 0 };

        struct Command
        {
            const char* name;
            const char* value;
            const char* note;
        };

        // Frontend/content candidates learned from prior Cold War research.
        // No address is trusted here: every name must resolve through the
        // current executable's Dvar_FindVar path before its native setter is
        // called. Names absent from a build are simply skipped.
        const Command kCommands[] =
        {
            { "MNMLRKRSSL", "1", "enable_cod_account" },
            { "online_store_catalog_fence_enabled", "0", "disable store catalog fence" },
            { "LNKTTMTOMR", "0", "lui_tournament_allow_warzone_players" },
            { "LOQQOSNQKN", "1", "wz_private_match_enabled" },
            { "wz_private_match_enabled", "1", "semantic private-match alias when present" },
            { "wz_enable_blades_refresh", "1", "refresh S2+ frontend blades" },
            { "LKSKPKTOON", "1", "text_chat_enabled" },
            { "NQPKQNMQSR", "1", "display_ng_blade_enabled (research candidate)" },
            { "LQQNTKTLQK", "1", "battlenet_modify_install_enabled (research candidate)" },
            { "LKSTRMKTML", "1", "checkReleaseDLC" },
            { "challenge_summary_test", "1", "challenge_summary_test" },

            // Keep the LIVE-style frontend state available while the network
            // layer remains hard-isolated. This exposes the online-era menus,
            // loadout/custom-game presentation, and locally present content
            // without restoring official/public service connectivity.
            { "onlinegame", "1", "enable LIVE-style frontend semantics under offline isolation" },
            { "xblive_privatematch", "1", "prefer private/custom-match frontend while offline" },
            { "xblive_rankedmatch", "0", "keep ranked/public matchmaking disabled" },
            { "lobby_open", "1", "keep the local lobby frontend open" },
            { "lobby_open_for_pres_join", "1", "keep normal lobby presentation/join UI available" },
        };

        // These are the stock online/frontend state dvars we want when the user
        // asks /setmode multiplayer or /setmode zombies. They are semantic names,
        // not addresses, and are only applied when the running build actually
        // registers them. Official/public networking remains blocked elsewhere.
        const Command kHybridOnlineCommands[] =
        {
            { "onlinegame", "1", "use LIVE/online frontend semantics" },
            { "xblive_privatematch", "1", "prefer private/custom-match frontend while offline" },
            { "xblive_rankedmatch", "0", "leave ranked matchmaking disabled while offline" },
            { "lobby_open", "1", "keep local lobby frontend open" },
            { "lobby_open_for_pres_join", "1", "allow normal lobby presentation path" },
        };

        struct VerifiedDvar
        {
            const char* name;
            const char* value;
            const char* note;
        };

        // These are never blindly created.  Each name must resolve through the
        // running build's Dvar_FindVar path before CodRevamped attempts to set
        // it.  That keeps the automatic local-content pass update-safe: names
        // absent from this Cold War build are reported and skipped.
        const VerifiedDvar kVerifiedLocalUnlockDvars[] =
        {
            { "online_store_catalog_fence_enabled", "0", "disable store catalog fence" },
            { "unlockAllItems", "1", "engine-provided all-items debug gate" },
            { "force_unlock_all_attachments", "1", "engine-provided attachment gate" },
            { "force_unlock_all_attachment_lines", "1", "engine-provided attachment-line gate" },
            { "force_unlock_all_killstreaks", "1", "engine-provided killstreak gate" },
            { "force_unlock_all_camos", "1", "engine-provided camo gate if present" },
            { "force_unlock_all_blueprints", "1", "engine-provided blueprint gate if present" },
            { "force_unlock_all_operators", "1", "engine-provided operator gate if present" },
            { "force_unlock_all_outfits", "1", "engine-provided outfit gate if present" },
        };

        void LogLine(const std::string& line)
        {
            log_paths::EnsureAll();
            CreateDirectoryA("logs\\frontend", nullptr);

            std::ofstream out(
                "logs\\frontend\\coldwar_dvar_preset.log",
                std::ios::app);

            if (out)
                out << line << "\n";
        }

        unsigned int ApplyVerifiedLocalUnlockDvars()
        {
            unsigned int appliedCount = 0;
            std::printf("[CW-LOCAL-UNLOCK] probing build-registered local-content dvars...\n");
            std::fflush(stdout);

            for (const auto& candidate : kVerifiedLocalUnlockDvars)
            {
                t9_dvars::Entry entry{};
                if (!t9_dvars::VerifyCandidate(candidate.name, entry))
                {
                    std::ostringstream line;
                    line
                        << "SKIP " << candidate.name
                        << " // not registered in this build";
                    LogLine(line.str());

                    std::printf(
                        "[CW-LOCAL-UNLOCK] SKIP %s // not registered in this build\n",
                        candidate.name);
                    std::fflush(stdout);
                    continue;
                }

                std::string setMessage;
                const auto result =
                    t9_dvars::Execute(candidate.name, candidate.value, setMessage);
                const bool applied =
                    result == t9_dvars::ExecuteResult::Set ||
                    result == t9_dvars::ExecuteResult::Read;

                std::ostringstream line;
                line
                    << (applied ? "APPLIED " : "FAIL ")
                    << candidate.name
                    << "=" << candidate.value
                    << " // " << candidate.note;
                LogLine(line.str());

                std::printf(
                    "[CW-LOCAL-UNLOCK] %s %s=%s // %s\n",
                    applied ? "APPLIED" : "FAIL",
                    candidate.name,
                    candidate.value,
                    candidate.note);
                if (applied)
                    ++appliedCount;
                if (!applied && !setMessage.empty())
                    std::printf("[CW-LOCAL-UNLOCK]   %s\n", setMessage.c_str());
                std::fflush(stdout);
            }

            std::printf(
                "[CW-LOCAL-UNLOCK] verified local-content gates applied=%u\n",
                appliedCount);
            std::fflush(stdout);
            return appliedCount;
        }


        static std::string LowerCopy(std::string value)
        {
            std::transform(
                value.begin(), value.end(), value.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        }

        static bool ContainsAny(
            const std::string& value,
            const char* const* terms,
            size_t termCount)
        {
            for (size_t i = 0; i < termCount; ++i)
            {
                if (value.find(terms[i]) != std::string::npos)
                    return true;
            }
            return false;
        }

        // Future-proof content/frontend pass. Only verified, already-registered
        // boolean-like dvars are considered. It intentionally ignores purchase,
        // checkout, currency and commerce controls: the goal is offline content
        // presentation, not restoring transaction services.
        unsigned int ApplySemanticOfflineOnlineDvars()
        {
            static const char* kContentTerms[] =
            {
                "store", "catalog", "battlepass", "battle_pass", "itemshop", "item_shop",
                "operator", "outfit", "blueprint", "camo", "execution", "challenge",
                "prestige", "loadout", "inventory", "private_match", "privatematch"
            };
            static const char* kEnableTerms[] =
            {
                "enable", "enabled", "available", "visible", "show", "allow", "refresh"
            };
            static const char* kUnsafeTransactionTerms[] =
            {
                "purchase", "checkout", "transaction", "currency", "commerce", "payment"
            };

            t9_dvars::Refresh();
            const auto entries = t9_dvars::Entries({}, true);

            unsigned int applied = 0;
            unsigned int failed = 0;
            unsigned int considered = 0;

            for (const auto& entry : entries)
            {
                if (!entry.verified || entry.name.empty())
                    continue;

                const std::string lower = LowerCopy(entry.name);
                if (ContainsAny(
                        lower,
                        kUnsafeTransactionTerms,
                        sizeof(kUnsafeTransactionTerms) / sizeof(kUnsafeTransactionTerms[0])))
                {
                    continue;
                }

                std::string desired;
                const char* reason = nullptr;

                if (lower == "onlinegame")
                {
                    desired = "1";
                    reason = "LIVE-style frontend under offline isolation";
                }
                else if (lower == "xblive_privatematch")
                {
                    desired = "1";
                    reason = "offline private/custom-match presentation";
                }
                else if (lower == "xblive_rankedmatch")
                {
                    desired = "0";
                    reason = "never enter ranked/public matchmaking";
                }
                else if (lower == "lobby_open" ||
                         lower == "lobby_open_for_pres_join")
                {
                    desired = "1";
                    reason = "keep local lobby UI open";
                }
                else if (lower == "unlockallitems" ||
                         lower.rfind("force_unlock_all_", 0) == 0)
                {
                    desired = "1";
                    reason = "engine-provided local unlock/debug gate";
                }
                else
                {
                    const bool contentRelated = ContainsAny(
                        lower,
                        kContentTerms,
                        sizeof(kContentTerms) / sizeof(kContentTerms[0]));
                    if (!contentRelated)
                        continue;

                    const bool fence = lower.find("fence") != std::string::npos;
                    const bool enableStyle = ContainsAny(
                        lower,
                        kEnableTerms,
                        sizeof(kEnableTerms) / sizeof(kEnableTerms[0]));

                    if (fence)
                    {
                        desired = "0";
                        reason = "disable local content/frontend fence";
                    }
                    else if (enableStyle)
                    {
                        // Only mutate values that already look boolean. This
                        // avoids guessing at integer/enum/range semantics.
                        const std::string current = LowerCopy(entry.value);
                        if (current != "0" && current != "1" &&
                            current != "true" && current != "false")
                        {
                            continue;
                        }
                        desired = "1";
                        reason = "enable registered local content/frontend flag";
                    }
                    else
                    {
                        continue;
                    }
                }

                ++considered;
                std::string setMessage;
                const auto result =
                    t9_dvars::Execute(entry.name, desired, setMessage);
                const bool ok =
                    result == t9_dvars::ExecuteResult::Set ||
                    result == t9_dvars::ExecuteResult::Read;

                std::ostringstream line;
                line
                    << (ok ? "AUTO " : "AUTO-FAIL ")
                    << entry.name << "=" << desired
                    << " // " << reason;
                LogLine(line.str());

                std::printf(
                    "[CW-OFFLINE-ONLINE] %s %s=%s // %s\n",
                    ok ? "APPLIED" : "FAIL",
                    entry.name.c_str(),
                    desired.c_str(),
                    reason);
                if (!ok && !setMessage.empty())
                    std::printf("[CW-OFFLINE-ONLINE]   %s\n", setMessage.c_str());

                if (ok) ++applied;
                else ++failed;
            }

            std::printf(
                "[CW-OFFLINE-ONLINE] semantic exposure pass considered=%u applied=%u failed=%u\n",
                considered,
                applied,
                failed);
            std::fflush(stdout);
            return applied;
        }

        DWORD WINAPI Worker(LPVOID)
        {
            // The dvar registry becomes usable during normal Retail frontend
            // initialization. Retry until at least one verified frontend/local
            // content gate resolves; never create missing dvars speculatively.
            for (unsigned int attempt = 0; attempt < 120; ++attempt)
            {
                // Retail local-content mode is automatic in both Offline/LAN
                // and Online Research. The caller only starts this worker for
                // the Retail build, so do not gate it on startup mode.
                std::string message;
                if (Apply(message))
                {
                    std::printf(
                        "[CW-DVARS] auto applied: %s\n",
                        message.c_str());
                    std::printf(
                        "[CW-OFFLINE-ONLINE] online-era frontend/content exposure is armed; public networking remains blocked.\n");
                    std::fflush(stdout);
                    return 0;
                }

                Sleep(250);
            }

            std::printf(
                "[CW-DVARS] automatic local-content preset timed out because no verified frontend/local-content dvars resolved.\n");
            std::fflush(stdout);
            return 0;
        }
    }

    void StartAuto()
    {
        if (g_workerStarted.exchange(true))
            return;

        HANDLE thread = CreateThread(
            nullptr,
            0,
            Worker,
            nullptr,
            0,
            nullptr);

        if (thread)
            CloseHandle(thread);
    }

    bool Apply(std::string& message)
    {
        t9_dvars::Refresh();

        unsigned int success = 0;
        unsigned int failed = 0;
        unsigned int skipped = 0;

        for (const auto& command : kCommands)
        {
            t9_dvars::Entry entry{};
            if (!t9_dvars::VerifyCandidate(command.name, entry))
            {
                ++skipped;
                std::printf(
                    "[CW-DVARS] SKIP: %s // not registered in this build (%s)\n",
                    command.name,
                    command.note);
                continue;
            }

            std::string setMessage;
            const auto result = t9_dvars::Execute(command.name, command.value, setMessage);
            const bool ok = result == t9_dvars::ExecuteResult::Set ||
                            result == t9_dvars::ExecuteResult::Read;

            std::ostringstream line;
            line
                << (ok ? "OK " : "FAIL ")
                << command.name << "=" << command.value
                << " // " << command.note;
            LogLine(line.str());

            std::printf(
                "[CW-DVARS] %s: %s=%s // %s\n",
                ok ? "OK" : "FAIL",
                command.name,
                command.value,
                command.note);
            if (!ok && !setMessage.empty())
                std::printf("[CW-DVARS]   %s\n", setMessage.c_str());
            std::fflush(stdout);

            if (ok) ++success;
            else ++failed;
        }

        const unsigned int localUnlockApplied = ApplyVerifiedLocalUnlockDvars();
        const unsigned int semanticOnlineApplied = ApplySemanticOfflineOnlineDvars();
        const unsigned int totalApplied =
            success + localUnlockApplied + semanticOnlineApplied;

        g_successCount.store(totalApplied);
        g_failureCount.store(failed);
        g_applied.store(totalApplied > 0 && failed == 0);

        std::ostringstream result;
        result
            << success << " verified frontend dvars + "
            << localUnlockApplied << " local-content gates + "
            << semanticOnlineApplied << " semantic offline-online flags applied, "
            << skipped << " absent on this build";
        if (failed)
            result << ", " << failed << " failed";

        message = result.str();
        // If everything was merely absent, the registry may not be ready yet.
        // Let the automatic worker retry instead of treating SKIP-only as success.
        return totalApplied > 0;
    }

    bool ApplyHybridOnline(std::string& message)
    {
        std::string baseMessage;
        Apply(baseMessage);

        t9_dvars::Refresh();
        unsigned int applied = 0;
        unsigned int skipped = 0;
        unsigned int failed = 0;

        std::printf("[CW-ONLINE-DVAR] Applying verified LIVE/frontend dvars for offline-isolated hybrid mode...\n");

        for (const auto& command : kHybridOnlineCommands)
        {
            t9_dvars::Entry entry{};
            if (!t9_dvars::VerifyCandidate(command.name, entry))
            {
                ++skipped;
                std::printf(
                    "[CW-ONLINE-DVAR] SKIP %s // not registered in this build\n",
                    command.name);
                continue;
            }

            std::string setMessage;
            const auto result = t9_dvars::Execute(command.name, command.value, setMessage);
            const bool ok = result == t9_dvars::ExecuteResult::Set ||
                            result == t9_dvars::ExecuteResult::Read;
            if (ok) ++applied;
            else ++failed;

            std::printf(
                "[CW-ONLINE-DVAR] %s %s=%s // %s\n",
                ok ? "APPLIED" : "FAIL",
                command.name,
                command.value,
                command.note);
            if (!ok && !setMessage.empty())
                std::printf("[CW-ONLINE-DVAR]   %s\n", setMessage.c_str());
        }
        std::fflush(stdout);

        std::ostringstream out;
        out << "base={" << baseMessage << "}; online=" << applied
            << " applied, " << skipped << " absent";
        if (failed) out << ", " << failed << " failed";
        message = out.str();
        return applied > 0 || skipped > 0;
    }

    void PrintStatus()
    {
        std::printf(
            "[CW-DVARS] applied=%s verifiedApplied=%u failed=%u presetCommands=%llu\n",
            g_applied.load() ? "yes" : "no",
            g_successCount.load(),
            g_failureCount.load(),
            static_cast<unsigned long long>(
                sizeof(kCommands) / sizeof(kCommands[0])));
        std::fflush(stdout);
    }
}
