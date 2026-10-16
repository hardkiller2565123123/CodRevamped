#pragma once
#include "../Loading/HostLaunchTrace.h"
// MW2019 Replay 1.20: native bot lobby bridge for version.dll.
// Engine function RVAs and bot record layout are from DW-1.20's native Replay
// replacement units. This file is included by MW2019RedirectProxy.cpp because
// that is the translation unit compiled into the CodRevamped MW2019 project.
// Do not include it for any other game build.

// Core hooks are included inside the proxy translation unit so they can reuse
// its existing MinHook installation and game-thread logger.  Pure bot identity
// and name-resource logic is compiled separately from Features/Bots/BotProfiles.cpp.
namespace replay120_local_bots
{
    namespace
    {
        constexpr std::uintptr_t kScrPlaceEndFrame = 0x015DB560;
        constexpr std::uintptr_t kBotEligibility = 0x00CA1C80;
        constexpr std::uintptr_t kNativeMatchmaker = 0x0C27E4B0;
        constexpr unsigned kMaxNativeSlots = 200;
        // Public matchmaking may form a waiting lobby immediately, but game
        // launch is not permitted until six real game participants are present.
        // A bot quota or an uninitialized record is never a participant.
        constexpr unsigned kMinimumLaunchPlayers = 6;

        // The exact native record used by BG_GameStateInfo_GetBotMember.
        // No synthetic Demonware users or session/player identities are made.
        struct BotRecord
        {
            char name[36];
            char clan[11];
            std::uint8_t displayPad;
            std::uint16_t nameIndex;
            std::uint8_t unknown50[2];
            std::uint32_t modelIndex[3];
            std::uint8_t unknown64[12];
            std::uint8_t unknown76;
            std::uint8_t team;
            std::uint16_t skill;
            std::uint16_t rank;
            std::uint16_t unknown82;
            std::uint8_t valid;
            std::uint8_t inUse;
            std::uint8_t client;
            std::uint8_t pad;
        };
        static_assert(sizeof(BotRecord) == 88);
        static_assert(offsetof(BotRecord, valid) == 84);

        using FrameFn = void(__fastcall*)();
        using AllowedFn = bool(__fastcall*)();
        using LobbyFn = bool(__fastcall*)();
        using PartyFn = void*(__fastcall*)();
        using PartyCheckFn = bool(__fastcall*)(const void*);
        using CountFn = unsigned(__fastcall*)(const void*, int);
        using CountTeamFn = unsigned(__fastcall*)(const void*, int, int);
        using PartyCapacityFn = unsigned(__fastcall*)(const void*);
        using MemberAvailableFn = bool(__fastcall*)(const void*, unsigned);
        using VoidFn = void(__fastcall*)();
        using SetupCountsFn = void(__fastcall*)(int, int);
        using SetTeamLimitFn = void(__fastcall*)(int, std::uint8_t);
        using MemberFn = void*(__fastcall*)(unsigned);
        using StateChangedFn = void(__fastcall*)(void*);
        using CommandFn = std::uintptr_t(__fastcall*)(int, const char*);
        using BotPresentFn = bool(__fastcall*)(unsigned);
        using PartyVisibleFn = bool(__fastcall*)(const void*, unsigned);
        using PartyVisibleCountFn = unsigned(__fastcall*)(const void*);
        using LobbyModelFn = void(__fastcall*)(const void*, std::uint16_t);
        using NativeReadyToLaunchFn = bool(__fastcall*)(void*, const void*);
        using NativeStartMatchFn = std::uint64_t(__fastcall*)(void*, const void*);
        using ServerAssignBotFn = int(__fastcall*)(unsigned);
        using ServerAssignedTeamFn = int(__fastcall*)(unsigned);
        using ModelPathFn = std::uint16_t(__fastcall*)(std::uint16_t, const char*);
        using ModelIntFn = int(__fastcall*)(std::uint16_t);
        using ModelSetIntFn = void(__fastcall*)(std::uint16_t, int);
        using ModelSetBoolFn = void(__fastcall*)(std::uint16_t, bool);
        using ModelSetTextFn = void(__fastcall*)(std::uint16_t, const char*);

        FrameFn s_originalFrame = nullptr;
        AllowedFn s_originalAllowed = nullptr;
        BotPresentFn s_originalBotPresent = nullptr;
        PartyVisibleFn s_originalPartyVisible = nullptr;
        PartyVisibleCountFn s_originalPartyVisibleCount = nullptr;
        LobbyModelFn s_originalLobbyModel = nullptr;
        LobbyModelFn s_originalFilteredLobbyModel = nullptr;
        NativeReadyToLaunchFn s_originalReadyToLaunch = nullptr;
        NativeStartMatchFn s_originalStartMatchInternal = nullptr;
        ServerAssignBotFn s_originalServerAssignBot = nullptr;
        ServerAssignedTeamFn s_originalServerAssignedTeam = nullptr;
        ServerAssignedTeamFn s_originalServerAssignedSquad = nullptr;
        unsigned s_serverBotAssigned = 0;
        std::uint64_t s_lastNativeLaunchResultLoggedMs = 0;
        codrevamped::mw120::loading::HostLaunchTrace s_hostLaunchTrace;
        std::uint64_t s_lastPopulationNoteMs = 0;
        unsigned s_lastPopulationTotal = ~0u;
        std::uint64_t s_lastDisplayedLobby = 0;
        unsigned s_lastDisplayedBots = ~0u;
        unsigned s_lastVisibleNativeBots = ~0u;
        bool s_loggedLobbyExit = false;
        std::uint64_t s_lobbyId = 0;
        std::uint64_t s_lobbyFirstSeen = 0;
        unsigned s_botCount = ~0u;
        unsigned s_humanCount = ~0u;
        unsigned s_capacity = 0;
        unsigned s_initAttempts = 0;
        unsigned s_frameCounter = 0;
        bool s_nativePoolReady = false;
        bool s_launchRequested = false;
        bool s_brMinimumRequested = false;
        std::uint64_t s_lastNativeAttemptMs = 0;
        bool s_fixedOneSlotLobby = false;
        bool s_allowBots = false;
        bool s_optimizationQueued = false;
        bool s_active = false;
        // The stock LUI builder already refreshes its party model. The previous
        // unconditional post-processing wrote hundreds of new model values per
        // refresh and coincided with a frozen frontend. UI augmentation is
        // therefore OFF by default until its native lifecycle is validated.
        bool s_experimentalUi = false;
        std::uint64_t s_lastGateNote = 0;
        unsigned s_uiReentries = 0;
        std::uint64_t s_uiLastWrite = 0;
        std::uint16_t s_uiLastRoot = 0;
        std::uint64_t s_uiLastLobby = 0;
        unsigned s_uiLastBotCount = 0;
        // Prevent model write cascades from rebuilding the entire UI every frame.
        bool s_uiDiagnosticWritten = false;

        unsigned Option(const wchar_t* name, unsigned defaultValue, unsigned maxValue) noexcept
        {
            wchar_t buf[16]{};
            const DWORD len = GetEnvironmentVariableW(name, buf, 16);
            if (!len || len >= 16) return defaultValue;
            unsigned value = 0;
            for (DWORD i = 0; i < len; ++i)
            {
                if (buf[i] < L'0' || buf[i] > L'9') return defaultValue;
                value = value * 10 + unsigned(buf[i] - L'0');
                if (value > maxValue) return maxValue;
            }
            return value;
        }

        std::uintptr_t ImageBase() noexcept
        {
            return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        }
        template<typename T>
        T Native(std::uintptr_t rva) noexcept
        {
            return reinterpret_cast<T>(ImageBase() + rva);
        }

        void QueueModeOne() noexcept
        {
            if (s_optimizationQueued || Option(L"CODREVAMPED_120_COM_OPTIMIZED", 1, 1) == 0)
                return;
            // Port the six engine dvar overrides from com_optimized mode 1.
            // The source project also changes its recompiled worker loop;
            // that replacement is intentionally NOT forced into the DLL.
            // Mode 2 graphics settings are omitted.
            // Commands go through the game's own engine command submission;
            // no dvar structs are written from an external thread.
            const auto command = Native<CommandFn>(0x015C1C20);
            static constexpr const char* kCommands[] = {
                "set com_optimized 1\n",
                "set lui_gc_use_new_frontend_collect 1\n",
                "set lui_gc_allocated_time 8000\n",
                "set lui_gc_step_size 0\n",
                "set r_smp_workercmds_on_render 1\n",
                "set r_smp_workercmds_on_frontend 1\n",
                "set r_smp_workercmds_on_server 1\n"
            };
            for (const char* entry : kCommands)
                command(0, entry);
            s_optimizationQueued = true;
            ConsolePrint("[BOT120-OPT] requested com_optimized mode=1 dvars=6 mode2=disabled\r\n");
        }

        bool __fastcall AllowBotMatchmaking() noexcept
        {
            return s_allowBots || (s_originalAllowed && s_originalAllowed());
        }

        // Native bot records are NOT remote party members. The original DW
        // 1.20 project binds them into the LUI model separately. Merely
        // publishing an 11-bot quota, or preparing the engine pool, does not
        // increment the visible lobby member count.
        bool __fastcall IsBotPresent(unsigned index) noexcept
        {
            if (s_allowBots && index < kMaxNativeSlots)
            {
                auto party = Native<PartyFn>(0x01187EE0)();
                if (party && !Native<MemberAvailableFn>(0x0118E020)(party, index) &&
                    Native<AllowedFn>(0x00CA2250)())
                {
                    auto* record = Native<MemberFn>(0x00CA2210)(index);
                    if (record && static_cast<const BotRecord*>(record)->valid == 1)
                        return true;
                }
            }
            return s_originalBotPresent && s_originalBotPresent(index);
        }

        std::uint16_t Child(std::uint16_t parent, const char* name) noexcept
        {
            return Native<ModelPathFn>(0x01B0D390)(parent, name);
        }
        void BotModelInt(std::uint16_t parent, const char* key, int value) noexcept
        {
            Native<ModelSetIntFn>(0x01B0E150)(Child(parent, key), value);
        }
        void BotModelBool(std::uint16_t parent, const char* key, bool value) noexcept
        {
            Native<ModelSetBoolFn>(0x01B0E0B0)(Child(parent, key), value);
        }
        void BotModelText(std::uint16_t parent, const char* key, const char* text) noexcept
        {
            Native<ModelSetTextFn>(0x01B0E280)(Child(parent, key), text);
        }

        // Native executable research: 0x141B21D50 takes (party*, uint16 modelRoot),
        // sorts the party, binds stock human rows through 0x141B22140 and sets
        // count/memberCount/maxCount at the END. The DW-1.20 project replaces
        // this entire function; calling the original and appending rows caused
        // competing writes to the same counters and a frontend update storm.
        // Only use this replacement for a complete native bot pool. No records
        // are inserted into party/network state or impersonate actual accounts.
        using SortFn = void(__fastcall*)(const void*, int*);
        using HumanRowFn = void(__fastcall*)(const void*, unsigned, std::uint16_t, int);
        using BotDataFn = const void*(__fastcall*)(unsigned);
        using DediFn = bool(__fastcall*)(const void*);

        // Match the complete native DW-1.20 MemberRecord stride. The earlier
        // reduced struct stopped at offset 400 and was indexed as an array,
        // misaddressing every party member after slot zero (actual stride=488).
        // Source: DW-1.20-main/integration/replay/DW_BotRoster.cpp.
        struct PartyUiMember
        {
            std::uint8_t unknown0[52];
            char name[36];
            std::uint8_t unknown88[52];
            int follower;
            std::uint8_t unknown144[244];
            int subparty, team, squad;
            std::uint8_t unknown400[2], status, unknown403[5];
            std::uint64_t xuid;
            std::uint8_t unknown416[72];
        };
        static_assert(sizeof(PartyUiMember) == 488);
        static_assert(offsetof(PartyUiMember, follower) == 140);
        static_assert(offsetof(PartyUiMember, team) == 392);
        static_assert(offsetof(PartyUiMember, xuid) == 408);

        // Stock party UI visibility and its global count are separate
        // from GameStateInfo. Both must agree with the same bot-slot map.
        // Confirmed by disassembly of game_dx12_ship_replay.exe 1.20:
        // Party_IsMemberUIVisible at 0x118E2C0 tests member.status at
        // party + 0xA22 + slot * 0x1E8; Party_CountUIVisible at 0x118ADD0
        // runs the same test for the 200 party slots.
        bool NativeBotForUi(const void* party, unsigned slot) noexcept
        {
            if (!s_experimentalUi || !s_nativePoolReady || !s_allowBots ||
                !party || slot >= kMaxNativeSlots || !s_lobbyId ||
                party != Native<PartyFn>(0x01187EE0)() ||
                !Native<AllowedFn>(0x00CA2250)() ||
                Native<MemberAvailableFn>(0x0118E020)(party, slot))
                return false;
            const auto* bot = static_cast<const BotRecord*>(Native<MemberFn>(0x00CA2210)(slot));
            return bot && bot->valid == 1 && bot->name[0] != '\0';
        }

        bool __fastcall PartyVisibleHook(const void* party, unsigned slot) noexcept
        {
            if (slot >= kMaxNativeSlots || !party)
                return false;
            return (s_originalPartyVisible && s_originalPartyVisible(party, slot)) ||
                   NativeBotForUi(party, slot);
        }

        unsigned __fastcall PartyVisibleCountHook(const void* party) noexcept
        {
            const unsigned humans = s_originalPartyVisibleCount
                ? s_originalPartyVisibleCount(party) : 0u;
            if (!party || !s_experimentalUi || !s_nativePoolReady ||
                party != Native<PartyFn>(0x01187EE0)() ||
                !*reinterpret_cast<const volatile int*>(
                    static_cast<const std::uint8_t*>(party) + 311116))
                return humans;
            unsigned bots = 0;
            const unsigned cap = std::min<unsigned>(
                kMaxNativeSlots, Native<PartyCapacityFn>(0x0118C7D0)(party));
            for (unsigned i = 0; i < cap; ++i)
                bots += NativeBotForUi(party, i) ? 1u : 0u;
            return std::min<unsigned>(humans + bots, cap);
        }

        int UiRowLimit() noexcept
        {
            const auto enabled = *reinterpret_cast<const void* const*>(
                ImageBase() + 0x0D386988);
            const auto count = *reinterpret_cast<const void* const*>(
                ImageBase() + 0x0D386990);
            // DW-1.20 uses registered dvars at value offset +0x28.
            if (enabled && count && *reinterpret_cast<const volatile std::uint8_t*>(
                    static_cast<const std::uint8_t*>(enabled) + 0x28))
                return std::clamp(int(*reinterpret_cast<const volatile int*>(
                    static_cast<const std::uint8_t*>(count) + 0x28)), 0, 200);
            return 28;
        }

        bool EligibleForUi(const void* party, std::uint16_t model) noexcept
        {
            if (!s_experimentalUi || !s_nativePoolReady || !s_allowBots ||
                !model || !party || !s_lobbyId || !s_botCount || s_botCount > kMaxNativeSlots ||
                party != Native<PartyFn>(0x01187EE0)() ||
                !Native<AllowedFn>(0x00CA2250)())
                return false;
            // The original DW-1.20 replacements do not touch party models
            // until the party is initialized and the frontend client state
            // allows model creation. Apply the identical native guards here.
            if (!*reinterpret_cast<const volatile int*>(
                    static_cast<const std::uint8_t*>(party) + 311116))
                return false;
            const auto* const localClientActive = reinterpret_cast<const volatile std::uint8_t*>(
                ImageBase() + 0x0EEF12A4);
            const auto* const connectionState = reinterpret_cast<const volatile int*>(
                ImageBase() + 0x0EEF1288);
            if (localClientActive[0] == 0 && connectionState[0] >= 3)
                return false;
            // Stock UI has a special model writer for active GameBattles.
            // Let it handle those sessions rather than replacing their rows.
            if (Native<bool(__fastcall*)()>(0x01528240)() &&
                Native<bool(__fastcall*)()>(0x00F22880)())
                return false;
            const unsigned capacity = Native<PartyCapacityFn>(0x0118C7D0)(party);
            if (!capacity || capacity > kMaxNativeSlots ||
                !Native<PartyCheckFn>(0x0118DD00)(party) ||
                !Native<PartyCheckFn>(0x01189120)(party) ||
                *reinterpret_cast<const std::uint64_t*>(ImageBase() + kNativeMatchmaker + 79656) != s_lobbyId)
                return false;
            unsigned recognized = 0;
            for (unsigned slot = 0; slot < capacity; ++slot)
            {
                if (Native<MemberAvailableFn>(0x0118E020)(party, slot)) continue;
                const auto* bot = static_cast<const BotRecord*>(Native<MemberFn>(0x00CA2210)(slot));
                if (bot && bot->valid == 1 && bot->name[0] != '\0') ++recognized;
            }
            return recognized >= s_botCount;
        }

        std::uint16_t UiRow(std::uint16_t parent, unsigned index) noexcept
        {
            char number[4]{};
            std::snprintf(number, sizeof(number), "%u", index);
            return Child(parent, number);
        }

        // Rebuild the complete party model using the native DW-1.20 field
        // contract. This is lobby DISPLAY only: never turn a bot into a real
        // network account or write a synthetic XUID into PartyData.
        // The original DW replacement lives in replay120/DW_BotRoster.cpp.
        void WriteNativePartyModels(const void* party, std::uint16_t model,
                                    bool filtered) noexcept
        {
            const unsigned capacity = Native<PartyCapacityFn>(0x0118C7D0)(party);
            const auto local = Native<PartyVisibleFn>(0x0118E0E0);
            const auto memberVisible = Native<PartyVisibleFn>(0x0118E2C0);
            const auto bindHuman = Native<HumanRowFn>(0x01B22140);
            const auto waiting = Native<PartyVisibleFn>(0x0118EE80);
            // Keep the native 28-row frontend window.  Party_CountUIVisible
            // and memberCount still report the full 150-member roster.
            const int limit = std::min(UiRowLimit(), 28);
            std::array<int, kMaxNativeSlots> sorted{};
            Native<SortFn>(0x01B23610)(party, sorted.data());
            int friendlySubparty = 0, friendlyTeam = 0, friendlySquad = 0;
            for (int slot : sorted)
            {
                if (slot < 0 || slot >= static_cast<int>(kMaxNativeSlots) ||
                    !local(party, unsigned(slot))) continue;
                const auto& m = reinterpret_cast<const PartyUiMember*>(
                    static_cast<const std::uint8_t*>(party) + 2192)[slot];
                friendlySubparty = m.subparty;
                friendlyTeam = m.team;
                friendlySquad = m.squad;
                break;
            }
            if (!filtered)
                BotModelInt(model, "friendlySubPartyIndex", friendlySubparty);
            int teamCounts[156]{};
            unsigned shown = 0, nonFollowers = 0, total = 0, bots = 0;
            const bool useTeams = filtered && Native<PartyCheckFn>(0x01192AC0)(party);
            const bool useSquads = filtered && Native<PartyCheckFn>(0x01192AA0)(party);
            // Native Party UI filtered model reads these shared values from
            // alwaysLoaded.activeParty.members, not from its input model root.
            int filteredTeam = friendlyTeam, filteredSquad = friendlySquad;
            if (filtered)
            {
                const auto global = Native<std::uint16_t(__fastcall*)()>(0x01B0D520)();
                const auto get = Native<std::uint16_t(__fastcall*)(
                    std::uint16_t, const char*)>(0x01B0D710);
                const auto getInt = Native<ModelIntFn>(0x01B0D530);
                filteredTeam = getInt(get(global,
                    "alwaysLoaded.activeParty.members.friendlyTeamIndex"));
                filteredSquad = getInt(get(global,
                    "alwaysLoaded.activeParty.members.friendlySquadIndex"));
            }
            for (int ordinal = 0; ordinal < std::min(limit, 200); ++ordinal)
            {
                const int slot = sorted[ordinal];
                if (slot < 0 || slot >= static_cast<int>(kMaxNativeSlots) ||
                    NativeBotForUi(party, unsigned(slot)) ||
                    !memberVisible(party, unsigned(slot))) continue;
                const auto& m = reinterpret_cast<const PartyUiMember*>(
                    static_cast<const std::uint8_t*>(party) + 2192)[slot];
                if (filtered && !local(party, unsigned(slot)) &&
                    ((useTeams && (filteredTeam == 0 || m.team != filteredTeam)) ||
                     (useSquads && (filteredSquad == -1 || m.squad != filteredSquad))))
                    continue;
                if (shown >= static_cast<unsigned>(limit)) break;
                bindHuman(party, unsigned(slot), UiRow(model, shown++), ordinal);
                if (m.follower == 0) ++nonFollowers;
                if (!filtered && m.team >= 0 && m.team < 156) ++teamCounts[m.team];
            }
            // The count is ALL visible party members, including off-screen
            // members. The actual rendered rows remain bounded by the UI dvar.
            for (unsigned slot = 0; slot < kMaxNativeSlots; ++slot)
                if (!NativeBotForUi(party, slot) &&
                    (reinterpret_cast<const PartyUiMember*>(
                        static_cast<const std::uint8_t*>(party) + 2192)[slot].status >= 5 ||
                     waiting(party, slot)))
                    ++total;
            // Use the real local host's cached appearance and playercard,
            // matching DW_BotRoster::PushBot. A blank row lacks several
            // LUI customization keys and can cause Lua consumers to refresh.
            struct Appearance { int head = 0, body = 0, execution = 0; };
            Appearance west{}, east{};
            std::uint8_t selectedOperator = 0;
            alignas(16) std::array<std::uint8_t, 45248> playerCard{};
            bool haveLocalCard = false;
            for (unsigned i = 0; i < kMaxNativeSlots; ++i)
            {
                if (!local(party, i)) continue;
                const auto& host = reinterpret_cast<const PartyUiMember*>(
                    static_cast<const std::uint8_t*>(party) + 2192)[i];
                Native<void(__fastcall*)(std::uint64_t, const char*, std::uint8_t*,
                    Appearance*, Appearance*)>(0x01B97080)(
                    host.xuid, host.name, &selectedOperator, &west, &east);
                Native<void(__fastcall*)(std::uint64_t, const char*, void*)>(
                    0x01B97230)(host.xuid, host.name, playerCard.data());
                haveLocalCard = true;
                break;
            }
            for (unsigned slot = 0; slot < capacity; ++slot)
            {
                if (!NativeBotForUi(party, slot)) continue;
                const auto& bot = *static_cast<const BotRecord*>(
                    Native<MemberFn>(0x00CA2210)(slot));
                ++bots;
                ++total;
                const int team = static_cast<int>(bot.team);
                // Bot teams and squads are not fabricated: there is no
                // party-level squad assignment until the gameplay policy runs.
                if (filtered && ((useTeams && (filteredTeam == 0 || team != filteredTeam)) ||
                                 (useSquads && filteredSquad != -1)))
                    continue;
                if (shown >= static_cast<unsigned>(limit)) continue;
                const auto row = UiRow(model, shown++);
                char name[37]{};
                std::memcpy(name, bot.name, 36);
                BotModelInt(row, "memberIndex", int(slot));
                // Stable *UI-only* key: not a fabricated network account ID.
                const auto profile = codrevamped::bots120::For(slot);
                char displayKey[32]{};
                std::snprintf(displayKey, sizeof(displayKey), "%llu",
                    static_cast<unsigned long long>(0xB070000000000000ull | (
                        (static_cast<std::uint64_t>(slot) << 20u) |
                        (s_lobbyId & 0xfffffull))));
                BotModelText(row, "xuid", displayKey);
                // Platform is presentation-only, never a real service login.
                char platformId[4]{};
                std::snprintf(platformId, sizeof(platformId), "%u", profile.platform);
                BotModelText(row, "platformId", platformId);
                BotModelText(row, "gamertag", name);
                BotModelText(row, "gamertagWithHash", name);
                BotModelText(row, "clanTag", "");
                BotModelBool(row, "isBot", true);
                for (const char* key : {"isLobbyHost", "isPrivatePartyHost",
                    "missingGamertag", "isMyPlayer",
                    "customEmblemEquipped", "isPlaceHolderPlayer", "usingGamepad"})
                    BotModelBool(row, key, false);
                BotModelBool(row, "isCrossplayPlayer", profile.platform != 0);
                BotModelBool(row, "usingGamepad", profile.gamepad);
                BotModelBool(row, "commitReady", true);
                BotModelInt(row, "controllerIndex", -1);
                BotModelInt(row, "subparty", -1);
                BotModelInt(row, "team", team);
                BotModelInt(row, "desiredTeam", team);
                BotModelInt(row, "squad", -1);
                BotModelInt(row, "rank", static_cast<int>(profile.rank));
                BotModelInt(row, "baseRank", static_cast<int>(profile.rank));
                BotModelInt(row, "prestige", static_cast<int>(profile.prestige));
                BotModelInt(row, "presencePlatform", static_cast<int>(profile.platform));
                // Additional stable display-only metadata. Stock LUI ignores
                // unknown fields; none represent a network account or owned item.
                BotModelInt(row, "botSkillTier", static_cast<int>(profile.skillTier));
                BotModelText(row, "botSkillLabel", codrevamped::bots120::TierName(profile.skillTier));
                BotModelInt(row, "botAccuracyPercent", static_cast<int>(profile.accuracyPercent));
                BotModelInt(row, "botReactionMs", static_cast<int>(profile.reactionMilliseconds));
                BotModelInt(row, "botAggression", static_cast<int>(profile.aggression));
                BotModelInt(row, "botMovement", static_cast<int>(profile.movement));
                BotModelInt(row, "botCareerMatches", static_cast<int>(profile.matches));
                BotModelInt(row, "botCareerWins", static_cast<int>(profile.wins));
                BotModelInt(row, "botCareerKills", static_cast<int>(profile.kills));
                BotModelInt(row, "botCareerDeaths", static_cast<int>(profile.deaths));
                BotModelInt(row, "botCareerHeadshots", static_cast<int>(profile.headshots));
                BotModelInt(row, "botCareerAssists", static_cast<int>(profile.assists));
                BotModelInt(row, "botBestStreak", static_cast<int>(profile.streakBest));
                BotModelInt(row, "botHoursPlayed", static_cast<int>(profile.hoursPlayed));
                BotModelInt(row, "botKD100", static_cast<int>(profile.kdHundredths));
                BotModelInt(row, "botWinRatePercent", static_cast<int>(profile.winRatePercent));
                BotModelText(row, "botPrimaryWeapon", codrevamped::bots120::WeaponName(profile.favoriteWeapon));
                BotModelText(row, "botSecondaryWeapon", codrevamped::bots120::WeaponName(profile.secondaryWeapon));
                BotModelText(row, "botCallingCardTheme", codrevamped::bots120::CallingCardTheme(profile.callingCardTheme));
                BotModelInt(row, "botOperatorTheme", static_cast<int>(profile.operatorTheme));
                BotModelInt(row, "botControllerPreferred", profile.gamepad ? 1 : 0);
                BotModelInt(row, "microphoneState", 0);
                BotModelInt(row, "emblemIndex", static_cast<int>(profile.emblem));
                BotModelInt(row, "backgroundIndex", static_cast<int>(profile.background));
                BotModelInt(row, "followersCount", 0);
                BotModelText(row, "botLoadoutStyle", codrevamped::bots120::StyleName(profile.style));
                // The lobby profile does not assign a gameplay class.  Game
                // loadouts require a separate verified server spawn path.
                BotModelInt(row, "followerIndex", -1);
                BotModelInt(row, "selectedOperatorIndex", selectedOperator);
                // Native selector provides real model asset IDs; do not invent
                // operator asset indices. Fall back to the host outfit if the
                // selected bot record has not populated its model IDs.
                const int botHead = bot.modelIndex[0] > 0 && bot.modelIndex[0] <= 65535
                    ? static_cast<int>(bot.modelIndex[0]) : west.head;
                const int botBody = bot.modelIndex[1] > 0 && bot.modelIndex[1] <= 65535
                    ? static_cast<int>(bot.modelIndex[1]) : west.body;
                BotModelInt(row, "headWest", botHead);
                BotModelInt(row, "bodyWest", botBody);
                BotModelInt(row, "execWest", west.execution);
                BotModelInt(row, "headEast", bot.modelIndex[0] > 0 && bot.modelIndex[0] <= 65535
                    ? static_cast<int>(bot.modelIndex[0]) : east.head);
                BotModelInt(row, "bodyEast", bot.modelIndex[1] > 0 && bot.modelIndex[1] <= 65535
                    ? static_cast<int>(bot.modelIndex[1]) : east.body);
                BotModelInt(row, "execEast", east.execution);
                if (haveLocalCard)
                    Native<void(__fastcall*)(std::uint16_t, const void*)>(
                        0x01B24690)(row, playerCard.data());
                ++nonFollowers;
                if (!filtered && team >= 0 && team < 156) ++teamCounts[team];
            }
            if (!filtered)
            {
                BotModelInt(model, "friendlyTeamCount",
                    friendlyTeam >= 0 && friendlyTeam < 156 ? teamCounts[friendlyTeam] : 0);
                BotModelInt(model, "teamAlliesCount", teamCounts[2]);
                BotModelInt(model, "teamAxisCount", teamCounts[1]);
                BotModelInt(model, "teamSpectatorCount", teamCounts[153]);
                BotModelInt(model, "teamFollowerCount", teamCounts[154]);
                BotModelInt(model, "maxCount", int(capacity));
                BotModelInt(model, "friendlyTeamIndex", friendlyTeam);
                BotModelInt(model, "friendlySquadIndex", friendlySquad);
            }
            BotModelInt(model, "count", int(nonFollowers));
            BotModelInt(model, "memberCount", int(total));
            if (!filtered && (!s_uiDiagnosticWritten || s_uiLastBotCount != bots ||
                              s_uiLastLobby != s_lobbyId))
            {
                s_uiDiagnosticWritten = true;
                s_uiLastBotCount = bots;
                s_uiLastLobby = s_lobbyId;
                ConsolePrint("[BOT120-UI] lobby=%llu rendered=%u nativeBots=%u visibleCount=%u capacity=%u lobby-only=yes\r\n",
                    static_cast<unsigned long long>(s_lobbyId), shown, bots, total, capacity);
            }
        }

        void UiDispatcher(const void* party, std::uint16_t model, bool filtered) noexcept
        {
            const auto original=filtered?s_originalFilteredLobbyModel:s_originalLobbyModel;
            static thread_local bool writing=false;
            if (writing) return; // model setters may notify the LUI observer synchronously
            writing=true;
            struct Guard{bool& flag;~Guard() noexcept { flag=false; }} guard{writing};
            if (!EligibleForUi(party,model))
            {
                if (original) original(party,model);
                return;
            }
            // Only publish the same complete set of UI model rows once per
            // lobby / model root / participant-count generation. The prior
            // implementation rewrote dozens of model properties every 100ms,
            // triggering LUI observers and repeated Lua module registration.
            // Human join/leave, bot count changes, or a newly-created model
            // root all trigger the next coherent publication automatically.
            struct Published
            {
                std::uint16_t root = 0;
                std::uint64_t lobby = 0;
                unsigned humans = ~0u;
                unsigned bots = ~0u;
                unsigned capacity = 0;
            };
            static Published last[2]{};
            const unsigned which = filtered ? 1u : 0u;
            const unsigned humans = Native<CountFn>(0x0118AB60)(party, 1);
            const unsigned capacity = Native<PartyCapacityFn>(0x0118C7D0)(party);
            const Published current{model, s_lobbyId, humans, s_botCount, capacity};
            const auto& prior = last[which];
            if (prior.root == current.root && prior.lobby == current.lobby &&
                prior.humans == current.humans && prior.bots == current.bots &&
                prior.capacity == current.capacity)
            {
                const auto memberCountModel = Child(model, "memberCount");
                if (memberCountModel && Native<ModelIntFn>(0x01B0D530)(memberCountModel)
                    == static_cast<int>(PartyVisibleCountHook(party)))
                    return;
            }
            // Update the publication cursor before model setters execute; they
            // can synchronously cause another UI render request.
            last[which] = current;
            WriteNativePartyModels(party, model, filtered);
        }
        void __fastcall LobbyModelHook(const void* party,std::uint16_t model) noexcept
        { UiDispatcher(party,model,false); }
        void __fastcall FilteredLobbyModelHook(const void* party,std::uint16_t model) noexcept
        { UiDispatcher(party,model,true); }

        bool PopulateRoster(const void* party, unsigned capacity, unsigned requested) noexcept
        {
            // The native selector initially fills a dense list. Preserve its
            // original records before reassigning them to unoccupied party slots.
            // That is the same wire-data layout the Replay 1.20 client uses.
            auto member = Native<MemberFn>(0x00CA2210);
            auto present = Native<MemberAvailableFn>(0x0118E020);
            std::array<BotRecord, kMaxNativeSlots> source{};
            unsigned available = 0;
            for (unsigned slot = 0; slot < capacity; ++slot)
                available += present(party, slot) ? 0u : 1u;
            if (available < requested) return false;

            for (unsigned i = 0; i < requested; ++i)
            {
                const void* raw = member(i);
                if (!raw) return false;
                std::memcpy(&source[i], raw, sizeof(BotRecord));
                // Never wipe the game's backing pool when the native selector
                // hasn't produced real initialized bot records yet. BR uses
                // different team/quota policy from MP and may be one frame
                // behind the front-end lobby document. The name field may
                // be empty until the native name-expansion step, so valid is
                // the relevant prerequisite, not a populated display name.
                if (source[i].valid != 1)
                {
                    ConsolePrint("[BOT120-SELECT] index=%u initialized=no valid=%u nameEmpty=%u; preserving native pool for retry\r\n",
                        i, unsigned(source[i].valid), unsigned(source[i].name[0] == '\0'));
                    return false;
                }
            }
            // Customize selected native records BEFORE publication.  Keep
            // stock nameIndex/skill/modelIndex wire semantics intact; only
            // the human-readable name is changed.  Never create accounts.
            for (unsigned i = 0; i < requested; ++i)
            {
                const auto profile = codrevamped::bots120::For(i);
                std::memcpy(source[i].name, profile.name, sizeof(source[i].name));
                source[i].name[sizeof(source[i].name) - 1] = '\0';
                // The 1.20 skill field's behavior values need a gameplay
                // trace before changing them.  A cosmetic rank isn't AI skill.
            }
            for (unsigned i = 0; i < kMaxNativeSlots; ++i)
                if (void* raw = member(i))
                    std::memset(raw, 0, sizeof(BotRecord));

            unsigned placed = 0;
            for (unsigned slot = 0; slot < capacity && placed < requested; ++slot)
            {
                if (present(party, slot)) continue;
                if (void* raw = member(slot))
                {
                    std::memcpy(raw, &source[placed], sizeof(BotRecord));
                    ++placed;
                }
            }
            return placed == requested;
        }

        bool PrepareBots(void* party, unsigned capacity, unsigned humans, unsigned requested) noexcept
        {
            const auto clear = Native<VoidFn>(0x00CA2070);
            const auto setup = Native<SetupCountsFn>(0x00CA2370);
            const auto select = Native<VoidFn>(0x00CA1D20);
            const auto enable = Native<VoidFn>(0x00CA2110);
            const auto changed = Native<StateChangedFn>(0x0119A5A0);
            const auto usingTeams = Native<PartyCheckFn>(0x01192AC0);
            const auto countTeam = Native<CountTeamFn>(0x0118AD10);
            const auto teamLimit = Native<SetTeamLimitFn>(0x01119B40);
            const bool twoTeams = capacity <= 32 && usingTeams(party);
            codrevamped::bots120::SetLobby(s_lobbyId);

            clear();
            if (!requested)
            {
                changed(party);
                ConsolePrint("[BOT120] lobby=%llu humans=%u bots=0 pool=cleared\r\n",
                    static_cast<unsigned long long>(s_lobbyId), humans);
                return true;
            }
            // DW-1.20 native BR selector reads party_teamCount directly from
            // the engine dvar; calling SetupCounts(..., 0) alone cannot
            // override it. On >2 team layouts it produces zero native bots.
            // Restrict the temporary neutralization to this one synchronous
            // selector call on the frontend thread, restoring every exit.
            const auto teamDvar = *reinterpret_cast<std::uintptr_t*>(ImageBase() + 0x0C796328);
            int* currentTeams = teamDvar
                ? reinterpret_cast<int*>(teamDvar + 0x28) : nullptr;
            const int previousTeams = currentTeams ? *currentTeams : 0;
            if (capacity > 32 && previousTeams > 2 && previousTeams <= 156)
            {
                *currentTeams = 0;
                ConsolePrint("[BOT120-BR] native team selector neutralized from %d for one selection pass\r\n",previousTeams);
            }
            struct TeamRestore
            {
                int* destination;
                int value;
                void Restore() noexcept { if (destination) { *destination = value; destination = nullptr; } }
                ~TeamRestore() noexcept { Restore(); }
            } restore{currentTeams,previousTeams};
            setup(static_cast<int>(humans + requested), twoTeams ? 2 : 0);
            if (twoTeams)
            {
                unsigned allies = countTeam(party, 2, 1);
                unsigned axis = countTeam(party, 1, 1);
                for (unsigned i = 0; i < requested; ++i)
                    if (allies <= axis) ++allies; else ++axis;
                teamLimit(0, static_cast<std::uint8_t>(std::min(allies, 255u)));
                teamLimit(1, static_cast<std::uint8_t>(std::min(axis, 255u)));
            }
            select();
            // Restore the playlist's true team count BEFORE GameStateInfo is
            // published (the original DW-1.20 code does the same).
            restore.Restore();
            // The native selector may need an additional frontend frame after
            // counts are published. Never read/copy the backing pool until the
            // stock GameStateInfo reports initialized data.
            const bool botDataReady = Native<AllowedFn>(0x00CA2250)();
            const bool populated = botDataReady && PopulateRoster(party, capacity, requested);
            if (populated)
            {
                enable();
                changed(party);
            }
            // Distinguish physically valid native records from LUI visibility.
            // LUI augmentation is deliberately disabled because it triggered
            // synchronous rebuild loops in previous tests. 'records' is NOT
            // the UI player count and does NOT prove bots spawned in gameplay.
            unsigned validRecords = 0;
            for (unsigned i = 0; i < capacity; ++i)
            {
                const auto* record = static_cast<const BotRecord*>(Native<MemberFn>(0x00CA2210)(i));
                if (record && record->valid == 1 &&
                    !Native<MemberAvailableFn>(0x0118E020)(party, i))
                    ++validRecords;
            }
            // DW_BotPolicy_BuildRoster (original project) explicitly assigns
            // distinct names/nameIndex values, avoids human-name collisions,
            // and keeps slots stable across roster revisions. The compact
            // DLL port currently copies the selector's records without that
            // identity reconciliation. Inspect the actual pool before doing
            // any additional LUI work; no synthetic names or XUIDs are ever
            // written into game/network state here.
            unsigned duplicateNameIndexes = 0;
            unsigned duplicateNames = 0;
            unsigned emptyNames = 0;
            unsigned observed = 0;
            for (unsigned slot = 0; slot < capacity && observed < requested; ++slot)
            {
                if (Native<MemberAvailableFn>(0x0118E020)(party, slot)) continue;
                const auto* bot = static_cast<const BotRecord*>(Native<MemberFn>(0x00CA2210)(slot));
                if (!bot || bot->valid != 1) continue;
                ++observed;
                if (!bot->name[0]) ++emptyNames;
                for (unsigned other = 0; other < slot; ++other)
                {
                    if (Native<MemberAvailableFn>(0x0118E020)(party, other)) continue;
                    const auto* previous = static_cast<const BotRecord*>(Native<MemberFn>(0x00CA2210)(other));
                    if (!previous || previous->valid != 1) continue;
                    if (previous->nameIndex == bot->nameIndex) { ++duplicateNameIndexes; break; }
                }
                if (bot->name[0])
                {
                    for (unsigned other = 0; other < slot; ++other)
                    {
                        if (Native<MemberAvailableFn>(0x0118E020)(party, other)) continue;
                        const auto* previous = static_cast<const BotRecord*>(Native<MemberFn>(0x00CA2210)(other));
                        if (previous && previous->valid == 1 &&
                            std::memcmp(previous->name, bot->name, sizeof(bot->name)) == 0)
                        { ++duplicateNames; break; }
                    }
                }
            }
            ConsolePrint("[BOT120-PROFILE] lobby=%llu generated=%u profileSource=embedded-names skillWeights=3/17/54/21/5 operatorModels=native-selected stats=local-fictional\r\n",
                static_cast<unsigned long long>(s_lobbyId), requested);
            ConsolePrint("[BOT120-ROSTER] lobby=%llu staged=%u duplicateNativeNameIndexes=%u duplicateNames=%u emptyNames=%u gameMembersAdded=no\r\n",
                static_cast<unsigned long long>(s_lobbyId), observed,
                duplicateNameIndexes, duplicateNames, emptyNames);
            const unsigned dataReady = Native<AllowedFn>(0x00CA2250)() ? 1u : 0u;
            ConsolePrint("[BOT120-NATIVE] requested=%u copied=%s rawValid=%u dataReady=%u stockUi=%s\r\n",
                requested, populated ? "yes" : "no", validRecords, dataReady,
                s_experimentalUi ? "augmented" : "unchanged");
            ConsolePrint("[BOT120] lobby=%llu humans=%u capacity=%u requested=%u nativePool=%s mode=%s\r\n",
                static_cast<unsigned long long>(s_lobbyId), humans, capacity, requested,
                populated ? "prepared" : "unavailable", capacity > 32 ? "large" : "mp");
            // The caller must not cache the requested amount after failure:
            // otherwise this lobby permanently suppresses a valid retry.
            if (!populated) ++s_initAttempts;
            return populated;
        }

        struct LaunchPopulation
        {
            unsigned humans = 0;
            unsigned nativeBots = 0;
            unsigned capacity = 0;
            bool valid = false;
        };

        LaunchPopulation ReadLaunchPopulation(const void* party) noexcept
        {
            LaunchPopulation population;
            if (!party) return population;
            const unsigned capacity = Native<PartyCapacityFn>(0x0118C7D0)(party);
            if (!capacity || capacity > kMaxNativeSlots) return population;
            const unsigned humans = Native<CountFn>(0x0118AB60)(party, 1);
            if (!humans || humans > capacity) return population;
            population.humans = humans;
            population.capacity = capacity;
            population.valid = true;

            // Only game-recognized native bot members count. A ReplayDW
            // botQuota, copied uninitialized record, and a fabricated LUI row
            // are NOT additional players. This matters on Warzone where the
            // old trace reported requested=24 but present=0.
            if (!s_allowBots || !Native<AllowedFn>(0x00CA2250)())
                return population;
            const auto occupied = Native<MemberAvailableFn>(0x0118E020);
            const auto member = Native<MemberFn>(0x00CA2210);
            // The 1.20 stock presence predicate also tests the playlist BOTS
            // flag, which TU19 public playlists may not publish. This prevented
            // a fully initialized 11-record native MP pool from ever meeting
            // the six-player launch threshold. Require the pool to have been
            // selected, copied, and published to GameStateInfo this lobby.
            if (!s_nativePoolReady) return population;
            for (unsigned slot = 0; slot < capacity; ++slot)
            {
                if (occupied(party, slot)) continue;
                const auto* bot = static_cast<const BotRecord*>(member(slot));
                if (bot && bot->valid == 1 && bot->name[0])
                    ++population.nativeBots;
            }
            if (population.nativeBots != s_botCount)
                population.nativeBots = 0; // incomplete publication cannot launch

            return population;
        }

        bool LaunchPopulationReady(void* party) noexcept
        {
            // Restrict to the *local hosted online matchmaking party*.
            // Non-match lobbies and internal/split-screen parties retain the
            // engine's original startup behavior, not this Replay policy.
            if (!party || party != Native<PartyFn>(0x01187EE0)() ||
                !Native<PartyCheckFn>(0x0118DD00)(party) ||
                !Native<PartyCheckFn>(0x01189120)(party))
                return true;
            const auto nativeLobby =
                *reinterpret_cast<const std::uint64_t*>(ImageBase() + kNativeMatchmaker + 79656);
            const bool hostDocumentReady =
                *reinterpret_cast<const volatile std::uint8_t*>(ImageBase() + kNativeMatchmaker + 80128) != 0;
            const auto population = ReadLaunchPopulation(party);
            const unsigned total = population.humans + population.nativeBots;
            // Phase 1 is lobby population, not gameplay. Even after the
            // roster reaches six slots, leave the lobby waiting until the
            // gameplay feature is explicitly enabled for a later test.
            const bool lobbyOnly = Option(L"CODREVAMPED_120_LOBBY_ONLY", 0, 1) != 0;
            const bool permitted = !lobbyOnly && nativeLobby && nativeLobby == s_lobbyId &&
                hostDocumentReady && population.valid &&
                total >= kMinimumLaunchPlayers;
            if (!permitted)
            {
                const auto now = GetTickCount64();
                if (total != s_lastPopulationTotal ||
                    now - s_lastPopulationNoteMs >= 3000)
                {
                    s_lastPopulationTotal = total;
                    s_lastPopulationNoteMs = now;
                    ConsolePrint("[BOT120-MINPLAYERS] lobby=%llu humans=%u presentBots=%u total=%u required=%u capacity=%u hostDoc=%u state=waiting\r\n",
                        static_cast<unsigned long long>(nativeLobby),
                        population.humans, population.nativeBots, total,
                        kMinimumLaunchPlayers, population.capacity,
                        static_cast<unsigned>(hostDocumentReady));
                }
            }
            return permitted;
        }

        // Native Replay 1.20 SV_AssignBotDataToTeam. The stock selector
        // restricts bots to the requested MP team; BR's neutral native bot
        // pool deliberately has no single axis/allies team, so stock returns
        // -1. Only in a hosted BR lobby can we choose an available bot record
        // without that MP team filter. All records remain real engine data.
        int __fastcall ServerAssignBotHook(unsigned requestedTeam) noexcept
        {
            const int stock = s_originalServerAssignBot
                ? s_originalServerAssignBot(requestedTeam) : -1;
            if (stock >= 0)
            {
                // Stock assignment is a real game-server event, unlike a
                // prepared frontend record. Log it without altering its data.
                if (s_capacity > 32 && s_nativePoolReady && s_allowBots)
                    ConsolePrint("[BOT120-SV] assignment=stock botIndex=%d requestedTeam=%u\r\n",
                        stock, requestedTeam);
                return stock;
            }
            if (Option(L"CODREVAMPED_120_GAMEPLAY_BOTS", 1, 1) == 0 ||
                !s_nativePoolReady || !s_allowBots ||
                s_capacity <= 32 || !s_lobbyId ||
                !Native<void*(__fastcall*)()>(0x0137D670)())
                return stock;
            auto* pool = reinterpret_cast<BotRecord*>(ImageBase() + 0x0E183D00);
            const auto* party = Native<PartyFn>(0x01187EE0)();
            if (!party) return stock;
            for (unsigned index = 0; index < kMaxNativeSlots; ++index)
            {
                auto& bot = pool[index];
                if (!bot.valid || bot.inUse ||
                    Native<MemberAvailableFn>(0x0118E1F0)(party, index))
                    continue;
                bot.inUse = 1;
                // Only use an engine-requested valid group; a zero means
                // neutral/unassigned and must not be fabricated into a squad.
                if (requestedTeam >= 1 && requestedTeam <= 152)
                    bot.team = static_cast<std::uint8_t>(requestedTeam);
                ++s_serverBotAssigned;
                ConsolePrint("[BOT120-SV] assignment=accepted botIndex=%u requestedTeam=%u assignedTotal=%u\r\n",
                    index, requestedTeam, s_serverBotAssigned);
                return static_cast<int>(index);
            }
            ConsolePrint("[BOT120-SV] assignment=exhausted requestedTeam=%u assignedTotal=%u\r\n",
                requestedTeam, s_serverBotAssigned);
            return -1;
        }

        // Preserve stock team/squad behavior for all humans and non-Warzone
        // clients. An actual server bot is identified by native SV_BotIsBot
        // plus an in-use native record whose client field matches.
        const BotRecord* FindServerBot(unsigned client, unsigned* slot = nullptr) noexcept
        {
            if (Option(L"CODREVAMPED_120_GAMEPLAY_BOTS", 1, 1) == 0 ||
                !s_nativePoolReady || !s_allowBots || s_capacity <= 32 ||
                client >= kMaxNativeSlots ||
                !Native<bool(__fastcall*)(unsigned)>(0x01359F90)(client))
                return nullptr;
            auto* pool = reinterpret_cast<const BotRecord*>(ImageBase() + 0x0E183D00);
            for (unsigned i = 0; i < kMaxNativeSlots; ++i)
                if (pool[i].valid && pool[i].inUse && pool[i].client == client)
                {
                    if (slot) *slot = i;
                    return &pool[i];
                }
            return nullptr;
        }

        int __fastcall ServerAssignedTeamHook(unsigned client) noexcept
        {
            if (const auto* bot = FindServerBot(client))
                if (bot->team >= 1 && bot->team <= 152)
                    return bot->team;
            return s_originalServerAssignedTeam ? s_originalServerAssignedTeam(client) : 0;
        }
        int __fastcall ServerAssignedSquadHook(unsigned client) noexcept
        {
            if (const auto* bot = FindServerBot(client))
                if (bot->team >= 1 && bot->team <= 152)
                    return static_cast<int>(bot->team) - 1;
            return s_originalServerAssignedSquad ? s_originalServerAssignedSquad(client) : -1;
        }

        bool __fastcall ReadyToLaunchHook(void* party, const void* activeClient) noexcept
        {
            // Both native launch paths are guarded. PartyHost_Frame can call
            // StartMatchInternal without taking this predicate first.
            if (!LaunchPopulationReady(party)) {
                s_hostLaunchTrace.RecordPolicyBlocked(false);
                return false;
            }
            const bool nativeReady = s_originalReadyToLaunch &&
                s_originalReadyToLaunch(party, activeClient);
            const auto now = GetTickCount64();
            s_hostLaunchTrace.RecordReady(now, nativeReady);
            if (s_launchRequested && now - s_lastNativeLaunchResultLoggedMs >= 1500)
            {
                s_lastNativeLaunchResultLoggedMs = now;
                ConsolePrint("[BOT120-LAUNCH-CHECK] kind=ready nativeReady=%u lobby=%llu assignedBots=%u\r\n",
                    static_cast<unsigned>(nativeReady),
                    static_cast<unsigned long long>(s_lobbyId), s_serverBotAssigned);
            }
            return nativeReady;
        }

        std::uint64_t __fastcall StartMatchInternalHook(void* party,
                                                       const void* activeClient) noexcept
        {
            if (!LaunchPopulationReady(party)) {
                s_hostLaunchTrace.RecordPolicyBlocked(true);
                return 0;
            }
            if (!s_originalStartMatchInternal) return 0;
            const auto result = s_originalStartMatchInternal(party, activeClient);
            s_hostLaunchTrace.RecordStart(GetTickCount64(), result);
            ConsolePrint("[BOT120-LAUNCH-CHECK] kind=start-internal result=0x%llX lobby=%llu assignedBots=%u\r\n",
                static_cast<unsigned long long>(result),
                static_cast<unsigned long long>(s_lobbyId), s_serverBotAssigned);
            return result;
        }

        void TryStartHostedMatch(void* party, unsigned capacity, std::uint64_t ageMs) noexcept
        {
            if (s_launchRequested ||
                Option(L"CODREVAMPED_120_AUTO_START", 1, 1) == 0 ||
                !LaunchPopulationReady(party))
                return;
            // Native 1.20's DW_LobbyControls uses PartyHost_RequestStartMatch
            // after bot pool preparation; a quota alone never requests a
            // gameplay launch. Allow time for authenticated 145/18 and 145/15
            // to finish before signaling the local host. Single shot/lobby.
            if (capacity > 32 && !s_brMinimumRequested && ageMs >= 15000)
            {
                // Never undercut the common six-player start requirement
                // with the old DW-1.20 Warzone two-player override.
                Native<CommandFn>(0x015C1C20)(0, "set br_minplayers 6\n");
                s_brMinimumRequested = true;
                ConsolePrint("[BOT120-LAUNCH] Warzone br_minplayers=6 requested\r\n");
            }
            if (ageMs < 20000 || (capacity > 32 && !s_brMinimumRequested)) return;
            // Exactly the same native function used in DW_LobbyControls_Frame.
            Native<void(__fastcall*)(void*, bool)>(0x0119CFA0)(party, true);
            s_launchRequested = true;
            s_hostLaunchTrace.RecordRequest(GetTickCount64());
            ConsolePrint("[BOT120-LAUNCH] lobby=%llu native-host-start-requested bots=%u capacity=%u ageMs=%llu\r\n",
                static_cast<unsigned long long>(s_lobbyId), s_botCount, capacity,
                static_cast<unsigned long long>(ageMs));
        }

        void Frame() noexcept
        {
            ++s_frameCounter;
            if (!s_optimizationQueued && s_frameCounter >= 60)
                QueueModeOne();
            if (!s_active) return;
            // Always track the hosted lobby, even if automatic bots are off.
            // The minimum-population policy still permits six real players.
            const bool botsEnabled = Option(L"CODREVAMPED_120_AUTOBOTS", 1, 1) != 0;

            const auto inLobby = Native<LobbyFn>(0x01187FA0);
            if (!inLobby())
            {
                if (s_lobbyId && !s_loggedLobbyExit)
                {
                    s_loggedLobbyExit = true;
                    ConsolePrint("[BOT120-STAGE] lobby-exited id=%llu wantedBots=%u previouslyPrepared=%u frame=%u; native gameplay/load reason not exposed here\r\n",
                        static_cast<unsigned long long>(s_lobbyId),
                        s_botCount == ~0u ? 0 : s_botCount,
                        s_lastDisplayedBots == ~0u ? 0 : s_lastDisplayedBots,
                        s_frameCounter);
                    ConsolePrint("[BOT120-STAGE] hostServerLobby=%p engineAssignedBots=%u (frontend-staged-bot-count-is-not-spawn-count)\r\n",
                        Native<void*(__fastcall*)()>(0x0137D670)(),
                        s_serverBotAssigned);
                    const auto trace = s_hostLaunchTrace.Read();
                    const auto now = GetTickCount64();
                    ConsolePrint("[LOAD120] lobby=%llu phase=%s requested=%u readyChecks=%u readyAccepted=%u internalCalls=%u policyBlockedReady=%u policyBlockedStart=%u lastResult=0x%llX ageSinceRequestMs=%llu assignedBots=%u (observations-not-cause)\r\n",
                        static_cast<unsigned long long>(s_lobbyId),
                        codrevamped::mw120::loading::LastObservedPhase(trace),
                        static_cast<unsigned>(trace.requestTick != 0), trace.readyChecks,
                        trace.readyAccepted, trace.internalCalls,
                        trace.policyBlockedReady, trace.policyBlockedStart,
                        static_cast<unsigned long long>(trace.lastInternalResult),
                        static_cast<unsigned long long>(trace.requestTick && now >= trace.requestTick ? now - trace.requestTick : 0),
                        s_serverBotAssigned);
                }
                // The lobby predicate can go false *during level loading*.
                // Keep native bot eligibility/records alive until the game
                // takes ownership of them; otherwise bots disappear exactly
                // as the host transitions into Shipment/Verdansk.
                return;
            }
            s_loggedLobbyExit = false;
            const auto getParty = Native<PartyFn>(0x01187EE0);
            auto* party = getParty();
            if (!party || !Native<PartyCheckFn>(0x0118DD00)(party) ||
                !Native<PartyCheckFn>(0x01189120)(party))
                return; // Client never spawns remote-host bots.
            const auto id = *reinterpret_cast<const std::uint64_t*>(ImageBase() + kNativeMatchmaker + 79656);
            if (!id) return;
            if (id != s_lobbyId)
            {
                s_lobbyId = id;
                s_hostLaunchTrace.Reset();
                s_serverBotAssigned = 0;
                s_lastNativeLaunchResultLoggedMs = 0;
                codrevamped::bots120::SetLobby(id);
                s_lobbyFirstSeen = GetTickCount64();
                s_humanCount = ~0u;
                s_botCount = ~0u;
                s_capacity = 0;
                s_initAttempts = 0;
                s_nativePoolReady = false;
                s_launchRequested = false;
                s_brMinimumRequested = false;
                s_lastNativeAttemptMs = 0;
                s_fixedOneSlotLobby = false;
                s_lastPopulationTotal = ~0u;
                s_lastPopulationNoteMs = 0;
                // A lobby id can exist before the backend starts a search.
                // Do not override the stock bot-eligibility predicate until
                // an actual hosted match has reached the launch phase.
                s_allowBots = false;
                s_lastGateNote = 0;
                s_lastDisplayedBots = ~0u;
                s_uiLastRoot = 0;
                s_uiLastWrite = 0;
                s_uiLastLobby = 0;
                s_uiLastBotCount = 0;
                s_uiDiagnosticWritten = false;
            }
            // A valid local lobby id alone does not mean the game has joined
            // a backend-created match. In the October 13 trace, this path
            // initialized 24 BR bots six seconds BEFORE startSearch (145/18).
            // The source Replay DW client validates the host-document state at
            // matchmaker +80128, and requires Party_IsGameLobby before fill.
            const auto now = GetTickCount64();
            const auto elapsedMs = now - s_lobbyFirstSeen;
            constexpr std::uint64_t kEarliestHostedFillMs = 10000;
            const bool gameLobby = Native<PartyCheckFn>(0x0118DD00)(party);
            const bool hostDocumentReady =
                *reinterpret_cast<const volatile std::uint8_t*>(ImageBase() + kNativeMatchmaker + 80128) != 0;
            if (!gameLobby || !hostDocumentReady || elapsedMs < kEarliestHostedFillMs)
            {
                // One reason line every five seconds, not on every UI frame.
                // This also reveals if the server is not reaching the stock
                // host-document-ready transition for this lobby.
                if (now - s_lastGateNote >= 5000)
                {
                    s_lastGateNote = now;
                    ConsolePrint("[BOT120-GATE] lobby=%llu gameLobby=%u hostDocumentReady=%u ageMs=%llu stage=waiting-for-hosted-match\r\n",
                        static_cast<unsigned long long>(s_lobbyId),
                        static_cast<unsigned>(gameLobby),
                        static_cast<unsigned>(hostDocumentReady),
                        static_cast<unsigned long long>(elapsedMs));
                }
                return;
            }
            unsigned capacity = Native<PartyCapacityFn>(0x0118C7D0)(party);
            const unsigned humans = Native<CountFn>(0x0118AB60)(party, 1);
            // Never infer a game mode from "capacity=1". Wait for the native
            // host document/catalog to apply the actual playlist capacity.
            // This handles Shipment, Ground War, and Verdansk without guessing
            // which playlist was selected.
            if (!humans || capacity < kMinimumLaunchPlayers ||
                capacity > kMaxNativeSlots || humans > capacity)
                return;
            if (!botsEnabled)
            {
                TryStartHostedMatch(party, capacity, elapsedMs);
                return;
            }
            // A six-human lobby can start without waiting for a synthetic
            // bot pool. The real-player minimum has already been satisfied.
            if (humans >= kMinimumLaunchPlayers && !s_nativePoolReady)
            {
                TryStartHostedMatch(party, capacity, elapsedMs);
                return;
            }
            // No artificial multiplayer or Warzone cap: always reserve the
            // actual human members, then fill the remaining native party slots.
            // The bounded native Replay 1.20 GameStateInfo pool has 200 slots.
            // A server-advertised quota is not itself a spawned player.
            const unsigned target = std::min<unsigned>(
                capacity - humans, kMaxNativeSlots - humans);
            if (s_nativePoolReady && s_botCount == target &&
                s_humanCount == humans && s_capacity == capacity)
            {
                TryStartHostedMatch(party, capacity, elapsedMs);
                return;
            }
            if (s_initAttempts >= 3) return;
            // A failed selector can be transient during playlist/BR script
            // initialization. Retry at most three times, no sooner than one
            // second apart, rather than hammering engine data every frame.
            if (s_lastNativeAttemptMs && now - s_lastNativeAttemptMs < 1000) return;
            s_lastNativeAttemptMs = now;
            s_allowBots = true;
            const bool ready = PrepareBots(party, capacity, humans, target);
            if (ready)
            {
                s_nativePoolReady = true;
                s_botCount = target;
                s_humanCount = humans;
                s_capacity = capacity;
                TryStartHostedMatch(party, capacity, elapsedMs);
            }
            else
            {
                s_nativePoolReady = false;
                ConsolePrint("[BOT120-RETRY] lobby=%llu attempt=%u/3; native selection incomplete\r\n",
                    static_cast<unsigned long long>(s_lobbyId), s_initAttempts);
            }
        }

        void __fastcall FrameHook() noexcept
        {
            if (s_originalFrame) s_originalFrame();
            // Called from the game's ScrPlace_EndFrame on the game/UI thread.
            // Never invoke game APIs from the proxy loader or background worker.
            Frame();
        }
    }

    void Install() noexcept
    {
        if (s_active) return;
        unsigned hooks = 0;
        hooks += Replay120InstallHook("ScrPlace_EndFrame/autobots", kScrPlaceEndFrame,
            reinterpret_cast<void*>(&FrameHook),
            reinterpret_cast<void**>(&s_originalFrame)) ? 1u : 0u;
        hooks += Replay120InstallHook("BG_Bots_IsBotMatchMakingAllowed", kBotEligibility,
            reinterpret_cast<void*>(&AllowBotMatchmaking),
            reinterpret_cast<void**>(&s_originalAllowed)) ? 1u : 0u;
        // Exact Replay 1.20 native functions from DW_LobbyControls.cpp.
        // Block both stock readiness and the final internal start call, so
        // a direct PartyHost_Frame branch cannot start a one-player match.
        hooks += Replay120InstallHook("PartyHost_ReadyToLaunch/min6", 0x0119B0E0,
            reinterpret_cast<void*>(&ReadyToLaunchHook),
            reinterpret_cast<void**>(&s_originalReadyToLaunch)) ? 1u : 0u;
        hooks += Replay120InstallHook("PartyHost_StartMatchInternal/min6", 0x0119E3D0,
            reinterpret_cast<void*>(&StartMatchInternalHook),
            reinterpret_cast<void**>(&s_originalStartMatchInternal)) ? 1u : 0u;
        const unsigned baseHooks = hooks; // all four stock lobby/launch hooks must install
        // Executable checked: 0x14132ED80 native SV_AssignBotDataToTeam.
        // Called only after native server/bot spawn exists. No fabricated
        // party members or XUIDs; not a substitute for a running game server.
        hooks += Replay120InstallHook("SV_AssignBotDataToTeam/BR", 0x0132ED80,
            reinterpret_cast<void*>(&ServerAssignBotHook),
            reinterpret_cast<void**>(&s_originalServerAssignBot)) ? 1u : 0u;
        hooks += Replay120InstallHook("SV_GetAssignedTeam/BR", 0x01370860,
            reinterpret_cast<void*>(&ServerAssignedTeamHook),
            reinterpret_cast<void**>(&s_originalServerAssignedTeam)) ? 1u : 0u;
        hooks += Replay120InstallHook("SV_GetAssignedSquad/BR", 0x013707D0,
            reinterpret_cast<void*>(&ServerAssignedSquadHook),
            reinterpret_cast<void**>(&s_originalServerAssignedSquad)) ? 1u : 0u;
        // Stock UI can query presence while game-state publication is still
        // in progress. Making freshly initialized bot records visible here
        // caused the host to stall even with extra LUI binding disabled.
        // Leave the stock predicate untouched by default. It can be opted
        // into separately for future diagnosis once gameplay loads.
        const bool hookBotPresence = Option(L"CODREVAMPED_120_BOT_PRESENCE", 0, 1) != 0;
        if (hookBotPresence)
        {
            hooks += Replay120InstallHook("BG_GameStateInfo_IsBotMemberPresent", 0x00CA2270,
                reinterpret_cast<void*>(&IsBotPresent),
                reinterpret_cast<void**>(&s_originalBotPresent)) ? 1u : 0u;
        }

        const unsigned coreHooks = hooks;
        // Coherent single-pass UI replacements are active only with a complete
        // staged native roster. CODREVAMPED_120_BOT_UI=0 disables both hooks.
        // Multiple live runs failed immediately after publishing staged
        // bot records into a synthetic 25-member LUI model. The original
        // DW-1.20 client replaces bot visibility, name expansion, team/squad
        // resolution AND complete party-model functions together; this DLL
        // does not yet provide that entire contract. Fail closed for all
        // users until those engine-side functions are ported as a unit.
        s_experimentalUi = Option(L"CODREVAMPED_120_BOT_UI", 1, 1) != 0;
        if (s_experimentalUi)
        {
            // Install all four as a single lobby-display feature. Before,
            // only the two LUI builders were hooked while the stock visible
            // predicate and count continued to report one human participant.
            unsigned uiHooks = 0;
            uiHooks += Replay120InstallHook("Party_IsMemberUIVisible/bots", 0x0118E2C0,
                reinterpret_cast<void*>(&PartyVisibleHook),
                reinterpret_cast<void**>(&s_originalPartyVisible)) ? 1u : 0u;
            uiHooks += Replay120InstallHook("Party_CountUIVisible/bots", 0x0118ADD0,
                reinterpret_cast<void*>(&PartyVisibleCountHook),
                reinterpret_cast<void**>(&s_originalPartyVisibleCount)) ? 1u : 0u;
            uiHooks += Replay120InstallHook("LUI_UpdateActivePartyBotMembers", 0x01B21D50,
                reinterpret_cast<void*>(&LobbyModelHook),
                reinterpret_cast<void**>(&s_originalLobbyModel)) ? 1u : 0u;
            uiHooks += Replay120InstallHook("LUI_UpdatePartyBotMembersFiltered", 0x01B22B40,
                reinterpret_cast<void*>(&FilteredLobbyModelHook),
                reinterpret_cast<void**>(&s_originalFilteredLobbyModel)) ? 1u : 0u;
            hooks += uiHooks;
            if (uiHooks != 4)
            {
                // Detours are persistent, so on partial installation all
                // wrappers immediately fall through to stock behavior.
                s_experimentalUi = false;
                ConsolePrint("[BOT120-UI-GUARD] partial UI hooks=%u/4; stock behavior\r\n", uiHooks);
            }
        }
        s_active = baseHooks == 4u;
        ConsolePrint("[BOT120] native hosting hooks=%u/%u autobots=%s fill=party-capacity-minus-real-players maxNative=%u com_optimized=1-only\r\n",
            coreHooks, hookBotPresence ? 8u : 7u,
            Option(L"CODREVAMPED_120_AUTOBOTS", 1, 1) ? "on" : "off", kMaxNativeSlots);
        ConsolePrint("[BOT120-SV] native-server-hooks-installed=%u/3 fallback=%s (MP passes through stock; check hooks above)\r\n",
            coreHooks >= baseHooks ? (coreHooks - baseHooks - (hookBotPresence ? 1u : 0u)) : 0u,
            Option(L"CODREVAMPED_120_GAMEPLAY_BOTS", 1, 1) ? "on" : "off");
        ConsolePrint("[BOT120-GATE] native-pool-deferred=10s backend-host-document-required=yes bot-presence-override=%s\r\n",
            hookBotPresence ? "on" : "off");
        ConsolePrint("[BOT120-MINPLAYERS] required=%u (humans + game-recognized bots) appliesTo=all-hosted-playlists strict=yes\r\n",
            kMinimumLaunchPlayers);
        ConsolePrint("[BOT120-LAUNCH] autoStart=%s minParticipants=6 minHostAge=20s retryInterval=1s\r\n",
            Option(L"CODREVAMPED_120_AUTO_START", 1, 1) ? "on" : "off");
        ConsolePrint("[BOT120-PHASE] lobby-population-only=%s native-start-blocked-until-enabled\r\n",
            Option(L"CODREVAMPED_120_LOBBY_ONLY", 0, 1) ? "yes" : "no");
        ConsolePrint("[BOT120-UI-GUARD] native-lobby-ui=%s partyVisible+count+model unified; disable CODREVAMPED_120_BOT_UI=0\r\n",
            s_experimentalUi ? "enabled" : "disabled");
    }
}
