// Backend controls enter through the native ruleset dvar window. Only the
// current lobby host submits native start/bot requests, on the main thread.
#include "com_debugstates.h"
#include "replay_dvar.h"

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    void DW_BotPolicy_Register();
    void DW_BotPolicy_Prepare(const void *);
    void DW_BotPolicy_BuildRoster(const void *, unsigned, unsigned);
    void replay_rva_00ca2070();                 // BG_GameStateInfo_ClearBotData
    bool replay_rva_01187fa0();                 // Lobby_IsInLobby
    void *replay_rva_01187ee0();                // Lobby_GetPartyData
    bool replay_rva_01189120(const void *);     // Party_AreWeHost
    bool replay_rva_0118dd00(const void *);     // Party_IsGameLobby
    void replay_rva_0119cfa0(void *, bool);     // PartyHost_RequestStartMatch
    void replay_rva_0119a5a0(void *);           // PartyHost_GamestateChanged
    unsigned replay_rva_0118c7d0(const void *); // Party_GetNumGameSlots
    void replay_rva_011916c0(void *, int);  // Party_SetNumGameSlots, including member index bits
    void replay_rva_00ca2370(int, int);     // BG_GameStateInfo_SetupBotsCountsPerTeamForScript
    void replay_rva_00ca1d20();             // BG_Bots_SelectBotsWithInitializedCount
    void replay_rva_01119b40(int, uint8_t); // BG_SetBotsTeamLimit
    unsigned replay_rva_0118ab60(const void *, int);      // Party_CountMembersEvenIfInactive
    unsigned replay_rva_0118ad10(const void *, int, int); // Party_CountTeamMembers
    void replay_rva_00ca2110();         // BG_GameStateInfo_EnableGameLaunchWithBots
    bool replay_rva_01528420();         // Live_IsInSystemlinkLobby
    int replay_rva_00ca1c50();          // BG_Bots_GetControllerIndex
    unsigned replay_rva_010cd460(int);  // Playlist_GetPlaylistIdForNum
    bool replay_rva_010cc6f0(unsigned); // Playlist_GetBotMatchMakingEnabled
    bool replay_rva_00ca2250();         // BG_GameStateInfo_IsBotMatchMakingDataInitialized
    bool replay_rva_00ca2270(unsigned); // BG_GameStateInfo_IsBotMemberPresent
    bool replay_rva_0118e020(const void *, unsigned); // Party_IsMemberIndexDataAvailable
    extern uint8_t replay_rva_0c27e4b0[];             // OnlineMatchmakerOmniscient::ms_instance
    extern dvar_t *gl_14D386820;                      // xblive_privatematch
    extern dvar_t *gl_14D386948;                      // playlist selector
    extern dvar_t *gl_14D386840;                      // party_maxplayers
    extern dvar_t *gl_14C796328;                      // party_teamCount
    extern dvar_t *DVARBOOL_onlinegame;
    extern void *gl_151868880;                           // LUI_luaVM, protected by native LUI lock
    void replay_rva_019bdad0();                          // LUI_EnterCriticalSection
    void replay_rva_019bedb0();                          // LUI_LeaveCriticalSection
    int replay_rva_020838b0(void *);                     // lua_gettop
    void replay_rva_020836e0(void *, int, const char *); // lua_getfield
    int replay_rva_02084ac0(void *, int);                // lua_type
    void replay_rva_02084100(void *, double);            // lua_pushnumber
    void replay_rva_02084510(void *, int, const char *); // lua_setfield
    void replay_rva_02084790(void *, int);               // lua_settop
    unsigned replay_rva_0148fce0();                      // Sys_Milliseconds
}

namespace
{
    // Replay's complete registered type encoding. Script dvars use STRING (9),
    // while 7 is an unsigned 64-bit value, not a string pointer.
    enum class DvarType : uint8_t
    {
        Bool = 0,
        Float = 1,
        Vec2 = 2,
        Vec3 = 3,
        Vec4 = 4,
        Int = 5,
        Int64 = 6,
        UInt64 = 7,
        Enum = 8,
        String = 9,
        Color = 10,
        ColorXYZ = 11
    };
    dvar_t *s_start{}, *s_bots{}, *s_botCount{};
    bool s_started = false, s_filled = false;
    unsigned s_luaPoll = 0;
    cmd_function_s s_fillCommand{};
    uint64_t s_lobby = 0;
    int s_commandBotCount = 0;
    unsigned s_requestStarted = 0;
    bool s_requestPending = false;
    char s_requestDocument[16384]{};

    void SyncLobby()
    {
        // Native lobby identity at the target-build matchmaker field. A command
        // belongs to one matchmaking round, not a later lobby using this party.
        const auto lobby = *reinterpret_cast<const uint64_t *>(replay_rva_0c27e4b0 + 79656);
        if (lobby == s_lobby)
            return;
        s_lobby = lobby;
        s_commandBotCount = 0;
        s_requestPending = false;
        s_filled = false;
        s_started = false;
    }

    void FillLobby_f()
    {
        if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread() || !s_botCount)
            return;
        unsigned requested = 0;
        const char *text = Cmd_Argc() == 2 ? Cmd_Argv(1) : nullptr;
        if (!text || !*text)
        {
            Com_Printf(25, "Usage: fill_lobby <number> (1-199 bots to add)\n");
            return;
        }
        for (const char *p = text; *p; ++p)
        {
            if (*p < '0' || *p > '9' || requested > 199 / 10)
            {
                Com_Printf(25, "fill_lobby: enter a whole number from 1 to 199.\n");
                return;
            }
            requested = requested * 10 + unsigned(*p - '0');
        }
        if (!requested || requested > 199)
        {
            Com_Printf(25, "fill_lobby: enter a whole number from 1 to 199.\n");
            return;
        }
        if (!Com_FrontEndScene_IsActive() || !replay_rva_01187fa0() || replay_rva_01528420() ||
            !DVARBOOL_onlinegame || !DVARBOOL_onlinegame->current.enabled || !gl_14D386820 ||
            gl_14D386820->current.enabled)
        {
            Com_Printf(25, "fill_lobby: run this in a public matchmaking lobby in the frontend.\n");
            return;
        }
        auto *party = replay_rva_01187ee0();
        if (!party || !replay_rva_0118dd00(party) || !replay_rva_01189120(party))
        {
            Com_Printf(25, "fill_lobby: only the current matchmaking host can add bots.\n");
            return;
        }
        SyncLobby();
        if (!s_lobby)
        {
            Com_Printf(25, "fill_lobby: wait until the matchmaking lobby is ready.\n");
            return;
        }
        const auto humans = replay_rva_0118ab60(party, 1);
        const auto capacity = replay_rva_0118c7d0(party);
        if (!humans || capacity > 200 || humans >= capacity)
        {
            Com_Printf(25, "fill_lobby: no playlist slots are available.\n");
            return;
        }
        unsigned bots = 0;
        if (replay_rva_00ca2250())
            for (unsigned i = 0; i < capacity; ++i)
                if (!replay_rva_0118e020(party, i) && replay_rva_00ca2270(i))
                    ++bots;
        // A second command before the next frame also includes the queued bots.
        if (s_requestPending && s_commandBotCount > int(bots))
            bots = unsigned(s_commandBotCount);
        if (bots >= capacity - humans)
        {
            Com_Printf(25, "fill_lobby: the lobby is already full.\n");
            return;
        }
        const auto available = capacity - humans - bots;
        const auto added = requested < available ? requested : available;
        s_commandBotCount = int(bots + added);
        s_requestPending = true;
        s_requestStarted = replay_rva_0148fce0();
        // Queue the SDK's existing authenticated 145/15 host document update.
        // The backend retains the count; no operator credential is used.
        *reinterpret_cast<bool *>(replay_rva_0c27e4b0 + 79636) = true;
        *reinterpret_cast<unsigned *>(replay_rva_0c27e4b0 + 79640) = 0;
        Com_Printf(
            25,
            "fill_lobby: adding %u bots (%u requested); %u bots total, playlist capacity %u.\n",
            added,
            requested,
            unsigned(s_commandBotCount),
            capacity);
    }

    void BotSetupLimits()
    {
        // The shipped GameSetupButtonsBots uses Lobby.GetMaxBotLimit, which
        // clamps these two Lua constants against real lobby slots. Change the
        // constants in the existing VM; no modified fastfile is required.
        const auto now = replay_rva_0148fce0();
        if (s_luaPoll && unsigned(now - s_luaPoll) < 1000)
            return;
        s_luaPoll = now;
        // Script-created BR dvars may appear only when its VM loads. Retain
        // their registered type and enforce the local two-player rule there too.
        if (auto *minimum = Dvar_FindVarByName("br_minplayers"))
        {
            DvarValue value{};
            if (static_cast<DvarType>(minimum->type) == DvarType::Int &&
                minimum->current.integer != 2)
            {
                value.integer = 2;
                Dvar_SetVariant(minimum, &value, 0);
            }
            else if (static_cast<DvarType>(minimum->type) == DvarType::String &&
                     minimum->current.string &&
                     (minimum->current.string[0] != '2' || minimum->current.string[1]))
            {
                value.string = "2";
                Dvar_SetVariant(minimum, &value, 0);
            }
        }
        if (auto *salePrice = Dvar_FindVarByName("lui_battlepass_tier_sale_price"))
        {
            if (static_cast<DvarType>(salePrice->type) == DvarType::Int &&
                salePrice->current.integer)
            {
                DvarValue free{};
                Dvar_SetVariant(salePrice, &free, 0);
            }
        }
        if (!gl_151868880)
            return;
        replay_rva_019bdad0();
        if (auto *vm = gl_151868880)
        {
            const auto top = replay_rva_020838b0(vm);
            replay_rva_020836e0(vm, -10002, "Lobby");
            if (replay_rva_02084ac0(vm, -1) == 5)
            {
                constexpr const char *keys[] = {"BotLimit", "BotLimitForSplitScreen"};
                for (const char *key : keys)
                {
                    replay_rva_02084100(vm, 200.0);
                    replay_rva_02084510(vm, -2, key);
                }
            }
            replay_rva_02084790(vm, top);
            replay_rva_020836e0(vm, -10002, "BATTLEPASS");
            if (replay_rva_02084ac0(vm, -1) == 5)
            {
                replay_rva_02084100(vm, 0.0);
                replay_rva_02084510(vm, -2, "SINGLE_TIER_COST");
            }
            replay_rva_02084790(vm, top);
        }
        replay_rva_019bedb0();
    }

    bool BotsRequested()
    {
        return DW_LocalBackend_IsEnabled() && s_botCount && s_botCount->current.integer > 0;
    }
} // namespace

// Complete original eligibility predicate, retaining every native platform,
// online mode and controller check. A DW operator request additionally enables
// the shipped bot consumer for playlists whose BOTS flag is normally absent.
extern "C" bool func_140CA1C80()
{
    if (replay_rva_01528420() || gl_14D386820->current.enabled ||
        Com_GameMode_GetActiveGameMode() == 3 || !DVARBOOL_onlinegame->current.enabled)
        return false;
    const auto controller = replay_rva_00ca1c50();
    const auto playlist = replay_rva_010cd460(gl_14D386948->current.integer);
    return controller >= 0 && (BotsRequested() || replay_rva_010cc6f0(playlist));
}

extern "C" void DW_LobbyControls_Frame()
{
    if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread())
        return;
    BotSetupLimits();
    if (!s_start)
    {
        Dvar_BeginPermanentRegistration();
        s_start = Dvar_RegisterInt(
            "replay_dw_forceStart", 0, 0, 1, 0, "DW operator native lobby start request");
        s_bots = Dvar_RegisterInt(
            "replay_dw_fillBots", 0, 0, 1, 0, "Legacy DW bot request; use replay_dw_botCount");
        s_botCount = Dvar_RegisterInt(
            "replay_dw_botCount", 0, 0, 199, 0, "DW operator number of native bots to add");
        DW_BotPolicy_Register();
        Dvar_EndPermanentRegistration();
        Cmd_AddCommandInternal("fill_lobby", FillLobby_f, &s_fillCommand);
    }
    if (!s_start->current.integer)
        s_started = false;
    if (!s_botCount->current.integer)
        s_filled = false;
    if (!Com_FrontEndScene_IsActive() || !replay_rva_01187fa0())
        return;
    auto *party = replay_rva_01187ee0();
    if (!party || !replay_rva_0118dd00(party) || !replay_rva_01189120(party))
        return;
    SyncLobby();
    if (s_requestPending)
    {
        if (s_botCount->current.integer == s_commandBotCount)
        {
            s_requestPending = false;
            s_filled = false;
            Com_Printf(
                25, "fill_lobby: backend accepted %u native bots.\n", unsigned(s_commandBotCount));
        }
        else if (unsigned(replay_rva_0148fce0() - s_requestStarted) > 15000)
        {
            s_requestPending = false;
            Com_Printf(25, "fill_lobby: backend request timed out; no local-only fill applied.\n");
        }
    }
    if (gl_14D386820->current.enabled)
    {
        if (gl_14D386840->current.integer != 200 || replay_rva_0118c7d0(party) != 200)
        {
            DvarValue maximum{};
            maximum.integer = 200;
            Dvar_SetVariant(gl_14D386840, &maximum, 0);
            replay_rva_011916c0(party, 200);
            replay_rva_0119a5a0(party);
        }
        return;
    }
    if (s_botCount->current.integer && !s_filled)
    {
        auto *teams = gl_14C796328;
        // Use the native neutral-team bot pool for BR's many-squad layout,
        // then restore its real team count before publishing the game state.
        // No synthetic party members or Demonware accounts are created.
        if (!teams || static_cast<DvarType>(teams->type) != DvarType::Int)
            return;
        const DvarValue saved = teams->current;
        const auto humans = replay_rva_0118ab60(party, 1);
        const auto capacity = replay_rva_0118c7d0(party);
        const auto requested = unsigned(s_botCount->current.integer);
        if (!humans || capacity > 200 || humans >= capacity || requested > capacity - humans)
            return;
        const auto total = humans + requested;
        auto allies = 0u, axis = 0u;
        if (saved.integer == 2)
        {
            allies = replay_rva_0118ad10(party, 2, 1);
            axis = replay_rva_0118ad10(party, 1, 1);
            if (allies > humans || axis > humans - allies)
                return;
        }
        if (saved.integer > 2)
        {
            DvarValue neutral{};
            Dvar_SetVariant(teams, &neutral, 0);
        }
        // Initialize only the native bot quotas and pool. Party slots and their
        // network encoding retain the playlist's actual capacity (e.g. 152 BR).
        replay_rva_00ca2070();
        replay_rva_00ca2370(int(total), saved.integer == 2 ? 2 : 0);
        if (saved.integer == 2)
        {
            for (unsigned unassigned = humans - allies - axis + requested; unassigned; --unassigned)
                if (allies <= axis)
                    ++allies;
                else
                    ++axis;
            replay_rva_01119b40(0, uint8_t(allies));
            replay_rva_01119b40(1, uint8_t(axis));
        }
        replay_rva_00ca1d20();
        DW_BotPolicy_BuildRoster(party, capacity, requested);
        if (saved.integer > 2)
            Dvar_SetVariant(teams, &saved, 0);
        DW_BotPolicy_Prepare(party);
        replay_rva_00ca2110();
        replay_rva_0119a5a0(party);
        s_filled = true;
        Com_Printf(
            25,
            "DW_LOBBY_BOTS native pool prepared for %u bots; playlist capacity %u retained.\n",
            requested,
            capacity);
    }
    if (s_start->current.integer && !s_started)
    {
        replay_rva_0119cfa0(party, true);
        s_started = true;
        Com_Printf(25, "DW_LOBBY_START native host start requested.\n");
    }
}

// The migration and lobby controls share Replay's original host-document SDK
// wrapper. Extend its bounded JSON before the SDK copies the caller's buffer.
extern "C" void DW_LobbyControls_HostDocument(uint64_t lobby,
                                              void *result,
                                              const char **document,
                                              unsigned *length)
{
    if (!s_requestPending || lobby != s_lobby || result != replay_rva_0c27e4b0 + 131864 ||
        !*reinterpret_cast<const bool *>(replay_rva_0c27e4b0 + 80128))
        return;
    if (!document || !*document || !length || *length < 3 ||
        *length > sizeof(s_requestDocument) - 64 || (*document)[*length - 1] != 0 ||
        (*document)[*length - 2] != '}')
    {
        s_requestPending = false;
        Com_Printf(25, "fill_lobby: host document has no room for the request.\n");
        return;
    }
    for (unsigned i = 0; i < *length - 2; ++i)
        s_requestDocument[i] = (*document)[i];
    const int added = Com_sprintf(s_requestDocument + *length - 2,
                                  sizeof(s_requestDocument) - (*length - 2),
                                  ",\"dw_bot_count\":%u}",
                                  unsigned(s_commandBotCount));
    if (added <= 0 || unsigned(added) >= sizeof(s_requestDocument) - (*length - 2))
    {
        s_requestPending = false;
        return;
    }
    *length = *length - 2 + unsigned(added) + 1;
    *document = s_requestDocument;
}
