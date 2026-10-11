// Replay bot records are serialized with GameStateInfo, not Demonware users.
// Bind those records to the stock lobby models and to native ClientBegin.
#include "com_debugstates.h"
#include "replay_dvar.h"
#include <initializer_list>

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    bool func_141187FA0();                       // Lobby_IsInLobby
    void *func_141187EE0();                      // Lobby_GetPartyData
    bool func_14118E1F0(const void *, unsigned); // Party_IsMemberPresent
    bool func_14118E020(const void *, unsigned); // Party_IsMemberIndexDataAvailable
    bool func_14118E2C0(const void *, unsigned); // Party_IsMemberUIVisible
    bool func_14118EE80(const void *, unsigned); // Party_IsWaitingForPartyMember
    bool func_14118E0E0(const void *, unsigned); // Party_IsMemberLocal
    bool func_140CA2250();                       // BG_GameStateInfo_IsBotMatchMakingDataInitialized
    bool func_140CA2270(unsigned);               // BG_GameStateInfo_IsBotMemberPresent
    const void *func_140CA2230(unsigned);        // BG_GameStateInfo_GetBotMemberReadOnly
    void *func_140CA2210(unsigned);              // BG_GameStateInfo_GetBotMember
    bool func_141359F90(unsigned);               // SV_BotIsBot
    bool func_141371450(unsigned);               // SV_ClientMP_HasAssignedTeam
    void *func_14137D670();                      // SV_MainMP_GetServerLobby
    void *func_14118CF60(uint64_t *, const void *, unsigned); // Party_GetXuid
    int func_14118C070(const void *, uint64_t);               // Party_GetAssignedSquad
    int func_14118C110(const void *, uint64_t);               // Party_GetAssignedTeam
    const char *func_14107EA60(const uint64_t *);             // XUID::ToDevString
    void func_1412B0570(int, const char *, ...);              // Com_PrintError
    extern unsigned char gl_14E183D00[];                      // g_svMPBotData, 200 native records
    extern unsigned char gl_14EEF12A4[];                      // frontend client state
    extern int gl_14EEF1288[];                                // clientUIActives.connectionState
    extern unsigned char g_partyData[];
    extern dvar_t *gl_14D386988, *gl_14D386990, *gl_14C796328;
    void func_141B23610(const void *, int *);                   // SortPartyMembers
    void func_141B22140(const void *, unsigned, uint16_t, int); // stock human binding
    bool func_141528240();                                      // GameBattles active feature
    bool func_140F22880();                                      // GameBattles active session
    void func_140F23A00(const void *, uint16_t, int *, int *);
    bool func_14118DDB0(const void *);               // Party_IsHostDedicated
    unsigned func_14118C7D0(const void *);           // Party_GetNumGameSlots
    uint16_t func_141B0D390(uint16_t, const char *); // CreateModelFromPath
    void func_141B0E150(uint16_t, int);              // SetInt
    void func_141B0E0B0(uint16_t, bool);             // SetBool
    void func_141B0E280(uint16_t, const char *);     // SetString
    void func_141B97080(uint64_t, const char *, uint8_t *, void *, void *);
    void func_141B97230(uint64_t, const char *, void *); // PlayercardCache_GetPlayercard
    void func_141B24690(uint16_t, const void *);         // PushWeaponCustomization
    uint16_t func_141B0D520();                           // GetGlobalModel
    uint16_t func_141B0D710(uint16_t, const char *);     // GetModelFromPath
    int func_141B0D530(uint16_t);                        // GetInt
    bool func_141192AC0(const void *);                   // Party_UsingTeams (verified below)
    bool func_141192AA0(const void *);                   // Party_UsingSquads
}

namespace
{
    // All 88 bytes, including the complete opaque portion of the native 36-byte
    // wire data. Offsets are verified against Replay ReadBotData and its users.
    struct BotRecord
    {
        char name[36];
        char clan[11];
        uint8_t displayPad;
        uint16_t nameIndex;
        uint8_t unknown50[2];
        uint32_t modelIndex[3];
        uint8_t unknown64[12];
        uint8_t unknown76, team;
        uint16_t skill, rank, unknown82;
        uint8_t valid, inUse, client, pad;
    };

    static_assert(sizeof(BotRecord) == 88 && offsetof(BotRecord, team) == 77);
    static_assert(offsetof(BotRecord, valid) == 84 && offsetof(BotRecord, client) == 86);
    // Five visible characters, including the brackets. The engine's two-byte
    // color controls do not occupy visible tag characters; the complete text
    // and terminator still fit the native eleven-byte bot clan field.
    constexpr char BotClanTag[] = "[^3Bot^7]";
    static_assert(sizeof(BotClanTag) <= sizeof(BotRecord::clan));

    struct MemberRecord
    {
        uint8_t unknown0[52];
        char name[36];
        uint8_t unknown88[52];
        int follower;
        uint8_t unknown144[244];
        int subparty, team, squad;
        uint8_t unknown400[2], status, unknown403[5];
        uint64_t xuid;
        uint8_t unknown416[72];
    };

    static_assert(sizeof(MemberRecord) == 488 && offsetof(MemberRecord, team) == 392);
    static_assert(offsetof(MemberRecord, xuid) == 408);
    dvar_t *s_reserved{}, *s_squadSize{};

    const MemberRecord &Member(const void *party, unsigned index)
    {
        return reinterpret_cast<const MemberRecord *>(static_cast<const uint8_t *>(party) +
                                                      2192)[index];
    }

    bool Ready(const void *party)
    {
        return party && DW_LocalBackend_IsEnabled() && func_141187FA0() &&
               party == func_141187EE0() && func_140CA2250();
    }

    struct Assignments
    {
        const BotRecord *bots[200]{};
        int groups[200]{};
    };

    void Calculate(const void *party, Assignments &result, const BotRecord *serverPool = nullptr)
    {
        if (!party || (!serverPool && !Ready(party)))
            return;
        const unsigned size = s_squadSize ? unsigned(s_squadSize->current.integer) : 0;
        const unsigned limit = size == 1 ? 152 : 63;
        unsigned count[152]{};
        bool reserved[152]{};
        const char *value = s_reserved ? s_reserved->current.string : nullptr;
        bool validMask = value != nullptr;
        if (validMask)
        {
            for (unsigned i = 0; i < 50; ++i)
                if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
                {
                    validMask = false;
                    break;
                }
            if (validMask && value[50])
                validMask = false;
        }
        if (validMask)
            for (unsigned i = 0; i < limit; ++i)
            {
                const char digit = value[49 - i / 4];
                const unsigned bits = unsigned(digit <= '9' ? digit - '0' : digit - 'a' + 10);
                reserved[i] = (bits & (1u << (i % 4))) != 0;
            }
        for (unsigned i = 0; i < 200; ++i)
        {
            result.groups[i] = -1;
            const bool human = func_14118E1F0(party, i);
            if (human)
            {
                const auto &member = Member(party, i);
                const int group = size == 1 ? member.team - 1 : member.squad;
                if (group >= 0 && unsigned(group) < limit)
                {
                    ++count[group];
                    if (!validMask)
                        reserved[group] = true;
                }
            }
            else if (serverPool)
            {
                if (serverPool[i].valid)
                    result.bots[i] = &serverPool[i];
            }
            else if (!func_14118E020(party, i) && func_140CA2270(i))
                result.bots[i] = static_cast<const BotRecord *>(func_140CA2230(i));
        }
        if (!size)
            return;
        unsigned group = 0;
        for (unsigned i = 0; i < 200; ++i)
            if (result.bots[i])
            {
                while (group < limit && (reserved[group] || count[group] >= size))
                    ++group;
                if (group == limit)
                    break;
                ++count[group];
                result.groups[i] = int(group);
            }
    }

    int Group(const void *party, unsigned index, const BotRecord *pool)
    {
        Assignments assignments{};
        Calculate(party, assignments, pool);
        return index < 200 ? assignments.groups[index] : -1;
    }

    int Team(const Assignments &assignments, unsigned index)
    {
        return assignments.groups[index] >= 0 ? assignments.groups[index] + 1
                                              : assignments.bots[index]->team;
    }

    int Squad(const Assignments &assignments, unsigned index)
    {
        return s_squadSize && s_squadSize->current.integer > 1 ? assignments.groups[index] : -1;
    }

    const BotRecord *ServerBot(unsigned client, unsigned &index)
    {
        if (!DW_LocalBackend_IsEnabled() || client >= 200 || !func_141359F90(client))
            return nullptr;
        const auto *pool = reinterpret_cast<const BotRecord *>(gl_14E183D00);
        for (index = 0; index < 200; ++index)
            if (pool[index].valid && pool[index].inUse && pool[index].client == client)
                return &pool[index];
        return nullptr;
    }

    void Int(uint16_t parent, const char *key, int value)
    {
        func_141B0E150(func_141B0D390(parent, key), value);
    }

    void Bool(uint16_t parent, const char *key, bool value)
    {
        func_141B0E0B0(func_141B0D390(parent, key), value);
    }

    void Text(uint16_t parent, const char *key, const char *value)
    {
        func_141B0E280(func_141B0D390(parent, key), value);
    }

    uint16_t Row(uint16_t model, unsigned number)
    {
        char text[4]{};
        if (number >= 100)
        {
            text[0] = char('0' + number / 100);
            text[1] = char('0' + number / 10 % 10);
            text[2] = char('0' + number % 10);
        }
        else if (number >= 10)
        {
            text[0] = char('0' + number / 10);
            text[1] = char('0' + number % 10);
        }
        else
            text[0] = char('0' + number);
        return func_141B0D390(model, text);
    }

    void PushBot(const void *party,
                 unsigned index,
                 const BotRecord &bot,
                 uint16_t model,
                 const Assignments &assignments)
    {
        char name[37]{};
        for (unsigned i = 0; i < 36; ++i)
            name[i] = bot.name[i];
        Int(model, "memberIndex", int(index));
        Text(model, "xuid", "0");
        Text(model, "platformId", "0");
        Text(model, "gamertag", name);
        Text(model, "gamertagWithHash", name);
        Text(model, "clanTag", BotClanTag);
        Bool(model, "isBot", true);
        for (const auto *key : {"isLobbyHost",
                                "isPrivatePartyHost",
                                "missingGamertag",
                                "isMyPlayer",
                                "isCrossplayPlayer",
                                "customEmblemEquipped",
                                "isPlaceHolderPlayer"})
            Bool(model, key, false);
        Bool(model, "commitReady", true);
        Bool(model, "usingGamepad", false);
        Int(model, "controllerIndex", -1);
        Int(model, "subparty", -1);
        Int(model, "team", Team(assignments, index));
        Int(model, "squad", Squad(assignments, index));
        Int(model, "desiredTeam", Team(assignments, index));
        Int(model, "rank", bot.rank);
        Int(model, "baseRank", bot.rank);
        for (const auto *key : {"prestige",
                                "microphoneState",
                                "presencePlatform",
                                "emblemIndex",
                                "backgroundIndex",
                                "followersCount"})
            Int(model, key, 0);
        Int(model, "followerIndex", -1);
        // Use the host's real operator/weapon customization through the stock
        // playercard consumer; bot names/XUIDs never enter its identity cache.
        for (unsigned i = 0; i < 200; ++i)
            if (func_14118E0E0(party, i))
            {
                const auto &host = Member(party, i);
                uint8_t selected{};

                struct Appearance
                {
                    int head, body, execution;
                } west{}, east{};

                func_141B97080(host.xuid, host.name, &selected, &west, &east);
                Int(model, "selectedOperatorIndex", selected);
                Int(model, "headWest", west.head);
                Int(model, "bodyWest", west.body);
                Int(model, "execWest", west.execution);
                Int(model, "headEast", east.head);
                Int(model, "bodyEast", east.body);
                Int(model, "execEast", east.execution);
                alignas(16) uint8_t card[45248]{};
                func_141B97230(host.xuid, host.name, card);
                func_141B24690(model, card);
                break;
            }
    }
} // namespace

extern "C" void DW_BotPolicy_Register()
{
    if (s_reserved)
        return;
    DvarValue value{};
    DvarLimits limits{};
    value.string = "";
    s_reserved = Dvar_RegisterVariant("replay_dw_reservedSquads",
                                      Dvar_GenerateChecksum("replay_dw_reservedSquads"),
                                      9,
                                      0,
                                      &value,
                                      &limits,
                                      "DW No Fill squad reservations (200-bit hexadecimal)");
    s_squadSize =
        Dvar_RegisterInt("replay_dw_squadSize", 0, 0, 200, 0, "DW native battle royale squad size");
}

extern "C" void DW_BotPolicy_BuildRoster(const void *party, unsigned capacity, unsigned count)
{
    if (!party || !count || count > 199 || capacity > 200 || count > capacity || !func_140CA2250())
        return;
    // Native selection fills a prefix and does not clear old valid records.
    // Place exactly the requested bots in unused real party indices, including
    // holes left by departing humans, using the complete native 88-byte record.
    static BotRecord selected[200]{};
    for (unsigned i = 0; i < count; ++i)
        selected[i] = *static_cast<const BotRecord *>(func_140CA2230(i));
    for (unsigned i = 0; i < 200; ++i)
        *static_cast<BotRecord *>(func_140CA2210(i)) = {};
    unsigned used = 0;
    for (unsigned i = 0; i < capacity && used < count; ++i)
        if (!func_14118E020(party, i))
            *static_cast<BotRecord *>(func_140CA2210(i)) = selected[used++];
}

extern "C" bool func_14118E2C0(const void *party, unsigned index)
{
    if (!party || index >= 200)
        return false;
    if (Member(party, index).status >= 5 || func_14118EE80(party, index))
        return true;
    return Ready(party) && !func_14118E020(party, index) && func_140CA2270(index);
}

extern "C" unsigned func_14118ADD0(const void *party)
{
    if (!party)
        return 0;
    const auto *bytes = static_cast<const uint8_t *>(party);
    if (!*reinterpret_cast<const int *>(bytes + 311116) ||
        (*reinterpret_cast<const int *>(bytes + 311112) &&
         !*reinterpret_cast<const int *>(bytes + 311020)))
        return 0;
    unsigned count = 0;
    for (unsigned i = 0; i < 200; ++i)
        if (func_14118E2C0(party, i))
            ++count;
    return count;
}

extern "C" void DW_BotPolicy_Prepare(const void *party)
{
    Assignments assignments{};
    Calculate(party, assignments);
    unsigned axis = 0, allies = 0;
    for (unsigned i = 0; i < 200; ++i)
        if (func_14118E1F0(party, i))
        {
            if (Member(party, i).team == 1)
                ++axis;
            if (Member(party, i).team == 2)
                ++allies;
        }
    for (unsigned i = 0; i < 200; ++i)
        if (assignments.bots[i])
        {
            auto *bot = static_cast<BotRecord *>(func_140CA2210(i));
            for (unsigned character = 0; character < sizeof(bot->clan); ++character)
                bot->clan[character] = character < sizeof(BotClanTag) ? BotClanTag[character] : 0;
            if (s_squadSize && s_squadSize->current.integer > 0)
                bot->team = uint8_t(Team(assignments, i));
            else if (gl_14C796328->current.integer == 2)
            {
                bot->team = allies <= axis ? 2 : 1;
                if (bot->team == 2)
                    ++allies;
                else
                    ++axis;
            }
        }
}

// BR scripts request bots through the stock spawn quotas. Select from the
// native pool, then ClientBegin applies the explicit BR group instead of
// restricting available bot records to axis/allies.
extern "C" int func_14132ED80(unsigned requestedTeam)
{
    auto *pool = reinterpret_cast<BotRecord *>(gl_14E183D00);
    const bool br = DW_LocalBackend_IsEnabled() && s_squadSize && s_squadSize->current.integer > 0;
    int selected = -1;
    for (unsigned i = 0; i < 200; ++i)
        if ((br || pool[i].team == requestedTeam) && !pool[i].inUse && pool[i].valid &&
            !func_14118E1F0(func_141187EE0(), i))
        {
            pool[i].inUse = 1;
            selected = int(i);
            break;
        }
    Com_Printf(131087,
               "SV_AssignBotDataToTeam: Assigning bot data for index %d for team %d\n",
               selected,
               requestedTeam);
    return selected;
}

// Complete native ClientBegin getters. Bots receive their pool assignment
// before GSC begins; human, non-DW and non-BR behavior remains native.
extern "C" int func_1413707D0(unsigned client)
{
    unsigned index = 0;
    if (ServerBot(client, index) && s_squadSize && s_squadSize->current.integer > 0)
        return s_squadSize->current.integer == 1
                   ? -1
                   : Group(func_14137D670(),
                           index,
                           reinterpret_cast<const BotRecord *>(gl_14E183D00));
    if (!func_141371450(client))
        return 0;
    auto *party = func_14137D670();
    uint64_t xuid{};
    func_14118CF60(&xuid, party, client);
    if (xuid)
        return func_14118C070(party, xuid);
    func_1412B0570(15,
                   "SV_GetAssignedSquad Error: unknown xuid (%s) for client (%i).\n",
                   func_14107EA60(&xuid),
                   client);
    return -1;
}

extern "C" int func_141370860(unsigned client)
{
    unsigned index = 0;
    if (const auto *bot = ServerBot(client, index);
        bot && s_squadSize && s_squadSize->current.integer > 0)
    {
        const int group =
            Group(func_14137D670(), index, reinterpret_cast<const BotRecord *>(gl_14E183D00));
        return group >= 0 ? group + 1 : bot->team;
    }
    if (!func_141371450(client))
        return 0;
    auto *party = func_14137D670();
    uint64_t xuid{};
    func_14118CF60(&xuid, party, client);
    if (xuid)
        return func_14118C110(party, xuid);
    func_1412B0570(15,
                   "SV_GetAssignedTeam Error: unknown xuid (%s) for client (%i).\n",
                   func_14107EA60(&xuid),
                   client);
    return 0;
}

// Complete stock party-to-model sequence, adding the native pool at the same
// model root and leaving the human binding untouched. No party records, XUIDs,
// session identities or backend members are fabricated for display.
extern "C" void func_141B21D50(const void *party, uint16_t model)
{
    if (!party || !*reinterpret_cast<const int *>(static_cast<const uint8_t *>(party) + 311116) ||
        (!gl_14EEF12A4[0] && gl_14EEF1288[0] >= 3))
        return;
    int sorted[200]{}, teamCounts[156]{}, subparty = 0, friendlyTeam = 0, friendlySquad = 0;
    func_141B23610(party, sorted);
    const int limit = gl_14D386988->current.enabled ? gl_14D386990->current.integer : 28;
    for (int slot : sorted)
        if (slot >= 0 && slot < 200 && func_14118E0E0(party, unsigned(slot)))
        {
            const auto &member = Member(party, unsigned(slot));
            subparty = member.subparty;
            friendlyTeam = member.team;
            friendlySquad = member.squad;
            break;
        }
    Int(model, "friendlySubPartyIndex", subparty);
    Assignments assignments{};
    Calculate(party, assignments);
    unsigned shown = 0, count = 0, all = 0;
    const bool gameBattlesFeature = func_141528240(), gameBattlesActive = func_140F22880();
    if (gameBattlesFeature && gameBattlesActive)
        func_140F23A00(party, model, sorted, teamCounts);
    else
    {
        for (int ordinal = 0; ordinal < limit && ordinal < 200; ++ordinal)
        {
            const int slot = sorted[ordinal];
            if (slot < 0 || slot >= 200 || assignments.bots[slot] ||
                !func_14118E2C0(party, unsigned(slot)))
                continue;
            const auto &member = Member(party, unsigned(slot));
            func_141B22140(party, unsigned(slot), Row(model, shown++), ordinal);
            if (member.team >= 0 && member.team < 156)
                ++teamCounts[member.team];
            if (!member.follower)
                ++count;
        }
        for (unsigned i = 0; i < 200; ++i)
            if (const auto *bot = assignments.bots[i])
            {
                ++all;
                if (int(shown) < limit && shown < 200)
                {
                    PushBot(party, i, *bot, Row(model, shown++), assignments);
                    const int team = Team(assignments, i);
                    if (team >= 0 && team < 156)
                        ++teamCounts[team];
                    ++count;
                }
            }
    }
    for (int slot : sorted)
        if (slot >= 0 && slot < 200 && !assignments.bots[slot] &&
            func_14118E2C0(party, unsigned(slot)))
            ++all;
    Int(model,
        "friendlyTeamCount",
        friendlyTeam >= 0 && friendlyTeam < 156 ? teamCounts[friendlyTeam] : 0);
    Int(model, "teamAlliesCount", teamCounts[2]);
    Int(model, "teamAxisCount", teamCounts[1]);
    Int(model, "teamSpectatorCount", teamCounts[153]);
    Int(model, "teamFollowerCount", teamCounts[154]);
    Bool(model, "isDedi", func_14118DDB0(g_partyData));
    Int(model, "count", int(count));
    Int(model, "memberCount", int(all));
    Int(model, "maxCount", int(func_14118C7D0(party)));
    Int(model, "friendlyTeamIndex", friendlyTeam);
    Int(model, "friendlySquadIndex", friendlySquad);
}

extern "C" void func_141B22B40(const void *party, uint16_t model)
{
    if (!party || !*reinterpret_cast<const int *>(static_cast<const uint8_t *>(party) + 311116) ||
        (!gl_14EEF12A4[0] && gl_14EEF1288[0] >= 3))
        return;
    const auto global = func_141B0D520();
    const int squad = func_141B0D530(
        func_141B0D710(global, "alwaysLoaded.activeParty.members.friendlySquadIndex"));
    const int team = func_141B0D530(
        func_141B0D710(global, "alwaysLoaded.activeParty.members.friendlyTeamIndex"));
    const bool teams = func_141192AC0(party), squads = func_141192AA0(party);
    int sorted[200]{};
    func_141B23610(party, sorted);
    const int limit = gl_14D386988->current.enabled ? gl_14D386990->current.integer : 28;
    Assignments assignments{};
    Calculate(party, assignments);
    unsigned shown = 0, count = 0, all = 0;
    for (int ordinal = 0; ordinal < limit && ordinal < 200; ++ordinal)
    {
        const int slot = sorted[ordinal];
        if (slot < 0 || slot >= 200 || assignments.bots[slot] ||
            !func_14118E2C0(party, unsigned(slot)))
            continue;
        const auto &member = Member(party, unsigned(slot));
        if (func_14118E0E0(party, unsigned(slot)) ||
            ((!teams || (team != 0 && member.team == team)) &&
             (!squads || (squad != -1 && member.squad == squad))))
        {
            func_141B22140(party, unsigned(slot), Row(model, shown++), ordinal);
            if (!member.follower)
                ++count;
        }
    }
    for (unsigned i = 0; i < 200; ++i)
        if (const auto *bot = assignments.bots[i])
        {
            ++all;
            if (int(shown) < limit && shown < 200 &&
                (!teams || (team != 0 && Team(assignments, i) == team)) &&
                (!squads || (squad != -1 && Squad(assignments, i) == squad)))
            {
                PushBot(party, i, *bot, Row(model, shown++), assignments);
                ++count;
            }
        }
    for (int slot : sorted)
        if (slot >= 0 && slot < 200 && !assignments.bots[slot] &&
            func_14118E2C0(party, unsigned(slot)))
            ++all;
    Int(model, "count", int(count));
    Int(model, "memberCount", int(all));
}
