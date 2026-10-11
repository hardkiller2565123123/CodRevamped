// DW-only, link-time source integration. All RVAs below are original Replay
// 1.20 identities, relocated by the recompiler (not addresses in the output).
#include "com_debugstates.h"

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    void DW_LobbyControls_HostDocument(uint64_t, void *, const char **, unsigned *);
    bool replay_rva_012b0290();                                   // Com_IsGameLocalServerRunning
    void replay_rva_0132d750();                                   // SV_WaitServer
    bool replay_rva_0137f020();                                   // SV_IsMigrating
    bool replay_rva_0137f380();                                   // SV_MigrationLimitReached
    int replay_rva_01376100();                                    // SV_CountRealClients
    bool replay_rva_01359f90(int);                                // SV_BotIsBot
    bool replay_rva_013717b0(int);                                // SV_ClientMP_IsLocalClient
    void replay_rva_0137f4c0(const char *, int);                  // SV_MigrationStart
    unsigned char *replay_rva_01187ee0();                         // Lobby_GetPartyData
    const char *replay_rva_0118c6b0(const void *, int);           // Party_GetMemberName
    uint64_t *replay_rva_0118cf60(uint64_t *, const void *, int); // Party_GetXuid, sret
    int replay_rva_012b9380(void *);                              // MSG_ReadLong
    unsigned replay_rva_0148fce0();                               // Sys_Milliseconds
    void *replay_rva_00f6eb20(void *); // DWLobbyService::getAsyncMatchmaking
    void **replay_rva_021367b0(void *, void **, uint64_t, void *, uint64_t, const char *, unsigned);
    void replay_rva_0104ba20(void *, void *, int); // TaskUpdateLobbyDocument
    extern unsigned char *replay_rva_0e17f690[];   // SvClient pointers
    extern int replay_rva_0e17fcd0;                // SvClient::ms_clientCount
    extern int replay_rva_0e19affc;                // migGlob.migrationCount
    extern unsigned char replay_rva_0c27e4b0[];    // OnlineMatchmakerOmniscient::ms_instance
    extern int replay_rva_0d216da8;                // Cbuf_AddCall queue count
    extern void (*replay_rva_0d216db0[])();        // Cbuf_AddCall queue
}

// Entire Replay migration-client record, verified against Start, HandleRatingMsg
// and CheckTimeouts. Do not substitute the SvClient or a later-build layout.
struct ReplayMigrationClient
{
    int state; // 0 inactive, 1 waiting for rating, 2 migrating
    int attempts;
    int timeout;
    int rating;
    int unreachable;
    int startTime;
    bool timedOut;
    unsigned char padding[3];
};

static_assert(sizeof(ReplayMigrationClient) == 28);
static_assert(offsetof(ReplayMigrationClient, rating) == 12);
static_assert(offsetof(ReplayMigrationClient, timedOut) == 24);
extern "C" ReplayMigrationClient replay_rva_0e199884[200];

namespace
{
    cmd_function_s s_command{};
    bool s_registered = false;
    enum class Phase
    {
        Idle,
        Authorizing,
        Submitted,
        Ready,
        Queued,
        Migrating
    };
    // Publish the selected generation to the server's rating handler. Target
    // fields change only after SV_WaitServer; the task and queue run on main.
    struct PhaseState
    {
        uint32_t value;
        operator Phase() const
        {
            return static_cast<Phase>(__atomic_load_n(&value, __ATOMIC_SEQ_CST));
        }
        void operator=(Phase phase)
        {
            __atomic_store_n(&value, static_cast<uint32_t>(phase), __ATOMIC_SEQ_CST);
        }
    };
    static_assert(sizeof(PhaseState) == 4 && __atomic_always_lock_free(4, nullptr));
    PhaseState s_phase{static_cast<uint32_t>(Phase::Idle)};
    int s_client = -1, s_generation = -1;
    uint64_t s_xuid = 0, s_lobby = 0;
    unsigned s_started = 0;
    void *s_task = nullptr; // identity only; native TaskManager owns its reference
    char s_document[16384];

    template <class T> T &MM(size_t offset)
    {
        return *reinterpret_cast<T *>(replay_rva_0c27e4b0 + offset);
    }

    bool SameName(const char *left, const char *right)
    {
        // Exact full name, ASCII case-insensitive; quoted names may contain spaces.
        for (;;)
        {
            unsigned char a = *left++, b = *right++;
            if (a >= 'A' && a <= 'Z')
                a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z')
                b += 'a' - 'A';
            if (a != b)
                return false;
            if (!a)
                return true;
        }
    }

    bool TargetPresent()
    {
        if (s_client < 0 || s_client >= replay_rva_0e17fcd0 || s_client >= 200)
            return false;
        auto *client = replay_rva_0e17f690[s_client];
        if (!client || client[8] != 5 || replay_rva_01359f90(s_client) ||
            replay_rva_013717b0(s_client))
            return false;
        uint64_t xuid = 0;
        replay_rva_0118cf60(&xuid, replay_rva_01187ee0(), s_client);
        return xuid == s_xuid;
    }

    void Cancel(const char *why)
    {
        Com_Printf(25, "migrate_host: %s\n", why);
        s_phase = Phase::Idle;
        s_task = nullptr;
    }

    void Start()
    {
        if (s_phase != Phase::Queued)
            return;
        replay_rva_0132d750();
        if (!replay_rva_012b0290() || replay_rva_0137f020() || replay_rva_0137f380() ||
            replay_rva_01376100() <= 1 || MM<uint64_t>(79656) != s_lobby || MM<int>(4) != 6 ||
            !MM<bool>(80128) || !TargetPresent() ||
            unsigned(replay_rva_0148fce0() - s_started) > 15000)
        {
            Cancel("match or target changed before handoff; migration not started.");
            return;
        }
        s_generation = replay_rva_0e19affc + 1;
        s_phase = Phase::Migrating;
        Com_Printf(25,
                   "migrate_host: transferring to %s; the current host stays in the match.\n",
                   replay_rva_0118c6b0(replay_rva_01187ee0(), s_client));
        // Bit 0 marks the local clients PLAYERKICKED in the migration save and sets
        // stopAfterRound. Zero is the native migrate-and-remain path, regardless of
        // the migration default dvar. Never use UI_MakeHost (private-party only).
        replay_rva_0137f4c0(nullptr, 0);
    }

    void MigrateHost_f()
    {
        if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread())
            return;
        if (Cmd_Argc() != 2 || !*Cmd_Argv(1))
        {
            Com_Printf(25, "Usage: migrate_host <playername> (quote names containing spaces)\n");
            return;
        }
        if (s_phase != Phase::Idle)
        {
            Com_Printf(25, "migrate_host: a handoff is already pending.\n");
            return;
        }
        replay_rva_0132d750();
        if (!replay_rva_012b0290() || Com_GameMode_GetActiveGameMode() != 2)
        {
            Cancel("run this on the current host during a multiplayer match.");
            return;
        }
        if (replay_rva_0137f020() || replay_rva_0137f380() || replay_rva_01376100() <= 1)
        {
            Cancel("migration is active, at its limit, or has no remote player.");
            return;
        }
        if (replay_rva_0e17fcd0 < 1 || replay_rva_0e17fcd0 > 200)
            return;
        auto *party = replay_rva_01187ee0();
        int found = -1;
        for (int i = 0; i < replay_rva_0e17fcd0; ++i)
        {
            auto *client = replay_rva_0e17f690[i];
            if (!client || client[8] != 5 || !SameName(Cmd_Argv(1), replay_rva_0118c6b0(party, i)))
                continue;
            if (found != -1)
            {
                Cancel("more than one player has that name.");
                return;
            }
            found = i;
        }
        s_client = found;
        if (found < 0)
        {
            Cancel("no active player has that exact name.");
            return;
        }
        replay_rva_0118cf60(&s_xuid, party, found);
        if (!s_xuid || !TargetPresent())
        {
            Cancel("target must be a remote human player.");
            return;
        }
        s_lobby = MM<uint64_t>(79656);
        // These are the exact UpdateHostDoc eligibility fields in Replay, not a
        // newer Matchmaker layout. Wait for a stable, locally owned lobby first.
        if (!s_lobby || MM<int>(0) != 7 || MM<int>(4) != 6 || !MM<bool>(80128))
        {
            Cancel("DW lobby is not ready for an authenticated host handoff.");
            return;
        }
        s_started = replay_rva_0148fce0();
        s_phase = Phase::Authorizing;
        MM<bool>(79636) = true;  // hostDocDirty
        MM<unsigned>(79640) = 0; // next dirty host-document update
        Com_Printf(
            25, "migrate_host: authorizing handoff to %s.\n", replay_rva_0118c6b0(party, found));
    }
} // namespace

extern "C" void DW_HostMigration_Frame()
{
    if (!s_registered)
    {
        Cmd_AddCommandInternal("migrate_host", MigrateHost_f, &s_command);
        s_registered = true;
    }
    if (s_phase == Phase::Idle)
        return;
    if (s_phase == Phase::Migrating)
    {
        if (!replay_rva_0137f020())
            Cancel("native migration finished; see migration messages for its result.");
        return;
    }
    if (unsigned(replay_rva_0148fce0() - s_started) > 15000)
    {
        Cancel("handoff authorization timed out; migration not started.");
        return;
    }
    if (s_phase != Phase::Ready)
        return;
    // Use the same deferred Cbuf callback queue as SV_MigrationStartCall; never
    // serialize a live server from the network task-completion callback.
    Sys_EnterCriticalSection(35);
    if (unsigned(replay_rva_0d216da8) < 32)
    {
        replay_rva_0d216db0[replay_rva_0d216da8++] = Start;
        s_phase = Phase::Queued;
    }
    Sys_LeaveCriticalSection(35);
}

// Replay DW wrapper for bdAsyncMatchMaking::syncLobbyDocuments (145/15).
// Its old database alias is submitPerformance. Preserve the native request and
// ownership; extend only the command's pending, owner-authenticated document.
extern "C" void **func_140F77B40(unsigned char *self,
                                 void **task,
                                 uint64_t lobby,
                                 void *result,
                                 const char *document,
                                 unsigned length,
                                 uint64_t revision)
{
    *task = nullptr;
    using Ready = bool (*)(void *);
    auto **vtable = *reinterpret_cast<void ***>(self);
    if (!reinterpret_cast<Ready>(vtable[0])(self))
        return task;
    auto *service = *reinterpret_cast<unsigned char **>(self + 8);
    if (!service)
        return task;
    void *async = replay_rva_00f6eb20(service + 904);
    if (!async)
        return task;
    const bool handoff =
        s_phase == Phase::Authorizing && lobby == s_lobby && result == replay_rva_0c27e4b0 + 131864;
    if (handoff)
    {
        if (length < 3 || length > sizeof(s_document) - 96 || document[length - 1] != 0 ||
            document[length - 2] != '}')
        {
            Cancel("host document has no room for handoff; migration not started.");
        }
        else
        {
            for (unsigned i = 0; i < length - 2; ++i)
                s_document[i] = document[i];
            const int added = Com_sprintf(s_document + length - 2,
                                          sizeof(s_document) - (length - 2),
                                          ",\"dw_migration_target\":%llu}",
                                          s_xuid);
            if (added > 0)
            {
                document = s_document;
                length = length - 2 + unsigned(added) + 1;
                s_phase = Phase::Submitted;
            }
            else
                Cancel("could not serialize handoff; migration not started.");
        }
    }
    DW_LobbyControls_HostDocument(lobby, result, &document, &length);
    // Native lower function constructs the single owning bdReference directly
    // into the caller's empty output, avoiding the wrapper's temporary add/release.
    replay_rva_021367b0(async, task, lobby, result, revision, document, length);
    if (handoff && s_phase == Phase::Submitted)
    {
        s_task = *task;
        if (!s_task)
            Cancel("DW could not submit the handoff; migration not started.");
    }
    return task;
}

// Native task callback trampoline, retaining TaskUpdateLobbyDocument in full.
extern "C" void func_14104EC50(unsigned char *task, int status)
{
    auto *matchmaker = *reinterpret_cast<unsigned char **>(task + 56);
    const bool ours = s_phase == Phase::Submitted &&
                      *reinterpret_cast<void **>(task + 32) == s_task &&
                      matchmaker == replay_rva_0c27e4b0 && MM<uint64_t>(79656) == s_lobby;
    const bool accepted = ours && status == 0 && MM<int>(4) == 5 && MM<bool>(131896);
    if (matchmaker)
        replay_rva_0104ba20(matchmaker, task, status);
    if (!ours)
        return;
    s_task = nullptr;
    if (accepted)
        s_phase = Phase::Ready;
    else
        Cancel("DW rejected/conflicted the handoff; migration not started. Retry when stable.");
}

// Native HandleRatingMsg, preserving connectivity penalties and the complete
// native picker/save/header/ack/reconnect state machine. Only non-target ratings
// become zero during this command's migration generation. Never inflate the
// requested player's capability or bypass native crossplay/timeout checks.
extern "C" void func_14137EB80(int clientNum, void *message)
{
    if (clientNum < 0 || clientNum >= replay_rva_0e17fcd0 || clientNum >= 200)
        return;
    auto &client = replay_rva_0e199884[clientNum];
    if (client.state != 1)
    {
        Com_Printf(25, "Got stray mrate msg from client %i\n", clientNum);
        return;
    }
    client.state = 2;
    client.rating = replay_rva_012b9380(message);
    client.unreachable = 0;
    const unsigned connectivity = unsigned(replay_rva_012b9380(message));
    Com_Printf(25,
               "HandleRatingMsg - client %i (%s): rating %i, connectivity 0x%x.\n",
               clientNum,
               replay_rva_0118c6b0(replay_rva_01187ee0(), clientNum),
               client.rating,
               connectivity);
    if (connectivity != ~0u)
    {
        for (int i = 0; i < replay_rva_0e17fcd0 && i < 200; ++i)
        {
            if (replay_rva_0e199884[i].state && !(connectivity & (1u << (i & 31))) &&
                replay_rva_0e17f690[i][8] >= 5)
                ++client.unreachable;
        }
    }
    if (s_phase == Phase::Migrating && s_generation == replay_rva_0e19affc &&
        (clientNum != s_client || !TargetPresent()))
        client.rating = 0;
}
