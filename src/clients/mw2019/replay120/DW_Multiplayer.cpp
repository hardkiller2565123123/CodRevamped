#include <stdint.h>

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    uint64_t func_140F5C390(void *manager, unsigned controller, const uint64_t *xuids, int count);
    void *func_140F3BB20(void *manager,
                       unsigned controller,
                       uint64_t chatId,
                       uint64_t member,
                       const char *name,
                       bool initiated);
    unsigned func_141370C40(unsigned client);
    void Com_Printf(int channel, const char *format, ...);
}

// Replay SendInvitation divides recipients between the launcher SDK and DW.
// This provider has DW identities, without a Battle.net invitation transport.
// Keep the native DW serializer, remote task, completion and recent-invite list.
extern "C" uint64_t func_140F5C750(void *manager,
                                  unsigned controller,
                                  const uint64_t *xuids,
                                  const uint64_t *,
                                  int count)
{
    if (!DW_LocalBackend_IsEnabled() || !manager || !xuids || controller >= 8 || count <= 0)
        return 0;
    if (count > 16)
        count = 16;
    Com_Printf(25, "[DW] Routing %d party invitation(s) through native DW messaging\n", count);
    return func_140F5C390(manager, controller, xuids, count);
}

// The shared native constructor owns chat lifetime, members, notifications and
// history. Keep its XUID/chat ID; do not change the chat into a launcher whisper.
extern "C" void func_140F3BA70(void *manager,
                              unsigned controller,
                              uint64_t xuid,
                              const char *name,
                              bool initiated)
{
    if (!DW_LocalBackend_IsEnabled() || !manager || controller >= 8 || !xuid || !name)
        return;
    func_140F3BB20(manager, controller, xuid, xuid, name, initiated);
}

// Original SV_ClientMP_GetLocalClientPing reports the minimum remote ping for
// the listen host. Scoreboard consumers should use this client's own ACK RTT,
// just as they already do for every remote client. RTT collection stays native.
extern "C" __attribute__((disable_tail_calls)) unsigned func_1413711C0(unsigned client)
{
    return func_141370C40(client);
}
