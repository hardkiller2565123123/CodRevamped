#include "RecentPlayersService.h"
#include "../BgsDispatcher.h"
#include "Common/Logging/Log.h"

namespace revamped::iw8::bgs
{
    bool HandleRecentPlayersService(RequestContext& context)
    {
        if (context.rpc.header.methodId == 1u)
        {
            // RecentPlayersService.Subscribe -> SubscribeResponse { state: RecentPlayersState }.
            std::vector<Byte> state;
            std::vector<Byte> response;
            AppendBytesField(response, 1u, state);
            QueueResponse(context, response, "RecentPlayersService.Subscribe response");
            log::Print("[BGS-RECENT] id=%llu Subscribe token=%u -> empty RecentPlayersState",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token);
            MarkHandled(context, "RecentPlayers Subscribe returned empty local state");
            return true;
        }

        MarkMissing(context, "RecentPlayersService method not implemented");
        return true;
    }
}
