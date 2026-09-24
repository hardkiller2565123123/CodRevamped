#include "ChannelMembershipService.h"
#include "../BgsDispatcher.h"
#include "Common/Logging/Log.h"

namespace revamped::iw8::bgs
{
    bool HandleChannelMembershipService(RequestContext& context)
    {
        if (context.rpc.header.methodId == 1u)
        {
            // ChannelMembershipService.Subscribe -> SubscribeResponse { state }.
            // The request's field 1 is the local GameAccountHandle.  No channels
            // or invitations exist in the preservation backend yet.
            std::vector<Byte> agent;
            const bool hasAgent = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 1u, agent);

            std::vector<Byte> state;
            std::vector<Byte> response;
            AppendBytesField(response, 1u, state);
            QueueResponse(context, response, "ChannelMembershipService.Subscribe response");
            log::Print("[BGS-CHANNEL-MEMBERSHIP] id=%llu Subscribe token=%u agentBytes=%s%llu -> empty state",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                hasAgent ? "" : "<missing>/", static_cast<unsigned long long>(agent.size()));
            MarkHandled(context, "ChannelMembership Subscribe returned no channels/invitations");
            return true;
        }

        MarkMissing(context, "ChannelMembershipService method not implemented");
        return true;
    }
}
