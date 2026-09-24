#include "PresenceService.h"
#include "../BgsDispatcher.h"
#include "Common/Logging/Log.h"

namespace revamped::iw8::bgs
{
    bool HandlePresenceService(RequestContext& context)
    {
        const auto method = context.rpc.header.methodId;
        const std::vector<Byte> empty;

        switch (method)
        {
        case 1u: // Subscribe -> NoData / empty success in this local no-presence backend
            QueueResponse(context, empty, "PresenceService.Subscribe response");
            MarkHandled(context, "Subscribe acknowledged; no remote presence entries");
            return true;
        case 2u: // Unsubscribe
            QueueResponse(context, empty, "PresenceService.Unsubscribe response");
            MarkHandled(context, "Unsubscribe acknowledged");
            return true;
        case 3u: // Update
            QueueResponse(context, empty, "PresenceService.Update response");
            MarkHandled(context, "Update acknowledged");
            return true;
        case 4u: // Query -> QueryResponse { repeated field = empty }
            QueueResponse(context, empty, "PresenceService.Query empty response");
            MarkHandled(context, "Query returned zero presence fields");
            return true;
        case 5u: // BatchSubscribe -> empty repeated results
            QueueResponse(context, empty, "PresenceService.BatchSubscribe empty response");
            MarkHandled(context, "BatchSubscribe returned zero remote entries");
            return true;
        case 6u: // legacy/older SDK BatchUnsubscribe mapping
            QueueResponse(context, empty, "PresenceService.BatchUnsubscribe response");
            MarkHandled(context, "BatchUnsubscribe acknowledged");
            return true;
        case 8u:
            // IW8 2.02.0 sends method 8 with BatchSubscribeRequest:
            // field 2 entity_id + repeated field 4 FieldKey.  An empty
            // BatchSubscribeResponse means none of the subscriptions failed.
            QueueResponse(context, empty, "PresenceService.BatchSubscribe empty-success response");
            log::Print("[BGS-PRESENCE] id=%llu BatchSubscribe token=%u bodyBytes=%llu -> subscribe_failed=0",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                static_cast<unsigned long long>(context.rpc.body.size()));
            MarkHandled(context, "BatchSubscribe accepted with zero failed subscriptions");
            return true;
        default:
            log::Print("[BGS-PRESENCE] id=%llu unknown method=%u token=%u",
                static_cast<unsigned long long>(context.connectionId), method, context.rpc.header.token);
            MarkMissing(context, "PresenceService method not implemented");
            return true;
        }
    }
}
