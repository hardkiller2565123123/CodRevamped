#include "BlockListService.h"
#include "../BgsDispatcher.h"
#include "../../Log.h"

namespace revamped::iw8::bgs
{
    bool HandleBlockListService(RequestContext& context)
    {
        if (context.rpc.header.methodId == 1u)
        {
            // BlockListService.Subscribe -> SubscribeResponse { state: BlockListState }.
            // An empty state is a valid local account with no blocked players.
            std::vector<Byte> state;
            std::vector<Byte> response;
            AppendBytesField(response, 1u, state);
            QueueResponse(context, response, "BlockListService.Subscribe response");
            log::Print("[BGS-BLOCKLIST] id=%llu Subscribe token=%u -> empty BlockListState",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token);
            MarkHandled(context, "BlockList Subscribe returned empty local state");
            return true;
        }

        MarkMissing(context, "BlockListService method not implemented");
        return true;
    }
}
