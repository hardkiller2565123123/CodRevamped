#include "ConnectionService.h"
#include "../BgsDispatcher.h"
#include "Common/Logging/Log.h"

namespace revamped::iw8::bgs
{
    bool HandleConnectionService(RequestContext& context)
    {
        const auto method = context.rpc.header.methodId;
        if (method == 1u)
        {
            std::uint64_t bindless = 1;
            const bool hasBindless = TryGetVarintField(context.rpc.body.data(), context.rpc.body.size(), 3u, bindless);
            const bool useBindless = !hasBindless || bindless != 0;
            const std::uint64_t serverTime = UnixTimeMilliseconds();
            const std::uint32_t serverEpoch = static_cast<std::uint32_t>(serverTime / 1000ull);

            std::vector<Byte> processId;
            AppendVarintField(processId, 1, 1u);
            AppendVarintField(processId, 2, serverEpoch);

            std::vector<Byte> response;
            AppendBytesField(response, 1, processId);
            AppendVarintField(response, 6, serverTime);
            AppendVarintField(response, 7, useBindless ? 1u : 0u);
            QueueResponse(context, response, "ConnectionService.ConnectResponse");

            log::Print("[BGS-CONNECTION] id=%llu Connect token=%u useBindlessRpc=%s serverTime=%llu",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                useBindless ? "true" : "false", static_cast<unsigned long long>(serverTime));
            MarkHandled(context, "ConnectResponse queued");
            return true;
        }

        if (method == 5u)
        {
            log::Print("[BGS-CONNECTION] id=%llu KeepAlive token=%u; notification acknowledged without response",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token);
            MarkHandled(context, "KeepAlive notification");
            return true;
        }

        // Battle.net ConnectionService.RequestDisconnect.  The stock client sends
        // this while tearing down an otherwise valid BGS session.  It is a semantic
        // notification/cleanup path, not an auth-success shortcut, so acknowledge
        // it without inventing a payload or changing any client state.
        if (method == 7u)
        {
            std::uint64_t reason = 0;
            const bool hasReason = TryGetVarintField(context.rpc.body.data(), context.rpc.body.size(), 1u, reason);
            log::Print("[BGS-CONNECTION] id=%llu RequestDisconnect token=%u reason=%s%llu; graceful teardown acknowledged without response",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                hasReason ? "" : "<missing>/", static_cast<unsigned long long>(hasReason ? reason : 0u));
            MarkHandled(context, "RequestDisconnect notification");
            return true;
        }

        MarkMissing(context, "ConnectionService method not implemented");
        return true;
    }
}
