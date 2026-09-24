#include "ResourcesService.h"
#include "../BgsDispatcher.h"
#include "Common/Logging/Log.h"

#include <array>

namespace revamped::iw8::bgs
{
    namespace
    {
        std::vector<Byte> LocalContentHash(std::uint32_t program, std::uint32_t stream, std::uint32_t version)
        {
            // ContentHandle.hash is an opaque cache/content identifier.  Keep it
            // deterministic for a given request instead of inventing a remote URL.
            std::array<std::uint32_t, 8> words = {
                program, stream, version, 0x52564D50u,
                program ^ 0xA5A5A5A5u, stream ^ 0x5A5A5A5Au,
                version ^ 0x49573831u, 0x4C4F434Cu
            };
            std::vector<Byte> out;
            out.reserve(32);
            for (const auto word : words)
            {
                out.push_back(static_cast<Byte>(word & 0xFFu));
                out.push_back(static_cast<Byte>((word >> 8) & 0xFFu));
                out.push_back(static_cast<Byte>((word >> 16) & 0xFFu));
                out.push_back(static_cast<Byte>((word >> 24) & 0xFFu));
            }
            return out;
        }
    }

    bool HandleResourcesService(RequestContext& context)
    {
        if (context.rpc.header.methodId == 1u)
        {
            std::uint32_t program = 0;
            std::uint32_t stream = 0;
            std::uint32_t version = 1701729619u;
            const bool hasProgram = TryGetFixed32Field(context.rpc.body.data(), context.rpc.body.size(), 1u, program);
            const bool hasStream = TryGetFixed32Field(context.rpc.body.data(), context.rpc.body.size(), 2u, stream);
            const bool hasVersion = TryGetFixed32Field(context.rpc.body.data(), context.rpc.body.size(), 3u, version);

            // bgs.protocol.ContentHandle:
            //   required fixed32 region = 1
            //   required fixed32 usage  = 2
            //   required bytes   hash   = 3
            //   optional string  proto_url = 4
            // Do not advertise a fake remote URL.  The local handle is enough to
            // let the stock client decide whether it already has/can skip content.
            const auto hash = LocalContentHash(program, stream, version);
            std::vector<Byte> response;
            AppendFixed32Field(response, 1u, 1u); // local/default region
            AppendFixed32Field(response, 2u, stream);
            AppendBytesField(response, 3u, hash);
            QueueResponse(context, response, "ResourcesService.GetContentHandle response");

            log::Print("[BGS-RESOURCES] id=%llu GetContentHandle token=%u program=%s0x%08X stream=%s0x%08X version=%s0x%08X hashBytes=%llu protoUrl=omitted-local",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                hasProgram ? "" : "<missing>/", program,
                hasStream ? "" : "<missing>/", stream,
                hasVersion ? "" : "<default>/", version,
                static_cast<unsigned long long>(hash.size()));
            MarkHandled(context, "local deterministic ContentHandle queued");
            return true;
        }

        MarkMissing(context, "ResourcesService method not implemented");
        return true;
    }
}
