#include "ResourcesService.h"
#include "../BgsDispatcher.h"
#include "Common/Logging/Log.h"

#include <array>

namespace revamped::iw8::bgs
{
    namespace
    {
        constexpr std::uint32_t kBnetProgram = 0x0000424Eu; // "BN"
        constexpr std::uint32_t kApftStream = 0x61706674u;  // "apft" request
        constexpr std::uint32_t kUsRegion = 0x00005553u;    // "US"
        constexpr std::uint32_t kProfanityUsage = 0x70667479u; // "pfty"

        // Battle.net's shared profanity-filter resource is identified by the
        // BNet ContentHandle, not by echoing the request stream/version. This
        // 32-byte handle is used by open BGS implementations for the BNet
        // profanity resource and matches the stock handle shape: region=US,
        // usage=pfty, hash=<32 bytes>, proto_url optional/omitted.
        constexpr std::array<Byte, 32> kBnetProfanityHash = {
            0x06, 0xCD, 0x1B, 0x9A, 0x6E, 0xC5, 0x80, 0xE4,
            0xCF, 0xF7, 0xB0, 0x42, 0xA0, 0x53, 0x19, 0x07,
            0x59, 0xC3, 0xA1, 0x45, 0x4B, 0xC7, 0x9D, 0xBB,
            0x6D, 0x3E, 0xFF, 0x2C, 0xB4, 0x16, 0x8B, 0x61
        };

        std::vector<Byte> LocalContentHash(std::uint32_t program, std::uint32_t stream, std::uint32_t version)
        {
            // Unknown resource types retain the old deterministic local handle
            // until their native content contract is understood.
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
            std::vector<Byte> response;

            const bool bnetProfanity =
                hasProgram && hasStream &&
                program == kBnetProgram && stream == kApftStream;
            if (bnetProfanity)
            {
                const std::vector<Byte> hash(
                    kBnetProfanityHash.begin(), kBnetProfanityHash.end());
                AppendFixed32Field(response, 1u, kUsRegion);
                AppendFixed32Field(response, 2u, kProfanityUsage);
                AppendBytesField(response, 3u, hash);
                QueueResponse(context, response, "ResourcesService.GetContentHandle BNet profanity response");

                log::Print(
                    "[BGS-RESOURCES] id=%llu GetContentHandle token=%u program=0x%08X stream=0x%08X version=%s0x%08X region=0x%08X usage=0x%08X hashBytes=32 protoUrl=omitted-bnet-pfty",
                    static_cast<unsigned long long>(context.connectionId),
                    context.rpc.header.token, program, stream,
                    hasVersion ? "" : "<default>/", version,
                    kUsRegion, kProfanityUsage);
                MarkHandled(context, "BNet profanity ContentHandle queued");
                return true;
            }

            // Unknown resource types retain the deterministic local handle; do
            // not fabricate a remote depot URL for them.
            const auto hash = LocalContentHash(program, stream, version);
            AppendFixed32Field(response, 1u, 1u);
            AppendFixed32Field(response, 2u, stream);
            AppendBytesField(response, 3u, hash);
            QueueResponse(context, response, "ResourcesService.GetContentHandle response");

            log::Print("[BGS-RESOURCES] id=%llu GetContentHandle token=%u program=%s0x%08X stream=%s0x%08X version=%s0x%08X hashBytes=%llu protoUrl=omitted-local-fallback",
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
