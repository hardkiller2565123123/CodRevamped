#include "../DemonwareTaskRouter.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace revamped::iw8::demonware
{
    namespace
    {
        constexpr std::uint64_t kFnvOffset64 = 1469598103934665603ull;
        constexpr std::uint64_t kFnvPrime64 = 1099511628211ull;

        void HashByte(std::uint64_t& hash, std::uint8_t value)
        {
            hash ^= value;
            hash *= kFnvPrime64;
        }

        void HashU32(std::uint64_t& hash, std::uint32_t value)
        {
            HashByte(hash, static_cast<std::uint8_t>(value));
            HashByte(hash, static_cast<std::uint8_t>(value >> 8u));
            HashByte(hash, static_cast<std::uint8_t>(value >> 16u));
            HashByte(hash, static_cast<std::uint8_t>(value >> 24u));
        }

        std::uint8_t LengthBucket(std::size_t bytes)
        {
            if (bytes == 0u) return 0u;
            if (bytes <= 4u) return 1u;
            if (bytes <= 16u) return 2u;
            if (bytes <= 64u) return 3u;
            if (bytes <= 256u) return 4u;
            if (bytes <= 1024u) return 5u;
            return 6u;
        }

        bool IsLegacyTag(std::uint8_t tag)
        {
            switch (tag)
            {
            case kBbBool:
            case kBbUnsignedChar8:
            case kBbUnsignedInteger16:
            case kBbUnsignedInteger32:
            case kBbUnsignedInteger64:
            case kBbFloat32:
            case kBbString:
            case kBbBlob:
            case kBbStruct:
                return true;
            default:
                return false;
            }
        }

        bool SkipLegacyField(const std::uint8_t*& cursor, const std::uint8_t* end,
            std::uint8_t tag, std::uint64_t& shape)
        {
            HashByte(shape, tag);
            switch (tag)
            {
            case kBbBool:
            case kBbUnsignedChar8:
                if (cursor + 1u > end) return false;
                ++cursor;
                return true;

            case kBbUnsignedInteger16:
                if (cursor + 2u > end) return false;
                cursor += 2u;
                return true;

            case kBbUnsignedInteger32:
            case kBbFloat32:
                if (cursor + 4u > end) return false;
                cursor += 4u;
                return true;

            case kBbUnsignedInteger64:
                if (cursor + 8u > end) return false;
                cursor += 8u;
                return true;

            case kBbString:
            {
                const auto* begin = cursor;
                while (cursor < end && *cursor != 0u)
                    ++cursor;
                if (cursor >= end)
                    return false;
                (void)begin;
                ++cursor;
                return true;
            }

            case kBbBlob:
            case kBbStruct:
            {
                if (cursor >= end || *cursor++ != kBbUnsignedInteger32 || cursor + 4u > end)
                    return false;
                const std::uint32_t bytes = ReadLe32(cursor);
                cursor += 4u;
                if (bytes > static_cast<std::uint32_t>(end - cursor))
                    return false;
                cursor += bytes;
                if (tag == kBbStruct)
                {
                    if (cursor >= end || *cursor != kBbStructEnd)
                        return false;
                    ++cursor;
                }
                return true;
            }

            default:
                return false;
            }
        }
    }

    const char* TaskWireEncodingName(TaskWireEncoding encoding)
    {
        switch (encoding)
        {
        case TaskWireEncoding::TypedU8: return "typed-u8";
        case TaskWireEncoding::RawServiceTask: return "raw-service-task";
        default: return "unknown";
        }
    }

    const char* PayloadSchemaName(PayloadSchema schema)
    {
        switch (schema)
        {
        case PayloadSchema::Empty: return "empty";
        case PayloadSchema::LegacyByteBuffer: return "legacy-bytebuffer";
        case PayloadSchema::StructBuffer: return "structbuffer";
        case PayloadSchema::Opaque: return "opaque";
        default: return "unknown";
        }
    }

    const char* TaskSemanticName(TaskSemantic semantic)
    {
        switch (semantic)
        {
        case TaskSemantic::PublisherVariablesRetrieve: return "publisher-variables.retrieve";
        case TaskSemantic::RestRequest: return "rest.request";
        case TaskSemantic::ProfilesGetPublic: return "profiles.get-public";
        case TaskSemantic::ProfilesSetPublic: return "profiles.set-public";
        case TaskSemantic::ObjectStoreUserGet: return "objectstore.user-get";
        case TaskSemantic::ObjectStoreUserUpload: return "objectstore.user-upload";
        case TaskSemantic::ObjectStorePublisherGet: return "objectstore.publisher-get";
        case TaskSemantic::ObjectStorePublisherBatchGet: return "objectstore.publisher-batch-get";
        case TaskSemantic::PlayerStatsWrite: return "playerstats.write";
        case TaskSemantic::PlayerStatsValidatedWrite: return "playerstats.validated-write";
        case TaskSemantic::DcQos: return "dcqos";
        case TaskSemantic::RelayAuth: return "relay-auth";
        default: return "generic";
        }
    }

    void AnalyzeTaskPayload(TaskRequest& request, const std::uint8_t* payload, std::size_t payloadBytes)
    {
        request.payloadSchema = PayloadSchema::Unknown;
        request.shapeFingerprint = kFnvOffset64;
        if (!payloadBytes)
        {
            request.payloadSchema = PayloadSchema::Empty;
            HashByte(request.shapeFingerprint, 0u);
            return;
        }
        if (!payload)
            return;

        if (payload[0] == kBbStruct)
        {
            const std::uint8_t* body = nullptr;
            std::size_t bodyBytes = 0u;
            if (ExtractTypedStructBody(payload, payloadBytes, body, bodyBytes))
            {
                request.payloadSchema = PayloadSchema::StructBuffer;
                const auto* cursor = body;
                const auto* end = body + bodyBytes;
                HashByte(request.shapeFingerprint, kBbStruct);
                while (cursor < end)
                {
                    PbField field{};
                    if (!NextPbField(cursor, end, field))
                    {
                        request.payloadSchema = PayloadSchema::Opaque;
                        break;
                    }
                    HashU32(request.shapeFingerprint, field.tag);
                    HashByte(request.shapeFingerprint, field.wireType);
                    (void)field.bytesSize;
                }
                if (request.payloadSchema == PayloadSchema::StructBuffer)
                    return;
            }
        }

        if (IsLegacyTag(payload[0]))
        {
            const auto* cursor = payload;
            const auto* end = payload + payloadBytes;
            std::uint64_t shape = kFnvOffset64;
            bool parsedAny = false;
            while (cursor < end)
            {
                if (*cursor == 0u)
                {
                    ++cursor;
                    continue;
                }
                const std::uint8_t tag = *cursor++;
                if (!IsLegacyTag(tag) || !SkipLegacyField(cursor, end, tag, shape))
                {
                    parsedAny = false;
                    break;
                }
                parsedAny = true;
            }
            if (parsedAny)
            {
                request.payloadSchema = PayloadSchema::LegacyByteBuffer;
                request.shapeFingerprint = shape;
                return;
            }
        }

        request.payloadSchema = PayloadSchema::Opaque;
        const std::size_t prefix = (std::min)(payloadBytes, static_cast<std::size_t>(32u));
        for (std::size_t i = 0; i < prefix; ++i)
            HashByte(request.shapeFingerprint, payload[i]);
        HashByte(request.shapeFingerprint, LengthBucket(payloadBytes));
    }
}
