#include "PublisherVariables.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        constexpr std::uint16_t kPublisherMajorVersion = 1u;
        constexpr std::uint16_t kPublisherMinorVersion = 0u;

        // Retail ONLINE bootstrap does not consider the required "general"
        // publisher-variable namespace complete when its parsed variable map
        // contains only the synthetic MajorVersion/MinorVersion entries.
        // Native storage processing marks the record successful when it can
        // read at least one additional key/value entry.  Keep the payload
        // deliberately small, deterministic and string-only so every supported
        // serializer path produces the same local cache representation.
        constexpr const char* kEmptyPublisherVariablesJson = "{}";
        constexpr const char* kGeneralPublisherVariablesJson =
            "{"
            "\"revamped_bootstrap\":\"1\","
            "\"NKTMRPRKKK\":\"0\","  // net_relay_enabled
            "\"NSPPTONLNP\":\"0\","  // online_blueprints_enabled
            "\"LKQRNQSSQS\":\"0\","  // online_challenge_fence_enabled
            "\"MNLNLSTSNT\":\"0\","  // crm_enabled
            "\"NQONKSKTLQ\":\"0\","  // dw_region_lookup_timeout
            "\"LNSPMQMSS\":\"0\","  // anticheat main-menu fence failure
            "\"MTNQMNRQML\":\"0\","  // publisher-variable fetch-always
            "\"MLMKNTSSSL\":\"0\","  // publisher-variable fetch-all-on-update
            "\"LNKRTPTKPR\":\"0\","  // publisher-variable refetch-on-mismatch
            "\"MROLPRPTPO\":\"1\","  // com_force_premium
            "\"LNLPTMKPT\":\"1\","  // lui_store_enabled
            "\"LNTOKPTKS\":\"1\","  // lui_cod_points_enabled
            "\"NRTSOTKTOS\":\"1\","  // lui_battle_pass_enabled
            "\"LSSPPSTLQ\":\"1\","  // store bundle preview list
            "\"LSOLLKOPQT\":\"1\","  // free bundle visibility
            "\"LQKTNLONLP\":\"1\","   // MP private-match/menu feature gate
            "\"NLMSQOPNMK\":\"1\","   // WZ tournament first
            "\"LNRQKOQLNN\":\"0\","   // BR featured before promoted trial buttons
            "\"NKOOQPNSKM\":\"1\","   // WZ squad-fill control enabled
            "\"MNRTKTQMLS\":\"0\","   // hide WZ practice mode from public play list
            "\"NORMPNKNK\":\"0\","   // hide WZ trials entry
            "\"LOQQOSNQKN\":\"1\""    // WZ private/custom match enabled
            "}";

        const char* PublisherVariablesJsonForNamespace(const std::string& nameSpace)
        {
            return nameSpace == "general"
                ? kGeneralPublisherVariablesJson
                : kEmptyPublisherVariablesJson;
        }

        bool ReadLegacyTypedString(const std::uint8_t*& cursor, const std::uint8_t* end,
            std::string& value)
        {
            value.clear();
            if (!cursor || cursor >= end || *cursor++ != kBbString)
                return false;

            const std::uint8_t* begin = cursor;
            while (cursor < end && *cursor != 0u)
                ++cursor;
            if (cursor >= end)
                return false;

            value.assign(reinterpret_cast<const char*>(begin),
                static_cast<std::size_t>(cursor - begin));
            ++cursor; // NUL terminator
            return true;
        }

        bool CollectLegacyPublisherNamespace(const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes, std::string& nameSpace)
        {
            nameSpace.clear();
            if (!requestPayload || requestPayloadBytes == 0u)
                return false;

            // Stock IW8 1.20 builds task 95/1 with two legacy strings:
            //   string #1 = service/context value (observed empty)
            //   string #2 = publisher-variable namespace, max length 32 incl. NUL
            // The task buffer may contain zero padding after the strings.
            const std::uint8_t* cursor = requestPayload;
            const std::uint8_t* end = requestPayload + requestPayloadBytes;
            std::string current;
            std::size_t stringCount = 0u;
            while (cursor < end)
            {
                if (*cursor == 0u)
                {
                    ++cursor;
                    continue;
                }

                if (!ReadLegacyTypedString(cursor, end, current))
                    return false;
                ++stringCount;
                nameSpace = current; // namespace is the final serialized string
            }

            return stringCount >= 2u && !nameSpace.empty() && nameSpace.size() <= 31u;
        }

        bool CollectPublisherNamespaces(const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
            std::vector<std::string>& namespaces)
        {
            namespaces.clear();
            const std::uint8_t* body = nullptr;
            std::size_t bodyBytes = 0;
            if (!ExtractTypedStructBody(requestPayload, requestPayloadBytes, body, bodyBytes))
                return false;

            const std::uint8_t* cursor = body;
            const std::uint8_t* end = body + bodyBytes;
            while (cursor < end)
            {
                PbField field{};
                if (!NextPbField(cursor, end, field))
                    return false;
                if (field.tag == 2u && field.wireType == 2u)
                {
                    if (!field.bytes || field.bytesSize > 31u)
                        return false;
                    namespaces.emplace_back(reinterpret_cast<const char*>(field.bytes), field.bytesSize);
                }
            }
            return !namespaces.empty();
        }


        bool IsPublisherVariablesPayload(const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes, PayloadSchema* detectedSchema = nullptr)
        {
            std::vector<std::string> structNamespaces;
            if (CollectPublisherNamespaces(requestPayload, requestPayloadBytes, structNamespaces))
            {
                if (detectedSchema)
                    *detectedSchema = PayloadSchema::StructBuffer;
                return true;
            }

            std::string legacyNamespace;
            if (CollectLegacyPublisherNamespace(requestPayload, requestPayloadBytes, legacyNamespace))
            {
                if (detectedSchema)
                    *detectedSchema = PayloadSchema::LegacyByteBuffer;
                return true;
            }

            if (detectedSchema)
                *detectedSchema = PayloadSchema::Unknown;
            return false;
        }

        bool AppendPublisherVariablesAdaptive(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
            PayloadSchema* detectedSchema = nullptr)
        {
            std::vector<std::string> namespaces;
            if (CollectPublisherNamespaces(requestPayload, requestPayloadBytes, namespaces))
            {
                std::vector<std::uint8_t> responseBody;
                responseBody.reserve(namespaces.size() * 32u);
                for (const auto& nameSpace : namespaces)
                {
                    std::vector<std::uint8_t> info;
                    info.reserve(nameSpace.size() + 16u);
                    AppendPbU32(info, 1u, kPublisherMajorVersion);
                    AppendPbU32(info, 2u, kPublisherMinorVersion);
                    AppendPbString(info, 3u, nameSpace);
                    AppendPbString(info, 4u, PublisherVariablesJsonForNamespace(nameSpace));
                    AppendPbObject(responseBody, 1u, info);
                }

                AppendTypedStruct(serviceReply, responseBody);
                if (detectedSchema)
                    *detectedSchema = PayloadSchema::StructBuffer;
                return true;
            }

            std::string nameSpace;
            if (CollectLegacyPublisherNamespace(requestPayload, requestPayloadBytes, nameSpace))
            {
                AppendTypedU32(serviceReply, 1u);
                AppendTypedU32(serviceReply, 1u);
                AppendTypedU16(serviceReply, kPublisherMajorVersion);
                AppendTypedU16(serviceReply, kPublisherMinorVersion);
                AppendTypedString(serviceReply, nameSpace);
                AppendTypedString(serviceReply, PublisherVariablesJsonForNamespace(nameSpace));
                if (detectedSchema)
                    *detectedSchema = PayloadSchema::LegacyByteBuffer;
                return true;
            }

            if (detectedSchema)
                *detectedSchema = PayloadSchema::Unknown;
            return false;
        }
        bool AppendPublisherVariablesLegacy120(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::string nameSpace;
            if (!CollectLegacyPublisherNamespace(requestPayload, requestPayloadBytes, nameSpace))
                return false;

            // Normal legacy bdRemoteTask result envelope: one returned result.
            AppendTypedU32(serviceReply, 1u); // numResults
            AppendTypedU32(serviceReply, 1u); // totalNumResults

            // IW8 1.20 result deserializer order, proven from the native class:
            //   UInt16 MajorVersion
            //   UInt16 MinorVersion
            //   String namespace
            //   String JSON publisher-variable object
            // The client parses JSON and injects MajorVersion/MinorVersion into
            // that object before exposing the namespace to OnlineStorage.
            AppendTypedU16(serviceReply, kPublisherMajorVersion);
            AppendTypedU16(serviceReply, kPublisherMinorVersion);
            AppendTypedString(serviceReply, nameSpace);
            AppendTypedString(serviceReply, PublisherVariablesJsonForNamespace(nameSpace));
            return true;
        }

        bool AppendPublisherVariablesStruct(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::vector<std::string> namespaces;
            if (!CollectPublisherNamespaces(requestPayload, requestPayloadBytes, namespaces))
                return false;

            std::vector<std::uint8_t> responseBody;
            responseBody.reserve(namespaces.size() * 32u);
            for (const auto& nameSpace : namespaces)
            {
                std::vector<std::uint8_t> info;
                info.reserve(nameSpace.size() + 16u);
                AppendPbU32(info, 1u, kPublisherMajorVersion);
                AppendPbU32(info, 2u, kPublisherMinorVersion);
                AppendPbString(info, 3u, nameSpace);
                AppendPbString(info, 4u, PublisherVariablesJsonForNamespace(nameSpace));
                AppendPbObject(responseBody, 1u, info);
            }

            AppendTypedStruct(serviceReply, responseBody);
            return true;
        }
    }
}
