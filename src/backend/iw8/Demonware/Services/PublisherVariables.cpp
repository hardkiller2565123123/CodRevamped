#include "PublisherVariables.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace revamped::iw8::demonware
{
    namespace
    {
        constexpr std::uint16_t kPublisherMajorVersion = 1u;
        constexpr std::uint16_t kPublisherMinorVersion = 0u;
        constexpr const char* kEmptyPublisherVariablesJson = "{}";

        // PublisherVariableManager marks the first namespace ("general") as
        // critical. A successful task carrying an empty object still fails that
        // fence because ApplyPublisherVariables() returns false when there are
        // no non-version variables to apply.
        //
        // Keep the local response intentionally inert: one project-specific
        // string dvar is enough to make the stock client treat "general" as a
        // successfully populated publisher-variable namespace without changing
        // gameplay/network behavior.
        constexpr const char* kGeneralPublisherVariablesJson =
            "{\"codrevamped_local_pubvar\":\"1\"}";

        bool IsCriticalPublisherNamespace(const std::string& nameSpace)
        {
            return nameSpace == "general";
        }

        const char* PublisherVariablesJsonForNamespace(const std::string& nameSpace)
        {
            return IsCriticalPublisherNamespace(nameSpace)
                ? kGeneralPublisherVariablesJson
                : kEmptyPublisherVariablesJson;
        }

        void LogPublisherVariablesReply(const char* schema, const std::string& nameSpace,
            const char* json)
        {
            std::printf(
                "[DW-PUBVARS] schema=%s namespace=%s major=%u minor=%u criticalSeed=%s json=%s\n",
                schema ? schema : "unknown",
                nameSpace.c_str(),
                static_cast<unsigned>(kPublisherMajorVersion),
                static_cast<unsigned>(kPublisherMinorVersion),
                IsCriticalPublisherNamespace(nameSpace) ? "yes" : "no",
                json ? json : "{}");
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
                responseBody.reserve(namespaces.size() * 64u);
                for (const auto& nameSpace : namespaces)
                {
                    const char* json = PublisherVariablesJsonForNamespace(nameSpace);

                    std::vector<std::uint8_t> info;
                    info.reserve(nameSpace.size() + std::strlen(json) + 16u);
                    AppendPbU32(info, 1u, kPublisherMajorVersion);
                    AppendPbU32(info, 2u, kPublisherMinorVersion);
                    AppendPbString(info, 3u, nameSpace);
                    AppendPbString(info, 4u, json);
                    AppendPbObject(responseBody, 1u, info);

                    LogPublisherVariablesReply("struct-adaptive", nameSpace, json);
                }

                AppendTypedStruct(serviceReply, responseBody);
                if (detectedSchema)
                    *detectedSchema = PayloadSchema::StructBuffer;
                return true;
            }

            std::string nameSpace;
            if (CollectLegacyPublisherNamespace(requestPayload, requestPayloadBytes, nameSpace))
            {
                const char* json = PublisherVariablesJsonForNamespace(nameSpace);

                AppendTypedU32(serviceReply, 1u);
                AppendTypedU32(serviceReply, 1u);
                AppendTypedU16(serviceReply, kPublisherMajorVersion);
                AppendTypedU16(serviceReply, kPublisherMinorVersion);
                AppendTypedString(serviceReply, nameSpace);
                AppendTypedString(serviceReply, json);

                LogPublisherVariablesReply("legacy-adaptive", nameSpace, json);

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

            const char* json = PublisherVariablesJsonForNamespace(nameSpace);

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
            AppendTypedString(serviceReply, json);

            LogPublisherVariablesReply("legacy-95-1", nameSpace, json);
            return true;
        }

        bool AppendPublisherVariablesStruct(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::vector<std::string> namespaces;
            if (!CollectPublisherNamespaces(requestPayload, requestPayloadBytes, namespaces))
                return false;

            std::vector<std::uint8_t> responseBody;
            responseBody.reserve(namespaces.size() * 64u);
            for (const auto& nameSpace : namespaces)
            {
                const char* json = PublisherVariablesJsonForNamespace(nameSpace);

                std::vector<std::uint8_t> info;
                info.reserve(nameSpace.size() + std::strlen(json) + 16u);
                AppendPbU32(info, 1u, kPublisherMajorVersion);
                AppendPbU32(info, 2u, kPublisherMinorVersion);
                AppendPbString(info, 3u, nameSpace);
                AppendPbString(info, 4u, json);
                AppendPbObject(responseBody, 1u, info);

                LogPublisherVariablesReply("struct-95-3", nameSpace, json);
            }

            std::printf(
                "[DW-PUBVARS] schema=struct-95-3 namespaces=%zu responseObjects=%zu generalCriticalSeed=%s\n",
                namespaces.size(),
                namespaces.size(),
                std::find(namespaces.begin(), namespaces.end(), "general") != namespaces.end()
                    ? "yes"
                    : "not-requested");

            AppendTypedStruct(serviceReply, responseBody);
            return true;
        }
    }
}
