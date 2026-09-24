#include "PublisherVariables.h"

namespace revamped::iw8::demonware
{
    namespace
    {
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
                AppendPbU32(info, 1u, 1u); // deterministic local data version
                AppendPbU32(info, 2u, 0u);
                AppendPbString(info, 3u, nameSpace);
                AppendPbString(info, 4u, "{}");
                AppendPbObject(responseBody, 1u, info);
            }

            AppendTypedStruct(serviceReply, responseBody);
            return true;
        }
    }
}
