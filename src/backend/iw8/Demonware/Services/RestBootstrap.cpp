#include "RestBootstrap.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        bool ContainsAscii(const std::uint8_t* data, std::size_t size, const char* needle)
        {
            if (!data || !needle || !*needle)
                return false;
            const std::size_t needleSize = std::strlen(needle);
            if (needleSize > size)
                return false;
            const auto* match = std::search(data, data + size,
                reinterpret_cast<const std::uint8_t*>(needle),
                reinterpret_cast<const std::uint8_t*>(needle) + needleSize);
            return match != data + size;
        }

        enum class RestBootstrapKind : std::uint8_t
        {
            Unknown = 0,
            UserListsGetUserList,
            FriendsGetFriends,
            FriendsGetPending,
        };

        RestBootstrapKind ClassifyRestBootstrap(const std::uint8_t* payload, std::size_t payloadBytes)
        {
            if (ContainsAscii(payload, payloadBytes, "UserLists") &&
                ContainsAscii(payload, payloadBytes, "get_user_list"))
                return RestBootstrapKind::UserListsGetUserList;

            if (ContainsAscii(payload, payloadBytes, "Friends") &&
                ContainsAscii(payload, payloadBytes, "get_friends_v1"))
                return RestBootstrapKind::FriendsGetFriends;

            if (ContainsAscii(payload, payloadBytes, "Friends") &&
                ContainsAscii(payload, payloadBytes, "get_pending_friend_requests_v1"))
                return RestBootstrapKind::FriendsGetPending;

            return RestBootstrapKind::Unknown;
        }

        std::string ExtractAsciiQueryValue(const std::uint8_t* payload, std::size_t payloadBytes,
            const char* key, const char* fallback)
        {
            if (!payload || !key || !*key)
                return fallback ? fallback : "";

            const std::string needle = std::string(key) + "=";
            const auto* begin = payload;
            const auto* end = payload + payloadBytes;
            const auto* found = std::search(begin, end,
                reinterpret_cast<const std::uint8_t*>(needle.data()),
                reinterpret_cast<const std::uint8_t*>(needle.data()) + needle.size());
            if (found == end)
                return fallback ? fallback : "";

            found += needle.size();
            std::string value;
            while (found != end && value.size() < 64u)
            {
                const unsigned char ch = *found++;
                if (ch == '&' || ch == 0 || ch < 0x20 || ch > 0x7Eu)
                    break;
                if (ch == '"' || ch == '\\')
                    value.push_back('\\');
                value.push_back(static_cast<char>(ch));
            }
            return value.empty() ? (fallback ? fallback : "") : value;
        }

        std::string RestBootstrapBody(RestBootstrapKind kind,
            const std::uint8_t* payload, std::size_t payloadBytes)
        {
            switch (kind)
            {
            case RestBootstrapKind::UserListsGetUserList:
                return "{\"pageToken\":\"\",\"userList\":[]}";

            case RestBootstrapKind::FriendsGetFriends:
            case RestBootstrapKind::FriendsGetPending:
            {
                const std::string context = ExtractAsciiQueryValue(payload, payloadBytes,
                    "context", "cod-shared");
                return std::string("{\"context\":\"") + context + "\",\"page\":\"\",\"users\":[]}";
            }

            default:
                return {};
            }
        }

        void BuildRestResponseMetadata(std::uint64_t transactionId,
            std::vector<std::uint8_t>& metadata)
        {
            metadata.clear();
            AppendPbU32(metadata, 1u, kHttpOk);
            AppendPbU32(metadata, 302u, kRestMimeJson);
            AppendPbBool(metadata, 400u, false);

            std::vector<std::uint8_t> replyExtra;
            replyExtra.reserve(24u);
            AppendPbU64(replyExtra, 101u, transactionId);
            AppendPbBool(replyExtra, 102u, false);
            AppendPbObject(metadata, 1000u, replyExtra);
        }

        bool AppendRestJsonResult(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
            std::uint64_t transactionId)
        {
            const RestBootstrapKind kind = ClassifyRestBootstrap(requestPayload, requestPayloadBytes);
            const std::string body = RestBootstrapBody(kind, requestPayload, requestPayloadBytes);
            if (body.empty())
                return false;

            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, kRestVersion);

            std::vector<std::uint8_t> metadata;
            metadata.reserve(64u);
            BuildRestResponseMetadata(transactionId, metadata);
            AppendTypedBlob(serviceReply, metadata.data(), metadata.size());
            AppendTypedBool(serviceReply, true);
            AppendTypedBlob(serviceReply, body.c_str(), body.size() + 1u);
            return true;
        }
    }
}
