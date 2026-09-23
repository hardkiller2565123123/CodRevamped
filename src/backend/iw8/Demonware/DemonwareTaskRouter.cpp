#include "DemonwareTaskRouter.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace revamped::iw8::demonware
{
    namespace
    {
        constexpr std::uint8_t kTaskRequestType = 0x86;
        constexpr std::uint8_t kTaskReplyType = 0x01;

        // bdByteBuffer legacy type tags used by the stock IW8 Demonware client.
        constexpr std::uint8_t kBbBool = 0x01;
        constexpr std::uint8_t kBbUnsignedChar8 = 0x03;
        constexpr std::uint8_t kBbUnsignedInteger32 = 0x08;
        constexpr std::uint8_t kBbUnsignedInteger64 = 0x0A;
        constexpr std::uint8_t kBbFloat32 = 0x0D;
        constexpr std::uint8_t kBbString = 0x10;
        constexpr std::uint8_t kBbBlob = 0x13;
        constexpr std::uint8_t kBbStruct = 0x17;
        constexpr std::uint8_t kBbStructEnd = 0x00;

        constexpr std::uint32_t kRestVersion = 1u;
        constexpr std::uint32_t kHttpOk = 200u;
        constexpr std::uint32_t kRestMimeJson = 1u;

        // V88: the byte after serviceId is a typed-U8 marker (0x03), not the
        // task number. The actual task number follows it. These task IDs now
        // line up with stock OpenIW8 call sites and the captured 1.44 payloads.
        constexpr TaskRoute kRoutes[] = {
            {38u, 6u, "bdAntiCheat", "reportExtendedAuthInfo", ReplyPolicy::NoResultSuccess},
            {38u, 7u, "bdAntiCheat", "reportBNetSessionToken", ReplyPolicy::NoResultSuccess},

            {27u, 2u, "bdDML", "getUserData", ReplyPolicy::LegacyDmlInfo},
            {67u, 6u, "bdEventLog", "initializeFiltering", ReplyPolicy::NoResultSuccess},
            {12u, 6u, "bdTitleUtilities", "getServerTime", ReplyPolicy::LegacyServerTime},

            {95u, 3u, "bdPublisherVariables", "retrievePublisherVariables", ReplyPolicy::StructPublisherVariables},
            {104u, 6u, "bdMarketingComms", "getMessages", ReplyPolicy::StructMarketingMessagesEmpty},

            {193u, 6u, "bdObjectStore", "getUserObjectsVectorized", ReplyPolicy::StructObjectStoreVectorized},
            {193u, 7u, "bdObjectStore", "uploadUserObjectsVectorized", ReplyPolicy::StructObjectStoreUploadVectorized},
            {197u, 0x15u, "bdMW4Service", "getGroupInfos", ReplyPolicy::StructClanGroupInfosEmpty},
            {197u, 0x1Cu, "bdMW4Service", "getMembershipProposalsByUser", ReplyPolicy::StructClanProposalsEmpty},
            {197u, 0x1Eu, "bdMW4Service", "getMembershipsByUsers", ReplyPolicy::StructClanMembershipsEmpty},

            // Achievement Engine user-state bootstrap used by OnlineProgression.
            // Stock OpenIW8 maps service 0x7D/task 9 to getUserState.
            {125u, 9u, "bdAchievementsEngineService", "getUserState", ReplyPolicy::StructAchievementsUserState},

            {198u, 0x0Cu, "bdMessaging", "channelUnsubscribeFromCategory", ReplyPolicy::StructMessagingUnsubscribeAck},

            // Stock bdRESTTaskManager uses service 0xFF / task 0x0A.
            // Only the reconstructed startup social reads below get replies.
            {255u, 0x0Au, "bdRESTLegacy", "request", ReplyPolicy::RestJsonSuccess},
        };

        std::uint32_t ReadLe32(const std::uint8_t* p)
        {
            return static_cast<std::uint32_t>(p[0]) |
                (static_cast<std::uint32_t>(p[1]) << 8) |
                (static_cast<std::uint32_t>(p[2]) << 16) |
                (static_cast<std::uint32_t>(p[3]) << 24);
        }

        void AppendLe32(std::vector<std::uint8_t>& out, std::uint32_t value)
        {
            out.push_back(static_cast<std::uint8_t>(value));
            out.push_back(static_cast<std::uint8_t>(value >> 8));
            out.push_back(static_cast<std::uint8_t>(value >> 16));
            out.push_back(static_cast<std::uint8_t>(value >> 24));
        }

        void AppendLe64(std::vector<std::uint8_t>& out, std::uint64_t value)
        {
            AppendLe32(out, static_cast<std::uint32_t>(value));
            AppendLe32(out, static_cast<std::uint32_t>(value >> 32));
        }

        void AppendTypedBool(std::vector<std::uint8_t>& out, bool value)
        {
            out.push_back(kBbBool);
            out.push_back(value ? 1u : 0u);
        }

        void AppendTypedU8(std::vector<std::uint8_t>& out, std::uint8_t value)
        {
            out.push_back(kBbUnsignedChar8);
            out.push_back(value);
        }

        void AppendTypedU32(std::vector<std::uint8_t>& out, std::uint32_t value)
        {
            out.push_back(kBbUnsignedInteger32);
            AppendLe32(out, value);
        }

        void AppendTypedU64(std::vector<std::uint8_t>& out, std::uint64_t value)
        {
            out.push_back(kBbUnsignedInteger64);
            AppendLe64(out, value);
        }

        void AppendTypedFloat(std::vector<std::uint8_t>& out, float value)
        {
            std::uint32_t bits = 0;
            static_assert(sizeof(bits) == sizeof(value), "float32 size mismatch");
            std::memcpy(&bits, &value, sizeof(bits));
            out.push_back(kBbFloat32);
            AppendLe32(out, bits);
        }

        void AppendTypedString(std::vector<std::uint8_t>& out, const std::string& value)
        {
            out.push_back(kBbString);
            out.insert(out.end(), value.begin(), value.end());
            out.push_back(0u);
        }

        void AppendTypedBlob(std::vector<std::uint8_t>& out, const void* data, std::size_t size)
        {
            if (size > (std::numeric_limits<std::uint32_t>::max)())
                return;

            out.push_back(kBbBlob);
            AppendTypedU32(out, static_cast<std::uint32_t>(size));
            if (size && data)
            {
                const auto* bytes = static_cast<const std::uint8_t*>(data);
                out.insert(out.end(), bytes, bytes + size);
            }
        }

        void AppendTypedStruct(std::vector<std::uint8_t>& out, const std::vector<std::uint8_t>& body)
        {
            out.push_back(kBbStruct);
            AppendTypedU32(out, static_cast<std::uint32_t>(body.size()));
            out.insert(out.end(), body.begin(), body.end());
            out.push_back(kBbStructEnd);
        }

        void AppendPbVarint(std::vector<std::uint8_t>& out, std::uint64_t value)
        {
            do
            {
                std::uint8_t byte = static_cast<std::uint8_t>(value & 0x7Fu);
                value >>= 7u;
                if (value)
                    byte |= 0x80u;
                out.push_back(byte);
            } while (value);
        }

        bool ReadPbVarint(const std::uint8_t*& cursor, const std::uint8_t* end, std::uint64_t& value)
        {
            value = 0;
            unsigned shift = 0;
            while (cursor < end && shift < 64u)
            {
                const std::uint8_t byte = *cursor++;
                value |= static_cast<std::uint64_t>(byte & 0x7Fu) << shift;
                if ((byte & 0x80u) == 0)
                    return true;
                shift += 7u;
            }
            return false;
        }

        void AppendPbTag(std::vector<std::uint8_t>& out, std::uint32_t tag, std::uint8_t wireType)
        {
            AppendPbVarint(out, (static_cast<std::uint64_t>(tag) << 3u) | wireType);
        }

        void AppendPbU32(std::vector<std::uint8_t>& out, std::uint32_t tag, std::uint32_t value)
        {
            AppendPbTag(out, tag, 0u);
            AppendPbVarint(out, value);
        }

        void AppendPbU64(std::vector<std::uint8_t>& out, std::uint32_t tag, std::uint64_t value)
        {
            AppendPbTag(out, tag, 0u);
            AppendPbVarint(out, value);
        }

        void AppendPbBool(std::vector<std::uint8_t>& out, std::uint32_t tag, bool value)
        {
            AppendPbTag(out, tag, 0u);
            AppendPbVarint(out, value ? 1u : 0u);
        }

        void AppendPbBytes(std::vector<std::uint8_t>& out, std::uint32_t tag,
            const void* data, std::size_t size)
        {
            AppendPbTag(out, tag, 2u);
            AppendPbVarint(out, static_cast<std::uint64_t>(size));
            if (size && data)
            {
                const auto* bytes = static_cast<const std::uint8_t*>(data);
                out.insert(out.end(), bytes, bytes + size);
            }
        }

        void AppendPbString(std::vector<std::uint8_t>& out, std::uint32_t tag, const std::string& value)
        {
            AppendPbBytes(out, tag, value.data(), value.size());
        }

        void AppendPbObject(std::vector<std::uint8_t>& out, std::uint32_t tag,
            const std::vector<std::uint8_t>& object)
        {
            AppendPbBytes(out, tag, object.data(), object.size());
        }

        struct PbField
        {
            std::uint32_t tag = 0;
            std::uint8_t wireType = 0;
            std::uint64_t varint = 0;
            const std::uint8_t* bytes = nullptr;
            std::size_t bytesSize = 0;
        };

        bool NextPbField(const std::uint8_t*& cursor, const std::uint8_t* end, PbField& field)
        {
            if (!cursor || cursor >= end)
                return false;

            std::uint64_t key = 0;
            if (!ReadPbVarint(cursor, end, key))
                return false;

            field = {};
            field.tag = static_cast<std::uint32_t>(key >> 3u);
            field.wireType = static_cast<std::uint8_t>(key & 7u);
            if (!field.tag)
                return false;

            switch (field.wireType)
            {
            case 0u:
                return ReadPbVarint(cursor, end, field.varint);

            case 1u:
                if (static_cast<std::size_t>(end - cursor) < 8u)
                    return false;
                field.bytes = cursor;
                field.bytesSize = 8u;
                cursor += 8u;
                return true;

            case 2u:
            {
                std::uint64_t len = 0;
                if (!ReadPbVarint(cursor, end, len) || len > static_cast<std::uint64_t>(end - cursor))
                    return false;
                field.bytes = cursor;
                field.bytesSize = static_cast<std::size_t>(len);
                cursor += field.bytesSize;
                return true;
            }

            case 5u:
                if (static_cast<std::size_t>(end - cursor) < 4u)
                    return false;
                field.bytes = cursor;
                field.bytesSize = 4u;
                cursor += 4u;
                return true;

            default:
                return false;
            }
        }

        bool ExtractTypedStructBody(const std::uint8_t* payload, std::size_t payloadBytes,
            const std::uint8_t*& body, std::size_t& bodyBytes)
        {
            body = nullptr;
            bodyBytes = 0;
            if (!payload || payloadBytes < 7u || payload[0] != kBbStruct || payload[1] != kBbUnsignedInteger32)
                return false;

            const std::uint32_t declared = ReadLe32(payload + 2u);
            const std::size_t bodyOffset = 6u;
            if (declared > payloadBytes - bodyOffset)
                return false;

            body = payload + bodyOffset;
            bodyBytes = declared;

            // Stock writeStructEnd emits one trailing 0 marker. Permit an exact
            // envelope or extra task-buffer padding after the struct.
            if (payloadBytes > bodyOffset + bodyBytes && payload[bodyOffset + bodyBytes] != kBbStructEnd)
                return false;
            return true;
        }

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

        void AppendLegacyDmlInfo(std::vector<std::uint8_t>& serviceReply)
        {
            // Deterministic local/offline DML view. This is protocol data only;
            // it is not inferred from the user's physical location.
            AppendTypedU32(serviceReply, 1u); // numResults
            AppendTypedU32(serviceReply, 1u); // totalNumResults
            AppendTypedString(serviceReply, "US");
            AppendTypedString(serviceReply, "United States");
            AppendTypedString(serviceReply, "");
            AppendTypedString(serviceReply, "");
            AppendTypedFloat(serviceReply, 0.0f);
            AppendTypedFloat(serviceReply, 0.0f);
            AppendTypedU32(serviceReply, 0u);
            AppendTypedString(serviceReply, "UTC");
        }

        void AppendLegacyServerTime(std::vector<std::uint8_t>& serviceReply)
        {
            const auto now = std::chrono::system_clock::now().time_since_epoch();
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now).count();
            const std::uint32_t unixTime = seconds <= 0 ? 0u :
                static_cast<std::uint32_t>((std::min)(static_cast<std::uint64_t>(seconds),
                    static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())));

            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, unixTime);
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

        std::string JsonEscape(const std::string& value)
        {
            std::string out;
            out.reserve(value.size() + 8u);
            static const char* hex = "0123456789ABCDEF";
            for (unsigned char c : value)
            {
                switch (c)
                {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20u)
                    {
                        out += "\\u00";
                        out.push_back(hex[(c >> 4u) & 0xFu]);
                        out.push_back(hex[c & 0xFu]);
                    }
                    else
                    {
                        out.push_back(static_cast<char>(c));
                    }
                    break;
                }
            }
            return out;
        }

        struct StoredObjectStoreObject
        {
            std::string owner;
            std::string name;
            std::string contentBase64;
            std::string metadataJson;
            std::string objectJson;
            std::string checksum;
            std::string objectVersion;
            std::string context;
            std::string acl;
            std::string category;
            std::uint64_t contentLength = 0;
            std::int64_t expiresOn = 0;
            std::int64_t created = 0;
            std::int64_t modified = 0;
        };

        std::mutex g_objectStoreMutex;
        std::unordered_map<std::string, StoredObjectStoreObject> g_objectStoreObjects;

        std::string ObjectStoreKey(const std::string& owner, const std::string& name)
        {
            return owner + std::string(1, '\0') + name;
        }

        bool IsJsonWhitespace(char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }

        void SkipJsonWhitespace(const std::string& json, std::size_t& pos)
        {
            while (pos < json.size() && IsJsonWhitespace(json[pos]))
                ++pos;
        }

        bool ExtractHttpProxyJsonBody(const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
            std::string& method, std::string& url, std::string& jsonBody)
        {
            method.clear();
            url.clear();
            jsonBody.clear();

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
                if (field.wireType != 2u)
                    continue;

                const std::string value(reinterpret_cast<const char*>(field.bytes), field.bytesSize);
                if (field.tag == 1u)
                    method = value;
                else if (field.tag == 2u)
                    url = value;
                else if (field.tag == 3u)
                    jsonBody = value;
            }
            return !method.empty() && !url.empty();
        }

        bool ExtractJsonCompositeField(const std::string& json, const char* key,
            char openChar, char closeChar, std::string& value)
        {
            value.clear();
            if (!key || !*key)
                return false;

            const std::string needle = std::string("\"") + key + "\"";
            std::size_t pos = json.find(needle);
            if (pos == std::string::npos)
                return false;
            pos = json.find(':', pos + needle.size());
            if (pos == std::string::npos)
                return false;
            ++pos;
            SkipJsonWhitespace(json, pos);
            if (pos >= json.size() || json[pos] != openChar)
                return false;

            const std::size_t start = pos;
            bool inString = false;
            bool escaped = false;
            int depth = 0;
            for (; pos < json.size(); ++pos)
            {
                const char c = json[pos];
                if (inString)
                {
                    if (escaped)
                        escaped = false;
                    else if (c == '\\')
                        escaped = true;
                    else if (c == '"')
                        inString = false;
                    continue;
                }

                if (c == '"')
                {
                    inString = true;
                    continue;
                }
                if (c == openChar)
                    ++depth;
                else if (c == closeChar)
                {
                    --depth;
                    if (depth == 0)
                    {
                        ++pos;
                        value.assign(json, start, pos - start);
                        return true;
                    }
                }
            }
            return false;
        }

        bool ExtractJsonObjectArray(const std::string& json, const char* key,
            std::vector<std::string>& objects)
        {
            objects.clear();
            std::string arrayJson;
            if (!ExtractJsonCompositeField(json, key, '[', ']', arrayJson))
                return false;

            std::size_t pos = 1u;
            while (pos + 1u <= arrayJson.size())
            {
                while (pos < arrayJson.size() &&
                    (IsJsonWhitespace(arrayJson[pos]) || arrayJson[pos] == ','))
                    ++pos;
                if (pos >= arrayJson.size() || arrayJson[pos] == ']')
                    return true;
                if (arrayJson[pos] != '{')
                    return false;

                const std::size_t start = pos;
                bool inString = false;
                bool escaped = false;
                int depth = 0;
                for (; pos < arrayJson.size(); ++pos)
                {
                    const char c = arrayJson[pos];
                    if (inString)
                    {
                        if (escaped)
                            escaped = false;
                        else if (c == '\\')
                            escaped = true;
                        else if (c == '"')
                            inString = false;
                        continue;
                    }
                    if (c == '"')
                    {
                        inString = true;
                        continue;
                    }
                    if (c == '{')
                        ++depth;
                    else if (c == '}')
                    {
                        --depth;
                        if (depth == 0)
                        {
                            ++pos;
                            objects.emplace_back(arrayJson.substr(start, pos - start));
                            break;
                        }
                    }
                }
                if (depth != 0)
                    return false;
            }
            return true;
        }

        bool ExtractJsonStringField(const std::string& object, const char* key, std::string& value)
        {
            value.clear();
            if (!key || !*key)
                return false;

            const std::string needle = std::string("\"") + key + "\"";
            std::size_t pos = object.find(needle);
            if (pos == std::string::npos)
                return false;
            pos = object.find(':', pos + needle.size());
            if (pos == std::string::npos)
                return false;
            ++pos;
            SkipJsonWhitespace(object, pos);
            if (pos >= object.size() || object[pos] != '"')
                return false;
            ++pos;

            while (pos < object.size())
            {
                char c = object[pos++];
                if (c == '"')
                    return true;
                if (c != '\\')
                {
                    value.push_back(c);
                    continue;
                }
                if (pos >= object.size())
                    return false;
                const char e = object[pos++];
                switch (e)
                {
                case '"': value.push_back('"'); break;
                case '\\': value.push_back('\\'); break;
                case '/': value.push_back('/'); break;
                case 'b': value.push_back('\b'); break;
                case 'f': value.push_back('\f'); break;
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                default:
                    // The ObjectStore identifiers/metadata used by IW8 startup are ASCII.
                    return false;
                }
            }
            return false;
        }

        bool ExtractJsonInt64Field(const std::string& object, const char* key, std::int64_t& value)
        {
            value = 0;
            if (!key || !*key)
                return false;
            const std::string needle = std::string("\"") + key + "\"";
            std::size_t pos = object.find(needle);
            if (pos == std::string::npos)
                return false;
            pos = object.find(':', pos + needle.size());
            if (pos == std::string::npos)
                return false;
            ++pos;
            SkipJsonWhitespace(object, pos);
            if (pos >= object.size())
                return false;

            bool negative = false;
            if (object[pos] == '-')
            {
                negative = true;
                ++pos;
            }
            if (pos >= object.size() || object[pos] < '0' || object[pos] > '9')
                return false;

            std::uint64_t parsed = 0;
            while (pos < object.size() && object[pos] >= '0' && object[pos] <= '9')
            {
                const std::uint64_t digit = static_cast<std::uint64_t>(object[pos++] - '0');
                if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10u)
                    return false;
                parsed = parsed * 10u + digit;
            }
            if (negative)
            {
                if (parsed > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1u)
                    return false;
                value = parsed == static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1u
                    ? (std::numeric_limits<std::int64_t>::min)()
                    : -static_cast<std::int64_t>(parsed);
            }
            else
            {
                if (parsed > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
                    return false;
                value = static_cast<std::int64_t>(parsed);
            }
            return true;
        }

        bool ExtractJsonUInt64Field(const std::string& object, const char* key, std::uint64_t& value)
        {
            std::int64_t signedValue = 0;
            if (!ExtractJsonInt64Field(object, key, signedValue) || signedValue < 0)
                return false;
            value = static_cast<std::uint64_t>(signedValue);
            return true;
        }

        bool ExtractQueryParam(const std::string& url, const char* key, std::string& value)
        {
            value.clear();
            if (!key || !*key)
                return false;
            const std::string needle = std::string(key) + "=";
            std::size_t pos = url.find('?');
            if (pos == std::string::npos)
                return false;
            ++pos;
            while (pos < url.size())
            {
                const std::size_t amp = url.find('&', pos);
                const std::size_t end = amp == std::string::npos ? url.size() : amp;
                if (url.compare(pos, needle.size(), needle) == 0)
                {
                    value.assign(url, pos + needle.size(), end - (pos + needle.size()));
                    return true;
                }
                if (amp == std::string::npos)
                    break;
                pos = amp + 1u;
            }
            return false;
        }

        std::uint64_t Fnv1a64(const std::string& value, std::uint64_t seed = 1469598103934665603ull)
        {
            std::uint64_t hash = seed;
            for (unsigned char c : value)
            {
                hash ^= static_cast<std::uint64_t>(c);
                hash *= 1099511628211ull;
            }
            return hash;
        }

        std::string HexU64(std::uint64_t value)
        {
            static const char* digits = "0123456789abcdef";
            std::string out(16u, '0');
            for (int i = 15; i >= 0; --i)
            {
                out[static_cast<std::size_t>(i)] = digits[value & 0xFu];
                value >>= 4u;
            }
            return out;
        }

        std::string StableDigest32(const std::string& value)
        {
            const std::uint64_t h1 = Fnv1a64(value);
            const std::uint64_t h2 = Fnv1a64(value, 1099511628211ull ^ h1);
            return HexU64(h1) + HexU64(h2);
        }

        std::string Base64Encode(const std::string& bytes)
        {
            static const char table[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            out.reserve(((bytes.size() + 2u) / 3u) * 4u);
            std::size_t i = 0;
            while (i + 3u <= bytes.size())
            {
                const std::uint32_t n =
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16u) |
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1u])) << 8u) |
                    static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 2u]));
                out.push_back(table[(n >> 18u) & 63u]);
                out.push_back(table[(n >> 12u) & 63u]);
                out.push_back(table[(n >> 6u) & 63u]);
                out.push_back(table[n & 63u]);
                i += 3u;
            }
            const std::size_t remain = bytes.size() - i;
            if (remain == 1u)
            {
                const std::uint32_t n = static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16u;
                out.push_back(table[(n >> 18u) & 63u]);
                out.push_back(table[(n >> 12u) & 63u]);
                out += "==";
            }
            else if (remain == 2u)
            {
                const std::uint32_t n =
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16u) |
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1u])) << 8u);
                out.push_back(table[(n >> 18u) & 63u]);
                out.push_back(table[(n >> 12u) & 63u]);
                out.push_back(table[(n >> 6u) & 63u]);
                out.push_back('=');
            }
            return out;
        }

        std::size_t Base64DecodedLength(const std::string& base64)
        {
            if (base64.empty())
                return 0u;
            std::size_t useful = 0u;
            for (char c : base64)
            {
                if (!IsJsonWhitespace(c))
                    ++useful;
            }
            if (!useful)
                return 0u;
            std::size_t padding = 0u;
            for (std::size_t i = base64.size(); i > 0u && padding < 2u; --i)
            {
                const char c = base64[i - 1u];
                if (IsJsonWhitespace(c))
                    continue;
                if (c == '=')
                    ++padding;
                else
                    break;
            }
            return (useful / 4u) * 3u - (std::min)(padding, static_cast<std::size_t>(2u));
        }

        std::int64_t UnixTimeSeconds()
        {
            return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        }

        std::string BuildObjectStoreMetadataJson(const StoredObjectStoreObject& object)
        {
            std::string json = "{";
            json += "\"name\":\"" + JsonEscape(object.name) + "\",";
            json += "\"owner\":\"" + JsonEscape(object.owner) + "\",";
            json += "\"checksum\":\"" + JsonEscape(object.checksum) + "\",";
            json += "\"objectVersion\":\"" + JsonEscape(object.objectVersion) + "\",";
            json += "\"expiresOn\":" + std::to_string(object.expiresOn) + ",";
            json += "\"created\":" + std::to_string(object.created) + ",";
            json += "\"modified\":" + std::to_string(object.modified) + ",";
            json += "\"acl\":\"" + JsonEscape(object.acl) + "\",";
            json += "\"contentLength\":" + std::to_string(object.contentLength) + ",";
            json += "\"context\":\"" + JsonEscape(object.context) + "\",";
            if (object.category.empty())
                json += "\"category\":null";
            else
                json += "\"category\":\"" + JsonEscape(object.category) + "\"";
            json += "}";
            return json;
        }

        std::string BuildObjectStoreObjectJson(const StoredObjectStoreObject& object)
        {
            return std::string("{\"content\":\"") + JsonEscape(object.contentBase64) +
                "\",\"metadata\":" + object.metadataJson + "}";
        }

        bool ParseObjectStoreUploadObject(const std::string& objectJson, const std::string& url,
            const StoredObjectStoreObject* existing, StoredObjectStoreObject& stored)
        {
            std::string metadata;
            if (!ExtractJsonCompositeField(objectJson, "metadata", '{', '}', metadata))
                return false;

            std::string owner;
            std::string name;
            if (!ExtractJsonStringField(metadata, "owner", owner) ||
                !ExtractJsonStringField(metadata, "name", name))
            {
                // Some SDK serializers place the ID next to metadata. Accept that
                // stock-compatible form but never invent an owner/name.
                if (!ExtractJsonStringField(objectJson, "owner", owner) ||
                    !ExtractJsonStringField(objectJson, "name", name))
                    return false;
            }

            std::string content;
            if (!ExtractJsonStringField(objectJson, "content", content))
                return false;

            stored = {};
            stored.owner = owner;
            stored.name = name;
            stored.contentBase64 = content;

            ExtractJsonStringField(metadata, "checksum", stored.checksum);
            ExtractJsonStringField(metadata, "objectVersion", stored.objectVersion);
            ExtractJsonStringField(metadata, "context", stored.context);
            ExtractJsonStringField(metadata, "acl", stored.acl);
            ExtractJsonStringField(metadata, "category", stored.category);
            ExtractJsonInt64Field(metadata, "expiresOn", stored.expiresOn);
            ExtractJsonUInt64Field(metadata, "contentLength", stored.contentLength);

            if (stored.context.empty())
            {
                std::string queryContext;
                if (ExtractQueryParam(url, "context", queryContext))
                    stored.context = queryContext;
            }
            if (stored.context.empty())
                stored.context = "cod-shared";
            if (stored.acl.empty())
                stored.acl = "private";
            if (!stored.contentLength)
                stored.contentLength = Base64DecodedLength(stored.contentBase64);
            if (stored.checksum.empty())
                stored.checksum = StableDigest32(stored.contentBase64);

            const std::string versionMaterial = stored.owner + std::string(1, '\0') + stored.name +
                std::string(1, '\0') + stored.checksum + std::string(1, '\0') + stored.contentBase64;
            const std::string generatedVersion = StableDigest32(versionMaterial);

            const std::int64_t now = UnixTimeSeconds();
            if (existing && existing->contentBase64 == stored.contentBase64 && existing->checksum == stored.checksum)
            {
                stored.objectVersion = existing->objectVersion;
                stored.created = existing->created;
                stored.modified = existing->modified;
                if (stored.expiresOn == 0)
                    stored.expiresOn = existing->expiresOn;
            }
            else
            {
                stored.objectVersion = generatedVersion;
                stored.created = existing ? existing->created : now;
                stored.modified = now;
            }

            stored.metadataJson = BuildObjectStoreMetadataJson(stored);
            stored.objectJson = BuildObjectStoreObjectJson(stored);
            return true;
        }

        std::string BuildObjectStoreValidationToken(const StoredObjectStoreObject& object)
        {
            // Validation tokens are opaque to the IW8 client. The stock client only
            // base64-decodes and forwards them; the backend owns their meaning. Use a
            // deterministic local token bound to owner/name/version/checksum so later
            // validation can be implemented without capture replay or guessed bytes.
            const std::string raw = "RV-IW8-OBJVAL-1|" + object.owner + "|" + object.name + "|" +
                object.objectVersion + "|" + object.checksum;
            return Base64Encode(raw);
        }

        bool ParseObjectIdJson(const std::string& json,
            std::vector<std::pair<std::string, std::string>>& objectIds)
        {
            objectIds.clear();
            std::size_t pos = 0;
            SkipJsonWhitespace(json, pos);
            if (pos >= json.size() || json[pos] != '[')
                return false;

            ++pos;
            while (pos < json.size())
            {
                while (pos < json.size() && (IsJsonWhitespace(json[pos]) || json[pos] == ','))
                    ++pos;
                if (pos >= json.size())
                    return false;
                if (json[pos] == ']')
                    return true;
                if (json[pos] != '{')
                    return false;

                const std::size_t start = pos;
                bool inString = false;
                bool escaped = false;
                int depth = 0;
                for (; pos < json.size(); ++pos)
                {
                    const char c = json[pos];
                    if (inString)
                    {
                        if (escaped)
                            escaped = false;
                        else if (c == '\\')
                            escaped = true;
                        else if (c == '"')
                            inString = false;
                        continue;
                    }
                    if (c == '"')
                    {
                        inString = true;
                        continue;
                    }
                    if (c == '{')
                        ++depth;
                    else if (c == '}')
                    {
                        --depth;
                        if (depth == 0)
                        {
                            ++pos;
                            break;
                        }
                    }
                }
                if (depth != 0)
                    return false;

                const std::string object = json.substr(start, pos - start);
                std::string name;
                std::string owner;
                if (!ExtractJsonStringField(object, "name", name) ||
                    !ExtractJsonStringField(object, "owner", owner))
                    return false;
                objectIds.emplace_back(std::move(owner), std::move(name));
            }
            return false;
        }

        bool ExtractObjectStoreIds(const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
            std::vector<std::pair<std::string, std::string>>& objectIds)
        {
            objectIds.clear();
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
                if (field.tag != 4u || field.wireType != 2u)
                    continue;

                std::string key;
                std::string value;
                const std::uint8_t* hcur = field.bytes;
                const std::uint8_t* hend = field.bytes + field.bytesSize;
                while (hcur < hend)
                {
                    PbField headerField{};
                    if (!NextPbField(hcur, hend, headerField))
                        return false;
                    if (headerField.wireType != 2u)
                        continue;
                    if (headerField.tag == 1u)
                        key.assign(reinterpret_cast<const char*>(headerField.bytes), headerField.bytesSize);
                    else if (headerField.tag == 2u)
                        value.assign(reinterpret_cast<const char*>(headerField.bytes), headerField.bytesSize);
                }

                if (key == "DW-Objectstore-ObjectIDs")
                    return ParseObjectIdJson(value, objectIds);
            }
            return false;
        }

        std::string AddRequestIndexToJsonObject(const std::string& object, std::size_t requestIndex)
        {
            std::size_t pos = 0;
            SkipJsonWhitespace(object, pos);
            if (pos >= object.size() || object[pos] != '{')
                return {};

            std::string out;
            out.reserve(object.size() + 40u);
            out.append(object, 0u, pos + 1u);
            out += "\"requestIndex\":" + std::to_string(requestIndex);
            std::size_t next = pos + 1u;
            SkipJsonWhitespace(object, next);
            if (next < object.size() && object[next] != '}')
                out.push_back(',');
            out.append(object, pos + 1u, std::string::npos);
            return out;
        }

        void AppendRestProxyJsonStruct(std::vector<std::uint8_t>& serviceReply, const std::string& json)
        {
            std::vector<std::uint8_t> responseBody;
            std::vector<std::uint8_t> contentLengthHeader;
            AppendPbString(contentLengthHeader, 1u, "Content-Length");
            AppendPbString(contentLengthHeader, 2u, std::to_string(json.size()));
            AppendPbObject(responseBody, 1u, contentLengthHeader);

            std::vector<std::uint8_t> contentTypeHeader;
            AppendPbString(contentTypeHeader, 1u, "Content-Type");
            AppendPbString(contentTypeHeader, 2u, "application/json");
            AppendPbObject(responseBody, 1u, contentTypeHeader);

            AppendPbU64(responseBody, 2u, kHttpOk);
            AppendPbString(responseBody, 3u, json);
            AppendTypedStruct(serviceReply, responseBody);
        }

        bool AppendObjectStoreVectorizedStruct(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::vector<std::pair<std::string, std::string>> objectIds;
            if (!ExtractObjectStoreIds(requestPayload, requestPayloadBytes, objectIds))
                return false;

            std::vector<std::string> objectReplies;
            std::vector<std::string> errorReplies;
            std::size_t persistedCount = 0;
            {
                std::lock_guard<std::mutex> lock(g_objectStoreMutex);
                objectReplies.reserve(objectIds.size());
                errorReplies.reserve(objectIds.size());
                for (std::size_t i = 0; i < objectIds.size(); ++i)
                {
                    const auto it = g_objectStoreObjects.find(ObjectStoreKey(objectIds[i].first, objectIds[i].second));
                    if (it != g_objectStoreObjects.end())
                    {
                        std::string object = AddRequestIndexToJsonObject(it->second.objectJson, i);
                        if (!object.empty())
                        {
                            objectReplies.emplace_back(std::move(object));
                            continue;
                        }
                    }

                    // Vectorized GET requires exactly one entry across objects+errors
                    // for each requested slot, keyed by requestIndex.
                    errorReplies.emplace_back(
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"owner\":\"" + JsonEscape(objectIds[i].first) +
                        "\",\"name\":\"" + JsonEscape(objectIds[i].second) +
                        "\",\"error\":\"Error:ClientError:NotFound\"}");
                }
                persistedCount = g_objectStoreObjects.size();
            }

            std::string json = "{\"objects\":[";
            for (std::size_t i = 0; i < objectReplies.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += objectReplies[i];
            }
            json += "],\"errors\":[";
            for (std::size_t i = 0; i < errorReplies.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += errorReplies[i];
            }
            json += "]}";

            std::printf("[DW-OBJECTSTORE] GET requested=%zu hit=%zu miss=%zu persisted=%zu canonicalMetadata=yes\n",
                objectIds.size(), objectReplies.size(), errorReplies.size(), persistedCount);
            AppendRestProxyJsonStruct(serviceReply, json);
            return true;
        }

        bool AppendObjectStoreUploadVectorizedStruct(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::string method;
            std::string url;
            std::string requestJson;
            if (!ExtractHttpProxyJsonBody(requestPayload, requestPayloadBytes, method, url, requestJson) ||
                method != "PUT" || requestJson.empty())
                return false;

            std::vector<std::string> uploadedObjects;
            if (!ExtractJsonObjectArray(requestJson, "objects", uploadedObjects) || uploadedObjects.empty())
                return false;

            const bool validationRequested = url.find("validationToken") != std::string::npos ||
                ContainsAscii(requestPayload, requestPayloadBytes, "validationToken");
            std::vector<StoredObjectStoreObject> storedObjects;
            storedObjects.reserve(uploadedObjects.size());
            std::size_t persistedCount = 0;
            {
                std::lock_guard<std::mutex> lock(g_objectStoreMutex);
                for (const std::string& objectJson : uploadedObjects)
                {
                    std::string metadataJson;
                    if (!ExtractJsonCompositeField(objectJson, "metadata", '{', '}', metadataJson))
                        return false;

                    std::string owner;
                    std::string name;
                    if (!ExtractJsonStringField(metadataJson, "owner", owner) ||
                        !ExtractJsonStringField(metadataJson, "name", name))
                    {
                        if (!ExtractJsonStringField(objectJson, "owner", owner) ||
                            !ExtractJsonStringField(objectJson, "name", name))
                            return false;
                    }

                    const auto key = ObjectStoreKey(owner, name);
                    const auto existingIt = g_objectStoreObjects.find(key);
                    const StoredObjectStoreObject* existing = existingIt == g_objectStoreObjects.end()
                        ? nullptr : &existingIt->second;

                    StoredObjectStoreObject stored;
                    if (!ParseObjectStoreUploadObject(objectJson, url, existing, stored))
                        return false;
                    g_objectStoreObjects[key] = stored;
                    storedObjects.emplace_back(std::move(stored));
                }
                persistedCount = g_objectStoreObjects.size();
            }

            std::string json = "{\"objects\":[";
            for (std::size_t i = 0; i < storedObjects.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += "{\"metadata\":" + storedObjects[i].metadataJson + "}";
            }
            json += "],\"errors\":[],\"validationTokens\":[";
            if (validationRequested)
            {
                for (std::size_t i = 0; i < storedObjects.size(); ++i)
                {
                    if (i)
                        json.push_back(',');
                    json += "{\"owner\":\"" + JsonEscape(storedObjects[i].owner) +
                        "\",\"name\":\"" + JsonEscape(storedObjects[i].name) +
                        "\",\"validationToken\":\"" + JsonEscape(BuildObjectStoreValidationToken(storedObjects[i])) + "\"}";
                }
            }
            json += "]}";

            std::printf("[DW-OBJECTSTORE] PUT objects=%zu stored=%zu persisted=%zu metadata=%zu validationTokens=%zu\n",
                uploadedObjects.size(), storedObjects.size(), persistedCount, storedObjects.size(),
                validationRequested ? storedObjects.size() : 0u);

            AppendRestProxyJsonStruct(serviceReply, json);
            return true;
        }

        bool ExtractAchievementsRequestedKeys(const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes, std::string& context, std::vector<std::string>& keys)
        {
            context.clear();
            keys.clear();

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
                if (field.wireType != 2u)
                    continue;
                const std::string value(reinterpret_cast<const char*>(field.bytes), field.bytesSize);
                if (field.tag == 1u && context.empty())
                    context = value;
                else if (field.tag == 2u && !value.empty())
                    keys.push_back(value);
            }
            return !context.empty();
        }

        std::string FreshAchievementStateJsonValue(const std::string& key)
        {
            if (key == "br_tutorial_rewarded")
            {
                // Fresh-account tutorial rewards: no reward has been granted.
                return "{\"br_tutorial_reward_0\":false,\"br_tutorial_reward_1\":false,\"br_tutorial_reward_2\":false,\"br_tutorial_reward_3\":false}";
            }
            if (key == "games_of_summer_rewarded")
            {
                // Trial medals use integer enum values; 0 is the fresh/unearned state.
                return "{\"trial_0\":0,\"trial_1\":0,\"trial_2\":0,\"trial_3\":0,\"trial_4\":0,\"trial_5\":0}";
            }
            if (key.size() >= 6u && key.compare(key.size() - 6u, 6u, "_owned") == 0)
                return "false";

            // All expiry/count/rank/xp style fields consumed by the IW8
            // OnlineProgression bootstrap are numeric. Zero is a real fresh-account
            // value, not an empty/generic response.
            return "0";
        }

        bool AppendAchievementsUserStateStruct(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::string context;
            std::vector<std::string> keys;
            if (!ExtractAchievementsRequestedKeys(requestPayload, requestPayloadBytes, context, keys))
                return false;

            std::string json = "{";
            for (std::size_t i = 0; i < keys.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += "\"" + JsonEscape(keys[i]) + "\":" + FreshAchievementStateJsonValue(keys[i]);
            }
            json += "}";

            std::printf("[DW-ACHIEVEMENTS] getUserState context=%s requestedKeys=%zu response=fresh-account-state\n",
                context.c_str(), keys.size());

            std::vector<std::uint8_t> body;
            AppendPbString(body, 1u, json);
            AppendTypedStruct(serviceReply, body);
            return true;
        }

    }

    TaskRequest DecodeTaskRequest(const std::vector<std::uint8_t>& plain)
    {
        TaskRequest request{};
        if (plain.size() < 8u)
        {
            request.error = "plaintext shorter than Demonware typed task header";
            return request;
        }

        request.declaredBytes = ReadLe32(plain.data());
        request.innerType = plain[4];
        request.serviceId = plain[5];
        request.taskTypeTag = plain[6];
        request.taskId = plain[7];
        request.payloadOffset = 8u;

        if (request.innerType != kTaskRequestType)
        {
            request.error = "inner message is not TASK_REQUEST (0x86)";
            return request;
        }
        if (request.taskTypeTag != kBbUnsignedChar8)
        {
            request.error = "task id is not encoded as bdByteBuffer typed U8 (0x03)";
            return request;
        }
        if (request.declaredBytes < 3u)
        {
            request.error = "declared task size is smaller than service/type/task header";
            return request;
        }

        const std::size_t availableTaskBody = plain.size() - 5u;
        if (request.declaredBytes > availableTaskBody)
        {
            request.error = "declared task size exceeds decrypted plaintext";
            return request;
        }

        request.payloadBytes = static_cast<std::size_t>(request.declaredBytes - 3u);
        if (request.payloadBytes > plain.size() - request.payloadOffset)
        {
            request.error = "decoded parameter size exceeds decrypted plaintext";
            return request;
        }

        request.valid = true;
        return request;
    }

    const TaskRoute* FindTaskRoute(std::uint8_t serviceId, std::uint8_t taskId)
    {
        for (const auto& route : kRoutes)
        {
            if (route.serviceId == serviceId && route.taskId == taskId)
                return &route;
        }
        return nullptr;
    }

    std::string DescribeTaskRequest(const TaskRequest& request)
    {
        char buffer[384]{};
        const TaskRoute* route = request.valid ? FindTaskRoute(request.serviceId, request.taskId) : nullptr;
        if (!request.valid)
        {
            std::snprintf(buffer, sizeof(buffer),
                "valid=0 innerType=0x%02X service=%u taskType=0x%02X task=%u declared=%u error=%s",
                static_cast<unsigned>(request.innerType), static_cast<unsigned>(request.serviceId),
                static_cast<unsigned>(request.taskTypeTag), static_cast<unsigned>(request.taskId),
                request.declaredBytes, request.error.empty() ? "unknown" : request.error.c_str());
        }
        else
        {
            std::snprintf(buffer, sizeof(buffer),
                "valid=1 innerType=0x%02X service=%u(%s) taskType=0x%02X task=%u(%s) declared=%u payloadBytes=%llu",
                static_cast<unsigned>(request.innerType), static_cast<unsigned>(request.serviceId),
                route && route->serviceName ? route->serviceName : "unknown",
                static_cast<unsigned>(request.taskTypeTag), static_cast<unsigned>(request.taskId),
                route && route->taskName ? route->taskName : "unknown",
                request.declaredBytes, static_cast<unsigned long long>(request.payloadBytes));
        }
        return buffer;
    }

    bool BuildTaskReply(const TaskRoute& route, const TaskRequest& request,
        const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
        std::uint64_t transactionId, std::vector<std::uint8_t>& replyPlain)
    {
        replyPlain.clear();
        if (!request.valid || request.serviceId != route.serviceId || request.taskId != route.taskId)
            return false;
        if (requestPayloadBytes && !requestPayload)
            return false;

        std::vector<std::uint8_t> serviceReply;
        serviceReply.reserve(route.replyPolicy == ReplyPolicy::StructPublisherVariables ||
            route.replyPolicy == ReplyPolicy::StructObjectStoreVectorized ||
            route.replyPolicy == ReplyPolicy::StructObjectStoreUploadVectorized ? 1024u : 256u);

        AppendTypedU64(serviceReply, transactionId);
        AppendTypedU32(serviceReply, 0u); // BD_NO_ERROR
        AppendTypedU8(serviceReply, request.taskId);

        switch (route.replyPolicy)
        {
        case ReplyPolicy::NoResultSuccess:
            AppendTypedU32(serviceReply, 0u);
            break;

        case ReplyPolicy::LegacyDmlInfo:
            AppendLegacyDmlInfo(serviceReply);
            break;

        case ReplyPolicy::LegacyServerTime:
            AppendLegacyServerTime(serviceReply);
            break;

        case ReplyPolicy::StructMarketingMessagesEmpty:
        {
            // bdCommsGetMessagesResponse repeatedly reads bdCommsMessage objects
            // at StructBuffer tag 1 until TAG_NOT_FOUND. A local account with no
            // marketing inbox therefore has a canonical empty StructBuffer body.
            const std::vector<std::uint8_t> emptyBody;
            AppendTypedStruct(serviceReply, emptyBody);
            break;
        }

        case ReplyPolicy::StructClanMembershipsEmpty:
        {
            // bdClansGetMembershipsByUsersResponse reads an object array at tag 1.
            // Zero memberships is encoded by omitting tag 1 entirely.
            const std::vector<std::uint8_t> emptyBody;
            AppendTypedStruct(serviceReply, emptyBody);
            break;
        }

        case ReplyPolicy::StructMessagingUnsubscribeAck:
        {
            // channelUnsubscribeFromCategory is started with no bound response
            // object in stock IW8. Keep the struct-task acknowledgement empty
            // rather than routing it through a generic payload builder.
            const std::vector<std::uint8_t> emptyBody;
            AppendTypedStruct(serviceReply, emptyBody);
            break;
        }

        case ReplyPolicy::StructClanGroupInfosEmpty:
        {
            // Stock IW8 deserializes bdClansGetGroupInfosResponse with
            // readObjectArray<bdClansGroupInfo>(tag=1). Repeated fields encode a
            // zero-length array by omitting tag 1 entirely, so the canonical
            // fresh/local-account response body is an empty StructBuffer.
            const std::vector<std::uint8_t> emptyBody;
            AppendTypedStruct(serviceReply, emptyBody);
            break;
        }

        case ReplyPolicy::StructClanProposalsEmpty:
        {
            std::vector<std::uint8_t> body;
            AppendPbString(body, 2u, ""); // required nextPageToken; no tag-1 proposals
            AppendTypedStruct(serviceReply, body);
            break;
        }

        case ReplyPolicy::StructPublisherVariables:
            if (!AppendPublisherVariablesStruct(serviceReply, requestPayload, requestPayloadBytes))
                return false;
            break;

        case ReplyPolicy::StructObjectStoreVectorized:
            if (!AppendObjectStoreVectorizedStruct(serviceReply, requestPayload, requestPayloadBytes))
                return false;
            break;

        case ReplyPolicy::StructObjectStoreUploadVectorized:
            if (!AppendObjectStoreUploadVectorizedStruct(serviceReply, requestPayload, requestPayloadBytes))
                return false;
            break;

        case ReplyPolicy::StructAchievementsUserState:
            if (!AppendAchievementsUserStateStruct(serviceReply, requestPayload, requestPayloadBytes))
                return false;
            break;

        case ReplyPolicy::RestJsonSuccess:
            if (!AppendRestJsonResult(serviceReply, requestPayload, requestPayloadBytes, transactionId))
                return false;
            break;

        case ReplyPolicy::None:
        default:
            return false;
        }

        if (serviceReply.size() > (std::numeric_limits<std::uint32_t>::max)())
            return false;

        AppendLe32(replyPlain, static_cast<std::uint32_t>(serviceReply.size()));
        replyPlain.push_back(kTaskReplyType);
        replyPlain.insert(replyPlain.end(), serviceReply.begin(), serviceReply.end());
        replyPlain.resize((replyPlain.size() + 15u) & ~static_cast<std::size_t>(15u), 0u);
        return true;
    }
}
