#include "RestBootstrap.h"
#include "../../Web/WebAuthService.h"
#include "../../LocalPublisherContent.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        // Shared serializer defined in Internal/JsonObjectStoreParsing.cpp.
        std::string Base64Encode(const std::string& bytes);

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
            UserPresenceSet,
            UserEventsReportBatch,
            ObjectStoreGetUserObjects,
            ObjectStorePutUserObjects,
            AccountSearchUno,
            UserAuthenticate,
            UserLink,
            ProfanityFilterVerifyString,
            UsersStructuredDataGet,
            PublisherObjectMetadataGet,
            ClanMembershipsGet,
            UserTfaStatusGet,
            FirstPartySkusGet,
        };

        RestBootstrapKind ClassifyRestBootstrap(const std::uint8_t* payload, std::size_t payloadBytes)
        {
            if (ContainsAscii(payload, payloadBytes, "UserLists") &&
                ContainsAscii(payload, payloadBytes, "get_user_list"))
                return RestBootstrapKind::UserListsGetUserList;

            if (ContainsAscii(payload, payloadBytes, "Friends") &&
                (ContainsAscii(payload, payloadBytes, "get_friends_v1") ||
                 ContainsAscii(payload, payloadBytes, "get_friends")))
                return RestBootstrapKind::FriendsGetFriends;

            if (ContainsAscii(payload, payloadBytes, "Friends") &&
                (ContainsAscii(payload, payloadBytes, "get_pending_friend_requests_v1") ||
                 ContainsAscii(payload, payloadBytes, "get_pending_friend_requests")))
                return RestBootstrapKind::FriendsGetPending;

            // 1.20 emits the legacy operation name while later IW8 builds use
            // set_user_presence_v3. bdSetUserPresenceResponse::handleReplySuccess
            // does not require a response body beyond a successful REST reply.
            if (ContainsAscii(payload, payloadBytes, "UserPresence") &&
                (ContainsAscii(payload, payloadBytes, "set_user_presence_v3") ||
                 ContainsAscii(payload, payloadBytes, "set_user_presence")))
                return RestBootstrapKind::UserPresenceSet;

            // Retail uses bdRESTTaskManager for the same vectorized user-object
            // bootstrap that older IW8 paths submit as service 0xC1/task 6.
            // The response contract is bdObjectStoreGetUserObjectsVectorizedResponse:
            // objects[] + errors[] must contain exactly one entry per requested ID.
            if (ContainsAscii(payload, payloadBytes, "VectorizedUserObjectsResource") &&
                ContainsAscii(payload, payloadBytes, "get_objects") &&
                ContainsAscii(payload, payloadBytes, "DW-Objectstore-ObjectIDs"))
                return RestBootstrapKind::ObjectStoreGetUserObjects;

            // Fresh-account stats initialization immediately follows get_objects
            // with this vectorized upload.  Stock
            // bdObjectStoreUploadUserObjectsVectorizedResponse::handleReplySuccess
            // requires the JSON response to contain objects[], errors[], and
            // validationTokens[].  All three arrays may be empty; the IW8 stats
            // completion path treats an empty validation-token list as a normal
            // successful upload and simply skips leaderboard validation work.
            if (ContainsAscii(payload, payloadBytes, "VectorizedUserObjectsResource") &&
                ContainsAscii(payload, payloadBytes, "put_objects"))
                return RestBootstrapKind::ObjectStorePutUserObjects;

            // Retail social bootstrap batches platform account IDs through
            // Umbrella to resolve cross-platform/UNO identities.  For the local
            // offline backend we intentionally return an empty mapping rather
            // than inventing identities for arbitrary Steam accounts.
            if (ContainsAscii(payload, payloadBytes, "AccountSearchesResource") &&
                ContainsAscii(payload, payloadBytes, "unoaccountsearch"))
                return RestBootstrapKind::AccountSearchUno;

            // Existing-account login. Stock bdAuthenticateCrossPlatformUserResponse
            // needs unoID and bdLoginAndLink additionally requires all three UNO
            // token strings to be non-empty before it advances to account linking.
            if (ContainsAscii(payload, payloadBytes, "UserResource") &&
                ContainsAscii(payload, payloadBytes, "authenticateUser") &&
                ContainsAscii(payload, payloadBytes, "/v1.0/auth/"))
                return RestBootstrapKind::UserAuthenticate;

            // The immediately following bdLoginAndLink step links that UNO account
            // to the already-established Umbrella identity.
            if (ContainsAscii(payload, payloadBytes, "UserResource") &&
                ContainsAscii(payload, payloadBytes, "linkUser") &&
                ContainsAscii(payload, payloadBytes, "/v1.0/users/crossplatform/"))
                return RestBootstrapKind::UserLink;

            // Retail migrated the old bdTitleUtilities::verifyString check to
            // bdRESTLegacy.  A missing route is treated by the frontend as a
            // failed/inappropriate display-name check.  Match only the exact
            // moderation operation so unrelated REST requests keep their normal
            // terminal 404 behavior.
            if (ContainsAscii(payload, payloadBytes, "ProfanityFilter") &&
                ContainsAscii(payload, payloadBytes, "get_verify_string") &&
                ContainsAscii(payload, payloadBytes, "/v1/profanity-filter/verify/"))
                return RestBootstrapKind::ProfanityFilterVerifyString;

            // Retail asks for the cod-shared-profile through the structured-data
            // REST service after login.  Returning 404 here leaves the local UNO
            // identity authenticated but without the game-profile record that the
            // frontend expects for an already-established player.
            if (ContainsAscii(payload, payloadBytes, "UsersStructuredData") &&
                ContainsAscii(payload, payloadBytes, "get_structured_data") &&
                ContainsAscii(payload, payloadBytes, "/v1/users/structured-data/list/") &&
                ContainsAscii(payload, payloadBytes, "cod-shared-profile"))
                return RestBootstrapKind::UsersStructuredDataGet;

            // Retail update/content bootstrap uses the REST migration of
            // bdObjectStoreGetPublisherObjectMetadatasResponse.  This is the
            // operation behind "Checking for update..." for store_v2.json,
            // patch/comms manifests, and the unified playlist aggregate.
            if (ContainsAscii(payload, payloadBytes, "VectorizedPublisherObjectMetadataResource") &&
                ContainsAscii(payload, payloadBytes, "get_metadata") &&
                ContainsAscii(payload, payloadBytes, "/v1/core/publishers/objects/metadata/") &&
                ContainsAscii(payload, payloadBytes, "DW-Objectstore-ObjectIDs"))
                return RestBootstrapKind::PublisherObjectMetadataGet;

            // Retail asks for clan memberships even when the user is not in a
            // clan. A 404 leaves the generated clan REST client in an error
            // state, while an empty members array is a valid local/offline
            // result.
            if (ContainsAscii(payload, payloadBytes, "MembersResource") &&
                ContainsAscii(payload, payloadBytes, "get_memberships") &&
                ContainsAscii(payload, payloadBytes, "/v1/users/clans/"))
                return RestBootstrapKind::ClanMembershipsGet;

            // Existing UNO accounts query two-factor state during frontend
            // bootstrap. Local preservation accounts intentionally do not use
            // TFA, so return the stock boolean field as false.
            if (ContainsAscii(payload, payloadBytes, "UserResource") &&
                ContainsAscii(payload, payloadBytes, "getTfaStatus") &&
                ContainsAscii(payload, payloadBytes, "/tfa/"))
                return RestBootstrapKind::UserTfaStatusGet;

            // Steam storefront bootstrap asks Exchange for first-party SKU
            // mappings. Offline/local mode has no platform purchases to map,
            // so an empty firstPartySKUs array is the neutral successful
            // response.
            if (ContainsAscii(payload, payloadBytes, "first_party_skus") &&
                ContainsAscii(payload, payloadBytes, "get_first_party_skus") &&
                ContainsAscii(payload, payloadBytes, "/v2/exchange/first_party_skus/"))
                return RestBootstrapKind::FirstPartySkusGet;

            // Achievement-engine login telemetry.  The stock
            // bdReportUserEventsResponse::handleReplySuccess parser requires a
            // JSON object containing the allSucceeded boolean.  Leaving this
            // request unanswered also used to desynchronize the inferred legacy
            // transaction ids for every task after it.
            if ((ContainsAscii(payload, payloadBytes, "user_events") &&
                 ContainsAscii(payload, payloadBytes, "report_user_events_batch")) ||
                ContainsAscii(payload, payloadBytes, "/v2/user-events/$batch/"))
                return RestBootstrapKind::UserEventsReportBatch;

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


        std::string JsonEscapeRest(const std::string& value)
        {
            std::string out;
            out.reserve(value.size() + 8u);
            for (const unsigned char ch : value)
            {
                switch (ch)
                {
                case '\\': out += "\\\\"; break;
                case '"': out += "\\\""; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (ch >= 0x20u && ch <= 0x7Eu)
                        out.push_back(static_cast<char>(ch));
                    break;
                }
            }
            return out;
        }

        bool ExtractQuotedJsonValue(const std::string& object, const char* key, std::string& value)
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
            pos = object.find('"', pos + 1u);
            if (pos == std::string::npos)
                return false;
            ++pos;

            bool escaped = false;
            while (pos < object.size())
            {
                const char ch = object[pos++];
                if (escaped)
                {
                    value.push_back(ch);
                    escaped = false;
                    continue;
                }
                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }
                if (ch == '"')
                    return !value.empty();
                if (static_cast<unsigned char>(ch) < 0x20u)
                    return false;
                value.push_back(ch);
                if (value.size() > 256u)
                    return false;
            }
            return false;
        }

        bool ExtractRestObjectStoreIds(const std::uint8_t* payload, std::size_t payloadBytes,
            std::vector<std::pair<std::string, std::string>>& objectIds)
        {
            objectIds.clear();
            if (!payload || !payloadBytes)
                return false;

            static constexpr const char* marker = "DW-Objectstore-ObjectIDs";
            const std::size_t markerBytes = std::char_traits<char>::length(marker);
            const auto* begin = payload;
            const auto* end = payload + payloadBytes;
            const auto* markerPos = std::search(begin, end,
                reinterpret_cast<const std::uint8_t*>(marker),
                reinterpret_cast<const std::uint8_t*>(marker) + markerBytes);
            if (markerPos == end)
                return false;

            const auto* jsonBegin = std::find(markerPos + markerBytes, end, static_cast<std::uint8_t>('['));
            if (jsonBegin == end)
                return false;

            const auto* cursor = jsonBegin + 1u;
            while (cursor < end && objectIds.size() < 64u)
            {
                while (cursor < end && (*cursor == ',' || *cursor == ' ' || *cursor == '\r' || *cursor == '\n' || *cursor == '\t'))
                    ++cursor;
                if (cursor == end)
                    return false;
                if (*cursor == ']')
                    return !objectIds.empty();
                if (*cursor != '{')
                    return false;

                const auto* objectStart = cursor;
                bool inString = false;
                bool escaped = false;
                int depth = 0;
                for (; cursor < end; ++cursor)
                {
                    const char ch = static_cast<char>(*cursor);
                    if (inString)
                    {
                        if (escaped)
                            escaped = false;
                        else if (ch == '\\')
                            escaped = true;
                        else if (ch == '"')
                            inString = false;
                        continue;
                    }
                    if (ch == '"')
                    {
                        inString = true;
                        continue;
                    }
                    if (ch == '{')
                        ++depth;
                    else if (ch == '}')
                    {
                        --depth;
                        if (depth == 0)
                        {
                            ++cursor;
                            break;
                        }
                    }
                }
                if (depth != 0)
                    return false;

                const std::string object(reinterpret_cast<const char*>(objectStart),
                    static_cast<std::size_t>(cursor - objectStart));
                std::string name;
                std::string owner;
                if (!ExtractQuotedJsonValue(object, "name", name) ||
                    !ExtractQuotedJsonValue(object, "owner", owner))
                    return false;
                objectIds.emplace_back(std::move(owner), std::move(name));
            }
            return false;
        }

        std::uint64_t RestPublisherFnv1a64(const std::string& value,
            std::uint64_t seed = 1469598103934665603ull)
        {
            std::uint64_t hash = seed;
            for (const unsigned char c : value)
            {
                hash ^= static_cast<std::uint64_t>(c);
                hash *= 1099511628211ull;
            }
            return hash;
        }

        std::string RestPublisherHexU64(std::uint64_t value)
        {
            static constexpr char digits[] = "0123456789abcdef";
            std::string out(16u, '0');
            for (int i = 15; i >= 0; --i)
            {
                out[static_cast<std::size_t>(i)] = digits[value & 0xFu];
                value >>= 4u;
            }
            return out;
        }

        std::string RestPublisherDigest32(const std::string& value)
        {
            const std::uint64_t h1 = RestPublisherFnv1a64(value);
            const std::uint64_t h2 = RestPublisherFnv1a64(
                value, 1099511628211ull ^ h1);
            return RestPublisherHexU64(h1) + RestPublisherHexU64(h2);
        }

        bool RestPublisherContentForObject(const std::string& name,
            std::string& content, const char*& contentType)
        {
            content.clear();
            contentType = "application/octet-stream";

            if (localpublisher::IsManifest(name))
            {
                contentType = "application/json; charset=utf-8";
                return localpublisher::LoadManifest(name, content);
            }

            if (localpublisher::IsPlaylist(name))
            {
                content = localpublisher::PlaylistBody();
                contentType = "application/octet-stream";
                return true;
            }
            // Retail fetches this list during frontend bootstrap and retries
            // when metadata advertises NotFound. The local publisher and HTTP
            // content router already provide its neutral, one-LF-byte body;
            // expose that identical body through the Retail REST metadata path.
            if (localpublisher::IsContentCreatorList(name))
            {
                content = localpublisher::ContentCreatorListBody();
                contentType = "text/plain; charset=utf-8";
                return true;
            }

            if (name == "store_v2.json" || name == "store_v2_warzone.json")
            {
                // Neutral local store layout. The store itself is not required
                // for offline gameplay; Retail only needs a valid existing
                // publisher object while update/store bootstrap completes.
                content = localpublisher::RetailStoreBody();
                contentType = "application/json; charset=utf-8";
                return true;
            }

            // Retail requests these two Raven objects by their hashed/numeric
            // publisher names during frontend bootstrap. Returning per-object
            // NotFound leaves that publisher-object stage unresolved and the
            // client requests them again on later bootstrap passes.
            //
            // Their exact production payload is not required by the local
            // preservation backend. Supply a valid neutral JSON object so the
            // native ObjectStore pipeline gets a real metadata hit + HTTP
            // content object and can complete the request normally.
            if (name == "12114594447999834387" ||
                name == "371105840287708794")
            {
                content = "{}";
                contentType = "application/json; charset=utf-8";
                return true;
            }

            return false;
        }

        std::string BuildRestPublisherMetadataBody(
            const std::uint8_t* payload, std::size_t payloadBytes)
        {
            std::vector<std::pair<std::string, std::string>> objectIds;
            if (!ExtractRestObjectStoreIds(payload, payloadBytes, objectIds) ||
                objectIds.empty())
            {
                return {};
            }

            const std::string context = ExtractAsciiQueryValue(
                payload, payloadBytes, "context", "5800");

            constexpr std::int64_t publishedAt = 1760000000ll;
            constexpr std::int64_t expiresOn = 2075360000ll;

            std::string objects;
            std::string errors;
            std::size_t hitCount = 0;
            std::size_t missCount = 0;

            for (std::size_t i = 0; i < objectIds.size(); ++i)
            {
                const std::string& owner = objectIds[i].first;
                const std::string& name = objectIds[i].second;

                std::string content;
                const char* contentType = nullptr;
                const bool allowedOwner =
                    owner == "raven" || owner == "infinityward";
                const bool available =
                    allowedOwner &&
                    RestPublisherContentForObject(name, content, contentType);

                if (available)
                {
                    // Text publisher assets follow the SHA-1/Base64 metadata
                    // contract verified with native manifests. Keep the older
                    // synthetic hashes on other Retail objects unchanged.
                    const bool sha1Content = localpublisher::IsManifest(name) ||
                        localpublisher::IsContentCreatorList(name);
                    const std::string checksum = sha1Content
                        ? localpublisher::retailsigning::ManifestSha1ChecksumBase64(content)
                        : RestPublisherDigest32(content);
                    const std::string objectVersion = RestPublisherDigest32(
                        owner + std::string(1u, '\0') +
                        name + std::string(1u, '\0') + checksum);
                    const std::string contentUrl =
                        std::string("https://objectstore.prod.demonware.net/"
                            "__revamped/objectstore/publisher/") +
                        owner + "/" + name;

                    if (!objects.empty())
                        objects.push_back(',');

                    // The 1.20 manifest metadata path includes a nonzero
                    // numeric objectID; the Retail REST path previously omitted
                    // it even though both paths serve the same object types.
                    // Keep the IDs identical across both native transports.
                    const bool isManifest = localpublisher::IsManifest(name);
                    const std::string manifestObjectId = !isManifest ? std::string{} :
                        (name.find("_manifest_patch_") != std::string::npos
                            ? std::string("\"objectID\":120001,")
                            : std::string("\"objectID\":120002,"));

                    objects +=
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"metadata\":{" + manifestObjectId +
                        "\"name\":\"" + JsonEscapeRest(name) + "\","
                        "\"owner\":\"" + JsonEscapeRest(owner) + "\","
                        "\"checksum\":\"" + JsonEscapeRest(checksum) + "\","
                        "\"objectVersion\":\"" + JsonEscapeRest(objectVersion) + "\","
                        "\"expiresOn\":" + std::to_string(expiresOn) + ","
                        "\"created\":" + std::to_string(publishedAt) + ","
                        "\"modified\":" + std::to_string(publishedAt) + ","
                        "\"acl\":\"public\","
                        "\"contentLength\":" + std::to_string(content.size()) + ","
                        "\"context\":\"" + JsonEscapeRest(context) + "\"," +
                        (localpublisher::IsManifest(name)
                            ? std::string("\"category\":\"1\",")
                            : std::string("\"category\":null,")) +
                        "\"contentURL\":\"" + JsonEscapeRest(contentUrl) + "\""
                        "}}";

                    ++hitCount;
                    std::printf(
                        "[DW-REST-PUBLISHER] index=%zu owner=%s name=%s "
                        "response=metadata-success bytes=%zu objectID=%u "
                        "category=%s checksum=%s url=%s\n",
                        i, owner.c_str(), name.c_str(), content.size(),
                        isManifest ? (name.find("_manifest_patch_") != std::string::npos
                            ? 120001u : 120002u) : 0u,
                        isManifest ? "1" : "null", checksum.c_str(),
                        contentUrl.c_str());
                }
                else
                {
                    if (!errors.empty())
                        errors.push_back(',');

                    errors +=
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"owner\":\"" + JsonEscapeRest(owner) + "\","
                        "\"name\":\"" + JsonEscapeRest(name) + "\","
                        "\"error\":\"Error:ClientError:NotFound\"}";

                    ++missCount;
                    std::printf(
                        "[DW-REST-PUBLISHER] index=%zu owner=%s name=%s "
                        "response=per-object-not-found\n",
                        i, owner.c_str(), name.c_str());
                }
            }

            std::printf(
                "[DW-REST-PUBLISHER] "
                "resource=VectorizedPublisherObjectMetadataResource/get_metadata "
                "requested=%zu hit=%zu miss=%zu context=%s "
                "response=success fifo=preserved\n",
                objectIds.size(), hitCount, missCount, context.c_str());

            return std::string("{\"objects\":[") + objects +
                "],\"errors\":[" + errors + "]}";
        }

        struct RestStoredUserObject
        {
            std::string owner;
            std::string name;
            std::string contentBase64;
            std::string checksum;
            std::string objectVersion;
            std::uint64_t contentLength = 0;
            std::int64_t created = 0;
            std::int64_t modified = 0;
        };

        std::mutex g_restUserObjectMutex;
        std::vector<RestStoredUserObject> g_restUserObjects;
        bool g_restUserObjectsLoaded = false;

        std::filesystem::path RestUserObjectPath()
        {
            return std::filesystem::current_path() / "ReplayDWData" /
                "retail-user-objectstore" / "objects.bin";
        }

        bool ReadRestObjectString(std::ifstream& in, std::string& out,
            std::uint32_t maxLength)
        {
            std::uint32_t length = 0;
            if (!in.read(reinterpret_cast<char*>(&length), sizeof(length)) || length > maxLength)
                return false;
            out.resize(length);
            return !length || static_cast<bool>(in.read(out.data(), length));
        }

        void WriteRestObjectString(std::ofstream& out, const std::string& value)
        {
            const auto length = static_cast<std::uint32_t>(value.size());
            out.write(reinterpret_cast<const char*>(&length), sizeof(length));
            out.write(value.data(), length);
        }

        // Caller holds g_restUserObjectMutex. Never accept arbitrary filenames
        // from game requests: all identities are fields inside this one store.
        void LoadRestUserObjectsLocked()
        {
            if (g_restUserObjectsLoaded)
                return;
            g_restUserObjectsLoaded = true;
            std::ifstream in(RestUserObjectPath(), std::ios::binary);
            if (!in)
                return;
            std::uint32_t magic = 0, count = 0;
            if (!in.read(reinterpret_cast<char*>(&magic), 4) || magic != 0x32575352u ||
                !in.read(reinterpret_cast<char*>(&count), 4) || count > 2048u)
                return;
            std::vector<RestStoredUserObject> restored;
            for (std::uint32_t i = 0; i < count; ++i)
            {
                RestStoredUserObject item;
                if (!ReadRestObjectString(in, item.owner, 256u) ||
                    !ReadRestObjectString(in, item.name, 256u) ||
                    !ReadRestObjectString(in, item.contentBase64, 65536u) ||
                    !ReadRestObjectString(in, item.checksum, 256u) ||
                    !ReadRestObjectString(in, item.objectVersion, 256u) ||
                    !in.read(reinterpret_cast<char*>(&item.contentLength), 8) ||
                    !in.read(reinterpret_cast<char*>(&item.created), 8) ||
                    !in.read(reinterpret_cast<char*>(&item.modified), 8))
                    return; // Never publish a partially parsed store.
                restored.emplace_back(std::move(item));
            }
            g_restUserObjects = std::move(restored);
            std::printf("[DW-REST-OBJECTSTORE] loaded persisted objects=%zu\n",
                g_restUserObjects.size());
        }

        bool SaveRestUserObjectsLocked()
        {
            if (g_restUserObjects.size() > 2048u)
                return false;
            std::error_code ec;
            const auto path = RestUserObjectPath();
            std::filesystem::create_directories(path.parent_path(), ec);
            if (ec)
                return false;
            const auto temporary = path.string() + ".tmp";
            {
                std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
                if (!out)
                    return false;
                const std::uint32_t magic = 0x32575352u;
                const auto count = static_cast<std::uint32_t>(g_restUserObjects.size());
                out.write(reinterpret_cast<const char*>(&magic), 4);
                out.write(reinterpret_cast<const char*>(&count), 4);
                for (const auto& item : g_restUserObjects)
                {
                    if (item.owner.size() > 256u || item.name.size() > 256u ||
                        item.contentBase64.size() > 65536u ||
                        item.checksum.size() > 256u || item.objectVersion.size() > 256u)
                        return false;
                    WriteRestObjectString(out, item.owner);
                    WriteRestObjectString(out, item.name);
                    WriteRestObjectString(out, item.contentBase64);
                    WriteRestObjectString(out, item.checksum);
                    WriteRestObjectString(out, item.objectVersion);
                    out.write(reinterpret_cast<const char*>(&item.contentLength), 8);
                    out.write(reinterpret_cast<const char*>(&item.created), 8);
                    out.write(reinterpret_cast<const char*>(&item.modified), 8);
                }
                out.flush();
                if (!out)
                    return false;
            }
            // Windows rename does not replace an existing destination. Back up
            // the previous good file before publishing the new store.
            auto backup = path;
            backup += ".bak";
            std::filesystem::remove(backup, ec);
            ec.clear();
            if (std::filesystem::exists(path))
            {
                std::filesystem::rename(path, backup, ec);
                if (ec)
                    return false;
            }
            std::filesystem::rename(temporary, path, ec);
            if (ec)
            {
                std::error_code ignored;
                if (std::filesystem::exists(backup))
                    std::filesystem::rename(backup, path, ignored);
                return false;
            }
            return true;
        }

        std::uint64_t RestBase64DecodedLength(const std::string& value)
        {
            if (value.empty())
                return 0;

            std::size_t useful = value.size();
            while (useful && (value[useful - 1u] == '\r' ||
                              value[useful - 1u] == '\n' ||
                              value[useful - 1u] == ' ' ||
                              value[useful - 1u] == '\t'))
            {
                --useful;
            }

            std::size_t padding = 0;
            if (useful && value[useful - 1u] == '=')
            {
                ++padding;
                if (useful > 1u && value[useful - 2u] == '=')
                    ++padding;
            }

            if (useful < padding)
                return 0;

            return static_cast<std::uint64_t>((useful / 4u) * 3u - padding);
        }

        bool ExtractRestJsonObjectArray(const std::uint8_t* payload,
            std::size_t payloadBytes, const char* fieldName,
            std::vector<std::string>& objects)
        {
            objects.clear();
            if (!payload || !payloadBytes || !fieldName || !*fieldName)
                return false;

            const std::string marker = std::string("\"") + fieldName + "\"";
            const auto* begin = payload;
            const auto* end = payload + payloadBytes;
            const auto* markerPos = std::search(
                begin, end,
                reinterpret_cast<const std::uint8_t*>(marker.data()),
                reinterpret_cast<const std::uint8_t*>(marker.data()) + marker.size());
            if (markerPos == end)
                return false;

            const auto* arrayPos = std::find(
                markerPos + marker.size(), end, static_cast<std::uint8_t>('['));
            if (arrayPos == end)
                return false;

            const auto* cursor = arrayPos + 1u;
            while (cursor < end)
            {
                while (cursor < end &&
                       (*cursor == ',' || *cursor == ' ' || *cursor == '\r' ||
                        *cursor == '\n' || *cursor == '\t'))
                {
                    ++cursor;
                }

                if (cursor == end)
                    return false;
                if (*cursor == ']')
                    return true;
                if (*cursor != '{')
                    return false;

                const auto* objectStart = cursor;
                bool inString = false;
                bool escaped = false;
                int depth = 0;

                for (; cursor < end; ++cursor)
                {
                    const char ch = static_cast<char>(*cursor);

                    if (inString)
                    {
                        if (escaped)
                            escaped = false;
                        else if (ch == '\\')
                            escaped = true;
                        else if (ch == '"')
                            inString = false;
                        continue;
                    }

                    if (ch == '"')
                    {
                        inString = true;
                        continue;
                    }

                    if (ch == '{')
                        ++depth;
                    else if (ch == '}')
                    {
                        --depth;
                        if (depth == 0)
                        {
                            ++cursor;
                            break;
                        }
                    }
                }

                if (depth != 0)
                    return false;

                objects.emplace_back(
                    reinterpret_cast<const char*>(objectStart),
                    static_cast<std::size_t>(cursor - objectStart));

                if (objects.size() > 64u)
                    return false;
            }

            return false;
        }

        bool ExtractLargeQuotedJsonValue(const std::string& object,
            const char* key, std::string& value)
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

            pos = object.find('"', pos + 1u);
            if (pos == std::string::npos)
                return false;
            ++pos;

            bool escaped = false;
            while (pos < object.size())
            {
                const char ch = object[pos++];

                if (escaped)
                {
                    // The content field is base64 in current IW8 requests and
                    // normally contains no JSON escapes, but preserve ordinary
                    // escaped characters for robustness.
                    value.push_back(ch);
                    escaped = false;
                    continue;
                }

                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (ch == '"')
                    return true;

                if (static_cast<unsigned char>(ch) < 0x20u)
                    return false;

                value.push_back(ch);

                // Retail's DDL blobs are much larger than the 256-byte limit of
                // ExtractQuotedJsonValue(), so allow a full ObjectStore-sized
                // payload while still bounding malformed input.
                if (value.size() > 65536u)
                    return false;
            }

            return false;
        }

        bool StoreRestUserObjectsFromPut(const std::uint8_t* payload,
            std::size_t payloadBytes)
        {
            std::vector<std::string> uploaded;
            if (!ExtractRestJsonObjectArray(payload, payloadBytes, "objects", uploaded) ||
                uploaded.empty())
            {
                return false;
            }

            std::vector<RestStoredUserObject> parsed;
            parsed.reserve(uploaded.size());

            constexpr std::int64_t now = 1760000000ll;

            for (const std::string& objectJson : uploaded)
            {
                RestStoredUserObject object;

                // Object contents are base64 DDL blobs and regularly exceed
                // 256 bytes. ExtractQuotedJsonValue() is intentionally capped
                // at 256 for small metadata/query fields, so use the large
                // bounded extractor for content.
                if (!ExtractLargeQuotedJsonValue(objectJson, "content", object.contentBase64) ||
                    !ExtractQuotedJsonValue(objectJson, "name", object.name) ||
                    !ExtractQuotedJsonValue(objectJson, "owner", object.owner))
                {
                    std::printf(
                        "[DW-REST-OBJECTSTORE] PUT parse=failed reason=object-fields "
                        "objectBytes=%zu\n",
                        objectJson.size());
                    return false;
                }

                // The client-generated first-run objects generally carry an empty
                // checksum. Generate deterministic local metadata for the later
                // GET so bdObjectStoreMetadata::deserializeFromJSON receives every
                // required field.
                object.checksum = RestPublisherDigest32(object.contentBase64);
                object.objectVersion = RestPublisherDigest32(
                    object.owner + std::string(1u, '\0') +
                    object.name + std::string(1u, '\0') +
                    object.checksum);
                object.contentLength = RestBase64DecodedLength(object.contentBase64);
                object.created = now;
                object.modified = now;

                parsed.emplace_back(std::move(object));
            }

            std::lock_guard<std::mutex> lock(g_restUserObjectMutex);
            LoadRestUserObjectsLocked();

            for (RestStoredUserObject& object : parsed)
            {
                bool replaced = false;
                for (RestStoredUserObject& existing : g_restUserObjects)
                {
                    if (existing.owner == object.owner && existing.name == object.name)
                    {
                        object.created = existing.created ? existing.created : object.created;
                        existing = object;
                        replaced = true;
                        break;
                    }
                }

                if (!replaced)
                    g_restUserObjects.emplace_back(object);

                std::printf(
                    "[DW-REST-OBJECTSTORE] PUT owner=%s name=%s bytes=%llu "
                    "persisted=yes replacing=%s\n",
                    object.owner.c_str(),
                    object.name.c_str(),
                    static_cast<unsigned long long>(object.contentLength),
                    replaced ? "yes" : "no");
            }

            const bool savedToDisk = SaveRestUserObjectsLocked();
            std::printf("[DW-REST-OBJECTSTORE] diskPersist=%s objects=%zu\n",
                savedToDisk ? "yes" : "FAILED", g_restUserObjects.size());

            std::printf(
                "[DW-REST-OBJECTSTORE] resource=VectorizedUserObjectsResource/put_objects "
                "response=success stored=%zu persistedTotal=%zu validationTokens=0 "
                "mode=local-persistent-store\n",
                parsed.size(), g_restUserObjects.size());

            return true;
        }

        std::string BuildRestStoredUserObjectJson(
            const RestStoredUserObject& object, std::size_t requestIndex)
        {
            return std::string("{\"requestIndex\":") + std::to_string(requestIndex) +
                ",\"metadata\":{" +
                "\"name\":\"" + JsonEscapeRest(object.name) + "\"," +
                "\"owner\":\"" + JsonEscapeRest(object.owner) + "\"," +
                "\"checksum\":\"" + JsonEscapeRest(object.checksum) + "\"," +
                "\"objectVersion\":\"" + JsonEscapeRest(object.objectVersion) + "\"," +
                "\"expiresOn\":0," +
                "\"created\":" + std::to_string(object.created) + "," +
                "\"modified\":" + std::to_string(object.modified) + "," +
                "\"acl\":\"private\"," +
                "\"contentLength\":" + std::to_string(object.contentLength) + "," +
                "\"context\":\"5800\"," +
                "\"category\":null}," +
                "\"content\":\"" + JsonEscapeRest(object.contentBase64) + "\"}";
        }

        std::string BuildRestObjectStoreUserBody(
            const std::uint8_t* payload, std::size_t payloadBytes)
        {
            std::vector<std::pair<std::string, std::string>> objectIds;
            if (!ExtractRestObjectStoreIds(payload, payloadBytes, objectIds) ||
                objectIds.empty())
            {
                return {};
            }

            std::string objects;
            std::string errors;
            std::size_t hitCount = 0;
            std::size_t missCount = 0;
            std::size_t persistedCount = 0;

            std::lock_guard<std::mutex> lock(g_restUserObjectMutex);
            LoadRestUserObjectsLocked();
            persistedCount = g_restUserObjects.size();

            for (std::size_t i = 0; i < objectIds.size(); ++i)
            {
                const std::string& owner = objectIds[i].first;
                const std::string& name = objectIds[i].second;

                const RestStoredUserObject* found = nullptr;
                for (const RestStoredUserObject& object : g_restUserObjects)
                {
                    if (object.owner == owner && object.name == name)
                    {
                        found = &object;
                        break;
                    }
                }

                if (found)
                {
                    if (!objects.empty())
                        objects.push_back(',');
                    objects += BuildRestStoredUserObjectJson(*found, i);
                    ++hitCount;
                }
                else
                {
                    if (!errors.empty())
                        errors.push_back(',');
                    errors +=
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"owner\":\"" + JsonEscapeRest(owner) + "\"," +
                        "\"name\":\"" + JsonEscapeRest(name) + "\"," +
                        "\"error\":\"Error:ClientError:NotFound\"}";
                    ++missCount;
                }
            }

            std::printf(
                "[DW-REST-OBJECTSTORE] resource=VectorizedUserObjectsResource/get_objects "
                "requested=%zu hit=%zu miss=%zu persisted=%zu "
                "response=%s\n",
                objectIds.size(), hitCount, missCount, persistedCount,
                hitCount ? "stored-user-objects" : "fresh-account-not-found");

            return std::string("{\"objects\":[") + objects +
                "],\"errors\":[" + errors + "]}";
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

            case RestBootstrapKind::UserPresenceSet:
                return "{}";

            case RestBootstrapKind::UserEventsReportBatch:
                return "{\"allSucceeded\":true}";

            case RestBootstrapKind::AccountSearchUno:
                // Stock IW8 cross-platform identity search responses are parsed from
                // a top-level users array.  An empty users array is a valid
                // successful result and avoids fabricating UNO identities for
                // arbitrary Steam accounts in local/offline mode.
                std::printf("[DW-REST-UMBRELLA] resource=AccountSearchesResource/unoaccountsearch response=success users=0 mode=local-offline\n");
                return "{\"users\":[]}";

            case RestBootstrapKind::UserAuthenticate:
            {
                const std::uint64_t userId = ::revamped::iw8::web::GetCurrentLocalUserId();

                // The stock response parser accepts these four fields. The token
                // strings are local-only placeholders; they are never forwarded.
                std::printf(
                    "[DW-REST-UNO] resource=UserResource/authenticateUser response=success unoId=%llu tokens=local-only mode=local-offline\n",
                    static_cast<unsigned long long>(userId));

                return std::string("{\"unoID\":") + std::to_string(userId) +
                    ",\"tokens\":{\"IDToken\":\"revamped-local-uno-id\","
                    "\"accessToken\":\"revamped-local-uno-access\","
                    "\"refreshToken\":\"revamped-local-uno-refresh\"}}";
            }

            case RestBootstrapKind::ProfanityFilterVerifyString:
                // The stock bdVerifyString contract uses numeric verification
                // result 0 for a clean string.  Retail moved this operation to
                // REST; its generated response class is not present in OpenIW8,
                // so provide the clean value under the compatible scalar names
                // seen across the legacy/migrated contract. Unknown JSON members
                // are ignored by Demonware's generated deserializers.
                std::printf(
                    "[DW-REST-PROFANITY] resource=ProfanityFilter/get_verify_string "
                    "response=success clean=yes field=isProfane value=false mode=local-offline\n");
                return "{\"isProfane\":false}";

            case RestBootstrapKind::UsersStructuredDataGet:
            {
                const std::uint64_t userId = ::revamped::iw8::web::GetCurrentLocalUserId();

                // Retail's generated structured-data client names the response
                // collection `usersStructuredData` and each record contains a
                // schemaName + structuredData pair.  Keep both userID and dwid in
                // the local compatibility object: builds which use the common
                // bdUserAccountID JSON convention consume userID, while the
                // request-side structured-data schema uses dwid. Unknown members
                // are ignored by the generated JSON deserializer.
                //
                // hasPlayed=true deliberately models an established local profile
                // rather than another first-run account. The remaining shared
                // progression fields use neutral local defaults.
                const bool retailProfile = web::UsesNativeSteamLoginKey();
                const std::string profile =
                    "{\"clanID\":0,\"seasonRank\":0,\"seasonNumber\":0,"
                    "\"rankXP\":0,\"seasonXP\":0,\"battlepassXP\":0,"
                    "\"battlepassOwned\":false,\"hasPlayed\":" +
                    std::string(retailProfile ? "[]" : "true") +
                    ",\"wishlistSkus\":[],\"wishlistItems\":[]}";
                std::string body =
                    "{\"usersStructuredData\":[{"
                    "\"userID\":" + std::to_string(userId) +
                    ",\"dwid\":" + std::to_string(userId) +
                    ",\"accountType\":\"uno\""
                    ",\"context\":\"cod-shared\""
                    ",\"schemaName\":\"cod-shared-profile\""
                    ",\"version\":2"
                    ",\"structuredData\":" + profile + "}],\"errors\":[]}";

                if (retailProfile)
                {
                    // Retail dump: 6CCE110 reads usersStructuredData[],
                    // 6CCE192 reads each entry's items[], 6CCE275 reads a
                    // payload string, and 6CCE293 requires numeric errorCode.
                    // A structuredData object directly on the user is not
                    // consumed by that native response parser.
                    // Caller 1F02E129 sets the decode flag; 6CCE250 calls the
                    // base64 decoder 6C6FF90 (table RVA 7173B40).
                    // The profile consumer 6D46550 reads hasPlayed as an
                    // array, not a bool. A new local profile has no entries.
                    body = "{\"usersStructuredData\":[{\"userID\":" +
                        std::to_string(userId) + ",\"accountType\":\"uno\",\"items\":[{"
                        "\"payload\":\"" + Base64Encode(profile) +
                        "\",\"errorCode\":0}]}],\"errors\":[]}";
                }

                std::printf(
                    "[DW-REST-STRUCTURED] resource=UsersStructuredData/get_structured_data "
                    "response=success userId=%llu schema=cod-shared-profile version=2 "
                    "hasPlayed=%s mode=local-offline\n",
                    static_cast<unsigned long long>(userId),
                    retailProfile ? "empty-array" : "true");
                return body;
            }

            case RestBootstrapKind::UserLink:
            {
                const std::uint64_t userId = ::revamped::iw8::web::GetCurrentLocalUserId();

                // bdCrossPlatformLinkUserResponse::handleReplySuccess requires only
                // umbrellaID. Reuse the same local identity already carried through
                // Auth3/Umbrella/LSG so downstream account IDs stay consistent.
                std::printf(
                    "[DW-REST-UNO] resource=UserResource/linkUser response=success umbrellaId=%llu mode=local-offline\n",
                    static_cast<unsigned long long>(userId));
                return std::string("{\"umbrellaID\":") + std::to_string(userId) + "}";
            }

            case RestBootstrapKind::PublisherObjectMetadataGet:
                return BuildRestPublisherMetadataBody(payload, payloadBytes);

            case RestBootstrapKind::ClanMembershipsGet:
                std::printf(
                    "[DW-REST-CLANS] resource=MembersResource/get_memberships "
                    "response=success members=0 mode=local-offline\n");
                return "{\"members\":[]}";

            case RestBootstrapKind::UserTfaStatusGet:
                std::printf(
                    "[DW-REST-UNO] resource=UserResource/getTfaStatus "
                    "response=success TFAEnabled=false mode=local-offline\n");
                return "{\"TFAEnabled\":false}";

            case RestBootstrapKind::FirstPartySkusGet:
                std::printf(
                    "[DW-REST-EXCHANGE] resource=first_party_skus/get_first_party_skus "
                    "response=success firstPartySKUs=0 store=steam mode=local-offline\n");
                return "{\"firstPartySKUs\":[]}";

            case RestBootstrapKind::ObjectStoreGetUserObjects:
                return BuildRestObjectStoreUserBody(payload, payloadBytes);

            case RestBootstrapKind::ObjectStorePutUserObjects:
                // Learn the exact DDL/stat objects Retail creates on its first
                // local run. This keeps a reconnect from looking like a brand-new
                // account and repeating the entire stats initialization path.
                if (!StoreRestUserObjectsFromPut(payload, payloadBytes))
                    return {};
                return "{\"objects\":[],\"errors\":[],\"validationTokens\":[]}";

            default:
                return {};
            }
        }

        void BuildRestResponseMetadata(std::uint64_t transactionId, std::uint32_t httpStatus,
            std::vector<std::uint8_t>& metadata)
        {
            metadata.clear();
            AppendPbU32(metadata, 1u, httpStatus);
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
            std::string body = RestBootstrapBody(kind, requestPayload, requestPayloadBytes);
            std::uint32_t httpStatus = kHttpOk;

            // bdRemoteTaskManager consumes task replies strictly from the head
            // of its pending FIFO.  Silently dropping an unimplemented REST
            // request therefore shifts every later Demonware reply onto the
            // wrong task.  Retail exposed this first with ProfanityFilter: its
            // missing reply caused later ObjectStore get_objects responses to
            // be consumed by older pending REST tasks and the stats download
            // retried forever.
            //
            // Unknown REST operations must still terminate their own task.
            // Return a normal, non-retryable HTTP 404 error envelope rather
            // than inventing a successful response schema.  Operation-specific
            // handlers are free to treat the failure however stock IW8 expects,
            // while the global remote-task FIFO remains synchronized.
            if (body.empty())
            {
                httpStatus = 404u;
                body =
                    "{\"error\":{\"name\":\"Error:ClientError:NotFound\","
                    "\"msg\":\"CodRevamped local REST operation not reconstructed\"}}";
                std::printf(
                    "[DW-REST-FALLBACK] transaction=%llu status=404 error=Error:ClientError:NotFound "
                    "reason=operation-not-reconstructed fifo=preserved\n",
                    static_cast<unsigned long long>(transactionId));
            }

            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, kRestVersion);

            std::vector<std::uint8_t> metadata;
            metadata.reserve(64u);
            BuildRestResponseMetadata(transactionId, httpStatus, metadata);
            AppendTypedBlob(serviceReply, metadata.data(), metadata.size());
            AppendTypedBool(serviceReply, true);
            AppendTypedBlob(serviceReply, body.c_str(), body.size() + 1u);
            return true;
        }
    }
}
