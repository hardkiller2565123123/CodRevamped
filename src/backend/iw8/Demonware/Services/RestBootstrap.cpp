#include "RestBootstrap.h"
#include "../../Web/WebAuthService.h"
#include "../../LocalPublisherContent.h"

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

            // Retail social bootstrap asks for the current user's clan memberships
            // even when the player is not in a clan.  A terminal HTTP 404 keeps
            // the request FIFO aligned but leaves the generated clan client in
            // an error state.  Return an empty successful collection instead.
            if (ContainsAscii(payload, payloadBytes, "MembersResource") &&
                ContainsAscii(payload, payloadBytes, "get_memberships") &&
                ContainsAscii(payload, payloadBytes, "/v1/users/clans/"))
                return RestBootstrapKind::ClanMembershipsGet;

            // Existing UNO accounts query two-factor status during frontend
            // bootstrap.  Retail's generated response uses the exact JSON field
            // name TFAEnabled; local/offline accounts intentionally have no TFA.
            if (ContainsAscii(payload, payloadBytes, "UserResource") &&
                ContainsAscii(payload, payloadBytes, "getTfaStatus") &&
                ContainsAscii(payload, payloadBytes, "/tfa/"))
                return RestBootstrapKind::UserTfaStatusGet;

            // Steam store bootstrap requests the first-party SKU mapping through
            // Exchange.  The local preservation backend does not manufacture
            // platform purchases, so a valid empty firstPartySKUs array is the
            // neutral successful result.
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
                content = localpublisher::ManifestBody();
                contentType = "application/json; charset=utf-8";
                return true;
            }

            if (localpublisher::IsPlaylist(name))
            {
                content = localpublisher::PlaylistBody();
                contentType = "application/octet-stream";
                return true;
            }

            if (name == "store_v2.json" || name == "store_v2_warzone.json")
            {
                // Neutral local store layout. The store itself is not required
                // for offline gameplay; Retail only needs a valid existing
                // publisher object while update/store bootstrap completes.
                content = "{\"categories\":[]}";
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
                    const std::string checksum = localpublisher::IsManifest(name)
                        ? localpublisher::ManifestChecksum
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

                    objects +=
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"metadata\":{"
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
                        "response=metadata-success bytes=%zu url=%s\n",
                        i, owner.c_str(), name.c_str(), content.size(),
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

        std::string BuildRestObjectStoreNotFoundBody(const std::uint8_t* payload, std::size_t payloadBytes)
        {
            std::vector<std::pair<std::string, std::string>> objectIds;
            if (!ExtractRestObjectStoreIds(payload, payloadBytes, objectIds))
                return {};

            std::string json = "{\"objects\":[],\"errors\":[";
            for (std::size_t i = 0; i < objectIds.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += "{\"requestIndex\":" + std::to_string(i) +
                    ",\"owner\":\"" + JsonEscapeRest(objectIds[i].first) +
                    "\",\"name\":\"" + JsonEscapeRest(objectIds[i].second) +
                    "\",\"error\":\"Error:ClientError:NotFound\"}";
            }
            json += "]}";

            std::printf("[DW-REST-OBJECTSTORE] resource=VectorizedUserObjectsResource/get_objects requested=%zu response=canonical-not-found fresh-account=yes\n",
                objectIds.size());
            return json;
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
                std::string body =
                    "{\"usersStructuredData\":[{"
                    "\"userID\":" + std::to_string(userId) +
                    ",\"dwid\":" + std::to_string(userId) +
                    ",\"accountType\":\"uno\""
                    ",\"context\":\"cod-shared\""
                    ",\"schemaName\":\"cod-shared-profile\""
                    ",\"version\":2"
                    ",\"structuredData\":{"
                        "\"clanID\":0,"
                        "\"seasonRank\":0,"
                        "\"seasonNumber\":0,"
                        "\"rankXP\":0,"
                        "\"seasonXP\":0,"
                        "\"battlepassXP\":0,"
                        "\"battlepassOwned\":false,"
                        "\"hasPlayed\":true,"
                        "\"wishlistSkus\":[],"
                        "\"wishlistItems\":[]"
                    "}}],\"errors\":[]}";

                std::printf(
                    "[DW-REST-STRUCTURED] resource=UsersStructuredData/get_structured_data "
                    "response=success userId=%llu schema=cod-shared-profile version=2 "
                    "hasPlayed=true mode=local-offline\n",
                    static_cast<unsigned long long>(userId));
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
                // The Retail clan REST response exposes its collection as
                // `members`.  Empty is the correct local/offline state for a
                // pre-created account that has not joined a clan.
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
                return BuildRestObjectStoreNotFoundBody(payload, payloadBytes);

            case RestBootstrapKind::ObjectStorePutUserObjects:
                // Do not fabricate server-validation tokens in the local/offline
                // backend.  The stock parser accepts these required arrays empty,
                // and OnStatsWriteComplete explicitly cleans up successfully when
                // validationTokens.size() == 0.
                std::printf("[DW-REST-OBJECTSTORE] resource=VectorizedUserObjectsResource/put_objects response=success validationTokens=0 mode=local-offline\n");
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
