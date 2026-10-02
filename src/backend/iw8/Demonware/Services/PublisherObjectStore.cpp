#include "../../LocalPublisherContent.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        constexpr const char* kIw8StorePublisher = "infinityward";

        constexpr const char* kIw8StoreLayoutName = "store_v2_warzone.json";
        constexpr const char* kIw8StoreLayoutJson = "{\"categories\":[]}";
        constexpr const char* kIw8StoreLayoutContentUrl =
            "https://objectstore.prod.demonware.net/__revamped/objectstore/publisher/infinityward/store_v2_warzone.json";

        // IW8 1.20 InGameStore_CoFetchObjectStoreConfig constructs
        // "ingamestore_xb3_%s.json". This build reports enUS during BGS startup,
        // so task 0xC1/8 resolves to the hashed ObjectStore id seen in the log.
        constexpr const char* kIw8InGameStoreName = "ingamestore_xb3_enUS.json";
        constexpr const char* kIw8InGameStoreJson = "{\"categories\":[]}";
        constexpr const char* kIw8InGameStoreContentUrl =
            "https://objectstore.prod.demonware.net/__revamped/objectstore/publisher/infinityward/ingamestore_xb3_enUS.json";

        constexpr const char* kIw8StoreAuthorization = "Bearer revamped-local-objectstore";

        bool IsLocalIw8PublisherObject(const std::string& owner, const std::string& name)
        {
            return owner == kIw8StorePublisher &&
                (name == kIw8StoreLayoutName ||
                 localpublisher::IsPlaylist(name) ||
                 (localpublisher::LocalManifestEnabled() && localpublisher::IsManifest(name)));
        }

        std::string PublisherContextFromUrl(const std::string& url)
        {
            std::string context;
            if (!ExtractQueryParam(url, "context", context) || context.empty())
                context = "5800";
            return context;
        }

        std::string BuildLocalPublisherMetadataJsonForContent(
            const std::string& owner,
            const std::string& name,
            const std::string& context,
            const std::string& content,
            const std::string& contentUrl)
        {
            static const std::int64_t publishedAt = UnixTimeSeconds();
            const std::string checksum = localpublisher::IsManifest(name)
                ? localpublisher::ManifestChecksum : StableDigest32(content);
            const std::string objectVersion =
                StableDigest32(owner + std::string(1, '\0') +
                    name + std::string(1, '\0') + checksum);

            const std::int64_t expiresOn = publishedAt + 315360000ll; // ten years

            std::string json = "{";
            if (localpublisher::IsManifest(name))
                json += std::string("\"objectID\":") +
                    (name == "1_manifest_patch_pc_8.19.txt" ? "120001," : "120002,");
            json += "\"name\":\"" + JsonEscape(name) + "\",";
            json += "\"owner\":\"" + JsonEscape(owner) + "\",";
            json += "\"checksum\":\"" + JsonEscape(checksum) + "\",";
            json += "\"objectVersion\":\"" + JsonEscape(objectVersion) + "\",";
            json += "\"expiresOn\":" + std::to_string(expiresOn) + ",";
            json += "\"created\":" + std::to_string(publishedAt) + ",";
            json += "\"modified\":" + std::to_string(publishedAt) + ",";
            json += "\"acl\":\"public\",";
            json += "\"contentLength\":" + std::to_string(content.size()) + ",";
            json += "\"context\":\"" + JsonEscape(context) + "\",";
            json += localpublisher::IsManifest(name) ? "\"category\":\"1\"," : "\"category\":null,";
            json += "\"contentURL\":\"" + JsonEscape(contentUrl) + "\"";
            json += "}";
            return json;
        }

        std::string BuildLocalPublisherMetadataJson(
            const std::string& owner, const std::string& name, const std::string& context)
        {
            if (localpublisher::IsManifest(name))
                return BuildLocalPublisherMetadataJsonForContent(owner, name, context,
                    localpublisher::ManifestBody(),
                    std::string("https://objectstore.prod.demonware.net") + localpublisher::PathPrefix + name);
            if (localpublisher::IsPlaylist(name))
                return BuildLocalPublisherMetadataJsonForContent(owner, name, context,
                    localpublisher::PlaylistBody(),
                    std::string("https://objectstore.prod.demonware.net") +
                        localpublisher::PathPrefix + name);
            return BuildLocalPublisherMetadataJsonForContent(
                owner,
                name,
                context,
                kIw8StoreLayoutJson,
                kIw8StoreLayoutContentUrl);
        }

        void AppendObjectStoreJsonStructWithAuthorization(
            std::vector<std::uint8_t>& serviceReply, const std::string& json)
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

            std::vector<std::uint8_t> authorizationHeader;
            AppendPbString(authorizationHeader, 1u, "Authorization");
            AppendPbString(authorizationHeader, 2u, kIw8StoreAuthorization);
            AppendPbObject(responseBody, 1u, authorizationHeader);

            AppendPbU32(responseBody, 2u, kHttpOk);
            AppendPbString(responseBody, 3u, json);
            AppendTypedStruct(serviceReply, responseBody);
        }

        bool AppendPublisherObjectMetadatasStruct(
            std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::vector<std::pair<std::string, std::string>> objectIds;
            if (!ExtractObjectStoreIds(requestPayload, requestPayloadBytes, objectIds) ||
                objectIds.empty())
            {
                return false;
            }

            std::string method;
            std::string url;
            std::string unusedBody;
            if (!ExtractHttpProxyJsonBody(requestPayload, requestPayloadBytes, method, url, unusedBody) ||
                method != "GET")
            {
                return false;
            }

            const std::string context = PublisherContextFromUrl(url);
            std::vector<std::string> objects;
            std::vector<std::string> errors;
            objects.reserve(objectIds.size());
            errors.reserve(objectIds.size());

            for (std::size_t i = 0; i < objectIds.size(); ++i)
            {
                const std::string& owner = objectIds[i].first;
                const std::string& name = objectIds[i].second;
                std::printf("[DW-PUBLISHER-LOOKUP] index=%zu owner=%s name=%s available=%s\n",
                    i, owner.c_str(), name.c_str(), IsLocalIw8PublisherObject(owner, name) ? "yes" : "no");
                std::fflush(stdout);
                if (IsLocalIw8PublisherObject(owner, name))
                {
                    objects.emplace_back(
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"metadata\":" + BuildLocalPublisherMetadataJson(owner, name, context) + "}");
                }
                else
                {
                    errors.emplace_back(
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"owner\":\"" + JsonEscape(owner) +
                        "\",\"name\":\"" + JsonEscape(name) +
                        "\",\"error\":\"" + kObjectStoreNotFoundError + "\"}");
                }
            }

            std::string json = "{\"objects\":[";
            for (std::size_t i = 0; i < objects.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += objects[i];
            }
            json += "],\"errors\":[";
            for (std::size_t i = 0; i < errors.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += errors[i];
            }
            json += "]}";

            std::printf(
                "[DW-OBJECTSTORE] GET service=0xC1 task=16 resource=PublisherObjects requested=%zu hit=%zu miss=%zu localStoreLayout=%s authHeader=yes\n",
                objectIds.size(), objects.size(), errors.size(),
                objects.empty() ? "no" : "yes");

            AppendObjectStoreJsonStructWithAuthorization(serviceReply, json);
            return true;
        }

        bool AppendPublisherObjectStruct(
            std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::string method;
            std::string url;
            std::string unusedBody;
            if (!ExtractHttpProxyJsonBody(requestPayload, requestPayloadBytes, method, url, unusedBody) ||
                method != "GET")
            {
                return false;
            }

            // The single publisher-object REST route uses the hashed numeric
            // object id in the URL, not the original object name. OpenIW8 shows
            // the caller constructed that id from:
            //   infinityward / ingamestore_xb3_<language>.json
            // For 1.20 this client advertises enUS.
            const bool publisherObjectRoute =
                url.find("/v1/core/publishers/infinityward/objects/") != std::string::npos &&
                url.find("/metadata/") != std::string::npos;
            if (!publisherObjectRoute)
            {
                std::printf(
                    "[DW-OBJECTSTORE] GET service=0xC1 task=8 resource=PublisherObject response=unsupported url=%s\n",
                    url.c_str());
                return false;
            }

            const std::string context = PublisherContextFromUrl(url);
            const std::string metadata = BuildLocalPublisherMetadataJsonForContent(
                kIw8StorePublisher,
                kIw8InGameStoreName,
                context,
                kIw8InGameStoreJson,
                kIw8InGameStoreContentUrl);

            std::printf(
                "[DW-OBJECTSTORE] GET service=0xC1 task=8 resource=PublisherObject owner=%s name=%s response=local-success authHeader=yes contentURL=%s requestedUrl=%s\n",
                kIw8StorePublisher,
                kIw8InGameStoreName,
                kIw8InGameStoreContentUrl,
                url.c_str());

            AppendObjectStoreJsonStructWithAuthorization(serviceReply, metadata);
            return true;
        }
    }
}
