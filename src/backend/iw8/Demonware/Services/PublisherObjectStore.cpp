#include "../../LocalPublisherContent.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        constexpr const char* kIw8StorePublisher = "infinityward";

        constexpr const char* kIw8StoreLayoutName = "store_v2_warzone.json";
        constexpr const char* kIw8StoreCategoryName = "revamped_store_category.json";
        constexpr const char* kIw8StoreLayoutJson =
            "{\"categories\":[\"revamped_store_category.json\"]}";
        constexpr const char* kIw8StoreCategoryJson = "{\"layoutType\":0}";
        constexpr const char* kIw8StoreLayoutContentUrl =
            "https://objectstore.prod.demonware.net/__revamped/objectstore/publisher/infinityward/store_v2_warzone.json";

        // Task 0xC1/8 is used for both the older numeric ObjectStore key and
        // the later explicit BNet filename. Build 1.20's Battle.net path must
        // stay on the BNet object instead of being rewritten to the Xbox file.
        constexpr const char* kIw8InGameStoreFallbackName = "ingamestore_bnet_en.json";
        constexpr const char* kIw8InGameStoreJson =
            "{\"products\":{},\"categories\":{\"revamped\":{\"title\":\"Revamped Store\",\"layout\":\"normal\",\"image\":\"\",\"products\":[]}},\"store\":[\"revamped\"]}";

        constexpr const char* kIw8StoreAuthorization = "Bearer revamped-local-objectstore";
        constexpr const char* kPublisherContentUrlPrefix =
            "https://objectstore.prod.demonware.net/__revamped/objectstore/publisher/infinityward/";
        constexpr const char* kPublisherMetadataRoutePrefix =
            "/v1/core/publishers/infinityward/objects/";

        bool IsSafePublisherObjectName(const std::string& name)
        {
            return !name.empty() &&
                name.find('/') == std::string::npos &&
                name.find('\\') == std::string::npos &&
                name.find("..") == std::string::npos;
        }

        bool IsInGameStoreName(const std::string& name)
        {
            static constexpr const char* prefix = "ingamestore_";
            static constexpr const char* suffix = ".json";
            const std::size_t prefixLength = std::char_traits<char>::length(prefix);
            const std::size_t suffixLength = std::char_traits<char>::length(suffix);
            return IsSafePublisherObjectName(name) &&
                name.size() > prefixLength + suffixLength &&
                name.compare(0, prefixLength, prefix) == 0 &&
                name.compare(name.size() - suffixLength, suffixLength, suffix) == 0;
        }

        std::string BuildPublisherContentUrl(const std::string& name)
        {
            return std::string(kPublisherContentUrlPrefix) + name;
        }

        std::string ExtractPublisherObjectNameFromMetadataUrl(const std::string& url)
        {
            const std::string prefix = kPublisherMetadataRoutePrefix;
            const std::size_t start = url.find(prefix);
            if (start == std::string::npos)
                return {};
            const std::size_t nameStart = start + prefix.size();
            const std::size_t metadata = url.find("/metadata/", nameStart);
            if (metadata == std::string::npos || metadata <= nameStart)
                return {};
            const std::string name = url.substr(nameStart, metadata - nameStart);
            return IsSafePublisherObjectName(name) ? name : std::string{};
        }

        bool IsLocalIw8PublisherObject(const std::string& owner, const std::string& name)
        {
            return owner == kIw8StorePublisher &&
                (name == kIw8StoreLayoutName ||
                 name == kIw8StoreCategoryName ||
                 IsInGameStoreName(name) ||
                 localpublisher::IsContentCreatorList(name) ||
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
                    localpublisher::ManifestBody(), BuildPublisherContentUrl(name));
            if (localpublisher::IsPlaylist(name))
                return BuildLocalPublisherMetadataJsonForContent(owner, name, context,
                    localpublisher::PlaylistBody(), BuildPublisherContentUrl(name));
            if (localpublisher::IsContentCreatorList(name))
                return BuildLocalPublisherMetadataJsonForContent(owner, name, context,
                    localpublisher::ContentCreatorListBody(), BuildPublisherContentUrl(name));
            if (IsInGameStoreName(name))
                return BuildLocalPublisherMetadataJsonForContent(owner, name, context,
                    kIw8InGameStoreJson, BuildPublisherContentUrl(name));
            if (name == kIw8StoreCategoryName)
                return BuildLocalPublisherMetadataJsonForContent(owner, name, context,
                    kIw8StoreCategoryJson, BuildPublisherContentUrl(name));
            return BuildLocalPublisherMetadataJsonForContent(
                owner, name, context, kIw8StoreLayoutJson, kIw8StoreLayoutContentUrl);
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
                std::size_t localBytes = 0;
                if (localpublisher::IsPlaylist(name)) localBytes = localpublisher::PlaylistBody().size();
                else if (localpublisher::IsManifest(name)) localBytes = localpublisher::ManifestBody().size();
                else if (localpublisher::IsContentCreatorList(name)) localBytes = localpublisher::ContentCreatorListBody().size();
                else if (name == kIw8StoreLayoutName) localBytes = std::char_traits<char>::length(kIw8StoreLayoutJson);
                else if (name == kIw8StoreCategoryName) localBytes = std::char_traits<char>::length(kIw8StoreCategoryJson);
                else if (IsInGameStoreName(name)) localBytes = std::char_traits<char>::length(kIw8InGameStoreJson);
                std::printf("[DW-PUBLISHER-LOOKUP] index=%zu owner=%s name=%s available=%s contentLength=%zu\n",
                    i, owner.c_str(), name.c_str(), IsLocalIw8PublisherObject(owner, name) ? "yes" : "no", localBytes);
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

            const std::string requestedName = ExtractPublisherObjectNameFromMetadataUrl(url);
            if (requestedName.empty())
            {
                std::printf(
                    "[DW-OBJECTSTORE] GET service=0xC1 task=8 resource=PublisherObject response=unsupported url=%s\n",
                    url.c_str());
                return false;
            }

            // Numeric keys are the legacy hashed ObjectStore form observed at
            // startup. Explicit names (for example ingamestore_bnet_en.json)
            // must round-trip unchanged or the later Store fetch is redirected
            // to the wrong platform/language object.
            const bool symbolicInGameStore = IsInGameStoreName(requestedName);
            const std::string objectName = symbolicInGameStore
                ? requestedName : std::string(kIw8InGameStoreFallbackName);
            const std::string contentUrl = BuildPublisherContentUrl(objectName);
            const std::string context = PublisherContextFromUrl(url);
            const std::string metadata = BuildLocalPublisherMetadataJsonForContent(
                kIw8StorePublisher, objectName, context, kIw8InGameStoreJson, contentUrl);

            std::printf(
                "[DW-OBJECTSTORE] GET service=0xC1 task=8 resource=PublisherObject owner=%s requestedObject=%s name=%s source=%s response=local-success authHeader=yes contentLength=%zu contentURL=%s requestedUrl=%s\n",
                kIw8StorePublisher, requestedName.c_str(), objectName.c_str(),
                symbolicInGameStore ? "symbolic" : "numeric-fallback",
                std::char_traits<char>::length(kIw8InGameStoreJson),
                contentUrl.c_str(), url.c_str());

            AppendObjectStoreJsonStructWithAuthorization(serviceReply, metadata);
            return true;
        }
    }
}
