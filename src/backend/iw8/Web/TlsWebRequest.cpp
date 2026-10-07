#include "TlsWebRequest.h"
#include "../LocalPublisherContent.h"

namespace revamped::iw8
{
    namespace
    {
        bool HandleWebAuthPlaintext(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            const void* payload, std::size_t size)
        {
            if (!payload || !size) return true;
            const auto* bytes = static_cast<const unsigned char*>(payload);
            session.httpInput.insert(session.httpInput.end(), bytes, bytes + size);
            if (session.httpInput.size() > 1024u * 1024u)
            {
                log::Print("[WEB-AUTH] id=%llu request buffer exceeded 1 MiB; closing", static_cast<unsigned long long>(id));
                return false;
            }

            for (;;)
            {
                web::HttpResult result = web::TryHandleLocalWebRequest(session.httpInput);
                if (!result.complete)
                {
                    log::Print("[WEB-AUTH] id=%llu HTTPS request fragmented; bufferedPlaintextBytes=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(session.httpInput.size()));
                    return true;
                }

                static constexpr const char* kPublisherHost = "objectstore.prod.demonware.net";
                static constexpr const char* kStoreLayoutPath =
                    "/__revamped/objectstore/publisher/infinityward/store_v2_warzone.json";
                static constexpr const char* kStoreCategoryPath =
                    "/__revamped/objectstore/publisher/infinityward/revamped_store_category.json";
                static constexpr const char* kRavenPublisherPrefix =
                    "/__revamped/objectstore/publisher/raven/";
                static constexpr const char* kStoreLayoutBody =
                    "{\"categories\":[\"revamped_store_category.json\"]}";
                static constexpr const char* kStoreCategoryBody = "{\"layoutType\":0}";
                static constexpr const char* kInGameStoreBody =
                    "{\"products\":{},\"categories\":{\"revamped\":{\"title\":\"Revamped Store\",\"layout\":\"normal\",\"image\":\"\",\"products\":[]}},\"store\":[\"revamped\"]}";
                static constexpr const char* kMetricsHost =
                    "pipes-prod-glutton.public.aws.demonware.net";
                static constexpr const char* kMetricsPath =
                    "/v1.0/secureingest/5800/metrics/";
                static constexpr const char* kBlizzardApiHostSuffix =
                    ".api.blizzard.com";
                static constexpr const char* kDefaultCurrencyPath =
                    "/PurchaseService/v1/GetAccountDefaultCurrency";
                static constexpr const char* kSimpleCatalogPath =
                    "/SimpleCatalogService/v1/GetCatalog";

                const bool objectStoreHost =
                    result.host.find(kPublisherHost) != std::string::npos;
                const auto isSafeObjectName = [](const std::string& name)
                {
                    return !name.empty() &&
                        name.find('/') == std::string::npos &&
                        name.find('\\') == std::string::npos &&
                        name.find("..") == std::string::npos;
                };
                const auto isInGameStoreName = [&isSafeObjectName](const std::string& name)
                {
                    static constexpr const char* prefix = "ingamestore_";
                    static constexpr const char* suffix = ".json";
                    const std::size_t prefixLength = std::char_traits<char>::length(prefix);
                    const std::size_t suffixLength = std::char_traits<char>::length(suffix);
                    return isSafeObjectName(name) && name.size() > prefixLength + suffixLength &&
                        name.compare(0, prefixLength, prefix) == 0 &&
                        name.compare(name.size() - suffixLength, suffixLength, suffix) == 0;
                };

                std::string localBody;
                const char* localLabel = nullptr;
                const char* localContentType = "application/json; charset=utf-8";
                const char* localBodyKind = "local-publisher-json";
                bool hasLocalBody = false;
                if (result.method == "GET" && objectStoreHost)
                {
                    std::string objectName;
                    const std::string infinityWardPrefix = localpublisher::PathPrefix;
                    if (result.path.rfind(infinityWardPrefix, 0) == 0)
                        objectName = result.path.substr(infinityWardPrefix.size());
                    else if (result.path.rfind(kRavenPublisherPrefix, 0) == 0)
                        objectName = result.path.substr(
                            std::char_traits<char>::length(kRavenPublisherPrefix));

                    if (!objectName.empty() &&
                        localpublisher::LocalManifestEnabled() &&
                        localpublisher::IsManifest(objectName))
                    {
                        localBody = localpublisher::ManifestBody();
                        localLabel = "local signed manifest (RSA-PSS; native validation active)";
                        localContentType = "application/json; charset=utf-8";
                        localBodyKind = "local-publisher-manifest";
                        hasLocalBody = true;
                    }
                    else if (objectName == "store_v2.json")
                    {
                        localBody = "{\"categories\":[]}";
                        localLabel = "local ObjectStore publisher store_v2.json";
                        localContentType = "application/json; charset=utf-8";
                        localBodyKind = "local-publisher-json";
                        hasLocalBody = true;
                    }
                    else if (result.path == kStoreLayoutPath)
                    {
                        localBody = kStoreLayoutBody;
                        localLabel = "local ObjectStore publisher store_v2_warzone.json";
                        hasLocalBody = true;
                    }
                    else if (result.path == kStoreCategoryPath)
                    {
                        localBody = kStoreCategoryBody;
                        localLabel = "local ObjectStore publisher revamped_store_category.json";
                        hasLocalBody = true;
                    }
                    else if (!objectName.empty())
                    {
                        if (isInGameStoreName(objectName))
                        {
                            localBody = kInGameStoreBody;
                            localLabel = "local ObjectStore publisher ingamestore config";
                            hasLocalBody = true;
                        }
                        else if (localpublisher::IsContentCreatorList(objectName))
                        {
                            localBody = localpublisher::ContentCreatorListBody();
                            localLabel = "local ObjectStore publisher contentCreatorList.txt";
                            localContentType = "text/plain; charset=utf-8";
                            localBodyKind = "local-publisher-text";
                            hasLocalBody = true;
                        }
                        else if (localpublisher::IsPlaylist(objectName))
                        {
                            localBody = localpublisher::PlaylistBody();
                            localLabel = "local ObjectStore publisher unified playlist aggregate";
                            localContentType = "application/octet-stream";
                            localBodyKind = "local-publisher-zlib";
                            hasLocalBody = true;
                        }
                    }
                }

                if (hasLocalBody)
                {
                    result.handled = true;
                    result.statusCode = 200;
                    result.label = localLabel;

                    result.response =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: " + std::string(localContentType) + "\r\n"
                        "Cache-Control: no-store\r\n"
                        "Accept-Ranges: bytes\r\n"
                        "Connection: keep-alive\r\n"
                        "Keep-Alive: timeout=5, max=8\r\n"
                        "Content-Length: " + std::to_string(localBody.size()) + "\r\n"
                        "\r\n" + localBody;

                    log::Print(
                        "[DW-OBJECTSTORE-HTTP] id=%llu host=%s path=%s status=200 bytes=%llu body=%s connection=keep-alive",
                        static_cast<unsigned long long>(id),
                        result.host.c_str(),
                        result.path.c_str(),
                        static_cast<unsigned long long>(localBody.size()),
                        localBodyKind);
                }

                // Blizzard CommerceSDK calls this immediately after local BNet
                // authentication. The public Blizzard commerce model for
                // GetAccountDefaultCurrencyResponse contains currencyAlphaCode
                // plus an optional RpcError. Return the ordinary US-account
                // success shape locally instead of a 404 so the commerce shell
                // can finish initialization without contacting Blizzard.
                const bool blizzardApiHost =
                    result.host.size() > std::char_traits<char>::length(kBlizzardApiHostSuffix) &&
                    result.host.compare(
                        result.host.size() - std::char_traits<char>::length(kBlizzardApiHostSuffix),
                        std::char_traits<char>::length(kBlizzardApiHostSuffix),
                        kBlizzardApiHostSuffix) == 0;
                if (result.method == "POST" && blizzardApiHost &&
                    result.path == kDefaultCurrencyPath)
                {
                    static constexpr const char* kDefaultCurrencyBody =
                        "{\"currencyAlphaCode\":\"USD\",\"error\":null}";

                    result.handled = true;
                    result.statusCode = 200;
                    result.label = "local Blizzard PurchaseService default currency";
                    result.response =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json; charset=utf-8\r\n"
                        "Cache-Control: no-store\r\n"
                        "Connection: close\r\n"
                        "Content-Length: " +
                        std::to_string(std::char_traits<char>::length(kDefaultCurrencyBody)) +
                        "\r\n\r\n" + kDefaultCurrencyBody;

                    log::Print(
                        "[BNET-COMMERCE-HTTP] id=%llu host=%s path=%s status=200 currency=USD",
                        static_cast<unsigned long long>(id),
                        result.host.c_str(),
                        result.path.c_str());
                }
                else if (result.method == "POST" && blizzardApiHost &&
                    result.path == kSimpleCatalogPath)
                {
                    // The frontend only needs a structurally valid catalog to
                    // finish Store initialization. Keep the local catalog empty
                    // rather than inventing purchasable products.
                    static constexpr const char* kSimpleCatalogBody =
                        "{\"productList\":[],\"error\":null}";

                    result.handled = true;
                    result.statusCode = 200;
                    result.label = "local Blizzard SimpleCatalogService empty catalog";
                    result.response =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json; charset=utf-8\r\n"
                        "Cache-Control: no-store\r\n"
                        "Connection: close\r\n"
                        "Content-Length: " +
                        std::to_string(std::char_traits<char>::length(kSimpleCatalogBody)) +
                        "\r\n\r\n" + kSimpleCatalogBody;

                    log::Print(
                        "[BNET-COMMERCE-HTTP] id=%llu host=%s path=%s status=200 products=0",
                        static_cast<unsigned long long>(id),
                        result.host.c_str(),
                        result.path.c_str());
                }

                // The retail client treats secure-ingest as best-effort telemetry.
                // Accept the exact 1.20 endpoint locally so it does not retry a
                // deliberate 404 every thirty seconds. The payload is never used
                // to advance sign-in, fence, or frontend state.
                if (result.method == "POST" &&
                    result.host == kMetricsHost &&
                    result.path == kMetricsPath)
                {
                    result.handled = true;
                    result.statusCode = 204;
                    result.label = "local Demonware metrics accepted";
                    result.response =
                        "HTTP/1.1 204 No Content\r\n"
                        "Cache-Control: no-store\r\n"
                        "Connection: close\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n";

                    log::Print(
                        "[DW-METRICS-HTTP] id=%llu host=%s path=%s status=204 body=discarded-local-metrics",
                        static_cast<unsigned long long>(id),
                        result.host.c_str(),
                        result.path.c_str());
                }

                log::Print("[WEB-AUTH] id=%llu request method=%s host=%s path=%s requestBytes=%llu formKeys=%s values=REDACTED",
                    static_cast<unsigned long long>(id),
                    result.method.empty() ? "<unknown>" : result.method.c_str(),
                    result.host.empty() ? "<missing>" : result.host.c_str(),
                    result.path.empty() ? "<missing>" : result.path.c_str(),
                    static_cast<unsigned long long>(result.requestBytes),
                    result.formKeys.empty() ? "<none>" : result.formKeys.c_str());

                if (result.handled)
                    log::Print("[WEB-HANDLED] id=%llu status=%d detail=%s",
                        static_cast<unsigned long long>(id), result.statusCode, result.label.c_str());
                else
                    log::Print("[WEB-MISSING] id=%llu status=%d host=%s path=%s detail=%s",
                        static_cast<unsigned long long>(id), result.statusCode,
                        result.host.empty() ? "<missing>" : result.host.c_str(),
                        result.path.empty() ? "<missing>" : result.path.c_str(), result.label.c_str());

                if (result.response.empty() ||
                    !SendTlsApplication(session, socket, id, peer, result.response.data(), result.response.size(),
                        result.handled ? "local online-services HTTP response" : "local unimplemented HTTP response"))
                    return false;

                if (!(hasLocalBody && objectStoreHost))
                    shutdown(socket, SD_SEND);
                session.webAuthHttpServed = true;
                return true;
            }
        }
    }
}
