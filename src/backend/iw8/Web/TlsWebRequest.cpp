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
                static constexpr const char* kStoreLayoutBody = "{\"categories\":[]}";
                static constexpr const char* kInGameStorePath =
                    "/__revamped/objectstore/publisher/infinityward/ingamestore_xb3_enUS.json";
                static constexpr const char* kInGameStoreBody = "{\"categories\":[]}";
                static constexpr const char* kMetricsHost =
                    "pipes-prod-glutton.public.aws.demonware.net";
                static constexpr const char* kMetricsPath =
                    "/v1.0/secureingest/5800/metrics/";

                const bool objectStoreHost =
                    result.host.find(kPublisherHost) != std::string::npos;

                std::string localBody;
                const char* localLabel = nullptr;
                const char* localContentType = "application/json; charset=utf-8";
                const char* localBodyKind = "local-publisher-json";
                bool hasLocalBody = false;
                if (result.method == "GET" && objectStoreHost)
                {
                    const std::string manifestPrefix = localpublisher::PathPrefix;
                    if (localpublisher::LocalManifestEnabled() &&
                        result.path.rfind(manifestPrefix, 0) == 0 &&
                        localpublisher::IsManifest(result.path.substr(manifestPrefix.size())))
                    {
                        localBody = localpublisher::ManifestBody();
                        localLabel = "local signed manifest (RSA-PSS; native validation active)";
                        hasLocalBody = true;
                    }
                    if (result.path == kStoreLayoutPath)
                    {
                        localBody = kStoreLayoutBody;
                        localLabel = "local ObjectStore publisher store_v2_warzone.json";
                        hasLocalBody = true;
                    }
                    else if (result.path == kInGameStorePath)
                    {
                        localBody = kInGameStoreBody;
                        localLabel = "local ObjectStore publisher ingamestore_xb3_enUS.json";
                        hasLocalBody = true;
                    }
                    else if (result.path.rfind(localpublisher::PathPrefix, 0) == 0 &&
                        localpublisher::IsPlaylist(result.path.substr(std::string(localpublisher::PathPrefix).size())))
                    {
                        localBody = localpublisher::PlaylistBody();
                        localLabel = "local ObjectStore publisher unified playlist aggregate";
                        localContentType = "application/octet-stream";
                        localBodyKind = "local-publisher-zlib";
                        hasLocalBody = true;
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
                        "Connection: close\r\n"
                        "Content-Length: " + std::to_string(localBody.size()) + "\r\n"
                        "\r\n" + localBody;

                    log::Print(
                        "[DW-OBJECTSTORE-HTTP] id=%llu host=%s path=%s status=200 bytes=%llu body=%s",
                        static_cast<unsigned long long>(id),
                        result.host.c_str(),
                        result.path.c_str(),
                        static_cast<unsigned long long>(localBody.size()),
                        localBodyKind);
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

                shutdown(socket, SD_SEND);
                session.webAuthHttpServed = true;
                return true;
            }
        }
    }
}
