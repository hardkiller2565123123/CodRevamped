#include "../LocalPublisherContent.h"

namespace revamped::iw8
{
    namespace
    {
        constexpr const char* kLocalPublisherStorePath =
            "/__revamped/objectstore/publisher/infinityward/store_v2_warzone.json";
        constexpr const char* kLocalPublisherStoreJson = "{\"categories\":[]}";

        bool HandleWebAuthPlaintext(TlsSession& session, SOCKET socket, std::uint64_t id,
            const std::string& peer, const void* payload, std::size_t size)
        {
            if (payload && size)
            {
                std::vector<std::uint8_t> combined = session.httpInput;
                const auto* bytes = static_cast<const std::uint8_t*>(payload);
                combined.insert(combined.end(), bytes, bytes + size);

                if (combined.size() <= 1024u * 1024u)
                {
                    const std::string request(
                        reinterpret_cast<const char*>(combined.data()), combined.size());
                    const std::size_t headerEnd = request.find("\r\n\r\n");
                    if (headerEnd != std::string::npos)
                    {
                        const std::size_t firstLineEnd = request.find("\r\n");
                        const std::string firstLine = firstLineEnd == std::string::npos
                            ? request.substr(0, headerEnd)
                            : request.substr(0, firstLineEnd);

                        const std::size_t pathEnd = firstLine.find(' ', 4u);
                        const std::string path = firstLine.rfind("GET ", 0) == 0 && pathEnd != std::string::npos
                            ? firstLine.substr(4u, pathEnd - 4u) : std::string();
                        const std::string prefix = localpublisher::PathPrefix;
                        const bool manifest = localpublisher::LocalManifestEnabled() &&
                            path.rfind(prefix, 0) == 0 &&
                            localpublisher::IsManifest(path.substr(prefix.size()));
                        if (path == kLocalPublisherStorePath || manifest)
                        {
                            const std::string body = manifest
                                ? localpublisher::ManifestBody() : kLocalPublisherStoreJson;
                            std::ostringstream response;
                            response << "HTTP/1.1 200 OK\r\n"
                                     << "Content-Type: application/json; charset=utf-8\r\n"
                                     << "Content-Length: " << body.size() << "\r\n"
                                     << "Cache-Control: no-store\r\n"
                                     << "Connection: close\r\n"
                                     << "\r\n"
                                     << body;
                            const std::string wire = response.str();

                            if (!SendTlsApplication(
                                    session, socket, id, peer,
                                    wire.data(), wire.size(),
                                    "local ObjectStore publisher content"))
                            {
                                return false;
                            }

                            session.httpInput.clear();
                            session.webAuthHttpServed = true;
                            log::Print(
                                "[DW-OBJECTSTORE-HTTP] id=%llu path=%s status=200 bytes=%llu body=local-publisher-content",
                                static_cast<unsigned long long>(id),
                                path.c_str(),
                                static_cast<unsigned long long>(body.size()));
                            shutdown(socket, SD_SEND);
                            return true;
                        }
                    }
                }
            }

            return HandleWebAuthPlaintext_Base(session, socket, id, peer, payload, size);
        }
    }
}
