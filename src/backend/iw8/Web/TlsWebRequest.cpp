#include "TlsWebRequest.h"

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

                // The stock client opens these as short-lived HTTPS requests. Close
                // the send side after one response so retry/next-stage behavior is             
                shutdown(socket, SD_SEND);
                session.webAuthHttpServed = true;
                return true;
            }
        }
    }
}
