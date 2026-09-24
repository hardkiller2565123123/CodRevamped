#include "BgsPlaintext.h"

namespace revamped::iw8
{
    namespace
    {
        bool HandleBgsPlaintext(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            const void* payload, std::size_t size)
        {
            if (!payload || !size) return true;
            const BYTE* bytes = static_cast<const BYTE*>(payload);

            if (!session.websocketUpgraded)
            {
                if (session.webAuthHttpServed)
                    return true;
                session.websocketInput.insert(session.websocketInput.end(), bytes, bytes + size);
                if (session.websocketInput.size() > 64u * 1024u)
                {
                    log::Print("[WS1119] id=%llu websocket HTTP upgrade header exceeded 64 KiB",
                        static_cast<unsigned long long>(id));
                    return false;
                }

                const std::string bufferedRequest(reinterpret_cast<const char*>(session.websocketInput.data()), session.websocketInput.size());
                const std::size_t headerTerminator = bufferedRequest.find("\r\n\r\n");
                if (headerTerminator == std::string::npos)
                {
                    log::Print("[WS1119] id=%llu websocket HTTP upgrade request is fragmented; bufferedBytes=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(session.websocketInput.size()));
                    return true;
                }
                const std::size_t headerBytes = headerTerminator + 4;
                const std::string request = bufferedRequest.substr(0, headerBytes);
                std::vector<BYTE> trailing;
                if (session.websocketInput.size() > headerBytes)
                    trailing.assign(session.websocketInput.begin() + static_cast<std::ptrdiff_t>(headerBytes), session.websocketInput.end());

                // A second HTTPS connection to this same :1119 listener is used
                // as the local web-auth endpoint advertised by the BGS challenge.
                // Serve a deliberately local/test-only page so we can prove the
                // stock web-auth UI has reached Revamped before implementing ticket
                // issuance. No credentials are accepted or stored in this step.
                if (request.rfind("GET /bnet/login/", 0) == 0 || request.rfind("GET /bnet/login?", 0) == 0)
                {
                    static const char html[] =
                        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                        "<title>Revamped Local Sign In</title><style>body{margin:0;background:#11151b;color:#f4f7fb;font-family:Segoe UI,Arial,sans-serif;display:grid;place-items:center;min-height:100vh}"
                        ".card{width:min(560px,calc(100% - 48px));background:#1a2029;border:1px solid #303a48;border-radius:12px;padding:32px;box-shadow:0 20px 60px #0008}"
                        "h1{font-size:28px;margin:0 0 10px}p{line-height:1.5;color:#b9c4d2}.ok{margin-top:22px;padding:14px 16px;background:#152d22;border:1px solid #2d7652;border-radius:8px;color:#bff3d5}"
                        "code{color:#d7e7ff}</style></head><body><main class=\"card\"><h1>Revamped Local Sign In</h1>"
                        "<p>MW2019 reached the local Battle.net web-auth endpoint successfully.</p>"
                        "<div class=\"ok\">Local web authentication is connected. Account login/create-account ticket exchange is the next emulation step.</div>"
                        "<p>This page does not accept or store Blizzard credentials.</p></main></body></html>";
                    char responseHeader[512]{};
                    const int responseHeaderLength = _snprintf_s(responseHeader, sizeof(responseHeader), _TRUNCATE,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: %llu\r\nConnection: close\r\n\r\n",
                        static_cast<unsigned long long>(sizeof(html) - 1));
                    if (responseHeaderLength <= 0 ||
                        !SendTlsApplication(session, socket, id, peer, responseHeader, static_cast<std::size_t>(responseHeaderLength), "local web-auth HTTP headers") ||
                        !SendTlsApplication(session, socket, id, peer, html, sizeof(html) - 1, "local web-auth HTML"))
                        return false;

                    session.webAuthHttpServed = true;
                    session.websocketInput.clear();
                    log::Print("[WEB-AUTH] id=%llu LOCAL LOGIN PAGE SERVED path=/bnet/login/; no credentials accepted yet; waiting for the next stock auth action",
                        static_cast<unsigned long long>(id));
                    shutdown(socket, SD_SEND);
                    return true;
                }

                if (request.rfind("GET / HTTP/1.1", 0) != 0 || request.find("Upgrade: websocket") == std::string::npos)
                {
                    log::Print("[WS1119] id=%llu plaintext before websocket upgrade is not the expected HTTP websocket request ascii=%s",
                        static_cast<unsigned long long>(id), protocol::AsciiPrefix(request.data(), request.size(), 512).c_str());
                    return false;
                }

                session.websocketUpgradeSeen = true;
                const std::string clientKey = HttpHeaderValue(request, "Sec-WebSocket-Key");
                const std::string requestedProtocol = HttpHeaderValue(request, "Sec-WebSocket-Protocol");
                const std::string accept = BuildWebSocketAccept(clientKey);
                if (clientKey.empty() || accept.empty())
                {
                    log::Print("[WS1119] id=%llu websocket upgrade parse failed key=%s accept=%s",
                        static_cast<unsigned long long>(id), clientKey.empty() ? "missing" : "present", accept.empty() ? "missing" : "present");
                    return false;
                }

                std::ostringstream response;
                response << "HTTP/1.1 101 Switching Protocols\r\n"
                         << "Upgrade: websocket\r\n"
                         << "Connection: Upgrade\r\n"
                         << "Sec-WebSocket-Accept: " << accept << "\r\n";
                if (!requestedProtocol.empty())
                    response << "Sec-WebSocket-Protocol: " << requestedProtocol << "\r\n";
                response << "\r\n";
                const std::string responseText = response.str();

                log::Print("[WS1119] id=%llu websocket upgrade request key=%s protocol=%s",
                    static_cast<unsigned long long>(id), clientKey.c_str(), requestedProtocol.empty() ? "<none>" : requestedProtocol.c_str());
                if (!SendTlsApplication(session, socket, id, peer, responseText.data(), responseText.size(), "WebSocket HTTP 101"))
                    return false;

                session.websocketUpgraded = true;
                session.websocketInput.clear();
                log::Print("[WS1119] id=%llu WEBSOCKET UPGRADE ACCEPTED status=101 protocol=%s accept=%s; waiting for first v1.rpc.battle.net binary frame",
                    static_cast<unsigned long long>(id), requestedProtocol.empty() ? "<none>" : requestedProtocol.c_str(), accept.c_str());
                if (!trailing.empty())
                {
                    log::Print("[WS1119] id=%llu websocket upgrade carried trailing encrypted-application plaintext bytes=%llu; decoding as websocket frames",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(trailing.size()));
                    return PumpWebSocketFrames(session, socket, id, peer, trailing.data(), trailing.size());
                }
                return true;
            }

            return PumpWebSocketFrames(session, socket, id, peer, bytes, size);
        }
    }
}
