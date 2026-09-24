#include "TcpReceive.h"

namespace revamped::iw8
{
    void Server::ReadTcp(std::size_t index)
    {
        if (index >= clients_.size()) return;
        Client& client = clients_[index];
        unsigned char buffer[64 * 1024]{};
        const int result = recv(client.socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
        if (result == 0)
        {
            CloseClient(index, "peer-closed");
            return;
        }
        if (result == SOCKET_ERROR)
        {
            const int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK)
            {
                char detail[64]{};
                _snprintf_s(detail, sizeof(detail), _TRUNCATE, "recv-error-wsa=%d", error);
                CloseClient(index, detail);
            }
            return;
        }
        if (config_.dumpPayloads)
            log::Payload(client.id, "IN", client.localPort, client.peer, buffer, static_cast<std::size_t>(result));

        if (client.localPort == 3074u || client.localPort == 3075u)
        {
            if (!HandleLsgTcp(client, buffer, static_cast<std::size_t>(result)))
                CloseClient(index, "lsg-send-failed");
            return;
        }

        if (client.firstPacket)
        {
            client.firstPacket = false;
            if (client.localPort == 1119)
                log::Print("[AUTH] id=%llu first Battle.net client payload captured bytes=%d; attempting real TLS transport only",
                    static_cast<unsigned long long>(client.id), result);
            else if (client.localPort == 443 && result >= 5 && buffer[0] == 0x16 && buffer[1] == 0x03)
                log::Print("[WEB-AUTH] id=%llu HTTPS/TLS ClientHello reached local :443 bytes=%d after BGS challenge; web-login TLS/HTTP emulation is the next layer",
                    static_cast<unsigned long long>(client.id), result);
        }

        if (client.localPort == 1119 || client.localPort == 443)
        {
            auto* session = static_cast<TlsSession*>(client.tlsState);
            if (!session)
            {
                session = new TlsSession();
                session->localPort = client.localPort;
                client.tlsState = session;
            }
            session->input.insert(session->input.end(), buffer, buffer + static_cast<std::size_t>(result));
            if (!session->helloLogged)
            {
                session->helloLogged = LogTlsClientHello(client.id, client.localPort, session->input.data(), session->input.size(), &session->sni);
                if (session->helloLogged)
                    log::Print("[TLS%u] id=%llu ClientHello decoded; replying through SChannel with the local diagnostic certificate",
                        static_cast<unsigned>(client.localPort), static_cast<unsigned long long>(client.id));
            }
            if (!PumpTls(*session, client.socket, client.id, client.peer))
            {
                CloseClient(index, client.localPort == 443 ? "tls443-handshake-or-http-failed" : "tls1119-handshake-or-decrypt-failed");
            }
            return;
        }

        // We now have one decoded, non-auth bootstrap request from the 1.44 client:
        //   GET /pc/0/xpak_ignore.keylist
        // An empty ignore list is a valid local preservation fallback and lets the
        // client continue without inventing any Battle.net/Demonware auth payload.
        if (client.localPort == 80)
        {
            const std::string request(reinterpret_cast<const char*>(buffer), static_cast<std::size_t>(result));

            if (request.rfind("GET /__revamped/iw8.crl ", 0) == 0)
            {
                if (g_tlsCrlDer.empty())
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Length: 0\r\n"
                        "Cache-Control: no-store\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    log::Print("[TRUST-CRL] id=%llu CRL fetch arrived before CRL was ready",
                        static_cast<unsigned long long>(client.id));
                    CloseClient(index, "crl-not-ready-503");
                    return;
                }

                char header[384]{};
                const int headerLength = _snprintf_s(header, sizeof(header), _TRUNCATE,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/pkix-crl\r\n"
                    "Content-Length: %llu\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    static_cast<unsigned long long>(g_tlsCrlDer.size()));
                const bool headerOk = headerLength > 0 &&
                    SendAllNonBlocking(client.socket, header, static_cast<std::size_t>(headerLength));
                const bool bodyOk = headerOk &&
                    SendAllNonBlocking(client.socket, g_tlsCrlDer.data(), g_tlsCrlDer.size());

                if (config_.dumpPayloads && headerOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer,
                        header, static_cast<std::size_t>(headerLength));
                if (config_.dumpPayloads && bodyOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer,
                        g_tlsCrlDer.data(), g_tlsCrlDer.size());

                log::Print("[TRUST-CRL] id=%llu served local empty CRL bytes=%llu result=%s",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(g_tlsCrlDer.size()),
                    bodyOk ? "ok" : "send-failed");
                CloseClient(index, bodyOk ? "crl-200" : "crl-send-failed");
                return;
            }

            // Tiny startup health/prewarm route used by the redirect DLL.  It
            // intentionally carries no auth state; its only purpose is to make
            // the local accept path, trust bootstrap and first socket work happen
            // before the intro starts doing time-sensitive online work.
            if (request.rfind("GET /__revamped/prewarm ", 0) == 0)
            {
                static const char response[] =
                    "HTTP/1.1 204 No Content\r\n"
                    "Content-Length: 0\r\n"
                    "Cache-Control: no-store\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                const bool sent = SendAllNonBlocking(client.socket, response, sizeof(response) - 1);
                log::Print("[PREWARM] id=%llu local backend prewarm request served status=204",
                    static_cast<unsigned long long>(client.id));
                CloseClient(index, sent ? "prewarm-204" : "prewarm-send-failed");
                return;
            }

            if (request.rfind("GET /pc/0/xpak_ignore.keylist ", 0) == 0)
            {
                static const char response[] =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                const int sent = send(client.socket, response, static_cast<int>(sizeof(response) - 1), 0);
                if (sent > 0 && config_.dumpPayloads)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, response, static_cast<std::size_t>(sent));
                if (sent == SOCKET_ERROR)
                {
                    char detail[64]{};
                    _snprintf_s(detail, sizeof(detail), _TRUNCATE, "http-keylist-send-wsa=%d", WSAGetLastError());
                    CloseClient(index, detail);
                }
                else
                {
                    CloseClient(index, "http-keylist-empty-200");
                }
                return;
            }

            if (request.rfind("GET /Bnet/zxx/client/bgs-key-fingerprint ", 0) == 0)
            {
                log::Print("[BGS-BUNDLE] id=%llu stock client requested /Bnet/zxx/client/bgs-key-fingerprint",
                    static_cast<unsigned long long>(client.id));

                const auto stockBundle = LoadStockBgsCertificateBundle();
                if (stockBundle.empty())
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    log::Print("[BGS-BUNDLE] id=%llu stock signed bundle file is not available yet; expected CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock",
                        static_cast<unsigned long long>(client.id));
                    CloseClient(index, "bgs-key-fingerprint-stock-bundle-missing");
                    return;
                }

                std::size_t pinReplacements = 0;
                bool signatureVerified = false;
                const auto bundle = BuildLocalBgsTrustBundle(stockBundle, pinReplacements, signatureVerified);
                log::Print("[BGS-BUNDLE] id=%llu OPTION2 signed local trust bundle trustCert=local-root-ca+ca-signed-leaf caSpki=%s pinReplacements=%llu signatureVerified=%s stockJsonBytes=%llu wireBytes=%llu",
                    static_cast<unsigned long long>(client.id),
                    g_tlsSpkiSha256.empty() ? "<unavailable>" : g_tlsSpkiSha256.c_str(),
                    static_cast<unsigned long long>(pinReplacements),
                    signatureVerified ? "yes" : "no",
                    static_cast<unsigned long long>(stockBundle.size()),
                    static_cast<unsigned long long>(bundle.size()));

                if (bundle.empty() || !signatureVerified)
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    CloseClient(index, "bgs-key-fingerprint-local-signing-failed");
                    return;
                }

                char header[512]{};
                const int headerLength = _snprintf_s(header, sizeof(header), _TRUNCATE,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Content-Length: %llu\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    static_cast<unsigned long long>(bundle.size()));

                const bool headerOk = headerLength > 0 &&
                    SendAllNonBlocking(client.socket, header, static_cast<std::size_t>(headerLength));
                const bool bodyOk = headerOk &&
                    SendAllNonBlocking(client.socket, bundle.data(), bundle.size());

                if (config_.dumpPayloads && headerOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, header, static_cast<std::size_t>(headerLength));
                if (config_.dumpPayloads && bodyOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, bundle.data(), bundle.size());

                if (!bodyOk)
                {
                    const int error = WSAGetLastError();
                    log::Print("[BGS-BUNDLE] id=%llu failed sending stock signed bundle bytes=%llu wsa=%d",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(bundle.size()),
                        error);
                    CloseClient(index, "bgs-key-fingerprint-send-failed");
                }
                else
                {
                    log::Print("[BGS-BUNDLE] id=%llu served OPTION2 signed BGS bundle bytes=%llu format=JSON(local CA trust)+NGIS+RSA2048LE pinReplacements=%llu signatureVerified=yes; login/fence/LUI state remains server-driven",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(bundle.size()),
                        static_cast<unsigned long long>(pinReplacements));
                    CloseClient(index, "bgs-key-fingerprint-option2-signed-200");
                }
                return;
            }
        }

        // Private diagnostic probe only; unknown IW8 binary traffic remains
        // capture-only until its framing/handshake is actually observed.
        static const char probe[] = "CRIW8PNG";
        static const char reply[] = "CRIW8PONG\n";
        if (result >= static_cast<int>(sizeof(probe) - 1) && std::equal(buffer, buffer + sizeof(probe) - 1, reinterpret_cast<const unsigned char*>(probe)))
            send(client.socket, reply, static_cast<int>(sizeof(reply) - 1), 0);
    }
}
