#include "Run.h"

namespace revamped::iw8
{
    void Server::Run()
    {
        while (running_)
        {
            fd_set readSet{};
            FD_ZERO(&readSet);
            SOCKET maximum = 0;
            for (const auto& listener : listeners_)
            {
                FD_SET(listener.socket, &readSet);
                maximum = (std::max)(maximum, listener.socket);
            }
            for (const auto& client : clients_)
            {
                FD_SET(client.socket, &readSet);
                maximum = (std::max)(maximum, client.socket);
            }
            timeval timeout{};
            timeout.tv_sec = 0;
            timeout.tv_usec = 250000;
            const int ready = select(static_cast<int>(maximum + 1), &readSet, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR)
            {
                log::Print("select failed WSA=%d", WSAGetLastError());
                Sleep(100);
                continue;
            }
            for (auto& listener : listeners_)
            {
                if (!FD_ISSET(listener.socket, &readSet)) continue;
                if (listener.udp) ReadUdp(listener); else AcceptTcp(listener);
            }
            for (std::size_t i = clients_.size(); i-- > 0; )
                if (i < clients_.size() && FD_ISSET(clients_[i].socket, &readSet)) ReadTcp(i);

            web::PollAuthPipelineDiagnostics();

            const ULONGLONG now = GetTickCount64();
            for (auto& client : clients_)
            {
                if (client.localPort != 1119) continue;

                if (client.firstPacket && !client.authIdleLogged && client.acceptedAtMs && now - client.acceptedAtMs >= 3000)
                {
                    client.authIdleLogged = true;
                    log::Print("[AUTH] id=%llu :1119 has no TLS client payload after 3s. No guessed bytes sent.",
                        static_cast<unsigned long long>(client.id));
                }

                auto* session = static_cast<TlsSession*>(client.tlsState);
                if (session && session->established && !session->bgsApplicationSeen && !session->serverFirstLogged &&
                    session->establishedAtMs && now - session->establishedAtMs >= 3000)
                {
                    session->serverFirstLogged = true;
                    log::Print("[BGS1119] id=%llu no decrypted application data arrived within 3s of TLS establishment",
                        static_cast<unsigned long long>(client.id));
                    log::Print("[BGS1119] id=%llu documented BGS order is client ConnectionService.Connect -> ConnectResponse -> server ChallengeListener.OnExternalChallenge -> client AuthenticationService.Logon",
                        static_cast<unsigned long long>(client.id));
                    log::Print("[BGS1119] id=%llu MW2019 has not issued ConnectionService.Connect yet; pure emulation will NOT inject a challenge or fake a connection response. Waiting for the client while the DLL scans the Battle.net token/bootstrap gate.",
                        static_cast<unsigned long long>(client.id));
                }
            }
        }
    }
}
