#include "TcpAccept.h"

namespace revamped::iw8
{
    void Server::AcceptTcp(Listener& listener)
    {
        for (;;)
        {
            sockaddr_storage peer{};
            int peerLength = sizeof(peer);
            SOCKET socket = accept(listener.socket, reinterpret_cast<sockaddr*>(&peer), &peerLength);
            if (socket == INVALID_SOCKET)
            {
                const int error = WSAGetLastError();
                if (error != WSAEWOULDBLOCK) log::Print("accept(%u) failed WSA=%d", listener.port, error);
                break;
            }
            MakeNonBlocking(socket);
            Client client{};
            client.socket = socket;
            client.id = nextClientId_++;
            client.localPort = listener.port;
            client.peer = EndpointToString(reinterpret_cast<sockaddr*>(&peer), peerLength);
            client.acceptedAtMs = GetTickCount64();
            clients_.push_back(client);
            log::Connection(client.id, client.peer, client.localPort, "accepted");
            if (client.localPort == 3074u || client.localPort == 3075u)
                web::NotePostLsgTransport(client.localPort, "TCP_UNATTRIBUTED");
            if (client.localPort == 1119)
                log::Print("[AUTH] id=%llu Battle.net :1119 connected; TLS transport will be handled by SChannel. BGS/login application replies remain capture-driven.",
                    static_cast<unsigned long long>(client.id));
        }
    }
}
