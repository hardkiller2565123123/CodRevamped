#include "Stop.h"

namespace revamped::iw8
{
    void Server::Stop()
    {
        if (!running_.exchange(false)) return;
        for (auto& client : clients_)
        {
            DestroyTlsSession(client.tlsState);
            if (client.socket != INVALID_SOCKET) closesocket(client.socket);
        }
        clients_.clear();
        for (auto& listener : listeners_)
            if (listener.socket != INVALID_SOCKET) closesocket(listener.socket);
        listeners_.clear();
        ShutdownTlsCredential();
        ShutdownBundleSigner();
        WSACleanup();
    }
}
