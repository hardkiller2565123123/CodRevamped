#include "CloseClient.h"
#include "../../Demonware/Lsg/LsgHostedSessions.h"

namespace revamped::iw8
{
    void Server::CloseClient(std::size_t index, const char* reason)
    {
        if (index >= clients_.size()) return;
        Client& client = clients_[index];
        log::Connection(client.id, client.peer, client.localPort, "closed", reason);
        lsg::RetireHostedLsgClient(client.id);
        DestroyTlsSession(client.tlsState);
        closesocket(client.socket);
        clients_.erase(clients_.begin() + static_cast<std::ptrdiff_t>(index));
    }
}
