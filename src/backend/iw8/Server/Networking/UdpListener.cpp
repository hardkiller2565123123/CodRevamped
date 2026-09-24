#include "UdpListener.h"

namespace revamped::iw8
{
    bool Server::CreateUdpListener(std::uint16_t port)
    {
        SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket == INVALID_SOCKET)
        {
            log::Print("UDP socket(%u) failed WSA=%d", port, WSAGetLastError());
            return false;
        }
        BOOL reuse = TRUE;
        setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        if (InetPtonA(AF_INET, config_.bindAddress.c_str(), &address.sin_addr) != 1)
            address.sin_addr.s_addr = INADDR_ANY;
        if (bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR)
        {
            log::Print("UDP bind %s:%u failed WSA=%d", config_.bindAddress.c_str(), port, WSAGetLastError());
            closesocket(socket);
            return false;
        }
        MakeNonBlocking(socket);
        listeners_.push_back({socket, port, true});
        log::Print("UDP listening on %s:%u", config_.bindAddress.c_str(), port);
        return true;
    }
}
