#include "UdpReceive.h"

namespace revamped::iw8
{
    void Server::ReadUdp(Listener& listener)
    {
        for (;;)
        {
            unsigned char buffer[64 * 1024]{};
            sockaddr_storage peer{};
            int peerLength = sizeof(peer);
            const int result = recvfrom(listener.socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                reinterpret_cast<sockaddr*>(&peer), &peerLength);
            if (result == SOCKET_ERROR)
            {
                const int error = WSAGetLastError();
                if (error != WSAEWOULDBLOCK) log::Print("recvfrom(%u) failed WSA=%d", listener.port, error);
                break;
            }
            if (result <= 0) break;
            if (listener.port == 3074u)
            {
                // Port 3074 is shared by several Demonware flows (notably STUN).
                // Do not promote arbitrary UDP here to a proven lobby connection.
                // The client-side DNS->transport correlator identifies the original
                // hostname; this server log only exposes the raw datagram shape.
                web::NotePostLsgTransport(listener.port, "UDP_UNATTRIBUTED");
                static unsigned visibleUdp3074 = 0;
                if (visibleUdp3074 < 12u)
                {
                    ++visibleUdp3074;
                    const std::string peerText = EndpointToString(reinterpret_cast<sockaddr*>(&peer), peerLength);
                    const bool stunLike = result >= 20 && (buffer[0] & 0xC0u) == 0u &&
                        buffer[4] == 0x21u && buffer[5] == 0x12u && buffer[6] == 0xA4u && buffer[7] == 0x42u;
                    const std::string packetType = stunLike ? "stun-rfc5389" : protocol::Classify(buffer, static_cast<std::size_t>(result));
                    log::Print("[UDP3074-PROBE] packet=%u peer=%s bytes=%d type=%s hex=%s ascii=%s attribution=UNVERIFIED",
                        visibleUdp3074, peerText.c_str(), result, packetType.c_str(),
                        protocol::HexPrefix(buffer, static_cast<std::size_t>(result), 96).c_str(),
                        protocol::AsciiPrefix(buffer, static_cast<std::size_t>(result), 96).c_str());
                }
            }
            log::Udp(listener.port, EndpointToString(reinterpret_cast<sockaddr*>(&peer), peerLength), buffer, static_cast<std::size_t>(result));
        }
    }
}
