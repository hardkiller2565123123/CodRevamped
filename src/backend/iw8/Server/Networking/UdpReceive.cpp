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
            // Legacy Demonware discovery (not RFC5389). The existing local
            // Demonware implementation uses reply 31/21, version 2, followed
            // by IPv4 bytes and a little-endian port. Derive endpoints from
            // the socket instead of inventing the client's external port.
            if (listener.port == 3074u && peer.ss_family == AF_INET &&
                ((result == 3 && buffer[0] == 30 && buffer[1] == 3 && buffer[2] == 0) ||
                 (result == 4 && buffer[0] == 20 && buffer[1] == 2 && buffer[2] == 0)))
            {
                const auto& remote = reinterpret_cast<const sockaddr_in&>(peer);
                unsigned char reply[15]{static_cast<unsigned char>(buffer[0] + 1), 2, 0};
                std::memcpy(reply + 3, &remote.sin_addr, 4);
                const auto remotePort = ntohs(remote.sin_port);
                reply[7] = static_cast<unsigned char>(remotePort);
                reply[8] = static_cast<unsigned char>(remotePort >> 8);
                const int replyLength = buffer[0] == 30 ? 9 : 15;
                if (replyLength == 15)
                {
                    sockaddr_in local{};
                    int localLength = sizeof(local);
                    getsockname(listener.socket, reinterpret_cast<sockaddr*>(&local), &localLength);
                    if (local.sin_addr.s_addr == INADDR_ANY)
                        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                    std::memcpy(reply + 9, &local.sin_addr, 4);
                    reply[13] = static_cast<unsigned char>(listener.port);
                    reply[14] = static_cast<unsigned char>(listener.port >> 8);
                }
                const int sent = sendto(listener.socket, reinterpret_cast<const char*>(reply), replyLength, 0,
                    reinterpret_cast<const sockaddr*>(&peer), peerLength);
                log::Print("[DW-DISCOVERY] request=%u peer=%s replyBytes=%d sent=%d",
                    buffer[0], EndpointToString(reinterpret_cast<const sockaddr*>(&peer), peerLength).c_str(), replyLength, sent);
            }
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
