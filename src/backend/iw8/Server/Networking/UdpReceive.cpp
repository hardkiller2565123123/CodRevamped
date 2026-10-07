#include "UdpReceive.h"

namespace revamped::iw8
{
    namespace
    {
        constexpr std::uint32_t kIpDiscoveryXorAddress = 0x2112A442u;
        constexpr std::uint16_t kIpDiscoveryXorPort = 0x2112u;
        constexpr std::uint16_t kNatDiscoveryPrimaryPort = 3074u;
        constexpr std::uint16_t kNatDiscoverySecondaryPort = 3075u;

        void WriteBdIpv4Address(unsigned char* output, const sockaddr_in& address)
        {
            // bdSockAddr::serialize (IW8, IPv4) is exactly:
            //   4 raw IPv4 bytes + uint16 host-order port written little-endian.
            std::memcpy(output, &address.sin_addr, 4);
            const std::uint16_t port = ntohs(address.sin_port);
            output[4] = static_cast<unsigned char>(port & 0xFFu);
            output[5] = static_cast<unsigned char>((port >> 8) & 0xFFu);
        }

        void WriteProtectedBdIpv4Address(unsigned char* output, const sockaddr_in& address)
        {
            // bdIPDiscoveryPacketReply protocol >= 3 serializes a second
            // protected address. The stock client XORs it back with the same
            // constants before comparing it with the ordinary public address.
            std::uint32_t ip = 0;
            std::memcpy(&ip, &address.sin_addr, sizeof(ip));
            ip ^= kIpDiscoveryXorAddress;
            std::memcpy(output, &ip, sizeof(ip));

            const std::uint16_t protectedPort = static_cast<std::uint16_t>(ntohs(address.sin_port) ^ kIpDiscoveryXorPort);
            output[4] = static_cast<unsigned char>(protectedPort & 0xFFu);
            output[5] = static_cast<unsigned char>((protectedPort >> 8) & 0xFFu);
        }
    }

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

            // IW8 uses Demonware's legacy IP/NAT discovery packets here, not
            // RFC5389 STUN. Their wire structs are defined by bdSockAddr's
            // compact IPv4 serializer (4-byte address + LE uint16 port).
            if ((listener.port == kNatDiscoveryPrimaryPort || listener.port == kNatDiscoverySecondaryPort) &&
                peer.ss_family == AF_INET)
            {
                const auto& remote = reinterpret_cast<const sockaddr_in&>(peer);

                // bdIPDiscoveryPacket: type 30 + uint16 protocol version.
                if (listener.port == kNatDiscoveryPrimaryPort && result == 3 && buffer[0] == 30)
                {
                    const std::uint16_t protocolVersion = static_cast<std::uint16_t>(buffer[1] | (buffer[2] << 8));
                    if (protocolVersion == 2u || protocolVersion == 3u)
                    {
                        unsigned char reply[15]{};
                        reply[0] = 31; // bdIPDiscoveryPacketReply
                        reply[1] = static_cast<unsigned char>(protocolVersion & 0xFFu);
                        reply[2] = static_cast<unsigned char>((protocolVersion >> 8) & 0xFFu);
                        WriteBdIpv4Address(reply + 3, remote);

                        int replyLength = 9;
                        if (protocolVersion >= 3u)
                        {
                            // v3 MUST include the protected/XOR address. A
                            // 9-byte v3 reply deserializes the first address,
                            // then fails while reading this second one and keeps
                            // bdIPDiscoveryClient in BD_IP_DISC_RUNNING.
                            WriteProtectedBdIpv4Address(reply + 9, remote);
                            replyLength = 15;
                        }

                        const int sent = sendto(listener.socket, reinterpret_cast<const char*>(reply), replyLength, 0,
                            reinterpret_cast<const sockaddr*>(&peer), peerLength);
                        log::Print("[DW-IPDISCOVERY] version=%u peer=%s replyBytes=%d sent=%d hex=%s",
                            static_cast<unsigned>(protocolVersion),
                            EndpointToString(reinterpret_cast<const sockaddr*>(&peer), peerLength).c_str(),
                            replyLength, sent,
                            protocol::HexPrefix(reply, static_cast<std::size_t>(replyLength), 32).c_str());
                    }
                }
                // bdNATTypeDiscoveryPacket: type 20 + uint16 version + request.
                else if (result == 4 && buffer[0] == 20 && buffer[1] == 2 && buffer[2] == 0)
                {
                    unsigned char reply[15]{21, 2, 0}; // bdNATTypeDiscoveryPacketReply v2
                    WriteBdIpv4Address(reply + 3, remote); // mapped address

                    sockaddr_in secondary{};
                    int secondaryLength = sizeof(secondary);
                    getsockname(listener.socket, reinterpret_cast<sockaddr*>(&secondary), &secondaryLength);
                    if (secondary.sin_addr.s_addr == INADDR_ANY)
                        secondary.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                    // Demonware NAT discovery test 1 returns a secondary server
                    // address.  IW8's test-2 handler then requires the reply
                    // source IP to match that secondary address while the reply
                    // source PORT must differ from the advertised secondary
                    // port.  Advertising 3074 while also replying from 3074
                    // leaves the client in BD_NTDCS_RUN_TEST_2 and causes the
                    // repeated request=3 loop seen on Steam Retail.
                    //
                    // Advertise the companion UDP port (3075) while answering
                    // test 2 from the primary 3074 socket.  That satisfies the
                    // stock "same secondary IP, different port" check and lets
                    // IW8 classify the local path as open/no-NAT immediately.
                    secondary.sin_port = htons(kNatDiscoverySecondaryPort);
                    WriteBdIpv4Address(reply + 9, secondary);

                    const int sent = sendto(listener.socket, reinterpret_cast<const char*>(reply), sizeof(reply), 0,
                        reinterpret_cast<const sockaddr*>(&peer), peerLength);
                    log::Print("[DW-NATDISCOVERY] request=%u version=2 rxPort=%u secondary=%s peer=%s replyBytes=%u sent=%d hex=%s",
                        static_cast<unsigned>(buffer[3]),
                        static_cast<unsigned>(listener.port),
                        EndpointToString(reinterpret_cast<const sockaddr*>(&secondary), sizeof(secondary)).c_str(),
                        EndpointToString(reinterpret_cast<const sockaddr*>(&peer), peerLength).c_str(),
                        static_cast<unsigned>(sizeof(reply)), sent,
                        protocol::HexPrefix(reply, sizeof(reply), 32).c_str());
                }
            }

            if (listener.port == 3074u)
            {
                // Port 3074 is shared by several Demonware flows. Do not
                // promote arbitrary UDP here to a proven lobby connection.
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
