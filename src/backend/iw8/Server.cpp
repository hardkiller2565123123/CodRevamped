#include "Server.h"
#include "Log.h"
#include "Protocol.h"
#include "Web/WebAuthService.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <utility>

#pragma comment(lib, "Ws2_32.lib")

namespace revamped::iw8
{
    namespace
    {
        std::string EndpointToString(const sockaddr* address, int length)
        {
            if (!address || length < static_cast<int>(sizeof(sockaddr))) return "<unknown>";
            char buffer[128]{};
            if (address->sa_family == AF_INET && length >= static_cast<int>(sizeof(sockaddr_in)))
            {
                const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
                const auto* bytes = reinterpret_cast<const unsigned char*>(&v4->sin_addr.s_addr);
                _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "%u.%u.%u.%u:%u",
                    bytes[0], bytes[1], bytes[2], bytes[3], ntohs(v4->sin_port));
                return buffer;
            }
            if (address->sa_family == AF_INET6 && length >= static_cast<int>(sizeof(sockaddr_in6)))
            {
                const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
                _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "[ipv6]:%u", ntohs(v6->sin6_port));
                return buffer;
            }
            _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "family=%d", address->sa_family);
            return buffer;
        }

        void MakeNonBlocking(SOCKET socket)
        {
            u_long value = 1;
            ioctlsocket(socket, FIONBIO, &value);
        }
    }

    Server::Server(ServerConfig config) : config_(std::move(config)) {}

    Server::~Server()
    {
        Stop();
    }

    bool Server::CreateTcpListener(std::uint16_t port)
    {
        SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket == INVALID_SOCKET)
        {
            log::Print("TCP socket(%u) failed WSA=%d", port, WSAGetLastError());
            return false;
        }
        BOOL reuse = TRUE;
        setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        if (InetPtonA(AF_INET, config_.bindAddress.c_str(), &address.sin_addr) != 1)
            address.sin_addr.s_addr = INADDR_ANY;
        if (bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR || listen(socket, SOMAXCONN) == SOCKET_ERROR)
        {
            log::Print("TCP bind/listen %s:%u failed WSA=%d", config_.bindAddress.c_str(), port, WSAGetLastError());
            closesocket(socket);
            return false;
        }
        MakeNonBlocking(socket);
        listeners_.push_back({socket, port, false});
        log::Print("TCP listening on %s:%u", config_.bindAddress.c_str(), port);

        // The stock IW8 bootstrap can occasionally surface an AF_INET6 direct-IP
        // candidate before its normal IPv4 candidate.  The client bridge preserves
        // the socket family and therefore redirects that candidate to ::1.  The
        // preservation server historically listened only on 0.0.0.0, so ::1 had
        // nobody accepting it and the stock bootstrap would enter a different
        // failure/retry path before falling back to IPv4.
        //
        // Keep the existing IPv4 listener as the primary listener, but add a
        // loopback-only IPv6 companion for the two direct bootstrap ports.  This
        // changes transport reachability only; it does not synthesize any auth,
        // sign-in, fence or LUI state.
        if (port == 80u || port == 1119u)
        {
            SOCKET socket6 = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
            if (socket6 == INVALID_SOCKET)
            {
                log::Print("[IPV6-BOOT] TCP socket([::1]:%u) unavailable WSA=%d; IPv4 listener remains active",
                    port, WSAGetLastError());
            }
            else
            {
                BOOL reuse6 = TRUE;
                setsockopt(socket6, SOL_SOCKET, SO_REUSEADDR,
                    reinterpret_cast<const char*>(&reuse6), sizeof(reuse6));

                // Keep this companion IPv6-only so it cannot conflict with the
                // existing AF_INET listener on the same port.
                DWORD v6Only = 1;
                const int v6OnlyResult = setsockopt(socket6, IPPROTO_IPV6, IPV6_V6ONLY,
                    reinterpret_cast<const char*>(&v6Only), sizeof(v6Only));

                sockaddr_in6 address6{};
                address6.sin6_family = AF_INET6;
                address6.sin6_port = htons(port);
                address6.sin6_addr.u.Byte[15] = 1; // ::1

                if (v6OnlyResult == SOCKET_ERROR ||
                    bind(socket6, reinterpret_cast<const sockaddr*>(&address6), sizeof(address6)) == SOCKET_ERROR ||
                    listen(socket6, SOMAXCONN) == SOCKET_ERROR)
                {
                    const int error = WSAGetLastError();
                    log::Print("[IPV6-BOOT] TCP bind/listen [::1]:%u failed WSA=%d; IPv4 listener remains active",
                        port, error);
                    closesocket(socket6);
                }
                else
                {
                    MakeNonBlocking(socket6);
                    listeners_.push_back({socket6, port, false});
                    log::Print("[IPV6-BOOT] TCP listening on [::1]:%u v6only=yes role=bootstrap-companion", port);
                }
            }
        }

        return true;
    }

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
