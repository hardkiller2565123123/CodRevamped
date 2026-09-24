#include "TcpListener.h"

namespace revamped::iw8
{
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
}
