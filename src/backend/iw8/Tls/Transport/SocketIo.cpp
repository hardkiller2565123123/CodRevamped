#include "SocketIo.h"

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

        bool SendAllNonBlocking(SOCKET socket, const void* data, std::size_t size)
        {
            const auto* bytes = static_cast<const unsigned char*>(data);
            std::size_t sentTotal = 0;
            while (sentTotal < size)
            {
                const int chunk = static_cast<int>((std::min)(size - sentTotal, static_cast<std::size_t>(0x7FFFFFFF)));
                const int sent = send(socket, reinterpret_cast<const char*>(bytes + sentTotal), chunk, 0);
                if (sent > 0)
                {
                    sentTotal += static_cast<std::size_t>(sent);
                    continue;
                }
                if (sent == 0)
                    return false;

                const int error = WSAGetLastError();
                if (error != WSAEWOULDBLOCK)
                    return false;

                fd_set writeSet{};
                FD_ZERO(&writeSet);
                FD_SET(socket, &writeSet);
                timeval timeout{};
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                const int ready = select(0, nullptr, &writeSet, nullptr, &timeout);
                if (ready <= 0)
                    return false;
            }
            return true;
        }
    }
}
