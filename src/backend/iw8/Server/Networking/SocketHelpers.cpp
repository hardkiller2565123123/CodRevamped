#include "SocketHelpers.h"

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
}
