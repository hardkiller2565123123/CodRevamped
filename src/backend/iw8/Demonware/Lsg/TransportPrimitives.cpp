#include "TransportPrimitives.h"

namespace revamped::iw8
{
    namespace
    {
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

        std::uint32_t ReadLe32(const std::uint8_t* p)
        {
            return static_cast<std::uint32_t>(p[0]) |
                (static_cast<std::uint32_t>(p[1]) << 8) |
                (static_cast<std::uint32_t>(p[2]) << 16) |
                (static_cast<std::uint32_t>(p[3]) << 24);
        }

        void AppendLe32(std::vector<std::uint8_t>& out, std::uint32_t value)
        {
            out.push_back(static_cast<std::uint8_t>(value));
            out.push_back(static_cast<std::uint8_t>(value >> 8));
            out.push_back(static_cast<std::uint8_t>(value >> 16));
            out.push_back(static_cast<std::uint8_t>(value >> 24));
        }

        void AppendLe64(std::vector<std::uint8_t>& out, std::uint64_t value)
        {
            AppendLe32(out, static_cast<std::uint32_t>(value));
            AppendLe32(out, static_cast<std::uint32_t>(value >> 32));
        }
    }
}
