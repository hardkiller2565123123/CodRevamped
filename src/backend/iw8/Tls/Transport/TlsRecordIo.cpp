#include "TlsRecordIo.h"

namespace revamped::iw8
{
    namespace
    {
        void DestroyTlsSession(void*& opaque)
        {
            auto* session = static_cast<TlsSession*>(opaque);
            if (!session) return;
            if (session->contextValid) DeleteSecurityContext(&session->context);
            delete session;
            opaque = nullptr;
        }

        bool SendTlsToken(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer, const void* data, std::size_t size)
        {
            const auto* bytes = static_cast<const char*>(data);
            std::size_t offset = 0;
            while (offset < size)
            {
                const int result = send(socket, bytes + offset,
                    static_cast<int>((std::min)(size - offset, static_cast<std::size_t>(0x7FFFFFFF))), 0);
                if (result == SOCKET_ERROR)
                {
                    log::Print("[TLS%u] id=%llu send server-flight failed WSA=%d after=%llu/%llu",
                        static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), WSAGetLastError(),
                        static_cast<unsigned long long>(offset), static_cast<unsigned long long>(size));
                    return false;
                }
                if (result == 0) return false;
                offset += static_cast<std::size_t>(result);
            }
            log::Payload(id, "TLS-OUT", session.localPort, peer, data, size);
            log::Print("[TLS%u] id=%llu sent SChannel server flight bytes=%llu",
                static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long long>(size));
            return true;
        }
    }
}
