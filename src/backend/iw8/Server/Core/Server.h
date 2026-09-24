#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace revamped::iw8
{
    struct ServerConfig
    {
        std::string bindAddress = "0.0.0.0";
        std::vector<std::uint16_t> tcpPorts{80, 443, 1119, 3074, 3075};
        std::vector<std::uint16_t> udpPorts{3074};
        bool dumpPayloads = true;
    };

    class Server
    {
    public:
        explicit Server(ServerConfig config);
        ~Server();

        bool Start();
        void Run();
        void Stop();

    private:
        struct Listener
        {
            SOCKET socket = INVALID_SOCKET;
            std::uint16_t port = 0;
            bool udp = false;
        };

        struct Client
        {
            SOCKET socket = INVALID_SOCKET;
            std::uint64_t id = 0;
            std::uint16_t localPort = 0;
            std::string peer;
            std::uint64_t acceptedAtMs = 0;
            bool firstPacket = true;
            bool authIdleLogged = false;
            void* tlsState = nullptr;

            // IW8 Demonware lobby/LSG state.  This is server-side protocol
            // state only; it never changes stock client auth/fence/LUI truth.
            std::vector<std::uint8_t> lsgInput;
            std::uint32_t lsgStage = 0;
            std::uint32_t lsgMaxPacket = 0;
            std::uint32_t lsgSelectedVersion = 0;
            std::uint8_t lsgClientNonce[8]{};
            std::uint8_t lsgServerNonce[8]{};
            std::string lsgCryptoVariant;
            std::uint8_t lsgPrk[20]{};
            std::uint8_t lsgBdData[72]{};
            std::uint32_t lsgSendCounter = 0;
            std::uint64_t lsgTransactionId = 0;
        };

        bool HandleLsgTcp(Client& client, const std::uint8_t* data, std::size_t size);
        bool CreateTcpListener(std::uint16_t port);
        bool CreateUdpListener(std::uint16_t port);
        void AcceptTcp(Listener& listener);
        void ReadTcp(std::size_t index);
        void ReadUdp(Listener& listener);
        void CloseClient(std::size_t index, const char* reason);

        ServerConfig config_;
        std::vector<Listener> listeners_;
        std::vector<Client> clients_;
        std::atomic_bool running_{false};
        std::uint64_t nextClientId_ = 1;
    };
}
