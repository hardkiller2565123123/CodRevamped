#ifndef WIN32_LEAN_AND_MEAN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif
#ifndef NOMINMAX
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "ClientServices.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace client_services
{
    namespace
    {
        constexpr unsigned short kDiscoveryPort = 28970;
        constexpr unsigned short kChatPort = 28971;
        constexpr unsigned short kGamePort = 3074;
        constexpr char kDiscoveryQuery[] = "T9CLIENT_DISCOVER_V1";
        constexpr char kServerPrefix[] = "T9CLIENT_SERVER_V1|";
        constexpr char kChatPrefix[] = "T9CLIENT_CHAT_V1|";

        std::atomic_bool g_running{ false };
        std::atomic_bool g_advertising{ false };
        std::thread g_worker;
        SOCKET g_discoverySocket = INVALID_SOCKET;
        SOCKET g_chatSocket = INVALID_SOCKET;
        std::mutex g_mutex;
        std::string g_nickname = "Revampedplayer";
        std::string g_serverName = "T9 Local Match";
        std::vector<ServerEntry> g_servers;
        std::vector<ChatMessage> g_chat;
        std::atomic_bool g_refreshRequested{ false };

        std::uint64_t NowMs()
        {
            return static_cast<std::uint64_t>(GetTickCount64());
        }

        std::string Sanitize(std::string value, std::size_t maxLength)
        {
            value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c)
            {
                return c < 0x20 || c == '|' || c == '\r' || c == '\n';
            }), value.end());
            if (value.size() > maxLength)
                value.resize(maxLength);
            return value;
        }

        void ConfigureSocket(SOCKET socket)
        {
            u_long nonBlocking = 1;
            ioctlsocket(socket, FIONBIO, &nonBlocking);
            BOOL broadcast = TRUE;
            setsockopt(socket, SOL_SOCKET, SO_BROADCAST,
                reinterpret_cast<const char*>(&broadcast), sizeof(broadcast));
            BOOL reuse = TRUE;
            setsockopt(socket, SOL_SOCKET, SO_REUSEADDR,
                reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        }

        SOCKET CreateBoundSocket(unsigned short port)
        {
            SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (socket == INVALID_SOCKET)
                return INVALID_SOCKET;
            ConfigureSocket(socket);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_ANY);
            address.sin_port = htons(port);
            if (bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR)
            {
                closesocket(socket);
                return INVALID_SOCKET;
            }
            return socket;
        }

        void Broadcast(SOCKET socket, unsigned short port, const std::string& payload)
        {
            if (socket == INVALID_SOCKET || payload.empty())
                return;
            sockaddr_in destination{};
            destination.sin_family = AF_INET;
            destination.sin_addr.s_addr = htonl(INADDR_BROADCAST);
            destination.sin_port = htons(port);
            sendto(socket, payload.data(), static_cast<int>(payload.size()), 0,
                reinterpret_cast<sockaddr*>(&destination), sizeof(destination));
        }

        std::vector<std::string> Split(const std::string& text)
        {
            std::vector<std::string> fields;
            std::size_t start = 0;
            while (start <= text.size())
            {
                const auto end = text.find('|', start);
                fields.push_back(text.substr(start,
                    end == std::string::npos ? std::string::npos : end - start));
                if (end == std::string::npos)
                    break;
                start = end + 1;
            }
            return fields;
        }

        std::string AddressText(const sockaddr_in& source)
        {
            char ip[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &source.sin_addr, ip, sizeof(ip));
            char output[64]{};
            std::snprintf(output, sizeof(output), "%s:%u", ip, kGamePort);
            return output;
        }

        void SendServerAdvertisement(const sockaddr_in* directTarget = nullptr)
        {
            if (!g_advertising.load() || g_discoverySocket == INVALID_SOCKET)
                return;

            std::string name;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                name = Sanitize(g_serverName, 64);
            }
            const std::string payload = std::string(kServerPrefix) + name +
                "|Local Match|Unknown|1|18";

            if (directTarget)
            {
                sockaddr_in target = *directTarget;
                sendto(g_discoverySocket, payload.data(), static_cast<int>(payload.size()), 0,
                    reinterpret_cast<sockaddr*>(&target), sizeof(target));
            }
            else
            {
                Broadcast(g_discoverySocket, kDiscoveryPort, payload);
            }
        }

        void HandleDiscoveryPacket(const std::string& packet, const sockaddr_in& source)
        {
            if (packet == kDiscoveryQuery)
            {
                SendServerAdvertisement(&source);
                return;
            }
            if (packet.rfind(kServerPrefix, 0) != 0)
                return;

            const auto fields = Split(packet.substr(std::strlen(kServerPrefix)));
            if (fields.size() < 5)
                return;

            ServerEntry incoming{};
            incoming.name = fields[0];
            incoming.mode = fields[1];
            incoming.map = fields[2];
            incoming.players = (std::max)(0, std::atoi(fields[3].c_str()));
            incoming.maxPlayers = (std::max)(1, std::atoi(fields[4].c_str()));
            incoming.address = AddressText(source);
            incoming.lastSeenMs = NowMs();
            incoming.pingMs = 1;

            std::lock_guard<std::mutex> lock(g_mutex);
            auto it = std::find_if(g_servers.begin(), g_servers.end(), [&](const ServerEntry& item)
            {
                return item.address == incoming.address;
            });
            if (it == g_servers.end())
                g_servers.push_back(std::move(incoming));
            else
                *it = std::move(incoming);
        }

        void HandleChatPacket(const std::string& packet)
        {
            if (packet.rfind(kChatPrefix, 0) != 0)
                return;
            const auto fields = Split(packet.substr(std::strlen(kChatPrefix)));
            if (fields.size() < 2)
                return;

            ChatMessage message{};
            message.sender = Sanitize(fields[0], 32);
            message.text = Sanitize(fields[1], 180);
            message.receivedMs = NowMs();
            message.local = false;
            if (message.text.empty())
                return;

            std::lock_guard<std::mutex> lock(g_mutex);
            g_chat.push_back(std::move(message));
            if (g_chat.size() > 128)
                g_chat.erase(g_chat.begin(), g_chat.begin() + 32);
        }

        void ReceivePackets(SOCKET socket, bool discovery)
        {
            if (socket == INVALID_SOCKET)
                return;
            for (;;)
            {
                char buffer[1024]{};
                sockaddr_in source{};
                int sourceLength = sizeof(source);
                const int received = recvfrom(socket, buffer, sizeof(buffer) - 1, 0,
                    reinterpret_cast<sockaddr*>(&source), &sourceLength);
                if (received <= 0)
                    break;
                buffer[received] = '\0';
                if (discovery)
                    HandleDiscoveryPacket(buffer, source);
                else
                    HandleChatPacket(buffer);
            }
        }

        void Worker()
        {
            ULONGLONG lastAdvertise = 0;
            while (g_running.load())
            {
                ReceivePackets(g_discoverySocket, true);
                ReceivePackets(g_chatSocket, false);

                const ULONGLONG now = GetTickCount64();
                if (g_refreshRequested.exchange(false))
                    Broadcast(g_discoverySocket, kDiscoveryPort, kDiscoveryQuery);
                if (g_advertising.load() && now - lastAdvertise >= 2000)
                {
                    SendServerAdvertisement();
                    lastAdvertise = now;
                }

                {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    g_servers.erase(std::remove_if(g_servers.begin(), g_servers.end(), [now](const ServerEntry& server)
                    {
                        return now - server.lastSeenMs > 7000;
                    }), g_servers.end());
                }
                Sleep(25);
            }
        }
    }

    bool Initialize()
    {
        if (g_running.exchange(true))
            return true;

        bool winsockStarted = false;
        try
        {
            WSADATA data{};
            if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
            {
                g_running.store(false);
                return false;
            }
            winsockStarted = true;

            g_discoverySocket = CreateBoundSocket(kDiscoveryPort);
            g_chatSocket = CreateBoundSocket(kChatPort);

            // A port may already be occupied by another client instance. Keep
            // whichever service could bind instead of terminating the process.
            if (g_discoverySocket == INVALID_SOCKET && g_chatSocket == INVALID_SOCKET)
            {
                WSACleanup();
                g_running.store(false);
                return false;
            }

            g_worker = std::thread(Worker);
            return true;
        }
        catch (...)
        {
            g_running.store(false);
            if (g_discoverySocket != INVALID_SOCKET)
                closesocket(g_discoverySocket);
            if (g_chatSocket != INVALID_SOCKET)
                closesocket(g_chatSocket);
            g_discoverySocket = INVALID_SOCKET;
            g_chatSocket = INVALID_SOCKET;
            if (winsockStarted)
                WSACleanup();
            return false;
        }
    }

    void Shutdown()
    {
        if (!g_running.exchange(false))
            return;
        if (g_worker.joinable())
            g_worker.join();
        if (g_discoverySocket != INVALID_SOCKET)
            closesocket(g_discoverySocket);
        if (g_chatSocket != INVALID_SOCKET)
            closesocket(g_chatSocket);
        g_discoverySocket = INVALID_SOCKET;
        g_chatSocket = INVALID_SOCKET;
        WSACleanup();
    }

    void SetNickname(const std::string& name)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const auto clean = Sanitize(name, 32);
        if (!clean.empty())
            g_nickname = clean;
    }

    std::string Nickname()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_nickname;
    }

    void SetAdvertising(bool enabled) { g_advertising.store(enabled); }
    bool IsAdvertising() { return g_advertising.load(); }

    void SetAdvertisedServerName(const std::string& name)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const auto clean = Sanitize(name, 64);
        if (!clean.empty())
            g_serverName = clean;
    }

    std::string AdvertisedServerName()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_serverName;
    }

    void RefreshServers() { g_refreshRequested.store(true); }

    std::vector<ServerEntry> Servers()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_servers;
    }

    bool SendChat(const std::string& text)
    {
        const std::string clean = Sanitize(text, 180);
        if (clean.empty())
            return false;
        std::string nickname;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            nickname = g_nickname;
            g_chat.push_back({ nickname, clean, NowMs(), true });
            if (g_chat.size() > 128)
                g_chat.erase(g_chat.begin(), g_chat.begin() + 32);
        }
        Broadcast(g_chatSocket, kChatPort, std::string(kChatPrefix) + nickname + "|" + clean);
        return true;
    }

    std::vector<ChatMessage> ChatMessages()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_chat;
    }

    void ClearChat()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_chat.clear();
    }
}
