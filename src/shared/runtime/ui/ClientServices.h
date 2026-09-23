#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace client_services
{
    struct ServerEntry
    {
        std::string name;
        std::string address;
        std::string map;
        std::string mode;
        int players = 0;
        int maxPlayers = 18;
        int pingMs = 0;
        std::uint64_t lastSeenMs = 0;
    };

    struct ChatMessage
    {
        std::string sender;
        std::string text;
        std::uint64_t receivedMs = 0;
        bool local = false;
    };

    bool Initialize();
    void Shutdown();

    void SetNickname(const std::string& name);
    std::string Nickname();

    void SetAdvertising(bool enabled);
    bool IsAdvertising();
    void SetAdvertisedServerName(const std::string& name);
    std::string AdvertisedServerName();

    void RefreshServers();
    std::vector<ServerEntry> Servers();

    bool SendChat(const std::string& text);
    std::vector<ChatMessage> ChatMessages();
    void ClearChat();
}
