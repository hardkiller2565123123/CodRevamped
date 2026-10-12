#pragma once
#include "crypto.h"
#include "platform.h"
#include <optional>
#include <functional>
#include <string>
#include <atomic>

namespace services { struct Delivery; }

namespace lobby
{
    struct IO
    {
        // The transport checks this connection's issuer lease while an idle or
        // partial read is waiting. An empty guard is used only during handshake.
        using ReadGuard = std::function<bool()>;
        std::function<bool(std::span<uint8_t>, const ReadGuard &)> read;
        std::function<bool(std::span<const uint8_t>)> write;
        std::function<void(const std::string &)> log;
        ReadGuard authenticatedRead;
    };

    void serve(const IO &io);

    // Bridge a CodRevamped-authenticated native LSG connection into ReplayDW's
    // online/push registry without pretending ReplayDW issued the login lease.
    void registerHostedConnection(
        uint64_t connection,
        const platform::LobbyIdentity &identity,
        std::function<bool(std::span<const uint8_t>)> writer);
    void unregisterHostedConnection(uint64_t connection);
    bool publishHostedPush(uint64_t connection, std::span<const uint8_t> payload);

    void publishOperatorUpdates(uint32_t title, std::span<const services::Delivery> deliveries);
    struct OnlinePlayer
    {
        uint32_t title;
        uint64_t user;
        std::string name;
    };

    std::vector<OnlinePlayer> onlinePlayerList();
    unsigned onlinePlayers();
    bool online(uint32_t title, uint64_t user);
    std::optional<platform::LobbyIdentity> onlineIdentity(uint32_t title, uint64_t user);
    std::optional<platform::LobbyIdentity> onlineIdentity(uint32_t title, uint64_t user,
                                                        const std::string &fingerprint);
    bool sessionOnline(uint32_t title, uint64_t user, const std::string &fingerprint);
    extern std::atomic<unsigned> connections, authenticated, frames, tasks, failures;
} // namespace lobby
