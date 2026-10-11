#pragma once
#include "services.h"
#include <array>

namespace relay
{
    // Replay's serializeInit sends version + encrypted[56] + expiryDelta, omitting
    // the client secret. The relay must recover that secret before checking INIT.
    struct ClientCredential
    {
        uint32_t title = 0, expires = 0, expiryDelta = 0;
        uint64_t user = 0;
        std::array<uint8_t, 8> session{};
        std::array<uint8_t, 16> secret{};
    };

    void initialize(const std::filesystem::path &directory);
    ClientCredential verifyClientInit(std::span<const uint8_t> token);
    ClientCredential verifyClientToken(std::span<const uint8_t> token);

    struct ServerCredential
    {
        uint32_t title = 0, expires = 0;
        uint64_t user = 0, relayId = 0;
        std::array<uint8_t, 16> secret{};
    };

    wire::Bytes issueServerToken(const platform::LobbyIdentity &id,
                                 uint64_t relayId,
                                 std::span<const uint8_t> address);
    ServerCredential verifyServerInit(std::span<const uint8_t> token, uint64_t relayId);
} // namespace relay

namespace services
{
    std::optional<Reply> relayServices(const std::filesystem::path &directory,
                                       const platform::LobbyIdentity &id,
                                       uint8_t service,
                                       uint8_t task,
                                       wire::Reader &params);
}
