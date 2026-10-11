#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <string>

namespace network
{
    // Request-local endpoint publication avoids depending on router NAT loopback.
    // Scope the real socket peer; never trust a Host header or request body.
    class PeerScope
    {
        bool previous;

      public:
        explicit PeerScope(uint32_t address);
        ~PeerScope();
        PeerScope(const PeerScope &) = delete;
        PeerScope &operator=(const PeerScope &) = delete;
    };

    bool isLoopbackPeer();
    void initialize(const std::filesystem::path &directory);
    uint32_t bindAddress();
    uint32_t advertisedAddress();
    std::array<uint8_t, 4> advertisedBytes();
    std::string httpOrigin(uint16_t port);
    uint16_t qosPort();
    uint16_t relayPort();
    uint16_t bandwidthPort();
    unsigned bandwidthPortCount();
    bool permittedPeer(uint32_t address);
    bool loginPermitted(bool loopback, const std::string &profile, const std::string &credential);
} // namespace network
