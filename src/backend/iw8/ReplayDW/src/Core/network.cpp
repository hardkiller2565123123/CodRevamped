#include "host_os.h"
#include "network.h"
#include "wire.h"
#include "nlohmann/json.hpp"
#include <cstring>
#include <fstream>
#include <map>

namespace network
{
    namespace
    {
        uint32_t bindIp = htonl(INADDR_LOOPBACK), publicIp = htonl(INADDR_LOOPBACK);
        std::string publicHost = "127.0.0.1";
        uint16_t qos = 0, relay = 0, bandwidth = 0;
        unsigned bandwidthCount = 1;
        std::map<std::string, std::string> clients;
        thread_local bool loopbackPeer = false;

        uint32_t ipv4(const std::string &value)
        {
            IN_ADDR result{};
            wire::require(InetPtonA(AF_INET, value.c_str(), &result) == 1);
            return result.S_un.S_addr;
        }
    } // namespace

    void initialize(const std::filesystem::path &directory)
    {
        bindIp = publicIp = htonl(INADDR_LOOPBACK);
        publicHost = "127.0.0.1";
        qos = relay = bandwidth = 0;
        bandwidthCount = 1;
        clients.clear();
        const auto path = directory / "network.json";
        if (!std::filesystem::exists(path))
            return;
        wire::require(std::filesystem::file_size(path) <= 16384);
        std::ifstream stream(path);
        wire::require(bool(stream));
        const auto config = nlohmann::json::parse(stream);
        wire::require(config.at("schema") == 1);
        bindIp = ipv4(config.at("bind_address").get<std::string>());
        publicHost = config.at("advertised_address").get<std::string>();
        publicIp = ipv4(publicHost);
        wire::require(publicIp != INADDR_ANY && publicIp != INADDR_BROADCAST);
        const auto port = [&](const char *name)
        {
            const auto value = config.at(name).get<unsigned>();
            wire::require(value >= 1024 && value <= 65535);
            return static_cast<uint16_t>(value);
        };
        qos = port("qos_port");
        relay = port("relay_port");
        bandwidth = port("bandwidth_port");
        bandwidthCount = config.value("bandwidth_port_count", 1u);
        wire::require(bandwidthCount >= 1 && bandwidthCount <= 32 &&
                      unsigned(bandwidth) + bandwidthCount - 1 <= 65535);
        const auto occupied = [&](uint16_t candidate)
        {
            return candidate >= bandwidth && candidate < unsigned(bandwidth) + bandwidthCount;
        };
        wire::require(!occupied(qos) && !occupied(relay));
        wire::require(qos != relay && qos != bandwidth && relay != bandwidth);
        const auto entries = config.at("clients");
        wire::require(entries.is_object() && entries.size() <= 63);
        for (const auto &[name, secret] : entries.items())
        {
            wire::require(!name.empty() && name.size() <= 64 && secret.is_string());
            const auto key = secret.get<std::string>();
            wire::require(key.size() == 64);
            for (const auto c : key)
                wire::require((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'));
            clients.emplace(name, key);
        }
    }

    uint32_t bindAddress()
    {
        return bindIp;
    }

    PeerScope::PeerScope(uint32_t address) : previous(loopbackPeer)
    {
        loopbackPeer = address == htonl(INADDR_LOOPBACK);
    }

    PeerScope::~PeerScope()
    {
        loopbackPeer = previous;
    }

    bool isLoopbackPeer()
    {
        return loopbackPeer;
    }

    uint32_t advertisedAddress()
    {
        return loopbackPeer ? htonl(INADDR_LOOPBACK) : publicIp;
    }

    std::array<uint8_t, 4> advertisedBytes()
    {
        std::array<uint8_t, 4> bytes{};
        const auto address = advertisedAddress();
        std::memcpy(bytes.data(), &address, bytes.size());
        return bytes;
    }

    std::string httpOrigin(uint16_t port)
    {
        return "http://" + (loopbackPeer ? std::string("127.0.0.1") : publicHost) + ":" +
               std::to_string(port);
    }

    uint16_t qosPort()
    {
        return qos;
    }

    uint16_t relayPort()
    {
        return relay;
    }

    uint16_t bandwidthPort()
    {
        return bandwidth;
    }

    unsigned bandwidthPortCount()
    {
        return bandwidthCount;
    }

    bool permittedPeer(uint32_t address)
    {
        return bindIp != htonl(INADDR_LOOPBACK) || address == htonl(INADDR_LOOPBACK);
    }

    bool loginPermitted(bool loopback, const std::string &profile, const std::string &credential)
    {
        if (loopback && credential.empty())
            return true;
        const auto found = clients.find(profile);
        if (found == clients.end() || credential.size() != found->second.size())
            return false;
        unsigned difference = 0;
        for (size_t i = 0; i < credential.size(); ++i)
            difference |= static_cast<unsigned char>(credential[i] ^ found->second[i]);
        return difference == 0;
    }
} // namespace network
