#include "host_os.h"
#include "qos_provider.h"
#include "network.h"
#include "../third_party/nlohmann/json.hpp"
#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace qos_provider
{
    namespace
    {
        using Clock = std::chrono::steady_clock;
        std::atomic<uint64_t> probeCount{0}, traversalCount{0};

        struct Lease
        {
            uint32_t id;
            Clock::time_point expires;
        };

        struct Provider
        {
            SOCKET socket = INVALID_SOCKET;
            uint16_t port = 0;
            std::mutex mutex;
            std::vector<Lease> leases;
            std::jthread worker;

            Provider()
            {
                socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (socket == INVALID_SOCKET)
                    throw std::runtime_error("QoS socket creation failed");
                const BOOL exclusive = TRUE;
                setsockopt(socket,
                           SOL_SOCKET,
                           SO_EXCLUSIVEADDRUSE,
                           reinterpret_cast<const char *>(&exclusive),
                           sizeof(exclusive));
                sockaddr_in address{};
                address.sin_family = AF_INET;
                address.sin_addr.s_addr = network::bindAddress();
                address.sin_port = htons(network::qosPort());
                int size = sizeof(address);
                if (bind(socket, reinterpret_cast<sockaddr *>(&address), sizeof(address)) ||
                    getsockname(socket, reinterpret_cast<sockaddr *>(&address), &size))
                {
                    closesocket(socket);
                    socket = INVALID_SOCKET;
                    throw std::runtime_error("QoS loopback bind failed");
                }
                port = ntohs(address.sin_port);
                try
                {
                    worker = std::jthread(
                        [this](std::stop_token stop)
                        {
                            run(stop);
                        });
                }
                catch (...)
                {
                    closesocket(socket);
                    socket = INVALID_SOCKET;
                    throw;
                }
            }

            ~Provider()
            {
                worker.request_stop();
                if (worker.joinable())
                    worker.join();
                if (socket != INVALID_SOCKET)
                    closesocket(socket);
            }

            bool permitted(uint32_t id)
            {
                std::lock_guard lock(mutex);
                const auto now = Clock::now();
                std::erase_if(leases,
                              [&](const auto &item)
                              {
                                  return item.expires <= now;
                              });
                return std::any_of(leases.begin(),
                                   leases.end(),
                                   [&](const auto &item)
                                   {
                                       return item.id == id;
                                   });
            }

            void run(std::stop_token stop) noexcept
            {
                std::array<uint8_t, 1290> packet{};
                auto window = Clock::now();
                unsigned count = 0;
                while (!stop.stop_requested())
                {
                    fd_set readable{};
                    FD_SET(socket, &readable);
                    timeval timeout{0, 50000};
                    const auto ready = select(0, &readable, nullptr, nullptr, &timeout);
                    if (ready == SOCKET_ERROR)
                        return;
                    if (!ready)
                        continue;
                    sockaddr_in peer{};
                    int size = sizeof(peer);
                    const int bytes = recvfrom(socket,
                                               reinterpret_cast<char *>(packet.data()),
                                               static_cast<int>(packet.size()),
                                               0,
                                               reinterpret_cast<sockaddr *>(&peer),
                                               &size);
                    if (bytes <= 0 || peer.sin_family != AF_INET ||
                        !network::permittedPeer(peer.sin_addr.s_addr))
                        continue;
                    const auto received = Clock::now();
                    if (received - window >= std::chrono::seconds(1))
                    {
                        window = received;
                        count = 0;
                    }
                    if (++count > 256)
                        continue;
                    try
                    {
                        const network::PeerScope publication(peer.sin_addr.s_addr);
                        const auto incoming = std::span(packet.data(), static_cast<size_t>(bytes));
                        wire::Bytes reply;
                        if (bytes == 29 && packet[0] == 13 && wire::at<uint16_t>(incoming, 1) == 2)
                        {
                            // Same-Replay 0x1421A25F0 / 0x14219B4D0. Intro requests
                            // carry version, opaque client HMAC, identifier and two
                            // IPv4 endpoints. Reply 12 preserves the authenticated
                            // challenge exactly, as the native receiving peer does.
                            // Only introductions addressed to this local endpoint
                            // are answered; never forward to a caller-supplied address.
                            const auto loopback = network::advertisedBytes();
                            if (!std::equal(
                                    loopback.begin(), loopback.end(), incoming.begin() + 23) ||
                                wire::at<uint16_t>(incoming, 27) != port)
                                continue;
                            reply.assign(incoming.begin(), incoming.end());
                            reply[0] = 12;
                        }
                        else if (bytes == 18 && packet[0] == 40 && packet[17] <= 1 &&
                                 permitted(wire::at<uint32_t>(incoming, 13)))
                        {
                            // Request 0x142197830 and full reply 0x142197300. Timestamp
                            // and request ID echo the real probe. Native computes RTT;
                            // we report measured handler time, no invented latency.
                            reply.push_back(41);
                            wire::raw(reply, wire::at<uint32_t>(incoming, 9));
                            wire::raw(reply, wire::at<uint64_t>(incoming, 1));
                            reply.push_back(1);
                            const wire::Bytes payload =
                                packet[17] ? wire::Bytes{'l', 'o', 'c', 'a', 'l', 0}
                                           : wire::Bytes{};
                            wire::raw(reply, static_cast<uint32_t>(payload.size()));
                            wire::raw(reply, uint32_t{0});
                            const auto processing =
                                std::chrono::duration<float>(Clock::now() - received).count();
                            wire::raw(reply, processing);
                            reply.push_back(packet[17]);
                            reply.insert(reply.end(), payload.begin(), payload.end());
                        }
                        else
                            continue;
                        if (sendto(socket,
                                   reinterpret_cast<const char *>(reply.data()),
                                   static_cast<int>(reply.size()),
                                   0,
                                   reinterpret_cast<const sockaddr *>(&peer),
                                   sizeof(peer)) == static_cast<int>(reply.size()))
                        {
                            if (packet[0] == 40)
                                ++probeCount;
                            else
                                ++traversalCount;
                        }
                    }
                    catch (...)
                    { /* Reject malformed datagrams without terminating the provider. */
                    }
                }
            }
        };

        std::unique_ptr<Provider> provider;
    } // namespace

    void start(const std::filesystem::path &directory)
    {
        stop();
        const auto path = directory / "qos" / "local-provider.json";
        if (!std::filesystem::exists(path))
            return;
        wire::require(std::filesystem::file_size(path) <= 4096);
        std::ifstream in(path);
        if (!in)
            throw std::runtime_error("QoS provider configuration read failed");
        const auto config = nlohmann::json::parse(in);
        wire::require(config.is_object() && config.at("enabled").is_boolean());
        if (config.at("enabled").get<bool>())
            provider = std::make_unique<Provider>();
    }

    void stop()
    {
        provider.reset();
    }

    bool enabled()
    {
        return provider != nullptr;
    }

    uint64_t probes()
    {
        return probeCount.load();
    }

    uint64_t traversals()
    {
        return traversalCount.load();
    }

    Host host()
    {
        if (!provider)
            throw std::runtime_error("QoS provider is disabled");
        Host out;
        out.securityId = crypto::random(8);
        out.securityKey = crypto::random(16);
        const auto id =
            wire::at<uint32_t>(out.securityId, 0); // native QoS request stores the first 32 bits
        {
            std::lock_guard lock(provider->mutex);
            const auto now = Clock::now();
            std::erase_if(provider->leases,
                          [&](const auto &item)
                          {
                              return item.expires <= now;
                          });
            wire::require(provider->leases.size() < 256);
            provider->leases.push_back({id, now + std::chrono::minutes(5)});
        }
        const auto ip = network::advertisedBytes();
        wire::Bytes endpoint(ip.begin(), ip.end());
        wire::raw(endpoint, provider->port);
        // Full bdCommonAddr 0x1420EC6B0: five local addresses, public address,
        // NAT kind, platform, then 43-byte bdRelayJoinData 0x142192930. A direct
        // local endpoint has no relay route, join ID or relay secret.
        for (unsigned i = 0; i < 6; ++i)
            out.address.insert(out.address.end(), endpoint.begin(), endpoint.end());
        out.address.push_back(1);
        wire::raw(out.address, uint32_t{101});
        out.address.push_back(1);
        out.address.resize(84, 0);
        return out;
    }
} // namespace qos_provider
