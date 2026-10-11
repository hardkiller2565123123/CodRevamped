#include "host_os.h"
#include "relay_provider.h"
#include "network.h"
#include "relay_services.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <fstream>
#include <map>
#include <memory>
#include <thread>

namespace relay_provider
{
    namespace
    {
        using Json = nlohmann::json;
        using Clock = std::chrono::steady_clock;
        using Secret = std::array<uint8_t, 16>;
        enum class Failure : uint8_t
        {
            none,
            socketWait,
            eventWrite,
            socketSend,
            internal
        };

        struct ProviderFailure : std::exception
        {
            Failure reason;

            explicit ProviderFailure(Failure value) : reason(value) {}

            const char *what() const noexcept override
            {
                switch (reason)
                {
                case Failure::socketWait:
                    return "Relay socket wait failed";
                case Failure::eventWrite:
                    return "Relay event write failed";
                case Failure::socketSend:
                    return "Relay socket send failed";
                default:
                    return "Relay provider failed";
                }
            }
        };

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        std::string hex(std::span<const uint8_t> bytes)
        {
            std::string out;
            for (const auto b : bytes)
            {
                out.push_back("0123456789abcdef"[b >> 4]);
                out.push_back("0123456789abcdef"[b & 15]);
            }
            return out;
        }

        void append(wire::Bytes &bytes, std::span<const uint8_t> more)
        {
            bytes.insert(bytes.end(), more.begin(), more.end());
        }

        Secret randomSecret()
        {
            const auto bytes = crypto::random(16);
            Secret out;
            std::copy(bytes.begin(), bytes.end(), out.begin());
            return out;
        }

        wire::Bytes hkdf(std::span<const uint8_t> seed,
                         const char *label,
                         unsigned labelBytes,
                         unsigned bytes)
        {
            const std::array<uint8_t, 32> salt{};
            const auto prk = crypto::hmac256(salt, seed);
            // Native 1421A2FE0 and 14219EF90 use 21 bytes, including NUL.
            return crypto::expand256(
                prk, std::span(reinterpret_cast<const uint8_t *>(label), labelBytes), bytes);
        }

        wire::Bytes initKey(const Secret &client,
                            const Secret &relay,
                            std::span<const uint8_t> random)
        {
            wire::Bytes seed;
            append(seed, client);
            append(seed, relay);
            append(seed, random);
            return hkdf(seed, "GceTGCsU2PYWfEYWJ0wA", 21, 16);
        }

        wire::Bytes packet(uint8_t type,
                           uint32_t route,
                           uint32_t counter,
                           std::span<const uint8_t> payload,
                           std::span<const uint8_t> key)
        {
            wire::Bytes out{type};
            wire::raw(out, route);
            wire::raw(out, static_cast<uint16_t>(counter));
            append(out, payload);
            wire::Bytes signedBytes(out);
            wire::raw(signedBytes, counter);
            const auto digest = crypto::hmac256(key, signedBytes);
            append(out, std::span(digest).first(type == 5 ? 5 : 16));
            return out;
        }

        bool validMac(std::span<const uint8_t> bytes,
                      uint32_t counter,
                      std::span<const uint8_t> key)
        {
            const size_t size = bytes[0] == 5 ? 5 : 16;
            if (bytes.size() < 7 + size)
                return false;
            wire::Bytes payload(bytes.begin(), bytes.end() - size);
            wire::raw(payload, counter);
            const auto digest = crypto::hmac256(key, payload);
            return crypto::equal(std::span(digest).first(size), bytes.last(size));
        }

        struct Sequence
        {
            int64_t highest = -1;
            uint32_t seen = 0;

            std::optional<uint32_t> candidate(uint16_t low) const
            {
                int64_t full = highest < 0 ? low : (highest & ~int64_t{65535}) | low;
                if (highest >= 0)
                {
                    if (full - highest > 32768)
                        full -= 65536;
                    else if (highest - full > 32768)
                        full += 65536;
                }
                if (full < 0 || full >= INT32_MAX)
                    return std::nullopt;
                if (full <= highest &&
                    (highest - full >= 32 ||
                     (seen & (uint32_t{1} << static_cast<unsigned>(highest - full)))))
                    return std::nullopt;
                return static_cast<uint32_t>(full);
            }

            void accept(uint32_t full)
            {
                if (full > highest)
                {
                    const auto delta = full - highest;
                    seen = delta >= 32 ? 1 : (seen << static_cast<unsigned>(delta)) | 1;
                    highest = full;
                }
                else
                    seen |= uint32_t{1} << static_cast<unsigned>(highest - full);
            }
        };

        struct Association
        {
            sockaddr_in peer{};
            relay::ClientCredential client;
            uint32_t route = 0, transmit = 1;
            uint64_t join = 0;
            bool established = false, closed = false;
            Secret joinSecret{}, verification{}, sendMac{}, cipher{}, receiveMac{};
            Sequence receive;
            wire::Bytes initDigest, initAck;
            Clock::time_point lastSeen = Clock::now();

            ~Association()
            {
                SecureZeroMemory(client.secret.data(), 16);
                SecureZeroMemory(joinSecret.data(), 16);
                SecureZeroMemory(verification.data(), 16);
                SecureZeroMemory(sendMac.data(), 16);
                SecureZeroMemory(cipher.data(), 16);
                SecureZeroMemory(receiveMac.data(), 16);
            }
        };

        struct Provider
        {
            SOCKET socket = INVALID_SOCKET;
            uint16_t port = 0;
            uint64_t relayId = 0;
            std::filesystem::path directory;
            std::map<uint32_t, Association> associations;
            std::ofstream events;
            std::atomic<uint64_t> verified{0}, forwarded{0}, pings{0}, rejected{0}, active{0};
            std::atomic<uint64_t> rejectionEvents{0}, suppressedRejectionEvents{0};
            Clock::time_point rejectionWindow = Clock::now();
            unsigned rejectionWindowCount = 0;
            std::atomic<Failure> failure{Failure::none};
            std::atomic<bool> running{true};
            std::jthread worker;

            explicit Provider(const std::filesystem::path &data) : directory(data)
            {
                socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (socket == INVALID_SOCKET)
                    throw std::runtime_error("Relay socket creation failed");
                const BOOL exclusive = TRUE;
                setsockopt(socket,
                           SOL_SOCKET,
                           SO_EXCLUSIVEADDRUSE,
                           reinterpret_cast<const char *>(&exclusive),
                           sizeof(exclusive));
                sockaddr_in local{};
                local.sin_family = AF_INET;
                local.sin_addr.s_addr = network::bindAddress();
                local.sin_port = htons(network::relayPort());
                int size = sizeof(local);
                if (bind(socket, reinterpret_cast<sockaddr *>(&local), sizeof(local)) ||
                    getsockname(socket, reinterpret_cast<sockaddr *>(&local), &size))
                {
                    closesocket(socket);
                    socket = INVALID_SOCKET;
                    throw std::runtime_error("Relay loopback bind failed");
                }
                port = ntohs(local.sin_port);
                do
                {
                    relayId = wire::at<uint64_t>(crypto::random(8), 0);
                } while (!relayId);
                try
                {
                    std::filesystem::create_directories(directory / "relay");
                    events.open(directory / "relay" / "transport-events.jsonl", std::ios::app);
                    if (!events)
                        throw std::runtime_error("Relay event persistence failed");
                    event("started", nullptr);
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

            wire::Bytes address() const
            {
                const auto ip = network::advertisedBytes();
                wire::Bytes out(ip.begin(), ip.end());
                wire::raw(out, port);
                return out;
            }

            void event(const char *action, const Association *association)
            {
                Json record = {{"schema", 1},
                               {"time", now()},
                               {"action", action},
                               {"relay_id", relayId},
                               {"port", port}};
                if (association)
                {
                    record["user"] = association->client.user;
                    record["title"] = association->client.title;
                    record["route"] = association->route;
                    record["expires"] = association->client.expires;
                    record["init_sha256"] = hex(association->initDigest);
                    record["verification_sha256"] = hex(crypto::sha256(association->verification));
                }
                events << record.dump() << '\n';
                events.flush();
                if (!events)
                    throw ProviderFailure{Failure::eventWrite};
            }

            void rejectedPacket(std::span<const uint8_t> bytes,
                                const char *overrideReason = nullptr)
            {
                ++rejected;
                const auto clock = Clock::now();
                if (clock - rejectionWindow >= std::chrono::minutes(1))
                {
                    rejectionWindow = clock;
                    rejectionWindowCount = 0;
                }
                // Keep invalid UDP traffic from producing an unbounded log rate.
                // Counters still include every rejection; proofs detect omissions.
                if (++rejectionWindowCount > 64)
                {
                    ++suppressedRejectionEvents;
                    return;
                }
                const bool header = bytes.size() >= 7;
                const uint32_t route = header ? wire::at<uint32_t>(bytes, 1) : 0;
                const auto reason = overrideReason                             ? overrideReason
                                    : bytes.size() < 12 || bytes.size() > 1288 ? "invalid-size"
                                    : bytes[0] <= 1                            ? "init-rejected"
                                    : !associations.contains(route) ? "unknown-route"
                                                                    : "known-route-rejected";
                Json record = {{"schema", 1},
                               {"time", now()},
                               {"action", "rejected"},
                               {"relay_id", relayId},
                               {"port", port},
                               {"reason", reason},
                               {"bytes", bytes.size()},
                               {"route", route},
                               {"packet_type", bytes.empty() ? -1 : int(bytes[0])}};
                // Never retain packet bodies, credentials, keys or peer addresses.
                events << record.dump() << '\n';
                events.flush();
                if (!events)
                    throw ProviderFailure{Failure::eventWrite};
                ++rejectionEvents;
            }

            bool session(const Association &item) const
            {
                // The signed token admits a new handshake; it is not an
                // established connection's lease. Replay does not refresh it
                // while connected/in a match (NetRelay::Frame/Request).
                // An established route is still bound to the exact live native
                // session digest. Signed renewal preserves that key; expiry or
                // reauthentication invalidates it. Pending handshakes retain
                // the original client/server token deadline, and INIT always
                // runs the strict credential verifiers before route lookup.
                return (item.established || item.client.expires > now()) &&
                       platform::relaySessionMatches(
                           item.client.title, item.client.user, item.client.session);
            }

            void send(const Association &item, std::span<const uint8_t> bytes) const
            {
                if (sendto(socket,
                           reinterpret_cast<const char *>(bytes.data()),
                           static_cast<int>(bytes.size()),
                           0,
                           reinterpret_cast<const sockaddr *>(&item.peer),
                           sizeof(item.peer)) != static_cast<int>(bytes.size()))
                    throw ProviderFailure{Failure::socketSend};
            }

            void reply(Association &item, uint8_t type, std::span<const uint8_t> payload = {})
            {
                wire::require(item.transmit < INT32_MAX);
                send(item, packet(type, item.route, item.transmit++, payload, item.sendMac));
            }

            void init(std::span<const uint8_t> bytes, const sockaddr_in &peer)
            {
                const bool bindRequest = bytes[0] == 0;
                const size_t credentialBytes = bindRequest ? 53 : 27;
                wire::require(bytes.size() == 7 + 1 + 61 + credentialBytes + 16 + 4 + 100 + 16 &&
                              wire::at<uint32_t>(bytes, 1) == 0 &&
                              wire::at<uint16_t>(bytes, 5) == 0 && bytes[7] == 2);
                const auto client = relay::verifyClientInit(bytes.subspan(8, 61));
                wire::require(
                    platform::relaySessionMatches(client.title, client.user, client.session));
                const auto credential = bytes.subspan(69, credentialBytes);
                Secret relaySecret{};
                uint32_t expires = client.expires;
                if (bindRequest)
                {
                    const auto server = relay::verifyServerInit(credential, relayId);
                    wire::require(server.user == client.user && server.title == client.title);
                    relaySecret = server.secret;
                    expires = std::min(expires, server.expires);
                }
                else
                {
                    wire::require(credential[0] == 1 &&
                                  wire::at<uint64_t>(credential, 1) == relayId &&
                                  crypto::equal(credential.last(6), address()));
                    const auto route = wire::at<uint32_t>(credential, 9);
                    const auto join = wire::at<uint64_t>(credential, 13);
                    const auto target = associations.find(route);
                    wire::require(target != associations.end() && target->second.established &&
                                  !target->second.closed && join && target->second.join == join &&
                                  target->second.client.title == client.title &&
                                  session(target->second));
                    relaySecret = target->second.joinSecret;
                }
                const auto random = bytes.subspan(69 + credentialBytes, 16);
                const auto platformAt = 85 + credentialBytes;
                wire::require(wire::at<uint32_t>(bytes, platformAt) == 101 &&
                              std::all_of(bytes.begin() + platformAt + 4,
                                          bytes.end() - 16,
                                          [](uint8_t b)
                                          {
                                              return !b;
                                          }));
                wire::require(validMac(bytes, 0, initKey(client.secret, relaySecret, random)));
                const auto digest = crypto::sha256(bytes);
                for (auto &[route, item] : associations)
                    if (crypto::equal(item.initDigest, digest))
                    {
                        (void)route;
                        wire::require(item.peer.sin_addr.s_addr == peer.sin_addr.s_addr &&
                                      item.peer.sin_port == peer.sin_port && !item.closed &&
                                      session(item));
                        send(item, item.initAck);
                        return;
                    }
                wire::require(associations.size() < 256);
                uint32_t route;
                do
                {
                    route = wire::at<uint32_t>(crypto::random(4), 0);
                } while (!route || associations.contains(route));
                auto &item = associations[route];
                item.peer = peer;
                item.client = client;
                item.client.expires = expires;
                item.route = route;
                item.initDigest = digest;
                if (bindRequest)
                    do
                    {
                        item.join = wire::at<uint64_t>(crypto::random(8), 0);
                    } while (!item.join);
                item.joinSecret = randomSecret();
                item.verification = randomSecret();
                const auto serverRandom = crypto::random(16);
                wire::Bytes seed;
                wire::raw(seed, client.title);
                wire::raw(seed, client.user);
                append(seed, client.secret);
                append(seed, relaySecret);
                append(seed, random);
                append(seed, serverRandom);
                const auto keys = hkdf(seed, "atOnU0BTUtmM0ju414F7", 21, 48);
                std::copy_n(keys.begin(), 16, item.sendMac.begin());
                std::copy_n(keys.begin() + 16, 16, item.cipher.begin());
                std::copy_n(keys.begin() + 32, 16, item.receiveMac.begin());
                // Native 142192750 decrypts 58 bytes: secret, verification, relay ID,
                // routing ID, join ID, IPv4 endpoint. Version + nonce[12]/cipher[58]/tag[16] = 87.
                wire::Bytes plain;
                append(plain, item.joinSecret);
                append(plain, item.verification);
                wire::raw(plain, relayId);
                wire::raw(plain, route);
                wire::raw(plain, item.join);
                append(plain, address());
                const auto nonce = crypto::random(12);
                wire::Bytes payload;
                append(payload, random);
                append(payload, serverRandom);
                payload.push_back(1);
                append(payload, nonce);
                const auto encrypted = crypto::gcm(item.cipher, nonce, plain, true);
                append(payload, encrypted);
                item.initAck = packet(2, route, 0, payload, item.sendMac);
                event(bindRequest ? "bind-init" : "join-init", &item);
                send(item, item.initAck);
            }

            void receive(std::span<const uint8_t> bytes, const sockaddr_in &peer)
            {
                wire::require(bytes.size() >= 12 && bytes.size() <= 1288);
                if (bytes[0] <= 1)
                {
                    init(bytes, peer);
                    return;
                }
                const auto route = wire::at<uint32_t>(bytes, 1);
                auto iterator = associations.find(route);
                wire::require(iterator != associations.end());
                auto &item = iterator->second;
                wire::require(item.peer.sin_addr.s_addr == peer.sin_addr.s_addr &&
                              item.peer.sin_port == peer.sin_port && session(item));
                const auto counter = item.receive.candidate(wire::at<uint16_t>(bytes, 5));
                wire::require(counter && validMac(bytes, *counter, item.receiveMac));
                const auto payload = bytes.subspan(7, bytes.size() - 7 - (bytes[0] == 5 ? 5 : 16));
                switch (bytes[0])
                {
                case 3:
                    wire::require(!item.closed && payload.size() == 16 &&
                                  crypto::equal(payload, item.verification));
                    item.receive.accept(*counter);
                    if (!item.established)
                    {
                        event("established", &item);
                        item.established = true;
                        ++verified;
                        ++active;
                    }
                    reply(item, 4);
                    break;
                case 5:
                {
                    wire::require(item.established && !item.closed && payload.size() >= 4 &&
                                  payload.size() <= 1276);
                    item.receive.accept(*counter);
                    const auto target = associations.find(wire::at<uint32_t>(payload, 0));
                    if (target != associations.end() && target->second.established &&
                        !target->second.closed &&
                        target->second.client.title == item.client.title && session(target->second))
                    {
                        auto &destination = target->second;
                        wire::require(destination.transmit < INT32_MAX);
                        // Native receiver checks destination ID, then constructs the source
                        // bdRelayRoute from the header routing ID (14219FE20).
                        send(destination,
                             packet(5,
                                    item.route,
                                    destination.transmit++,
                                    payload,
                                    destination.sendMac));
                        ++forwarded;
                    }
                    break;
                }
                case 6:
                {
                    wire::require(item.established && !item.closed && payload.size() == 9 &&
                                  payload[8] <= 1);
                    item.receive.accept(*counter);
                    // 1421A04A0 sends origin=1; 14219FE20 treats origin=1 as the
                    // echo of its own timestamp and origin=0 as a server probe. This
                    // is an origin tag, NOT a request/reply flag. Preserve it.
                    if (payload[8])
                    {
                        reply(item, 6, payload);
                        ++pings;
                    }
                    break;
                }
                case 8:
                {
                    wire::require(item.established && !item.closed && payload.size() == 53);
                    const auto server = relay::verifyServerInit(payload, relayId);
                    wire::require(server.title == item.client.title &&
                                  server.user == item.client.user);
                    item.receive.accept(*counter);
                    item.client.expires = std::min(item.client.expires, server.expires);
                    if (!item.join)
                    {
                        do
                        {
                            item.join = wire::at<uint64_t>(crypto::random(8), 0);
                        } while (!item.join);
                        event("bind-upgrade", &item);
                    }
                    wire::Bytes joined;
                    wire::raw(joined, item.join);
                    reply(item, 9, joined);
                    break;
                }
                case 10:
                    wire::require(payload.empty());
                    item.receive.accept(*counter);
                    if (!item.closed)
                    {
                        if (item.established)
                            --active;
                        item.closed = true;
                        event("disconnect", &item);
                    }
                    reply(item, 11);
                    break;
                default:
                    wire::require(false);
                }
                item.lastSeen = Clock::now();
            }

            void run(std::stop_token stop) noexcept
            {
                std::array<uint8_t, 1289> buffer{};
                auto window = Clock::now();
                unsigned count = 0;
                try
                {
                    while (!stop.stop_requested())
                    {
                        const auto clock = Clock::now();
                        for (auto it = associations.begin(); it != associations.end();)
                        {
                            const auto &item = it->second;
                            if (!session(item) || clock - item.lastSeen >
                                                      std::chrono::seconds(item.closed        ? 5
                                                                           : item.established ? 300
                                                                                              : 10))
                            {
                                if (item.established && !item.closed)
                                    --active;
                                it = associations.erase(it);
                            }
                            else
                                ++it;
                        }
                        fd_set readable{};
                        FD_SET(socket, &readable);
                        timeval timeout{0, 50000};
                        const auto ready = select(0, &readable, nullptr, nullptr, &timeout);
                        if (ready == SOCKET_ERROR)
                            throw ProviderFailure{Failure::socketWait};
                        if (!ready)
                            continue;
                        sockaddr_in peer{};
                        int size = sizeof(peer);
                        const auto bytes = recvfrom(socket,
                                                    reinterpret_cast<char *>(buffer.data()),
                                                    static_cast<int>(buffer.size()),
                                                    0,
                                                    reinterpret_cast<sockaddr *>(&peer),
                                                    &size);
                        if (bytes <= 0 || peer.sin_family != AF_INET ||
                            !network::permittedPeer(peer.sin_addr.s_addr))
                            continue;
                        if (clock - window >= std::chrono::seconds(1))
                        {
                            window = clock;
                            count = 0;
                        }
                        if (++count > 2048)
                        {
                            rejectedPacket(std::span(buffer.data(), static_cast<size_t>(bytes)),
                                           "rate-limit");
                            continue;
                        }
                        try
                        {
                            const network::PeerScope publication(peer.sin_addr.s_addr);
                            receive(std::span(buffer.data(), static_cast<size_t>(bytes)), peer);
                        }
                        catch (const ProviderFailure &)
                        {
                            throw;
                        }
                        catch (const std::bad_alloc &)
                        {
                            throw;
                        }
                        catch (...)
                        {
                            rejectedPacket(std::span(buffer.data(), static_cast<size_t>(bytes)));
                        }
                    }
                }
                catch (const ProviderFailure &error)
                {
                    failure = error.reason;
                }
                catch (...)
                {
                    failure = Failure::internal;
                }
                running = false;
                active = 0;
                associations.clear();
            }
        };

        std::unique_ptr<Provider> provider;
    } // namespace

    void start(const std::filesystem::path &directory)
    {
        stop();
        const auto path = directory / "relay" / "local-provider.json";
        if (!std::filesystem::exists(path))
            return;
        wire::require(std::filesystem::file_size(path) <= 4096);
        std::ifstream in(path);
        if (!in)
            throw std::runtime_error("Relay provider configuration read failed");
        const auto config = Json::parse(in);
        wire::require(config.is_object() && config.at("enabled").is_boolean());
        if (config.at("enabled").get<bool>())
            provider = std::make_unique<Provider>(directory);
    }

    void stop()
    {
        provider.reset();
    }

    bool enabled()
    {
        return provider && provider->running.load();
    }

    wire::Bytes serverToken(const platform::LobbyIdentity &id)
    {
        wire::require(enabled());
        return relay::issueServerToken(id, provider->relayId, provider->address());
    }

    std::string status()
    {
        const auto failure = provider ? provider->failure.load() : Failure::none;
        const char *error = "";
        switch (failure)
        {
        case Failure::none:
            break;
        case Failure::socketWait:
            error = "socket-wait";
            break;
        case Failure::eventWrite:
            error = "event-write";
            break;
        case Failure::socketSend:
            error = "socket-send";
            break;
        case Failure::internal:
            error = "internal";
            break;
        }
        return Json{{"enabled", enabled()},
                    {"port", provider ? provider->port : 0},
                    {"relay_id", provider ? provider->relayId : 0},
                    {"failure", error},
                    {"verified_associations", provider ? provider->verified.load() : 0},
                    {"active_associations", provider ? provider->active.load() : 0},
                    {"forwarded_packets", provider ? provider->forwarded.load() : 0},
                    {"ping_replies", provider ? provider->pings.load() : 0},
                    {"rejected_packets", provider ? provider->rejected.load() : 0},
                    {"rejection_events", provider ? provider->rejectionEvents.load() : 0},
                    {"suppressed_rejection_events",
                     provider ? provider->suppressedRejectionEvents.load() : 0}}
            .dump();
    }
} // namespace relay_provider
