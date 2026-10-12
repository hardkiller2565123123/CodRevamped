#include "host_os.h"
#include "lobby.h"
#include "platform.h"
#include "wire.h"
#include "services.h"
#include "bandwidth.h"
#include "traffic_kdf.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <map>
#include <unordered_map>
#include <set>
#include <tuple>

namespace lobby
{
    std::atomic<unsigned> connections{0}, authenticated{0}, frames{0}, tasks{0}, failures{0};

    namespace
    {
        using crypto::Bytes;
        constexpr unsigned maxFrame = 1024 * 1024;

        // A registered endpoint owns only its serialized outbound channel. The lease
        // retires it before the stack-held socket/traffic key can be destroyed. No
        // detached writer can outlive serve(), and readers never hold this lock.
        struct PushEndpoint
        {
            std::mutex mutex;
            platform::LobbyIdentity identity;
            std::string sessionFingerprint;
            std::function<bool(std::span<const uint8_t>)> writer;
            bool hostAuthenticated = false;
            uint64_t lastTournament = 0;
            uint64_t lastTournamentSearch = 0;
            bool lastTournamentJoin = false;
            bool lastTournamentFormationDisband = false;
            uint64_t lastTournamentRoundLobby = 0, lastTournamentRoundSearch = 0;
            std::string lastTournamentHash;
            std::map<std::string, uint64_t> lastMail;
            std::map<std::pair<std::string, uint64_t>, std::pair<uint64_t, std::string>> lastProgression;
            // This is transport publication history, not a guessed native state.
            // Each serialized writer publishes a required join before a message
            // and coalesces the same join still pending in the delayed queue.
            using ChannelMember = std::tuple<std::string, uint64_t, uint64_t>;
            std::map<ChannelMember, std::pair<uint32_t, uint32_t>> channelJoins;
        };

        std::mutex endpointMutex;
        std::unordered_map<uint64_t, std::shared_ptr<PushEndpoint>> endpoints;
        // Brief presence reads do not reverse endpointMutex -> service-store lock
        // ordering. Release this separate lock before calling any service handler.
        std::mutex onlineMutex;

        struct OnlineSession
        {
            unsigned count = 0;
            platform::LobbyIdentity identity;
        };

        std::map<std::pair<uint32_t, uint64_t>, std::map<std::string, OnlineSession>> onlineUsers;
        // Counts native CodRevamped-hosted sessions by the same SHA-256 key
        // fingerprint used by matchmaking token_session.
        std::map<std::tuple<uint32_t, uint64_t, std::string>, unsigned> hostedSessions;
        void route(uint32_t title, const services::Delivery &delivery);
        void startPublicationUpdates();

        struct PushLease
        {
            uint64_t connection;
            std::shared_ptr<PushEndpoint> endpoint;

            PushLease(uint64_t key,
                      const platform::LobbyIdentity &identity,
                      std::function<bool(std::span<const uint8_t>)> writer,
                      const std::function<bool()> &announce)
                : connection(key), endpoint(std::make_shared<PushEndpoint>())
            {
                endpoint->identity = identity;
                endpoint->sessionFingerprint = wire::base64Encode(crypto::sha256(identity.key));
                endpoint->writer = std::move(writer);
                startPublicationUpdates();
                std::lock_guard lock(endpointMutex);
                wire::require(!endpoints.contains(connection));
                // Routing holds this same lock when selecting recipients. Publish the
                // native connection-ready record inside the registration transaction:
                // a peer can never observe readiness yet miss this endpoint, and no
                // unsolicited push can precede that record on the new connection.
                if (!announce())
                    throw std::runtime_error("Lobby connection announcement failed");
                endpoints.emplace(connection, endpoint);
                {
                    std::lock_guard presenceLock(onlineMutex);
                    auto &session = onlineUsers[{identity.titleId, identity.userId}]
                                               [endpoint->sessionFingerprint];
                    session.identity = identity;
                    ++session.count;
                }
            }

            ~PushLease()
            {
                std::vector<services::Delivery> notifications;
                {
                    std::lock_guard lock(endpointMutex);
                    endpoints.erase(connection);
                    {
                        std::lock_guard presenceLock(onlineMutex);
                        const auto key =
                            std::make_pair(endpoint->identity.titleId, endpoint->identity.userId);
                        auto found = onlineUsers.find(key);
                        if (found != onlineUsers.end())
                        {
                            auto session = found->second.find(endpoint->sessionFingerprint);
                            if (session != found->second.end() && !--session->second.count)
                                found->second.erase(session);
                            if (found->second.empty())
                                onlineUsers.erase(found);
                        }
                    }
                    bool online = false;
                    for (const auto &entry : endpoints)
                        if (entry.second->identity.titleId == endpoint->identity.titleId &&
                            entry.second->identity.userId == endpoint->identity.userId &&
                            (entry.second->hostAuthenticated ||
                             platform::valid(entry.second->identity)))
                            online = true;
                    if (!online)
                        try
                        {
                            notifications = services::disconnected(endpoint->identity.titleId,
                                                                   endpoint->identity.userId);
                        }
                        catch (...)
                        {
                            ++failures;
                        }
                }
                {
                    std::lock_guard lock(endpoint->mutex);
                    endpoint->writer = {};
                    SecureZeroMemory(endpoint->identity.key.data(), endpoint->identity.key.size());
                }
                // Select/deliver only after releasing the endpoint and service locks.
                // Revision validation drops an offline snapshot if the peer has
                // already reconnected and published a newer presence.
                for (const auto &notification : notifications)
                    try
                    {
                        route(endpoint->identity.titleId, notification);
                    }
                    catch (...)
                    {
                        ++failures;
                    }
            }
        };

        std::vector<std::shared_ptr<PushEndpoint>> targetsFor(uint32_t title, uint64_t user)
        {
            std::vector<std::shared_ptr<PushEndpoint>> targets;
            {
                std::lock_guard lock(endpointMutex);
                for (const auto &entry : endpoints)
                    if (entry.second->identity.titleId == title &&
                        entry.second->identity.userId == user)
                        targets.push_back(entry.second);
            }
            return targets;
        }

        void deliver(uint32_t title,
                     const services::Delivery &delivery,
                     const std::vector<std::shared_ptr<PushEndpoint>> &targets)
        {
            for (const auto &endpoint : targets)
            {
                std::lock_guard lock(endpoint->mutex);
                if (delivery.progressionRefresh)
                {
                    const auto previous = endpoint->lastProgression.find(
                        {delivery.progressionContext, delivery.progressionId});
                    if (previous != endpoint->lastProgression.end() &&
                        previous->second == std::make_pair(delivery.progressionXp,
                                                          delivery.progressionRewardsHash))
                        continue;
                }
                // Validate after taking the serialized writer lock. A newer presence
                // cannot overtake a previously validated push waiting for this lock.
                if (delivery.mailId)
                {
                    const auto previous = endpoint->lastMail.find(delivery.mailContext);
                    if (previous != endpoint->lastMail.end() && previous->second >= delivery.mailId)
                        continue;
                    if (previous == endpoint->lastMail.end() && endpoint->lastMail.size() >= 128)
                        continue;
                }
                if (!services::deliveryValid(title, delivery))
                    return;
                const PushEndpoint::ChannelMember channelMember = {
                    delivery.channelCategory, delivery.channelId, delivery.channelMember};
                const auto channelGeneration = std::make_pair(delivery.channelMemberGeneration,
                                                              delivery.channelRecipientGeneration);
                const auto priorJoin = endpoint->channelJoins.find(channelMember);
                const bool joined = priorJoin != endpoint->channelJoins.end() &&
                                    priorJoin->second == channelGeneration;
                if (delivery.channelEvent == 24 && joined)
                    continue;
                if (delivery.tournamentRoundLobby &&
                    endpoint->lastTournamentRoundLobby == delivery.lobbyId &&
                    endpoint->lastTournamentRoundSearch == delivery.searchId)
                    continue;
                if (!delivery.tournamentRoundLobby && delivery.tournamentRefresh &&
                    endpoint->lastTournament == delivery.tournamentId &&
                    endpoint->lastTournamentSearch == delivery.searchId &&
                    endpoint->lastTournamentJoin == delivery.tournamentJoin &&
                    endpoint->lastTournamentFormationDisband ==
                        delivery.tournamentFormationDisband &&
                    endpoint->lastTournamentHash == delivery.tournamentStateHash)
                    continue;
                try
                {
                    if (endpoint->writer &&
                        (endpoint->hostAuthenticated || platform::valid(endpoint->identity)))
                    {
                        if (!delivery.channelJoinPayload.empty() && !joined)
                        {
                            if (!endpoint->writer(delivery.channelJoinPayload))
                            {
                                endpoint->writer = {};
                                continue;
                            }
                            if (endpoint->channelJoins.size() >= 8192 &&
                                !endpoint->channelJoins.contains(channelMember))
                                endpoint->channelJoins.erase(endpoint->channelJoins.begin());
                            endpoint->channelJoins[channelMember] = channelGeneration;
                        }
                        if (!endpoint->writer(delivery.payload))
                            endpoint->writer = {};
                        else if (delivery.channelEvent == 24)
                        {
                            if (endpoint->channelJoins.size() >= 8192 &&
                                !endpoint->channelJoins.contains(channelMember))
                                endpoint->channelJoins.erase(endpoint->channelJoins.begin());
                            endpoint->channelJoins[channelMember] = channelGeneration;
                        }
                        else if (delivery.channelEvent == 25)
                            endpoint->channelJoins.erase(channelMember);
                        else if (delivery.mailId)
                            endpoint->lastMail[delivery.mailContext] = delivery.mailId;
                        else if (!delivery.progressionContext.empty())
                            endpoint->lastProgression[{delivery.progressionContext, delivery.progressionId}] =
                                {delivery.progressionXp, delivery.progressionRewardsHash};
                        else if (delivery.tournamentRoundLobby)
                        {
                            endpoint->lastTournamentRoundLobby = delivery.lobbyId;
                            endpoint->lastTournamentRoundSearch = delivery.searchId;
                        }
                        else if (delivery.tournamentId)
                        {
                            endpoint->lastTournament = delivery.tournamentId;
                            endpoint->lastTournamentSearch = delivery.searchId;
                            endpoint->lastTournamentJoin = delivery.tournamentJoin;
                            endpoint->lastTournamentFormationDisband =
                                delivery.tournamentFormationDisband;
                            endpoint->lastTournamentHash = delivery.tournamentStateHash;
                        }
                    }
                }
                catch (...)
                {
                    endpoint->writer = {};
                    ++failures;
                }
            }
        }

        // Matchmaking notifications become ready separately from the request's remote
        // task. Queue them without stalling socket readers or holding service locks.
        struct DeliveryQueue
        {
            using Time = std::chrono::steady_clock::time_point;
            std::mutex mutex;
            std::condition_variable condition;

            struct Pending
            {
                uint32_t title;
                services::Delivery delivery;
                std::vector<std::shared_ptr<PushEndpoint>> targets;
            };

            std::multimap<Time, Pending> pending;
            bool stopping = false;
            std::thread worker;

            DeliveryQueue()
                : worker(
                      [this]
                      {
                          std::unique_lock lock(mutex);
                          while (!stopping)
                          {
                              if (pending.empty())
                              {
                                  condition.wait(lock);
                                  continue;
                              }
                              const auto next = pending.begin()->first;
                              if (next > std::chrono::steady_clock::now())
                              {
                                  condition.wait_until(lock, next);
                                  continue;
                              }
                              auto value = std::move(pending.begin()->second);
                              pending.erase(pending.begin());
                              lock.unlock();
                              deliver(value.title, value.delivery, value.targets);
                              lock.lock();
                          }
                      })
            {
            }

            ~DeliveryQueue()
            {
                {
                    std::lock_guard lock(mutex);
                    stopping = true;
                }
                condition.notify_one();
                worker.join();
            }

            void add(uint32_t title, const services::Delivery &delivery)
            {
                // Capture connection leases now. Reconnecting the same user later
                // must not inherit a notification queued for the retired connection.
                auto targets = targetsFor(title, delivery.user);
                std::lock_guard lock(mutex);
                wire::require(pending.size() < 16384 && delivery.delayMs <= 5000);
                pending.emplace(std::chrono::steady_clock::now() +
                                    std::chrono::milliseconds(delivery.delayMs),
                                Pending{title, delivery, std::move(targets)});
                condition.notify_one();
            }
        };

        DeliveryQueue &deliveryQueue()
        {
            static DeliveryQueue queue;
            return queue;
        }

        void startPublicationUpdates()
        {
            // Construct the writer queue first so the idle publisher is joined
            // before that queue is destroyed during orderly process shutdown.
            (void)deliveryQueue();

            // Snapshot connection leases before reading the service store. Never
            // retain endpointMutex or a service lock while sending a native frame.
            struct Updates
            {
                std::mutex mutex;
                std::condition_variable condition;
                bool stopping = false;
                std::thread worker;

                Updates()
                    : worker(
                          [this]
                          {
                              std::unique_lock lock(mutex);
                              while (!condition.wait_for(lock,
                                                         std::chrono::seconds(1),
                                                         [this]
                                                         {
                                                             return stopping;
                                                         }))
                              {
                                  lock.unlock();
                                  std::set<std::pair<uint32_t, uint64_t>> accounts;
                                  {
                                      std::lock_guard endpointLock(endpointMutex);
                                      for (const auto &entry : endpoints)
                                          accounts.emplace(entry.second->identity.titleId,
                                                           entry.second->identity.userId);
                                  }
                                  for (const auto &[title, user] : accounts)
                                  {
                                      try
                                      {
                                          const auto update =
                                              services::tournamentUpdate(title, user);
                                          if (update)
                                              route(title, *update);
                                          const auto lobbyUpdate =
                                              services::tournamentLobbyUpdate(title, user);
                                          if (lobbyUpdate)
                                              route(title, *lobbyUpdate);
                                      }
                                      catch (const std::exception &)
                                      {
                                          // A malformed publication is not a disband.
                                          // The task reader still reports its storage error.
                                      }
                                      try
                                      {
                                          for (const auto &delivery :
                                               services::mailUpdates(title, user))
                                              route(title, delivery);
                                      }
                                      catch (const std::exception &)
                                      {
                                          // A malformed mailbox cannot notify or prevent
                                          // another account's publication from progressing.
                                      }
                                      try
                                      {
                                          for (const auto &progression :
                                               services::progressionUpdates(title, user))
                                              route(title, progression);
                                      }
                                      catch (const std::exception &)
                                      {
                                          // An incomplete/corrupt XP transaction must not
                                          // publish a fabricated snapshot or block mail.
                                      }
                                  }
                                  lock.lock();
                              }
                          })
                {
                }

                ~Updates()
                {
                    {
                        std::lock_guard lock(mutex);
                        stopping = true;
                    }
                    condition.notify_one();
                    worker.join();
                }
            };

            static Updates updates;
        }

        void route(uint32_t title, const services::Delivery &delivery)
        {
            if (!delivery.delayMs)
            {
                deliver(title, delivery, targetsFor(title, delivery.user));
                return;
            }
            deliveryQueue().add(title, delivery);
        }

        Bytes frame(const IO &io, bool keepalive = true)
        {
            auto window = std::chrono::steady_clock::now();
            unsigned pings = 0;
            for (;;)
            {
                std::array<uint8_t, 4> header{};
                if (!io.read(header, io.authenticatedRead))
                    return {};
                const auto size = wire::at<uint32_t>(header, 0);
                wire::require(size <= maxFrame);
                if (!size)
                {
                    wire::require(keepalive);
                    const auto time = std::chrono::steady_clock::now();
                    if (time - window >= std::chrono::seconds(1))
                    {
                        window = time;
                        pings = 0;
                    }
                    wire::require(++pings <=
                                  128); // reject floods without imposing a session lifetime
                    if (!io.write(header))
                        return {};
                    continue;
                }
                Bytes data(header.begin(), header.end());
                data.resize(size + 4);
                if (!io.read(std::span(data).subspan(4), io.authenticatedRead))
                    return {};
                ++frames;
                return data;
            }
        }

        uint64_t bits(std::span<const uint8_t> bytes, unsigned &position, unsigned count)
        {
            wire::require(count <= 64 && position + count <= bytes.size() * 8);
            uint64_t out = 0;
            for (unsigned i = 0; i < count; ++i)
                out |= uint64_t((bytes[(position + i) / 8] >> ((position + i) % 8)) & 1) << i;
            position += count;
            return out;
        }

        struct Traffic
        {
            Bytes material;
            uint32_t incoming = 1, outgoing = 1;

            ~Traffic()
            {
                SecureZeroMemory(material.data(), material.size());
            }

            Bytes encode(uint8_t type, std::span<const uint8_t> payload)
            {
                wire::require(outgoing != UINT32_MAX);
                Bytes plain;
                wire::raw(plain, static_cast<uint32_t>(payload.size()));
                plain.push_back(type);
                plain.insert(plain.end(), payload.begin(), payload.end());
                plain.resize((plain.size() + 15) & ~size_t(15), 0);
                auto iv = crypto::random(16);
                auto cipher = crypto::aes(std::span(material).subspan(56, 16), iv, plain, true);
                Bytes record;
                wire::raw(record, static_cast<uint32_t>(cipher.size() + 30));
                record.push_back(0xab);
                record.push_back(0x85);
                wire::raw(record, outgoing++);
                record.insert(record.end(), iv.begin(), iv.end());
                record.insert(record.end(), cipher.begin(), cipher.end());
                auto mac = crypto::hmac(std::span(material).subspan(20, 20), record);
                record.insert(record.end(), mac.begin(), mac.begin() + 8);
                return record;
            }

            Bytes decode(std::span<const uint8_t> packet)
            {
                if (!(packet.size() >= 50 && packet[4] == 0xab && packet[5] == 0x85 &&
                      (packet.size() - 34) % 16 == 0))
                    throw std::runtime_error("Encrypted record shape invalid");
                if (incoming == UINT32_MAX || wire::at<uint32_t>(packet, 6) != incoming)
                    throw std::runtime_error("Encrypted record sequence invalid");
                const auto mac =
                    crypto::hmac(std::span(material).first(20), packet.first(packet.size() - 8));
                if (!crypto::equal(std::span(mac).first(8), packet.last(8)))
                    throw std::runtime_error("Encrypted record authentication invalid");
                auto plain = crypto::aes(std::span(material).subspan(40, 16),
                                         packet.subspan(10, 16),
                                         packet.subspan(26, packet.size() - 34),
                                         false);
                const auto length = wire::at<uint32_t>(plain, 0);
                if (!(length <= plain.size() - 5 && plain.size() - 5 - length < 16))
                    throw std::runtime_error("Encrypted record plaintext length invalid");
                if (plain[4] != 0x86)
                    throw std::runtime_error("Authenticated client channel unsupported; type=" +
                                             std::to_string(plain[4]));
                for (size_t i = 5 + length; i < plain.size(); ++i)
                    if (plain[i])
                        throw std::runtime_error("Encrypted record padding invalid");
                ++incoming;
                return Bytes(plain.begin() + 5, plain.begin() + 5 + length);
            }
        };
    } // namespace

    void registerHostedConnection(
        uint64_t connection,
        const platform::LobbyIdentity &identity,
        std::function<bool(std::span<const uint8_t>)> writer)
    {
        wire::require(connection && identity.titleId && identity.userId && writer);

        auto endpoint = std::make_shared<PushEndpoint>();
        endpoint->identity = identity;
        endpoint->sessionFingerprint = wire::base64Encode(crypto::sha256(identity.key));
        endpoint->writer = std::move(writer);
        endpoint->hostAuthenticated = true;
        startPublicationUpdates();

        std::lock_guard lock(endpointMutex);
        wire::require(!endpoints.contains(connection));
        endpoints.emplace(connection, endpoint);
        {
            std::lock_guard presenceLock(onlineMutex);
            auto &session =
                onlineUsers[{identity.titleId, identity.userId}][endpoint->sessionFingerprint];
            session.identity = identity;
            ++session.count;
            ++hostedSessions[
                {identity.titleId, identity.userId, endpoint->sessionFingerprint}];
        }
    }

    void unregisterHostedConnection(uint64_t connection)
    {
        std::shared_ptr<PushEndpoint> endpoint;
        std::vector<services::Delivery> notifications;
        {
            std::lock_guard lock(endpointMutex);
            const auto foundEndpoint = endpoints.find(connection);
            if (foundEndpoint == endpoints.end() || !foundEndpoint->second->hostAuthenticated)
                return;

            endpoint = foundEndpoint->second;
            endpoints.erase(foundEndpoint);

            {
                std::lock_guard presenceLock(onlineMutex);
                const auto userKey =
                    std::make_pair(endpoint->identity.titleId, endpoint->identity.userId);
                const auto foundUser = onlineUsers.find(userKey);
                if (foundUser != onlineUsers.end())
                {
                    const auto session = foundUser->second.find(endpoint->sessionFingerprint);
                    if (session != foundUser->second.end())
                    {
                        if (session->second.count)
                            --session->second.count;
                        if (!session->second.count)
                            foundUser->second.erase(session);
                    }
                    if (foundUser->second.empty())
                        onlineUsers.erase(foundUser);
                }

                const auto hostedKey = std::make_tuple(
                    endpoint->identity.titleId,
                    endpoint->identity.userId,
                    endpoint->sessionFingerprint);
                const auto hosted = hostedSessions.find(hostedKey);
                if (hosted != hostedSessions.end())
                {
                    if (hosted->second > 1)
                        --hosted->second;
                    else
                        hostedSessions.erase(hosted);
                }
            }

            bool online = false;
            for (const auto &entry : endpoints)
                if (entry.second->identity.titleId == endpoint->identity.titleId &&
                    entry.second->identity.userId == endpoint->identity.userId &&
                    (entry.second->hostAuthenticated ||
                     platform::valid(entry.second->identity)))
                    online = true;

            if (!online)
                try
                {
                    notifications =
                        services::disconnected(endpoint->identity.titleId,
                                               endpoint->identity.userId);
                }
                catch (...)
                {
                    ++failures;
                }
        }

        {
            std::lock_guard lock(endpoint->mutex);
            endpoint->writer = {};
            SecureZeroMemory(endpoint->identity.key.data(), endpoint->identity.key.size());
        }

        for (const auto &notification : notifications)
            try
            {
                route(endpoint->identity.titleId, notification);
            }
            catch (...)
            {
                ++failures;
            }
    }

    bool publishHostedPush(uint64_t connection, std::span<const uint8_t> payload)
    {
        std::shared_ptr<PushEndpoint> endpoint;
        {
            std::lock_guard lock(endpointMutex);
            const auto found = endpoints.find(connection);
            if (found == endpoints.end() || !found->second->hostAuthenticated)
                return false;
            endpoint = found->second;
        }

        std::lock_guard lock(endpoint->mutex);
        try
        {
            if (!endpoint->writer)
                return false;
            if (!endpoint->writer(payload))
            {
                endpoint->writer = {};
                return false;
            }
            return true;
        }
        catch (...)
        {
            endpoint->writer = {};
            ++failures;
            return false;
        }
    }

    void publishOperatorUpdates(uint32_t title, std::span<const services::Delivery> deliveries)
    {
        for (const auto &delivery : deliveries)
            route(title, delivery);
    }

    std::vector<OnlinePlayer> onlinePlayerList()
    {
        struct Snapshot
        {
            platform::LobbyIdentity identity;
            bool hosted = false;
        };

        std::vector<std::vector<Snapshot>> users;
        {
            std::lock_guard lock(onlineMutex);
            for (const auto &[key, sessions] : onlineUsers)
            {
                auto &identities = users.emplace_back();
                for (const auto &[fingerprint, session] : sessions)
                {
                    const auto hosted = hostedSessions.find(
                        {key.first, key.second, fingerprint});
                    identities.push_back(
                        {session.identity,
                         hosted != hostedSessions.end() && hosted->second != 0});
                }
            }
        }

        std::vector<OnlinePlayer> players;
        for (const auto &identities : users)
            for (const auto &snapshot : identities)
                if (snapshot.hosted || platform::valid(snapshot.identity))
                {
                    players.push_back(
                        {snapshot.identity.titleId,
                         snapshot.identity.userId,
                         platform::accountName(snapshot.identity.userId)
                             .value_or(snapshot.identity.name)});
                    break;
                }
        return players;
    }

    unsigned onlinePlayers()
    {
        return static_cast<unsigned>(onlinePlayerList().size());
    }

    bool online(uint32_t title, uint64_t user)
    {
        struct Snapshot
        {
            platform::LobbyIdentity identity;
            bool hosted = false;
        };

        std::vector<Snapshot> identities;
        {
            std::lock_guard lock(onlineMutex);
            const auto entry = onlineUsers.find({title, user});
            if (entry != onlineUsers.end())
                for (const auto &[fingerprint, session] : entry->second)
                {
                    const auto hosted = hostedSessions.find({title, user, fingerprint});
                    identities.push_back(
                        {session.identity,
                         hosted != hostedSessions.end() && hosted->second != 0});
                }
        }
        return std::any_of(
            identities.begin(),
            identities.end(),
            [](const Snapshot &snapshot)
            {
                return snapshot.hosted || platform::valid(snapshot.identity);
            });
    }

    std::optional<platform::LobbyIdentity> onlineIdentity(uint32_t title, uint64_t user)
    {
        struct Snapshot
        {
            platform::LobbyIdentity identity;
            bool hosted = false;
        };

        std::vector<Snapshot> identities;
        {
            std::lock_guard lock(onlineMutex);
            const auto entry = onlineUsers.find({title, user});
            if (entry != onlineUsers.end())
                for (const auto &[fingerprint, session] : entry->second)
                {
                    const auto hosted = hostedSessions.find({title, user, fingerprint});
                    identities.push_back(
                        {session.identity,
                         hosted != hostedSessions.end() && hosted->second != 0});
                }
        }

        for (auto &snapshot : identities)
        {
            if (snapshot.hosted)
                return snapshot.identity;
            if (platform::refreshLease(snapshot.identity))
                return snapshot.identity;
        }
        return std::nullopt;
    }

    std::optional<platform::LobbyIdentity> onlineIdentity(uint32_t title,
                                                          uint64_t user,
                                                          const std::string &fingerprint)
    {
        std::optional<platform::LobbyIdentity> identity;
        bool hosted = false;
        {
            std::lock_guard lock(onlineMutex);
            const auto userEntry = onlineUsers.find({title, user});
            if (userEntry != onlineUsers.end())
            {
                const auto session = userEntry->second.find(fingerprint);
                if (session != userEntry->second.end())
                {
                    identity = session->second.identity;
                    const auto hostedEntry =
                        hostedSessions.find({title, user, fingerprint});
                    hosted =
                        hostedEntry != hostedSessions.end() && hostedEntry->second != 0;
                }
            }
        }

        if (identity && hosted)
            return identity;
        if (identity && platform::refreshLease(*identity))
            return identity;
        return std::nullopt;
    }

    bool sessionOnline(uint32_t title, uint64_t user, const std::string &fingerprint)
    {
        return onlineIdentity(title, user, fingerprint).has_value();
    }

    void serve(const IO &transport)
    {
        ++connections;
        std::mutex sendMutex;
        IO io = transport;
        // Serialize keepalives with encrypted records, including writes initiated
        // by other authenticated lobby connections. Preserve whole-frame order.
        io.write = [&](std::span<const uint8_t> bytes)
        {
            std::lock_guard lock(sendMutex);
            return transport.write(bytes);
        };
        std::string stage = "handshake";
        try
        {
            // Client hello is a raw 28-byte compatibility header, not size-prefixed.
            // Permit a bounded diagnostic keepalive before it, as the original probe does.
            Bytes hello(4);
            for (unsigned attempt = 0;; ++attempt)
            {
                if (!io.read(hello, io.authenticatedRead))
                    return;
                if (wire::at<uint32_t>(hello, 0) != 0)
                    break;
                wire::require(attempt < 8);
                if (!io.write(hello))
                    return;
            }
            wire::require(wire::at<uint32_t>(hello, 0) == 200);
            hello.resize(28);
            if (!io.read(std::span(hello).subspan(4), io.authenticatedRead))
                return;
            wire::require(wire::at<uint32_t>(hello, 4) == 200 &&
                          wire::at<uint32_t>(hello, 8) <= 210 &&
                          wire::at<uint32_t>(hello, 12) >= 210);
            const auto maxReceive = wire::at<uint32_t>(hello, 16);
            wire::require(maxReceive >= 128);
            const auto connectionBytes = crypto::random(8);
            const auto connection = wire::at<uint64_t>(connectionBytes, 0) | 1;
            Bytes ack;
            wire::raw(ack, uint32_t(22));
            ack.push_back(0xab);
            ack.push_back(0x81);
            wire::raw(ack, uint32_t(210));
            wire::raw(ack, connection);
            const auto nonce = crypto::random(8);
            ack.insert(ack.end(), nonce.begin(), nonce.end());
            if (!io.write(ack))
                return;
            auto auth = frame(io, false);
            wire::require(auth.size() == 153 && auth[4] == 0xab && auth[5] == 0x82);
            const auto blob = std::span(auth).subspan(6, 139);
            unsigned position = 0;
            wire::require(bits(blob, position, 8) == 7 && bits(blob, position, 1) == 1 &&
                          bits(blob, position, 5) == 8);
            const auto title = static_cast<uint32_t>(bits(blob, position, 32));
            wire::require(bits(blob, position, 5) == 8);
            const auto seed = static_cast<uint32_t>(bits(blob, position, 32));
            std::array<uint8_t, 128> ticket{};
            for (auto &value : ticket)
                value = static_cast<uint8_t>(bits(blob, position, 8));
            wire::require(bits(blob, position, 5) == 0);
            platform::LobbyIdentity identity;
            if (!platform::authorize(ticket, title, seed, identity))
                throw std::runtime_error("Lobby ticket unknown, expired or mismatched");
            Bytes transcript(hello.begin() + 8, hello.end());
            transcript.insert(transcript.end(), ack.begin(), ack.end());
            transcript.insert(transcript.end(), auth.begin(), auth.end() - 8);
            auto trafficSession = crypto::expand(identity.key, trafficKdfInfo, 24);
            auto prk = crypto::hmac(crypto::sha1(transcript), trafficSession);
            constexpr uint8_t challengeLabel[] = {'C', 'L', 'I', 'E', 'N', 'T', 'C', 'H', 'A', 'L'},
                              dataLabel[] = {'B', 'D', 'D', 'A', 'T', 'A'};
            auto challenge = crypto::expand(prk, challengeLabel, 16);
            wire::require(crypto::equal(std::span(auth).last(8), std::span(challenge).first(8)));
            Traffic traffic;
            traffic.material = crypto::expand(prk, dataLabel, 72);
            auto sendRecord = [&](uint8_t type, std::span<const uint8_t> data)
            {
                std::lock_guard lock(sendMutex);
                const auto packet = traffic.encode(type, data);
                return transport.write(packet);
            };
            Bytes done;
            wire::raw(done, uint32_t(10));
            done.push_back(0xab);
            done.push_back(0x83);
            done.insert(done.end(), challenge.begin() + 8, challenge.end());
            SecureZeroMemory(trafficSession.data(), trafficSession.size());
            SecureZeroMemory(prk.data(), prk.size());
            SecureZeroMemory(challenge.data(), challenge.size());
            io.authenticatedRead = [&identity, &io]
            {
                if (platform::valid(identity))
                    return true;
                io.log("LOBBY retired expired or superseded issuer lease during read");
                return false;
            };
            if (!io.write(done))
                return;
            wire::Writer connectionMessage;
            connectionMessage.u64(connection);
            PushLease lease(
                connection,
                identity,
                [&](std::span<const uint8_t> data)
                {
                    if (data.size() + 64 > maxReceive)
                        return false;
                    return sendRecord(2, data);
                },
                [&]
                {
                    return sendRecord(4, connectionMessage.data);
                });
            ++authenticated;
            io.log("LOBBY authenticated native protocol 210 session; connection=" +
                   std::to_string(connection));
            uint64_t transaction = 1;
            bandwidth::Session bandwidthSession;
            for (;;)
            {
                stage = "record-read";
                auto record = frame(io);
                if (record.empty())
                    return;
                stage = "session-validity";
                if (!platform::valid(identity))
                    throw std::runtime_error("Lobby session expired or superseded");
                stage = "record-decode";
                auto payload = traffic.decode(record);
                if (payload.size() >= 2 && payload[0] == 18 && payload[1] == 1)
                {
                    stage = "lsg-bandwidth-dispatch";
                    const auto reply = bandwidthSession.dispatch(std::span(payload).subspan(2));
                    // 0x142126250 dispatches message type 5 to 0x142116FD0, which
                    // consumes a raw u64 transaction then retains the byte buffer.
                    // Ordinary type 1 replies would lose bdRemoteTask::m_byteResults.
                    Bytes response;
                    wire::raw(response, transaction++);
                    response.insert(response.end(), reply.data.begin(), reply.data.end());
                    wire::require(response.size() + 64 <= maxReceive);
                    ++tasks;
                    io.log("TASK service=18 task=1 operation=" + reply.operation + " error=" +
                           std::to_string(reply.data[0] ? wire::at<uint16_t>(reply.data, 1) : 0) +
                           reply.detail);
                    if (!sendRecord(5, response))
                        return;
                    continue;
                }
                if (payload.size() < 3)
                    throw std::runtime_error("Native task header is truncated; payload bytes=" +
                                             std::to_string(payload.size()));
                stage = "task-header bytes=" + std::to_string(payload.size()) +
                        " service=" + std::to_string(payload[0]) +
                        " task_tag=" + std::to_string(payload[1]);
                const auto service = payload[0];
                wire::Reader reader{std::span(payload).subspan(1)};
                const auto task = reader.u8();
                stage = "task-dispatch service=" + std::to_string(service) +
                        " task=" + std::to_string(task);
                auto reply = services::dispatch(identity, service, task, reader);
                auto response = services::taskReply(transaction++, task, reply);
                if (response.size() + 64 > maxReceive)
                {
                    reply = {100, {}, "reply-exceeds-client-buffer"};
                    response = services::taskReply(transaction - 1, task, reply);
                }
                ++tasks;
                io.log("TASK service=" + std::to_string(service) + " task=" + std::to_string(task) +
                       " operation=" + reply.operation + " error=" + std::to_string(reply.error) +
                       " results=" + std::to_string(reply.rest ? 1 : reply.results.size()) +
                       reply.detail);
                if (!sendRecord(1, response))
                    return;
                for (const auto &push : reply.pushes)
                {
                    wire::require(push.size() + 64 <= maxReceive);
                    if (!sendRecord(2, push))
                        return;
                }
                for (const auto &delivery : reply.deliveries)
                    route(identity.titleId, delivery);
            }
        }
        catch (const std::exception &error)
        {
            ++failures;
            io.log(std::string("LOBBY rejected stage=") + stage + ": " + error.what());
        }
    }
} // namespace lobby
