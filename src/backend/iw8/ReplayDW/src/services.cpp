#include "host_os.h"
#include "lobby.h"
#include "services.h"
#include "inventory_validation_services.h"
#include "protobuf.h"
#include "startup_services.h"
#include "rest_services.h"
#include "objectstore_services.h"
#include "account_services.h"
#include "leaderboard_services.h"
#include "engagement_services.h"
#include "qos_services.h"
#include "marketplace_services.h"
#include "achievement_services.h"
#include "matchmaking_services.h"
#include "matchmaking_store.h"
#include "tournament_services.h"
#include "channel_services.h"
#include "clan_services.h"
#include "mail_services.h"
#include "identity_services.h"
#include "social_services.h"
#include "scheduled_services.h"
#include "counter_services.h"
#include "team_services.h"
#include "content_services.h"
#include "anticheat_services.h"
#include "relay_services.h"
#include "tournament_map_policy.h"
#include "../third_party/nlohmann/json.hpp"
#include <chrono>
#include <fstream>
#include <mutex>
#include <optional>
#include <charconv>
#include <set>

namespace services
{
    namespace
    {
        using wire::Bytes;
        using Json = nlohmann::json;
        // Exact values from Replay's dwLobbyErrorCodeToString constant table.
        constexpr uint32_t denied = 101, invalid = 106, unavailable = 108, noFile = 1000,
                           storageFailure = 102;
        std::filesystem::path directory;
        std::mutex storeMutex;

        uint32_t now()
        {
            return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        std::string safe(const std::string &name, bool empty = false)
        {
            wire::require((empty || !name.empty()) && name.size() < 128 && name != "." &&
                          name != "..");
            for (auto c : name)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            return name.empty() ? "_default" : name;
        }

        std::optional<Bytes> read(const std::filesystem::path &path)
        {
            std::ifstream in(path, std::ios::binary | std::ios::ate);
            if (!in)
            {
                if (!std::filesystem::exists(path))
                    return std::nullopt;
                throw std::runtime_error("Cannot read persisted DW data");
            }
            const auto size = in.tellg();
            if (size < 0 || size > 300 * 1024)
                throw std::runtime_error("Persisted DW data size is invalid");
            Bytes bytes(static_cast<size_t>(size));
            in.seekg(0);
            if (size && !in.read(reinterpret_cast<char *>(bytes.data()), size))
                throw std::runtime_error("Persisted DW data read failed");
            return bytes;
        }

        void write(const std::filesystem::path &path, std::span<const uint8_t> bytes)
        {
            wire::require(bytes.size() <= 300 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto temp = path;
            temp += ".pending";
            {
                std::ofstream out(temp, std::ios::binary | std::ios::trunc);
                if (!out.write(reinterpret_cast<const char *>(bytes.data()),
                               static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("Persisting DW data failed");
            }
            if (!MoveFileExW(
                    temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Publishing DW data failed");
        }

        std::filesystem::path profilePath(const platform::LobbyIdentity &id,
                                          uint64_t owner,
                                          bool privateInfo)
        {
            return directory / "profiles" / std::to_string(id.titleId) / std::to_string(owner) /
                   (privateInfo ? "private.bin" : "public.bin");
        }

        Reply profiles(const platform::LobbyIdentity &id, uint8_t task, wire::Reader &p)
        {
            Reply reply{0, {}, "profiles"};
            const bool privateInfo = task == 2 || task == 4 || task == 6 || task == 7;
            if (task == 5)
            {
                p.end();
                std::filesystem::remove(profilePath(id, id.userId, false));
                std::filesystem::remove(profilePath(id, id.userId, true));
                return reply;
            }
            if (task == 3 || task == 4 || task == 6 || task == 8)
            {
                uint64_t owner = id.userId;
                if (task == 6 || task == 8)
                    owner = p.u64();
                auto blob = p.blob(4096);
                p.end();
                if (owner != id.userId)
                    return {denied, {}, "profile-owner-denied"};
                write(profilePath(id, owner, privateInfo), blob);
                reply.operation = "profile-save";
                return reply;
            }
            std::vector<uint64_t> owners;
            if (task == 1)
            {
                while (p.more())
                {
                    wire::require(owners.size() < 64);
                    owners.push_back(p.u64());
                }
            }
            else if (task == 2)
                owners.push_back(id.userId);
            else if (task == 7)
                owners.push_back(p.u64());
            else
                return {unavailable, {}, "profile-task-unimplemented"};
            p.end();
            for (auto owner : owners)
            {
                if (privateInfo && owner != id.userId)
                    return {denied, {}, "profile-owner-denied"};
                auto blob = read(profilePath(id, owner, privateInfo));
                if (!blob)
                    continue;
                wire::Writer result;
                result.u64(owner);
                result.blob(*blob);
                reply.results.push_back(std::move(result.data));
            }
            reply.operation = "profile-read";
            return reply;
        }

        struct ContextUser
        {
            uint64_t id;
            std::string account;
        };

        ContextUser owner(wire::Reader &p, const platform::LobbyIdentity &id)
        {
            // Native context users carry UInt64 + account-type string. NAN denotes the
            // implicit logged-in owner; do not allow the sentinel to escape into paths.
            auto user = p.u64();
            auto account = p.text(10);
            if (user == UINT64_MAX || user == 0)
                user = id.userId;
            // Replay's universal ID may be explicitly represented as uno or bnet.
            // The local provider binds both representations to this authenticated ID.
            wire::require(account.empty() || account == "bnet" || account == "uno");
            return {user, account.empty() ? "bnet" : account};
        }

        std::filesystem::path filePath(const platform::LobbyIdentity &id,
                                       const std::string &context,
                                       const std::string &name,
                                       uint64_t user,
                                       bool publisher = false)
        {
            return directory / (publisher ? "publisher" : "storage") / std::to_string(id.titleId) /
                   safe(context, true) / (publisher ? "shared" : std::to_string(user)) /
                   (safe(name) + ".dwfile");
        }

        struct StoredFile
        {
            uint32_t created = 0, modified = 0, version = 0;
            bool privateFile = true;
            Bytes bytes;
        };

        Bytes pack(const StoredFile &file)
        {
            wire::Writer w;
            w.u32(file.created);
            w.u32(file.modified);
            w.u32(file.version);
            w.boolean(file.privateFile);
            w.blob(file.bytes);
            w.data.push_back(0);
            return w.data;
        }

        StoredFile unpack(const Bytes &bytes)
        {
            wire::Reader r{bytes};
            StoredFile file;
            file.created = r.u32();
            file.modified = r.u32();
            file.version = r.u32();
            file.privateFile = r.boolean();
            file.bytes = r.blob();
            r.end();
            return file;
        }

        Bytes fileInfo(const StoredFile &file, const ContextUser &user, const std::string &name)
        {
            wire::Writer w;
            w.u32(static_cast<uint32_t>(file.bytes.size()));
            w.u32(file.created);
            w.u32(file.modified);
            w.boolean(file.privateFile);
            w.u64(user.id);
            w.text(user.account);
            w.text(name);
            return w.data;
        }

        Reply storage(const platform::LobbyIdentity &id, uint8_t task, wire::Reader &p)
        {
            const auto context = p.text(16);
            safe(context, true);
            const auto name = p.text(128);
            safe(name);
            if (task == 21)
            {
                p.end();
                auto bytes = read(filePath(id, context, name, 0, true));
                if (!bytes)
                    return {noFile, {}, "publisher-file-missing"};
                wire::Writer w;
                w.blob(unpack(*bytes).bytes);
                return {0, {std::move(w.data)}, "publisher-file-read"};
            }
            if (task == 10)
            {
                StoredFile file;
                file.privateFile = p.boolean();
                file.bytes = p.blob();
                const auto user = owner(p, id);
                if (p.more())
                    file.version = p.u32();
                p.end();
                if (user.id != id.userId)
                    return {denied, {}, "storage-owner-denied"};
                const auto path = filePath(id, context, name, user.id);
                file.created = file.modified = now();
                if (auto existing = read(path))
                    file.created = unpack(*existing).created;
                write(path, pack(file));
                return {0, {fileInfo(file, user, name)}, "storage-upload"};
            }
            if (task == 11 || task == 12 || task == 17)
            {
                const auto user = owner(p, id);
                p.end();
                const auto path = filePath(id, context, name, user.id);
                const auto bytes = read(path);
                if (!bytes)
                    return {noFile, {}, "storage-file-missing"};
                const auto file = unpack(*bytes);
                if (user.id != id.userId && (task != 12 || file.privateFile))
                    return {denied, {}, "storage-owner-denied"};
                if (task == 11)
                {
                    std::filesystem::remove(path);
                    return {0, {}, "storage-remove"};
                }
                if (task == 17)
                {
                    auto backup = path;
                    backup += ".backup";
                    write(backup, *bytes);
                    return {0, {}, "storage-backup"};
                }
                wire::Writer w;
                w.blob(file.bytes);
                return {0, {std::move(w.data)}, "storage-download"};
            }
            return {unavailable, {}, "storage-task-unimplemented"};
        }

        Reply extendedAuth(const platform::LobbyIdentity &id, uint8_t task, wire::Reader &p)
        {
            if (task == 7)
            {
                const auto token = p.text(2048);
                p.end();
                if (!platform::sessionTokenMatches(id, token))
                    return {denied, {}, "reported-session-token-invalid"};
                // This task is the local session-token report, recorded as receipt only.
                // The real paired tokens were authenticated before this lobby session.
            }
            else if (task == 6 || task == 8)
            {
                const auto mode = p.u32(), version = p.u32();
                const auto checksum = p.u64(), internal = p.u64(), external = p.u64();
                const auto mac = p.blob(6);
                wire::require(mac.size() == 6);
                const auto info = p.text(4096);
                wire::require(!info.empty());
                if (task == 8)
                    (void)p.value<int32_t>(7);
                p.end();
                Json receipt = {{"title", id.titleId},
                                {"game_mode", mode},
                                {"game_version", version},
                                {"checksum", checksum},
                                {"recorded", now()}};
                (void)internal;
                (void)external;
                const auto data = receipt.dump();
                write(directory / "auth-reports" / (std::to_string(id.userId) + ".json"),
                      std::span(reinterpret_cast<const uint8_t *>(data.data()), data.size()));
            }
            else
                return {unavailable, {}, "auth-report-task-unimplemented"};
            return {0, {}, "extended-auth-report-recorded"};
        }

        uint16_t publisherVersion(const Json &json, const char *key, uint16_t fallback);

        Json publisherDocument(const platform::LobbyIdentity &id,
                               const std::string &context,
                               const std::string &name)
        {
            const auto path = directory / "publisher-variables" / std::to_string(id.titleId) /
                              safe(context, true) / (name + ".json");
            const bool replayNamespace =
                id.titleId == 5800 && (context == "iw8" || context.empty()) &&
                (name == "general" || name == "pc" || name == "f2p" || name == "general_8_19" ||
                 name == "pc_8_19" || name == "f2p_8_19" || name == "autobuild");
            auto content = read(path);
            // Replay's signed native auth reports establish title 5800 / game version
            // 967. Namespace initialization at 0x14107B7D0 also requests the build
            // name returned by CompassBuildName (0x140E51A10): "autobuild" in this
            // target's version.txt. A local publication has no remote tuning overrides.
            // Other builds/namespaces require an explicit document, never guessed data.
            // DWLobbyService::getPublisherVariables in this Replay passes the empty
            // context string. Keep its default store separate from named contexts.
            if (!content && replayNamespace)
            {
                const auto defaults = Json{{"MajorVersion", "1"}, {"MinorVersion", "0"}}.dump();
                write(
                    path,
                    std::span(reinterpret_cast<const uint8_t *>(defaults.data()), defaults.size()));
                content = read(path);
            }
            if (!content)
                return nullptr;
            auto json = Json::parse(content->begin(), content->end());
            if (id.titleId == 5800 && (context.empty() || context == "iw8") && name == "general")
                if (const auto policy = tournamentMapPolicy(directory, id.titleId))
                {
                    // One publication drives both native dvar strings and the
                    // server selector. Never store a second independent map list.
                    const auto revision = policy->at("revision").get<uint16_t>();
                    if (revision < publisherVersion(json, "MinorVersion", 0))
                        throw std::runtime_error(
                            "Tournament map policy revision is older than publisher variables");
                    json["MinorVersion"] = std::to_string(revision);
                    const auto variables = tournamentMapDvars(directory, id.titleId, *policy);
                    for (const auto &variable : variables.items())
                        json[variable.key()] = variable.value();
                }
            wire::require(json.is_object() && json.dump().size() < 65536);
            for (auto it = json.begin(); it != json.end(); ++it)
            {
                wire::require(!it.key().empty() && it.key().size() < 64 &&
                              it.key().find('\0') == std::string::npos && it.value().is_string());
                const auto value = it.value().get<std::string>();
                // Original Replay 14107BB50 supplies 64/128-byte name/value
                // buffers to the iterator. Reject a native tuning publication
                // that would silently truncate a value before dvar assignment.
                const size_t valueCapacity = replayNamespace ? 128 : 1024;
                wire::require(value.size() < valueCapacity &&
                              value.find('\0') == std::string::npos);
            }
            return json;
        }

        uint16_t publisherVersion(const Json &json, const char *key, uint16_t fallback)
        {
            if (!json.contains(key))
                return fallback;
            const auto text = json.at(key).get<std::string>();
            wire::require(!text.empty());
            uint32_t value = 0;
            for (const char c : text)
            {
                wire::require(c >= '0' && c <= '9');
                value = value * 10 + static_cast<unsigned>(c - '0');
                wire::require(value <= UINT16_MAX);
            }
            return static_cast<uint16_t>(value);
        }

        Reply missingPublisher(const std::string &context, const std::string &name)
        {
            Reply reply{unavailable, {}, "publisher-namespace-not-configured"};
            reply.detail = " context=" + safe(context, true) + " namespace=" + safe(name);
            return reply;
        }

        Reply variables(const platform::LobbyIdentity &id, uint8_t task, wire::Reader &p)
        {
            if (task == 3)
            {
                wire::require(p.offset < p.data.size() && p.data[p.offset++] == 23);
                const auto size = p.u32();
                wire::require(size <= p.data.size() - p.offset);
                proto::Reader request{p.data.subspan(p.offset, size)};
                p.offset += size;
                p.end();
                std::string context;
                std::vector<std::string> names;
                proto::Field field;
                while (request.next(field))
                {
                    if (field.tag == 1 || field.tag == 2)
                    {
                        wire::require(field.type == 2 &&
                                      field.bytes.size() < (field.tag == 1 ? 16u : 32u));
                        std::string value(reinterpret_cast<const char *>(field.bytes.data()),
                                          field.bytes.size());
                        safe(value, field.tag == 1);
                        if (field.tag == 1)
                            context = value;
                        else
                        {
                            wire::require(names.size() < 64);
                            names.push_back(value);
                        }
                    }
                }
                wire::require(!names.empty());
                Reply reply{0, {}, "publisher-variables-bulk-read", true, {}};
                for (const auto &name : names)
                {
                    const auto json = publisherDocument(id, context, name);
                    if (json.is_null())
                        return missingPublisher(context, name);
                    Bytes object;
                    proto::integer(object, 1, publisherVersion(json, "MajorVersion", 1));
                    proto::integer(object, 2, publisherVersion(json, "MinorVersion", 0));
                    proto::text(object, 3, name);
                    proto::text(object, 4, json.dump());
                    proto::bytes(reply.structure, 1, object);
                }
                return reply;
            }
            if (task != 1)
                return {unavailable, {}, "publisher-variables-task-unimplemented"};
            const auto context = p.text(16), name = p.text(32);
            p.end();
            safe(context, true);
            safe(name);
            const auto json = publisherDocument(id, context, name);
            if (json.is_null())
                return missingPublisher(context, name);
            wire::Writer w;
            w.u16(publisherVersion(json, "MajorVersion", 1));
            w.u16(publisherVersion(json, "MinorVersion", 0));
            w.text(name);
            w.text(json.dump());
            return {0, {std::move(w.data)}, "publisher-variables-read"};
        }
    } // namespace

    void initialize(const std::filesystem::path &data)
    {
        directory = std::filesystem::absolute(data);
        std::filesystem::create_directories(directory / "profiles");
        std::filesystem::create_directories(directory / "storage");
        matchmaking_store::initialize(directory);
        initializeStartup(directory);
        initializeChannels(directory);
        relay::initialize(directory);
    }

    nlohmann::json publicActivity()
    {
        const auto players = lobby::onlinePlayerList();
        std::lock_guard lock(storeMutex);
        return matchmakingPublicActivity(directory, players);
    }

    OperatorMatchStart operatorStartMatch(const std::string &credential,
                                         const std::string &matchToken,
                                         bool fillBots,
                                         unsigned botCount)
    {
        // An independent operator secret never shares client identity credentials.
        const auto path = directory / "operator-access.key";
        if (!std::filesystem::is_regular_file(path) || std::filesystem::file_size(path) > 66)
            return {503, "Operator controls are not configured."};
        std::ifstream input(path, std::ios::binary);
        std::string expected;
        std::getline(input, expected);
        if (!expected.empty() && expected.back() == '\r')
            expected.pop_back();
        if (expected.size() != 64 || expected.find_first_not_of("0123456789abcdef") != std::string::npos)
            return {503, "Operator controls are not configured."};
        unsigned difference = credential.size() == expected.size() ? 0U : 1U;
        for (size_t i = 0; i < expected.size(); ++i)
            difference |= static_cast<unsigned char>(expected[i]) ^
                          (i < credential.size() ? static_cast<unsigned char>(credential[i]) : 0U);
        if (difference)
            return {403, "Operator key rejected."};
        if (matchToken.size() != 64 || matchToken.find_first_not_of("0123456789abcdef") != std::string::npos)
            return {400, "Invalid match selection."};
        if ((fillBots && (!botCount || botCount > 199)) || (!fillBots && botCount))
            return {400, "Bot count must be a whole number from 1 to 199."};
        const auto players = lobby::onlinePlayerList();
        std::lock_guard lock(storeMutex);
        return matchmakingStartWaitingMatch(directory, players, matchToken, fillBots, botCount);
    }

    void restoreLocalProgression(
        uint32_t title, uint64_t user, uint64_t xp, bool restore, unsigned startingRank,
        uint32_t platformAccount)
    {
        std::lock_guard lock(storeMutex);
        restoreAchievementProgression(directory, title, user, xp, restore, startingRank, platformAccount);
    }

    std::vector<Delivery> disconnected(uint32_t title, uint64_t user)
    {
        std::lock_guard lock(storeMutex);
        std::vector<Delivery> deliveries;
        try
        {
            deliveries = socialDisconnected(directory, title, user);
        }
        catch (const std::exception &)
        {
            // Corrupt social storage cannot suppress an independent channel leave.
        }
        try
        {
            const auto updates = disconnectChannels(directory, title, user);
            deliveries.insert(deliveries.end(), updates.begin(), updates.end());
        }
        catch (const std::exception &)
        {
            // Channel source errors remain task-level storage errors. They must
            // not discard already prepared native offline presence notifications.
        }
        return deliveries;
    }

    void maintainTournamentPublications(const std::function<void(const std::string &)> &log)
    {
        std::lock_guard lock(storeMutex);
        std::set<uint32_t> titles;
        // Formations survive independently of enrollment/catalog files. Discover
        // both owners so loss of the tournament realm cannot strand assignments.
        for (const auto &root : {directory / "tournaments", directory / "matchmaking"})
            try
            {
                if (!std::filesystem::exists(root))
                    continue;
                wire::require(std::filesystem::is_directory(root) &&
                              !std::filesystem::is_symlink(root));
                unsigned count = 0;
                for (const auto &entry : std::filesystem::directory_iterator(root))
                {
                    wire::require(++count <= 1024);
                    const auto name = entry.path().filename().string();
                    uint32_t title = 0;
                    const auto parsed =
                        std::from_chars(name.data(), name.data() + name.size(), title);
                    if (!entry.is_directory() || entry.is_symlink() || parsed.ec != std::errc{} ||
                        parsed.ptr != name.data() + name.size() || !title ||
                        std::to_string(title) != name)
                    {
                        log("TOURNAMENT maintenance rejected invalid realm path");
                        continue;
                    }
                    wire::require(titles.contains(title) || titles.size() < 1024);
                    titles.insert(title);
                }
            }
            catch (const std::exception &)
            {
                log("TOURNAMENT maintenance realm discovery storage failure");
            }
        for (const auto title : titles)
        {
            try
            {
                retireUnavailableManagedTournaments(directory, title, log);
            }
            catch (const std::exception &)
            {
                log("TOURNAMENT maintenance realm storage failure; title=" + std::to_string(title));
            }
        }
    }

    std::optional<Delivery> tournamentUpdate(uint32_t title, uint64_t user)
    {
        std::lock_guard lock(storeMutex);
        return currentTournamentDelivery(directory, title, user);
    }

    std::vector<Delivery> mailUpdates(uint32_t title, uint64_t user)
    {
        std::lock_guard lock(storeMutex);
        return currentMailDeliveries(directory, title, user);
    }

    std::vector<Delivery> progressionUpdates(uint32_t title, uint64_t user)
    {
        std::lock_guard lock(storeMutex);
        return currentProgressionDeliveries(directory, title, user);
    }

    std::optional<Delivery> tournamentLobbyUpdate(uint32_t title, uint64_t user)
    {
        std::lock_guard lock(storeMutex);
        return currentTournamentRoundDelivery(directory, title, user);
    }

    bool deliveryValid(uint32_t title, const Delivery &delivery)
    {
        std::lock_guard lock(storeMutex);
        try
        {
            return achievementDeliveryValid(directory, title, delivery) &&
                   channelDeliveryValid(directory, title, delivery) &&
                   socialDeliveryValid(title, delivery) &&
                   mailDeliveryValid(directory, title, delivery) &&
                   clanDeliveryValid(directory, title, delivery) &&
                   tournamentDeliveryValid(directory, title, delivery) &&
                   (!delivery.lobbyId || matchmakingDeliveryValid(directory, title, delivery));
        }
        catch (...)
        {
            return false;
        }
    }

    Reply dispatch(const platform::LobbyIdentity &authenticatedIdentity,
                   uint8_t service,
                   uint8_t task,
                   wire::Reader &p,
                   bool hostAuthenticated)
    {
        auto id = authenticatedIdentity;
        // Standalone ReplayDW owns and refreshes its lobby lease.  When the
        // same service layer is hosted behind CodRevamped, CodRevamped has
        // already authenticated the native BGS/Auth3/LSG connection, so no
        // ReplayDW-issued lease exists and the host transport is authoritative.
        if (!hostAuthenticated && !platform::refreshLease(id))
            return Reply{101, {}, "service-session-expired-or-superseded"};
        std::lock_guard lock(storeMutex);
        try
        {
            if (auto reply = channelServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = clanServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = mailServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = scheduledServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = counterServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = teamServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = contentServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = anticheatServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = startup(id, service, task, p))
                return *reply;
            if (auto reply = accountServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = leaderboardServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = engagementServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = qosServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = relayServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = inventoryValidationServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = marketplaceServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = achievementServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = tournamentServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = matchmakingServices(directory, id, service, task, p))
                return *reply;
            if (auto reply = identity(id, service, task, p))
                return *reply;
            if (service == 255 && task == 10)
                return rest(directory, id, p);
            if (service == 193)
                return objectStore(directory, id, task, p);
            if (service == 12 && (task == 6 || task == 12))
            {
                p.end();
                wire::Writer w;
                if (task == 6)
                    w.u32(now());
                else
                    w.u64(static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count()));
                return {0, {std::move(w.data)}, "server-time"};
            }
            if (service == 8)
                return profiles(id, task, p);
            if (service == 10)
                return storage(id, task, p);
            if (service == 38)
                return extendedAuth(id, task, p);
            if (service == 95)
                return variables(id, task, p);
            return {unavailable, {}, "service-unimplemented"};
        }
        catch (const nlohmann::json::exception &)
        {
            return {storageFailure, {}, "persistent-json-invalid"};
        }
        catch (const std::filesystem::filesystem_error &)
        {
            return {storageFailure, {}, "persistent-filesystem-error"};
        }
        catch (const std::runtime_error &e)
        {
            if (std::string(e.what()) == "Malformed native task parameters")
                return {invalid, {}, "task-parameters-invalid"};
            return {storageFailure, {}, "persistent-data-error"};
        }
    }

    Bytes taskReply(uint64_t transaction, uint8_t task, const Reply &reply)
    {
        wire::Writer w;
        w.u64(transaction);
        w.u32(reply.error);
        if (!reply.error)
        {
            w.u8(task);
            if (reply.rest)
            {
                w.u32(1);
                w.u32(1);
                const auto result = restResult(transaction, *reply.rest);
                w.data.insert(w.data.end(), result.begin(), result.end());
                return w.data;
            }
            if (reply.structured)
            {
                w.data.push_back(23);
                w.u32(static_cast<uint32_t>(reply.structure.size()));
                w.data.insert(w.data.end(), reply.structure.begin(), reply.structure.end());
                return w.data;
            }
            w.u32(static_cast<uint32_t>(reply.results.size()));
            if (!reply.results.empty())
                w.u32(static_cast<uint32_t>(reply.results.size()));
            for (const auto &result : reply.results)
                w.data.insert(w.data.end(), result.begin(), result.end());
        }
        return w.data;
    }
} // namespace services
