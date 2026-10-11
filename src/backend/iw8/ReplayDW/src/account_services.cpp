#include "host_os.h"
#include "account_services.h"
#include "battlepass_services.h"
#include "leaderboard_row.h"
#include "protobuf.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>
#include <limits>
#include <algorithm>
#include <chrono>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        std::string component(std::span<const uint8_t> bytes, size_t capacity)
        {
            wire::require(!bytes.empty() && bytes.size() < capacity);
            std::string value(reinterpret_cast<const char *>(bytes.data()), bytes.size());
            wire::require(value != "." && value != "..");
            for (unsigned char c : value)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            return value;
        }

        Json document(const std::filesystem::path &path, size_t limit)
        {
            if (!std::filesystem::exists(path))
                return Json::object();
            wire::require(std::filesystem::file_size(path) <= limit);
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Account document read failed");
            auto value = Json::parse(stream);
            wire::require(value.is_object());
            return value;
        }

        void publish(const std::filesystem::path &path, const Json &value, size_t limit)
        {
            const auto bytes = value.dump();
            wire::require(bytes.size() <= limit);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream stream(pending, std::ios::binary | std::ios::trunc);
                if (!stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !stream.flush())
                    throw std::runtime_error("Account document persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Account document publication failed");
        }

        Json validatedDocument(const std::filesystem::path &path, size_t limit)
        {
            try
            {
                return document(path, limit);
            }
            catch (const std::runtime_error &)
            {
                // Persisted bounds/schema errors are storage failures, distinct
                // from a malformed incoming token or typed client stat request.
                throw std::runtime_error("Validated stats document invalid");
            }
        }

        Reply userState(const std::filesystem::path &directory,
                        const platform::LobbyIdentity &id,
                        wire::Reader &p)
        {
            // bdGetUserStateRequest: field 1 context. bdGetUserStateResponse: field 1
            // a JSON string (capacity 4097). Identity comes from the lobby session.
            proto::Reader reader{p.structure(1024)};
            proto::Field f;
            std::string context;
            while (reader.next(f))
                if (f.tag == 1)
                {
                    wire::require(f.type == 2 && context.empty());
                    context = component(f.bytes, 21);
                }
            wire::require(!context.empty());
            const auto path = directory / "achievement-user-state" / std::to_string(id.titleId) /
                              context / (std::to_string(id.userId) + ".json");
            auto state = document(path, 4096);
            projectBattlepassUserState(directory, id, context, state);
            const auto json = state.dump();
            wire::require(json.size() <= 4096);
            // A new local account has no claimed battlepasses, tutorial rewards or XP
            // boosts. Missing optional keys leave the native progression defaults intact.
            if (!std::filesystem::exists(path))
                publish(path, state, 4096);
            Reply reply{0, {}, "achievement-user-state-read", true, {}};
            proto::text(reply.structure, 1, json);
            return reply;
        }

        struct StatRow
        {
            uint32_t board = 0;
            uint64_t owner = 0;
            uint8_t mode = 0;
            std::optional<int64_t> rating;
            std::vector<std::optional<int32_t>> columns;
        };

        template <class T> std::optional<T> statValue(wire::Reader &p, uint8_t tag)
        {
            if (p.offset < p.data.size() && p.data[p.offset] == 20)
            {
                ++p.offset;
                return std::nullopt;
            }
            return p.value<T>(tag);
        }

        int64_t merge(int64_t old, int64_t value, uint8_t mode, int64_t minimum, int64_t maximum)
        {
            if (mode == 2)
                return std::max(old, value);
            if (mode == 0)
                return value;
            wire::require((value >= 0 && old <= maximum - value) ||
                          (value < 0 && old >= minimum - value));
            return old + value;
        }

        std::vector<StatRow> parseStats(wire::Reader &p)
        {
            // Same-Replay bdStatsInfo base, then LeaderBoardRow<10>'s typed Int32
            // columns. The next UInt32 starts a row; NAN (20) preserves a column.
            // Replay LiveTracker_Process maps replace/add/max to 0/1/2 respectively.
            std::vector<StatRow> rows;
            while (p.more())
            {
                wire::require(rows.size() < 200);
                StatRow row;
                row.board = p.u32();
                row.owner = p.u64();
                row.mode = p.u8();
                wire::require(row.board != UINT32_MAX && row.mode <= 2);
                row.rating = statValue<int64_t>(p, 9);
                while (p.offset < p.data.size() &&
                       (p.data[p.offset] == 7 || p.data[p.offset] == 20))
                {
                    wire::require(row.columns.size() < leaderboard_row::maximumResponseColumns);
                    row.columns.push_back(statValue<int32_t>(p, 7));
                }
                rows.push_back(std::move(row));
            }
            p.end();
            wire::require(!rows.empty());
            return rows;
        }

        bool digestText(const std::string &value)
        {
            return value.size() == 64 && std::all_of(value.begin(),
                                                     value.end(),
                                                     [](char c)
                                                     {
                                                         return (c >= '0' && c <= '9') ||
                                                                (c >= 'a' && c <= 'f');
                                                     });
        }

        std::string digest(std::span<const uint8_t> bytes)
        {
            std::string result;
            for (const auto byte : crypto::sha256(bytes))
            {
                result += "0123456789abcdef"[byte >> 4];
                result += "0123456789abcdef"[byte & 15];
            }
            return result;
        }

        Reply applyStats(const std::filesystem::path &directory,
                         const platform::LobbyIdentity &id,
                         const std::vector<StatRow> &rows,
                         const std::string &tokenHash = {},
                         const std::string &authorizationHash = {})
        {
            for (const auto &row : rows)
                if (row.owner != id.userId)
                    return {101, {}, "stats-owner-denied"};
            const auto path = directory / "leaderboard-stats" / std::to_string(id.titleId) /
                              (std::to_string(id.userId) + ".json");
            auto data = tokenHash.empty() ? document(path, 256 * 1024)
                                          : validatedDocument(path, 256 * 1024);
            if (data.contains("_validated_tokens"))
            {
                const auto &receipts = data["_validated_tokens"];
                try
                {
                    wire::require(receipts.is_object() && receipts.size() <= 1024);
                    for (const auto &entry : receipts.items())
                        wire::require(
                            digestText(entry.key()) && entry.value().is_object() &&
                            digestText(
                                entry.value().at("authorization_sha256").get<std::string>()) &&
                            entry.value().at("accepted").is_number_unsigned());
                }
                catch (const std::runtime_error &)
                {
                    throw std::runtime_error("Validated stats receipt schema invalid");
                }
            }
            if (!tokenHash.empty())
            {
                auto &receipts = data["_validated_tokens"];
                if (receipts.is_null())
                    receipts = Json::object();
                if (receipts.contains(tokenHash))
                    return receipts[tokenHash]["authorization_sha256"] == authorizationHash
                               ? Reply{0, {}, "validated-stats-retry"}
                               : Reply{108, {}, "validated-stats-authorization-conflict"};
                if (receipts.size() >= 1024)
                    return {108, {}, "validated-stats-receipt-capacity"};
            }
            for (const auto &row : rows)
            {
                const auto key = std::to_string(row.board);
                auto &target = data[key];
                if (target.is_null())
                    target = Json{{"rating", nullptr}, {"columns", Json::array()}};
                leaderboard_row::validate(target);
                auto &rating = target["rating"];
                if (row.rating)
                    rating = rating.is_null() ? *row.rating
                                              : merge(rating.get<int64_t>(),
                                                      *row.rating,
                                                      row.mode,
                                                      std::numeric_limits<int64_t>::min(),
                                                      std::numeric_limits<int64_t>::max());
                auto &columns = target["columns"];
                while (columns.size() < row.columns.size())
                    columns.push_back(nullptr);
                for (size_t i = 0; i < row.columns.size(); ++i)
                    if (row.columns[i])
                    {
                        columns[i] = columns[i].is_null() ? *row.columns[i]
                                                          : merge(columns[i].get<int32_t>(),
                                                                  *row.columns[i],
                                                                  row.mode,
                                                                  INT32_MIN,
                                                                  INT32_MAX);
                    }
                target["name"] = id.name;
                target["updated"] =
                    static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
                leaderboard_row::validate(target);
            }
            if (!tokenHash.empty())
                data["_validated_tokens"][tokenHash] = {
                    {"authorization_sha256", authorizationHash},
                    {"accepted",
                     static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count())}};
            // Validate/merge the entire batch before one atomic publication. A denied,
            // malformed or overflowing later row never commits earlier rows.
            publish(path, data, 256 * 1024);
            return {0,
                    {},
                    tokenHash.empty() ? "leaderboard-stats-written"
                                      : "server-validated-stats-written"};
        }

        Reply validatedStats(const std::filesystem::path &directory,
                             const platform::LobbyIdentity &id,
                             wire::Reader &p)
        {
            // Exact Replay 0x1421286F0: one typed blob, SDK capacity 10240,
            // no result binding. Its opaque token is never treated as client stats.
            const auto token = p.blob(10240);
            p.end();
            wire::require(!token.empty());
            const auto tokenHash = digest(token);
            const auto path =
                directory / "validated-stats" / std::to_string(id.titleId) / "catalog.json";
            if (!std::filesystem::exists(path))
                return {108, {}, "validated-stats-authorization-unavailable"};
            const auto catalog = validatedDocument(path, 4 * 1024 * 1024);
            const auto time =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
            const Json *selected = nullptr;
            std::vector<StatRow> authorized;
            try
            {
                wire::require(catalog.at("schema") == 1 && catalog.at("title") == id.titleId &&
                              catalog.at("authorizations").is_array() &&
                              catalog["authorizations"].size() <= 4096);
                std::set<std::string> hashes;
                for (const auto &entry : catalog["authorizations"])
                {
                    const auto hash = entry.at("token_sha256").get<std::string>();
                    wire::require(
                        digestText(hash) && hashes.insert(hash).second &&
                        entry.at("owner").is_number_unsigned() &&
                        entry["owner"].get<uint64_t>() != 0 &&
                        entry["owner"].get<uint64_t>() != UINT64_MAX &&
                        entry.at("enabled").is_boolean() &&
                        entry.at("starts").is_number_unsigned() &&
                        entry.at("expires").is_number_unsigned() &&
                        (!entry["expires"].get<uint64_t>() || entry["expires"] > entry["starts"]));
                    const auto bytes = wire::base64(
                        entry.at("stat_request_base64").get<std::string>(), 256 * 1024);
                    wire::Reader request{bytes};
                    auto rows = parseStats(request);
                    for (const auto &row : rows)
                        wire::require(row.owner == entry["owner"].get<uint64_t>());
                    if (hash == tokenHash)
                    {
                        selected = &entry;
                        authorized = std::move(rows);
                    }
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Validated stats authorization schema invalid");
            }
            if (!selected)
                return {108, {}, "validated-stats-token-unavailable"};
            if ((*selected)["owner"] != id.userId)
                return {101, {}, "validated-stats-token-owner-denied"};
            if ((*selected)["enabled"] != true || (*selected)["starts"].get<uint64_t>() > time ||
                ((*selected)["expires"].get<uint64_t>() &&
                 (*selected)["expires"].get<uint64_t>() <= time))
                return {108, {}, "validated-stats-token-inactive"};
            const auto authorization = selected->dump();
            const auto authorizationHash = digest(std::span(
                reinterpret_cast<const uint8_t *>(authorization.data()), authorization.size()));
            return applyStats(directory, id, authorized, tokenHash, authorizationHash);
        }
    } // namespace

    std::optional<Reply> accountServices(const std::filesystem::path &directory,
                                         const platform::LobbyIdentity &id,
                                         uint8_t service,
                                         uint8_t task,
                                         wire::Reader &p)
    {
        if (service == 125 && task == 9)
            return userState(directory, id, p);
        if (service == 4 && task == 1)
            return applyStats(directory, id, parseStats(p));
        if (service == 4 && task == 14)
            return validatedStats(directory, id, p);
        return std::nullopt;
    }
} // namespace services
