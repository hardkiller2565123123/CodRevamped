#include "leaderboard_services.h"
#include "leaderboard_row.h"
#include "achievement_services.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>
#include <charconv>
#include <numeric>
#include <bit>
#include <map>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        using leaderboard_row::maximumStoredColumns;
        using leaderboard_row::maximumResponseColumns;

        struct Definition
        {
            uint32_t storageBoard = 0;
            std::vector<std::string> columns;
            std::optional<size_t> xpColumn;
            std::string progressionContext;
        };

        struct Row
        {
            uint64_t user = 0, rank = 0, updated = 0;
            int64_t rating = 0;
            std::string name;
            std::vector<int32_t> columns;
        };

        Json document(const std::filesystem::path &path)
        {
            wire::require(std::filesystem::file_size(path) <= 256 * 1024);
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Leaderboard read failed");
            auto result = Json::parse(stream);
            wire::require(result.is_object());
            return result;
        }

        std::optional<Definition> definition(const std::filesystem::path &directory,
                                               uint32_t title,
                                               uint32_t board)
        {
            const auto path = directory / "leaderboard-definitions" / std::to_string(title) /
                              (std::to_string(board) + ".json");
            if (!std::filesystem::exists(path))
                return std::nullopt;
            const auto data = document(path);
            if (data.contains("schema"))
                wire::require(data["schema"] == 1 || data["schema"] == 2);
            wire::require(data.contains("columns") && data["columns"].is_array() &&
                          !data["columns"].empty() &&
                          data["columns"].size() <= maximumStoredColumns);
            Definition result;
            result.storageBoard = board;
            if (data.contains("storage_board"))
            {
                wire::require(data.contains("schema") && data["schema"] == 2 &&
                              data["storage_board"].is_number_unsigned() &&
                              data["storage_board"].get<uint64_t>() < UINT32_MAX);
                result.storageBoard = data["storage_board"].get<uint32_t>();
            }
            std::set<std::string> names;
            for (const auto &column : data["columns"])
            {
                wire::require(column.is_string());
                const auto name = column.get<std::string>();
                wire::require(!name.empty() && name.size() < 65 &&
                              name.find('\0') == std::string::npos && names.insert(name).second);
                result.columns.push_back(name);
            }
            if (data.contains("progression"))
            {
                const auto &progression = data["progression"];
                wire::require(data.contains("schema") && data["schema"] == 2 &&
                              progression.is_object() && progression.size() == 3 &&
                              progression.at("type") == "player_xp" &&
                              progression.at("context").is_string() &&
                              progression.at("xp_column").is_number_unsigned());
                result.progressionContext = progression["context"].get<std::string>();
                wire::require(result.progressionContext == std::to_string(title) ||
                              result.progressionContext == "iw8");
                const auto index = progression["xp_column"].get<uint64_t>();
                wire::require(index < result.columns.size());
                result.xpColumn = static_cast<size_t>(index);
            }
            return result;
        }

        std::vector<Row> rows(const std::filesystem::path &directory,
                              const platform::LobbyIdentity &id,
                              uint32_t board,
                              const std::optional<Definition> &definition)
        {
            std::vector<Row> result;
            const auto root = directory / "leaderboard-stats" / std::to_string(id.titleId);
            size_t files = 0;
            if (std::filesystem::exists(root))
            {
                for (const auto &entry : std::filesystem::directory_iterator(root))
                {
                    if (!entry.is_regular_file() || entry.path().extension() != L".json")
                        continue;
                    wire::require(++files <= 10000);
                    const auto owner = entry.path().stem().string();
                    uint64_t user = 0;
                    const auto parsed =
                        std::from_chars(owner.data(), owner.data() + owner.size(), user);
                    wire::require(parsed.ec == std::errc{} &&
                                  parsed.ptr == owner.data() + owner.size() && user != 0);
                    const auto data = document(entry.path());
                    const auto key = std::to_string(board);
                    if (!data.contains(key))
                        continue;
                    const auto &value = data.at(key);
                    leaderboard_row::validate(value);
                    Row row;
                    row.user = user;
                    if (!value["rating"].is_null())
                        row.rating = value["rating"].get<int64_t>();
                    row.updated = value.value("updated", uint64_t{});
                    row.name = value.value("name", user == id.userId ? id.name : std::string{});
                    wire::require(row.name.size() < 64);
                    for (const auto &column : value["columns"])
                    {
                        if (column.is_null())
                            row.columns.push_back(0);
                        else
                            row.columns.push_back(column.get<int32_t>());
                    }
                    if (row.columns.size() < maximumResponseColumns)
                        row.columns.resize(maximumResponseColumns, 0);
                    result.push_back(std::move(row));
                }
            }
            if (definition && definition->xpColumn)
            {
                std::map<uint64_t, size_t> owners;
                for (size_t i = 0; i < result.size(); ++i)
                    owners.emplace(result[i].user, i);
                for (const auto &progression : achievementProgressionSnapshot(
                         directory, id.titleId, definition->progressionContext))
                {
                    // Native LB_VR_GetXUserColExt interprets physical columns as
                    // UInt32. The transport stores Int32 bits; preserve the entire
                    // native unsigned range rather than narrowing or clamping XP.
                    wire::require(progression.xp <= UINT32_MAX);
                    if (!owners.contains(progression.user))
                    {
                        owners[progression.user] = result.size();
                        Row row;
                        row.user = progression.user;
                        row.columns.resize(maximumResponseColumns, 0);
                        result.push_back(std::move(row));
                    }
                    auto &row = result[owners.at(progression.user)];
                    row.rating = static_cast<int64_t>(progression.xp);
                    row.name = progression.name;
                    if (row.columns.size() <= *definition->xpColumn)
                        row.columns.resize(*definition->xpColumn + 1, 0);
                    row.columns[*definition->xpColumn] =
                        std::bit_cast<int32_t>(static_cast<uint32_t>(progression.xp));
                }
            }
            std::sort(result.begin(),
                      result.end(),
                      [](const Row &a, const Row &b)
                      {
                          return a.rating != b.rating ? a.rating > b.rating : a.user < b.user;
                      });
            for (size_t i = 0; i < result.size(); ++i)
                result[i].rank = i + 1;
            return result;
        }

        wire::Bytes serialize(const Row &row, const std::vector<size_t> &selected)
        {
            // Native bdStatsInfo reader 0x14214AEE0, followed by the selected typed
            // Int32 columns in LeaderBoardRow<10>::deserialize 0x14150E900.
            wire::Writer out;
            out.u64(row.user);
            out.data.push_back(9);
            wire::raw(out.data, row.rating);
            out.u64(row.rank);
            out.text(row.name);
            const auto time =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
            out.u32(row.updated && row.updated <= time
                        ? static_cast<uint32_t>(std::min(time - row.updated, uint64_t{UINT32_MAX}))
                        : 0);
            wire::require(selected.size() <= maximumResponseColumns);
            for (const auto index : selected)
            {
                wire::require(index < maximumStoredColumns);
                out.data.push_back(7);
                // An absent, unrecorded column has the same zero default as an
                // absent trailing field in existing ten-column publications.
                wire::raw(out.data, index < row.columns.size() ? row.columns[index] : int32_t{0});
            }
            return std::move(out.data);
        }

        std::vector<size_t> ordinaryColumns()
        {
            std::vector<size_t> result(maximumResponseColumns);
            std::iota(result.begin(), result.end(), size_t{0});
            return result;
        }

        std::optional<std::vector<size_t>> projection(const std::optional<Definition> &definition,
                                                       const std::vector<std::string> &requested,
                                                       bool included)
        {
            if (requested.empty())
                return ordinaryColumns();
            // Column names are asset data, not SDK layout. Do not guess their indices.
            if (!definition)
                return std::nullopt;
            std::vector<size_t> indices;
            for (const auto &name : requested)
            {
                auto found = std::find(
                    definition->columns.begin(), definition->columns.end(), name);
                if (found == definition->columns.end())
                    return std::nullopt;
                indices.push_back(static_cast<size_t>(found - definition->columns.begin()));
            }
            if (included)
                return indices;
            else
            {
                std::vector<size_t> retained;
                for (size_t i = 0; i < definition->columns.size(); ++i)
                    if (std::find(indices.begin(), indices.end(), i) == indices.end())
                        retained.push_back(i);
                // Excluded-column reads retain numeric schema order. Included
                // reads above MUST retain request order: the original virtual
                // leaderboard UI indexes its packed response by that order.
                wire::require(retained.size() <= maximumResponseColumns);
                return retained;
            }
        }
    } // namespace

    std::optional<Reply> leaderboardServices(const std::filesystem::path &directory,
                                             const platform::LobbyIdentity &id,
                                             uint8_t service,
                                             uint8_t task,
                                             wire::Reader &p)
    {
        if (service != 4 || (task != 4 && task != 11 && task != 13 && task != 16 && task != 17))
            return std::nullopt;
        std::vector<uint64_t> users;
        std::vector<uint32_t> boards;
        std::vector<std::string> excluded;
        uint64_t firstRank = 0;
        uint32_t maximum = 0;
        if (task == 11)
        {
            // 0x142127C30: entity count + UInt64 entities, board count + UInt32
            // boards. Results use bdStatsInfoEx (0x14214AFA0), entity-major order.
            const auto count = p.u32();
            wire::require(count > 0 && count <= 200);
            for (uint32_t i = 0; i < count; ++i)
            {
                const auto user = p.u64();
                wire::require(user != 0 && user != UINT64_MAX);
                users.push_back(user);
            }
            const auto boardCount = p.u32();
            wire::require(boardCount > 0 && boardCount <= 200 / count);
            for (uint32_t i = 0; i < boardCount; ++i)
            {
                const auto board = p.u32();
                wire::require(board != UINT32_MAX);
                boards.push_back(board);
            }
        }
        else
        {
            const auto board = p.u32();
            wire::require(board != UINT32_MAX);
            boards.push_back(board);
            if (task == 13 || task == 16)
            {
                maximum = p.u32();
                wire::require(maximum <= 200);
                for (uint32_t i = 0; i < maximum; ++i)
                {
                    const auto user = p.u64();
                    wire::require(user != 0 && user != UINT64_MAX);
                    users.push_back(user);
                }
            }
            else
            {
                firstRank = p.u64();
                maximum = p.u32();
                wire::require(firstRank > 0 && firstRank != UINT64_MAX && maximum <= 200);
            }
            const auto count = p.u32();
            wire::require(count <= 10);
            std::set<std::string> names;
            for (uint32_t i = 0; i < count; ++i)
            {
                auto name = p.text(65);
                wire::require(!name.empty() && names.insert(name).second);
                excluded.push_back(std::move(name));
            }
        }
        p.end();
        Reply reply{0, {}, "leaderboard-rows-read"};
        std::vector<std::vector<Row>> datasets;
        std::vector<std::optional<Definition>> definitions;
        for (const auto board : boards)
        {
            definitions.push_back(definition(directory, id.titleId, board));
            // Native writers use base/tracked IDs. Read namespaces resolve only
            // through published layouts; never subtract a prefix from arbitrary
            // client IDs or change the requested board ID in the reply.
            datasets.push_back(rows(directory, id,
                                    definitions.back() ? definitions.back()->storageBoard : board,
                                    definitions.back()));
        }
        if (task == 11)
        {
            for (const auto user : users)
                for (size_t i = 0; i < boards.size(); ++i)
                {
                    const auto found = std::find_if(datasets[i].begin(),
                                                    datasets[i].end(),
                                                    [&](const Row &row)
                                                    {
                                                        return row.user == user;
                                                    });
                    wire::Writer item;
                    item.u32(boards[i]);
                    item.u32(found == datasets[i].end() ? 108 : 0);
                    if (found == datasets[i].end())
                        item.u64(user);
                    else
                    {
                        auto bytes = serialize(*found, ordinaryColumns());
                        item.data.insert(item.data.end(), bytes.begin(), bytes.end());
                    }
                    reply.results.push_back(std::move(item.data));
                }
            return reply;
        }
        // Replay constructors 0x142128100/0x142128500 are the included-column
        // entity/rank variants (16/17); 13/4 are the excluded-column variants.
        const auto selected =
            projection(definitions[0], excluded, task == 16 || task == 17);
        if (!selected)
            return Reply{108, {}, "leaderboard-column-definition-required"};
        if (task == 13 || task == 16)
            for (const auto user : users)
            {
                const auto found = std::find_if(datasets[0].begin(),
                                                datasets[0].end(),
                                                [&](const Row &row)
                                                {
                                                    return row.user == user;
                                                });
                if (found != datasets[0].end())
                    reply.results.push_back(serialize(*found, *selected));
            }
        if (task == 4 || task == 17)
            for (const auto &row : datasets[0])
            {
                if (row.rank >= firstRank && reply.results.size() < maximum)
                    reply.results.push_back(serialize(row, *selected));
            }
        return reply;
    }
} // namespace services
