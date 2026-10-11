#include "host_os.h"
#include "scheduled_services.h"
#include "matchmaking_services.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>
#include <map>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        uint32_t now()
        {
            return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        Json read(const std::filesystem::path &path, const Json &fallback)
        {
            if (!std::filesystem::exists(path))
                return fallback;
            if (std::filesystem::file_size(path) > 8 * 1024 * 1024)
                throw std::runtime_error("Scheduled store size invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Scheduled store read failed");
            return Json::parse(in);
        }

        void save(const std::filesystem::path &path, const Json &data)
        {
            const auto bytes = data.dump();
            wire::require(bytes.size() <= 8 * 1024 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream out(pending, std::ios::binary | std::ios::trunc);
                if (!out.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("Scheduled store write failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Scheduled store publication failed");
        }

        std::string context(const std::string &value)
        {
            wire::require(value.size() < 16 && value != "." && value != "..");
            for (char c : value)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            return value.empty() ? "_default" : value;
        }

        Json schedules(const std::filesystem::path &root, uint32_t title)
        {
            auto data = read(root / "scheduled-matches" / std::to_string(title) / "matches.json",
                             Json{{"schema", 1}, {"matches", Json::array()}});
            try
            {
                wire::require(data.at("schema") == 1 && data.at("matches").is_array() &&
                              data.at("matches").size() <= 128);
                std::set<uint64_t> ids;
                for (const auto &row : data.at("matches"))
                {
                    wire::require(row.at("id").is_number_unsigned());
                    const auto id = row.at("id").get<uint64_t>();
                    wire::require(id && id != UINT64_MAX && ids.insert(id).second);
                    for (const auto *name : {"start", "end", "status"})
                        wire::require(row.at(name).is_number_unsigned() &&
                                      row.at(name).get<uint64_t>() <= UINT32_MAX);
                    wire::require(row.at("end").get<uint32_t>() >=
                                      row.at("start").get<uint32_t>() &&
                                  row.at("affinity").is_number_unsigned());
                    (void)wire::base64(row.at("metadata").get<std::string>(), 4096);
                    const auto &users = row.at("users");
                    wire::require(users.is_array() && !users.empty() && users.size() <= 200);
                    std::set<uint64_t> members;
                    for (const auto &user : users)
                    {
                        wire::require(user.at("userID").is_number_unsigned());
                        const auto uid = user.at("userID").get<uint64_t>();
                        wire::require(uid && uid != UINT64_MAX && members.insert(uid).second);
                        wire::require(user.at("accountType") == "uno" ||
                                      user.at("accountType") == "bnet");
                    }
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Scheduled store schema invalid");
            }
            return data;
        }

        bool member(const Json &row, uint64_t user)
        {
            return std::any_of(row.at("users").begin(),
                               row.at("users").end(),
                               [&](const auto &a)
                               {
                                   return a.at("userID") == user;
                               });
        }

        wire::Bytes scheduledInfo(const Json &row)
        {
            // Complete same-Replay bdScheduledMatchInfo::deserialize, 0x1420FEE60:
            // ID/start/end/blob/affinity/status, followed by paired packed arrays.
            wire::Writer out;
            out.u64(row.at("id").get<uint64_t>());
            out.u32(row.at("start").get<uint32_t>());
            out.u32(row.at("end").get<uint32_t>());
            out.blob(wire::base64(row.at("metadata").get<std::string>(), 4096));
            out.u64(row.at("affinity").get<uint64_t>());
            out.u32(row.at("status").get<uint32_t>());
            const auto &users = row.at("users");
            out.data.push_back(110);
            out.data.push_back(8);
            wire::raw(out.data, static_cast<uint32_t>(users.size() * 8));
            wire::raw(out.data, static_cast<uint32_t>(users.size()));
            for (const auto &user : users)
                wire::raw(out.data, user.at("userID").get<uint64_t>());
            wire::Bytes types;
            for (const auto &user : users)
            {
                const auto type = user.at("accountType").get<std::string>();
                types.insert(types.end(), type.begin(), type.end());
                types.push_back(0);
            }
            out.data.push_back(116);
            out.data.push_back(0);
            wire::raw(out.data, static_cast<uint32_t>(types.size()));
            wire::raw(out.data, static_cast<uint32_t>(users.size()));
            out.data.insert(out.data.end(), types.begin(), types.end());
            return std::move(out.data);
        }

        Json events(const std::filesystem::path &path)
        {
            auto data = read(
                path, Json{{"schema", 1}, {"next_id", uint64_t{1}}, {"events", Json::array()}});
            try
            {
                wire::require(data.at("schema") == 1 && data.at("events").is_array() &&
                              data.at("events").size() <= 8192);
                wire::require(data.at("next_id").is_number_unsigned());
                const auto next = data.at("next_id").get<uint64_t>();
                wire::require(next > 0);
                uint64_t previous = 0;
                for (const auto &row : data.at("events"))
                {
                    for (const auto *key : {"id", "match", "owner", "time"})
                        wire::require(row.at(key).is_number_unsigned());
                    const auto id = row.at("id").get<uint64_t>();
                    wire::require(id > previous && id < next);
                    previous = id;
                    wire::require(row.at("match").get<uint64_t>() > 0 &&
                                  row.at("match").get<uint64_t>() != UINT64_MAX &&
                                  row.at("owner").get<uint64_t>() > 0 &&
                                  row.at("owner").get<uint64_t>() != UINT64_MAX &&
                                  row.at("time").get<uint64_t>() <= UINT32_MAX);
                    (void)wire::base64(row.at("data").get<std::string>(), 4096);
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Scheduled event schema invalid");
            }
            return data;
        }

        Reply scheduler(const std::filesystem::path &root,
                        const platform::LobbyIdentity &id,
                        uint8_t task,
                        wire::Reader &p)
        {
            uint64_t match = 0;
            uint32_t maximum = 1;
            wire::Bytes event;
            // Exact request constructors: 142134F30 / 142134C40 /
            // 1421350A0 / 142134DB0 for tasks 1 / 2 / 3 / 4.
            if (task == 1)
                maximum = p.u32();
            else
            {
                match = p.u64();
                wire::require(match && match != UINT64_MAX);
            }
            if (task == 3)
                event = p.blob(4096);
            else if (task == 4)
                maximum = p.u32();
            p.end();
            wire::require(maximum <= 128);
            const auto data = schedules(root, id.titleId);
            const auto &matches = data.at("matches");
            if (task == 1)
            {
                std::vector<Json> selected;
                for (const auto &row : matches)
                    if (member(row, id.userId))
                        selected.push_back(row);
                std::sort(selected.begin(),
                          selected.end(),
                          [](const auto &a, const auto &b)
                          {
                              return a.at("start") == b.at("start") ? a.at("id") < b.at("id")
                                                                    : a.at("start") < b.at("start");
                          });
                Reply reply{0, {}, "scheduled-matches-read"};
                for (size_t i = 0; i < std::min(selected.size(), static_cast<size_t>(maximum)); ++i)
                    reply.results.push_back(scheduledInfo(selected[i]));
                return reply;
            }
            const auto found = std::find_if(matches.begin(),
                                            matches.end(),
                                            [&](const auto &row)
                                            {
                                                return row.at("id") == match;
                                            });
            if (found == matches.end())
                return {108, {}, "scheduled-match-not-found"};
            if (!member(*found, id.userId))
                return {101, {}, "scheduled-match-membership-denied"};
            if (task == 2)
                return {0, {scheduledInfo(*found)}, "scheduled-match-info-read"};
            const auto path =
                root / "scheduled-matches" / std::to_string(id.titleId) / "events.json";
            auto journal = events(path);
            if (task == 3)
            {
                auto &rows = journal["events"];
                if (rows.size() >= 8192)
                    return {102, {}, "scheduled-event-capacity-exceeded"};
                const auto next = journal.at("next_id").get<uint64_t>();
                wire::require(next < UINT64_MAX);
                rows.push_back(Json{{"id", next},
                                    {"match", match},
                                    {"owner", id.userId},
                                    {"time", now()},
                                    {"data", wire::base64Encode(event)}});
                journal["next_id"] = next + 1;
                save(path, journal);
                return {0, {}, "scheduled-match-event-recorded"};
            }
            // Complete same-Replay bdMatchEventInfo reader 0x1420FF310.
            Reply reply{0, {}, "scheduled-match-events-read"};
            for (const auto &row : journal.at("events"))
                if (row.at("match") == match && reply.results.size() < maximum)
                {
                    wire::Writer out;
                    out.u64(row.at("match").get<uint64_t>());
                    out.blob(wire::base64(row.at("data").get<std::string>(), 4096));
                    out.u32(row.at("time").get<uint32_t>());
                    out.u64(row.at("id").get<uint64_t>());
                    reply.results.push_back(std::move(out.data));
                }
            return reply;
        }

        Reply performance(const std::filesystem::path &root,
                          const platform::LobbyIdentity &id,
                          wire::Reader &p)
        {
            // Exact Replay request 0x142129DC0: context, game type, then repeated
            // 64-byte bdPerformanceValue serializables, without an on-wire count.
            // Vtable 0x1426A2858 slot 2 -> 0x1421435E0 emits UInt64/Int64.
            const auto scope = context(p.text(16));
            const auto gameType = p.u32();
            wire::require(gameType != UINT32_MAX);
            std::map<uint64_t, std::vector<int64_t>> samples;
            size_t total = 0;
            while (p.more())
            {
                wire::require(total++ < 200);
                const auto user = p.u64();
                wire::require(p.offset < p.data.size());
                const bool nan = p.data[p.offset] == 20;
                const auto value = nan ? (++p.offset, INT64_MAX) : p.value<int64_t>(9);
                wire::require(nan || value != INT64_MAX);
                if (!matchmakingReportIdentity(root, id, user))
                    return {101, {}, "performance-owner-denied"};
                samples[user].push_back(value);
            }
            p.end();
            if (samples.empty())
                return {0, {}, "performance-empty-batch"};
            std::vector<std::pair<std::filesystem::path, Json>> writes;
            for (const auto &[user, values] : samples)
            {
                const auto path = root / "performance" / std::to_string(id.titleId) / scope /
                                  (std::to_string(user) + ".json");
                auto data =
                    read(path, Json{{"schema", 1}, {"owner", user}, {"types", Json::object()}});
                try
                {
                    wire::require(data.at("schema") == 1 && data.at("owner") == user &&
                                  data.at("types").is_object() && data.at("types").size() <= 128);
                    for (auto row = data.at("types").begin(); row != data.at("types").end(); ++row)
                    {
                        const auto &name = row.key();
                        wire::require(!name.empty() && name.size() <= 10 &&
                                      (name.size() == 1 || name[0] != '0'));
                        uint64_t type = 0;
                        for (char c : name)
                        {
                            wire::require(c >= '0' && c <= '9');
                            type = type * 10 + static_cast<unsigned>(c - '0');
                        }
                        wire::require(type < UINT32_MAX);
                        wire::require(row->at("count").is_number_unsigned() &&
                                      row->at("recent").is_array() && row->at("recent").size() <= 256 &&
                                      row->at("count").get<uint64_t>() >= row->at("recent").size());
                        for (const auto &value : row->at("recent"))
                            wire::require(value.is_null() ||
                                          (value.is_number_integer() &&
                                           (!value.is_number_unsigned() ||
                                            value.get<uint64_t>() < uint64_t(INT64_MAX)) &&
                                           value.get<int64_t>() != INT64_MAX));
                        if (row->contains("updated"))
                            wire::require(row->at("updated").is_number_unsigned() &&
                                          row->at("updated").get<uint64_t>() <= UINT32_MAX);
                    }
                }
                catch (const std::runtime_error &)
                {
                    throw std::runtime_error("Performance store schema invalid");
                }
                auto &types = data["types"];
                const auto key = std::to_string(gameType);
                wire::require(types.contains(key) || types.size() < 128);
                auto entry = types.value(key, Json{{"count", uint64_t{0}}, {"recent", Json::array()}});
                auto &recent = entry["recent"];
                wire::require(recent.is_array() && recent.size() <= 256);
                const auto count = entry.at("count").get<uint64_t>();
                wire::require(count <= UINT64_MAX - values.size());
                for (const auto value : values)
                    recent.push_back(value == INT64_MAX ? Json() : Json(value));
                if (recent.size() > 256)
                    recent.erase(recent.begin(),
                                 recent.begin() +
                                     static_cast<Json::difference_type>(recent.size() - 256));
                entry["count"] = count + values.size();
                entry["updated"] = now();
                types[key] = std::move(entry);
                writes.emplace_back(path, std::move(data));
            }
            for (const auto &[path, data] : writes)
                save(path, data);
            return {0, {}, "performance-samples-recorded"};
        }
    } // namespace

    std::optional<Reply> scheduledServices(const std::filesystem::path &root,
                                           const platform::LobbyIdentity &id,
                                           uint8_t service,
                                           uint8_t task,
                                           wire::Reader &p)
    {
        if (service == 150 && task >= 1 && task <= 4)
            return scheduler(root, id, task, p);
        if (service == 152 && task == 1)
            return performance(root, id, p);
        return std::nullopt;
    }
} // namespace services
