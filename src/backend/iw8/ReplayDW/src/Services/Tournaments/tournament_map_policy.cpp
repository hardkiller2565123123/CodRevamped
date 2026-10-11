#include "host_os.h"
#include "tournament_map_policy.h"
#include "crypto.h"
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        void require(bool valid)
        {
            if (!valid)
                throw std::runtime_error("Invalid persisted tournament map policy");
        }

        Json read(const std::filesystem::path &path)
        {
            require(std::filesystem::file_size(path) <= 1024 * 1024);
            std::ifstream file(path);
            require(static_cast<bool>(file));
            bool unique = true;
            std::map<int, std::set<std::string>> keys;
            const auto value = Json::parse(
                file,
                [&](int depth, Json::parse_event_t event, Json &parsed)
                {
                    if (event == Json::parse_event_t::object_start)
                        keys[depth + 1].clear();
                    else if (event == Json::parse_event_t::object_end)
                        keys.erase(depth + 1);
                    else if (event == Json::parse_event_t::key)
                        unique = keys[depth].insert(parsed.get<std::string>()).second && unique;
                    return true;
                });
            require(unique);
            return value;
        }

        std::string fingerprint(const Json &policy)
        {
            const auto bytes = policy.dump();
            const auto hash =
                crypto::sha256({reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()});
            constexpr char digits[] = "0123456789abcdef";
            std::string result;
            for (const auto value : hash)
            {
                result += digits[value >> 4];
                result += digits[value & 15];
            }
            return result;
        }

        void acceptRevision(const std::filesystem::path &path, const Json &policy)
        {
            const Json receipt = {{"schema", 1},
                                  {"title", policy["title"]},
                                  {"revision", policy["revision"]},
                                  {"sha256", fingerprint(policy)}};
            if (std::filesystem::exists(path))
            {
                const auto previous = read(path);
                require(previous.is_object() && previous.size() == 4 &&
                        previous.at("schema") == 1 && previous.at("title") == policy["title"] &&
                        previous.at("revision").is_number_unsigned() &&
                        previous["revision"].get<uint64_t>() > 0 &&
                        previous["revision"].get<uint64_t>() <= UINT16_MAX &&
                        previous.at("sha256").is_string());
                const auto hash = previous["sha256"].get<std::string>();
                require(hash.size() == 64 &&
                        hash.find_first_not_of("0123456789abcdef") == std::string::npos &&
                        previous["revision"] <= policy["revision"]);
                if (previous["revision"] == policy["revision"])
                {
                    require(previous == receipt);
                    return;
                }
            }
            auto pending = path;
            pending += ".pending";
            const auto bytes = receipt.dump();
            const auto file = CreateFileW(pending.c_str(),
                                          GENERIC_WRITE,
                                          0,
                                          nullptr,
                                          CREATE_ALWAYS,
                                          FILE_ATTRIBUTE_NORMAL,
                                          nullptr);
            if (file == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Tournament map revision write failed");
            DWORD written = 0;
            const auto valid =
                WriteFile(
                    file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                written == bytes.size() && FlushFileBuffers(file);
            CloseHandle(file);
            if (!valid || !MoveFileExW(pending.c_str(),
                                       path.c_str(),
                                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Tournament map revision publication failed");
        }
    } // namespace

    void validateTournamentMapPolicy(const Json &policy, uint32_t title)
    {
        require(title == 5800 && policy.is_object() && policy.size() == 4 &&
                policy.at("schema") == 1 && policy.at("title") == title &&
                policy.at("revision").is_number_unsigned() &&
                policy["revision"].get<uint64_t>() > 0 &&
                policy["revision"].get<uint64_t>() <= UINT16_MAX &&
                policy.at("rounds").is_array() && policy["rounds"].size() == 4);
        for (const auto &round : policy["rounds"])
        {
            // Replay 0x141077E60 copies at most eight comma-separated names into
            // 32-byte slots from a 256-byte dvar buffer. The common playlist's
            // map identifier bound is stricter, so no native truncation is needed.
            require(round.is_array() && !round.empty() && round.size() <= 8);
            std::set<std::string> names;
            for (const auto &entry : round)
            {
                require(entry.is_string());
                const auto name = entry.get<std::string>();
                require(!name.empty() && name.size() < 24 && names.insert(name).second &&
                        std::all_of(name.begin(),
                                    name.end(),
                                    [](char c)
                                    {
                                        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                                               c == '_';
                                    }));
            }
        }
    }

    std::optional<Json> tournamentMapPolicy(const std::filesystem::path &directory, uint32_t title)
    {
        const auto path = directory / "tournaments" / std::to_string(title) / "map-pools.json";
        if (!std::filesystem::exists(path))
            return std::nullopt;
        auto policy = read(path);
        validateTournamentMapPolicy(policy, title);
        acceptRevision(path.parent_path() / "map-pools.applied.json", policy);
        return policy;
    }

    std::array<std::string, 4> tournamentMapsForId(const Json &policy, uint64_t tournament)
    {
        require(policy.at("title").is_number_unsigned() && tournament);
        validateTournamentMapPolicy(policy, policy["title"].get<uint32_t>());
        std::array<std::string, 4> chosen;
        for (size_t round = 0; round < chosen.size(); ++round)
        {
            const auto &pool = policy["rounds"][round];
            if (pool.size() == 1)
            {
                chosen[round] = pool[0].get<std::string>();
                continue;
            }
            auto available = [&](size_t omitFrom)
            {
                std::vector<std::string> candidates;
                for (const auto &entry : pool)
                {
                    const auto name = entry.get<std::string>();
                    if (std::find(chosen.begin() + omitFrom, chosen.begin() + round, name) ==
                        chosen.begin() + round)
                        candidates.push_back(name);
                }
                return candidates;
            };
            // Original Replay 0x141070840 / 0x141070950: omit all prior maps;
            // if exhausted, omit only the immediately preceding round. Selection
            // uses this round's unsigned 16-bit slice of the full tournament ID.
            auto candidates = available(0);
            if (candidates.empty() && round)
                candidates = available(round - 1);
            require(!candidates.empty());
            const auto seed = (tournament >> (16 * round)) & UINT16_MAX;
            chosen[round] = candidates[seed % candidates.size()];
        }
        return chosen;
    }

    Json tournamentMapDvars(const std::filesystem::path &directory,
                            uint32_t title,
                            const Json &policy)
    {
        validateTournamentMapPolicy(policy, title);
        const auto bindings =
            read(directory / "playlists" / std::to_string(title) / "native-dvar-names.json");
        require(bindings.is_object());
        Json variables = Json::object();
        for (size_t round = 0; round < 4; ++round)
        {
            const auto logical = "online_tournament_round_" + std::to_string(round) + "_mapnames";
            require(bindings.contains(logical) && bindings[logical].is_string());
            const auto native = bindings[logical].get<std::string>();
            require(!native.empty() && native.size() < 64 &&
                    native.find('\0') == std::string::npos);
            std::string names;
            for (const auto &entry : policy["rounds"][round])
            {
                if (!names.empty())
                    names += ',';
                names += entry.get<std::string>();
            }
            require(names.size() < 256 && !variables.contains(native));
            variables[native] = names;
        }
        return variables;
    }
} // namespace services
