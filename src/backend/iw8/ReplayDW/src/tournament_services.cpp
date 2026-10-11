#include "host_os.h"
#include "tournament_services.h"
#include "matchmaking_store.h"
#include "lobby.h"
#include "matchmaking_services.h"
#include "tournament_map_policy.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <set>
#include <charconv>
#include <memory>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t maxDocument = 16383, maxCatalog = 2 * 1024 * 1024;
        constexpr uint32_t notEnrolled = 14526;

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        void persisted(bool valid)
        {
            if (!valid)
                throw std::runtime_error("Invalid tournament publication or persistent state");
        }

        bool boundedText(const Json &value, size_t capacity)
        {
            return value.is_string() && !value.get_ref<const std::string &>().empty() &&
                   value.get_ref<const std::string &>().size() < capacity &&
                   value.get_ref<const std::string &>().find('\0') == std::string::npos;
        }

        Json document(const std::string &bytes)
        {
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            auto callback = [&](int, Json::parse_event_t event, Json &value)
            {
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    unique = keys.back().insert(value.get<std::string>()).second && unique;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            auto result = Json::parse(bytes, callback, false);
            return unique ? result : Json(Json::value_t::discarded);
        }

        Json read(const std::filesystem::path &path, size_t capacity)
        {
            // Hold one immutable file snapshot while allowing the publisher to
            // atomically replace its path. CRT streams deny delete sharing on
            // Windows and otherwise race the live-publication watcher.
            const auto handle = CreateFileW(path.c_str(),
                                            GENERIC_READ,
                                            FILE_SHARE_READ | FILE_SHARE_DELETE,
                                            nullptr,
                                            OPEN_EXISTING,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Tournament state read failed");
            const std::unique_ptr<void, decltype(&CloseHandle)> snapshot(handle, &CloseHandle);
            LARGE_INTEGER size{};
            if (!GetFileSizeEx(handle, &size))
                throw std::runtime_error("Tournament state size read failed");
            persisted(size.QuadPart >= 0 && static_cast<uint64_t>(size.QuadPart) <= capacity);
            std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
            size_t offset = 0;
            while (offset < bytes.size())
            {
                DWORD received = 0;
                if (!ReadFile(handle,
                              bytes.data() + offset,
                              static_cast<DWORD>(bytes.size() - offset),
                              &received,
                              nullptr) ||
                    !received)
                    throw std::runtime_error("Tournament state snapshot read failed");
                offset += received;
            }
            auto result = document(bytes);
            persisted(result.is_object());
            return result;
        }

        void write(const std::filesystem::path &path, const Json &state)
        {
            const auto bytes = state.dump();
            persisted(bytes.size() <= maxCatalog);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream stream(pending, std::ios::binary | std::ios::trunc);
                if (!stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !stream.flush())
                    throw std::runtime_error("Tournament state write failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Tournament state publication failed");
        }

        std::set<uint64_t> validateBracket(const Json &state, uint64_t tournament)
        {
            // Exact Replay consumer 0x141074530: every ID indexes fixed native
            // arrays. Validate the complete bracket before emitting any string.
            persisted(
                state.is_object() && state.at("tournamentID") == tournament &&
                boundedText(state.at("tournamentStatus"), 64) &&
                (state["tournamentStatus"] == "FORMING" || state["tournamentStatus"] == "PLAYING"));
            const auto &definition = state.at("tournamentDefinition");
            persisted(definition.is_object() && definition.at("teamSize").is_number_unsigned() &&
                      definition.at("numTeams").is_number_unsigned() &&
                      definition.at("numPlayers").is_number_unsigned());
            persisted(definition["teamSize"].get<uint64_t>() <= 4 &&
                      definition["numTeams"].get<uint64_t>() <= 16);
            const auto teamSize = definition["teamSize"].get<unsigned>();
            const auto teamCount = definition["numTeams"].get<unsigned>();
            persisted(teamSize >= 1 && teamSize <= 4 && (teamCount == 8 || teamCount == 16) &&
                      definition["numPlayers"] == teamSize * teamCount);
            const auto &teams = state.at("teams");
            persisted(teams.is_array() && teams.size() == teamCount);
            std::set<uint64_t> members;
            for (unsigned index = 0; index < teamCount; ++index)
            {
                const auto &team = teams[index];
                persisted(team.is_object() && team.at("teamID") == index &&
                          team.at("playerIDs").is_array() && team["playerIDs"].size() <= teamSize);
                for (const auto &user : team["playerIDs"])
                    persisted(user.is_number_unsigned() && user.get<uint64_t>() &&
                              members.insert(user.get<uint64_t>()).second);
            }
            const auto &players = state.at("players");
            persisted(players.is_array() && players.size() == members.size());
            std::set<uint64_t> playerIds;
            for (const auto &player : players)
            {
                persisted(player.is_object() && player.at("playerID").is_number_unsigned());
                const auto user = player["playerID"].get<uint64_t>();
                persisted(members.contains(user) && playerIds.insert(user).second);
            }
            const auto &rounds = state.at("rounds");
            const unsigned roundCount = teamCount == 8 ? 3 : 4;
            persisted(rounds.is_array() && rounds.size() == roundCount);
            std::set<uint64_t> lobbies;
            for (unsigned round = 0; round < roundCount; ++round)
            {
                const auto &row = rounds[round];
                persisted(row.is_object() && row.at("roundID") == round &&
                          row.at("matches").is_array() &&
                          row["matches"].size() == (teamCount >> (round + 1)));
                std::set<unsigned> participants;
                for (const auto &match : row["matches"])
                {
                    persisted(match.is_object() && match.at("teamIDs").is_array() &&
                              match["teamIDs"].size() <= 2 &&
                              match.at("readyPlayerIDs").is_array() &&
                              match["readyPlayerIDs"].size() <= 2 * teamSize &&
                              match.at("lobbyID").is_number_unsigned() &&
                              match.at("expired").is_boolean());
                    const auto lobby = match["lobbyID"].get<uint64_t>();
                    persisted(!lobby || lobbies.insert(lobby).second);
                    persisted(!lobby || match["teamIDs"].size() == 2);
                    std::set<uint64_t> matchMembers;
                    std::set<uint64_t> ready;
                    for (const auto &team : match["teamIDs"])
                    {
                        persisted(team.is_number_unsigned() && team.get<uint64_t>() < teamCount &&
                                  participants.insert(team.get<unsigned>()).second);
                        for (const auto &user : teams[team.get<unsigned>()]["playerIDs"])
                            matchMembers.insert(user.get<uint64_t>());
                    }
                    for (const auto &user : match["readyPlayerIDs"])
                        persisted(user.is_number_unsigned() &&
                                  matchMembers.contains(user.get<uint64_t>()) &&
                                  ready.insert(user.get<uint64_t>()).second);
                    if (match.contains("winningTeamID"))
                    {
                        persisted(match["winningTeamID"].is_number_integer() &&
                                  match["winningTeamID"] >= -1 &&
                                  match["winningTeamID"] < teamCount);
                        const auto winner = match["winningTeamID"].get<int>();
                        persisted(winner == -1 ||
                                  std::find(match["teamIDs"].begin(),
                                            match["teamIDs"].end(),
                                            Json(winner)) != match["teamIDs"].end());
                    }
                    if (match.contains("matchResultPayload"))
                    {
                        const auto &scores = match["matchResultPayload"].at("scores");
                        persisted(scores.is_array() && scores.size() <= 2);
                        for (const auto &score : scores)
                            persisted(score.is_number_unsigned() && score.get<uint64_t>() <= 65535);
                    }
                    if (match["expired"] == true)
                        persisted(match.contains("expireReason") &&
                                  match["expireReason"].is_number_integer());
                }
            }
            persisted(state.dump().size() <= maxDocument);
            return members;
        }

        std::string stateHash(const Json &state);

        bool roundAllocated(const Json *row)
        {
            if (!row || !row->contains("round_rules"))
                return false;
            for (const auto &round : row->at("state")["rounds"])
                for (const auto &match : round["matches"])
                    if (match["lobbyID"] != 0)
                        return true;
            return false;
        }

        Json formationDefinition(const Json &row)
        {
            Json definition = {{"id", row.at("id")},
                               {"name", row.at("name")},
                               {"data_center", row.at("data_center")},
                               {"expires", row.at("expires")},
                               {"formation", row.at("formation")}};
            if (row.contains("round_rules"))
                definition["round_rules"] = row["round_rules"];
            if (row.contains("native_map_pool"))
                definition["native_map_pool"] = row["native_map_pool"];
            return definition;
        }

        Json emptyBracket(const Json &row)
        {
            const auto &definition = row.at("formation");
            persisted(definition.is_object() && definition.size() == 2 &&
                      definition.at("team_size").is_number_unsigned() &&
                      definition["team_size"].get<uint64_t>() >= 1 &&
                      definition["team_size"].get<uint64_t>() <= 4 &&
                      definition.at("num_teams").is_number_unsigned() &&
                      (definition["num_teams"] == 8 || definition["num_teams"] == 16));
            const auto teamCount = definition["num_teams"].get<unsigned>();
            if (row.contains("native_map_pool"))
            {
                persisted(row.contains("round_rules"));
                validateTournamentMapPolicy(row["native_map_pool"],
                                            row["native_map_pool"].at("title").get<uint32_t>());
            }
            if (row.contains("round_rules"))
            {
                const auto &rules = row["round_rules"];
                persisted(rules.is_array() && rules.size() == (teamCount == 8 ? 3 : 4));
                for (const auto &query : rules)
                {
                    persisted(query.is_object() && query.size() <= 3 && query.dump().size() < 8192);
                    for (const auto &field : query.items())
                        persisted(field.key() == "ruleset_payload" ||
                                  field.key() == "performance" ||
                                  field.key() == "acceptable_platforms");
                    const auto &filter = query.at("ruleset_payload").at("filter");
                    persisted(filter.is_object() && filter.at("playlist_id").is_number_unsigned() &&
                              filter["playlist_id"].get<uint64_t>() > 0 &&
                              filter["playlist_id"].get<uint64_t>() < 128 &&
                              filter.at("playlist_version").is_number_unsigned() &&
                              filter["playlist_version"].get<uint64_t>() <= UINT32_MAX);
                    if (query.contains("performance"))
                        persisted(query["performance"].is_object());
                    if (query.contains("acceptable_platforms"))
                        persisted(query["acceptable_platforms"].is_array() &&
                                  query["acceptable_platforms"] == Json::array({"bnet"}));
                }
            }
            Json state = {{"tournamentID", row["id"]},
                          {"tournamentStatus", "FORMING"},
                          {"tournamentDefinition",
                           {{"teamSize", definition["team_size"]},
                            {"numTeams", teamCount},
                            {"numPlayers", teamCount * definition["team_size"].get<unsigned>()}}},
                          {"teams", Json::array()},
                          {"players", Json::array()},
                          {"rounds", Json::array()}};
            for (unsigned team = 0; team < teamCount; ++team)
                state["teams"].push_back({{"teamID", team}, {"playerIDs", Json::array()}});
            for (unsigned round = 0; (teamCount >> (round + 1)) != 0; ++round)
            {
                Json matches = Json::array();
                for (unsigned index = 0; index < (teamCount >> (round + 1)); ++index)
                    matches.push_back(
                        {{"teamIDs",
                          round ? Json::array() : Json::array({2 * index, 2 * index + 1})},
                         {"readyPlayerIDs", Json::array()},
                         {"lobbyID", uint64_t{0}},
                         {"expired", false},
                         {"winningTeamID", -1}});
                state["rounds"].push_back({{"roundID", round}, {"matches", std::move(matches)}});
            }
            validateBracket(state, row["id"].get<uint64_t>());
            return state;
        }

        void validateFormation(const Json &record, uint32_t title, uint64_t id)
        {
            persisted(record.is_object() && record.size() == 7 && record.at("schema") == 1 &&
                      record.at("title") == title && record.at("id") == id && id &&
                      record.at("expires").is_number_unsigned() &&
                      record.at("definition").is_object() &&
                      record["definition"].size() ==
                          5 + (record["definition"].contains("round_rules") ? 1 : 0) +
                              (record["definition"].contains("native_map_pool") ? 1 : 0) &&
                      record["definition"].at("id") == id &&
                      record["definition"].at("expires") == record["expires"] &&
                      boundedText(record["definition"].at("name"), 128) &&
                      boundedText(record["definition"].at("data_center"), 64) &&
                      record.at("parties").is_object() && record["parties"].size() <= 64);
            const auto expected = emptyBracket(record["definition"]);
            if (record["definition"].contains("native_map_pool"))
                validateTournamentMapPolicy(record["definition"]["native_map_pool"], title);
            const auto &state = record.at("state");
            const auto members = validateBracket(state, id);
            persisted(state["tournamentDefinition"] == expected["tournamentDefinition"]);
            std::set<uint64_t> assigned;
            for (const auto &party : record["parties"].items())
            {
                uint64_t owner = 0;
                const auto parsed = std::from_chars(
                    party.key().data(), party.key().data() + party.key().size(), owner);
                persisted(parsed.ec == std::errc{} &&
                          parsed.ptr == party.key().data() + party.key().size() && owner &&
                          std::to_string(owner) == party.key());
                const auto &entry = party.value();
                persisted(entry.is_object() && entry.size() == 2 &&
                          entry.at("team").is_number_unsigned() &&
                          entry["team"].get<uint64_t>() < state["teams"].size() &&
                          entry.at("members").is_array() && !entry["members"].empty() &&
                          entry["members"].size() <=
                              state["tournamentDefinition"]["teamSize"].get<size_t>());
                bool ownerPresent = false;
                const auto &team = state["teams"][entry["team"].get<size_t>()]["playerIDs"];
                for (const auto &user : entry["members"])
                {
                    persisted(user.is_number_unsigned() && members.contains(user.get<uint64_t>()) &&
                              assigned.insert(user.get<uint64_t>()).second &&
                              std::find(team.begin(), team.end(), user) != team.end());
                    ownerPresent = ownerPresent || user == owner;
                }
                persisted(ownerPresent);
            }
            persisted(assigned == members);
            for (const auto &round : state["rounds"])
                for (const auto &match : round["matches"])
                    persisted(match["lobbyID"] == 0 ||
                              (record["definition"].contains("round_rules") &&
                               state["tournamentStatus"] == "PLAYING"));
            if (state["tournamentStatus"] == "PLAYING")
                for (const auto &team : state["teams"])
                    persisted(team["playerIDs"].size() ==
                              state["tournamentDefinition"]["teamSize"].get<size_t>());
        }

        std::filesystem::path formationPath(const std::filesystem::path &tournamentRoot,
                                            uint32_t title,
                                            uint64_t id)
        {
            return tournamentRoot.parent_path().parent_path() / "matchmaking" /
                   std::to_string(title) / "tournaments" / (std::to_string(id) + ".json");
        }

        Json formationRecord(const std::filesystem::path &root, uint32_t title, const Json &row)
        {
            const auto path = formationPath(root, title, row["id"].get<uint64_t>());
            Json record;
            if (std::filesystem::exists(path))
                record = read(path, 128 * 1024);
            else
                record = {{"schema", 1},
                          {"title", title},
                          {"id", row["id"]},
                          {"expires", row["expires"]},
                          {"definition", formationDefinition(row)},
                          {"parties", Json::object()},
                          {"state", emptyBracket(row)}};
            validateFormation(record, title, row["id"].get<uint64_t>());
            persisted(record["definition"] == formationDefinition(row));
            return record;
        }

        std::filesystem::path terminationPath(const std::filesystem::path &directory,
                                              uint32_t title,
                                              uint64_t tournament)
        {
            return directory / "matchmaking" / std::to_string(title) / "tournament-terminations" /
                   (std::to_string(tournament) + ".json");
        }

        bool terminated(const std::filesystem::path &directory, uint32_t title, uint64_t tournament)
        {
            const auto path = terminationPath(directory, title, tournament);
            if (!std::filesystem::exists(path))
                return false;
            validateTournamentTermination(read(path, 128 * 1024), title, tournament);
            return true;
        }

        Json catalog(const std::filesystem::path &path, uint32_t title)
        {
            if (!std::filesystem::exists(path))
                return Json::array();
            auto result = read(path, maxCatalog);
            persisted(result.at("schema") == 1 && result.at("title") == title &&
                      result.at("tournaments").is_array() && result["tournaments"].size() <= 128);
            std::set<uint64_t> ids;
            std::set<std::pair<std::string, std::string>> names;
            Json available = Json::array();
            matchmaking_store::recover(path.parent_path().parent_path().parent_path() /
                                           "matchmaking" / std::to_string(title),
                                       title);
            for (auto &row : result["tournaments"])
            {
                persisted(
                    row.is_object() && row.at("id").is_number_unsigned() &&
                    row["id"].get<uint64_t>() && ids.insert(row["id"].get<uint64_t>()).second &&
                    boundedText(row.at("name"), 128) && boundedText(row.at("data_center"), 64) &&
                    row.at("expires").is_number_unsigned() &&
                    row.at("registration_open").is_boolean() &&
                    row.at("start_search_offset_seconds").is_number() &&
                    row["start_search_offset_seconds"].get<double>() >= 0 &&
                    row["start_search_offset_seconds"].get<double>() <= 3600);
                persisted(names
                              .emplace(row["name"].get<std::string>(),
                                       row["data_center"].get<std::string>())
                              .second);
                persisted(!row.contains("native_map_pool"));
                if (row.contains("native_map_pool_revision"))
                {
                    persisted(row.contains("formation") && row.contains("round_rules") &&
                              row["native_map_pool_revision"].is_number_unsigned() &&
                              row["native_map_pool_revision"].get<uint64_t>() > 0 &&
                              row["native_map_pool_revision"].get<uint64_t>() <= UINT16_MAX);
                    const auto policy =
                        tournamentMapPolicy(path.parent_path().parent_path().parent_path(), title);
                    // An incomplete catalog/pool publication is not evidence
                    // of withdrawal. Fail the read so maintenance cannot turn
                    // this live row into a durable terminal competition.
                    persisted(policy && policy->at("revision") == row["native_map_pool_revision"]);
                    row["native_map_pool"] = *policy;
                }
                if (row.contains("formation"))
                {
                    // A formation publication specifies capacity, never player IDs
                    // or native bracket arrays. Those come from authenticated searches.
                    persisted(!row.contains("state"));
                    row["state"] = formationRecord(path.parent_path(), title, row)["state"];
                    if (!row.contains("live_updates"))
                        row["live_updates"] = true;
                }
                persisted(!row.contains("round_rules") || row.contains("formation"));
                validateBracket(row.at("state"), row["id"].get<uint64_t>());
                if (terminated(path.parent_path().parent_path().parent_path(),
                               title,
                               row["id"].get<uint64_t>()))
                    continue;
                if (row.contains("live_updates"))
                    persisted(row["live_updates"].is_boolean());
                available.push_back(std::move(row));
            }
            return available;
        }

        void validateEnrollments(const Json &result, uint32_t title)
        {
            persisted(result.is_object() && result.at("schema") == 1 &&
                      result.at("title") == title && result.at("players").is_object() &&
                      result["players"].size() <= 4096);
            for (const auto &row : result["players"].items())
            {
                const auto &value = row.value();
                persisted(!row.key().empty() && row.key().size() <= 20 &&
                          row.key().find_first_not_of("0123456789") == std::string::npos &&
                          value.is_object() && value.at("id").is_number_unsigned() &&
                          value["id"].get<uint64_t>() && value.at("accepted").is_boolean() &&
                          value.at("ready").is_boolean());
                uint64_t user = 0;
                const auto parsed =
                    std::from_chars(row.key().data(), row.key().data() + row.key().size(), user);
                persisted(parsed.ec == std::errc{} &&
                          parsed.ptr == row.key().data() + row.key().size() && user &&
                          std::to_string(user) == row.key());
                if (value.contains("ready_round") || value.contains("ready_match"))
                    persisted(value.at("ready_round").is_number_unsigned() &&
                              value["ready_round"].get<uint64_t>() < 4 &&
                              value.at("ready_match").is_number_unsigned() &&
                              value["ready_match"].get<uint64_t>() < 8);
                if (value.contains("live_updates"))
                    persisted(value["live_updates"].is_boolean());
                if (value.contains("accepted_session"))
                    persisted(value["accepted_session"].is_string() &&
                              value["accepted_session"].get_ref<const std::string &>().size() ==
                                  44 &&
                              value["accepted"] == true);
                if (value.contains("formation_disbanded"))
                    persisted(
                        value["formation_disbanded"].is_boolean() &&
                        (!value["formation_disbanded"].get<bool>() || value["accepted"] == false));
            }
        }

        Json enrollments(const std::filesystem::path &path, uint32_t title)
        {
            Json result = {{"schema", 1}, {"title", title}, {"players", Json::object()}};
            if (std::filesystem::exists(path))
                result = read(path, maxCatalog);
            validateEnrollments(result, title);
            return result;
        }

        Json reserveParty(Json record, uint64_t owner, const Json &members)
        {
            std::set<uint64_t> requested;
            for (const auto &user : members)
                requested.insert(user.get<uint64_t>());
            const auto key = std::to_string(owner);
            if (record["parties"].contains(key))
            {
                std::set<uint64_t> assigned;
                for (const auto &user : record["parties"][key]["members"])
                    assigned.insert(user.get<uint64_t>());
                return assigned == requested ? record : Json();
            }
            for (const auto &player : record["state"]["players"])
                if (requested.contains(player["playerID"].get<uint64_t>()))
                    return Json();
            if (record["state"]["tournamentStatus"] != "FORMING")
                return Json();
            const auto size = record["state"]["tournamentDefinition"]["teamSize"].get<size_t>();
            for (auto &team : record["state"]["teams"])
                if (team["playerIDs"].size() + members.size() <= size)
                {
                    record["parties"][key] = {{"team", team["teamID"]}, {"members", members}};
                    for (const auto &user : members)
                    {
                        team["playerIDs"].push_back(user);
                        record["state"]["players"].push_back({{"playerID", user}});
                    }
                    return record;
                }
            return Json();
        }

        void commitEnrollment(const std::filesystem::path &directory,
                              uint32_t title,
                              const Json &enrollment,
                              const std::optional<Json> &formation = std::nullopt,
                              const std::vector<matchmaking_store::Write> &roundWrites = {})
        {
            std::vector<matchmaking_store::Write> writes = {
                {"tournament-enrollments.json", enrollment}};
            if (formation)
                writes.push_back(
                    {"tournaments/" + std::to_string(formation->at("id").get<uint64_t>()) + ".json",
                     *formation});
            writes.insert(writes.end(), roundWrites.begin(), roundWrites.end());
            matchmaking_store::commit(
                directory / "matchmaking" / std::to_string(title), title, writes);
        }

        bool formationAccepted(const Json &record, uint32_t title, const Json &players)
        {
            const auto &state = record["state"];
            for (const auto &team : state["teams"])
                if (team["playerIDs"].size() !=
                    state["tournamentDefinition"]["teamSize"].get<size_t>())
                    return false;
            for (const auto &player : state["players"])
            {
                const auto user = player["playerID"].get<uint64_t>();
                const auto key = std::to_string(user);
                if (!players.contains(key) || players[key]["id"] != record["id"] ||
                    players[key]["accepted"] != true ||
                    !players[key].contains("accepted_session") ||
                    !lobby::sessionOnline(
                        title, user, players[key]["accepted_session"].get<std::string>()))
                    return false;
            }
            return true;
        }

        bool releaseFormingParty(Json &record, uint64_t user, Json &players, Reply &reply)
        {
            if (record["state"]["tournamentStatus"] != "FORMING")
                return false;
            std::set<uint64_t> released;
            for (auto party = record["parties"].begin(); party != record["parties"].end(); ++party)
                if (std::find(party.value()["members"].begin(),
                              party.value()["members"].end(),
                              Json(user)) != party.value()["members"].end())
                {
                    for (const auto &member : party.value()["members"])
                        released.insert(member.get<uint64_t>());
                    record["parties"].erase(party);
                    break;
                }
            if (released.empty())
                return false;
            for (auto &team : record["state"]["teams"])
            {
                auto &members = team["playerIDs"];
                members.erase(std::remove_if(members.begin(),
                                             members.end(),
                                             [&](const Json &member)
                                             {
                                                 return released.contains(member.get<uint64_t>());
                                             }),
                              members.end());
            }
            auto &members = record["state"]["players"];
            members.erase(std::remove_if(members.begin(),
                                         members.end(),
                                         [&](const Json &member)
                                         {
                                             return released.contains(
                                                 member["playerID"].get<uint64_t>());
                                         }),
                          members.end());
            // A broken formation party cannot retain acceptance for a changed
            // assignment. Preserve its other registrations, and use the native
            // formation-disband event; no PLAYER/PLAYING bracket is fabricated.
            for (const auto member : released)
            {
                const auto key = std::to_string(member);
                if (!players.contains(key) || players[key]["id"] != record["id"])
                    continue;
                players[key]["accepted"] = false;
                players[key]["ready"] = false;
                players[key]["formation_disbanded"] = true;
                for (const auto *field : {"accepted_session", "ready_round", "ready_match"})
                    players[key].erase(field);
                if (member == user)
                    continue;
                wire::Writer push;
                push.u32(2011);
                push.u64(record["id"]);
                Delivery delivery;
                delivery.user = member;
                delivery.tournamentId = record["id"].get<uint64_t>();
                delivery.tournamentStateHash = stateHash(record["state"]);
                delivery.tournamentFormationDisband = true;
                delivery.delayMs = 250;
                delivery.payload = std::move(push.data);
                reply.deliveries.push_back(std::move(delivery));
            }
            return true;
        }

        const Json *published(const Json &rows, uint64_t tournament, uint64_t user)
        {
            for (const auto &row : rows)
                if (row["id"] == tournament && row["expires"].get<uint64_t>() > now() &&
                    validateBracket(row["state"], tournament).contains(user))
                    return &row;
            return nullptr;
        }

        Json results(const std::filesystem::path &path, uint32_t title, uint64_t tournament)
        {
            Json state = {{"schema", 1},
                          {"title", title},
                          {"tournament", tournament},
                          {"results", Json::array()}};
            if (std::filesystem::exists(path))
                state = read(path, maxCatalog);
            persisted(state.at("schema") == 1 && state.at("title") == title &&
                      state.at("tournament") == tournament && state.at("results").is_array() &&
                      state["results"].size() <= 15);
            std::set<std::pair<uint64_t, uint64_t>> matches;
            std::set<uint64_t> lobbies;
            for (const auto &entry : state["results"])
            {
                persisted(
                    entry.is_object() && entry.at("round").is_number_unsigned() &&
                    entry["round"].get<uint64_t>() < 4 && entry.at("match").is_number_unsigned() &&
                    entry["match"].get<uint64_t>() < 8 &&
                    matches.emplace(entry["round"].get<uint64_t>(), entry["match"].get<uint64_t>())
                        .second &&
                    entry.at("lobby").is_number_unsigned() && entry["lobby"].get<uint64_t>() &&
                    lobbies.insert(entry["lobby"].get<uint64_t>()).second &&
                    entry.at("reporter").is_number_unsigned() &&
                    entry["reporter"].get<uint64_t>() &&
                    entry.at("recorded").is_number_unsigned() &&
                    entry["recorded"].get<uint64_t>() && entry.at("teams").is_array() &&
                    entry["teams"].size() == 2 && entry.at("scores").is_array() &&
                    entry["scores"].size() == 2 && entry.at("winner").is_number_unsigned() &&
                    entry["winner"].get<uint64_t>() < 16);
                for (const auto &team : entry["teams"])
                    persisted(team.is_number_unsigned() && team.get<uint64_t>() < 16);
                persisted(entry["teams"][0] != entry["teams"][1] &&
                          std::find(entry["teams"].begin(),
                                    entry["teams"].end(),
                                    entry["winner"]) != entry["teams"].end());
                for (const auto &score : entry["scores"])
                    persisted(score.is_number_unsigned() && score.get<uint64_t>() <= 65535);
            }
            return state;
        }

        bool prerequisitesComplete(const Json &state, size_t round, size_t match)
        {
            if (!round)
                return true;
            const auto &previous = state["rounds"][round - 1]["matches"];
            return previous[2 * match].value("winningTeamID", -1) >= 0 &&
                   previous[2 * match + 1].value("winningTeamID", -1) >= 0;
        }

        Json stateWithResults(const Json &row, const Json &journal)
        {
            auto state = row["state"];
            auto &rounds = state["rounds"];
            // Replay 0x141071680 checks the two previous matches. The document
            // consumer 0x141074530 reads global team indices and two UInt16 scores.
            for (const auto &entry : journal["results"])
                persisted(entry["round"].get<size_t>() < rounds.size() &&
                          entry["match"].get<size_t>() <
                              rounds[entry["round"].get<size_t>()]["matches"].size());
            for (size_t round = 0; round < rounds.size(); ++round)
            {
                auto &matches = rounds[round]["matches"];
                for (size_t index = 0; index < matches.size(); ++index)
                    for (const auto &entry : journal["results"])
                        if (entry["round"] == round && entry["match"] == index)
                        {
                            auto &match = matches[index];
                            persisted(match["lobbyID"] == entry["lobby"] &&
                                      match["teamIDs"] == entry["teams"] &&
                                      match["expired"] == false &&
                                      prerequisitesComplete(state, round, index));
                            bool reporterPresent = false;
                            for (const auto &team : match["teamIDs"])
                                for (const auto &player :
                                     state["teams"][team.get<size_t>()]["playerIDs"])
                                    reporterPresent =
                                        reporterPresent || player == entry["reporter"];
                            persisted(reporterPresent);
                            const auto winner = match.value("winningTeamID", -1);
                            persisted(winner == -1 || Json(winner) == entry["winner"]);
                            if (winner != -1 && match.contains("matchResultPayload"))
                                persisted(match["matchResultPayload"]["scores"] == entry["scores"]);
                            match["winningTeamID"] = entry["winner"];
                            match["matchResultPayload"] = {{"scores", entry["scores"]}};
                        }
                if (round + 1 == rounds.size())
                    continue;
                auto &next = rounds[round + 1]["matches"];
                for (size_t index = 0; index < next.size(); ++index)
                {
                    const auto left = matches[2 * index].value("winningTeamID", -1);
                    const auto right = matches[2 * index + 1].value("winningTeamID", -1);
                    auto &teams = next[index]["teamIDs"];
                    if (left >= 0 && right >= 0)
                    {
                        const auto advanced = Json::array(
                            {static_cast<uint64_t>(left), static_cast<uint64_t>(right)});
                        persisted(teams.empty() || teams == advanced);
                        teams = advanced;
                    }
                    else if (teams.size() == 2)
                        persisted((left < 0 || teams[0] == left) &&
                                  (right < 0 || teams[1] == right));
                }
            }
            validateBracket(state, row["id"].get<uint64_t>());
            return state;
        }

        void notifyUpdate(Reply &reply, const Json &row, const Json &journal, const Json &players);

        Reply submitResult(const std::filesystem::path &directory,
                           const platform::LobbyIdentity &id,
                           const Json &query,
                           const Json &state,
                           Json journal,
                           const Json &players,
                           const std::filesystem::path &path)
        {
            const auto lobby = query["lobbyID"].get<uint64_t>();
            for (const auto &entry : journal["results"])
                if (entry["lobby"] == lobby)
                {
                    if (entry["reporter"] != id.userId)
                        return {101, {}, "tournament-result-reporter-denied"};
                    if (entry["winner"] == query["winningTeamID"] &&
                        entry["scores"] == query["matchResultPayload"]["scores"])
                        return {0, {}, "tournament-result-retry"};
                    // Verified native completion 0x141078610 stops retrying 14536.
                    return {14536, {}, "tournament-result-conflict"};
                }
            for (size_t round = 0; round < state["rounds"].size(); ++round)
                for (size_t index = 0; index < state["rounds"][round]["matches"].size(); ++index)
                {
                    const auto &match = state["rounds"][round]["matches"][index];
                    if (match["lobbyID"] != lobby)
                        continue;
                    if (state["tournamentStatus"] != "PLAYING" || match["expired"] == true ||
                        match["teamIDs"].size() != 2 || !prerequisitesComplete(state, round, index))
                        return {108, {}, "tournament-result-match-unavailable"};
                    std::vector<uint64_t> participants;
                    for (const auto &team : match["teamIDs"])
                    {
                        const auto &members = state["teams"][team.get<size_t>()]["playerIDs"];
                        if (members.empty())
                            return {108, {}, "tournament-result-team-unassigned"};
                        for (const auto &user : members)
                            participants.push_back(user.get<uint64_t>());
                    }
                    if (std::find(participants.begin(), participants.end(), id.userId) ==
                        participants.end())
                        return {101, {}, "tournament-result-player-not-in-match"};
                    if (const auto error =
                            matchmakingHostAuthorized(directory, id, lobby, participants))
                        return {error, {}, "tournament-result-lobby-host-unavailable"};
                    if (std::find(match["teamIDs"].begin(),
                                  match["teamIDs"].end(),
                                  query["winningTeamID"]) == match["teamIDs"].end())
                        return {101, {}, "tournament-result-winner-not-in-match"};
                    if (match.value("winningTeamID", -1) != -1)
                    {
                        if (match["winningTeamID"] == query["winningTeamID"] &&
                            match.contains("matchResultPayload") &&
                            match["matchResultPayload"]["scores"] ==
                                query["matchResultPayload"]["scores"])
                            return {0, {}, "tournament-result-already-published"};
                        return {14536, {}, "tournament-result-already-complete"};
                    }
                    journal["results"].push_back({{"round", round},
                                                  {"match", index},
                                                  {"lobby", lobby},
                                                  {"reporter", id.userId},
                                                  {"teams", match["teamIDs"]},
                                                  {"winner", query["winningTeamID"]},
                                                  {"scores", query["matchResultPayload"]["scores"]},
                                                  {"recorded", now()}});
                    if (journal["results"].size() > 15)
                        return {108, {}, "tournament-result-capacity"};
                    // Validate the complete derived document before the one atomic write.
                    Json row = {{"id", query["tournamentID"]}, {"state", state}};
                    Reply reply{0, {}, "tournament-result-committed"};
                    notifyUpdate(reply, row, journal, players);
                    write(path, journal);
                    return reply;
                }
            return {108, {}, "tournament-result-lobby-unassigned"};
        }

        Json stateWithReadiness(Json state, uint64_t tournament, const Json &enrolled)
        {
            // Ready-up applies to the first unfinished match for each player,
            // not future rounds. Publication remains the bracket authority.
            std::set<uint64_t> visited;
            for (auto &round : state["rounds"])
                for (size_t index = 0; index < round["matches"].size(); ++index)
                {
                    auto &match = round["matches"][index];
                    if (match["expired"] == true || match.value("winningTeamID", -1) != -1)
                        continue;
                    for (const auto &team : match["teamIDs"])
                        for (const auto &user : state["teams"][team.get<size_t>()]["playerIDs"])
                        {
                            const auto player = user.get<uint64_t>();
                            const auto key = std::to_string(player);
                            if (!visited.insert(player).second || !enrolled.contains(key))
                                continue;
                            const auto &entry = enrolled[key];
                            const bool scoped = entry.contains("ready_round")
                                                    ? entry["ready_round"] == round["roundID"] &&
                                                          entry["ready_match"] == index
                                                    : round["roundID"] == 0;
                            if (entry["id"] == tournament && entry["ready"] == true && scoped &&
                                std::find(match["readyPlayerIDs"].begin(),
                                          match["readyPlayerIDs"].end(),
                                          user) == match["readyPlayerIDs"].end())
                                match["readyPlayerIDs"].push_back(user);
                        }
                }
            validateBracket(state, tournament);
            return state;
        }

        std::string stateHash(const Json &state)
        {
            const auto bytes = state.dump();
            const auto hash =
                crypto::sha256({reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()});
            std::string result;
            for (const auto byte : hash)
            {
                result.push_back("0123456789abcdef"[byte >> 4]);
                result.push_back("0123456789abcdef"[byte & 15]);
            }
            return result;
        }

        void notifyUpdate(Reply &reply, const Json &row, const Json &journal, const Json &players)
        {
            const auto tournament = row["id"].get<uint64_t>();
            const auto state =
                stateWithReadiness(stateWithResults(row, journal), tournament, players);
            const auto members = validateBracket(state, tournament);
            wire::Writer push;
            // Exact Replay decoder 0x14213F1C0, event 2010: one typed string,
            // no synthetic length field. Native consumer 0x14103F3F0 forwards it
            // to OnlineTournament_OnUpdateTournament and the bracket parser.
            push.u32(2010);
            push.text(state.dump());
            const auto hash = stateHash(state);
            for (const auto &player : players.items())
                if (player.value()["id"] == tournament && player.value()["accepted"] == true)
                {
                    const auto user = std::stoull(player.key());
                    if (!members.contains(user))
                        continue;
                    Delivery delivery{user, push.data, 250};
                    delivery.tournamentId = tournament;
                    delivery.tournamentStateHash = hash;
                    reply.deliveries.push_back(std::move(delivery));
                }
        }

        std::string unavailableHash(uint64_t tournament)
        {
            return stateHash(Json{{"tournamentID", tournament}, {"event", 2012}, {"reason", 0}});
        }

        Json searchIndex(const std::filesystem::path &root, uint32_t title)
        {
            Json index = {{"schema", 1},
                          {"title", title},
                          {"user", uint64_t{0}},
                          {"revision", uint64_t{0}},
                          {"searches", Json::object()}};
            if (std::filesystem::exists(root / "tournament-searches.json"))
                index = read(root / "tournament-searches.json", 128 * 1024);
            matchmaking_store::validateWrite({"tournament-searches.json", index}, title);
            return index;
        }

        Json searchDocument(const std::filesystem::path &root, uint32_t title, uint64_t search)
        {
            const auto name = "searches/" + std::to_string(search) + ".json";
            auto state = read(root / name, 128 * 1024);
            matchmaking_store::validateWrite({name, state}, title);
            return state;
        }

        bool participantStillCompeting(const Json &state, uint64_t user)
        {
            if (state["tournamentStatus"] != "PLAYING")
                return false;
            for (const auto &team : state["teams"])
                if (std::find(team["playerIDs"].begin(), team["playerIDs"].end(), Json(user)) !=
                    team["playerIDs"].end())
                {
                    const auto id = team["teamID"].get<int>();
                    for (size_t round = 0; round < state["rounds"].size(); ++round)
                        for (const auto &match : state["rounds"][round]["matches"])
                            if (std::find(match["teamIDs"].begin(),
                                          match["teamIDs"].end(),
                                          Json(id)) != match["teamIDs"].end())
                            {
                                const auto winner = match.value("winningTeamID", -1);
                                if (winner >= 0 && winner != id)
                                    return false;
                                if (round + 1 == state["rounds"].size() && winner == id)
                                    return false;
                            }
                    return true;
                }
            return false;
        }

        std::vector<matchmaking_store::Write> retireTournamentAssignments(
            const std::filesystem::path &directory,
            uint32_t title,
            uint64_t tournament,
            const Json &bracket,
            std::optional<size_t> eliminatedTeam = std::nullopt)
        {
            const auto root = directory / "matchmaking" / std::to_string(title);
            std::vector<matchmaking_store::Write> writes;
            std::set<uint64_t> lobbies, searches;
            std::set<uint64_t> departing;
            for (const auto &team : bracket["teams"])
                if (!eliminatedTeam || team["teamID"] == *eliminatedTeam)
                    for (const auto &user : team["playerIDs"])
                        departing.insert(user.get<uint64_t>());
            for (const auto &round : bracket["rounds"])
                for (const auto &match : round["matches"])
                    if ((!eliminatedTeam ||
                         (match.value("winningTeamID", -1) >= 0 &&
                          std::find(match["teamIDs"].begin(),
                                    match["teamIDs"].end(),
                                    Json(*eliminatedTeam)) != match["teamIDs"].end())) &&
                        match["lobbyID"].get<uint64_t>())
                    {
                        const auto lobby = match["lobbyID"].get<uint64_t>();
                        lobbies.insert(lobby);
                    }
            for (const auto lobby : lobbies)
            {
                const auto name = "lobbies/" + std::to_string(lobby) + ".json";
                auto state = read(root / name, 128 * 1024);
                matchmaking_store::validateWrite({name, state}, title);
                persisted(state.at("backend_doc").at("tournament").at("tournament_id") ==
                          tournament);
                const auto &bindings = state["backend_doc"].at("player_id_to_mm_id");
                persisted(bindings.is_object() && bindings.size() == state["members"].size());
                for (const auto &member : state["members"])
                {
                    const auto user = member.get<uint64_t>();
                    const auto key = std::to_string(user);
                    persisted(bindings.contains(key) && bindings[key].is_number_unsigned() &&
                              bindings[key].get<uint64_t>());
                    if (departing.contains(user))
                        searches.insert(bindings[key].get<uint64_t>());
                }
                if (!state.value("disbanded", false))
                {
                    state["disbanded"] = true;
                    writes.push_back({name, std::move(state)});
                }
            }
            auto index = searchIndex(root, title);
            if (!eliminatedTeam)
                for (const auto &entry : index["searches"].items())
                {
                    // A FORMING competition may also have authenticated searches
                    // which have not reserved a bracket slot yet. Retire these on
                    // whole-competition cancellation, preserving other tournaments.
                    const auto search = searchDocument(root, title, entry.value().get<uint64_t>());
                    if (search.at("tournament_id") == tournament)
                        searches.insert(search["id"].get<uint64_t>());
                }
            for (const auto &player : bracket["players"])
            {
                const auto key = std::to_string(player["playerID"].get<uint64_t>());
                if (!departing.contains(player["playerID"].get<uint64_t>()))
                    continue;
                if (index["searches"].contains(key))
                {
                    const auto search =
                        searchDocument(root, title, index["searches"][key].get<uint64_t>());
                    if (search.at("tournament_id") == tournament)
                        searches.insert(search["id"].get<uint64_t>());
                }
            }
            for (const auto search : searches)
            {
                auto state = searchDocument(root, title, search);
                persisted(state.at("tournament_id") == tournament);
                if (state["active"] != false)
                {
                    state["active"] = false;
                    writes.push_back(
                        {"searches/" + std::to_string(search) + ".json", std::move(state)});
                }
            }
            bool changed = false;
            for (auto item = index["searches"].begin(); item != index["searches"].end();)
                if (searches.contains(item.value().get<uint64_t>()))
                {
                    item = index["searches"].erase(item);
                    changed = true;
                }
                else
                    ++item;
            if (changed)
            {
                persisted(index["revision"].get<uint64_t>() != UINT64_MAX);
                index["revision"] = index["revision"].get<uint64_t>() + 1;
                writes.push_back({"tournament-searches.json", std::move(index)});
            }
            const auto assignmentPath = root / "current-lobbies.json";
            if (std::filesystem::exists(assignmentPath))
            {
                auto assignments = read(assignmentPath, 128 * 1024);
                matchmaking_store::validateWrite({"current-lobbies.json", assignments}, title);
                changed = false;
                for (auto item = assignments["lobbies"].begin();
                     item != assignments["lobbies"].end();)
                    if (lobbies.contains(item.value().get<uint64_t>()))
                    {
                        item = assignments["lobbies"].erase(item);
                        changed = true;
                    }
                    else
                        ++item;
                if (changed)
                {
                    persisted(assignments["revision"].get<uint64_t>() != UINT64_MAX);
                    assignments["revision"] = assignments["revision"].get<uint64_t>() + 1;
                    writes.push_back({"current-lobbies.json", std::move(assignments)});
                }
            }
            return writes;
        }

        bool retireUnavailableManagedTournament(const std::filesystem::path &directory,
                                                uint32_t title,
                                                uint64_t tournament,
                                                const Json &rows,
                                                Json &enrollment)
        {
            // Being absent from one user's bracket is not publication withdrawal.
            // Only globally unavailable managed publications enter this path.
            for (const auto &row : rows)
                if (row["id"] == tournament && row["expires"].get<uint64_t>() > now())
                    return false;
            if (terminated(directory, title, tournament))
                return false;
            const auto root = directory / "tournaments" / std::to_string(title);
            const auto path = formationPath(root, title, tournament);
            if (!std::filesystem::exists(path))
                return false;
            const auto formation = read(path, 128 * 1024);
            validateFormation(formation, title, tournament);
            auto row = formation["definition"];
            row["state"] = formation["state"];
            const auto journal = results(
                root / "results" / (std::to_string(tournament) + ".json"), title, tournament);
            const auto bracket = stateWithReadiness(
                stateWithResults(row, journal), tournament, enrollment["players"]);
            Json termination = {{"schema", 1},
                                {"title", title},
                                {"id", tournament},
                                {"expires", formation["expires"]},
                                {"actor", uint64_t{0}},
                                {"action", "publication-unavailable"},
                                {"recorded", now()},
                                {"state", bracket}};
            validateTournamentTermination(termination, title, tournament);
            auto writes = retireTournamentAssignments(directory, title, tournament, bracket);
            writes.push_back({"tournament-terminations/" + std::to_string(tournament) + ".json",
                              std::move(termination)});
            for (auto &player : enrollment["players"])
                if (player["id"] == tournament)
                {
                    // Reuse the native unavailable-publication event and retain
                    // registrations for authenticated leave. Never invent results.
                    player["live_updates"] = true;
                    player["ready"] = false;
                    player.erase("ready_round");
                    player.erase("ready_match");
                }
            commitEnrollment(directory, title, enrollment, std::nullopt, writes);
            return true;
        }

        std::optional<Reply> withdrawManagedParticipant(const std::filesystem::path &directory,
                                                        const platform::LobbyIdentity &identity,
                                                        const Json &row,
                                                        Json &enrollment,
                                                        const char *action)
        {
            // Local realm policy: cancel an unfinished managed competition. Do not
            // fabricate a host result, score or a retail forfeit reason. Eliminated
            // players and players in a finished final may leave normally.
            if (!row.contains("round_rules"))
                return std::nullopt;
            const auto tournament = row["id"].get<uint64_t>();
            const auto root = directory / "tournaments" / std::to_string(identity.titleId);
            const auto journal = results(root / "results" / (std::to_string(tournament) + ".json"),
                                         identity.titleId,
                                         tournament);
            const auto bracket = stateWithReadiness(
                stateWithResults(row, journal), tournament, enrollment["players"]);
            if (bracket["tournamentStatus"] != "PLAYING")
                return std::nullopt;
            if (!participantStillCompeting(bracket, identity.userId))
            {
                std::optional<size_t> eliminatedTeam;
                if (bracket["rounds"].back()["matches"][0].value("winningTeamID", -1) < 0)
                    for (const auto &team : bracket["teams"])
                        if (std::find(team["playerIDs"].begin(),
                                      team["playerIDs"].end(),
                                      Json(identity.userId)) != team["playerIDs"].end())
                            eliminatedTeam = team["teamID"].get<size_t>();
                const auto writes = retireTournamentAssignments(
                    directory, identity.titleId, tournament, bracket, eliminatedTeam);
                enrollment["players"].erase(std::to_string(identity.userId));
                Reply reply{0, {}, "tournament-completed-participant-left"};
                notifyUpdate(reply, row, journal, enrollment["players"]);
                commitEnrollment(directory, identity.titleId, enrollment, std::nullopt, writes);
                return reply;
            }
            Json termination = {{"schema", 1},
                                {"title", identity.titleId},
                                {"id", tournament},
                                {"expires", row["expires"]},
                                {"actor", identity.userId},
                                {"action", action},
                                {"recorded", now()},
                                {"state", bracket}};
            validateTournamentTermination(termination, identity.titleId, tournament);
            auto writes =
                retireTournamentAssignments(directory, identity.titleId, tournament, bracket);
            writes.push_back({"tournament-terminations/" + std::to_string(tournament) + ".json",
                              std::move(termination)});
            auto &players = enrollment["players"];
            players.erase(std::to_string(identity.userId));
            for (auto &player : players)
                if (player["id"] == tournament)
                {
                    // Idle event-2012 must be delivered even when live_updates was
                    // off or no round was allocated yet. Keep peer registrations
                    // for authenticated leave and diagnostics, but retire readiness.
                    player["live_updates"] = true;
                    player["ready"] = false;
                    player.erase("ready_round");
                    player.erase("ready_match");
                }
            commitEnrollment(directory, identity.titleId, enrollment, std::nullopt, writes);
            return Reply{0, {}, "tournament-playing-withdrawal-cancelled"};
        }

        std::optional<Json> formationSearch(const std::filesystem::path &directory,
                                            uint32_t title,
                                            uint64_t user)
        {
            const auto root = directory / "matchmaking" / std::to_string(title);
            matchmaking_store::recover(root, title);
            const auto index = searchIndex(root, title);
            const auto key = std::to_string(user);
            if (!index["searches"].contains(key))
                return std::nullopt;
            const auto search = searchDocument(root, title, index["searches"][key].get<uint64_t>());
            persisted(search.contains("tournament_id"));
            persisted(search["member_sessions"].contains(key));
            if (!search["active"].get<bool>() || search["expires"].get<uint64_t>() <= now())
                return std::nullopt;
            if (!lobby::sessionOnline(title,
                                      search["user"].get<uint64_t>(),
                                      search["owner_session"].get<std::string>()))
                return std::nullopt;
            // Bind every party member to the token/session which authorized this
            // search. A new login, cancellation or partial reassignment retires it.
            for (size_t i = 0; i < search["query"]["members"].size(); ++i)
            {
                const auto member = search["query"]["members"][i].get<uint64_t>();
                const auto memberKey = std::to_string(member);
                if (!index["searches"].contains(memberKey) ||
                    index["searches"][memberKey] != search["id"])
                    return std::nullopt;
                const auto player = read(root / "players" / (memberKey + ".json"), 128 * 1024);
                persisted(player.at("schema") == 1 && player.at("title") == title &&
                          player.at("user") == member);
                const auto session = search["member_sessions"][memberKey].get<std::string>();
                if (player.at("token_session") != session ||
                    player.at("token") != search["query"]["tokens"][i] ||
                    player.at("token_expires").get<uint64_t>() <= now() ||
                    !lobby::sessionOnline(title, member, session))
                    return std::nullopt;
            }
            return search;
        }

        bool assignedParty(const Json &search, const Json &bracket, const Json &enrolled)
        {
            const auto &query = search["query"];
            if (query["tournament"]["team_size"] != bracket["tournamentDefinition"]["teamSize"])
                return false;
            const Json *team = nullptr;
            for (const auto &candidate : bracket["teams"])
                if (std::find(candidate["playerIDs"].begin(),
                              candidate["playerIDs"].end(),
                              search["user"]) != candidate["playerIDs"].end())
                    team = &candidate;
            if (!team)
                return false;
            for (const auto &member : query["members"])
            {
                const auto key = std::to_string(member.get<uint64_t>());
                if (!enrolled.contains(key) || enrolled[key]["id"] != search["tournament_id"] ||
                    std::find((*team)["playerIDs"].begin(), (*team)["playerIDs"].end(), member) ==
                        (*team)["playerIDs"].end())
                    return false;
            }
            return true;
        }

        Delivery joinDelivery(uint64_t user, const Json &search, const Json &bracket)
        {
            // Exact Replay 0x14213F1C0 case 2009 and callback 0x14103F330:
            // UInt64 matchmaking ID followed by one typed bracket string.
            wire::Writer push;
            push.u32(2009);
            push.u64(search["id"]);
            push.text(bracket.dump());
            Delivery delivery;
            delivery.user = user;
            delivery.searchId = search["id"].get<uint64_t>();
            delivery.tournamentId = search["tournament_id"].get<uint64_t>();
            delivery.tournamentStateHash = stateHash(bracket);
            delivery.tournamentJoin = true;
            delivery.tournamentRefresh = true;
            delivery.delayMs = 500;
            delivery.payload = std::move(push.data);
            return delivery;
        }

        bool scheduleRound(const std::filesystem::path &directory,
                           uint32_t title,
                           const Json &row,
                           const Json &journal,
                           const Json &players,
                           uint64_t user,
                           Json &formation,
                           std::vector<matchmaking_store::Write> &writes)
        {
            if (!row.contains("round_rules") || !row.contains("native_map_pool") ||
                formation["state"]["tournamentStatus"] != "PLAYING")
                return false;
            Json updated = row;
            updated["state"] = formation["state"];
            const auto bracket = stateWithReadiness(
                stateWithResults(updated, journal), row["id"].get<uint64_t>(), players);
            for (size_t round = 0; round < bracket["rounds"].size(); ++round)
                for (size_t index = 0; index < bracket["rounds"][round]["matches"].size(); ++index)
                {
                    const auto &match = bracket["rounds"][round]["matches"][index];
                    if (match["expired"] == true || match.value("winningTeamID", -1) != -1 ||
                        match["teamIDs"].size() != 2)
                        continue;
                    Json teams = Json::array();
                    std::set<uint64_t> members;
                    for (const auto &team : match["teamIDs"])
                    {
                        teams.push_back(bracket["teams"][team.get<size_t>()]);
                        for (const auto &member : teams.back()["playerIDs"])
                            members.insert(member.get<uint64_t>());
                    }
                    if (!members.contains(user))
                        continue;
                    if (match["lobbyID"] != 0 || !prerequisitesComplete(bracket, round, index) ||
                        match["readyPlayerIDs"].size() != members.size())
                        return false;
                    std::set<uint64_t> searchIds;
                    std::vector<Json> searches;
                    for (const auto member : members)
                    {
                        const auto key = std::to_string(member);
                        if (!players.contains(key) || players[key]["id"] != row["id"] ||
                            players[key]["accepted"] != true ||
                            !players[key].contains("accepted_session") ||
                            !lobby::sessionOnline(
                                title, member, players[key]["accepted_session"].get<std::string>()))
                            return false;
                        const auto search = formationSearch(directory, title, member);
                        if (!search || search->at("tournament_id") != row["id"] ||
                            search->at("member_sessions").at(key) !=
                                players[key]["accepted_session"] ||
                            !assignedParty(*search, bracket, players))
                            return false;
                        for (const auto &partyMember : search->at("query")["members"])
                            if (!members.contains(partyMember.get<uint64_t>()))
                                return false;
                        if (searchIds.insert(search->at("id").get<uint64_t>()).second)
                            searches.push_back(*search);
                    }
                    const auto maps =
                        tournamentMapsForId(row["native_map_pool"], row["id"].get<uint64_t>());
                    auto plan = prepareTournamentRoundLobby(directory,
                                                            title,
                                                            row["id"].get<uint64_t>(),
                                                            static_cast<unsigned>(round),
                                                            static_cast<unsigned>(index),
                                                            teams,
                                                            searches,
                                                            row["round_rules"][round],
                                                            row["expires"].get<uint64_t>(),
                                                            maps[round]);
                    if (!plan)
                        return false;
                    auto &assigned = formation["state"]["rounds"][round]["matches"][index];
                    assigned["lobbyID"] = plan->lobbyId;
                    assigned["teamIDs"] = match["teamIDs"];
                    writes.insert(writes.end(), plan->writes.begin(), plan->writes.end());
                    return true;
                }
            return false;
        }
    } // namespace

    void retireUnavailableManagedTournaments(const std::filesystem::path &directory,
                                             uint32_t title,
                                             const std::function<void(const std::string &)> &log)
    {
        const auto root = directory / "tournaments" / std::to_string(title);
        const auto matchmakingRoot = directory / "matchmaking" / std::to_string(title);
        // Discovery from one domain must not bypass a malformed/symlinked path
        // in the other domain when the shared transaction publishes enrollment.
        for (const auto &owner :
             {root.parent_path(), root, matchmakingRoot.parent_path(), matchmakingRoot})
            if (std::filesystem::exists(owner))
                persisted(std::filesystem::is_directory(owner) &&
                          !std::filesystem::is_symlink(owner));
        matchmaking_store::recover(matchmakingRoot, title);
        const auto path = root / "enrollments.json";
        auto enrollment = enrollments(path, title);
        const auto rows = catalog(root / "catalog.json", title);
        std::set<uint64_t> competitions;
        for (const auto &player : enrollment["players"])
            competitions.insert(player["id"].get<uint64_t>());
        const auto formations = matchmakingRoot / "tournaments";
        if (std::filesystem::exists(formations))
        {
            persisted(std::filesystem::is_directory(formations) &&
                      !std::filesystem::is_symlink(formations));
            unsigned count = 0;
            for (const auto &entry : std::filesystem::directory_iterator(formations))
            {
                if (++count > 4096)
                {
                    log("TOURNAMENT maintenance formation discovery limit; title=" +
                        std::to_string(title));
                    break;
                }
                if (entry.path().extension() != ".json")
                    continue;
                const auto name = entry.path().stem().string();
                uint64_t tournament = 0;
                const auto parsed =
                    std::from_chars(name.data(), name.data() + name.size(), tournament);
                if (!entry.is_regular_file() || entry.is_symlink() || parsed.ec != std::errc{} ||
                    parsed.ptr != name.data() + name.size() || !tournament ||
                    std::to_string(tournament) != name)
                {
                    log("TOURNAMENT maintenance rejected invalid formation path; title=" +
                        std::to_string(title));
                    continue;
                }
                competitions.insert(tournament);
            }
        }
        for (const auto tournament : competitions)
            try
            {
                if (retireUnavailableManagedTournament(
                        directory, title, tournament, rows, enrollment))
                    log("TOURNAMENT maintenance retired unavailable publication; title=" +
                        std::to_string(title) + " tournament=" + std::to_string(tournament));
            }
            catch (const std::exception &)
            {
                // A bad terminal/formation cannot cancel a live competition or
                // prevent an independent competition from being examined.
                log("TOURNAMENT maintenance storage failure; title=" + std::to_string(title) +
                    " tournament=" + std::to_string(tournament));
            }
    }

    void validateTournamentFormation(const Json &state, uint32_t title, uint64_t id)
    {
        validateFormation(state, title, id);
    }

    void validateTournamentEnrollments(const Json &state, uint32_t title)
    {
        validateEnrollments(state, title);
    }

    void validateTournamentTermination(const Json &record, uint32_t title, uint64_t id)
    {
        persisted(record.is_object() && record.size() == 8 && record.at("schema") == 1 &&
                  record.at("title") == title && record.at("id") == id && id &&
                  record.at("expires").is_number_unsigned() &&
                  record.at("actor").is_number_unsigned() &&
                  record.at("recorded").is_number_unsigned() &&
                  record["recorded"].get<uint64_t>() && record.at("action").is_string() &&
                  (record["action"] == "leave" || record["action"] == "decline" ||
                   record["action"] == "publication-unavailable"));
        const auto members = validateBracket(record.at("state"), id);
        if (record["action"] == "publication-unavailable")
            persisted(record["actor"] == 0 && record["expires"].get<uint64_t>());
        else
            persisted(record["recorded"].get<uint64_t>() <= record["expires"].get<uint64_t>() &&
                      members.contains(record["actor"].get<uint64_t>()) &&
                      participantStillCompeting(record["state"], record["actor"].get<uint64_t>()));
    }

    std::optional<Reply> startTournamentSearch(const std::filesystem::path &directory,
                                               const platform::LobbyIdentity &id,
                                               const Json &query)
    {
        if (!query.contains("tournament"))
            return std::nullopt;
        // Original StartMatchmaking 0x14104A450 emits this exact object. Member
        // tokens and their live sessions were checked by the ordinary task-18 path.
        const auto &request = query["tournament"];
        wire::require(request.is_object() && request.size() == 1 && request.contains("team_size") &&
                      request["team_size"].is_number_unsigned() &&
                      request["team_size"].get<uint64_t>() >= 1 &&
                      request["team_size"].get<uint64_t>() <= 4 &&
                      query["members"].size() <= request["team_size"].get<uint64_t>() &&
                      !query.contains("private_lobby") &&
                      !query.contains("lobby_id_to_presence_join") &&
                      !query.contains("player_id_to_presence_join"));
        const auto tournamentRoot = directory / "tournaments" / std::to_string(id.titleId);
        auto enrolled = enrollments(tournamentRoot / "enrollments.json", id.titleId);
        const auto key = std::to_string(id.userId);
        if (!enrolled["players"].contains(key))
            return Reply{14526, {}, "tournament-search-player-not-enrolled"};
        const auto tournament = enrolled["players"][key]["id"].get<uint64_t>();
        const auto rows = catalog(tournamentRoot / "catalog.json", id.titleId);
        const Json *publication = nullptr;
        for (const auto &candidate : rows)
            if (candidate["id"] == tournament && candidate["expires"].get<uint64_t>() > now() &&
                (candidate.contains("formation") || published(rows, tournament, id.userId)))
                publication = &candidate;
        if (!publication ||
            publication->at("state")["tournamentDefinition"]["teamSize"] != request["team_size"])
            return Reply{108, {}, "tournament-search-publication-unavailable"};
        Json row = *publication;
        std::optional<Json> formation;
        bool formationChanged = false, enrollmentChanged = false;
        if (row.contains("formation"))
        {
            for (const auto &member : query["members"])
            {
                const auto memberKey = std::to_string(member.get<uint64_t>());
                if (!enrolled["players"].contains(memberKey) ||
                    enrolled["players"][memberKey]["id"] != tournament)
                    return Reply{101, {}, "tournament-search-party-not-registered"};
            }
            const auto original = formationRecord(tournamentRoot, id.titleId, row);
            auto reserved = reserveParty(original, id.userId, query["members"]);
            if (reserved.is_null())
                return Reply{108, {}, "tournament-formation-party-capacity-or-conflict"};
            row["state"] = reserved["state"];
            formationChanged = reserved != original;
            formation = std::move(reserved);
            for (const auto &member : query["members"])
                enrollmentChanged =
                    (enrolled["players"][std::to_string(member.get<uint64_t>())].erase(
                         "formation_disbanded") != 0) ||
                    enrollmentChanged;
        }
        const auto journal =
            results(tournamentRoot / "results" / (std::to_string(tournament) + ".json"),
                    id.titleId,
                    tournament);
        const auto bracket =
            stateWithReadiness(stateWithResults(row, journal), tournament, enrolled["players"]);
        const Json *partyTeam = nullptr;
        for (const auto &team : bracket["teams"])
            if (std::find(team["playerIDs"].begin(), team["playerIDs"].end(), Json(id.userId)) !=
                team["playerIDs"].end())
                partyTeam = &team;
        persisted(partyTeam != nullptr);
        for (const auto &member : query["members"])
        {
            const auto memberKey = std::to_string(member.get<uint64_t>());
            if (!enrolled["players"].contains(memberKey) ||
                enrolled["players"][memberKey]["id"] != tournament ||
                std::find((*partyTeam)["playerIDs"].begin(),
                          (*partyTeam)["playerIDs"].end(),
                          member) == (*partyTeam)["playerIDs"].end())
                return Reply{101, {}, "tournament-search-party-not-assigned"};
        }
        const auto root = directory / "matchmaking" / std::to_string(id.titleId);
        auto index = searchIndex(root, id.titleId);
        const auto fingerprint = wire::base64Encode(crypto::sha256(id.key));
        Json search;
        if (const auto previous = formationSearch(directory, id.titleId, id.userId);
            previous && !formationChanged && previous->at("user") == id.userId &&
            previous->at("query") == query && previous->at("tournament_id") == tournament &&
            previous->at("owner_session") == fingerprint)
            search = *previous;
        else
        {
            if (enrolled["players"][key]["accepted"] == true)
                return Reply{108, {}, "tournament-search-already-accepted"};
            uint64_t searchId = 0;
            do
                searchId = wire::at<uint64_t>(crypto::random(8), 0);
            while (!searchId || std::filesystem::exists(root / "searches" /
                                                        (std::to_string(searchId) + ".json")));
            search = {{"schema", 1},
                      {"title", id.titleId},
                      {"user", id.userId},
                      {"revision", uint64_t{0}},
                      {"id", searchId},
                      {"lobby_id", uint64_t{0}},
                      {"tournament_id", tournament},
                      {"query", query},
                      {"expires",
                       std::min({now() + 3600, id.expires, row.at("expires").get<uint64_t>()})},
                      {"active", true},
                      {"owner_session", fingerprint},
                      {"member_sessions", Json::object()}};
            std::set<uint64_t> obsolete;
            for (const auto &member : query["members"])
            {
                const auto memberKey = std::to_string(member.get<uint64_t>());
                if (index["searches"].contains(memberKey))
                    obsolete.insert(index["searches"][memberKey].get<uint64_t>());
                const auto player = read(root / "players" / (memberKey + ".json"), 128 * 1024);
                search["member_sessions"][memberKey] = player.at("token_session");
                index["searches"][memberKey] = searchId;
            }
            persisted(index["revision"].get<uint64_t>() != UINT64_MAX);
            index["revision"] = index["revision"].get<uint64_t>() + 1;
            std::vector<matchmaking_store::Write> writes;
            for (const auto old : obsolete)
            {
                auto prior = searchDocument(root, id.titleId, old);
                persisted(prior.contains("tournament_id"));
                prior["active"] = false;
                writes.push_back({"searches/" + std::to_string(old) + ".json", std::move(prior)});
            }
            writes.push_back({"searches/" + std::to_string(searchId) + ".json", search});
            writes.push_back({"tournament-searches.json", index});
            if (formation)
                writes.push_back(
                    {"tournaments/" + std::to_string(tournament) + ".json", *formation});
            if (enrollmentChanged)
                writes.push_back({"tournament-enrollments.json", enrolled});
            matchmaking_store::commit(root, id.titleId, writes);
        }
        wire::Writer result;
        result.text(Json{{"mm_id", search["id"]}}.dump());
        Reply reply{0, {std::move(result.data)}, "tournament-search-joined"};
        for (const auto &member : query["members"])
            if (enrolled["players"][std::to_string(member.get<uint64_t>())]["accepted"] != true)
                reply.deliveries.push_back(joinDelivery(member.get<uint64_t>(), search, bracket));
        return reply;
    }

    std::optional<Delivery> currentTournamentDelivery(const std::filesystem::path &directory,
                                                      uint32_t title,
                                                      uint64_t user)
    {
        matchmaking_store::recover(directory / "matchmaking" / std::to_string(title), title);
        const auto root = directory / "tournaments" / std::to_string(title);
        const auto enrollmentPath = root / "enrollments.json";
        if (!std::filesystem::exists(enrollmentPath))
            return std::nullopt;
        auto enrollment = enrollments(enrollmentPath, title);
        const auto key = std::to_string(user);
        if (!enrollment["players"].contains(key))
            return std::nullopt;
        const auto tournament = enrollment["players"][key]["id"].get<uint64_t>();
        const auto rows = catalog(root / "catalog.json", title);
        retireUnavailableManagedTournament(directory, title, tournament, rows, enrollment);
        const auto *row = published(rows, tournament, user);
        Json activeRow;
        if (row && row->contains("formation") &&
            (row->at("state")["tournamentStatus"] == "FORMING" || row->contains("round_rules")))
        {
            auto formation = formationRecord(root, title, *row);
            bool changed = false;
            if (formation["state"]["tournamentStatus"] == "FORMING" &&
                formationAccepted(formation, title, enrollment["players"]))
            {
                formation["state"]["tournamentStatus"] = "PLAYING";
                changed = true;
            }
            std::vector<matchmaking_store::Write> writes;
            const auto journal = results(
                root / "results" / (std::to_string(tournament) + ".json"), title, tournament);
            changed = scheduleRound(directory,
                                    title,
                                    *row,
                                    journal,
                                    enrollment["players"],
                                    user,
                                    formation,
                                    writes) ||
                      changed;
            if (changed)
            {
                writes.push_back(
                    {"tournaments/" + std::to_string(tournament) + ".json", formation});
                matchmaking_store::commit(
                    directory / "matchmaking" / std::to_string(title), title, writes);
                activeRow = *row;
                activeRow["state"] = formation["state"];
                row = &activeRow;
            }
        }
        if (enrollment["players"][key]["accepted"] != true &&
            (row || !terminated(directory, title, tournament)))
        {
            if (!row && enrollment["players"][key].value("formation_disbanded", false))
                for (const auto &publication : rows)
                    if (publication["id"] == tournament && publication.contains("formation") &&
                        publication["expires"].get<uint64_t>() > now() &&
                        publication["state"]["tournamentStatus"] == "FORMING")
                    {
                        wire::Writer push;
                        push.u32(2011);
                        push.u64(tournament);
                        Delivery delivery;
                        delivery.user = user;
                        delivery.tournamentId = tournament;
                        delivery.tournamentStateHash = stateHash(publication["state"]);
                        delivery.tournamentFormationDisband = true;
                        delivery.tournamentRefresh = true;
                        delivery.delayMs = 500;
                        delivery.payload = std::move(push.data);
                        return delivery;
                    }
            const auto search = formationSearch(directory, title, user);
            if (!row || !search || search->at("tournament_id") != tournament)
                return std::nullopt;
            const auto journal = results(
                root / "results" / (std::to_string(tournament) + ".json"), title, tournament);
            const auto bracket = stateWithReadiness(
                stateWithResults(*row, journal), tournament, enrollment["players"]);
            if (!assignedParty(*search, bracket, enrollment["players"]))
                return std::nullopt;
            return joinDelivery(user, *search, bracket);
        }
        if (!enrollment["players"][key].value("live_updates", false) && !roundAllocated(row))
            return std::nullopt;
        if (row && !row->value("live_updates", false) && !roundAllocated(row))
            return std::nullopt;
        wire::Writer push;
        Delivery delivery;
        delivery.user = user;
        delivery.tournamentId = tournament;
        delivery.delayMs = 500;
        delivery.tournamentRefresh = true;
        if (!row)
        {
            // Replay 0x14213F1C0 reads 2012 as ID, UInt64 reason and string.
            // Game 0x14103F470 forwards it to the native disband consumer.
            // Reason zero is this local realm's generic unavailable-publication reason.
            push.u32(2012);
            push.u64(tournament);
            push.u64(0);
            push.text("Tournament publication is no longer available");
            delivery.tournamentUnavailable = true;
            delivery.tournamentStateHash = unavailableHash(tournament);
        }
        else
        {
            const auto journal = results(
                root / "results" / (std::to_string(tournament) + ".json"), title, tournament);
            const auto state = stateWithReadiness(
                stateWithResults(*row, journal), tournament, enrollment["players"]);
            push.u32(2010);
            push.text(state.dump());
            delivery.tournamentStateHash = stateHash(state);
        }
        delivery.payload = std::move(push.data);
        return delivery;
    }

    std::optional<Delivery> currentTournamentRoundDelivery(const std::filesystem::path &directory,
                                                           uint32_t title,
                                                           uint64_t user)
    {
        matchmaking_store::recover(directory / "matchmaking" / std::to_string(title), title);
        const auto root = directory / "tournaments" / std::to_string(title);
        const auto enrolled = enrollments(root / "enrollments.json", title);
        const auto key = std::to_string(user);
        if (!enrolled["players"].contains(key) || enrolled["players"][key]["accepted"] != true)
            return std::nullopt;
        const auto tournament = enrolled["players"][key]["id"].get<uint64_t>();
        const auto rows = catalog(root / "catalog.json", title);
        const auto *row = published(rows, tournament, user);
        if (!row || !row->contains("round_rules") || !row->contains("native_map_pool") ||
            row->at("state")["tournamentStatus"] != "PLAYING" ||
            !enrolled["players"][key].contains("accepted_session") ||
            !lobby::sessionOnline(
                title, user, enrolled["players"][key]["accepted_session"].get<std::string>()))
            return std::nullopt;
        const auto bracket = stateWithResults(
            *row,
            results(root / "results" / (std::to_string(tournament) + ".json"), title, tournament));
        for (const auto &round : bracket["rounds"])
            for (const auto &match : round["matches"])
                if (match["expired"] == false && match.value("winningTeamID", -1) == -1)
                    for (const auto &team : match["teamIDs"])
                        for (const auto &member : bracket["teams"][team.get<size_t>()]["playerIDs"])
                            if (member == user)
                                return match["lobbyID"] == 0
                                           ? std::nullopt
                                           : tournamentRoundLobbyDelivery(
                                                 directory,
                                                 title,
                                                 user,
                                                 tournament,
                                                 match["lobbyID"].get<uint64_t>(),
                                                 Json{{"tournament_id", tournament},
                                                      {"round_id", round["roundID"]},
                                                      {"lobby_to_tournament_team_ids",
                                                       {{"0", match["teamIDs"][0]},
                                                        {"1", match["teamIDs"][1]}}}});
        return std::nullopt;
    }

    bool tournamentDeliveryValid(const std::filesystem::path &directory,
                                 uint32_t title,
                                 const Delivery &delivery)
    {
        if (!delivery.tournamentId)
            return true;
        matchmaking_store::recover(directory / "matchmaking" / std::to_string(title), title);
        const auto root = directory / "tournaments" / std::to_string(title);
        const auto state = enrollments(root / "enrollments.json", title);
        const auto key = std::to_string(delivery.user);
        if (!state["players"].contains(key))
            return false;
        const auto &player = state["players"][key];
        if (delivery.tournamentRoundLobby)
        {
            if (player["id"] != delivery.tournamentId || player["accepted"] != true)
                return false;
            const auto current = currentTournamentRoundDelivery(directory, title, delivery.user);
            return current && current->lobbyId == delivery.lobbyId &&
                   current->searchId == delivery.searchId &&
                   current->tournamentStateHash == delivery.tournamentStateHash;
        }
        if (delivery.tournamentFormationDisband)
        {
            if (player["id"] != delivery.tournamentId || player["accepted"] != false ||
                !player.value("formation_disbanded", false))
                return false;
            for (const auto &row : catalog(root / "catalog.json", title))
                if (row["id"] == delivery.tournamentId && row.contains("formation") &&
                    row["expires"].get<uint64_t>() > now() &&
                    row["state"]["tournamentStatus"] == "FORMING")
                    return !validateBracket(row["state"], delivery.tournamentId)
                                .contains(delivery.user) &&
                           stateHash(row["state"]) == delivery.tournamentStateHash;
            return false;
        }
        if (player["id"] != delivery.tournamentId ||
            (player["accepted"] == delivery.tournamentJoin &&
             !(delivery.tournamentUnavailable &&
               terminated(directory, title, delivery.tournamentId))))
            return false;
        if (delivery.tournamentRefresh && !delivery.tournamentJoin &&
            !player.value("live_updates", false))
        {
            const auto rows = catalog(root / "catalog.json", title);
            const auto *row = published(rows, delivery.tournamentId, delivery.user);
            if (!roundAllocated(row))
                return false;
        }
        const auto rows = catalog(root / "catalog.json", title);
        const auto *row = published(rows, delivery.tournamentId, delivery.user);
        if (delivery.tournamentRefresh && !delivery.tournamentJoin && row &&
            !row->value("live_updates", false) && !roundAllocated(row))
            return false;
        if (delivery.tournamentUnavailable)
            return !row && delivery.tournamentStateHash == unavailableHash(delivery.tournamentId);
        if (!row)
            return false;
        if (delivery.tournamentJoin)
        {
            const auto search = formationSearch(directory, title, delivery.user);
            if (!search || search->at("id") != delivery.searchId ||
                search->at("tournament_id") != delivery.tournamentId)
                return false;
            if (!assignedParty(
                    *search,
                    stateWithResults(*row,
                                     results(root / "results" /
                                                 (std::to_string(delivery.tournamentId) + ".json"),
                                             title,
                                             delivery.tournamentId)),
                    state["players"]))
                return false;
        }
        const auto journal =
            results(root / "results" / (std::to_string(delivery.tournamentId) + ".json"),
                    title,
                    delivery.tournamentId);
        return stateHash(stateWithReadiness(stateWithResults(*row, journal),
                                            delivery.tournamentId,
                                            state["players"])) == delivery.tournamentStateHash;
    }

    std::optional<Reply> tournamentServices(const std::filesystem::path &directory,
                                            const platform::LobbyIdentity &id,
                                            uint8_t service,
                                            uint8_t task,
                                            wire::Reader &params)
    {
        if (service != 145 || (task != 19 && task != 20 && task != 21 && task != 22 && task != 23 &&
                               task != 28 && task != 29))
            return std::nullopt;
        uint64_t tournament = 0;
        bool accepted = true;
        Json query;
        if (task == 19 || task == 23 || task == 28)
        {
            tournament = params.u64();
            wire::require(tournament != 0);
            if (task == 19)
                wire::require(params.u64() == 0xFFFFFFFFULL);
            if (task == 23)
                accepted = params.boolean();
        }
        if (task == 29)
        {
            // Replay 0x142136240 binds one bdStringResult; game registration
            // 0x1410758E0 supplies these exact two JSON keys in a 256-byte buffer.
            const auto bytes = params.text(256);
            query = document(bytes);
            wire::require(query.is_object() && query.contains("tournament_name") &&
                          query.contains("data_center") &&
                          boundedText(query["tournament_name"], 128) &&
                          boundedText(query["data_center"], 64) && query.size() == 2);
        }
        if (task == 21)
        {
            // Exact Replay 0x1421366F0 writes one typed string and binds no result.
            // Native 0x141076A10 formats this document into a 256-byte buffer.
            query = document(params.text(256));
            wire::require(
                query.is_object() && query.size() == 4 && query.contains("tournamentID") &&
                query["tournamentID"].is_number_unsigned() &&
                query["tournamentID"].get<uint64_t>() && query.contains("lobbyID") &&
                query["lobbyID"].is_number_unsigned() && query["lobbyID"].get<uint64_t>() &&
                query.contains("winningTeamID") && query["winningTeamID"].is_number_unsigned() &&
                query["winningTeamID"].get<uint64_t>() < 16 &&
                query.contains("matchResultPayload") && query["matchResultPayload"].is_object() &&
                query["matchResultPayload"].size() == 1 &&
                query["matchResultPayload"].contains("scores") &&
                query["matchResultPayload"]["scores"].is_array() &&
                query["matchResultPayload"]["scores"].size() == 2);
            for (const auto &score : query["matchResultPayload"]["scores"])
                wire::require(score.is_number_unsigned() && score.get<uint64_t>() <= 65535);
            tournament = query["tournamentID"].get<uint64_t>();
        }
        params.end();
        matchmaking_store::recover(directory / "matchmaking" / std::to_string(id.titleId),
                                   id.titleId);
        const auto root = directory / "tournaments" / std::to_string(id.titleId);
        const auto path = root / "enrollments.json";
        auto state = enrollments(path, id.titleId);
        const auto previous = state;
        auto &players = state["players"];
        const auto key = std::to_string(id.userId);
        if (task == 22)
        {
            const auto tournamentLeft =
                players.contains(key) ? players[key]["id"].get<uint64_t>() : 0;
            Reply reply{0, {}, "tournament-owner-left-all"};
            std::optional<Json> leaveFormation;
            std::optional<Json> leaveRow;
            std::optional<Json> leaveRows;
            // Leave must still succeed when publication is unavailable. A malformed
            // notification source cannot undo the authenticated enrollment removal.
            try
            {
                const auto rows = catalog(root / "catalog.json", id.titleId);
                leaveRows = rows;
                const auto *row = published(rows, tournamentLeft, id.userId);
                if (row)
                    leaveRow = *row;
            }
            catch (const std::exception &)
            {
                reply.detail = "tournament leave notification source unavailable";
            }
            if (leaveRows && tournamentLeft)
                retireUnavailableManagedTournament(
                    directory, id.titleId, tournamentLeft, *leaveRows, state);
            // Fail closed on retirement/transaction errors. The fallback below
            // applies to notification-source failures, never a half-committed
            // cancellation whose active lobbies could otherwise survive the leave.
            if (leaveRow)
                if (auto withdrawal =
                        withdrawManagedParticipant(directory, id, *leaveRow, state, "leave"))
                    return withdrawal;
            try
            {
                const auto *row = leaveRow ? &*leaveRow : nullptr;
                if (row && row->contains("formation"))
                {
                    auto formation = formationRecord(root, id.titleId, *row);
                    releaseFormingParty(formation, id.userId, players, reply);
                    players.erase(key);
                    Json updated = *row;
                    updated["state"] = formation["state"];
                    // Notification data can be unavailable independently of a
                    // valid release. Keep its coupled snapshot for the commit.
                    leaveFormation = formation;
                    const auto journal =
                        results(root / "results" / (std::to_string(tournamentLeft) + ".json"),
                                id.titleId,
                                tournamentLeft);
                    notifyUpdate(reply, updated, journal, players);
                }
                else if (row)
                {
                    auto remaining = players;
                    remaining.erase(key);
                    const auto journal =
                        results(root / "results" / (std::to_string(tournamentLeft) + ".json"),
                                id.titleId,
                                tournamentLeft);
                    notifyUpdate(reply, *row, journal, remaining);
                }
            }
            catch (const std::exception &)
            {
                reply.detail = "tournament leave notification source unavailable";
            }
            if (leaveFormation)
            {
                commitEnrollment(directory, id.titleId, state, leaveFormation);
                return reply;
            }
            if (players.erase(key))
                write(path, state);
            return reply;
        }
        const auto rows = catalog(root / "catalog.json", id.titleId);
        if (players.contains(key))
            retireUnavailableManagedTournament(
                directory, id.titleId, players[key]["id"].get<uint64_t>(), rows, state);
        if (task == 29)
        {
            const Json *selected = nullptr;
            for (const auto &row : rows)
                if (row["name"] == query["tournament_name"] &&
                    row["data_center"] == query["data_center"] &&
                    row["expires"].get<uint64_t>() > now() && row["registration_open"] == true)
                    selected = &row;
            if (!selected)
                return Reply{108, {}, "tournament-registration-unpublished"};
            tournament = (*selected)["id"].get<uint64_t>();
            if (!selected->contains("formation") && !published(rows, tournament, id.userId))
                return Reply{101, {}, "tournament-participant-not-authorized"};
            if (selected->contains("formation") &&
                (*selected)["state"]["tournamentStatus"] == "PLAYING" &&
                !published(rows, tournament, id.userId))
                return Reply{108, {}, "tournament-registration-already-formed"};
            if (players.contains(key) && players[key]["id"] != tournament)
                return Reply{101, {}, "tournament-conflicting-enrollment"};
            if (!players.contains(key))
            {
                if (players.size() >= 4096)
                    return Reply{108, {}, "tournament-enrollment-capacity"};
                players[key] = {{"id", tournament}, {"accepted", false}, {"ready", false}};
                if (selected->value("live_updates", false))
                    players[key]["live_updates"] = true;
                if (selected->contains("formation"))
                    commitEnrollment(directory, id.titleId, state);
                else
                    write(path, state);
            }
            wire::Writer result;
            result.text(
                Json{{"start_search_offset_seconds", (*selected)["start_search_offset_seconds"]}}
                    .dump());
            return Reply{0, {std::move(result.data)}, "tournament-owner-registered"};
        }
        if (!players.contains(key))
            return Reply{notEnrolled, {}, "tournament-player-not-enrolled"};
        auto &entry = players[key];
        if (task == 20)
            tournament = entry["id"].get<uint64_t>();
        if (entry["id"] != tournament)
            return Reply{task == 21 ? 14529 : notEnrolled, {}, "tournament-owner-id-mismatch"};
        const auto *row = published(rows, tournament, id.userId);
        if (!row)
            return Reply{task == 21 ? 14529 : notEnrolled,
                         {},
                         "tournament-publication-expired-or-owner-absent"};
        const auto resultPath = root / "results" / (std::to_string(tournament) + ".json");
        const auto journal = results(resultPath, id.titleId, tournament);
        const auto bracket = stateWithResults(*row, journal);
        if (task == 21)
        {
            if (entry["accepted"] != true)
                return Reply{101, {}, "tournament-result-join-not-accepted"};
            return submitResult(directory, id, query, bracket, journal, players, resultPath);
        }
        if (task == 20)
        {
            wire::Writer result;
            result.text(stateWithReadiness(bracket, tournament, players).dump());
            return Reply{0, {std::move(result.data)}, "tournament-owner-state"};
        }
        if (task == 23 && !accepted)
            if (auto withdrawal = withdrawManagedParticipant(directory, id, *row, state, "decline"))
                return withdrawal;
        if (task == 23 && !accepted)
            players.erase(key);
        else if (task == 23 || task == 28)
        {
            entry["accepted"] = true;
            if (row->contains("formation"))
                entry["accepted_session"] = wire::base64Encode(crypto::sha256(id.key));
        }
        else if (task == 19)
        {
            if (row->contains("formation") &&
                (bracket["tournamentStatus"] != "PLAYING" || entry["accepted"] != true ||
                 entry.value("accepted_session", std::string{}) !=
                     wire::base64Encode(crypto::sha256(id.key))))
                return Reply{101, {}, "tournament-ready-formation-not-accepted"};
            bool assigned = false;
            for (const auto &round : bracket["rounds"])
                for (size_t index = 0; index < round["matches"].size(); ++index)
                {
                    const auto &match = round["matches"][index];
                    if (assigned || match["expired"] == true ||
                        match.value("winningTeamID", -1) != -1)
                        continue;
                    for (const auto &team : match["teamIDs"])
                        for (const auto &user : bracket["teams"][team.get<size_t>()]["playerIDs"])
                            if (user == id.userId)
                            {
                                assigned = true;
                                entry["ready_round"] = round["roundID"];
                                entry["ready_match"] = index;
                            }
                }
            if (!assigned)
                return Reply{108, {}, "tournament-ready-match-unassigned"};
            entry["ready"] = true;
        }
        stateWithReadiness(bracket, tournament, players);
        Reply reply{0,
                    {},
                    task == 19   ? "tournament-owner-ready"
                    : task == 28 ? "tournament-owner-rejoined"
                    : accepted   ? "tournament-owner-join-accepted"
                                 : "tournament-owner-join-declined"};
        if (state != previous || (task == 19 && row->contains("round_rules")))
        {
            if (row->contains("formation"))
            {
                auto formation = formationRecord(root, id.titleId, *row);
                if (task == 23 && !accepted)
                    releaseFormingParty(formation, id.userId, players, reply);
                else if (formation["state"]["tournamentStatus"] == "FORMING" &&
                         formationAccepted(formation, id.titleId, players))
                    formation["state"]["tournamentStatus"] = "PLAYING";
                std::vector<matchmaking_store::Write> roundWrites;
                const bool scheduled = scheduleRound(directory,
                                                     id.titleId,
                                                     *row,
                                                     journal,
                                                     players,
                                                     id.userId,
                                                     formation,
                                                     roundWrites);
                if (state == previous && !scheduled)
                    return reply;
                Json updated = *row;
                updated["state"] = formation["state"];
                notifyUpdate(reply, updated, journal, players);
                commitEnrollment(directory, id.titleId, state, formation, roundWrites);
                for (const auto &player : players.items())
                    if (player.value()["id"] == tournament && player.value()["accepted"] == true)
                        if (auto delivery = currentTournamentRoundDelivery(
                                directory, id.titleId, std::stoull(player.key())))
                            reply.deliveries.push_back(std::move(*delivery));
            }
            else
            {
                notifyUpdate(reply, *row, journal, players);
                write(path, state);
            }
        }
        return reply;
    }
} // namespace services
