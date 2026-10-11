#include "host_os.h"
#include "matchmaking_store.h"
#include "tournament_services.h"
#include <algorithm>
#include <charconv>
#include <memory>
#include <set>
#include <stdexcept>

namespace matchmaking_store
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t documentLimit = 128 * 1024;
        constexpr size_t journalLimit = 32 * 1024 * 1024;
        constexpr size_t entryLimit = 202; // Lobby, at most 200 searches, player index.

        void require(bool valid)
        {
            if (!valid)
                throw std::runtime_error("Invalid matchmaking transaction state");
        }

        uint64_t number(const std::string &text)
        {
            uint64_t value = 0;
            const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
            require(result.ec == std::errc{} && result.ptr == text.data() + text.size() && value &&
                    std::to_string(value) == text);
            return value;
        }

        Json parse(const std::string &bytes)
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
            auto value = Json::parse(bytes, callback, false);
            require(unique && value.is_object());
            return value;
        }

        Json read(const std::filesystem::path &path)
        {
            const auto handle = CreateFileW(path.c_str(),
                                            GENERIC_READ,
                                            FILE_SHARE_READ,
                                            nullptr,
                                            OPEN_EXISTING,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Matchmaking transaction read failed");
            const std::unique_ptr<void, decltype(&CloseHandle)> file(handle, &CloseHandle);
            LARGE_INTEGER size{};
            require(GetFileSizeEx(handle, &size) && size.QuadPart >= 0 &&
                    static_cast<uint64_t>(size.QuadPart) <= journalLimit);
            std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
            DWORD received = 0;
            if (!bytes.empty() &&
                (!ReadFile(
                     handle, bytes.data(), static_cast<DWORD>(bytes.size()), &received, nullptr) ||
                 received != bytes.size()))
                throw std::runtime_error("Matchmaking transaction snapshot read failed");
            return parse(bytes);
        }

        void write(const std::filesystem::path &path, const Json &document)
        {
            const auto bytes = document.dump();
            require(bytes.size() <= journalLimit);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            const auto handle = CreateFileW(pending.c_str(),
                                            GENERIC_WRITE,
                                            0,
                                            nullptr,
                                            CREATE_ALWAYS,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Matchmaking transaction write failed");
            {
                const std::unique_ptr<void, decltype(&CloseHandle)> file(handle, &CloseHandle);
                DWORD written = 0;
                if (!WriteFile(handle,
                               bytes.data(),
                               static_cast<DWORD>(bytes.size()),
                               &written,
                               nullptr) ||
                    written != bytes.size() || !FlushFileBuffers(handle))
                    throw std::runtime_error("Matchmaking transaction flush failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Matchmaking transaction publication failed");
        }

        void validateEntry(const Write &entry, uint32_t title)
        {
            const auto &state = entry.document;
            require(state.is_object() && state.at("schema") == 1 && state.at("title") == title &&
                    state.dump().size() <= (entry.path == "tournament-enrollments.json"
                                                ? 2 * 1024 * 1024
                                                : documentLimit));
            if (entry.path == "tournament-enrollments.json")
            {
                services::validateTournamentEnrollments(state, title);
                return;
            }
            if (entry.path == "current-lobbies.json" || entry.path == "tournament-searches.json")
            {
                const auto field = entry.path == "current-lobbies.json" ? "lobbies" : "searches";
                require(state.at("user") == 0 && state.at("revision").is_number_unsigned() &&
                        state.at(field).is_object() && state[field].size() <= 4096);
                for (const auto &assignment : state[field].items())
                {
                    (void)number(assignment.key());
                    require(assignment.value().is_number_unsigned() &&
                            assignment.value().get<uint64_t>());
                }
                return;
            }
            const auto slash = entry.path.find('/');
            require(slash != std::string::npos && entry.path.ends_with(".json"));
            const auto kind = entry.path.substr(0, slash);
            const auto id = number(entry.path.substr(slash + 1, entry.path.size() - slash - 6));
            require((kind == "lobbies" || kind == "searches" || kind == "tournaments" ||
                     kind == "tournament-terminations") &&
                    state.at("id").is_number_unsigned() && state["id"] == id &&
                    state.at("expires").is_number_unsigned());
            if (kind == "tournaments")
            {
                services::validateTournamentFormation(state, title, id);
                return;
            }
            if (kind == "tournament-terminations")
            {
                services::validateTournamentTermination(state, title, id);
                return;
            }
            if (kind == "searches")
            {
                require(state.at("user").is_number_unsigned() && state["user"].get<uint64_t>() &&
                        state.at("revision").is_number_unsigned() &&
                        state.at("lobby_id").is_number_unsigned() &&
                        state.at("query").is_object() && state.at("active").is_boolean());
                // Session bindings use the same persisted layout for public,
                // private and tournament searches. Older unbound ordinary
                // searches are readable, but cannot authorize report credit.
                if (state.contains("member_sessions") || state.contains("owner_session") ||
                    state.contains("tournament_id"))
                {
                    require(
                        state.at("owner_session").is_string() &&
                        state["owner_session"].get_ref<const std::string &>().size() == 44 &&
                        state.at("member_sessions").is_object() &&
                        !state["member_sessions"].empty() && state["member_sessions"].size() <= 200 &&
                        state["query"].at("members").is_array() &&
                        state["query"]["members"].size() == state["member_sessions"].size() &&
                        state["query"].at("tokens").is_array() &&
                        state["query"]["tokens"].size() == state["member_sessions"].size() &&
                        state["member_sessions"].contains(
                            std::to_string(state["user"].get<uint64_t>())) &&
                        state["member_sessions"][std::to_string(state["user"].get<uint64_t>())] ==
                            state["owner_session"]);
                    std::set<uint64_t> members;
                    for (size_t i = 0; i < state["query"]["members"].size(); ++i)
                    {
                        const auto &member = state["query"]["members"][i];
                        require(member.is_number_unsigned() && member.get<uint64_t>() &&
                                members.insert(member.get<uint64_t>()).second &&
                                state["query"]["tokens"][i].is_number_unsigned() &&
                                state["query"]["tokens"][i].get<uint64_t>());
                        const auto &session =
                            state["member_sessions"].at(std::to_string(member.get<uint64_t>()));
                        require(session.is_string() &&
                                session.get_ref<const std::string &>().size() == 44);
                    }
                }
                if (state.contains("tournament_id"))
                {
                    require(state["tournament_id"].is_number_unsigned() &&
                            state["tournament_id"].get<uint64_t>() &&
                            state["member_sessions"].size() <= 4 &&
                            state["query"].at("tournament").at("team_size").is_number_unsigned() &&
                            state["query"]["tournament"]["team_size"].get<uint64_t>() >= 1 &&
                            state["query"]["tournament"]["team_size"].get<uint64_t>() <= 4 &&
                            state["member_sessions"].size() <=
                                state["query"]["tournament"]["team_size"].get<uint64_t>());
                    if (state["lobby_id"] != 0)
                        require(state.at("round_id").is_number_unsigned() &&
                                state["round_id"].get<uint64_t>() < 4 &&
                                state.at("match_id").is_number_unsigned() &&
                                state["match_id"].get<uint64_t>() < 8);
                }
                else
                    require(state["lobby_id"].get<uint64_t>() != 0);
                return;
            }
            require(state.at("owner").is_number_unsigned() && state["owner"].get<uint64_t>() &&
                    state.at("update_id").is_number_unsigned() &&
                    state["update_id"].get<uint64_t>() && state.at("members").is_array() &&
                    !state["members"].empty() && state["members"].size() <= 200 &&
                    state.at("host_doc").is_object() && state.at("backend_doc").is_object() &&
                    state["host_doc"].dump().size() < 16384 &&
                    state["backend_doc"].dump().size() < 16384 &&
                    state["host_doc"].at("listen_server").at("host_player_id") == state["owner"] &&
                    state["host_doc"]["listen_server"].at("host_address").is_string() &&
                    state["backend_doc"].at("lobby_id") == id &&
                    (!state.contains("disbanded") || state["disbanded"].is_boolean()));
            std::set<uint64_t> members;
            for (const auto &member : state["members"])
                require(member.is_number_unsigned() && member.get<uint64_t>() &&
                        members.insert(member.get<uint64_t>()).second);
            require(members.contains(state["owner"].get<uint64_t>()));
            if (state.contains("host_ready"))
                require(state["host_ready"].is_boolean());
            validatePendingJoins(state);
            if (state.contains("match_selection"))
            {
                const auto &selection = state.at("match_selection");
                require(selection.is_object());
                if (selection.contains("split_parties_for_team_balance"))
                    require(selection["split_parties_for_team_balance"].is_boolean());
            }
            if (state["backend_doc"].contains("tournament"))
            {
                // Exact Replay 0x1410451D0: UInt64 ID, two UInt32 global team
                // indices, UInt16 round. Validate the entire closed-match layout.
                const auto &metadata = state["backend_doc"]["tournament"];
                require(metadata.is_object() && metadata.size() == 3 &&
                        metadata.at("tournament_id").is_number_unsigned() &&
                        metadata["tournament_id"].get<uint64_t>() &&
                        metadata.at("round_id").is_number_unsigned() &&
                        metadata["round_id"].get<uint64_t>() < 4);
                const auto &mapping = metadata.at("lobby_to_tournament_team_ids");
                require(mapping.is_object() && mapping.size() == 2 &&
                        mapping.at("0").is_number_unsigned() && mapping["0"].get<uint64_t>() < 16 &&
                        mapping.at("1").is_number_unsigned() && mapping["1"].get<uint64_t>() < 16 &&
                        mapping["0"] != mapping["1"]);
                const auto &teams = state["backend_doc"].at("team_balance").at("teams");
                require(teams.is_object() && teams.size() == 2 && teams.at("0").is_array() &&
                        teams.at("1").is_array() && !teams["0"].empty() && teams["0"].size() <= 4 &&
                        teams["0"].size() == teams["1"].size() &&
                        state["host_doc"].at("lobby_open_for_pres_join") == false &&
                        state["host_doc"].at("team_balance").at("can_change_teams") == false &&
                        !state.contains("public_pool"));
                std::set<uint64_t> assigned;
                for (const auto &team : teams)
                    for (const auto &member : team)
                        require(member.is_number_unsigned() &&
                                assigned.insert(member.get<uint64_t>()).second);
                require(assigned == members);
            }
            if (state.contains("owner_session"))
            {
                require(state["owner_session"].is_string());
                const auto &fingerprint = state["owner_session"].get_ref<const std::string &>();
                require(fingerprint.size() == 44 && fingerprint.back() == '=' &&
                        std::all_of(fingerprint.begin(),
                                    fingerprint.end() - 1,
                                    [](char c)
                                    {
                                        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                               (c >= '0' && c <= '9') || c == '+' || c == '/';
                                    }));
            }
            if (state.contains("maximum_members"))
                require(state["maximum_members"].is_number_unsigned() &&
                        state["maximum_members"].get<uint64_t>() <= 200 &&
                        members.size() <= state["maximum_members"].get<uint64_t>());
            for (const auto *key : {"operator_start_requested", "operator_bots_requested"})
                if (state.contains(key))
                    require(state[key].is_boolean());
            if (state.contains("operator_bot_count"))
                require(state["operator_bot_count"].is_number_unsigned() &&
                        state["operator_bot_count"].get<uint64_t>() > 0 &&
                        state["operator_bot_count"].get<uint64_t>() < 200 &&
                        state.value("operator_bots_requested", false));
            if (state.contains("squad_fill"))
            {
                const auto &fill = state["squad_fill"];
                const auto &balance = state["backend_doc"].at("team_balance");
                const auto &squads = balance.at("squads");
                const auto size = balance.at("squad_size").get<unsigned>();
                require(fill.is_object() && fill.size() <= 200 &&
                        squads.is_object() && squads.size() <= 200 && size > 0 && size <= 200);
                std::set<uint64_t> assigned;
                for (const auto &preference : fill.items())
                    require(preference.value().is_boolean() && squads.contains(preference.key()));
                for (const auto &squad : squads)
                {
                    require(squad.is_array());
                    uint64_t occupied = 0;
                    for (const auto &user : squad)
                    {
                        require(user.is_number_unsigned() && members.contains(user.get<uint64_t>()) &&
                                assigned.insert(user.get<uint64_t>()).second);
                        const auto key = std::to_string(user.get<uint64_t>());
                        const auto &slots = state["backend_doc"].at("player_id_to_slots");
                        occupied += 1 + slots.value(key, uint64_t{0});
                    }
                    require(occupied <= size);
                }
                require(assigned == members);
            }
            if (state.contains("operator_start_overrides"))
            {
                const auto &saved = state["operator_start_overrides"];
                require(saved.is_object() && saved.size() <= 8);
                for (const auto &setting : saved.items())
                    require(!setting.key().empty() && setting.key().size() <= 128 &&
                            (setting.value().is_null() || setting.value().is_boolean() ||
                             setting.value().is_number_integer() || setting.value().is_number_float() ||
                             (setting.value().is_string() && setting.value().get_ref<const std::string &>().size() < 128)));
            }
            if (state.contains("operator_bots_capacity"))
                require(state["operator_bots_capacity"].is_number_unsigned() &&
                        state["operator_bots_capacity"].get<uint64_t>() > 0 &&
                        state["operator_bots_capacity"].get<uint64_t>() <= 200 &&
                        state.value("operator_bots_requested", false) &&
                        state.at("maximum_members") == 12);
        }

        std::vector<Write> validate(const Json &journal, uint32_t title)
        {
            require(journal.size() == 5 && journal.at("schema") == 1 &&
                    journal.at("title") == title && journal.at("revision").is_number_unsigned() &&
                    journal["revision"].get<uint64_t>() && journal.at("phase").is_string() &&
                    journal.at("writes").is_array() && journal["writes"].size() <= entryLimit);
            const bool prepared = journal["phase"] == "prepared";
            require(prepared || journal["phase"] == "applied");
            require(prepared ? !journal["writes"].empty() : journal["writes"].empty());
            std::vector<Write> entries;
            std::set<std::string> paths;
            for (const auto &entry : journal["writes"])
            {
                require(entry.is_object() && entry.size() == 2 && entry.at("path").is_string());
                Write snapshot{entry["path"].get<std::string>(), entry.at("document")};
                validateEntry(snapshot, title);
                require(paths.insert(snapshot.path).second);
                entries.push_back(std::move(snapshot));
            }
            return entries;
        }

        uint64_t recoverPending(const std::filesystem::path &root, uint32_t title)
        {
            require(root.filename() == std::to_string(title));
            const auto path = root / "transaction.json";
            if (!std::filesystem::exists(path))
                return 0;
            auto journal = read(path);
            const auto entries = validate(journal, title);
            if (journal["phase"] == "prepared")
            {
                // All paths and complete snapshots were validated first. No reader
                // under the store mutex can observe a partially applied transaction.
                for (const auto &entry : entries)
                {
                    // This one named cross-domain document has a fixed target.
                    // Journal paths cannot select arbitrary parents or files.
                    const auto target = entry.path == "tournament-enrollments.json"
                                            ? root.parent_path().parent_path() / "tournaments" /
                                                  std::to_string(title) / "enrollments.json"
                                            : root / entry.path;
                    write(target, entry.document);
                }
                journal["phase"] = "applied";
                journal["writes"] = Json::array();
                // Retain a flushed completion marker. Deleting the journal could
                // resurrect an older prepared transaction after a power failure.
                write(path, journal);
            }
            return journal["revision"].get<uint64_t>();
        }
    } // namespace

    void initialize(const std::filesystem::path &directory)
    {
        const auto root = directory / "matchmaking";
        if (!std::filesystem::exists(root))
            return;
        size_t count = 0;
        for (const auto &entry : std::filesystem::directory_iterator(root))
        {
            require(entry.is_directory() && ++count <= 1024);
            const auto title = number(entry.path().filename().string());
            require(title <= UINT32_MAX);
            recover(entry.path(), static_cast<uint32_t>(title));
        }
    }

    void recover(const std::filesystem::path &root, uint32_t title)
    {
        (void)recoverPending(root, title);
    }

    void validateWrite(const Write &write, uint32_t title)
    {
        validateEntry(write, title);
    }

    void validatePendingJoins(const nlohmann::json &lobby)
    {
        if (!lobby.contains("pending_join_members"))
            return;
        const auto &pending = lobby.at("pending_join_members");
        const auto &members = lobby.at("members");
        require(pending.is_array() && pending.size() < members.size());
        std::set<uint64_t> unique;
        for (const auto &user : pending)
            require(user.is_number_unsigned() && user.get<uint64_t>() &&
                    user != lobby.at("owner") &&
                    std::find(members.begin(), members.end(), user) != members.end() &&
                    unique.insert(user.get<uint64_t>()).second);
    }

    void commit(const std::filesystem::path &root, uint32_t title, std::span<const Write> writes)
    {
        const auto revision = recoverPending(root, title);
        require(revision != UINT64_MAX);
        Json journal = {{"schema", 1},
                        {"title", title},
                        {"revision", revision + 1},
                        {"phase", "prepared"},
                        {"writes", Json::array()}};
        for (const auto &entry : writes)
            journal["writes"].push_back({{"path", entry.path}, {"document", entry.document}});
        (void)validate(journal, title);
        write(root / "transaction.json", journal);
        (void)recoverPending(root, title);
    }
} // namespace matchmaking_store
