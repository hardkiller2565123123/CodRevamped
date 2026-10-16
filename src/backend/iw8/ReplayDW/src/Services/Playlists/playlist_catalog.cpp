#include "playlist_catalog.h"
#include "crypto.h"
#include "wire.h"
#include <algorithm>
#include <cmath>
#include <charconv>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        struct CachedDocument
        {
            std::filesystem::file_time_type modified;
            uintmax_t size = 0;
            Json value;
            std::string sha256;
        };

        std::string digest(const std::string &bytes)
        {
            const auto hash =
                crypto::sha256({reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()});
            constexpr char digits[] = "0123456789abcdef";
            std::string result;
            result.reserve(hash.size() * 2);
            for (const auto value : hash)
            {
                result.push_back(digits[value >> 4]);
                result.push_back(digits[value & 15]);
            }
            return result;
        }

        Json document(const std::filesystem::path &path,
                      uintmax_t maximum,
                      const Json &fallback,
                      std::string *sha256 = nullptr)
        {
            if (!std::filesystem::exists(path))
                return fallback;
            const auto size = std::filesystem::file_size(path);
            wire::require(size <= maximum);
            const auto modified = std::filesystem::last_write_time(path);
            // services::dispatch serializes access, including catalog refreshes.
            static std::map<std::filesystem::path, CachedDocument> cache;
            const auto found = cache.find(path);
            if (found != cache.end() && found->second.modified == modified &&
                found->second.size == size)
            {
                if (sha256)
                    *sha256 = found->second.sha256;
                return found->second.value;
            }
            std::ifstream in(path, std::ios::binary);
            if (!in)
                throw std::runtime_error("Playlist catalog read failed");
            const std::string bytes((std::istreambuf_iterator<char>(in)), {});
            wire::require(bytes.size() <= maximum);
            auto value = Json::parse(bytes);
            const auto hash = digest(bytes);
            cache[path] = {modified, size, value, hash};
            if (sha256)
                *sha256 = hash;
            return value;
        }

        std::string identifier(const Json &value, size_t capacity)
        {
            wire::require(value.is_string());
            const auto name = value.get<std::string>();
            wire::require(!name.empty() && name.size() < capacity &&
                          std::all_of(name.begin(),
                                      name.end(),
                                      [](unsigned char c)
                                      {
                                          return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                                 (c >= '0' && c <= '9') || c == '_' || c == '.';
                                      }));
            return name;
        }

        unsigned number(const Json &value, unsigned maximum)
        {
            wire::require(value.is_number_integer());
            const auto result = value.get<int64_t>();
            wire::require(result >= 0 && static_cast<uint64_t>(result) <= maximum);
            return static_cast<unsigned>(result);
        }

        unsigned capacityValue(const Json &value)
        {
            if (!value.is_string())
            {
                const auto capacity = number(value, 200);
                wire::require(capacity > 0);
                return capacity;
            }
            const auto text = value.get<std::string>();
            unsigned capacity = 0;
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), capacity);
            wire::require(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() &&
                          capacity > 0 && capacity <= 200);
            return capacity;
        }

        std::optional<unsigned> capacityRule(const Json &rules, const Json &bindings)
        {
            wire::require(rules.is_object());
            const auto native = bindings.value("party_maxplayers", std::string("party_maxplayers"));
            std::optional<unsigned> result;
            for (const auto &row : rules.items())
            {
                auto name = row.key();
                if (name.starts_with("set "))
                    name.erase(0, 4);
                while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
                    name.pop_back();
                if (name != "party_maxplayers" && name != native)
                    continue;
                const auto value = capacityValue(row.value());
                wire::require(!result || *result == value);
                result = value;
            }
            return result;
        }

        void overrides(Json &out, const Json &source, const Json &bindings)
        {
            wire::require(source.is_object());
            for (auto it = source.begin(); it != source.end(); ++it)
            {
                auto name = it.key();
                if (name.starts_with("set "))
                    name.erase(0, 4);
                while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
                    name.pop_back();
                name = identifier(name, 128);
                if (bindings.contains(name))
                    name = identifier(bindings.at(name), 128);
                wire::require(it.value().is_string() || it.value().is_number() ||
                              it.value().is_boolean());
                const auto text =
                    it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
                wire::require(text.size() < 256 && text.find('\0') == std::string::npos);
                out[name] = it.value();
            }
        }

        void assign(Json &out, const Json &bindings, const std::string &name, const Json &value)
        {
            out[bindings.contains(name) ? identifier(bindings.at(name), 128) : name] = value;
        }
    } // namespace

    std::optional<PlaylistSelection> selectPlaylist(const std::filesystem::path &directory,
                                                    uint32_t title,
                                                    const Json &query,
                                                    const std::string &requiredMap,
                                                    unsigned preferredPlaylist)
    {
        const auto root = directory / "playlists" / std::to_string(title);
        if (!requiredMap.empty())
            (void)identifier(requiredMap, 24);
        std::string catalogHash;
        const auto catalog = document(root / "catalog.json", 409600, Json(), &catalogHash);
        if (catalog.is_null())
            return std::nullopt;
        wire::require(catalog.is_object() && catalog.at("playlists").is_array() &&
                      catalog.at("gametypes").is_array());
        wire::require(catalog["playlists"].size() <= 128 && catalog["gametypes"].size() <= 64);
        const auto version = number(catalog.at("system").at("version"), UINT32_MAX);
        const auto &filter = query.at("ruleset_payload").at("filter");
        wire::require(filter.is_object());
        const auto clientVersion = number(filter.at("playlist_version"), UINT32_MAX);
        const auto requested = number(filter.at("playlist_id"), 127);
        // A 1.20 executable can send the publisher's native playlist version,
        // while our offline bootstrap catalogue has revision 1.  Accept this
        // alias ONLY for this title and our own revision-1 bootstrap; a real
        // publisher catalog still requires an exact version match.
        const bool localBootstrapVersionAlias =
            title == 5800u && version == 1u && clientVersion != version;
        if (clientVersion != version && !localBootstrapVersionAlias)
        {
            std::printf("[MM-CATALOG] reject=version title=%u requestedId=%u clientVersion=%u catalogVersion=%u\n",
                title, requested, clientVersion, version);
            return std::nullopt;
        }
        if (localBootstrapVersionAlias)
            std::printf("[MM-CATALOG] local-version-alias title=%u requestedId=%u clientVersion=%u bootstrapVersion=%u\n",
                title, requested, clientVersion, version);
        std::vector<unsigned> candidates{requested};
        if (query.contains("playlist_config"))
        {
            // Quick Play's filter playlist_id is only the category anchor.
            // playlist_config contains the actual modes selected in its UI.
            candidates.clear();
            wire::require(query["playlist_config"].is_array() &&
                          query["playlist_config"].size() <= 128);
            for (const auto &group : query["playlist_config"])
            {
                wire::require(group.at("playlist_ids").is_array() &&
                              group["playlist_ids"].size() <= 128);
                for (const auto &value : group["playlist_ids"])
                {
                    const auto id = number(value, 127);
                    if (std::find(candidates.begin(), candidates.end(), id) == candidates.end())
                        candidates.push_back(id);
                }
            }
            wire::require(!candidates.empty());
            if (!preferredPlaylist)
            {
                const auto first = wire::at<uint64_t>(crypto::random(8), 0) % candidates.size();
                std::rotate(candidates.begin(), candidates.begin() + first, candidates.end());
            }
        }
        const auto policy = document(root / "policy.json", 16384, Json::object());
        wire::require(policy.is_object());
        if (policy.contains("split_parties_for_team_balance"))
            wire::require(policy["split_parties_for_team_balance"].is_boolean());
        if (preferredPlaylist)
        {
            const auto match = std::find(candidates.begin(), candidates.end(), preferredPlaylist);
            if (match == candidates.end())
                return std::nullopt;
            candidates = {*match};
        }
        if (!preferredPlaylist && policy.contains("preferred_playlist_id"))
        {
            const auto preferred = number(policy["preferred_playlist_id"], 127);
            const auto match = std::find(candidates.begin(), candidates.end(), preferred);
            if (match != candidates.end())
                std::rotate(candidates.begin(), match, match + 1);
        }
        const auto bindings =
            document(root / "native-dvar-names.json", 1024 * 1024, Json::object());
        wire::require(bindings.is_object());
        const auto packages = document(root / "packages.json", 512 * 1024, Json());
        std::optional<std::set<std::string>> installedMaps;
        if (!packages.is_null())
        {
            wire::require(packages.is_object() && packages.at("schema") == 1 &&
                          packages.at("title") == title &&
                          packages.at("playlist_version") == version &&
                          packages.at("catalog_sha256") == catalogHash &&
                          packages.at("maps").is_array() && packages["maps"].size() <= 256);
            const auto revision = packages.at("revision").get<std::string>();
            wire::require(revision.size() == 64 &&
                          revision.find_first_not_of("0123456789abcdef") == std::string::npos);
            auto revisionPayload = packages;
            revisionPayload.erase("revision");
            wire::require(digest(revisionPayload.dump()) == revision);
            std::set<std::string> known;
            installedMaps.emplace();
            for (const auto &map : packages["maps"])
            {
                const auto name = identifier(map.at("name"), 24);
                wire::require(map.at("available").is_boolean() && known.insert(name).second);
                if (map["available"].get<bool>())
                    installedMaps->insert(name);
            }
            std::set<std::string> declared;
            for (const auto &playlist : catalog["playlists"])
                for (const auto &entry : playlist.at("maps"))
                    declared.insert(identifier(entry.at("map"), 24));
            wire::require(known == declared);
        }
        std::set<std::string> maps;
        if (policy.contains("available_maps"))
        {
            wire::require(policy["available_maps"].is_array() &&
                          policy["available_maps"].size() <= 256);
            for (const auto &map : policy["available_maps"])
                wire::require(maps.insert(identifier(map, 24)).second);
        }
        std::map<unsigned, Json> playlists;
        std::map<std::string, Json> modes;
        for (const auto &mode : catalog["gametypes"])
        {
            const auto name = identifier(mode.at("gametype"), 32);
            wire::require(modes.emplace(name, mode).second);
            (void)identifier(mode.at("script"), 32);
            if (mode.contains("teamCount"))
                (void)number(mode.at("teamCount"), 200);
        }
        for (const auto &playlist : catalog["playlists"])
        {
            const auto id = number(playlist.at("playlist"), 127);
            wire::require(id && playlists.emplace(id, playlist).second);
            wire::require(playlist.at("maps").is_array() && !playlist["maps"].empty() &&
                          playlist["maps"].size() <= 1024);
            for (const auto &entry : playlist["maps"])
            {
                (void)identifier(entry.at("map"), 24);
                wire::require(modes.contains(identifier(entry.at("gametype"), 32)));
                wire::require(entry.at("weight").is_number() &&
                              std::isfinite(entry["weight"].get<double>()) &&
                              entry["weight"].get<double>() >= 0);
            }
        }
        std::printf("[MM-CATALOG] search title=%u requestedId=%u requestedVersion=%u catalogVersion=%u candidates=%zu availableMapsPolicy=%s installedPackages=%s requiredMap=%s\n",
            title, requested, clientVersion, version, candidates.size(),
            policy.contains("available_maps") ? "yes" : "no",
            installedMaps ? "yes" : "no",
            requiredMap.empty() ? "none" : requiredMap.c_str());
        for (const auto id : candidates)
        {
            const auto found = playlists.find(id);
            if (found == playlists.end())
            {
                std::printf("[MM-CATALOG] reject=unknown-playlist title=%u id=%u\n", title, id);
                continue;
            }
            const auto &playlist = found->second;
            Json searchConfiguration = Json::object();
            if (query.contains("playlist_config"))
            {
                bool matched = false;
                for (const auto &group : query["playlist_config"])
                {
                    if (std::none_of(group.at("playlist_ids").begin(),
                                     group.at("playlist_ids").end(),
                                     [&](const Json &value)
                                     {
                                         return number(value, 127) == id;
                                     }))
                        continue;
                    Json configuration = Json::object();
                    for (const auto *key : {"max_slots", "min_slots", "num_teams"})
                        if (group.contains(key))
                        {
                            const auto value = number(group[key], 200);
                            wire::require(key != std::string_view("max_slots") || value > 0);
                            configuration[key] = value;
                        }
                    if (configuration.contains("min_slots") && configuration.contains("max_slots"))
                        wire::require(configuration["min_slots"] <= configuration["max_slots"]);
                    if (group.contains("build_name_context"))
                        configuration["build_name_context"] =
                            identifier(group["build_name_context"], 32);
                    wire::require(!matched || configuration == searchConfiguration);
                    matched = true;
                    searchConfiguration = std::move(configuration);
                }
                wire::require(matched);
            }
            Json weights = Json::object();
            std::vector<Json> eligible;
            // Replay's native ChooseEntry weights the first 20 entries. Every map
            // outside a restricted local installation receives an explicit zero.
            const auto count = std::min(size_t{20}, playlist["maps"].size());
            for (size_t i = 0; i < count; ++i)
            {
                const auto &entry = playlist["maps"][i];
                const auto map = entry["map"].get<std::string>();
                const bool allowed = (!policy.contains("available_maps") || maps.contains(map)) &&
                                     (!installedMaps || installedMaps->contains(map)) &&
                                     (requiredMap.empty() || requiredMap == map) &&
                                     entry["weight"].get<double>() > 0;
                weights[map] = allowed ? entry["weight"] : Json(0);
                if (allowed)
                    eligible.push_back(entry);
            }
            if (eligible.empty())
            {
                std::printf("[MM-CATALOG] reject=no-eligible-map title=%u id=%u inspected=%zu policy=%s packages=%s\n",
                    title, id, count, policy.contains("available_maps") ? "restricted" : "all",
                    installedMaps ? "restricted" : "all");
                continue;
            }
            std::set<unsigned> teamCounts;
            std::set<unsigned> squadSizes;
            bool squadMode = false, ordinaryMode = false;
            for (const auto &entry : eligible)
            {
                const auto &mode = modes.at(entry["gametype"].get<std::string>());
                if (mode.contains("teamCount"))
                    teamCounts.insert(number(mode.at("teamCount"), 200));
                if (mode.value("script", std::string{}) == "br")
                {
                    squadMode = true;
                    const auto size = number(mode.at("teamSize"), 200);
                    wire::require(size > 0);
                    squadSizes.insert(size);
                }
                else
                    ordinaryMode = true;
            }
            // The current mixed-mode publications agree on team count. A future
            // mixed team/FFA publication cannot safely inherit its first entry's
            // team layout before the native client selects the actual mode.
            wire::require(teamCounts.size() <= 1);
            wire::require(!(squadMode && ordinaryMode) && squadSizes.size() <= 1);
            const bool splitParties =
                policy.value("split_parties_for_team_balance", false) && !squadMode;
            Json rules = query.at("ruleset_payload"),
                 dvars = rules.value("dvar_overrides", Json::object());
            wire::require(dvars.is_object());
            // Replay Playlist_RunRules already applies the complete native
            // publication. The backend document is a separate, 128-entry override
            // window, not a second copy of that publication (Plunder has 161).
            // Preserve the caller's backend rules and explicit local policy here;
            // keep catalog rules in match metadata for every selected entry.
            assign(dvars, bindings, "online_matchmaking_use_map_weights", 1);
            assign(dvars, bindings, "replay_dw_forceStart", 0);
            assign(dvars, bindings, "replay_dw_fillBots", 0);
            assign(dvars, bindings, "replay_dw_botCount", 0);
            if (squadMode)
            {
                assign(dvars, bindings, "br_minplayers", 2);
                // Replay otherwise retains the party host's local squad
                // assignment after parsing a correct DW squad document.
                assign(
                    dvars, bindings, "online_matchmaking_update_party_team_squad_assignments", 1);
            }
            if (policy.contains("minimum_players"))
            {
                const auto minimum = number(policy["minimum_players"], 200);
                wire::require(minimum > 0);
                assign(dvars, bindings, "party_minplayers", minimum);
                rules["min_slots_scale_percent"] = 0;
            }
            if (policy.contains("minimum_lobby_seconds"))
                assign(dvars,
                       bindings,
                       "party_minLobbyTime",
                       number(policy["minimum_lobby_seconds"], 2147483));
            if (splitParties)
            {
                // Replay ReadyTeams otherwise evaluates the original private
                // subparty as an indivisible group, even after DW balances its
                // primaries. This rule accompanies the explicit split policy;
                // normal party grouping retains the native partition check.
                assign(dvars, bindings, "online_matchmaking_ignore_partition_value", 1);
            }
            if (policy.contains("dvar_overrides"))
                overrides(dvars, policy["dvar_overrides"], bindings);
            if (squadMode)
                assign(dvars, bindings, "online_matchmaking_ignore_partition_value", 0);
            wire::require(dvars.size() <= 128);
            rules["dvar_overrides"] = dvars;
            rules["map_weights"] = weights;
            rules["filter"]["playlist_id"] = id;
            rules["filter"]["playlist_version"] =
                localBootstrapVersionAlias ? clientVersion : version;
            PlaylistSelection selected;
            std::set<unsigned> capacities;
            for (const auto &entry : eligible)
            {
                const auto &mode = modes.at(entry["gametype"].get<std::string>());
                auto capacity =
                    capacityRule(catalog.value("global_dvars", Json::object()), bindings);
                if (const auto limit = capacityRule(mode.value("dvars", Json::object()), bindings))
                    capacity = limit;
                if (const auto limit =
                        capacityRule(playlist.value("dvars", Json::object()), bindings))
                    capacity = limit;
                // The native selector computes each Quick Play group's slots
                // from its full rule layers. The anchor's lobby_slots belongs
                // to another group and must not replace the selected one.
                if (searchConfiguration.contains("max_slots"))
                    capacity = number(searchConfiguration["max_slots"], 200);
                else if (capacity && (*capacity & 1))
                    ++*capacity; // Replay Playlist_RunRules rounds before backend overrides
                if (const auto limit = capacityRule(dvars, bindings))
                    capacity = limit;
                capacities.insert(capacity.value_or(0));
            }
            // Native mode rules precede playlist rules, then the backend override
            // window. A mixed-mode lobby must share one effective capacity.
            wire::require(capacities.size() == 1);
            selected.maximumMembers = *capacities.begin();
            selected.rules = rules;
            selected.splitPartiesForTeamBalance = splitParties;
            if (!squadSizes.empty())
                selected.squadSize = *squadSizes.begin();
            if (!teamCounts.empty())
                selected.teamCount = *teamCounts.begin();
            selected.metadata = {{"playlist_id", id},
                                 {"playlist_version", localBootstrapVersionAlias ? clientVersion : version},
                                 {"context", playlist.value("context", std::string{})},
                                 {"eligible_entries", eligible},
                                 {"score_limit", playlist.value("score_limit", Json())},
                                 {"time_limit", playlist.value("time_limit", Json())},
                                 {"flags", playlist.value("flags", Json::array())},
                                 {"playlist_dvars", playlist.value("dvars", Json::object())},
                                 {"game_types", Json::object()}};
            if (!packages.is_null())
                selected.metadata["map_package_revision"] = packages.at("revision");
            if (selected.maximumMembers)
                selected.metadata["maximum_members"] = selected.maximumMembers;
            if (!searchConfiguration.empty())
                selected.metadata["search_configuration"] = searchConfiguration;
            if (selected.splitPartiesForTeamBalance)
                selected.metadata["split_parties_for_team_balance"] = true;
            if (selected.squadSize)
            {
                selected.metadata["squad_size"] = selected.squadSize;
                selected.metadata["native_team_count_dvar"] =
                    bindings.value("party_teamCount", std::string("party_teamCount"));
            }
            for (const auto &entry : eligible)
                selected.metadata["game_types"][entry["gametype"].get<std::string>()] =
                    modes.at(entry["gametype"].get<std::string>());
            std::printf("[MM-CATALOG] selected title=%u id=%u maps=%zu slots=%u nativeVersion=%u\n",
                title, id, eligible.size(), selected.maximumMembers,
                localBootstrapVersionAlias ? clientVersion : version);
            return selected;
        }
        std::printf("[MM-CATALOG] search-failed title=%u requestedId=%u version=%u candidates=%zu\n",
            title, requested, clientVersion, candidates.size());
        return std::nullopt;
    }
} // namespace services
