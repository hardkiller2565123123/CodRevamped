#include "host_os.h"
#include "achievement_services.h"
#include "achievement_store.h"
#include "protobuf.h"
#include "matchmaking_services.h"
#include "progression_ranks.h"
#include "weapon_progression_data.h"
#include "gunsmith_rank_unlock_data.h"
#include "replay_quest_data.h"
#include "marketplace_services.h"
#include "battlepass_services.h"
#include "quest_services.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <algorithm>
#include <charconv>
#include <set>
#include <map>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        std::string text(const proto::Field &f, size_t maximum)
        {
            wire::require(f.type == 2 && f.bytes.size() <= maximum);
            std::string value(reinterpret_cast<const char *>(f.bytes.data()), f.bytes.size());
            wire::require(value.find('\0') == std::string::npos);
            return value;
        }

        uint64_t number(const proto::Field &f, uint64_t maximum = UINT64_MAX)
        {
            wire::require(f.type == 0 && f.value <= maximum);
            return f.value;
        }

        void account(const proto::Field &f, const platform::LobbyIdentity &id)
        {
            wire::require(f.type == 2);
            proto::Reader r{f.bytes};
            proto::Field g;
            unsigned seen = 0;
            uint64_t owner = 0;
            std::string type;
            while (r.next(g))
            {
                wire::require(g.tag >= 1 && g.tag <= 2 && !(seen & (1U << g.tag)));
                seen |= 1U << g.tag;
                if (g.tag == 1)
                    owner = number(g);
                else
                    type = text(g, 10);
            }
            wire::require(seen == 6 && owner == id.userId && (type == "bnet" || type == "uno"));
        }

        struct Query
        {
            std::string context, page;
            uint16_t maximum = 0;
            std::vector<uint16_t> kinds, statuses;
            std::vector<std::string> names;
            std::vector<uint64_t> ids;
        };

        Query query(const platform::LobbyIdentity &id, wire::Reader &p, bool definitions)
        {
            // Same Replay 0x1421040E0 / 0x14215C450; preserve all repeated filters,
            // optional account objects and platform field, including their capacities.
            proto::Reader r{p.structure(16 * 1024)};
            proto::Field f;
            Query q;
            unsigned seen = 0;
            while (r.next(f))
            {
                wire::require(f.tag >= 1 && f.tag <= (definitions ? 5u : 11u));
                const bool repeated =
                    f.tag == 2 || (definitions ? f.tag == 5 : (f.tag >= 5 && f.tag <= 7));
                if (!repeated)
                {
                    wire::require(!(seen & (1U << f.tag)));
                    seen |= 1U << f.tag;
                }
                if (f.tag == 1)
                    q.context = text(f, 20);
                else if (f.tag == 2)
                {
                    wire::require(q.kinds.size() < 18);
                    q.kinds.push_back(static_cast<uint16_t>(number(f, UINT16_MAX)));
                }
                else if (f.tag == 3)
                    q.maximum = static_cast<uint16_t>(number(f, UINT16_MAX));
                else if (f.tag == 4)
                    q.page = text(f, 1024);
                else if (definitions || f.tag == 7)
                {
                    wire::require(q.ids.size() < (definitions ? 100u : 3u));
                    q.ids.push_back(number(f));
                }
                else if (f.tag == 5)
                {
                    wire::require(q.statuses.size() < 5);
                    const auto value = number(f, 5);
                    wire::require(value >= 1);
                    q.statuses.push_back(static_cast<uint16_t>(value));
                }
                else if (f.tag == 6)
                {
                    wire::require(q.names.size() < 3);
                    q.names.push_back(text(f, 100));
                }
                else if (f.tag == 8)
                    (void)number(f, 1);
                else if (f.tag == 9 || f.tag == 10)
                    account(f, id);
                else
                    (void)number(f, UINT8_MAX);
            }
            wire::require((seen & 26) == 26 && (definitions || (seen & 256)) && q.maximum > 0 &&
                          q.maximum <= 100);
            wire::require(q.context == std::to_string(id.titleId) || q.context == "iw8");
            return q;
        }

        Json document(const std::filesystem::path &path, const Json &initial)
        {
            if (!std::filesystem::exists(path))
                return initial;
            if (std::filesystem::file_size(path) > 4 * 1024 * 1024)
                throw std::runtime_error("Achievement document size invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Achievement document read failed");
            return Json::parse(in);
        }

        void publish(const std::filesystem::path &path, const Json &data)
        {
            const auto bytes = data.dump();
            if (bytes.size() > 4 * 1024 * 1024)
                throw std::runtime_error("Achievement document capacity exceeded");
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            const auto file = CreateFileW(pending.c_str(),
                                          GENERIC_WRITE,
                                          0,
                                          nullptr,
                                          CREATE_ALWAYS,
                                          FILE_ATTRIBUTE_NORMAL,
                                          nullptr);
            if (file == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Achievement persistence failed");
            DWORD written = 0;
            const bool saved =
                WriteFile(
                    file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                written == bytes.size() && FlushFileBuffers(file);
            CloseHandle(file);
            if (!saved)
                throw std::runtime_error("Achievement persistence flush failed");
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Achievement publication failed");
        }

        uint64_t integer(const Json &data, const char *key, uint64_t maximum = UINT64_MAX)
        {
            const auto value = data.value(key, Json(uint64_t{0}));
            wire::require(value.is_number_unsigned());
            const auto out = value.get<uint64_t>();
            wire::require(out <= maximum);
            return out;
        }

        std::string string(const Json &data, const char *key, size_t maximum)
        {
            const auto value = data.value(key, Json(""));
            wire::require(value.is_string());
            const auto out = value.get<std::string>();
            wire::require(out.size() <= maximum && out.find('\0') == std::string::npos);
            return out;
        }

        wire::Bytes state(const Json &data)
        {
            // Full 552-byte native bdAchievementState (0x142102180), including the
            // four-element bdAchievementProgress array (0x142101F90).
            wire::require(data.is_object());
            wire::Bytes out;
            proto::text(out, 1, string(data, "name", 100));
            proto::integer(out, 2, integer(data, "kind", UINT16_MAX));
            proto::integer(out, 3, integer(data, "progress", UINT32_MAX));
            proto::integer(out, 4, integer(data, "target", UINT32_MAX));
            const auto status = integer(data, "status", 5);
            wire::require(status >= 1);
            proto::integer(out, 5, status);
            proto::integer(out, 6, integer(data, "completionTimestamp"));
            proto::integer(out, 7, integer(data, "activationTimestamp"));
            proto::integer(out, 8, integer(data, "expirationTimestamp"));
            proto::integer(out, 9, integer(data, "completionCount", UINT32_MAX));
            const auto multi = data.value("multiProgress", Json::array());
            wire::require(multi.is_array() && multi.size() <= 4);
            for (const auto &progress : multi)
            {
                wire::require(progress.is_object());
                wire::Bytes row;
                proto::text(row, 1, string(progress, "name", 32));
                proto::integer(row, 2, integer(progress, "current"));
                proto::integer(row, 3, integer(progress, "target"));
                proto::bytes(out, 10, row);
            }
            const auto id = integer(data, "id");
            wire::require(id > 0);
            proto::integer(out, 11, id);
            return out;
        }

        Json object(const Json &data, const char *key)
        {
            const auto out = data.value(key, Json::object());
            wire::require(out.is_object());
            return out;
        }

        Json array(const Json &data, const char *key, size_t maximum)
        {
            const auto out = data.value(key, Json::array());
            wire::require(out.is_array() && out.size() <= maximum);
            return out;
        }

        wire::Bytes unsignedFields(const Json &data, unsigned count, uint64_t maximum)
        {
            wire::require(data.is_object());
            wire::Bytes out;
            for (unsigned i = 1; i <= count; ++i)
            {
                const auto key = std::to_string(i);
                proto::integer(out, i, integer(data, key.c_str(), maximum));
            }
            return out;
        }

        wire::Bytes schedule(const Json &data)
        {
            // 0x142159840: UInt16 discriminator 0..3 + five UInt32 date components.
            wire::Bytes out;
            proto::integer(out, 1, integer(data, "1", 3));
            proto::bytes(out, 2, unsignedFields(object(data, "2"), 5, UINT32_MAX));
            return out;
        }

        wire::Bytes actions(const Json &data)
        {
            // 0x142159FD0: two product objects, two currency objects, two activation
            // objects. Their native readers are 0x14215A490 / 0x14215A430 / 0x14215A2A0.
            wire::Bytes out;
            for (const auto &row : array(data, "1", 2))
                proto::bytes(out, 1, unsignedFields(row, 1, UINT32_MAX));
            for (const auto &row : array(data, "2", 2))
                proto::bytes(out, 2, unsignedFields(row, 2, UINT32_MAX));
            for (const auto &row : array(data, "3", 2))
            {
                wire::Bytes action;
                proto::text(action, 1, string(row, "1", 100));
                proto::bytes(action, 2, schedule(object(row, "2")));
                if (row.contains("3"))
                    proto::bytes(action, 3, schedule(object(row, "3")));
                proto::bytes(out, 3, action);
            }
            return out;
        }

        wire::Bytes definition(const Json &data)
        {
            // Complete 3064-byte bdAchievementDefinition at 0x14215B060. Numeric JSON
            // keys preserve the native field identities where semantics are unnamed.
            wire::require(data.is_object());
            wire::Bytes out;
            proto::text(out, 1, string(data, "1", 100));
            proto::text(out, 2, string(data, "2", 250));
            proto::integer(out, 3, integer(data, "3", UINT16_MAX));
            proto::bytes(out, 4, actions(object(data, "4")));
            proto::integer(out, 5, integer(data, "5", UINT32_MAX));
            proto::bytes(out, 6, schedule(object(data, "6")));
            proto::integer(out, 7, integer(data, "7", UINT32_MAX));
            for (unsigned i = 8; i <= 9; ++i)
            {
                const auto key = std::to_string(i);
                const auto value = data.value(key, Json(false));
                wire::require(value.is_boolean());
                proto::integer(out, i, value.get<bool>());
            }
            proto::bytes(out, 10, actions(object(data, "10")));
            for (const auto &row : array(data, "11", 4))
            {
                wire::Bytes target;
                proto::text(target, 1, string(row, "1", 32));
                proto::integer(target, 2, integer(row, "2"));
                proto::bytes(out, 11, target);
            }
            for (unsigned i = 12; i <= 13; ++i)
            {
                const auto key = std::to_string(i);
                if (!data.contains(key))
                    continue;
                const auto range = object(data, key.c_str());
                wire::Bytes optional;
                if (range.contains("1"))
                    proto::bytes(optional, 1, unsignedFields(object(range, "1"), 2, UINT64_MAX));
                proto::bytes(out, i, optional);
            }
            const auto id = integer(data, "14");
            wire::require(id > 0);
            proto::integer(out, 14, id);
            if (data.contains("15"))
                proto::integer(out, 15, integer(data, "15"));
            for (const auto &row : array(data, "16", 4))
                proto::bytes(out, 16, unsignedFields(row, 2, UINT64_MAX));
            for (const auto &value : array(data, "17", 4))
            {
                wire::require(value.is_number_unsigned());
                proto::integer(out, 17, value.get<uint64_t>());
            }
            return out;
        }

        std::string fingerprint(const Json &data)
        {
            const auto text = data.dump();
            const auto hash = crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(text.data()), text.size()));
            std::string value;
            for (unsigned i = 0; i < 16; ++i)
            {
                value += "0123456789abcdef"[hash[i] >> 4];
                value += "0123456789abcdef"[hash[i] & 15];
            }
            return value;
        }

        template <class T> bool includes(const std::vector<T> &values, const T &value)
        {
            return values.empty() || std::find(values.begin(), values.end(), value) != values.end();
        }

        uint64_t playerRank(uint64_t xp)
        {
            return static_cast<uint64_t>(std::upper_bound(replayPlayerRankMinimumXp.begin(),
                                                          replayPlayerRankMinimumXp.end(),
                                                          xp) -
                                         replayPlayerRankMinimumXp.begin() - 1);
        }

        Json playerState(uint64_t xp)
        {
            const auto rank = playerRank(xp);
            return {
                {"id", uint64_t{1000000}},
                {"name", "player_xp"},
                {"kind", uint64_t{0}},
                {"status", uint64_t{1}},
                {"progress", uint64_t{0}},
                {"target", uint64_t{0}},
                {"multiProgress",
                 Json::array({{{"name", "xp"}, {"current", xp}, {"target", uint64_t{0}}},
                              {{"name", "rank"}, {"current", rank}, {"target", uint64_t{0}}}})}};
        }

        const ReplayQuest *quest(uint64_t id, const std::string &name = {})
        {
            const auto found = std::find_if(replayQuests.begin(),
                                            replayQuests.end(),
                                            [&](const ReplayQuest &row)
                                            {
                                                return id ? row.id == id : row.name == name;
                                            });
            return found == replayQuests.end() ? nullptr : &*found;
        }

        Json questState(const ReplayQuest &row)
        {
            return {{"id", uint64_t{row.id}},
                    {"name", row.name},
                    {"kind", uint64_t{15}},
                    {"status", uint64_t{2}},
                    {"progress", uint64_t{0}},
                    {"target", uint64_t{row.target}}};
        }

        Json questDefinition(const ReplayQuest &row)
        {
            return {{"1", row.name},
                    {"2", row.description},
                    {"3", uint64_t{15}},
                    {"5", uint64_t{1}},
                    {"7", uint64_t{row.target}},
                    {"9", true},
                    {"14", uint64_t{row.id}},
                    {"initialState", questState(row)}};
        }

        const ReplayWeaponProgression &weapon(uint64_t id)
        {
            wire::require(id < replayWeaponAliases.size() && replayWeaponAliases[id]);
            const auto canonical = replayWeaponAliases[id];
            const auto found = std::find_if(replayWeapons.begin(),
                                            replayWeapons.end(),
                                            [canonical](const auto &row)
                                            {
                                                return row.id == canonical;
                                            });
            wire::require(found != replayWeapons.end());
            return *found;
        }

        uint64_t weaponRank(const ReplayWeaponProgression &row, uint64_t xp)
        {
            const auto rank = static_cast<uint64_t>(
                std::upper_bound(replayWeaponMinimumXp.begin(), replayWeaponMinimumXp.end(), xp) -
                replayWeaponMinimumXp.begin() - 1);
            return std::min(rank, static_cast<uint64_t>(row.maximumRank));
        }

        using WeaponXp = std::map<uint16_t, uint64_t>;

        WeaponXp storedWeaponXp(const Json &journal, const std::filesystem::path &path)
        {
            WeaponXp result;
            if (journal.contains("weapon_xp"))
            {
                const auto values = object(journal, "weapon_xp");
                wire::require(values.size() <= replayWeapons.size());
                for (const auto &[key, value] : values.items())
                {
                    uint64_t id = 0;
                    const auto parsed = std::from_chars(key.data(), key.data() + key.size(), id);
                    wire::require(parsed.ec == std::errc{} &&
                                  parsed.ptr == key.data() + key.size() &&
                                  key == std::to_string(id) && weapon(id).id == id);
                    // UpdateWeaponStats persists XP through DDL_SetInt. Keep all
                    // UInt32 bits, but reject totals that would truncate locally.
                    wire::require(value.is_number_unsigned() &&
                                  value.get<uint64_t>() <= UINT32_MAX);
                    result.emplace(static_cast<uint16_t>(id), value.get<uint64_t>());
                }
                return result;
            }
            if (path.empty())
                return result;
            const auto states = document(path.parent_path() / "states.json", Json::array());
            wire::require(states.is_array() && states.size() <= 15000);
            for (const auto &state : states)
            {
                const auto id = integer(state, "id");
                if (integer(state, "kind") != 5 || id <= 2000000)
                    continue; // Preserve the separate camo/attachment families.
                const auto &row = weapon(id - 2000000);
                std::optional<uint64_t> xp;
                for (const auto &progress : array(state, "multiProgress", 4))
                    if (string(progress, "name", 32) == "xp")
                    {
                        wire::require(!xp);
                        xp = integer(progress, "current", UINT32_MAX);
                    }
                wire::require(xp.has_value());
                const auto [previous, inserted] = result.emplace(row.id, *xp);
                wire::require(inserted || previous->second == *xp);
            }
            wire::require(result.size() <= replayWeapons.size());
            return result;
        }

        Json weaponState(const ReplayWeaponProgression &row, uint64_t xp)
        {
            auto result = playerState(xp);
            result["id"] = uint64_t{2000000} + row.id;
            result["name"] = row.reference;
            result["kind"] = uint64_t{5};
            result["multiProgress"][1]["current"] = weaponRank(row, xp);
            return result;
        }

        std::vector<uint32_t> rankItems(const WeaponXp &weapons)
        {
            std::set<uint32_t> items;
            for (const auto &[id, xp] : weapons)
            {
                const auto rank = weaponRank(weapon(id), xp);
                for (const auto &unlock : replayRankUnlocks)
                    if (unlock.weapon == id && unlock.rank <= rank)
                        items.insert(unlock.item);
            }
            return {items.begin(), items.end()};
        }

        std::vector<uint32_t> playerRankItems(uint64_t xp)
        {
            std::set<uint32_t> items(replayInitialItems.begin(), replayInitialItems.end());
            const auto rank = playerRank(xp);
            for (const auto &unlock : replayPlayerRankUnlocks)
                if (unlock.rank <= rank)
                    items.insert(unlock.item);
            return {items.begin(), items.end()};
        }

        std::vector<uint32_t> rankItems(const WeaponXp &weapons, uint64_t playerXp)
        {
            auto items = rankItems(weapons);
            const auto player = playerRankItems(playerXp);
            items.insert(items.end(), player.begin(), player.end());
            std::sort(items.begin(), items.end());
            items.erase(std::unique(items.begin(), items.end()), items.end());
            return items;
        }

        struct RankNotification
        {
            Json grants = Json::array();
            std::string hash;
        };

        RankNotification rankNotification(const ReplayWeaponProgression *row,
                                          uint64_t xp,
                                          const RankInventory *inventory,
                                          bool refresh)
        {
            RankNotification result;
            const auto selected = row ? rankItems({{row->id, xp}}) : playerRankItems(xp);
            if (selected.empty() || !inventory)
                return result;
            auto quantities = Json::array();
            for (const auto item : selected)
            {
                const auto found = std::lower_bound(inventory->quantities.begin(),
                                                    inventory->quantities.end(),
                                                    std::make_pair(item, uint32_t{0}));
                wire::require(found != inventory->quantities.end() && found->first == item);
                quantities.push_back(Json::array({item, found->second}));
                if (found->second && (refresh || std::binary_search(inventory->newlyOwned.begin(),
                                                                    inventory->newlyOwned.end(),
                                                                    item)))
                    result.grants.push_back({{"id", item}, {"quantity", found->second}});
            }
            result.hash = fingerprint(quantities);
            return result;
        }

        void validatePendingXp(const Json &journal)
        {
            if (journal.contains("player_xp_pending"))
                wire::require(journal.contains("player_xp") &&
                              integer(journal, "player_xp_pending") ==
                                  integer(journal, "player_xp"));
        }

        uint64_t initialPlayerXp(const std::filesystem::path &journal)
        {
            const auto states = document(journal.parent_path() / "states.json", Json::array());
            wire::require(states.is_array());
            for (const auto &row : states)
                if (integer(row, "id") == 1000000)
                    for (const auto &progress : array(row, "multiProgress", 4))
                        if (string(progress, "name", 32) == "xp")
                            return integer(progress, "current");
            return 0;
        }

        Delivery progressionUpdate(const platform::LobbyIdentity &id,
                                   const std::string &context,
                                   uint64_t xp,
                                   bool rankedUp,
                                   const ReplayWeaponProgression *row = nullptr,
                                   const RankInventory *inventory = nullptr,
                                   bool refreshAwards = true)
        {
            // Replay's event 67 -> 0x142125410 reads version UByte8(1), full
            // user identity. 1420EFB80 checks tag 3 and copies one byte despite
            // the SQLite alias naming it readUInt64. Keep the actual wire ABI.
            // ContextSerialization context, Int32 JSON format, count,
            // then each bdRewardEventJSONV2 (Int32 format + typed string).
            const auto achievementId = row ? uint64_t{2000000} + row->id : uint64_t{1000000};
            Json event = {{"type", "ACHIEVEMENT"},
                          {"name", row ? std::string(row->reference) : "player_xp"},
                          {"reason", rankedUp ? "completed" : "inProgress"},
                          {"kind", row ? 5 : 0},
                          {"id_", achievementId},
                          {"multiProgress",
                           {{"xp", {{"value", xp}}},
                            {"rank", {{"value", row ? weaponRank(*row, xp) : playerRank(xp)}}}}}};
            const auto rewards = rankNotification(row, xp, inventory, refreshAwards);
            if (!rewards.grants.empty())
                event["triggers"] =
                    Json::array({{{"type", "GRANT_PRODUCT"},
                                  {"inventory", {{"granted_items", rewards.grants}}}}});
            const auto body = event.dump();
            wire::require(body.size() < 16 * 1024);
            wire::Writer push;
            push.u32(67);
            push.u8(1);
            push.u64(id.userId);
            push.text("uno");
            push.text(context);
            push.data.push_back(7);
            wire::raw(push.data, int32_t{1});
            push.u32(1);
            push.data.push_back(7);
            wire::raw(push.data, int32_t{1});
            push.text(body);
            Delivery delivery{id.userId, std::move(push.data)};
            delivery.progressionContext = context;
            delivery.progressionXp = xp;
            delivery.progressionId = achievementId;
            delivery.progressionRewardsHash = rewards.hash;
            return delivery;
        }

        Reply get(const std::filesystem::path &root,
                  const platform::LobbyIdentity &id,
                  wire::Reader &p,
                  bool definitions)
        {
            const auto q = query(id, p, definitions);
            const auto folder = root / "achievements" / std::to_string(id.titleId) / q.context;
            const auto path = definitions ? folder / "definitions.json"
                                          : folder / std::to_string(id.userId) / "states.json";
            auto data = document(path, Json::array());
            wire::require(data.is_array() && data.size() <= 15000);
            if (definitions && id.titleId == 5800 && data.empty())
                for (const auto &row : replayQuests)
                    data.push_back(questDefinition(row));
            if (!definitions)
            {
                // The first Battle Pass backend left completed activations at
                // ACTIVE. Present their inactive status without queuing
                // them again into the native challenge-activation cache.
                for (auto &row : data)
                    if (row.contains("battlepass_pending") &&
                        !row.at("battlepass_pending").get<bool>())
                        row["status"] = uint64_t{2};
                const auto journal = document(path.parent_path() / "events.json", Json::object());
                validatePendingXp(journal);
                if (journal.contains("player_xp"))
                {
                    const auto xp = integer(journal, "player_xp");
                    data.erase(std::remove_if(data.begin(),
                                              data.end(),
                                              [](const Json &row)
                                              {
                                                  return integer(row, "id") == 1000000;
                                              }),
                               data.end());
                    data.push_back(playerState(xp));
                }
                const auto weapons = storedWeaponXp(journal, path);
                data.erase(std::remove_if(data.begin(),
                                          data.end(),
                                          [](const Json &row)
                                          {
                                              return integer(row, "kind") == 5 &&
                                                     integer(row, "id") > 2000000;
                                          }),
                           data.end());
                for (const auto &[weaponId, xp] : weapons)
                    data.push_back(weaponState(weapon(weaponId), xp));
            }
            std::vector<Json> filtered;
            std::set<uint64_t> ids;
            for (const auto &row : data)
            {
                if (definitions)
                    (void)definition(row);
                else
                    (void)state(row);
                const auto rowId = integer(row, definitions ? "14" : "id");
                wire::require(ids.insert(rowId).second);
                if (includes(q.ids, rowId) &&
                    includes(q.names, string(row, definitions ? "1" : "name", 100)) &&
                    includes(q.kinds,
                             static_cast<uint16_t>(
                                 integer(row, definitions ? "3" : "kind", UINT16_MAX))) &&
                    (definitions ||
                     includes(q.statuses, static_cast<uint16_t>(integer(row, "status", 5)))))
                    filtered.push_back(row);
            }
            std::sort(filtered.begin(),
                      filtered.end(),
                      [definitions](const auto &a, const auto &b)
                      {
                          return integer(a, definitions ? "14" : "id") <
                                 integer(b, definitions ? "14" : "id");
                      });
            const auto digest = fingerprint(Json{{"title", id.titleId},
                                                 {"user", id.userId},
                                                 {"context", q.context},
                                                 {"rows", filtered}});
            size_t start = 0;
            if (!q.page.empty())
            {
                wire::require(q.page.starts_with(digest + ":"));
                const auto value = q.page.substr(33);
                const auto parsed =
                    std::from_chars(value.data(), value.data() + value.size(), start);
                wire::require(parsed.ec == std::errc{} &&
                              parsed.ptr == value.data() + value.size() && start < filtered.size());
            }
            const auto end = std::min(filtered.size(), start + q.maximum);
            Reply reply{0,
                        {},
                        definitions ? "achievement-definitions-read" : "achievement-states-read",
                        true,
                        {}};
            for (size_t i = start; i < end; ++i)
                proto::bytes(
                    reply.structure, 1, definitions ? definition(filtered[i]) : state(filtered[i]));
            proto::text(reply.structure,
                        2,
                        end < filtered.size() ? digest + ":" + std::to_string(end) : "");
            wire::require(reply.structure.size() <= 256 * 1024);
            if (!definitions && !std::filesystem::exists(path))
                publish(path, data);
            return reply;
        }

        void validateEvent(const Json &event)
        {
            wire::require(event.is_object() && event.contains("name") &&
                          event.contains("timestamp") && event.contains("values"));
            const auto name = string(event, "name", 100);
            wire::require(!name.empty());
            (void)integer(event, "timestamp");
            const auto values = object(event, "values");
            wire::require(values.size() <= 10);
            for (auto entry = values.begin(); entry != values.end(); ++entry)
            {
                wire::require(!entry.key().empty() && entry.key().size() <= 20 &&
                              entry.key().find('\0') == std::string::npos &&
                              entry.value().is_number_unsigned());
            }
        }

        Json eventObject(const proto::Field &f)
        {
            // Same-Replay 0x142103540 / 0x142103630, shared by both event transports.
            wire::require(f.type == 2);
            proto::Reader reader{f.bytes};
            proto::Field e;
            unsigned seen = 0, pairs = 0;
            std::string name;
            uint64_t timestamp = 0, numericName = 0;
            Json values = Json::object();
            while (reader.next(e))
            {
                wire::require(e.tag >= 1 && e.tag <= 4);
                if (e.tag != 3)
                {
                    wire::require(!(seen & (1U << e.tag)));
                    seen |= 1U << e.tag;
                }
                if (e.tag == 1)
                    name = text(e, 100);
                else if (e.tag == 2)
                    timestamp = number(e);
                else if (e.tag == 4)
                    numericName = number(e);
                else
                {
                    wire::require(e.type == 2 && ++pairs <= 10);
                    proto::Reader pairReader{e.bytes};
                    proto::Field v;
                    std::string key;
                    uint64_t value = 0;
                    unsigned pairSeen = 0;
                    while (pairReader.next(v))
                    {
                        wire::require(v.tag >= 1 && v.tag <= 2 && !(pairSeen & (1U << v.tag)));
                        pairSeen |= 1U << v.tag;
                        if (v.tag == 1)
                            key = text(v, 20);
                        else
                            value = number(v);
                    }
                    wire::require(pairSeen == 6 && !key.empty() && !values.contains(key));
                    values[key] = value;
                }
            }
            wire::require(seen == 22);
            if (numericName)
                name = std::to_string(numericName);
            Json out{{"name", name}, {"timestamp", timestamp}, {"values", values}};
            validateEvent(out);
            return out;
        }

        struct EventAccount
        {
            uint64_t user = 0;
            std::string type;
        };

        EventAccount eventAccount(const proto::Field &f)
        {
            wire::require(f.type == 2);
            proto::Reader r{f.bytes};
            proto::Field g;
            unsigned seen = 0;
            EventAccount out;
            while (r.next(g))
            {
                wire::require(g.tag >= 1 && g.tag <= 2 && !(seen & (1U << g.tag)));
                seen |= 1U << g.tag;
                if (g.tag == 1)
                    out.user = number(g);
                else
                    out.type = text(g, 10);
            }
            wire::require(seen == 6);
            return out;
        }

        bool eventOwner(const EventAccount &owner, const platform::LobbyIdentity &id)
        {
            return owner.user == id.userId && (owner.type == "bnet" || owner.type == "uno");
        }

        bool firstPartyOwner(const EventAccount &owner, const platform::LobbyIdentity &id)
        {
            // The first-party ID is the signed local Battle.net account, not an
            // arbitrary client-supplied account. Same-ID universal aliases remain valid.
            return (owner.type == "bnet" &&
                    (owner.user == id.userId ||
                     (id.platformAccountId && owner.user == id.platformAccountId))) ||
                   (owner.type == "uno" && owner.user == id.userId);
        }

        std::string batchRequestId(std::string request)
        {
            // Native 0x14216A100 decodes a URL-safe 16-byte ID and formats its bytes in
            // reverse order as a UUID for REST. Normalize before durable deduplication.
            wire::require(request.size() == 22 || request.size() == 24);
            if (request.size() == 24)
            {
                wire::require(request.ends_with("=="));
                request.resize(22);
            }
            for (auto &c : request)
            {
                wire::require((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '-' || c == '_');
                if (c == '-')
                    c = '+';
                else if (c == '_')
                    c = '/';
            }
            const auto bytes = wire::base64(request + "==", 16);
            wire::require(bytes.size() == 16);
            std::string uuid;
            uuid.reserve(36);
            for (size_t i = 0; i < 16; ++i)
            {
                if (i == 4 || i == 6 || i == 8 || i == 10)
                    uuid += '-';
                const auto value = bytes[15 - i];
                uuid += "0123456789abcdef"[value >> 4];
                uuid += "0123456789abcdef"[value & 15];
            }
            return uuid;
        }

        Json attribution(const EventAccount &owner, const EventAccount &firstParty, size_t count)
        {
            // Account aliases identify the same signed owner. Canonicalize their
            // representation so binary/REST fallback retries cannot double-record.
            return Json{{"userID", owner.user},
                        {"accountType", "uno"},
                        {"firstPartyUserID", firstParty.user},
                        {"firstPartyAccountType", firstParty.type},
                        {"platform", "bnet"},
                        {"eventCount", count}};
        }

        std::vector<std::string> requestAliases(const std::string &request)
        {
            std::vector<std::string> aliases{request};
            if (request.size() != 36)
                return aliases;
            wire::Bytes bytes;
            unsigned nibble = 0, count = 0;
            for (size_t i = 0; i < request.size(); ++i)
            {
                const auto c = request[i];
                if (i == 8 || i == 13 || i == 18 || i == 23)
                {
                    if (c != '-')
                        return aliases;
                    continue;
                }
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    return aliases;
                nibble = (nibble << 4) | static_cast<unsigned>(c <= '9' ? c - '0' : c - 'a' + 10);
                if (++count % 2 == 0)
                {
                    bytes.push_back(static_cast<uint8_t>(nibble));
                    nibble = 0;
                }
            }
            std::reverse(bytes.begin(), bytes.end());
            auto encoded = wire::base64Encode(bytes);
            for (auto &c : encoded)
            {
                if (c == '+')
                    c = '-';
                else if (c == '/')
                    c = '_';
            }
            aliases.push_back(encoded.substr(0, 22));
            aliases.push_back(encoded);
            return aliases;
        }

        void validateReceipt(const Json &receipt, const platform::LobbyIdentity &id)
        {
            const auto receiptId = string(receipt, "id", 36), hash = string(receipt, "digest", 32);
            wire::require(!receiptId.empty() && hash.size() == 32 &&
                          std::all_of(hash.begin(),
                                      hash.end(),
                                      [](char c)
                                      {
                                          return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                                      }));
            if (receipt.contains("quest_updates"))
            {
                const auto &updates = receipt.at("quest_updates");
                wire::require(updates.is_array() && updates.size() <= replayQuests.size());
                std::set<uint64_t> seen;
                for (const auto &value : updates)
                {
                    wire::require(value.is_number_unsigned());
                    const auto identity = value.get<uint64_t>();
                    wire::require(quest(identity) && seen.insert(identity).second);
                }
            }
            if (receipt.contains("users"))
            {
                const auto &users = receipt.at("users");
                wire::require(users.is_array() && !users.empty() && users.size() <= 16);
                uint64_t count = 0;
                for (const auto &user : users)
                {
                    wire::require(
                        eventOwner({integer(user, "userID"), string(user, "accountType", 10)},
                                   id) &&
                        firstPartyOwner({integer(user, "firstPartyUserID"),
                                         string(user, "firstPartyAccountType", 10)},
                                        id) &&
                        string(user, "platform", 16) == "bnet");
                    const auto size = integer(user, "eventCount", 128);
                    wire::require(size > 0 && count <= 128 - size);
                    count += size;
                }
            }
        }

        void validateJournal(const Json &data, const platform::LobbyIdentity &id)
        {
            wire::require(data.is_object() && data.at("schema") == 1 &&
                          data.at("events").is_array() && data.at("requests").is_array() &&
                          data.at("events").size() <= 1024 && data.at("requests").size() <= 4096);
            const auto next = integer(data, "next");
            wire::require(next > 0);
            if (data.contains("player_xp"))
                (void)integer(data, "player_xp");
            validatePendingXp(data);
            (void)storedWeaponXp(data, {});
            uint64_t previous = 0;
            std::set<std::string> requests;
            for (const auto &row : data.at("events"))
            {
                const auto sequence = integer(row, "id");
                wire::require(sequence > previous && sequence < next);
                previous = sequence;
                validateEvent(row.at("event"));
            }
            for (const auto &receipt : data.at("requests"))
            {
                validateReceipt(receipt, id);
                wire::require(requests.insert(receipt.at("id").get<std::string>()).second);
            }
        }

        std::filesystem::path receiptPath(const std::filesystem::path &journal,
                                          const std::string &request)
        {
            const auto hash = crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(request.data()), request.size()));
            std::string key;
            for (auto byte : hash)
            {
                key += "0123456789abcdef"[byte >> 4];
                key += "0123456789abcdef"[byte & 15];
            }
            return journal.parent_path() / "receipts" / (key + ".json");
        }

        void validateEventWrite(const achievement_store::Write &write)
        {
            if (write.kind == achievement_store::Destination::inventory)
            {
                validateRankInventory(write.document);
                return;
            }
            if (write.kind == achievement_store::Destination::states)
            {
                wire::require(write.receiptKey.empty() && write.document.is_array() &&
                              write.document.size() <= 15000);
                std::set<uint64_t> identities;
                for (const auto &row : write.document)
                {
                    // Use the same complete native state serializer as query
                    // replies. Recover no part of a batch with a later malformed
                    // progress record or duplicated achievement identity.
                    (void)state(row);
                    wire::require(identities.insert(integer(row, "id")).second);
                }
                return;
            }
            platform::LobbyIdentity id;
            id.titleId = 5800;
            id.userId = write.owner;
            id.platformAccountId = write.platformAccount;
            if (write.receiptKey.empty())
            {
                validateJournal(write.document, id);
                return;
            }
            const auto &archive = write.document;
            wire::require(archive.is_object() && archive.size() == 6 && archive.at("schema") == 1 &&
                          integer(archive, "title") == id.titleId &&
                          integer(archive, "owner") == id.userId &&
                          archive.at("context") == write.context);
            const auto &receipt = archive.at("receipt");
            validateReceipt(receipt, id);
            wire::require(archive.at("checksum") == fingerprint(receipt) &&
                          receiptPath({}, receipt.at("id").get<std::string>()).stem().string() ==
                              write.receiptKey);
        }

        Json archivedReceipt(const std::filesystem::path &path,
                             const platform::LobbyIdentity &id,
                             const std::string &context,
                             const std::string &request)
        {
            try
            {
                wire::require(std::filesystem::file_size(path) <= 64 * 1024);
                const auto archive = document(path, Json());
                wire::require(archive.is_object() && archive.size() == 6 &&
                              archive.at("schema") == 1 &&
                              integer(archive, "title", UINT32_MAX) == id.titleId &&
                              integer(archive, "owner") == id.userId &&
                              string(archive, "context", 16) == context);
                const auto &receipt = archive.at("receipt");
                validateReceipt(receipt, id);
                wire::require(receipt.at("id") == request &&
                              archive.at("checksum") == fingerprint(receipt));
                return receipt;
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Achievement receipt archive invalid");
            }
            catch (const Json::exception &)
            {
                throw std::runtime_error("Achievement receipt archive invalid");
            }
        }

        void archiveReceipt(const std::filesystem::path &journal,
                            const platform::LobbyIdentity &id,
                            const std::string &context,
                            const Json &receipt,
                            std::vector<achievement_store::Write> &writes)
        {
            const auto request = receipt.at("id").get<std::string>();
            const auto path = receiptPath(journal, request);
            if (std::filesystem::exists(path))
            {
                if (archivedReceipt(path, id, context, request) != receipt)
                    throw std::runtime_error("Achievement receipt archive conflict");
                return;
            }
            writes.push_back({id.userId,
                              id.platformAccountId,
                              context,
                              path.stem().string(),
                              Json{{"schema", 1},
                                   {"title", id.titleId},
                                   {"owner", id.userId},
                                   {"context", context},
                                   {"receipt", receipt},
                                   {"checksum", fingerprint(receipt)}}});
        }

        Reply recordEvents(const std::filesystem::path &root,
                           const platform::LobbyIdentity &id,
                           const std::string &context,
                           const std::string &request,
                           const Json &events,
                           const Json &owners = Json(),
                           std::vector<achievement_store::Write> *staged = nullptr)
        {
            wire::require(context == std::to_string(id.titleId) || context == "iw8");
            wire::require(!request.empty() && request.size() <= 36 && events.is_array() &&
                          events.size() <= 128);
            for (const auto &event : events)
                validateEvent(event);
            const auto path = root / "achievements" / std::to_string(id.titleId) / context /
                              std::to_string(id.userId) / "events.json";
            auto data = document(path,
                                 Json{{"schema", 1},
                                      {"next", uint64_t{1}},
                                      {"events", Json::array()},
                                      {"requests", Json::array()}});
            try
            {
                validateJournal(data, id);
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Achievement event journal schema invalid");
            }
            catch (const Json::exception &)
            {
                throw std::runtime_error("Achievement event journal schema invalid");
            }
            const auto digest = fingerprint(
                owners.is_null() ? events : Json{{"events", events}, {"users", owners}});
            // Older backend versions stored the binary token verbatim. Lookup both
            // old representations as well as the canonical UUID without rewriting or
            // duplicating accepted events during upgrade.
            const auto aliases = requestAliases(request);
            bool accepted = false;
            std::set<uint32_t> refreshedQuests;
            const auto restoreQuests = [&](const Json &receipt)
            {
                if (receipt.contains("quest_updates"))
                    for (const auto &value : receipt.at("quest_updates"))
                        refreshedQuests.insert(value.get<uint32_t>());
            };
            for (const auto &receipt : data.at("requests"))
                if (includes(aliases, receipt.at("id").get<std::string>()))
                {
                    if (receipt.at("digest") != digest)
                        return {106, {}, "achievement-event-retry-conflict"};
                    accepted = true;
                    restoreQuests(receipt);
                }
            for (const auto &alias : aliases)
            {
                const auto archive = receiptPath(path, alias);
                if (!std::filesystem::exists(archive))
                    continue;
                const auto receipt = archivedReceipt(archive, id, context, alias);
                if (receipt.at("digest") != digest)
                    return {106, {}, "achievement-event-retry-conflict"};
                accepted = true;
                restoreQuests(receipt);
            }
            if (accepted)
            {
                Reply result{0, {}, "achievement-events-idempotent", true, {}};
                bool earnedXp =
                    std::any_of(events.begin(),
                                events.end(),
                                [](const Json &event)
                                {
                                    return event.at("name") == "mp_addxp" &&
                                           integer(event.at("values"), "Param0") > 0;
                                });
                const auto xp =
                    data.contains("player_xp") ? integer(data, "player_xp") : initialPlayerXp(path);
                if (earnedXp)
                {
                    // The original consumer assigns absolute XP/rank. Replay the
                    // latest accepted snapshot after a lost result or recovered
                    // commit; never award the delta or repeat a rank-up event.
                    result.operation = "achievement-events-idempotent-refresh";
                    result.detail = " progression_xp=" + std::to_string(xp);
                }
                const auto weapons = storedWeaponXp(data, path);
                std::set<uint16_t> refreshed;
                WeaponXp snapshots;
                for (const auto &event : events)
                    if (event.at("name") == "mp_addxp" && integer(event.at("values"), "Param3"))
                    {
                        const auto &row = weapon(integer(event.at("values"), "Param2"));
                        if (refreshed.insert(row.id).second)
                        {
                            const auto found = weapons.find(row.id);
                            wire::require(found != weapons.end());
                            snapshots.emplace(row.id, found->second);
                        }
                    }
                std::optional<RankInventory> awards;
                auto selected = rankItems(snapshots, xp);
                QuestProgress questRefresh;
                if (!refreshedQuests.empty())
                {
                    questRefresh.states = document(path.parent_path() / "states.json", Json::array());
                    wire::require(questRefresh.states.is_array() && questRefresh.states.size() <= 15000);
                    for (const auto &row : questRefresh.states)
                    {
                        (void)state(row);
                        const auto identity = integer(row, "id");
                        if (!refreshedQuests.contains(static_cast<uint32_t>(identity)))
                            continue;
                        const auto *definition = quest(identity);
                        wire::require(definition);
                        const bool completed = integer(row, "status") == 3;
                        questRefresh.updates[definition->id] = completed;
                        if (completed)
                        {
                            earnedXp = earnedXp || definition->xpReward > 0;
                            if (definition->itemReward)
                                selected.push_back(definition->itemReward);
                        }
                    }
                    std::sort(selected.begin(), selected.end());
                    selected.erase(std::unique(selected.begin(), selected.end()), selected.end());
                }
                if (!selected.empty())
                    awards = prepareRankInventory(root, id, selected, true);
                if (awards && awards->changed)
                {
                    // Repair entitlements from an older XP-only backend without
                    // applying its accepted delta or changing the retry identity.
                    std::vector<achievement_store::Write> local;
                    auto &writes = staged ? *staged : local;
                    writes.push_back({id.userId, id.platformAccountId, context, {}, data});
                    writes.push_back({id.userId,
                                      id.platformAccountId,
                                      "5800",
                                      {},
                                      std::move(awards->document),
                                      achievement_store::Destination::inventory});
                    if (!staged)
                        achievement_store::commit(root, id.titleId, writes, validateEventWrite);
                }
                if (earnedXp)
                    result.deliveries.push_back(progressionUpdate(
                        id, context, xp, false, nullptr, awards ? &*awards : nullptr));
                for (const auto &[weaponId, total] : snapshots)
                    result.deliveries.push_back(progressionUpdate(
                        id, context, total, false, &weapon(weaponId), awards ? &*awards : nullptr));
                if (!refreshed.empty())
                    result.operation = "achievement-events-idempotent-refresh";
                if (!questRefresh.updates.empty())
                {
                    auto deliveries = replayQuestUpdates(id, context, questRefresh,
                                                          awards ? &*awards : nullptr, true);
                    result.deliveries.insert(result.deliveries.end(),
                                             std::make_move_iterator(deliveries.begin()),
                                             std::make_move_iterator(deliveries.end()));
                    result.operation = "achievement-events-idempotent-refresh";
                }
                std::vector<achievement_store::Write> refreshWrites;
                battlepassEvents(root, id, context, events, refreshWrites, result.deliveries, true);
                return result;
            }
            const auto previousXp =
                data.contains("player_xp") ? integer(data, "player_xp") : initialPlayerXp(path);
            auto xp = previousXp;
            const auto previousWeapons = storedWeaponXp(data, path);
            auto weapons = previousWeapons;
            for (const auto &event : events)
            {
                // The native engine aggregates earned score/bonuses into this
                // event. Consume its XP delta; do not invent XP for raw kills.
                if (event.at("name") != "mp_addxp")
                    continue;
                const auto &values = event.at("values");
                const auto delta = integer(values, "Param0");
                wire::require(xp <= UINT64_MAX - delta);
                xp += delta;
                const auto weaponDelta = integer(values, "Param3", UINT32_MAX);
                if (weaponDelta)
                {
                    const auto &row = weapon(integer(values, "Param2"));
                    auto &total = weapons[row.id];
                    wire::require(total <= UINT32_MAX - weaponDelta);
                    total += weaponDelta;
                }
            }
            QuestProgress questProgress;
            if (id.titleId == 5800 && std::any_of(events.begin(), events.end(),
                [](const Json &event)
                {
                    const auto &name = event.at("name").get_ref<const std::string &>();
                    return replayQuestEventMayEarn(name);
                }))
            {
                const auto stored = document(path.parent_path() / "states.json", Json::array());
                wire::require(stored.is_array() && stored.size() <= 15000);
                std::set<uint64_t> identities;
                for (const auto &row : stored)
                {
                    (void)state(row);
                    wire::require(identities.insert(integer(row, "id")).second);
                }
                if (!stored.empty())
                    questProgress = advanceReplayQuests(stored, events,
                                                          matchmakingPublicMatchCategory(root, id));
                wire::require(xp <= UINT64_MAX - questProgress.xp);
                xp += questProgress.xp;
            }
            WeaponXp changedWeapons;
            for (const auto &[weaponId, total] : weapons)
            {
                const auto previous = previousWeapons.find(weaponId);
                if (previous == previousWeapons.end() || total != previous->second)
                    changedWeapons.emplace(weaponId, total);
            }
            std::optional<RankInventory> awards;
            auto selected = rankItems(changedWeapons, xp);
            selected.insert(selected.end(), questProgress.items.begin(), questProgress.items.end());
            std::sort(selected.begin(), selected.end());
            selected.erase(std::unique(selected.begin(), selected.end()), selected.end());
            if (!selected.empty())
                awards = prepareRankInventory(root, id, selected, true);
            data["player_xp"] = xp;
            if (xp != previousXp)
                data["player_xp_pending"] = xp;
            if (!weapons.empty() || data.contains("weapon_xp"))
            {
                auto values = Json::object();
                for (const auto &[weaponId, total] : weapons)
                    values[std::to_string(weaponId)] = total;
                data["weapon_xp"] = std::move(values);
            }
            auto next = integer(data, "next");
            wire::require(next > 0 && next <= UINT64_MAX - events.size());
            for (const auto &event : events)
                data["events"].push_back(Json{{"id", next++}, {"event", event}});
            data["next"] = next;
            Json receipt{{"id", request}, {"digest", digest}};
            if (!questProgress.updates.empty())
            {
                receipt["quest_updates"] = Json::array();
                for (const auto &[identity, completed] : questProgress.updates)
                {
                    (void)completed;
                    receipt["quest_updates"].push_back(uint64_t{identity});
                }
            }
            if (!owners.is_null())
                receipt["users"] = owners;
            data["requests"].push_back(std::move(receipt));
            while (data["events"].size() > 1024)
                data["events"].erase(data["events"].begin());
            std::vector<achievement_store::Write> local;
            auto &writes = staged ? *staged : local;
            // Archived receipts and their journal eviction share the same intent,
            // including every other recipient in an attributed multiplayer batch.
            while (data["requests"].size() > 256)
            {
                archiveReceipt(path, id, context, data["requests"].front(), writes);
                data["requests"].erase(data["requests"].begin());
            }
            writes.push_back({id.userId, id.platformAccountId, context, {}, std::move(data)});
            if (!questProgress.updates.empty())
                writes.push_back({id.userId, id.platformAccountId, context, {}, questProgress.states,
                                  achievement_store::Destination::states});
            if (awards && awards->changed)
                writes.push_back({id.userId,
                                  id.platformAccountId,
                                  "5800",
                                  {},
                                  std::move(awards->document),
                                  achievement_store::Destination::inventory});
            std::vector<Delivery> battlepassDeliveries;
            battlepassEvents(root, id, context, events, writes, battlepassDeliveries);
            if (!staged)
                achievement_store::commit(root, id.titleId, writes, validateEventWrite);
            Reply result{0, {}, "achievement-events-recorded", true, {}};
            result.deliveries = std::move(battlepassDeliveries);
            auto missionDeliveries = replayQuestUpdates(id, context, questProgress,
                                                         awards ? &*awards : nullptr);
            result.deliveries.insert(result.deliveries.end(),
                                     std::make_move_iterator(missionDeliveries.begin()),
                                     std::make_move_iterator(missionDeliveries.end()));
            if (xp != previousXp)
            {
                result.deliveries.push_back(
                    progressionUpdate(id,
                                      context,
                                      xp,
                                      playerRank(xp) > playerRank(previousXp),
                                      nullptr,
                                      awards ? &*awards : nullptr,
                                      false));
                result.detail = " progression_xp=" + std::to_string(xp) +
                                " progression_rank=" + std::to_string(playerRank(xp));
            }
            for (const auto &[weaponId, total] : changedWeapons)
            {
                const auto previous = previousWeapons.find(weaponId);
                const auto oldXp =
                    previous == previousWeapons.end() ? uint64_t{0} : previous->second;
                if (total == oldXp)
                    continue;
                const auto &row = weapon(weaponId);
                result.deliveries.push_back(
                    progressionUpdate(id,
                                      context,
                                      total,
                                      weaponRank(row, total) > weaponRank(row, oldXp),
                                      &row,
                                      awards ? &*awards : nullptr,
                                      false));
            }
            return result;
        }

        Reply recordAttributedEvents(const std::filesystem::path &root,
                                     const platform::LobbyIdentity &sender,
                                     const std::string &context,
                                     const std::string &request,
                                     const Json &events,
                                     const Json &owners)
        {
            struct Batch
            {
                platform::LobbyIdentity recipient;
                Json events = Json::array(), owners = Json::array();
            };

            std::map<uint64_t, Batch> batches;
            size_t offset = 0;
            // Validate every recipient before recording any part of the batch.
            for (const auto &owner : owners)
            {
                const auto user = integer(owner, "userID");
                const auto recipient = matchmakingReportIdentity(root, sender, user);
                if (!recipient || !firstPartyOwner({integer(owner, "firstPartyUserID"),
                                                    string(owner, "firstPartyAccountType", 10)},
                                                   *recipient))
                    return {101, {}, "achievement-event-owner-denied"};
                const auto count = integer(owner, "eventCount", 128);
                wire::require(count && offset + count <= events.size());
                auto &batch = batches[user];
                batch.recipient = *recipient;
                batch.owners.push_back(owner);
                for (size_t index = 0; index < count; ++index)
                    batch.events.push_back(events[offset++]);
            }
            wire::require(offset == events.size());
            Reply reply{0, {}, "achievement-events-recorded", true, {}};
            std::vector<achievement_store::Write> writes;
            for (const auto &[user, batch] : batches)
            {
                // Preflight all retry receipts and XP arithmetic before changing
                // any account. Late conflicts reject the whole submission.
                auto recorded = recordEvents(
                    root, batch.recipient, context, request, batch.events, batch.owners, &writes);
                if (recorded.error)
                    return recorded;
                for (auto &delivery : recorded.deliveries)
                    reply.deliveries.push_back(std::move(delivery));
            }
            achievement_store::commit(root, sender.titleId, writes, validateEventWrite);
            reply.detail = " event_owners=" + std::to_string(batches.size()) +
                           " progression_updates=" + std::to_string(reply.deliveries.size());
            return reply;
        }

        Reply events(const std::filesystem::path &root,
                     const platform::LobbyIdentity &id,
                     wire::Reader &p)
        {
            // 0x142102D70 / 0x142103540 / 0x142103630, including numeric event names.
            proto::Reader r{p.structure(256 * 1024)};
            proto::Field f;
            unsigned seen = 0;
            std::string context, request;
            Json events = Json::array();
            while (r.next(f))
            {
                wire::require(f.tag >= 1 && f.tag <= 3);
                if (f.tag != 2)
                {
                    wire::require(!(seen & (1U << f.tag)));
                    seen |= 1U << f.tag;
                }
                if (f.tag == 1)
                    context = text(f, 16);
                else if (f.tag == 3)
                    request = text(f, 25);
                else
                {
                    wire::require(events.size() < 128);
                    events.push_back(eventObject(f));
                }
            }
            wire::require(seen == 10);
            // reportEvents (125/1) uses the same UUID-to-REST transformation as task 2.
            // Preserve legacy opaque IDs, while canonical native UUID encodings share
            // the exact REST receipt. Only the last four zero padding bits are legal.
            const auto encoded =
                (request.size() == 24 && request.ends_with("==")) ? request.substr(0, 22) : request;
            if (encoded.size() == 22 &&
                std::string("AQgw").find(encoded.back()) != std::string::npos &&
                std::all_of(encoded.begin(),
                            encoded.end(),
                            [](char c)
                            {
                                return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                       (c >= '0' && c <= '9') || c == '-' || c == '_';
                            }))
                request = batchRequestId(request);
            return recordEvents(root, id, context, request, events);
        }

        Reply userEvents(const std::filesystem::path &root,
                         const platform::LobbyIdentity &id,
                         wire::Reader &p)
        {
            // Same-Replay task 125/2: constructor 0x142118150 and serializers
            // 0x14216A3A0 / 0x142169D10. No task result binding; ACK is empty structured.
            proto::Reader r{p.structure(256 * 1024)};
            proto::Field f;
            unsigned seen = 0;
            std::string context, request;
            Json events = Json::array(), owners = Json::array();
            while (r.next(f))
            {
                wire::require(f.tag >= 1 && f.tag <= 3);
                if (f.tag != 2)
                {
                    wire::require(!(seen & (1U << f.tag)));
                    seen |= 1U << f.tag;
                }
                if (f.tag == 1)
                    context = text(f, 16);
                else if (f.tag == 3)
                    request = text(f, 25);
                else
                {
                    wire::require(f.type == 2 && owners.size() < 16);
                    proto::Reader batch{f.bytes};
                    proto::Field b;
                    unsigned batchSeen = 0;
                    EventAccount owner, firstParty;
                    uint64_t platform = 0;
                    Json pending = Json::array();
                    while (batch.next(b))
                    {
                        wire::require(b.tag >= 1 && b.tag <= 4);
                        if (b.tag != 2)
                        {
                            wire::require(!(batchSeen & (1U << b.tag)));
                            batchSeen |= 1U << b.tag;
                        }
                        if (b.tag == 1)
                            owner = eventAccount(b);
                        else if (b.tag == 3)
                            firstParty = eventAccount(b);
                        else if (b.tag == 4)
                            platform = number(b, UINT8_MAX);
                        else
                        {
                            wire::require(events.size() + pending.size() < 128);
                            pending.push_back(eventObject(b));
                        }
                    }
                    wire::require(batchSeen == 26 && !pending.empty() && platform == 113);
                    const auto recipient = matchmakingReportIdentity(root, id, owner.user);
                    if (!recipient || !eventOwner(owner, *recipient) ||
                        !firstPartyOwner(firstParty, *recipient))
                        return {101, {}, "achievement-event-owner-denied"};
                    owners.push_back(attribution(owner, firstParty, pending.size()));
                    for (auto &event : pending)
                        events.push_back(std::move(event));
                }
            }
            wire::require(seen == 10 && !owners.empty());
            return recordAttributedEvents(
                root, id, context, batchRequestId(request), events, owners);
        }

        Reply activation(const std::filesystem::path &root,
                         const platform::LobbyIdentity &id,
                         wire::Reader &p,
                         bool activate)
        {
            // 0x1421027A0 / 0x142141670: name/ID selectors; activation additionally
            // carries a timestamp. A missing local definition is an explicit error,
            // never a fabricated challenge or entitlement.
            proto::Reader r{p.structure(1024)};
            proto::Field f;
            unsigned seen = 0;
            std::string context, name;
            uint64_t selected = 0, timestamp = 0;
            while (r.next(f))
            {
                wire::require(f.tag >= 1 && f.tag <= (activate ? 4u : 3u) &&
                              !(seen & (1U << f.tag)));
                seen |= 1U << f.tag;
                if (f.tag == 1)
                    context = text(f, 20);
                else if (f.tag == 2)
                    name = text(f, 100);
                else if (activate && f.tag == 3)
                    timestamp = number(f);
                else
                    selected = number(f);
            }
            wire::require(seen == (activate ? 30u : 14u) && (selected || !name.empty()) &&
                          (context == std::to_string(id.titleId) || context == "iw8"));
            if (activate)
                if (auto reply = battlepassActivation(root, id, context, name, selected, timestamp,
                                                       validateEventWrite))
                    return *reply;
            const auto folder = root / "achievements" / std::to_string(id.titleId) / context;
            const auto path = folder / std::to_string(id.userId) / "states.json";
            auto data = document(path, Json::array());
            wire::require(data.is_array() && data.size() <= 15000);
            Json *found = nullptr;
            for (auto &row : data)
            {
                (void)state(row);
                if ((selected && integer(row, "id") == selected) ||
                    (!selected && string(row, "name", 100) == name))
                {
                    wire::require(!found);
                    found = &row;
                }
            }
            if (!found && activate)
            {
                const auto definitions = document(folder / "definitions.json", Json::array());
                wire::require(definitions.is_array() && definitions.size() <= 15000);
                bool published = false;
                for (const auto &row : definitions)
                {
                    (void)definition(row);
                    if ((selected && integer(row, "14") == selected) ||
                        (!selected && string(row, "1", 100) == name))
                    {
                        published = true;
                        // Progression rules explicitly supply a complete initial state;
                        // unknown definition fields are not guessed into XP targets.
                        if (!row.contains("initialState"))
                            break;
                        const auto initial = row.at("initialState");
                        (void)state(initial);
                        wire::require(integer(initial, "id") == integer(row, "14") &&
                                      data.size() < 15000);
                        data.push_back(initial);
                        found = &data.back();
                        break;
                    }
                }
                if (!found && !published && id.titleId == 5800)
                    if (const auto *row = quest(selected, name))
                    {
                        wire::require((name.empty() || row->name == name) && data.size() < 15000);
                        data.push_back(questState(*row));
                        found = &data.back();
                    }
            }
            if (!found)
            {
                Reply reply{108, {}, "achievement-not-published"};
                reply.detail = " achievement_id=" + std::to_string(selected);
                return reply;
            }
            if (!name.empty())
                wire::require(string(*found, "name", 100) == name);
            // Same-Replay 0x1410625A0 compares status getter 0x142102470 with 1
            // when marking a quest active. Preserve other terminal states on repeats.
            const auto status = integer(*found, "status", 5);
            if (activate && (status == 1 || status == 2))
            {
                // Native StartQuest deactivates the current mission in this mode
                // before selecting another. Preserve MP/BR/CP independence and
                // reject neither a retry nor an interrupted deactivation sequence.
                if (id.titleId == 5800 && integer(*found, "kind") == 15)
                {
                    if (const auto *selectedQuest = quest(integer(*found, "id")))
                    {
                        for (auto &row : data)
                        {
                            if (&row != found && integer(row, "kind") == 15 &&
                                integer(row, "status") == 1)
                            {
                                if (const auto *previous = quest(integer(row, "id"));
                                    previous && previous->category == selectedQuest->category)
                                    row["status"] = uint64_t{2};
                            }
                        }
                    }
                }
                (*found)["status"] = uint64_t{1};
                if (status != 1)
                    (*found)["activationTimestamp"] = timestamp;
            }
            else if (!activate && status == 1)
                (*found)["status"] = uint64_t{2};
            if (id.titleId == 5800)
            {
                const achievement_store::Write write{id.userId,
                                                       id.platformAccountId,
                                                       context,
                                                       {},
                                                       data,
                                                       achievement_store::Destination::states};
                achievement_store::commit(root, id.titleId, {&write, 1}, validateEventWrite);
            }
            else
                publish(path, data);
            return {
                0, {}, activate ? "achievement-activated" : "achievement-deactivated", true, {}};
        }
    } // namespace

    void recoverAchievementWrites(const std::filesystem::path &root, uint32_t title)
    {
        if (title == 5800)
            achievement_store::recover(root, title, validateEventWrite);
    }

    bool achievementDeliveryValid(const std::filesystem::path &root,
                                  uint32_t title,
                                  const Delivery &delivery)
    {
        if (!delivery.questContext.empty())
        {
            wire::require(title == 5800 && delivery.user && delivery.user != UINT64_MAX &&
                          (delivery.questContext == "5800" || delivery.questContext == "iw8"));
            achievement_store::recover(root, title, validateEventWrite);
            const auto path = root / "achievements" / std::to_string(title) /
                              delivery.questContext / std::to_string(delivery.user) / "states.json";
            return replayQuestDeliveryValid(document(path, Json::array()), delivery);
        }
        if (delivery.progressionContext.empty())
            return true;
        wire::require(
            title == 5800 && delivery.user && delivery.user != UINT64_MAX &&
            (delivery.progressionContext == "5800" || delivery.progressionContext == "iw8"));
        // A second event or signed local restore can supersede an absolute
        // notification between dispatch and its serialized socket write.
        achievement_store::recover(root, title, validateEventWrite);
        const auto path = root / "achievements" / std::to_string(title) /
                          delivery.progressionContext / std::to_string(delivery.user) /
                          "events.json";
        const auto journal = document(path, Json::object());
        validatePendingXp(journal);
        if (!journal.empty())
            wire::require(journal.at("schema") == 1 && journal.at("events").is_array() &&
                          journal.at("requests").is_array() &&
                          journal.at("events").size() <= 1024 &&
                          journal.at("requests").size() <= 4096 && integer(journal, "next") > 0);
        if (delivery.progressionId != 1000000)
        {
            wire::require(delivery.progressionId > 2000000);
            const auto &row = weapon(delivery.progressionId - 2000000);
            wire::require(delivery.progressionId == uint64_t{2000000} + row.id);
            const auto weapons = storedWeaponXp(journal, path);
            const auto found = weapons.find(row.id);
            if (found == weapons.end() || delivery.progressionXp != found->second)
                return false;
            platform::LobbyIdentity identity;
            identity.titleId = title;
            identity.userId = delivery.user;
            const auto selected = rankItems({{row.id, found->second}});
            std::optional<RankInventory> inventory;
            if (!selected.empty())
                inventory = prepareRankInventory(root, identity, selected, false);
            return delivery.progressionRewardsHash ==
                   rankNotification(&row, found->second, inventory ? &*inventory : nullptr, true)
                       .hash;
        }
        const auto xp =
            journal.contains("player_xp") ? integer(journal, "player_xp") : initialPlayerXp(path);
        if (delivery.progressionXp != xp)
            return false;
        if (delivery.progressionRewardsHash.empty())
            return true;
        platform::LobbyIdentity identity;
        identity.titleId = title;
        identity.userId = delivery.user;
        const auto inventory = prepareRankInventory(root, identity, playerRankItems(xp), false);
        return delivery.progressionRewardsHash ==
               rankNotification(nullptr, xp, &inventory, true).hash;
    }

    std::vector<Delivery> currentProgressionDeliveries(const std::filesystem::path &root,
                                                       uint32_t title,
                                                       uint64_t user)
    {
        if (title != 5800 || !user || user == UINT64_MAX || !platform::accountName(user))
            return {};
        achievement_store::recover(root, title, validateEventWrite);
        // Actual Replay login/event captures use the title context. Do not
        // merge independent legacy contexts into the one native player record.
        const auto context = std::to_string(title);
        const auto path =
            root / "achievements" / context / context / std::to_string(user) / "events.json";
        const auto journal = document(path, Json::object());
        validatePendingXp(journal);
        if (!journal.empty())
            wire::require(journal.at("schema") == 1 && journal.at("events").is_array() &&
                          journal.at("requests").is_array() &&
                          journal.at("events").size() <= 1024 &&
                          journal.at("requests").size() <= 4096 && integer(journal, "next") > 0);
        platform::LobbyIdentity id;
        id.titleId = title;
        id.userId = user;
        std::vector<Delivery> result;
        const auto weapons = storedWeaponXp(journal, path);
        const auto xp =
            journal.contains("player_xp") ? integer(journal, "player_xp") : initialPlayerXp(path);
        const auto selected = rankItems(weapons, xp);
        std::optional<RankInventory> inventory;
        if (!selected.empty())
            inventory = prepareRankInventory(root, id, selected, false);
        if (journal.contains("player_xp"))
            result.push_back(progressionUpdate(
                id, context, xp, false, nullptr, inventory ? &*inventory : nullptr));
        for (const auto &[weaponId, weaponXp] : weapons)
            result.push_back(progressionUpdate(id,
                                               context,
                                               weaponXp,
                                               false,
                                               &weapon(weaponId),
                                               inventory ? &*inventory : nullptr));
        for (auto &delivery : result)
            delivery.progressionRefresh = true;
        return result;
    }

    std::vector<StoredProgression> achievementProgressionSnapshot(const std::filesystem::path &root,
                                                                  uint32_t title,
                                                                  const std::string &context)
    {
        wire::require(title == 5800 && (context == std::to_string(title) || context == "iw8"));
        // Service dispatch owns the common store mutex. Recover any accepted
        // multi-account intent before exposing a cross-account ranking snapshot.
        achievement_store::recover(root, title, validateEventWrite);
        const auto directory = root / "achievements" / std::to_string(title) / context;
        std::vector<StoredProgression> result;
        if (!std::filesystem::exists(directory))
            return result;
        wire::require(std::filesystem::is_directory(directory) &&
                      !std::filesystem::is_symlink(directory));
        size_t count = 0;
        for (const auto &entry : std::filesystem::directory_iterator(directory))
        {
            if (!entry.is_directory())
                continue;
            wire::require(++count <= 10000 && !entry.is_symlink());
            const auto key = entry.path().filename().string();
            uint64_t owner = 0;
            const auto parsed = std::from_chars(key.data(), key.data() + key.size(), owner);
            wire::require(parsed.ec == std::errc{} && parsed.ptr == key.data() + key.size() &&
                          owner != 0 && owner != UINT64_MAX && std::to_string(owner) == key);
            const auto name = platform::accountName(owner);
            if (!name)
                continue; // A persisted record never provisions an account.
            const auto journal = document(entry.path() / "events.json", Json::object());
            validatePendingXp(journal);
            if (journal.contains("player_xp"))
            {
                wire::require(
                    journal.at("schema") == 1 && journal.at("events").is_array() &&
                    journal.at("events").size() <= 1024 && journal.at("requests").is_array() &&
                    journal.at("requests").size() <= 4096 && integer(journal, "next") > 0);
                result.push_back({owner, integer(journal, "player_xp"), *name});
                continue;
            }
            // Older accepted progression publications live in states.json.
            // Distinguish an explicit zero XP state from no XP state at all.
            const auto states = document(entry.path() / "states.json", Json::array());
            wire::require(states.is_array() && states.size() <= 15000);
            bool found = false;
            for (const auto &state : states)
            {
                if (integer(state, "id") != 1000000)
                    continue;
                for (const auto &progress : array(state, "multiProgress", 4))
                    if (string(progress, "name", 32) == "xp")
                    {
                        wire::require(!found);
                        found = true;
                        result.push_back({owner, integer(progress, "current"), *name});
                    }
            }
        }
        return result;
    }

    void restoreAchievementProgression(const std::filesystem::path &root,
                                       uint32_t title,
                                       uint64_t user,
                                       uint64_t xp,
                                       bool restore,
                                       unsigned startingRank,
                                       uint32_t platformAccount)
    {
        wire::require(title == 5800 && user && user != UINT64_MAX &&
                      startingRank <= replayPlayerRankMinimumXp.size());
        achievement_store::recover(root, title, validateEventWrite);
        platform::LobbyIdentity identity;
        identity.titleId = title;
        identity.userId = user;
        identity.platformAccountId = platformAccount;
        if (!restore && !startingRank)
        {
            auto inventory = prepareRankInventory(root, identity, playerRankItems(0), true);
            if (inventory.changed)
            {
                const achievement_store::Write write{user,
                                                     platformAccount,
                                                     "5800",
                                                     {},
                                                     std::move(inventory.document),
                                                     achievement_store::Destination::inventory};
                achievement_store::commit(root, title, {&write, 1}, validateEventWrite);
            }
            return;
        }
        const auto path = root / "achievements" / std::to_string(title) / std::to_string(title) /
                          std::to_string(user) / "events.json";
        auto journal = document(path,
                                Json{{"schema", 1},
                                     {"next", uint64_t{1}},
                                     {"events", Json::array()},
                                     {"requests", Json::array()}});
        wire::require(journal.at("schema") == 1 && journal.at("events").is_array() &&
                      journal.at("requests").is_array() &&
                      journal.at("next").is_number_unsigned() && integer(journal, "next") > 0 &&
                      journal.at("events").size() <= 1024 && journal.at("requests").size() <= 4096);
        validatePendingXp(journal);
        if (!restore)
            xp = journal.contains("player_xp") ? integer(journal, "player_xp")
                                               : initialPlayerXp(path);
        if (startingRank)
        {
            xp = replayPlayerRankMinimumXp[startingRank - 1];
            journal.erase("player_xp_pending");
        }
        else if (restore && journal.contains("player_xp_pending"))
        {
            const auto pending = integer(journal, "player_xp_pending");
            if (xp >= pending)
                journal.erase("player_xp_pending"); // Signed local snapshot confirms saving.
            else
                xp = pending; // Preserve an accepted award missing from the local snapshot.
        }
        journal["player_xp"] = xp;
        const auto selected = rankItems(storedWeaponXp(journal, path), xp);
        auto inventory = prepareRankInventory(root, identity, selected, true);
        std::vector<achievement_store::Write> writes;
        // Profile selection and native item ownership are one recovery window;
        // a custom displayed rank must not leave create-a-class still locked.
        writes.push_back({user, platformAccount, "5800", {}, std::move(journal)});
        if (inventory.changed)
            writes.push_back({user,
                              platformAccount,
                              "5800",
                              {},
                              std::move(inventory.document),
                              achievement_store::Destination::inventory});
        achievement_store::commit(root, title, writes, validateEventWrite);
    }

    Reply achievementEventsRest(const std::filesystem::path &root,
                                const platform::LobbyIdentity &id,
                                const std::string &context,
                                std::span<const uint8_t> bytes)
    {
        achievement_store::recover(root, id.titleId, validateEventWrite);
        const char *stage = "json";
        try
        {
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            const auto callback =
                [&keys, &unique](int depth, Json::parse_event_t event, Json &value)
            {
                wire::require(depth <= 7);
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    unique = keys.back().insert(value.get<std::string>()).second && unique;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            const auto body = Json::parse(bytes.begin(), bytes.end(), callback);
            wire::require(unique && body.is_object() && body.size() == 3 &&
                          integer(body, "titleID", UINT32_MAX) == id.titleId);
            stage = "request-id";
            const auto request = string(body, "idempotentRequestID", 36);
            wire::require(request.size() == 36);
            for (size_t i = 0; i < request.size(); ++i)
                wire::require((i == 8 || i == 13 || i == 18 || i == 23)
                                  ? request[i] == '-'
                                  : ((request[i] >= '0' && request[i] <= '9') ||
                                     (request[i] >= 'a' && request[i] <= 'f')));
            stage = "batches";
            const auto batches = array(body, "userEvents", 16);
            wire::require(!batches.empty());
            Json events = Json::array(), owners = Json::array();
            bool attributed = false, legacy = false;
            for (const auto &batch : batches)
            {
                stage = "owner";
                const auto owner = integer(batch, "userID");
                const auto type = string(batch, "accountType", 10);
                const auto recipient = matchmakingReportIdentity(root, id, owner);
                if (!recipient || !eventOwner({owner, type}, *recipient))
                    return {101, {}, "achievement-event-owner-denied"};
                const auto rows = array(batch, "events", 128);
                wire::require(!rows.empty());
                const bool hasIdentity = batch.contains("firstPartyUserID") ||
                                         batch.contains("firstPartyAccountType") ||
                                         batch.contains("platform");
                wire::require(batch.size() == (hasIdentity ? 6u : 3u));
                if (hasIdentity)
                {
                    stage = "first-party";
                    wire::require(batch.contains("firstPartyUserID") &&
                                  batch.contains("firstPartyAccountType") &&
                                  batch.contains("platform") &&
                                  string(batch, "platform", 16) == "bnet");
                    EventAccount firstParty{integer(batch, "firstPartyUserID"),
                                            string(batch, "firstPartyAccountType", 10)};
                    if (!firstPartyOwner(firstParty, *recipient))
                        return {101, {}, "achievement-event-owner-denied"};
                    owners.push_back(attribution({owner, type}, firstParty, rows.size()));
                    attributed = true;
                }
                else
                {
                    if (owner != id.userId)
                        return {101, {}, "achievement-event-owner-denied"};
                    legacy = true;
                }
                wire::require(!(attributed && legacy));
                stage = "event-list";
                for (const auto &event : rows)
                {
                    stage = "event";
                    wire::require(events.size() < 128);
                    wire::require(event.size() == 3);
                    validateEvent(event);
                    events.push_back(event);
                }
            }
            stage = "context";
            wire::require(context == std::to_string(id.titleId) || context == "iw8");
            stage = "persistence";
            return attributed ? recordAttributedEvents(root, id, context, request, events, owners)
                              : recordEvents(root, id, context, request, events);
        }
        catch (const Json::exception &)
        {
            if (std::string(stage) == "persistence")
                throw;
        }
        catch (const std::runtime_error &e)
        {
            if (std::string(stage) == "persistence" ||
                std::string(e.what()) != "Malformed native task parameters")
                throw;
        }
        Reply invalid{106, {}, "achievement-rest-domain-invalid"};
        invalid.detail = " validation_stage=" + std::string(stage);
        return invalid;
    }

    std::optional<Reply> achievementServices(const std::filesystem::path &root,
                                             const platform::LobbyIdentity &id,
                                             uint8_t service,
                                             uint8_t task,
                                             wire::Reader &p)
    {
        if (service == 125)
            achievement_store::recover(root, id.titleId, validateEventWrite);
        if (service == 125 && (task == 3 || task == 4))
            return get(root, id, p, task == 4);
        if (service == 125 && task == 1)
            return events(root, id, p);
        if (service == 125 && task == 2)
            return userEvents(root, id, p);
        if (service == 125 && (task == 5 || task == 6))
            return activation(root, id, p, task == 5);
        return std::nullopt;
    }
} // namespace services
