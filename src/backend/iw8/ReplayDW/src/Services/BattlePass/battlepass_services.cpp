#include "battlepass_services.h"
#include "marketplace_services.h"
#include "achievement_services.h"
#include <algorithm>
#include <fstream>
#include <map>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        using Destination = achievement_store::Destination;

        Json read(const std::filesystem::path &path, const Json &fallback)
        {
            if (!std::filesystem::exists(path))
                return fallback;
            wire::require(std::filesystem::is_regular_file(path) &&
                          std::filesystem::file_size(path) <= 4 * 1024 * 1024);
            std::ifstream file(path);
            if (!file)
                throw std::runtime_error("Battle Pass document read failed");
            return Json::parse(file);
        }

        uint64_t number(const Json &row, const char *key, uint64_t maximum = UINT64_MAX)
        {
            const auto &value = row.at(key);
            wire::require(value.is_number_unsigned() && value.get<uint64_t>() <= maximum);
            return value.get<uint64_t>();
        }

        Json rules(const std::filesystem::path &root)
        {
            auto value = read(root / "battlepass/5800/rules.json", Json());
            if (value.is_null())
                return value;
            wire::require(value.is_object() && value.at("schema") == 1 &&
                          number(value, "current_season", 6) >= 1 &&
                          value.at("activations").is_array() &&
                          value.at("activations").size() == 13 && value.at("seasons").is_object() &&
                          value.at("seasons").size() == 6);
            std::set<uint64_t> ids;
            for (const auto &row : value.at("activations"))
            {
                wire::require(ids.insert(number(row, "id")).second &&
                              number(row, "item", INT32_MAX) && number(row, "season", 6) <= 6 &&
                              number(row, "skips", 100) <= 100 && row.at("name").is_string());
            }
            return value;
        }

        std::filesystem::path statePath(const std::filesystem::path &root,
                                        const platform::LobbyIdentity &id,
                                        const std::string &context)
        {
            wire::require(id.titleId == 5800 && (context == "5800" || context == "iw8"));
            return root / "achievements/5800" / context / std::to_string(id.userId) / "states.json";
        }

        Json states(const std::filesystem::path &path)
        {
            auto rows = read(path, Json::array());
            wire::require(rows.is_array() && rows.size() <= 15000);
            std::set<uint64_t> ids;
            for (const auto &row : rows)
                wire::require(ids.insert(number(row, "id")).second);
            return rows;
        }

        Json *find(Json &rows, uint64_t id)
        {
            const auto found = std::find_if(rows.begin(),
                                            rows.end(),
                                            [&](const Json &row)
                                            {
                                                return number(row, "id") == id;
                                            });
            return found == rows.end() ? nullptr : &*found;
        }

        Json initial(uint64_t id, const std::string &name, uint64_t status)
        {
            return Json{{"id", id},
                        {"name", name},
                        {"kind", uint64_t{20}},
                        {"status", status},
                        {"progress", uint64_t{0}},
                        {"target", uint64_t{0}}};
        }

        uint64_t rank(const Json &tiers, uint64_t xp)
        {
            wire::require(tiers.is_array() && tiers.size() == 101);
            uint64_t result = 0, previous = 0;
            for (size_t i = 0; i < tiers.size(); ++i)
            {
                const auto current = number(tiers[i], "xp");
                wire::require(number(tiers[i], "rank", 100) == i && (!i || current > previous));
                if (current <= xp)
                    result = i;
                previous = current;
            }
            return result;
        }

        uint64_t xp(const Json &state)
        {
            for (const auto &progress : state.value("multiProgress", Json::array()))
                if (progress.at("name") == "xp")
                    return number(progress, "current");
            return 0;
        }

        Json &progress(Json &rows, uint64_t season)
        {
            const auto id = uint64_t{3000000} + (season - 1) * 1000;
            if (auto *row = find(rows, id))
                return *row;
            wire::require(rows.size() < 15000);
            rows.push_back(initial(id, "battlepass_season" + std::to_string(season), 1));
            return rows.back();
        }

        Json &item(Json &inventory, uint64_t selected)
        {
            auto &items = inventory.at("items");
            for (auto &row : items)
                if (number(row, "1") == selected)
                    return row;
            wire::require(items.size() < 15000);
            items.push_back(Json{{"1", selected}, {"2", uint64_t{0}}});
            return items.back();
        }

        Delivery update(const platform::LobbyIdentity &id,
                        const std::string &context,
                        const Json &state,
                        const Json &inventory,
                        const std::set<uint64_t> &granted,
                        bool completed = true)
        {
            const auto total = xp(state);
            const auto tier = number(state.at("multiProgress")[1], "current");
            Json event{
                {"type", "ACHIEVEMENT"},
                {"name", state.at("name")},
                {"reason", completed ? "completed" : "inProgress"},
                {"kind", uint64_t{20}},
                {"id_", state.at("id")},
                {"multiProgress", {{"xp", {{"value", total}}}, {"rank", {{"value", tier}}}}}};
            Json items = Json::array();
            for (const auto &row : inventory.at("items"))
                if (granted.contains(number(row, "1")) && number(row, "2"))
                    items.push_back(Json{{"id", row.at("1")}, {"quantity", row.at("2")}});
            if (!items.empty())
                event["triggers"] = Json::array(
                    {{{"type", "GRANT_PRODUCT"}, {"inventory", {{"granted_items", items}}}}});
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
            return Delivery{id.userId, std::move(push.data)};
        }

        void advance(Json &state,
                     const Json &tiers,
                     uint64_t total,
                     Json &inventory,
                     std::set<uint64_t> &granted)
        {
            const auto newRank = rank(tiers, total);
            wire::require(total <= number(tiers.at(100), "xp"));
            state["multiProgress"] =
                Json::array({{{"name", "xp"}, {"current", total}, {"target", uint64_t{0}}},
                             {{"name", "rank"}, {"current", newRank}, {"target", uint64_t{100}}}});
            auto claimed = state.value("claimed", Json::array());
            wire::require(claimed.is_array() && claimed.size() <= 202);
            std::set<std::string> earned;
            for (const auto &claim : claimed)
            {
                wire::require(claim.is_string() && earned.insert(claim.get<std::string>()).second);
            }
            for (size_t level = 0; level <= newRank; ++level)
            {
                const auto &tier = tiers.at(level);
                wire::require(tier.at("free").is_boolean());
                const bool free = tier.at("free").get<bool>();
                if (!free && !state.value("premium", false))
                    continue;
                const auto key = std::string(free ? "free:" : "premium:") + std::to_string(level);
                if (!earned.insert(key).second)
                    continue;
                claimed.push_back(key);
                wire::require(tier.at("items").is_array() && tier.at("items").size() <= 32);
                for (const auto &value : tier.at("items"))
                {
                    wire::require(value.is_number_unsigned() && value.get<uint64_t>() > 0 &&
                                  value.get<uint64_t>() <= INT32_MAX);
                    const auto reward = value.get<uint64_t>();
                    auto &owned = item(inventory, reward);
                    if (!number(owned, "2", INT32_MAX))
                        owned["2"] = uint64_t{1};
                    granted.insert(reward);
                }
                const auto points = number(tier, "cod_points", UINT32_MAX);
                if (points)
                {
                    auto &balances = inventory.at("balances");
                    auto balance = std::find_if(balances.begin(),
                                                balances.end(),
                                                [](const Json &row)
                                                {
                                                    return number(row, "currency") == 20;
                                                });
                    if (balance == balances.end())
                    {
                        wire::require(balances.size() < 16);
                        balances.push_back(
                            Json{{"currency", uint64_t{20}}, {"amount", uint64_t{0}}});
                        balance = std::prev(balances.end());
                    }
                    const auto amount = number(*balance, "amount", UINT32_MAX);
                    wire::require(points <= UINT32_MAX - amount);
                    (*balance)["amount"] = amount + points;
                }
            }
            state["claimed"] = std::move(claimed);
        }
    } // namespace

    void projectBattlepassUserState(const std::filesystem::path &root,
                                    const platform::LobbyIdentity &id,
                                    const std::string &context,
                                    Json &state)
    {
        if (id.titleId != 5800 || (context != "5800" && context != "iw8"))
            return;
        recoverAchievementWrites(root, id.titleId);
        const auto data = states(statePath(root, id, context));
        // Same-Replay 0x14105E1C0 resets each of the seven ownership flags and
        // reads Int32 battlepassN_owned. JSON booleans are not its wire contract.
        for (const auto &row : data)
        {
            const auto identity = number(row, "id");
            if (identity < 3000000 || identity > 3005000 || (identity - 3000000) % 1000 != 0 ||
                !row.value("premium", false))
                continue;
            const auto season = (identity - 3000000) / 1000 + 1;
            state["battlepass" + std::to_string(season) + "_owned"] = uint64_t{1};
        }
    }

    std::optional<Reply> battlepassActivation(const std::filesystem::path &root,
                                              const platform::LobbyIdentity &id,
                                              const std::string &context,
                                              const std::string &name,
                                              uint64_t selected,
                                              uint64_t timestamp,
                                              const achievement_store::Validator &validate)
    {
        if (id.titleId != 5800)
            return std::nullopt;
        // Ordinary mission activations never touch Battle Pass publication data.
        const bool premiumId =
            selected >= 3000001 && selected <= 3005001 && (selected - 3000001) % 1000 == 0;
        const bool tokenId = selected >= 3000002 && selected <= 3000008;
        if (selected && !premiumId && !tokenId)
            return std::nullopt;
        if (!selected && name == "skip_tier")
            return Reply{106, {}, "battlepass-token-selector-ambiguous"};
        const auto config = rules(root);
        if (config.is_null())
            return std::nullopt;
        const auto &definitions = config.at("activations");
        const auto definition = std::find_if(definitions.begin(),
                                             definitions.end(),
                                             [&](const Json &row)
                                             {
                                                 return selected ? number(row, "id") == selected
                                                                 : row.at("name") == name;
                                             });
        if (definition == definitions.end())
            return std::nullopt;
        if (!name.empty() && definition->at("name") != name)
            return Reply{106, {}, "battlepass-activation-selector-conflict"};
        selected = number(*definition, "id");
        auto data = states(statePath(root, id, context));
        auto *active = find(data, selected);
        if (active && active->value("battlepass_pending", false))
            return Reply{0, {}, "battlepass-activation-idempotent", true, {}};
        auto inventory = prepareRankInventory(root, id, {}, false).document;
        const auto owned = number(item(inventory, number(*definition, "item")), "2", INT32_MAX);
        const auto configured = number(*definition, "season", 6);
        const auto season = configured ? configured : number(config, "current_season", 6);
        const auto *seasonState = find(data, uint64_t{3000000} + (season - 1) * 1000);
        const bool premium =
            !number(*definition, "skips") && seasonState && seasonState->value("premium", false);
        if (!owned && !premium)
            return Reply{101, {}, "battlepass-activation-item-not-owned"};
        if (!active)
        {
            wire::require(data.size() < 15000);
            data.push_back(initial(selected, definition->at("name"), 1));
            active = &data.back();
        }
        (*active)["status"] = uint64_t{1};
        (*active)["activationTimestamp"] = timestamp;
        (*active)["battlepass_pending"] = true;
        (*active)["battlepass_season"] = season;
        (*active)["battlepass_debit"] = owned > 0;
        const achievement_store::Write write{
            id.userId, id.platformAccountId, context, {}, data, Destination::states};
        achievement_store::commit(root, id.titleId, {&write, 1}, validate);
        return Reply{0, {}, "battlepass-activated", true, {}};
    }

    void battlepassEvents(const std::filesystem::path &root,
                          const platform::LobbyIdentity &id,
                          const std::string &context,
                          const Json &events,
                          std::vector<achievement_store::Write> &writes,
                          std::vector<Delivery> &deliveries,
                          bool refresh)
    {
        if (id.titleId != 5800)
            return;
        if (std::none_of(events.begin(),
                         events.end(),
                         [](const Json &event)
                         {
                             const auto &name = event.at("name").get_ref<const std::string &>();
                             const auto &values = event.at("values");
                             return name == "skip_tier" ||
                                    name.starts_with("activate_battlepass") ||
                                    (name == "mp_addxp" && values.contains("Param4") &&
                                     number(values, "Param4") > 0);
                         }))
            return;
        const auto config = rules(root);
        if (config.is_null())
            return;
        const auto stateWrite = std::find_if(writes.begin(), writes.end(), [&](const auto &write)
        {
            return write.owner == id.userId && write.context == context &&
                   write.kind == Destination::states;
        });
        const auto stateIndex = static_cast<size_t>(stateWrite - writes.begin());
        const bool stagedStates = stateWrite != writes.end();
        auto data = stagedStates ? stateWrite->document : states(statePath(root, id, context));
        Json inventory;
        auto existing = std::find_if(writes.begin(),
                                     writes.end(),
                                     [&](const auto &write)
                                     {
                                         return write.owner == id.userId &&
                                                write.kind == Destination::inventory;
                                     });
        if (existing != writes.end())
            inventory = existing->document;
        else
            inventory = prepareRankInventory(root, id, {}, false).document;
        if (refresh)
        {
            std::set<uint64_t> seasons;
            for (const auto &event : events)
            {
                if (event.at("name") == "mp_addxp" && event.at("values").contains("Param4") &&
                    number(event.at("values"), "Param4"))
                    seasons.insert(number(config, "current_season", 6));
                for (const auto &definition : config.at("activations"))
                    if (definition.at("name") == event.at("name"))
                    {
                        const auto *activation = find(data, number(definition, "id"));
                        if (activation && activation->contains("battlepass_season"))
                            seasons.insert(number(*activation, "battlepass_season", 6));
                    }
            }
            for (auto season : seasons)
                if (season >= 1)
                    if (const auto *row = find(data, uint64_t{3000000} + (season - 1) * 1000))
                        deliveries.push_back(update(id, context, *row, inventory, {}, false));
            return;
        }
        bool changed = false;
        std::set<uint64_t> changedSeasons, completedSeasons;
        std::map<uint64_t, std::set<uint64_t>> grants;
        for (const auto &event : events)
        {
            if (event.at("name") == "mp_addxp")
            {
                const auto &values = event.at("values");
                const auto delta = values.contains("Param4") ? number(values, "Param4") : 0;
                if (!delta)
                    continue;
                // Replay's FlushXPCache emits the cached battlepass XP in Param4
                // once per player cache entry. It is independent of Param0 and
                // Param3; later weapon rows explicitly carry zero here.
                const auto season = number(config, "current_season", 6);
                auto &state = progress(data, season);
                const auto &tiers = config.at("seasons").at(std::to_string(season));
                const auto before = xp(state), oldRank = rank(tiers, before);
                const auto maximum = number(tiers.at(100), "xp");
                wire::require(before <= maximum);
                const auto total = before + std::min(delta, maximum - before);
                if (total == before)
                    continue;
                advance(state, tiers, total, inventory, grants[season]);
                changed = true;
                changedSeasons.insert(season);
                if (rank(tiers, total) > oldRank)
                    completedSeasons.insert(season);
                continue;
            }
            if (event.at("name") != "skip_tier" &&
                !event.at("name").get<std::string>().starts_with("activate_battlepass"))
                continue;
            for (const auto &definition : config.at("activations"))
            {
                if (definition.at("name") != event.at("name"))
                    continue;
                auto *activation = find(data, number(definition, "id"));
                if (!activation || !activation->value("battlepass_pending", false))
                    continue;
                const auto season = number(*activation, "battlepass_season", 6);
                wire::require(season >= 1);
                if (activation->value("battlepass_debit", false))
                {
                    auto &owned = item(inventory, number(definition, "item"));
                    const auto quantity = number(owned, "2", INT32_MAX);
                    wire::require(quantity > 0);
                    owned["2"] = quantity - 1;
                }
                (*activation)["battlepass_pending"] = false;
                (*activation)["completionTimestamp"] = event.at("timestamp");
                const auto skips = number(definition, "skips", 100);
                // This is a consumed activation, not an earned challenge state.
                // Native 0x140F33B70 fetches statuses 1/3/5, and every returned
                // non-season kind-20 ID re-enters its pending activation cache.
                // Retire the actuator as INACTIVE (2); keep season progress active.
                (*activation)["status"] = uint64_t{2};
                auto &state = progress(data, season);
                const auto &tiers = config.at("seasons").at(std::to_string(season));
                const auto before = xp(state), oldRank = rank(tiers, before);
                const auto newRank = std::min<uint64_t>(100, oldRank + skips);
                const auto delta = number(tiers.at(static_cast<size_t>(newRank)), "xp") -
                                   number(tiers.at(static_cast<size_t>(oldRank)), "xp");
                wire::require(before <= UINT64_MAX - delta);
                const auto total = std::min(before + delta, number(tiers.at(100), "xp"));
                if (!skips)
                    state["premium"] = true;
                advance(state, tiers, total, inventory, grants[season]);
                changed = true;
                changedSeasons.insert(season);
                completedSeasons.insert(season);
            }
        }
        if (!changed)
            return;
        validateRankInventory(inventory);
        if (existing != writes.end())
            existing->document = inventory;
        else
            writes.push_back(
                {id.userId, id.platformAccountId, "5800", {}, inventory, Destination::inventory});
        if (stagedStates)
            writes[stateIndex].document = data;
        else
            writes.push_back({id.userId, id.platformAccountId, context, {}, data, Destination::states});
        for (auto season : changedSeasons)
            deliveries.push_back(update(id,
                                        context,
                                        *find(data, uint64_t{3000000} + (season - 1) * 1000),
                                        inventory,
                                        grants[season],
                                        completedSeasons.contains(season)));
    }
} // namespace services
