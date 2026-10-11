#include "quest_services.h"
#include "replay_quest_data.h"
#include "replay_kill_data.h"
#include "replay_kill_event.h"
#include "replay_objective_event.h"
#include <algorithm>
#include <string_view>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        uint64_t number(const Json &row, const char *key)
        {
            const auto value = row.value(key, Json(uint64_t{0}));
            wire::require(value.is_number_unsigned());
            return value.get<uint64_t>();
        }

        const ReplayQuest *quest(uint64_t id)
        {
            const auto row = std::find_if(replayQuests.begin(), replayQuests.end(),
                                           [id](const auto &value) { return value.id == id; });
            return row == replayQuests.end() ? nullptr : &*row;
        }

        Json *find(Json &states, uint32_t id)
        {
            const auto row = std::find_if(states.begin(), states.end(),
                                           [id](const Json &value) { return number(value, "id") == id; });
            return row == states.end() ? nullptr : &*row;
        }

        // Same-image ProcessParams 0x140F35980: Param0 low 16 = weapon/equipment
        // ID; Param5 high 16 = class mask, low byte = attachment count; Param6
        // bits 16..31 = means-of-death ordinal. Kill events bypass the <=4-param
        // aggregate caches. Do not interpret packed values as raw kill counts.
        bool killMatches(uint32_t id, const Json &values)
        {
            ReplayKillEvent event{};
            for (unsigned index = 0; index < event.parameters.size(); ++index)
                event.parameters[index] = number(values, ("Param" + std::to_string(index)).c_str());
            const auto weapon = event.weapon();
            const auto classification = event.classification();
            const auto attachments = event.attachmentCount();
            const auto cause = event.cause();
            const auto mode = event.gameType();
            const auto marksman = std::find(replay_kill_data::Marksman.begin(),
                                            replay_kill_data::Marksman.end(), weapon) !=
                                  replay_kill_data::Marksman.end();
            const auto sniper = std::find(replay_kill_data::Sniper.begin(),
                                          replay_kill_data::Sniper.end(), weapon) !=
                                replay_kill_data::Sniper.end();
            // Destruction is reported through the same native kill packet.
            // Its flags overlap: a killstreak vehicle satisfies both criteria.
            if (id == 10012)
                return event.targets(ReplayKillTarget::Vehicle);
            if (id == 10013)
                return event.targets(ReplayKillTarget::Killstreak);
            if (!event.targets(ReplayKillTarget::Player))
                return false;
            switch (id)
            {
            case 1501:
            case 1569:
                return true;
            case 1503:
                return (classification & 0xC00) == 0xC00;
            case 1505:
                return classification == 3;
            case 1506:
                return classification == 5;
            case 1507:
                return classification == 9;
            case 1508:
                return classification == 17;
            case 1509:
                // Replay packs DMRs into the same class mask. The shipped
                // statstable distinguishes weapon_dmr from weapon_sniper.
                return classification == 65 && sniper;
            case 1510:
                return classification == 129;
            case 1513:
                return cause == 21;
            case 1514:
            case 1563:
                return event.hasPerk(replay_kill_data::Ghost);
            case 1562:
                return (classification & 0xC00) == 0xC00 &&
                       event.hasPerk(replay_kill_data::Shrapnel);
            case 1553:
                return weapon == 50000;
            case 1555:
                return weapon == 50002;
            case 1556:
                return weapon == 50007;
            case 1557:
                return weapon == 50001;
            case 1559:
            case 10007:
                return weapon == 50004 || weapon == 50017;
            case 1560:
                return weapon == 50006;
            case 1571:
                return (classification & 0x400) != 0;
            case 1570:
                return mode == ReplayChallengeGameType::war && cause == 9;
            case 1589:
                return mode == ReplayChallengeGameType::war;
            case 1592:
                return mode == ReplayChallengeGameType::hq;
            case 1594:
                return attachments == 1 && (classification & 1) != 0;
            case 1595:
                return cause == 9 && event.optic() == replay_kill_data::Reflex &&
                       (classification & 1) != 0;
            case 1596:
                return classification == 17 && attachments == 5;
            case 1597:
                return weapon == 18;
            case 1598:
                return classification == 65 && marksman && attachments == 5;
            case 1600:
                return classification == 65 && sniper &&
                       attachments == 5 && cause == 9;
            case 1624:
                return classification == 129 && event.optic() == replay_kill_data::Reflex;
            case 10000:
                return classification == 5 && cause == 9;
            case 10003:
                return classification == 5 && event.hasPerk(replay_kill_data::Tracker);
            case 10006:
                return classification == 5 && event.hasPerk(replay_kill_data::DoubleTime);
            case 10004:
                return classification == 5 && mode == ReplayChallengeGameType::arena;
            case 10047:
                return weapon == replay_challenge_mode_data::M19Weapon &&
                       mode == ReplayChallengeGameType::dom;
            case 10040:
                return cause == 9 && event.optic() == replay_kill_data::VariableZoom &&
                       (classification & 1) != 0;
            case 10044:
                return weapon == 1;
            case 10046:
                return weapon == 5 && attachments == 3;
            case 10131:
                return weapon == replay_kill_data::Ak47 && cause == 9;
            default:
                return false;
            }
        }

        bool completeParameters(const Json &values, unsigned count)
        {
            for (unsigned index = 0; index < count; ++index)
                if (!values.contains("Param" + std::to_string(index)))
                    return false;
            return true;
        }

        uint64_t counter(const Json &values, const char *name)
        {
            const auto value = number(values, name);
            wire::require(value <= UINT32_MAX);
            return value;
        }

        uint64_t mpProgress(uint32_t id, const Json &event)
        {
            const auto &values = event.at("values");
            const auto &name = event.at("name");
            if ((name == "capture" || name == "plant" || name == "defuse") &&
                completeParameters(values, 2))
            {
                const ReplayObjectiveEvent objective{{number(values, "Param0"), number(values, "Param1")}};
                const auto mode = objective.gameType();
                if (name == "capture")
                {
                    if (id == 1512 || id == 1588)
                        return mode == ReplayChallengeGameType::dom;
                    if (id == 1517)
                        return mode == ReplayChallengeGameType::hq;
                }
                // Shipped onplant calls the defuse event too. Both native names
                // describe one completed bomb action for this combined criterion.
                if (id == 1590 && (name == "plant" || name == "defuse"))
                    return mode == ReplayChallengeGameType::sd || mode == ReplayChallengeGameType::cyber;
                return 0;
            }
            if (id == 1558 && event.at("name") == "stim" && completeParameters(values, 1))
            {
                // Original ProcessParams converts the reported health amount
                // to an integer before it is submitted as Param0.
                // Count that amount, rather than treating each use as one heal.
                return counter(values, "Param0");
            }
            if (event.at("name") == "kill" && completeParameters(values, 7))
                return killMatches(id, values) ? uint64_t{1} : uint64_t{0};
            return 0;
        }

        uint64_t brProgress(uint32_t id, const Json &event, Json &state)
        {
            const auto &values = event.at("values");
            const auto &name = event.at("name").get_ref<const std::string &>();
            uint64_t contractLocale = 0;
            // Shipped setupchallengelocales assigns IDs to location_volume
            // script_noteworthy labels. Param1 is the contract card's locale;
            // Param0 is the player's locale and can differ near a boundary.
            switch (id)
            {
            case 50012: contractLocale = 4; break; // dam
            case 50015:
            case 50082: contractLocale = 33; break; // tvstation
            case 50019:
            case 50068: contractLocale = 15; break; // port
            case 50022:
            case 50075: contractLocale = 32; break; // transit / train station
            case 50026:
            case 50078: contractLocale = 6; break; // farms
            case 50029: contractLocale = 31; break; // super
            case 50033: contractLocale = 11; break; // lumber
            case 50036: contractLocale = 2; break; // boneyard
            case 50040: contractLocale = 10; break; // layover / airport
            case 50043: contractLocale = 5; break; // downtown
            case 50047:
            case 50085: contractLocale = 7; break; // gulag / prison complex
            case 50050: contractLocale = 8; break; // hospital
            case 50054:
            case 50071: contractLocale = 1; break; // airfield / military base
            case 50057: contractLocale = 20; break; // stadium
            case 50061: contractLocale = 21; break; // storagetown
            case 50064: contractLocale = 16; break; // quarry
            default: break;
            }
            if (contractLocale)
                return name == "contract_start" && completeParameters(values, 3) &&
                       number(values, "Param1") == contractLocale ? 1 : 0;
            switch (id)
            {
            case 50006:
            case 50034:
                // Successful crate selection reports both preset (0) and custom
                // (1) classes. The generic collection stages accept either.
                return name == "loadout" && completeParameters(values, 2) &&
                       number(values, "Param0") <= 1 ? 1 : 0;
            case 50011:
            case 50024:
            case 50070:
                // Replay's shared UI/BR reference table maps armor_plate to 7.
                // Collecting a plate is distinct from consuming it.
                return name == "use_item" && completeParameters(values, 2) &&
                       number(values, "Param0") == 7 ? 1 : 0;
            case 50016:
            case 50023:
            case 50030:
            case 50037:
            case 50044:
            case 50051:
            case 50058:
            case 50065:
            case 50072:
            case 50079:
            case 50086:
                // brmissions.csv defines IDs 1..11. releaseteamonquest reports
                // success=1 to contract owners (role=1), including dead team
                // members; hunted targets (role=2) receive a separate outcome.
                return name == "contract_end" && completeParameters(values, 5) &&
                       number(values, "Param0") >= 1 && number(values, "Param0") <= 11 &&
                       number(values, "Param1") == 1 && number(values, "Param2") <= 1 &&
                       number(values, "Param3") == 1 ? 1 : 0;
            case 50000:
            case 50001:
            case 50003:
                if (name != "ping" || !completeParameters(values, 2))
                    return 0;
                // Native UI StringTable mp/achievementenginerefs.csv. Other
                // builds differ: Replay's object is 13, not map_enemy (11).
                return number(values, "Param0") ==
                       (id == 50000 ? 9u : id == 50001 ? 13u : 10u) ? 1 : 0;
            case 50014:
            case 50077:
                return name == "revive" && completeParameters(values, 3) &&
                       number(values, "Param0") == 1 && number(values, "Param1") == 1 ? 1 : 0;
            case 50049:
                return name == "revive" && completeParameters(values, 3) &&
                       number(values, "Param0") == 0 && number(values, "Param1") == 1 ? 1 : 0;
            case 50048:
            case 50076:
                return name == "gulag_end_match" && completeParameters(values, 2) &&
                       number(values, "Param0") == 1 ? 1 : 0;
            case 50005:
                return name == "pickup" && completeParameters(values, 4)
                           ? counter(values, "Param0") : 0;
            case 50007:
            case 50042:
            case 50066:
            case 50069:
                return name == "pickup" && completeParameters(values, 4)
                           ? counter(values, "Param1") : 0;
            case 50010:
            case 50031:
            case 50084:
                return name == "pickup" && completeParameters(values, 4)
                           ? counter(values, "Param2") : 0;
            default:
                break;
            }
            uint64_t divisor = 0;
            if ((id == 50008 || id == 50063) && name == "alive_in_gas")
                divisor = 1000;
            else if ((id == 50009 || id == 50021) && name == "driving")
                divisor = 60000;
            else if (id == 50059 && name == "alive_not_downed")
                divisor = 60000;
            if (!divisor || !completeParameters(values, 2))
                return 0;
            // The original script reports gettime() differences in ms. Timers
            // and pickup counts are summed by native event caches. Preserve
            // sub-unit time across batches and restarts, never round up.
            const auto remainder = number(state, "timerRemainderMs");
            wire::require(remainder < divisor);
            const auto total = remainder + counter(values, "Param0");
            state["timerRemainderMs"] = total % divisor;
            return total / divisor;
        }

        std::string snapshotHash(const Json &states, const Json &state)
        {
            auto selected = Json::array();
            const auto *owner = quest(number(state, "id"));
            wire::require(owner);
            for (const auto &candidate : states)
                if (number(candidate, "kind") == 15 && number(candidate, "status") == 1)
                    if (const auto *definition = quest(number(candidate, "id"));
                        definition && definition->category == owner->category)
                        selected.push_back(number(candidate, "id"));
            const auto bytes = Json{{"state", state}, {"selected", selected}}.dump();
            return wire::base64Encode(crypto::sha256(
                {reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()}));
        }
    } // namespace

    bool replayQuestEventMayEarn(const std::string &name)
    {
        // Keep admission beside the earning rules. The achievement transport
        // must not maintain a separate list that silently drops a new family.
        static constexpr std::array<std::string_view, 16> supported = {
            "kill", "stim", "pickup", "driving", "alive_in_gas", "alive_not_downed",
            "revive", "gulag_end_match", "ping", "contract_start", "contract_end",
            "use_item", "loadout", "capture", "plant", "defuse"};
        return std::find(supported.begin(), supported.end(), std::string_view(name)) != supported.end();
    }

    QuestProgress advanceReplayQuests(const Json &stored, const Json &events,
                                       std::optional<unsigned> publicCategory)
    {
        wire::require(stored.is_array() && stored.size() <= 15000);
        QuestProgress result;
        result.states = stored;
        if (!publicCategory)
            return result;
        for (const auto &event : events)
        {
            const auto &values = event.at("values");
            // The original AddGamemode emits 2 for MP, 8/24 for BR. Neither
            // client gamemode nor a public-looking name proves lobby membership.
            const auto mode = number(values, "gamemode");
            if (number(values, "version") != 1 || (mode != 2 && mode != 8 && mode != 24))
                continue;
            const auto category = mode == 2 ? 0u : 1u;
            if (category != *publicCategory)
                continue;
            std::vector<uint32_t> active;
            for (const auto &state : result.states)
                if (number(state, "kind") == 15 && number(state, "status") == 1)
                    if (const auto *row = quest(number(state, "id")); row && row->category == category)
                        active.push_back(row->id);
            wire::require(active.size() <= 1);
            // Snapshot active selections before processing this event: one report
            // cannot also satisfy the successor activated by that same kill.
            for (const auto identity : active)
            {
                const auto &row = *quest(identity);
                auto &state = *find(result.states, identity);
                if (state.at("name") != row.name || number(state, "target") != row.target ||
                    number(event, "timestamp") < number(state, "activationTimestamp"))
                    continue;
                const auto before = number(state, "progress");
                if (before >= row.target)
                    continue;
                const auto oldRemainder = number(state, "timerRemainderMs");
                const auto increment = category == 1 ? brProgress(identity, event, state)
                    : mpProgress(identity, event);
                if (!increment && oldRemainder == number(state, "timerRemainderMs"))
                    continue;
                const auto total = before + std::min(increment, uint64_t{row.target} - before);
                state["progress"] = total;
                const bool finished = total == row.target;
                result.updates[identity] = finished;
                if (!finished)
                    continue;
                state["status"] = uint64_t{3};
                state["completionCount"] = uint64_t{1};
                state["completionTimestamp"] = number(event, "timestamp");
                wire::require(result.xp <= UINT64_MAX - row.xpReward);
                result.xp += row.xpReward;
                if (row.itemReward)
                    result.items.insert(row.itemReward);
                if (const auto *next = quest(row.nextId))
                {
                    auto *successor = find(result.states, next->id);
                    if (!successor)
                    {
                        wire::require(result.states.size() < 15000);
                        result.states.push_back(Json{{"id", uint64_t{next->id}},
                                                      {"name", next->name},
                                                      {"kind", uint64_t{15}},
                                                      {"status", uint64_t{2}},
                                                      {"progress", uint64_t{0}},
                                                      {"target", uint64_t{next->target}}});
                        successor = &result.states.back();
                    }
                    if (number(*successor, "status") == 2)
                    {
                        wire::require(successor->at("name") == next->name &&
                                      number(*successor, "kind") == 15 &&
                                      number(*successor, "target") == next->target);
                        (*successor)["status"] = uint64_t{1};
                        (*successor)["activationTimestamp"] = number(event, "timestamp");
                        result.successors[identity] = next->id;
                    }
                }
            }
        }
        return result;
    }

    std::vector<Delivery> replayQuestUpdates(const platform::LobbyIdentity &id,
                                              const std::string &context,
                                              const QuestProgress &progress,
                                              const RankInventory *inventory,
                                              bool refresh)
    {
        std::vector<Delivery> result;
        for (const auto &[identity, completed] : progress.updates)
        {
            const auto &row = *quest(identity);
            const auto state = std::find_if(progress.states.begin(), progress.states.end(),
                                             [identity](const Json &value)
                                             { return number(value, "id") == identity; });
            wire::require(state != progress.states.end());
            Json event{{"type", "ACHIEVEMENT"}, {"kind", uint64_t{15}},
                       {"id_", uint64_t{identity}}, {"name", row.name},
                       {"progress", number(*state, "progress")},
                       {"reason", completed && !refresh ? "completed" : "inProgress"}};
            auto triggers = Json::array();
            if (completed && row.itemReward && inventory)
                for (const auto &[item, quantity] : inventory->quantities)
                    if (item == row.itemReward && quantity)
                        triggers.push_back(Json{{"type", "GRANT_PRODUCT"},
                                                {"inventory", {{"granted_items", Json::array(
                                                    {{{"id", item}, {"quantity", quantity}}})}}}});
            // HandleCompletion 0x1410635F0 consumes this named activation trigger.
            // Retries refresh absolute progress without replaying completion UI
            // or appending another successor to the native 640-stage cache.
            if (completed && !refresh && progress.successors.contains(identity))
                if (const auto *next = quest(progress.successors.at(identity)))
                    triggers.push_back(Json{{"type", "ACTIVATE_ACHIEVEMENT"}, {"name", next->name}});
            if (!triggers.empty())
                event["triggers"] = std::move(triggers);
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
            push.text(event.dump());
            Delivery delivery{id.userId, std::move(push.data)};
            delivery.questContext = context;
            delivery.questId = identity;
            delivery.questStateHash = snapshotHash(progress.states, *state);
            result.push_back(std::move(delivery));
        }
        return result;
    }

    bool replayQuestDeliveryValid(const Json &states, const Delivery &delivery)
    {
        wire::require(states.is_array() && states.size() <= 15000 && quest(delivery.questId));
        const auto row = std::find_if(states.begin(), states.end(), [&](const Json &value)
                                     { return number(value, "id") == delivery.questId; });
        return row != states.end() && snapshotHash(states, *row) == delivery.questStateHash;
    }
} // namespace services
