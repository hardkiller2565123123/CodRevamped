#pragma once
#include "services.h"
#include "marketplace_services.h"
#include <map>
#include <set>
#include <string>

namespace services
{
    // Admission alone never establishes public-match/category eligibility.
    bool replayQuestEventMayEarn(const std::string &name);
    struct QuestProgress
    {
        nlohmann::json states;
        std::map<uint32_t, bool> updates;
        std::map<uint32_t, uint32_t> successors;
        std::set<uint32_t> items;
        uint64_t xp = 0;
    };

    // Original Replay parser fields and shipped mission criteria only.
    // Unbound producer predicates leave their selected stages unchanged.
    QuestProgress advanceReplayQuests(const nlohmann::json &states,
                                       const nlohmann::json &events,
                                       std::optional<unsigned> publicCategory);
    std::vector<Delivery> replayQuestUpdates(const platform::LobbyIdentity &identity,
                                              const std::string &context,
                                              const QuestProgress &progress,
                                              const RankInventory *inventory,
                                              bool refresh = false);
    bool replayQuestDeliveryValid(const nlohmann::json &states, const Delivery &delivery);
} // namespace services
