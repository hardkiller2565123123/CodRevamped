#pragma once
#include "services.h"

namespace services
{
    struct RankInventory
    {
        nlohmann::json document;
        std::vector<std::pair<uint32_t, uint32_t>> quantities;
        std::vector<uint32_t> newlyOwned;
        bool changed = false;
    };

    // The common service-store lock is held. Preparation does not publish.
    RankInventory prepareRankInventory(const std::filesystem::path &,
                                       const platform::LobbyIdentity &,
                                       std::span<const uint32_t> items,
                                       bool award);
    void validateRankInventory(const nlohmann::json &);
    std::optional<Reply> marketplaceServices(const std::filesystem::path &,
                                             const platform::LobbyIdentity &,
                                             uint8_t service,
                                             uint8_t task,
                                             wire::Reader &);
}
