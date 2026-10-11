#pragma once
#include "services.h"
#include <vector>

namespace services
{
    void recoverAchievementWrites(const std::filesystem::path &, uint32_t title);
    struct StoredProgression
    {
        uint64_t user = 0, xp = 0;
        std::string name;
    };

    std::vector<StoredProgression> achievementProgressionSnapshot(
        const std::filesystem::path &, uint32_t title, const std::string &context);
    bool achievementDeliveryValid(const std::filesystem::path &, uint32_t title,
                                  const Delivery &);
    std::vector<Delivery> currentProgressionDeliveries(const std::filesystem::path &,
                                                      uint32_t title, uint64_t user);
    void restoreAchievementProgression(const std::filesystem::path &,
                                       uint32_t title, uint64_t user, uint64_t xp,
                                       bool restore, unsigned startingRank,
                                       uint32_t platformAccount = 0);
    std::optional<Reply> achievementServices(const std::filesystem::path &,
                                             const platform::LobbyIdentity &,
                                             uint8_t,
                                             uint8_t,
                                             wire::Reader &);
    Reply achievementEventsRest(const std::filesystem::path &,
                                const platform::LobbyIdentity &,
                                const std::string &,
                                std::span<const uint8_t>);
} // namespace services
