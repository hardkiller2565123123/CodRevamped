#pragma once
#include "services.h"
#include "nlohmann/json.hpp"

namespace services
{
    // Caller owns the service-store lock; visits enrollment and persisted formations,
    // independently of sockets or a surviving tournament catalog/enrollment file.
    void retireUnavailableManagedTournaments(const std::filesystem::path &directory,
                                             uint32_t title,
                                             const std::function<void(const std::string &)> &log);
    // Pure snapshot validators shared with matchmaking transaction recovery.
    void validateTournamentFormation(const nlohmann::json &state, uint32_t title, uint64_t id);
    void validateTournamentEnrollments(const nlohmann::json &state, uint32_t title);
    void validateTournamentTermination(const nlohmann::json &state, uint32_t title, uint64_t id);
    std::optional<Delivery> currentTournamentRoundDelivery(const std::filesystem::path &directory,
                                                           uint32_t title,
                                                           uint64_t user);
    // Called only after matchmaking validates the request's authenticated party tokens.
    std::optional<Reply> startTournamentSearch(const std::filesystem::path &directory,
                                               const platform::LobbyIdentity &identity,
                                               const nlohmann::json &query);
    std::optional<Delivery> currentTournamentDelivery(const std::filesystem::path &directory,
                                                      uint32_t title,
                                                      uint64_t user);
    bool tournamentDeliveryValid(const std::filesystem::path &directory,
                                 uint32_t title,
                                 const Delivery &delivery);
    std::optional<Reply> tournamentServices(const std::filesystem::path &directory,
                                            const platform::LobbyIdentity &identity,
                                            uint8_t service,
                                            uint8_t task,
                                            wire::Reader &params);
} // namespace services
