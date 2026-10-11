#pragma once
#include "../third_party/nlohmann/json.hpp"
#include <array>
#include <filesystem>
#include <optional>
#include <string>

namespace services
{
    void validateTournamentMapPolicy(const nlohmann::json &policy, uint32_t title);
    std::optional<nlohmann::json> tournamentMapPolicy(const std::filesystem::path &directory,
                                                      uint32_t title);
    std::array<std::string, 4> tournamentMapsForId(const nlohmann::json &policy,
                                                   uint64_t tournament);
    nlohmann::json tournamentMapDvars(const std::filesystem::path &directory,
                                      uint32_t title,
                                      const nlohmann::json &policy);
} // namespace services
