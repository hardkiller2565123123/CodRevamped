#pragma once
#include "nlohmann/json.hpp"
#include <filesystem>
#include <optional>

namespace services
{
    struct PlaylistSelection
    {
        nlohmann::json rules;
        nlohmann::json metadata;
        unsigned teamCount = 0;
        unsigned squadSize = 0;
        unsigned maximumMembers = 0; // zero only when no native capacity rule is published
        bool splitPartiesForTeamBalance = false;
    };

    std::optional<PlaylistSelection> selectPlaylist(const std::filesystem::path &directory,
                                                    uint32_t title,
                                                    const nlohmann::json &query,
                                                    const std::string &requiredMap = {},
                                                    unsigned preferredPlaylist = 0);
} // namespace services
