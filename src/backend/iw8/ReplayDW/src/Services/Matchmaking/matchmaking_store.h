#pragma once
#include "nlohmann/json.hpp"
#include <filesystem>
#include <span>

namespace matchmaking_store
{
    struct Write
    {
        std::string path;
        nlohmann::json document;
    };

    // Callers hold the service-store mutex. Recovery validates every entry
    // before publishing any snapshot; incomplete commits roll forward.
    void initialize(const std::filesystem::path &directory);
    void recover(const std::filesystem::path &root, uint32_t title);
    void validateWrite(const Write &write, uint32_t title);
    void validatePendingJoins(const nlohmann::json &lobby);
    void commit(const std::filesystem::path &root, uint32_t title, std::span<const Write> writes);
} // namespace matchmaking_store
