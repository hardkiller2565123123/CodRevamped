#pragma once
#include "nlohmann/json.hpp"
#include <filesystem>

namespace channel_store
{
    using Json = nlohmann::json;
    // Replay OnlineChat::AddMemberToChat 0x141B31530 has 200 member slots.
    inline constexpr uint32_t memberLimit = 200;
    // Validate the whole persisted layout, upgrading legacy fields in memory.
    Json load(const std::filesystem::path &path, uint32_t title);
    void save(const std::filesystem::path &path, uint32_t title, const Json &state);
    uint32_t advance(Json &channel);
} // namespace channel_store
