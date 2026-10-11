#pragma once
#include "nlohmann/json.hpp"
#include <filesystem>
#include <functional>
#include <span>

namespace achievement_store
{
    enum class Destination : uint8_t
    {
        event,
        inventory,
        states
    };

    struct Write
    {
        uint64_t owner = 0;
        uint32_t platformAccount = 0;
        std::string context, receiptKey;
        nlohmann::json document;
        Destination kind = Destination::event;
    };

    using Validator = std::function<void(const Write &)>;

    // Service dispatch holds the store lock. Every destination and snapshot is
    // validated before any file is replaced. Interrupted commits roll forward.
    std::filesystem::path destination(const std::filesystem::path &root,
                                      uint32_t title,
                                      const Write &write);
    void recover(const std::filesystem::path &root, uint32_t title, const Validator &validate);
    void commit(const std::filesystem::path &root,
                uint32_t title,
                std::span<const Write> writes,
                const Validator &validate);
} // namespace achievement_store
