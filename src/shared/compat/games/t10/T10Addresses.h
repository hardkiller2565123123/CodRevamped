#pragma once
#include <cstdint>

namespace t10_addresses
{
    enum class Variant
    {
        Unknown,
        Beta,
        Retail
    };

    struct Profile
    {
        const char* label;
        std::uint32_t timestamp;
        std::uint32_t imageSize;
        std::uint32_t entryPointRva;
    };

    // No executable fingerprints/validated runtime addresses have been supplied
    // yet. These profiles intentionally remain scanner-only instead of guessing.
    inline constexpr Profile Beta
    {
        "T10 / Black Ops 6 Beta",
        0,
        0,
        0
    };

    inline constexpr Profile Retail
    {
        "T10 / Black Ops 6 Retail",
        0,
        0,
        0
    };
}
