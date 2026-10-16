#pragma once
#include <cstdint>

// Synthetic *lobby presentation* profiles. No platform logins, real account
// statistics, entitlements, or gameplay weapon inventories are created.
namespace codrevamped::bots120
{
    struct Profile
    {
        char name[36]{};
        unsigned rank{}, prestige{}, platform{};
        bool gamepad{};
        unsigned emblem{}, background{}, callingCardTheme{}, operatorTheme{};
        unsigned style{}, skillTier{}, accuracyPercent{}, reactionMilliseconds{};
        unsigned aggression{}, movement{}, matches{}, wins{}, kills{}, deaths{};
        unsigned headshots{}, assists{}, streakBest{}, hoursPlayed{}, kdHundredths{}, winRatePercent{};
        unsigned favoriteWeapon{}, secondaryWeapon{};
    };
    void SetLobby(std::uint64_t lobby) noexcept;
    Profile For(unsigned ordinal) noexcept;
    unsigned NameCount() noexcept;
    const char* StyleName(unsigned style) noexcept;
    const char* TierName(unsigned tier) noexcept;
    const char* WeaponName(unsigned weapon) noexcept;
    const char* CallingCardTheme(unsigned theme) noexcept;
}
