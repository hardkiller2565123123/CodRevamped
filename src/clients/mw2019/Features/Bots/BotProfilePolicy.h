#pragma once
#include <cstdint>

// Deterministic, lobby-scoped presentation profile only. Actual shooting,
// pathfinding, damage, and loadouts remain the game's native responsibility.
namespace codrevamped::bots120::policy
{
    constexpr std::uint64_t Mix(std::uint64_t x) noexcept
    {
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
        return x ^ (x >> 31);
    }
    enum class Tier : unsigned { VeryEasy, Casual, Average, Skilled, Elite };
    constexpr Tier ChooseTier(std::uint64_t seed) noexcept
    {
        // 3% inexperienced, 17% casual, 54% average, 21% skilled,
        // 5% elite; percentages hold statistically across many lobbies.
        const unsigned roll = static_cast<unsigned>(Mix(seed ^ 0x534b494c4c544945ull) % 100);
        return roll < 3 ? Tier::VeryEasy : roll < 20 ? Tier::Casual :
               roll < 74 ? Tier::Average : roll < 95 ? Tier::Skilled : Tier::Elite;
    }
    constexpr unsigned Between(std::uint64_t seed, unsigned lo, unsigned hi) noexcept
    {
        return lo + static_cast<unsigned>(Mix(seed) % (hi - lo + 1u));
    }
    constexpr unsigned AccuracyPercent(Tier tier, std::uint64_t seed) noexcept
    {
        switch (tier)
        {
        case Tier::VeryEasy: return Between(seed, 3, 12);
        case Tier::Casual: return Between(seed, 12, 24);
        case Tier::Average: return Between(seed, 23, 38);
        case Tier::Skilled: return Between(seed, 36, 51);
        default: return Between(seed, 48, 66);
        }
    }
    constexpr unsigned ReactionMs(Tier tier, std::uint64_t seed) noexcept
    {
        switch (tier)
        {
        case Tier::VeryEasy: return Between(seed, 650, 1000);
        case Tier::Casual: return Between(seed, 420, 740);
        case Tier::Average: return Between(seed, 280, 490);
        case Tier::Skilled: return Between(seed, 160, 310);
        default: return Between(seed, 105, 205);
        }
    }
    constexpr const char* TierName(Tier tier) noexcept
    {
        switch (tier)
        {
        case Tier::VeryEasy: return "Newcomer";
        case Tier::Casual: return "Casual";
        case Tier::Average: return "Regular";
        case Tier::Skilled: return "Veteran";
        default: return "Elite";
        }
    }
}
