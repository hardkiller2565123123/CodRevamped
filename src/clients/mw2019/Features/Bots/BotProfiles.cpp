#include "BotProfiles.h"
#include "BotProfilePolicy.h"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

namespace codrevamped::bots120
{
    namespace
    {
        constexpr unsigned kNamesResource = 41021;
        struct NameSpan { std::uint32_t start{}, length{}; };
        const char* s_data = nullptr;
        std::vector<NameSpan> s_names;
        std::once_flag s_loadOnce;
        std::atomic<std::uint64_t> s_lobby{0};

        using policy::Mix;
        void LoadNames() noexcept
        {
            HMODULE module = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<LPCWSTR>(&LoadNames), &module)) return;
            HRSRC source = FindResourceW(module, MAKEINTRESOURCEW(kNamesResource), RT_RCDATA);
            if (!source) return;
            HGLOBAL handle = LoadResource(module, source);
            if (!handle) return;
            const auto size = static_cast<std::uint32_t>(SizeofResource(module, source));
            s_data = static_cast<const char*>(LockResource(handle));
            if (!s_data || !size) return;
            s_names.reserve(100000);
            for (std::uint32_t begin = 0, i = 0; i <= size; ++i)
            {
                if (i < size && s_data[i] != '\n') continue;
                std::uint32_t end = i;
                while (end > begin && s_data[end - 1] == '\r') --end;
                if (end > begin && end - begin < 36)
                    s_names.push_back({begin, end - begin});
                begin = i + 1;
            }
        }
    }
    void SetLobby(std::uint64_t lobby) noexcept { s_lobby.store(lobby, std::memory_order_relaxed); }
    unsigned NameCount() noexcept
    {
        std::call_once(s_loadOnce, LoadNames);
        return static_cast<unsigned>(s_names.size());
    }
    const char* StyleName(unsigned style) noexcept
    {
        static constexpr const char* kStyles[] = {
            "Assault", "SMG", "Marksman", "Sniper", "LMG", "Support", "Shotgun", "Flanker"
        };
        return kStyles[style % 8];
    }
    const char* TierName(unsigned tier) noexcept
    {
        return policy::TierName(static_cast<policy::Tier>(std::min(tier, 4u)));
    }
    const char* WeaponName(unsigned n) noexcept
    {
        // Display labels, NOT unverified fastfile/loot IDs.
        static constexpr const char* names[] = {
            "M4A1", "Kilo 141", "Grau 5.56", "RAM-7", "M13", "AK-47",
            "MP5", "MP7", "P90", "AUG", "Fennec", "PKM", "Bruen Mk9",
            "Kar98k", "HDR", "AX-50", "Origin 12", "R9-0", "725",
            "CR-56 AMAX", "FN SCAR 17", "Uzi", "PP19 Bizon", "Oden"
        };
        return names[n % (sizeof(names) / sizeof(*names))];
    }
    const char* CallingCardTheme(unsigned theme) noexcept
    {
        static constexpr const char* themes[] = {
            "Veteran", "Victory", "Precision", "Night Ops", "Blackout",
            "Reaper", "Recon", "Tactical", "Ember", "Frost",
            "Desert", "Urban", "Skull", "Spec Ops", "Storm", "Shadow"
        };
        return themes[theme % 16];
    }
    Profile For(unsigned ordinal) noexcept
    {
        Profile result{};
        const auto count = NameCount();
        const std::uint64_t lobby = s_lobby.load(std::memory_order_relaxed);
        const std::uint64_t seed = Mix((lobby ? lobby : 1) ^ 0x424f544944454e54ull);
        const std::uint64_t id = Mix(seed ^ (static_cast<std::uint64_t>(ordinal) << 17));
        if (count)
        {
            const auto which = static_cast<unsigned>((seed % count +
                              std::uint64_t(ordinal) * 173ull) % count);
            const auto span = s_names[which];
            std::memcpy(result.name, s_data + span.start, span.length);
            result.name[span.length] = '\0';
        }
        else
            std::snprintf(result.name, sizeof(result.name), "Operator%03u", ordinal + 1);
        const auto tier = policy::ChooseTier(id);
        result.skillTier = static_cast<unsigned>(tier);
        result.accuracyPercent = policy::AccuracyPercent(tier, id + 9);
        result.reactionMilliseconds = policy::ReactionMs(tier, id + 10);
        result.aggression = policy::Between(id + 11, 10, 95);
        result.movement = policy::Between(id + 12, 20, 99);
        // Experience and combat ability are related but not identical.
        result.rank = policy::Between(id + 13, 1, 155);
        result.prestige = result.rank > 55 ? policy::Between(id + 14, 0, 10) : 0;
        result.platform = policy::Between(id + 15, 0, 2);
        result.gamepad = result.platform != 0 || policy::Between(id + 16, 0, 99) < 40;
        result.style = policy::Between(id + 17, 0, 7);
        result.favoriteWeapon = policy::Between(id + 18, 0, 23);
        result.secondaryWeapon = policy::Between(id + 19, 0, 23);
        result.operatorTheme = policy::Between(id + 20, 0, 15);
        result.callingCardTheme = policy::Between(id + 21, 0, 15);
        // Zero are deliberate: only the engine can authorize actual playercard
        // asset indices. Unverified raw indices can corrupt the frontend.
        result.emblem = 0;
        result.background = 0;
        result.matches = policy::Between(id + 22, 4, 2800);
        const unsigned winPercent = policy::Between(id + 23, 2,
            tier == policy::Tier::Elite ? 48u : 30u);
        result.wins = result.matches * winPercent / 100;
        const unsigned avgKills = 2 + result.accuracyPercent / 8 +
            (tier == policy::Tier::Elite ? 5u : 0u);
        result.kills = result.matches * avgKills;
        const unsigned avgDeaths = 8 + policy::Between(id + 24, 0, 8);
        result.deaths = result.matches * avgDeaths;
        result.assists = result.matches * policy::Between(id + 25, 0, 7);
        result.headshots = result.kills * policy::Between(id + 26, 5, 46) / 100;
        result.streakBest = policy::Between(id + 27, 1, tier == policy::Tier::Elite ? 24u : 12u);
        result.hoursPlayed = policy::Between(id + 28, 2, 1600);
        result.kdHundredths = (result.kills * 100u) / std::max(1u, result.deaths);
        result.winRatePercent = result.wins * 100u / std::max(1u, result.matches);
        return result;
    }
}
