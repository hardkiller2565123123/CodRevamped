#pragma once
#include <array>
#include <cstdint>
#include "replay_kill_target.h"
#include "replay_challenge_game_type.h"

// Complete seven-UInt64 native kill/death parameter packet. Retain every bit;
// only expose meanings verified by original ProcessParams execution. The
// other actor, operator, mode and modifier fields remain opaque here.
struct ReplayKillEvent
{
    std::array<uint64_t, 7> parameters;

    uint16_t weapon() const { return static_cast<uint16_t>(parameters[0]); }
    uint16_t classification() const { return static_cast<uint16_t>(parameters[5] >> 48); }
    uint16_t target() const { return static_cast<uint16_t>(parameters[5] >> 16); }
    uint8_t attachmentCount() const { return static_cast<uint8_t>(parameters[5]); }
    uint16_t optic() const { return static_cast<uint16_t>(parameters[6]); }
    uint16_t cause() const { return static_cast<uint16_t>(parameters[6] >> 16); }
    ReplayChallengeGameType gameType() const
    {
        return static_cast<ReplayChallengeGameType>(static_cast<uint32_t>(parameters[2] >> 32));
    }

    bool targets(ReplayKillTarget flag) const
    {
        return (target() & static_cast<uint16_t>(flag)) != 0;
    }

    bool hasPerk(uint16_t id) const
    {
        // Param4 contains three 16-bit loadout IDs plus the upper super-ID
        // field. Searching the upper field could incorrectly identify a perk.
        for (unsigned slot = 0; slot < 3; ++slot)
            if (static_cast<uint16_t>(parameters[4] >> (16 * slot)) == id)
                return true;
        return false;
    }
};
