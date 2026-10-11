#pragma once
#include <array>
#include <cstdint>
#include "replay_challenge_game_type.h"

// Original capture/plant/defuse packet: preserve both complete UInt64 fields.
// Specific game type comes from Param0's integer conversion. Param1 retains
// producer flags; this build's parser ignores later masks/operator arguments.
struct ReplayObjectiveEvent
{
    std::array<uint64_t, 2> parameters;

    ReplayChallengeGameType gameType() const
    {
        return static_cast<ReplayChallengeGameType>(static_cast<uint32_t>(parameters[0]));
    }
};
