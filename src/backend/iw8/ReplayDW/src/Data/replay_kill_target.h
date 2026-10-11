#pragma once
#include <cstdint>

// Generated from Replay's native findenemytype/return_enemy_type_mask.
// Flags can overlap; unrecognized bits in the packet remain intact.
enum class ReplayKillTarget : uint16_t
{
    Player = 1,
    Killstreak = 2,
    AirborneStreak = 4,
    Ground = 8,
    SupportStreak = 16,
    Vehicle = 32,
    Equipment = 64,
    AgentSoldier = 512,
    AgentJuggernaut = 128,
    AgentSuicideBomber = 1024,
    AgentShield = 256,
};
