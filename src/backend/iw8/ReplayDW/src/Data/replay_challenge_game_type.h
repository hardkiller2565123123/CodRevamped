#pragma once
#include <cstdint>

// Generated from Replay initchallengeandeventglobals and native operands.
// These are specific game types, distinct from the gamemode family field.
enum class ReplayChallengeGameType : uint32_t
{
    dm = 5,
    war = 6,
    sd = 7,
    dom = 8,
    conf = 9,
    sr = 10,
    grind = 11,
    ball = 12,
    infect = 13,
    tjugg = 14,
    gun = 15,
    grnd = 16,
    siege = 17,
    koth = 18,
    ctf = 19,
    dd = 20,
    tdef = 21,
    front = 22,
    cmd = 23,
    br = 24,
    arena = 25,
    cyber = 26,
    rush = 27,
    esc = 28,
    vip = 29,
    btm = 30,
    rugby = 31,
    arm = 32,
    mtmc = 33,
    snatch = 34,
    hq = 35,
    defcon = 36,
    pill = 37,
    blitz = 38,
    brm = 39,
    hvt = 40,
    trial = 41,
    cp_survival = 42,
    cp_wave_sv = 43,
};

namespace replay_challenge_mode_data
{
    inline constexpr uint16_t M19Weapon = 2;
}
