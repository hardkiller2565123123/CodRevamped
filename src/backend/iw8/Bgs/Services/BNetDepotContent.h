#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace revamped::iw8::bgs::depot
{
    // Battle.net's BNet/apft resource is a NUL-separated sequence of
    // filter-name / regular-expression pairs.  A local empty filter remains a
    // syntactically valid resource while avoiding any dependency on Blizzard's
    // historical depot object.  The hash below is SHA-256 of kProfanityBody,
    // exactly as required by bgs.protocol.ContentHandle.
    inline constexpr std::array<std::uint8_t, 29> kProfanityBody = {
        'b','a','d',0,'a','^',0,
        'r','e','s','e','r','v','e','d',0,'a','^',0,
        's','2','m','a','p','s',0,'a','^',0
    };

    inline constexpr std::array<std::uint8_t, 32> kProfanitySha256 = {
        0x7F, 0xA8, 0x57, 0x71, 0xEE, 0x17, 0x42, 0x46,
        0x35, 0x13, 0x95, 0xF7, 0x3E, 0x76, 0x1B, 0xEC,
        0xAC, 0x3B, 0x6A, 0x6A, 0x8B, 0xE5, 0x0A, 0x6C,
        0xF2, 0x39, 0xB3, 0xAE, 0xE0, 0xA9, 0x4D, 0xE0
    };

    inline constexpr char kProfanityHashHex[] =
        "7fa85771ee174246351395f73e761becac3b6a6a8be50a6cf239b3aee0a94de0";
}
