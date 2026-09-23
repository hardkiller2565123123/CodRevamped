#pragma once

#include <cstddef>
#include <cstdint>

namespace patches::win11
{
    // Generic Windows 11 compatibility patch description.
    // IMPORTANT: this project intentionally contains no game/build addresses.
    // Every executable fingerprint and RVA is owned by the game project that
    // uses this patch engine (ColdWar, MW2019, BO4, ...).
    struct ExecutableFingerprint
    {
        std::uint32_t timestamp{};
        std::uint32_t imageSize{};
        std::uint32_t entryPointRva{};
    };

    struct Profile
    {
        const char* name{};
        ExecutableFingerprint executable{};
        std::uintptr_t exceptionFilterRva{};
        std::uintptr_t breakpointRva{};
        std::uintptr_t resumeRva{};
        std::uint8_t restoreByte{};
        bool discoveryOnly{};
        std::uintptr_t probeDumpRva{};
        std::size_t probeDumpSize{};
    };

    // Installs the generic one-shot Win11 exception redirect for one exact
    // build profile supplied by a game project. Returns false without writing
    // to the process if the current executable fingerprint does not match.
    bool Initialize(const Profile& profile);

    bool IsArmed();
    bool HasApplied();
    const char* ActiveProfileName();
}
