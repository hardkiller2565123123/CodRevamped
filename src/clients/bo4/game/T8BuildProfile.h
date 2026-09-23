#pragma once

#include "T8Addresses.h"

#include <cstdint>
#include <string>

namespace t8_build
{
    struct PeFingerprint
    {
        std::uint32_t timestamp{};
        std::uint32_t imageSize{};
        std::uint32_t entryPointRva{};
    };

    bool IsBlackOps4Process() noexcept;
    PeFingerprint ReadPeFingerprint() noexcept;

    // Detection is runtime-only. The same BO4 version.dll supports retail,
    // Multiplayer Beta, and Blackout Beta without separate DLL projects.
    t8_addresses::Build Detect() noexcept;
    t8_addresses::Build Active() noexcept;
    const t8_addresses::AddressSet& ActiveAddressSet() noexcept;
    const t8_addresses::CoreRvas& ActiveCore() noexcept;

    const char* Key(t8_addresses::Build build) noexcept;
    const char* Label(t8_addresses::Build build) noexcept;
    const char* LogFolder(t8_addresses::Build build) noexcept;

    bool IsRetail() noexcept;
    bool IsMultiplayerBeta() noexcept;
    bool IsBlackoutBeta() noexcept;

    // Validates the exact beta fingerprint and the per-build marker when one is
    // known. Retail keeps Shield's CL marker verification.
    bool VerifyActive(std::string& message) noexcept;

    // Retail Shield uses preferred VAs through the _g literal. This function is
    // now the one translation seam for the entire T8 family. Retail translates
    // directly. Betas only translate addresses explicitly mapped later; until
    // those tables are complete, the retail full-client hook set remains gated.
    std::uintptr_t TranslatePreferredAddress(std::uintptr_t preferredVa) noexcept;
    bool FullClientAddressMapComplete() noexcept;
}
