#include "ColdWarPatches.h"

#include "T9Addresses.h"
#include "../../../shared/patches/Win11Patch.h"

#include <Windows.h>
#include <cstdint>

namespace
{
    using patches::win11::ExecutableFingerprint;
    using patches::win11::Profile;

    // Cold War owns these addresses. The generic Patches project only knows
    // how to apply a supplied profile and contains no game-specific RVAs.
    constexpr Profile kJune4AlphaWin11
    {
        "Cold War June 4 Alpha",
        {
            t9_addresses::AlphaFingerprint.timestamp,
            t9_addresses::AlphaFingerprint.imageSize,
            t9_addresses::AlphaFingerprint.entryPointRva
        },
        0x0212915Cu, // observed SetUnhandledExceptionFilter target
        0x109A858Du, // one-shot breakpoint
        0x0050D2E2u, // Win11-safe resume
        0x0Fu        // original byte restored after breakpoint
    };

    // Exact October Open Beta Win11 redirect recovered from the working
    // compatibility path. Keep it isolated from the old Beta gameplay/
    // frontend bootstrap: v7 only re-enables the one-shot Win11 compatibility
    // fix so the executable can stay alive long enough for the focused Retail-
    // style address/direct-camo scanner to observe it.
    constexpr Profile kOpenBetaWin11
    {
        "Cold War Open Beta",
        {
            t9_addresses::BetaFingerprint.timestamp,
            t9_addresses::BetaFingerprint.imageSize,
            t9_addresses::BetaFingerprint.entryPointRva
        },
        t9_addresses::OpenBetaRecovered.exceptionFilter,
        t9_addresses::OpenBetaRecovered.win11Breakpoint,
        t9_addresses::OpenBetaRecovered.win11Resume,
        0x74u // recovered original byte at the one-shot breakpoint
    };

    constexpr Profile kSeason2Win11
    {
        "Cold War Season 2",
        {
            t9_addresses::Season2Fingerprint.timestamp,
            t9_addresses::Season2Fingerprint.imageSize,
            t9_addresses::Season2Fingerprint.entryPointRva
        },
        0x0CBD699Cu, // observed handler shape: entry RVA + 0x2FC
        0,
        0,
        0,
        true,
        0x004584F0u, // runtime function containing the old beta comparison area
        0x0001589Cu
    };

    bool ReadFingerprint(ExecutableFingerprint& out)
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return false;

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return false;

            out.timestamp = nt->FileHeader.TimeDateStamp;
            out.imageSize = nt->OptionalHeader.SizeOfImage;
            out.entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool Matches(
        const ExecutableFingerprint& actual,
        const ExecutableFingerprint& expected)
    {
        return actual.timestamp == expected.timestamp &&
               actual.imageSize == expected.imageSize &&
               actual.entryPointRva == expected.entryPointRva;
    }
}

namespace coldwar_patches
{
    bool InitializeEarly()
    {
        ExecutableFingerprint actual{};
        if (!ReadFingerprint(actual))
            return false;

        if (Matches(actual, kJune4AlphaWin11.executable))
            return patches::win11::Initialize(kJune4AlphaWin11);

        if (Matches(actual, kOpenBetaWin11.executable))
            return patches::win11::Initialize(kOpenBetaWin11);

        if (Matches(actual, kSeason2Win11.executable))
            return patches::win11::Initialize(kSeason2Win11);

        return false;
    }
}
