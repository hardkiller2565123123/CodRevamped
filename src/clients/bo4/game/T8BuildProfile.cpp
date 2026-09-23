#include "T8BuildProfile.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <cstdio>
#include <sstream>

namespace t8_build
{
    namespace
    {
        std::uintptr_t Base() noexcept
        {
            return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        }

        bool Matches(const PeFingerprint& actual, const t8_addresses::Fingerprint& wanted) noexcept
        {
            return wanted.timestamp && wanted.imageSize && wanted.entryPointRva &&
                actual.timestamp == wanted.timestamp &&
                actual.imageSize == wanted.imageSize &&
                actual.entryPointRva == wanted.entryPointRva;
        }

        bool ReadU32(std::uintptr_t address, std::uint32_t& value) noexcept
        {
            SIZE_T got = 0;
            return address &&
                ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                    &value, sizeof(value), &got) && got == sizeof(value);
        }

        const t8_addresses::AddressSet& AddressSetFor(t8_addresses::Build build) noexcept
        {
            switch (build)
            {
            case t8_addresses::Build::MultiplayerBetaAug2018:
                return t8_addresses::MultiplayerBetaAddressSet;
            case t8_addresses::Build::BlackoutBetaSep2018:
                return t8_addresses::BlackoutBetaAddressSet;
            case t8_addresses::Build::LatestBnet:
            default:
                return t8_addresses::RetailAddressSet;
            }
        }
    }

    bool IsBlackOps4Process() noexcept
    {
        wchar_t path[MAX_PATH]{};
        const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (!length || length >= MAX_PATH)
            return false;

        const wchar_t* base = path;
        for (DWORD i = 0; i < length; ++i)
            if (path[i] == L'\\' || path[i] == L'/')
                base = path + i + 1;

        return lstrcmpiW(base, L"BlackOps4.exe") == 0;
    }

    PeFingerprint ReadPeFingerprint() noexcept
    {
        PeFingerprint result{};
        const auto base = Base();
        if (!base)
            return result;

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return result;

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return result;

            result.timestamp = nt->FileHeader.TimeDateStamp;
            result.imageSize = nt->OptionalHeader.SizeOfImage;
            result.entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return {};
        }
        return result;
    }

    t8_addresses::Build Detect() noexcept
    {
        if (!IsBlackOps4Process())
            return t8_addresses::Build::Unknown;

        const auto pe = ReadPeFingerprint();
        if (Matches(pe, t8_addresses::MultiplayerBetaAug2018))
            return t8_addresses::Build::MultiplayerBetaAug2018;
        if (Matches(pe, t8_addresses::BlackoutBetaSep2018))
            return t8_addresses::Build::BlackoutBetaSep2018;

        // Preserve the working retail behavior: any BlackOps4.exe that is not
        // one of the two exact beta fingerprints is routed through the retail
        // Shield path and the CL marker is verified later during startup.
        return t8_addresses::Build::LatestBnet;
    }

    t8_addresses::Build Active() noexcept
    {
        static const auto build = Detect();
        return build;
    }

    const t8_addresses::AddressSet& ActiveAddressSet() noexcept
    {
        return AddressSetFor(Active());
    }

    const t8_addresses::CoreRvas& ActiveCore() noexcept
    {
        return *ActiveAddressSet().core;
    }

    const char* Key(t8_addresses::Build build) noexcept
    {
        switch (build)
        {
        case t8_addresses::Build::LatestBnet: return "retail";
        case t8_addresses::Build::MultiplayerBetaAug2018: return "mp_beta";
        case t8_addresses::Build::BlackoutBetaSep2018: return "blackout_beta";
        default: return "unknown";
        }
    }

    const char* Label(t8_addresses::Build build) noexcept
    {
        return AddressSetFor(build).fingerprint->label;
    }

    const char* LogFolder(t8_addresses::Build build) noexcept
    {
        switch (build)
        {
        case t8_addresses::Build::MultiplayerBetaAug2018: return "logs\\t8_mp_beta";
        case t8_addresses::Build::BlackoutBetaSep2018: return "logs\\t8_blackout_beta";
        case t8_addresses::Build::LatestBnet: return "logs\\t8";
        default: return "logs\\t8_unknown";
        }
    }

    bool IsRetail() noexcept { return Active() == t8_addresses::Build::LatestBnet; }
    bool IsMultiplayerBeta() noexcept { return Active() == t8_addresses::Build::MultiplayerBetaAug2018; }
    bool IsBlackoutBeta() noexcept { return Active() == t8_addresses::Build::BlackoutBetaSep2018; }

    bool VerifyActive(std::string& message) noexcept
    {
        if (!IsBlackOps4Process())
        {
            message = "process is not BlackOps4.exe";
            return false;
        }

        const auto& set = ActiveAddressSet();
        const auto& fp = *set.fingerprint;
        const auto pe = ReadPeFingerprint();

        if (fp.timestamp &&
            (pe.timestamp != fp.timestamp || pe.imageSize != fp.imageSize || pe.entryPointRva != fp.entryPointRva))
        {
            std::ostringstream out;
            out << "PE fingerprint mismatch for " << fp.label
                << " actual(ts=0x" << std::hex << pe.timestamp
                << " image=0x" << pe.imageSize
                << " entry=0x" << pe.entryPointRva << ")";
            message = out.str();
            return false;
        }

        if (fp.buildMarkerRva && fp.expectedBuildMarker)
        {
            std::uint32_t marker = 0;
            if (!ReadU32(Base() + fp.buildMarkerRva, marker))
            {
                message = std::string("could not read build marker for ") + fp.label;
                return false;
            }
            if (marker != fp.expectedBuildMarker)
            {
                std::ostringstream out;
                out << "build marker mismatch for " << fp.label
                    << " actual=" << std::dec << marker
                    << " expected=" << fp.expectedBuildMarker;
                message = out.str();
                return false;
            }
        }

        std::ostringstream out;
        out << "profile=" << Key(set.build)
            << " verified=yes addressEntries=" << set.namedCount
            << " retailMapEntries=" << set.retailMapCount
            << " fullClientMap=" << (set.fullClientAddressMapComplete ? "complete" : "partial");
        message = out.str();
        return true;
    }

    std::uintptr_t TranslatePreferredAddress(std::uintptr_t preferredVa) noexcept
    {
        const auto base = Base();
        if (!base || preferredVa < t8_addresses::PreferredImageBase)
            return 0;

        if (IsRetail())
            return base + (preferredVa - t8_addresses::PreferredImageBase);

        const auto& set = ActiveAddressSet();
        for (std::size_t i = 0; i < set.retailMapCount; ++i)
        {
            if (set.retailMap[i].retailPreferredVa == preferredVa)
                return base + set.retailMap[i].buildRva;
        }

        // Never silently reuse a 2023 retail RVA on a 2018 executable.
        return 0;
    }

    bool FullClientAddressMapComplete() noexcept
    {
        return ActiveAddressSet().fullClientAddressMapComplete;
    }
}
