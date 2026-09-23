#include "T8Scanner.h"
#include "T8Addresses.h"
#include "T8BuildProfile.h"
#include "../../../shared/runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

namespace t8_scanner
{
    namespace
    {
        std::atomic_uint g_runs{ 0 };
        std::atomic_uint g_lastReadable{ 0 };
        std::atomic_uint g_lastExecutable{ 0 };

        std::uintptr_t Base()
        {
            return reinterpret_cast<std::uintptr_t>(
                GetModuleHandleW(nullptr));
        }

        bool CategoryMatches(
            const char* category,
            Mode mode)
        {
            if (mode == Mode::All)
                return true;

            const std::string c =
                category ? category : "";

            switch (mode)
            {
            case Mode::Lua:
                return c == "lua";
            case Mode::Frontend:
                return c == "game" ||
                       c == "platform" ||
                       c == "scheduler" ||
                       c == "input" ||
                       c == "frontend" ||
                       c == "lobby";
            case Mode::Network:
                return c == "game" ||
                       c == "platform" ||
                       c == "network" ||
                       c == "lobby";
            case Mode::Assets:
                return c == "xasset";
            default:
                return true;
            }
        }

        const char* ProtectionName(DWORD protect)
        {
            switch (protect & 0xFF)
            {
            case PAGE_EXECUTE: return "X";
            case PAGE_EXECUTE_READ: return "XR";
            case PAGE_EXECUTE_READWRITE: return "XRW";
            case PAGE_EXECUTE_WRITECOPY: return "XWC";
            case PAGE_READONLY: return "R";
            case PAGE_READWRITE: return "RW";
            case PAGE_WRITECOPY: return "WC";
            default: return "?";
            }
        }
    }

    bool Run(
        Mode mode,
        std::string& message)
    {
        const auto base = Base();
        if (!base)
        {
            message = "T8 module base unavailable";
            return false;
        }

        log_paths::EnsureAll();
        const std::string folder = t8_build::LogFolder(t8_build::Active());
        CreateDirectoryA(folder.c_str(), nullptr);

        std::ofstream out(folder + "\\address_scan.log", std::ios::trunc);

        if (!out)
        {
            message = "could not create T8 address scan log";
            return false;
        }

        unsigned int selected = 0;
        unsigned int readable = 0;
        unsigned int executable = 0;

        const auto& set = t8_build::ActiveAddressSet();

        out
            << "profile="
            << set.fingerprint->label
            << "\n"
            << "profileKey=" << t8_build::Key(set.build) << "\n"
            << "moduleBase=0x"
            << std::hex
            << std::uppercase
            << base
            << std::dec
            << "\n"
            << "importedAddressCount="
            << set.namedCount
            << "\n\n";

        for (std::size_t i = 0; i < set.namedCount; ++i)
        {
            const auto& item = set.named[i];
            if (!CategoryMatches(
                    item.category,
                    mode))
                continue;

            ++selected;

            const auto address =
                t8_addresses::Resolve(
                    base,
                    item.rva);

            MEMORY_BASIC_INFORMATION mbi{};
            const bool queried =
                address &&
                VirtualQuery(
                    reinterpret_cast<const void*>(
                        address),
                    &mbi,
                    sizeof(mbi));

            const bool isReadable =
                queried &&
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect &
                  (PAGE_NOACCESS |
                   PAGE_GUARD));

            const DWORD p =
                queried
                    ? mbi.Protect & 0xFF
                    : 0;

            const bool isExecutable =
                isReadable &&
                (p == PAGE_EXECUTE ||
                 p == PAGE_EXECUTE_READ ||
                 p == PAGE_EXECUTE_READWRITE ||
                 p == PAGE_EXECUTE_WRITECOPY);

            if (isReadable)
                ++readable;
            if (isExecutable)
                ++executable;

            out
                << item.category
                << "\t"
                << item.name
                << "\trva=0x"
                << std::hex
                << std::uppercase
                << item.rva
                << "\taddr=0x"
                << address
                << std::dec
                << "\treadable="
                << (isReadable ? 1 : 0)
                << "\texecutable="
                << (isExecutable ? 1 : 0);

            if (queried)
                out
                    << "\tprotect="
                    << ProtectionName(
                        mbi.Protect);

            out << "\n";
        }

        ++g_runs;
        g_lastReadable.store(readable);
        g_lastExecutable.store(executable);

        std::ostringstream result;
        result
            << "T8 address profile scan complete: selected="
            << selected
            << " readable="
            << readable
            << " executable="
            << executable
            << " -- dump complete";

        message = result.str();

        std::printf(
            "[T8-SCAN] %s\n",
            message.c_str());
        std::fflush(stdout);

        return selected > 0;
    }

    void PrintStatus()
    {
        std::printf(
            "[T8-SCAN] runs=%u lastReadable=%u lastExecutable=%u imported=%llu\n",
            g_runs.load(),
            g_lastReadable.load(),
            g_lastExecutable.load(),
            static_cast<unsigned long long>(t8_build::ActiveAddressSet().namedCount));
        std::fflush(stdout);
    }
}
