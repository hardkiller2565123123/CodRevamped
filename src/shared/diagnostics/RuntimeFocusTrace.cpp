#include "RuntimeFocusTrace.h"
#include "../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace runtime_focus_trace
{
    namespace
    {
        struct Target
        {
            const char* name;
            std::uintptr_t rva;
            std::uintptr_t radius;
            Mode family;
        };

        // Build217: only the exact candidates already established by earlier
        // research. No broad discovery is done here.
        constexpr Target kTargets[] =
        {
            // LAN/system-link path
            { "LAN_B40DA59", 0xB40DA59, 0x900, Mode::Lan },
            { "LAN_B40E019", 0xB40E019, 0x80,  Mode::Lan },
            { "LAN_B40E283", 0xB40E283, 0x80,  Mode::Lan },
            { "LAN_B40D140", 0xB40D140, 0x180, Mode::Lan },
            { "LAN_B40D310", 0xB40D310, 0x180, Mode::Lan },
            { "LAN_B40D550", 0xB40D550, 0x180, Mode::Lan },
            { "LAN_C174E40", 0xC174E40, 0x120, Mode::Lan },
            { "LAN_C174E50", 0xC174E50, 0x120, Mode::Lan },
            { "LAN_C174ED0", 0xC174ED0, 0x120, Mode::Lan },
            { "LAN_C174F00", 0xC174F00, 0x120, Mode::Lan },
            { "LAN_C174F20", 0xC174F20, 0x120, Mode::Lan },
            { "LAN_C175010", 0xC175010, 0x120, Mode::Lan },
            { "LAN_C175030", 0xC175030, 0x120, Mode::Lan },
            { "LAN_C175060", 0xC175060, 0x120, Mode::Lan },

            // Confirmed online/lobby/matchmaking family
            { "ONLINE_AF93BB0", 0xAF93BB0, 0x180, Mode::Online },
            { "ONLINE_AF93C90", 0xAF93C90, 0x180, Mode::Online },
            { "ONLINE_AF93D60", 0xAF93D60, 0x180, Mode::Online },
            { "ONLINE_AF93DF0", 0xAF93DF0, 0x180, Mode::Online },
            { "ONLINE_AF95680", 0xAF95680, 0x180, Mode::Online },
            { "ONLINE_AF95710", 0xAF95710, 0x180, Mode::Online },
            { "ONLINE_AF958B0", 0xAF958B0, 0x220, Mode::Online },
            { "ONLINE_AF95940", 0xAF95940, 0x180, Mode::Online },
            { "ONLINE_AF95980", 0xAF95980, 0x180, Mode::Online },
            { "ONLINE_AF95A50", 0xAF95A50, 0x180, Mode::Online },
            { "ONLINE_AF95BA0", 0xAF95BA0, 0x180, Mode::Online },
            { "ONLINE_AF95E60", 0xAF95E60, 0x200, Mode::Online },
            { "ONLINE_D2B7820", 0xD2B7820, 0x240, Mode::Online },
            { "ONLINE_D2B7A00", 0xD2B7A00, 0x240, Mode::Online },
            { "ONLINE_D232F70", 0xD232F70, 0x240, Mode::Online },
        };

        constexpr std::size_t kTargetCount =
            sizeof(kTargets) / sizeof(kTargets[0]);

        std::atomic_bool g_running{ false };
        std::atomic<Mode> g_mode{ Mode::Off };
        std::mutex g_logMutex;
        std::array<std::atomic_uint, kTargetCount> g_hits{};
        std::atomic_uint g_networkStacks{ 0 };
        std::atomic_uint g_networkEvents{ 0 };
        std::atomic_uint64_t g_authManager{ 0 };
        std::atomic_uint g_networkMode{ 0 };
        std::atomic_bool g_inited{ false };

        bool FamilyEnabled(Mode targetFamily)
        {
            const Mode mode = g_mode.load();
            return mode == Mode::Both || mode == targetFamily;
        }

        std::uintptr_t MainBase()
        {
            return reinterpret_cast<std::uintptr_t>(
                GetModuleHandleW(nullptr));
        }

        std::string LogPath()
        {
            std::ostringstream out;
            out << "logs\\research\\runtime_focus_"
                << GetCurrentProcessId() << ".log";
            return out.str();
        }

        void Append(const std::string& line)
        {
            log_paths::EnsureAll();
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::ofstream file(LogPath(), std::ios::app);
            if (!file)
                return;

            SYSTEMTIME st{};
            GetLocalTime(&st);
            char stamp[32]{};
            sprintf_s(
                stamp,
                "%02u:%02u:%02u.%03u",
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds);
            file << stamp << " " << line << "\n";
        }

        int MatchAddress(std::uintptr_t address)
        {
            const auto base = MainBase();
            if (!base || address < base)
                return -1;

            const auto rva = address - base;
            for (std::size_t i = 0; i < kTargetCount; ++i)
            {
                const auto& target = kTargets[i];
                if (!FamilyEnabled(target.family))
                    continue;

                if (rva >= target.rva &&
                    rva < target.rva + target.radius)
                    return static_cast<int>(i);
            }

            return -1;
        }

        void RecordHit(
            std::size_t index,
            const char* source,
            DWORD threadId,
            std::uintptr_t address)
        {
            const unsigned int hit =
                g_hits[index].fetch_add(1) + 1;

            // Log the first 16 hits per target, then powers of two. This keeps
            // hot lobby loops from exploding the log.
            const bool shouldLog =
                hit <= 16 || (hit & (hit - 1)) == 0;
            if (!shouldLog)
                return;

            const auto base = MainBase();
            std::ostringstream out;
            out << "[HIT] source=" << source
                << " target=" << kTargets[index].name
                << " hit=" << hit
                << " tid=" << threadId
                << " rva=0x" << std::hex
                << (address >= base ? address - base : address)
                << std::dec;
            Append(out.str());
        }

    }

    bool Start(Mode mode, std::string& message)
    {
        if (mode == Mode::Off)
        {
            message = "use Stop() for off";
            return false;
        }

        g_mode.store(mode);

        for (auto& hit : g_hits)
            hit.store(0);
        g_networkStacks.store(0);
        g_networkEvents.store(0);

        g_running.store(true);

        Append(mode == Mode::Lan
            ? "[TRACE] mode=LAN"
            : mode == Mode::Online
                ? "[TRACE] mode=ONLINE"
                : "[TRACE] mode=BOTH");

        message =
            "runtime focus trace enabled; perform the menu/lobby action now";
        return true;
    }

    void Stop(std::string& message)
    {
        g_running.store(false);
        g_mode.store(Mode::Off);

        std::ostringstream out;
        out << "runtime focus trace stopped; passive=yes networkEvents="
            << g_networkEvents.load()
            << " targetStacks="
            << g_networkStacks.load();

        for (std::size_t i = 0;
             i < kTargetCount; ++i)
        {
            const auto count = g_hits[i].load();
            if (count)
                out << " " << kTargets[i].name
                    << "=" << count;
        }

        message = out.str();
        Append("[SUMMARY] " + message);
    }

    std::string Status()
    {
        std::ostringstream out;
        const Mode mode = g_mode.load();

        out << "runtime focus trace="
            << (g_running.load() ? "running" : "stopped")
            << " mode="
            << (mode == Mode::Lan ? "lan"
                : mode == Mode::Online ? "online"
                : mode == Mode::Both ? "both"
                : "off")
            << " passive=yes networkEvents="
            << g_networkEvents.load()
            << " targetStacks=" << g_networkStacks.load();

        for (std::size_t i = 0;
             i < kTargetCount; ++i)
        {
            const auto count = g_hits[i].load();
            if (count)
                out << " " << kTargets[i].name
                    << "=" << count;
        }

        return out.str();
    }

    void Mark(const std::string& label)
    {
        Append("[MARK] " + label);
    }

    void ObserveCurrentNetworkStack(const char* api)
    {
        if (!g_running.load())
            return;

        const unsigned int eventIndex =
            g_networkEvents.fetch_add(1);

        std::ostringstream out;
        out << "[NET] api="
            << (api ? api : "network")
            << " event=" << eventIndex
            << " tid=" << GetCurrentThreadId()
            << " auth=0x" << std::hex
            << g_authManager.load()
            << " networkMode=0x"
            << g_networkMode.load()
            << std::dec
            << " inited="
            << (g_inited.load() ? 1 : 0);

        Append(out.str());
    }

    void ObserveDnsRequest(
        const char* api,
        const char* host,
        std::uintptr_t callerAddress)
    {
        if (!g_running.load())
            return;

        std::string value = host ? host : "(null)";
        std::string lower = value;
        std::transform(
            lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });

        const char* category = "DNS_OTHER";
        if (lower.find("demonware.net") != std::string::npos)
        {
            if (lower.find("t9-steam-loginservice") !=
                std::string::npos)
            {
                category = "DEMONWARE_STEAM_LOGIN";
            }
            else
            {
                category =
                    lower.find("stun") != std::string::npos
                        ? "DEMONWARE_STUN_NAT"
                        : "DEMONWARE_SERVICE";
            }
        }
        else if (lower.find("battle.net") != std::string::npos ||
                 lower.find("battlenet") != std::string::npos ||
                 lower.find("blizzard") != std::string::npos)
        {
            category = "BNET_BOOTSTRAP";
        }
        else if (lower.find("activision") != std::string::npos ||
                 lower.find("callofduty") != std::string::npos)
        {
            category = "ACTIVISION_SERVICE";
        }
        else if (lower.find("uno") != std::string::npos)
        {
            category = "UNO_IDENTITY";
        }

        std::ostringstream out;
        const auto module =
            GetModuleHandleW(nullptr);
        const auto moduleBase =
            reinterpret_cast<std::uintptr_t>(module);

        std::uintptr_t moduleEnd = 0;
        if (moduleBase)
        {
            IMAGE_DOS_HEADER dos{};
            IMAGE_NT_HEADERS64 nt{};
            SIZE_T got = 0;

            if (ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(moduleBase),
                    &dos, sizeof(dos), &got) &&
                got == sizeof(dos) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(
                        moduleBase +
                        static_cast<std::uintptr_t>(
                            dos.e_lfanew)),
                    &nt, sizeof(nt), &got) &&
                got == sizeof(nt) &&
                nt.Signature == IMAGE_NT_SIGNATURE)
            {
                moduleEnd =
                    moduleBase +
                    static_cast<std::uintptr_t>(
                        nt.OptionalHeader.SizeOfImage);
            }
        }

        out << "[DNS] api=" << (api ? api : "dns")
            << " category=" << category
            << " host=" << value
            << " tid=" << GetCurrentThreadId();

        if (callerAddress)
        {
            out << " caller=0x"
                << std::hex << callerAddress;

            if (moduleBase &&
                moduleEnd &&
                callerAddress >= moduleBase &&
                callerAddress < moduleEnd)
            {
                out << " callerGameRva=0x"
                    << (callerAddress - moduleBase);
            }

            out << std::dec;
        }

        Append(out.str());

        if (strcmp(category, "DEMONWARE_STEAM_LOGIN") == 0)
        {
            Mark("demonware_steam_login_dns_attempt");

            char path[MAX_PATH]{};
            sprintf_s(
                path,
                "logs\\online\\steam_login_callers_%lu.log",
                static_cast<unsigned long>(
                    GetCurrentProcessId()));

            HANDLE file = CreateFileA(
                path,
                FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (file != INVALID_HANDLE_VALUE)
            {
                char line[1024]{};
                int used = sprintf_s(
                    line,
                    "[LOGIN-DNS] api=%s tid=%lu caller=0x%llX",
                    api ? api : "dns",
                    static_cast<unsigned long>(
                        GetCurrentThreadId()),
                    static_cast<unsigned long long>(
                        callerAddress));

                if (moduleBase &&
                    moduleEnd &&
                    callerAddress >= moduleBase &&
                    callerAddress < moduleEnd)
                {
                    used += sprintf_s(
                        line + used,
                        sizeof(line) - used,
                        " callerRva=0x%llX",
                        static_cast<unsigned long long>(
                            callerAddress - moduleBase));
                }

                used += sprintf_s(
                    line + used,
                    sizeof(line) - used,
                    " auth=0x%llX networkMode=0x%X inited=%u\\r\\n",
                    static_cast<unsigned long long>(
                        g_authManager.load()),
                    g_networkMode.load(),
                    g_inited.load() ? 1u : 0u);

                DWORD written = 0;
                WriteFile(
                    file,
                    line,
                    static_cast<DWORD>(used),
                    &written,
                    nullptr);

                if (callerAddress > 0x80)
                {
                    const auto start =
                        callerAddress - 0x80;
                    unsigned char bytes[0x140]{};
                    SIZE_T got = 0;

                    if (ReadProcessMemory(
                            GetCurrentProcess(),
                            reinterpret_cast<const void*>(
                                start),
                            bytes,
                            sizeof(bytes),
                            &got) &&
                        got)
                    {
                        for (SIZE_T off = 0;
                             off < got;
                             off += 16)
                        {
                            char byteLine[256]{};
                            int byteUsed = 0;

                            if (moduleBase &&
                                start + off >= moduleBase &&
                                start + off < moduleEnd)
                            {
                                byteUsed = sprintf_s(
                                    byteLine,
                                    "    rva=0x%llX: ",
                                    static_cast<unsigned long long>(
                                        start + off - moduleBase));
                            }
                            else
                            {
                                byteUsed = sprintf_s(
                                    byteLine,
                                    "    abs=0x%llX: ",
                                    static_cast<unsigned long long>(
                                        start + off));
                            }

                            for (SIZE_T j = 0;
                                 j < 16 &&
                                 off + j < got;
                                 ++j)
                            {
                                byteUsed += sprintf_s(
                                    byteLine + byteUsed,
                                    sizeof(byteLine) - byteUsed,
                                    "%02X ",
                                    static_cast<unsigned int>(
                                        bytes[off + j]));
                            }

                            byteUsed += sprintf_s(
                                byteLine + byteUsed,
                                sizeof(byteLine) - byteUsed,
                                "\\r\\n");

                            WriteFile(
                                file,
                                byteLine,
                                static_cast<DWORD>(byteUsed),
                                &written,
                                nullptr);
                        }
                    }
                }

                CloseHandle(file);
            }
        }

        ObserveCurrentNetworkStack(api ? api : "dns");
    }

    void UpdateCorrelationState(
        std::uintptr_t authManager,
        std::uint32_t networkMode,
        bool inited)
    {
        g_authManager.store(
            static_cast<std::uint64_t>(authManager));
        g_networkMode.store(networkMode);
        g_inited.store(inited);
    }

}
