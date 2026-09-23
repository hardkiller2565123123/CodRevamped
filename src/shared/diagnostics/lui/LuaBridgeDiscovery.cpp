#include "LuaBridgeDiscovery.h"
#include "../../core/Main.hpp"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace lua_bridge_discovery
{
    namespace
    {
        std::atomic_bool g_running{ false };
        std::atomic_bool g_completed{ false };
        std::atomic_bool g_bridgeReady{ false };

        struct Candidate
        {
            const char* name;
            std::uintptr_t rva;
        };

        // Recovered from the user's runtime research_catalog. These are a
        // tightly clustered Lua-engine family in this exact retail build.
        const Candidate kCandidates[] =
        {
            { "__Lua_Engine_Function_49C5F27295601778", 0x1D64E50 },
            { "__Lua_Engine_Function_66F76A7726BAA362", 0x1D64F60 },
            { "__Lua_Engine_Function_5392DE52AAF1524A", 0x1D65080 },
            { "__Lua_Engine_Function_642C33FC244F1071", 0x1D650D0 },
            { "__Lua_Engine_Function_6B356BB0AF6EE665", 0x1D65220 },
            { "__Lua_Engine_Function_3D36C267A07DB296", 0x1D652C0 },
            { "__Lua_Engine_Function_7A12CA07097B822B", 0x1D65330 },
            { "__Lua_Engine_Function_61BBB39F76C1A04B", 0x1D65410 },
            { "__Lua_Engine_Function_6A0F0BC61EE66B5E", 0x1D65500 },
            { "__Lua_Engine_Function_CE326D48856DEBC",  0x1D65570 },
            { "__Lua_Engine_Function_5A31A6CCD8DCD181", 0x1D65600 },
            { "__Lua_Engine_Function_65BBAEBE20B6669F", 0x1D656F0 },
            { "__Lua_Engine_Function_889A6176CDF642D",  0x1D65800 },
            { "__Lua_Engine_Function_6881698562E943FA", 0x1D658A0 },
            { "__Lua_Engine_Function_47899906EABDA3E1", 0x1D6F990 },
            { "__Lua_Engine_Function_LuiVM_Event",       0x1D85690 },
        };

        template <typename T>
        bool SafeRead(
            std::uintptr_t address,
            T& value)
        {
            SIZE_T got = 0;
            return address &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    &value,
                    sizeof(value),
                    &got) &&
                got == sizeof(value);
        }

        bool SafeReadBytes(
            std::uintptr_t address,
            void* output,
            std::size_t size)
        {
            SIZE_T got = 0;
            return address && output && size &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    output,
                    size,
                    &got) &&
                got == size;
        }

        void Print(
            const char* fmt,
            ...)
        {
            char buffer[2048]{};
            va_list args;
            va_start(args, fmt);
            vsprintf_s(buffer, sizeof(buffer), fmt, args);
            va_end(args);
            printf("%s", buffer);
            fflush(stdout);
        }

        std::string HexBytes(
            std::uintptr_t address,
            std::size_t count)
        {
            std::vector<unsigned char> bytes(count);

            if (!SafeReadBytes(
                    address,
                    bytes.data(),
                    bytes.size()))
            {
                return {};
            }

            std::ostringstream out;
            out << std::hex << std::uppercase << std::setfill('0');

            for (std::size_t i = 0; i < bytes.size(); ++i)
            {
                if (i) out << ' ';
                out << std::setw(2)
                    << static_cast<unsigned int>(bytes[i]);
            }

            return out.str();
        }

        void ScanReferencesToCandidate(
            std::uintptr_t module,
            std::uintptr_t imageSize,
            const Candidate& candidate,
            std::ofstream& refs)
        {
            const auto target =
                module + candidate.rva;

            constexpr std::size_t chunkSize =
                1024 * 1024;

            std::vector<unsigned char>
                bytes(chunkSize + 8);

            for (std::uintptr_t consumed = 0;
                 consumed < imageSize;)
            {
                const auto want =
                    static_cast<std::size_t>(
                        (std::min<std::uintptr_t>)(
                            chunkSize,
                            imageSize - consumed));

                SIZE_T got = 0;

                if (!ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(
                            module + consumed),
                        bytes.data(),
                        want,
                        &got) ||
                    got < 5)
                {
                    consumed += want;
                    continue;
                }

                for (SIZE_T i = 0;
                     i + 5 <= got;
                     ++i)
                {
                    if (bytes[i] != 0xE8 &&
                        bytes[i] != 0xE9)
                    {
                        continue;
                    }

                    std::int32_t rel = 0;
                    std::memcpy(
                        &rel,
                        bytes.data() + i + 1,
                        sizeof(rel));

                    const auto at =
                        module +
                        consumed +
                        i;

                    const auto resolved =
                        static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(
                                at + 5) +
                            rel);

                    if (resolved != target)
                        continue;

                    refs
                        << candidate.name
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << candidate.rva
                        << ",0x"
                        << (at - module)
                        << ","
                        << (bytes[i] == 0xE8 ? "CALL" : "JMP")
                        << "\n";
                }

                consumed += want;
            }
        }

        bool RunScan(
            std::string& message)
        {
            g_completed.store(false);

            log_paths::EnsureAll();
            CreateDirectoryA("logs\\lui", nullptr);

            {
                std::ofstream decoded(
                    "logs\\lui\\decoded_director_knowledge.txt",
                    std::ios::trunc);

                if (decoded)
                {
                    decoded
                        << "[READABLE LUAJIT KNOWLEDGE FROM EARLIER DUMPS]\\n"
                        << "0x6C22220D6FCFCCA7 index 1728:\\n"
                        << "  LuaUtils.ShouldShowCampaign\\n"
                        << "  LuaUtils.ShouldShowMultiplayer\\n"
                        << "  LuaUtils.ShouldShowZombies\\n"
                        << "  LuaUtils.ShouldShowWarzone\\n"
                        << "  LuaUtils.GetLanMenu\\n"
                        << "  LuaUtils.GetLanSelectMenu\\n"
                        << "  LuaUtils.GetOnlineSelectMenu\\n"
                        << "  LuaUtils.GetDirectorMainMenu\\n"
                        << "  ForceLobbyButtonUpdate\\n"
                        << "\\n0x463D46EAF0995AEE index 1751:\\n"
                        << "  BootMenu\\n"
                        << "  ZombiesMain\\n"
                        << "  MultiplayerMain\\n"
                        << "  FrontendMain\\n"
                        << "  menu_open / menu_go_back\\n"
                        << "\\n0x1C73A5DF0BB8A2A6 index 1756:\\n"
                        << "  navToMenu\\n"
                        << "  OnGoForward\\n"
                        << "  GetDirectorMainMenu\\n"
                        << "  GetLobbyMenuIDByName\\n";
                }
            }

            const auto module =
                reinterpret_cast<std::uintptr_t>(
                    GetModuleHandleW(nullptr));

            if (!module)
            {
                message = "game module unavailable";
                g_completed.store(true);
                return false;
            }

            IMAGE_DOS_HEADER dos{};
            IMAGE_NT_HEADERS64 nt{};

            if (!SafeRead(module, dos) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE ||
                !SafeRead(
                    module +
                        static_cast<std::uintptr_t>(
                            dos.e_lfanew),
                    nt) ||
                nt.Signature != IMAGE_NT_SIGNATURE)
            {
                message = "could not parse game image";
                g_completed.store(true);
                return false;
            }

            const auto imageSize =
                static_cast<std::uintptr_t>(
                    nt.OptionalHeader.SizeOfImage);

            std::ofstream report(
                "logs\\lui\\lua_bridge_candidates.txt",
                std::ios::trunc);

            std::ofstream refs(
                "logs\\lui\\lua_bridge_callers.csv",
                std::ios::trunc);

            if (refs)
                refs << "candidate,candidate_rva,caller_rva,kind\n";

            Print(
                "\n[LUA-BRIDGE] ========================================\n"
                "[LUA-BRIDGE] BUILD260 Lua source bridge discovery START\n");

            for (const auto& c : kCandidates)
            {
                const auto address =
                    module + c.rva;

                MEMORY_BASIC_INFORMATION mbi{};
                const bool valid =
                    VirtualQuery(
                        reinterpret_cast<const void*>(address),
                        &mbi,
                        sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect &
                      (PAGE_NOACCESS | PAGE_GUARD));

                const auto bytes =
                    valid
                        ? HexBytes(address, 96)
                        : std::string{};

                if (report)
                {
                    report
                        << c.name
                        << " rva=0x"
                        << std::hex
                        << std::uppercase
                        << c.rva
                        << " address=0x"
                        << address
                        << std::dec
                        << " readable="
                        << (valid ? 1 : 0)
                        << "\nbytes="
                        << bytes
                        << "\n\n";
                }

                Print(
                    "[LUA-BRIDGE] %-42s rva=0x%llX %s\n",
                    c.name,
                    static_cast<unsigned long long>(c.rva),
                    valid ? "READABLE" : "INVALID");

                if (valid && refs)
                {
                    ScanReferencesToCandidate(
                        module,
                        imageSize,
                        c,
                        refs);
                }
            }

            // Also dump strings around the known LUI VM/event candidate because
            // it is likely to reveal the stack/state/event API family.
            {
                const auto address =
                    module + 0x1D85690;

                std::vector<unsigned char> bytes(0x800);
                if (SafeReadBytes(
                        address - 0x400,
                        bytes.data(),
                        bytes.size()))
                {
                    std::ofstream nearby(
                        "logs\\lui\\lua_bridge_luivm_nearby.bin",
                        std::ios::binary |
                        std::ios::trunc);

                    if (nearby)
                    {
                        nearby.write(
                            reinterpret_cast<const char*>(bytes.data()),
                            static_cast<std::streamsize>(bytes.size()));
                    }
                }
            }

            // Build259 is discovery-first: do NOT call unknown VM functions.
            // We only mark bridgeReady once a future revision has exact,
            // validated load-buffer + protected-call signatures.
            g_bridgeReady.store(false);
            g_completed.store(true);

            Print(
                "[LUA-BRIDGE] SCAN COMPLETE\n"
                "[LUA-BRIDGE] decoded knowledge=logs\\lui\\decoded_director_knowledge.txt\n"
                "[LUA-BRIDGE] candidate report=logs\\lui\\lua_bridge_candidates.txt\n"
                "[LUA-BRIDGE] callers=logs\\lui\\lua_bridge_callers.csv\n"
                "[LUA-BRIDGE] loose module=mods\\lua\\director_hub.lua\n"
                "[LUA-BRIDGE] No unknown Lua function is called in this build.\n"
                "[LUA-BRIDGE] ========================================\n\n");

            message =
                "Lua-engine candidate/caller map completed; source execution is still guarded until load/call APIs are identified";

            return true;
        }

        DWORD WINAPI Worker(
            LPVOID)
        {
            // Wait until the frontend/LUI system is alive.
            for (;;)
            {
                if (!g_running.load())
                    return 0;

                unsigned char inited = 0;
                std::uint32_t screen = 0;

                SafeRead(g_Addrs.s_inited, inited);
                SafeRead(g_Addrs.s_uiScreen, screen);

                if (inited != 0 &&
                    screen == 10)
                {
                    std::string message;
                    RunScan(message);
                    g_running.store(false);
                    return 0;
                }

                Sleep(100);
            }
        }
    }

    void StartAsync()
    {
        if (g_running.exchange(true))
            return;

        g_completed.store(false);

        HANDLE thread =
            CreateThread(
                nullptr,
                0,
                Worker,
                nullptr,
                0,
                nullptr);

        if (!thread)
        {
            g_running.store(false);
            return;
        }

        CloseHandle(thread);
    }

    bool IsRunning()
    {
        return g_running.load();
    }

    bool HasCompleted()
    {
        return g_completed.load();
    }

    bool ScanNow(std::string& message)
    {
        return RunScan(message);
    }

    bool LoadDirectorHub(std::string& message)
    {
        if (!g_bridgeReady.load())
        {
            message =
                "source Lua execution is not armed yet; Build259 only maps the exact VM/load/call candidates so we do not crash by calling an unknown Lua ABI";
            return false;
        }

        message =
            "bridge ready but source executor not implemented";
        return false;
    }

    void PrintStatus()
    {
        printf(
            "[LUA-BRIDGE] running=%s complete=%s bridgeReady=%s module=mods\\lua\\director_hub.lua\n",
            g_running.load() ? "yes" : "no",
            g_completed.load() ? "yes" : "no",
            g_bridgeReady.load() ? "yes" : "no");
        fflush(stdout);
    }
}
