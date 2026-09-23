#include "NativeDirectorMap.h"
#include "../../core/Main.hpp"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <algorithm>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace native_director_map
{
    namespace
    {
        std::atomic_bool g_running{ false };
        std::atomic_bool g_completed{ false };

        constexpr std::uint64_t kDirectorHash =
            0x251BB4F2EDE86F4Cull;
        constexpr int kDirectorPool = 0x58;

        constexpr std::uint64_t kRouteHash =
            0x1B22F3BD3AD851EBull;
        constexpr int kRoutePool = 0x7C;

        struct AssetView
        {
            int poolId = -1;
            std::uint64_t hash = 0;
            std::uintptr_t item = 0;
            std::uintptr_t data = 0;
            std::uint64_t size = 0;
            std::uint32_t dataOffset = 0;
            std::uint32_t sizeOffset = 0;
            std::uint32_t sizeWidth = 0;
            std::uint32_t stride = 0;
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
            vsprintf_s(
                buffer,
                sizeof(buffer),
                fmt,
                args);
            va_end(args);
            printf("%s", buffer);
            fflush(stdout);
        }

        bool FindExactAsset(
            int poolId,
            std::uint64_t wantedHash,
            std::uint32_t dataOffset,
            std::uint32_t sizeOffset,
            std::uint32_t sizeWidth,
            AssetView& out)
        {
            out = {};

            if (!g_assetPool ||
                poolId < 0)
            {
                return false;
            }

            XAssetPool pool{};

            const auto poolAddress =
                reinterpret_cast<std::uintptr_t>(
                    &g_assetPool[poolId]);

            if (!SafeRead(
                    poolAddress,
                    pool))
            {
                return false;
            }

            const auto array =
                reinterpret_cast<std::uintptr_t>(
                    pool.pool.unk);

            const auto count =
                pool.itemAllocCount > 0
                    ? static_cast<unsigned int>(
                        pool.itemAllocCount)
                    : pool.itemCount > 0
                        ? static_cast<unsigned int>(
                            pool.itemCount)
                        : 0u;

            if (!array ||
                !count ||
                count > 500000)
            {
                return false;
            }

            const auto stride =
                pool.itemSize >= 0x18 &&
                pool.itemSize <= 0x400
                    ? static_cast<std::uint32_t>(
                        pool.itemSize)
                    : 0x20u;

            for (unsigned int i = 0;
                 i < count;
                 ++i)
            {
                const auto item =
                    array +
                    static_cast<std::uintptr_t>(i) *
                        stride;

                std::uint64_t raw = 0;

                if (!SafeRead(item, raw) ||
                    raw != wantedHash)
                {
                    continue;
                }

                std::uintptr_t data = 0;
                if (!SafeRead(
                        item + dataOffset,
                        data))
                {
                    return false;
                }

                std::uint64_t size = 0;

                if (sizeWidth == 4)
                {
                    std::uint32_t value = 0;
                    if (!SafeRead(
                            item + sizeOffset,
                            value))
                    {
                        return false;
                    }
                    size = value;
                }
                else
                {
                    if (!SafeRead(
                            item + sizeOffset,
                            size))
                    {
                        return false;
                    }
                }

                if (!data ||
                    !size ||
                    size > 8ull * 1024ull * 1024ull)
                {
                    return false;
                }

                out.poolId = poolId;
                out.hash = wantedHash;
                out.item = item;
                out.data = data;
                out.size = size;
                out.dataOffset = dataOffset;
                out.sizeOffset = sizeOffset;
                out.sizeWidth = sizeWidth;
                out.stride = stride;
                return true;
            }

            return false;
        }

        std::vector<std::size_t> FindAll(
            const std::vector<unsigned char>& bytes,
            const char* token)
        {
            std::vector<std::size_t> offsets;

            if (!token || !*token)
                return offsets;

            const auto tokenLen =
                strlen(token);

            const char* begin =
                reinterpret_cast<const char*>(
                    bytes.data());
            const char* end =
                begin + bytes.size();

            auto it =
                std::search(
                    begin,
                    end,
                    token,
                    token + tokenLen);

            while (it != end)
            {
                offsets.push_back(
                    static_cast<std::size_t>(
                        it - begin));

                it = std::search(
                    it + tokenLen,
                    end,
                    token,
                    token + tokenLen);
            }

            return offsets;
        }

        std::vector<std::string> CollectNearbyStrings(
            const std::vector<unsigned char>& bytes,
            std::size_t center,
            std::size_t radius)
        {
            std::vector<std::string> out;

            const auto begin =
                center > radius
                    ? center - radius
                    : 0;

            const auto end =
                (std::min<std::size_t>)(
                    bytes.size(),
                    center + radius);

            std::string current;

            for (std::size_t i = begin;
                 i < end;
                 ++i)
            {
                const auto c = bytes[i];

                if (c >= 0x20 &&
                    c <= 0x7E)
                {
                    current.push_back(
                        static_cast<char>(c));
                }
                else
                {
                    if (current.size() >= 4)
                    {
                        if (std::find(
                                out.begin(),
                                out.end(),
                                current) ==
                            out.end())
                        {
                            out.push_back(current);
                        }
                    }

                    current.clear();
                }
            }

            if (current.size() >= 4 &&
                std::find(
                    out.begin(),
                    out.end(),
                    current) == out.end())
            {
                out.push_back(current);
            }

            return out;
        }

        void DumpNeighborhood(
            std::ofstream& out,
            const std::vector<unsigned char>& bytes,
            const char* token,
            std::size_t offset)
        {
            constexpr std::size_t kRadius = 0x180;

            const auto begin =
                offset > kRadius
                    ? offset - kRadius
                    : 0;

            const auto end =
                (std::min<std::size_t>)(
                    bytes.size(),
                    offset + kRadius);

            out << "[TOKEN] "
                << token
                << " offset=0x"
                << std::hex
                << std::uppercase
                << offset
                << std::dec
                << "\n";

            out << "[BYTES]\n";

            for (std::size_t row = begin;
                 row < end;
                 row += 16)
            {
                out << "0x"
                    << std::hex
                    << std::uppercase
                    << std::setw(6)
                    << std::setfill('0')
                    << row
                    << ": ";

                for (std::size_t j = 0;
                     j < 16 &&
                     row + j < end;
                     ++j)
                {
                    out << std::setw(2)
                        << static_cast<unsigned int>(
                            bytes[row + j])
                        << ' ';
                }

                out << std::dec << "\n";
            }

            out << "[NEARBY-STRINGS]\n";

            for (const auto& s :
                 CollectNearbyStrings(
                     bytes,
                     offset,
                     kRadius))
            {
                out << s << "\n";
            }

            out << "[END TOKEN]\n\n";
        }

        void FindOffsetReferences(
            std::ofstream& out,
            const std::vector<unsigned char>& bytes,
            const char* token,
            std::size_t targetOffset)
        {
            out << "[OFFSET-REFS] token="
                << token
                << " targetOffset=0x"
                << std::hex
                << std::uppercase
                << targetOffset
                << std::dec
                << "\n";

            const std::uint32_t off32 =
                static_cast<std::uint32_t>(
                    targetOffset);

            unsigned int hits = 0;

            for (std::size_t i = 0;
                 i + 4 <= bytes.size();
                 ++i)
            {
                std::uint32_t value = 0;
                std::memcpy(
                    &value,
                    bytes.data() + i,
                    sizeof(value));

                if (value == off32)
                {
                    out << "absoluteOffset32 @0x"
                        << std::hex
                        << std::uppercase
                        << i
                        << std::dec
                        << "\n";
                    ++hits;
                }

                const auto after =
                    i + 4;

                const std::int64_t delta =
                    static_cast<std::int64_t>(
                        targetOffset) -
                    static_cast<std::int64_t>(
                        after);

                if (delta >= INT32_MIN &&
                    delta <= INT32_MAX &&
                    static_cast<std::int32_t>(
                        value) ==
                    static_cast<std::int32_t>(
                        delta))
                {
                    out << "relative32-from-end @0x"
                        << std::hex
                        << std::uppercase
                        << i
                        << std::dec
                        << "\n";
                    ++hits;
                }
            }

            out << "refHitCount="
                << hits
                << "\n"
                << "[END OFFSET-REFS]\n\n";
        }

        bool ExportAsset(
            const AssetView& asset,
            const char* outputPath,
            std::vector<unsigned char>& bytes)
        {
            bytes.resize(
                static_cast<std::size_t>(
                    asset.size));

            if (!SafeReadBytes(
                    asset.data,
                    bytes.data(),
                    bytes.size()))
            {
                bytes.clear();
                return false;
            }

            std::ofstream out(
                outputPath,
                std::ios::binary |
                std::ios::trunc);

            if (!out)
                return false;

            out.write(
                reinterpret_cast<const char*>(
                    bytes.data()),
                static_cast<std::streamsize>(
                    bytes.size()));

            return out.good();
        }

        bool Run(std::string& message)
        {
            g_completed.store(false);

            log_paths::EnsureAll();
            CreateDirectoryA(
                "logs\\lui",
                nullptr);
            CreateDirectoryA(
                "logs\\lui\\targets",
                nullptr);

            Print(
                "\n[DIRECTOR-MAP] ========================================\n"
                "[DIRECTOR-MAP] BUILD253 native director map START\n");

            AssetView director{};
            AssetView route{};

            const bool haveDirector =
                FindExactAsset(
                    kDirectorPool,
                    kDirectorHash,
                    0x10,
                    0x08,
                    4,
                    director);

            const bool haveRoute =
                FindExactAsset(
                    kRoutePool,
                    kRouteHash,
                    0x10,
                    0x08,
                    8,
                    route);

            Print(
                "[DIRECTOR-MAP] director pool=0x58 hash=251BB4F2EDE86F4C %s\n",
                haveDirector ? "FOUND" : "NOT FOUND");

            Print(
                "[DIRECTOR-MAP] route    pool=0x7C hash=1B22F3BD3AD851EB %s\n",
                haveRoute ? "FOUND" : "NOT FOUND");

            if (!haveDirector &&
                !haveRoute)
            {
                message =
                    "neither exact runtime target was found";
                g_completed.store(true);
                return false;
            }

            std::ofstream summary(
                "logs\\lui\\native_director_map.txt",
                std::ios::trunc);

            if (!summary)
            {
                message =
                    "could not create native_director_map.txt";
                g_completed.store(true);
                return false;
            }

            if (haveDirector)
            {
                summary
                    << "[DIRECTOR]\n"
                    << "pool=0x58\n"
                    << "hash=0x251BB4F2EDE86F4C\n"
                    << "item=0x"
                    << std::hex
                    << std::uppercase
                    << director.item
                    << "\n"
                    << "data=0x"
                    << director.data
                    << std::dec
                    << "\n"
                    << "size="
                    << director.size
                    << "\n"
                    << "layout=name_size32_data"
                    << "\n\n";
            }

            if (haveRoute)
            {
                summary
                    << "[ROUTE-LUA]\n"
                    << "pool=0x7C\n"
                    << "hash=0x1B22F3BD3AD851EB\n"
                    << "item=0x"
                    << std::hex
                    << std::uppercase
                    << route.item
                    << "\n"
                    << "data=0x"
                    << route.data
                    << std::dec
                    << "\n"
                    << "size="
                    << route.size
                    << "\n"
                    << "layout=name_size_data"
                    << "\n\n";
            }

            std::vector<unsigned char>
                directorBytes;

            std::vector<unsigned char>
                routeBytes;

            if (haveDirector)
            {
                ExportAsset(
                    director,
                    "logs\\lui\\targets\\251BB4F2EDE86F4C.bin",
                    directorBytes);
            }

            if (haveRoute)
            {
                ExportAsset(
                    route,
                    "logs\\lui\\targets\\1B22F3BD3AD851EB.luac",
                    routeBytes);
            }

            const char* directorTokens[] =
            {
                "GetDirectorMainMenu",
                "GetLanSelectMenu",
                "GetOnlineSelectMenu",
                "GetLanMenu",
                "LanMenu",
                "CreateDedicatedLANLobby",
                "SetLobbyNav",
                "ProcessNavigate",
                "GetLobbyMenuByName",
                "GetLobbyMenuIDByName",
                "Multiplayer",
                "Zombies",
                "ForceLobbyButtonUpdate",
                "LobbyButton"
            };

            const char* routeTokens[] =
            {
                "menu_open",
                "menu_go_back",
                "MultiplayerMain",
                "ZombiesMain",
                "FrontendMain",
                "BootMenu"
            };

            std::ofstream neighborhoods(
                "logs\\lui\\native_director_neighborhoods.txt",
                std::ios::trunc);

            std::ofstream refs(
                "logs\\lui\\native_director_offset_refs.txt",
                std::ios::trunc);

            std::ofstream offsets(
                "logs\\lui\\native_director_offsets.csv",
                std::ios::trunc);

            if (offsets)
                offsets << "asset,token,offset\n";

            if (!directorBytes.empty())
            {
                for (const char* token :
                     directorTokens)
                {
                    const auto matches =
                        FindAll(
                            directorBytes,
                            token);

                    Print(
                        "[DIRECTOR-MAP] %-28s occurrences=%llu\n",
                        token,
                        static_cast<unsigned long long>(
                            matches.size()));

                    for (const auto offset :
                         matches)
                    {
                        if (offsets)
                        {
                            offsets
                                << "director,"
                                << token
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << offset
                                << std::dec
                                << "\n";
                        }

                        if (neighborhoods)
                        {
                            DumpNeighborhood(
                                neighborhoods,
                                directorBytes,
                                token,
                                offset);
                        }

                        if (refs)
                        {
                            FindOffsetReferences(
                                refs,
                                directorBytes,
                                token,
                                offset);
                        }
                    }
                }
            }

            if (!routeBytes.empty())
            {
                for (const char* token :
                     routeTokens)
                {
                    const auto matches =
                        FindAll(
                            routeBytes,
                            token);

                    Print(
                        "[DIRECTOR-MAP] ROUTE %-22s occurrences=%llu\n",
                        token,
                        static_cast<unsigned long long>(
                            matches.size()));

                    for (const auto offset :
                         matches)
                    {
                        if (offsets)
                        {
                            offsets
                                << "route,"
                                << token
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << offset
                                << std::dec
                                << "\n";
                        }

                        if (neighborhoods)
                        {
                            DumpNeighborhood(
                                neighborhoods,
                                routeBytes,
                                token,
                                offset);
                        }
                    }
                }
            }

            summary
                << "[OUTPUTS]\n"
                << "logs\\lui\\targets\\251BB4F2EDE86F4C.bin\n"
                << "logs\\lui\\targets\\1B22F3BD3AD851EB.luac\n"
                << "logs\\lui\\native_director_offsets.csv\n"
                << "logs\\lui\\native_director_neighborhoods.txt\n"
                << "logs\\lui\\native_director_offset_refs.txt\n"
                << "logs\\lui\\native_button_insertion_plan.txt\n";

            std::ofstream plan(
                "logs\\lui\\native_button_insertion_plan.txt",
                std::ios::trunc);

            if (plan)
            {
                plan
                    << "[BUILD254 NATIVE BUTTON TARGET PLAN]\n"
                    << "Desired native director entries:\n"
                    << "  MULTIPLAYER      -> existing native online MP path\n"
                    << "  ZOMBIES          -> existing native online ZM path\n"
                    << "  LAN MULTIPLAYER  -> LAN selector/menu path with MP session mode\n"
                    << "  LAN ZOMBIES      -> LAN selector/menu path with ZM session mode\n"
                    << "  CAMPAIGN         -> remove/hide from this custom director\n\n"
                    << "Confirmed director-side symbols to map before insertion:\n"
                    << "  GetDirectorMainMenu\n"
                    << "  GetOnlineSelectMenu\n"
                    << "  GetLanSelectMenu\n"
                    << "  GetLanMenu\n"
                    << "  CreateDedicatedLANLobby\n"
                    << "  SetLobbyNav\n"
                    << "  ProcessNavigate\n"
                    << "  ForceLobbyButtonUpdate\n"
                    << "  LobbyButton\n\n"
                    << "Confirmed live targets:\n"
                    << "  pool 0x58 hash 0x251BB4F2EDE86F4C (director/menu data)\n"
                    << "  pool 0x7C hash 0x1B22F3BD3AD851EB (Lua route asset)\n";
            }

            Print(
                "[DIRECTOR-MAP] MAP COMPLETE\n"
                "[DIRECTOR-MAP] outputs=logs\\lui\\native_director_*.txt/csv\n"
                "[DIRECTOR-MAP] ========================================\n\n");

            message =
                "native director/route targets mapped successfully";
            g_completed.store(true);
            return true;
        }

        DWORD WINAPI Worker(
            LPVOID)
        {
            for (unsigned int attempt = 0;
                 attempt < 30;
                 ++attempt)
            {
                if (!g_running.load())
                    return 0;

                std::string message;

                if (Run(message))
                {
                    g_running.store(false);
                    return 0;
                }

                Print(
                    "[DIRECTOR-MAP] targets not ready (%u/30); retrying in 2s...\n",
                    attempt + 1);

                Sleep(2000);
            }

            g_completed.store(true);
            g_running.store(false);
            Print(
                "[DIRECTOR-MAP] MAP COMPLETE: targets not found after retries.\n");
            return 0;
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
        return Run(message);
    }
}
