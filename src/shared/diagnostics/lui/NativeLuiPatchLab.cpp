#include "NativeLuiPatchLab.h"
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

namespace native_lui_patch_lab
{
    namespace
    {
        std::atomic_bool g_running{ false };
        std::atomic_bool g_scanComplete{ false };

        constexpr std::uint64_t kDirectorHash =
            0x251BB4F2EDE86F4Cull;
        constexpr std::uint64_t kRouteHash =
            0x1B22F3BD3AD851EBull;

        struct Layout
        {
            const char* name = nullptr;
            std::uint32_t nameOffset = 0;
            std::uint32_t dataOffset = 0;
            std::uint32_t sizeOffset = 0;
            std::uint32_t sizeWidth = 0;
        };

        const Layout kLayouts[] =
        {
            { "name_unk_size_data", 0x00, 0x18, 0x10, 8 },
            { "name_data_size64",   0x00, 0x08, 0x10, 8 },
            { "name_data_size32",   0x00, 0x08, 0x10, 4 },
            { "name_size_data",     0x00, 0x10, 0x08, 8 },
            { "name_size32_data",   0x00, 0x10, 0x08, 4 },
        };

        struct Candidate
        {
            int poolId = -1;
            XAssetPool pool{};
            Layout layout{};
            std::uintptr_t item = 0;
            std::uintptr_t rawName = 0;
            std::uintptr_t data = 0;
            std::uint64_t size = 0;
            std::uint64_t inferredHash = 0;
            unsigned int stringScore = 0;
            bool director = false;
            bool route = false;
        };

        struct OverrideRecord
        {
            std::uintptr_t item = 0;
            Layout layout{};
            std::uintptr_t originalData = 0;
            std::uint64_t originalSize = 0;
            void* replacement = nullptr;
            std::size_t replacementSize = 0;
            std::uint64_t hash = 0;
        };

        CRITICAL_SECTION g_lock{};
        std::atomic_bool g_lockReady{ false };
        std::vector<Candidate> g_candidates;
        std::vector<OverrideRecord> g_overrides;

        void EnsureLock()
        {
            if (!g_lockReady.exchange(true))
                InitializeCriticalSection(&g_lock);
        }

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

        bool IsReadable(
            std::uintptr_t address)
        {
            if (!address)
                return false;

            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(
                    reinterpret_cast<const void*>(address),
                    &mbi,
                    sizeof(mbi)))
            {
                return false;
            }

            return mbi.State == MEM_COMMIT &&
                !(mbi.Protect &
                  (PAGE_NOACCESS | PAGE_GUARD));
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

        std::uint64_t ReadSize(
            std::uintptr_t item,
            const Layout& layout)
        {
            if (layout.sizeWidth == 4)
            {
                std::uint32_t value = 0;
                SafeRead(
                    item + layout.sizeOffset,
                    value);
                return value;
            }

            std::uint64_t value = 0;
            SafeRead(
                item + layout.sizeOffset,
                value);
            return value;
        }

        bool WritePointer(
            std::uintptr_t address,
            std::uintptr_t value)
        {
            DWORD oldProtect = 0;

            if (!VirtualProtect(
                    reinterpret_cast<void*>(address),
                    sizeof(value),
                    PAGE_READWRITE,
                    &oldProtect))
            {
                return false;
            }

            *reinterpret_cast<std::uintptr_t*>(
                address) = value;

            DWORD ignored = 0;
            VirtualProtect(
                reinterpret_cast<void*>(address),
                sizeof(value),
                oldProtect,
                &ignored);
            FlushInstructionCache(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(address),
                sizeof(value));
            return true;
        }

        bool WriteSize(
            std::uintptr_t address,
            std::uint64_t value,
            std::uint32_t width)
        {
            const SIZE_T bytes =
                width == 4 ? 4 : 8;

            DWORD oldProtect = 0;

            if (!VirtualProtect(
                    reinterpret_cast<void*>(address),
                    bytes,
                    PAGE_READWRITE,
                    &oldProtect))
            {
                return false;
            }

            if (width == 4)
            {
                *reinterpret_cast<std::uint32_t*>(
                    address) =
                    static_cast<std::uint32_t>(value);
            }
            else
            {
                *reinterpret_cast<std::uint64_t*>(
                    address) = value;
            }

            DWORD ignored = 0;
            VirtualProtect(
                reinterpret_cast<void*>(address),
                bytes,
                oldProtect,
                &ignored);

            return true;
        }

        bool BlobContains(
            std::uintptr_t data,
            std::uint64_t size,
            const char* token)
        {
            if (!data || !size || !token || !*token)
                return false;

            const auto tokenLen =
                strlen(token);

            if (!tokenLen)
                return false;

            const auto inspectSize =
                static_cast<std::size_t>(
                    (std::min<std::uint64_t>)(
                        size,
                        512ull * 1024ull));

            std::vector<unsigned char>
                bytes(inspectSize);

            if (!SafeReadBytes(
                    data,
                    bytes.data(),
                    bytes.size()))
            {
                return false;
            }

            const auto first =
                reinterpret_cast<const char*>(
                    bytes.data());

            const auto last =
                first + bytes.size();

            return std::search(
                       first,
                       last,
                       token,
                       token + tokenLen) != last;
        }

        unsigned int ScoreBlob(
            std::uintptr_t data,
            std::uint64_t size,
            bool& director,
            bool& route)
        {
            director = false;
            route = false;

            if (!data ||
                !size ||
                size > 4ull * 1024ull * 1024ull ||
                !IsReadable(data))
            {
                return 0;
            }

            struct Token
            {
                const char* text;
                unsigned int weight;
                bool directorToken;
                bool routeToken;
            };

            const Token tokens[] =
            {
                { "ShouldShowCampaign",       20, true,  false },
                { "ShouldShowMultiplayer",    20, true,  false },
                { "ShouldShowZombies",        20, true,  false },
                { "GetLanMenu",               18, true,  false },
                { "GetLanSelectMenu",         18, true,  false },
                { "GetOnlineSelectMenu",      18, true,  false },
                { "GetDirectorMainMenu",      18, true,  false },
                { "LanMenu",                  12, true,  false },
                { "MultiplayerMain",          20, false, true  },
                { "ZombiesMain",              20, false, true  },
                { "FrontendMain",             15, false, true  },
                { "BootMenu",                 12, false, true  },
                { "menu_open",                 8, false, true  },
                { "menu_go_back",              8, false, true  },
            };

            unsigned int score = 0;
            unsigned int directorHits = 0;
            unsigned int routeHits = 0;

            for (const auto& token : tokens)
            {
                if (!BlobContains(
                        data,
                        size,
                        token.text))
                {
                    continue;
                }

                score += token.weight;

                if (token.directorToken)
                    ++directorHits;

                if (token.routeToken)
                    ++routeHits;
            }

            director =
                directorHits >= 4;

            route =
                routeHits >= 2;

            if (director)
                score += 100;

            if (route)
                score += 80;

            return score;
        }

        std::uint64_t ReadRawNameValue(
            std::uintptr_t item,
            const Layout& layout)
        {
            std::uint64_t raw = 0;
            SafeRead(
                item + layout.nameOffset,
                raw);
            return raw;
        }

        void DumpCandidateStrings(
            const Candidate& c,
            std::ofstream& out)
        {
            const auto inspectSize =
                static_cast<std::size_t>(
                    (std::min<std::uint64_t>)(
                        c.size,
                        512ull * 1024ull));

            std::vector<unsigned char>
                bytes(inspectSize);

            if (!SafeReadBytes(
                    c.data,
                    bytes.data(),
                    bytes.size()))
            {
                return;
            }

            out << "[STRINGS pool=0x"
                << std::hex
                << std::uppercase
                << c.poolId
                << " item=0x"
                << c.item
                << std::dec
                << "]\n";

            std::string current;

            for (unsigned char ch : bytes)
            {
                if (ch >= 0x20 &&
                    ch <= 0x7E)
                {
                    current.push_back(
                        static_cast<char>(ch));

                    if (current.size() > 512)
                        current.erase(
                            current.begin());
                }
                else
                {
                    if (current.size() >= 4)
                        out << current << "\n";

                    current.clear();
                }
            }

            if (current.size() >= 4)
                out << current << "\n";

            out << "[END STRINGS]\n\n";
        }

        bool Discover(
            std::vector<Candidate>& found,
            std::string& message)
        {
            found.clear();

            if (!g_assetPool)
            {
                message =
                    "g_assetPool is null.";
                return false;
            }

            Print(
                "\n[LUI-PATCH] ========================================\n"
                "[LUI-PATCH] Native LUI discovery START\n"
                "[LUI-PATCH] Looking for director/routes by real bytecode strings...\n");

            const int maxPool =
                static_cast<int>(
                    ASSET_TYPE_SCENARIO);

            for (int poolId = 0;
                 poolId <= maxPool;
                 ++poolId)
            {
                XAssetPool pool{};

                const auto poolAddress =
                    reinterpret_cast<std::uintptr_t>(
                        &g_assetPool[poolId]);

                if (!SafeRead(
                        poolAddress,
                        pool))
                {
                    continue;
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
                    count > 200000 ||
                    !IsReadable(array))
                {
                    continue;
                }

                for (const auto& layout :
                     kLayouts)
                {
                    const auto stride =
                        pool.itemSize >= 0x18 &&
                        pool.itemSize <= 0x400
                            ? static_cast<std::size_t>(
                                pool.itemSize)
                            : static_cast<std::size_t>(
                                0x20);

                    unsigned int goodInLayout = 0;

                    for (unsigned int i = 0;
                         i < count;
                         ++i)
                    {
                        const auto item =
                            array +
                            static_cast<std::uintptr_t>(i) *
                                stride;

                        std::uintptr_t data = 0;

                        if (!SafeRead(
                                item + layout.dataOffset,
                                data))
                        {
                            continue;
                        }

                        const auto size =
                            ReadSize(
                                item,
                                layout);

                        bool director = false;
                        bool route = false;

                        const auto score =
                            ScoreBlob(
                                data,
                                size,
                                director,
                                route);

                        if (!score)
                            continue;

                        Candidate c{};
                        c.poolId = poolId;
                        c.pool = pool;
                        c.layout = layout;
                        c.item = item;
                        c.rawName =
                            ReadRawNameValue(
                                item,
                                layout);
                        c.data = data;
                        c.size = size;
                        c.inferredHash =
                            c.rawName;
                        c.stringScore = score;
                        c.director = director;
                        c.route = route;

                        found.push_back(c);
                        ++goodInLayout;

                        Print(
                            "[LUI-PATCH] candidate pool=0x%X index=%u layout=%s "
                            "score=%u size=%llu name/hash=0x%llX%s%s\n",
                            poolId,
                            i,
                            layout.name,
                            score,
                            static_cast<unsigned long long>(
                                size),
                            static_cast<unsigned long long>(
                                c.rawName),
                            director
                                ? " [DIRECTOR]"
                                : "",
                            route
                                ? " [ROUTE]"
                                : "");

                        if (director ||
                            route)
                        {
                            // The correct layout is normally obvious once one
                            // strong director/route asset appears. Do not keep
                            // reinterpreting the same pool with weaker layouts.
                            if (goodInLayout >= 4)
                                break;
                        }
                    }

                    if (goodInLayout >= 4)
                        break;
                }
            }

            std::sort(
                found.begin(),
                found.end(),
                [](const Candidate& a,
                   const Candidate& b)
                {
                    return
                        a.stringScore >
                        b.stringScore;
                });

            std::ostringstream out;
            out << "found "
                << found.size()
                << " LUI candidates";

            message = out.str();

            return !found.empty();
        }

        void WriteReports(
            const std::vector<Candidate>& found)
        {
            log_paths::EnsureAll();
            CreateDirectoryA(
                "logs\\lui",
                nullptr);

            std::ofstream csv(
                "logs\\lui\\native_lui_candidates.csv",
                std::ios::trunc);

            if (csv)
            {
                csv
                    << "rank,pool,item,layout,raw_name_or_hash,data,size,score,director,route\n";

                for (std::size_t i = 0;
                     i < found.size();
                     ++i)
                {
                    const auto& c =
                        found[i];

                    csv
                        << i
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << c.poolId
                        << ",0x"
                        << c.item
                        << ","
                        << c.layout.name
                        << ",0x"
                        << c.rawName
                        << ",0x"
                        << c.data
                        << std::dec
                        << ","
                        << c.size
                        << ","
                        << c.stringScore
                        << ","
                        << (c.director ? 1 : 0)
                        << ","
                        << (c.route ? 1 : 0)
                        << "\n";
                }
            }

            CreateDirectoryA(
                "logs\\lui\\targets",
                nullptr);

            std::ofstream offsets(
                "logs\\lui\\native_lui_string_offsets.csv",
                std::ios::trunc);

            if (offsets)
            {
                offsets
                    << "rank,pool,item,raw_name_or_hash,token,offset\\n";
            }

            const char* importantTokens[] =
            {
                "ShouldShowCampaign",
                "ShouldShowMultiplayer",
                "ShouldShowZombies",
                "GetLanMenu",
                "GetLanSelectMenu",
                "GetOnlineSelectMenu",
                "GetDirectorMainMenu",
                "LanMenu",
                "MultiplayerMain",
                "ZombiesMain",
                "FrontendMain",
                "BootMenu",
                "menu_open",
                "menu_go_back"
            };

            for (std::size_t rank = 0;
                 rank < found.size();
                 ++rank)
            {
                const auto& c = found[rank];

                if (!c.director &&
                    !c.route)
                {
                    continue;
                }

                const auto inspectSize =
                    static_cast<std::size_t>(
                        (std::min<std::uint64_t>)(
                            c.size,
                            4ull * 1024ull * 1024ull));

                std::vector<unsigned char>
                    bytes(inspectSize);

                if (!SafeReadBytes(
                        c.data,
                        bytes.data(),
                        bytes.size()))
                {
                    continue;
                }

                const auto hash =
                    c.rawName;

                char targetPath[MAX_PATH]{};

                if (c.poolId == 0x58 &&
                    c.rawName == kDirectorHash)
                {
                    sprintf_s(
                        targetPath,
                        "logs\\lui\\targets\\251BB4F2EDE86F4C.bin");
                }
                else
                {
                    sprintf_s(
                        targetPath,
                        "logs\\lui\\targets\\%016llX.luac",
                        static_cast<unsigned long long>(hash));
                }

                std::ofstream target(
                    targetPath,
                    std::ios::binary |
                    std::ios::trunc);

                if (target)
                {
                    target.write(
                        reinterpret_cast<const char*>(
                            bytes.data()),
                        static_cast<std::streamsize>(
                            bytes.size()));
                }

                if (offsets)
                {
                    const auto* begin =
                        reinterpret_cast<const char*>(
                            bytes.data());

                    const auto* end =
                        begin + bytes.size();

                    for (const char* token :
                         importantTokens)
                    {
                        const auto tokenLen =
                            strlen(token);

                        auto it =
                            std::search(
                                begin,
                                end,
                                token,
                                token + tokenLen);

                        while (it != end)
                        {
                            const auto offset =
                                static_cast<std::size_t>(
                                    it - begin);

                            offsets
                                << rank
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << c.poolId
                                << ",0x"
                                << c.item
                                << ",0x"
                                << c.rawName
                                << std::dec
                                << ","
                                << token
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << offset
                                << std::dec
                                << "\\n";

                            it = std::search(
                                it + tokenLen,
                                end,
                                token,
                                token + tokenLen);
                        }
                    }
                }
            }

            std::ofstream strings(
                "logs\\lui\\native_lui_target_strings.txt",
                std::ios::trunc);

            if (strings)
            {
                const auto limit =
                    (std::min<std::size_t>)(
                        found.size(),
                        8);

                for (std::size_t i = 0;
                     i < limit;
                     ++i)
                {
                    strings
                        << "RANK "
                        << i
                        << " pool=0x"
                        << std::hex
                        << std::uppercase
                        << found[i].poolId
                        << " item=0x"
                        << found[i].item
                        << " raw=0x"
                        << found[i].rawName
                        << std::dec
                        << " score="
                        << found[i].stringScore
                        << " director="
                        << found[i].director
                        << " route="
                        << found[i].route
                        << "\n";

                    DumpCandidateStrings(
                        found[i],
                        strings);
                }
            }
        }

        bool LoadFile(
            const std::string& path,
            std::vector<unsigned char>& bytes)
        {
            bytes.clear();

            std::ifstream file(
                path,
                std::ios::binary |
                std::ios::ate);

            if (!file)
                return false;

            const auto end =
                file.tellg();

            if (end <= 0 ||
                end >
                    static_cast<std::streamoff>(
                        16 * 1024 * 1024))
            {
                return false;
            }

            bytes.resize(
                static_cast<std::size_t>(
                    end));

            file.seekg(
                0,
                std::ios::beg);

            file.read(
                reinterpret_cast<char*>(
                    bytes.data()),
                static_cast<std::streamsize>(
                    bytes.size()));

            return file.good();
        }

        std::string OverridePathFor(
            const Candidate& c)
        {
            char name[128]{};

            // Build253 uses the exact live hashes/pools confirmed by
            // Build252, not the earlier content-guess filenames.
            if (c.poolId == 0x58 &&
                c.rawName == kDirectorHash)
            {
                sprintf_s(
                    name,
                    "mods\\lui\\251BB4F2EDE86F4C.bin");
            }
            else if (c.poolId == 0x7C &&
                     c.rawName == kRouteHash)
            {
                sprintf_s(
                    name,
                    "mods\\lui\\1B22F3BD3AD851EB.luac");
            }
            else
            {
                sprintf_s(
                    name,
                    "mods\\lui\\%016llX.luac",
                    static_cast<unsigned long long>(
                        c.rawName));
            }

            return name;
        }

        bool ApplyOne(
            const Candidate& c,
            const std::vector<unsigned char>& bytes,
            std::string& reason)
        {
            if (!c.item ||
                !c.data ||
                !c.size ||
                bytes.empty())
            {
                reason =
                    "invalid candidate or replacement bytes";
                return false;
            }

            void* memory =
                VirtualAlloc(
                    nullptr,
                    bytes.size(),
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE);

            if (!memory)
            {
                reason =
                    "VirtualAlloc failed";
                return false;
            }

            std::memcpy(
                memory,
                bytes.data(),
                bytes.size());

            OverrideRecord record{};
            record.item = c.item;
            record.layout = c.layout;
            record.originalData = c.data;
            record.originalSize = c.size;
            record.replacement = memory;
            record.replacementSize =
                bytes.size();
            record.hash =
                c.director
                    ? kDirectorHash
                    : c.route
                        ? kRouteHash
                        : c.rawName;

            if (!WritePointer(
                    c.item +
                        c.layout.dataOffset,
                    reinterpret_cast<std::uintptr_t>(
                        memory)) ||
                !WriteSize(
                    c.item +
                        c.layout.sizeOffset,
                    bytes.size(),
                    c.layout.sizeWidth))
            {
                WritePointer(
                    c.item +
                        c.layout.dataOffset,
                    c.data);

                WriteSize(
                    c.item +
                        c.layout.sizeOffset,
                    c.size,
                    c.layout.sizeWidth);

                VirtualFree(
                    memory,
                    0,
                    MEM_RELEASE);

                reason =
                    "failed to update live LuaFile fields";
                return false;
            }

            g_overrides.push_back(record);
            reason = "applied";
            return true;
        }

        bool DoScan(std::string& message)
        {
            std::vector<Candidate> found;

            if (!Discover(
                    found,
                    message))
            {
                WriteReports(found);
                return false;
            }

            WriteReports(found);

            EnsureLock();
            EnterCriticalSection(&g_lock);
            g_candidates = found;
            LeaveCriticalSection(&g_lock);

            g_scanComplete.store(true);

            Print(
                "[LUI-PATCH] SCAN COMPLETE: %llu candidate(s)\n"
                "[LUI-PATCH] report=logs\\lui\\native_lui_candidates.csv\n"
                "[LUI-PATCH] strings=logs\\lui\\native_lui_target_strings.txt\n"
                "[LUI-PATCH] offsets=logs\\lui\\native_lui_string_offsets.csv\n"
                "[LUI-PATCH] target bytecode=logs\\lui\\targets\\\n"
                "[LUI-PATCH] Override directory=mods\\lui\\\n"
                "[LUI-PATCH] ========================================\n\n",
                static_cast<unsigned long long>(
                    found.size()));

            return true;
        }

        DWORD WINAPI Worker(LPVOID)
        {
            // Wait for the live Lua pool to populate.
            for (unsigned int attempt = 0;
                 attempt < 30;
                 ++attempt)
            {
                if (!g_running.load())
                    return 0;

                std::string message;

                if (DoScan(message))
                {
                    g_running.store(false);
                    return 0;
                }

                Print(
                    "[LUI-PATCH] discovery not ready yet (%u/30); retrying in 2s...\n",
                    attempt + 1);

                Sleep(2000);
            }

            Print(
                "[LUI-PATCH] SCAN COMPLETE: no validated director assets found.\n");
            g_scanComplete.store(true);
            g_running.store(false);
            return 0;
        }
    }

    void StartAsync()
    {
        if (g_running.exchange(true))
            return;

        g_scanComplete.store(false);

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

    bool HasScanCompleted()
    {
        return g_scanComplete.load();
    }

    bool ScanNow(std::string& message)
    {
        return DoScan(message);
    }

    bool ApplyOverrides(std::string& message)
    {
        EnsureLock();
        EnterCriticalSection(&g_lock);

        if (!g_overrides.empty())
        {
            LeaveCriticalSection(&g_lock);
            message =
                "overrides are already active; restore first";
            return false;
        }

        const auto candidates =
            g_candidates;

        LeaveCriticalSection(&g_lock);

        if (candidates.empty())
        {
            message =
                "no candidates cached; run /lui scan first";
            return false;
        }

        CreateDirectoryA(
            "mods",
            nullptr);
        CreateDirectoryA(
            "mods\\lui",
            nullptr);

        unsigned int applied = 0;
        std::ostringstream details;

        for (const auto& c :
             candidates)
        {
            const bool exactDirector =
                c.poolId == 0x58 &&
                c.rawName ==
                    kDirectorHash;

            const bool exactRoute =
                c.poolId == 0x7C &&
                c.rawName ==
                    kRouteHash;

            if (!exactDirector &&
                !exactRoute)
            {
                continue;
            }

            const auto path =
                OverridePathFor(c);

            std::vector<unsigned char>
                bytes;

            if (!LoadFile(
                    path,
                    bytes))
            {
                continue;
            }

            std::string reason;

            if (ApplyOne(
                    c,
                    bytes,
                    reason))
            {
                ++applied;
                details
                    << " applied="
                    << path;
            }
            else
            {
                details
                    << " failed="
                    << path
                    << "("
                    << reason
                    << ")";
            }
        }

        std::ostringstream result;
        result
            << "native LUI overrides applied="
            << applied
            << details.str();

        if (!applied)
        {
            result
                << " | place replacement bytecode at "
                << "mods\\lui\\251BB4F2EDE86F4C.bin "
                << "and/or mods\\lui\\1B22F3BD3AD851EB.luac";
        }

        message = result.str();
        return applied != 0;
    }

    bool RestoreOverrides(std::string& message)
    {
        EnsureLock();
        EnterCriticalSection(&g_lock);

        unsigned int restored = 0;

        for (auto& record :
             g_overrides)
        {
            if (!record.item)
                continue;

            const bool pointerOk =
                WritePointer(
                    record.item +
                        record.layout.dataOffset,
                    record.originalData);

            const bool sizeOk =
                WriteSize(
                    record.item +
                        record.layout.sizeOffset,
                    record.originalSize,
                    record.layout.sizeWidth);

            if (pointerOk &&
                sizeOk)
            {
                ++restored;
            }

            if (record.replacement)
            {
                VirtualFree(
                    record.replacement,
                    0,
                    MEM_RELEASE);
            }
        }

        g_overrides.clear();

        LeaveCriticalSection(&g_lock);

        std::ostringstream out;
        out
            << "restored "
            << restored
            << " native LUI override(s)";
        message = out.str();

        return restored != 0;
    }
}
