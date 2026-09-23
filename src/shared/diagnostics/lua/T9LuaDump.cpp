#include "T9LuaDump.h"
#include "../../core/Main.hpp"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>

namespace t9_lua_dump
{
    namespace
    {
        std::atomic_bool g_running{ false };
        std::atomic_bool g_completed{ false };

        struct CandidateLayout
        {
            const char* name;
            std::uint32_t nameOffset;
            std::uint32_t dataOffset;
            std::uint32_t sizeOffset;
            std::uint32_t sizeWidth;
        };

        struct PoolCandidate
        {
            int poolId = -1;
            XAssetPool pool{};
            CandidateLayout layout{};
            unsigned int validSamples = 0;
            unsigned int signatureSamples = 0;
            unsigned int printableNameSamples = 0;
            unsigned int score = 0;
        };

        const CandidateLayout kLayouts[] =
        {
            { "name_unk_size_data", 0x00, 0x18, 0x10, 8 },
            { "name_data_size64",   0x00, 0x08, 0x10, 8 },
            { "name_data_size32",   0x00, 0x08, 0x10, 4 },
            { "name_size_data",     0x00, 0x10, 0x08, 8 },
            { "name_size32_data",   0x00, 0x10, 0x08, 4 },
            { "hash_data_size64",   0x00, 0x08, 0x10, 8 }
        };

        bool SafeRead(
            std::uintptr_t address,
            void* output,
            SIZE_T size)
        {
            SIZE_T got = 0;
            return address &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    output,
                    size,
                    &got) &&
                got == size;
        }

        bool IsReadableAddress(
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

        void PrintStatus(
            const char* format,
            ...)
        {
            char buffer[2048]{};
            va_list args;
            va_start(args, format);
            vsprintf_s(
                buffer,
                sizeof(buffer),
                format,
                args);
            va_end(args);

            printf("%s", buffer);
            fflush(stdout);
        }

        bool ReadPrintableName(
            std::uintptr_t address,
            std::string& out)
        {
            out.clear();

            if (!IsReadableAddress(address))
                return false;

            char buffer[512]{};
            SIZE_T got = 0;

            if (!ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    buffer,
                    sizeof(buffer) - 1,
                    &got) ||
                !got)
            {
                return false;
            }

            std::size_t len = 0;

            while (len < got &&
                   buffer[len] != '\0')
            {
                const auto c =
                    static_cast<unsigned char>(
                        buffer[len]);

                if (c < 0x20 ||
                    c > 0x7E)
                {
                    return false;
                }

                ++len;
            }

            if (len < 2 ||
                len >= sizeof(buffer) - 1)
            {
                return false;
            }

            out.assign(buffer, len);
            return true;
        }

        bool LooksLikeLuaBlob(
            std::uintptr_t address,
            std::uint64_t size,
            bool& knownSignature)
        {
            knownSignature = false;

            if (!address ||
                !size ||
                size > 128ull * 1024ull * 1024ull ||
                !IsReadableAddress(address))
            {
                return false;
            }

            unsigned char head[64]{};
            SIZE_T got = 0;

            if (!ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    head,
                    sizeof(head),
                    &got) ||
                got < 8)
            {
                return false;
            }

            if ((head[0] == 0x1B &&
                 head[1] == 'L' &&
                 head[2] == 'u' &&
                 head[3] == 'a') ||
                (head[0] == 0x1B &&
                 head[1] == 'L' &&
                 head[2] == 'J'))
            {
                knownSignature = true;
                return true;
            }

            const std::string text(
                reinterpret_cast<const char*>(head),
                reinterpret_cast<const char*>(head) +
                    static_cast<std::size_t>(got));

            if (text.find("function") != std::string::npos ||
                text.find("require") != std::string::npos ||
                text.find("LUI") != std::string::npos ||
                text.find("CoD.") != std::string::npos)
            {
                return true;
            }

            // Even compiled T9 LUI assets may not expose a conventional Lua
            // magic at byte 0, so a readable nonzero blob remains a weak
            // candidate if the containing pool/layout scores strongly.
            return size >= 16;
        }

        std::uint64_t ReadSizedValue(
            std::uintptr_t address,
            std::uint32_t width)
        {
            if (width == 4)
            {
                std::uint32_t value = 0;
                if (SafeRead(
                        address,
                        &value,
                        sizeof(value)))
                {
                    return value;
                }

                return 0;
            }

            std::uint64_t value = 0;

            if (SafeRead(
                    address,
                    &value,
                    sizeof(value)))
            {
                return value;
            }

            return 0;
        }

        std::string SanitizeName(
            std::string value,
            unsigned int index,
            std::uintptr_t rawName)
        {
            std::replace(
                value.begin(),
                value.end(),
                '\\',
                '/');

            while (!value.empty() &&
                   (value.front() == '/' ||
                    value.front() == '.'))
            {
                value.erase(value.begin());
            }

            for (char& c : value)
            {
                const auto u =
                    static_cast<unsigned char>(c);

                if (c == ':' || c == '*' ||
                    c == '?' || c == '"' ||
                    c == '<' || c == '>' ||
                    c == '|' || u < 0x20)
                {
                    c = '_';
                }
            }

            if (value.empty())
            {
                char fallback[128]{};
                sprintf_s(
                    fallback,
                    "lua_%05u_%016llX.luac",
                    index,
                    static_cast<unsigned long long>(
                        rawName));
                value = fallback;
            }
            else
            {
                const auto slash =
                    value.find_last_of('/');

                const auto dot =
                    value.find_last_of('.');

                if (dot == std::string::npos ||
                    (slash != std::string::npos &&
                     dot < slash))
                {
                    value += ".luac";
                }
            }

            return value;
        }

        void EnsureParents(
            const std::string& path)
        {
            std::string current;

            for (char c : path)
            {
                current += c;

                if ((c == '/' || c == '\\') &&
                    current.size() > 1)
                {
                    CreateDirectoryA(
                        current.c_str(),
                        nullptr);
                }
            }
        }

        unsigned int ScorePoolLayout(
            int poolId,
            const XAssetPool& pool,
            const CandidateLayout& layout,
            PoolCandidate& out)
        {
            out = {};
            out.poolId = poolId;
            out.pool = pool;
            out.layout = layout;

            const auto array =
                reinterpret_cast<std::uintptr_t>(
                    pool.pool.unk);

            if (!array ||
                !IsReadableAddress(array))
            {
                return 0;
            }

            const auto count =
                pool.itemAllocCount > 0
                    ? static_cast<unsigned int>(
                        pool.itemAllocCount)
                    : pool.itemCount > 0
                        ? static_cast<unsigned int>(
                            pool.itemCount)
                        : 0u;

            if (!count ||
                count > 1000000)
            {
                return 0;
            }

            const auto stride =
                pool.itemSize >= 0x18 &&
                pool.itemSize <= 0x400
                    ? static_cast<std::size_t>(
                        pool.itemSize)
                    : static_cast<std::size_t>(
                        0x20);

            const unsigned int samples =
                (std::min)(
                    count,
                    64u);

            for (unsigned int i = 0;
                 i < samples;
                 ++i)
            {
                const auto item =
                    array +
                    static_cast<std::uintptr_t>(i) *
                    stride;

                std::uintptr_t rawName = 0;
                std::uintptr_t data = 0;

                if (!SafeRead(
                        item + layout.nameOffset,
                        &rawName,
                        sizeof(rawName)) ||
                    !SafeRead(
                        item + layout.dataOffset,
                        &data,
                        sizeof(data)))
                {
                    continue;
                }

                const auto size =
                    ReadSizedValue(
                        item +
                        layout.sizeOffset,
                        layout.sizeWidth);

                if (!data ||
                    !size ||
                    size >
                        128ull *
                        1024ull *
                        1024ull ||
                    !IsReadableAddress(data))
                {
                    continue;
                }

                bool signature = false;

                if (!LooksLikeLuaBlob(
                        data,
                        size,
                        signature))
                {
                    continue;
                }

                ++out.validSamples;

                if (signature)
                    ++out.signatureSamples;

                std::string name;

                if (ReadPrintableName(
                        rawName,
                        name))
                {
                    ++out.printableNameSamples;
                }
            }

            out.score =
                out.signatureSamples * 100 +
                out.printableNameSamples * 10 +
                out.validSamples;

            return out.score;
        }

        bool DiscoverPool(
            PoolCandidate& best)
        {
            best = {};

            CreateDirectoryA("logs", nullptr);
            CreateDirectoryA("logs\\lua", nullptr);

            std::ofstream report(
                "logs\\lua\\lua_pool_discovery.log",
                std::ios::trunc);

            PrintStatus(
                "\n[LUA-DUMP] ========================================\n"
                "[LUA-DUMP] BUILD247 Lua pool/layout discovery START\n");

            if (!g_assetPool)
            {
                PrintStatus(
                    "[LUA-DUMP] FAILED: g_assetPool is null.\n");
                return false;
            }

            const int maxPool =
                static_cast<int>(
                    ASSET_TYPE_SCENARIO);

            PrintStatus(
                "[LUA-DUMP] Phase 1/2: inspecting asset-pool metadata 0..0x%X\n",
                maxPool);

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
                        &pool,
                        sizeof(pool)))
                {
                    continue;
                }

                if (!pool.pool.unk &&
                    pool.itemCount <= 0 &&
                    pool.itemAllocCount <= 0)
                {
                    continue;
                }

                if (report)
                {
                    report
                        << "POOL id=0x"
                        << std::hex << std::uppercase
                        << poolId
                        << std::dec
                        << " address=0x"
                        << std::hex
                        << poolAddress
                        << std::dec
                        << " array=0x"
                        << std::hex
                        << reinterpret_cast<std::uintptr_t>(
                            pool.pool.unk)
                        << std::dec
                        << " itemSize="
                        << pool.itemSize
                        << " itemCount="
                        << pool.itemCount
                        << " allocCount="
                        << pool.itemAllocCount
                        << " singleton="
                        << static_cast<unsigned int>(
                            pool.isSingleton)
                        << "\n";
                }

                // Always test the declared LUAFILE/LUAFILEDEBUG pools, but also
                // score every populated pool because the project-side enum or
                // runtime pool representation may differ.
                for (const auto& layout :
                     kLayouts)
                {
                    PoolCandidate candidate{};

                    const auto score =
                        ScorePoolLayout(
                            poolId,
                            pool,
                            layout,
                            candidate);

                    if (report &&
                        (score ||
                         poolId ==
                            ASSET_TYPE_LUAFILE ||
                         poolId ==
                            ASSET_TYPE_LUAFILEDEBUG))
                    {
                        report
                            << "  layout="
                            << layout.name
                            << " score="
                            << score
                            << " valid="
                            << candidate.validSamples
                            << " signatures="
                            << candidate.signatureSamples
                            << " printableNames="
                            << candidate.printableNameSamples
                            << "\n";
                    }

                    if (score > best.score)
                        best = candidate;
                }
            }

            if (report)
                report.flush();

            PrintStatus(
                "[LUA-DUMP] Phase 1 complete.\n"
                "[LUA-DUMP] Phase 2/2: selecting best validated layout...\n");

            if (best.score == 0)
            {
                PrintStatus(
                    "[LUA-DUMP] No valid live Lua layout found yet.\n"
                    "[LUA-DUMP] discovery report=logs\\lua\\lua_pool_discovery.log\n");
                return false;
            }

            PrintStatus(
                "[LUA-DUMP] best pool=0x%X layout=%s score=%u valid=%u signatures=%u names=%u\n",
                best.poolId,
                best.layout.name,
                best.score,
                best.validSamples,
                best.signatureSamples,
                best.printableNameSamples);

            return true;
        }

        unsigned int DumpCandidate(
            const PoolCandidate& candidate)
        {
            const auto& pool =
                candidate.pool;

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

            const auto stride =
                pool.itemSize >= 0x18 &&
                pool.itemSize <= 0x400
                    ? static_cast<std::size_t>(
                        pool.itemSize)
                    : static_cast<std::size_t>(
                        0x20);

            CreateDirectoryA(
                "logs\\lua\\dumped",
                nullptr);
            CreateDirectoryA(
                "logs\\lua\\dumped\\raw",
                nullptr);

            std::ofstream manifest(
                "logs\\lua\\dumped\\manifest.csv",
                std::ios::trunc);

            if (manifest)
            {
                manifest
                    << "pool,index,layout,name_raw,name,path,address,size,signature,status\n";
            }

            unsigned int dumped = 0;
            unsigned int skipped = 0;
            std::uint64_t totalBytes = 0;

            for (unsigned int i = 0;
                 i < count;
                 ++i)
            {
                const auto item =
                    array +
                    static_cast<std::uintptr_t>(i) *
                    stride;

                std::uintptr_t rawName = 0;
                std::uintptr_t data = 0;

                if (!SafeRead(
                        item +
                        candidate.layout.nameOffset,
                        &rawName,
                        sizeof(rawName)) ||
                    !SafeRead(
                        item +
                        candidate.layout.dataOffset,
                        &data,
                        sizeof(data)))
                {
                    ++skipped;
                    continue;
                }

                const auto size =
                    ReadSizedValue(
                        item +
                        candidate.layout.sizeOffset,
                        candidate.layout.sizeWidth);

                bool signature = false;

                if (!data ||
                    !size ||
                    size >
                        128ull *
                        1024ull *
                        1024ull ||
                    !LooksLikeLuaBlob(
                        data,
                        size,
                        signature))
                {
                    ++skipped;
                    continue;
                }

                std::vector<unsigned char>
                    bytes(
                        static_cast<std::size_t>(
                            size));

                if (!SafeRead(
                        data,
                        bytes.data(),
                        bytes.size()))
                {
                    ++skipped;
                    continue;
                }

                std::string readableName;
                ReadPrintableName(
                    rawName,
                    readableName);

                auto name =
                    SanitizeName(
                        readableName,
                        i,
                        rawName);

                std::string outputPath =
                    "logs/lua/dumped/raw/" +
                    name;

                EnsureParents(outputPath);

                if (GetFileAttributesA(
                        outputPath.c_str()) !=
                    INVALID_FILE_ATTRIBUTES)
                {
                    char suffix[64]{};
                    sprintf_s(
                        suffix,
                        "_%05u.luac",
                        i);

                    outputPath += suffix;
                }

                std::ofstream out(
                    outputPath,
                    std::ios::binary |
                    std::ios::trunc);

                if (!out)
                {
                    ++skipped;
                    continue;
                }

                out.write(
                    reinterpret_cast<const char*>(
                        bytes.data()),
                    static_cast<std::streamsize>(
                        bytes.size()));

                if (!out.good())
                {
                    ++skipped;
                    continue;
                }

                ++dumped;
                totalBytes += size;

                if (manifest)
                {
                    manifest
                        << "0x"
                        << std::hex
                        << std::uppercase
                        << candidate.poolId
                        << std::dec
                        << ','
                        << i
                        << ','
                        << candidate.layout.name
                        << ",0x"
                        << std::hex
                        << std::uppercase
                        << rawName
                        << std::dec
                        << ",\""
                        << readableName
                        << "\",\""
                        << outputPath
                        << "\",0x"
                        << std::hex
                        << std::uppercase
                        << data
                        << std::dec
                        << ','
                        << size
                        << ','
                        << (signature
                            ? "known"
                            : "heuristic")
                        << ",dumped\n";
                }

                if ((dumped % 100) == 0 ||
                    i + 1 == count)
                {
                    PrintStatus(
                        "[LUA-DUMP] progress %u/%u scanned | %u dumped | %u skipped | %.2f MB\n",
                        i + 1,
                        count,
                        dumped,
                        skipped,
                        static_cast<double>(
                            totalBytes) /
                            (1024.0 * 1024.0));
                }
            }

            if (manifest)
                manifest.flush();

            PrintStatus(
                "[LUA-DUMP] LUA DUMP COMPLETE\n"
                "[LUA-DUMP] pool=0x%X layout=%s scanned=%u dumped=%u skipped=%u bytes=%llu\n"
                "[LUA-DUMP] raw=logs\\lua\\dumped\\raw\n"
                "[LUA-DUMP] manifest=logs\\lua\\dumped\\manifest.csv\n",
                candidate.poolId,
                candidate.layout.name,
                count,
                dumped,
                skipped,
                static_cast<unsigned long long>(
                    totalBytes));

            return dumped;
        }

        void PerformDump()
        {
            g_completed.store(false);

            PoolCandidate best{};

            if (!DiscoverPool(best))
            {
                PrintStatus(
                    "[LUA-DUMP] LUA DUMP COMPLETE (0 files; discovery only)\n"
                    "[LUA-DUMP] ========================================\n\n");
                g_completed.store(true);
                return;
            }

            DumpCandidate(best);

            PrintStatus(
                "[LUA-DUMP] ========================================\n\n");

            g_completed.store(true);
        }

        DWORD WINAPI Worker(
            LPVOID)
        {
            // Wait for the asset database to populate, but run discovery
            // periodically instead of assuming LUAFILE 0x7C is ready.
            for (unsigned int attempt = 0;
                 attempt < 6;
                 ++attempt)
            {
                if (!g_running.load())
                    return 0;

                if (g_assetPool)
                {
                    PoolCandidate best{};

                    if (DiscoverPool(best) &&
                        best.score > 0)
                    {
                        DumpCandidate(best);

                        PrintStatus(
                            "[LUA-DUMP] ========================================\n\n");

                        g_completed.store(true);
                        g_running.store(false);
                        return 0;
                    }
                }

                PrintStatus(
                    "[LUA-DUMP] no validated pool yet; retrying in 10s... (attempt %u/6)\n",
                    attempt + 1);

                Sleep(10000);
            }

            PrintStatus(
                "[LUA-DUMP] LUA DUMP COMPLETE (0 files after discovery retries)\n"
                "[LUA-DUMP] discovery report=logs\\lua\\lua_pool_discovery.log\n"
                "[LUA-DUMP] ========================================\n\n");

            g_completed.store(true);
            g_running.store(false);
            return 0;
        }
    }

    void StartAsync()
    {
        if (g_running.exchange(true))
        {
            PrintStatus(
                "[LUA-DUMP] already running.\n");
            return;
        }

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
            PrintStatus(
                "[LUA-DUMP] FAILED: could not create worker thread.\n");
            return;
        }

        CloseHandle(thread);
    }

    void DumpNow()
    {
        if (g_running.exchange(true))
        {
            PrintStatus(
                "[LUA-DUMP] already running.\n");
            return;
        }

        PerformDump();
        g_running.store(false);
    }

    bool IsRunning()
    {
        return g_running.load();
    }

    bool HasCompleted()
    {
        return g_completed.load();
    }
}
