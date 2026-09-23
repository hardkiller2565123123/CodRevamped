#include "OnlineResearch.h"
#include "../runtime/LogPaths.h"

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    bool SafeRead(std::uintptr_t address, void* out, std::size_t size)
    {
        if (!address || !out || !size)
            return false;
        SIZE_T got = 0;
        return ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<const void*>(address),
            out, size, &got) && got == size;
    }

    std::vector<std::uintptr_t> FindAscii(
        const char* needle,
        std::size_t maxHits)
    {
        std::vector<std::uintptr_t> hits;
        if (!needle || !*needle)
            return hits;

        const auto module = GetModuleHandleW(nullptr);
        if (!module)
            return hits;

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        if (!SafeRead(base, &dos, sizeof(dos)) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE ||
            !SafeRead(base + static_cast<std::uintptr_t>(dos.e_lfanew),
                &nt, sizeof(nt)) ||
            nt.Signature != IMAGE_NT_SIGNATURE)
            return hits;

        const auto end =
            base + static_cast<std::uintptr_t>(
                nt.OptionalHeader.SizeOfImage);

        const auto needleLen = std::strlen(needle);
        std::uintptr_t cursor = base;

        while (cursor < end && hits.size() < maxHits)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(
                    reinterpret_cast<const void*>(cursor),
                    &mbi, sizeof(mbi)))
                break;

            const auto regionBase =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto regionEnd =
                regionBase + static_cast<std::uintptr_t>(
                    mbi.RegionSize);
            const auto start = std::max(regionBase, base);
            const auto finish = std::min(regionEnd, end);

            const bool readable =
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                finish > start;

            if (readable)
            {
                const auto size =
                    static_cast<std::size_t>(finish - start);
                std::vector<unsigned char> bytes(size);
                if (SafeRead(start, bytes.data(), bytes.size()))
                {
                    for (std::size_t i = 0;
                         i + needleLen <= bytes.size() &&
                         hits.size() < maxHits;
                         ++i)
                    {
                        if (_strnicmp(
                                reinterpret_cast<const char*>(
                                    bytes.data() + i),
                                needle,
                                needleLen) == 0)
                            hits.push_back(start + i);
                    }
                }
            }

            if (regionEnd <= cursor)
                break;
            cursor = regionEnd;
        }

        return hits;
    }
}

namespace online_research
{
    std::string Status()
    {
        return "Online research scanner ready (analysis-only; no auth/backend behavior is changed).";
    }

    bool Scan(std::string& message)
    {
        log_paths::EnsureAll();

        struct Term
        {
            const char* role;
            const char* text;
            int weight;
        };

        // Focus on service boundaries useful for a future compatible private
        // backend: authentication, lobby, matchmaking, presence, storage and
        // Demonware-facing service calls. The scanner is read-only.
        const Term terms[] =
        {
            { "DEMONWARE", "demonware", 10 },
            { "DEMONWARE", "Demonware", 10 },
            { "AUTH", "authentication", 9 },
            { "AUTH", "auth", 6 },
            { "MATCHMAKING", "matchmaking", 10 },
            { "LOBBY", "lobby", 7 },
            { "DW_LOBBY", "bdLobby", 10 },
            { "DW_AUTH", "bdAuth", 10 },
            { "DW_TASK", "bdRemoteTask", 9 },
            { "PRESENCE", "presence", 8 },
            { "FRIENDS", "friends", 7 },
            { "STORAGE", "storage", 7 },
            { "MARKETPLACE", "marketplace", 7 },
            { "INVENTORY", "inventory", 7 },
            { "UNO", "uno", 8 },
            { "UMBRELLA", "umbrella", 8 },
            { "LIVESTORAGE", "LiveStorage", 9 },
            { "DW_LOGON", "logon", 6 },
            { "BACKEND", "backend", 6 }
        };

        struct Hit
        {
            const char* role = nullptr;
            std::uintptr_t address = 0;
            int weight = 0;
        };

        std::vector<Hit> hits;
        for (const auto& term : terms)
        {
            const auto found = FindAscii(term.text, 24);
            for (const auto address : found)
                hits.push_back({ term.role, address, term.weight });
        }

        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
        {
            message = "main module unavailable";
            return false;
        }

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        if (!SafeRead(base, &dos, sizeof(dos)) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE ||
            !SafeRead(base + static_cast<std::uintptr_t>(dos.e_lfanew),
                &nt, sizeof(nt)) ||
            nt.Signature != IMAGE_NT_SIGNATURE)
        {
            message = "could not read PE headers";
            return false;
        }

        const auto moduleEnd =
            base + static_cast<std::uintptr_t>(
                nt.OptionalHeader.SizeOfImage);
        const auto sectionHeaders =
            base + static_cast<std::uintptr_t>(dos.e_lfanew) +
            sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
            nt.FileHeader.SizeOfOptionalHeader;

        std::ostringstream csvPath;
        csvPath << "logs\\online\\online_candidates_"
                << GetCurrentProcessId() << ".csv";
        std::ofstream csv(csvPath.str(), std::ios::trunc);
        if (!csv)
        {
            message = "could not create online candidate CSV";
            return false;
        }

        csv << "role,string_rva,xref_rva,call_rva,call_target_rva,distance,score\n";

        struct Candidate
        {
            int score = 0;
            unsigned int hits = 0;
            std::map<std::string, unsigned int> roles;
        };
        std::map<std::uintptr_t, Candidate> candidates;

        unsigned int xrefCount = 0;
        unsigned int callCount = 0;
        constexpr std::size_t kWindow = 0x70;
        constexpr unsigned int kMaxRows = 3500;

        for (unsigned int si = 0;
             si < nt.FileHeader.NumberOfSections &&
             callCount < kMaxRows;
             ++si)
        {
            IMAGE_SECTION_HEADER sh{};
            if (!SafeRead(sectionHeaders +
                    static_cast<std::uintptr_t>(si) * sizeof(sh),
                    &sh, sizeof(sh)))
                continue;

            if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                continue;

            const auto sectionStart =
                base + sh.VirtualAddress;
            const auto sectionSize =
                static_cast<std::size_t>(
                    std::max(sh.Misc.VirtualSize,
                        sh.SizeOfRawData));

            if (sectionSize < 8 ||
                sectionSize > 512ull * 1024ull * 1024ull)
                continue;

            const auto sectionEnd =
                sectionStart + sectionSize;
            std::uintptr_t cursor = sectionStart;

            while (cursor < sectionEnd &&
                   callCount < kMaxRows)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(
                        reinterpret_cast<const void*>(cursor),
                        &mbi, sizeof(mbi)))
                    break;

                const auto regionBase =
                    reinterpret_cast<std::uintptr_t>(
                        mbi.BaseAddress);
                const auto regionEnd =
                    regionBase +
                    static_cast<std::uintptr_t>(
                        mbi.RegionSize);
                const auto start =
                    std::max(cursor, regionBase);
                const auto finish =
                    std::min(sectionEnd, regionEnd);

                const bool readable =
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect &
                        (PAGE_NOACCESS | PAGE_GUARD)) &&
                    finish > start;

                if (readable)
                {
                    const auto size =
                        static_cast<std::size_t>(
                            finish - start);
                    std::vector<unsigned char> bytes(size);

                    if (SafeRead(start, bytes.data(),
                        bytes.size()))
                    {
                        for (std::size_t off = 0;
                             off + 8 <= bytes.size() &&
                             callCount < kMaxRows;
                             ++off)
                        {
                            for (unsigned int len : {6u, 7u})
                            {
                                for (unsigned int dispOff :
                                     {2u, 3u})
                                {
                                    if (off + len > bytes.size() ||
                                        dispOff + 4 > len)
                                        continue;

                                    std::int32_t disp = 0;
                                    std::memcpy(&disp,
                                        bytes.data() + off +
                                            dispOff,
                                        sizeof(disp));

                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                start + off + len) +
                                            disp);

                                    const Hit* matched = nullptr;
                                    for (const auto& hit : hits)
                                    {
                                        if (hit.address == target)
                                        {
                                            matched = &hit;
                                            break;
                                        }
                                    }
                                    if (!matched)
                                        continue;

                                    ++xrefCount;
                                    const auto xref =
                                        start + off;
                                    const auto begin =
                                        off > kWindow
                                            ? off - kWindow : 0;
                                    const auto end =
                                        std::min<std::size_t>(
                                            bytes.size(),
                                            off + kWindow + 1);

                                    for (std::size_t ci = begin;
                                         ci + 5 <= end &&
                                         callCount < kMaxRows;
                                         ++ci)
                                    {
                                        if (bytes[ci] != 0xE8)
                                            continue;

                                        std::int32_t rel = 0;
                                        std::memcpy(&rel,
                                            bytes.data() + ci + 1,
                                            sizeof(rel));

                                        const auto call =
                                            start + ci;
                                        const auto callTarget =
                                            static_cast<std::uintptr_t>(
                                                static_cast<std::intptr_t>(
                                                    call + 5) + rel);

                                        if (callTarget < base ||
                                            callTarget >= moduleEnd)
                                            continue;

                                        const long long distance =
                                            static_cast<long long>(call) -
                                            static_cast<long long>(xref);
                                        const long long absDistance =
                                            distance < 0
                                                ? -distance : distance;

                                        int score =
                                            matched->weight * 10;
                                        if (absDistance <= 0x20)
                                            score += 30;
                                        else if (absDistance <= 0x50)
                                            score += 15;

                                        auto& aggregate =
                                            candidates[callTarget];
                                        aggregate.score += score;
                                        ++aggregate.hits;
                                        ++aggregate.roles[
                                            matched->role];

                                        csv << matched->role
                                            << ",0x"
                                            << std::hex
                                            << std::uppercase
                                            << (matched->address - base)
                                            << ",0x"
                                            << (xref - base)
                                            << ",0x"
                                            << (call - base)
                                            << ",0x"
                                            << (callTarget - base)
                                            << std::dec << ','
                                            << distance << ','
                                            << score << "\n";
                                        ++callCount;
                                    }
                                }
                            }
                        }
                    }
                }

                if (regionEnd <= cursor)
                    break;
                cursor = regionEnd;
            }
        }

        std::vector<std::pair<std::uintptr_t, Candidate>> ranked(
            candidates.begin(), candidates.end());
        std::sort(ranked.begin(), ranked.end(),
            [](const auto& a, const auto& b)
            {
                if (a.second.score != b.second.score)
                    return a.second.score > b.second.score;
                return a.second.hits > b.second.hits;
            });

        std::ostringstream summaryPath;
        summaryPath
            << "logs\\online\\online_summary_"
            << GetCurrentProcessId() << ".txt";
        std::ofstream summary(
            summaryPath.str(), std::ios::trunc);

        if (summary)
        {
            summary << "[T9 ONLINE SERVICE RESEARCH]\n";
            summary << "analysisOnly=yes\n";
            summary << "moduleBase=0x"
                    << std::hex << std::uppercase
                    << base << std::dec << "\n";
            summary << "stringHits=" << hits.size()
                    << " xrefs=" << xrefCount
                    << " nearbyCalls=" << callCount
                    << " uniqueTargets="
                    << ranked.size() << "\n\n";

            summary << "[SERVICE STRING HITS]\n";
            for (const auto& hit : hits)
                summary << hit.role
                        << " rva=0x"
                        << std::hex << std::uppercase
                        << (hit.address - base)
                        << std::dec << "\n";

            summary << "\n[RANKED SERVICE CALL TARGETS]\n";
            const auto count =
                std::min<std::size_t>(ranked.size(), 80);
            for (std::size_t i = 0; i < count; ++i)
            {
                const auto address = ranked[i].first;
                const auto& candidate = ranked[i].second;
                summary << "#" << (i + 1)
                        << " rva=0x"
                        << std::hex << std::uppercase
                        << (address - base)
                        << std::dec
                        << " score=" << candidate.score
                        << " hits=" << candidate.hits
                        << " roles=";

                bool first = true;
                for (const auto& role : candidate.roles)
                {
                    if (!first)
                        summary << '|';
                    first = false;
                    summary << role.first
                            << ':' << role.second;
                }
                summary << "\n";
            }
        }

        // Build213: focused analysis of the repeatedly dominant
        // 0xAF93xxx-0xAF95xxx lobby/service cluster.
        {
            constexpr std::uintptr_t kFocusStartRva = 0xAF93000;
            constexpr std::uintptr_t kFocusEndRva = 0xAF97000;

            std::ostringstream focusPath;
            focusPath
                << "logs\\online\\online_af93_af95_"
                << GetCurrentProcessId() << ".txt";
            std::ofstream focus(
                focusPath.str(), std::ios::trunc);

            if (focus)
            {
                focus << "[T9 ONLINE AF93-AF95 FOCUS BUILD213]\n";
                focus << "rangeRva=0x"
                      << std::hex << std::uppercase
                      << kFocusStartRva << "-0x"
                      << kFocusEndRva << std::dec << "\n\n";

                focus << "[RANKED CANDIDATES IN RANGE]\n";
                for (const auto& item : ranked)
                {
                    const auto address = item.first;
                    const auto rva = address - base;
                    if (rva < kFocusStartRva ||
                        rva >= kFocusEndRva)
                        continue;

                    focus << "rva=0x"
                          << std::hex << std::uppercase
                          << rva << std::dec
                          << " score=" << item.second.score
                          << " hits=" << item.second.hits
                          << " roles=";

                    bool first = true;
                    for (const auto& role : item.second.roles)
                    {
                        if (!first) focus << '|';
                        first = false;
                        focus << role.first
                              << ':' << role.second;
                    }
                    focus << "\n";
                }

                focus << "\n[CODE WINDOWS]\n";
                for (const auto& item : ranked)
                {
                    const auto address = item.first;
                    const auto rva = address - base;
                    if (rva < kFocusStartRva ||
                        rva >= kFocusEndRva)
                        continue;

                    constexpr std::size_t kBefore = 0x80;
                    constexpr std::size_t kAfter = 0x140;
                    const auto start =
                        address > base + kBefore
                            ? address - kBefore : base;
                    constexpr std::size_t kSize =
                        kBefore + kAfter;

                    unsigned char bytes[kSize]{};
                    focus << "[targetRva=0x"
                          << std::hex << std::uppercase
                          << rva << std::dec << "]\n";

                    if (!SafeRead(start, bytes, sizeof(bytes)))
                    {
                        focus << "unreadable\n\n";
                        continue;
                    }

                    for (std::size_t off = 0;
                         off < sizeof(bytes); off += 16)
                    {
                        focus << "rva=0x"
                              << std::hex << std::uppercase
                              << (start + off - base)
                              << ": ";
                        for (std::size_t j = 0;
                             j < 16 &&
                             off + j < sizeof(bytes); ++j)
                        {
                            focus << std::setw(2)
                                  << std::setfill('0')
                                  << static_cast<unsigned int>(
                                      bytes[off + j])
                                  << ' ';
                        }
                        focus << std::dec << "\n";
                    }
                    focus << "\n";
                }
            }
        }

        // Build214: compact call graph for the AF93xxx-AF95xxx service family.
        {
            constexpr std::uintptr_t kClusterStartRva = 0xAF93000;
            constexpr std::uintptr_t kClusterEndRva = 0xAF97000;
            const auto clusterStart = base + kClusterStartRva;
            const auto clusterEnd = base + kClusterEndRva;

            std::ostringstream graphPath;
            graphPath << "logs\\online\\online_af93_af95_graph_"
                      << GetCurrentProcessId() << ".csv";
            std::ofstream graph(graphPath.str(), std::ios::trunc);

            if (graph)
            {
                graph << "edge_type,call_rva,source_region,target_rva\n";

                // Outgoing direct calls from the cluster.
                const auto clusterBytes =
                    static_cast<std::size_t>(
                        clusterEnd - clusterStart);
                std::vector<unsigned char> bytes(clusterBytes);

                if (SafeRead(clusterStart,
                    bytes.data(), bytes.size()))
                {
                    for (std::size_t off = 0;
                         off + 5 <= bytes.size(); ++off)
                    {
                        if (bytes[off] != 0xE8)
                            continue;

                        std::int32_t rel = 0;
                        std::memcpy(&rel,
                            bytes.data() + off + 1,
                            sizeof(rel));

                        const auto callAddress =
                            clusterStart + off;
                        const auto target =
                            static_cast<std::uintptr_t>(
                                static_cast<std::intptr_t>(
                                    callAddress + 5) + rel);

                        if (target >= base && target < moduleEnd)
                        {
                            graph << "outgoing,0x"
                                  << std::hex << std::uppercase
                                  << (callAddress - base)
                                  << ",AF93_AF95,0x"
                                  << (target - base)
                                  << std::dec << "\n";
                        }
                    }
                }

                // Incoming direct CALLs from executable sections into cluster.
                const auto sectionHeaders =
                    base + static_cast<std::uintptr_t>(dos.e_lfanew) +
                    sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                    nt.FileHeader.SizeOfOptionalHeader;

                for (unsigned int si = 0;
                     si < nt.FileHeader.NumberOfSections; ++si)
                {
                    IMAGE_SECTION_HEADER sh{};
                    if (!SafeRead(sectionHeaders +
                            static_cast<std::uintptr_t>(si) * sizeof(sh),
                            &sh, sizeof(sh)))
                        continue;

                    if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                        !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        continue;

                    const auto sectionStart = base + sh.VirtualAddress;
                    const auto sectionSize = static_cast<std::size_t>(
                        std::max(sh.Misc.VirtualSize, sh.SizeOfRawData));
                    if (sectionSize < 5 ||
                        sectionSize > 512ull * 1024ull * 1024ull)
                        continue;

                    const auto sectionEnd = sectionStart + sectionSize;
                    std::uintptr_t cursor = sectionStart;

                    while (cursor < sectionEnd)
                    {
                        MEMORY_BASIC_INFORMATION mbi{};
                        if (!VirtualQuery(
                                reinterpret_cast<const void*>(cursor),
                                &mbi, sizeof(mbi)))
                            break;

                        const auto regionBase =
                            reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                        const auto regionEnd =
                            regionBase +
                            static_cast<std::uintptr_t>(mbi.RegionSize);
                        const auto chunkStart = std::max(cursor, regionBase);
                        const auto chunkEnd = std::min(sectionEnd, regionEnd);

                        const bool readable =
                            mbi.State == MEM_COMMIT &&
                            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                            chunkEnd > chunkStart;

                        if (readable)
                        {
                            const auto size =
                                static_cast<std::size_t>(chunkEnd - chunkStart);
                            std::vector<unsigned char> sectionBytes(size);

                            if (SafeRead(chunkStart,
                                sectionBytes.data(), sectionBytes.size()))
                            {
                                for (std::size_t off = 0;
                                     off + 5 <= sectionBytes.size(); ++off)
                                {
                                    if (sectionBytes[off] != 0xE8)
                                        continue;

                                    std::int32_t rel = 0;
                                    std::memcpy(&rel,
                                        sectionBytes.data() + off + 1,
                                        sizeof(rel));

                                    const auto callAddress =
                                        chunkStart + off;
                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                callAddress + 5) + rel);

                                    if (target >= clusterStart &&
                                        target < clusterEnd)
                                    {
                                        graph << "incoming,0x"
                                              << std::hex << std::uppercase
                                              << (callAddress - base)
                                              << ",EXEC,0x"
                                              << (target - base)
                                              << std::dec << "\n";
                                    }
                                }
                            }
                        }

                        if (regionEnd <= cursor)
                            break;
                        cursor = regionEnd;
                    }
                }
            }
        }

        // Build215: compact classifier for the confirmed online family.
        {
            struct FocusFunction
            {
                std::uintptr_t rva;
                const char* label;
            };

            const FocusFunction focusFunctions[] =
            {
                { 0xAF93BB0, "AF93BB0" },
                { 0xAF93C90, "AF93C90" },
                { 0xAF93D60, "AF93D60" },
                { 0xAF93DF0, "AF93DF0" },
                { 0xAF95680, "AF95680" },
                { 0xAF95710, "AF95710" },
                { 0xAF958B0, "AF958B0" },
                { 0xAF95940, "AF95940" },
                { 0xAF95980, "AF95980" },
                { 0xAF95A50, "AF95A50" },
                { 0xAF95BA0, "AF95BA0" },
                { 0xAF95E60, "AF95E60" },
                { 0xD2B7820, "D2B7820" },
                { 0xD2B7A00, "D2B7A00" },
                { 0xD232F70, "D232F70" }
            };

            std::ostringstream classifyPath;
            classifyPath
                << "logs\\online\\online_focus_classification_"
                << GetCurrentProcessId() << ".txt";
            std::ofstream classify(
                classifyPath.str(), std::ios::trunc);

            if (classify)
            {
                classify << "[T9 ONLINE FOCUS CLASSIFIER BUILD215]\n";
                classify << "moduleBase=0x"
                         << std::hex << std::uppercase
                         << base << std::dec << "\n\n";

                for (const auto& focus : focusFunctions)
                {
                    const auto address = base + focus.rva;

                    auto rankedIt = std::find_if(
                        ranked.begin(), ranked.end(),
                        [&](const auto& item)
                        {
                            return item.first == address;
                        });

                    classify << "[" << focus.label
                             << " rva=0x"
                             << std::hex << std::uppercase
                             << focus.rva << std::dec << "]\n";

                    if (rankedIt != ranked.end())
                    {
                        classify << "score="
                                 << rankedIt->second.score
                                 << " hits="
                                 << rankedIt->second.hits
                                 << " roles=";

                        bool first = true;
                        for (const auto& role :
                             rankedIt->second.roles)
                        {
                            if (!first) classify << '|';
                            first = false;
                            classify << role.first
                                     << ':' << role.second;
                        }
                        classify << "\n";
                    }
                    else
                    {
                        classify << "score=0 hits=0 roles=none\n";
                    }

                    constexpr std::size_t kBytes = 0x180;
                    unsigned char bytes[kBytes]{};
                    unsigned int localCalls = 0;
                    unsigned int familyCalls = 0;

                    if (SafeRead(address, bytes, sizeof(bytes)))
                    {
                        classify << "directCalls:\n";
                        for (std::size_t off = 0;
                             off + 5 <= sizeof(bytes);
                             ++off)
                        {
                            if (bytes[off] != 0xE8)
                                continue;

                            std::int32_t rel = 0;
                            std::memcpy(
                                &rel,
                                bytes + off + 1,
                                sizeof(rel));

                            const auto callAddress =
                                address + off;
                            const auto target =
                                static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(
                                        callAddress + 5) + rel);

                            if (target < base ||
                                target >= moduleEnd)
                                continue;

                            ++localCalls;

                            bool inFamily = false;
                            for (const auto& other :
                                 focusFunctions)
                            {
                                if (target ==
                                    base + other.rva)
                                {
                                    inFamily = true;
                                    ++familyCalls;
                                    break;
                                }
                            }

                            classify << "  callRva=0x"
                                     << std::hex
                                     << std::uppercase
                                     << (callAddress - base)
                                     << " targetRva=0x"
                                     << (target - base)
                                     << (inFamily
                                         ? " [FOCUS_FAMILY]"
                                         : "")
                                     << std::dec << "\n";
                        }
                    }

                    classify << "directCallCount="
                             << localCalls
                             << " familyCallCount="
                             << familyCalls
                             << "\n";

                    // Lightweight inferred bucket from the existing role evidence.
                    std::string bucket = "GENERIC_HELPER";
                    if (rankedIt != ranked.end())
                    {
                        const auto& roles =
                            rankedIt->second.roles;

                        const auto countRole =
                            [&](const char* key)
                            {
                                const auto it = roles.find(key);
                                return it == roles.end()
                                    ? 0u : it->second;
                            };

                        const unsigned int auth =
                            countRole("AUTH") +
                            countRole("DW_AUTH") +
                            countRole("DW_LOGON") +
                            countRole("DEMONWARE");
                        const unsigned int lobby =
                            countRole("LOBBY") +
                            countRole("DW_LOBBY");
                        const unsigned int mm =
                            countRole("MATCHMAKING");
                        const unsigned int presence =
                            countRole("PRESENCE") +
                            countRole("FRIENDS");
                        const unsigned int storage =
                            countRole("STORAGE") +
                            countRole("LIVESTORAGE") +
                            countRole("INVENTORY") +
                            countRole("MARKETPLACE");

                        unsigned int best = auth;
                        bucket = "AUTH_LOGON";

                        if (lobby > best)
                        {
                            best = lobby;
                            bucket = "LOBBY_STATE";
                        }
                        if (mm > best)
                        {
                            best = mm;
                            bucket = "MATCHMAKING_SESSION";
                        }
                        if (presence > best)
                        {
                            best = presence;
                            bucket = "PRESENCE_FRIENDS";
                        }
                        if (storage > best)
                        {
                            best = storage;
                            bucket = "STORAGE_INVENTORY";
                        }
                        if (best == 0)
                            bucket = "GENERIC_HELPER";
                    }

                    classify << "inferredBucket="
                             << bucket << "\n\n";
                }
            }
        }

        std::ostringstream windowsPath;
        windowsPath
            << "logs\\online\\online_windows_"
            << GetCurrentProcessId() << ".txt";
        std::ofstream windows(
            windowsPath.str(), std::ios::trunc);

        if (windows)
        {
            windows << "[T9 ONLINE SERVICE CODE WINDOWS]\n";
            windows << "Read-only bytes around the highest-ranked auth/lobby/matchmaking/backend call targets.\n\n";

            const auto count =
                std::min<std::size_t>(ranked.size(), 24);

            for (std::size_t i = 0; i < count; ++i)
            {
                const auto address = ranked[i].first;
                constexpr std::size_t kBefore = 0x60;
                constexpr std::size_t kAfter = 0xE0;
                const auto start =
                    address > base + kBefore
                        ? address - kBefore
                        : base;
                constexpr std::size_t kSize =
                    kBefore + kAfter;

                unsigned char bytes[kSize]{};
                windows << "[#" << (i + 1)
                        << " targetRva=0x"
                        << std::hex << std::uppercase
                        << (address - base)
                        << std::dec << "]\n";

                if (!SafeRead(start, bytes, sizeof(bytes)))
                {
                    windows << "unreadable\n\n";
                    continue;
                }

                for (std::size_t off = 0;
                     off < sizeof(bytes);
                     off += 16)
                {
                    windows << "rva=0x"
                            << std::hex << std::uppercase
                            << (start + off - base)
                            << ": ";
                    for (std::size_t j = 0;
                         j < 16 &&
                         off + j < sizeof(bytes);
                         ++j)
                    {
                        windows << std::setw(2)
                                << std::setfill('0')
                                << static_cast<unsigned int>(
                                    bytes[off + j])
                                << ' ';
                    }
                    windows << std::dec << "\n";
                }
                windows << "\n";
            }
        }

        std::ostringstream out;
        out << "online service scan complete: "
            << hits.size() << " service strings, "
            << xrefCount << " xrefs, "
            << callCount << " nearby calls. PID="
            << GetCurrentProcessId();
        message = out.str();
        return !hits.empty();
    }
}
