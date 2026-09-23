#include "ResearchCatalog.h"
#include "../../clients/coldwar/game/T9Addresses.h"
#include "../core/functions.hpp"

std::uintptr_t find_pattern(std::uintptr_t start, const char* moduleName, const char* pattern);

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <vector>

namespace research_catalog
{
    namespace
    {
        std::uintptr_t g_moduleBase = 0;
        std::size_t g_imageSize = 0;
        std::string g_fingerprint = "uninitialized";
        std::mutex g_mutex;
        std::vector<Entry> g_entries = {
#include "T9ResearchCatalog.generated.inl"
        };
        std::vector<Pattern> g_patterns = {
#include "T9ResearchPatterns.generated.inl"
        };

        struct CachedCodeRva
        {
            const char* name;
            std::uintptr_t rva;
        };

        constexpr DWORD kKnownRetailTimestamp = t9_addresses::RetailFingerprint.timestamp;
        constexpr std::size_t kKnownRetailImageSize = t9_addresses::RetailFingerprint.imageSize;
        constexpr CachedCodeRva kKnownRetailCode[] =
        {
            {"cl_getusercmd", t9_addresses::RetailResearch.cl_getusercmd},
            {"cl_getusercmdnumber", t9_addresses::RetailResearch.cl_getusercmdnumber},
            {"pmovehandler", t9_addresses::RetailResearch.pmovehandler},
            {"com_sessionmode_getmode", t9_addresses::RetailResearch.com_sessionmode_getmode},
            {"com_ingame", t9_addresses::RetailResearch.com_ingame},
            {"cg_predictedplayerstate", t9_addresses::RetailResearch.cg_predictedplayerstate},
            {"CG_GetEntityState", t9_addresses::RetailResearch.CG_GetEntityState},
            {"unknown_CG_GetEntity", t9_addresses::RetailResearch.unknown_CG_GetEntity},
            {"CG_GetEntityOriginAngles", t9_addresses::RetailResearch.CG_GetEntityOriginAngles},
            {"cg_getclientinfo", t9_addresses::RetailResearch.cg_getclientinfo},
            {"istargetvisible", t9_addresses::RetailResearch.istargetvisible},
            {"worldpostoscreenpos", t9_addresses::RetailResearch.worldpostoscreenpos},
            {"cg_getplayervieworigin", t9_addresses::RetailResearch.cg_getplayervieworigin},
            {"getviewaxisprojections", t9_addresses::RetailResearch.getviewaxisprojections},
            {"cl_setviewangles", t9_addresses::RetailResearch.cl_setviewangles},
            {"CG_DObjGetWorldTagMatrix", t9_addresses::RetailResearch.CG_DObjGetWorldTagMatrix},
            {"cg_getdobj", t9_addresses::RetailResearch.cg_getdobj}
        };

        bool g_exactKnownRetailBuild = false;

        std::uintptr_t CachedAddressFor(const char* name)
        {
            if (!g_exactKnownRetailBuild || !name)
                return 0;
            for (const auto& cached : kKnownRetailCode)
                if (_stricmp(cached.name, name) == 0)
                    return g_moduleBase + cached.rva;
            return 0;
        }

        std::string Lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        }

        bool QueryReadable(std::uintptr_t address, bool requireExecutable)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!address || !VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)))
                return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
                return false;
            if (!requireExecutable)
                return true;
            const DWORD p = mbi.Protect & 0xFF;
            return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                   p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsInsideImage(std::uintptr_t address)
        {
            return g_moduleBase && g_imageSize && address >= g_moduleBase && address < g_moduleBase + g_imageSize;
        }

        bool ReadImageInfo(std::uintptr_t base, std::size_t& imageSize, DWORD& timestamp)
        {
            __try
            {
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
                if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
                    return false;
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
                if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
                    return false;
                imageSize = nt->OptionalHeader.SizeOfImage;
                timestamp = nt->FileHeader.TimeDateStamp;
                return imageSize != 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        std::uintptr_t ResolveTarget(std::uintptr_t match, Pattern& p)
        {
            p.scalarValue = p.resolve == ResolveKind::OFFSET;
            if (!match)
            {
                p.status = "pattern not found";
                return 0;
            }

            const std::uintptr_t at = match + p.operandOffset;
            __try
            {
                switch (p.resolve)
                {
                case ResolveKind::CALL:
                    return at + 5 + *reinterpret_cast<const std::int32_t*>(at + 1);
                case ResolveKind::MOV:
                case ResolveKind::LEA:
                    return at + 7 + *reinterpret_cast<const std::int32_t*>(at + 3);
                case ResolveKind::OFFSET:
                    return *reinterpret_cast<const std::uint32_t*>(at);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                p.status = "operand read fault";
            }
            return 0;
        }

        bool ValidatePatternResult(Pattern& p)
        {
            if (!p.resolvedAddress)
            {
                if (p.status.empty()) p.status = "unresolved";
                return false;
            }

            if (p.scalarValue)
            {
                // Structure offsets and sizes are scalar values, not virtual addresses.
                // Reject obvious opcode/immediate misreads and implausibly large values.
                if (p.resolvedAddress > 0x04000000ull)
                {
                    p.status = "scalar outside plausible range";
                    return false;
                }
                p.status = "validated scalar offset";
                return true;
            }

            if (!IsInsideImage(p.resolvedAddress))
            {
                p.status = "target outside main image";
                return false;
            }
            if (!QueryReadable(p.resolvedAddress, true))
            {
                p.status = "target is not executable";
                return false;
            }
            p.status = "validated executable target";
            return true;
        }

        std::string LogPath(const char* file)
        {
            char modulePath[MAX_PATH]{};
            GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
            std::string path(modulePath);
            const auto slash = path.find_last_of("\\/");
            path = slash == std::string::npos ? "." : path.substr(0, slash);
            CreateDirectoryA((path + "\\logs").c_str(), nullptr);
            return path + "\\logs\\research\\" + file;
        }

        void RefreshEntryCandidates()
        {
            for (auto& entry : g_entries)
            {
                entry.runtimeAddress = 0;
                entry.currentBuildCandidate = false;
                if (!entry.referenceRva || entry.referenceRva >= g_imageSize)
                    continue;
                const auto address = g_moduleBase + static_cast<std::uintptr_t>(entry.referenceRva);
                const bool requireExecutable = entry.kind == EntryKind::Function;
                if (!QueryReadable(address, requireExecutable))
                    continue;
                entry.runtimeAddress = address;
                entry.currentBuildCandidate = true;
            }
        }
    }

    void Initialize(std::uintptr_t moduleBase)
    {
        g_moduleBase = moduleBase;
        DWORD timestamp = 0;
        ReadImageInfo(g_moduleBase, g_imageSize, timestamp);
        std::ostringstream fingerprint;
        fingerprint << "timestamp=0x" << std::hex << std::uppercase << timestamp
                    << " image=0x" << g_imageSize;
        g_fingerprint = fingerprint.str();
        g_exactKnownRetailBuild = timestamp == kKnownRetailTimestamp && g_imageSize == kKnownRetailImageSize;
        RefreshEntryCandidates();
        std::printf("[RESEARCH] Loaded %zu version-tagged references and %zu signatures (%s).\n",
            g_entries.size(), g_patterns.size(), g_fingerprint.c_str());
        WriteReports();
    }

    void ResolveAll()
    {
        if (!g_moduleBase)
            return;
        std::lock_guard<std::mutex> lock(g_mutex);
        std::size_t resolved = 0;
        for (auto& p : g_patterns)
        {
            p.resolvedAddress = 0;
            p.unique = false;
            p.scalarValue = false;
            p.status.clear();
            const auto match = find_pattern(g_moduleBase, nullptr, p.bytes);
            p.resolvedAddress = ResolveTarget(match, p);
            p.unique = ValidatePatternResult(p);
            if (!p.unique && !p.scalarValue)
            {
                const auto cached = CachedAddressFor(p.name);
                if (cached)
                {
                    p.resolvedAddress = cached;
                    p.status = "exact-build cached RVA fallback";
                    p.unique = ValidatePatternResult(p);
                    if (p.unique)
                        p.status = "validated exact-build cached RVA";
                }
            }
            if (p.unique)
                ++resolved;
        }
        std::printf("[RESEARCH] Signature pass: %zu/%zu validated for current image; no automatic hooks installed.\n",
            resolved, g_patterns.size());
        WriteReports();
    }

    void Revalidate()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto& p : g_patterns)
        {
            if (!p.unique)
                continue;
            p.unique = ValidatePatternResult(p);
        }
        RefreshEntryCandidates();
    }

    std::vector<Entry> Search(const std::string& query, std::size_t limit)
    {
        const std::string needle = Lower(query);
        std::vector<Entry> out;
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& entry : g_entries)
        {
            const std::string name = Lower(entry.name ? entry.name : "");
            const std::string subsystem = Lower(entry.subsystem ? entry.subsystem : "");
            if (needle.empty() || name.find(needle) != std::string::npos || subsystem.find(needle) != std::string::npos)
            {
                out.push_back(entry);
                if (out.size() >= limit)
                    break;
            }
        }
        return out;
    }

    std::vector<Pattern> PatternSnapshot()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_patterns;
    }

    bool TryGetResolved(const std::string& name, std::uintptr_t& value, bool& scalar)
    {
        const auto needle = Lower(name);
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& p : g_patterns)
        {
            if (Lower(p.name ? p.name : "") == needle && p.unique)
            {
                value = p.resolvedAddress;
                scalar = p.scalarValue;
                return true;
            }
        }
        value = 0;
        scalar = false;
        return false;
    }

    std::string BuildFingerprint()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_fingerprint;
    }

    std::size_t EntryCount()
    {
        return g_entries.size();
    }

    std::size_t ResolvedCount()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return static_cast<std::size_t>(std::count_if(g_patterns.begin(), g_patterns.end(),
            [](const Pattern& p) { return p.unique; }));
    }

    void WriteReports()
    {
        {
            std::ofstream out(LogPath("research_catalog.csv"), std::ios::trunc);
            out << "name,reference_rva,runtime_address,current_build_candidate,kind,subsystem,source\n";
            for (const auto& e : g_entries)
            {
                out << '"' << e.name << "\",0x" << std::hex << std::uppercase << e.referenceRva
                    << ",0x" << e.runtimeAddress << std::dec << ',' << (e.currentBuildCandidate ? 1 : 0)
                    << ',' << (e.kind == EntryKind::Function ? "function" : "reference")
                    << ",\"" << e.subsystem << "\",\"" << e.source << "\"\n";
            }
        }
        {
            std::ofstream out(LogPath("research_resolver.csv"), std::ios::trunc);
            out << "name,pattern,value,value_kind,resolved_rva,validated,status,build\n";
            for (const auto& p : g_patterns)
            {
                const auto rva = (!p.scalarValue && p.resolvedAddress && IsInsideImage(p.resolvedAddress))
                    ? p.resolvedAddress - g_moduleBase : 0;
                out << '"' << p.name << "\",\"" << p.bytes << "\",0x" << std::hex << std::uppercase
                    << p.resolvedAddress << ',' << (p.scalarValue ? "scalar" : "address")
                    << ",0x" << rva << std::dec << ',' << (p.unique ? 1 : 0)
                    << ",\"" << p.status << "\",\"" << g_fingerprint << "\"\n";
            }
        }
    }
}
