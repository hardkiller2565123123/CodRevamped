#include "ValidatedAddressScanner.h"
#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace
{
    struct Candidate
    {
        uintptr_t address{};
        unsigned callReferences{};
        bool executableSection{};
        bool unwindEntry{};
        bool commonPrologue{};
        bool instructionBoundary{};
        unsigned confidence{};
    };

    bool IsCommonX64Prologue(const unsigned char* p, size_t n)
    {
        if (!p || n < 8) return false;
        if (p[0] == 0x40 && (p[1] == 0x53 || p[1] == 0x55 || p[1] == 0x56 || p[1] == 0x57)) return true;
        if (p[0] == 0x48 && p[1] == 0x89 && (p[2] == 0x5C || p[2] == 0x6C || p[2] == 0x74 || p[2] == 0x7C)) return true;
        if (p[0] == 0x48 && (p[1] == 0x83 || p[1] == 0x81) && p[2] == 0xEC) return true;
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xDC) return true;
        return false;
    }

    std::string AnalysisDirectory()
    {
        wchar_t path[MAX_PATH]{};
        if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return "logs\\scanner\\analysis";
        wchar_t* slash = wcsrchr(path, L'\\');
        if (slash) *slash = L'\0';
        std::wstring root(path);
        std::wstring logs = root + L"\\logs";
        std::wstring analysis = logs + L"\\analysis";
        CreateDirectoryW(logs.c_str(), nullptr);
        CreateDirectoryW(analysis.c_str(), nullptr);
        char utf8[MAX_PATH * 3]{};
        WideCharToMultiByte(CP_UTF8, 0, analysis.c_str(), -1, utf8, sizeof(utf8), nullptr, nullptr);
        return utf8;
    }

    bool InRange(uintptr_t value, uintptr_t begin, uintptr_t end)
    {
        return value >= begin && value < end;
    }
}

namespace scanner
{
    bool RunValidatedAddressPass()
    {
        const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return false;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        const uintptr_t imageEnd = base + nt->OptionalHeader.SizeOfImage;

        struct Range { uintptr_t begin, end; std::string name; };
        std::vector<Range> executable;
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            char name[9]{};
            memcpy(name, sec[i].Name, 8);
            const uintptr_t begin = base + sec[i].VirtualAddress;
            const auto sectionSize = (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            const uintptr_t end = (std::min)(imageEnd, begin + static_cast<uintptr_t>(sectionSize));
            if (end > begin) executable.push_back({ begin, end, name });
        }

        std::map<uintptr_t, Candidate> candidates;
        for (const auto& range : executable)
        {
            const auto* bytes = reinterpret_cast<const unsigned char*>(range.begin);
            const size_t size = static_cast<size_t>(range.end - range.begin);
            for (size_t i = 0; i + 5 <= size; ++i)
            {
                if (bytes[i] != 0xE8) continue;
                int32_t displacement{};
                memcpy(&displacement, bytes + i + 1, sizeof(displacement));
                const uintptr_t target = range.begin + i + 5 + displacement;
                if (!InRange(target, base, imageEnd)) continue;
                auto inExec = std::find_if(executable.begin(), executable.end(), [target](const Range& r) {
                    return InRange(target, r.begin, r.end);
                });
                if (inExec == executable.end()) continue;
                Candidate& c = candidates[target];
                c.address = target;
                ++c.callReferences;
                c.executableSection = true;
            }
        }

        for (auto& pair : candidates)
        {
            Candidate& c = pair.second;
            DWORD64 imageBase = 0;
            c.unwindEntry = RtlLookupFunctionEntry(static_cast<DWORD64>(c.address), &imageBase, nullptr) != nullptr;
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T queried = VirtualQuery(reinterpret_cast<const void*>(c.address), &mbi, sizeof(mbi));
            const DWORD protection = queried ? (mbi.Protect & 0xFFu) : 0u;
            const bool readable = queried != 0 &&
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_GUARD) &&
                protection != PAGE_NOACCESS;
            const uintptr_t regionEnd = queried
                ? reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize
                : 0;
            c.commonPrologue = readable &&
                c.address <= regionEnd &&
                regionEnd - c.address >= 16 &&
                IsCommonX64Prologue(reinterpret_cast<const unsigned char*>(c.address), 16);
            // A direct call target is itself a CPU instruction boundary. Requiring unwind
            // metadata or a recognized entry prologue avoids treating internal labels as entries.
            c.instructionBoundary = c.callReferences > 0;
            unsigned score = 0;
            if (c.executableSection) score += 20;
            if (c.instructionBoundary) score += 20;
            if (c.unwindEntry) score += 35;
            if (c.commonPrologue) score += 20;
            if (c.callReferences >= 2) score += 3;
            if (c.callReferences >= 5) score += 2;
            c.confidence = (std::min)(score, 100u);
        }

        const std::string dir = AnalysisDirectory();
        std::ofstream all(dir + "\\function_boundaries_validated.csv", std::ios::trunc);
        std::ofstream safe(dir + "\\hook_safe_candidates.csv", std::ios::trunc);
        all << "rva,address,call_references,executable,unwind_entry,common_prologue,instruction_boundary,confidence,classification\n";
        safe << "rva,address,call_references,confidence,reason\n";

        size_t safeCount = 0;
        for (const auto& pair : candidates)
        {
            const Candidate& c = pair.second;
            const bool hookSafe = c.confidence >= 95 && c.unwindEntry && c.commonPrologue && c.callReferences >= 1;
            all << "0x" << std::hex << std::uppercase << (c.address - base)
                << ",0x" << c.address << std::dec
                << ',' << c.callReferences
                << ',' << (c.executableSection ? 1 : 0)
                << ',' << (c.unwindEntry ? 1 : 0)
                << ',' << (c.commonPrologue ? 1 : 0)
                << ',' << (c.instructionBoundary ? 1 : 0)
                << ',' << c.confidence
                << ',' << (hookSafe ? "HOOK_SAFE_CANDIDATE" : "ANALYSIS_ONLY") << '\n';
            if (hookSafe)
            {
                ++safeCount;
                safe << "0x" << std::hex << std::uppercase << (c.address - base)
                     << ",0x" << c.address << std::dec << ',' << c.callReferences << ',' << c.confidence
                     << ",unique direct-call boundary + executable section + unwind entry + recognized prologue\n";
            }
        }

        std::ofstream summary(dir + "\\validated_scan_summary.json", std::ios::trunc);
        summary << "{\n"
                << "  \"direct_call_targets\": " << candidates.size() << ",\n"
                << "  \"hook_safe_candidates\": " << safeCount << ",\n"
                << "  \"policy\": \"analysis only; no hooks are installed automatically\"\n"
                << "}\n";
        std::printf("[VALIDATE] Function-boundary pass complete: %zu call targets, %zu hook-safe candidates.\n",
            candidates.size(), safeCount);
        return true;
    }
}
