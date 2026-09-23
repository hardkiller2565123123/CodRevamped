#include "AdvancedAnalysisScanner.h"

#include <Windows.h>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{
    struct Range
    {
        uintptr_t begin{};
        uintptr_t end{};
        bool executable{};
        bool readable{};
        std::string name;
    };

    struct FunctionInfo
    {
        uintptr_t begin{};
        uintptr_t end{};
        unsigned incoming{};
        unsigned outgoing{};
        unsigned ripReferences{};
        unsigned stringReferences{};
        std::set<std::string> strings;
        std::set<std::string> imports;
        std::string subsystem{"unknown"};
        unsigned confidence{};
    };

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

    bool IsPrintableAscii(unsigned char c)
    {
        return c >= 0x20 && c <= 0x7E;
    }

    std::string CsvEscape(const std::string& input)
    {
        if (input.find_first_of(",\"\r\n") == std::string::npos) return input;
        std::string out = "\"";
        for (char c : input)
        {
            if (c == '\"') out += "\"\"";
            else out += c;
        }
        out += '\"';
        return out;
    }

    std::string JoinLimited(const std::set<std::string>& values, size_t maxValues)
    {
        std::ostringstream out;
        size_t count = 0;
        for (const auto& value : values)
        {
            if (count++) out << " | ";
            out << value;
            if (count >= maxValues) break;
        }
        return out.str();
    }

    std::string Lower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    std::string ClassifySubsystem(const FunctionInfo& function)
    {
        std::string corpus;
        for (const auto& value : function.strings)
        {
            corpus += ' ';
            corpus += Lower(value);
        }
        for (const auto& value : function.imports)
        {
            corpus += ' ';
            corpus += Lower(value);
        }

        struct Rule { const char* name; const char* needles[8]; };
        static const Rule rules[] = {
            {"demonware", {"demonware", "dw_", "loginservice", "auth", "bdlobby", nullptr}},
            {"matchmaking", {"matchmaking", "playlist", "search lobby", "join lobby", nullptr}},
            {"lobby", {"lobby", "session", "party", "host migration", nullptr}},
            {"network", {"socket", "winsock", "getaddrinfo", "sendto", "recvfrom", "http", "tcp", "udp"}},
            {"console", {"cbuf", "command", "console", "cmd", "dvar", nullptr}},
            {"script_vm", {"script", "scr_", "scrvm", "opcode", "notify", nullptr}},
            {"renderer", {"material", "shader", "draw", "render", "d3d", "dxgi", "font", "text"}},
            {"frontend_ui", {"frontend", "menu", "ui_", "uiscreen", "widget", nullptr}},
            {"asset_database", {"asset", "xasset", "zone", "fastfile", "stream", "pak", nullptr}},
            {"filesystem", {"file", "path", "directory", "openfile", "readfile", "writefile", nullptr}},
            {"audio", {"sound", "audio", "voice", "wwise", "speaker", nullptr}},
            {"stats", {"stats", "rank", "progression", "leaderboard", "inventory", nullptr}},
            {"gameplay", {"gametype", "player", "weapon", "spawn", "clientthink", nullptr}}
        };

        for (const auto& rule : rules)
        {
            for (const char* needle : rule.needles)
            {
                if (!needle) break;
                if (corpus.find(needle) != std::string::npos) return rule.name;
            }
        }
        return "unknown";
    }

    const Range* FindRange(const std::vector<Range>& ranges, uintptr_t address)
    {
        for (const auto& range : ranges)
            if (InRange(address, range.begin, range.end)) return &range;
        return nullptr;
    }

    size_t FindOwningFunction(const std::vector<FunctionInfo>& functions, uintptr_t address)
    {
        size_t lo = 0;
        size_t hi = functions.size();
        while (lo < hi)
        {
            const size_t mid = lo + (hi - lo) / 2;
            if (functions[mid].begin <= address) lo = mid + 1;
            else hi = mid;
        }
        if (!lo) return static_cast<size_t>(-1);
        const size_t index = lo - 1;
        return address < functions[index].end ? index : static_cast<size_t>(-1);
    }

    bool DecodeRipTarget(const unsigned char* p, size_t remaining, uintptr_t instruction, uintptr_t& target)
    {
        if (remaining < 7) return false;
        size_t prefix = 0;
        if ((p[0] & 0xF0) == 0x40) prefix = 1;
        if (remaining < prefix + 6) return false;
        const unsigned char opcode = p[prefix];
        if (opcode != 0x8D && opcode != 0x8B && opcode != 0x89 && opcode != 0x3B && opcode != 0x85) return false;
        const unsigned char modrm = p[prefix + 1];
        if ((modrm & 0xC7) != 0x05) return false;
        int32_t displacement{};
        std::memcpy(&displacement, p + prefix + 2, sizeof(displacement));
        const size_t length = prefix + 6;
        target = instruction + length + displacement;
        return true;
    }
}

namespace scanner
{
    bool RunAdvancedAnalysisPass()
    {
        const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return false;
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        const uintptr_t imageEnd = base + nt->OptionalHeader.SizeOfImage;

        std::vector<Range> ranges;
        const auto* section = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            char name[9]{};
            std::memcpy(name, section[i].Name, 8);
            const uintptr_t begin = base + section[i].VirtualAddress;
            const uintptr_t size = (std::max)(section[i].Misc.VirtualSize, section[i].SizeOfRawData);
            const uintptr_t end = (std::min)(imageEnd, begin + size);
            if (end <= begin) continue;
            const DWORD c = section[i].Characteristics;
            ranges.push_back({begin, end, (c & IMAGE_SCN_MEM_EXECUTE) != 0, (c & IMAGE_SCN_MEM_READ) != 0, name});
        }

        std::vector<FunctionInfo> functions;
        const auto& exceptionDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exceptionDir.VirtualAddress && exceptionDir.Size >= sizeof(RUNTIME_FUNCTION))
        {
            const auto* entries = reinterpret_cast<const RUNTIME_FUNCTION*>(base + exceptionDir.VirtualAddress);
            const size_t count = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);
            functions.reserve(count);
            for (size_t i = 0; i < count; ++i)
            {
                const uintptr_t begin = base + entries[i].BeginAddress;
                const uintptr_t end = base + entries[i].EndAddress;
                if (begin >= end || !InRange(begin, base, imageEnd) || end > imageEnd) continue;
                const Range* owner = FindRange(ranges, begin);
                if (!owner || !owner->executable) continue;
                functions.push_back({begin, end});
            }
        }
        std::sort(functions.begin(), functions.end(), [](const FunctionInfo& a, const FunctionInfo& b) {
            return a.begin < b.begin;
        });
        functions.erase(std::unique(functions.begin(), functions.end(), [](const FunctionInfo& a, const FunctionInfo& b) {
            return a.begin == b.begin;
        }), functions.end());

        std::unordered_map<uintptr_t, std::string> strings;
        for (const auto& range : ranges)
        {
            if (!range.readable || range.executable) continue;
            const auto* bytes = reinterpret_cast<const unsigned char*>(range.begin);
            const size_t size = static_cast<size_t>(range.end - range.begin);
            size_t i = 0;
            while (i < size)
            {
                if (!IsPrintableAscii(bytes[i])) { ++i; continue; }
                const size_t start = i;
                while (i < size && IsPrintableAscii(bytes[i]) && i - start < 512) ++i;
                const size_t length = i - start;
                if (length >= 4 && i < size && bytes[i] == 0)
                    strings.emplace(range.begin + start, std::string(reinterpret_cast<const char*>(bytes + start), length));
                if (i == start) ++i;
            }
        }

        std::map<std::pair<size_t, size_t>, unsigned> edges;
        for (size_t index = 0; index < functions.size(); ++index)
        {
            auto& function = functions[index];
            const size_t size = static_cast<size_t>(function.end - function.begin);
            const auto* bytes = reinterpret_cast<const unsigned char*>(function.begin);
            for (size_t offset = 0; offset < size; ++offset)
            {
                if (offset + 5 <= size && bytes[offset] == 0xE8)
                {
                    int32_t displacement{};
                    std::memcpy(&displacement, bytes + offset + 1, sizeof(displacement));
                    const uintptr_t target = function.begin + offset + 5 + displacement;
                    const size_t callee = FindOwningFunction(functions, target);
                    if (callee != static_cast<size_t>(-1))
                    {
                        ++function.outgoing;
                        ++functions[callee].incoming;
                        ++edges[{index, callee}];
                    }
                    offset += 4;
                    continue;
                }

                uintptr_t target{};
                if (DecodeRipTarget(bytes + offset, size - offset, function.begin + offset, target))
                {
                    ++function.ripReferences;
                    const auto stringIt = strings.find(target);
                    if (stringIt != strings.end())
                    {
                        ++function.stringReferences;
                        if (function.strings.size() < 32) function.strings.insert(stringIt->second);
                    }
                }
            }
        }

        for (auto& function : functions)
        {
            function.subsystem = ClassifySubsystem(function);
            unsigned score = 35;
            if (function.incoming) score += 15;
            if (function.outgoing) score += 10;
            if (function.ripReferences) score += 10;
            if (function.stringReferences) score += 15;
            if (function.subsystem != "unknown") score += 15;
            function.confidence = (std::min)(score, 100u);
        }

        const std::string dir = AnalysisDirectory();
        std::ofstream database(dir + "\\functions_enriched.csv", std::ios::trunc);
        database << "rva_begin,rva_end,size,incoming_calls,outgoing_calls,rip_references,string_references,subsystem,confidence,strings\n";
        for (const auto& function : functions)
        {
            database << "0x" << std::hex << std::uppercase << (function.begin - base)
                     << ",0x" << (function.end - base) << std::dec
                     << ',' << (function.end - function.begin)
                     << ',' << function.incoming
                     << ',' << function.outgoing
                     << ',' << function.ripReferences
                     << ',' << function.stringReferences
                     << ',' << function.subsystem
                     << ',' << function.confidence
                     << ',' << CsvEscape(JoinLimited(function.strings, 12)) << '\n';
        }

        std::ofstream graph(dir + "\\call_graph_enriched.csv", std::ios::trunc);
        graph << "caller_rva,callee_rva,reference_count,caller_subsystem,callee_subsystem\n";
        for (const auto& edge : edges)
        {
            const auto& caller = functions[edge.first.first];
            const auto& callee = functions[edge.first.second];
            graph << "0x" << std::hex << std::uppercase << (caller.begin - base)
                  << ",0x" << (callee.begin - base) << std::dec
                  << ',' << edge.second << ',' << caller.subsystem << ',' << callee.subsystem << '\n';
        }

        std::map<std::string, size_t> subsystemCounts;
        for (const auto& function : functions) ++subsystemCounts[function.subsystem];
        std::ofstream clusters(dir + "\\subsystem_clusters.csv", std::ios::trunc);
        clusters << "subsystem,function_count\n";
        for (const auto& item : subsystemCounts) clusters << item.first << ',' << item.second << '\n';

        std::ofstream candidates(dir + "\\command_buffer_candidates.csv", std::ios::trunc);
        candidates << "rva,size,incoming_calls,outgoing_calls,rip_references,string_references,confidence,strings\n";
        for (const auto& function : functions)
        {
            std::string corpus = Lower(JoinLimited(function.strings, 32));
            const bool commandLike = function.subsystem == "console" || corpus.find("command") != std::string::npos ||
                corpus.find("cbuf") != std::string::npos || corpus.find("cmd") != std::string::npos;
            if (!commandLike || function.confidence < 60) continue;
            candidates << "0x" << std::hex << std::uppercase << (function.begin - base) << std::dec
                       << ',' << (function.end - function.begin)
                       << ',' << function.incoming << ',' << function.outgoing
                       << ',' << function.ripReferences << ',' << function.stringReferences
                       << ',' << function.confidence << ',' << CsvEscape(JoinLimited(function.strings, 12)) << '\n';
        }

        std::ofstream summary(dir + "\\advanced_analysis_summary.json", std::ios::trunc);
        summary << "{\n"
                << "  \"unwind_functions\": " << functions.size() << ",\n"
                << "  \"call_edges\": " << edges.size() << ",\n"
                << "  \"ascii_strings_indexed\": " << strings.size() << ",\n"
                << "  \"subsystem_clusters\": " << subsystemCounts.size() << ",\n"
                << "  \"outputs\": [\"functions_enriched.csv\", \"call_graph_enriched.csv\", \"subsystem_clusters.csv\", \"command_buffer_candidates.csv\"],\n"
                << "  \"policy\": \"read-only analysis; no hooks or patches are installed\"\n"
                << "}\n";

        std::printf("[ADVANCED] Enrichment complete: %zu unwind functions, %zu call edges, %zu indexed strings.\n",
            functions.size(), edges.size(), strings.size());
        return true;
    }
}
