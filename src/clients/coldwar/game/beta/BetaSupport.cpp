#include "BetaSupport.h"
#include "BetaResearch.h"
#include "../T9Addresses.h"
#include "../../../../shared/runtime/StoragePaths.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <utility>
#include <intrin.h>

namespace beta_support
{
    struct SectionInfo
    {
        std::string name;
        DWORD rva = 0;
        DWORD virtualSize = 0;
        DWORD rawSize = 0;
        DWORD characteristics = 0;
    };

    struct ImageLayout
    {
        uintptr_t base = 0;
        DWORD timestamp = 0;
        DWORD imageSize = 0;
        DWORD entryPoint = 0;
        DWORD importRva = 0;
        DWORD importSize = 0;
        DWORD exceptionRva = 0;
        DWORD exceptionSize = 0;
        std::vector<SectionInfo> sections;
    };

    static bool ReadBytes(uintptr_t address, void* output, size_t size)
    {
        SIZE_T read = 0;
        return size != 0 && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), output, size, &read) && read == size;
    }

    static bool ReadImageLayout(HMODULE module, ImageLayout& out)
    {
        if (!module) return false;
        const uintptr_t base = reinterpret_cast<uintptr_t>(module);
        IMAGE_DOS_HEADER dos{};
        if (!ReadBytes(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
            return false;

        IMAGE_NT_HEADERS64 nt{};
        if (!ReadBytes(base + static_cast<uintptr_t>(dos.e_lfanew), &nt, sizeof(nt)) ||
            nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return false;

        out = {};
        out.base = base;
        out.timestamp = nt.FileHeader.TimeDateStamp;
        out.imageSize = nt.OptionalHeader.SizeOfImage;
        out.entryPoint = nt.OptionalHeader.AddressOfEntryPoint;
        out.importRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        out.importSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        out.exceptionRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        out.exceptionSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

        const uintptr_t sectionTable = base + static_cast<uintptr_t>(dos.e_lfanew) +
            offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
        const WORD sectionCount = (std::min<WORD>)(nt.FileHeader.NumberOfSections, 96);
        out.sections.reserve(sectionCount);
        for (WORD i = 0; i < sectionCount; ++i)
        {
            IMAGE_SECTION_HEADER sh{};
            if (!ReadBytes(sectionTable + static_cast<uintptr_t>(i) * sizeof(sh), &sh, sizeof(sh)))
                break;
            char name[9]{};
            memcpy(name, sh.Name, 8);
            SectionInfo s{};
            s.name = name;
            s.rva = sh.VirtualAddress;
            s.virtualSize = sh.Misc.VirtualSize;
            s.rawSize = sh.SizeOfRawData;
            s.characteristics = sh.Characteristics;
            if (s.rva < out.imageSize)
                out.sections.push_back(s);
        }
        return out.imageSize != 0;
    }

    BuildInfo DetectCurrentBuild()
    {
        BuildInfo out{};
        ImageLayout image{};
        if (!ReadImageLayout(GetModuleHandleW(nullptr), image)) return out;
        out.timestamp = image.timestamp;
        out.imageSize = image.imageSize;
        out.entryPointRva = image.entryPoint;
        if (out.timestamp == t9_addresses::BetaFingerprint.timestamp &&
            out.imageSize == t9_addresses::BetaFingerprint.imageSize &&
            out.entryPointRva == t9_addresses::BetaFingerprint.entryPointRva)
            out.kind = BuildKind::OpenBeta;
        else if (out.imageSize == t9_addresses::RetailFingerprint.imageSize)
            out.kind = BuildKind::Retail;
        return out;
    }

    const char* BuildName(BuildKind kind)
    {
        switch (kind)
        {
        case BuildKind::Retail: return "Retail";
        case BuildKind::OpenBeta: return "Open Beta";
        default: return "Unknown";
        }
    }

    static std::string AnalysisDir()
    {
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"beta_game_scan");
        return storage_paths::PathA("logs\\beta_game_scan");
    }

    static std::string JsonEscape(const std::string& value)
    {
        std::ostringstream out;
        for (unsigned char c : value)
        {
            switch (c)
            {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c >= 0x20 && c < 0x7F) out << static_cast<char>(c);
                else out << '?';
                break;
            }
        }
        return out.str();
    }

    static void WriteBuildInfo(const BuildInfo& info, const ImageLayout& image)
    {
        std::ofstream f(AnalysisDir() + "\\build_info.json", std::ios::trunc);
        if (!f) return;
        f << "{\n  \"build\": \"" << BuildName(info.kind) << "\",\n"
          << "  \"module_base\": \"0x" << std::hex << std::uppercase << image.base << "\",\n"
          << "  \"timestamp\": \"0x" << image.timestamp << "\",\n"
          << "  \"image_size\": \"0x" << image.imageSize << "\",\n"
          << "  \"entry_point_rva\": \"0x" << image.entryPoint << "\"\n}\n";
    }

    static void WriteSections(const ImageLayout& image)
    {
        std::ofstream f(AnalysisDir() + "\\pe_sections.json", std::ios::trunc);
        if (!f) return;
        f << "{\n  \"sections\": [\n";
        for (size_t i = 0; i < image.sections.size(); ++i)
        {
            const auto& s = image.sections[i];
            f << "    {\"name\": \"" << JsonEscape(s.name) << "\", \"rva\": \"0x" << std::hex << std::uppercase
              << s.rva << "\", \"virtual_size\": \"0x" << s.virtualSize << "\", \"raw_size\": \"0x"
              << s.rawSize << "\", \"characteristics\": \"0x" << s.characteristics << "\"}";
            if (i + 1 != image.sections.size()) f << ',';
            f << '\n';
        }
        f << "  ]\n}\n";
    }

    static bool ReadCString(uintptr_t address, std::string& out, size_t maxLength = 512)
    {
        out.clear();
        for (size_t i = 0; i < maxLength; ++i)
        {
            char c = 0;
            if (!ReadBytes(address + i, &c, 1)) return false;
            if (!c) return true;
            if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) return false;
            out.push_back(c);
        }
        return true;
    }

    static bool ContainsInterestingKeyword(const std::string& text)
    {
        static const char* words[] = {
            "online", "offline", "network", "socket", "connect", "disconnect", "lobby", "session",
            "matchmaking", "demonware", "battle.net", "bnet", "auth", "signin", "login", "profile",
            "frontend", "menu", "server", "party", "invite", "playlist", "dw", "live", "entitlement",
            "license", "ownership", "fatal", "error", "platform", "user", "controller", "mode",
            "multiplayer", "private match", "gametype", "game mode", "mp_", "tdm", "team deathmatch",
            "deathmatch", "zombies", "campaign", "local game", "custom games", "lobbydata", "sessionmode"
        };
        std::string lower = text;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const char* word : words)
            if (lower.find(word) != std::string::npos) return true;
        return false;
    }

    struct InterestingString
    {
        uintptr_t address = 0;
        std::string value;
    };

    static std::vector<InterestingString> ScanInterestingStrings(const ImageLayout& image)
    {
        std::vector<InterestingString> strings;
        std::ofstream f(AnalysisDir() + "\\interesting_strings.csv", std::ios::trunc);
        if (!f) return strings;
        f << "rva,section,length,text\n";

        for (const auto& section : image.sections)
        {
            if (section.characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
            const size_t size = static_cast<size_t>((std::min<DWORD>)(section.virtualSize ? section.virtualSize : section.rawSize,
                image.imageSize - section.rva));
            if (size == 0 || size > 512ull * 1024ull * 1024ull) continue;
            std::vector<unsigned char> bytes(size);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva), bytes.data(), size, &got) || got == 0)
                continue;

            size_t i = 0;
            while (i < got)
            {
                const size_t start = i;
                while (i < got && bytes[i] >= 0x20 && bytes[i] <= 0x7E) ++i;
                const size_t length = i - start;
                if (length >= 5 && length <= 384)
                {
                    std::string text(reinterpret_cast<const char*>(bytes.data() + start), length);
                    if (ContainsInterestingKeyword(text))
                    {
                        InterestingString item{ image.base + section.rva + start, text };
                        strings.push_back(item);
                        f << "0x" << std::hex << std::uppercase << (item.address - image.base) << ',' << section.name << ','
                          << std::dec << text.size() << ",\"" << JsonEscape(text) << "\"\n";
                    }
                }
                ++i;
            }
        }
        return strings;
    }

    static void ScanStringReferences(const ImageLayout& image, const std::vector<InterestingString>& strings)
    {
        std::unordered_map<uintptr_t, const InterestingString*> byAddress;
        byAddress.reserve(strings.size());
        std::vector<const InterestingString*> orderedStrings;
        orderedStrings.reserve(strings.size());
        for (const auto& s : strings)
        {
            byAddress.emplace(s.address, &s);
            orderedStrings.push_back(&s);
        }
        std::sort(orderedStrings.begin(), orderedStrings.end(), [](const InterestingString* a, const InterestingString* b)
        {
            return a->address < b->address;
        });
        const auto findStringAt = [&](uintptr_t target) -> const InterestingString*
        {
            const auto exact = byAddress.find(target);
            if (exact != byAddress.end())
                return exact->second;
            const auto it = std::upper_bound(orderedStrings.begin(), orderedStrings.end(), target,
                [](uintptr_t value, const InterestingString* item)
                {
                    return value < item->address;
                });
            if (it == orderedStrings.begin())
                return nullptr;
            const InterestingString* candidate = *(it - 1);
            const uintptr_t end = candidate->address + candidate->value.size();
            return target >= candidate->address && target < end ? candidate : nullptr;
        };

        std::ofstream refs(AnalysisDir() + "\\string_xrefs.csv", std::ios::trunc);
        std::ofstream rip(AnalysisDir() + "\\rip_relative_refs.csv", std::ios::trunc);
        if (!refs || !rip) return;
        refs << "instruction_rva,section,opcode,target_rva,string\n";
        rip << "instruction_rva,section,opcode,target_rva,target_section\n";

        size_t ripCount = 0;
        const size_t ripLimit = 250000;
        for (const auto& section : image.sections)
        {
            if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            const size_t size = static_cast<size_t>((std::min<DWORD>)(section.virtualSize ? section.virtualSize : section.rawSize,
                image.imageSize - section.rva));
            if (size < 7) continue;
            std::vector<unsigned char> bytes(size);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva), bytes.data(), size, &got) || got < 7)
                continue;

            for (size_t i = 0; i + 7 <= got; ++i)
            {
                size_t instructionLength = 0;
                size_t displacementOffset = 0;
                const char* opcode = nullptr;

                // Common x64 RIP-relative forms used for globals and string addresses.
                if ((bytes[i] == 0x48 || bytes[i] == 0x4C) && (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B) &&
                    (bytes[i + 2] & 0xC7) == 0x05)
                {
                    instructionLength = 7;
                    displacementOffset = 3;
                    opcode = bytes[i + 1] == 0x8D ? "LEA_RIP" : "MOV_RIP";
                }
                else if ((bytes[i] == 0x80 || bytes[i] == 0x81 || bytes[i] == 0x83 || bytes[i] == 0xC6 || bytes[i] == 0xC7) &&
                    (bytes[i + 1] & 0xC7) == 0x05)
                {
                    instructionLength = 6;
                    displacementOffset = 2;
                    opcode = "OP_RIP";
                }
                if (!instructionLength || i + displacementOffset + 4 > got) continue;

                int32_t disp = 0;
                memcpy(&disp, bytes.data() + i + displacementOffset, sizeof(disp));
                const uintptr_t instruction = image.base + section.rva + i;
                const uintptr_t target = instruction + instructionLength + disp;
                if (target < image.base || target >= image.base + image.imageSize) continue;

                const InterestingString* matched = findStringAt(target);
                if (matched)
                {
                    refs << "0x" << std::hex << std::uppercase << (instruction - image.base) << ',' << section.name << ',' << opcode
                         << ",0x" << (target - image.base) << ",\"" << JsonEscape(matched->value) << "\"\n";
                }

                if (ripCount < ripLimit)
                {
                    std::string targetSection;
                    for (const auto& ts : image.sections)
                    {
                        const uintptr_t begin = image.base + ts.rva;
                        const uintptr_t end = begin + (ts.virtualSize ? ts.virtualSize : ts.rawSize);
                        if (target >= begin && target < end) { targetSection = ts.name; break; }
                    }
                    rip << "0x" << std::hex << std::uppercase << (instruction - image.base) << ',' << section.name << ',' << opcode
                        << ",0x" << (target - image.base) << ',' << targetSection << "\n";
                    ++ripCount;
                }
            }
        }
    }

    static bool IsNetworkImport(const std::string& module, const std::string& name)
    {
        std::string value = module + "!" + name;
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        static const char* terms[] = { "ws2_32", "winhttp", "wininet", "dnsapi", "iphlpapi", "connect", "socket", "send", "recv", "http", "internet", "getaddrinfo", "closesocket" };
        for (const char* term : terms) if (value.find(term) != std::string::npos) return true;
        return false;
    }

    static size_t ScanImports(const ImageLayout& image)
    {
        std::ofstream all(AnalysisDir() + "\\imports.csv", std::ios::trunc);
        std::ofstream net(AnalysisDir() + "\\network_imports.csv", std::ios::trunc);
        if (!all || !net) return 0;
        all << "module,name,ordinal,iat_rva,resolved_address\n";
        net << "module,name,ordinal,iat_rva,resolved_address\n";
        if (!image.importRva || image.importRva >= image.imageSize) return 0;

        const size_t maxDescriptors = image.importSize ? image.importSize / sizeof(IMAGE_IMPORT_DESCRIPTOR) : 4096;
        size_t count = 0;
        for (size_t di = 0; di < maxDescriptors; ++di)
        {
            IMAGE_IMPORT_DESCRIPTOR desc{};
            if (!ReadBytes(image.base + image.importRva + di * sizeof(desc), &desc, sizeof(desc)) || !desc.Name) break;
            if (desc.Name >= image.imageSize || desc.FirstThunk >= image.imageSize) continue;
            std::string module;
            if (!ReadCString(image.base + desc.Name, module, 260)) continue;
            const DWORD lookupRva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
            if (lookupRva >= image.imageSize) continue;

            for (size_t ti = 0; ti < 65536; ++ti)
            {
                IMAGE_THUNK_DATA64 lookup{};
                IMAGE_THUNK_DATA64 iat{};
                if (!ReadBytes(image.base + lookupRva + ti * sizeof(lookup), &lookup, sizeof(lookup)) || lookup.u1.AddressOfData == 0) break;
                if (!ReadBytes(image.base + desc.FirstThunk + ti * sizeof(iat), &iat, sizeof(iat))) break;
                std::string name;
                unsigned long long ordinal = 0;
                if (IMAGE_SNAP_BY_ORDINAL64(lookup.u1.Ordinal))
                    ordinal = IMAGE_ORDINAL64(lookup.u1.Ordinal);
                else if (lookup.u1.AddressOfData < image.imageSize)
                    ReadCString(image.base + static_cast<uintptr_t>(lookup.u1.AddressOfData) + sizeof(WORD), name, 512);

                std::ostringstream row;
                row << module << ",\"" << JsonEscape(name) << "\"," << ordinal << ",0x" << std::hex << std::uppercase
                    << (desc.FirstThunk + ti * sizeof(iat)) << ",0x" << static_cast<uintptr_t>(iat.u1.Function) << "\n";
                all << row.str();
                if (IsNetworkImport(module, name)) net << row.str();
                ++count;
            }
        }
        return count;
    }

    static size_t ScanDirectCalls(const ImageLayout& image)
    {
        std::ofstream f(AnalysisDir() + "\\direct_calls.csv", std::ios::trunc);
        if (!f) return 0;
        f << "call_rva,section,target_rva,target_section\n";
        size_t count = 0;
        const size_t limit = 1000000;
        for (const auto& section : image.sections)
        {
            if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            const size_t size = static_cast<size_t>((std::min<DWORD>)(section.virtualSize ? section.virtualSize : section.rawSize,
                image.imageSize - section.rva));
            std::vector<unsigned char> bytes(size);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva), bytes.data(), size, &got)) continue;
            for (size_t i = 0; i + 5 <= got && count < limit; ++i)
            {
                if (bytes[i] != 0xE8) continue;
                int32_t rel = 0;
                memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
                const uintptr_t source = image.base + section.rva + i;
                const uintptr_t target = source + 5 + rel;
                if (target < image.base || target >= image.base + image.imageSize) continue;
                std::string targetSection;
                for (const auto& ts : image.sections)
                {
                    const uintptr_t begin = image.base + ts.rva;
                    const uintptr_t end = begin + (ts.virtualSize ? ts.virtualSize : ts.rawSize);
                    if (target >= begin && target < end) { targetSection = ts.name; break; }
                }
                f << "0x" << std::hex << std::uppercase << (source - image.base) << ',' << section.name << ",0x"
                  << (target - image.base) << ',' << targetSection << "\n";
                ++count;
            }
        }
        return count;
    }

    namespace
    {
        std::atomic_bool g_recoveredClientStarted{false};
        std::atomic_bool g_monitorStarted{false};
        std::atomic_bool g_betaScannerAutoThreadStarted{false};

        using CommandFn = void(*)(int, const char*);
        using TransitionFn = void(*)(int, int);
        using InitFn = void(*)(int);
        using UsernameContextFn = void*(*)(int);
        using SetUsernameFn = void(*)(void*, const char*);

        static std::atomic_bool g_mpScanThreadRunning{false};
        static std::atomic_bool g_firstConfirmScanRequested{false};
        static std::atomic_bool g_passiveScanFilesInitialized{false};
        static std::atomic_bool g_stackBaselineThreadStarted{false};
        static std::atomic_bool g_clickStackSamplerStarted{false};
        static std::atomic_bool g_fullMemoryScanRunning{false};
        static std::atomic_bool g_lobbyRuntimeProbeRunning{false};
        static std::atomic_ullong g_lastConfirmTick{0};

        static void RuntimeLog(const char* fmt, ...)
        {
            char message[2048]{};
            va_list ap;
            va_start(ap, fmt);
            vsnprintf_s(message, sizeof(message), _TRUNCATE, fmt, ap);
            va_end(ap);

            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta");
            const std::string logPath = storage_paths::PathA("logs\\t9_beta\\recovered_client.log");
            FILE* f = nullptr;
            if (fopen_s(&f, logPath.c_str(), "a") == 0 && f)
            {
                SYSTEMTIME st{};
                GetLocalTime(&st);
                std::fprintf(f, "%04u-%02u-%02u %02u:%02u:%02u.%03u %s\n",
                    st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    message);
                std::fflush(f);
                std::fclose(f);
            }

            // Keep the important Beta frontend/runtime trace visible in the
            // console as it happens so a test does not require opening logs.
            std::printf("[T9-BETA] %s\n", message);
            std::fflush(stdout);
        }

        static uintptr_t ToGameRva(uintptr_t address)
        {
            const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            if (!base || address < base || address >= base + t9_addresses::BetaFingerprint.imageSize)
                return 0;
            return address - base;
        }

        static const char* ModeName(int value)
        {
            switch (value)
            {
            case 0: return "Zombies";
            case 1: return "Multiplayer";
            case 2: return "Campaign";
            default: return "Unknown";
            }
        }


        static unsigned long long MillisSinceConfirm()
        {
            const unsigned long long last = g_lastConfirmTick.load(std::memory_order_relaxed);
            if (!last) return ~0ull;
            const unsigned long long now = GetTickCount64();
            return now >= last ? now - last : 0ull;
        }

        struct FrontendTarget
        {
            const char* name;
            uintptr_t rva;
        };

        static std::string LowerAscii(std::string text)
        {
            std::transform(text.begin(), text.end(), text.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return text;
        }

        static bool IsMultiplayerString(const std::string& text)
        {
            const std::string lower = LowerAscii(text);
            static const char* terms[] = {
                // Multiplayer / frontend labels.
                "multiplayer", "private match", "private_game", "custom games", "custom game",
                "local game", "local multiplayer", "gametype", "game type", "game mode",
                "mp_", "tdm", "deathmatch", "team deathmatch", "playlist", "lobby",
                "session", "sessionmode", "session mode", "frontend", "front end", "menu",
                "party", "matchmaking", "start match", "start game", "launch game",
                "join game", "host game", "create lobby", "game lobby", "lobby state",

                // Explicit offline / local-network labels requested for Beta research.
                "offline", "offline mode", "offline multiplayer", "local", "lan",
                "system link", "systemlink", "split screen", "splitscreen", "solo",
                "bot", "bots", "network mode", "networkmode",

                // Service/state words that often gate the offline frontend.
                "online", "live", "signin", "sign in", "signed in", "signedin", "signed out", "signedout",
                "login", "auth", "authentication", "demonware", "dw", "battle.net", "bnet",
                "service", "services", "fence", "online services", "connect", "connection", "disconnect",
                "error", "failure", "failed", "controller", "local user", "ready",
                "button", "action", "callback", "confirm", "selected", "startmultiplayer",
                "transition", "initialize", "initialise", "initialization", "initialisation", "init",
                "networkmode", "network mode", "sessionmode", "session mode", "party state", "lobby state"
            };
            for (const char* term : terms)
                if (lower.find(term) != std::string::npos)
                    return true;
            return false;
        }

        static std::string FrontendKeywordTags(const std::string& text)
        {
            const std::string lower = LowerAscii(text);
            std::vector<std::string> tags;
            const auto add = [&](const char* tag)
            {
                if (std::find(tags.begin(), tags.end(), tag) == tags.end())
                    tags.emplace_back(tag);
            };

            if (lower.find("offline") != std::string::npos) add("offline");
            if (lower.find("multiplayer") != std::string::npos || lower.find("mp_") != std::string::npos ||
                lower.find("deathmatch") != std::string::npos || lower.find("tdm") != std::string::npos) add("multiplayer");
            if (lower.find("local") != std::string::npos || lower.find("lan") != std::string::npos ||
                lower.find("system link") != std::string::npos || lower.find("systemlink") != std::string::npos ||
                lower.find("split screen") != std::string::npos || lower.find("splitscreen") != std::string::npos) add("local");
            if (lower.find("frontend") != std::string::npos || lower.find("front end") != std::string::npos ||
                lower.find("menu") != std::string::npos) add("frontend");
            if (lower.find("lobby") != std::string::npos) add("lobby");
            if (lower.find("session") != std::string::npos) add("session");
            if (lower.find("playlist") != std::string::npos) add("playlist");
            if (lower.find("gametype") != std::string::npos || lower.find("game type") != std::string::npos ||
                lower.find("game mode") != std::string::npos) add("gametype");
            if (lower.find("button") != std::string::npos || lower.find("action") != std::string::npos ||
                lower.find("callback") != std::string::npos || lower.find("confirm") != std::string::npos ||
                lower.find("selected") != std::string::npos) add("ui_action");
            if (lower.find("transition") != std::string::npos || lower.find("startmultiplayer") != std::string::npos) add("transition");
            if (lower.find("initialize") != std::string::npos || lower.find("initialise") != std::string::npos ||
                lower.find("initialization") != std::string::npos || lower.find("initialisation") != std::string::npos ||
                lower.find("init") != std::string::npos) add("init");
            if (lower.find("networkmode") != std::string::npos || lower.find("network mode") != std::string::npos) add("networkmode");
            if (lower.find("sessionmode") != std::string::npos || lower.find("session mode") != std::string::npos) add("sessionmode");
            if (lower.find("online") != std::string::npos || lower.find("connect") != std::string::npos ||
                lower.find("connection") != std::string::npos || lower.find("network") != std::string::npos ||
                lower.find("service") != std::string::npos) add("network");
            if (lower.find("disconnect") != std::string::npos || lower.find("disconnected") != std::string::npos) add("disconnect");
            if (lower.find("fence") != std::string::npos) add("fence");
            if (lower.find("party") != std::string::npos) add("party");
            if (lower.find("controller") != std::string::npos || lower.find("local user") != std::string::npos) add("controller");
            if (lower.find("error") != std::string::npos || lower.find("failure") != std::string::npos ||
                lower.find("failed") != std::string::npos) add("error");
            if (lower.find("auth") != std::string::npos || lower.find("signin") != std::string::npos ||
                lower.find("sign in") != std::string::npos || lower.find("signedin") != std::string::npos ||
                lower.find("signed out") != std::string::npos || lower.find("signedout") != std::string::npos ||
                lower.find("login") != std::string::npos || lower.find("demonware") != std::string::npos ||
                lower.find("battle.net") != std::string::npos || lower.find("bnet") != std::string::npos ||
                lower == "dw" || lower.find(" dw") != std::string::npos) add("auth");
            if (lower.find("demonware") != std::string::npos || lower.find("ondw") != std::string::npos ||
                lower == "dw" || lower.find(" dw") != std::string::npos) add("dw");
            if (lower.find("battle.net") != std::string::npos || lower.find("bnet") != std::string::npos) add("bnet");
            if (lower.find("private match") != std::string::npos || lower.find("custom game") != std::string::npos) add("private_match");
            if (lower.find("bot") != std::string::npos) add("bots");

            std::ostringstream out;
            for (size_t i = 0; i < tags.size(); ++i)
            {
                if (i) out << '|';
                out << tags[i];
            }
            return out.str();
        }

        static bool HasOfflineTag(const std::string& tags)
        {
            return tags.find("offline") != std::string::npos;
        }

        struct FrontendPassiveScanStats
        {
            size_t xrefs = 0;
            size_t nearbyCalls = 0;
            size_t offlineXrefs = 0;
            size_t rvaSlotXrefs = 0;
            size_t relativeSlotXrefs = 0;
            size_t priorityNeighborhoodXrefs = 0;
        };

        struct RuntimeFunctionRange
        {
            DWORD beginRva = 0;
            DWORD endRva = 0;
        };

        static std::vector<RuntimeFunctionRange> LoadRuntimeFunctionRanges(const ImageLayout& image)
        {
            std::vector<RuntimeFunctionRange> ranges;
            if (!image.exceptionRva || image.exceptionSize < sizeof(RUNTIME_FUNCTION) ||
                image.exceptionRva >= image.imageSize)
                return ranges;

            const size_t readableSize = (std::min<size_t>)(
                image.exceptionSize,
                static_cast<size_t>(image.imageSize - image.exceptionRva));
            const size_t count = readableSize / sizeof(RUNTIME_FUNCTION);
            if (!count || count > 4000000)
                return ranges;

            std::vector<RUNTIME_FUNCTION> entries(count);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(image.base + image.exceptionRva),
                entries.data(), count * sizeof(RUNTIME_FUNCTION), &got) || got < sizeof(RUNTIME_FUNCTION))
                return ranges;

            const size_t actual = got / sizeof(RUNTIME_FUNCTION);
            ranges.reserve(actual);
            for (size_t i = 0; i < actual; ++i)
            {
                const auto& entry = entries[i];
                if (!entry.BeginAddress || entry.EndAddress <= entry.BeginAddress ||
                    entry.EndAddress > image.imageSize)
                    continue;
                ranges.push_back({ entry.BeginAddress, entry.EndAddress });
            }

            std::sort(ranges.begin(), ranges.end(), [](const RuntimeFunctionRange& a, const RuntimeFunctionRange& b)
            {
                return a.beginRva < b.beginRva;
            });
            return ranges;
        }

        static bool FindRuntimeFunctionOwner(
            const std::vector<RuntimeFunctionRange>& ranges,
            DWORD rva,
            DWORD& beginRva,
            DWORD& endRva)
        {
            beginRva = 0;
            endRva = 0;
            if (ranges.empty())
                return false;

            auto it = std::upper_bound(ranges.begin(), ranges.end(), rva,
                [](DWORD value, const RuntimeFunctionRange& range)
                {
                    return value < range.beginRva;
                });
            if (it == ranges.begin())
                return false;
            --it;
            if (rva < it->beginRva || rva >= it->endRva)
                return false;
            beginRva = it->beginRva;
            endRva = it->endRva;
            return true;
        }

        // Protected/rewritten Beta images do not always expose a useful exception
        // directory through the mapped PE headers. Ask Windows for the same unwind
        // ownership information as a fallback. This is read-only and does not place
        // hooks or alter the game's function table.
        static bool ResolveFunctionOwner(
            const ImageLayout& image,
            const std::vector<RuntimeFunctionRange>& ranges,
            uintptr_t address,
            DWORD& beginRva,
            DWORD& endRva)
        {
            beginRva = 0;
            endRva = 0;
            if (address < image.base || address >= image.base + image.imageSize)
                return false;

            const DWORD rva = static_cast<DWORD>(address - image.base);
            if (FindRuntimeFunctionOwner(ranges, rva, beginRva, endRva))
                return true;

        #if defined(_M_X64) || defined(__x86_64__)
            DWORD64 unwindImageBase = 0;
            PRUNTIME_FUNCTION runtime = RtlLookupFunctionEntry(
                static_cast<DWORD64>(address), &unwindImageBase, nullptr);
            if (runtime && unwindImageBase)
            {
                const DWORD64 begin = unwindImageBase + runtime->BeginAddress;
                const DWORD64 end = unwindImageBase + runtime->EndAddress;
                if (begin >= image.base && end > begin && end <= image.base + image.imageSize)
                {
                    beginRva = static_cast<DWORD>(begin - image.base);
                    endRva = static_cast<DWORD>(end - image.base);
                    return true;
                }
            }
        #endif
            return false;
        }


        struct CriticalGateNeedle
        {
            const char* label = nullptr;
            const char* text = nullptr;
            std::size_t nearWindow = 0x80;
        };

        struct CriticalGateStringHit
        {
            const CriticalGateNeedle* needle = nullptr;
            uintptr_t address = 0;
            std::string section;
        };

        struct CriticalGateScanStats
        {
            std::size_t strings = 0;
            std::size_t xrefs = 0;
            std::size_t errorXrefs = 0;
            std::size_t sessionValidationXrefs = 0;
            std::size_t nearbyCalls = 0;
        };

        static const CriticalGateNeedle* CriticalGateNeedles(std::size_t& count)
        {
            // Exact Open Beta strings observed in the user's live scan.  These are
            // discovery anchors only; no Alpha/Retail addresses or state values are
            // copied into the Beta profile.
            static const CriticalGateNeedle kNeedles[] =
            {
                { "UI_ERROR_84360", "UI Error 84360", 0x40 },
                { "LOBBY_LUA", "lua/Lobby/Lobby.lua", 0x400 },
                { "CORE_FRONTEND", "core_frontend", 0x100 },
                { "ON_SESSION_START", "OnSessionStart", 0x100 },
                { "ON_SESSION_END", "OnSessionEnd", 0x100 },
                { "ON_DISCONNECT", "OnDisconnect", 0x100 },
                { "ON_DW_DISCONNECT", "OnDWDisconnect", 0x100 },
                { "SESSION_VALIDATE", "OnValidateSessionModeChangeAllowed", 0x180 },
                { "SESSION_CHANGE", "OnSessionModeChange", 0x180 },
                { "ON_PUMP", "OnPump", 0x100 },
                { "SIGNED_IN_DW", "signedInDW", 0x100 },
                { "SIGNIN_STATE", "signInState", 0x100 },
                { "CONNECTION_STATE", "connectionState", 0x100 },
                { "NETWORK_MODE", "networkMode", 0x100 },
                { "NETWORK_MODE_LOWER", "networkmode", 0x100 },
                { "NETWORK_MODE_MISMATCH", "NetworkModeMismatch", 0x100 },
                { "INVALID_LOBBY", "InvalidLobby", 0x100 },
                { "NO_MULTIPLAYER", "No Multiplayer", 0x100 },
                { "LOBBY_NETWORK_MODE", "lobbyNetworkMode", 0x100 },
                { "LOBBY_MODE", "lobbyMode", 0x100 },
                { "LOBBY_TYPE", "LobbyType", 0x100 },
                { "SESSION_STATUS", "sessionstatus", 0x100 },
                { "SESSION_GAMEMODE", "sessiongamemode", 0x100 },
                { "PREV_SESSION_VALID", "prev session is valid", 0x180 },
                { "MP_OFFLINE", "MP Offline", 0x100 },
                { "MP_OFFLINE_CODE", "MPO", 0x40 },
                { "SESSIONMODE", "SESSIONMODE", 0x100 },
                { "INIT_VERSIONS", "Initial versions set to:", 0x180 },
                { "NET_NOT_INITIALIZED", "ERROR_NETWORK_MODULE_NOT_INITIALIZED", 0x180 },
                { "NET_SSL_INIT_FAILED", "ERROR_NETWORK_MODULE_SSL_INITIALIZATION_FAILED", 0x180 },
                { "NET_SCHANNEL_INIT_FAILED", "ERROR_NETWORK_MODULE_SCHANNEL_INIT_FAIL", 0x180 },
                { "ON_COM_ERROR", "OnComError", 0x100 },
                { "COM_ERROR_IN_PROGRESS", "comErrorInProgress", 0x100 },
            };
            count = sizeof(kNeedles) / sizeof(kNeedles[0]);
            return kNeedles;
        }

        static std::string SectionNameForAddress(const ImageLayout& image, uintptr_t address)
        {
            if (address < image.base || address >= image.base + image.imageSize)
                return "?";
            const DWORD rva = static_cast<DWORD>(address - image.base);
            for (const auto& section : image.sections)
            {
                const DWORD span = section.virtualSize ? section.virtualSize : section.rawSize;
                if (rva >= section.rva && rva < section.rva + span)
                    return section.name;
            }
            return "?";
        }

        static const SectionInfo* ExecutableSectionForAddress(const ImageLayout& image, uintptr_t address)
        {
            if (address < image.base || address >= image.base + image.imageSize)
                return nullptr;
            const DWORD rva = static_cast<DWORD>(address - image.base);
            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                const DWORD span = section.virtualSize ? section.virtualSize : section.rawSize;
                if (rva >= section.rva && rva < section.rva + span)
                    return &section;
            }
            return nullptr;
        }

        static bool HeuristicFunctionOwner(
            const ImageLayout& image,
            uintptr_t address,
            DWORD& beginRva,
            DWORD& endRva)
        {
            beginRva = 0;
            endRva = 0;
            const SectionInfo* section = ExecutableSectionForAddress(image, address);
            if (!section)
                return false;

            const uintptr_t sectionBegin = image.base + section->rva;
            const uintptr_t sectionEnd = sectionBegin +
                static_cast<uintptr_t>(section->virtualSize ? section->virtualSize : section->rawSize);
            const uintptr_t windowBegin = address > sectionBegin + 0x1000 ? address - 0x1000 : sectionBegin;
            const uintptr_t windowEnd = (std::min<uintptr_t>)(sectionEnd, address + 0x2000);
            if (windowEnd <= windowBegin || windowEnd - windowBegin > 0x4000)
                return false;

            std::vector<unsigned char> bytes(static_cast<std::size_t>(windowEnd - windowBegin));
            if (!ReadBytes(windowBegin, bytes.data(), bytes.size()))
                return false;

            const std::size_t pivot = static_cast<std::size_t>(address - windowBegin);
            std::size_t start = pivot;
            bool foundStart = false;

            // Protected Beta code is missing unwind ownership in several ranges.
            // Fall back to a deliberately conservative padding/prologue heuristic.
            for (std::size_t pos = pivot; pos > 2; --pos)
            {
                const unsigned char prev = bytes[pos - 1];
                const unsigned char cur = bytes[pos];
                const bool padding = prev == 0xCC || prev == 0x90;
                const bool plausible =
                    cur == 0x40 || cur == 0x48 || cur == 0x4C ||
                    cur == 0x53 || cur == 0x55 || cur == 0x56 || cur == 0x57;
                if (padding && plausible)
                {
                    start = pos;
                    foundStart = true;
                    break;
                }

                if (pos > 4 &&
                    bytes[pos - 4] == 0xCC && bytes[pos - 3] == 0xCC &&
                    bytes[pos - 2] == 0xCC && bytes[pos - 1] == 0xCC)
                {
                    start = pos;
                    foundStart = true;
                    break;
                }
            }

            if (!foundStart)
                return false;

            std::size_t finish = (std::min<std::size_t>)(bytes.size(), pivot + 0x1800);
            bool foundEnd = false;
            for (std::size_t pos = pivot; pos + 1 < finish; ++pos)
            {
                if (bytes[pos] != 0xC3 && bytes[pos] != 0xC2)
                    continue;

                const unsigned char next = bytes[pos + 1];
                if (next == 0xCC || next == 0x90 || next == 0x00)
                {
                    finish = pos + 1;
                    foundEnd = true;
                    break;
                }
            }

            if (!foundEnd || finish <= start)
                return false;

            beginRva = static_cast<DWORD>((windowBegin + start) - image.base);
            endRva = static_cast<DWORD>((windowBegin + finish) - image.base);
            return endRva > beginRva;
        }

        static std::string HexWindow(
            uintptr_t address,
            std::size_t before = 0x30,
            std::size_t after = 0x60)
        {
            const uintptr_t start = address > before ? address - before : address;
            const std::size_t wanted = before + after;
            std::vector<unsigned char> bytes(wanted);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(start),
                bytes.data(), bytes.size(), &got) || got == 0)
                return {};

            std::ostringstream out;
            for (std::size_t i = 0; i < got; ++i)
            {
                if (i) out << ' ';
                out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned>(bytes[i]);
            }
            return out.str();
        }

        static std::vector<CriticalGateStringHit> FindCriticalGateStringsAllSections(
            const ImageLayout& image,
            const char* phase,
            bool resetOutputFiles)
        {
            std::vector<CriticalGateStringHit> hits;
            std::size_t needleCount = 0;
            const CriticalGateNeedle* needles = CriticalGateNeedles(needleCount);
            if (!needleCount)
                return hits;

            const std::string outPath =
                storage_paths::PathA("logs\\t9_beta\\research\\critical_gate_strings.csv");
            const bool newFile = resetOutputFiles ||
                GetFileAttributesA(outPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            std::ofstream out(outPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            if (out && newFile)
                out << "phase,label,string_rva,section,text\n";

            const uintptr_t imageEnd = image.base + image.imageSize;
            uintptr_t cursor = image.base;
            constexpr std::size_t kChunk = 4ull * 1024ull * 1024ull;

            while (cursor < imageEnd)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                    break;

                const uintptr_t regionBegin =
                    (std::max<uintptr_t>)(cursor, reinterpret_cast<uintptr_t>(mbi.BaseAddress));
                const uintptr_t rawRegionEnd =
                    reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                const uintptr_t regionEnd = (std::min<uintptr_t>)(imageEnd, rawRegionEnd);
                if (regionEnd <= regionBegin)
                    break;

                const DWORD p = mbi.Protect & 0xFFu;
                const bool readable =
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect & PAGE_GUARD) &&
                    !(mbi.Protect & PAGE_NOACCESS) &&
                    p != PAGE_NOACCESS;

                if (readable)
                {
                    uintptr_t part = regionBegin;
                    while (part < regionEnd)
                    {
                        const std::size_t wanted = static_cast<std::size_t>(
                            (std::min<uintptr_t>)(regionEnd - part, kChunk));
                        std::vector<unsigned char> bytes(wanted);
                        SIZE_T got = 0;
                        if (ReadProcessMemory(GetCurrentProcess(),
                            reinterpret_cast<const void*>(part),
                            bytes.data(), bytes.size(), &got) && got)
                        {
                            for (std::size_t i = 0; i < got; ++i)
                            {
                                const char first = static_cast<char>(bytes[i]);
                                for (std::size_t n = 0; n < needleCount; ++n)
                                {
                                    const char* target = needles[n].text;
                                    if (!target || !*target || first != target[0])
                                        continue;
                                    const std::size_t len = std::strlen(target);
                                    if (i + len > got || std::memcmp(bytes.data() + i, target, len) != 0)
                                        continue;

                                    const uintptr_t at = part + i;
                                    bool duplicate = false;
                                    for (const auto& existing : hits)
                                    {
                                        if (existing.needle == &needles[n] && existing.address == at)
                                        {
                                            duplicate = true;
                                            break;
                                        }
                                    }
                                    if (duplicate)
                                        continue;

                                    CriticalGateStringHit hit{};
                                    hit.needle = &needles[n];
                                    hit.address = at;
                                    hit.section = SectionNameForAddress(image, at);
                                    hits.push_back(hit);

                                    if (out)
                                    {
                                        out << (phase ? phase : "unknown") << ','
                                            << needles[n].label << ",0x"
                                            << std::hex << std::uppercase << (at - image.base) << ','
                                            << hit.section << ",\"" << JsonEscape(target) << "\"\n";
                                    }

                                    if (std::strcmp(needles[n].label, "UI_ERROR_84360") == 0)
                                    {
                                        std::printf("[BETA-ERROR] exact UI Error 84360 string RVA=0x%llX section=%s\n",
                                            static_cast<unsigned long long>(at - image.base),
                                            hit.section.c_str());
                                    }
                                    else
                                    {
                                        std::printf("[BETA-GATE] exact string %-22s RVA=0x%llX section=%s text=%s\n",
                                            needles[n].label,
                                            static_cast<unsigned long long>(at - image.base),
                                            hit.section.c_str(), target);
                                    }
                                    std::fflush(stdout);
                                }
                            }
                        }
                        part += wanted;
                    }
                }

                cursor = regionEnd;
            }

            RuntimeLog("critical_gate_strings phase=%s found=%zu",
                phase ? phase : "unknown", hits.size());
            return hits;
        }

        static CriticalGateScanStats ScanCriticalGateXrefs(
            const ImageLayout& image,
            const std::vector<CriticalGateStringHit>& stringHits,
            const char* phase,
            bool resetOutputFiles)
        {
            CriticalGateScanStats stats{};
            stats.strings = stringHits.size();
            if (stringHits.empty())
                return stats;

            const auto runtimeFunctions = LoadRuntimeFunctionRanges(image);
            const std::string xrefPath =
                storage_paths::PathA("logs\\t9_beta\\research\\critical_gate_xrefs.csv");
            const std::string callPath =
                storage_paths::PathA("logs\\t9_beta\\research\\critical_gate_calls.csv");
            const bool xrefNew = resetOutputFiles ||
                GetFileAttributesA(xrefPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            const bool callNew = resetOutputFiles ||
                GetFileAttributesA(callPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            std::ofstream xrefs(xrefPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            std::ofstream calls(callPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            if (xrefs && xrefNew)
            {
                xrefs << "phase,label,string_rva,instruction_rva,section,reference_kind,target_rva,"
                         "delta,owner_kind,owner_begin_rva,owner_end_rva,bytes\n";
            }
            if (calls && callNew)
            {
                calls << "phase,label,xref_rva,call_rva,call_target_rva,target_owner_rva\n";
            }

            struct SlotTarget
            {
                std::size_t hitIndex = 0;
                const char* storageKind = nullptr;
            };
            std::unordered_map<uintptr_t, SlotTarget> slots;
            std::unordered_map<DWORD, std::size_t> hitByRva;
            std::unordered_map<uintptr_t, std::size_t> hitByAddress;
            uintptr_t lowestHit = static_cast<uintptr_t>(~static_cast<uintptr_t>(0));
            uintptr_t highestHit = 0;
            std::size_t largestNearWindow = 0;
            for (std::size_t h = 0; h < stringHits.size(); ++h)
            {
                hitByRva.emplace(static_cast<DWORD>(stringHits[h].address - image.base), h);
                hitByAddress.emplace(stringHits[h].address, h);
                lowestHit = (std::min<uintptr_t>)(lowestHit, stringHits[h].address);
                highestHit = (std::max<uintptr_t>)(highestHit, stringHits[h].address);
                if (stringHits[h].needle)
                    largestNearWindow = (std::max<std::size_t>)(largestNearWindow, stringHits[h].needle->nearWindow);
            }

            // Small exact-target slot pass.  This intentionally does not scan the
            // thousands of generic frontend strings, so it finishes early enough to
            // produce useful data before the long passive graph completes.
            for (const auto& section : image.sections)
            {
                if (section.characteristics & IMAGE_SCN_MEM_EXECUTE)
                    continue;

                const std::size_t size = static_cast<std::size_t>((std::min<DWORD>)(
                    section.virtualSize ? section.virtualSize : section.rawSize,
                    image.imageSize - section.rva));
                if (size < sizeof(DWORD) || size > 512ull * 1024ull * 1024ull)
                    continue;

                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(image.base + section.rva),
                    bytes.data(), bytes.size(), &got) || got < sizeof(DWORD))
                    continue;

                for (std::size_t i = 0; i + sizeof(DWORD) <= got; i += sizeof(DWORD))
                {
                    const uintptr_t slotAddress = image.base + section.rva + i;

                    DWORD rva32 = 0;
                    std::memcpy(&rva32, bytes.data() + i, sizeof(rva32));
                    const auto rvaIt = hitByRva.find(rva32);
                    if (rvaIt != hitByRva.end())
                        slots.emplace(slotAddress, SlotTarget{ rvaIt->second, "rva32" });

                    const int32_t rel = static_cast<int32_t>(rva32);
                    const uintptr_t relTarget = static_cast<uintptr_t>(
                        static_cast<intptr_t>(slotAddress + sizeof(DWORD)) +
                        static_cast<intptr_t>(rel));
                    const auto relIt = hitByAddress.find(relTarget);
                    if (relIt != hitByAddress.end())
                        slots.emplace(slotAddress, SlotTarget{ relIt->second, "rel32" });
                }

                for (std::size_t i = 0; i + sizeof(uintptr_t) <= got; i += sizeof(uintptr_t))
                {
                    uintptr_t value = 0;
                    std::memcpy(&value, bytes.data() + i, sizeof(value));
                    const auto vaIt = hitByAddress.find(value);
                    if (vaIt != hitByAddress.end())
                        slots.emplace(image.base + section.rva + i, SlotTarget{ vaIt->second, "va64" });
                }
            }

            std::size_t printed = 0;
            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;

                const std::size_t size = static_cast<std::size_t>((std::min<DWORD>)(
                    section.virtualSize ? section.virtualSize : section.rawSize,
                    image.imageSize - section.rva));
                if (size < 6)
                    continue;

                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(image.base + section.rva),
                    bytes.data(), bytes.size(), &got) || got < 6)
                    continue;

                for (std::size_t i = 0; i + 6 <= got; ++i)
                {
                    const uintptr_t instruction = image.base + section.rva + i;
                    std::size_t hitIndex = static_cast<std::size_t>(-1);
                    const char* referenceKind = nullptr;
                    uintptr_t resolvedTarget = 0;
                    intptr_t delta = 0;

                    std::size_t length = 0;
                    std::size_t dispOffset = 0;
                    if (i + 7 <= got && bytes[i] >= 0x40 && bytes[i] <= 0x4F &&
                        (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B) &&
                        (bytes[i + 2] & 0xC7) == 0x05)
                    {
                        length = 7;
                        dispOffset = 3;
                    }
                    else if ((bytes[i] == 0x8D || bytes[i] == 0x8B) &&
                        (bytes[i + 1] & 0xC7) == 0x05)
                    {
                        length = 6;
                        dispOffset = 2;
                    }
                    else if (bytes[i] == 0xFF && (bytes[i + 1] == 0x15 || bytes[i + 1] == 0x25))
                    {
                        length = 6;
                        dispOffset = 2;
                    }

                    if (length && i + length <= got)
                    {
                        int32_t disp = 0;
                        std::memcpy(&disp, bytes.data() + i + dispOffset, sizeof(disp));
                        resolvedTarget = static_cast<uintptr_t>(
                            static_cast<intptr_t>(instruction + length) +
                            static_cast<intptr_t>(disp));

                        const auto slot = slots.find(resolvedTarget);
                        if (slot != slots.end())
                        {
                            hitIndex = slot->second.hitIndex;
                            referenceKind = slot->second.storageKind;
                            resolvedTarget = stringHits[hitIndex].address;
                            delta = 0;
                        }
                        else if (resolvedTarget + largestNearWindow >= lowestHit &&
                                 resolvedTarget <= highestHit + largestNearWindow)
                        {
                            intptr_t bestAbs = static_cast<intptr_t>(0x7FFFFFFF);
                            for (std::size_t h = 0; h < stringHits.size(); ++h)
                            {
                                const intptr_t d = static_cast<intptr_t>(resolvedTarget) -
                                    static_cast<intptr_t>(stringHits[h].address);
                                const intptr_t absd = d < 0 ? -d : d;
                                const std::size_t allowed =
                                    stringHits[h].needle ? stringHits[h].needle->nearWindow : 0x80;
                                if (static_cast<std::size_t>(absd) <= allowed && absd < bestAbs)
                                {
                                    bestAbs = absd;
                                    hitIndex = h;
                                    delta = d;
                                }
                            }
                            if (hitIndex != static_cast<std::size_t>(-1))
                                referenceKind = delta == 0 ? "rip_direct" : "rip_near";
                        }
                    }

                    // Keep this pass fast: exact image-relative constants are
                    // already captured through data slots above.  Do not brute-force
                    // every byte in the very large protected .text range.

                    if (hitIndex == static_cast<std::size_t>(-1) || !referenceKind)
                        continue;

                    const auto& hit = stringHits[hitIndex];
                    DWORD ownerBegin = 0, ownerEnd = 0;
                    const char* ownerKind = "none";
                    if (ResolveFunctionOwner(image, runtimeFunctions, instruction, ownerBegin, ownerEnd))
                    {
                        ownerKind = "unwind";
                    }
                    else if (HeuristicFunctionOwner(image, instruction, ownerBegin, ownerEnd))
                    {
                        ownerKind = "heuristic";
                    }

                    ++stats.xrefs;
                    const bool uiError =
                        hit.needle && std::strcmp(hit.needle->label, "UI_ERROR_84360") == 0;
                    const bool sessionValidation =
                        hit.needle && std::strcmp(hit.needle->label, "SESSION_VALIDATE") == 0;
                    if (uiError) ++stats.errorXrefs;
                    if (sessionValidation) ++stats.sessionValidationXrefs;

                    const std::string bytesAround = HexWindow(instruction);
                    if (xrefs)
                    {
                        xrefs << (phase ? phase : "unknown") << ','
                            << (hit.needle ? hit.needle->label : "?") << ",0x"
                            << std::hex << std::uppercase << (hit.address - image.base)
                            << ",0x" << (instruction - image.base) << ','
                            << section.name << ',' << referenceKind << ",0x"
                            << (resolvedTarget - image.base) << ',' << std::dec
                            << static_cast<long long>(delta) << ',' << ownerKind << ",0x"
                            << std::hex << ownerBegin << ",0x" << ownerEnd << ",\""
                            << JsonEscape(bytesAround) << "\"\n";
                    }

                    if (uiError || sessionValidation || printed < 48)
                    {
                        std::printf("%s %-22s XREF=0x%llX via=%s target=0x%llX delta=%lld owner=%s/0x%X\n",
                            uiError ? "[BETA-ERROR]" : "[BETA-GATE]",
                            hit.needle ? hit.needle->label : "?",
                            static_cast<unsigned long long>(instruction - image.base),
                            referenceKind,
                            static_cast<unsigned long long>(resolvedTarget - image.base),
                            static_cast<long long>(delta), ownerKind, ownerBegin);
                        std::fflush(stdout);
                        ++printed;
                    }

                    // Record direct calls around each critical xref.  This does not
                    // detour or execute anything; it only gives the next run a small
                    // candidate call graph around the exact gate/error reference.
                    const std::size_t localBegin = i > 0x100 ? i - 0x100 : 0;
                    const std::size_t localEnd = (std::min<std::size_t>)(got, i + 0x180);
                    for (std::size_t j = localBegin; j + 5 <= localEnd; ++j)
                    {
                        if (bytes[j] != 0xE8)
                            continue;
                        int32_t rel = 0;
                        std::memcpy(&rel, bytes.data() + j + 1, sizeof(rel));
                        const uintptr_t callAt = image.base + section.rva + j;
                        const uintptr_t target = static_cast<uintptr_t>(
                            static_cast<intptr_t>(callAt + 5) + static_cast<intptr_t>(rel));
                        if (target < image.base || target >= image.base + image.imageSize)
                            continue;

                        DWORD targetOwner = 0, targetEnd = 0;
                        ResolveFunctionOwner(image, runtimeFunctions, target, targetOwner, targetEnd);
                        if (calls)
                        {
                            calls << (phase ? phase : "unknown") << ','
                                << (hit.needle ? hit.needle->label : "?") << ",0x"
                                << std::hex << std::uppercase << (instruction - image.base)
                                << ",0x" << (callAt - image.base) << ",0x"
                                << (target - image.base) << ",0x" << targetOwner << "\n";
                        }
                        ++stats.nearbyCalls;
                    }
                }
            }

            RuntimeLog(
                "critical_gate_xrefs phase=%s strings=%zu xrefs=%zu error84360=%zu session_validate=%zu calls=%zu",
                phase ? phase : "unknown", stats.strings, stats.xrefs,
                stats.errorXrefs, stats.sessionValidationXrefs, stats.nearbyCalls);
            std::printf(
                "[BETA-GATE] exact gate scan complete: strings=%zu xrefs=%zu UI84360=%zu sessionValidate=%zu calls=%zu\n",
                stats.strings, stats.xrefs, stats.errorXrefs,
                stats.sessionValidationXrefs, stats.nearbyCalls);
            std::fflush(stdout);
            return stats;
        }

        static CriticalGateScanStats RunCriticalGateScan(
            const ImageLayout& image,
            const char* phase,
            bool resetOutputFiles)
        {
            const auto hits = FindCriticalGateStringsAllSections(
                image, phase, resetOutputFiles);
            return ScanCriticalGateXrefs(image, hits, phase, resetOutputFiles);
        }

        struct StackPointerHit
        {
            DWORD threadId = 0;
            DWORD depth = 0;
            DWORD returnRva = 0;
            DWORD ownerBeginRva = 0;
            DWORD ownerEndRva = 0;
        };

        struct StackSnapshot
        {
            std::vector<StackPointerHit> hits;
            size_t threadsSeen = 0;
            size_t threadsRead = 0;
            size_t bytesRead = 0;
        };

        static SRWLOCK g_stackSnapshotLock = SRWLOCK_INIT;
        static StackSnapshot g_idleStackBaseline;
        static std::vector<DWORD> g_idleNoiseOwners;
        static bool g_idleStackBaselineReady = false;

        using NtQueryInformationThreadFn = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        struct BetaClientId
        {
            HANDLE process = nullptr;
            HANDLE thread = nullptr;
        };

        struct BetaThreadBasicInformation
        {
            LONG exitStatus = 0;
            PVOID tebBaseAddress = nullptr;
            BetaClientId clientId{};
            ULONG_PTR affinityMask = 0;
            LONG priority = 0;
            LONG basePriority = 0;
        };

        static NtQueryInformationThreadFn ResolveNtQueryInformationThread()
        {
            static NtQueryInformationThreadFn fn = []() -> NtQueryInformationThreadFn
            {
                HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                if (!ntdll) ntdll = LoadLibraryW(L"ntdll.dll");
                return ntdll ? reinterpret_cast<NtQueryInformationThreadFn>(
                    GetProcAddress(ntdll, "NtQueryInformationThread")) : nullptr;
            }();
            return fn;
        }

        static bool ReadThreadStackBounds(HANDLE thread, uintptr_t& stackBase, uintptr_t& stackLimit)
        {
            stackBase = 0;
            stackLimit = 0;
            const auto query = ResolveNtQueryInformationThread();
            if (!query || !thread)
                return false;

            BetaThreadBasicInformation info{};
            const LONG status = query(thread, 0, &info, sizeof(info), nullptr);
            if (status < 0 || !info.tebBaseAddress)
                return false;

            const uintptr_t teb = reinterpret_cast<uintptr_t>(info.tebBaseAddress);
            if (!ReadBytes(teb + sizeof(uintptr_t), &stackBase, sizeof(stackBase)) ||
                !ReadBytes(teb + sizeof(uintptr_t) * 2, &stackLimit, sizeof(stackLimit)))
                return false;
            return stackBase > stackLimit && stackBase - stackLimit <= 64ull * 1024ull * 1024ull;
        }

        static StackSnapshot CaptureGameThreadStackSnapshot(const ImageLayout& image)
        {
            StackSnapshot snapshot{};
            const auto runtimeFunctions = LoadRuntimeFunctionRanges(image);
            if (runtimeFunctions.empty())
                return snapshot;

            HANDLE toolhelp = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (toolhelp == INVALID_HANDLE_VALUE)
                return snapshot;

            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);
            const DWORD processId = GetCurrentProcessId();
            const DWORD ownThreadId = GetCurrentThreadId();
            constexpr uintptr_t kStackWindow = 0x30000; // top 192 KiB per game thread
            constexpr size_t kMaxHitsPerThread = 4096;

            if (Thread32First(toolhelp, &entry))
            {
                do
                {
                    if (entry.th32OwnerProcessID != processId || entry.th32ThreadID == ownThreadId)
                        continue;
                    ++snapshot.threadsSeen;

                    HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                        FALSE, entry.th32ThreadID);
                    if (!thread)
                        continue;

                    uintptr_t stackBase = 0, stackLimit = 0;
                    const bool boundsOk = ReadThreadStackBounds(thread, stackBase, stackLimit);
                    CloseHandle(thread);
                    if (!boundsOk)
                        continue;
                    ++snapshot.threadsRead;

                    const uintptr_t windowBegin = (std::max<uintptr_t>)(
                        stackLimit, stackBase > kStackWindow ? stackBase - kStackWindow : stackLimit);
                    uintptr_t cursor = windowBegin;
                    size_t threadHits = 0;

                    while (cursor < stackBase && threadHits < kMaxHitsPerThread)
                    {
                        MEMORY_BASIC_INFORMATION mbi{};
                        if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) || !mbi.RegionSize)
                            break;
                        const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                        const uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
                        const uintptr_t regionBegin = (std::max<uintptr_t>)(cursor, regionBase);
                        const uintptr_t regionEnd = (std::min<uintptr_t>)(stackBase, regionEndRaw);
                        if (regionEnd <= regionBegin)
                            break;

                        const DWORD protect = mbi.Protect & 0xFFu;
                        const bool readable = mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
                            !(mbi.Protect & PAGE_NOACCESS) && protect != PAGE_NOACCESS;
                        if (readable)
                        {
                            std::vector<unsigned char> bytes(static_cast<size_t>(regionEnd - regionBegin));
                            SIZE_T got = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(regionBegin),
                                bytes.data(), bytes.size(), &got) && got >= sizeof(uintptr_t))
                            {
                                snapshot.bytesRead += got;
                                size_t offset = static_cast<size_t>((sizeof(uintptr_t) - (regionBegin & (sizeof(uintptr_t) - 1))) &
                                    (sizeof(uintptr_t) - 1));
                                for (; offset + sizeof(uintptr_t) <= got && threadHits < kMaxHitsPerThread;
                                    offset += sizeof(uintptr_t))
                                {
                                    uintptr_t candidate = 0;
                                    memcpy(&candidate, bytes.data() + offset, sizeof(candidate));
                                    if (candidate < image.base || candidate >= image.base + image.imageSize)
                                        continue;

                                    const DWORD candidateRva = static_cast<DWORD>(candidate - image.base);
                                    DWORD ownerBegin = 0, ownerEnd = 0;
                                    if (!FindRuntimeFunctionOwner(runtimeFunctions, candidateRva, ownerBegin, ownerEnd))
                                        continue;

                                    const uintptr_t slotAddress = regionBegin + offset;
                                    const uintptr_t depth64 = stackBase > slotAddress ? stackBase - slotAddress : 0;
                                    if (!depth64 || depth64 > 0xFFFFFFFFull)
                                        continue;

                                    snapshot.hits.push_back({ entry.th32ThreadID, static_cast<DWORD>(depth64),
                                        candidateRva, ownerBegin, ownerEnd });
                                    ++threadHits;
                                }
                            }
                        }
                        cursor = regionEndRaw > cursor ? regionEndRaw : cursor + 0x1000;
                    }
                } while (Thread32Next(toolhelp, &entry));
            }

            CloseHandle(toolhelp);
            return snapshot;
        }

        static std::vector<StackPointerHit> DiffStackSnapshots(
            const StackSnapshot& before, const StackSnapshot& after)
        {
            std::unordered_map<unsigned long long, DWORD> previous;
            previous.reserve(before.hits.size() * 2 + 1);
            for (const auto& hit : before.hits)
            {
                const unsigned long long key = (static_cast<unsigned long long>(hit.threadId) << 32) |
                    static_cast<unsigned long long>(hit.depth);
                previous[key] = hit.returnRva;
            }

            std::vector<StackPointerHit> changed;
            changed.reserve(after.hits.size() / 8 + 64);
            for (const auto& hit : after.hits)
            {
                const unsigned long long key = (static_cast<unsigned long long>(hit.threadId) << 32) |
                    static_cast<unsigned long long>(hit.depth);
                const auto old = previous.find(key);
                if (old == previous.end() || old->second != hit.returnRva)
                    changed.push_back(hit);
            }
            return changed;
        }

        static bool ContainsOwner(const std::vector<DWORD>& owners, DWORD owner)
        {
            return std::find(owners.begin(), owners.end(), owner) != owners.end();
        }

        static std::vector<DWORD> BuildNoiseOwnerList(
            const StackSnapshot& before, const StackSnapshot& after)
        {
            const auto changed = DiffStackSnapshots(before, after);
            std::vector<DWORD> owners;
            owners.reserve(changed.size());
            for (const auto& hit : changed)
                if (hit.ownerBeginRva && !ContainsOwner(owners, hit.ownerBeginRva))
                    owners.push_back(hit.ownerBeginRva);
            std::sort(owners.begin(), owners.end());
            return owners;
        }

        static DWORD WINAPI IdleStackBaselineThread(LPVOID)
        {
            ImageLayout image{};
            if (!ReadImageLayout(GetModuleHandleW(nullptr), image))
            {
                g_stackBaselineThreadStarted.store(false, std::memory_order_release);
                return 1;
            }

            RuntimeLog("stack_baseline=begin mode=no_suspend top_bytes_per_thread=0x30000");
            const StackSnapshot first = CaptureGameThreadStackSnapshot(image);
            Sleep(120);
            const StackSnapshot second = CaptureGameThreadStackSnapshot(image);
            const auto noise = BuildNoiseOwnerList(first, second);

            AcquireSRWLockExclusive(&g_stackSnapshotLock);
            g_idleStackBaseline = second;
            g_idleNoiseOwners = noise;
            g_idleStackBaselineReady = !second.hits.empty();
            ReleaseSRWLockExclusive(&g_stackSnapshotLock);

            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta" / L"research");
            std::ofstream out(storage_paths::PathA("logs\\t9_beta\\research\\click_stack_idle_noise.csv"), std::ios::trunc);
            if (out)
            {
                out << "owner_function_rva\n";
                for (DWORD owner : noise)
                    out << "0x" << std::hex << std::uppercase << owner << "\n";
            }

            RuntimeLog("stack_baseline=ready hits=%zu threads=%zu/%zu bytes=%zu idle_noise_owners=%zu",
                second.hits.size(), second.threadsRead, second.threadsSeen, second.bytesRead, noise.size());
            return 0;
        }

        static void StartIdleStackBaselineAsync()
        {
            if (g_stackBaselineThreadStarted.exchange(true, std::memory_order_acq_rel))
                return;
            HANDLE thread = CreateThread(nullptr, 0, &IdleStackBaselineThread, nullptr, 0, nullptr);
            if (!thread)
            {
                g_stackBaselineThreadStarted.store(false, std::memory_order_release);
                RuntimeLog("stack_baseline=create_thread_failed error=%lu",
                    static_cast<unsigned long>(GetLastError()));
                return;
            }
            CloseHandle(thread);
        }

        struct StackOwnerRank
        {
            DWORD ownerEndRva = 0;
            DWORD sampleReturnRva = 0;
            size_t changedSlots = 0;
            std::vector<DWORD> threadIds;
            bool idleNoise = false;
        };

        static void WriteClickStackSample(
            const char* sampleName,
            const StackSnapshot& baseline,
            const std::vector<DWORD>& idleNoise,
            const StackSnapshot& sample,
            bool resetFiles)
        {
            const auto changed = DiffStackSnapshots(baseline, sample);
            std::unordered_map<DWORD, StackOwnerRank> ranks;
            ranks.reserve(changed.size() / 2 + 1);

            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta" / L"research");
            const std::string diffPath = storage_paths::PathA("logs\\t9_beta\\research\\click_stack_diff.csv");
            const std::string rankPath = storage_paths::PathA("logs\\t9_beta\\research\\click_stack_owner_rank.csv");
            std::ofstream diff(diffPath, resetFiles ? std::ios::trunc : std::ios::app);
            if (diff && resetFiles)
                diff << "sample,thread_id,stack_depth,return_rva,owner_function_rva,owner_end_rva,idle_noise\n";

            for (const auto& hit : changed)
            {
                const bool noise = ContainsOwner(idleNoise, hit.ownerBeginRva);
                auto& rank = ranks[hit.ownerBeginRva];
                rank.ownerEndRva = hit.ownerEndRva;
                rank.sampleReturnRva = hit.returnRva;
                ++rank.changedSlots;
                rank.idleNoise = noise;
                if (std::find(rank.threadIds.begin(), rank.threadIds.end(), hit.threadId) == rank.threadIds.end())
                    rank.threadIds.push_back(hit.threadId);

                if (diff)
                    diff << (sampleName ? sampleName : "click") << ',' << std::dec << hit.threadId
                        << ",0x" << std::hex << std::uppercase << hit.depth
                        << ",0x" << hit.returnRva << ",0x" << hit.ownerBeginRva
                        << ",0x" << hit.ownerEndRva << ',' << (noise ? 1 : 0) << "\n";
            }

            std::vector<std::pair<DWORD, StackOwnerRank>> ordered(ranks.begin(), ranks.end());
            std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b)
            {
                if (a.second.idleNoise != b.second.idleNoise)
                    return !a.second.idleNoise;
                if (a.second.changedSlots != b.second.changedSlots)
                    return a.second.changedSlots > b.second.changedSlots;
                return a.first < b.first;
            });

            std::ofstream rankOut(rankPath, resetFiles ? std::ios::trunc : std::ios::app);
            if (rankOut && resetFiles)
                rankOut << "sample,owner_function_rva,owner_end_rva,changed_slots,thread_count,sample_return_rva,idle_noise\n";
            size_t emitted = 0;
            for (const auto& item : ordered)
            {
                if (emitted >= 256) break;
                if (rankOut)
                    rankOut << (sampleName ? sampleName : "click") << ",0x" << std::hex << std::uppercase
                        << item.first << ",0x" << item.second.ownerEndRva << ',' << std::dec
                        << item.second.changedSlots << ',' << item.second.threadIds.size() << ",0x"
                        << std::hex << std::uppercase << item.second.sampleReturnRva << ','
                        << (item.second.idleNoise ? 1 : 0) << "\n";
                if (!item.second.idleNoise && emitted < 24)
                {
                    std::printf("[BETA-CLICK-STACK] sample=%s owner=0x%X changed=%zu threads=%zu ret=0x%X\n",
                        sampleName ? sampleName : "click", item.first, item.second.changedSlots,
                        item.second.threadIds.size(), item.second.sampleReturnRva);
                }
                ++emitted;
            }
            std::fflush(stdout);
            RuntimeLog("click_stack sample=%s hits=%zu changed=%zu owners=%zu threads=%zu/%zu bytes=%zu",
                sampleName ? sampleName : "click", sample.hits.size(), changed.size(), ranks.size(),
                sample.threadsRead, sample.threadsSeen, sample.bytesRead);
        }

        static DWORD WINAPI ClickStackSamplerThread(LPVOID)
        {
            ImageLayout image{};
            if (!ReadImageLayout(GetModuleHandleW(nullptr), image))
                return 1;

            StackSnapshot baseline{};
            std::vector<DWORD> idleNoise;
            AcquireSRWLockShared(&g_stackSnapshotLock);
            const bool baselineReady = g_idleStackBaselineReady;
            if (baselineReady)
            {
                baseline = g_idleStackBaseline;
                idleNoise = g_idleNoiseOwners;
            }
            ReleaseSRWLockShared(&g_stackSnapshotLock);

            if (!baselineReady)
            {
                RuntimeLog("click_stack=no_idle_baseline action=capture_immediate_reference");
                baseline = CaptureGameThreadStackSnapshot(image);
            }

            const StackSnapshot sample0 = CaptureGameThreadStackSnapshot(image);
            WriteClickStackSample("confirm_0", baseline, idleNoise, sample0, true);
            Sleep(8);
            const StackSnapshot sample1 = CaptureGameThreadStackSnapshot(image);
            WriteClickStackSample("confirm_1", baseline, idleNoise, sample1, false);
            Sleep(24);
            const StackSnapshot sample2 = CaptureGameThreadStackSnapshot(image);
            WriteClickStackSample("confirm_2", baseline, idleNoise, sample2, false);
            RuntimeLog("click_stack=complete samples=3 baseline_ready=%u idle_noise_owners=%zu",
                baselineReady ? 1u : 0u, idleNoise.size());
            return 0;
        }

        static void StartClickStackSamplingAsync()
        {
            if (g_clickStackSamplerStarted.exchange(true, std::memory_order_acq_rel))
                return;
            HANDLE thread = CreateThread(nullptr, 0, &ClickStackSamplerThread, nullptr, 0, nullptr);
            if (!thread)
            {
                g_clickStackSamplerStarted.store(false, std::memory_order_release);
                RuntimeLog("click_stack=create_thread_failed error=%lu",
                    static_cast<unsigned long>(GetLastError()));
                return;
            }
            CloseHandle(thread);
            RuntimeLog("click_stack=scheduled mode=no_suspend_no_game_hooks");
        }

        struct SelectedStringRange
        {
            uintptr_t begin = 0;
            uintptr_t end = 0;
            size_t index = 0;
        };

        static std::vector<SelectedStringRange> BuildSelectedStringRanges(
            const std::vector<InterestingString>& selected)
        {
            std::vector<SelectedStringRange> ranges;
            ranges.reserve(selected.size());
            for (size_t i = 0; i < selected.size(); ++i)
            {
                if (selected[i].value.empty())
                    continue;
                ranges.push_back({ selected[i].address,
                    selected[i].address + selected[i].value.size(), i });
            }
            std::sort(ranges.begin(), ranges.end(), [](const SelectedStringRange& a, const SelectedStringRange& b)
            {
                return a.begin < b.begin;
            });
            return ranges;
        }

        static bool FindSelectedStringIndex(
            const std::vector<SelectedStringRange>& ranges,
            uintptr_t address,
            size_t& index)
        {
            if (ranges.empty())
                return false;
            auto it = std::upper_bound(ranges.begin(), ranges.end(), address,
                [](uintptr_t value, const SelectedStringRange& range)
                {
                    return value < range.begin;
                });
            if (it == ranges.begin())
                return false;
            --it;
            if (address < it->begin || address >= it->end)
                return false;
            index = it->index;
            return true;
        }

        static bool IsPriorityFrontendString(const std::string& text)
        {
            const std::string lower = LowerAscii(text);
            static const char* terms[] = {
                "mp offline", "mp arena offline", "zm offline", "dedicated lan server",
                "startmultiplayer", "no multiplayer", "networkmodemismatch", "destnetworkmode",
                "lobbynetworkmode", "networkmode", "sessionmode", "runlobbytest", "private sessions",
                "new private p2p lobby requested", "onsessionmodechange",
                "onvalidatesessionmodechangeallowed", "isgamelobbyactive", "sessionactive",
                "sessionstatus", "lobby_change", "platformappearoffline",
                "ondwdisconnect", "onlobbyonlineupdate", "online services", "signedout",
                "signinchanged", "server_disconnected", "exe/disconnected", "disconnect",
                "connection_state_disconnected", "connection_state_connecting", "authenticationservice",
                "bnet", "battle.net", "fence", "frontend initialization", "frontend_init"
            };
            for (const char* term : terms)
                if (lower.find(term) != std::string::npos)
                    return true;
            return false;
        }

        static size_t DumpPriorityFrontendContexts(
            const ImageLayout& image,
            const std::vector<InterestingString>& selected,
            const char* phase,
            bool resetOutputFiles)
        {
            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta" / L"research");
            const std::string path = storage_paths::PathA("logs\\t9_beta\\research\\frontend_priority_context_strings.csv");
            const bool newFile = resetOutputFiles || GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES;
            std::ofstream out(path, resetOutputFiles ? std::ios::trunc : std::ios::app);
            if (!out)
                return 0;
            if (newFile)
                out << "phase,anchor_rva,anchor_tags,anchor_text,context_rva,delta,length,text\n";

            size_t rows = 0;
            constexpr size_t kBefore = 0x1800;
            constexpr size_t kAfter = 0x1800;
            constexpr size_t kMaxRowsPerAnchor = 320;

            for (const auto& anchor : selected)
            {
                if (!IsPriorityFrontendString(anchor.value) ||
                    anchor.address < image.base || anchor.address >= image.base + image.imageSize)
                    continue;

                const uintptr_t imageEnd = image.base + image.imageSize;
                const uintptr_t begin = anchor.address > image.base + kBefore ? anchor.address - kBefore : image.base;
                const uintptr_t end = (std::min<uintptr_t>)(imageEnd, anchor.address + anchor.value.size() + kAfter);
                if (end <= begin)
                    continue;

                std::vector<unsigned char> bytes(static_cast<size_t>(end - begin));
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(begin),
                    bytes.data(), bytes.size(), &got) || got < 4)
                    continue;

                size_t anchorRows = 0;
                for (size_t i = 0; i < got && anchorRows < kMaxRowsPerAnchor;)
                {
                    const size_t start = i;
                    while (i < got && bytes[i] >= 0x20 && bytes[i] <= 0x7E)
                        ++i;
                    const size_t len = i - start;
                    if (len >= 4)
                    {
                        const size_t bounded = (std::min<size_t>)(len, 768);
                        const uintptr_t textAddress = begin + start;
                        const intptr_t delta = static_cast<intptr_t>(textAddress) - static_cast<intptr_t>(anchor.address);
                        const std::string text(reinterpret_cast<const char*>(bytes.data() + start), bounded);
                        out << (phase ? phase : "unknown") << ",0x" << std::hex << std::uppercase
                            << (anchor.address - image.base) << ",\"" << JsonEscape(FrontendKeywordTags(anchor.value))
                            << "\",\"" << JsonEscape(anchor.value) << "\",0x" << (textAddress - image.base)
                            << ',' << std::dec << delta << ',' << len << ",\"" << JsonEscape(text) << "\"\n";
                        ++rows;
                        ++anchorRows;
                    }
                    if (i == start)
                        ++i;
                    else
                        while (i < got && !(bytes[i] >= 0x20 && bytes[i] <= 0x7E))
                            ++i;
                }
            }

            RuntimeLog("priority_context phase=%s rows=%zu window=0x%zX/0x%zX",
                phase ? phase : "unknown", rows, kBefore, kAfter);
            return rows;
        }

        struct PriorityStringAddress
        {
            uintptr_t address = 0;
            size_t index = 0;
        };

        static bool FindNearestPriorityString(
            const std::vector<PriorityStringAddress>& anchors,
            uintptr_t address,
            size_t maxDistance,
            size_t& stringIndex,
            intptr_t& delta)
        {
            if (anchors.empty())
                return false;

            auto it = std::lower_bound(anchors.begin(), anchors.end(), address,
                [](const PriorityStringAddress& anchor, uintptr_t value)
                {
                    return anchor.address < value;
                });

            bool found = false;
            uintptr_t bestDistance = static_cast<uintptr_t>(maxDistance) + 1;
            const auto consider = [&](const PriorityStringAddress& anchor)
            {
                const uintptr_t distance = address >= anchor.address ?
                    address - anchor.address : anchor.address - address;
                if (distance <= maxDistance && distance < bestDistance)
                {
                    bestDistance = distance;
                    stringIndex = anchor.index;
                    delta = static_cast<intptr_t>(address) - static_cast<intptr_t>(anchor.address);
                    found = true;
                }
            };

            if (it != anchors.end()) consider(*it);
            if (it != anchors.begin())
            {
                auto prev = it;
                --prev;
                consider(*prev);
            }
            return found;
        }

        struct OwnerSummary
        {
            size_t xrefs = 0;
            size_t pointerXrefs = 0;
            bool offline = false;
            bool priority = false;
            std::string tags;
            std::string sample;
            DWORD endRva = 0;
        };

        static FrontendPassiveScanStats ScanFrontendKeywordXrefs(
            const ImageLayout& image,
            const std::vector<InterestingString>& selected,
            const char* phase,
            bool resetOutputFiles)
        {
            FrontendPassiveScanStats stats{};
            if (selected.empty())
                return stats;

            const auto stringRanges = BuildSelectedStringRanges(selected);
            const auto runtimeFunctions = LoadRuntimeFunctionRanges(image);

            std::vector<PriorityStringAddress> priorityAnchors;
            priorityAnchors.reserve(64);
            std::unordered_map<DWORD, size_t> selectedByRva;
            std::unordered_map<uintptr_t, size_t> selectedByAddress;
            selectedByRva.reserve(selected.size() * 2);
            selectedByAddress.reserve(selected.size() * 2);
            for (size_t i = 0; i < selected.size(); ++i)
            {
                if (selected[i].address < image.base || selected[i].address >= image.base + image.imageSize)
                    continue;
                const DWORD rva = static_cast<DWORD>(selected[i].address - image.base);
                selectedByRva.emplace(rva, i);
                selectedByAddress.emplace(selected[i].address, i);
                if (IsPriorityFrontendString(selected[i].value))
                    priorityAnchors.push_back({ selected[i].address, i });
            }
            std::sort(priorityAnchors.begin(), priorityAnchors.end(),
                [](const PriorityStringAddress& a, const PriorityStringAddress& b)
                {
                    return a.address < b.address;
                });

            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta" / L"research");
            const std::string pointerPath = storage_paths::PathA("logs\\t9_beta\\research\\frontend_string_pointer_slots.csv");
            const std::string rvaSlotPath = storage_paths::PathA("logs\\t9_beta\\research\\frontend_string_rva32_slots.csv");
            const std::string relSlotPath = storage_paths::PathA("logs\\t9_beta\\research\\frontend_string_rel32_slots.csv");
            const bool pointerNew = resetOutputFiles || GetFileAttributesA(pointerPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            const bool rvaSlotNew = resetOutputFiles || GetFileAttributesA(rvaSlotPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            const bool relSlotNew = resetOutputFiles || GetFileAttributesA(relSlotPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            std::ofstream pointerFile(pointerPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            std::ofstream rvaSlotFile(rvaSlotPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            std::ofstream relSlotFile(relSlotPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            if (pointerFile && pointerNew)
                pointerFile << "phase,slot_rva,section,string_rva,tags,text\n";
            if (rvaSlotFile && rvaSlotNew)
                rvaSlotFile << "phase,slot_rva,section,string_rva,tags,text\n";
            if (relSlotFile && relSlotNew)
                relSlotFile << "phase,slot_rva,section,string_rva,relative_value,tags,text\n";

            // T9/Arxan data can represent frontend strings in several ways. Keep all
            // three indexes passive: native VA pointers, image-relative DWORD RVAs,
            // and self-relative DWORD displacements used by compact metadata tables.
            std::unordered_map<uintptr_t, size_t> pointerSlots;
            std::unordered_map<uintptr_t, size_t> rvaSlots;
            std::unordered_map<uintptr_t, size_t> relativeSlots;
            pointerSlots.reserve(selected.size() * 2);
            rvaSlots.reserve(selected.size() * 2);
            relativeSlots.reserve(selected.size() * 2);

            for (const auto& section : image.sections)
            {
                if (section.characteristics & IMAGE_SCN_MEM_EXECUTE)
                    continue;
                const size_t size = static_cast<size_t>((std::min<DWORD>)(
                    section.virtualSize ? section.virtualSize : section.rawSize,
                    image.imageSize - section.rva));
                if (size < sizeof(DWORD) || size > 512ull * 1024ull * 1024ull)
                    continue;

                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(image.base + section.rva),
                    bytes.data(), size, &got) || got < sizeof(DWORD))
                    continue;

                for (size_t i = 0; i + sizeof(uintptr_t) <= got; i += sizeof(uintptr_t))
                {
                    uintptr_t value = 0;
                    memcpy(&value, bytes.data() + i, sizeof(value));
                    size_t stringIndex = 0;
                    if (!FindSelectedStringIndex(stringRanges, value, stringIndex))
                        continue;

                    const uintptr_t slot = image.base + section.rva + i;
                    if (!pointerSlots.emplace(slot, stringIndex).second)
                        continue;
                    if (pointerFile)
                    {
                        const auto& item = selected[stringIndex];
                        pointerFile << (phase ? phase : "unknown") << ",0x"
                            << std::hex << std::uppercase << (slot - image.base)
                            << ',' << section.name << ",0x" << (item.address - image.base)
                            << ",\"" << JsonEscape(FrontendKeywordTags(item.value)) << "\",\""
                            << JsonEscape(item.value) << "\"\n";
                    }
                }

                for (size_t i = 0; i + sizeof(DWORD) <= got; i += sizeof(DWORD))
                {
                    DWORD value = 0;
                    memcpy(&value, bytes.data() + i, sizeof(value));
                    const uintptr_t slot = image.base + section.rva + i;

                    const auto absoluteRva = selectedByRva.find(value);
                    if (absoluteRva != selectedByRva.end())
                    {
                        const size_t stringIndex = absoluteRva->second;
                        if (rvaSlots.emplace(slot, stringIndex).second && rvaSlotFile)
                        {
                            const auto& item = selected[stringIndex];
                            rvaSlotFile << (phase ? phase : "unknown") << ",0x"
                                << std::hex << std::uppercase << (slot - image.base)
                                << ',' << section.name << ",0x" << (item.address - image.base)
                                << ",\"" << JsonEscape(FrontendKeywordTags(item.value)) << "\",\""
                                << JsonEscape(item.value) << "\"\n";
                        }
                    }

                    const int32_t relative = static_cast<int32_t>(value);
                    const uintptr_t relativeTarget = static_cast<uintptr_t>(
                        static_cast<intptr_t>(slot + sizeof(DWORD)) + static_cast<intptr_t>(relative));
                    const auto relativeHit = selectedByAddress.find(relativeTarget);
                    if (relativeHit != selectedByAddress.end())
                    {
                        const size_t relativeIndex = relativeHit->second;
                        if (relativeSlots.emplace(slot, relativeIndex).second && relSlotFile)
                        {
                            const auto& item = selected[relativeIndex];
                            relSlotFile << (phase ? phase : "unknown") << ",0x"
                                << std::hex << std::uppercase << (slot - image.base)
                                << ',' << section.name << ",0x" << (item.address - image.base)
                                << ",0x" << static_cast<DWORD>(value) << ",\""
                                << JsonEscape(FrontendKeywordTags(item.value)) << "\",\""
                                << JsonEscape(item.value) << "\"\n";
                        }
                    }
                }
            }

            const std::string xrefsPath = storage_paths::PathA("logs\\t9_beta\\research\\frontend_keyword_xrefs.csv");
            const std::string callsPath = storage_paths::PathA("logs\\t9_beta\\research\\frontend_nearby_calls.csv");
            const std::string ownersPath = storage_paths::PathA("logs\\t9_beta\\research\\frontend_owner_functions.csv");
            const std::string neighborhoodPath = storage_paths::PathA("logs\\t9_beta\\research\\frontend_priority_neighborhood_xrefs.csv");
            const bool xrefsNew = resetOutputFiles || GetFileAttributesA(xrefsPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            const bool callsNew = resetOutputFiles || GetFileAttributesA(callsPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            const bool ownersNew = resetOutputFiles || GetFileAttributesA(ownersPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            const bool neighborhoodNew = resetOutputFiles || GetFileAttributesA(neighborhoodPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            std::ofstream xrefs(xrefsPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            std::ofstream calls(callsPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            std::ofstream owners(ownersPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            std::ofstream neighborhoods(neighborhoodPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            if (xrefs && xrefsNew)
                xrefs << "phase,instruction_rva,section,reference_kind,target_rva,string_rva,owner_function_rva,owner_end_rva,tags,text\n";
            if (calls && callsNew)
                calls << "phase,owner_function_rva,owner_end_rva,branch_rva,branch_target_rva,tags,sample\n";
            if (owners && ownersNew)
                owners << "phase,owner_function_rva,owner_end_rva,xrefs,pointer_xrefs,offline,priority,tags,sample\n";
            if (neighborhoods && neighborhoodNew)
                neighborhoods << "phase,instruction_rva,section,target_rva,anchor_string_rva,delta,owner_function_rva,owner_end_rva,tags,text\n";

            std::unordered_map<DWORD, OwnerSummary> ownerSummary;
            size_t printedXrefs = 0;
            size_t printedNeighborhoods = 0;
            size_t pointerResolvedXrefs = 0;

            const auto addOwner = [&](DWORD ownerBegin, DWORD ownerEnd, const std::string& tags,
                const std::string& sample, bool offline, bool priority, bool indirect)
            {
                if (!ownerBegin)
                    return;
                auto& summary = ownerSummary[ownerBegin];
                ++summary.xrefs;
                if (indirect) ++summary.pointerXrefs;
                summary.offline = summary.offline || offline;
                summary.priority = summary.priority || priority;
                summary.endRva = ownerEnd;
                if (summary.tags.empty()) summary.tags = tags;
                if (summary.sample.empty() || priority) summary.sample = sample;
            };

            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                const size_t size = static_cast<size_t>((std::min<DWORD>)(
                    section.virtualSize ? section.virtualSize : section.rawSize,
                    image.imageSize - section.rva));
                if (size < 6)
                    continue;

                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(image.base + section.rva),
                    bytes.data(), size, &got) || got < 6)
                    continue;

                for (size_t i = 0; i + 6 <= got; ++i)
                {
                    size_t length = 0;
                    size_t dispOffset = 0;
                    if (i + 7 <= got && bytes[i] >= 0x40 && bytes[i] <= 0x4F &&
                        (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B) &&
                        (bytes[i + 2] & 0xC7) == 0x05)
                    {
                        length = 7;
                        dispOffset = 3;
                    }
                    else if ((bytes[i] == 0x8D || bytes[i] == 0x8B) &&
                        (bytes[i + 1] & 0xC7) == 0x05)
                    {
                        length = 6;
                        dispOffset = 2;
                    }
                    if (!length || i + length > got)
                        continue;

                    int32_t disp = 0;
                    memcpy(&disp, bytes.data() + i + dispOffset, sizeof(disp));
                    const uintptr_t instruction = image.base + section.rva + i;
                    const uintptr_t target = static_cast<uintptr_t>(
                        static_cast<intptr_t>(instruction + length) + static_cast<intptr_t>(disp));

                    size_t stringIndex = 0;
                    const char* referenceKind = nullptr;
                    bool indirect = false;
                    if (FindSelectedStringIndex(stringRanges, target, stringIndex))
                    {
                        referenceKind = "direct_string";
                    }
                    else
                    {
                        const auto pointerHit = pointerSlots.find(target);
                        if (pointerHit != pointerSlots.end())
                        {
                            stringIndex = pointerHit->second;
                            referenceKind = "pointer_slot";
                            indirect = true;
                            ++pointerResolvedXrefs;
                        }
                        else
                        {
                            const auto rvaHit = rvaSlots.find(target);
                            if (rvaHit != rvaSlots.end())
                            {
                                stringIndex = rvaHit->second;
                                referenceKind = "rva32_slot";
                                indirect = true;
                                ++stats.rvaSlotXrefs;
                            }
                            else
                            {
                                const auto relHit = relativeSlots.find(target);
                                if (relHit != relativeSlots.end())
                                {
                                    stringIndex = relHit->second;
                                    referenceKind = "relative32_slot";
                                    indirect = true;
                                    ++stats.relativeSlotXrefs;
                                }
                            }
                        }
                    }

                    if (referenceKind)
                    {
                        const auto& item = selected[stringIndex];
                        const std::string tags = FrontendKeywordTags(item.value);
                        const bool offline = HasOfflineTag(tags);
                        const bool priority = IsPriorityFrontendString(item.value);
                        ++stats.xrefs;
                        if (offline) ++stats.offlineXrefs;

                        DWORD ownerBegin = 0, ownerEnd = 0;
                        ResolveFunctionOwner(image, runtimeFunctions, instruction, ownerBegin, ownerEnd);
                        addOwner(ownerBegin, ownerEnd, tags, item.value, offline, priority, indirect);

                        if (xrefs)
                        {
                            xrefs << (phase ? phase : "unknown") << ",0x"
                                << std::hex << std::uppercase << (instruction - image.base) << ','
                                << section.name << ',' << referenceKind << ",0x" << (target - image.base)
                                << ",0x" << (item.address - image.base) << ",0x" << ownerBegin
                                << ",0x" << ownerEnd << ",\"" << JsonEscape(tags) << "\",\""
                                << JsonEscape(item.value) << "\"\n";
                        }

                        if (printedXrefs < 64 || offline || priority)
                        {
                            std::printf("[BETA-FRONTEND] %s%sXREF RVA=0x%llX owner=0x%X via=%s str=0x%llX tags=%s text=%s\n",
                                offline ? "OFFLINE " : "",
                                priority ? "PRIORITY " : "",
                                static_cast<unsigned long long>(instruction - image.base),
                                ownerBegin, referenceKind,
                                static_cast<unsigned long long>(item.address - image.base),
                                tags.empty() ? "frontend" : tags.c_str(), item.value.c_str());
                            ++printedXrefs;
                        }
                    }

                    // A frontend table is often addressed at its header/base instead
                    // of at the member containing a label. Resolve RIP-relative data
                    // accesses landing near the highest-value offline/LAN anchors.
                    size_t priorityIndex = 0;
                    intptr_t delta = 0;
                    if (FindNearestPriorityString(priorityAnchors, target, 0x800, priorityIndex, delta))
                    {
                        const auto& item = selected[priorityIndex];
                        const std::string tags = FrontendKeywordTags(item.value);
                        const bool offline = HasOfflineTag(tags);
                        DWORD ownerBegin = 0, ownerEnd = 0;
                        const bool ownerResolved =
                            ResolveFunctionOwner(image, runtimeFunctions, instruction, ownerBegin, ownerEnd) && ownerBegin != 0;
                        ++stats.priorityNeighborhoodXrefs;
                        if (ownerResolved)
                            addOwner(ownerBegin, ownerEnd, tags, item.value, offline, true, true);

                        if (neighborhoods)
                        {
                            neighborhoods << (phase ? phase : "unknown") << ",0x"
                                << std::hex << std::uppercase << (instruction - image.base) << ','
                                << section.name << ",0x" << (target - image.base) << ",0x"
                                << (item.address - image.base) << ',' << std::dec << delta << ",0x"
                                << std::hex << ownerBegin << ",0x" << ownerEnd << ",\""
                                << JsonEscape(tags) << "\",\"" << JsonEscape(item.value) << "\"\n";
                        }

                        if (printedNeighborhoods < 80)
                        {
                            std::printf("[BETA-GATE] PRIORITY-NEAR RVA=0x%llX target=0x%llX anchor=0x%llX delta=%lld owner=%s0x%X text=%s\n",
                                static_cast<unsigned long long>(instruction - image.base),
                                static_cast<unsigned long long>(target - image.base),
                                static_cast<unsigned long long>(item.address - image.base),
                                static_cast<long long>(delta), ownerResolved ? "" : "unresolved/",
                                ownerBegin, item.value.c_str());
                            ++printedNeighborhoods;
                        }
                    }
                }
            }

            // Once owners are known, inspect only those bounded functions for direct
            // calls. The call scan remains passive and validates every target against
            // unwind/function ownership before reporting it.
            size_t printedCalls = 0;
            for (const auto& pair : ownerSummary)
            {
                const DWORD ownerBegin = pair.first;
                const OwnerSummary& summary = pair.second;
                if (!ownerBegin || summary.endRva <= ownerBegin || summary.endRva > image.imageSize)
                    continue;
                const size_t functionSize = static_cast<size_t>(summary.endRva - ownerBegin);
                if (!functionSize || functionSize > 0x20000)
                    continue;

                std::vector<unsigned char> functionBytes(functionSize);
                if (!ReadBytes(image.base + ownerBegin, functionBytes.data(), functionBytes.size()))
                    continue;
                for (size_t j = 0; j + 5 <= functionBytes.size(); ++j)
                {
                    if (functionBytes[j] != 0xE8)
                        continue;
                    int32_t rel = 0;
                    memcpy(&rel, functionBytes.data() + j + 1, sizeof(rel));
                    const uintptr_t branch = image.base + ownerBegin + j;
                    const uintptr_t branchTarget = static_cast<uintptr_t>(
                        static_cast<intptr_t>(branch + 5) + static_cast<intptr_t>(rel));
                    if (branchTarget < image.base || branchTarget >= image.base + image.imageSize)
                        continue;

                    DWORD targetOwner = 0, targetEnd = 0;
                    if (!ResolveFunctionOwner(image, runtimeFunctions, branchTarget, targetOwner, targetEnd) ||
                        targetOwner != static_cast<DWORD>(branchTarget - image.base))
                        continue;

                    ++stats.nearbyCalls;
                    if (calls)
                    {
                        calls << (phase ? phase : "unknown") << ",0x" << std::hex << std::uppercase
                            << ownerBegin << ",0x" << summary.endRva << ",0x" << (branch - image.base)
                            << ",0x" << (branchTarget - image.base) << ",\"" << JsonEscape(summary.tags)
                            << "\",\"" << JsonEscape(summary.sample) << "\"\n";
                    }
                    if (printedCalls < 64 && (summary.priority || summary.offline))
                    {
                        std::printf("[BETA-FRONTEND] owner 0x%X CALL RVA=0x%llX -> 0x%llX priority=%u sample=%s\n",
                            ownerBegin,
                            static_cast<unsigned long long>(branch - image.base),
                            static_cast<unsigned long long>(branchTarget - image.base),
                            summary.priority ? 1u : 0u, summary.sample.c_str());
                        ++printedCalls;
                    }
                }
            }

            if (owners)
            {
                std::vector<std::pair<DWORD, OwnerSummary>> ordered(ownerSummary.begin(), ownerSummary.end());
                std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b)
                {
                    if (a.second.priority != b.second.priority) return a.second.priority > b.second.priority;
                    if (a.second.offline != b.second.offline) return a.second.offline > b.second.offline;
                    if (a.second.xrefs != b.second.xrefs) return a.second.xrefs > b.second.xrefs;
                    return a.first < b.first;
                });
                for (const auto& pair : ordered)
                {
                    const auto& summary = pair.second;
                    owners << (phase ? phase : "unknown") << ",0x" << std::hex << std::uppercase
                        << pair.first << ",0x" << summary.endRva << std::dec << ',' << summary.xrefs
                        << ',' << summary.pointerXrefs << ',' << (summary.offline ? 1 : 0)
                        << ',' << (summary.priority ? 1 : 0) << ",\"" << JsonEscape(summary.tags)
                        << "\",\"" << JsonEscape(summary.sample) << "\"\n";
                }
            }

            RuntimeLog("frontend_xrefs phase=%s selected=%zu priority=%zu runtime_ranges=%zu pointer_slots=%zu rva_slots=%zu rel_slots=%zu xrefs=%zu pointer_xrefs=%zu rva_xrefs=%zu rel_xrefs=%zu priority_near=%zu offline_xrefs=%zu owner_functions=%zu validated_calls=%zu",
                phase ? phase : "unknown", selected.size(), priorityAnchors.size(), runtimeFunctions.size(),
                pointerSlots.size(), rvaSlots.size(), relativeSlots.size(), stats.xrefs,
                pointerResolvedXrefs, stats.rvaSlotXrefs, stats.relativeSlotXrefs,
                stats.priorityNeighborhoodXrefs, stats.offlineXrefs, ownerSummary.size(), stats.nearbyCalls);
            std::printf("[BETA-FRONTEND] passive graph v4: selected=%zu priority=%zu ptr=%zu rva32=%zu rel32=%zu xrefs=%zu near=%zu owners=%zu calls=%zu\n",
                selected.size(), priorityAnchors.size(), pointerSlots.size(), rvaSlots.size(),
                relativeSlots.size(), stats.xrefs, stats.priorityNeighborhoodXrefs,
                ownerSummary.size(), stats.nearbyCalls);
            std::fflush(stdout);
            return stats;
        }

        static bool IsExecutableTarget(uintptr_t address)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!address || !VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
                return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
                return false;
            const DWORD p = mbi.Protect & 0xFFu;
            return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        static std::unordered_map<std::string, size_t> ScanKnownTargetIndirectReferences(
            const ImageLayout& image,
            const FrontendTarget* targets,
            size_t targetCount,
            const char* phase,
            bool resetOutputFiles)
        {
            std::unordered_map<std::string, size_t> counts;
            std::unordered_map<uintptr_t, const char*> targetByAddress;
            std::unordered_map<DWORD, const char*> targetByRva;
            for (size_t i = 0; i < targetCount; ++i)
            {
                counts[targets[i].name] = 0;
                targetByAddress.emplace(image.base + targets[i].rva, targets[i].name);
                targetByRva.emplace(static_cast<DWORD>(targets[i].rva), targets[i].name);
            }

            struct TargetSlot
            {
                const char* target = nullptr;
                const char* storage = nullptr;
            };
            std::unordered_map<uintptr_t, TargetSlot> slotTargets;
            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta" / L"research");
            const std::string slotsPath = storage_paths::PathA("logs\\t9_beta\\research\\mp_target_pointer_slots.csv");
            const std::string refsPath = storage_paths::PathA("logs\\t9_beta\\research\\mp_target_indirect_refs.csv");
            const bool slotsNew = resetOutputFiles || GetFileAttributesA(slotsPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            const bool refsNew = resetOutputFiles || GetFileAttributesA(refsPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            std::ofstream slots(slotsPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            std::ofstream refs(refsPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            if (slots && slotsNew) slots << "phase,storage_kind,slot_rva,section,target,target_rva\n";
            if (refs && refsNew) refs << "phase,reference_kind,storage_kind,instruction_rva,section,slot_rva,target,target_rva\n";

            const auto recordSlot = [&](uintptr_t slot, const char* target, const char* storage,
                const std::string& sectionName)
            {
                if (!target || !storage)
                    return;
                if (!slotTargets.emplace(slot, TargetSlot{ target, storage }).second)
                    return;
                uintptr_t targetAddress = 0;
                for (size_t t = 0; t < targetCount; ++t)
                    if (strcmp(targets[t].name, target) == 0)
                        targetAddress = image.base + targets[t].rva;
                if (slots)
                    slots << (phase ? phase : "unknown") << ',' << storage << ",0x"
                        << std::hex << std::uppercase << (slot - image.base) << ',' << sectionName
                        << ',' << target << ",0x" << (targetAddress ? targetAddress - image.base : 0) << "\n";
            };

            for (const auto& section : image.sections)
            {
                if (section.characteristics & IMAGE_SCN_MEM_EXECUTE)
                    continue;
                const size_t size = static_cast<size_t>((std::min<DWORD>)(
                    section.virtualSize ? section.virtualSize : section.rawSize,
                    image.imageSize - section.rva));
                if (size < sizeof(DWORD) || size > 512ull * 1024ull * 1024ull)
                    continue;
                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva),
                    bytes.data(), size, &got) || got < sizeof(DWORD))
                    continue;

                for (size_t i = 0; i + sizeof(uintptr_t) <= got; i += sizeof(uintptr_t))
                {
                    uintptr_t value = 0;
                    memcpy(&value, bytes.data() + i, sizeof(value));
                    const auto hit = targetByAddress.find(value);
                    if (hit != targetByAddress.end())
                        recordSlot(image.base + section.rva + i, hit->second, "va64", section.name);
                }

                for (size_t i = 0; i + sizeof(DWORD) <= got; i += sizeof(DWORD))
                {
                    DWORD value = 0;
                    memcpy(&value, bytes.data() + i, sizeof(value));
                    const uintptr_t slot = image.base + section.rva + i;
                    const auto rvaHit = targetByRva.find(value);
                    if (rvaHit != targetByRva.end())
                        recordSlot(slot, rvaHit->second, "rva32", section.name);

                    const int32_t relative = static_cast<int32_t>(value);
                    const uintptr_t relativeTarget = static_cast<uintptr_t>(
                        static_cast<intptr_t>(slot + sizeof(DWORD)) + static_cast<intptr_t>(relative));
                    const auto relativeHit = targetByAddress.find(relativeTarget);
                    if (relativeHit != targetByAddress.end())
                        recordSlot(slot, relativeHit->second, "rel32", section.name);
                }
            }

            size_t printed = 0;
            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                const size_t size = static_cast<size_t>((std::min<DWORD>)(
                    section.virtualSize ? section.virtualSize : section.rawSize,
                    image.imageSize - section.rva));
                if (size < 6)
                    continue;
                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva),
                    bytes.data(), size, &got) || got < 6)
                    continue;

                for (size_t i = 0; i + 6 <= got; ++i)
                {
                    size_t length = 0;
                    size_t dispOffset = 0;
                    const char* kind = nullptr;
                    if (i + 7 <= got && bytes[i] >= 0x40 && bytes[i] <= 0x4F &&
                        (bytes[i + 1] == 0x8B || bytes[i + 1] == 0x8D) &&
                        (bytes[i + 2] & 0xC7) == 0x05)
                    {
                        length = 7;
                        dispOffset = 3;
                        kind = bytes[i + 1] == 0x8B ? "mov_slot" : "lea_slot";
                    }
                    else if ((bytes[i] == 0x8B || bytes[i] == 0x8D) &&
                        (bytes[i + 1] & 0xC7) == 0x05)
                    {
                        length = 6;
                        dispOffset = 2;
                        kind = bytes[i] == 0x8B ? "mov_slot" : "lea_slot";
                    }
                    else if (bytes[i] == 0xFF && (bytes[i + 1] == 0x15 || bytes[i + 1] == 0x25))
                    {
                        length = 6;
                        dispOffset = 2;
                        kind = bytes[i + 1] == 0x15 ? "call_indirect" : "jmp_indirect";
                    }
                    if (!length || i + length > got)
                        continue;

                    int32_t disp = 0;
                    memcpy(&disp, bytes.data() + i + dispOffset, sizeof(disp));
                    const uintptr_t instruction = image.base + section.rva + i;
                    const uintptr_t slotAddress = static_cast<uintptr_t>(
                        static_cast<intptr_t>(instruction + length) + static_cast<intptr_t>(disp));
                    const auto slot = slotTargets.find(slotAddress);
                    if (slot == slotTargets.end())
                        continue;

                    const char* targetName = slot->second.target;
                    ++counts[targetName];
                    uintptr_t targetAddress = 0;
                    for (size_t t = 0; t < targetCount; ++t)
                        if (strcmp(targets[t].name, targetName) == 0)
                            targetAddress = image.base + targets[t].rva;

                    if (refs)
                        refs << (phase ? phase : "unknown") << ',' << kind << ',' << slot->second.storage
                            << ",0x" << std::hex << std::uppercase << (instruction - image.base) << ','
                            << section.name << ",0x" << (slotAddress - image.base) << ',' << targetName
                            << ",0x" << (targetAddress ? targetAddress - image.base : 0) << "\n";

                    if (printed < 64)
                    {
                        std::printf("[BETA-MP] INDIRECT %-22s <- %s/%s RVA 0x%llX slot=0x%llX\n",
                            targetName, kind, slot->second.storage,
                            static_cast<unsigned long long>(instruction - image.base),
                            static_cast<unsigned long long>(slotAddress - image.base));
                        ++printed;
                    }
                }
            }

            RuntimeLog("mp_indirect_scan phase=%s target_slots=%zu", phase ? phase : "unknown", slotTargets.size());
            return counts;
        }

        static void RunMultiplayerTransitionScan(const char* phase)
        {
            ImageLayout image{};
            if (!ReadImageLayout(GetModuleHandleW(nullptr), image) ||
                DetectCurrentBuild().kind != BuildKind::OpenBeta)
                return;

            // The first successful passive scan in this process starts fresh CSVs.
            // Later phases append so launch/ready/click can be compared side by side.
            const bool resetOutputFiles = !g_passiveScanFilesInitialized.exchange(true, std::memory_order_acq_rel);

            const auto& r = t9_addresses::OpenBetaRecovered;
            const FrontendTarget targets[] = {
                { "Command/Cbuf", r.command },
                { "SetScreen/transition", r.transition },
                { "Com_SessionMode_SetMode/initA", r.initA },
                { "LobbyBase_SetNetworkMode/initB", r.initB },
                { "UsernameContext", r.usernameContext },
                { "SetUsername", r.setUsername }
            };

            DWORD a = 0, b = 0, c = 0;
            std::uint8_t ready = 0;
            ReadBytes(image.base + r.stateA, &a, sizeof(a));
            ReadBytes(image.base + r.stateB, &b, sizeof(b));
            ReadBytes(image.base + r.stateC, &c, sizeof(c));
            ReadBytes(image.base + r.readyByte, &ready, sizeof(ready));

            RuntimeLog("mp_scan=begin phase=%s ready=0x%02X A=0x%X B=0x%X C=0x%X",
                phase ? phase : "unknown", static_cast<unsigned>(ready), a, b, c);
            std::printf("[BETA-MP] scan phase=%s | ready=0x%02X | A=0x%X B=0x%X C=0x%X\n",
                phase ? phase : "unknown", static_cast<unsigned>(ready), a, b, c);

            for (const auto& target : targets)
            {
                unsigned char bytes[12]{};
                const bool readable = ReadBytes(image.base + target.rva, bytes, sizeof(bytes));
                std::ostringstream firstBytes;
                if (readable)
                {
                    firstBytes << std::hex << std::uppercase << std::setfill('0');
                    for (size_t i = 0; i < sizeof(bytes); ++i)
                    {
                        if (i) firstBytes << ' ';
                        firstBytes << std::setw(2) << static_cast<unsigned>(bytes[i]);
                    }
                }
                RuntimeLog("mp_target name=%s rva=0x%llX executable=%u bytes=%s",
                    target.name,
                    static_cast<unsigned long long>(target.rva),
                    IsExecutableTarget(image.base + target.rva) ? 1u : 0u,
                    readable ? firstBytes.str().c_str() : "<unreadable>");
                std::printf("[BETA-MP] target %-22s RVA=0x%llX %s\n",
                    target.name,
                    static_cast<unsigned long long>(target.rva),
                    IsExecutableTarget(image.base + target.rva) ? "READY" : "NOT-READY");
            }
            std::fflush(stdout);

            // Run the exact-string gate/error pass first.  It searches every
            // committed image section (including executable/protected sections),
            // so the known "UI Error 84360" marker and the Lobby.lua validation
            // strings are available before the slower generic frontend graph.
            const CriticalGateScanStats criticalGateStats =
                RunCriticalGateScan(image, phase, resetOutputFiles);
            RuntimeLog("mp_scan=critical_gate_first phase=%s strings=%zu xrefs=%zu ui84360=%zu session_validate=%zu calls=%zu",
                phase ? phase : "unknown",
                criticalGateStats.strings,
                criticalGateStats.xrefs,
                criticalGateStats.errorXrefs,
                criticalGateStats.sessionValidationXrefs,
                criticalGateStats.nearbyCalls);

            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta" / L"research");
            const std::string callersPath = storage_paths::PathA("logs\\t9_beta\\research\\mp_target_callers.csv");
            const bool newFile = resetOutputFiles || GetFileAttributesA(callersPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            std::ofstream callers(callersPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            if (callers && newFile)
                callers << "phase,kind,instruction_rva,section,target,target_rva\n";

            std::unordered_map<uintptr_t, const char*> targetMap;
            for (const auto& t : targets)
                targetMap.emplace(image.base + t.rva, t.name);

            std::unordered_map<std::string, size_t> callerCounts;
            for (const auto& t : targets) callerCounts[t.name] = 0;

            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                const size_t size = static_cast<size_t>((std::min<DWORD>)(
                    section.virtualSize ? section.virtualSize : section.rawSize,
                    image.imageSize - section.rva));
                if (!size) continue;

                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(image.base + section.rva),
                    bytes.data(), size, &got) || got < 5)
                    continue;

                for (size_t i = 0; i + 5 <= got; ++i)
                {
                    const unsigned char op = bytes[i];
                    if (op != 0xE8 && op != 0xE9)
                        continue;
                    int32_t rel = 0;
                    memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
                    const uintptr_t source = image.base + section.rva + i;
                    const uintptr_t target = source + 5 + rel;
                    const auto hit = targetMap.find(target);
                    if (hit == targetMap.end())
                        continue;

                    ++callerCounts[hit->second];
                    if (callers)
                    {
                        callers << (phase ? phase : "unknown") << ','
                            << (op == 0xE8 ? "call" : "jmp") << ",0x"
                            << std::hex << std::uppercase << (source - image.base) << ','
                            << section.name << ',' << hit->second << ",0x"
                            << (target - image.base) << "\n";
                    }

                    // Keep a bounded sample visible in CMD. The CSV retains all
                    // matches for IDA/research.
                    if (callerCounts[hit->second] <= 12)
                    {
                        std::printf("[BETA-MP] %-22s <- %s RVA 0x%llX (%s)\n",
                            hit->second,
                            op == 0xE8 ? "CALL" : "JMP",
                            static_cast<unsigned long long>(source - image.base),
                            section.name.c_str());
                    }
                }
            }

            const auto indirectCounts = ScanKnownTargetIndirectReferences(
                image, targets, sizeof(targets) / sizeof(targets[0]), phase, resetOutputFiles);

            for (const auto& t : targets)
            {
                const size_t indirectCount = indirectCounts.count(t.name) ? indirectCounts.at(t.name) : 0;
                RuntimeLog("mp_scan_callers phase=%s target=%s direct=%zu indirect=%zu",
                    phase ? phase : "unknown", t.name, callerCounts[t.name], indirectCount);
                std::printf("[BETA-MP] callers %-22s direct=%zu indirect=%zu\n",
                    t.name, callerCounts[t.name], indirectCount);
            }


            const auto strings = ScanInterestingStrings(image);
            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta" / L"research");
            const std::string stringsPath = storage_paths::PathA("logs\\t9_beta\\research\\mp_frontend_strings.csv");
            const std::string offlinePath = storage_paths::PathA("logs\\t9_beta\\research\\offline_frontend_strings.csv");
            const bool stringsNew = resetOutputFiles || GetFileAttributesA(stringsPath.c_str()) == INVALID_FILE_ATTRIBUTES;
            const bool offlineNew = resetOutputFiles || GetFileAttributesA(offlinePath.c_str()) == INVALID_FILE_ATTRIBUTES;
            std::ofstream mpStrings(stringsPath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            std::ofstream offlineStrings(offlinePath, resetOutputFiles ? std::ios::trunc : std::ios::app);
            if (mpStrings && stringsNew)
                mpStrings << "phase,rva,tags,text\n";
            if (offlineStrings && offlineNew)
                offlineStrings << "phase,rva,tags,text\n";

            std::vector<InterestingString> selectedStrings;
            selectedStrings.reserve(strings.size());
            size_t mpStringCount = 0;
            size_t offlineStringCount = 0;
            size_t printedGeneral = 0;
            size_t printedOffline = 0;
            for (const auto& item : strings)
            {
                if (!IsMultiplayerString(item.value))
                    continue;

                const std::string tags = FrontendKeywordTags(item.value);
                const bool offline = HasOfflineTag(tags);
                selectedStrings.push_back(item);
                ++mpStringCount;
                if (offline) ++offlineStringCount;

                if (mpStrings)
                    mpStrings << (phase ? phase : "unknown") << ",0x" << std::hex << std::uppercase
                        << (item.address - image.base) << ",\"" << JsonEscape(tags) << "\",\""
                        << JsonEscape(item.value) << "\"\n";
                if (offline && offlineStrings)
                    offlineStrings << (phase ? phase : "unknown") << ",0x" << std::hex << std::uppercase
                        << (item.address - image.base) << ",\"" << JsonEscape(tags) << "\",\""
                        << JsonEscape(item.value) << "\"\n";

                const bool priority = IsPriorityFrontendString(item.value);
                if (offline && (printedOffline < 40 || priority))
                {
                    std::printf("[BETA-OFFLINE] %sSTRING RVA=0x%llX tags=%s text=%s\n",
                        priority ? "PRIORITY " : "",
                        static_cast<unsigned long long>(item.address - image.base),
                        tags.empty() ? "offline" : tags.c_str(), item.value.c_str());
                    ++printedOffline;
                }
                else if (!offline && (printedGeneral < 24 || priority))
                {
                    std::printf("[BETA-FRONTEND] %sSTRING RVA=0x%llX tags=%s text=%s\n",
                        priority ? "PRIORITY " : "",
                        static_cast<unsigned long long>(item.address - image.base),
                        tags.empty() ? "frontend" : tags.c_str(), item.value.c_str());
                    ++printedGeneral;
                }
            }

            const size_t priorityContextRows =
                DumpPriorityFrontendContexts(image, selectedStrings, phase, resetOutputFiles);
            const FrontendPassiveScanStats passiveStats =
                ScanFrontendKeywordXrefs(image, selectedStrings, phase, resetOutputFiles);

            RuntimeLog("mp_scan=complete phase=%s frontend_strings=%zu offline_strings=%zu context_rows=%zu string_xrefs=%zu rva_slot_xrefs=%zu rel_slot_xrefs=%zu priority_near=%zu offline_xrefs=%zu nearby_calls=%zu transition_callers=%zu/%zu game_mode_callers=%zu/%zu session_callers=%zu/%zu command_callers=%zu/%zu",
                phase ? phase : "unknown",
                mpStringCount,
                offlineStringCount,
                priorityContextRows,
                passiveStats.xrefs,
                passiveStats.rvaSlotXrefs,
                passiveStats.relativeSlotXrefs,
                passiveStats.priorityNeighborhoodXrefs,
                passiveStats.offlineXrefs,
                passiveStats.nearbyCalls,
                callerCounts["SetScreen/transition"], indirectCounts.count("SetScreen/transition") ? indirectCounts.at("SetScreen/transition") : 0,
                callerCounts["Com_SessionMode_SetMode/initA"], indirectCounts.count("Com_SessionMode_SetMode/initA") ? indirectCounts.at("Com_SessionMode_SetMode/initA") : 0,
                callerCounts["LobbyBase_SetNetworkMode/initB"], indirectCounts.count("LobbyBase_SetNetworkMode/initB") ? indirectCounts.at("LobbyBase_SetNetworkMode/initB") : 0,
                callerCounts["Command/Cbuf"], indirectCounts.count("Command/Cbuf") ? indirectCounts.at("Command/Cbuf") : 0);
            std::printf("[BETA-FRONTEND] scan complete: strings=%zu OFFLINE=%zu context=%zu xrefs=%zu rva32=%zu rel32=%zu priority_near=%zu offline_xrefs=%zu nearby_calls=%zu\n",
                mpStringCount, offlineStringCount, priorityContextRows, passiveStats.xrefs, passiveStats.rvaSlotXrefs,
                passiveStats.relativeSlotXrefs, passiveStats.priorityNeighborhoodXrefs,
                passiveStats.offlineXrefs, passiveStats.nearbyCalls);
            std::printf("[BETA-FRONTEND] known callers direct/indirect: SetScreen=%zu/%zu ComSessionMode=%zu/%zu LobbyNetworkMode=%zu/%zu Command=%zu/%zu\n",
                callerCounts["SetScreen/transition"], indirectCounts.count("SetScreen/transition") ? indirectCounts.at("SetScreen/transition") : 0,
                callerCounts["Com_SessionMode_SetMode/initA"], indirectCounts.count("Com_SessionMode_SetMode/initA") ? indirectCounts.at("Com_SessionMode_SetMode/initA") : 0,
                callerCounts["LobbyBase_SetNetworkMode/initB"], indirectCounts.count("LobbyBase_SetNetworkMode/initB") ? indirectCounts.at("LobbyBase_SetNetworkMode/initB") : 0,
                callerCounts["Command/Cbuf"], indirectCounts.count("Command/Cbuf") ? indirectCounts.at("Command/Cbuf") : 0);
            std::fflush(stdout);
        }

        static DWORD WINAPI MultiplayerScanThread(LPVOID parameter)
        {
            const char* phase = reinterpret_cast<const char*>(parameter);
            RunMultiplayerTransitionScan(phase ? phase : "async");
            g_mpScanThreadRunning.store(false, std::memory_order_release);
            return 0;
        }

        static void StartMultiplayerScanAsync(const char* phase)
        {
            // All current callers pass string literals, so the phase pointer is
            // valid for the lifetime of the worker thread.
            if (g_mpScanThreadRunning.exchange(true, std::memory_order_acq_rel))
            {
                RuntimeLog("mp_scan=request_skipped phase=%s reason=previous_scan_still_running",
                    phase ? phase : "unknown");
                return;
            }

            HANDLE thread = CreateThread(nullptr, 0, &MultiplayerScanThread,
                const_cast<char*>(phase), 0, nullptr);
            if (!thread)
            {
                g_mpScanThreadRunning.store(false, std::memory_order_release);
                RuntimeLog("mp_scan=create_thread_failed phase=%s error=%lu",
                    phase ? phase : "unknown", static_cast<unsigned long>(GetLastError()));
                return;
            }
            CloseHandle(thread);
        }

        struct FullMemoryScanStats
        {
            std::uint64_t regions = 0;
            std::uint64_t readableRegions = 0;
            std::uint64_t bytesRead = 0;
            std::uint64_t asciiHits = 0;
            std::uint64_t wideHits = 0;
            std::uint64_t pointerHits = 0;
            std::uint64_t rvaHits = 0;
            std::uint64_t readFailures = 0;
        };

        struct FullMemoryScanRequest
        {
            std::string phase;
        };

        static bool IsReadableMemoryProtection(DWORD protect)
        {
            if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS))
                return false;
            switch (protect & 0xFFu)
            {
            case PAGE_READONLY:
            case PAGE_READWRITE:
            case PAGE_WRITECOPY:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
            }
        }

        static const char* MemoryTypeName(DWORD type)
        {
            if (type == MEM_IMAGE) return "IMAGE";
            if (type == MEM_MAPPED) return "MAPPED";
            if (type == MEM_PRIVATE) return "PRIVATE";
            return "OTHER";
        }

        static std::string SanitizeFileToken(std::string value)
        {
            if (value.empty()) value = "scan";
            for (char& c : value)
            {
                if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-')
                    c = '_';
            }
            if (value.size() > 48) value.resize(48);
            return value;
        }

        static std::string AllocationModuleName(uintptr_t allocationBase)
        {
            if (!allocationBase) return {};
            wchar_t path[1024]{};
            const DWORD n = GetModuleFileNameW(reinterpret_cast<HMODULE>(allocationBase), path,
                static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
            if (!n) return {};
            std::string out;
            out.reserve(n);
            for (DWORD i = 0; i < n; ++i)
            {
                const wchar_t wc = path[i];
                out.push_back(wc >= 0x20 && wc < 0x7F ? static_cast<char>(wc) : '?');
            }
            return out;
        }

        struct KnownMemoryTarget
        {
            const char* name;
            uintptr_t address;
            std::uint32_t rva;
        };

        static std::vector<KnownMemoryTarget> BuildKnownMemoryTargets(uintptr_t gameBase)
        {
            const auto& r = t9_addresses::OpenBetaRecovered;
            const auto add = [gameBase](std::vector<KnownMemoryTarget>& out, const char* name, std::uintptr_t rva)
            {
                if (rva && rva < t9_addresses::BetaFingerprint.imageSize)
                    out.push_back({ name, gameBase + rva, static_cast<std::uint32_t>(rva) });
            };

            std::vector<KnownMemoryTarget> out;
            out.reserve(20);
            add(out, "readyByte", r.readyByte);
            add(out, "stateA", r.stateA);
            add(out, "stateB", r.stateB);
            add(out, "stateC", r.stateC);
            add(out, "command", r.command);
            add(out, "SetScreen/transition", r.transition);
            add(out, "Com_SessionMode_SetMode/initA", r.initA);
            add(out, "LobbyBase_SetNetworkMode/initB", r.initB);
            add(out, "forceReadyFlag", r.forceReadyFlag);
            add(out, "endpointA", r.endpointA);
            add(out, "endpointB", r.endpointB);
            add(out, "authManagerSlot", r.authManagerSlot);
            add(out, "usernameContext", r.usernameContext);
            add(out, "setUsername", r.setUsername);
            add(out, "exceptionFilter", r.exceptionFilter);
            add(out, "win11Breakpoint", r.win11Breakpoint);
            add(out, "win11Resume", r.win11Resume);
            return out;
        }

        static bool MemoryStringInteresting(const std::string& text, std::string& tags)
        {
            tags = FrontendKeywordTags(text);
            if (!tags.empty()) return true;
            return ContainsInterestingKeyword(text);
        }

        static void WriteFullMemoryStringHit(std::ofstream& out, const char* phase,
            uintptr_t address, const MEMORY_BASIC_INFORMATION& mbi,
            const std::string& module, const char* encoding,
            const std::string& tags, const std::string& text)
        {
            out << '"' << JsonEscape(phase ? phase : "scan") << "\",0x"
                << std::hex << std::uppercase << address << ",0x"
                << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << ",0x"
                << mbi.RegionSize << ',' << MemoryTypeName(mbi.Type) << ",0x"
                << mbi.Protect << ",\"" << JsonEscape(module) << "\","
                << encoding << ",\"" << JsonEscape(tags) << "\",\""
                << JsonEscape(text) << "\"\n";
        }

        static FullMemoryScanStats RunFullMemoryCensus(const char* phase)
        {
            FullMemoryScanStats stats{};
            const uintptr_t gameBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            const std::string safePhase = SanitizeFileToken(phase ? phase : "scan");
            const std::string dir = AnalysisDir();
            const std::string prefix = dir + "\\full_memory_" + safePhase;

            std::ofstream regions(prefix + "_regions.csv", std::ios::trunc);
            std::ofstream strings(prefix + "_keyword_hits.csv", std::ios::trunc);
            std::ofstream pointers(prefix + "_known_refs.csv", std::ios::trunc);
            std::ofstream summary(prefix + "_summary.txt", std::ios::trunc);
            if (!regions || !strings || !pointers || !summary)
            {
                RuntimeLog("full_memscan phase=%s result=open_output_failed", phase ? phase : "scan");
                return stats;
            }

            regions << "base,size,allocation_base,type,protect,module,bytes_read\n";
            strings << "phase,address,region_base,region_size,type,protect,module,encoding,tags,text\n";
            pointers << "phase,slot_address,region_base,type,protect,module,reference_kind,target_name,target_address,target_rva\n";

            const auto knownTargets = BuildKnownMemoryTargets(gameBase);
            std::unordered_map<std::uint64_t, const KnownMemoryTarget*> pointerTargets;
            std::unordered_map<std::uint32_t, const KnownMemoryTarget*> rvaTargets;
            for (const auto& target : knownTargets)
            {
                pointerTargets.emplace(static_cast<std::uint64_t>(target.address), &target);
                rvaTargets.emplace(target.rva, &target);
            }

            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            uintptr_t cursor = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
            const uintptr_t maximum = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
            constexpr SIZE_T kChunk = 8u * 1024u * 1024u;
            constexpr std::uint64_t kProgressStep = 128ull * 1024ull * 1024ull;
            constexpr std::uint64_t kSafetyByteLimit = 8ull * 1024ull * 1024ull * 1024ull;
            std::uint64_t nextProgress = kProgressStep;
            const std::uint64_t gameEnd = static_cast<std::uint64_t>(gameBase) +
                static_cast<std::uint64_t>(t9_addresses::BetaFingerprint.imageSize);
            // Reuse one buffer for the entire census instead of allocating a new
            // multi-megabyte vector for every chunk.
            std::vector<unsigned char> buffer(kChunk);

            RuntimeLog("full_memscan phase=%s begin scope=all_committed_readable_regions chunk=0x%zX safety_limit_gib=8",
                phase ? phase : "scan", static_cast<size_t>(kChunk));
            std::printf("[BETA-MEMSCAN] full process memory census started (%s). This is a one-shot read-only scan.\n",
                phase ? phase : "scan");
            std::fflush(stdout);

            while (cursor < maximum && stats.bytesRead < kSafetyByteLimit)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                    break;

                ++stats.regions;
                const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                const uintptr_t allocationBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
                const SIZE_T regionSize = mbi.RegionSize;
                const uintptr_t next = regionSize && regionBase <= maximum - regionSize
                    ? regionBase + regionSize : maximum;

                if (mbi.State == MEM_COMMIT && regionSize && IsReadableMemoryProtection(mbi.Protect))
                {
                    ++stats.readableRegions;
                    const std::string module = AllocationModuleName(allocationBase);
                    std::uint64_t regionBytesRead = 0;

                    for (SIZE_T offset = 0; offset < regionSize && stats.bytesRead < kSafetyByteLimit; )
                    {
                        const SIZE_T want = (std::min<SIZE_T>)(kChunk, regionSize - offset);
                        SIZE_T got = 0;
                        const uintptr_t chunkAddress = regionBase + offset;
                        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(chunkAddress),
                            buffer.data(), want, &got) || got == 0)
                        {
                            ++stats.readFailures;
                            offset += want;
                            continue;
                        }

                        stats.bytesRead += got;
                        regionBytesRead += got;
                        // ASCII strings.  Heap/private hits are especially useful for finding
                        // live Lobby/Party/session objects that do not exist in the mapped PE.
                        for (SIZE_T i = 0; i < got; )
                        {
                            const SIZE_T start = i;
                            while (i < got && buffer[i] >= 0x20 && buffer[i] <= 0x7E) ++i;
                            const SIZE_T len = i - start;
                            if (len >= 5 && len <= 512)
                            {
                                std::string text(reinterpret_cast<const char*>(buffer.data() + start), len);
                                std::string tags;
                                if (MemoryStringInteresting(text, tags))
                                {
                                    WriteFullMemoryStringHit(strings, phase, chunkAddress + start, mbi,
                                        module, "ascii", tags, text);
                                    ++stats.asciiHits;
                                }
                            }
                            if (i == start) ++i;
                        }

                        // UTF-16LE strings used by some platform/auth/frontend layers.
                        for (SIZE_T i = 0; i + 1 < got; )
                        {
                            const SIZE_T start = i;
                            std::string text;
                            while (i + 1 < got && buffer[i] >= 0x20 && buffer[i] <= 0x7E && buffer[i + 1] == 0)
                            {
                                text.push_back(static_cast<char>(buffer[i]));
                                i += 2;
                                if (text.size() > 512) break;
                            }
                            if (text.size() >= 5 && text.size() <= 512)
                            {
                                std::string tags;
                                if (MemoryStringInteresting(text, tags))
                                {
                                    WriteFullMemoryStringHit(strings, phase, chunkAddress + start, mbi,
                                        module, "utf16le", tags, text);
                                    ++stats.wideHits;
                                }
                            }
                            if (i == start) ++i;
                        }

                        // Find live pointers to the exact recovered Beta globals/functions.
                        // These are valuable for locating owning structs, callback tables and
                        // initialization objects without detouring hot game code.
                        for (SIZE_T i = 0; i + sizeof(std::uint64_t) <= got; i += sizeof(std::uint64_t))
                        {
                            std::uint64_t value = 0;
                            std::memcpy(&value, buffer.data() + i, sizeof(value));
                            // Almost every 64-bit word is not a pointer into the Beta image.
                            // Reject those with two cheap comparisons before touching the hash table.
                            if (value < static_cast<std::uint64_t>(gameBase) || value >= gameEnd) continue;
                            const auto it = pointerTargets.find(value);
                            if (it == pointerTargets.end()) continue;
                            const KnownMemoryTarget& target = *it->second;
                            pointers << '"' << JsonEscape(phase ? phase : "scan") << "\",0x"
                                << std::hex << std::uppercase << (chunkAddress + i) << ",0x" << regionBase
                                << ',' << MemoryTypeName(mbi.Type) << ",0x" << mbi.Protect << ",\""
                                << JsonEscape(module) << "\",pointer,\"" << target.name << "\",0x"
                                << target.address << ",0x" << target.rva << "\n";
                            ++stats.pointerHits;
                        }

                        // Also locate stored 32-bit RVAs.  The Beta uses RVA/offset tables in
                        // places where a normal absolute-pointer scan would miss the owner.
                        for (SIZE_T i = 0; i + sizeof(std::uint32_t) <= got; i += sizeof(std::uint32_t))
                        {
                            std::uint32_t value = 0;
                            std::memcpy(&value, buffer.data() + i, sizeof(value));
                            // Reject ordinary data before the hash lookup.  Valid recovered
                            // RVAs must point inside the exact Open Beta image.
                            if (value >= t9_addresses::BetaFingerprint.imageSize) continue;
                            const auto it = rvaTargets.find(value);
                            if (it == rvaTargets.end()) continue;
                            const KnownMemoryTarget& target = *it->second;
                            pointers << '"' << JsonEscape(phase ? phase : "scan") << "\",0x"
                                << std::hex << std::uppercase << (chunkAddress + i) << ",0x" << regionBase
                                << ',' << MemoryTypeName(mbi.Type) << ",0x" << mbi.Protect << ",\""
                                << JsonEscape(module) << "\",rva32,\"" << target.name << "\",0x"
                                << target.address << ",0x" << target.rva << "\n";
                            ++stats.rvaHits;
                        }

                        offset += got;
                        if (got < want) offset += (want - got);

                        if (stats.bytesRead >= nextProgress)
                        {
                            const auto progressMiB = static_cast<unsigned long long>(stats.bytesRead / (1024ull * 1024ull));
                            const auto stringHits = static_cast<unsigned long long>(stats.asciiHits + stats.wideHits);
                            const auto refHits = static_cast<unsigned long long>(stats.pointerHits + stats.rvaHits);
                            RuntimeLog("full_memscan phase=%s progress_mib=%llu regions=%llu strings=%llu refs=%llu failures=%llu",
                                phase ? phase : "scan", progressMiB,
                                static_cast<unsigned long long>(stats.readableRegions),
                                stringHits, refHits,
                                static_cast<unsigned long long>(stats.readFailures));
                            // Flush partial results so a logs ZIP captured while the scan is still
                            // running contains the pointer/reference rows already discovered.
                            regions.flush();
                            strings.flush();
                            pointers.flush();
                            std::printf("[BETA-MEMSCAN] progress: %llu MiB | regions=%llu strings=%llu refs=%llu failures=%llu\n",
                                progressMiB,
                                static_cast<unsigned long long>(stats.readableRegions),
                                stringHits, refHits,
                                static_cast<unsigned long long>(stats.readFailures));
                            std::fflush(stdout);
                            nextProgress += kProgressStep;
                            Sleep(1);
                        }
                    }

                    regions << "0x" << std::hex << std::uppercase << regionBase << ",0x" << regionSize
                        << ",0x" << allocationBase << ',' << MemoryTypeName(mbi.Type) << ",0x"
                        << mbi.Protect << ",\"" << JsonEscape(module) << "\"," << std::dec
                        << regionBytesRead << "\n";
                }

                if (next <= cursor) break;
                cursor = next;
            }

            summary << "phase=" << (phase ? phase : "scan") << "\n"
                << "regions=" << stats.regions << "\n"
                << "readable_regions=" << stats.readableRegions << "\n"
                << "bytes_read=" << stats.bytesRead << "\n"
                << "ascii_keyword_hits=" << stats.asciiHits << "\n"
                << "utf16_keyword_hits=" << stats.wideHits << "\n"
                << "known_pointer_hits=" << stats.pointerHits << "\n"
                << "known_rva_hits=" << stats.rvaHits << "\n"
                << "read_failures=" << stats.readFailures << "\n";

            RuntimeLog("full_memscan phase=%s complete bytes=%llu regions=%llu/%llu ascii=%llu wide=%llu ptr=%llu rva=%llu failures=%llu",
                phase ? phase : "scan",
                static_cast<unsigned long long>(stats.bytesRead),
                static_cast<unsigned long long>(stats.readableRegions),
                static_cast<unsigned long long>(stats.regions),
                static_cast<unsigned long long>(stats.asciiHits),
                static_cast<unsigned long long>(stats.wideHits),
                static_cast<unsigned long long>(stats.pointerHits),
                static_cast<unsigned long long>(stats.rvaHits),
                static_cast<unsigned long long>(stats.readFailures));
            std::printf("[BETA-MEMSCAN] complete: %.1f MiB read, strings=%llu, known refs=%llu.\n",
                static_cast<double>(stats.bytesRead) / (1024.0 * 1024.0),
                static_cast<unsigned long long>(stats.asciiHits + stats.wideHits),
                static_cast<unsigned long long>(stats.pointerHits + stats.rvaHits));
            std::fflush(stdout);
            return stats;
        }

        static DWORD WINAPI FullMemoryScanThread(LPVOID parameter)
        {
            std::unique_ptr<FullMemoryScanRequest> request(reinterpret_cast<FullMemoryScanRequest*>(parameter));
            const std::string phase = request ? request->phase : "scan";
            Sleep(3000);
            RunFullMemoryCensus(phase.c_str());
            g_fullMemoryScanRunning.store(false, std::memory_order_release);
            return 0;
        }

        static bool StartFullMemoryScanAsync(const char* phase)
        {
            if (g_fullMemoryScanRunning.exchange(true, std::memory_order_acq_rel))
            {
                RuntimeLog("full_memscan request_skipped phase=%s reason=scan_already_running",
                    phase ? phase : "scan");
                return false;
            }

            auto* request = new (std::nothrow) FullMemoryScanRequest{};
            if (!request)
            {
                g_fullMemoryScanRunning.store(false, std::memory_order_release);
                return false;
            }
            request->phase = phase ? phase : "scan";
            HANDLE thread = CreateThread(nullptr, 0, &FullMemoryScanThread, request, 0, nullptr);
            if (!thread)
            {
                delete request;
                g_fullMemoryScanRunning.store(false, std::memory_order_release);
                RuntimeLog("full_memscan create_thread_failed phase=%s error=%lu",
                    phase ? phase : "scan", static_cast<unsigned long>(GetLastError()));
                return false;
            }
            CloseHandle(thread);
            return true;
        }


        // v16 focused runtime probe.
        //
        // The v15 process census proved that the useful frontend/lobby material
        // is already unpacked into MEM_PRIVATE allocations. Scanning every
        // printable string in the entire process was much slower than necessary
        // and the "known ref" pass could see the scanner's own bookkeeping.
        //
        // This probe is deliberately read-only and much narrower:
        //   * MEM_PRIVATE only
        //   * exact high-value Lobby/LUI/session/network markers
        //   * printable neighborhoods around each live hit
        //   * absolute pointer references to the live strings (and likely
        //     Lua TString header offsets immediately before the characters)
        //
        // It never hooks or patches game code.
        struct LobbyProbeMarker
        {
            const char* name;
            const char* text;
        };

        static const LobbyProbeMarker kLobbyProbeMarkers[] =
        {
            { "SESSION_VALIDATE", "OnValidateSessionModeChangeAllowed" },
            { "SESSION_VALIDATE_LOWER", "onvalidatesessionmodechangeallowed" },
            { "SESSION_CHANGE", "OnSessionModeChange" },
            { "SESSION_START", "OnSessionStart" },
            { "SESSION_END", "OnSessionEnd" },
            { "NETWORK_MODE_CHANGED", "OnNetworkModeChanged" },
            { "LOBBY_NETWORK_MODE_MODEL", "lobbyRoot.lobbyNetworkMode" },
            { "FAILED_DW_MODEL", "lobbyRoot.failedDemonwareConnection" },
            { "BEGIN_PLAY_MODEL", "lobbyRoot.beginPlay" },
            { "SET_SESSION_MODE", "setSessionMode" },
            { "GET_SESSION_MODE", "getSessionMode" },
            { "GET_LAN_MENU", "GetLanMenu" },
            { "GET_LAN_SELECT_MENU", "GetLanSelectMenu" },
            { "GET_ONLINE_CUSTOM_MENU", "GetOnlineCustomMenu" },
            { "GET_ONLINE_SELECT_MENU", "GetOnlineSelectMenu" },
            { "GET_LOBBY_MENU_ID", "GetLobbyMenuIDByName" },
            { "GET_LOBBY_MENU", "GetLobbyMenuByName" },
            { "LOBBY_DATA", "LobbyData" },
            { "SESSION_CLIENTS", "sessionClients" },
            { "GAME_LOBBY_ACTIVE", "isGameLobbyActive" },
            { "PRIVATE_P2P_REQUEST", "new private p2p lobby requested" },
            { "RUN_LOBBY_TEST", "RunLobbyTest" },
            { "CONNECTION_STATE", "connectionState" },
            { "SIGNED_IN_DW", "signedInDW" },
            { "MP_OFFLINE", "MP Offline" },
            { "NO_MULTIPLAYER", "No Multiplayer" },
            { "NETWORK_MODE_MISMATCH", "NetworkModeMismatch" },
            { "NETWORK_MODE", "networkMode" },
            { "LOBBY_NETWORK_MODE", "lobbyNetworkMode" },
            { "SESSION_MODE", "sessionMode" },
            { "SESSION_STATUS", "sessionStatus" },
            { "SESSION_ACTIVE", "sessionActive" },
            { "LOBBY_CHANGE", "lobby_change" },
            { "LOBBY_LUA", "lua/Lobby/Lobby.lua" },
            { "ON_DW_DISCONNECT", "OnDWDisconnect" },
            { "ON_DISCONNECT", "OnDisconnect" }
        };

        struct LobbyProbeHit
        {
            uintptr_t address = 0;
            uintptr_t regionBase = 0;
            SIZE_T regionSize = 0;
            DWORD protect = 0;
            std::size_t markerIndex = 0;
        };

        struct LobbyProbePointerTarget
        {
            uintptr_t value = 0;
            std::size_t hitIndex = 0;
            unsigned headerBytes = 0;
        };

        struct LobbyProbeStats
        {
            std::uint64_t regions = 0;
            std::uint64_t readablePrivateRegions = 0;
            std::uint64_t bytesRead = 0;
            std::uint64_t markerHits = 0;
            std::uint64_t pointerRefs = 0;
            std::uint64_t readFailures = 0;
        };

        struct LobbyProbeRequest
        {
            std::string phase;
        };

        static bool AddressInsideRange(uintptr_t address, uintptr_t begin, SIZE_T size)
        {
            if (!begin || !size || address < begin)
                return false;
            return static_cast<std::uint64_t>(address - begin) < static_cast<std::uint64_t>(size);
        }

        static void DumpLobbyProbeContext(std::ofstream& out, const LobbyProbeHit& hit)
        {
            constexpr SIZE_T kBefore = 0x600;
            constexpr SIZE_T kAfter = 0x1200;
            const uintptr_t regionEnd = hit.regionBase + hit.regionSize;
            const uintptr_t start = hit.address > hit.regionBase + kBefore
                ? hit.address - kBefore : hit.regionBase;
            const uintptr_t wantedEnd = hit.address <= (~static_cast<uintptr_t>(0)) - kAfter
                ? hit.address + kAfter : regionEnd;
            const uintptr_t end = (std::min)(regionEnd, wantedEnd);
            if (end <= start)
                return;

            const SIZE_T size = static_cast<SIZE_T>(end - start);
            std::vector<unsigned char> bytes(size);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(start), bytes.data(), size, &got) || got == 0)
                return;

            out << "\n=== " << kLobbyProbeMarkers[hit.markerIndex].name
                << " @ 0x" << std::hex << std::uppercase << hit.address
                << " | region=0x" << hit.regionBase
                << "+0x" << hit.regionSize << " ===\n";

            std::size_t i = 0;
            std::size_t rows = 0;
            while (i < got && rows < 220)
            {
                while (i < got && (bytes[i] < 0x20 || bytes[i] > 0x7E))
                    ++i;
                const std::size_t begin = i;
                while (i < got && bytes[i] >= 0x20 && bytes[i] <= 0x7E)
                    ++i;
                const std::size_t length = i - begin;
                if (length < 4)
                    continue;

                const std::size_t keep = (std::min<std::size_t>)(length, 320);
                std::string value(reinterpret_cast<const char*>(bytes.data() + begin), keep);
                out << "0x" << std::hex << std::uppercase << (start + begin)
                    << "  " << value;
                if (keep < length)
                    out << "...";
                out << "\n";
                ++rows;
            }
        }


        enum class InitSignatureResolve
        {
            Match,
            FirstCall,
            RipByteAt2Len7
        };

        struct InitSignatureSpec
        {
            const char* name;
            const char* pattern;
            InitSignatureResolve resolve;
        };

        static const InitSignatureSpec kInitSignatureSpecs[] =
        {
            { "SetScreen/transition",
              "48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 54 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 27 0F B6 FA 48 63 D9 8B 05 ?? ?? ?? ??",
              InitSignatureResolve::Match },
            { "LobbyBase_SetNetworkMode/initB",
              "40 53 48 83 EC 20 8B D9 89 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ??",
              InitSignatureResolve::Match },
            { "Com_SessionMode_SetMode/initA",
              "8B 05 ?? ?? ?? ?? 8B D0 33 D1 83 E2 0F 33 C2 89 05 ?? ?? ?? ?? C3",
              InitSignatureResolve::Match },
            { "config[0]",
              "80 3D ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B 3F 48 8B C8 48 0F 45 3D ?? ?? ?? ?? E8 ?? ?? ?? ??",
              InitSignatureResolve::RipByteAt2Len7 },
            { "config[1]",
              "80 3D ?? ?? ?? ?? ?? 75 58 33 C9 48 89 5C 24 ??",
              InitSignatureResolve::RipByteAt2Len7 },
            { "LobbySession_GetControllingLobbySession",
              "E8 ?? ?? ?? ?? 48 8B D7 8B C8 E8 ?? ?? ?? ?? 48 8B 7C 24 ?? E8 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ??",
              InitSignatureResolve::FirstCall },
            { "LobbyData_SetMap",
              "E8 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ?? 84 C0 74 13 8B CB E8 ?? ?? ?? ?? 8B C8 BA ?? ?? ?? ??",
              InitSignatureResolve::FirstCall },
            { "LobbyData_SetGameType",
              "E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 2D 33 D2 41 B8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 D2 41 B8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??",
              InitSignatureResolve::FirstCall }
        };

        static std::vector<int> ParseInitSignature(const char* pattern)
        {
            std::vector<int> bytes;
            if (!pattern) return bytes;

            std::istringstream input(pattern);
            std::string token;
            while (input >> token)
            {
                if (token == "?" || token == "??")
                {
                    bytes.push_back(-1);
                    continue;
                }

                char* end = nullptr;
                const unsigned long value = std::strtoul(token.c_str(), &end, 16);
                if (!end || *end != '\0' || value > 0xFFul)
                {
                    bytes.clear();
                    return bytes;
                }
                bytes.push_back(static_cast<int>(value));
            }
            return bytes;
        }

        static bool InitSignatureMatches(const unsigned char* data, SIZE_T available,
            const std::vector<int>& pattern)
        {
            if (!data || pattern.empty() || available < pattern.size())
                return false;
            for (std::size_t i = 0; i < pattern.size(); ++i)
            {
                if (pattern[i] >= 0 && data[i] != static_cast<unsigned char>(pattern[i]))
                    return false;
            }
            return true;
        }

        static uintptr_t ResolveInitSignatureTarget(uintptr_t match,
            InitSignatureResolve resolve)
        {
            if (!match)
                return 0;

            if (resolve == InitSignatureResolve::Match)
                return match;

            int32_t displacement = 0;
            if (resolve == InitSignatureResolve::FirstCall)
            {
                if (!ReadBytes(match + 1, &displacement, sizeof(displacement)))
                    return 0;
                return match + 5 + static_cast<intptr_t>(displacement);
            }

            if (resolve == InitSignatureResolve::RipByteAt2Len7)
            {
                if (!ReadBytes(match + 2, &displacement, sizeof(displacement)))
                    return 0;
                return match + 7 + static_cast<intptr_t>(displacement);
            }

            return 0;
        }

        static void RunBetaInitializationSignatureProbe(const char* phase,
            const std::string& outputPrefix)
        {
            ImageLayout image{};
            if (!ReadImageLayout(GetModuleHandleW(nullptr), image))
            {
                RuntimeLog("init_signature_probe phase=%s result=image_layout_failed",
                    phase ? phase : "scan");
                return;
            }

            struct ParsedSpec
            {
                const InitSignatureSpec* spec = nullptr;
                std::vector<int> bytes;
            };

            std::vector<ParsedSpec> specs;
            specs.reserve(sizeof(kInitSignatureSpecs) / sizeof(kInitSignatureSpecs[0]));
            std::size_t maxPattern = 0;
            for (const auto& spec : kInitSignatureSpecs)
            {
                ParsedSpec parsed{};
                parsed.spec = &spec;
                parsed.bytes = ParseInitSignature(spec.pattern);
                maxPattern = (std::max)(maxPattern, parsed.bytes.size());
                if (!parsed.bytes.empty())
                    specs.push_back(std::move(parsed));
            }
            if (specs.empty())
                return;

            std::ofstream out(outputPrefix + "_init_signatures.csv", std::ios::trunc);
            if (!out)
            {
                RuntimeLog("init_signature_probe phase=%s result=open_output_failed",
                    phase ? phase : "scan");
                return;
            }
            out << "phase,name,match_address,match_rva,resolved_address,resolved_rva,current_byte,identity_match\n";

            constexpr SIZE_T kChunk = 4u * 1024u * 1024u;
            std::vector<unsigned char> buffer(kChunk + maxPattern + 16);
            std::vector<unsigned> matchesPerSpec(specs.size(), 0u);
            std::vector<std::vector<std::size_t>> firstByteBuckets(256);
            for (std::size_t i = 0; i < specs.size(); ++i)
            {
                if (!specs[i].bytes.empty() && specs[i].bytes[0] >= 0)
                    firstByteBuckets[static_cast<unsigned char>(specs[i].bytes[0])].push_back(i);
            }
            const uintptr_t imageEnd = image.base + image.imageSize;
            const auto& recovered = t9_addresses::OpenBetaRecovered;

            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;

                const SIZE_T sectionSize = static_cast<SIZE_T>((std::min<DWORD>)(
                    section.virtualSize ? section.virtualSize : section.rawSize,
                    image.imageSize - section.rva));
                if (!sectionSize)
                    continue;

                for (SIZE_T offset = 0; offset < sectionSize; offset += kChunk)
                {
                    const SIZE_T nominal = (std::min<SIZE_T>)(kChunk, sectionSize - offset);
                    const SIZE_T want = (std::min<SIZE_T>)(
                        nominal + maxPattern, sectionSize - offset);
                    SIZE_T got = 0;
                    const uintptr_t chunkAddress = image.base + section.rva + offset;
                    if (!ReadProcessMemory(GetCurrentProcess(),
                        reinterpret_cast<const void*>(chunkAddress), buffer.data(), want, &got) || !got)
                        continue;

                    for (SIZE_T i = 0; i < nominal; ++i)
                    {
                        const auto& bucket = firstByteBuckets[buffer[i]];
                        if (bucket.empty())
                            continue;

                        for (std::size_t bucketIndex = 0; bucketIndex < bucket.size(); ++bucketIndex)
                        {
                            const std::size_t specIndex = bucket[bucketIndex];
                            if (matchesPerSpec[specIndex] >= 24)
                                continue;

                            const auto& parsed = specs[specIndex];
                            if (parsed.bytes.empty() || i + parsed.bytes.size() > got)
                                continue;
                            if (!InitSignatureMatches(buffer.data() + i, got - i, parsed.bytes))
                                continue;

                            const uintptr_t match = chunkAddress + i;
                            const uintptr_t resolved = ResolveInitSignatureTarget(
                                match, parsed.spec->resolve);
                            const bool resolvedInImage =
                                resolved >= image.base && resolved < imageEnd;
                            const std::uint64_t matchRva = match - image.base;
                            const std::uint64_t resolvedRva = resolvedInImage
                                ? resolved - image.base : 0;

                            int currentByte = -1;
                            if (parsed.spec->resolve == InitSignatureResolve::RipByteAt2Len7 &&
                                resolved)
                            {
                                unsigned char value = 0;
                                if (ReadBytes(resolved, &value, sizeof(value)))
                                    currentByte = static_cast<int>(value);
                            }

                            bool identityMatch = false;
                            if (std::strcmp(parsed.spec->name, "SetScreen/transition") == 0)
                                identityMatch = resolved == image.base + recovered.transition;
                            else if (std::strcmp(parsed.spec->name, "LobbyBase_SetNetworkMode/initB") == 0)
                                identityMatch = resolved == image.base + recovered.initB;
                            else if (std::strcmp(parsed.spec->name, "Com_SessionMode_SetMode/initA") == 0)
                                identityMatch = resolved == image.base + recovered.initA;

                            out << '"' << JsonEscape(phase ? phase : "scan") << "\",\""
                                << parsed.spec->name << "\",0x" << std::hex << std::uppercase
                                << match << ",0x" << matchRva << ",0x" << resolved << ",0x"
                                << resolvedRva << ',';
                            if (currentByte >= 0)
                                out << "0x" << currentByte;
                            out << ',' << (identityMatch ? 1 : 0) << "\n";

                            if (identityMatch)
                            {
                                RuntimeLog("init_signature_identity name=%s rva=0x%llX confirmed=1",
                                    parsed.spec->name,
                                    static_cast<unsigned long long>(resolvedRva));
                                std::printf("[BETA-INIT-SIG] confirmed %s at RVA 0x%llX.\n",
                                    parsed.spec->name,
                                    static_cast<unsigned long long>(resolvedRva));
                            }
                            else if (parsed.spec->resolve == InitSignatureResolve::RipByteAt2Len7)
                            {
                                RuntimeLog("init_signature_candidate name=%s match_rva=0x%llX target_rva=0x%llX value=%d",
                                    parsed.spec->name,
                                    static_cast<unsigned long long>(matchRva),
                                    static_cast<unsigned long long>(resolvedRva),
                                    currentByte);
                                std::printf("[BETA-INIT-SIG] %s candidate target RVA 0x%llX current=0x%02X (read-only).\n",
                                    parsed.spec->name,
                                    static_cast<unsigned long long>(resolvedRva),
                                    currentByte >= 0 ? currentByte : 0xFF);
                            }
                            else if (parsed.spec->resolve == InitSignatureResolve::FirstCall &&
                                     resolvedInImage)
                            {
                                RuntimeLog("init_signature_candidate name=%s match_rva=0x%llX target_rva=0x%llX",
                                    parsed.spec->name,
                                    static_cast<unsigned long long>(matchRva),
                                    static_cast<unsigned long long>(resolvedRva));
                                std::printf("[BETA-INIT-SIG] candidate %s at RVA 0x%llX (read-only).\n",
                                    parsed.spec->name,
                                    static_cast<unsigned long long>(resolvedRva));
                            }

                            ++matchesPerSpec[specIndex];
                        }
                    }

                }
            }

            out.flush();
            RuntimeLog("init_signature_probe phase=%s complete", phase ? phase : "scan");
            std::fflush(stdout);
        }

        static LobbyProbeStats RunLobbyRuntimeProbe(const char* phase)
        {
            LobbyProbeStats stats{};
            const std::string safePhase = SanitizeFileToken(phase ? phase : "scan");
            const std::string dir = AnalysisDir();
            const std::string prefix = dir + "\\lobby_runtime_" + safePhase;

            // First validate/discover the Beta-native initialization chain from
            // decrypted executable memory. This is read-only and also searches
            // for the two config flags plus controlling-lobby/map helpers used
            // by the older SetMode flow.
            RunBetaInitializationSignatureProbe(phase, prefix);

            constexpr SIZE_T kChunk = 4u * 1024u * 1024u;
            constexpr SIZE_T kOverlap = 128u;
            constexpr std::uint64_t kSafetyByteLimit = 6ull * 1024ull * 1024ull * 1024ull;
            constexpr std::size_t kMaxHits = 8192;
            constexpr std::size_t kMaxPointerRefs = 16384;

            unsigned char* buffer = reinterpret_cast<unsigned char*>(
                VirtualAlloc(nullptr, kChunk + kOverlap, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!buffer)
            {
                RuntimeLog("lobby_probe phase=%s result=buffer_alloc_failed error=%lu",
                    phase ? phase : "scan", static_cast<unsigned long>(GetLastError()));
                return stats;
            }
            const uintptr_t bufferBegin = reinterpret_cast<uintptr_t>(buffer);
            const SIZE_T bufferSize = kChunk + kOverlap;

            std::vector<LobbyProbeHit> hits;
            hits.reserve(4096);

            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            uintptr_t cursor = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
            const uintptr_t maximum = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

            RuntimeLog("lobby_probe phase=%s begin scope=MEM_PRIVATE exact_markers=%zu",
                phase ? phase : "scan",
                sizeof(kLobbyProbeMarkers) / sizeof(kLobbyProbeMarkers[0]));
            std::printf("[BETA-LOBBY] focused runtime probe started (%s): private-memory Lobby/LUI/session markers only.\n",
                phase ? phase : "scan");
            std::fflush(stdout);

            while (cursor < maximum && stats.bytesRead < kSafetyByteLimit && hits.size() < kMaxHits)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                    break;

                ++stats.regions;
                const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                const SIZE_T regionSize = mbi.RegionSize;
                const uintptr_t next = regionSize && regionBase <= maximum - regionSize
                    ? regionBase + regionSize : maximum;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    regionSize && IsReadableMemoryProtection(mbi.Protect))
                {
                    ++stats.readablePrivateRegions;

                    if (!AddressInsideRange(regionBase, bufferBegin, bufferSize))
                    {
                        for (SIZE_T offset = 0;
                             offset < regionSize && stats.bytesRead < kSafetyByteLimit && hits.size() < kMaxHits;
                             offset += kChunk)
                        {
                            const SIZE_T nominal = (std::min<SIZE_T>)(kChunk, regionSize - offset);
                            const SIZE_T remaining = regionSize - offset;
                            const SIZE_T want = (std::min<SIZE_T>)(nominal + kOverlap, remaining);
                            SIZE_T got = 0;
                            const uintptr_t chunkAddress = regionBase + offset;

                            if (!ReadProcessMemory(GetCurrentProcess(),
                                reinterpret_cast<const void*>(chunkAddress), buffer, want, &got) || got == 0)
                            {
                                ++stats.readFailures;
                                continue;
                            }

                            stats.bytesRead += got;

                            for (std::size_t markerIndex = 0;
                                 markerIndex < sizeof(kLobbyProbeMarkers) / sizeof(kLobbyProbeMarkers[0]);
                                 ++markerIndex)
                            {
                                const char* marker = kLobbyProbeMarkers[markerIndex].text;
                                const std::size_t markerLength = std::strlen(marker);
                                if (!markerLength || markerLength > got)
                                    continue;

                                const unsigned char first = static_cast<unsigned char>(marker[0]);
                                SIZE_T pos = 0;
                                while (pos + markerLength <= got)
                                {
                                    const void* found = std::memchr(buffer + pos, first, got - pos);
                                    if (!found)
                                        break;
                                    const SIZE_T local = static_cast<SIZE_T>(
                                        reinterpret_cast<const unsigned char*>(found) - buffer);
                                    if (local >= nominal)
                                        break;

                                    if (local + markerLength <= got &&
                                        std::memcmp(buffer + local, marker, markerLength) == 0)
                                    {
                                        const uintptr_t liveAddress = chunkAddress + local;
                                        if (!AddressInsideRange(liveAddress, bufferBegin, bufferSize))
                                        {
                                            hits.push_back({
                                                liveAddress,
                                                regionBase,
                                                regionSize,
                                                mbi.Protect,
                                                markerIndex
                                            });
                                            ++stats.markerHits;
                                            if (hits.size() >= kMaxHits)
                                                break;
                                        }
                                    }
                                    pos = local + 1;
                                }

                                if (hits.size() >= kMaxHits)
                                    break;
                            }
                        }
                    }
                }

                if (next <= cursor)
                    break;
                cursor = next;
            }

            std::sort(hits.begin(), hits.end(),
                [](const LobbyProbeHit& a, const LobbyProbeHit& b)
                {
                    if (a.address != b.address) return a.address < b.address;
                    return a.markerIndex < b.markerIndex;
                });
            hits.erase(std::unique(hits.begin(), hits.end(),
                [](const LobbyProbeHit& a, const LobbyProbeHit& b)
                {
                    return a.address == b.address && a.markerIndex == b.markerIndex;
                }), hits.end());
            stats.markerHits = hits.size();

            std::ofstream hitFile(prefix + "_hits.csv", std::ios::trunc);
            std::ofstream refFile(prefix + "_pointer_refs.csv", std::ios::trunc);
            std::ofstream contextFile(prefix + "_contexts.txt", std::ios::trunc);
            std::ofstream summaryFile(prefix + "_summary.txt", std::ios::trunc);
            if (!hitFile || !refFile || !contextFile || !summaryFile)
            {
                RuntimeLog("lobby_probe phase=%s result=open_output_failed",
                    phase ? phase : "scan");
                VirtualFree(buffer, 0, MEM_RELEASE);
                return stats;
            }

            hitFile << "phase,address,region_base,region_size,protect,marker,text\n";
            for (const auto& hit : hits)
            {
                const auto& marker = kLobbyProbeMarkers[hit.markerIndex];
                hitFile << '"' << JsonEscape(phase ? phase : "scan") << "\",0x"
                    << std::hex << std::uppercase << hit.address << ",0x"
                    << hit.regionBase << ",0x" << hit.regionSize << ",0x"
                    << hit.protect << ",\"" << marker.name << "\",\""
                    << JsonEscape(marker.text) << "\"\n";
            }
            hitFile.flush();

            std::vector<LobbyProbePointerTarget> targets;
            targets.reserve(hits.size() * 6);
            static const unsigned kHeaderOffsets[] = { 0u, 8u, 16u, 24u, 32u, 40u };
            for (std::size_t hitIndex = 0; hitIndex < hits.size(); ++hitIndex)
            {
                for (unsigned headerBytes : kHeaderOffsets)
                {
                    if (hits[hitIndex].address >= headerBytes)
                        targets.push_back({
                            hits[hitIndex].address - headerBytes,
                            hitIndex,
                            headerBytes
                        });
                }
            }
            std::sort(targets.begin(), targets.end(),
                [](const LobbyProbePointerTarget& a, const LobbyProbePointerTarget& b)
                {
                    if (a.value != b.value) return a.value < b.value;
                    if (a.hitIndex != b.hitIndex) return a.hitIndex < b.hitIndex;
                    return a.headerBytes < b.headerBytes;
                });

            refFile << "phase,slot_address,region_base,protect,target_value,marker,string_address,header_bytes\n";

            const uintptr_t hitVectorBegin = hits.empty() ? 0 : reinterpret_cast<uintptr_t>(hits.data());
            const SIZE_T hitVectorBytes = hits.size() * sizeof(LobbyProbeHit);
            const uintptr_t targetVectorBegin = targets.empty() ? 0 : reinterpret_cast<uintptr_t>(targets.data());
            const SIZE_T targetVectorBytes = targets.size() * sizeof(LobbyProbePointerTarget);
            const uintptr_t minimumTarget = targets.empty() ? 0 : targets.front().value;
            const uintptr_t maximumTarget = targets.empty() ? 0 : targets.back().value;

            cursor = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
            std::uint64_t pointerBytesRead = 0;
            while (!targets.empty() && cursor < maximum &&
                   pointerBytesRead < kSafetyByteLimit && stats.pointerRefs < kMaxPointerRefs)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                    break;

                const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                const SIZE_T regionSize = mbi.RegionSize;
                const uintptr_t next = regionSize && regionBase <= maximum - regionSize
                    ? regionBase + regionSize : maximum;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    regionSize && IsReadableMemoryProtection(mbi.Protect) &&
                    !AddressInsideRange(regionBase, bufferBegin, bufferSize))
                {
                    for (SIZE_T offset = 0;
                         offset < regionSize && pointerBytesRead < kSafetyByteLimit &&
                         stats.pointerRefs < kMaxPointerRefs;
                         offset += kChunk)
                    {
                        const SIZE_T want = (std::min<SIZE_T>)(kChunk, regionSize - offset);
                        SIZE_T got = 0;
                        const uintptr_t chunkAddress = regionBase + offset;
                        if (!ReadProcessMemory(GetCurrentProcess(),
                            reinterpret_cast<const void*>(chunkAddress), buffer, want, &got) || got == 0)
                        {
                            ++stats.readFailures;
                            continue;
                        }
                        pointerBytesRead += got;

                        for (SIZE_T i = 0; i + sizeof(std::uint64_t) <= got; i += sizeof(std::uint64_t))
                        {
                            const uintptr_t slotAddress = chunkAddress + i;
                            if (AddressInsideRange(slotAddress, hitVectorBegin, hitVectorBytes) ||
                                AddressInsideRange(slotAddress, targetVectorBegin, targetVectorBytes) ||
                                AddressInsideRange(slotAddress, bufferBegin, bufferSize))
                                continue;

                            std::uint64_t raw = 0;
                            std::memcpy(&raw, buffer + i, sizeof(raw));
                            const uintptr_t value = static_cast<uintptr_t>(raw);
                            if (value < minimumTarget || value > maximumTarget)
                                continue;

                            const auto it = std::lower_bound(targets.begin(), targets.end(), value,
                                [](const LobbyProbePointerTarget& target, uintptr_t candidate)
                                {
                                    return target.value < candidate;
                                });
                            if (it == targets.end() || it->value != value)
                                continue;

                            for (auto jt = it;
                                 jt != targets.end() && jt->value == value &&
                                 stats.pointerRefs < kMaxPointerRefs;
                                 ++jt)
                            {
                                const LobbyProbeHit& hit = hits[jt->hitIndex];
                                const LobbyProbeMarker& marker = kLobbyProbeMarkers[hit.markerIndex];
                                refFile << '"' << JsonEscape(phase ? phase : "scan") << "\",0x"
                                    << std::hex << std::uppercase << slotAddress << ",0x"
                                    << regionBase << ",0x" << mbi.Protect << ",0x"
                                    << value << ",\"" << marker.name << "\",0x"
                                    << hit.address << ',' << std::dec << jt->headerBytes << "\n";
                                ++stats.pointerRefs;
                            }
                        }
                    }
                }

                if (next <= cursor)
                    break;
                cursor = next;
            }
            refFile.flush();

            std::vector<unsigned> contextsPerMarker(
                sizeof(kLobbyProbeMarkers) / sizeof(kLobbyProbeMarkers[0]), 0u);
            std::size_t totalContexts = 0;
            for (const auto& hit : hits)
            {
                if (totalContexts >= 96)
                    break;
                unsigned& count = contextsPerMarker[hit.markerIndex];
                if (count >= 4)
                    continue;
                DumpLobbyProbeContext(contextFile, hit);
                ++count;
                ++totalContexts;
            }
            contextFile.flush();

            summaryFile
                << "phase=" << (phase ? phase : "scan") << "\n"
                << "scope=MEM_PRIVATE\n"
                << "marker_count=" << (sizeof(kLobbyProbeMarkers) / sizeof(kLobbyProbeMarkers[0])) << "\n"
                << "regions_seen=" << stats.regions << "\n"
                << "readable_private_regions=" << stats.readablePrivateRegions << "\n"
                << "marker_scan_bytes=" << stats.bytesRead << "\n"
                << "marker_hits=" << stats.markerHits << "\n"
                << "pointer_refs=" << stats.pointerRefs << "\n"
                << "read_failures=" << stats.readFailures << "\n"
                << "note=read-only focused Lobby/LUI runtime probe; exhaustive full-memory census remains manual via /beta bigscan\n";
            summaryFile.flush();

            RuntimeLog("lobby_probe phase=%s complete bytes=%llu hits=%llu pointer_refs=%llu failures=%llu",
                phase ? phase : "scan",
                static_cast<unsigned long long>(stats.bytesRead),
                static_cast<unsigned long long>(stats.markerHits),
                static_cast<unsigned long long>(stats.pointerRefs),
                static_cast<unsigned long long>(stats.readFailures));
            std::printf("[BETA-LOBBY] probe complete: %.1f MiB private memory, markers=%llu, pointer refs=%llu, failures=%llu.\n",
                static_cast<double>(stats.bytesRead) / (1024.0 * 1024.0),
                static_cast<unsigned long long>(stats.markerHits),
                static_cast<unsigned long long>(stats.pointerRefs),
                static_cast<unsigned long long>(stats.readFailures));
            std::fflush(stdout);

            VirtualFree(buffer, 0, MEM_RELEASE);
            return stats;
        }

        static DWORD WINAPI LobbyRuntimeProbeThread(LPVOID parameter)
        {
            std::unique_ptr<LobbyProbeRequest> request(reinterpret_cast<LobbyProbeRequest*>(parameter));
            const std::string phase = request ? request->phase : "scan";
            Sleep(1500);
            RunLobbyRuntimeProbe(phase.c_str());
            g_lobbyRuntimeProbeRunning.store(false, std::memory_order_release);
            return 0;
        }

        static bool StartLobbyRuntimeProbeAsync(const char* phase)
        {
            if (g_lobbyRuntimeProbeRunning.exchange(true, std::memory_order_acq_rel))
            {
                RuntimeLog("lobby_probe request_skipped phase=%s reason=probe_already_running",
                    phase ? phase : "scan");
                return false;
            }

            auto* request = new (std::nothrow) LobbyProbeRequest{};
            if (!request)
            {
                g_lobbyRuntimeProbeRunning.store(false, std::memory_order_release);
                return false;
            }
            request->phase = phase ? phase : "scan";

            HANDLE thread = CreateThread(nullptr, 0, &LobbyRuntimeProbeThread, request, 0, nullptr);
            if (!thread)
            {
                delete request;
                g_lobbyRuntimeProbeRunning.store(false, std::memory_order_release);
                RuntimeLog("lobby_probe create_thread_failed phase=%s error=%lu",
                    phase ? phase : "scan", static_cast<unsigned long>(GetLastError()));
                return false;
            }
            CloseHandle(thread);
            return true;
        }

        static DWORD WINAPI BetaScannerAutoThread(LPVOID)
        {
            // The research scanner is read-only, so it can begin immediately
            // once the exact Open Beta profile is active. The recovered ready
            // byte is only a gate for calling game/frontend functions.
            beta_research::StartStateMonitor();
            beta_research::StartAutomatic("launch");
            StartMultiplayerScanAsync("launch");

            // Keep launch scanning read-only and single-shot. Repeated full-image
            // refresh passes are unnecessary for the current click-path test and
            // made it harder to distinguish scanner activity from game startup.
            g_betaScannerAutoThreadStarted.store(false, std::memory_order_release);
            return 0;
        }

        static void StartBetaScannerAutoRun()
        {
            if (g_betaScannerAutoThreadStarted.exchange(true, std::memory_order_acq_rel))
                return;

            HANDLE thread = CreateThread(nullptr, 0, &BetaScannerAutoThread, nullptr, 0, nullptr);
            if (!thread)
            {
                g_betaScannerAutoThreadStarted.store(false, std::memory_order_release);
                RuntimeLog("scanner_autorun=create_thread_failed error=%lu",
                    static_cast<unsigned long>(GetLastError()));
                return;
            }

            CloseHandle(thread);
            RuntimeLog("scanner_autorun=started mode=beta_frontend_gate_graph_internal_state_only_no_generic_input_hooks");
            std::printf("[BETA-SCAN] automatic Beta frontend/disconnect/fence scanner started at launch; generic mouse/keyboard click tracing is disabled.\n");
            std::fflush(stdout);
        }

        static uintptr_t GameBase()
        {
            return reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        }

        static bool IsCommitted(uintptr_t address, size_t size, bool executable)
        {
            if (!address || !size) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
                return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
                return false;
            const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (address > regionEnd || size > regionEnd - address)
                return false;
            if (!executable) return true;
            const DWORD p = mbi.Protect & 0xFFu;
            return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                   p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        template <typename T>
        static bool ReadValue(uintptr_t address, T& value)
        {
            return IsCommitted(address, sizeof(T), false) && ReadBytes(address, &value, sizeof(T));
        }

        static bool WriteProtected(uintptr_t address, const void* data, size_t size)
        {
            if (!address || !data || !size || !IsCommitted(address, size, false))
                return false;

            DWORD oldProtect = 0;
            if (!VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect))
                return false;
            std::memcpy(reinterpret_cast<void*>(address), data, size);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<const void*>(address), size);
            DWORD ignored = 0;
            VirtualProtect(reinterpret_cast<void*>(address), size, oldProtect, &ignored);
            return true;
        }

        template <typename T>
        static bool WriteValue(uintptr_t address, const T& value)
        {
            return WriteProtected(address, &value, sizeof(value));
        }

        static bool RestoreLegacyTraceDetours(uintptr_t base)
        {
            // A previous Beta trace build installed 5-byte E9 detours on these
            // four extremely hot engine functions. If one of those detours is
            // still being installed by an older/stale component, remove it
            // before the recovered bootstrap or passive scanner can use the
            // functions. This is exact-build-only and only writes when the
            // current first byte is E9.
            struct Patch
            {
                const char* name;
                uintptr_t rva;
                unsigned char original[5];
            };

            const auto& r = t9_addresses::OpenBetaRecovered;
            const Patch patches[] =
            {
                { "Command/Cbuf",          r.command,    { 0x48, 0x89, 0x5C, 0x24, 0x08 } },
                { "SetScreen/transition",      r.transition, { 0x48, 0x89, 0x5C, 0x24, 0x18 } },
                { "Com_SessionMode_SetMode/initA",     r.initA,      { 0x8B, 0x05, 0x62, 0xAD, 0x67 } },
                { "LobbyBase_SetNetworkMode/initB", r.initB,      { 0x40, 0x53, 0x48, 0x83, 0xEC } },
            };

            bool clean = true;
            for (const auto& patch : patches)
            {
                unsigned char current[5]{};
                const uintptr_t address = base + patch.rva;
                if (!ReadBytes(address, current, sizeof(current)))
                {
                    RuntimeLog("nohook_guard name=%s result=read_failed rva=0x%llX",
                        patch.name, static_cast<unsigned long long>(patch.rva));
                    clean = false;
                    continue;
                }

                if (current[0] != 0xE9)
                    continue;

                const bool restored = WriteProtected(address, patch.original, sizeof(patch.original));
                RuntimeLog("nohook_guard name=%s result=%s rva=0x%llX old=%02X %02X %02X %02X %02X",
                    patch.name, restored ? "restored_legacy_E9" : "restore_failed",
                    static_cast<unsigned long long>(patch.rva),
                    current[0], current[1], current[2], current[3], current[4]);
                std::printf("[BETA-FIX] %s legacy trace detour: %s\n",
                    patch.name, restored ? "REMOVED" : "REMOVE FAILED");
                clean = clean && restored;
            }

            std::fflush(stdout);
            return clean;
        }

        static bool ExactBetaLayout(uintptr_t base)
        {
            if (!base) return false;
            const BuildInfo info = DetectCurrentBuild();
            return info.kind == BuildKind::OpenBeta &&
                   info.timestamp == t9_addresses::BetaFingerprint.timestamp &&
                   info.imageSize == t9_addresses::BetaFingerprint.imageSize &&
                   info.entryPointRva == t9_addresses::BetaFingerprint.entryPointRva;
        }

        static bool ValidateRecoveredTargets(uintptr_t base)
        {
            const auto& r = t9_addresses::OpenBetaRecovered;
            const uintptr_t executableTargets[] = {
                base + r.command,
                base + r.transition,
                base + r.initA,
                base + r.initB,
                base + r.usernameContext,
                base + r.setUsername
            };
            for (uintptr_t address : executableTargets)
            {
                if (!IsCommitted(address, 1, true))
                    return false;
            }

            const uintptr_t dataTargets[] = {
                base + r.readyByte,
                base + r.stateA,
                base + r.stateB,
                base + r.stateC,
                base + r.forceReadyFlag,
                base + r.endpointA,
                base + r.endpointB,
                base + r.authManagerSlot
            };
            for (uintptr_t address : dataTargets)
            {
                if (!IsCommitted(address, 1, false))
                    return false;
            }
            return true;
        }

        static bool SafeCommand(CommandFn fn, int controller, const char* text)
        {
            if (!fn || !text) return false;
            __try
            {
                fn(controller, text);
                RuntimeLog("event=command controller=%d text=%s", controller, text);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                RuntimeLog("event=command_fault controller=%d text=%s code=0x%08lX",
                    controller, text, static_cast<unsigned long>(GetExceptionCode()));
                return false;
            }
        }

        static bool SafeTransition(TransitionFn fn, int state, int arg)
        {
            if (!fn) return false;
            __try
            {
                fn(state, arg);
                RuntimeLog("event=SetScreen/transition screen=0x%X arg=%d", state, arg);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                RuntimeLog("event=SetScreen/transition_fault screen=0x%X code=0x%08lX",
                    state, static_cast<unsigned long>(GetExceptionCode()));
                return false;
            }
        }

        static bool SafeInit(InitFn fn, const char* name, int value = 1)
        {
            if (!fn) return false;
            __try
            {
                fn(value);
                RuntimeLog("event=%s arg=%d", name, value);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                RuntimeLog("event=%s_fault arg=%d code=0x%08lX", name, value,
                    static_cast<unsigned long>(GetExceptionCode()));
                return false;
            }
        }

        static void LogRecoveredInitSnapshot(uintptr_t base, const char* stage)
        {
            if (!base || !stage) return;
            const auto& r = t9_addresses::OpenBetaRecovered;
            DWORD a = 0, b = 0, c = 0, forceReady = 0;
            std::uint8_t ready = 0;
            uintptr_t auth = 0;
            const bool okA = ReadValue(base + r.stateA, a);
            const bool okB = ReadValue(base + r.stateB, b);
            const bool okC = ReadValue(base + r.stateC, c);
            const bool okReady = ReadValue(base + r.readyByte, ready);
            const bool okAuth = ReadValue(base + r.authManagerSlot, auth);
            const bool okForce = ReadValue(base + r.forceReadyFlag, forceReady);

            RuntimeLog(
                "[BETA-INIT] stage=%s A=%s0x%X B=%s0x%X C=%s0x%X ready=%s0x%02X auth=%s0x%llX forceReady=%s0x%X",
                stage,
                okA ? "" : "?", a, okB ? "" : "?", b, okC ? "" : "?", c,
                okReady ? "" : "?", static_cast<unsigned int>(ready),
                okAuth ? "" : "?", static_cast<unsigned long long>(auth),
                okForce ? "" : "?", forceReady);

            std::printf(
                "[BETA-INIT] %-24s A=0x%X B=0x%X C=0x%X ready=0x%02X auth=0x%llX forceReady=0x%X\n",
                stage, a, b, c, static_cast<unsigned int>(ready),
                static_cast<unsigned long long>(auth), forceReady);
            std::fflush(stdout);
        }

        static void WriteInitializationAuditSummary()
        {
            storage_paths::EnsureDirectory(storage_paths::Logs() / L"t9_beta" / L"research");
            const std::string path = storage_paths::PathA(
                "logs\\t9_beta\\research\\frontend_init_audit.txt");
            std::ofstream out(path, std::ios::trunc);
            if (!out) return;

            out << "T9 Open Beta frontend initialization audit\n";
            out << "==========================================\n";
            out << "Recovered startup currently executes:\n";
            out << "  transition(0x14,0)\n";
            out << "  initB(1) / recovered session-state helper\n";
            out << "  initA(1) / recovered game-mode helper\n";
            out << "  forceReady=1\n";
            out << "  temporary loopback + 4disconnect\n";
            out << "  v13: udisconnect only; preserve native A/B outputs (legacy stateB=0x2014/stateA=2 overwrite disabled)\n\n";
            out << "Still unresolved in the Beta-specific offline resolver:\n";
            out << "  PreModeReset equivalent\n";
            out << "  PrepareFrontendMode equivalent\n";
            out << "  LobbyData/SetMap equivalent\n";
            out << "  explicit OfflineState marker/equivalent\n\n";
            out << "High-priority Beta-native initialization anchors now scanned automatically:\n";
            out << "  OnSessionStart / OnSessionEnd / OnPump\n";
            out << "  OnValidateSessionModeChangeAllowed / OnSessionModeChange\n";
            out << "  networkMode / lobbyNetworkMode / lobbyMode / LobbyType\n";
            out << "  sessionstatus / sessiongamemode / prev session is valid\n";
            out << "  MP Offline / MPO / core_frontend\n";
            out << "  ERROR_NETWORK_MODULE_NOT_INITIALIZED and network init failures\n";
            out << "\nNo additional initialization state is forced by this audit build.\n";
        }

        static std::string CommandLineUsername()
        {
            const char* commandLine = GetCommandLineA();
            if (!commandLine) return {};

            const char* marker = std::strstr(commandLine, ";-username");
            size_t markerLength = 10;
            if (!marker)
            {
                marker = std::strstr(commandLine, "-username");
                markerLength = 9;
            }
            if (!marker) return {};

            const char* p = marker + markerLength;
            while (*p == ' ' || *p == '=' || *p == ':' || *p == ';') ++p;
            if (!*p) return {};

            std::string value;
            if (*p == '"')
            {
                ++p;
                while (*p && *p != '"' && value.size() < 63) value.push_back(*p++);
            }
            else
            {
                while (*p && *p != ' ' && *p != '\t' && *p != ';' && value.size() < 63)
                    value.push_back(*p++);
            }
            return value;
        }

        static bool SafeSetUsername(
            UsernameContextFn getContext,
            SetUsernameFn setUsername,
            const char* username)
        {
            if (!getContext || !setUsername || !username || !*username)
                return false;
            __try
            {
                void* context = getContext(0);
                if (!context)
                    return false;
                setUsername(context, username);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                RuntimeLog("event=username_fault code=0x%08lX",
                    static_cast<unsigned long>(GetExceptionCode()));
                return false;
            }
        }

        static void ApplyOptionalUsername(uintptr_t base)
        {
            std::string username = CommandLineUsername();
            if (username.empty())
                username = "Player1";

            const auto& r = t9_addresses::OpenBetaRecovered;
            auto getContext = reinterpret_cast<UsernameContextFn>(base + r.usernameContext);
            auto setUsername = reinterpret_cast<SetUsernameFn>(base + r.setUsername);
            const bool applied = SafeSetUsername(getContext, setUsername, username.c_str());
            RuntimeLog(applied
                ? "event=username_applied value=%s length=%zu"
                : "event=username_skip reason=context_or_call_failed value=%s length=%zu",
                username.c_str(), username.size());
        }

        static bool WaitForByte(uintptr_t address, std::uint8_t wanted, DWORD timeoutMs)
        {
            const ULONGLONG start = GetTickCount64();
            while (GetTickCount64() - start < timeoutMs)
            {
                std::uint8_t value = 0;
                if (ReadValue(address, value) && value == wanted)
                    return true;
                Sleep(50);
            }
            return false;
        }

        static bool WaitForNonZeroByte(uintptr_t address, DWORD timeoutMs, std::uint8_t& observed)
        {
            const ULONGLONG start = GetTickCount64();
            while (GetTickCount64() - start < timeoutMs)
            {
                std::uint8_t value = 0;
                if (ReadValue(address, value))
                {
                    observed = value;
                    if (value != 0)
                        return true;
                }
                Sleep(50);
            }
            return false;
        }

        static bool WaitForLocalFrontendState(uintptr_t base, DWORD timeoutMs)
        {
            // In a real online bootstrap the recovered helper waits for an
            // auth-manager pointer. In our offline Beta that pointer correctly
            // remains null, while the game still reaches its usable LOCAL
            // frontend state. Gate on the actual frontend globals instead.
            const auto& r = t9_addresses::OpenBetaRecovered;
            const ULONGLONG start = GetTickCount64();
            DWORD lastA = 0xFFFFFFFFu;
            DWORD lastB = 0xFFFFFFFFu;
            DWORD lastC = 0xFFFFFFFFu;

            while (GetTickCount64() - start < timeoutMs)
            {
                DWORD a = 0, b = 0, c = 0;
                if (ReadValue(base + r.stateA, a) &&
                    ReadValue(base + r.stateB, b) &&
                    ReadValue(base + r.stateC, c))
                {
                    if (a != lastA || b != lastB || c != lastC)
                    {
                        RuntimeLog("offline_frontend_wait A=0x%X B=0x%X C=0x%X", a, b, c);
                        lastA = a;
                        lastB = b;
                        lastC = c;
                    }

                    // This is the exact LOCAL menu state captured in the test
                    // logs after transition(0x14), initB(1), initA(1) and the
                    // force-ready write. It does not require Demonware auth.
                    if (b == 0x2011u && c == 0x14u)
                    {
                        RuntimeLog("offline_frontend_wait=ready A=0x%X B=0x%X C=0x%X", a, b, c);
                        return true;
                    }
                }
                Sleep(10);
            }

            RuntimeLog("offline_frontend_wait=timeout timeout_ms=%lu action=continue_local_finalize",
                static_cast<unsigned long>(timeoutMs));
            return false;
        }

        DWORD WINAPI RecoveredStateMonitor(LPVOID)
        {
            const uintptr_t base = GameBase();
            if (!ExactBetaLayout(base)) return 1;

            const auto& r = t9_addresses::OpenBetaRecovered;
            auto command = reinterpret_cast<CommandFn>(base + r.command);
            auto transition = reinterpret_cast<TransitionFn>(base + r.transition);
            const uintptr_t stateA = base + r.stateA;
            const uintptr_t stateB = base + r.stateB;
            const uintptr_t stateC = base + r.stateC;
            const uintptr_t readyAddress = base + r.readyByte;
            const uintptr_t authAddress = base + r.authManagerSlot;
            const uintptr_t forceReadyAddress = base + r.forceReadyFlag;

            RuntimeLog("monitor=start mode=beta_internal_state_only generic_mouse_keyboard_capture=disabled");
            std::printf("[BETA-FRONTEND] internal state monitor active; generic mouse/keyboard click tracing is disabled.\n");
            std::fflush(stdout);

            DWORD lastA = 0xFFFFFFFFu, lastB = 0xFFFFFFFFu, lastC = 0xFFFFFFFFu;
            DWORD lastForceReady = 0xFFFFFFFFu;
            std::uint8_t lastReady = 0xFFu;
            uintptr_t lastAuth = UINTPTR_MAX;

            for (;;)
            {
                DWORD a = 0, b = 0, c = 0, forceReady = 0;
                std::uint8_t ready = 0;
                uintptr_t auth = 0;
                if (!ReadValue(stateA, a) || !ReadValue(stateB, b) || !ReadValue(stateC, c) ||
                    !ReadValue(readyAddress, ready) || !ReadValue(authAddress, auth) ||
                    !ReadValue(forceReadyAddress, forceReady))
                {
                    Sleep(10);
                    continue;
                }

                const bool changed =
                    a != lastA || b != lastB || c != lastC ||
                    ready != lastReady || auth != lastAuth || forceReady != lastForceReady;

                if (changed)
                {
                    RuntimeLog(
                        "monitor=frontend_change A=0x%X B=0x%X C=0x%X ready=0x%02X auth=0x%llX forceReady=0x%X",
                        a, b, c, static_cast<unsigned int>(ready),
                        static_cast<unsigned long long>(auth), forceReady);
                    std::printf(
                        "[BETA-FRONTEND] A=0x%X B=0x%X C=0x%X ready=0x%02X auth=0x%llX forceReady=0x%X\n",
                        a, b, c, static_cast<unsigned int>(ready),
                        static_cast<unsigned long long>(auth), forceReady);
                    std::fflush(stdout);

                    lastA = a;
                    lastB = b;
                    lastC = c;
                    lastReady = ready;
                    lastAuth = auth;
                    lastForceReady = forceReady;
                }

                // Keep the recovered disconnect handling isolated and Beta-specific.
                // We only change state after observing the exact recovered tuple.
                if (b == 0x2011u && a == 2u && c == 0x15u)
                {
                    RuntimeLog("[BETA-DISCONNECT] service_failure_state A=0x%X B=0x%X C=0x%X action=jdisconnect_transition17 intentional_error_tuple=1", a, b, c);
                    std::printf("[BETA-DISCONNECT] recovered service-failure tuple reached; applying isolated jdisconnect/transition(0x17) path.\n");
                    std::fflush(stdout);
                    Sleep(500);
                    const DWORD one = 1;
                    if (WriteValue(stateA, one))
                    {
                        const bool commandOk = SafeCommand(command, 0, "jdisconnect");
                        const bool transitionOk = SafeTransition(transition, 0x17, 0);
                        RuntimeLog("[BETA-DISCONNECT] transition17 command=%u transition=%u",
                            commandOk ? 1u : 0u, transitionOk ? 1u : 0u);
                        std::printf("[BETA-DISCONNECT] jdisconnect=%s transition17=%s\n",
                            commandOk ? "OK" : "FAILED", transitionOk ? "OK" : "FAILED");
                        std::fflush(stdout);
                    }
                }
                else if (b == 0x2014u && a == 1u && c == 0x14u)
                {
                    // v13: observation only. Earlier builds forced A=2 here,
                    // but the recovered LobbyBase_SetNetworkMode(1) call itself produces A=1.
                    // Do not overwrite the engine's native local-state result.
                    RuntimeLog("[BETA-INIT] observed A=1/B=0x2014/C=0x14; legacy stateA=2 rearm suppressed");
                }

                Sleep(5);
            }
        }

    }

    bool IsExactOpenBeta()
    {
        return DetectCurrentBuild().kind == BuildKind::OpenBeta;
    }

    bool ExecuteFrontendControl(const std::string& action, const std::string& arguments, std::string& message)
    {
        message.clear();

        const uintptr_t base = GameBase();
        if (!ExactBetaLayout(base))
        {
            message = "exact Open Beta fingerprint is not active";
            return false;
        }
        if (!ValidateRecoveredTargets(base))
        {
            message = "recovered Beta frontend targets failed validation";
            return false;
        }

        const auto& r = t9_addresses::OpenBetaRecovered;
        auto command = reinterpret_cast<CommandFn>(base + r.command);
        auto transition = reinterpret_cast<TransitionFn>(base + r.transition);
        auto initA = reinterpret_cast<InitFn>(base + r.initA);
        auto initB = reinterpret_cast<InitFn>(base + r.initB);

        auto trim = [](std::string value)
        {
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
                value.erase(value.begin());
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
                value.pop_back();
            return value;
        };

        auto parseU32 = [](const std::string& token, DWORD& out) -> bool
        {
            if (token.empty()) return false;
            char* end = nullptr;
            const unsigned long long value = std::strtoull(token.c_str(), &end, 0);
            if (!end || *end != '\0' || value > 0xFFFFFFFFull)
                return false;
            out = static_cast<DWORD>(value);
            return true;
        };

        auto parseInt = [](const std::string& token, int& out) -> bool
        {
            if (token.empty()) return false;
            char* end = nullptr;
            const long value = std::strtol(token.c_str(), &end, 0);
            if (!end || *end != '\0') return false;
            out = static_cast<int>(value);
            return true;
        };

        auto readback = [&](const char* label, bool ok) -> bool
        {
            DWORD a = 0, b = 0, c = 0, ready = 0;
            const bool stateOk =
                ReadValue(base + r.stateA, a) &&
                ReadValue(base + r.stateB, b) &&
                ReadValue(base + r.stateC, c);
            ReadValue(base + r.forceReadyFlag, ready);

            std::ostringstream out;
            out << label << ": " << (ok ? "OK" : "FAILED");
            if (stateOk)
            {
                out << " | A=0x" << std::hex << std::uppercase << a
                    << " B=0x" << b
                    << " C=0x" << c
                    << " ready=0x" << ready;
            }
            message = out.str();
            RuntimeLog("manual_frontend action=%s result=%s A=0x%X B=0x%X C=0x%X ready=0x%X",
                label, ok ? "ok" : "failed", a, b, c, ready);
            return ok && stateOk;
        };

        std::string op = LowerAscii(trim(action));
        const std::string args = trim(arguments);

        if (op == "lobbyprobe" || op == "lobbyscan" || op == "initprobe")
        {
            const std::string label = args.empty() ? "manual" : ("manual_" + SanitizeFileToken(args));
            const bool started = StartLobbyRuntimeProbeAsync(label.c_str());
            message = started
                ? "focused Beta Lobby/LUI runtime probe started; watch [BETA-LOBBY] and logs\\beta_game_scan\\lobby_runtime_*"
                : "focused Lobby/LUI probe is already running (or could not start)";
            return started;
        }

        if (op == "bigscan" || op == "memscan" || op == "fullscan")
        {
            const std::string label = args.empty() ? "manual" : ("manual_" + SanitizeFileToken(args));
            const bool started = StartFullMemoryScanAsync(label.c_str());
            message = started
                ? "full Beta process memory census started; watch [BETA-MEMSCAN] and logs\\beta_game_scan\\full_memory_*"
                : "full memory census is already running (or could not start)";
            return started;
        }

        if (op == "enter")
        {
            std::istringstream in(args);
            std::string target;
            in >> target;
            std::string rest;
            std::getline(in, rest);
            if (target.empty())
            {
                message = "usage: /beta enter mp|mpoffline|arena|mparenaoffline|zm|zmoffline|campaign|local|nativeinit|legacyfinalize|prelocal|servicefail|clean17";
                return false;
            }
            return ExecuteFrontendControl(target, trim(rest), message);
        }

        if (op.empty() || op == "read" || op == "status")
            return readback("status", true);

        if (op == "transition")
        {
            std::istringstream in(args);
            std::string stateToken, argToken;
            in >> stateToken >> argToken;
            DWORD state = 0;
            int arg = 0;
            if (!parseU32(stateToken, state) || (!argToken.empty() && !parseInt(argToken, arg)))
            {
                message = "usage: /beta transition <state> [arg]  (example: /beta transition 0x14 0)";
                return false;
            }
            const bool ok = SafeTransition(transition, static_cast<int>(state), arg);
            StartMultiplayerScanAsync("manual_transition");
            return readback("transition", ok);
        }

        if (op == "mode" || op == "gamemode")
        {
            std::istringstream in(args);
            std::string token;
            in >> token;
            int value = -1;
            if (!parseInt(token, value) || value < 0 || value > 2)
            {
                message = "usage: /beta mode <0|1|2>  (0=Zombies, 1=Multiplayer, 2=Campaign)";
                return false;
            }
            const bool ok = SafeInit(initA, "Com_SessionMode_SetMode/initA", value);
            StartMultiplayerScanAsync("manual_gamemode");
            return readback(ModeName(value), ok);
        }

        if (op == "session")
        {
            std::istringstream in(args);
            std::string token;
            in >> token;
            int value = 0;
            if (!parseInt(token, value))
            {
                message = "usage: /beta session <value>";
                return false;
            }
            const bool ok = SafeInit(initB, "LobbyBase_SetNetworkMode/initB", value);
            StartMultiplayerScanAsync("manual_session");
            return readback("session", ok);
        }

        if (op == "setstate")
        {
            std::istringstream in(args);
            std::string ta, tb, tc;
            in >> ta >> tb >> tc;
            DWORD a = 0, b = 0, c = 0;
            if (!parseU32(ta, a) || !parseU32(tb, b) || !parseU32(tc, c))
            {
                message = "usage: /beta setstate <A> <B> <C>  (hex accepted, e.g. 2 0x2014 0x14)";
                return false;
            }
            bool ok = WriteValue(base + r.stateA, a);
            ok = WriteValue(base + r.stateB, b) && ok;
            ok = WriteValue(base + r.stateC, c) && ok;
            StartMultiplayerScanAsync("manual_setstate");
            return readback("setstate", ok);
        }

        if (op == "cmd" || op == "gamecmd")
        {
            if (args.empty())
            {
                message = "usage: /beta cmd <native game command>";
                return false;
            }
            const bool ok = SafeCommand(command, 0, args.c_str());
            StartMultiplayerScanAsync("manual_gamecmd");
            return readback("gamecmd", ok);
        }

        if (op == "nativeinit" || op == "native" || op == "localnative")
        {
            // Re-run only the recovered Beta-native initialization calls and
            // preserve their outputs. Observed v12 behavior:
            //   transition(0x14) -> B=0x2034
            //   initB(1)         -> A=1, B=0x2014
            //   initA(1)         -> A=1, B=0x2011
            // The legacy final A=2/B=0x2014 writes are intentionally omitted.
            RuntimeLog("[BETA-INIT] nativeinit begin: preserve engine-produced A/B state");
            LogRecoveredInitSnapshot(base, "manual_native_before");

            bool ok = SafeTransition(transition, 0x14, 0);
            LogRecoveredInitSnapshot(base, "manual_native_after_setscreen14");
            ok = SafeInit(initB, "LobbyBase_SetNetworkMode/initB", 1) && ok;
            LogRecoveredInitSnapshot(base, "manual_native_after_lobby_network_mode");
            ok = SafeInit(initA, "Com_SessionMode_SetMode/initA", 1) && ok;
            LogRecoveredInitSnapshot(base, "manual_native_after_session_mode");

            const DWORD one = 1;
            ok = WriteValue(base + r.forceReadyFlag, one) && ok;
            LogRecoveredInitSnapshot(base, "manual_native_after_force_ready");

            // Keep the already-recovered disconnect handoff, but do not mutate
            // A/B afterward. This tests whether initialization was previously
            // being invalidated by our own final writes.
            ok = SafeCommand(command, 0, "udisconnect") && ok;
            Sleep(100);
            LogRecoveredInitSnapshot(base, "manual_native_after_udisconnect");

            StartMultiplayerScanAsync("manual_nativeinit");
            return readback("nativeinit", ok);
        }

        if (op == "legacyfinalize" || op == "legacy")
        {
            // Comparison/fallback only. Restores the old v12 final tuple so a
            // tester can compare without restarting the process.
            const DWORD a = 2u, b = 0x2014u, c = 0x14u;
            bool ok = WriteValue(base + r.stateA, a);
            ok = WriteValue(base + r.stateB, b) && ok;
            ok = WriteValue(base + r.stateC, c) && ok;
            RuntimeLog("[BETA-INIT] legacyfinalize restored A=2/B=0x2014/C=0x14 comparison_only=1");
            StartMultiplayerScanAsync("manual_legacyfinalize");
            return readback("legacyfinalize", ok);
        }

        if (op == "prelocal")
        {
            const DWORD a = 2, b = 0x2011u, c = 0x14u;
            bool ok = WriteValue(base + r.stateA, a);
            ok = WriteValue(base + r.stateB, b) && ok;
            ok = WriteValue(base + r.stateC, c) && ok;
            StartMultiplayerScanAsync("manual_prelocal");
            return readback("prelocal", ok);
        }

        if (op == "clean17" || op == "disconnect17" || op == "cleandisconnect")
        {
            // Reproduce the only path that visibly leaves the stuck frontend,
            // but never assert C=0x15 (the recovered service-failure/UI-error
            // state). Mirror the recovered cleanup in isolated steps so the log
            // shows exactly which write/call causes the frontend to advance.
            const DWORD initialA = 2, initialB = 0x2011u, initialC = 0x14u;
            bool ok = WriteValue(base + r.stateA, initialA);
            ok = WriteValue(base + r.stateB, initialB) && ok;
            ok = WriteValue(base + r.stateC, initialC) && ok;

            DWORD beforeA = 0, beforeB = 0, beforeC = 0;
            ReadValue(base + r.stateA, beforeA);
            ReadValue(base + r.stateB, beforeB);
            ReadValue(base + r.stateC, beforeC);
            RuntimeLog("[BETA-DISCONNECT] clean17 begin A=0x%X B=0x%X C=0x%X service_failure_flag=0 diagnostic_only=1 prior_result=UI_Error_84360",
                beforeA, beforeB, beforeC);
            std::printf("[BETA-DISCONNECT] clean17 is diagnostic only: the last run proved transition(0x17) reaches UI Error 84360, so it is NOT treated as the normal Multiplayer entry path.\n");
            std::fflush(stdout);

            // The recovered service-failure handler writes A=1 immediately
            // before jdisconnect + transition(0x17). Keep that part, but not the
            // C=0x15 error tuple, so we can tell whether the disconnect handoff
            // itself is the missing normal frontend path.
            const DWORD one = 1;
            const bool localStateOk = ok && WriteValue(base + r.stateA, one);
            Sleep(25);
            DWORD localA = 0, localB = 0, localC = 0;
            ReadValue(base + r.stateA, localA);
            ReadValue(base + r.stateB, localB);
            ReadValue(base + r.stateC, localC);
            RuntimeLog("[BETA-DISCONNECT] clean17 local_state ok=%u A=0x%X B=0x%X C=0x%X",
                localStateOk ? 1u : 0u, localA, localB, localC);

            const bool commandOk = localStateOk && SafeCommand(command, 0, "jdisconnect");
            Sleep(100);
            DWORD commandA = 0, commandB = 0, commandC = 0;
            ReadValue(base + r.stateA, commandA);
            ReadValue(base + r.stateB, commandB);
            ReadValue(base + r.stateC, commandC);
            RuntimeLog("[BETA-DISCONNECT] clean17 after_jdisconnect ok=%u A=0x%X B=0x%X C=0x%X",
                commandOk ? 1u : 0u, commandA, commandB, commandC);

            const bool transitionOk = commandOk && SafeTransition(transition, 0x17, 0);
            Sleep(150);
            DWORD afterA = 0, afterB = 0, afterC = 0;
            ReadValue(base + r.stateA, afterA);
            ReadValue(base + r.stateB, afterB);
            ReadValue(base + r.stateC, afterC);
            RuntimeLog("[BETA-DISCONNECT] clean17 after_transition17 ok=%u before=%X/%X/%X local=%X/%X/%X after=%X/%X/%X",
                transitionOk ? 1u : 0u,
                beforeA, beforeB, beforeC,
                localA, localB, localC,
                afterA, afterB, afterC);
            std::printf("[BETA-DISCONNECT] clean17: local=%s jdisconnect=%s transition17=%s | A=0x%X B=0x%X C=0x%X\n",
                localStateOk ? "OK" : "FAILED", commandOk ? "OK" : "FAILED",
                transitionOk ? "OK" : "FAILED", afterA, afterB, afterC);
            std::fflush(stdout);

            StartMultiplayerScanAsync("manual_clean17");
            return readback("clean17", transitionOk);
        }

        if (op == "servicefail" || op == "failure17")
        {
            // This is a state actually observed/handled by the recovered monitor.
            // The monitor will perform jdisconnect + transition(0x17, 0).
            const DWORD a = 2, b = 0x2011u, c = 0x15u;
            bool ok = WriteValue(base + r.stateA, a);
            ok = WriteValue(base + r.stateB, b) && ok;
            ok = WriteValue(base + r.stateC, c) && ok;
            StartMultiplayerScanAsync("manual_servicefail");
            return readback("servicefail", ok);
        }

        const bool wantsMp = op == "mp" || op == "local" || op == "mpoffline" || op == "mp_offline";
        const bool wantsArena = op == "arena" || op == "mparena" || op == "mparenaoffline" || op == "mp_arena_offline";
        const bool wantsZm = op == "zm" || op == "zombies" || op == "zmoffline" || op == "zm_offline";
        const bool wantsCampaign = op == "campaign" || op == "cp";
        if (wantsMp || wantsArena || wantsZm || wantsCampaign)
        {
            const int mode = wantsZm ? 0 : (wantsCampaign ? 2 : 1);
            bool ok = SafeTransition(transition, 0x14, 0);
            ok = SafeInit(initB, "LobbyBase_SetNetworkMode/initB", 1) && ok;
            ok = SafeInit(initA, "Com_SessionMode_SetMode/initA", mode) && ok;

            const DWORD one = 1;
            ok = WriteValue(base + r.forceReadyFlag, one) && ok;

            // v13: do not overwrite the state produced by initB/initA.
            // The v12 audit showed the old B=0x2014/A=2 finalization undoes
            // those native results. Keep only the recovered disconnect handoff.
            ok = SafeCommand(command, 0, "udisconnect") && ok;

            const char* label = wantsArena ? "MP Arena (native init; mode 1 shared)" :
                                wantsZm ? "ZM (native init)" :
                                wantsCampaign ? "Campaign (native init)" : "MP (native init)";
            StartMultiplayerScanAsync(wantsArena ? "manual_enter_arena_native" :
                (wantsZm ? "manual_enter_zm_native" :
                    (wantsCampaign ? "manual_enter_campaign_native" : "manual_enter_mp_native")));
            const bool result = readback(label, ok);
            if (wantsArena && result)
                message += " | NOTE: Arena still has no separately verified mode value; this preserves the native mode-1 result.";
            return result;
        }

        message = "unknown frontend control. Try: /beta read, /beta lobbyprobe [label], /beta bigscan [label], /beta enter mp|arena|zm|campaign, /beta transition, /beta mode, /beta session, /beta setstate, /beta cmd";
        return false;
    }

    DWORD WINAPI RecoveredClientThread(LPVOID)
    {
        const uintptr_t base = GameBase();
        if (!ExactBetaLayout(base))
        {
            RuntimeLog("bootstrap=skip reason=fingerprint_mismatch");
            return 1;
        }

        std::printf("[BETA-FIX] Beta v16 focused Lobby/LUI runtime probe + native-init preservation active\n");
        std::fflush(stdout);
        RuntimeLog("build_marker=beta_v16_focused_lobby_lui_runtime_probe_native_init_preservation");
        WriteInitializationAuditSummary();
        std::printf("[BETA-LOBBY] v16 auto-runs a focused read-only MEM_PRIVATE Lobby/LUI/session probe after local frontend; /beta bigscan remains manual.\n");
        std::fflush(stdout);

        // Defensive cleanup for the exact Open Beta build. The current source
        // never installs the old trace hooks, but restoring any unexpected E9
        // prefix here prevents a stale/second component from leaving those hot
        // functions redirected.
        RestoreLegacyTraceDetours(base);

        // Release cleanup: do not auto-start the broad Beta state/Lua/frontend
        // research scanner. Manual Beta research commands stay compiled for a
        // future development build, but launch now owns only playable bootstrap.
        RuntimeLog("scanner_autorun=disabled release=minimal");

        if (!ValidateRecoveredTargets(base))
        {
            RuntimeLog("bootstrap=skip reason=target_validation_failed scanner_autorun=disabled");
            return 2;
        }

        // Do not detour the Beta's hot transition/mode/session/command functions.
        // The previous trace build crashed while those MinHook trampolines were
        // active. Keep research read-only and use passive code/string/xref scans
        // plus the internal state monitor instead. Generic mouse/keyboard click capture is intentionally disabled.
        RuntimeLog("trace_hooks=disabled reason=beta_hot_function_crash passive_scanner=1");
        std::printf("[BETA-FRONTEND] Beta gate graph active; no hot game-function trace hooks or generic click hooks are installed.\n");
        std::printf("[BETA-FRONTEND] automatic Lobby/LUI/Lua/address research disabled in release mode.\n");
        std::fflush(stdout);
        RuntimeLog("lobby_lui_autoscan=disabled phase=bootstrap_start release=minimal");

        const auto& r = t9_addresses::OpenBetaRecovered;
        RuntimeLog(
            "bootstrap=start base=0x%llX timestamp=0x%08X image=0x%08X entry=0x%08X",
            static_cast<unsigned long long>(base),
            t9_addresses::BetaFingerprint.timestamp,
            t9_addresses::BetaFingerprint.imageSize,
            t9_addresses::BetaFingerprint.entryPointRva);

        // The recovered worker sleeps five seconds from DLL attach. GameManager
        // already gives the Win11 redirect a two-second quiet window, so keep
        // another three seconds here before touching beta frontend state.
        Sleep(3000);

        std::uint8_t readyValue = 0;
        bool observationScanStarted = false;

        // The scanner is already running. The ready byte only gates the code
        // that calls recovered game/frontend functions. Do not terminate this
        // worker because of an arbitrary timeout; keep waiting on this worker
        // thread while research continues independently.
        if (!WaitForNonZeroByte(base + r.readyByte, 30000, readyValue))
        {
            observationScanStarted = true;
            RuntimeLog("bootstrap=wait reason=ready_byte_initial_timeout rva=0x%llX action=continue_indefinitely scanner=already_running",
                static_cast<unsigned long long>(r.readyByte));
            std::printf("[T9-BETA] ready byte not set after 30s; scanner is already running, bootstrap will keep waiting.\n");
            std::fflush(stdout);

            unsigned waitChunk = 1;
            while (!WaitForNonZeroByte(base + r.readyByte, 30000, readyValue))
            {
                RuntimeLog("bootstrap=wait reason=ready_byte_still_zero chunk=%u elapsed_after_initial_ms=%u",
                    waitChunk, waitChunk * 30000u);
                ++waitChunk;
            }
        }

        RuntimeLog("bootstrap=ready_byte value=0x%02X rva=0x%llX late=%u",
            static_cast<unsigned int>(readyValue),
            static_cast<unsigned long long>(r.readyByte),
            observationScanStarted ? 1u : 0u);
        std::printf("[BETA-SCAN] Beta ready byte reached value=0x%02X%s.\n",
            static_cast<unsigned int>(readyValue),
            observationScanStarted ? " after extended wait" : "");
        std::fflush(stdout);

        // Release cleanup: no automatic ready-byte research refresh.
        RuntimeLog("scanner_ready_refresh=disabled release=minimal");

        ApplyOptionalUsername(base);

        // The Open Beta has now been observed repeatedly with the same partial
        // Season-2-style signature set. Four required targets are absent
        // (PreModeReset, PrepareFrontendMode, SetMap, OfflineState marker), so
        // probing the entire ~0x18130000 image three times only delays startup
        // by minutes before taking this recovered Beta-specific handoff anyway.
        // Skip that expensive probe during normal startup. BetaOffline remains
        // available as research code, but it is not part of the launch path.
        RuntimeLog("bootstrap=continue path=recovered_beta_network_handoff season2_probe=skipped_known_mismatch");

        auto command = reinterpret_cast<CommandFn>(base + r.command);
        auto transition = reinterpret_cast<TransitionFn>(base + r.transition);
        auto initA = reinterpret_cast<InitFn>(base + r.initA);
        auto initB = reinterpret_cast<InitFn>(base + r.initB);

        LogRecoveredInitSnapshot(base, "before_setscreen14");
        if (!SafeTransition(transition, 0x14, 0))
        {
            RuntimeLog("bootstrap=stop reason=transition14_failed");
            return 4;
        }
        LogRecoveredInitSnapshot(base, "after_setscreen14");

        if (!SafeInit(initB, "LobbyBase_SetNetworkMode/initB", 1))
        {
            RuntimeLog("bootstrap=stop reason=initB_failed");
            return 4;
        }
        LogRecoveredInitSnapshot(base, "after_lobby_network_mode_lan");

        if (!SafeInit(initA, "Com_SessionMode_SetMode/initA", 1))
        {
            RuntimeLog("bootstrap=stop reason=initA_failed");
            return 4;
        }
        LogRecoveredInitSnapshot(base, "after_session_mode_mp");

        const DWORD one = 1;
        if (!WriteValue(base + r.forceReadyFlag, one))
        {
            RuntimeLog("bootstrap=stop reason=force_ready_write_failed rva=0x%llX",
                static_cast<unsigned long long>(r.forceReadyFlag));
            return 5;
        }
        RuntimeLog("bootstrap=force_ready value=1");
        LogRecoveredInitSnapshot(base, "after_force_ready");

        unsigned char savedA[16]{};
        unsigned char savedB[16]{};
        if (!ReadBytes(base + r.endpointA, savedA, sizeof(savedA)) ||
            !ReadBytes(base + r.endpointB, savedB, sizeof(savedB)))
        {
            RuntimeLog("bootstrap=stop reason=endpoint_backup_failed");
            return 6;
        }

        char loopbackA[16]{};
        char loopbackB[16]{};
        strcpy_s(loopbackA, sizeof(loopbackA), ")127.0.0.1");
        strcpy_s(loopbackB, sizeof(loopbackB), "%127.0.0.1");

        if (!WriteProtected(base + r.endpointA, loopbackA, sizeof(loopbackA)) ||
            !WriteProtected(base + r.endpointB, loopbackB, sizeof(loopbackB)))
        {
            // Best-effort restore in case only the first write succeeded.
            WriteProtected(base + r.endpointA, savedA, sizeof(savedA));
            WriteProtected(base + r.endpointB, savedB, sizeof(savedB));
            RuntimeLog("bootstrap=stop reason=endpoint_patch_failed");
            return 7;
        }

        RuntimeLog("bootstrap=endpoints_temporarily_loopback");
        const bool disconnected = SafeCommand(command, 0, "4disconnect");
        LogRecoveredInitSnapshot(base, "after_4disconnect");

        // The previous build waited up to 60 seconds for authManagerSlot. The
        // supplied logs prove that slot stays null in the offline Beta even
        // though the LOCAL frontend is already loaded (A=1/B=0x2011/C=0x14).
        // Waiting for online auth therefore aborts before the final state writes
        // and before the state monitor starts. Wait for the LOCAL frontend state
        // produced by the recovered Beta-native initialization calls instead.
        const bool localFrontendReady = disconnected && WaitForLocalFrontendState(base, 10000);

        // Always restore the game's original endpoint bytes before the local
        // finalize. Loopback is only needed to push the recovered handoff into
        // the LOCAL frontend; it must not remain patched afterwards.
        const bool restoredA = WriteProtected(base + r.endpointA, savedA, sizeof(savedA));
        const bool restoredB = WriteProtected(base + r.endpointB, savedB, sizeof(savedB));
        RuntimeLog("bootstrap=endpoints_restored A=%u B=%u local_frontend=%u",
            restoredA ? 1u : 0u, restoredB ? 1u : 0u, localFrontendReady ? 1u : 0u);

        if (!disconnected || !restoredA || !restoredB)
        {
            RuntimeLog("bootstrap=stop reason=offline_handoff_or_restore_failed disconnected=%u",
                disconnected ? 1u : 0u);
            return 8;
        }

        // v13: preserve the outputs produced by the recovered Beta-native
        // initialization calls. The v12 audit proved:
        //   LobbyBase_SetNetworkMode(1/LAN) -> A=1 / B=0x2014
        //   Com_SessionMode_SetMode(1/MP) -> A=1 / B=0x2011
        // The previous bootstrap then overwrote B back to 0x2014 and A to 2.
        // That manufactured a mixed state after the native initialization had
        // already selected the local Multiplayer state. Keep the disconnect
        // handoff, but do not rewrite A/B afterward.
        RuntimeLog("[BETA-INIT] native_finalization begin legacy_B2014_write=disabled legacy_A2_write=disabled");
        LogRecoveredInitSnapshot(base, "before_native_udisconnect");

        Sleep(250);
        if (!SafeCommand(command, 0, "udisconnect"))
        {
            RuntimeLog("bootstrap=stop reason=udisconnect_failed");
            return 10;
        }
        LogRecoveredInitSnapshot(base, "after_native_udisconnect");
        Sleep(250);

        DWORD finalA = 0, finalB = 0, finalC = 0;
        ReadValue(base + r.stateA, finalA);
        ReadValue(base + r.stateB, finalB);
        ReadValue(base + r.stateC, finalC);
        RuntimeLog("[BETA-INIT] native_finalization complete A=0x%X B=0x%X C=0x%X expected_local_mp=1/2011/14",
            finalA, finalB, finalC);
        std::printf("[BETA-FRONTEND] native Beta init preserved: A=0x%X B=0x%X C=0x%X; legacy A=2/B=0x2014 final writes are disabled.\n",
            finalA, finalB, finalC);
        std::fflush(stdout);

        // Refresh the passive frontend scan once the LOCAL frontend is finalized
        // to capture late-decrypted MULTIPLAYER/OFFLINE strings, xrefs and calls.
        RuntimeLog("lobby_lui_autoscan=disabled phase=local_frontend_ready release=minimal");

        // Release cleanup: keep the focused Lobby/LUI probe manual. Do not run
        // any extra address/UI research automatically during playable startup.
        RuntimeLog("lobby_runtime_probe=disabled phase=local_frontend_ready release=minimal");

        if (!g_monitorStarted.exchange(true, std::memory_order_acq_rel))
        {
            HANDLE monitor = CreateThread(nullptr, 0, &RecoveredStateMonitor, nullptr, 0, nullptr);
            if (monitor)
            {
                CloseHandle(monitor);
                RuntimeLog("bootstrap=complete monitor=started");
            }
            else
            {
                g_monitorStarted.store(false, std::memory_order_release);
                RuntimeLog("bootstrap=complete monitor=create_failed error=%lu",
                    static_cast<unsigned long>(GetLastError()));
            }
        }
        return 0;
    }

    bool StartRecoveredClient()
    {
        if (!IsExactOpenBeta())
            return false;
        if (g_recoveredClientStarted.exchange(true, std::memory_order_acq_rel))
            return true;

        HANDLE thread = CreateThread(nullptr, 0, &RecoveredClientThread, nullptr, 0, nullptr);
        if (!thread)
        {
            g_recoveredClientStarted.store(false, std::memory_order_release);
            RuntimeLog("bootstrap=create_thread_failed error=%lu",
                static_cast<unsigned long>(GetLastError()));
            return false;
        }
        CloseHandle(thread);
        return true;
    }

    DWORD WINAPI ObservationThread(LPVOID)
    {
        ImageLayout image{};
        if (!ReadImageLayout(GetModuleHandleW(nullptr), image)) return 1;
        const BuildInfo info = DetectCurrentBuild();
        WriteBuildInfo(info, image);
        WriteSections(image);
        const size_t importCount = ScanImports(image);
        const auto strings = ScanInterestingStrings(image);
        ScanStringReferences(image, strings);
        const size_t callCount = ScanDirectCalls(image);

        std::ofstream summary(AnalysisDir() + "\\scan_summary.json", std::ios::trunc);
        if (summary)
        {
            summary << "{\n"
                    << "  \"mode\": \"game_only_read_only\",\n"
                    << "  \"external_mod_scanned\": false,\n"
                    << "  \"patches_applied\": false,\n"
                    << "  \"section_count\": " << image.sections.size() << ",\n"
                    << "  \"import_count\": " << importCount << ",\n"
                    << "  \"interesting_string_count\": " << strings.size() << ",\n"
                    << "  \"direct_call_count\": " << callCount << "\n"
                    << "}\n";
        }
        return 0;
    }



}
