#include "BetaResearch.h"

#include "../T9Addresses.h"
#include "../../../../shared/runtime/StoragePaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace beta_research
{
    namespace
    {
        struct SectionInfo
        {
            std::string name;
            std::uintptr_t rva = 0;
            std::uintptr_t size = 0;
            DWORD characteristics = 0;
        };

        struct ImageLayout
        {
            std::uintptr_t base = 0;
            DWORD timestamp = 0;
            DWORD imageSize = 0;
            DWORD entryPoint = 0;
            std::vector<SectionInfo> sections;
        };

        struct ModuleInfo
        {
            std::string name;
            std::string path;
            std::uintptr_t base = 0;
            std::size_t size = 0;
            DWORD timestamp = 0;
        };

        struct MemoryRegion
        {
            std::uintptr_t base = 0;
            std::uintptr_t end = 0;
            std::size_t size = 0;
            DWORD state = 0;
            DWORD protect = 0;
            DWORD type = 0;
            std::string module;
            std::string tags;
        };

        struct StringHit
        {
            std::uintptr_t address = 0;
            std::uintptr_t regionBase = 0;
            std::string module;
            std::string marker;
            std::string encoding;
            std::string context;
            bool highPriority = false;
        };

        struct XrefHit
        {
            std::string target;
            std::uintptr_t targetRva = 0;
            std::uintptr_t instructionRva = 0;
            std::uintptr_t functionRva = 0;
            std::string bytes;
            std::string type;
            std::string access;
        };

        struct Summary
        {
            std::size_t stateXrefs = 0;
            std::size_t functionCallers = 0;
            std::size_t frontendMarkers = 0;
            std::size_t luaStrings = 0;
            std::size_t luaTextChunks = 0;
            std::size_t luaBytecodeChunks = 0;
            std::size_t authSnapshots = 0;
            std::size_t identityMatches = 0;
            std::size_t offlineCandidates = 0;
            std::size_t fullMemoryRegions = 0;
            bool complete = false;
        };

        constexpr DWORD kBetaTimestamp = 0x5F88B829u;
        constexpr DWORD kBetaImageSize = 0x18130000u;
        constexpr DWORD kBetaEntryRva = 0x08B0C090u;
        constexpr DWORD kStateMonitorMs = 10u * 60u * 1000u;
        constexpr std::size_t kMaxRegionRead = 16ull * 1024ull * 1024ull;
        constexpr std::size_t kSnapshotBytes = 0x200;
        constexpr std::size_t kMaxTextChunks = 256;
        constexpr std::size_t kMaxBytecodeChunks = 128;

        std::atomic_bool g_win11Complete{ false };
        std::atomic_bool g_scanRunning{ false };
        std::atomic_bool g_scanComplete{ false };
        std::atomic_bool g_stateMonitorRunning{ false };
        std::atomic_int g_scanMode{ static_cast<int>(ScanMode::All) };
        std::mutex g_logMutex;
        std::string g_startReason = "manual";
        Summary g_lastSummary{};

        const auto& BetaRvas()
        {
            return t9_addresses::OpenBetaRecovered;
        }

        std::filesystem::path BetaRoot()
        {
            const auto path = storage_paths::Logs() / L"t9_beta";
            storage_paths::EnsureDirectory(path);
            return path;
        }

        std::filesystem::path ResearchRoot()
        {
            const auto path = BetaRoot() / L"research";
            storage_paths::EnsureDirectory(path);
            return path;
        }

        std::filesystem::path LuaTextRoot()
        {
            const auto path = ResearchRoot() / L"lua_text";
            storage_paths::EnsureDirectory(path);
            return path;
        }

        std::filesystem::path LuaBytecodeRoot()
        {
            const auto path = ResearchRoot() / L"lua_bytecode";
            storage_paths::EnsureDirectory(path);
            return path;
        }

        std::string Narrow(const std::wstring& wide)
        {
            if (wide.empty()) return {};
            const int needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (needed <= 1) return {};
            std::string out(static_cast<std::size_t>(needed), '\0');
            WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), needed, nullptr, nullptr);
            if (!out.empty() && out.back() == '\0') out.pop_back();
            return out;
        }

        std::string Hex(std::uint64_t value, int width = 0)
        {
            std::ostringstream out;
            out << "0x" << std::uppercase << std::hex;
            if (width > 0) out << std::setw(width) << std::setfill('0');
            out << value;
            return out.str();
        }

        std::string CsvEscape(const std::string& value)
        {
            std::string out;
            out.reserve(value.size() + 8);
            for (char c : value)
            {
                if (c == '"') out += "\"\"";
                else if (c == '\r' || c == '\n' || c == '\t') out += ' ';
                else out += c;
            }
            return out;
        }

        std::string JsonEscape(const std::string& value)
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

        void AppendProgress(const std::string& line)
        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::ofstream f(BetaRoot() / L"scan_progress.log", std::ios::app);
            if (!f) return;
            SYSTEMTIME st{};
            GetLocalTime(&st);
            f << std::setfill('0')
              << std::setw(4) << st.wYear << '-'
              << std::setw(2) << st.wMonth << '-'
              << std::setw(2) << st.wDay << ' '
              << std::setw(2) << st.wHour << ':'
              << std::setw(2) << st.wMinute << ':'
              << std::setw(2) << st.wSecond << '.'
              << std::setw(3) << st.wMilliseconds << ' '
              << line << '\n';
        }

        void PrintBeta(const char* text)
        {
            std::printf("[BETA-SCAN] %s\n", text);
            std::fflush(stdout);
            AppendProgress(text);
        }

        bool ReadBytes(std::uintptr_t address, void* output, std::size_t size)
        {
            if (!address || !output || !size) return false;
            SIZE_T read = 0;
            return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), output, size, &read) && read == size;
        }

        template <typename T>
        bool ReadValue(std::uintptr_t address, T& value)
        {
            return ReadBytes(address, &value, sizeof(value));
        }

        bool ReadCString(std::uintptr_t address, std::string& out, std::size_t maxLength = 512)
        {
            out.clear();
            for (std::size_t i = 0; i < maxLength; ++i)
            {
                char c = 0;
                if (!ReadBytes(address + i, &c, 1)) return false;
                if (!c) return true;
                if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) return false;
                out.push_back(c);
            }
            return true;
        }

        bool IsReadableProtect(DWORD protect)
        {
            const DWORD p = protect & 0xFFu;
            return p == PAGE_READONLY ||
                   p == PAGE_READWRITE ||
                   p == PAGE_WRITECOPY ||
                   p == PAGE_EXECUTE_READ ||
                   p == PAGE_EXECUTE_READWRITE ||
                   p == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsExecutableProtect(DWORD protect)
        {
            const DWORD p = protect & 0xFFu;
            return p == PAGE_EXECUTE ||
                   p == PAGE_EXECUTE_READ ||
                   p == PAGE_EXECUTE_READWRITE ||
                   p == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsWritableProtect(DWORD protect)
        {
            const DWORD p = protect & 0xFFu;
            return p == PAGE_READWRITE ||
                   p == PAGE_WRITECOPY ||
                   p == PAGE_EXECUTE_READWRITE ||
                   p == PAGE_EXECUTE_WRITECOPY;
        }

        std::string ProtectionName(DWORD protect)
        {
            std::string out;
            const DWORD p = protect & 0xFFu;
            switch (p)
            {
            case PAGE_NOACCESS: out = "NOACCESS"; break;
            case PAGE_READONLY: out = "READONLY"; break;
            case PAGE_READWRITE: out = "READWRITE"; break;
            case PAGE_WRITECOPY: out = "WRITECOPY"; break;
            case PAGE_EXECUTE: out = "EXECUTE"; break;
            case PAGE_EXECUTE_READ: out = "EXECUTE_READ"; break;
            case PAGE_EXECUTE_READWRITE: out = "EXECUTE_READWRITE"; break;
            case PAGE_EXECUTE_WRITECOPY: out = "EXECUTE_WRITECOPY"; break;
            default: out = Hex(p); break;
            }
            if (protect & PAGE_GUARD) out += "|GUARD";
            if (protect & PAGE_NOCACHE) out += "|NOCACHE";
            if (protect & PAGE_WRITECOMBINE) out += "|WRITECOMBINE";
            return out;
        }

        bool ReadImageLayout(HMODULE module, ImageLayout& out)
        {
            out = {};
            if (!module) return false;
            const auto base = reinterpret_cast<std::uintptr_t>(module);
            IMAGE_DOS_HEADER dos{};
            if (!ReadBytes(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
                return false;

            IMAGE_NT_HEADERS64 nt{};
            if (!ReadBytes(base + static_cast<std::uintptr_t>(dos.e_lfanew), &nt, sizeof(nt)) ||
                nt.Signature != IMAGE_NT_SIGNATURE ||
                nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                return false;
            }

            out.base = base;
            out.timestamp = nt.FileHeader.TimeDateStamp;
            out.imageSize = nt.OptionalHeader.SizeOfImage;
            out.entryPoint = nt.OptionalHeader.AddressOfEntryPoint;

            const auto sectionTable = base + static_cast<std::uintptr_t>(dos.e_lfanew) +
                offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
            const WORD count = (std::min<WORD>)(nt.FileHeader.NumberOfSections, 96);
            for (WORD i = 0; i < count; ++i)
            {
                IMAGE_SECTION_HEADER sh{};
                if (!ReadBytes(sectionTable + static_cast<std::uintptr_t>(i) * sizeof(sh), &sh, sizeof(sh)))
                    break;
                char name[9]{};
                std::memcpy(name, sh.Name, 8);
                SectionInfo section{};
                section.name = name;
                section.rva = sh.VirtualAddress;
                section.size = sh.Misc.VirtualSize ? sh.Misc.VirtualSize : sh.SizeOfRawData;
                section.characteristics = sh.Characteristics;
                if (section.rva < out.imageSize && section.size)
                    out.sections.push_back(section);
            }
            return out.base && out.imageSize;
        }

        bool CurrentFingerprint(ImageLayout* layoutOut = nullptr)
        {
            ImageLayout image{};
            if (!ReadImageLayout(GetModuleHandleW(nullptr), image)) return false;
            if (layoutOut) *layoutOut = image;
            return image.timestamp == kBetaTimestamp &&
                   image.imageSize == kBetaImageSize &&
                   image.entryPoint == kBetaEntryRva;
        }

        bool AlphaFingerprintMatches(const ImageLayout& image)
        {
            return image.timestamp == t9_addresses::AlphaFingerprint.timestamp &&
                   image.imageSize == t9_addresses::AlphaFingerprint.imageSize &&
                   image.entryPoint == t9_addresses::AlphaFingerprint.entryPointRva;
        }

        std::vector<ModuleInfo> EnumerateModules()
        {
            std::vector<ModuleInfo> modules;
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
            if (snapshot == INVALID_HANDLE_VALUE) return modules;
            MODULEENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            if (Module32FirstW(snapshot, &entry))
            {
                do
                {
                    ModuleInfo module{};
                    module.name = Narrow(entry.szModule);
                    module.path = Narrow(entry.szExePath);
                    module.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                    module.size = entry.modBaseSize;

                    IMAGE_DOS_HEADER dos{};
                    IMAGE_NT_HEADERS64 nt{};
                    if (ReadBytes(module.base, &dos, sizeof(dos)) &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE &&
                        ReadBytes(module.base + static_cast<std::uintptr_t>(dos.e_lfanew), &nt, sizeof(nt)) &&
                        nt.Signature == IMAGE_NT_SIGNATURE)
                    {
                        module.timestamp = nt.FileHeader.TimeDateStamp;
                    }
                    modules.push_back(module);
                    entry.dwSize = sizeof(entry);
                }
                while (Module32NextW(snapshot, &entry));
            }
            CloseHandle(snapshot);
            std::sort(modules.begin(), modules.end(), [](const ModuleInfo& a, const ModuleInfo& b) { return a.base < b.base; });
            return modules;
        }

        const ModuleInfo* FindModule(const std::vector<ModuleInfo>& modules, std::uintptr_t address)
        {
            for (const auto& module : modules)
            {
                if (address >= module.base && address < module.base + module.size)
                    return &module;
            }
            return nullptr;
        }

        std::vector<MemoryRegion> EnumerateMemory(const ImageLayout& image, const std::vector<ModuleInfo>& modules)
        {
            std::vector<MemoryRegion> regions;
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            std::uintptr_t address = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
            const std::uintptr_t maximum = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

            while (address < maximum)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
                    break;

                const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto size = static_cast<std::size_t>(mbi.RegionSize);
                const auto end = base + size;
                if (mbi.State == MEM_COMMIT &&
                    !(mbi.Protect & PAGE_GUARD) &&
                    !(mbi.Protect & PAGE_NOACCESS) &&
                    IsReadableProtect(mbi.Protect))
                {
                    MemoryRegion region{};
                    region.base = base;
                    region.end = end;
                    region.size = size;
                    region.state = mbi.State;
                    region.protect = mbi.Protect;
                    region.type = mbi.Type;
                    if (const auto* module = FindModule(modules, base))
                        region.module = module->name;

                    std::vector<std::string> tags;
                    if (image.base && base >= image.base && base < image.base + image.imageSize) tags.push_back("game image");
                    else if (mbi.Type == MEM_IMAGE) tags.push_back("DLL image");
                    else if (mbi.Type == MEM_PRIVATE) tags.push_back("private");
                    else if (mbi.Type == MEM_MAPPED) tags.push_back("mapped");
                    if (IsExecutableProtect(mbi.Protect)) tags.push_back("executable");
                    if (IsWritableProtect(mbi.Protect)) tags.push_back("writable");
                    if (IsReadableProtect(mbi.Protect)) tags.push_back("readable");
                    if (mbi.Type == MEM_PRIVATE && IsWritableProtect(mbi.Protect)) tags.push_back("heap-like");
                    for (std::size_t i = 0; i < tags.size(); ++i)
                    {
                        if (i) region.tags += '|';
                        region.tags += tags[i];
                    }
                    regions.push_back(region);
                }

                if (end <= address) break;
                address = end;
            }
            return regions;
        }

        void WriteProfileGuard(const ImageLayout& image)
        {
            storage_paths::EnsureDirectory(ResearchRoot());
            std::ofstream f(ResearchRoot() / L"profile_guard.txt", std::ios::trunc);
            if (!f) return;
            const bool betaMatch = image.timestamp == kBetaTimestamp &&
                image.imageSize == kBetaImageSize &&
                image.entryPoint == kBetaEntryRva;
            f << "scanner=T9 Open Beta\n"
              << "timestamp=" << Hex(image.timestamp, 8) << "\n"
              << "image_size=" << Hex(image.imageSize, 8) << "\n"
              << "entry_rva=" << Hex(image.entryPoint, 8) << "\n"
              << "beta_match=" << (betaMatch ? 1 : 0) << "\n"
              << "alpha_match=" << (AlphaFingerprintMatches(image) ? 1 : 0) << "\n"
              << "alpha_scanner_armed=0\n";
            if (!betaMatch) f << "scanner_aborted=1\n";
        }

        void WriteModuleMap(const std::vector<ModuleInfo>& modules)
        {
            std::ofstream f(ResearchRoot() / L"modules.csv", std::ios::trunc);
            if (!f) return;
            f << "module_name,base,size,path,timestamp\n";
            for (const auto& module : modules)
            {
                f << '"' << CsvEscape(module.name) << "\","
                  << Hex(module.base) << ','
                  << Hex(module.size) << ",\""
                  << CsvEscape(module.path) << "\","
                  << Hex(module.timestamp, 8) << '\n';
            }
        }

        void WriteMemoryMap(const std::vector<MemoryRegion>& regions)
        {
            std::ofstream f(ResearchRoot() / L"memory_regions.csv", std::ios::trunc);
            if (!f) return;
            f << "base,end,size,state,protection,type,module,tags\n";
            for (const auto& region : regions)
            {
                f << Hex(region.base) << ','
                  << Hex(region.end) << ','
                  << Hex(region.size) << ','
                  << Hex(region.state) << ",\""
                  << ProtectionName(region.protect) << "\","
                  << Hex(region.type) << ",\""
                  << CsvEscape(region.module) << "\",\""
                  << CsvEscape(region.tags) << "\"\n";
            }
        }

        std::string BytesToHex(const unsigned char* data, std::size_t size)
        {
            std::ostringstream out;
            out << std::uppercase << std::hex << std::setfill('0');
            for (std::size_t i = 0; i < size; ++i)
                out << std::setw(2) << static_cast<unsigned>(data[i]);
            return out.str();
        }

        std::string ReadInstructionBytes(std::uintptr_t address, std::size_t size = 12)
        {
            std::array<unsigned char, 16> bytes{};
            const auto count = (std::min)(bytes.size(), size);
            if (!ReadBytes(address, bytes.data(), count)) return {};
            return BytesToHex(bytes.data(), count);
        }

        std::uintptr_t ApproxFunctionStart(const std::vector<unsigned char>& bytes, std::uintptr_t sectionRva, std::size_t offset)
        {
            const std::size_t limit = offset > 0x300 ? offset - 0x300 : 0;
            for (std::size_t i = offset; i > limit; --i)
            {
                const std::size_t p = i - 1;
                if (bytes[p] == 0xCC || bytes[p] == 0xC3)
                    return sectionRva + p + 1;
                if (p + 4 < bytes.size() &&
                    bytes[p] == 0x40 &&
                    (bytes[p + 1] == 0x53 || bytes[p + 1] == 0x55 || bytes[p + 1] == 0x56 || bytes[p + 1] == 0x57))
                {
                    return sectionRva + p;
                }
                if (p + 4 < bytes.size() &&
                    bytes[p] == 0x48 && bytes[p + 1] == 0x89 &&
                    (bytes[p + 2] == 0x5C || bytes[p + 2] == 0x6C || bytes[p + 2] == 0x74 || bytes[p + 2] == 0x7C))
                {
                    return sectionRva + p;
                }
            }
            return sectionRva + limit;
        }

        const SectionInfo* FindSection(const ImageLayout& image, std::uintptr_t rva)
        {
            for (const auto& section : image.sections)
            {
                if (rva >= section.rva && rva < section.rva + section.size)
                    return &section;
            }
            return nullptr;
        }

        std::vector<XrefHit> ScanStateXrefs(const ImageLayout& image)
        {
            struct Target
            {
                const char* name;
                std::uintptr_t rva;
            };
            const auto& r = BetaRvas();
            const Target targets[] = {
                { "stateA", r.stateA },
                { "stateB", r.stateB },
                { "stateC", r.stateC },
                { "ready", r.readyByte },
                { "auth_slot", r.authManagerSlot },
                { "force_ready", r.forceReadyFlag },
            };

            std::vector<XrefHit> hits;
            std::ofstream f(ResearchRoot() / L"state_global_xrefs.csv", std::ios::trunc);
            if (!f) return hits;
            f << "target,target_rva,instruction_rva,instruction_bytes,instruction_type,access,containing_function_start\n";

            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE) || section.size < 7)
                    continue;
                const std::size_t size = static_cast<std::size_t>((std::min<std::uintptr_t>)(section.size, image.imageSize - section.rva));
                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva), bytes.data(), size, &got) || got < 7)
                    continue;

                for (std::size_t i = 0; i + 7 <= got; ++i)
                {
                    std::size_t instructionLength = 0;
                    std::size_t displacementOffset = 0;
                    const char* type = nullptr;
                    const char* access = "reference";

                    if ((bytes[i] == 0x48 || bytes[i] == 0x4C) && bytes[i + 1] == 0x8D && (bytes[i + 2] & 0xC7) == 0x05)
                    {
                        instructionLength = 7;
                        displacementOffset = 3;
                        type = "LEA_RIP";
                    }
                    else if ((bytes[i] == 0x48 || bytes[i] == 0x4C || bytes[i] == 0x8B || bytes[i] == 0x0F) &&
                        (bytes[i + 1] == 0x8B || bytes[i + 1] == 0x0F || bytes[i] == 0x8B) &&
                        (bytes[i + 2] & 0xC7) == 0x05)
                    {
                        instructionLength = 7;
                        displacementOffset = 3;
                        type = "MOV_RIP";
                        access = "read";
                    }
                    else if ((bytes[i] == 0x80 || bytes[i] == 0x81 || bytes[i] == 0x83 || bytes[i] == 0x39 || bytes[i] == 0x3B) &&
                        (bytes[i + 1] & 0xC7) == 0x05)
                    {
                        instructionLength = 6;
                        displacementOffset = 2;
                        type = "CMP_OP_RIP";
                        access = "compare";
                    }
                    else if ((bytes[i] == 0xC6 || bytes[i] == 0xC7 || bytes[i] == 0x89) &&
                        (bytes[i + 1] & 0xC7) == 0x05)
                    {
                        instructionLength = 6;
                        displacementOffset = 2;
                        type = "WRITE_RIP";
                        access = "write";
                    }
                    if (!instructionLength || i + displacementOffset + 4 > got)
                        continue;

                    std::int32_t disp = 0;
                    std::memcpy(&disp, bytes.data() + i + displacementOffset, sizeof(disp));
                    const auto instruction = image.base + section.rva + i;
                    const auto target = instruction + instructionLength + disp;
                    if (target < image.base || target >= image.base + image.imageSize)
                        continue;
                    const auto targetRva = target - image.base;

                    for (const auto& wanted : targets)
                    {
                        if (targetRva != wanted.rva) continue;
                        XrefHit hit{};
                        hit.target = wanted.name;
                        hit.targetRva = wanted.rva;
                        hit.instructionRva = instruction - image.base;
                        hit.functionRva = ApproxFunctionStart(bytes, section.rva, i);
                        hit.bytes = ReadInstructionBytes(instruction);
                        hit.type = type;
                        hit.access = access;
                        hits.push_back(hit);
                        f << hit.target << ','
                          << Hex(hit.targetRva) << ','
                          << Hex(hit.instructionRva) << ",\""
                          << hit.bytes << "\","
                          << hit.type << ','
                          << hit.access << ','
                          << Hex(hit.functionRva) << '\n';
                    }
                }
            }
            return hits;
        }

        std::size_t ScanRecoveredFunctionCallers(const ImageLayout& image)
        {
            struct Target
            {
                const char* name;
                std::uintptr_t rva;
            };
            const auto& r = BetaRvas();
            const Target targets[] = {
                { "command", r.command },
                { "transition", r.transition },
                { "initA", r.initA },
                { "initB", r.initB },
                { "usernameContext", r.usernameContext },
                { "setUsername", r.setUsername },
            };

            std::ofstream f(ResearchRoot() / L"recovered_function_callers.csv", std::ios::trunc);
            if (!f) return 0;
            f << "function_name,function_target,caller_instruction_rva,caller_function_start,nearby_instructions_bytes\n";
            std::size_t count = 0;

            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE) || section.size < 5)
                    continue;
                const std::size_t size = static_cast<std::size_t>((std::min<std::uintptr_t>)(section.size, image.imageSize - section.rva));
                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva), bytes.data(), size, &got) || got < 5)
                    continue;

                for (std::size_t i = 0; i + 5 <= got; ++i)
                {
                    if (bytes[i] != 0xE8) continue;
                    std::int32_t rel = 0;
                    std::memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
                    const auto caller = image.base + section.rva + i;
                    const auto target = caller + 5 + rel;
                    if (target < image.base || target >= image.base + image.imageSize)
                        continue;
                    const auto targetRva = target - image.base;

                    for (const auto& wanted : targets)
                    {
                        if (targetRva != wanted.rva) continue;
                        const auto start = i > 8 ? i - 8 : 0;
                        const auto available = (std::min<std::size_t>)(32, got - start);
                        f << wanted.name << ','
                          << Hex(wanted.rva) << ','
                          << Hex(caller - image.base) << ','
                          << Hex(ApproxFunctionStart(bytes, section.rva, i)) << ",\""
                          << BytesToHex(bytes.data() + start, available) << "\"\n";
                        ++count;
                    }
                }
            }
            return count;
        }

        const std::vector<std::pair<std::string, bool>>& FrontendMarkers()
        {
            static const std::vector<std::pair<std::string, bool>> markers = {
                { "core_frontend", true },
                { "MP Offline", true },
                { "MP Arena Offline", true },
                { "ZM Offline", true },
                { "lua/Lobby/Lobby.lua", true },
                { "lui_menu_data", true },
                { "lobbyNetworkMode", true },
                { "OnDWDisconnect", true },
                { "OnLobbyOnlineUpdate", true },
                { "CONNECTING", true },
                { "NOTICE", true },
                { "online services", true },
                { "fence", true },
                { "frontend fence", true },
                { "disconnect", true },
                { "disconnected", true },
                { "EXE/DISCONNECTED", true },
                { "EXE/SERVER_DISCONNECTED", true },
                { "SIGNINCHANGED", true },
                { "SIGNEDOUT", true },
                { "CONNECTION_STATE_DISCONNECTED", true },
                { "CONNECTION_STATE_CONNECTING", true },
                { "AuthenticationService", true },
                { "SessionService", true },
                { "No Multiplayer", true },
                { "NetworkModeMismatch", true },
                { "InvalidLobby", true },
                { "OnValidateSessionModeChangeAllowed", true },
                { "OnSessionModeChange", true },
                { "OnErrorShutdown", true },
                { "OnComError", true },
                { "comErrorInProgress", true },
                { "errorMsg", true },
                { "signedInDW", true },
                { "signInState", true },
                { "connectionState", true },
                { "platformAppearOffline", true },
                { "sessionActive", true },
                { "sessionStatus", true },
                { "lobby State message failed or timed out.", true },
                { "frontend", false },
                { "offline", false },
                { "online", false },
                { "connecting", false },
                { "connection", false },
                { "lobby", false },
                { "lobby state", false },
                { "party", false },
                { "party state", false },
                { "session", false },
                { "sessionmode", false },
                { "session mode", false },
                { "matchmaking", false },
                { "authentication", false },
                { "signin", false },
                { "signedin", false },
                { "signedout", false },
                { "sign in", false },
                { "login", false },
                { "controller", false },
                { "local user", false },
                { "error", false },
                { "failure", false },
                { "crossplay", false },
                { "network mode", false },
                { "networkmode", false },
                { "Demonware", false },
                { "DW", false },
                { "Battle.net", false },
                { "BNet", false },
                { "LUI", false },
                { "Lua", false },
                { "menu", false },
                { "transition", false },
                { "ZM", false },
                { "MP", false },
            };
            return markers;
        }

        std::string Lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        }

        bool ContainsMarkerTerm(const std::string& text)
        {
            const std::string lower = Lower(text);
            static const char* terms[] = {
                "lobby", "party", "frontend", "network", "networkmode", "online", "offline",
                "connect", "disconnect", "connection", "demonware", "dw", "battle.net", "bnet",
                "signin", "signedin", "signedout", "login", "session", "sessionmode", "fence",
                "authentication", "controller", "local user", "error", "failure", "transition",
                "lui", "lua", "mp", "zm"
            };
            for (const char* term : terms)
                if (lower.find(term) != std::string::npos)
                    return true;
            return false;
        }

        std::string ContextAscii(const std::vector<unsigned char>& bytes, std::size_t offset)
        {
            const std::size_t begin = offset > 64 ? offset - 64 : 0;
            const std::size_t end = (std::min)(bytes.size(), offset + 160);
            std::string out;
            out.reserve(end - begin);
            for (std::size_t i = begin; i < end; ++i)
            {
                const unsigned char c = bytes[i];
                out.push_back(c >= 0x20 && c <= 0x7E ? static_cast<char>(c) : ' ');
            }
            return out;
        }

        std::vector<std::size_t> FindAsciiInsensitive(const std::vector<unsigned char>& bytes, const std::string& marker)
        {
            std::vector<std::size_t> matches;
            if (marker.empty() || bytes.size() < marker.size()) return matches;
            const std::string needle = Lower(marker);
            for (std::size_t i = 0; i + marker.size() <= bytes.size(); ++i)
            {
                bool ok = true;
                for (std::size_t j = 0; j < marker.size(); ++j)
                {
                    if (static_cast<char>(std::tolower(bytes[i + j])) != needle[j])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok) matches.push_back(i);
            }
            return matches;
        }

        std::vector<std::size_t> FindUtf16Insensitive(const std::vector<unsigned char>& bytes, const std::string& marker)
        {
            std::vector<std::size_t> matches;
            if (marker.empty() || bytes.size() < marker.size() * 2) return matches;
            const std::string needle = Lower(marker);
            for (std::size_t i = 0; i + marker.size() * 2 <= bytes.size(); ++i)
            {
                bool ok = true;
                for (std::size_t j = 0; j < marker.size(); ++j)
                {
                    const unsigned char c = bytes[i + j * 2];
                    const unsigned char z = bytes[i + j * 2 + 1];
                    if (z != 0 || static_cast<char>(std::tolower(c)) != needle[j])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok) matches.push_back(i);
            }
            return matches;
        }

        std::vector<StringHit> ScanMarkersInRegions(
            const ImageLayout& image,
            const std::vector<MemoryRegion>& regions,
            bool mainImageOnly,
            const std::filesystem::path& outputFile)
        {
            std::vector<StringHit> hits;
            std::ofstream f(outputFile, std::ios::trunc);
            if (!f) return hits;
            f << "address,rva,region_base,module,marker,encoding,priority,context\n";

            struct NormalizedMarker
            {
                std::string original;
                std::string lower;
                bool highPriority = false;
            };
            std::vector<NormalizedMarker> markers;
            markers.reserve(FrontendMarkers().size());
            for (const auto& marker : FrontendMarkers())
                markers.push_back({ marker.first, Lower(marker.first), marker.second });

            const auto emitRun = [&](const MemoryRegion& region, std::uintptr_t cursor,
                const std::vector<unsigned char>& bytes, std::size_t start, std::size_t charCount,
                bool utf16)
            {
                if (charCount < 3 || charCount > 64 * 1024)
                    return;
                std::string text;
                text.reserve(charCount);
                if (utf16)
                {
                    for (std::size_t i = 0; i < charCount; ++i)
                        text.push_back(static_cast<char>(bytes[start + i * 2]));
                }
                else
                {
                    text.assign(reinterpret_cast<const char*>(bytes.data() + start), charCount);
                }
                const std::string lowerText = Lower(text);
                for (const auto& marker : markers)
                {
                    if (marker.lower.empty() || marker.lower.size() > lowerText.size())
                        continue;
                    std::size_t pos = 0;
                    while ((pos = lowerText.find(marker.lower, pos)) != std::string::npos)
                    {
                        StringHit hit{};
                        hit.address = cursor + start + pos * (utf16 ? 2u : 1u);
                        hit.regionBase = region.base;
                        hit.module = region.module;
                        hit.marker = marker.original;
                        hit.encoding = utf16 ? "utf16le" : "ascii";
                        const std::size_t contextBegin = pos > 64 ? pos - 64 : 0;
                        const std::size_t contextLength = (std::min<std::size_t>)(224, text.size() - contextBegin);
                        hit.context = text.substr(contextBegin, contextLength);
                        hit.highPriority = marker.highPriority;
                        hits.push_back(hit);
                        f << Hex(hit.address) << ','
                          << (image.base && hit.address >= image.base && hit.address < image.base + image.imageSize ? Hex(hit.address - image.base) : "") << ','
                          << Hex(hit.regionBase) << ",\""
                          << CsvEscape(hit.module) << "\",\""
                          << CsvEscape(hit.marker) << "\","
                          << hit.encoding << ','
                          << (hit.highPriority ? 1 : 0) << ",\""
                          << CsvEscape(hit.context) << "\"\n";
                        pos += (std::max<std::size_t>)(1, marker.lower.size());
                    }
                }
            };

            for (const auto& region : regions)
            {
                if (mainImageOnly && !(image.base && region.base >= image.base && region.base < image.base + image.imageSize))
                    continue;
                if (!IsReadableProtect(region.protect) || (region.protect & PAGE_GUARD) || !region.size)
                    continue;

                std::uintptr_t cursor = region.base;
                std::size_t remaining = region.size;
                while (remaining)
                {
                    const std::size_t chunkSize = (std::min)(remaining, kMaxRegionRead);
                    std::vector<unsigned char> bytes(chunkSize);
                    SIZE_T got = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(cursor), bytes.data(), chunkSize, &got) && got)
                    {
                        bytes.resize(got);

                        // Parse printable ASCII strings once, then match all frontend
                        // markers inside those strings. The previous implementation
                        // rescanned every byte once per marker and could take minutes.
                        for (std::size_t i = 0; i < bytes.size();)
                        {
                            while (i < bytes.size() && (bytes[i] < 0x20 || bytes[i] > 0x7E)) ++i;
                            const std::size_t runStart = i;
                            while (i < bytes.size() && bytes[i] >= 0x20 && bytes[i] <= 0x7E) ++i;
                            if (i > runStart)
                                emitRun(region, cursor, bytes, runStart, i - runStart, false);
                        }

                        // Same pass for the common ASCII subset of UTF-16LE strings.
                        for (std::size_t i = 0; i + 1 < bytes.size();)
                        {
                            while (i + 1 < bytes.size() &&
                                !(bytes[i] >= 0x20 && bytes[i] <= 0x7E && bytes[i + 1] == 0)) ++i;
                            const std::size_t runStart = i;
                            std::size_t chars = 0;
                            while (i + 1 < bytes.size() && bytes[i] >= 0x20 && bytes[i] <= 0x7E && bytes[i + 1] == 0)
                            {
                                i += 2;
                                ++chars;
                            }
                            if (chars)
                                emitRun(region, cursor, bytes, runStart, chars, true);
                            else
                                ++i;
                        }
                    }
                    cursor += chunkSize;
                    remaining -= chunkSize;
                    Sleep(0);
                }
            }
            return hits;
        }

        std::vector<XrefHit> ScanStringXrefs(const ImageLayout& image, const std::vector<StringHit>& stringHits)
        {
            std::vector<XrefHit> hits;
            std::ofstream pointerRefs(ResearchRoot() / L"static_frontend_lua_pointer_refs.csv", std::ios::trunc);
            std::ofstream codeRefs(ResearchRoot() / L"static_frontend_lua_xrefs.csv", std::ios::trunc);
            std::ofstream candidates(ResearchRoot() / L"frontend_lua_function_candidates.csv", std::ios::trunc);
            if (!pointerRefs || !codeRefs || !candidates) return hits;
            pointerRefs << "string_marker,string_rva,pointer_rva,section\n";
            codeRefs << "string_marker,string_rva,instruction_rva,function_start,access,bytes\n";
            candidates << "function_start,score,reason,markers\n";

            std::vector<const StringHit*> imageStrings;
            imageStrings.reserve(stringHits.size());
            std::unordered_map<std::uintptr_t, const StringHit*> exactByAddress;
            exactByAddress.reserve(stringHits.size() * 2 + 1);
            for (const auto& hit : stringHits)
            {
                if (hit.address < image.base || hit.address >= image.base + image.imageSize)
                    continue;
                imageStrings.push_back(&hit);
                exactByAddress.emplace(hit.address, &hit);
            }
            std::sort(imageStrings.begin(), imageStrings.end(), [](const StringHit* a, const StringHit* b)
            {
                return a->address < b->address;
            });

            const auto findStringAt = [&](std::uintptr_t target) -> const StringHit*
            {
                const auto exact = exactByAddress.find(target);
                if (exact != exactByAddress.end())
                    return exact->second;
                const auto it = std::upper_bound(imageStrings.begin(), imageStrings.end(), target,
                    [](std::uintptr_t value, const StringHit* item)
                    {
                        return value < item->address;
                    });
                if (it == imageStrings.begin())
                    return nullptr;
                const StringHit* candidate = *(it - 1);
                const std::size_t bytesPerChar = candidate->encoding == "utf16le" ? 2u : 1u;
                const std::uintptr_t end = candidate->address + candidate->marker.size() * bytesPerChar;
                return target >= candidate->address && target < end ? candidate : nullptr;
            };

            // First build exact pointer slots in non-executable image sections. This
            // catches frontend/Lua tables where code addresses the table slot rather
            // than the string itself.
            std::unordered_map<std::uintptr_t, const StringHit*> pointerSlots;
            pointerSlots.reserve(imageStrings.size() * 2 + 1);
            for (const auto& section : image.sections)
            {
                if (section.characteristics & IMAGE_SCN_MEM_EXECUTE)
                    continue;
                const std::size_t size = static_cast<std::size_t>((std::min<std::uintptr_t>)(section.size, image.imageSize - section.rva));
                if (size < sizeof(std::uintptr_t)) continue;
                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva), bytes.data(), size, &got) || got < sizeof(std::uintptr_t))
                    continue;
                bytes.resize(got);
                for (std::size_t i = 0; i + sizeof(std::uintptr_t) <= bytes.size(); i += sizeof(std::uintptr_t))
                {
                    std::uintptr_t value = 0;
                    std::memcpy(&value, bytes.data() + i, sizeof(value));
                    const auto match = exactByAddress.find(value);
                    if (match == exactByAddress.end())
                        continue;
                    const std::uintptr_t slot = image.base + section.rva + i;
                    pointerSlots.emplace(slot, match->second);
                    pointerRefs << '\"' << CsvEscape(match->second->marker) << "\","
                        << Hex(match->second->address - image.base) << ','
                        << Hex(section.rva + i) << ','
                        << section.name << '\n';
                }
            }

            std::unordered_map<std::uintptr_t, std::vector<std::string>> markersByFunction;
            for (const auto& section : image.sections)
            {
                if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                const std::size_t size = static_cast<std::size_t>((std::min<std::uintptr_t>)(section.size, image.imageSize - section.rva));
                if (!size) continue;
                std::vector<unsigned char> bytes(size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(image.base + section.rva), bytes.data(), size, &got) || got < 7)
                    continue;
                bytes.resize(got);

                for (std::size_t i = 0; i + 7 <= bytes.size(); ++i)
                {
                    std::size_t instructionLength = 0;
                    std::size_t displacementOffset = 0;
                    const char* access = "reference";
                    if ((bytes[i] == 0x48 || bytes[i] == 0x4C) && (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B) &&
                        (bytes[i + 2] & 0xC7) == 0x05)
                    {
                        instructionLength = 7;
                        displacementOffset = 3;
                        access = bytes[i + 1] == 0x8B ? "read" : "address";
                    }
                    if (!instructionLength) continue;

                    std::int32_t disp = 0;
                    std::memcpy(&disp, bytes.data() + i + displacementOffset, sizeof(disp));
                    const auto instruction = image.base + section.rva + i;
                    const auto target = instruction + instructionLength + disp;
                    const StringHit* stringHit = findStringAt(target);
                    const char* resolvedAccess = access;
                    if (!stringHit)
                    {
                        const auto slot = pointerSlots.find(target);
                        if (slot != pointerSlots.end())
                        {
                            stringHit = slot->second;
                            resolvedAccess = "pointer_slot";
                        }
                    }
                    if (!stringHit)
                        continue;

                    const auto function = ApproxFunctionStart(bytes, section.rva, i);
                    XrefHit hit{};
                    hit.target = stringHit->marker;
                    hit.targetRva = stringHit->address - image.base;
                    hit.instructionRva = instruction - image.base;
                    hit.functionRva = function;
                    hit.bytes = ReadInstructionBytes(instruction);
                    hit.access = resolvedAccess;
                    hits.push_back(hit);
                    markersByFunction[function].push_back(stringHit->marker);
                    codeRefs << '\"' << CsvEscape(stringHit->marker) << "\","
                        << Hex(hit.targetRva) << ','
                        << Hex(hit.instructionRva) << ','
                        << Hex(hit.functionRva) << ','
                        << hit.access << ",\""
                        << hit.bytes << "\"\n";
                }
            }

            std::size_t printedGateCandidates = 0;
            for (auto& item : markersByFunction)
            {
                auto& markers = item.second;
                std::sort(markers.begin(), markers.end());
                markers.erase(std::unique(markers.begin(), markers.end()), markers.end());
                int score = 0;
                std::string reason;
                for (const auto& marker : markers)
                {
                    const auto lower = Lower(marker);
                    if (lower.find("core_frontend") != std::string::npos) { score += 5; reason += "references_core_frontend;"; }
                    if (lower.find("mp offline") != std::string::npos) { score += 7; reason += "references_MP_Offline;"; }
                    if (lower.find("zm offline") != std::string::npos) { score += 5; reason += "references_ZM_Offline;"; }
                    if (lower.find("no multiplayer") != std::string::npos) { score += 10; reason += "references_No_Multiplayer;"; }
                    if (lower.find("networkmodemismatch") != std::string::npos) { score += 10; reason += "references_NetworkModeMismatch;"; }
                    if (lower.find("invalidlobby") != std::string::npos) { score += 7; reason += "references_InvalidLobby;"; }
                    if (lower.find("onvalidatesessionmodechangeallowed") != std::string::npos) { score += 10; reason += "references_session_mode_validation;"; }
                    if (lower.find("onsessionmodechange") != std::string::npos) { score += 8; reason += "references_session_mode_change;"; }
                    if (lower.find("ondwdisconnect") != std::string::npos) { score += 9; reason += "references_OnDWDisconnect;"; }
                    if (lower.find("disconnect") != std::string::npos || lower.find("disconnected") != std::string::npos)
                    { score += 5; reason += "references_disconnect;"; }
                    if (lower.find("fence") != std::string::npos) { score += 6; reason += "references_fence;"; }
                    if (lower.find("signin") != std::string::npos || lower.find("signedin") != std::string::npos ||
                        lower.find("signedout") != std::string::npos)
                    { score += 5; reason += "references_signin_state;"; }
                    if (lower.find("signedindw") != std::string::npos) { score += 8; reason += "references_signedInDW;"; }
                    if (lower.find("demonware") != std::string::npos || lower == "dw")
                    { score += 5; reason += "references_DW;"; }
                    if (lower.find("battle.net") != std::string::npos || lower.find("bnet") != std::string::npos)
                    { score += 5; reason += "references_BNet;"; }
                    if (lower.find("networkmode") != std::string::npos || lower.find("network mode") != std::string::npos)
                    { score += 7; reason += "references_network_mode;"; }
                    if (lower.find("sessionmode") != std::string::npos || lower.find("session mode") != std::string::npos)
                    { score += 7; reason += "references_session_mode;"; }
                    if (lower.find("connectionstate") != std::string::npos || lower.find("connecting") != std::string::npos || lower.find("connection_state") != std::string::npos)
                    { score += 5; reason += "references_connection_state;"; }
                    if (lower.find("online services") != std::string::npos) { score += 4; reason += "references_online_services;"; }
                    if (lower.find("lobby") != std::string::npos) { score += 2; reason += "references_lobby;"; }
                    if (lower.find("party") != std::string::npos) { score += 2; reason += "references_party;"; }
                    if (lower.find("transition") != std::string::npos) { score += 4; reason += "references_transition;"; }
                    if (lower.find("oncomerror") != std::string::npos || lower.find("onerrorshutdown") != std::string::npos ||
                        lower.find("comerrorinprogress") != std::string::npos)
                    { score += 7; reason += "references_frontend_error_path;"; }
                    else if (lower.find("error") != std::string::npos || lower.find("failure") != std::string::npos)
                    { score += 2; reason += "references_error;"; }
                }
                if (score == 0) score = static_cast<int>(markers.size());
                std::ostringstream markerList;
                for (std::size_t i = 0; i < markers.size(); ++i)
                {
                    if (i) markerList << '|';
                    markerList << markers[i];
                }
                candidates << Hex(item.first) << ','
                    << score << ",\""
                    << CsvEscape(reason) << "\",\""
                    << CsvEscape(markerList.str()) << "\"\n";

                if (score >= 5 && printedGateCandidates < 48)
                {
                    std::printf("[BETA-GATE] candidate function=%s score=%d reason=%s markers=%s\n",
                        Hex(item.first).c_str(), score, reason.c_str(), markerList.str().c_str());
                    std::fflush(stdout);
                    ++printedGateCandidates;
                }
            }
            return hits;
        }

        std::size_t WriteOfflineCandidates(const std::vector<XrefHit>& stringXrefs, const std::vector<XrefHit>& stateXrefs)
        {
            std::unordered_map<std::uintptr_t, std::string> reasonByFunction;
            for (const auto& hit : stringXrefs)
            {
                const auto lower = Lower(hit.target);
                if (lower.find("core_frontend") != std::string::npos) reasonByFunction[hit.functionRva] += "references_core_frontend;";
                if (lower.find("mp offline") != std::string::npos) reasonByFunction[hit.functionRva] += "references_MP_Offline;";
                if (lower.find("zm offline") != std::string::npos) reasonByFunction[hit.functionRva] += "references_ZM_Offline;";
                if (lower.find("ondwdisconnect") != std::string::npos) reasonByFunction[hit.functionRva] += "references_OnDWDisconnect;";
                if (lower.find("disconnect") != std::string::npos || lower.find("disconnected") != std::string::npos)
                    reasonByFunction[hit.functionRva] += "references_disconnect;";
                if (lower.find("fence") != std::string::npos) reasonByFunction[hit.functionRva] += "references_fence;";
                if (lower.find("signin") != std::string::npos || lower.find("signedin") != std::string::npos ||
                    lower.find("signedout") != std::string::npos)
                    reasonByFunction[hit.functionRva] += "references_signin_state;";
                if (lower.find("demonware") != std::string::npos || lower == "dw")
                    reasonByFunction[hit.functionRva] += "references_DW;";
                if (lower.find("battle.net") != std::string::npos || lower.find("bnet") != std::string::npos)
                    reasonByFunction[hit.functionRva] += "references_BNet;";
                if (lower.find("networkmode") != std::string::npos || lower.find("network mode") != std::string::npos)
                    reasonByFunction[hit.functionRva] += "references_network_mode;";
                if (lower.find("sessionmode") != std::string::npos || lower.find("session mode") != std::string::npos)
                    reasonByFunction[hit.functionRva] += "references_session_mode;";
                if (lower.find("connecting") != std::string::npos || lower.find("connection") != std::string::npos)
                    reasonByFunction[hit.functionRva] += "references_CONNECTION;";
                if (lower.find("online services") != std::string::npos) reasonByFunction[hit.functionRva] += "references_online_services;";
                if (lower.find("party") != std::string::npos) reasonByFunction[hit.functionRva] += "references_party;";
                if (lower.find("lobby") != std::string::npos) reasonByFunction[hit.functionRva] += "references_lobby;";
            }
            for (const auto& hit : stateXrefs)
            {
                if (hit.target == "stateB") reasonByFunction[hit.functionRva] += "reads_stateB;";
                if (hit.target == "stateA") reasonByFunction[hit.functionRva] += "reads_stateA;";
                if (hit.target == "stateC") reasonByFunction[hit.functionRva] += "reads_stateC;";
            }

            std::ofstream f(ResearchRoot() / L"offline_frontend_candidates.csv", std::ios::trunc);
            if (!f) return 0;
            f << "function_start,score,reason\n";
            std::size_t count = 0;
            for (const auto& item : reasonByFunction)
            {
                const std::string lower = Lower(item.second);
                int score = 0;
                if (lower.find("core_frontend") != std::string::npos) score += 5;
                if (lower.find("mp_offline") != std::string::npos || lower.find("zm_offline") != std::string::npos) score += 5;
                if (lower.find("ondwdisconnect") != std::string::npos) score += 7;
                if (lower.find("disconnect") != std::string::npos) score += 5;
                if (lower.find("fence") != std::string::npos) score += 6;
                if (lower.find("signin") != std::string::npos) score += 5;
                if (lower.find("network_mode") != std::string::npos) score += 6;
                if (lower.find("session_mode") != std::string::npos) score += 6;
                if (lower.find("dw") != std::string::npos || lower.find("bnet") != std::string::npos) score += 5;
                if (lower.find("state") != std::string::npos) score += 3;
                if (lower.find("connection") != std::string::npos) score += 3;
                if (lower.find("party") != std::string::npos || lower.find("lobby") != std::string::npos) score += 2;
                if (score <= 0) continue;
                f << Hex(item.first) << ','
                  << score << ",\""
                  << CsvEscape(item.second) << "\"\n";
                ++count;
            }
            return count;
        }

        bool WriteBinary(const std::filesystem::path& path, std::uintptr_t address, std::size_t size)
        {
            if (!address || !size) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) ||
                mbi.State != MEM_COMMIT ||
                (mbi.Protect & PAGE_GUARD) ||
                (mbi.Protect & PAGE_NOACCESS) ||
                !IsReadableProtect(mbi.Protect))
            {
                return false;
            }
            const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto regionEnd = regionBase + mbi.RegionSize;
            if (address >= regionEnd) return false;
            size = (std::min<std::size_t>)(size, regionEnd - address);
            std::vector<unsigned char> bytes(size);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), bytes.data(), size, &got) || !got)
                return false;
            std::ofstream f(path, std::ios::binary | std::ios::trunc);
            if (!f) return false;
            f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(got));
            return true;
        }

        std::uintptr_t NeighborhoodBase(std::uintptr_t address)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
                return address;
            const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            return address > regionBase + 0x80 ? address - 0x80 : regionBase;
        }

        std::string StateNotes(DWORD a, DWORD b, DWORD c, std::uint8_t ready, std::uintptr_t auth)
        {
            std::string notes;
            if (b == 0x2011u && a == 2u && c == 0x15u) notes += "possible_service_failure_state;";
            if (b == 0x2014u && a == 1u && c == 0x14u) notes += "recovered_frontend_handoff_state;";
            if (ready) notes += "ready_byte_nonzero;";
            if (auth) notes += "auth_ptr_nonzero;";
            if (notes.empty()) notes = "state_change";
            return notes;
        }

        void WriteStateSnapshot(
            int index,
            std::uintptr_t base,
            DWORD a,
            DWORD b,
            DWORD c,
            std::uint8_t ready,
            std::uintptr_t auth,
            DWORD forceReady)
        {
            const auto& r = BetaRvas();
            const auto name = [index](const char* suffix)
            {
                wchar_t file[128]{};
                swprintf_s(file, L"state_snapshot_%03d_%S", index, suffix);
                return ResearchRoot() / file;
            };

            {
                wchar_t file[128]{};
                swprintf_s(file, L"state_snapshot_%03d.txt", index);
                std::ofstream f(ResearchRoot() / file, std::ios::trunc);
                if (f)
                {
                    f << "base=" << Hex(base) << "\n"
                      << "stateA=" << Hex(a) << "\n"
                      << "stateB=" << Hex(b) << "\n"
                      << "stateC=" << Hex(c) << "\n"
                      << "ready=" << Hex(ready) << "\n"
                      << "auth_ptr=" << Hex(auth) << "\n"
                      << "force_ready=" << Hex(forceReady) << "\n"
                      << "notes=" << StateNotes(a, b, c, ready, auth) << "\n";
                }
            }

            WriteBinary(name("stateA.bin"), NeighborhoodBase(base + r.stateA), kSnapshotBytes);
            WriteBinary(name("stateB.bin"), NeighborhoodBase(base + r.stateB), kSnapshotBytes);
            WriteBinary(name("stateC.bin"), NeighborhoodBase(base + r.stateC), kSnapshotBytes);
            if (auth)
                WriteBinary(name("auth.bin"), auth, kSnapshotBytes);
        }

        DWORD WINAPI StateMonitorThread(LPVOID)
        {
            ImageLayout image{};
            if (!CurrentFingerprint(&image))
            {
                g_stateMonitorRunning.store(false);
                return 1;
            }

            const auto& r = BetaRvas();
            const std::uintptr_t base = image.base;
            std::ofstream timeline(ResearchRoot() / L"frontend_state_timeline.csv", std::ios::app);
            if (timeline.tellp() == 0)
                timeline << "timestamp_ms,stateA,stateB,stateC,ready,auth_ptr,force_ready,current_thread,notes\n";

            PrintBeta("lightweight state tracker started");
            AppendProgress("state_monitor_started");

            DWORD lastA = 0xFFFFFFFFu;
            DWORD lastB = 0xFFFFFFFFu;
            DWORD lastC = 0xFFFFFFFFu;
            DWORD lastForce = 0xFFFFFFFFu;
            std::uint8_t lastReady = 0xFFu;
            std::uintptr_t lastAuth = UINTPTR_MAX;
            int snapshotIndex = 0;
            const ULONGLONG start = GetTickCount64();

            while (GetTickCount64() - start < kStateMonitorMs)
            {
                DWORD a = 0, b = 0, c = 0, force = 0;
                std::uint8_t ready = 0;
                std::uintptr_t auth = 0;
                const bool ok =
                    ReadValue(base + r.stateA, a) &&
                    ReadValue(base + r.stateB, b) &&
                    ReadValue(base + r.stateC, c) &&
                    ReadValue(base + r.readyByte, ready) &&
                    ReadValue(base + r.authManagerSlot, auth) &&
                    ReadValue(base + r.forceReadyFlag, force);

                const ULONGLONG now = GetTickCount64();
                const bool changed = ok &&
                    (a != lastA || b != lastB || c != lastC || ready != lastReady || auth != lastAuth || force != lastForce);
                if (ok && changed)
                {
                    const std::string notes = StateNotes(a, b, c, ready, auth);
                    timeline << now << ','
                             << Hex(a) << ','
                             << Hex(b) << ','
                             << Hex(c) << ','
                             << Hex(ready) << ','
                             << Hex(auth) << ','
                             << Hex(force) << ','
                             << GetCurrentThreadId() << ",\""
                             << CsvEscape(notes) << "\"\n";
                    timeline.flush();

                    std::printf(
                        "[BETA-FRONTEND] state_change A=%s B=%s C=%s ready=%s auth=%s forceReady=%s notes=%s\n",
                        Hex(a).c_str(), Hex(b).c_str(), Hex(c).c_str(), Hex(ready).c_str(),
                        Hex(auth).c_str(), Hex(force).c_str(), notes.c_str());
                    std::fflush(stdout);
                    AppendProgress(
                        "frontend_state_change A=" + Hex(a) +
                        " B=" + Hex(b) +
                        " C=" + Hex(c) +
                        " ready=" + Hex(ready) +
                        " auth=" + Hex(auth) +
                        " forceReady=" + Hex(force) +
                        " notes=" + notes);

                    if (snapshotIndex < 128)
                        WriteStateSnapshot(snapshotIndex++, base, a, b, c, ready, auth, force);

                    lastA = a;
                    lastB = b;
                    lastC = c;
                    lastReady = ready;
                    lastAuth = auth;
                    lastForce = force;
                }
                Sleep(100);
            }

            AppendProgress("state_monitor_complete");
            g_stateMonitorRunning.store(false);
            return 0;
        }

        std::size_t DumpAuthObject(const ImageLayout& image)
        {
            const auto& r = BetaRvas();
            std::uintptr_t auth = 0;
            if (!ReadValue(image.base + r.authManagerSlot, auth) || !auth)
                return 0;

            const int index = 0;
            wchar_t binName[128]{};
            swprintf_s(binName, L"auth_object_%03d.bin", index);
            if (!WriteBinary(ResearchRoot() / binName, auth, 0x400))
                return 0;

            wchar_t refsName[128]{};
            swprintf_s(refsName, L"auth_object_%03d_refs.csv", index);
            std::ofstream refs(ResearchRoot() / refsName, std::ios::trunc);
            if (!refs) return 1;
            refs << "offset,value,classification,string\n";
            std::array<unsigned char, 0x400> bytes{};
            if (!ReadBytes(auth, bytes.data(), bytes.size()))
                return 1;

            for (std::size_t i = 0; i + sizeof(std::uintptr_t) <= bytes.size(); i += sizeof(std::uintptr_t))
            {
                std::uintptr_t value = 0;
                std::memcpy(&value, bytes.data() + i, sizeof(value));
                if (!value) continue;
                MEMORY_BASIC_INFORMATION mbi{};
                std::string classification;
                std::string text;
                if (VirtualQuery(reinterpret_cast<const void*>(value), &mbi, sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect & PAGE_GUARD) &&
                    !(mbi.Protect & PAGE_NOACCESS))
                {
                    if (IsExecutableProtect(mbi.Protect)) classification = "executable_or_vtable";
                    else if (IsReadableProtect(mbi.Protect)) classification = "readable_pointer";
                    if (value >= image.base && value < image.base + image.imageSize)
                        classification += "|game_image";
                    ReadCString(value, text, 160);
                }
                if (!classification.empty())
                {
                    refs << Hex(i) << ','
                         << Hex(value) << ",\""
                         << CsvEscape(classification) << "\",\""
                         << CsvEscape(text) << "\"\n";
                }
            }
            return 1;
        }

        std::string CommandLineUsername()
        {
            const char* commandLine = GetCommandLineA();
            if (!commandLine) return {};
            const char* marker = std::strstr(commandLine, "-username");
            if (!marker) return {};
            const char* p = marker + 9;
            while (*p == ' ' || *p == '=' || *p == ':' || *p == ';') ++p;
            std::string value;
            if (*p == '"')
            {
                ++p;
                while (*p && *p != '"' && value.size() < 64) value.push_back(*p++);
            }
            else
            {
                while (*p && *p != ' ' && *p != '\t' && *p != ';' && value.size() < 64) value.push_back(*p++);
            }
            return value;
        }

        std::size_t ScanIdentityNames(
            const ImageLayout& image,
            const std::vector<MemoryRegion>& regions)
        {
            std::vector<std::pair<std::string, bool>> needles = {
                { "username", false },
                { "playername", false },
                { "playerName", false },
                { "displayName", false },
                { "display_name", false },
                { "accountName", false },
                { "renameUsername", false },
                { "identity", false },
                { "platformName", false },
                { "crossplayName", false },
            };
            const std::string username = CommandLineUsername();
            if (!username.empty())
                needles.push_back({ username, true });

            std::ofstream f(ResearchRoot() / L"runtime_name_matches.csv", std::ios::trunc);
            if (!f) return 0;
            f << "address,rva,region,module,encoding,needle,nearby_bytes,nearby_readable_strings\n";
            std::size_t count = 0;

            for (const auto& region : regions)
            {
                if (!IsReadableProtect(region.protect) || region.size == 0)
                    continue;
                std::uintptr_t cursor = region.base;
                std::size_t remaining = region.size;
                while (remaining)
                {
                    const std::size_t chunkSize = (std::min)(remaining, kMaxRegionRead);
                    std::vector<unsigned char> bytes(chunkSize);
                    SIZE_T got = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(cursor), bytes.data(), chunkSize, &got) && got)
                    {
                        bytes.resize(got);
                        for (const auto& needle : needles)
                        {
                            for (const auto offset : FindAsciiInsensitive(bytes, needle.first))
                            {
                                f << Hex(cursor + offset) << ','
                                  << (image.base && cursor + offset >= image.base && cursor + offset < image.base + image.imageSize ? Hex(cursor + offset - image.base) : "") << ','
                                  << Hex(region.base) << ",\""
                                  << CsvEscape(region.module) << "\",ascii,\""
                                  << CsvEscape(needle.first) << "\",\""
                                  << BytesToHex(bytes.data() + (offset > 16 ? offset - 16 : 0), (std::min<std::size_t>)(64, bytes.size() - (offset > 16 ? offset - 16 : 0))) << "\",\""
                                  << CsvEscape(ContextAscii(bytes, offset)) << "\"\n";
                                ++count;
                            }
                            for (const auto offset : FindUtf16Insensitive(bytes, needle.first))
                            {
                                f << Hex(cursor + offset) << ','
                                  << (image.base && cursor + offset >= image.base && cursor + offset < image.base + image.imageSize ? Hex(cursor + offset - image.base) : "") << ','
                                  << Hex(region.base) << ",\""
                                  << CsvEscape(region.module) << "\",utf16le,\""
                                  << CsvEscape(needle.first) << "\",\""
                                  << BytesToHex(bytes.data() + (offset > 16 ? offset - 16 : 0), (std::min<std::size_t>)(64, bytes.size() - (offset > 16 ? offset - 16 : 0))) << "\",\""
                                  << CsvEscape(ContextAscii(bytes, offset)) << "\"\n";
                                ++count;
                            }
                        }
                    }
                    cursor += chunkSize;
                    remaining -= chunkSize;
                    Sleep(0);
                }
            }
            return count;
        }

        std::size_t DumpLuaTextChunks(const std::vector<MemoryRegion>& regions)
        {
            std::ofstream index(ResearchRoot() / L"lua_text_chunks.txt", std::ios::trunc);
            if (!index) return 0;
            std::size_t count = 0;
            for (const auto& region : regions)
            {
                if (count >= kMaxTextChunks) break;
                if (!IsReadableProtect(region.protect) || !region.size) continue;
                std::uintptr_t cursor = region.base;
                std::size_t remaining = region.size;
                while (remaining && count < kMaxTextChunks)
                {
                    const std::size_t chunkSize = (std::min)(remaining, kMaxRegionRead);
                    std::vector<unsigned char> bytes(chunkSize);
                    SIZE_T got = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(cursor), bytes.data(), chunkSize, &got) && got)
                    {
                        bytes.resize(got);
                        std::size_t i = 0;
                        while (i < bytes.size() && count < kMaxTextChunks)
                        {
                            while (i < bytes.size() && (bytes[i] < 0x20 || bytes[i] > 0x7E)) ++i;
                            const std::size_t start = i;
                            while (i < bytes.size() && bytes[i] >= 0x20 && bytes[i] <= 0x7E) ++i;
                            const std::size_t length = i - start;
                            if (length >= 96 && length <= 64 * 1024)
                            {
                                std::string text(reinterpret_cast<const char*>(bytes.data() + start), length);
                                if (ContainsMarkerTerm(text) &&
                                    (text.find("function") != std::string::npos ||
                                     text.find("LUI") != std::string::npos ||
                                     text.find("Lobby") != std::string::npos ||
                                     text.find("Frontend") != std::string::npos))
                                {
                                    wchar_t file[128]{};
                                    swprintf_s(file, L"lua_text_chunk_%03zu.txt", count);
                                    std::ofstream chunk(LuaTextRoot() / file, std::ios::trunc);
                                    if (chunk) chunk << text;
                                    index << "chunk=" << count << " address=" << Hex(cursor + start)
                                          << " length=" << length << " module=\"" << CsvEscape(region.module) << "\"\n"
                                          << text.substr(0, (std::min<std::size_t>)(text.size(), 512)) << "\n\n";
                                    ++count;
                                }
                            }
                            ++i;
                        }
                    }
                    cursor += chunkSize;
                    remaining -= chunkSize;
                    Sleep(0);
                }
            }
            return count;
        }

        std::size_t DumpLuaBytecode(const std::vector<MemoryRegion>& regions)
        {
            std::ofstream index(ResearchRoot() / L"lua_bytecode_index.csv", std::ios::trunc);
            if (!index) return 0;
            index << "address,size,header_type,source_region,module,possible_script_name\n";
            std::size_t count = 0;
            for (const auto& region : regions)
            {
                if (count >= kMaxBytecodeChunks) break;
                if (!IsReadableProtect(region.protect) || !region.size) continue;
                std::uintptr_t cursor = region.base;
                std::size_t remaining = region.size;
                while (remaining && count < kMaxBytecodeChunks)
                {
                    const std::size_t chunkSize = (std::min)(remaining, kMaxRegionRead);
                    std::vector<unsigned char> bytes(chunkSize);
                    SIZE_T got = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(cursor), bytes.data(), chunkSize, &got) && got)
                    {
                        bytes.resize(got);
                        for (std::size_t i = 0; i + 4 <= bytes.size() && count < kMaxBytecodeChunks; ++i)
                        {
                            const bool lua = bytes[i] == 0x1B && bytes[i + 1] == 'L' && bytes[i + 2] == 'u' && bytes[i + 3] == 'a';
                            const bool luaq = bytes[i] == 'L' && bytes[i + 1] == 'u' && bytes[i + 2] == 'a' && bytes[i + 3] == 'Q';
                            if (!lua && !luaq) continue;
                            const std::size_t dumpSize = (std::min<std::size_t>)(16 * 1024, bytes.size() - i);
                            wchar_t file[128]{};
                            swprintf_s(file, L"lua_bytecode_%03zu.bin", count);
                            std::ofstream chunk(LuaBytecodeRoot() / file, std::ios::binary | std::ios::trunc);
                            if (chunk) chunk.write(reinterpret_cast<const char*>(bytes.data() + i), static_cast<std::streamsize>(dumpSize));
                            index << Hex(cursor + i) << ','
                                  << dumpSize << ','
                                  << (lua ? "Lua" : "LuaQ") << ','
                                  << Hex(region.base) << ",\""
                                  << CsvEscape(region.module) << "\",\"\"\n";
                            ++count;
                        }
                    }
                    cursor += chunkSize;
                    remaining -= chunkSize;
                    Sleep(0);
                }
            }
            return count;
        }

        void WriteScreenCandidates(
            const std::vector<XrefHit>& stateXrefs,
            const std::vector<StringHit>& markers)
        {
            std::ofstream f(ResearchRoot() / L"screen_state_candidates.csv", std::ios::trunc);
            if (!f) return;
            f << "candidate,score,reason\n";
            for (const auto& hit : stateXrefs)
            {
                int score = 1;
                std::string reason = "state_global_reference;";
                if (hit.access == "write") { score += 3; reason += "writes_state;"; }
                if (hit.access == "compare") { score += 2; reason += "compares_state;"; }
                f << Hex(hit.functionRva) << ','
                  << score << ",\""
                  << CsvEscape(reason + hit.target) << "\"\n";
            }
            for (const auto& marker : markers)
            {
                if (!marker.highPriority) continue;
                f << Hex(marker.address) << ",1,\"marker=" << CsvEscape(marker.marker) << "\"\n";
            }
        }

        std::size_t FullMemoryFallback(const std::vector<MemoryRegion>& regions)
        {
            std::ofstream f(ResearchRoot() / L"full_memory_scan_index.csv", std::ios::trunc);
            if (!f) return 0;
            f << "region_base,size,module,tags,scanned\n";
            std::size_t scanned = 0;
            for (const auto& region : regions)
            {
                if (!IsReadableProtect(region.protect) || !region.size) continue;
                f << Hex(region.base) << ','
                  << Hex(region.size) << ",\""
                  << CsvEscape(region.module) << "\",\""
                  << CsvEscape(region.tags) << "\",1\n";
                ++scanned;
                if ((scanned % 64) == 0) Sleep(1);
            }
            return scanned;
        }

        void WriteSummary(const Summary& summary, bool fingerprintMatch)
        {
            std::ofstream f(ResearchRoot() / L"beta_research_summary.json", std::ios::trunc);
            if (!f) return;
            f << "{\n"
              << "  \"profile\": \"T9 Open Beta\",\n"
              << "  \"fingerprint_match\": " << (fingerprintMatch ? "true" : "false") << ",\n"
              << "  \"state_xrefs\": " << summary.stateXrefs << ",\n"
              << "  \"function_callers\": " << summary.functionCallers << ",\n"
              << "  \"frontend_markers\": " << summary.frontendMarkers << ",\n"
              << "  \"lua_strings\": " << summary.luaStrings << ",\n"
              << "  \"lua_text_chunks\": " << summary.luaTextChunks << ",\n"
              << "  \"lua_bytecode_chunks\": " << summary.luaBytecodeChunks << ",\n"
              << "  \"auth_snapshots\": " << summary.authSnapshots << ",\n"
              << "  \"identity_matches\": " << summary.identityMatches << ",\n"
              << "  \"offline_frontend_candidates\": " << summary.offlineCandidates << ",\n"
              << "  \"full_memory_regions_scanned\": " << summary.fullMemoryRegions << ",\n"
              << "  \"scan_complete\": " << (summary.complete ? "true" : "false") << "\n"
              << "}\n";
        }

        void RunStage(const char* name, const std::function<void()>& stage)
        {
            try
            {
                stage();
            }
            catch (...)
            {
                std::string line = "stage_failed=";
                line += name;
                AppendProgress(line);
            }
        }

        DWORD WINAPI ScanWorker(LPVOID)
        {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            g_scanComplete.store(false);

            Summary summary{};
            ImageLayout image{};
            const bool fingerprintMatch = CurrentFingerprint(&image);
            WriteProfileGuard(image);
            if (!fingerprintMatch)
            {
                PrintBeta("profile guard failed; scanner aborted");
                summary.complete = false;
                WriteSummary(summary, false);
                g_lastSummary = summary;
                g_scanRunning.store(false);
                return 1;
            }

            PrintBeta("exact Open Beta fingerprint confirmed");
            if (g_win11Complete.load())
                PrintBeta("Win11 patch complete");
            AppendProgress("scan_start reason=" + g_startReason);
            AppendProgress("profile_guard_complete");

            const auto mode = static_cast<ScanMode>(g_scanMode.load());
            std::vector<ModuleInfo> modules;
            std::vector<MemoryRegion> regions;
            std::vector<XrefHit> stateXrefs;
            std::vector<StringHit> staticMarkers;
            std::vector<StringHit> liveMarkers;
            std::vector<XrefHit> stringXrefs;

            RunStage("module_map", [&]()
            {
                modules = EnumerateModules();
                WriteModuleMap(modules);
                AppendProgress("module_map_complete");
            });

            RunStage("memory_map", [&]()
            {
                regions = EnumerateMemory(image, modules);
                WriteMemoryMap(regions);
                AppendProgress("memory_map_complete");
            });

            StartStateMonitor();

            if (mode == ScanMode::State || mode == ScanMode::All || mode == ScanMode::Frontend)
            {
                RunStage("state_xrefs", [&]()
                {
                    stateXrefs = ScanStateXrefs(image);
                    summary.stateXrefs = stateXrefs.size();
                    AppendProgress("state_xrefs_complete count=" + std::to_string(summary.stateXrefs));
                });

                RunStage("function_callers", [&]()
                {
                    summary.functionCallers = ScanRecoveredFunctionCallers(image);
                    AppendProgress("function_callers_complete count=" + std::to_string(summary.functionCallers));
                });
            }

            if (mode == ScanMode::Frontend || mode == ScanMode::Lua || mode == ScanMode::All)
            {
                RunStage("frontend_markers", [&]()
                {
                    staticMarkers = ScanMarkersInRegions(image, regions, true, ResearchRoot() / L"static_frontend_lua_strings.csv");
                    liveMarkers = ScanMarkersInRegions(image, regions, false, ResearchRoot() / L"live_frontend_lua_strings.csv");
                    ScanMarkersInRegions(image, regions, true, ResearchRoot() / L"known_beta_frontend_markers.csv");
                    summary.frontendMarkers = staticMarkers.size();
                    summary.luaStrings = liveMarkers.size();
                    AppendProgress("frontend_markers_complete count=" + std::to_string(summary.frontendMarkers));
                    AppendProgress("lua_scan_complete count=" + std::to_string(summary.luaStrings));
                });

                RunStage("string_xrefs", [&]()
                {
                    stringXrefs = ScanStringXrefs(image, staticMarkers);
                    WriteScreenCandidates(stateXrefs, staticMarkers);
                    AppendProgress("string_xrefs_complete count=" + std::to_string(stringXrefs.size()));
                });
            }

            if (mode == ScanMode::Lua || mode == ScanMode::All)
            {
                RunStage("lua_text", [&]()
                {
                    summary.luaTextChunks = DumpLuaTextChunks(regions);
                    AppendProgress("lua_text_dump_complete count=" + std::to_string(summary.luaTextChunks));
                });

                RunStage("lua_bytecode", [&]()
                {
                    summary.luaBytecodeChunks = DumpLuaBytecode(regions);
                    AppendProgress("lua_bytecode_scan_complete count=" + std::to_string(summary.luaBytecodeChunks));
                });
            }

            if (mode == ScanMode::Auth || mode == ScanMode::All)
            {
                RunStage("auth", [&]()
                {
                    summary.authSnapshots = DumpAuthObject(image);
                    AppendProgress("auth_scan_complete count=" + std::to_string(summary.authSnapshots));
                });
            }

            if (mode == ScanMode::Name || mode == ScanMode::All)
            {
                RunStage("name", [&]()
                {
                    summary.identityMatches = ScanIdentityNames(image, regions);
                    AppendProgress("name_scan_complete count=" + std::to_string(summary.identityMatches));
                });
            }

            if (mode == ScanMode::Frontend || mode == ScanMode::All)
            {
                RunStage("offline_candidates", [&]()
                {
                    summary.offlineCandidates = WriteOfflineCandidates(stringXrefs, stateXrefs);
                    AppendProgress("offline_candidate_scan_complete count=" + std::to_string(summary.offlineCandidates));
                });
            }

            if (mode == ScanMode::All)
            {
                RunStage("full_memory_fallback", [&]()
                {
                    summary.fullMemoryRegions = FullMemoryFallback(regions);
                    AppendProgress("full_memory_scan_complete regions=" + std::to_string(summary.fullMemoryRegions));
                });
            }

            summary.complete = true;
            WriteSummary(summary, true);
            g_lastSummary = summary;
            g_scanComplete.store(true);
            g_scanRunning.store(false);
            PrintBeta("scan_complete");
            return 0;
        }

        bool StartWorker(ScanMode mode, const char* reason)
        {
            if (!CurrentFingerprint())
            {
                ImageLayout image{};
                ReadImageLayout(GetModuleHandleW(nullptr), image);
                WriteProfileGuard(image);
                return false;
            }
            if (g_scanRunning.exchange(true))
            {
                PrintBeta("scan already running");
                return true;
            }

            g_scanMode.store(static_cast<int>(mode));
            g_startReason = reason && *reason ? reason : "manual";
            HANDLE thread = CreateThread(nullptr, 0, &ScanWorker, nullptr, 0, nullptr);
            if (!thread)
            {
                g_scanRunning.store(false);
                AppendProgress("stage_failed=create_scan_thread");
                return false;
            }
            CloseHandle(thread);
            PrintBeta("heavy research worker started");
            return true;
        }
    }

    bool IsExactOpenBeta()
    {
        return CurrentFingerprint();
    }

    void NotifyWin11PatchComplete()
    {
        g_win11Complete.store(true);
        PrintBeta("Win11 patch complete");
    }

    void StartStateMonitor()
    {
        if (!CurrentFingerprint())
            return;
        if (g_stateMonitorRunning.exchange(true))
            return;
        HANDLE thread = CreateThread(nullptr, 0, &StateMonitorThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        else g_stateMonitorRunning.store(false);
    }

    bool StartAutomatic(const char* reason)
    {
        return StartWorker(ScanMode::All, reason ? reason : "automatic");
    }

    bool RunManual(ScanMode mode, std::string& message)
    {
        if (!CurrentFingerprint())
        {
            message = "exact Open Beta fingerprint did not match";
            return false;
        }
        if (mode == ScanMode::State)
        {
            StartStateMonitor();
            message = "beta state monitor started or already running";
            return true;
        }
        const bool ok = StartWorker(mode, "manual");
        message = ok ? "beta research worker started or already running" : "could not start beta research worker";
        return ok;
    }

    bool RunManual(const std::string& modeText, std::string& message)
    {
        const std::string mode = Lower(modeText);
        if (mode == "beta" || mode == "all") return RunManual(ScanMode::All, message);
        if (mode == "frontend") return RunManual(ScanMode::Frontend, message);
        if (mode == "lua") return RunManual(ScanMode::Lua, message);
        if (mode == "state") return RunManual(ScanMode::State, message);
        if (mode == "auth") return RunManual(ScanMode::Auth, message);
        if (mode == "name") return RunManual(ScanMode::Name, message);
        message = "usage: /scan beta|frontend|lua|state|auth|name|all";
        return false;
    }

    void PrintStatus()
    {
        std::printf(
            "[BETA-SCAN] exact=%s win11=%s running=%s complete=%s state_monitor=%s last_summary={state_xrefs=%zu callers=%zu markers=%zu lua=%zu auth=%zu name=%zu offline=%zu full_regions=%zu}\n",
            CurrentFingerprint() ? "yes" : "no",
            g_win11Complete.load() ? "yes" : "no",
            g_scanRunning.load() ? "yes" : "no",
            g_scanComplete.load() ? "yes" : "no",
            g_stateMonitorRunning.load() ? "yes" : "no",
            g_lastSummary.stateXrefs,
            g_lastSummary.functionCallers,
            g_lastSummary.frontendMarkers,
            g_lastSummary.luaStrings,
            g_lastSummary.authSnapshots,
            g_lastSummary.identityMatches,
            g_lastSummary.offlineCandidates,
            g_lastSummary.fullMemoryRegions);
        std::fflush(stdout);
    }
}
