#include "LuiResearch.h"
#include "../../core/Main.hpp"
#include "../../runtime/LogPaths.h"

#include <Windows.h>
#include <atomic>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace lui_research
{
    namespace
    {
        struct Section
        {
            std::string name;
            std::uintptr_t begin{};
            std::size_t size{};
            bool readable{};
            bool executable{};
        };

        std::atomic_bool g_running{false};
        std::atomic_bool g_started{false};
        std::atomic_bool g_stop{false};
        std::mutex g_logMutex;
        std::unordered_set<std::string> g_seenAssets;

        std::string Hex(std::uintptr_t value)
        {
            std::ostringstream out;
            out << "0x" << std::hex << std::uppercase << value;
            return out.str();
        }

        const char* LogFile()
        {
            log_paths::EnsureAll();
            CreateDirectoryA("logs\\lui_research", nullptr);
            return "logs\\lui_research\\lui_research.log";
        }

        void Log(const std::string& text)
        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::ofstream file(LogFile(), std::ios::app);
            if (file)
                file << text << '\n';
        }

        bool ReadBytes(std::uintptr_t address, void* out, std::size_t size)
        {
            if (!address || !out || !size)
                return false;
            SIZE_T got = 0;
            return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), out, size, &got) && got == size;
        }

        bool ReadCString(std::uintptr_t address, std::string& out)
        {
            out.clear();
            if (!address)
                return false;
            char buf[257]{};
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), buf, 256, &got) || !got)
                return false;
            std::size_t len = 0;
            while (len < got && buf[len])
            {
                const unsigned char c = static_cast<unsigned char>(buf[len]);
                if (c < 0x20 || c > 0x7E)
                    return false;
                ++len;
            }
            if (len < 4 || len >= 256)
                return false;
            out.assign(buf, len);
            return true;
        }

        bool Interesting(const std::string& text)
        {
            std::string s = text;
            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            static const char* terms[] = {
                "lui", "lua", "uieditor", "ui/", "ui\\", "menu", "frontend",
                "gunsmith", "weaponcamo", "weapon_camo", "camo", "customization",
                "datasource", "data_source", "model", "loadout", "cac", "createaclass"
            };
            for (const char* term : terms)
            {
                if (s.find(term) != std::string::npos)
                    return true;
            }
            return false;
        }

        bool GetSections(std::vector<Section>& out)
        {
            const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            if (!base)
                return false;
            IMAGE_DOS_HEADER dos{};
            if (!ReadBytes(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            IMAGE_NT_HEADERS64 nt{};
            if (!ReadBytes(base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE)
                return false;
            const auto first = base + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
            for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
            {
                IMAGE_SECTION_HEADER sh{};
                if (!ReadBytes(first + i * sizeof(sh), &sh, sizeof(sh)))
                    continue;
                char name[9]{};
                std::memcpy(name, sh.Name, 8);
                out.push_back({
                    name,
                    base + sh.VirtualAddress,
                    static_cast<std::size_t>(sh.Misc.VirtualSize),
                    (sh.Characteristics & IMAGE_SCN_MEM_READ) != 0,
                    (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                });
            }
            return !out.empty();
        }

        void FindRipRefs(const Section& text, std::uintptr_t target, std::vector<std::uintptr_t>& refs)
        {
            if (!text.executable || text.size < 7)
                return;
            std::vector<unsigned char> bytes(text.size);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(text.begin), bytes.data(), bytes.size(), &got) || got < 7)
                return;
            for (std::size_t i = 0; i + 7 <= got; ++i)
            {
                const unsigned char rex = bytes[i];
                const unsigned char op = bytes[i+1];
                const unsigned char modrm = bytes[i+2];
                if ((rex & 0xF0) != 0x40 || (op != 0x8D && op != 0x8B) || (modrm & 0xC7) != 0x05)
                    continue;
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data()+i+3, sizeof(disp));
                const auto resolved = static_cast<std::uintptr_t>(static_cast<std::intptr_t>(text.begin+i+7) + disp);
                if (resolved == target)
                    refs.push_back(text.begin+i);
            }
        }

        void ScanStaticStrings()
        {
            std::vector<Section> sections;
            if (!GetSections(sections))
            {
                Log("[STATIC] failed to enumerate PE sections");
                return;
            }
            const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            const Section* text = nullptr;
            for (const auto& s : sections)
                if (s.executable && (!text || s.size > text->size)) text = &s;

            std::size_t strings = 0;
            std::size_t xrefs = 0;
            for (const auto& sec : sections)
            {
                if (!sec.readable || sec.executable || sec.size < 5)
                    continue;
                std::vector<unsigned char> bytes(sec.size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(sec.begin), bytes.data(), bytes.size(), &got))
                    continue;
                std::size_t i = 0;
                while (i < got && strings < 3000)
                {
                    if (bytes[i] < 0x20 || bytes[i] > 0x7E) { ++i; continue; }
                    const std::size_t start = i;
                    while (i < got && bytes[i] >= 0x20 && bytes[i] <= 0x7E && i-start < 384) ++i;
                    const std::size_t len = i-start;
                    if (len < 5) continue;
                    std::string value(reinterpret_cast<const char*>(bytes.data()+start), len);
                    if (!Interesting(value)) continue;
                    std::vector<std::uintptr_t> refs;
                    if (text) FindRipRefs(*text, sec.begin+start, refs);
                    if (value.size() > 220) value.resize(220);
                    Log("[STATIC_STRING] rva=" + Hex(sec.begin+start-base) + " refs=" + std::to_string(refs.size()) + " text=\"" + value + "\"");
                    ++strings;
                    for (std::size_t r=0; r<refs.size() && r<16; ++r)
                    {
                        Log("[STATIC_XREF] stringRva=" + Hex(sec.begin+start-base) + " refRva=" + Hex(refs[r]-base));
                        ++xrefs;
                    }
                }
            }
            Log("[STATIC_END] strings=" + std::to_string(strings) + " xrefs=" + std::to_string(xrefs));
        }

        void ScanAssetPool(unsigned type, const char* typeName)
        {
            if (!g_assetPool)
                return;
            XAssetPool& pool = g_assetPool[type];
            if (!pool.pool.unk || !pool.itemSize || pool.itemAllocCount <= 0 || pool.itemAllocCount > pool.itemCount)
                return;
            const auto base = reinterpret_cast<std::uintptr_t>(pool.pool.unk);
            const int count = (std::min)(static_cast<int>(pool.itemAllocCount), 25000);
            for (int i=0; i<count; ++i)
            {
                const auto entry = base + static_cast<std::uintptr_t>(i) * pool.itemSize;
                std::uintptr_t namePtr = 0;
                if (!ReadBytes(entry, &namePtr, sizeof(namePtr)))
                    continue;
                std::string name;
                if (!ReadCString(namePtr, name) || !Interesting(name))
                    continue;
                const std::string key = std::to_string(type) + ":" + name;
                if (!g_seenAssets.insert(key).second)
                    continue;
                Log(std::string("[ASSET] type=") + typeName + " index=" + std::to_string(i) + " entry=" + Hex(entry) + " name=\"" + name + "\"");
            }
        }

        DWORD WINAPI Worker(LPVOID)
        {
            g_running.store(true);
            g_stop.store(false);
            std::ofstream(LogFile(), std::ios::trunc).close();
            Log("[BEGIN] T9 LUI/Lua research - read-only, no hooks");
            Log("[GOAL] identify LUI/Lua loaders and Gunsmith/Camo menu assets for custom category/slots");
            ScanStaticStrings();

            const ULONGLONG start = GetTickCount64();
            bool poolReadyLogged = false;
            while (!g_stop.load() && GetTickCount64() - start < 10ull * 60ull * 1000ull)
            {
                if (g_assetPool)
                {
                    if (!poolReadyLogged)
                    {
                        Log("[RUNTIME] g_assetPool ready; sampling UI-related rawfile assets for 10 minutes");
                        poolReadyLogged = true;
                    }
                    ScanAssetPool(ASSET_TYPE_RAWFILE, "RAWFILE");
                    ScanAssetPool(ASSET_TYPE_RAWFILEPREPROC, "RAWFILEPREPROC");
                    ScanAssetPool(ASSET_TYPE_RAWTEXTFILE, "RAWTEXTFILE");
                    ScanAssetPool(ASSET_TYPE_UIMODELDATASTRUCT, "UIMODELDATASTRUCT");
                }
                Sleep(2000);
            }
            Log("[END] runtime asset names=" + std::to_string(g_seenAssets.size()));
            Log("[NEXT] send this log after visiting Weapons > Gunsmith > Camo and changing categories/weapons");
            g_running.store(false);
            return 0;
        }
    }

    void StartAutomatic()
    {
        if (g_started.exchange(true))
            return;
        HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }

    void Stop()
    {
        g_stop.store(true);
    }

    bool IsRunning()
    {
        return g_running.load();
    }
}
