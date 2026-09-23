#include "T9ScriptDump.h"
#include "../../core/Main.hpp"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace t9_script_dump
{
    namespace
    {
        std::atomic_bool g_started{ false };

        bool SafeRead(std::uintptr_t address, void* out, SIZE_T size)
        {
            SIZE_T got = 0;
            return address && out && size && ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<const void*>(address), out, size, &got) && got == size;
        }

        bool Readable(std::uintptr_t address)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            return address && VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));
        }

        std::string Hex64(std::uint64_t v)
        {
            std::ostringstream s;
            s << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << v;
            return s.str();
        }

        void DumpStrings(const std::vector<unsigned char>& bytes, const std::string& path)
        {
            std::ofstream out(path, std::ios::trunc);
            if (!out) return;
            for (std::size_t i = 0; i < bytes.size();)
            {
                if (bytes[i] < 0x20 || bytes[i] > 0x7E) { ++i; continue; }
                const auto start = i;
                std::string value;
                while (i < bytes.size() && bytes[i] >= 0x20 && bytes[i] <= 0x7E)
                    value.push_back(static_cast<char>(bytes[i++]));
                if (value.size() >= 4)
                    out << "0x" << std::hex << std::uppercase << start << std::dec << "," << value << "\n";
            }
        }

        void DumpGscMetadata(const std::vector<unsigned char>& bytes, const std::string& path)
        {
            std::ofstream out(path, std::ios::trunc);
            if (!out) return;
            out << "kind,index,address,checksum,name,namespace,param_count,flags,extra\n";
            if (bytes.size() < sizeof(GSC_OBJ))
            {
                out << "status,0,0,0,0,0,0,0,blob_too_small\n";
                return;
            }

            GSC_OBJ obj{};
            memcpy(&obj, bytes.data(), sizeof(obj));
            const auto inRange = [&](std::uint64_t off, std::uint64_t len)
            {
                return off <= bytes.size() && len <= bytes.size() - static_cast<std::size_t>(off);
            };

            out << "header,0,0x" << std::hex << std::uppercase << obj.cseg_offset
                << ",0x" << static_cast<std::uint32_t>(obj.checksum)
                << ",0x" << static_cast<std::uint64_t>(obj.name)
                << std::dec << ',' << obj.exports_count << ',' << obj.imports_count << ',' << obj.cseg_size << "\n";

            const auto exportCount = static_cast<unsigned int>(static_cast<std::uint16_t>(obj.exports_count));
            if (exportCount && exportCount < 65536 &&
                inRange(static_cast<std::uint32_t>(obj.exports_offset), static_cast<std::uint64_t>(exportCount) * sizeof(GSC_EXPORT_ITEM)))
            {
                for (unsigned int i = 0; i < exportCount; ++i)
                {
                    GSC_EXPORT_ITEM e{};
                    memcpy(&e, bytes.data() + static_cast<std::uint32_t>(obj.exports_offset) + i * sizeof(e), sizeof(e));
                    out << "export," << std::dec << i << ",0x" << std::hex << std::uppercase << e.address
                        << ",0x" << e.checksum << ",0x" << e.name << ",0x" << e.name_space
                        << std::dec << ',' << static_cast<unsigned int>(e.param_count)
                        << ',' << static_cast<unsigned int>(e.flags)
                        << ",callback=0x" << std::hex << std::uppercase << e.callback_event << std::dec << "\n";
                }
            }

            const auto importCount = static_cast<unsigned int>(static_cast<std::uint16_t>(obj.imports_count));
            if (importCount && importCount < 65536 &&
                inRange(static_cast<std::uint32_t>(obj.imports_offset), static_cast<std::uint64_t>(importCount) * sizeof(GSC_IMPORT_ITEM)))
            {
                for (unsigned int i = 0; i < importCount; ++i)
                {
                    GSC_IMPORT_ITEM e{};
                    memcpy(&e, bytes.data() + static_cast<std::uint32_t>(obj.imports_offset) + i * sizeof(e), sizeof(e));
                    out << "import," << std::dec << i << ",0,0,0x" << std::hex << std::uppercase << e.name
                        << ",0x" << e.name_space << std::dec << ',' << static_cast<unsigned int>(e.param_count)
                        << ',' << static_cast<unsigned int>(e.flags) << ",refs=" << e.num_address << "\n";
                }
            }
        }

        bool Candidate(std::uintptr_t item, bool oldLayout, std::uintptr_t& name, std::uintptr_t& data, std::uint32_t& size)
        {
            name = data = 0; size = 0;
            if (!SafeRead(item, &name, sizeof(name))) return false;
            const std::uintptr_t dataOffset = oldLayout ? 0x10 : 0x08;
            const std::uintptr_t sizeOffset = oldLayout ? 0x18 : 0x10;
            if (!SafeRead(item + dataOffset, &data, sizeof(data)) ||
                !SafeRead(item + sizeOffset, &size, sizeof(size))) return false;
            return data && size >= 16 && size <= 64u * 1024u * 1024u && Readable(data);
        }

        void PerformDump()
        {
            log_paths::EnsureAll();
            CreateDirectoryA("logs\\scripts", nullptr);
            CreateDirectoryA("logs\\scripts\\raw", nullptr);
            CreateDirectoryA("logs\\scripts\\strings", nullptr);
            CreateDirectoryA("logs\\scripts\\meta", nullptr);

            if (!g_assetPool)
            {
                std::printf("[GSC-DUMP] assetPool is not available yet.\n");
                return;
            }

            const auto& pool = g_assetPool[ASSET_TYPE_SCRIPTPARSETREE];
            const auto base = reinterpret_cast<std::uintptr_t>(pool.pool.unk);
            const unsigned int count = pool.itemAllocCount > 0 ? static_cast<unsigned int>(pool.itemAllocCount) :
                pool.itemCount > 0 ? static_cast<unsigned int>(pool.itemCount) : 0u;
            const std::size_t stride = pool.itemSize >= 0x18 && pool.itemSize <= 0x100 ? pool.itemSize : 0x20;

            if (!base || !count || count > 1000000)
            {
                std::printf("[GSC-DUMP] scriptparsetree pool not populated (base=%p count=%u stride=0x%llX).\n",
                    reinterpret_cast<void*>(base), count, static_cast<unsigned long long>(stride));
                return;
            }

            std::ofstream manifest("logs\\scripts\\manifest.csv", std::ios::trunc);
            if (manifest)
                manifest << "index,name_hash,data,size,layout,raw_path,strings_path,meta_path,magic\n";

            unsigned int dumped = 0;
            std::uint64_t total = 0;
            for (unsigned int i = 0; i < count; ++i)
            {
                const auto item = base + static_cast<std::uintptr_t>(i) * stride;
                std::uintptr_t name = 0, data = 0;
                std::uint32_t size = 0;
                bool oldLayout = false;

                // Retail layouts observed by this project are 0x18/0x20-byte records.
                // Test both safely instead of trusting one historical layout globally.
                if (!Candidate(item, false, name, data, size))
                {
                    if (!Candidate(item, true, name, data, size))
                        continue;
                    oldLayout = true;
                }

                std::vector<unsigned char> bytes(size);
                if (!SafeRead(data, bytes.data(), bytes.size()))
                    continue;

                const auto id = Hex64(name);
                char indexBuf[32]{};
                sprintf_s(indexBuf, "%06u", i);
                const std::string raw = std::string("logs\\scripts\\raw\\") + indexBuf + "_" + id + ".gscbin";
                const std::string strings = std::string("logs\\scripts\\strings\\") + indexBuf + "_" + id + ".txt";
                const std::string meta = std::string("logs\\scripts\\meta\\") + indexBuf + "_" + id + ".csv";

                std::ofstream out(raw, std::ios::binary | std::ios::trunc);
                if (!out) continue;
                out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
                if (!out.good()) continue;
                DumpStrings(bytes, strings);
                DumpGscMetadata(bytes, meta);

                std::string magic;
                for (std::size_t m = 0; m < (std::min)(std::size_t(8), bytes.size()); ++m)
                {
                    char b[4]{};
                    sprintf_s(b, "%02X", bytes[m]);
                    if (!magic.empty()) magic += ' ';
                    magic += b;
                }

                if (manifest)
                    manifest << i << ",0x" << id << ",0x" << std::hex << std::uppercase << data << std::dec
                        << ',' << size << ',' << (oldLayout ? "old" : "new") << ",\"" << raw << "\",\""
                        << strings << "\",\"" << meta << "\",\"" << magic << "\"\n";

                ++dumped;
                total += size;
            }

            std::printf("[GSC-DUMP] live post-load script pool: %u/%u assets dumped, %.2f MB. Raw bytecode + strings + parsed GSC metadata are in logs\\scripts.\n",
                dumped, count, static_cast<double>(total) / (1024.0 * 1024.0));
            std::fflush(stdout);
        }

        DWORD WINAPI Worker(LPVOID)
        {
            // Wait for DB pools to populate. Re-run a few times because frontend and mode scripts arrive in waves.
            for (unsigned int pass = 0; pass < 8; ++pass)
            {
                Sleep(pass == 0 ? 7000 : 5000);
                __try { PerformDump(); }
                __except (EXCEPTION_EXECUTE_HANDLER) { std::printf("[GSC-DUMP] guarded dump pass faulted; retrying.\n"); }
            }
            return 0;
        }
    }

    void StartAsync()
    {
        if (g_started.exchange(true)) return;
        HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }

    void DumpNow()
    {
        __try { PerformDump(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { std::printf("[GSC-DUMP] guarded manual dump faulted.\n"); }
    }
}
