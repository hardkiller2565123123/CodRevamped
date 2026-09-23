#include "LuaRuntimePathTrace.h"
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

namespace lua_runtime_path_trace
{
    namespace
    {
        std::atomic_bool g_running{ false };
        std::atomic_bool g_completed{ false };

        constexpr int kLuaPool = 0x7C;

        struct Target
        {
            const char* label;
            std::uint64_t hash;
        };

        const Target kTargets[] =
        {
            { "director_luautils", 0x6C22220D6FCFCCA7ull },
            { "frontend_route",    0x463D46EAF0995AEEull },
            { "director_nav",      0x53F6BDEF20831EBCull },
            { "nav_to_menu",       0x1C73A5DF0BB8A2A6ull },
        };

        struct Layout
        {
            const char* name;
            std::uint32_t dataOffset;
            std::uint32_t sizeOffset;
            std::uint32_t sizeWidth;
        };

        // Same layouts proven useful by the existing T9 Lua dumper.
        const Layout kLayouts[] =
        {
            { "name_unk_size_data", 0x18, 0x10, 8 },
            { "name_data_size64",   0x08, 0x10, 8 },
            { "name_data_size32",   0x08, 0x10, 4 },
            { "name_size_data",     0x10, 0x08, 8 },
            { "name_size32_data",   0x10, 0x08, 4 },
        };

        struct LiveAsset
        {
            Target target{};
            Layout layout{};
            std::uintptr_t item = 0;
            std::uintptr_t data = 0;
            std::uint64_t size = 0;
            unsigned int index = 0;
        };

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
            return
                VirtualQuery(
                    reinterpret_cast<const void*>(address),
                    &mbi,
                    sizeof(mbi)) &&
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
        }

        void Print(
            const char* fmt,
            ...)
        {
            char buffer[2048]{};
            va_list args;
            va_start(args, fmt);
            vsprintf_s(buffer, sizeof(buffer), fmt, args);
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
                if (SafeRead(item + layout.sizeOffset, value))
                    return value;
                return 0;
            }

            std::uint64_t value = 0;
            if (SafeRead(item + layout.sizeOffset, value))
                return value;
            return 0;
        }

        bool FindLiveAsset(
            const Target& target,
            LiveAsset& out)
        {
            out = {};

            if (!g_assetPool)
                return false;

            XAssetPool pool{};
            if (!SafeRead(
                    reinterpret_cast<std::uintptr_t>(&g_assetPool[kLuaPool]),
                    pool))
            {
                return false;
            }

            const auto array =
                reinterpret_cast<std::uintptr_t>(pool.pool.unk);

            const auto count =
                pool.itemAllocCount > 0
                    ? static_cast<unsigned int>(pool.itemAllocCount)
                    : pool.itemCount > 0
                        ? static_cast<unsigned int>(pool.itemCount)
                        : 0u;

            if (!array ||
                !count ||
                count > 500000 ||
                !IsReadable(array))
            {
                return false;
            }

            const auto stride =
                pool.itemSize >= 0x18 &&
                pool.itemSize <= 0x400
                    ? static_cast<std::size_t>(pool.itemSize)
                    : static_cast<std::size_t>(0x20);

            for (const auto& layout : kLayouts)
            {
                for (unsigned int i = 0; i < count; ++i)
                {
                    const auto item =
                        array +
                        static_cast<std::uintptr_t>(i) * stride;

                    std::uint64_t rawName = 0;
                    if (!SafeRead(item, rawName) ||
                        rawName != target.hash)
                    {
                        continue;
                    }

                    std::uintptr_t data = 0;
                    if (!SafeRead(
                            item + layout.dataOffset,
                            data))
                    {
                        continue;
                    }

                    const auto size =
                        ReadSize(item, layout);

                    if (!data ||
                        !size ||
                        size > 16ull * 1024ull * 1024ull ||
                        !IsReadable(data))
                    {
                        continue;
                    }

                    // The decoded Lua assets begin with LuaJIT magic 1B 4C 4A.
                    unsigned char head[3]{};
                    if (!SafeReadBytes(
                            data,
                            head,
                            sizeof(head)) ||
                        head[0] != 0x1B ||
                        head[1] != 0x4C ||
                        head[2] != 0x4A)
                    {
                        continue;
                    }

                    out.target = target;
                    out.layout = layout;
                    out.item = item;
                    out.data = data;
                    out.size = size;
                    out.index = i;
                    return true;
                }
            }

            return false;
        }

        std::uintptr_t GuessFunctionStart(
            const std::vector<unsigned char>& text,
            std::size_t hit)
        {
            const std::size_t floor =
                hit > 0x180 ? hit - 0x180 : 0;

            // Common x64 entry patterns in this build.
            for (std::size_t pos = hit; pos > floor; --pos)
            {
                const std::size_t i = pos - 1;

                if (i + 4 <= text.size())
                {
                    if ((text[i] == 0x40 ||
                         text[i] == 0x48 ||
                         text[i] == 0x4C) &&
                        (text[i + 1] == 0x53 ||
                         text[i + 1] == 0x55 ||
                         text[i + 1] == 0x56 ||
                         text[i + 1] == 0x57 ||
                         text[i + 1] == 0x89 ||
                         text[i + 1] == 0x83 ||
                         text[i + 1] == 0x8B))
                    {
                        return i;
                    }
                }

                // int3/alignment boundary followed by non-CC byte.
                if (i + 1 < text.size() &&
                    text[i] == 0xCC &&
                    text[i + 1] != 0xCC)
                {
                    return i + 1;
                }
            }

            return hit;
        }

        void DumpWindow(
            std::ofstream& out,
            const std::vector<unsigned char>& bytes,
            std::size_t center,
            std::size_t radius)
        {
            const auto begin =
                center > radius ? center - radius : 0;

            const auto end =
                (std::min<std::size_t>)(
                    bytes.size(),
                    center + radius);

            out << std::hex
                << std::uppercase
                << std::setfill('0');

            for (std::size_t row = begin;
                 row < end;
                 row += 16)
            {
                out << "0x"
                    << std::setw(8)
                    << row
                    << ": ";

                for (std::size_t j = 0;
                     j < 16 && row + j < end;
                     ++j)
                {
                    out << std::setw(2)
                        << static_cast<unsigned int>(
                            bytes[row + j])
                        << ' ';
                }

                out << "\n";
            }

            out << std::dec;
        }

        void ScanRuntimePointers(
            const std::vector<LiveAsset>& live)
        {
            std::ofstream out(
                "logs\\lui\\luafile_runtime_pointer_refs.csv",
                std::ios::trunc);

            if (!out)
                return;

            out
                << "target,hash,needle_kind,needle,region_base,region_size,region_type,protect,hit_address\n";

            SYSTEM_INFO si{};
            GetSystemInfo(&si);

            auto address =
                reinterpret_cast<std::uintptr_t>(
                    si.lpMinimumApplicationAddress);

            const auto maxAddress =
                reinterpret_cast<std::uintptr_t>(
                    si.lpMaximumApplicationAddress);

            unsigned int hitCount = 0;
            constexpr unsigned int kMaxHits = 8192;

            while (address < maxAddress &&
                   hitCount < kMaxHits)
            {
                MEMORY_BASIC_INFORMATION mbi{};

                if (!VirtualQuery(
                        reinterpret_cast<const void*>(address),
                        &mbi,
                        sizeof(mbi)))
                {
                    break;
                }

                const auto regionBase =
                    reinterpret_cast<std::uintptr_t>(
                        mbi.BaseAddress);

                const auto regionSize =
                    static_cast<std::size_t>(
                        mbi.RegionSize);

                const bool readable =
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect &
                      (PAGE_NOACCESS | PAGE_GUARD)) &&
                    regionSize > 0 &&
                    regionSize <=
                        512ull * 1024ull * 1024ull;

                if (readable)
                {
                    constexpr std::size_t kChunk =
                        4ull * 1024ull * 1024ull;

                    std::vector<unsigned char>
                        buffer(kChunk + 8);

                    for (std::size_t consumed = 0;
                         consumed < regionSize &&
                         hitCount < kMaxHits;)
                    {
                        const auto want =
                            (std::min<std::size_t>)(
                                kChunk,
                                regionSize - consumed);

                        SIZE_T got = 0;

                        if (!ReadProcessMemory(
                                GetCurrentProcess(),
                                reinterpret_cast<const void*>(
                                    regionBase + consumed),
                                buffer.data(),
                                want,
                                &got) ||
                            got < sizeof(std::uintptr_t))
                        {
                            consumed += want;
                            continue;
                        }

                        for (const auto& asset : live)
                        {
                            const std::uintptr_t needles[2] =
                            {
                                asset.item,
                                asset.data
                            };

                            const char* kinds[2] =
                            {
                                "ITEM",
                                "DATA"
                            };

                            for (int ni = 0;
                                 ni < 2;
                                 ++ni)
                            {
                                unsigned char needleBytes[
                                    sizeof(std::uintptr_t)]{};

                                std::memcpy(
                                    needleBytes,
                                    &needles[ni],
                                    sizeof(std::uintptr_t));

                                auto begin =
                                    buffer.begin();

                                auto end =
                                    buffer.begin() +
                                    static_cast<std::ptrdiff_t>(
                                        got);

                                auto it =
                                    std::search(
                                        begin,
                                        end,
                                        needleBytes,
                                        needleBytes +
                                            sizeof(std::uintptr_t));

                                while (it != end &&
                                       hitCount < kMaxHits)
                                {
                                    const auto off =
                                        static_cast<std::size_t>(
                                            it - begin);

                                    const auto hit =
                                        regionBase +
                                        consumed +
                                        off;

                                    // Ignore the LuaFile record's own data
                                    // pointer when looking for external owners.
                                    if (!(kinds[ni][0] == 'D' &&
                                          hit ==
                                              asset.item +
                                              asset.layout.dataOffset))
                                    {
                                        out
                                            << asset.target.label
                                            << ",0x"
                                            << std::hex
                                            << std::uppercase
                                            << asset.target.hash
                                            << ","
                                            << kinds[ni]
                                            << ",0x"
                                            << needles[ni]
                                            << ",0x"
                                            << regionBase
                                            << ",0x"
                                            << regionSize
                                            << ",0x"
                                            << mbi.Type
                                            << ",0x"
                                            << mbi.Protect
                                            << ",0x"
                                            << hit
                                            << std::dec
                                            << "\n";

                                        ++hitCount;
                                    }

                                    it =
                                        std::search(
                                            it + 1,
                                            end,
                                            needleBytes,
                                            needleBytes +
                                                sizeof(std::uintptr_t));
                                }
                            }
                        }

                        consumed += want;
                    }
                }

                const auto next =
                    regionBase +
                    regionSize;

                if (next <= address)
                    break;

                address = next;
            }

            Print(
                "[LUA-PATH] runtime pointer refs=%u -> logs\\\\lui\\\\luafile_runtime_pointer_refs.csv\\n",
                hitCount);
        }

        void ScanExecutable(
            std::uintptr_t module,
            const IMAGE_NT_HEADERS64& nt,
            const std::vector<LiveAsset>& live,
            std::uintptr_t poolSlotAddress)
        {
            const auto sectionHeaders =
                module +
                static_cast<std::uintptr_t>(
                    reinterpret_cast<const IMAGE_DOS_HEADER*>(
                        module)->e_lfanew) +
                sizeof(DWORD) +
                sizeof(IMAGE_FILE_HEADER) +
                nt.FileHeader.SizeOfOptionalHeader;

            std::ofstream refs(
                "logs\\lui\\luafile_runtime_refs.csv",
                std::ios::trunc);

            std::ofstream windows(
                "logs\\lui\\luafile_runtime_ref_windows.txt",
                std::ios::trunc);

            if (refs)
            {
                refs
                    << "kind,target,hash,reference_rva,function_guess_rva,resolved_address\n";
            }

            for (unsigned int si = 0;
                 si < nt.FileHeader.NumberOfSections;
                 ++si)
            {
                IMAGE_SECTION_HEADER sh{};
                if (!SafeRead(
                        sectionHeaders +
                            static_cast<std::uintptr_t>(si) *
                                sizeof(sh),
                        sh))
                {
                    continue;
                }

                if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                    !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                {
                    continue;
                }

                const auto size =
                    static_cast<std::size_t>(
                        (std::max)(
                            sh.Misc.VirtualSize,
                            sh.SizeOfRawData));

                if (!size || size > 512ull * 1024ull * 1024ull)
                    continue;

                const auto start =
                    module + sh.VirtualAddress;

                std::vector<unsigned char> bytes(size);
                if (!SafeReadBytes(
                        start,
                        bytes.data(),
                        bytes.size()))
                {
                    continue;
                }

                // 1) Search for exact target hash constants.
                for (const auto& asset : live)
                {
                    unsigned char hashBytes[8]{};
                    std::memcpy(
                        hashBytes,
                        &asset.target.hash,
                        sizeof(asset.target.hash));

                    auto it =
                        std::search(
                            bytes.begin(),
                            bytes.end(),
                            hashBytes,
                            hashBytes + 8);

                    while (it != bytes.end())
                    {
                        const auto off =
                            static_cast<std::size_t>(
                                it - bytes.begin());

                        const auto rva =
                            static_cast<std::uintptr_t>(
                                sh.VirtualAddress) + off;

                        const auto fnOff =
                            GuessFunctionStart(bytes, off);

                        const auto fnRva =
                            static_cast<std::uintptr_t>(
                                sh.VirtualAddress) + fnOff;

                        if (refs)
                        {
                            refs
                                << "HASH_CONSTANT,"
                                << asset.target.label
                                << ",0x"
                                << std::hex
                                << std::uppercase
                                << asset.target.hash
                                << ",0x"
                                << rva
                                << ",0x"
                                << fnRva
                                << ",0x"
                                << (module + rva)
                                << std::dec
                                << "\n";
                        }

                        if (windows)
                        {
                            windows
                                << "[HASH_CONSTANT "
                                << asset.target.label
                                << " hash=0x"
                                << std::hex
                                << std::uppercase
                                << asset.target.hash
                                << " rva=0x"
                                << rva
                                << " fnGuess=0x"
                                << fnRva
                                << std::dec
                                << "]\n";

                            DumpWindow(
                                windows,
                                bytes,
                                off,
                                0x80);
                            windows << "\n";
                        }

                        it =
                            std::search(
                                it + 1,
                                bytes.end(),
                                hashBytes,
                                hashBytes + 8);
                    }
                }

                // 2) Search generic RIP-relative MOV/LEA references resolving
                // exactly to the live LUAFILE pool slot.
                for (std::size_t i = 0;
                     i + 7 <= bytes.size();
                     ++i)
                {
                    if (bytes[i] != 0x48 &&
                        bytes[i] != 0x4C)
                    {
                        continue;
                    }

                    const auto op = bytes[i + 1];
                    if (op != 0x8B &&
                        op != 0x8D)
                    {
                        continue;
                    }

                    const auto modrm = bytes[i + 2];

                    // mod=00, r/m=101 => RIP-relative disp32.
                    if ((modrm & 0xC7) != 0x05)
                        continue;

                    std::int32_t disp = 0;
                    std::memcpy(
                        &disp,
                        bytes.data() + i + 3,
                        sizeof(disp));

                    const auto instr =
                        start + i;

                    const auto resolved =
                        static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(
                                instr + 7) +
                            disp);

                    if (resolved != poolSlotAddress)
                        continue;

                    const auto rva =
                        static_cast<std::uintptr_t>(
                            sh.VirtualAddress) + i;

                    const auto fnOff =
                        GuessFunctionStart(bytes, i);

                    const auto fnRva =
                        static_cast<std::uintptr_t>(
                            sh.VirtualAddress) + fnOff;

                    if (refs)
                    {
                        refs
                            << "POOL_SLOT_RIPREF,LUAFILE_POOL,0x7C,0x"
                            << std::hex
                            << std::uppercase
                            << rva
                            << ",0x"
                            << fnRva
                            << ",0x"
                            << resolved
                            << std::dec
                            << "\n";
                    }

                    if (windows)
                    {
                        windows
                            << "[POOL_SLOT_RIPREF rva=0x"
                            << std::hex
                            << std::uppercase
                            << rva
                            << " fnGuess=0x"
                            << fnRva
                            << " resolved=0x"
                            << resolved
                            << std::dec
                            << "]\n";

                        DumpWindow(
                            windows,
                            bytes,
                            i,
                            0x80);
                        windows << "\n";
                    }
                }

                // 3) Look for immediate 0x7C asset-type loads near CALLs.
                for (std::size_t i = 0;
                     i + 8 <= bytes.size();
                     ++i)
                {
                    bool match = false;

                    // mov ecx/edx/r8d/r9d, 0x7C
                    if ((bytes[i] == 0xB9 ||
                         bytes[i] == 0xBA) &&
                        bytes[i + 1] == 0x7C &&
                        bytes[i + 2] == 0x00 &&
                        bytes[i + 3] == 0x00 &&
                        bytes[i + 4] == 0x00)
                    {
                        match = true;
                    }
                    else if (i + 6 <= bytes.size() &&
                             bytes[i] == 0x41 &&
                             (bytes[i + 1] == 0xB8 ||
                              bytes[i + 1] == 0xB9) &&
                             bytes[i + 2] == 0x7C &&
                             bytes[i + 3] == 0x00 &&
                             bytes[i + 4] == 0x00 &&
                             bytes[i + 5] == 0x00)
                    {
                        match = true;
                    }

                    if (!match)
                        continue;

                    // Only keep cases with a CALL in the next 48 bytes.
                    bool nearbyCall = false;
                    for (std::size_t j = i;
                         j < (std::min<std::size_t>)(
                             bytes.size(),
                             i + 48);
                         ++j)
                    {
                        if (bytes[j] == 0xE8)
                        {
                            nearbyCall = true;
                            break;
                        }
                    }

                    if (!nearbyCall)
                        continue;

                    const auto rva =
                        static_cast<std::uintptr_t>(
                            sh.VirtualAddress) + i;

                    const auto fnOff =
                        GuessFunctionStart(bytes, i);

                    const auto fnRva =
                        static_cast<std::uintptr_t>(
                            sh.VirtualAddress) + fnOff;

                    if (refs)
                    {
                        refs
                            << "ASSETTYPE_7C_NEAR_CALL,LUAFILE,0x7C,0x"
                            << std::hex
                            << std::uppercase
                            << rva
                            << ",0x"
                            << fnRva
                            << ",0x"
                            << (module + rva)
                            << std::dec
                            << "\n";
                    }
                }
            }
        }

        bool Run(
            std::string& message)
        {
            g_completed.store(false);

            log_paths::EnsureAll();
            CreateDirectoryA("logs\\lui", nullptr);

            Print(
                "\n[LUA-PATH] ========================================\n"
                "[LUA-PATH] BUILD262 live LuaFile + runtime-pointer scan START\n");

            if (!g_assetPool)
            {
                message = "g_assetPool unavailable";
                g_completed.store(true);
                return false;
            }

            const auto module =
                reinterpret_cast<std::uintptr_t>(
                    GetModuleHandleW(nullptr));

            if (!module)
            {
                message = "game module unavailable";
                g_completed.store(true);
                return false;
            }

            IMAGE_DOS_HEADER dos{};
            IMAGE_NT_HEADERS64 nt{};

            if (!SafeRead(module, dos) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE ||
                !SafeRead(
                    module +
                        static_cast<std::uintptr_t>(
                            dos.e_lfanew),
                    nt) ||
                nt.Signature != IMAGE_NT_SIGNATURE)
            {
                message = "game PE headers unavailable";
                g_completed.store(true);
                return false;
            }

            std::vector<LiveAsset> live;

            std::ofstream report(
                "logs\\lui\\luafile_live_targets.txt",
                std::ios::trunc);

            for (const auto& target : kTargets)
            {
                LiveAsset asset{};

                if (!FindLiveAsset(
                        target,
                        asset))
                {
                    Print(
                        "[LUA-PATH] %-18s hash=0x%llX NOT FOUND\n",
                        target.label,
                        static_cast<unsigned long long>(
                            target.hash));

                    if (report)
                    {
                        report
                            << target.label
                            << " hash=0x"
                            << std::hex
                            << std::uppercase
                            << target.hash
                            << std::dec
                            << " NOT_FOUND\n";
                    }

                    continue;
                }

                live.push_back(asset);

                Print(
                    "[LUA-PATH] %-18s hash=0x%llX index=%u layout=%s size=%llu\n",
                    target.label,
                    static_cast<unsigned long long>(
                        target.hash),
                    asset.index,
                    asset.layout.name,
                    static_cast<unsigned long long>(
                        asset.size));

                if (report)
                {
                    report
                        << target.label
                        << " hash=0x"
                        << std::hex
                        << std::uppercase
                        << target.hash
                        << " item=0x"
                        << asset.item
                        << " data=0x"
                        << asset.data
                        << std::dec
                        << " index="
                        << asset.index
                        << " layout="
                        << asset.layout.name
                        << " size="
                        << asset.size
                        << "\n";
                }
            }

            const auto poolSlotAddress =
                reinterpret_cast<std::uintptr_t>(
                    &g_assetPool[kLuaPool]);

            if (report)
            {
                report
                    << "\nLUAFILE pool slot address=0x"
                    << std::hex
                    << std::uppercase
                    << poolSlotAddress
                    << std::dec
                    << "\n";
            }

            ScanExecutable(
                module,
                nt,
                live,
                poolSlotAddress);

            // Build261 found zero static executable references. Follow the
            // live runtime objects instead and locate owners/pointers in
            // committed process memory.
            ScanRuntimePointers(live);

            g_completed.store(true);

            std::ostringstream out;
            out
                << "mapped "
                << live.size()
                << "/"
                << (sizeof(kTargets) / sizeof(kTargets[0]))
                << " decoded LuaFile targets and scanned executable references";

            message = out.str();

            Print(
                "[LUA-PATH] SCAN COMPLETE\n"
                "[LUA-PATH] live targets=logs\\lui\\luafile_live_targets.txt\n"
                "[LUA-PATH] refs=logs\\lui\\luafile_runtime_refs.csv\n"
                "[LUA-PATH] windows=logs\\lui\\luafile_runtime_ref_windows.txt\n"
                "[LUA-PATH] runtime pointers=logs\\lui\\luafile_runtime_pointer_refs.csv\n"
                "[LUA-PATH] ========================================\n\n");

            return !live.empty();
        }

        DWORD WINAPI Worker(LPVOID)
        {
            for (;;)
            {
                if (!g_running.load())
                    return 0;

                unsigned char inited = 0;
                std::uint32_t screen = 0;

                SafeRead(g_Addrs.s_inited, inited);
                SafeRead(g_Addrs.s_uiScreen, screen);

                if (inited != 0 &&
                    screen == 10)
                {
                    std::string message;
                    Run(message);
                    g_running.store(false);
                    return 0;
                }

                Sleep(100);
            }
        }
    }

    void StartAsync()
    {
        if (g_running.exchange(true))
            return;

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
            return;
        }

        CloseHandle(thread);
    }

    bool IsRunning()
    {
        return g_running.load();
    }

    bool HasCompleted()
    {
        return g_completed.load();
    }

    bool ScanNow(std::string& message)
    {
        return Run(message);
    }

    void PrintStatus()
    {
        printf(
            "[LUA-PATH] running=%s complete=%s\n",
            g_running.load() ? "yes" : "no",
            g_completed.load() ? "yes" : "no");
        fflush(stdout);
    }
}
