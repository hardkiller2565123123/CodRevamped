#include "LuaOwnerStateTrace.h"
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
#include <cstring>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace lua_owner_state_trace
{
    namespace
    {
        struct Target
        {
            const char* label;
            std::uint64_t hash;
        };

        constexpr int kLuaPool = 0x7C;

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

        std::atomic_bool g_running{ false };
        std::atomic_bool g_ownerFound{ false };

        std::mutex g_mutex;
        std::vector<LiveAsset> g_assets;
        std::uintptr_t g_owner = 0;
        std::size_t g_ownerSpan = 0;

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
                    reinterpret_cast<std::uintptr_t>(
                        &g_assetPool[kLuaPool]),
                    pool))
            {
                return false;
            }

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
                    ? static_cast<std::size_t>(
                        pool.itemSize)
                    : static_cast<std::size_t>(
                        0x20);

            for (const auto& layout : kLayouts)
            {
                for (unsigned int i = 0; i < count; ++i)
                {
                    const auto item =
                        array +
                        static_cast<std::uintptr_t>(i) *
                            stride;

                    std::uint64_t hash = 0;

                    if (!SafeRead(item, hash) ||
                        hash != target.hash)
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

                    unsigned char magic[3]{};

                    if (!SafeReadBytes(
                            data,
                            magic,
                            sizeof(magic)) ||
                        magic[0] != 0x1B ||
                        magic[1] != 0x4C ||
                        magic[2] != 0x4A)
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

        bool RefreshAssets(
            std::vector<LiveAsset>& assets)
        {
            assets.clear();

            for (const auto& target : kTargets)
            {
                LiveAsset asset{};

                if (!FindLiveAsset(
                        target,
                        asset))
                {
                    return false;
                }

                assets.push_back(asset);
            }

            return
                assets.size() ==
                sizeof(kTargets) / sizeof(kTargets[0]);
        }

        bool MatchPointer(
            const unsigned char* bytes,
            std::size_t offset,
            std::uintptr_t wanted)
        {
            std::uintptr_t value = 0;
            std::memcpy(
                &value,
                bytes + offset,
                sizeof(value));

            return value == wanted;
        }

        bool SearchRegionForOwner(
            const MEMORY_BASIC_INFORMATION& mbi,
            const std::vector<LiveAsset>& assets,
            std::uintptr_t& owner,
            std::size_t& span)
        {
            owner = 0;
            span = 0;

            const auto regionBase =
                reinterpret_cast<std::uintptr_t>(
                    mbi.BaseAddress);

            const auto regionSize =
                static_cast<std::size_t>(
                    mbi.RegionSize);

            if (regionSize < 0xE8 ||
                regionSize >
                    512ull * 1024ull * 1024ull)
            {
                return false;
            }

            constexpr std::size_t kChunk =
                4ull * 1024ull * 1024ull;

            std::vector<unsigned char>
                bytes(kChunk + 0x100);

            for (std::size_t consumed = 0;
                 consumed < regionSize;)
            {
                const auto want =
                    (std::min<std::size_t>)(
                        bytes.size(),
                        regionSize - consumed);

                SIZE_T got = 0;

                if (!ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(
                            regionBase + consumed),
                        bytes.data(),
                        want,
                        &got) ||
                    got < 0xE8)
                {
                    consumed += want;
                    continue;
                }

                for (std::size_t i = 0;
                     i + 0xE8 <= got;
                     i += sizeof(std::uintptr_t))
                {
                    // Build263 log showed a stable 0x48 stride:
                    // +00 item0, +08 data0
                    // +48 item1, +50 data1
                    // +90 item2, +98 data2
                    // +D8 item3, +E0 data3
                    if (MatchPointer(
                            bytes.data(),
                            i + 0x00,
                            assets[0].item) &&
                        MatchPointer(
                            bytes.data(),
                            i + 0x08,
                            assets[0].data) &&
                        MatchPointer(
                            bytes.data(),
                            i + 0x48,
                            assets[1].item) &&
                        MatchPointer(
                            bytes.data(),
                            i + 0x50,
                            assets[1].data) &&
                        MatchPointer(
                            bytes.data(),
                            i + 0x90,
                            assets[2].item) &&
                        MatchPointer(
                            bytes.data(),
                            i + 0x98,
                            assets[2].data) &&
                        MatchPointer(
                            bytes.data(),
                            i + 0xD8,
                            assets[3].item) &&
                        MatchPointer(
                            bytes.data(),
                            i + 0xE0,
                            assets[3].data))
                    {
                        owner =
                            regionBase +
                            consumed +
                            i;

                        span = 0xE8;
                        return true;
                    }
                }

                if (want <= 0x100)
                    break;

                consumed +=
                    want - 0x100;
            }

            return false;
        }

        bool FindOwner(
            const std::vector<LiveAsset>& assets,
            std::uintptr_t& owner,
            std::size_t& span)
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);

            auto address =
                reinterpret_cast<std::uintptr_t>(
                    si.lpMinimumApplicationAddress);

            const auto maxAddress =
                reinterpret_cast<std::uintptr_t>(
                    si.lpMaximumApplicationAddress);

            while (address < maxAddress)
            {
                MEMORY_BASIC_INFORMATION mbi{};

                if (!VirtualQuery(
                        reinterpret_cast<const void*>(address),
                        &mbi,
                        sizeof(mbi)))
                {
                    break;
                }

                const bool readable =
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect &
                      (PAGE_NOACCESS | PAGE_GUARD));

                if (readable)
                {
                    if (SearchRegionForOwner(
                            mbi,
                            assets,
                            owner,
                            span))
                    {
                        return true;
                    }
                }

                const auto next =
                    reinterpret_cast<std::uintptr_t>(
                        mbi.BaseAddress) +
                    static_cast<std::uintptr_t>(
                        mbi.RegionSize);

                if (next <= address)
                    break;

                address = next;
            }

            return false;
        }

        std::string SanitizeLabel(
            std::string label)
        {
            if (label.empty())
                label = "mark";

            for (char& c : label)
            {
                const bool ok =
                    (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '_' ||
                    c == '-';

                if (!ok)
                    c = '_';
            }

            if (label.size() > 64)
                label.resize(64);

            return label;
        }

        void DumpHex(
            std::ofstream& out,
            std::uintptr_t address,
            std::size_t size)
        {
            std::vector<unsigned char>
                bytes(size);

            if (!SafeReadBytes(
                    address,
                    bytes.data(),
                    bytes.size()))
            {
                out << "READ_FAILED\n";
                return;
            }

            out
                << std::hex
                << std::uppercase
                << std::setfill('0');

            for (std::size_t row = 0;
                 row < bytes.size();
                 row += 16)
            {
                out
                    << "0x"
                    << std::setw(16)
                    << (address + row)
                    << ": ";

                for (std::size_t j = 0;
                     j < 16 &&
                     row + j < bytes.size();
                     ++j)
                {
                    out
                        << std::setw(2)
                        << static_cast<unsigned int>(
                            bytes[row + j])
                        << ' ';
                }

                out << "\n";
            }

            out << std::dec;
        }

        bool WriteSnapshot(
            const std::string& rawLabel,
            std::string& message)
        {
            std::lock_guard<std::mutex>
                lock(g_mutex);

            if (!g_ownerFound.load() ||
                !g_owner)
            {
                message =
                    "Lua owner has not been found yet";
                return false;
            }

            const auto label =
                SanitizeLabel(rawLabel);

            log_paths::EnsureAll();
            CreateDirectoryA(
                "logs\\lui",
                nullptr);
            CreateDirectoryA(
                "logs\\lui\\owner_marks",
                nullptr);

            SYSTEMTIME st{};
            GetLocalTime(&st);

            char path[MAX_PATH]{};

            sprintf_s(
                path,
                "logs\\lui\\owner_marks\\%02u%02u%02u_%03u_%s.txt",
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds,
                label.c_str());

            std::ofstream out(
                path,
                std::ios::trunc);

            if (!out)
            {
                message =
                    "could not create owner snapshot";
                return false;
            }

            std::uint32_t screen = 0;
            std::uint32_t network = 0;
            std::uint32_t session = 0;
            unsigned char inited = 0;

            SafeRead(
                g_Addrs.s_uiScreen,
                screen);
            SafeRead(
                g_Addrs.s_networkMode,
                network);
            SafeRead(
                g_Addrs.sSessionModeState,
                session);
            SafeRead(
                g_Addrs.s_inited,
                inited);

            out
                << "[MARK]\n"
                << "label="
                << label
                << "\n"
                << "owner=0x"
                << std::hex
                << std::uppercase
                << g_owner
                << std::dec
                << "\n"
                << "ownerSpan=0x"
                << std::hex
                << g_ownerSpan
                << std::dec
                << "\n"
                << "s_uiScreen=0x"
                << std::hex
                << screen
                << "\n"
                << "s_networkMode=0x"
                << network
                << "\n"
                << "sSessionModeState=0x"
                << session
                << "\n"
                << "s_inited=0x"
                << static_cast<unsigned int>(
                    inited)
                << std::dec
                << "\n\n";

            out << "[LIVE LUA ASSETS]\n";

            for (const auto& asset : g_assets)
            {
                out
                    << asset.target.label
                    << " hash=0x"
                    << std::hex
                    << std::uppercase
                    << asset.target.hash
                    << " item=0x"
                    << asset.item
                    << " data=0x"
                    << asset.data
                    << std::dec
                    << " size="
                    << asset.size
                    << " index="
                    << asset.index
                    << "\n";
            }

            out << "\n[OWNER WINDOW -0x100 .. +0x300]\n";

            const auto begin =
                g_owner > 0x100
                    ? g_owner - 0x100
                    : g_owner;

            DumpHex(
                out,
                begin,
                0x400);

            std::ofstream timeline(
                "logs\\lui\\lua_owner_timeline.csv",
                std::ios::app);

            if (timeline)
            {
                if (timeline.tellp() == 0)
                {
                    timeline
                        << "time,label,owner,screen,network,session,inited\n";
                }

                timeline
                    << st.wHour
                    << ":"
                    << st.wMinute
                    << ":"
                    << st.wSecond
                    << "."
                    << st.wMilliseconds
                    << ","
                    << label
                    << ",0x"
                    << std::hex
                    << std::uppercase
                    << g_owner
                    << ",0x"
                    << screen
                    << ",0x"
                    << network
                    << ",0x"
                    << session
                    << ",0x"
                    << static_cast<unsigned int>(
                        inited)
                    << std::dec
                    << "\n";
            }

            std::ostringstream result;
            result
                << "snapshot written: "
                << path;

            message = result.str();

            std::printf(
                "[LUA-CTX] mark=%s owner=0x%llX screen=0x%X network=0x%X session=0x%X\n",
                label.c_str(),
                static_cast<unsigned long long>(
                    g_owner),
                screen,
                network,
                session);
            std::fflush(stdout);

            return true;
        }

        bool ResolveOwner(
            std::string& message)
        {
            std::vector<LiveAsset> assets;

            if (!RefreshAssets(assets))
            {
                message =
                    "not all four decoded LuaFiles are live yet";
                return false;
            }

            std::uintptr_t owner = 0;
            std::size_t span = 0;

            if (!FindOwner(
                    assets,
                    owner,
                    span))
            {
                message =
                    "four-LuaFile runtime owner/table not found";
                return false;
            }

            {
                std::lock_guard<std::mutex>
                    lock(g_mutex);

                g_assets =
                    std::move(assets);
                g_owner = owner;
                g_ownerSpan = span;
            }

            g_ownerFound.store(true);

            log_paths::EnsureAll();
            CreateDirectoryA(
                "logs\\lui",
                nullptr);

            std::ofstream report(
                "logs\\lui\\lua_owner_context.txt",
                std::ios::trunc);

            if (report)
            {
                report
                    << "owner=0x"
                    << std::hex
                    << std::uppercase
                    << owner
                    << "\n"
                    << "span=0x"
                    << span
                    << std::dec
                    << "\n"
                    << "layout=4 entries, stride 0x48, item @ +0x0, data @ +0x8\n\n";

                for (std::size_t i = 0;
                     i < g_assets.size();
                     ++i)
                {
                    const auto& a =
                        g_assets[i];

                    report
                        << i
                        << " "
                        << a.target.label
                        << " hash=0x"
                        << std::hex
                        << a.target.hash
                        << " item=0x"
                        << a.item
                        << " data=0x"
                        << a.data
                        << std::dec
                        << " size="
                        << a.size
                        << "\n";
                }
            }

            std::ostringstream result;
            result
                << "Lua owner found at 0x"
                << std::hex
                << std::uppercase
                << owner;

            message =
                result.str();

            return true;
        }

        DWORD WINAPI Worker(
            LPVOID)
        {
            for (;;)
            {
                if (!g_running.load())
                    return 0;

                unsigned char inited = 0;
                std::uint32_t screen = 0;

                SafeRead(
                    g_Addrs.s_inited,
                    inited);
                SafeRead(
                    g_Addrs.s_uiScreen,
                    screen);

                if (inited != 0 &&
                    screen == 10)
                {
                    std::string message;

                    if (ResolveOwner(message))
                    {
                        std::printf(
                            "[LUA-CTX] %s\n",
                            message.c_str());
                        std::fflush(stdout);

                        std::string markMessage;
                        WriteSnapshot(
                            "auto_fresh_director",
                            markMessage);

                        g_running.store(false);
                        return 0;
                    }
                }

                Sleep(250);
            }
        }
    }

    void StartAsync()
    {
        if (g_running.exchange(true))
            return;

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

    bool HasOwner()
    {
        return g_ownerFound.load();
    }

    bool FindOwnerNow(
        std::string& message)
    {
        return ResolveOwner(message);
    }

    bool Mark(
        const std::string& label,
        std::string& message)
    {
        if (!g_ownerFound.load())
        {
            std::string findMessage;

            if (!ResolveOwner(
                    findMessage))
            {
                message = findMessage;
                return false;
            }
        }

        return WriteSnapshot(
            label,
            message);
    }

    void PrintStatus()
    {
        std::lock_guard<std::mutex>
            lock(g_mutex);

        std::printf(
            "[LUA-CTX] running=%s ownerFound=%s owner=0x%llX assets=%llu\n",
            g_running.load()
                ? "yes"
                : "no",
            g_ownerFound.load()
                ? "yes"
                : "no",
            static_cast<unsigned long long>(
                g_owner),
            static_cast<unsigned long long>(
                g_assets.size()));
        std::fflush(stdout);
    }

    bool GetOwnerAddress(
        std::uintptr_t& owner)
    {
        std::lock_guard<std::mutex>
            lock(g_mutex);

        owner = g_owner;
        return
            g_ownerFound.load() &&
            owner != 0;
    }

    bool GetLiveAssetPointers(
        std::uintptr_t items[4],
        std::uintptr_t data[4],
        std::uint64_t hashes[4])
    {
        if (!items ||
            !data ||
            !hashes)
        {
            return false;
        }

        std::lock_guard<std::mutex>
            lock(g_mutex);

        if (!g_ownerFound.load() ||
            g_assets.size() != 4)
        {
            return false;
        }

        for (std::size_t i = 0;
             i < 4;
             ++i)
        {
            items[i] =
                g_assets[i].item;
            data[i] =
                g_assets[i].data;
            hashes[i] =
                g_assets[i].target.hash;
        }

        return true;
    }
}
