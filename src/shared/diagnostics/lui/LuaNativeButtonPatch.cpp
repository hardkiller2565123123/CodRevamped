#include "LuaNativeButtonPatch.h"
#include "../../core/Main.hpp"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace lua_native_button_patch
{
    namespace
    {
        constexpr int kLuaPool = 0x7C;
        constexpr std::uint64_t kFrontendRouteHash = 0x463D46EAF0995AEEull;
        constexpr std::uint64_t kCampaignWidgetHash = 0x3A9E55EA9058A8BBull;

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
            std::uint64_t hash = 0;
            std::uintptr_t item = 0;
            std::uintptr_t data = 0;
            std::uint64_t size = 0;
            unsigned int index = 0;
            Layout layout{};
        };

        struct Override
        {
            LiveAsset asset{};
            std::uintptr_t originalData = 0;
            std::uint64_t originalSize = 0;
            void* replacement = nullptr;
        };

        std::mutex g_mutex;
        std::vector<Override> g_overrides;
        std::atomic_bool g_applied{ false };
        std::atomic_bool g_workerStarted{ false };

        template <typename T>
        bool SafeRead(std::uintptr_t address, T& value)
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

        bool SafeReadBytes(std::uintptr_t address, void* output, std::size_t size)
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

        bool IsReadable(std::uintptr_t address)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            return address &&
                VirtualQuery(
                    reinterpret_cast<const void*>(address),
                    &mbi,
                    sizeof(mbi)) &&
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
        }

        std::uint64_t ReadSize(std::uintptr_t item, const Layout& layout)
        {
            if (layout.sizeWidth == 4)
            {
                std::uint32_t v = 0;
                return SafeRead(item + layout.sizeOffset, v) ? v : 0;
            }

            std::uint64_t v = 0;
            return SafeRead(item + layout.sizeOffset, v) ? v : 0;
        }

        bool WritePointer(std::uintptr_t address, std::uintptr_t value)
        {
            DWORD oldProtect = 0;
            if (!VirtualProtect(
                    reinterpret_cast<void*>(address),
                    sizeof(value),
                    PAGE_READWRITE,
                    &oldProtect))
                return false;

            *reinterpret_cast<volatile std::uintptr_t*>(address) = value;

            DWORD ignored = 0;
            VirtualProtect(
                reinterpret_cast<void*>(address),
                sizeof(value),
                oldProtect,
                &ignored);
            return true;
        }

        bool WriteSize(std::uintptr_t address, std::uint64_t value, std::uint32_t width)
        {
            DWORD oldProtect = 0;
            if (!VirtualProtect(
                    reinterpret_cast<void*>(address),
                    width,
                    PAGE_READWRITE,
                    &oldProtect))
                return false;

            if (width == 4)
                *reinterpret_cast<volatile std::uint32_t*>(address) =
                    static_cast<std::uint32_t>(value);
            else
                *reinterpret_cast<volatile std::uint64_t*>(address) = value;

            DWORD ignored = 0;
            VirtualProtect(
                reinterpret_cast<void*>(address),
                width,
                oldProtect,
                &ignored);
            return true;
        }

        bool FindAsset(std::uint64_t hash, LiveAsset& out)
        {
            out = {};

            if (!g_assetPool)
                return false;

            XAssetPool pool{};
            if (!SafeRead(
                    reinterpret_cast<std::uintptr_t>(&g_assetPool[kLuaPool]),
                    pool))
                return false;

            const auto array =
                reinterpret_cast<std::uintptr_t>(pool.pool.unk);

            const auto count =
                pool.itemAllocCount > 0
                    ? static_cast<unsigned int>(pool.itemAllocCount)
                    : pool.itemCount > 0
                        ? static_cast<unsigned int>(pool.itemCount)
                        : 0u;

            if (!array || !count || count > 500000 || !IsReadable(array))
                return false;

            const auto stride =
                pool.itemSize >= 0x18 && pool.itemSize <= 0x400
                    ? static_cast<std::size_t>(pool.itemSize)
                    : static_cast<std::size_t>(0x20);

            for (const auto& layout : kLayouts)
            {
                for (unsigned int i = 0; i < count; ++i)
                {
                    const auto item =
                        array + static_cast<std::uintptr_t>(i) * stride;

                    std::uint64_t rawHash = 0;
                    if (!SafeRead(item, rawHash) || rawHash != hash)
                        continue;

                    std::uintptr_t data = 0;
                    if (!SafeRead(item + layout.dataOffset, data))
                        continue;

                    const auto size = ReadSize(item, layout);
                    if (!data || !size || size > 16ull * 1024ull * 1024ull || !IsReadable(data))
                        continue;

                    unsigned char magic[3]{};
                    if (!SafeReadBytes(data, magic, sizeof(magic)) ||
                        magic[0] != 0x1B ||
                        magic[1] != 0x4C ||
                        magic[2] != 0x4A)
                        continue;

                    out.hash = hash;
                    out.item = item;
                    out.data = data;
                    out.size = size;
                    out.index = i;
                    out.layout = layout;
                    return true;
                }
            }

            return false;
        }

        std::size_t CountExact(
            const std::vector<unsigned char>& bytes,
            const char* needle)
        {
            const auto length = std::strlen(needle);
            if (!length || bytes.size() < length)
                return 0;

            std::size_t count = 0;
            for (std::size_t i = 0; i + length <= bytes.size(); ++i)
            {
                if (std::memcmp(bytes.data() + i, needle, length) == 0)
                    ++count;
            }

            return count;
        }

        bool PatchBytes(
            std::vector<unsigned char>& bytes,
            const char* from,
            const char* to,
            std::size_t expectedCount,
            std::string& reason)
        {
            const auto a = std::strlen(from);
            const auto b = std::strlen(to);

            if (a != b)
            {
                reason = "replacement lengths differ";
                return false;
            }

            const auto count = CountExact(bytes, from);
            if (count != expectedCount)
            {
                std::ostringstream ss;
                ss << from << " expected " << expectedCount
                   << " occurrence(s), found " << count;
                reason = ss.str();
                return false;
            }

            for (std::size_t i = 0; i + a <= bytes.size(); ++i)
            {
                if (std::memcmp(bytes.data() + i, from, a) == 0)
                {
                    std::memcpy(bytes.data() + i, to, b);
                    i += a - 1;
                }
            }

            reason = "patched";
            return true;
        }

        bool MakeOverride(
            const LiveAsset& asset,
            const char* from,
            const char* to,
            std::size_t expectedCount,
            Override& out,
            std::string& reason)
        {
            std::vector<unsigned char> bytes(
                static_cast<std::size_t>(asset.size));

            if (!SafeReadBytes(asset.data, bytes.data(), bytes.size()))
            {
                reason = "could not read live LuaJIT chunk";
                return false;
            }

            if (!PatchBytes(bytes, from, to, expectedCount, reason))
                return false;

            void* memory = VirtualAlloc(
                nullptr,
                bytes.size(),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE);

            if (!memory)
            {
                reason = "VirtualAlloc failed";
                return false;
            }

            std::memcpy(memory, bytes.data(), bytes.size());

            if (!WritePointer(
                    asset.item + asset.layout.dataOffset,
                    reinterpret_cast<std::uintptr_t>(memory)) ||
                !WriteSize(
                    asset.item + asset.layout.sizeOffset,
                    bytes.size(),
                    asset.layout.sizeWidth))
            {
                WritePointer(
                    asset.item + asset.layout.dataOffset,
                    asset.data);
                WriteSize(
                    asset.item + asset.layout.sizeOffset,
                    asset.size,
                    asset.layout.sizeWidth);

                VirtualFree(memory, 0, MEM_RELEASE);
                reason = "failed to swap live LuaFile";
                return false;
            }

            out.asset = asset;
            out.originalData = asset.data;
            out.originalSize = asset.size;
            out.replacement = memory;
            reason = "installed";
            return true;
        }

        void UndoOverride(Override& record)
        {
            if (!record.asset.item)
                return;

            WritePointer(
                record.asset.item + record.asset.layout.dataOffset,
                record.originalData);

            WriteSize(
                record.asset.item + record.asset.layout.sizeOffset,
                record.originalSize,
                record.asset.layout.sizeWidth);

            if (record.replacement)
                VirtualFree(record.replacement, 0, MEM_RELEASE);

            record = {};
        }

        void Log(const std::string& text)
        {
            log_paths::EnsureAll();
            CreateDirectoryA("logs\\lui", nullptr);

            std::ofstream out(
                "logs\\lui\\lua_native_button_patch.log",
                std::ios::app);

            if (out)
                out << text << "\n";
        }

        DWORD WINAPI AutoWorker(LPVOID)
        {
            for (;;)
            {
                unsigned char inited = 0;
                std::uint32_t screen = 0;

                SafeRead(g_Addrs.s_inited, inited);
                SafeRead(g_Addrs.s_uiScreen, screen);

                if (inited != 0 && screen == 10)
                {
                    std::string message;
                    const bool ok = Apply(message);

                    std::printf(
                        "[LUA-BUTTON] auto %s: %s\n",
                        ok ? "applied" : "skipped",
                        message.c_str());
                    std::fflush(stdout);
                    return 0;
                }

                Sleep(100);
            }
        }
    }

    void StartAuto()
    {
        if (g_workerStarted.exchange(true))
            return;

        HANDLE thread =
            CreateThread(
                nullptr,
                0,
                AutoWorker,
                nullptr,
                0,
                nullptr);

        if (thread)
            CloseHandle(thread);
    }

    bool Apply(std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_mutex);

        if (g_applied.load())
        {
            message = "native Lua button patch already active";
            return true;
        }

        LiveAsset route{};
        LiveAsset widget{};

        if (!FindAsset(kFrontendRouteHash, route))
        {
            message = "frontend route LuaFile 463D46EAF0995AEE is not live";
            return false;
        }

        if (!FindAsset(kCampaignWidgetHash, widget))
        {
            message = "Campaign widget LuaFile 3A9E55EA9058A8BB is not live";
            return false;
        }

        Override routeOverride{};
        Override widgetOverride{};
        std::string reason;

        // Equal-length only. The LuaJIT chunk size and encoded string lengths
        // remain untouched:
        // CampaignMain (12) -> FrontendMain (12)
        // Campaign      (8) -> REVAMPED     (8)
        if (!MakeOverride(
                route,
                "CampaignMain",
                "FrontendMain",
                1,
                routeOverride,
                reason))
        {
            message = "route override refused: " + reason;
            return false;
        }

        if (!MakeOverride(
                widget,
                "Campaign",
                "REVAMPED",
                1,
                widgetOverride,
                reason))
        {
            UndoOverride(routeOverride);
            message = "label override refused: " + reason;
            return false;
        }

        g_overrides.push_back(routeOverride);
        g_overrides.push_back(widgetOverride);
        g_applied.store(true);

        std::ostringstream ss;
        ss
            << "native LUI proof active: Campaign slot -> REVAMPED; "
            << "safe route CampaignMain->FrontendMain; "
            << "routeIndex=" << route.index
            << " widgetIndex=" << widget.index;

        message = ss.str();
        Log(message);
        return true;
    }

    bool Restore(std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_mutex);

        for (auto it = g_overrides.rbegin();
             it != g_overrides.rend();
             ++it)
        {
            UndoOverride(*it);
        }

        g_overrides.clear();
        g_applied.store(false);
        message = "native Lua button overrides restored";
        Log(message);
        return true;
    }

    bool IsApplied()
    {
        return g_applied.load();
    }

    void PrintStatus()
    {
        std::lock_guard<std::mutex> lock(g_mutex);

        std::printf(
            "[LUA-BUTTON] applied=%s overrides=%llu "
            "route=463D46EAF0995AEE label=3A9E55EA9058A8BB\n",
            g_applied.load() ? "yes" : "no",
            static_cast<unsigned long long>(g_overrides.size()));
        std::fflush(stdout);
    }
}
