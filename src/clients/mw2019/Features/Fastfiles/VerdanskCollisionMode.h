#pragma once
// CodRevamped MW2019 replay 1.20: use native tiled Verdansk collision mode
// only when the combined collision fastfile is absent and numbered tiles exist.
// The hook preserves the original game's mode setter and all map/collision
// scheduling and unloading behavior. No fastfile data is modified or spoofed.
// Included from MW2019RedirectProxy.cpp inside its anonymous namespace, after
// Replay120InstallHook and VerdanskFastfileProbe.h.

namespace replay120_collision_mode
{
    constexpr std::uintptr_t kNativeModeSetterRva = 0x0D6B7D0ull;
    // The original setter: mov dword ptr [rip+0x4F5BD5E], ecx; ret.
    // 0x0D6B7D0 + 6 + 0x4F5BD5E = 0x5CC7534 (native mode variable).
    constexpr std::uintptr_t kRegisteredMapPointerRva = 0x05CC7538ull;
    using ModeSetter = void(__fastcall*)(int);
    inline ModeSetter originalSetMode = nullptr;

    inline bool RegisteredMapIsVerdansk() noexcept
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return false;
        std::uintptr_t nativeMapString = 0;
        SIZE_T transferred = 0;
        if (!ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<void*>(base + kRegisteredMapPointerRva),
                &nativeMapString, sizeof(nativeMapString), &transferred) ||
            transferred != sizeof(nativeMapString) || !nativeMapString)
            return false;
        char mapName[sizeof("mp_donetsk")]{};
        if (!ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<void*>(nativeMapString), mapName,
                sizeof(mapName), &transferred) ||
            transferred != sizeof(mapName))
            return false;
        return std::memcmp(mapName, "mp_donetsk", sizeof(mapName)) == 0;
    }

    inline bool CombinedFastfileMissing() noexcept
    {
        const DWORD attributes = GetFileAttributesW(L"zone\\mp_donetsk_cg_ls_tr.ff");
        if (attributes != INVALID_FILE_ATTRIBUTES)
            return false;
        const DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }

    inline bool NumberedTilesAvailable() noexcept
    {
        return replay120_fastfiles::HasNumberedTile(
            L"zone\\mp_donetsk_cg_?????_tr.ff");
    }

    inline void __fastcall SetModeDetour(int requested) noexcept
    {
        int selected = requested;
        if (requested == 2 && RegisteredMapIsVerdansk())
        {
            // Don't override a present combined file, including if Windows
            // reports an access/lock error. Only absence qualifies.
            const bool missingCombined = CombinedFastfileMissing();
            const bool hasTiles = missingCombined && NumberedTilesAvailable();
            if (hasTiles)
                selected = 1;
            ConsolePrint(
                "[FF120-MODE] map=mp_donetsk requested=%d selected=%d "
                "combinedMissing=%u numberedTiles=%u\r\n",
                requested, selected, missingCombined ? 1u : 0u,
                hasTiles ? 1u : 0u);
        }
        if (originalSetMode)
            originalSetMode(selected);
    }

    inline bool Install() noexcept
    {
        const bool installed = Replay120InstallHook(
            "CL_TransientsCollisionMP_SetTransientMode/verdansk-split",
            kNativeModeSetterRva, reinterpret_cast<void*>(&SetModeDetour),
            reinterpret_cast<void**>(&originalSetMode));
        ConsolePrint("[FF120-MODE] hook=%s policy=Verdansk-only "
                     "combined-missing-and-numbered-tiles\r\n",
                     installed ? "installed" : "failed");
        return installed;
    }
}
