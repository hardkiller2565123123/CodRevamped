#include "DW_LocalProgression.h"
#include "DW_LocalConfig.h"
#include "replay_dvar.h"
#include "com_optimized.h"
#include "dw_progression_ranks.h"
#include <stddef.h>
#include <emmintrin.h>

extern "C"
{
    uint64_t DW_LocalPlatform_UserId();
    bool DW_LocalBackend_IsEnabled();
    void *func_14105BC30(); // Original OnlineProgression::GetInstance
    int func_1420838B0(void *);               // lua_gettop
    int func_1420839E0(void *, int);          // lua_isnumber
    double func_142084A10(void *, int);       // lua_tonumber
    void func_142084100(void *, double);     // lua_pushnumber
    int func_142089FB0(void *, const char *, ...); // luaL_error
    int func_140D66C20(int);                 // CL_Mgr_GetClientFromController
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) int __stdcall FreeLibrary(void *);
    void Com_Printf(int, const char *, ...);
}

namespace
{
    struct API
    {
        unsigned long(__stdcall *GetEnvironmentVariableW)(const wchar_t *, wchar_t *, unsigned long);
        int(__stdcall *CreateDirectoryW)(const wchar_t *, void *);
        void *(__stdcall *CreateFileW)(const wchar_t *, unsigned long, unsigned long, void *,
                                      unsigned long, unsigned long, void *);
        int(__stdcall *ReadFile)(void *, void *, unsigned long, unsigned long *, void *);
        int(__stdcall *WriteFile)(void *, const void *, unsigned long, unsigned long *, void *);
        int(__stdcall *FlushFileBuffers)(void *);
        int(__stdcall *CloseHandle)(void *);
        int(__stdcall *MoveFileExW)(const wchar_t *, const wchar_t *, unsigned long);
        unsigned long(__stdcall *GetTickCount)();

        bool Load()
        {
            if (GetEnvironmentVariableW)
                return CreateDirectoryW && CreateFileW && ReadFile && WriteFile &&
                       FlushFileBuffers && CloseHandle && MoveFileExW && GetTickCount;
            auto library = LoadLibraryA("kernel32.dll");
            if (!library)
                return false;
#define DW_LOAD(name) name = reinterpret_cast<decltype(name)>(GetProcAddress(library, #name))
            DW_LOAD(CreateDirectoryW);
            DW_LOAD(CreateFileW);
            DW_LOAD(ReadFile);
            DW_LOAD(WriteFile);
            DW_LOAD(FlushFileBuffers);
            DW_LOAD(CloseHandle);
            DW_LOAD(MoveFileExW);
            DW_LOAD(GetTickCount);
            DW_LOAD(GetEnvironmentVariableW);
#undef DW_LOAD
            FreeLibrary(library); // Kernel32 stays loaded by the EXE's existing imports.
            return GetEnvironmentVariableW && CreateDirectoryW && CreateFileW && ReadFile &&
                   WriteFile && FlushFileBuffers && CloseHandle && MoveFileExW && GetTickCount;
        }
    };
    API s_api{};
    struct DWLocalProgressionRecord
    {
        uint32_t magic, version;
        uint64_t user, xp;
        uint32_t appliedRank, reserved;
        uint64_t checksum;
    };
    static_assert(sizeof(DWLocalProgressionRecord) == 40);
    static_assert(offsetof(DWLocalProgressionRecord, checksum) == 32);

    // Same Replay constructor and UpdateProgression: the complete player-array
    // prefix is 64 bytes followed by this Windows build's one (XP, rank) pair.
    // Its season array starts at +80; the Xbox source's eight players do not.
    struct DWReplayPlayerProgression
    {
        uint64_t xp, rank;
    };
    struct DWReplayProgressionPrefix
    {
        uint8_t native[64];
        DWReplayPlayerProgression players[1];
    };
    static_assert(offsetof(DWReplayProgressionPrefix, players) == 64);
    static_assert(sizeof(DWReplayProgressionPrefix) == 80);

    // Replay's Loot.IsOwned binding reads one Windows client, not the Xbox
    // source's eight inventory arrays. Keep quantities separate from unlock
    // policy; virtual ownership must not overwrite purchased/earned items.
    struct DWReplayInventoryItem
    {
        uint32_t id, quantity;
    };
    struct DWReplayLootInventoryPrefix
    {
        uint8_t native[64];
        DWReplayInventoryItem items[15000];
        int32_t count;
    };
    static_assert(sizeof(DWReplayInventoryItem) == 8);
    static_assert(offsetof(DWReplayLootInventoryPrefix, items) == 64);
    static_assert(offsetof(DWReplayLootInventoryPrefix, count) == 120064);
    extern "C" DWReplayLootInventoryPrefix gl_1459E05C0;

    uint32_t InventoryQuantity(const DWReplayLootInventoryPrefix &inventory, uint32_t item)
    {
        const int count = inventory.count;
        if (count < 0 || count > 15000)
            return 0;
        int index = 0;
        if (Com_Optimized_IsEnabled())
        {
            const auto wanted = _mm_set1_epi32(static_cast<int32_t>(item));
            // Four native (id, quantity) records, with no reads beyond count.
            // Select ID lanes only: a quantity equal to item is not a match.
            // SSE2 is baseline for this x64 executable; no AVX requirement.
            for (; index + 4 <= count; index += 4)
            {
                const auto first = _mm_loadu_si128(
                    reinterpret_cast<const __m128i *>(&inventory.items[index]));
                const auto second = _mm_loadu_si128(
                    reinterpret_cast<const __m128i *>(&inventory.items[index + 2]));
                const auto ids = _mm_castps_si128(_mm_shuffle_ps(
                    _mm_castsi128_ps(first), _mm_castsi128_ps(second), _MM_SHUFFLE(2, 0, 2, 0)));
                const unsigned matches = _mm_movemask_ps(_mm_castsi128_ps(_mm_cmpeq_epi32(ids, wanted)));
                if (matches)
                    return inventory.items[index + (__builtin_ctz(matches))].quantity;
            }
        }
        for (; index < count; ++index)
            if (inventory.items[index].id == item)
                return inventory.items[index].quantity;
        return 0;
    }

    DWLocalProgressionRecord s_record{};
    uint64_t s_savedUser = 0, s_savedXp = 0;
    unsigned s_savedRank = 0, s_savedValid = 0;
    wchar_t s_directory[1024]{}, s_path[1100]{}, s_pending[1100]{};
    bool s_loaded = false, s_valid = false, s_corrupt = false;
    unsigned s_poll = 0, s_unlockMask = 0;

    uint64_t Checksum(const DWLocalProgressionRecord &record)
    {
        uint64_t value = 14695981039346656037ULL;
        const auto *bytes = reinterpret_cast<const uint8_t *>(&record);
        for (unsigned i = 0; i < offsetof(DWLocalProgressionRecord, checksum); ++i)
            value = (value ^ bytes[i]) * 1099511628211ULL;
        return value;
    }

    void Append(wchar_t *destination, const wchar_t *suffix)
    {
        while ((*destination++ = *suffix++) != 0)
        {
            // Callers provide bounded fixed suffixes after a bounded environment path.
        }
    }

    void Load()
    {
        if (s_loaded)
            return;
        s_loaded = true;
        if (!s_api.Load())
            return;
        const auto length = s_api.GetEnvironmentVariableW(L"LOCALAPPDATA", s_directory, 900);
        if (!length || length >= 900)
            return;
        Append(s_directory + length, L"\\ReplayDW");
        unsigned end = 0;
        while (s_directory[end])
        {
            s_path[end] = s_pending[end] = s_directory[end];
            ++end;
        }
        Append(s_path + end, L"\\player-progression.bin");
        Append(s_pending + end, L"\\player-progression.pending");
        auto file = s_api.CreateFileW(s_path, 0x80000000, 1, nullptr, 3, 0x80, nullptr);
        if (file == reinterpret_cast<void *>(~uintptr_t{0}))
            return;
        DWLocalProgressionRecord record{};
        unsigned long received = 0, extraCount = 0;
        uint8_t extra = 0;
        const bool read = s_api.ReadFile(file, &record, sizeof(record), &received, nullptr) &&
                          received == sizeof(record) &&
                          s_api.ReadFile(file, &extra, 1, &extraCount, nullptr) && !extraCount;
        s_api.CloseHandle(file);
        s_valid = read && record.magic == 0x31505852 && record.version == 1 &&
                  record.user && record.appliedRank <= 55 && !record.reserved &&
                  record.checksum == Checksum(record);
        s_corrupt = !s_valid;
        if (s_valid)
        {
            s_record = record;
            __atomic_store_n(&s_savedUser, record.user, __ATOMIC_RELEASE);
            __atomic_store_n(&s_savedXp, record.xp, __ATOMIC_RELEASE);
            __atomic_store_n(&s_savedRank, record.appliedRank, __ATOMIC_RELEASE);
            __atomic_store_n(&s_savedValid, 1U, __ATOMIC_RELEASE);
        }
        else
            Com_Printf(25, "[DW] Local progression record invalid; preserving the existing file\n");
    }

    bool Save(uint64_t user, uint64_t xp)
    {
        if (!s_path[0] || s_corrupt)
            return false;
        s_api.CreateDirectoryW(s_directory, nullptr);
        DWLocalProgressionRecord record{0x31505852, 1, user, xp, DW_LocalConfig_Rank(), 0, 0};
        record.checksum = Checksum(record);
        auto file = s_api.CreateFileW(s_pending, 0x40000000, 0, nullptr, 2, 0x80, nullptr);
        if (file == reinterpret_cast<void *>(~uintptr_t{0}))
            return false;
        unsigned long written = 0;
        const bool saved = s_api.WriteFile(file, &record, sizeof(record), &written, nullptr) &&
                           written == sizeof(record) && s_api.FlushFileBuffers(file);
        s_api.CloseHandle(file);
        if (!saved || !s_api.MoveFileExW(s_pending, s_path, 9))
            return false;
        s_record = record;
        s_valid = true;
        __atomic_store_n(&s_savedUser, record.user, __ATOMIC_RELEASE);
        __atomic_store_n(&s_savedXp, record.xp, __ATOMIC_RELEASE);
        __atomic_store_n(&s_savedRank, record.appliedRank, __ATOMIC_RELEASE);
        __atomic_store_n(&s_savedValid, 1U, __ATOMIC_RELEASE);
        Com_Printf(25, "[DW] Local player progression saved: XP %llu\n", xp);
        return true;
    }
}

// The shipped binding inlines the inventory lookup and has no
// unlock_all_loot dvar branch. Recompile its existing registration target so
// every Lua ownership query receives the configured local unlock policy.
extern "C" int LUI_CoD_LuaCall_IsOwned(void *luaVM)
{
    if (func_1420838B0(luaVM) != 2 || !func_1420839E0(luaVM, 1) ||
        !func_1420839E0(luaVM, 2))
        return func_142089FB0(luaVM, "USAGE: Loot.IsOwned(<controller>, <item ID>)");
    const int controller = static_cast<int>(func_142084A10(luaVM, 1));
    const auto item = static_cast<uint32_t>(static_cast<int64_t>(func_142084A10(luaVM, 2)));
    uint32_t quantity = 0;
    if (controller >= 0 && controller < 8 && func_140D66C20(controller) == 0)
    {
        quantity = InventoryQuantity(gl_1459E05C0, item);
        // Shipped loot_master.csv assigns bundles to 400000..409999 and
        // Battle Pass products to 430000..439999. Store.BundleAvailable hides
        // owned products: an unlock policy must not fabricate their purchases.
        const bool product = (item >= 400000 && item <= 409999) ||
                             (item >= 430000 && item <= 439999);
        if (item && item != UINT32_MAX && !product && DW_LocalBackend_IsEnabled() &&
            DW_LocalConfig_UnlockAll() && !quantity)
            quantity = 1;
    }
    func_142084100(luaVM, static_cast<double>(static_cast<int32_t>(quantity)));
    if (func_1420838B0(luaVM) < 1)
        return func_142089FB0(luaVM, "Loot.IsOwned return stack mismatch");
    return 1;
}

extern "C" bool DW_LocalProgression_LoginFields(uint64_t *user, uint64_t *xp, unsigned *appliedRank)
{
    Load();
    const bool valid = __atomic_load_n(&s_savedValid, __ATOMIC_ACQUIRE) != 0;
    *user = valid ? __atomic_load_n(&s_savedUser, __ATOMIC_ACQUIRE) : 0;
    *xp = valid ? __atomic_load_n(&s_savedXp, __ATOMIC_ACQUIRE) : 0;
    *appliedRank = valid ? __atomic_load_n(&s_savedRank, __ATOMIC_ACQUIRE) : 0;
    return valid;
}

extern "C" void DW_LocalProgression_Frame()
{
    const auto user = DW_LocalPlatform_UserId();
    if (!user)
        return;
    if (!s_api.Load())
        return;
    const auto now = s_api.GetTickCount();
    if (now - s_poll < 250)
        return;
    s_poll = now;
    Load();
    constexpr const char *unlocks[] = {
        "NLOTNSOSKK", "OLKMKMTKRO", "LLQQNOO",
        "MNLPOPMMSK", "LSPQSSPSOL", "NQRLNKMTSL"};
    for (unsigned i = 0; i < sizeof(unlocks) / sizeof(*unlocks); ++i)
        if (!(s_unlockMask & (1U << i)))
        {
            auto *dvar = Dvar_FindVarByName(unlocks[i]);
            if (!dvar || dvar->type != 0)
                continue;
            DvarValue value{};
            value.enabled = DW_LocalConfig_UnlockAll();
            Dvar_SetVariant(dvar, &value, 0);
            s_unlockMask |= 1U << i;
        }
    const auto *progression = static_cast<const DWReplayProgressionPrefix *>(func_14105BC30());
    if (!progression)
        return;
    const auto xp = progression->players[0].xp;
    // Native arrays are briefly reset during sign-in/reconciliation. Never
    // erase a saved earned total before its authenticated local restore arrives.
    const auto configuredRank = DW_LocalConfig_Rank();
    const bool changedRank = configuredRank &&
                             (!s_valid || s_record.appliedRank != configuredRank);
    if (changedRank && xp < dwReplayPlayerRankMinimumXp[configuredRank - 1])
        return;
    if (s_valid && (s_record.user != user ||
        (!changedRank && xp < s_record.xp) ||
        (xp == s_record.xp && s_record.appliedRank == configuredRank)))
        return;
    if (!s_valid && !xp && !configuredRank)
        return;
    Save(user, xp);
}
