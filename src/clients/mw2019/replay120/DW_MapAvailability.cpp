#include <stdint.h>
#include <stddef.h>

// Complete same-build StringTable and game-info records. Data stays owned by
// the native fastfile loader; these consumers only change DW map selection.
struct DWReplayStringTable
{
    const char *name;
    int32_t columns, rows, uniqueCount;
    uint32_t reserved;
    const uint16_t *indices;
    const uint32_t *hashes;
    const char *const *strings;
};
static_assert(sizeof(DWReplayStringTable) == 48);
static_assert(offsetof(DWReplayStringTable, indices) == 24);
static_assert(offsetof(DWReplayStringTable, strings) == 40);

struct DWReplayGameTypeInfo
{
    char name[12];
    uint8_t native[160];
};
struct DWReplayMapInfo
{
    char displayName[32], loadName[16], description[32], image[32];
    uint8_t native[96];
    char gameTypes[1024];
    uint32_t supportsAliens, mapPack;
};
struct DWReplayGameInfo
{
    uint32_t gameTypeCount;
    DWReplayGameTypeInfo gameTypes[32];
    uint32_t mapCount;
    DWReplayMapInfo maps[128];
};
static_assert(sizeof(DWReplayGameTypeInfo) == 172);
static_assert(sizeof(DWReplayMapInfo) == 1240);
static_assert(offsetof(DWReplayMapInfo, gameTypes) == 208);
static_assert(offsetof(DWReplayGameInfo, maps) == 5512);

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    unsigned char Com_GameMode_GetActiveGameMode();
    int func_1413E2FE0(const DWReplayStringTable *, int column, const char *value);
    void func_1412B0570(int channel, const char *, ...);
    unsigned UI_GetMapIdForNum(unsigned index);
    DWReplayMapInfo *Com_GameInfo_GetMapInfoForIndex(unsigned index);
    extern DWReplayGameInfo gl_14C4FC330;
    extern const char *gl_145CC7538; // Native registered collision map name.
    extern int gl_145CC7534;        // Native CL_TRANSIENTS_COLLISION_MP mode.
    __declspec(dllimport) unsigned long __stdcall GetFileAttributesW(const wchar_t *);
    __declspec(dllimport) unsigned long __stdcall GetLastError();
}


namespace
{
    bool Equal(const char *left, const char *right)
    {
        if (!left || !right)
            return false;
        for (;; ++left, ++right)
        {
            const auto a = *left >= 'A' && *left <= 'Z' ? *left + 32 : *left;
            const auto b = *right >= 'A' && *right <= 'Z' ? *right + 32 : *right;
            if (a != b)
                return false;
            if (!a)
                return true;
        }
    }
}

// Mode 2 requests the combined <map>_cg_ls_tr package. Replay's Verdansk
// package set supplies numbered collision tiles instead. Use the existing
// mode-1 tile scheduler when the combined file is genuinely absent; keep its
// memory budget, priorities, physics setup and unload lifecycle native.
extern "C" void CL_TransientsCollisionMP_SetTransientMode(int mode)
{
    if (mode == 2 && DW_LocalBackend_IsEnabled() &&
        Equal(gl_145CC7538, "mp_donetsk"))
    {
        const auto combined = GetFileAttributesW(L"zone\\mp_donetsk_cg_ls_tr.ff");
        const auto error = combined == 0xffffffffUL ? GetLastError() : 0UL;
        if (combined == 0xffffffffUL && (error == 2 || error == 3))
        {
            const auto tile = GetFileAttributesW(L"zone\\mp_donetsk_cg_00000_tr.ff");
            if (tile != 0xffffffffUL && !(tile & 0x10UL))
            {
                mode = 1;
                func_1412B0570(16, "[DW] Verdansk collision: numbered transient tiles; combined cg_ls_tr package absent\n");
            }
        }
    }
    gl_145CC7534 = mode;
}


// Original lookup searches from the last row and uses the exact native hash
// and case-insensitive comparator. Reuse that row selector for all tables.
extern "C" const char *func_1413E2BA0(const DWReplayStringTable *table,
                                     int column, const char *value, int resultColumn)
{
    if (!table)
    {
        func_1412B0570(13, "Unable to find the lookup table in the fastfile, aborting lookup\n");
        return "";
    }
    if (!table->columns || column < 0 || resultColumn < 0 || resultColumn >= table->columns)
        return "";
    const auto row = func_1413E2FE0(table, column, value);
    if (row < 0 || row >= table->rows)
        return "";
    const auto cell = table->indices[row * table->columns + resultColumn];
    if (cell >= table->uniqueCount)
        return "";
    if (DW_LocalBackend_IsEnabled() && column == 0 && resultColumn == 28 &&
        Equal(table->name, "mp/mapInfo.csv") && Equal(value, "mp_donetsk"))
        return "0"; // Native PRIVATE_MATCH.MapSupportsCustomGames uses this column.
    return table->strings[cell];
}

extern "C" const char *func_141B9D400(unsigned index)
{
    const auto mapIndex = UI_GetMapIdForNum(index);
    const auto *map = Com_GameInfo_GetMapInfoForIndex(mapIndex);
    if (!DW_LocalBackend_IsEnabled() || Com_GameMode_GetActiveGameMode() != 2 ||
        !Equal(map->loadName, "mp_donetsk"))
        return map->gameTypes;

    // The same MP selector is used by local and online custom games. Offer
    // only game types that this native game-info publication actually loaded.
    // Copy no server/weapon rules or map assets, and keep BR arena rules intact.
    static char supported[1024];
    unsigned used = 0;
    const auto count = gl_14C4FC330.gameTypeCount;
    if (count > 32)
        return map->gameTypes;
    for (unsigned i = 0; i < count; ++i)
    {
        const auto *name = gl_14C4FC330.gameTypes[i].name;
        unsigned length = 0;
        while (length < sizeof(gl_14C4FC330.gameTypes[i].name) && name[length])
            ++length;
        if (!length || length == sizeof(gl_14C4FC330.gameTypes[i].name))
            continue;
        if (used && used + 1 < sizeof(supported))
            supported[used++] = ' ';
        for (unsigned j = 0; j < length && used + 1 < sizeof(supported); ++j)
            supported[used++] = name[j];
    }
    supported[used] = 0;
    return used ? supported : map->gameTypes;
}
