#pragma once
#include <cstddef>
#include <cstdint>

namespace iw8_addresses
{
    enum class Build
    {
        Unknown,
        IW8_Beta_2019,
        MW2019_1_69,
        MW2019_1_67_LegacyDisabled,
        MW2019_1_44
    };

    struct Fingerprint
    {
        const char* label;
        std::uint32_t timestamp;
        std::uint32_t imageSize;
        std::uint32_t entryPointRva;
        std::uintptr_t preferredImageBase;
    };

    // Exact fingerprint supplied from the user's beta-era ModernWarfare.exe.
    // PE timestamp decodes to 2019-09-19 23:47:24 UTC. Keep this profile
    // isolated from every retail/1.44 address table until beta-specific
    // targets are recovered and validated.
    inline constexpr Fingerprint IW8_Beta_2019
    {
        "IW8 Beta 2019 / Warzone-beta folder (2019-09-19)",
        0x5D84138C,
        0x16801800,
        0x02752D50,
        0x140000000ull
    };

    inline constexpr const char* IW8_Beta_2019_SHA256 =
        "b20e9badf003385338308043ecefefcb40e8502078032f1f808ea93c809404ac";

    inline constexpr Fingerprint MW2019_1_69
    {
        "MW2019 Steam 1.69 (1.69.0.26668155)",
        0x69DD404E,
        0x21679200,
        0x06E4931C,
        0x140000000ull
    };

    // The former 1.67 full-client implementation is intentionally retained in
    // games/iw8/full_client, but it is no longer selected by the current Steam
    // fingerprint. Do not invent an old 1.67 fingerprint here.
    inline constexpr bool EnableLegacySteam167 = false;

    // Validated MW2019 1.44 build used by the existing compatibility profile.
    // The earlier beta-profile merge accidentally replaced this with the old
    // all-zero placeholder.  Timestamp and image size are confirmed from the
    // working 1.44 logs.  entryPointRva remains zero intentionally so older
    // project snapshots that did not preserve that one PE field can still be
    // matched by the guarded 1.44 detector.
    inline constexpr Fingerprint MW2019_1_44
    {
        "MW2019 1.44.0.10435696",
        0x61671CE8,
        0x22C1BA00,
        0,
        0x140000000ull
    };
}

#include "1.44addressess.h"

namespace iw8_addresses
{
    // Additional address catalog imported from the supplied IW8 client source.
    // That source explicitly labels this table IW8_157. It is reference-only until fingerprinted.
    struct Reference157Rvas
    {
        std::uintptr_t CL_GetLocalClientSignInState = 0x3D35090;
        std::uintptr_t unk_SignInState = 0x1A799570;
        std::uintptr_t Dvar_RegisterBool_call_1 = 0x340828F;
        std::uintptr_t Dvar_RegisterBool_call_2 = 0x34082AA;
        std::uintptr_t GamerProfile_SetDataByName = 0x42D81A0;
        std::uintptr_t holdrand = 0x9DD41E8;
        std::uintptr_t Dvar_FindVarByName = 0x39CA9E0;
        std::uintptr_t LUI_OpenMenu = 0x6774040;
        std::uintptr_t LUI_CoD_LuaCall_IsConnectedToGameServer = 0x634F870;
        std::uintptr_t LUI_CoD_LuaCall_IsGameModeAllowed = 0x6350720;
        std::uintptr_t LUI_CoD_LuaCall_IsGameModeAvailable = 0x6350820;
        std::uintptr_t LUI_COD_LuaCall_IsPremiumPlayerReady = 0x6358E80;
        std::uintptr_t LuaShared_LuaCall_IsDemoBuild = 0x62976B0;
        std::uintptr_t xpartydisband = 0x6FD7288;
        std::uintptr_t GScr_EndLobby = 0x32D2370;
        std::uintptr_t dvar_force_offline_enabled = 0x1BD588C8;
        std::uintptr_t dvar_force_offline_menus = 0x1BD588D0;
        std::uintptr_t Com_RegisterCommonDvars = 0x3407480;
        std::uintptr_t SEH_StringEd_GetString = 0x3987BA0;
        std::uintptr_t Live_UserSignIn = 0x3A0E770;
        std::uintptr_t OnlineErrorManager_GetFenceState = 0x469CC40;
        std::uintptr_t OnlineErrorManager_IsMpNotAllowed = 0x4682C70;
        std::uintptr_t Platform_BeginAuth = 0x4685DA0;
        std::uintptr_t Live_FakeUserSignIn = 0x70A6F0;
        std::uintptr_t platformConnectionState = 0x1DDACC80;
        std::uintptr_t platformId = 0x1DDAC920;
        std::uintptr_t accountLoggedIn = 0x1DDAC382;
        std::uintptr_t dvar_xblive_loggedin = 0x1D9A2458;
        std::uintptr_t unk_PlatformPatch_flag1 = 0x1DDACB30;
        std::uintptr_t dvar_r_hudOutlineVRScopeThermalDarkColorFriend = 0x1F21E808;
        std::uintptr_t CurrentRegion_IssueFix1 = 0x4683ADE;
        std::uintptr_t CurrentRegion_IssueFix2 = 0x468355E;
        std::uintptr_t CurrentRegion_IssueFix2_flag = 0x1DDAC382;
        std::uintptr_t unk_BNetClass = 0x1DDAC860;
        std::uintptr_t s_isContentEnumerationFinished = 0x1D607400;
        std::uintptr_t unk_XUIDCheck1 = 0x21A40DE8;
        std::uintptr_t GamerProfile_IsProfileLoggedIn = 0x42C4460;
        std::uintptr_t Content_DoWeHaveContentPack = 0x39C4FC0;
        std::uintptr_t GetUsername = 0x3A0DB70;
        std::uintptr_t s_OnlineServicesFenceData_state = 0x1B443E18;
        std::uintptr_t dwGetLogOnStatus = 0x5E04330;
        std::uintptr_t dwLogOnHSM_base_HSM_IsInState = 0x28BB3C0;
        std::uintptr_t Live_IsSignedIn = 0x46866D0;
        std::uintptr_t Live_IsUserSignedIn = 0x3A0E0C0;
        std::uintptr_t Live_IsUserSignedInToDemonware = 0x3D77CA0;
        std::uintptr_t Live_IsUserSignedInToBnet = 0x2E19E30;
        std::uintptr_t Live_IsUserSignedInToLive = 0x3A0E0E0;
        std::uintptr_t Live_OnlineServicesFence_GetState = 0x2CE7B30;
        std::uintptr_t Live_SyncOnlineDataFence_GetState = 0x2CE8C40;
        std::uintptr_t j_LUI_CoD_LuaCall_ShouldBeInOnlineArea = 0x63A6780;
        std::uintptr_t LUI_CoD_LuaCall_IsUserSignedInToDemonware = 0x6350760;
        std::uintptr_t LUI_CoD_LuaCall_IsBattleNetAuthReady = 0x6368620;
        std::uintptr_t LUI_COD_LuaCall_IsBattleNetLanOnly = 0x6358B40;
        std::uintptr_t LUI_COD_LuaCall_IsBattleNet = 0x6358820;
        std::uintptr_t LUI_CoD_LuaCall_StatsResetGetState = 0x6516260;
        std::uintptr_t LUI_COD_LuaCall_IsPremiumPlayer = 0x6358C60;
        std::uintptr_t LUI_CoD_LuaCall_OfflineDataFetched = 0x6516150;
        std::uintptr_t LUI_CoD_LuaCall_IsLocalPlayAllowed = 0x6362880;
        std::uintptr_t LUI_CoD_LuaCall_IsUserSignedInToLive = 0x6350660;
        std::uintptr_t LUI_ReportError = 0x62B0DF0;
        std::uintptr_t lua_pushboolean = 0x6C2F980;
        std::uintptr_t lua_tolstring = 0x6C30450;
        std::uintptr_t LUI_LuaCall_LUIGlobalPackage_DebugPrint = 0x62AD8E0;
        std::uintptr_t Sys_Microseconds = 0x3B053D0;
        std::uintptr_t I_irand = 0x39BDF30;
        std::uintptr_t GetRandSeed = 0x39BDCB0;
        std::uintptr_t Dvar_SetBool_Internal = 0x39D26E0;
        std::uintptr_t R_EndFrame = 0x6125DC0;
        std::uintptr_t Dvar_RegisterBool = 0x39D03C0;
        std::uintptr_t DDL_Lookup_MoveToNameHash = 0x6BFA8F0;
        std::uintptr_t LUIMethod_LUIGlobalPackage_list = 0x205DA330;
        std::uintptr_t LUI_COD_LuaCall_HasActiveLocalClient = 0x635A470;
        std::uintptr_t LUI_CoD_LuaCall_GetBattleNetConnectionState = 0x6365150;
        std::uintptr_t LuaShared_LuaCall_IsDevelopmentBuild = 0x6297670;
        std::uintptr_t LuaShared_LuaCall_IsConsoleGame = 0x62976F0;
        std::uintptr_t lua_pushnumber = 0x6C2FC00;
        std::uintptr_t lua_pushinteger = 0x6C2FAE0;
        std::uintptr_t file_fopen = 0x6E095BC;
        std::uintptr_t file_fclose = 0x6E099FC;
        std::uintptr_t luaL_loadbuffer = 0x6C35890;
        std::uintptr_t unk_EncryptionKey = 0x205DA370;
        std::uintptr_t luaL_openlib = 0x6C33A10;
        std::uintptr_t LiveStorage_GetActiveStatsSource = 0x3391390;
        std::uintptr_t DB_FindXAssetHeader = 0x31EB8C0;
        std::uintptr_t xenonUserData_m_guardedUserData_signinState = 0x1DDAC860;
        std::uintptr_t DB_LoadXFile = 0x31E88B0;
        std::uintptr_t Live_IsInSystemlinkLobby = 0x3D77130;
        std::uintptr_t GamerProfile_LogInProfile = 0x42C46C0;
        std::uintptr_t LoadSavedAchievements = 0x21048A0;
        std::uintptr_t controllerStatData = 0x1BCADC64;
        std::uintptr_t LiveStorage_StatsInit = 0x3393620;
        std::uintptr_t Live_GetUserData = 0x2B405C0;
        std::uintptr_t luaL_loadfile = 0x6C35A20;
        std::uintptr_t CL_Mgr_IsControllerActive = 0x2793D20;
        std::uintptr_t CL_Mgr_GetClientFromController = 0x2793B90;
        std::uintptr_t Com_DDL_LoadAsset = 0x6BF8080;
        std::uintptr_t LiveStorage_GetPlayerDataBufferForSource = 0x3393550;
        std::uintptr_t LiveStorage_DoWeHaveStatsForSource = 0x3390BF0;
        std::uintptr_t LiveStorage_BeginGame = 0x3397D40;
        std::uintptr_t LiveStorage_ReadStats = 0x3391150;
        std::uintptr_t Load_ScriptFile = 0x29380B0;
        std::uintptr_t DB_PatchMem_PushAsset = 0x28B67D0;
        std::uintptr_t Load_Stream = 0x31F4200;
        std::uintptr_t DB_PushStreamPos = 0x31F3DF0;
        std::uintptr_t Load_XString = 0x29097C0;
        std::uintptr_t DB_PopStreamPos = 0x31F3D40;
        std::uintptr_t DB_PatchMem_PopAsset = 0x28B65A0;
        std::uintptr_t DB_ReadXFile = 0x31E96F0;
        std::uintptr_t Load_ConstCharArray = 0x2907650;
        std::uintptr_t Load_byteArray = 0x2909C00;
        std::uintptr_t varScriptFile = 0xB607A40;
        std::uintptr_t varXString = 0xB606240;
        std::uintptr_t varConstChar = 0xB606230;
        std::uintptr_t varbyte = 0xB606060;
        std::uintptr_t AllocLoad_ConstChar = 0x29056E0;
        std::uintptr_t AllocLoad_byte = 0x29059E0;
        std::uintptr_t g_streamPosGlob_pos = 0x1BB11F20;
    };

    inline constexpr Reference157Rvas MW2019_1_57_Reference{};

    struct ImportedNamedRva
    {
        const char* name;
        std::uintptr_t rva;
    };

    inline constexpr ImportedNamedRva MW2019_1_138_Source[] =
    {
        { "LUI_CoD_LuaCall_OfflineDataFetched", 0x05404F20ull },
        { "LUI_COD_LuaCall_IsPremiumPlayer", 0x05288040ull },
        { "LUI_CoD_LuaCall_IsLocalPlayAllowed", 0x0527CD60ull },
        { "LUI_ReportError", 0x05214770ull },
        { "lua_pushboolean", 0x05B570B0ull },
        { "lua_tolstring", 0x05B57B80ull },
        { "LUI_LuaCall_LUIGlobalPackage_DebugPrint", 0x05211390ull },
        { "I_irand", 0x02D4E5D0ull },
        { "GetRandSeed", 0x02D4E350ull },
        { "Sys_Microseconds", 0x02E67190ull },
        { "Live_IsSignedIn", 0x037B9AD0ull },
        { "Live_IsInSystemlinkLobby", 0x03072FB0ull },
        { "R_EndFrame", 0x05098750ull },
        { "Dvar_RegisterBool", 0x02D5F460ull },
        { "DDL_Lookup_MoveToNameHash", 0x05B24A70ull },
        { "Live_GetUserData", 0x16AB3334ull },
        { "GamerProfile_LogInProfile", 0x034380B0ull },
        { "LoadSavedAchievements", 0x01A23510ull },
        { "LiveStorage_DoWeHaveStatsForSource", 0x02A129C0ull },
        { "xenonUserData_m_guardedUserData_signinState", 0x08B6F480ull },
        { "CurrentRegion_IssueFix1", 0x037B07DEull },
        { "CurrentRegion_IssueFix2", 0x037B02BEull },
        { "controllerStatData", 0x1526B764ull },
        { "LiveStorage_StatsInit", 0x02A15620ull },
        { "Content_DoWeHaveContentPack", 0x02D557D0ull },
        { "unk_PlatformPatch_flag1", 0x08B6F750ull },
        { "unk_XUIDCheck1", 0x1A9D1E78ull },
        { "CurrentRegion_IssueFix2_flag", 0x16EBA682ull },
        { "s_isContentEnumerationFinished", 0x1673F600ull },
        { "dvar_r_hudOutlineVRScopeThermalDarkColorFriend", 0x1828E9C0ull },
        { "LiveStorage_ReadStats", 0x02A12F60ull },
    };

    inline constexpr std::size_t MW2019_1_138_SourceCount = sizeof(MW2019_1_138_Source) / sizeof(MW2019_1_138_Source[0]);

    inline constexpr ImportedNamedRva MW2019_1_157_Source[] =
    {
        { "CL_GetLocalClientSignInState", 0x03D35090ull },
        { "unk_SignInState", 0x1A799570ull },
        { "Dvar_RegisterBool_call_1", 0x0340828Full },
        { "Dvar_RegisterBool_call_2", 0x034082AAull },
        { "GamerProfile_SetDataByName", 0x042D81A0ull },
        { "holdrand", 0x09DD41E8ull },
        { "Dvar_FindVarByName", 0x039CA9E0ull },
        { "LUI_OpenMenu", 0x06774040ull },
        { "LUI_CoD_LuaCall_IsConnectedToGameServer", 0x0634F870ull },
        { "LUI_CoD_LuaCall_IsGameModeAllowed", 0x06350720ull },
        { "LUI_CoD_LuaCall_IsGameModeAvailable", 0x06350820ull },
        { "LUI_COD_LuaCall_IsPremiumPlayerReady", 0x06358E80ull },
        { "LuaShared_LuaCall_IsDemoBuild", 0x062976B0ull },
        { "xpartydisband", 0x06FD7288ull },
        { "GScr_EndLobby", 0x032D2370ull },
        { "dvar_force_offline_enabled", 0x1BD588C8ull },
        { "dvar_force_offline_menus", 0x1BD588D0ull },
        { "Com_RegisterCommonDvars", 0x03407480ull },
        { "SEH_StringEd_GetString", 0x03987BA0ull },
        { "Live_UserSignIn", 0x03A0E770ull },
        { "OnlineErrorManager_GetFenceState", 0x0469CC40ull },
        { "OnlineErrorManager_IsMpNotAllowed", 0x04682C70ull },
        { "Platform_BeginAuth", 0x04685DA0ull },
        { "Live_FakeUserSignIn", 0x0070A6F0ull },
        { "platformConnectionState", 0x1DDACC80ull },
        { "platformId", 0x1DDAC920ull },
        { "accountLoggedIn", 0x1DDAC382ull },
        { "dvar_xblive_loggedin", 0x1D9A2458ull },
        { "unk_PlatformPatch_flag1", 0x1DDACB30ull },
        { "dvar_r_hudOutlineVRScopeThermalDarkColorFriend", 0x1F21E808ull },
        { "CurrentRegion_IssueFix1", 0x04683ADEull },
        { "CurrentRegion_IssueFix2", 0x0468355Eull },
        { "CurrentRegion_IssueFix2_flag", 0x1DDAC382ull },
        { "unk_BNetClass", 0x1DDAC860ull },
        { "s_isContentEnumerationFinished", 0x1D607400ull },
        { "unk_XUIDCheck1", 0x21A40DE8ull },
        { "GamerProfile_IsProfileLoggedIn", 0x042C4460ull },
        { "Content_DoWeHaveContentPack", 0x039C4FC0ull },
        { "GetUsername", 0x03A0DB70ull },
        { "s_OnlineServicesFenceData_state", 0x1B443E18ull },
        { "dwGetLogOnStatus", 0x05E04330ull },
        { "dwLogOnHSM_base_HSM_IsInState", 0x028BB3C0ull },
        { "Live_IsSignedIn", 0x046866D0ull },
        { "Live_IsUserSignedIn", 0x03A0E0C0ull },
        { "Live_IsUserSignedInToDemonware", 0x03D77CA0ull },
        { "Live_IsUserSignedInToBnet", 0x02E19E30ull },
        { "Live_IsUserSignedInToLive", 0x03A0E0E0ull },
        { "Live_OnlineServicesFence_GetState", 0x02CE7B30ull },
        { "Live_SyncOnlineDataFence_GetState", 0x02CE8C40ull },
        { "j_LUI_CoD_LuaCall_ShouldBeInOnlineArea", 0x063A6780ull },
        { "LUI_CoD_LuaCall_IsUserSignedInToDemonware", 0x06350760ull },
        { "LUI_CoD_LuaCall_IsBattleNetAuthReady", 0x06368620ull },
        { "LUI_COD_LuaCall_IsBattleNetLanOnly", 0x06358B40ull },
        { "LUI_COD_LuaCall_IsBattleNet", 0x06358820ull },
        { "LUI_CoD_LuaCall_StatsResetGetState", 0x06516260ull },
        { "LUI_COD_LuaCall_IsPremiumPlayer", 0x06358C60ull },
        { "LUI_CoD_LuaCall_OfflineDataFetched", 0x06516150ull },
        { "LUI_CoD_LuaCall_IsLocalPlayAllowed", 0x06362880ull },
        { "LUI_CoD_LuaCall_IsUserSignedInToLive", 0x06350660ull },
        { "LUI_ReportError", 0x062B0DF0ull },
        { "lua_pushboolean", 0x06C2F980ull },
        { "lua_tolstring", 0x06C30450ull },
        { "LUI_LuaCall_LUIGlobalPackage_DebugPrint", 0x062AD8E0ull },
        { "Sys_Microseconds", 0x03B053D0ull },
        { "I_irand", 0x039BDF30ull },
        { "GetRandSeed", 0x039BDCB0ull },
        { "Dvar_SetBool_Internal", 0x039D26E0ull },
        { "R_EndFrame", 0x06125DC0ull },
        { "Dvar_RegisterBool", 0x039D03C0ull },
        { "DDL_Lookup_MoveToNameHash", 0x06BFA8F0ull },
        { "LUIMethod_LUIGlobalPackage_list", 0x205DA330ull },
        { "LUI_COD_LuaCall_HasActiveLocalClient", 0x0635A470ull },
        { "LUI_CoD_LuaCall_GetBattleNetConnectionState", 0x06365150ull },
        { "LuaShared_LuaCall_IsDevelopmentBuild", 0x06297670ull },
        { "LuaShared_LuaCall_IsConsoleGame", 0x062976F0ull },
        { "lua_pushnumber", 0x06C2FC00ull },
        { "lua_pushinteger", 0x06C2FAE0ull },
        { "file_fopen", 0x06E095BCull },
        { "file_fclose", 0x06E099FCull },
        { "luaL_loadbuffer", 0x06C35890ull },
        { "unk_EncryptionKey", 0x205DA370ull },
        { "luaL_openlib", 0x06C33A10ull },
        { "LiveStorage_GetActiveStatsSource", 0x03391390ull },
        { "DB_FindXAssetHeader", 0x031EB8C0ull },
        { "xenonUserData_m_guardedUserData_signinState", 0x1DDAC860ull },
        { "DB_LoadXFile", 0x031E88B0ull },
        { "Live_IsInSystemlinkLobby", 0x03D77130ull },
        { "GamerProfile_LogInProfile", 0x042C46C0ull },
        { "LoadSavedAchievements", 0x021048A0ull },
        { "controllerStatData", 0x1BCADC64ull },
        { "LiveStorage_StatsInit", 0x03393620ull },
        { "Live_GetUserData", 0x02B405C0ull },
        { "luaL_loadfile", 0x06C35A20ull },
        { "CL_Mgr_IsControllerActive", 0x02793D20ull },
        { "CL_Mgr_GetClientFromController", 0x02793B90ull },
        { "Com_DDL_LoadAsset", 0x06BF8080ull },
        { "LiveStorage_GetPlayerDataBufferForSource", 0x03393550ull },
        { "LiveStorage_DoWeHaveStatsForSource", 0x03390BF0ull },
        { "LiveStorage_BeginGame", 0x03397D40ull },
        { "LiveStorage_ReadStats", 0x03391150ull },
        { "Load_ScriptFile", 0x029380B0ull },
        { "DB_PatchMem_PushAsset", 0x028B67D0ull },
        { "Load_Stream", 0x031F4200ull },
        { "DB_PushStreamPos", 0x031F3DF0ull },
        { "Load_XString", 0x029097C0ull },
        { "DB_PopStreamPos", 0x031F3D40ull },
        { "DB_PatchMem_PopAsset", 0x028B65A0ull },
        { "DB_ReadXFile", 0x031E96F0ull },
        { "Load_ConstCharArray", 0x02907650ull },
        { "Load_byteArray", 0x02909C00ull },
        { "varScriptFile", 0x0B607A40ull },
        { "varXString", 0x0B606240ull },
        { "varConstChar", 0x0B606230ull },
        { "varbyte", 0x0B606060ull },
        { "AllocLoad_ConstChar", 0x029056E0ull },
        { "AllocLoad_byte", 0x029059E0ull },
        { "g_streamPosGlob_pos", 0x1BB11F20ull },
    };

    inline constexpr std::size_t MW2019_1_157_SourceCount = sizeof(MW2019_1_157_Source) / sizeof(MW2019_1_157_Source[0]);

    inline constexpr ImportedNamedRva MW2019_1_167_Source[] =
    {
        { "CL_GetLocalClientSignInState", 0x2DBA5090ull },
        { "unk_SignInState", 0x44609570ull },
        { "Dvar_RegisterBool_call_1", 0x2D27828Full },
        { "Dvar_RegisterBool_call_2", 0x2D2782AAull },
        { "GamerProfile_SetDataByName", 0x2E1481A0ull },
        { "holdrand", 0x33C441E8ull },
        { "Dvar_FindVarByName", 0x2D83A9E0ull },
        { "LUI_OpenMenu", 0x305E4040ull },
        { "LUI_CoD_LuaCall_IsConnectedToGameServer", 0x301BF870ull },
        { "LUI_CoD_LuaCall_IsGameModeAllowed", 0x301C0720ull },
        { "LUI_CoD_LuaCall_IsGameModeAvailable", 0x301C0820ull },
        { "LUI_COD_LuaCall_IsPremiumPlayerReady", 0x301C8E80ull },
        { "LuaShared_LuaCall_IsDemoBuild", 0x301076B0ull },
        { "xpartydisband", 0x30E47288ull },
        { "GScr_EndLobby", 0x2D142370ull },
        { "dvar_force_offline_enabled", 0x45BC88C8ull },
        { "dvar_force_offline_menus", 0x45BC88D0ull },
        { "Com_RegisterCommonDvars", 0x2D277480ull },
        { "SEH_StringEd_GetString", 0x2D7F7BA0ull },
        { "CurrentRegion_IssueFix1", 0x2E4F3ADEull },
        { "unk_BNetClass", 0x47C1C860ull },
        { "GamerProfile_IsProfileLoggedIn", 0x2E134460ull },
        { "GetUsername", 0x2D87DB70ull },
        { "s_OnlineServicesFenceData_state", 0x452B3E18ull },
        { "dwGetLogOnStatus", 0x2FC74330ull },
        { "dwLogOnHSM_base_HSM_IsInState", 0x2C72B3C0ull },
        { "Live_IsUserSignedIn", 0x2D87E0C0ull },
        { "Live_IsUserSignedInToDemonware", 0x2DBE7CA0ull },
        { "Live_IsUserSignedInToBnet", 0x2CC89E30ull },
        { "Live_IsUserSignedInToLive", 0x2D87E0E0ull },
        { "Live_OnlineServicesFence_GetState", 0x2CB57B30ull },
        { "Live_SyncOnlineDataFence_GetState", 0x2CB58C40ull },
        { "j_LUI_CoD_LuaCall_ShouldBeInOnlineArea", 0x30216780ull },
        { "LUI_CoD_LuaCall_IsUserSignedInToDemonware", 0x301C0760ull },
        { "LUI_CoD_LuaCall_IsBattleNetAuthReady", 0x301D8620ull },
        { "LUI_COD_LuaCall_IsBattleNetLanOnly", 0x301C8B40ull },
        { "LUI_COD_LuaCall_IsBattleNet", 0x301C8820ull },
        { "LUI_CoD_LuaCall_StatsResetGetState", 0x30386260ull },
        { "LUI_CoD_LuaCall_IsUserSignedInToLive", 0x301C0660ull },
        { "LUI_ReportError", 0x30120DF0ull },
        { "lua_tolstring", 0x30AA0450ull },
        { "LUI_LuaCall_LUIGlobalPackage_DebugPrint", 0x3011D8E0ull },
        { "Dvar_SetBool_Internal", 0x2D8426E0ull },
        { "DDL_Lookup_MoveToNameHash", 0x30A6A8F0ull },
        { "LUIMethod_LUIGlobalPackage_list", 0x4A44A330ull },
        { "LUI_COD_LuaCall_HasActiveLocalClient", 0x301CA470ull },
        { "LUI_CoD_LuaCall_GetBattleNetConnectionState", 0x301D5150ull },
        { "LuaShared_LuaCall_IsDevelopmentBuild", 0x30107670ull },
        { "LuaShared_LuaCall_IsConsoleGame", 0x301076F0ull },
        { "lua_pushnumber", 0x30A9FC00ull },
        { "lua_pushinteger", 0x30A9FAE0ull },
        { "file_fopen", 0x30C795BCull },
        { "file_fclose", 0x30C799FCull },
        { "luaL_loadbuffer", 0x30AA5890ull },
        { "unk_EncryptionKey", 0x4A44A370ull },
        { "luaL_openlib", 0x30AA3A10ull },
        { "LiveStorage_GetActiveStatsSource", 0x2D201390ull },
        { "DB_FindXAssetHeader", 0x2D05B8C0ull },
        { "DB_LoadXFile", 0x2D0588B0ull },
        { "luaL_loadfile", 0x30AA5A20ull },
        { "CL_Mgr_IsControllerActive", 0x2C603D20ull },
        { "CL_Mgr_GetClientFromController", 0x2C603B90ull },
        { "Com_DDL_LoadAsset", 0x30A68080ull },
        { "LiveStorage_GetPlayerDataBufferForSource", 0x2D203550ull },
        { "LiveStorage_BeginGame", 0x2D207D40ull },
        { "Load_ScriptFile", 0x2C7A80B0ull },
        { "DB_PatchMem_PushAsset", 0x2C7267D0ull },
        { "Load_Stream", 0x2D064200ull },
        { "DB_PushStreamPos", 0x2D063DF0ull },
        { "Load_XString", 0x2C7797C0ull },
        { "DB_PopStreamPos", 0x2D063D40ull },
        { "DB_PatchMem_PopAsset", 0x2C7265A0ull },
        { "DB_ReadXFile", 0x2D0596F0ull },
        { "Load_ConstCharArray", 0x2C777650ull },
        { "Load_byteArray", 0x2C779C00ull },
        { "varScriptFile", 0x35477A40ull },
        { "varXString", 0x35476240ull },
        { "varConstChar", 0x35476230ull },
        { "varbyte", 0x35476060ull },
        { "AllocLoad_ConstChar", 0x2C7756E0ull },
        { "AllocLoad_byte", 0x2C7759E0ull },
        { "g_streamPosGlob_pos", 0x45981F20ull },
    };

    inline constexpr std::size_t MW2019_1_167_SourceCount = sizeof(MW2019_1_167_Source) / sizeof(MW2019_1_167_Source[0]);

    inline constexpr const Fingerprint& FingerprintFor(Build build)
    {
        if (build == Build::IW8_Beta_2019)
            return IW8_Beta_2019;
        if (build == Build::MW2019_1_44)
            return MW2019_1_44;
        return MW2019_1_69;
    }
}
