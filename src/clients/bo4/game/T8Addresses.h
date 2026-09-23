#pragma once
#include <cstddef>
#include <cstdint>

namespace t8_addresses
{
    enum class Build
    {
        Unknown,
        LatestBnet,
        MultiplayerBetaAug2018,
        BlackoutBetaSep2018
    };

    struct Fingerprint
    {
        const char* label;
        std::uint32_t timestamp;
        std::uint32_t imageSize;
        std::uint32_t entryPointRva;
        std::uintptr_t preferredImageBase;
        std::uintptr_t buildMarkerRva;
        std::uint32_t expectedBuildMarker;
    };

    struct CoreRvas
    {
        std::uintptr_t Dvar_FindVar;
        std::uintptr_t Cbuf_AddText;
        std::uintptr_t Cbuf_ExecuteBuffer;
        std::uintptr_t Cmd_ExecuteSingleCommand;
        std::uintptr_t Com_LocalClients_GetPrimary;
        std::uintptr_t Com_GetBuildVersion;
        std::uintptr_t Com_IsInGame;
        std::uintptr_t Com_SessionMode_GetMode;
        std::uintptr_t Lua_CoD_LoadLuaFile;
        std::uintptr_t Lua_CoD_LuaStateManager_Error;
        std::uintptr_t hks_obj_tolstring;
        std::uintptr_t hks_obj_tonumber;
        std::uintptr_t R_AddCmdDrawStretchPic;
        std::uintptr_t T8_AddBaseDrawTextCmd;
        std::uintptr_t BNet_GetUsername;
        std::uintptr_t BNet_GetUserId;
    };

    struct NamedRva
    {
        const char* name;
        std::uintptr_t rva;
        const char* category;
    };

    struct RetailPreferredMapEntry
    {
        std::uintptr_t retailPreferredVa;
        std::uintptr_t buildRva;
        const char* name;
    };

    inline constexpr std::uintptr_t PreferredImageBase = 0x140000000ull;

    // Shield verifies this exact integer in the latest Battle.net executable:
    // "BlackOps4 CL(13869365) ... Wed Feb 22 2023".
    inline constexpr Fingerprint LatestBnet
    {
        "T8 Black Ops 4 latest Battle.net / Shield source build",
        0,
        0,
        0,
        PreferredImageBase,
        0x049CA7E8ull,
        13869365u
    };


    inline constexpr Fingerprint MultiplayerBetaAug2018
    {
        "T8 Black Ops 4 Multiplayer Beta / Aug 2018",
        0x5B6CB2BBu,
        0x105D1C00u,
        0x01C97AD0u,
        PreferredImageBase,
        0x01F004D8ull,
        0x002EB289u
    };

    inline constexpr Fingerprint BlackoutBetaSep2018
    {
        "T8 Black Ops 4 Blackout Beta / Sep 2018",
        0x5B9999E4u,
        0x121A0A00u,
        0x036828A0u,
        PreferredImageBase,
        0,
        0
    };

    // The retail project is the canonical implementation. Beta address tables
    // intentionally begin sparse and are filled as matching functions are
    // recovered from each executable. Zero means "not mapped for this build".
    inline constexpr CoreRvas MultiplayerBetaCore{};
    inline constexpr CoreRvas BlackoutBetaCore{};
    inline constexpr CoreRvas Core
    {
        0x03CEBE40ull,
        0x03CDE880ull,
        0x03CDEBE0ull,
        0x03CDF490ull,
        0x02893AF0ull,
        0x02892F40ull,
        0x0288FDB0ull,
        0x0289EFF0ull,
        0x03962DF0ull,
        0x0398A860ull,
        0x03755730ull,
        0x03755A90ull,
        0x03616790ull,
        0x03616B60ull,
        0x02325C70ull,
        0x02325CA0ull
    };

    inline constexpr NamedRva Imported[] =
    {
        { "BuildMarker_CL", 0x049CA7E8ull, "build" },
        { "CScr_GetFunction", 0x01F13140ull, "game" },
        { "CScr_GetMethod", 0x01F13650ull, "game" },
        { "Cbuf_AddServerText_f", 0x03CDE870ull, "game" },
        { "Cbuf_AddText", 0x03CDE880ull, "game" },
        { "Cbuf_ExecuteBuffer", 0x03CDEBE0ull, "game" },
        { "Cmd_AddCommandInternal", 0x03CDEE80ull, "game" },
        { "Cmd_AddServerCommandInternal", 0x03CDEEF0ull, "game" },
        { "Cmd_EndTokenizedString", 0x03CDF070ull, "game" },
        { "Cmd_ExecuteSingleCommand", 0x03CDF490ull, "game" },
        { "Cmd_TokenizeStringKernel", 0x03CE0750ull, "game" },
        { "Com_Error_", 0x0288B410ull, "game" },
        { "Com_GetBuildVersion", 0x02892F40ull, "game" },
        { "Com_IsInGame", 0x0288FDB0ull, "game" },
        { "Com_IsRunningUILevel", 0x0288FDF0ull, "game" },
        { "Com_LocalClients_GetPrimary", 0x02893AF0ull, "game" },
        { "Com_SessionMode_GetAbbreviationForMode", 0x0289EC70ull, "game" },
        { "Com_SessionMode_GetMode", 0x0289EFF0ull, "game" },
        { "Com_SessionMode_GetModeForAbbreviation", 0x0289F000ull, "game" },
        { "Dvar_FindVar", 0x03CEBE40ull, "game" },
        { "Dvar_FindVar_Hash", 0x03CEBED0ull, "game" },
        { "Live_GetConnectivityInformation", 0x037FA460ull, "game" },
        { "Live_SystemInfo", 0x03804B00ull, "game" },
        { "Lua_CoD_LoadLuaFile", 0x03962DF0ull, "game" },
        { "Lua_CoD_LuaStateManager_Error", 0x0398A860ull, "game" },
        { "NET_OutOfBandData", 0x02E06390ull, "game" },
        { "NetAdr_InitFromString", 0x02E05230ull, "game" },
        { "NetAdr_IsTheSameAddr", 0x02E053A0ull, "game" },
        { "R_AddCmdDrawStretchPic", 0x03616790ull, "game" },
        { "R_TextHeight", 0x035B2350ull, "game" },
        { "R_TextWidth", 0x035B2530ull, "game" },
        { "SV_Cmd_EndTokenizedString", 0x03CE09C0ull, "game" },
        { "SV_Cmd_TokenizeString", 0x03CE0A10ull, "game" },
        { "ScopedCriticalSectionConstructor", 0x0289E3C0ull, "game" },
        { "ScopedCriticalSectionDestructor", 0x0289E440ull, "game" },
        { "ScrPlace_GetView", 0x02876E70ull, "game" },
        { "ScrStr_ConvertToString", 0x02759030ull, "game" },
        { "ScrVar_NewVariableByIndex", 0x02760440ull, "game" },
        { "ScrVar_PushArray", 0x02775CF0ull, "game" },
        { "ScrVar_SetValue", 0x027616B0ull, "game" },
        { "ScrVm_AddBool", 0x0276E760ull, "game" },
        { "ScrVm_AddConstString", 0x0276E5F0ull, "game" },
        { "ScrVm_AddFloat", 0x0276E9B0ull, "game" },
        { "ScrVm_AddHash", 0x0276EAB0ull, "game" },
        { "ScrVm_AddInt", 0x0276EB80ull, "game" },
        { "ScrVm_AddString", 0x0276EE30ull, "game" },
        { "ScrVm_AddStruct", 0x0276EF00ull, "game" },
        { "ScrVm_AddToArray", 0x0276F1C0ull, "game" },
        { "ScrVm_AddToArrayStringIndexed", 0x0276F230ull, "game" },
        { "ScrVm_AddUndefined", 0x0276F3C0ull, "game" },
        { "ScrVm_AddVector", 0x0276F490ull, "game" },
        { "ScrVm_Error", 0x02770330ull, "game" },
        { "ScrVm_GetBool", 0x02772AB0ull, "game" },
        { "ScrVm_GetConstString", 0x02772E10ull, "game" },
        { "ScrVm_GetFloat", 0x027733F0ull, "game" },
        { "ScrVm_GetHash", 0x027738E0ull, "game" },
        { "ScrVm_GetInt", 0x02773B50ull, "game" },
        { "ScrVm_GetNumParam", 0x02774440ull, "game" },
        { "ScrVm_GetPointerType", 0x027746E0ull, "game" },
        { "ScrVm_GetString", 0x02774840ull, "game" },
        { "ScrVm_GetType", 0x02774A20ull, "game" },
        { "ScrVm_GetVector", 0x02774E40ull, "game" },
        { "ScrVm_SetStructField", 0x02778450ull, "game" },
        { "Scr_GetFunction", 0x033AF840ull, "game" },
        { "Scr_GetGscExportInfo", 0x02748550ull, "game" },
        { "Scr_GetMethod", 0x033AFC20ull, "game" },
        { "Sys_GetTLS", 0x03C56140ull, "game" },
        { "Sys_Milliseconds", 0x03D89E80ull, "game" },
        { "Sys_SendPacket", 0x03D89900ull, "game" },
        { "T8_AddBaseDrawTextCmd", 0x03616B60ull, "game" },
        { "UI_TextHeight", 0x03CD6560ull, "game" },
        { "UI_TextWidth", 0x03CD65B0ull, "game" },
        { "builtinLabels", 0x04F11530ull, "game" },
        { "cmd_functions", 0x0F99B188ull, "game" },
        { "gObjFileInfo", 0x082EFCD0ull, "game" },
        { "gObjFileInfoCount", 0x082F76B0ull, "game" },
        { "gVmOpJumpTable", 0x04EED340ull, "game" },
        { "hks_obj_tolstring", 0x03755730ull, "game" },
        { "hks_obj_tonumber", 0x03755A90ull, "game" },
        { "keyCatchers", 0x08A53F84ull, "game" },
        { "playerKeys", 0x08A3EF80ull, "game" },
        { "scrVarGlob", 0x08307830ull, "game" },
        { "scrVarPub", 0x08307880ull, "game" },
        { "scrVmPub", 0x08307AA0ull, "game" },
        { "sharedUiInfo", 0x0F956850ull, "game" },
        { "sv_cmd_args", 0x0F998070ull, "game" },
        { "var_typename", 0x04EED240ull, "game" },
        { "CharEvent", 0x02836F80ull, "input" },
        { "KeyEvent", 0x02839250ull, "input" },
        { "Lua_LoadHook_A", 0x01FD3220ull, "lua" },
        { "Lua_LoadHook_B", 0x01D34190ull, "lua" },
        { "Lua_UIVM_A", 0x037358D0ull, "lua" },
        { "Lua_UIVM_B", 0x03736A50ull, "lua" },
        { "Lua_UIVM_C", 0x0373B640ull, "lua" },
        { "BNet_GetUserId", 0x02325CA0ull, "platform" },
        { "BNet_GetUsername", 0x02325C70ull, "platform" },
        { "Scheduler_Main", 0x0288BAE0ull, "scheduler" },
        { "Scheduler_Render", 0x0361E260ull, "scheduler" },
        { "Scheduler_Server", 0x02D08FC0ull, "scheduler" },
    };

    inline constexpr std::size_t ImportedCount =
        sizeof(Imported) / sizeof(Imported[0]);

    // Addresses recovered from the original Aug-2018 Multiplayer Beta unlocker.
    // These are build-native RVAs; the shared scanner can audit them without
    // applying any patch until the expected bytes are validated.
    inline constexpr NamedRva MultiplayerBetaImported[] =
    {
        { "BuildMarker_CL", 0x01F004D8ull, "build" },
        { "Unlocker_Patch_ReturnTrue_A", 0x006D88B0ull, "patch" },
        { "Unlocker_Patch_ReturnTrue_B", 0x006D88C0ull, "patch" },
        { "Unlocker_Patch_Return", 0x006BDE20ull, "patch" },
        { "Unlocker_Patch_Nop13", 0x0109FC44ull, "patch" },
        { "Unlocker_Patch_ReturnTrue_C", 0x016AD170ull, "patch" },
        { "Unlocker_Patch_ReturnTrue_D", 0x016C0530ull, "patch" },
        { "Unlocker_Patch_Nop24", 0x0110BDFBull, "patch" },
        { "Unlocker_Patch_Nop22", 0x0112CDD6ull, "patch" },
        { "Unlocker_Detour_A", 0x006D7CC0ull, "game" },
        { "Unlocker_Detour_B", 0x006D7CD0ull, "game" },
        { "Unlocker_Patch_Nop6_A", 0x0081498Full, "patch" },
        { "Unlocker_Patch_Branch", 0x00BD3260ull, "patch" },
        { "Unlocker_Patch_Return_B", 0x007A9742ull, "patch" },
        { "Unlocker_Patch_Nop5", 0x00799B84ull, "patch" },
        { "Unlocker_Patch_ZeroR8D", 0x00842C94ull, "patch" },
        { "Unlocker_Patch_Nop2", 0x006B6672ull, "patch" },
        { "Unlocker_Patch_Jump", 0x006B6650ull, "patch" },
        { "Unlocker_HookTarget_A", 0x006D3F20ull, "game" },
        { "Unlocker_HookTarget_B", 0x01AA16C0ull, "game" },
        { "Unlocker_HookTarget_C", 0x01A7A2D0ull, "game" },
        { "Unlocker_Patch_Nop6_B", 0x008142E8ull, "patch" },
        { "Unlocker_Patch_ByteZero_A", 0x00AE0F0Cull, "patch" },
        { "Unlocker_Patch_ByteZero_B", 0x00AE1188ull, "patch" },
        { "Unlocker_Unknown_10BD110", 0x010BD110ull, "research" },
        { "Unlocker_Unknown_FB9C60", 0x00FB9C60ull, "research" },
        { "Unlocker_Unknown_12D0900", 0x012D0900ull, "research" },
        { "Unlocker_Unknown_F8C9A0", 0x00F8C9A0ull, "research" },
        { "Unlocker_Unknown_800470", 0x00800470ull, "research" },
        { "Unlocker_Unknown_1225140", 0x01225140ull, "research" },
        { "Unlocker_Unknown_1224C10", 0x01224C10ull, "research" },
        { "Unlocker_Unknown_1226890", 0x01226890ull, "research" },
        { "Unlocker_Unknown_12267F0", 0x012267F0ull, "research" },
        { "Unlocker_Unknown_1226750", 0x01226750ull, "research" },
        { "Unlocker_Unknown_1226840", 0x01226840ull, "research" },
        { "Unlocker_Unknown_81AC00", 0x0081AC00ull, "research" },
        { "Unlocker_Unknown_112A200", 0x0112A200ull, "research" },
        { "Unlocker_Unknown_116F840", 0x0116F840ull, "research" },
        { "Unlocker_Unknown_12D66E0", 0x012D66E0ull, "research" },
        { "Unlocker_Unknown_814ED0", 0x00814ED0ull, "research" },
        { "Unlocker_Unknown_FBACD0", 0x00FBACD0ull, "research" },
    };

    inline constexpr std::size_t MultiplayerBetaImportedCount =
        sizeof(MultiplayerBetaImported) / sizeof(MultiplayerBetaImported[0]);

    // Build-native offsets already recovered by the Blackout Beta research path.
    inline constexpr NamedRva BlackoutBetaImported[] =
    {
        { "unlockSessionMode", 0x002F24ECull, "game" },
        { "playlistEntry", 0x00208D91ull, "frontend" },
        { "LobbyVM", 0x018B52E0ull, "lua" },
        { "cancelMatchMaking", 0x018B5510ull, "lobby" },
        { "initMatchMaking", 0x018B5C80ull, "lobby" },
        { "shutdownMatchMaking", 0x018B6C60ull, "lobby" },
        { "startMatchMaking", 0x018B6DE0ull, "lobby" },
        { "open_hud_menu_A", 0x00B10740ull, "frontend" },
        { "open_hud_menu_B", 0x00B17250ull, "frontend" },
        { "emergencyShutdown_A", 0x0267B2A0ull, "game" },
        { "emergencyShutdown_B", 0x02689ED0ull, "game" },
        { "emergencyShutdown_C", 0x026969E0ull, "game" },
        { "OnGetAnticheatReputation", 0x027E0810ull, "network" },
        { "OnPopAnticheatMessage", 0x027E66A0ull, "network" },
        { "OnPushAnticheatMessageToUI", 0x027E6AC0ull, "frontend" },
        { "threadEntry_017D7C0", 0x0017D7C0ull, "scheduler" },
        { "threadEntry_2977E10", 0x02977E10ull, "scheduler" },
        { "threadEntry_36C9AE0", 0x036C9AE0ull, "scheduler" },
    };

    inline constexpr std::size_t BlackoutBetaImportedCount =
        sizeof(BlackoutBetaImported) / sizeof(BlackoutBetaImported[0]);

    // Strong action-matched candidates recovered by comparing the working retail
    // Shield patches with the original MP Beta unlocker. They are centralized
    // here so every retail _g call can eventually be ported without forking the
    // component source. The full beta post_unpack set remains gated until the
    // required mapping coverage is complete and runtime bytes are validated.
    inline constexpr RetailPreferredMapEntry MultiplayerBetaRetailMap[] =
    {
        { 0x144508469ull, 0x016E1869ull, "CURLOPT_SSL_VERIFYPEER" },
        { 0x144508455ull, 0x016E1855ull, "CURLOPT_SSL_VERIFYHOST" },
        { 0x144B28D98ull, 0x01F61EE4ull, "HTTPS_to_HTTP_flag" },
        { 0x144A27C70ull, 0x01F61198ull, "umbrella_url_buffer" },
        { 0x144A2BAA0ull, 0x01F617D0ull, "uno_url_buffer" },
        { 0x144A29CB0ull, 0x01F5F4D0ull, "auth_url_format" },
        { 0x1423271D0ull, 0x006D88B0ull, "BattleNet_IsDisabled" },
        { 0x1423271E0ull, 0x006D88C0ull, "BattleNet_IsConnected" },
        { 0x142325210ull, 0x006BDE20ull, "BattleNet_early_crash_gate" },
        { 0x1437DA454ull, 0x0109FC44ull, "LiveConnect_BeginCrossAuthPlatform" },
        { 0x1444D2D60ull, 0x016AD170ull, "bdAuth_validateResponseSignature_candidate" },
        { 0x1444E34C0ull, 0x016C0530ull, "bdAuthPC_processPlatformData_candidate" },
        { 0x1438994E9ull, 0x0110BDFBull, "Live_UserSignedIn_candidate" },
        { 0x1438C3476ull, 0x0112CDD6ull, "LiveUser_UserGetXuid_candidate" },
        { 0x1449CA7E8ull, 0x01F004D8ull, "BuildMarker_CL" },
    };

    inline constexpr std::size_t MultiplayerBetaRetailMapCount =
        sizeof(MultiplayerBetaRetailMap) / sizeof(MultiplayerBetaRetailMap[0]);

    struct AddressSet
    {
        Build build;
        const Fingerprint* fingerprint;
        const CoreRvas* core;
        const NamedRva* named;
        std::size_t namedCount;
        const RetailPreferredMapEntry* retailMap;
        std::size_t retailMapCount;
        bool fullClientAddressMapComplete;
    };

    inline constexpr AddressSet RetailAddressSet
    { Build::LatestBnet, &LatestBnet, &Core, Imported, ImportedCount, nullptr, 0, true };

    inline constexpr AddressSet MultiplayerBetaAddressSet
    { Build::MultiplayerBetaAug2018, &MultiplayerBetaAug2018, &MultiplayerBetaCore,
      MultiplayerBetaImported, MultiplayerBetaImportedCount,
      MultiplayerBetaRetailMap, MultiplayerBetaRetailMapCount, false };

    inline constexpr AddressSet BlackoutBetaAddressSet
    { Build::BlackoutBetaSep2018, &BlackoutBetaSep2018, &BlackoutBetaCore,
      BlackoutBetaImported, BlackoutBetaImportedCount, nullptr, 0, false };

    inline constexpr std::uintptr_t Resolve(
        std::uintptr_t moduleBase,
        std::uintptr_t rva)
    {
        return rva ? moduleBase + rva : 0;
    }
}
