#pragma once
#include <cstdint>

namespace t9_addresses
{
    enum class Build
    {
        Unknown,
        Retail,
        Beta,
        Alpha,
        Season2
    };

    struct Fingerprint
    {
        const char* label;
        std::uint32_t timestamp;
        std::uint32_t imageSize;
        std::uint32_t entryPointRva;
    };

    struct RetailRvas
    {
        std::uintptr_t s_uiScreen;
        std::uintptr_t s_networkMode;
        std::uintptr_t sSessionModeState;
        std::uintptr_t config0;
        std::uintptr_t config1;

        std::uintptr_t CL_Disconnect;
        std::uintptr_t set_username;
        std::uintptr_t LiveUser_GetUserDataForController;
        std::uintptr_t SetScreen;
        std::uintptr_t LobbyBase_SetNetworkMode;
        std::uintptr_t Com_SessionMode_SetNetworkMode;
        std::uintptr_t Com_GametypeSettings_SetGametype;
        std::uintptr_t Dvar_SetBoolFromSource;
        std::uintptr_t Dvar_SetStringFromSource;
        std::uintptr_t Dvar_FindVar;
        std::uintptr_t KeyboardInput;
        std::uintptr_t LobbySession_GetControllingLobbySession;
        std::uintptr_t LobbyData_SetMap;
        std::uintptr_t LobbyData_SetGameType;
        std::uintptr_t ScrStr_ConvertToString;
        std::uintptr_t VM_OP_Table;
        std::uintptr_t VM_OP_Notify_Handler;
        std::uintptr_t Dvar_GetBool_cmp;
        std::uintptr_t watermark_font;
        std::uintptr_t dvar_show_over_stack;
        std::uintptr_t CL_DrawTextPhysical;
        std::uintptr_t R_AddCmdDrawStretchPic;
        std::uintptr_t ScrVm_ExecThread;
        std::uintptr_t ScrVar_ReleaseVariable;
        std::uintptr_t Scr_GetFunctionHandle;
        std::uintptr_t ScrVm_AddString;
        std::uintptr_t ScrVm_AddInt;
        std::uintptr_t Com_IsInGame;
        std::uintptr_t Sys_IsServerThread;
        std::uintptr_t Material_RegisterHandle;
        std::uintptr_t ScrPlace_GetViewUIContext;
        std::uintptr_t UI_GetFontHandle;
        std::uintptr_t R_TextWidth;
        std::uintptr_t clientthink_ret;
        std::uintptr_t dvar_load_script;
        std::uintptr_t g_auth_manager;
        std::uintptr_t shader_white;
        std::uintptr_t dvar_noDW;
        std::uintptr_t Cbuf_AddText;
        std::uintptr_t CbufAddtextFunc;
        std::uintptr_t cusCbufBuffer1;
        std::uintptr_t cusCbufBuffer2;
        std::uintptr_t cusCbufBuffer3;
        std::uintptr_t LobbyHostBots_AddBotsToLobby;
        std::uintptr_t s_inited;
        std::uintptr_t assetPool;

        // Old research/helper addresses that were previously hardcoded in
        // core/functions.cpp and CoreRuntime.cpp.
        std::uintptr_t versionMarker;
        std::uintptr_t exceptionRipA;
        std::uintptr_t exceptionRipB;
        std::uintptr_t Dvar_RegisterInt;
        std::uintptr_t Dvar_SetInt;
        std::uintptr_t Dvar_SetFloatCandidateA;
        std::uintptr_t Dvar_SetFloatFromSource;
        std::uintptr_t Dvar_SetFloatCandidateC;
        std::uintptr_t Dvar_SetVariant;
        std::uintptr_t SV_AddTestClient;
        std::uintptr_t Scr_AddEntity;
        std::uintptr_t Cmd_AddCommandInternal;
    };

    struct LegacyRvas
    {
        std::uintptr_t frontendReady;
        std::uintptr_t SetScreen;
        std::uintptr_t Cbuf_AddText;
        std::uintptr_t modeState;
        std::uintptr_t modeAux;
        std::uintptr_t modeTag;
        std::uintptr_t alphaMarkerRva;
        std::uint32_t alphaMarkerValue;
    };

    // Exact Open Beta addresses recovered from the supplied working dxgi.dll.
    // Keep these separate from LegacyRvas: the old Beta/Alpha table was copied
    // from unrelated research and must not be used for the October beta.
    struct BetaRecoveredRvas
    {
        std::uintptr_t readyByte;
        std::uintptr_t stateA;
        std::uintptr_t stateB;
        std::uintptr_t stateC;
        std::uintptr_t command;
        std::uintptr_t transition;
        std::uintptr_t initA;
        std::uintptr_t initB;
        std::uintptr_t forceReadyFlag;
        std::uintptr_t endpointA;
        std::uintptr_t endpointB;
        std::uintptr_t authManagerSlot;
        std::uintptr_t usernameContext;
        std::uintptr_t setUsername;
        std::uintptr_t exceptionFilter;
        std::uintptr_t win11Breakpoint;
        std::uintptr_t win11Resume;
    };


    struct LegacyRetail126Rvas
    {
        std::uintptr_t Cinematic_StopPlayback;
        std::uintptr_t LobbyBase_SetNetworkMode;
        std::uintptr_t Com_SessionMode_SetMode;
        std::uintptr_t SetScreen;
        std::uintptr_t CL_Disconnect;
        std::uintptr_t LobbyData_SetMap;
        std::uintptr_t LobbySession_GetControllingLobbySession;
        std::uintptr_t LobbyHostBots_AddBotsToLobby;
        std::uintptr_t uiReady;
        std::uintptr_t forceReadyFlag;
    };

    struct ResearchRvas
    {
        std::uintptr_t cl_getusercmd;
        std::uintptr_t cl_getusercmdnumber;
        std::uintptr_t pmovehandler;
        std::uintptr_t com_sessionmode_getmode;
        std::uintptr_t com_ingame;
        std::uintptr_t cg_predictedplayerstate;
        std::uintptr_t CG_GetEntityState;
        std::uintptr_t unknown_CG_GetEntity;
        std::uintptr_t CG_GetEntityOriginAngles;
        std::uintptr_t cg_getclientinfo;
        std::uintptr_t istargetvisible;
        std::uintptr_t worldpostoscreenpos;
        std::uintptr_t cg_getplayervieworigin;
        std::uintptr_t getviewaxisprojections;
        std::uintptr_t cl_setviewangles;
        std::uintptr_t CG_DObjGetWorldTagMatrix;
        std::uintptr_t cg_getdobj;
        std::uintptr_t weaponCamoWrapper;
    };

    struct RvaRange
    {
        std::uintptr_t begin;
        std::uintptr_t end;
    };

    struct SingletonExitRvas
    {
        RvaRange exitWrapper;
        RvaRange earlyReject;
        RvaRange existingHandoffA;
        RvaRange existingHandoffB;
        RvaRange exactExitA;
        RvaRange exactExitB;
        RvaRange exactReject;
        RvaRange exactHandoffA;
    };

    inline constexpr std::uintptr_t PreferredImageBase = 0x140000000ull;

    inline constexpr Fingerprint RetailFingerprint
    {
        "T9 Retail",
        0x6A038464,
        0x1FC5E200,
        0
    };

    // Keep Alpha and Open Beta as distinct executable profiles.  The old
    // merged table incorrectly assigned the Beta fingerprint to Alpha too,
    // which made profile selection ambiguous.
    inline constexpr Fingerprint BetaFingerprint
    {
        "T9 Open Beta",
        0x5F88B829,
        0x18130000,
        0x08B0C090
    };

    inline constexpr Fingerprint AlphaFingerprint
    {
        "T9 June 4th Alpha / COD2020",
        0x5F1B8329,
        0x10C4A200,
        0x02128E60
    };

    inline constexpr Fingerprint Season2Fingerprint
    {
        "T9 Season 2",
        0x60368381,
        0x1DDC8000,
        0x0CBD66A0
    };

    inline constexpr RetailRvas Retail
    {
        0x0E785AD8, // s_uiScreen
        0x16039DA0, // s_networkMode
        0x1929C548, // sSessionModeState
        0x1ADCC978, // config[0]
        0,          // config[1]

        0x05C2FEA0, // CL_Disconnect
        0x0A8BC7F0, // set_username
        0x0A8BBE70, // LiveUser_GetUserDataForController
        0x0B1B69B0, // SetScreen
        0x0AF20CB0, // LobbyBase_SetNetworkMode
        0x0C175190, // Com_SessionMode_SetNetworkMode
        0x0A000680, // Com_GametypeSettings_SetGametype
        0x0C06DF20, // Dvar_SetBoolFromSource
        0x0C070F50, // Dvar_SetStringFromSource
        0,          // Dvar_FindVar - runtime resolved
        0x0CBA1D50, // KeyboardInput
        0x0A394CE0, // LobbySession_GetControllingLobbySession
        0x0AF2E6A0, // LobbyData_SetMap
        0x0AF2E5C0, // LobbyData_SetGameType
        0x01B9A6B0, // ScrStr_ConvertToString
        0x0E405DC0, // VM_OP_Table
        0x01B944B0, // VM_OP_Notify_Handler
        0x01A3AD5D, // Dvar_GetBool_cmp
        0,          // watermark_font - runtime resolved
        0x11DDA5F8, // dvar_show_over_stack
        0x0B5A9CF0, // CL_DrawTextPhysical
        0x0B5A9890, // R_AddCmdDrawStretchPic
        0x01BD4D80, // ScrVm_ExecThread
        0x01BAD480, // ScrVar_ReleaseVariable
        0x01B842B0, // Scr_GetFunctionHandle
        0x01BD2F70, // ScrVm_AddString
        0x01BD30C0, // ScrVm_AddInt
        0x056E89A0, // Com_IsInGame
        0x0C0EF1B0, // Sys_IsServerThread
        0x0C173030, // Material_RegisterHandle
        0x0AF1D700, // ScrPlace_GetViewUIContext
        0,          // UI_GetFontHandle - runtime resolved
        0x0C291B00, // R_TextWidth
        0x0718BE70, // clientthink_ret
        0x16855250, // dvar_load_script
        0x17A63C38, // g_auth_manager
        0x107515B8, // shader_white
        0x179AA458, // dvar_noDW
        0,          // validated Cbuf_AddText - runtime resolved
        0x03B682B0, // legacy CbufAddtextFunc
        0x0D42FC78, // cusCbufBuffer1
        0x0D42FC90, // cusCbufBuffer2
        0x0D42FD50, // cusCbufBuffer3
        0x077937E0, // LobbyHostBots_AddBotsToLobby
        0x13FB48D6, // s_inited
        0x123E2E70, // XAssetPool

        0x11017B0,  // versionMarker
        0x17794C3,  // exceptionRipA
        0x10DF720,  // exceptionRipB
        0xC0C7360,  // Dvar_RegisterInt
        0xC0B7B90,  // Dvar_SetInt
        0xC070530,  // Dvar_SetFloatCandidateA
        0xC06F520,  // Dvar_SetFloatFromSource
        0xC06B8D0,  // Dvar_SetFloatCandidateC
        0xC0B8DB0,  // Dvar_SetVariant
        0x7189410,  // SV_AddTestClient
        0x737F490,  // Scr_AddEntity
        0x9ACBAD0   // Cmd_AddCommandInternal
    };

    // Legacy table retained only for old research callers. Do not use this
    // table for the exact October Open Beta bootstrap below.
    inline constexpr LegacyRvas Beta
    {
        0x0A8609C8, // legacy frontendReady (unverified for October beta)
        0x0105D9C0, // legacy SetScreen
        0x016F3A10, // legacy Cbuf_AddText
        0x065259E4, // legacy modeState
        0x0B7D18A0, // legacy modeAux
        0x0B3333A9, // legacy modeTag
        0x02602E18, // legacy alphaMarkerRva
        0x5F1B8329  // legacy alphaMarkerValue
    };

    inline constexpr LegacyRvas Alpha = Beta;

    inline constexpr BetaRecoveredRvas OpenBetaRecovered
    {
        0x0F5F22E7, // readyByte
        0x113D70B8, // stateA
        0x14053008, // stateB
        0x097D5948, // stateC
        0x06022150, // command(controller, text)
        0x06F047B0, // transition(state, arg)
        0x079D82A0, // initA(1)
        0x06D6DB30, // initB(1)
        0x15B22738, // forceReadyFlag
        0x08DC71A0, // endpointA[16]
        0x08DC71B0, // endpointB[16]
        0x14BE7430, // authManagerSlot
        0x0690B330, // usernameContext(0)
        0x0690BDD0, // setUsername(context, text)
        0x08B0C38C, // exceptionFilter
        0x0046BC54, // Win11 one-shot breakpoint
        0x0046BC81  // Win11 resume
    };

    inline constexpr LegacyRetail126Rvas LegacyRetail126
    {
        0x09C0F5A0, // Cinematic_StopPlayback
        0x0AF652D0, // LobbyBase_SetNetworkMode
        0x0C1C78A0, // Com_SessionMode_SetMode
        0x0B1FAB70, // SetScreen
        0x05CDDBB0, // CL_Disconnect
        0x0AF72A10, // LobbyData_SetMap
        0x0A3CDEF0, // LobbySession_GetControllingLobbySession
        0x077AB7C0, // LobbyHostBots_AddBotsToLobby
        0x101BABB0, // uiReady
        0x1A5F7B97  // forceReadyFlag
    };

    inline constexpr ResearchRvas RetailResearch
    {
        0x09DFBF70, // cl_getusercmd
        0x09DE4F80, // cl_getusercmdnumber
        0x0E442C80, // pmovehandler
        0x0C174C80, // com_sessionmode_getmode
        0x056E89A0, // com_ingame
        0x05A186C0, // cg_predictedplayerstate
        0x09B005E0, // CG_GetEntityState
        0x0BB40000, // unknown_CG_GetEntity
        0x09AF70B0, // CG_GetEntityOriginAngles
        0x07A63180, // cg_getclientinfo
        0x086FD5C0, // istargetvisible
        0x08442E00, // worldpostoscreenpos
        0x05297690, // cg_getplayervieworigin
        0x05297690, // getviewaxisprojections
        0x09E71930, // cl_setviewangles
        0x061C4FC0, // CG_DObjGetWorldTagMatrix
        0x0A931330, // cg_getdobj
        0x01C0A515  // weaponCamoWrapper
    };

    inline constexpr SingletonExitRvas RetailSingletonExit
    {
        { 0x0D30B180, 0x0D30B1A8 },
        { 0x0D2B8500, 0x0D2B85FF },
        { 0x0CBD7000, 0x0CBD70FF },
        { 0x0CA05600, 0x0CA058FF },
        { 0x0D30B185, 0x0D30B1A5 },
        { 0x0D30B13B, 0x0D30B15B },
        { 0x0D2B85A0, 0x0D2B85C0 },
        { 0x0CBD703E, 0x0CBD705E }
    };

    inline constexpr const Fingerprint& FingerprintFor(Build build)
    {
        switch (build)
        {
        case Build::Retail: return RetailFingerprint;
        case Build::Beta:   return BetaFingerprint;
        case Build::Alpha:   return AlphaFingerprint;
        case Build::Season2: return Season2Fingerprint;
        default:             return RetailFingerprint;
        }
    }

    inline constexpr const LegacyRvas& LegacyFor(Build build)
    {
        return build == Build::Alpha ? Alpha : Beta;
    }

    inline constexpr std::uintptr_t Resolve(
        std::uintptr_t moduleBase,
        std::uintptr_t rva)
    {
        return rva ? moduleBase + rva : 0;
    }
}
