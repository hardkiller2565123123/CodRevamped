#pragma once
#include <cstddef>
#include <cstdint>

// MW2019 / Warzone 1.44.0.10435696 address catalog.
// Keep every 1.44-specific RVA, field offset, signature, and research landmark here.
// IW8Addresses.h owns only shared build/fingerprint types and cross-version tables.

namespace iw8_addresses
{
    struct Signatures144
    {
        const char* Live_PatchGetState;
        const char* Live_OnlineServicesFence_GetState;
        const char* Live_SyncOnlineDataFence_GetState;
        const char* GetBattleNetFenceState;
        const char* SignInExchangeStateRef;
        const char* Lua_IsGamemodeAllowedCandidate;
        const char* PartyFrontendPatch;
        const char* LiveStorage_GetUTC;
        const char* LiveStorage_IsTimeSyncedCallsite;
        int SignInExchangeControllerOffset;
    };

    struct Resolved144
    {
        bool matched = false;
        unsigned int matchedSignatures = 0;
        std::uintptr_t Live_PatchGetState = 0;
        std::uintptr_t Live_OnlineServicesFence_GetState = 0;
        std::uintptr_t Live_SyncOnlineDataFence_GetState = 0;
        std::uintptr_t GetBattleNetFenceState = 0;
        std::uintptr_t SignInExchangeStateRef = 0;
        std::uintptr_t Lua_IsGamemodeAllowedCandidate = 0;
        std::uintptr_t PartyFrontendPatch = 0;
        std::uintptr_t LiveStorage_GetUTC = 0;
        std::uintptr_t LiveStorage_IsTimeSyncedCallsite = 0;
    };

    struct Rvas144
    {
        std::uintptr_t Dvar_RegisterBool = 0x13E7670;
        std::uintptr_t Dvar_RegisterString = 0x13E7A70;
        std::uintptr_t Dvar_FindVarByName = 0x13E63A0;
        std::uintptr_t Cmd_Exec_Internal = 0x1297580;
        std::uintptr_t Live_PatchGetState = 0x2D21490; // REFERENCE: repeatedly resolved by the 1.44 signature scanner
        std::uintptr_t GetBattleNetFenceState = 0x4657480; // REFERENCE: repeatedly resolved by the 1.44 signature scanner
        std::uintptr_t CL_GetLocalClientSignInState = 0x4647840;
        std::uintptr_t dwGetLogOnStatus = 0x5D6ACA0;
        std::uintptr_t Live_IsUserSignedInToDemonware = 0x3D61700;
        std::uintptr_t unk_IsUserSignedInToBNet = 0x4647860;
        std::uintptr_t Content_DoWeHaveContentPack = 0x39EA080;
        std::uintptr_t Live_OnlineServicesFence_GetState = 0x2D0CBF0;
        std::uintptr_t Live_SyncOnlineDataFence_GetState = 0x2D0DD00;
        std::uintptr_t LUI_CoD_LuaCall_IsBattleNetAuthReady = 0x638D6E0;
        std::uintptr_t LUI_CoD_LuaCall_IsConnectedToGameServer = 0x6384930;
        std::uintptr_t LUI_CoD_LuaCall_ShouldBeInOnlineArea = 0x63CB840;
        std::uintptr_t LUI_CoD_LuaCall_OfflineDataFetched = 0x653B210;
        std::uintptr_t OnlineErrorManager_GetFenceState = 0x46C1D00;
        std::uintptr_t OnlineErrorManager_IsMpNotAllowed = 0x46A7D30;
        std::uintptr_t s_OnlineServicesFenceData_state = 0x1B468ED8;
        std::uintptr_t lua_pushboolean = 0x2083E80;
        std::uintptr_t LUI_OpenMenu = 0x1B9BDB0;
        std::uintptr_t LuaShared_PCall = 0x61EF7F0; // REFERENCE: old frontend-dispatch research hook, currently unused
        std::uintptr_t R_EndFrame = 0x1966950;
    };

    inline constexpr Rvas144 MW2019_1_44_Rvas{};

    // 1.44 discovery catalog. These values are intentionally kept separate from
    // Rvas144 so finding an address never implies that it should be hooked or
    // patched. Unless noted otherwise they are READ_ONLY/REFERENCE landmarks
    // recovered from the user's 1.44 logs, passive call stacks, and scanners.
    struct Discovery144
    {
        // Network / Battle.net bootstrap call sites.
        std::uintptr_t Http80BootstrapConnectCaller = 0x36F6F1E;
        std::uintptr_t Http80FingerprintConnectCaller = 0x6E6CC13;
        std::uintptr_t Bgs1119ConnectCaller = 0x80638F;
        std::uintptr_t BgsTlsSendCaller = 0x7F93F6;

        // Shared Battle.net launcher registry helper call sites.
        std::uintptr_t BattleNetRegistrySizeQueryCaller = 0x6968C3;
        std::uintptr_t BattleNetRegistryValueReadCaller = 0x6968FD;

        // ACCOUNT_STATE consumer stack captured after a successful 230-byte read.
        std::uintptr_t AccountStateConsumerFrame1 = 0x4640A84;
        std::uintptr_t AccountStateConsumerFrame2 = 0x4640543;
        std::uintptr_t AccountStateConsumerFrame3 = 0x34ADBC9;
        std::uintptr_t AccountStateConsumerFrame4 = 0x39DD962;
        std::uintptr_t AccountStateConsumerFrame5 = 0x3412DA8;
        std::uintptr_t AccountStateConsumerFrame6 = 0x341124F;
        std::uintptr_t AccountStateConsumerFrame7 = 0x3A323ED;
        std::uintptr_t AccountStateConsumerFrame8 = 0x3A27BDD;
        std::uintptr_t AccountStateConsumerFrame9 = 0x3B3E859;

        // WEB_TOKEN consumer stack captured after a successful 262-byte read.
        std::uintptr_t WebTokenConsumerFrame1 = 0x4647694;
        std::uintptr_t WebTokenConsumerFrame2 = 0x4641DAD;
        std::uintptr_t WebTokenConsumerAuthClusterFrame = 0x464798E;
        std::uintptr_t WebTokenConsumerFrame4 = 0x3A216D6;
        std::uintptr_t WebTokenConsumerFrame5 = 0x422700E;
        std::uintptr_t WebTokenConsumerFrame6 = 0x340CACC;
        std::uintptr_t WebTokenConsumerFrame7 = 0x33FDE19;
        std::uintptr_t WebTokenConsumerFrame8 = 0x3B3E886;
        std::uintptr_t WebTokenConsumerFrame9 = 0x6D4298A;

        // Direct callers recovered by the read-only auth-gate topology scan.
        // These are REFERENCE-only. The original capture stopped at 16 hits;
        // the follow-up full-xref pass recovered 68 Demonware-sign-in callers
        // and 43 dwGetLogOnStatus callers, all cataloged below.
        std::uintptr_t SignInStateCallerJmp1 = 0x3A21520;
        std::uintptr_t BNetSignedInCaller1 = 0x3A21562;
        std::uintptr_t SignInStateCaller2 = 0x3A2156D;
        std::uintptr_t SignInStateCaller3 = 0x3A215E8;
        std::uintptr_t SignInStateCaller4 = 0x3A21F84;
        std::uintptr_t SignInStateCaller5 = 0x3A21FA4;

        // Full 1.44 direct-xref capture for BNetSignInFirstStateGetter. An
        // earlier capture stopped at 128 entries; the completed 2026-08-28 pass
        // recovered 148 callers total.
        // REFERENCE only; no caller is hooked or patched.
        std::uintptr_t BNetFirstStateGetterCaller001 = 0x159E07F;
        std::uintptr_t BNetFirstStateGetterCaller002 = 0x159E1AA;
        std::uintptr_t BNetFirstStateGetterCaller003 = 0x159E1C7;
        std::uintptr_t BNetFirstStateGetterCaller004 = 0x159E4A9;
        std::uintptr_t BNetFirstStateGetterCaller005 = 0x1B5A880;
        std::uintptr_t BNetFirstStateGetterCaller006 = 0x1B5A9AB;
        std::uintptr_t BNetFirstStateGetterCaller007 = 0x1B5A9CA;
        std::uintptr_t BNetFirstStateGetterCaller008 = 0x1B5ACD4;
        std::uintptr_t BNetFirstStateGetterCaller009 = 0x1C6125E;
        std::uintptr_t BNetFirstStateGetterCaller010 = 0x1C61389;
        std::uintptr_t BNetFirstStateGetterCaller011 = 0x1C613A8;
        std::uintptr_t BNetFirstStateGetterCaller012 = 0x1C616B2;
        std::uintptr_t BNetFirstStateGetterCaller013 = 0x1D791E5;
        std::uintptr_t BNetFirstStateGetterCaller014 = 0x1D79310;
        std::uintptr_t BNetFirstStateGetterCaller015 = 0x1D7932F;
        std::uintptr_t BNetFirstStateGetterCaller016 = 0x1D79639;
        std::uintptr_t BNetFirstStateGetterCaller017 = 0x1E75CBA;
        std::uintptr_t BNetFirstStateGetterCaller018 = 0x1E75DE5;
        std::uintptr_t BNetFirstStateGetterCaller019 = 0x1E75E04;
        std::uintptr_t BNetFirstStateGetterCaller020 = 0x1E7610E;
        std::uintptr_t BNetFirstStateGetterCaller021 = 0x28FFDA6;
        std::uintptr_t BNetFirstStateGetterCaller022 = 0x28FFDB4;
        std::uintptr_t BNetFirstStateGetterCaller023 = 0x28FFDC6;
        std::uintptr_t BNetFirstStateGetterCaller024 = 0x28FFEC3;
        std::uintptr_t BNetFirstStateGetterCaller025 = 0x28FFED1;
        std::uintptr_t BNetFirstStateGetterCaller026 = 0x28FFEE3;
        std::uintptr_t BNetFirstStateGetterCaller027 = 0x290005E;
        std::uintptr_t BNetFirstStateGetterCaller028 = 0x2900074;
        std::uintptr_t BNetFirstStateGetterCaller029 = 0x29E5D39;
        std::uintptr_t BNetFirstStateGetterCaller030 = 0x29E5D4B;
        std::uintptr_t BNetFirstStateGetterCaller031 = 0x29E6C16;
        std::uintptr_t BNetFirstStateGetterCaller032 = 0x29E6C24;
        std::uintptr_t BNetFirstStateGetterCaller033 = 0x29E6C35;
        std::uintptr_t BNetFirstStateGetterCaller034 = 0x29E6CCD;
        std::uintptr_t BNetFirstStateGetterCaller035 = 0x29E6CDB;
        std::uintptr_t BNetFirstStateGetterCaller036 = 0x29E6CEC;
        std::uintptr_t BNetFirstStateGetterCaller037 = 0x29E6EA4;
        std::uintptr_t BNetFirstStateGetterCaller038 = 0x29E6EBA;
        std::uintptr_t BNetFirstStateGetterCaller039 = 0x2AD94EA;
        std::uintptr_t BNetFirstStateGetterCaller040 = 0x2AD9501;
        std::uintptr_t BNetFirstStateGetterCaller041 = 0x2AD9513;
        std::uintptr_t BNetFirstStateGetterCaller042 = 0x2BA24B1;
        std::uintptr_t BNetFirstStateGetterCaller043 = 0x2BA24C6;
        std::uintptr_t BNetFirstStateGetterCaller044 = 0x2BE09B6;
        std::uintptr_t BNetFirstStateGetterCaller045 = 0x2BE09C8;
        std::uintptr_t BNetFirstStateGetterCaller046 = 0x2C253FF;
        std::uintptr_t BNetFirstStateGetterCaller047 = 0x2C25411;
        std::uintptr_t BNetFirstStateGetterCaller048 = 0x2DC2FF8;
        std::uintptr_t BNetFirstStateGetterCaller049 = 0x2DE25BE;
        std::uintptr_t BNetFirstStateGetterCaller050 = 0x2DE25D4;
        std::uintptr_t BNetFirstStateGetterCaller051 = 0x2E03D6B;
        std::uintptr_t BNetFirstStateGetterCaller052 = 0x2E03D7D;
        std::uintptr_t BNetFirstStateGetterCaller053 = 0x2E82806;
        std::uintptr_t BNetFirstStateGetterCaller054 = 0x2E82814;
        std::uintptr_t BNetFirstStateGetterCaller055 = 0x2E82826;
        std::uintptr_t BNetFirstStateGetterCaller056 = 0x3168BA3;
        std::uintptr_t BNetFirstStateGetterCaller057 = 0x3168BB8;
        std::uintptr_t BNetFirstStateGetterCaller058 = 0x32B927F;
        std::uintptr_t BNetFirstStateGetterCaller059 = 0x32B93AA;
        std::uintptr_t BNetFirstStateGetterCaller060 = 0x32B93C9;
        std::uintptr_t BNetFirstStateGetterCaller061 = 0x32B96D3;
        std::uintptr_t BNetFirstStateGetterCaller062 = 0x32ECBD2;
        std::uintptr_t BNetFirstStateGetterCaller063 = 0x32ECCFD;
        std::uintptr_t BNetFirstStateGetterCaller064 = 0x32ECD1C;
        std::uintptr_t BNetFirstStateGetterCaller065 = 0x32ED026;
        std::uintptr_t BNetFirstStateGetterCaller066 = 0x3DAA87B;
        std::uintptr_t BNetFirstStateGetterCaller067 = 0x3DAA9A6;
        std::uintptr_t BNetFirstStateGetterCaller068 = 0x3DAA9C5;
        std::uintptr_t BNetFirstStateGetterCaller069 = 0x3DAACCF;
        std::uintptr_t BNetFirstStateGetterCaller070 = 0x3DF7872;
        std::uintptr_t BNetFirstStateGetterCaller071 = 0x3DF799D;
        std::uintptr_t BNetFirstStateGetterCaller072 = 0x3DF79BC;
        std::uintptr_t BNetFirstStateGetterCaller073 = 0x3DF7CC6;
        std::uintptr_t BNetFirstStateGetterCaller074 = 0x3E67DEB;
        std::uintptr_t BNetFirstStateGetterCaller075 = 0x3E67F16;
        std::uintptr_t BNetFirstStateGetterCaller076 = 0x3E67F35;
        std::uintptr_t BNetFirstStateGetterCaller077 = 0x3E6823F;
        std::uintptr_t BNetFirstStateGetterCaller078 = 0x3EAAD99;
        std::uintptr_t BNetFirstStateGetterCaller079 = 0x3EAAEC4;
        std::uintptr_t BNetFirstStateGetterCaller080 = 0x3EAAEE3;
        std::uintptr_t BNetFirstStateGetterCaller081 = 0x3EAB1ED;
        std::uintptr_t BNetFirstStateGetterCaller082 = 0x4236C9B;
        std::uintptr_t BNetFirstStateGetterCaller083 = 0x4236CAD;
        std::uintptr_t BNetFirstStateGetterCaller084 = 0x4465B79;
        std::uintptr_t BNetFirstStateGetterCaller085 = 0x4465B8B;
        std::uintptr_t BNetFirstStateGetterCaller086 = 0x4466458;
        std::uintptr_t BNetFirstStateGetterCaller087 = 0x446646D;
        std::uintptr_t BNetFirstStateGetterCaller088 = 0x460AFBD;
        std::uintptr_t BNetFirstStateGetterCaller089 = 0x460B0E8;
        std::uintptr_t BNetFirstStateGetterCaller090 = 0x460B105;
        std::uintptr_t BNetFirstStateGetterCaller091 = 0x460B3E7;
        std::uintptr_t BNetFirstStateGetterCaller092 = 0x4647869;
        std::uintptr_t BNetFirstStateGetterCaller093 = 0x464790E;
        std::uintptr_t BNetFirstStateGetterCaller094 = 0x4647981;
        std::uintptr_t BNetFirstStateGetterCaller095 = 0x46479B7;
        std::uintptr_t BNetFirstStateGetterCaller096 = 0x4649B98;
        std::uintptr_t BNetFirstStateGetterCaller097 = 0x4649BB4;
        std::uintptr_t BNetFirstStateGetterCaller098 = 0x4649C04;
        std::uintptr_t BNetFirstStateGetterCaller099 = 0x4649C0E;
        std::uintptr_t BNetFirstStateGetterCaller100 = 0x4649C74;
        std::uintptr_t BNetFirstStateGetterCaller101 = 0x4649CB4;
        std::uintptr_t BNetFirstStateGetterCaller102 = 0x4649CE4;
        std::uintptr_t BNetFirstStateGetterCaller103 = 0x464A8A9;
        std::uintptr_t BNetFirstStateGetterCaller104 = 0x464AE3F;
        std::uintptr_t BNetFirstStateGetterCaller105 = 0x464B9CF;
        std::uintptr_t BNetFirstStateGetterCaller106 = 0x464D06C;
        std::uintptr_t BNetFirstStateGetterCaller107 = 0x464D29B;
        std::uintptr_t BNetFirstStateGetterCaller108 = 0x464D491;
        std::uintptr_t BNetFirstStateGetterCaller109 = 0x4650F73;
        std::uintptr_t BNetFirstStateGetterCaller110 = 0x4650F85;
        std::uintptr_t BNetFirstStateGetterCaller111 = 0x5AE61BA;
        std::uintptr_t BNetFirstStateGetterCaller112 = 0x5AE61D0;
        std::uintptr_t BNetFirstStateGetterCaller113 = 0x628F6E1;
        std::uintptr_t BNetFirstStateGetterCaller114 = 0x628F6EF;
        std::uintptr_t BNetFirstStateGetterCaller115 = 0x628F701;
        std::uintptr_t BNetFirstStateGetterCaller116 = 0x628F9B1;
        std::uintptr_t BNetFirstStateGetterCaller117 = 0x628F9BF;
        std::uintptr_t BNetFirstStateGetterCaller118 = 0x628F9D1;
        std::uintptr_t BNetFirstStateGetterCaller119 = 0x628FE56;
        std::uintptr_t BNetFirstStateGetterCaller120 = 0x628FF26;
        std::uintptr_t BNetFirstStateGetterCaller121 = 0x62900D6;
        std::uintptr_t BNetFirstStateGetterCaller122 = 0x6292449;
        std::uintptr_t BNetFirstStateGetterCaller123 = 0x6292457;
        std::uintptr_t BNetFirstStateGetterCaller124 = 0x6292469;
        std::uintptr_t BNetFirstStateGetterCaller125 = 0x629247B;
        std::uintptr_t BNetFirstStateGetterCaller126 = 0x629E160;
        std::uintptr_t BNetFirstStateGetterCaller127 = 0x629E183;
        std::uintptr_t BNetFirstStateGetterCaller128 = 0x62B4E5E;
        std::uintptr_t BNetFirstStateGetterCaller129 = 0x62B4E70;
        std::uintptr_t BNetFirstStateGetterCaller130 = 0x62B4F01;
        std::uintptr_t BNetFirstStateGetterCaller131 = 0x62B4F13;
        std::uintptr_t BNetFirstStateGetterCaller132 = 0x62B4FA5;
        std::uintptr_t BNetFirstStateGetterCaller133 = 0x62B4FB7;
        std::uintptr_t BNetFirstStateGetterCaller134 = 0x650BC06;
        std::uintptr_t BNetFirstStateGetterCaller135 = 0x650BC14;
        std::uintptr_t BNetFirstStateGetterCaller136 = 0x650BC26;
        std::uintptr_t BNetFirstStateGetterCaller137 = 0x650C1B1;
        std::uintptr_t BNetFirstStateGetterCaller138 = 0x650C1C3;
        std::uintptr_t BNetFirstStateGetterCaller139 = 0x6518FC9;
        std::uintptr_t BNetFirstStateGetterCaller140 = 0x6518FDB;
        std::uintptr_t BNetFirstStateGetterCaller141 = 0x6524CB8;
        std::uintptr_t BNetFirstStateGetterCaller142 = 0x6524DE3;
        std::uintptr_t BNetFirstStateGetterCaller143 = 0x6524E00;
        std::uintptr_t BNetFirstStateGetterCaller144 = 0x65250E2;
        std::uintptr_t BNetFirstStateGetterCaller145 = 0x66682BC;
        std::uintptr_t BNetFirstStateGetterCaller146 = 0x66682D1;
        std::uintptr_t BNetFirstStateGetterCaller147 = 0x666E13C;
        std::uintptr_t BNetFirstStateGetterCaller148 = 0x666E14E;
        std::uintptr_t BNetPrerequisiteBoolCaller01 = 0x4647873;
        std::uintptr_t BNetPrerequisiteBoolCaller02 = 0x4649D1A;
        std::uintptr_t BNetPostFenceBoolInnerCaller01 = 0x463F079;
        std::uintptr_t BNetPostFenceBoolInnerCaller02 = 0x463F7C4;
        std::uintptr_t DemonwareSignedInCaller01 = 0x28834B4;
        std::uintptr_t DemonwareSignedInCaller02 = 0x29D90BE;
        std::uintptr_t DemonwareSignedInCaller03 = 0x29E8B9E;
        std::uintptr_t DemonwareSignedInCaller04 = 0x2B1F96D;
        std::uintptr_t DemonwareSignedInCaller05 = 0x2B69DEF;
        std::uintptr_t DemonwareSignedInCaller06 = 0x2BC32B2; // JMP
        std::uintptr_t DemonwareSignedInCaller07 = 0x2BD4AE4;
        std::uintptr_t DemonwareSignedInCaller08 = 0x2BDD282;
        std::uintptr_t DemonwareSignedInCaller09 = 0x2BEB796;
        std::uintptr_t DemonwareSignedInCaller10 = 0x2BF0AC7;
        std::uintptr_t DemonwareSignedInCaller11 = 0x2BF0BD8;
        std::uintptr_t DemonwareSignedInCaller12 = 0x2BFD323;
        std::uintptr_t DemonwareSignedInCaller13 = 0x2BFD962;
        std::uintptr_t DemonwareSignedInCaller14 = 0x2C034F1;
        std::uintptr_t DemonwareSignedInCaller15 = 0x2C1A90C;
        std::uintptr_t DemonwareSignedInCaller16 = 0x2C1AA2E;
        std::uintptr_t DemonwareSignedInCaller17 = 0x2C2BDF6;
        std::uintptr_t DemonwareSignedInCaller18 = 0x2D69933;
        std::uintptr_t DemonwareSignedInCaller19 = 0x2DD6547;
        std::uintptr_t DemonwareSignedInCaller20 = 0x2DD70AA;
        std::uintptr_t DemonwareSignedInCaller21 = 0x2DD7112;
        std::uintptr_t DemonwareSignedInCaller22 = 0x2DD81F7;
        std::uintptr_t DemonwareSignedInCaller23 = 0x2DD886D;
        std::uintptr_t DemonwareSignedInCaller24 = 0x2DDA331;
        std::uintptr_t DemonwareSignedInCaller25 = 0x2DDB1B9;
        std::uintptr_t DemonwareSignedInCaller26 = 0x2DDBF5B;
        std::uintptr_t DemonwareSignedInCaller27 = 0x2DDC2C6;
        std::uintptr_t DemonwareSignedInCaller28 = 0x2DDC303;
        std::uintptr_t DemonwareSignedInCaller29 = 0x2DDCEE1;
        std::uintptr_t DemonwareSignedInCaller30 = 0x2DDE52D;
        std::uintptr_t DemonwareSignedInCaller31 = 0x2DDE93A;
        std::uintptr_t DemonwareSignedInCaller32 = 0x2DE23E7;
        std::uintptr_t DemonwareSignedInCaller33 = 0x2DE8E68;
        std::uintptr_t DemonwareSignedInCaller34 = 0x2DF9CED;
        std::uintptr_t DemonwareSignedInCaller35 = 0x2DFD3B1;
        std::uintptr_t DemonwareSignedInCaller36 = 0x2DFD434;
        std::uintptr_t DemonwareSignedInCaller37 = 0x2DFDDE0;
        std::uintptr_t DemonwareSignedInCaller38 = 0x2E01060;
        std::uintptr_t DemonwareSignedInCaller39 = 0x2E010E6;
        std::uintptr_t DemonwareSignedInCaller40 = 0x3168CF9;
        std::uintptr_t DemonwareSignedInCaller41 = 0x31969A5;
        std::uintptr_t DemonwareSignedInCaller42 = 0x33E082D;
        std::uintptr_t DemonwareSignedInCaller43 = 0x33E237F;
        std::uintptr_t DemonwareSignedInCaller44 = 0x33E2923;
        std::uintptr_t DemonwareSignedInCaller45 = 0x33ECBFD;
        std::uintptr_t DemonwareSignedInCaller46 = 0x33EE740;
        std::uintptr_t DemonwareSignedInCaller47 = 0x3A21B2F;
        std::uintptr_t DemonwareSignedInCaller48 = 0x3A21FCF;
        std::uintptr_t DemonwareSignedInCaller49 = 0x3A21FF2;
        std::uintptr_t DemonwareSignedInCaller50 = 0x3D1E2D0;
        std::uintptr_t DemonwareSignedInCaller51 = 0x3D1E387;
        std::uintptr_t DemonwareSignedInCaller52 = 0x3D2158F;
        std::uintptr_t DemonwareSignedInCaller53 = 0x3D21608;
        std::uintptr_t DemonwareSignedInCaller54 = 0x4396B44;
        std::uintptr_t DemonwareSignedInCaller55 = 0x45FFB57;
        std::uintptr_t DemonwareSignedInCaller56 = 0x5663F82;
        std::uintptr_t DemonwareSignedInCaller57 = 0x61E9129;
        std::uintptr_t DemonwareSignedInCaller58 = 0x61EA59B;
        std::uintptr_t DemonwareSignedInCaller59 = 0x61EAC0B;
        std::uintptr_t DemonwareSignedInCaller60 = 0x61ED0EC;
        std::uintptr_t DemonwareSignedInCaller61 = 0x61ED1E1;
        std::uintptr_t DemonwareSignedInCaller62 = 0x61EF297;
        std::uintptr_t DemonwareSignedInCaller63 = 0x6287FB3;
        std::uintptr_t DemonwareSignedInCaller64 = 0x6294A74;
        std::uintptr_t DemonwareSignedInCaller65 = 0x63E4771;
        std::uintptr_t DemonwareSignedInCaller66 = 0x6513167;
        std::uintptr_t DemonwareSignedInCaller67 = 0x65131BB;
        std::uintptr_t DemonwareSignedInCaller68 = 0x651339A;

        std::uintptr_t DwLogOnStatusCaller01 = 0x2B977D1;
        std::uintptr_t DwLogOnStatusCaller02 = 0x2BE0358;
        std::uintptr_t DwLogOnStatusCaller03 = 0x2D5EFA6;
        std::uintptr_t DwLogOnStatusCaller04 = 0x2D611BE;
        std::uintptr_t DwLogOnStatusCaller05 = 0x2D613B3;
        std::uintptr_t DwLogOnStatusCaller06 = 0x2D7A701;
        std::uintptr_t DwLogOnStatusCaller07 = 0x33E083C;
        std::uintptr_t DwLogOnStatusCaller08 = 0x33E28BB;
        std::uintptr_t DwLogOnStatusCaller09 = 0x33E38AD;
        std::uintptr_t DwLogOnStatusCaller10 = 0x33EB87A;
        std::uintptr_t DwLogOnStatusCaller11 = 0x39CE92A;
        std::uintptr_t DwLogOnStatusCaller12 = 0x39CF55A;
        std::uintptr_t DwLogOnStatusCaller13 = 0x39CF638;
        std::uintptr_t DwLogOnStatusCaller14 = 0x39CF736;
        std::uintptr_t DwLogOnStatusCaller15 = 0x39CFE04;
        std::uintptr_t DwLogOnStatusCaller16 = 0x39CFED2;
        std::uintptr_t DwLogOnStatusCaller17 = 0x39CFEF2;
        std::uintptr_t DwLogOnStatusCaller18 = 0x39D08C2;
        std::uintptr_t DwLogOnStatusCaller19 = 0x39D0A47;
        std::uintptr_t DwLogOnStatusCaller20 = 0x39D33F8;
        std::uintptr_t DwLogOnStatusCaller21 = 0x3C1CFBD;
        std::uintptr_t DwLogOnStatusCaller22 = 0x3C1E003;
        std::uintptr_t DwLogOnStatusCaller23 = 0x3C1E630;
        std::uintptr_t DwLogOnStatusCaller24 = 0x3C1E748;
        std::uintptr_t DwLogOnStatusCaller25 = 0x3D01393;
        std::uintptr_t DwLogOnStatusCaller26 = 0x3D0153E;
        std::uintptr_t DwLogOnStatusCaller27 = 0x3D02033;
        std::uintptr_t DwLogOnStatusCaller28 = 0x3D021EE;
        std::uintptr_t DwLogOnStatusCaller29 = 0x3D02351;
        std::uintptr_t DwLogOnStatusCaller30 = 0x3D024B4;
        std::uintptr_t DwLogOnStatusCaller31 = 0x3D216C0;
        std::uintptr_t DwLogOnStatusCaller32 = 0x3D217DB;
        std::uintptr_t DwLogOnStatusCaller33 = 0x3D21866;
        std::uintptr_t DwLogOnStatusCaller34 = 0x3D22852;
        std::uintptr_t DwLogOnStatusCaller35 = 0x3D235E3;
        std::uintptr_t DwLogOnStatusCaller36 = 0x3D5B398;
        std::uintptr_t DwLogOnStatusCaller37 = 0x3D5B742;
        std::uintptr_t DwLogOnStatusCaller38 = 0x3D5B8E2;
        std::uintptr_t DwLogOnStatusCaller39 = 0x3D5D554;
        std::uintptr_t DwLogOnStatusCaller40 = 0x3D5E151;
        std::uintptr_t DwLogOnStatusCaller41 = 0x3D61731;
        std::uintptr_t DwLogOnStatusCaller42 = 0x3F5C448;
        std::uintptr_t DwLogOnStatusCaller43 = 0x6558586;

        // Direct dependencies decoded from the confirmed 1.44
        // unk_IsUserSignedInToBNet code window. The first call returns a pointer
        // whose dword is compared with 2 before any later BNet fence checks.
        std::uintptr_t BNetSignInFirstStateGetter = 0x4642000;
        std::uintptr_t BNetSignInFirstStateSnapshotHelper = 0x4642010;
        std::uintptr_t BNetSignInPrereqBool = 0x463FF00;
        std::uintptr_t BNetSignInPrereqInit = 0x463FF10;
        std::uintptr_t BNetSignInFenceObjectGetter = 0x46574E0;
        std::uintptr_t BNetSignInFenceObjectGetterAlias = 0x46574F0;
        std::uintptr_t BNetSignInPostFenceObjectGetter = 0x46573E0;
        std::uintptr_t BNetSignInPostFenceObjectGetter2 = 0x46573F0;
        std::uintptr_t BNetSignInPostFenceObjectGetter3 = 0x4657400;
        std::uintptr_t BNetSignInRelatedObjectGetter = 0x4657470;
        std::uintptr_t BNetSignInPostFenceBool = 0x463F7C0;
        std::uintptr_t BNetSignInPostFenceBoolInner = 0x463F4D0;
        std::uintptr_t BNetFailurePathHelper1 = 0x4644D00;
        std::uintptr_t BNetFailurePathStateGetter = 0x4644D10;

        // Auth-cluster helpers decoded from the WEB_TOKEN parent frame at
        // game+0x464798E. REFERENCE/READ_ONLY: the key pattern is
        // CALL BNetSignInFirstStateGetter -> MOV RCX,RAX -> CALL 0x4641D40,
        // making 0x4641D40 the current stock first-state pump candidate.
        std::uintptr_t BNetAuthClusterPrePumpHelper = 0x4644C50;
        std::uintptr_t BNetFirstStatePumpCandidate = 0x4641D40;
        std::uintptr_t BNetFirstStatePumpNonzeroBranch = 0x4641D5B; // JNE when [stateObject] != 0
        std::uintptr_t BNetFirstStatePumpEarlyReturnEpilogue = 0x4641E4D; // target of nonzero JNE; common return/epilogue, NOT a state-1 processor
        std::uintptr_t BNetFirstStatePumpState1Path = 0x4641E4D; // LEGACY MISNOMER kept for source compatibility; use BNetFirstStatePumpEarlyReturnEpilogue
        // Confirmed from the WEB_TOKEN consumer #2 code window inside the same
        // pump function: CALL 0x4647550; TEST AL,AL; JNZ +0x42; MOV [RBX],3.
        // The write is a candidate first-state failure transition until the next
        // read-only pass proves RBX aliases the RCX state pointer.
        std::uintptr_t BNetFirstStatePumpGuard = 0x4647550;
        // The guard begins by scanning six 0x28-byte descriptors at this table,
        // comparing the first dword of each entry against its ECX selector. The
        // runtime observer uses this only to report which descriptor was selected.
        std::uintptr_t BNetFirstStatePumpGuardDescriptorTable = 0x9BF6B40;
        std::uintptr_t BNetFirstStatePumpGuardDescriptorCount = 6;
        std::uintptr_t BNetFirstStatePumpGuardDescriptorStride = 0x28;
        std::uintptr_t BNetFirstStatePumpGuardLauncherContextHelper = 0x4646C40;
        std::uintptr_t BNetFirstStatePumpGuardNoDescriptorTarget = 0x4647804;
        std::uintptr_t BNetFirstStatePumpGuardCall = 0x4641DA8;
        std::uintptr_t BNetFirstStatePumpGuardResultTest = 0x4641DAD; // TEST AL,AL
        std::uintptr_t BNetFirstStatePumpGuardSuccessJnz = 0x4641DAF; // JNZ +0x42 when guard returns true
        std::uintptr_t BNetFirstStateWrite3Candidate = 0x4641DB1;     // false fallthrough: MOV DWORD PTR [RBX],3
        std::uintptr_t BNetFirstStatePumpGuardTrueTarget = 0x4641DF3; // 0x4641DAF + 2 + 0x42

        // Additional code topology recovered by the 2026-08-28 safe read-only
        // pass. Calls 01-07 are inside the first-state pump through its cookie
        // epilogue. Calls 08-13 are neighboring code reached only because the old
        // static window extended past the pump return; names are retained for
        // source compatibility and MUST NOT be treated as pump execution.
        std::uintptr_t BNetFirstStatePumpCall01 = 0x4641D61;
        std::uintptr_t BNetFirstStatePumpCall01Target = 0x4644D10;
        std::uintptr_t BNetFirstStatePumpCall02 = 0x4641D77;
        std::uintptr_t BNetFirstStatePumpCall02Target = 0x4642170;
        std::uintptr_t BNetFirstStatePumpCall03 = 0x4641DA8;
        std::uintptr_t BNetFirstStatePumpCall03Target = 0x4647550;
        std::uintptr_t BNetFirstStatePumpCall04 = 0x4641DCD;
        std::uintptr_t BNetFirstStatePumpCall04Target = 0x4641DCA;
        std::uintptr_t BNetFirstStatePumpCall05 = 0x4641E0F;
        std::uintptr_t BNetFirstStatePumpCall05Target = 0x4643E70;
        std::uintptr_t BNetFirstStatePumpCall06 = 0x4641E36;
        std::uintptr_t BNetFirstStatePumpCall06Target = 0x8716F0;
        std::uintptr_t BNetFirstStatePumpCall07 = 0x4641E55;
        std::uintptr_t BNetFirstStatePumpCall07Target = 0x6D41DC0;
        std::uintptr_t BNetFirstStatePumpCall08 = 0x4641ED6; // LEGACY NAME: neighboring function, not first-state pump
        std::uintptr_t BNetFirstStatePumpCall08Target = 0x65CA30;
        std::uintptr_t BNetFirstStatePumpCall09 = 0x4641EFC;
        std::uintptr_t BNetFirstStatePumpCall09Target = 0x8716F0;
        std::uintptr_t BNetFirstStatePumpCall10 = 0x4641F7C;
        std::uintptr_t BNetFirstStatePumpCall10Target = 0x5B7DB0;
        std::uintptr_t BNetFirstStatePumpCall11 = 0x4641F9C;
        std::uintptr_t BNetFirstStatePumpCall11Target = 0x8716F0;
        std::uintptr_t BNetFirstStatePumpCall12 = 0x4641FC2;
        std::uintptr_t BNetFirstStatePumpCall12Target = 0x6D41DC0;
        std::uintptr_t BNetFirstStatePumpCall13 = 0x4641FDB;
        std::uintptr_t BNetFirstStatePumpCall13Target = 0x6D41DC0;
        std::uintptr_t BNetFirstStatePumpWriteState1 = 0x4641E14;
        std::uintptr_t BNetFirstStatePumpSnapshotInitWrite0 = 0x4642019; // LEGACY NAME: snapshot helper function, not pump
        std::uintptr_t BNetFirstStatePumpSnapshotValueWrite = 0x4642028; // LEGACY NAME: snapshot helper function, not pump
        std::uintptr_t BNetFirstStateSnapshotInitWrite0 = 0x4642019;
        std::uintptr_t BNetFirstStateSnapshotValueWrite = 0x4642028;

        // V4 resolved the two apparent asynchronous-writer hits as false leads.
        // Candidate #1 is a STATE-2 CONSUMER: CALL getter -> CMP [RAX],2 -> JNE
        // reject, then it also requires byte [state+0x2D0] != 0 before deriving
        // an object at state+0x2D4. Candidate #2 was a byte-pattern false positive:
        // the apparent 89 00 at 0x3DAA9C8 lies inside the rel32 displacement of
        // the getter CALL at 0x3DAA9C5. Legacy candidate names are retained only
        // for source compatibility; neither address is a confirmed state writer.
        std::uintptr_t BNetFirstStateAsyncWriterCandidate1Call = 0x2AD9513; // LEGACY FALSE LEAD: state-2 consumer object getter
        std::uintptr_t BNetFirstStateAsyncWriterCandidate1WindowStart = 0x2AD94C0;
        std::uintptr_t BNetFirstStateAsyncWriterCandidate2Call = 0x3DAA9A6; // LEGACY FALSE LEAD: obfuscated read path
        std::uintptr_t BNetFirstStateAsyncWriterCandidate2WindowStart = 0x3DAA950;
        std::uintptr_t BNetFirstState2ConsumerGetterCall = 0x2AD94EA;
        std::uintptr_t BNetFirstState2ConsumerCompare = 0x2AD94F8; // CMP DWORD PTR [RAX],2
        std::uintptr_t BNetFirstState2ConsumerRejectJne = 0x2AD94FB;
        std::uintptr_t BNetFirstState2ConsumerRejectTarget = 0x2AD9B94;
        std::uintptr_t BNetFirstState2ConsumerSnapshotGetterCall = 0x2AD9501;
        std::uintptr_t BNetFirstState2ConsumerSnapshotCompare = 0x2AD9506; // CMP BYTE PTR [RAX+0x2D0],SIL
        std::uintptr_t BNetFirstState2ConsumerSnapshotRejectJe = 0x2AD950D;
        std::uintptr_t BNetFirstState2ConsumerObjectGetterCall = 0x2AD9513;
        std::uintptr_t BNetFirstState2ConsumerObjectLea = 0x2AD9518; // LEA R10,[RAX+0x2D4]
        std::uintptr_t BNetFirstStateFalseWriter2PostCallJmp = 0x3DAA9AC;
        std::uintptr_t BNetFirstStateFalseWriter2SecondGetterCall = 0x3DAA9C5;
        std::uintptr_t BNetFirstStateFalseWriter2BogusStoreByte = 0x3DAA9C8; // inside CALL rel32; NOT an instruction boundary

        // Confirmed by the process-wide first-state PAGE_GUARD capture on the
        // 1.44 stock auth response path. These writes execute after the local
        // AuthenticationListener/Logon reply is received. They are reference-only:
        // the client must still reach state 2 naturally from correct backend data.
        std::uintptr_t BNetAuthResultInitByteWriter = 0x46429DE;   // C6 87 B8 01 00 00 00 -> [state+0x1B8] = 0
        std::uintptr_t BNetAuthResultInitDwordWriter = 0x46429E5;  // 89 87 BC 01 00 00 -> [state+0x1BC] = EAX
        std::uintptr_t BNetAuthResultInitQwordWriter = 0x46429EB;  // 48 89 87 C0 01 00 00 -> [state+0x1C0] = RAX
        std::uintptr_t BNetAuthFailureState3Writer = 0x4642A2A;    // C7 07 03 00 00 00 -> firstState = 3
        std::uintptr_t BNetAuthFailureErrorWriter = 0x4642ABE;     // C7 87 C8 01 00 00 03 FF FF 7F
        std::uintptr_t BNetAuthFailureErrorJump = 0x4642AC8;       // JMP back to BNetAuthFailureState3Writer
        std::uintptr_t BNetAuthFailureError4Writer = 0x4642AD5;    // C7 87 C8 01 00 00 04 FF FF 7F
        std::uintptr_t BNetAuthFailureError4Jump = 0x4642ADF;      // JMP back to BNetAuthFailureState3Writer

        // V6 materialized-code decode of the same AuthenticationListener result
        // callback. These are structural success/failure gates only; they are
        // never patched and do not imply the current reply executed every branch.
        std::uintptr_t BNetAuthResponseErrorCodeLoad = 0x46429F2;          // MOV EDX,[RSI+0x38]
        std::uintptr_t BNetAuthResponseErrorCodeTest = 0x46429F5;          // TEST EDX,EDX
        std::uintptr_t BNetAuthResponseNoErrorBranch = 0x46429F7;          // JE -> 0x4642A65
        std::uintptr_t BNetAuthResponseNoErrorTarget = 0x4642A65;
        std::uintptr_t BNetAuthSuccessValidation1Call = 0x4642A80;         // CALL 0x46597C0
        std::uintptr_t BNetAuthSuccessValidation1RejectJcc = 0x4642A87;    // JE -> 0x4642CEF
        std::uintptr_t BNetAuthRequiredField28Compare = 0x4642A8D;         // CMP DWORD PTR [RSI+0x28],0
        std::uintptr_t BNetAuthRequiredField28RejectJcc = 0x4642A91;       // JE -> 0x4642CEF
        std::uintptr_t BNetAuthSuccessValidation2Call = 0x4642AA5;         // CALL 0x46597E0
        std::uintptr_t BNetAuthSuccessValidation2RejectJcc = 0x4642AAC;    // JE -> 0x4642CEF
        std::uintptr_t BNetAuthFlag6Test = 0x4642ABA;                      // TEST bit 6-derived AL,1
        std::uintptr_t BNetAuthFlag10Test = 0x4642AD0;                     // TEST bit 10-derived CL,1
        std::uintptr_t BNetAuthSuccessContinuation = 0x4642AE4;            // success-side payload copies continue here
        std::uintptr_t BNetAuthResultHandlerEntry = 0x4642950;              // materialized auth-result callback entry
        std::uintptr_t BNetAuthStructuralFailureState3Writer = 0x4642CEF;   // C7 07 03 00 00 00; validation reject path
        std::uintptr_t BNetAuthStructuralFailureError2Writer = 0x4642CF5;   // C7 87 C8 01 00 00 02 FF FF 7F
        std::uintptr_t BNetAuthFlag7Load = 0x4642C90;                       // MOV EAX,[RSI+0x10]
        std::uintptr_t BNetAuthFlag7Test = 0x4642C96;                       // TEST AL,1 after SHR EAX,7
        std::uintptr_t BNetAuthFlag7AbsentBranch = 0x4642C98;               // JE -> 0x4642CE1
        std::uintptr_t BNetAuthFlag7AbsentTarget = 0x4642CE1;
        std::uintptr_t BNetAuthFlag7AbsentHelperCall = 0x4642CE8;           // CALL 0x4641A60
        std::uintptr_t BNetAuthFlag7AbsentHelperTarget = 0x4641A60;
        std::uintptr_t BNetAuthResultHandlerEpilogue = 0x4642D2F;
        std::uintptr_t BNetAuthResultHandlerReturn = 0x4642D51;             // normal callback return; no literal state-2 store in handler

        // V8 consumer scan confirmed the real stock ready-state commit OUTSIDE
        // the auth-result handler. Note: 0x4641807 is only the +0x1C8 operand
        // displacement; decoding the bytes puts MOV [RCX],2 at 0x46417FF.
        std::uintptr_t BNetAuthSuccessState2Entry = 0x46417C0;               // obfuscated success routine entry; apparent direct call at 0x464314C is skipped by EB 08 at 0x4643147
        std::uintptr_t BNetAuthSuccessState2Writer = 0x46417FF;              // C7 01 02 00 00 00 -> [RCX] = 2
        std::uintptr_t BNetAuthSuccessErrorWriter = 0x4641805;               // 89 99 C8 01 00 00 -> [RCX+0x1C8] = EBX
        std::uintptr_t BNetAuthSuccessErrorDisp = 0x4641807;                 // +0x1C8 displacement bytes inside instruction above
        std::uintptr_t BNetAuthSuccessCommitWindowStart = 0x4641600;
        std::uintptr_t BNetAuthSuccessCommitWindowEnd = 0x4641940;
        std::uintptr_t BNetAuthSuccessDeadDirectCall = 0x464314C;            // E8 -> 0x46417C0, but skipped by unconditional jump below
        std::uintptr_t BNetAuthSuccessDeadSkipJmp = 0x4643147;               // EB 08 -> 0x4643151
        std::uintptr_t BNetAuthSuccessDeadSkipTarget = 0x4643151;

        // V13/V14 resolved these nearby routines as auth-object field accessors,
        // not State-2 producers. Keep them labeled by what they actually return.
        std::uintptr_t BNetAuthFieldA8AddressAccessor = 0x46416E0;   // LEA RAX,[auth+0xA8]; RET
        std::uintptr_t BNetAuthFieldF0LoadAccessor = 0x46416F0;      // MOV RAX,[auth+0xF0]; RET
        std::uintptr_t BNetAuthField118AddressAccessor = 0x46417B0;  // LEA RAX,[auth+0x118]; RET
        std::uintptr_t BNetAuthFieldA8AddressAccessorAlias = 0x4653A20; // JMP 0x46416E0
        std::uintptr_t BNetAuthFieldA8OwnerSlot = 0x9BF0958;         // auth base + 0xA8
        std::uintptr_t BNetAuthFieldA8FunctionTable = 0x7104948;     // live table observed in +0xA8
        std::uintptr_t BNetAuthFieldC8OwnerSlot = 0x9BF0978;         // auth base + 0xC8
        std::uintptr_t BNetAuthFieldC8FunctionTable = 0x71044E8;
        std::uintptr_t BNetAuthField318CallbackSlot = 0x9BF0BC8;     // auth base + 0x318
        std::uintptr_t BNetAuthField318Callback = 0x464A840;         // confirmed State-2 consumer, not writer

        // Static windows used by the read-only completion research.
        std::uintptr_t BNetAuthClusterScanStart = 0x463F000;
        std::uintptr_t BNetAuthClusterScanEnd = 0x4660000;
        std::uintptr_t BNetAuthSuccessLocalFlowStart = 0x4641700;
        std::uintptr_t BNetAuthSuccessLocalFlowEnd = 0x4641880;

        std::uintptr_t BNetAuthFailureTraceWindowStart = 0x4642940;
        std::uintptr_t BNetAuthFailureTraceWindowEnd = 0x4642B20;
        // V7 extends the read-only commit search beyond the V6 cutoff because the
        // success-side payload-copy path continues after 0x4642B20.
        std::uintptr_t BNetAuthCommitSearchWindowStart = 0x4642940;
        std::uintptr_t BNetAuthCommitSearchWindowEnd = 0x4642E80;

        // Other exact write instructions observed on the same 4 KiB state page
        // during this response. Their offsets are confirmed by PAGE_GUARD, but
        // their higher-level field semantics are intentionally left unresolved.
        std::uintptr_t BNetAuthStatePageWrite_B8 = 0x675A82;
        std::uintptr_t BNetAuthStatePageWrite_C0 = 0x675A86;
        std::uintptr_t BNetAuthStatePageWrite_D8 = 0x675B2B;
        std::uintptr_t BNetAuthStatePageWrite_E8 = 0x675B3A;
        std::uintptr_t BNetAuthStatePageWrite_E0 = 0x675B3E;
        std::uintptr_t BNetAuthStatePageWrite_E4 = 0x675B42;

        // Confirmed state-object field layout from those exact writes.
        std::uintptr_t BNetAuthResultField1B8Offset = 0x1B8;
        std::uintptr_t BNetAuthResultField1BCOffset = 0x1BC;
        std::uintptr_t BNetAuthResultField1C0Offset = 0x1C0;
        std::uintptr_t BNetAuthResultField1C8Offset = 0x1C8;
        std::uintptr_t BNetFirstStateSnapshotObjectOffset = 0x1CC;
        std::uintptr_t BNetFirstStateSnapshotValueOffset = 0x2CC;
        std::uintptr_t BNetFirstStateSnapshotInitOffset = 0x2D0;

        // Observed auth-object fields populated after the local 236-byte auth
        // response + 149-byte client follow-up + 64-byte server reply. Names are
        // intentionally neutral until the stock state-1 path identifies their use.
        std::uintptr_t BNetAuthObservedOffset0B8 = 0x0B8; // 00 -> 01
        std::uintptr_t BNetAuthObservedOffset0C0 = 0x0C0; // 00 -> 01
        std::uintptr_t BNetAuthObservedOffset0D8 = 0x0D8; // 00 -> 07
        std::uintptr_t BNetAuthObservedOffset0E0 = 0x0E0; // 00 -> 01
        std::uintptr_t BNetAuthObservedProgramOffset = 0x0E4; // "ODIN" + trailing 02
        std::uintptr_t BNetAuthObservedOffset0F8 = 0x0F8; // 00 -> 0D
        std::uintptr_t BNetAuthObservedAccountNameOffset = 0x108; // "Revamped#0001"
        std::uintptr_t BNetAuthObservedPointerOffset = 0x118;
        std::uintptr_t BNetAuthObservedOffset120 = 0x120; // 00 -> 12
        std::uintptr_t BNetAuthObservedOffset128 = 0x128; // 0F -> 16
        std::uintptr_t BNetAuthObservedOffset12F = 0x12F; // 80 -> 00
        std::uintptr_t BNetAuthObservedOffset198 = 0x198; // 00 -> 02
        std::uintptr_t BNetAuthObservedRegionOffset = 0x1A8; // "US"
        std::uintptr_t BNetAuthErrorCodeOffset = 0x1C8;
        std::uint32_t BNetAuthFailureErrorCode = 0x7FFFFF03u;

        // Confirmed by the 2026-08-27 focused post-auth SessionService trace.
        // The method-1 RPC parses successfully, response field 1 is present,
        // optional field20 is absent but accepted, and stock reaches the normal
        // completion tail without entering the old 0x7FFFFF03/state-3 writer.
        std::uint32_t BgsSessionServiceHash = 0x1E688C05u;
        std::uintptr_t BgsSessionServiceSharedRpcCall = 0x7ADE40;
        std::uintptr_t BgsSessionServiceMethod1Parser = 0x6B4390;
        std::uintptr_t BgsSessionServiceMethod1Caller = 0x7A8A28; // legacy name: observed return frame after shared RPC call
        std::uintptr_t BgsSessionServiceMethod1SharedRpcReturn = 0x7A8A28; // V23 stage-0 landmark
        std::uintptr_t BgsSessionServiceMethod1ResponseVtable = 0x71093C0; // parser-populated response object vtable
        std::uintptr_t BgsSessionServiceRpcResultDecision = 0x6BF39C;
        std::uintptr_t BgsSessionServiceOptionalField20Decision = 0x6BF43B;
        std::uintptr_t BgsSessionServiceNormalNoField20Path = 0x6BF4AE;
        std::uintptr_t BgsSessionServiceNormalPrepCall = 0x6BF4BC;
        std::uintptr_t BgsSessionServiceNormalPrepHelper = 0x5AD810;
        std::uintptr_t BgsSessionServiceNormalVirtualCallback = 0x6BF4E3; // FF 50 08 = CALL qword ptr [RAX+8]
        std::uintptr_t BgsSessionServiceNormalVirtualCallbackReturn = 0x6BF4E6; // post-call NOP
        std::uintptr_t BgsSessionServiceNormalCallbackObjectOffsetFromR14 = 0x8; // LEA RDI,[R14+8] before vcall
        std::uintptr_t BgsSessionServiceNormalCallbackVtableSlotOffset = 0x8; // selected virtual slot
        // V17/V18 live runtime capture: the accepted method-1 normal path
        // calls slot 1 of this callback object's vtable. V18 disassembled slot
        // 1 and proved 0x6C0B20 is a forwarding thunk:
        //   ADD RCX,8 -> resolve tagged/embedded interface -> JMP [vtable+8].
        // It does not mutate the outer object/RDX/R8 buffers itself.
        std::uintptr_t BgsSessionServiceMethod1CallbackVtable = 0x7109520;
        std::uintptr_t BgsSessionServiceMethod1CallbackSlot1 = 0x6C0B20; // forwarding thunk, not final completion body
        std::uintptr_t BgsSessionServiceMethod1CallbackSlot0 = 0x6C0C30;
        std::uintptr_t BgsSessionServiceMethod1CallbackSlot2 = 0x6C0AF0;

        // V18 page-safe xrefs to callback vtable 0x7109520. Keep labels neutral:
        // these functions assign/reference the vtable, but are not yet proven
        // constructors/destructors.
        std::uintptr_t BgsSessionServiceMethod1CallbackVtableWriterA = 0x6C06A0;
        std::uintptr_t BgsSessionServiceMethod1CallbackVtableAssignA = 0x6C07E1;
        std::uintptr_t BgsSessionServiceMethod1CallbackVtableWriterB = 0x6C0AB0;
        std::uintptr_t BgsSessionServiceMethod1CallbackVtableAssignB = 0x6C0AD0;

        // V18/V19 live callback-object layout. +0x8 is the embedded/tagged
        // interface consumed by 0x6C0B20. Its vtable slot 1 resolves to
        // 0x4641710, another tiny delegate dispatcher:
        //   MOV RAX,RCX; MOV RCX,[RCX+0x18]; JMP QWORD PTR [RAX+0x08].
        // Therefore embedded+0x08 (outer+0x10) is the actual invoke function
        // pointer and embedded+0x18 (outer+0x20) is its context. On the live
        // Method-1 path those were 0x4641CF0 and BNetFirstStateValue.
        std::uintptr_t BgsSessionServiceMethod1EmbeddedInterfaceOffset = 0x08;
        std::uintptr_t BgsSessionServiceMethod1ObservedEmbeddedVtable = 0x6F662C8;
        std::uintptr_t BgsSessionServiceMethod1EmbeddedSlot1Dispatch = 0x4641710;
        std::uintptr_t BgsSessionServiceMethod1EmbeddedInvokeTargetOffset = 0x08;
        std::uintptr_t BgsSessionServiceMethod1EmbeddedInvokeContextOffset = 0x18;
        std::uintptr_t BgsSessionServiceMethod1CompanionCodeOffset = 0x10; // outer+0x10 == embedded+0x08
        std::uintptr_t BgsSessionServiceMethod1ObservedCompanionCode = 0x4641CF0; // live delegate invoke pointer
        std::uintptr_t BgsSessionServiceMethod1StateObjectOffset = 0x20; // outer+0x20 == embedded+0x18 context

        // V20: only one focused BGS/BNet code xref takes the address of the
        // default invoke stub 0x4641CF0. It is inside the bounded function
        // 0x4641A60..0x4641CE2. Around that site the function constructs the
        // delegate locally: it takes 0x4641CF0 at 0x4641BF6, takes embedded
        // vtable 0x6F662C8 at 0x4641C0B, then calls 0x4644D10 at 0x4641C1A.
        //
        // V21 correction: a focused direct-caller scan found exactly one CALL
        // to 0x4641A60: 0x4642CE8 inside BNetAuthResultHandlerEntry. This is
        // already the catalogued BNetAuthFlag7AbsentHelperCall reached from the
        // bit-7-absent branch at 0x4642C98 -> 0x4642CE1. Therefore 0x4641A60
        // is not treated as the generic auth-success callback installer; V22
        // observes the live flag-7 gate and this helper path before assigning a
        // protocol meaning to the default delegate.
        std::uintptr_t BgsSessionServiceMethod1DelegateInstallerFunction = 0x4641A60;
        std::uintptr_t BgsSessionServiceMethod1DelegateInstallerFunctionEnd = 0x4641CE2;
        std::uintptr_t BgsSessionServiceMethod1DefaultInvokeAddressLoad = 0x4641BF6;
        std::uintptr_t BgsSessionServiceMethod1DelegateVtableAddressLoad = 0x4641C0B;
        std::uintptr_t BgsSessionServiceMethod1DelegateSubmitCall = 0x4641C1A;
        std::uintptr_t BgsSessionServiceMethod1DelegateSubmitTarget = 0x4644D10;
        std::uintptr_t BgsSessionServiceMethod1DelegatePreInstallCall = 0x4641BF1;
        std::uintptr_t BgsSessionServiceMethod1DelegatePreInstallTarget = 0x5B7DB0;
        std::uintptr_t BgsSessionServiceNormalCleanupCall1 = 0x6BF4F2;
        std::uintptr_t BgsSessionServiceNormalCleanupCall2 = 0x6BF513;
        std::uintptr_t BgsSessionServiceNormalObjectCleanupCall = 0x6BF52D;
        std::uintptr_t BgsSessionServiceNormalSecurityCookieCall = 0x6BF539;
        std::uintptr_t BgsSessionServiceSharedCleanupHelper = 0x8716F0;
        std::uintptr_t BgsSessionServiceObjectCleanupHelper = 0x6B4270;
        std::uintptr_t BgsSessionServiceSecurityCookieHelper = 0x6D41DC0;
        std::uintptr_t BgsSessionServiceNormalHandlerReturn = 0x6BF555;

        // V23 correction: repeated runs proved the transport-size sequence
        // 654 -> 236 -> 149 -> 64 is not sufficient to identify the RPC.
        // V17-V20 reached the Method-1 virtual callback after that sequence,
        // while V22 reproduced the same sizes without executing the callback.
        // The focused pipeline therefore observes these actual code landmarks:
        //   shared-RPC return 0x7A8A28 -> parser 0x6B4390 ->
        //   result decision 0x6BF39C -> optional field20 decision 0x6BF43B ->
        //   normal path 0x6BF4AE -> virtual callback 0x6BF4E3.
        // The protected auth flag-7 gate at 0x4642C90 is armed only after
        // natural firstState=1 so code materialization cannot replace its INT3
        // before the post-auth reply is processed.
        std::uintptr_t BgsSessionServiceMethod1PipelineRpcReturn = 0x7A8A28;
        std::uintptr_t BgsSessionServiceMethod1PipelineParser = 0x6B4390;
        std::uintptr_t BgsSessionServiceMethod1PipelineRpcDecision = 0x6BF39C;
        std::uintptr_t BgsSessionServiceMethod1PipelineField20Decision = 0x6BF43B;
        std::uintptr_t BgsSessionServiceMethod1PipelineNormalPath = 0x6BF4AE;
        std::uintptr_t BgsSessionServiceMethod1PipelineVirtualCallback = 0x6BF4E3;

        // Runtime parser/completion stack captured with firstState=1.  These
        // are correlation landmarks only; the completion probe arms them only
        // after the normal virtual callback is actually reached.
        std::uintptr_t BgsSessionParserStackFrame00 = 0x889E2D;
        std::uintptr_t BgsSessionParserStackFrame01 = 0x88A00D;
        std::uintptr_t BgsSessionParserStackFrame02 = 0x7ADEA8;
        std::uintptr_t BgsSessionParserStackFrame03 = 0x7A8A28;
        std::uintptr_t BgsSessionParserStackFrame04 = 0x6BF39C;
        std::uintptr_t BgsSessionParserStackFrame05 = 0x79365A;
        std::uintptr_t BgsSessionParserStackFrame06 = 0x6C48A0;
        std::uintptr_t BgsSessionParserStackFrame07 = 0x7B39E5;
        std::uintptr_t BgsSessionParserStackFrame08 = 0x7ABB18;
        std::uintptr_t BgsSessionParserStackFrame09 = 0x7F77E4;
        std::uintptr_t BgsSessionParserStackFrame10 = 0x7AB4DA;
        std::uintptr_t BgsSessionParserStackFrame11 = 0x7B2E82;

        // AuthenticationService / AuthenticationListener static dispatch
        // landmarks confirmed by the 2026-08-28 full auth xref pass. These
        // are reference-only protocol dispatch sites; no runtime patching is
        // implied by cataloguing them here.
        std::uint32_t BgsAuthenticationServiceHash = 0x0DECFC01u;
        std::uintptr_t BgsAuthenticationServiceMethod1Dispatch = 0x66F467;
        std::uintptr_t BgsAuthenticationServiceMethod5Dispatch = 0x66FC19;
        std::uintptr_t BgsAuthenticationServiceMethod8Dispatch = 0x6703CD;

        std::uint32_t BgsAuthenticationListenerHash = 0x71240E35u;
        std::uintptr_t BgsAuthenticationListenerMethod4Descriptor = 0x6C1447;
        std::uintptr_t BgsAuthenticationListenerMethod4Dispatch = 0x6C14F5;
        std::uintptr_t BgsAuthenticationListenerMethod4Forward = 0x6C1573;
        std::uintptr_t BgsAuthenticationListenerMethod5Descriptor = 0x6C1637;
        std::uintptr_t BgsAuthenticationListenerMethod5Dispatch = 0x6C16E5;
        std::uintptr_t BgsAuthenticationListenerMethod5Forward = 0x6C1763;
        std::uintptr_t BgsAuthenticationListenerMethod10Descriptor = 0x6C1827;
        std::uintptr_t BgsAuthenticationListenerMethod10Dispatch = 0x6C18D5;
        std::uintptr_t BgsAuthenticationListenerMethod10Forward = 0x6C1953;
        std::uintptr_t BgsAuthenticationListenerMethod11Descriptor = 0x6C1A17;
        std::uintptr_t BgsAuthenticationListenerMethod11Dispatch = 0x6C1AC5;
        std::uintptr_t BgsAuthenticationListenerMethod11Forward = 0x6C1B43;
        std::uintptr_t BgsAuthenticationListenerMethod12Descriptor = 0x6C1C07;
        std::uintptr_t BgsAuthenticationListenerMethod12Dispatch = 0x6C1CB5;
        std::uintptr_t BgsAuthenticationListenerMethod12Forward = 0x6C1D33;
        std::uintptr_t BgsAuthenticationListenerMethod13Dispatch = 0x6C1DF3;
        std::uintptr_t BgsAuthenticationListenerMethod13Forward = 0x6C1E63;


        // Additional AuthenticationService/AuthenticationListener hash xrefs
        // recovered by the same full 1.44 pass. These are intentionally named
        // runtime xrefs because the hash scan proves the service association
        // but does not by itself assign a higher-level callback semantic.
        std::uintptr_t BgsAuthenticationServiceRuntimeXref01 = 0x79247B;
        std::uintptr_t BgsAuthenticationServiceRuntimeXref02 = 0x792593;
        std::uintptr_t BgsAuthenticationServiceRuntimeXref03 = 0x792649;
        std::uintptr_t BgsAuthenticationServiceRuntimeXref04 = 0x792708;
        std::uintptr_t BgsAuthenticationServiceRuntimeXref05 = 0x7927D2;
        std::uintptr_t BgsAuthenticationServiceRuntimeXref06 = 0x792851;
        std::uintptr_t BgsAuthenticationServiceRuntimeXref07 = 0x79293F;
        std::uintptr_t BgsAuthenticationServiceRuntimeXref08 = 0x79296F;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref01 = 0x7A8FAB;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref02 = 0x7A90D0;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref03 = 0x7A91A9;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref04 = 0x7A9282;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref05 = 0x7A934D;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref06 = 0x7A940F;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref07 = 0x7A94D3;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref08 = 0x7A95AC;
        std::uintptr_t BgsAuthenticationListenerRuntimeXref09 = 0x7A962E;

        std::uintptr_t BNetAuthClusterHelper01 = 0x2224A80;
        std::uintptr_t BNetAuthClusterHelper02 = 0x2224240;
        std::uintptr_t BNetPrereqPumpCandidate = 0x463FF60;
        std::uintptr_t BNetPrereqPumpCandidate2 = 0x4640070;
        std::uintptr_t BNetAuthClusterHelper03 = 0x2917190;
        std::uintptr_t BNetAuthClusterHelper04 = 0x3D05850;
        std::uintptr_t BNetAuthClusterHelper05 = 0x33EF1C0;
        std::uintptr_t BNetAuthClusterHelper06 = 0x33ED120;
        std::uintptr_t BNetAuthClusterHelper07 = 0x3A22C90;
        std::uintptr_t BNetAuthClusterLauncherHelper = 0x4646950;

        // Confirmed instruction/call-site RVAs from the same auth cluster. These
        // are catalogued so discoveries do not get lost in logs; they are not
        // hooks or patches.
        std::uintptr_t BNetAuthClusterCallPrePump = 0x464797C;
        std::uintptr_t BNetAuthClusterCallFirstStateGetter = 0x4647981;
        std::uintptr_t BNetAuthClusterCallFirstStatePump = 0x4647989;
        std::uintptr_t BNetAuthClusterCallHelper01 = 0x464798E;
        std::uintptr_t BNetAuthClusterCallHelper02 = 0x4647996;
        std::uintptr_t BNetAuthClusterCallPrereqPump = 0x464799B;
        std::uintptr_t BNetAuthClusterCallPrereqPump2 = 0x46479A0;
        std::uintptr_t BNetAuthClusterCallHelper03 = 0x46479A5;
        std::uintptr_t BNetAuthClusterCallHelper04 = 0x46479AA;
        std::uintptr_t BNetAuthClusterReadyStateCheckGetterCall = 0x46479B7;
        std::uintptr_t BNetAuthClusterCallHelper05 = 0x46479D0;
        std::uintptr_t BNetAuthClusterCallHelper06 = 0x46479DB;
        std::uintptr_t BNetAuthClusterCallHelper07 = 0x46479F7;
        std::uintptr_t BNetAuthClusterCallLauncherHelper1 = 0x4647A0B;
        std::uintptr_t BNetAuthClusterCallLauncherHelper2 = 0x4647A24;

        // Data-reference instruction RVAs confirmed by the latest read-only
        // topology pass. Duplicate +1 decoder hits are intentionally omitted.
        std::uintptr_t BNetPrereqValueReadXref1 = 0x463FF00;
        std::uintptr_t BNetPrereqInitReadXref1 = 0x463FF14;
        std::uintptr_t BNetPrereqInitWriteXref1 = 0x463FF22;
        std::uintptr_t BNetPrereqValueReadXref2 = 0x463FF64;
        std::uintptr_t BNetPrereqValueWriteXref1 = 0x463FF85;
        std::uintptr_t BNetPrereqInitReadXref2 = 0x4640023;
        std::uintptr_t BNetPrereqInitWriteXref2 = 0x464002C;
        std::uintptr_t BNetFirstStateDirectReadXref = 0x4641E70;
        std::uintptr_t BNetFirstStateAddressXref = 0x4641FF0;
        std::uintptr_t BNetFirstStateSnapshotInitReadXref1 = 0x4642010;
        std::uintptr_t BNetFirstStateSnapshotValueReadXref = 0x4642022;
        std::uintptr_t BNetFirstStateSnapshotObjectXref1 = 0x464202A;
        std::uintptr_t BNetFirstStateSnapshotInitReadXref2 = 0x4642106;
        std::uintptr_t BNetFirstStateSnapshotObjectXref2 = 0x464211D;
        std::uintptr_t BNetFenceObjectWriteXref = 0x6EEFA62;

        // Data RVAs decoded from the same stock BNet sign-in dependency chain.
        // REFERENCE/READ_ONLY only: these are tracked so later backend work can
        // correlate the exact server event that naturally advances each state.
        std::uintptr_t LocalClientSignInStateArray = 0x17AF98A0;
        std::uintptr_t BNetFirstStateValue = 0x9BF08B0;       // *value must equal 2 at the first stock BNet gate
        std::uintptr_t BNetFirstStateSnapshotValue = 0x9BF0B7C;
        std::uintptr_t BNetFirstStateSnapshotObject = 0x9BF0A7C;
        std::uintptr_t BNetFirstStateSnapshotInit = 0x9BF0B80;
        std::uintptr_t BNetPrereqBoolValue = 0x17F51812;      // returned by game+0x463FF00
        std::uintptr_t BNetPrereqInitFlag = 0x17F51813;
        std::uintptr_t BNetFenceObject = 0x9BF73B0;           // returned by LEA getter game+0x46574E0
        std::uintptr_t BNetPostFenceObjectPtr = 0x9BF74B0;    // loaded by game+0x46573E0
        std::uintptr_t BNetPostFenceObjectPtr2 = 0x9BF74D0;   // loaded by game+0x46573F0
        std::uintptr_t BNetPostFenceObjectPtr3 = 0x9BF74C8;   // loaded by game+0x4657400
        std::uintptr_t BNetRelatedObjectPtr = 0x9BF7470;      // loaded by game+0x4657470
        std::uintptr_t BNetPostFenceTypeData01 = 0x6F65CA0;    // candidate type/vtable data from post-fence wrapper
        std::uintptr_t BNetPostFenceTypeData02 = 0x6F65DF0;
        std::uintptr_t BNetPostFenceTypeData03 = 0x6F65CD0;
        std::uintptr_t BNetPostFenceTypeData04 = 0x6F65DC0;
        std::uintptr_t BNetPostFenceTypeData05 = 0x6F65D30;
        std::uintptr_t BNetPostFenceTypeData06 = 0x6F65D60;

        // Focused auth scanner xrefs that have a stable semantic label.
        std::uintptr_t DemonwareInitialLoginDelayXref = 0x3C24421;
        std::uintptr_t Auth3LoginDevUrlXref = 0x6B944FF;
        std::uintptr_t UnoIdXref = 0x6C4D08F;

        // V35 live raw-:443 stack discoveries. READ_ONLY/REFERENCE only.
        // The low wrappers map WSAEWOULDBLOCK (10035) to 0x51, matching
        // libcurl CURLE_AGAIN, so V36 uses these landmarks to locate the curl
        // SSL verification/configuration path without forcing a TLS result.
        std::uintptr_t DwTlsEndpointConfigFunction = 0x4DBBD0;
        std::uintptr_t DwTlsConnectFunction = 0x6E6CA9D;
        std::uintptr_t DwTlsSendIoFunction = 0x6E6E280;
        std::uintptr_t DwTlsRecvIoFunction = 0x6E6E140;
        std::uintptr_t DwTlsSendStageFunction = 0x6E86FB0;
        std::uintptr_t DwTlsRecvDriverFunction = 0x6E87A7D;
        std::uintptr_t DwTlsTransferFunction = 0x6E86DC0;
        // V37 precise Schannel landmarks recovered from the V36 curl-chain pass.
        // READ_ONLY/REFERENCE only: these identify the exact stock branches so
        // runtime API observers can correlate SSPI status without forcing TLS.
        std::uintptr_t DwTlsPinnedPublicKeyHelper = 0x6E86C60;
        std::uintptr_t DwTlsAcquireCredentialsHandleCall = 0x6E87563;
        std::uintptr_t DwTlsAcquireCredentialsHandleReturn = 0x6E87568;
        std::uintptr_t DwTlsInitialInitializeSecurityContextCall = 0x6E8774B;
        std::uintptr_t DwTlsInitialInitializeSecurityContextReturn = 0x6E87750;
        std::uintptr_t DwTlsInitialSniOrCertificateFailure = 0x6E8775E;
        std::uintptr_t DwTlsHandshakeReceiveFailure = 0x6E87D64;
        std::uintptr_t DwTlsPinnedPublicKeyHelperCall = 0x6E87E55;
        std::uintptr_t DwTlsPinnedPublicKeyFailure = 0x6E87E60;
        std::uintptr_t DwTlsNextInitializeSecurityContextCall = 0x6E87EB8;
        std::uintptr_t DwTlsNextInitializeSecurityContextReturn = 0x6E87EBD;
        std::uintptr_t DwTlsNextSniOrCertificateFailure = 0x6E87ECB;
        std::uintptr_t DwTlsDispatchFunction = 0x6E70730;
        std::uintptr_t DwTlsTransportCheckFunction = 0x6E60680;
        std::uintptr_t DwTlsTransportCallbackFunction = 0x6E67780;
        std::uintptr_t DwTlsStateMachineFunction = 0x6E5784A;
        std::uintptr_t DwTlsStatePumpFunction = 0x6E56A60;
        std::uintptr_t DwTlsRetrySendFunction = 0x6E85F10;
        std::uintptr_t DwTlsRetryDispatchFunction = 0x6E70E20;
        std::uintptr_t DwTlsRetryStageFunction = 0x6E66DE0;
        std::uintptr_t DwTlsRetryPumpFunction = 0x6E6367B;
        std::uintptr_t DwTlsRetryStateFunction = 0x6E568E0;
        std::uintptr_t DwTlsAuthBridgeFunction = 0x2C28150;
        std::uintptr_t DwTlsDemonwareAuthPumpFunction = 0x3C1DFB3;
    };

    inline constexpr Discovery144 MW2019_1_44_Discovery{};

    // Exact accessor caller topology captured by the V14 read-only pass.
    // These are REFERENCE addresses only. V15's unwind-bounded, call-clobber-aware
    // replay confirmed ZERO same-function writes through these accessor returns;
    // V14's 25 apparent writes were decoder/alias false positives. The useful
    // signal is therefore the helper functions that receive the returned pointer.
    struct AuthAccessorCaller144
    {
        std::uintptr_t sourceRva;
        std::uintptr_t targetRva;
        std::uintptr_t authOffset;
        const char* accessorLabel;
        bool tailJump;
    };

    inline constexpr AuthAccessorCaller144 MW2019_1_44_AuthAccessorCallers[] =
    {
        { 0x463F018, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 01
        { 0x463F257, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 02
        { 0x463F2ED, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 03
        { 0x463F306, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 04
        { 0x463F43B, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 05
        { 0x463F502, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 06
        { 0x463F51E, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 07
        { 0x463F6E0, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 08
        { 0x463F73D, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 09
        { 0x463F768, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 10
        { 0x463FA31, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 11
        { 0x463FC3F, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 12
        { 0x463FC99, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 13
        { 0x463FCB5, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 14
        { 0x463FCC9, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 15
        { 0x463FD3B, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 16
        { 0x463FE9D, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 17
        { 0x4649B60, 0x46416F0, 0xF0, "F0_LOAD", false }, // V14 hit 18
        { 0x464A8B3, 0x46416E0, 0xA8, "A8_ADDR", false }, // V14 hit 19
        { 0x464E86A, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 20
        { 0x4651B6B, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 21
        { 0x4653A20, 0x46416E0, 0xA8, "A8_ADDR", true }, // V14 hit 22
        { 0x4654C9B, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 23
        { 0x4654D53, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 24
        { 0x46555BC, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 25
        { 0x465562C, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 26
        { 0x46557D2, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 27
        { 0x4655933, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 28
        { 0x4656AD1, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 29
        { 0x4657C8F, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 30
        { 0x465923C, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 31
        { 0x46592A5, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 32
        { 0x46596C9, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 33
        { 0x465B29B, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 34
        { 0x465B475, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 35
        { 0x465B55F, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 36
        { 0x465B5E2, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 37
        { 0x465B692, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 38
        { 0x465B6FF, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 39
        { 0x465B8F2, 0x4653A20, 0xA8, "A8_ALIAS", false }, // V14 hit 40
        { 0x465B97A, 0x46417B0, 0x118, "P118_ADDR", false }, // V14 hit 41
    };

    inline constexpr std::size_t MW2019_1_44_AuthAccessorCallerCount =
        sizeof(MW2019_1_44_AuthAccessorCallers) / sizeof(MW2019_1_44_AuthAccessorCallers[0]);

    // V15 confirmed helper destinations that receive an auth-field accessor
    // pointer as a Windows-x64 call argument. Names remain neutral until V16
    // resolves which helper actually mutates/forwards the completion object.
    struct AuthAccessorHelper144
    {
        std::uintptr_t targetRva;
        unsigned observedCalls;
    };

    inline constexpr AuthAccessorHelper144 MW2019_1_44_AuthAccessorHelpers[] =
    {
        { 0x067A4D0, 5 },
        { 0x067ABD0, 5 },
        { 0x06AAA20, 2 },
        { 0x06AAA30, 1 },
        { 0x06AAC80, 17 },
        { 0x0737B70, 1 },
        { 0x0767DF0, 1 },
        { 0x07685C0, 1 },
        { 0x0768960, 1 },
        { 0x0771C50, 1 },
        { 0x077F950, 1 },
        { 0x0780090, 1 },
        { 0x0780430, 1 },
        { 0x0780C00, 1 },
        { 0x3A11EB0, 1 },
        { 0x46597A0, 3 },
    };

    inline constexpr std::size_t MW2019_1_44_AuthAccessorHelperCount =
        sizeof(MW2019_1_44_AuthAccessorHelpers) / sizeof(MW2019_1_44_AuthAccessorHelpers[0]);

    // Read-only string/data landmarks used by the 1.44 auth/BGS scanners.
    // The two ACTIVE entries below are trust-material substitutions only: the
    // BGS bundle verifier and Auth3 response-signing public key. Neither writes
    // login/fence state or executable code.
    struct AuthLandmarks144
    {
        std::uintptr_t BattleNetLaunchOptionsRegistryString = 0x6F66840;
        std::uintptr_t BattleNetRegistryString = 0x6F66880;
        std::uintptr_t Auth3LoginDevUrlString = 0x706AD80;
        std::uintptr_t UnoIdString = 0x7081F88;

        std::uintptr_t FirstPartyTokensReadyString = 0x708C860;
        std::uintptr_t DemonwareInitialLoginDelayString = 0x708C8D0;
        std::uintptr_t DemonwareAuthenticatingString = 0x708C918;
        std::uintptr_t DemonwareAuthReplyString = 0x708C938;
        std::uintptr_t DemonwareAuthenticatedString = 0x708C958;
        std::uintptr_t BattleNetSessionTokenGateString = 0x708E6F0;
        std::uintptr_t BattleNetAccountTokenGateString = 0x708E720;
        std::uintptr_t DemonwareAuthReadyString = 0x708E830;
        std::uintptr_t AuthTrafficSigningPublicKey = 0x708E2B0; // ACTIVE: 294-byte DER response trust key only

        std::uintptr_t BgsFingerprintUrlString = 0x70CF348;
        std::uintptr_t BgsEmbeddedCertificateBundleJson = 0x70CF390;
        std::uintptr_t BgsBundleLabelString = 0x70D751C;
        std::uintptr_t BgsBundleVerifierPublicModulus = 0x70D7540; // ACTIVE: OPTION2 trust bootstrap only
        std::uintptr_t BgsSdkVersionString = 0x70FF7C0;
        std::uintptr_t BgsWebSocketProtocolString = 0x7120CE0;

        // Presence descriptors are already embedded in 1.44 and will be useful
        // when the backend reaches the friends/presence stage.
        std::uintptr_t PresenceServiceLegacyName = 0x711881A;
        std::uintptr_t PresenceListenerLegacyName = 0x7119338;
        std::uintptr_t PresenceServiceV1Name = 0x71264D8;
        std::uintptr_t PresenceListenerV1Name = 0x7126528;
    };

    inline constexpr AuthLandmarks144 MW2019_1_44_AuthLandmarks{};

    inline constexpr Signatures144 MW2019_1_44_Signatures
    {
        "8B 01 48 8D 0D ? ? ? ? 0F B6 04 C1",
        "48 63 C1 48 8D 0C 40 48 8D 05 ? ? ? ? 0F B6 04 88",
        "4C 63 C1 48 63 C2 4A 8D 0C 80 48 8D 04 89 48 8D 0D ? ? ? ? 0F B6 04 81",
        "48 89 5C 24 ? 4C 8B 99 ? ? ? ? 33 DB",
        "4C 8D 05 ? ? ? ? F2 0F 2C C8",
        "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 83 F8 ? 75 ? 8D 50 ? 48 8B CB E8 ? ? ? ? 85 C0 74 ? BA ? ? ? ? 48 8B CB E8 ? ? ? ? 85 C0 75 ?",
        "E8 ? ? ? ? 4C 8B 15 ? ? ? ? 49 8B 4A ? C6 44 24 ? ? 0F B6 44 24 ? 4C 8D 25",
        "48 83 EC ? E8 ? ? ? ? 8B C8 B8",
        "E8 ? ? ? ? 84 C0 74 ? E8 ? ? ? ? 8B C0 48 83 C4",
        1642
    };
}
