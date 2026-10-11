#pragma once
#include <stdint.h>
extern "C"
{
    const char *DW_LocalConfig_Host();
    const char *DW_LocalConfig_PlayerName();
    const wchar_t *DW_LocalConfig_WideHost();
    const wchar_t *DW_LocalConfig_LoginPath();
    const wchar_t *DW_LocalConfig_Headers();
    const char *DW_LocalConfig_AuthUrl();
    const char *DW_LocalConfig_NativeAuthUrl();
    const char *DW_LocalConfig_LegacyUrl();
    const char *DW_LocalConfig_TestCommand();
    const char *DW_LocalConfig_TestEnabled();
    bool DW_LocalConfig_UnlockAll();
    unsigned DW_LocalConfig_Rank();
}
