#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include "../game/BO4Entry.h"

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);

        // One BO4 version.dll for Retail + Multiplayer Beta + Blackout Beta.
        // BO4Entry performs runtime fingerprint routing and starts the correct
        // profile without any secondary proxy/client DLL.
        bo4_entry::ProcessAttach();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        bo4_entry::ProcessDetach();
    }
    return TRUE;
}
