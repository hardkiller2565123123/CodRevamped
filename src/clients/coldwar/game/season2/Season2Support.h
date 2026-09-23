#pragma once

#include <Windows.h>

namespace season2_support
{
    bool IsExactSeason2();
    bool StartRecoveredClient();
    DWORD WINAPI RecoveredClientThread(LPVOID);
}
