#include "RuntimeOwnership.h"
#include <cstdio>

namespace
{
    HANDLE g_ownerMutex = nullptr;
    volatile LONG g_owner = 0;
}

namespace proxy_runtime
{
    bool Acquire() noexcept
    {
        if (InterlockedCompareExchange(&g_owner, 0, 0) != 0)
            return true;

        wchar_t name[96]{};
        _snwprintf_s(name, (sizeof(name) / sizeof(name[0])), _TRUNCATE,
            L"Local\\CodRevamped.Runtime.%lu", GetCurrentProcessId());
        HANDLE mutex = CreateMutexW(nullptr, FALSE, name);
        if (!mutex)
        {
            // Fail open if Windows cannot create the guard; don't prevent startup.
            InterlockedExchange(&g_owner, 1);
            return true;
        }
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            CloseHandle(mutex);
            return false;
        }
        g_ownerMutex = mutex;
        InterlockedExchange(&g_owner, 1);
        return true;
    }

    bool IsOwner() noexcept
    {
        return InterlockedCompareExchange(&g_owner, 0, 0) != 0;
    }

    void Release() noexcept
    {
        if (g_ownerMutex)
        {
            CloseHandle(g_ownerMutex);
            g_ownerMutex = nullptr;
        }
        InterlockedExchange(&g_owner, 0);
    }
}
