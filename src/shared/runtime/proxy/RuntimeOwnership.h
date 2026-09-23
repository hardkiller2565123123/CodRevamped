#pragma once
#include <Windows.h>

namespace proxy_runtime
{
    // A version.dll + dxgi.dll pair can load the same payload twice.  Only one
    // copy may own game hooks/runtime threads; every copy can still forward APIs.
    bool Acquire() noexcept;
    bool IsOwner() noexcept;
    void Release() noexcept;
}
