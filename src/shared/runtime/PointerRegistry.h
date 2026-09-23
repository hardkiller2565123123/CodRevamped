#pragma once
#include <Windows.h>
#include <cstdint>

namespace pointer_registry
{
    struct Snapshot
    {
        uintptr_t moduleBase = 0;
        uintptr_t uiScreen = 0;
        uintptr_t networkMode = 0;
        uintptr_t sessionMode = 0;
        uintptr_t initialized = 0;
        uintptr_t commandBuffer = 0;
        uintptr_t dvarFind = 0;
        uintptr_t font = 0;
    };

    void Publish(const Snapshot& snapshot);
    Snapshot Get();
}
