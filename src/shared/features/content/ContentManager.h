#pragma once
#include <Windows.h>
#include <string>
#include <vector>

namespace content_manager
{
    struct ModuleSnapshot
    {
        std::wstring name;
        uintptr_t base = 0;
        DWORD size = 0;
    };

    void Initialize(DWORD processId);
    void Refresh();
    std::vector<ModuleSnapshot> Modules();
}
