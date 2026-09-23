#pragma once
#include <string>

namespace lua_native_button_patch
{
    void StartAuto();
    bool Apply(std::string& message);
    bool Restore(std::string& message);
    bool IsApplied();
    void PrintStatus();
}
