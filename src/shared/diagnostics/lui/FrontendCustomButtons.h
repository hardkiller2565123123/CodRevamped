#pragma once
#include <string>

namespace frontend_custom_buttons
{
    void StartAuto();
    bool Enable(std::string& message);
    bool Disable(std::string& message);
    bool IsInstalled();
    bool IsEnabled();
    void PrintStatus();
}
