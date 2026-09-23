#pragma once
#include <string>

namespace native_director_state_router
{
    void StartAuto();
    bool Enable(std::string& message);
    bool Disable(std::string& message);
    bool IsRunning();
    bool IsEnabled();
    void PrintStatus();
}
