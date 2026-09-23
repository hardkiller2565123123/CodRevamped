#pragma once
#include <string>

namespace lua_runtime_path_trace
{
    void StartAsync();
    bool IsRunning();
    bool HasCompleted();
    bool ScanNow(std::string& message);
    void PrintStatus();
}
