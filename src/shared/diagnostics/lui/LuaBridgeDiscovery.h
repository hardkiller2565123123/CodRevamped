#pragma once
#include <string>

namespace lua_bridge_discovery
{
    void StartAsync();
    bool IsRunning();
    bool HasCompleted();

    bool ScanNow(std::string& message);
    bool LoadDirectorHub(std::string& message);
    void PrintStatus();
}
