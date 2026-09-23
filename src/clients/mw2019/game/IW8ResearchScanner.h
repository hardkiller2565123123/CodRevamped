#pragma once
#include <string>

namespace iw8_research
{
    enum class ScanMode
    {
        All,
        Frontend,
        LuaLui,
        LanNetwork
    };

    void StartAutomatic();
    bool Run(ScanMode mode, std::string& message);
    bool IsRunning();
    bool HasCompleted();
    void PrintStatus();
}
