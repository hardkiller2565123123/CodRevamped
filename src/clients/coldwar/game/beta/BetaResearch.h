#pragma once

#include <string>

namespace beta_research
{
    enum class ScanMode
    {
        State,
        Frontend,
        Lua,
        Auth,
        Name,
        All
    };

    bool IsExactOpenBeta();
    void NotifyWin11PatchComplete();
    void StartStateMonitor();
    bool StartAutomatic(const char* reason);
    bool RunManual(ScanMode mode, std::string& message);
    bool RunManual(const std::string& mode, std::string& message);
    void PrintStatus();
}
