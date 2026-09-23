#pragma once
#include <string>

namespace t8_scanner
{
    enum class Mode
    {
        All,
        Lua,
        Frontend,
        Network,
        Assets
    };

    bool Run(Mode mode, std::string& message);
    void PrintStatus();
}
