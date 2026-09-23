#pragma once
#include "../../game/GameTypes.h"
#include <string>

namespace universal_scanner
{
    enum class Profile
    {
        Unknown,
        T9Retail,
        T9Beta,
        T9Alpha,
        IW8_167,
        IW8_144,
        T8_BO4,
        T10_BO6_Beta,
        T10_BO6_Retail,
        S2_Generic
    };

    void SetGame(games::GameKind game);
    Profile ActiveProfile();
    const char* ProfileName(Profile profile);
    void StartAutomatic();
    bool RunAll(std::string& message);
    bool RunFunctions(std::string& message);
    bool RunLua(std::string& message);
    bool RunFrontend(std::string& message);
    void PrintStatus();
}
