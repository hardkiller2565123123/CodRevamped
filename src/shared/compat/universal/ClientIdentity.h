#pragma once
#include "../../game/GameTypes.h"
#include <string>

namespace client_identity
{
    const char* DefaultName();
    std::string CurrentName();
    bool LoadForGame(games::GameKind game, std::string& message);
    bool Load(std::string& message);
    bool SaveNameForGame(games::GameKind game, const std::string& name, std::string& message);
    bool SaveName(const std::string& name, std::string& message);
    bool ApplyForGame(games::GameKind game, std::string& message);
    bool SetAndApply(games::GameKind game, const std::string& name, std::string& message);
    void PrintStatus(games::GameKind game);
}
