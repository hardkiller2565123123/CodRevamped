#pragma once
#include <Windows.h>
#include "../compat/games/common/GameTypes.h"

namespace game_manager
{
    struct BuildProfile
    {
        games::GameKind kind = games::GameKind::Unknown;
        const char* name = "Unknown";
        DWORD timestamp = 0;
        DWORD imageSize = 0;
        bool scannerOnly = true;
    };

    void SetMainThreadId(DWORD threadId);
    void Start(HMODULE selfModule);
    const BuildProfile& ActiveProfile();
    const games::ExecutableInfo& ActiveImage();
}
