#pragma once
#include <Windows.h>

namespace games
{
    enum class GameKind
    {
        Unknown,
        Retail,
        Beta,
        Alpha,
        S2,
        IW8,
        T8,
        T10, // Black Ops 6 / current T10-family scanner name
        BO6 = T10
    };

    struct ExecutableInfo
    {
        HMODULE module = nullptr;
        DWORD timestamp = 0;
        DWORD imageSize = 0;
        DWORD entryPointRva = 0;
        wchar_t executableName[MAX_PATH]{};
    };
}
