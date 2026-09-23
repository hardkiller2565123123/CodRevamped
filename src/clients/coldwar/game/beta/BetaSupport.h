#pragma once

#include <Windows.h>
#include <string>

namespace beta_support
{
    enum class BuildKind
    {
        Unknown,
        Retail,
        OpenBeta
    };

    struct BuildInfo
    {
        BuildKind kind = BuildKind::Unknown;
        DWORD timestamp = 0;
        DWORD imageSize = 0;
        DWORD entryPointRva = 0;
    };

    BuildInfo DetectCurrentBuild();
    const char* BuildName(BuildKind kind);
    bool IsExactOpenBeta();
    bool StartRecoveredClient();
    bool ExecuteFrontendControl(const std::string& action, const std::string& arguments, std::string& message);
    DWORD WINAPI RecoveredClientThread(LPVOID);
    DWORD WINAPI ObservationThread(LPVOID);
}
