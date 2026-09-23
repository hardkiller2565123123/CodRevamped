#pragma once
#include <Windows.h>
#include <cstdint>
#include "../compat/games/common/GameTypes.h"

namespace core_runtime
{
    enum class StartupMode
    {
        OfflineLan,
        OnlineResearch
    };

    void RecordStartupStage(const char* stage, const char* detail = nullptr);
    void SetStartupMode(StartupMode mode);
    StartupMode GetStartupMode();
    bool IsOnlineResearchMode();
    void InstallEarlyNetworkBlocker();
    void SetSelfModule(HMODULE module);
    void SetActiveGame(games::GameKind kind);
    void InstallMultiInstanceCompatEarly();
    void InitializeConsole();
    bool WaitForStableImage(DWORD timeoutMs);
    void SetModuleBase();
    uintptr_t ModuleBase();
    bool IsBattleNetRunning();
    void ShowBattleNetWarning();
    void StartCommandConsole();
    bool InitializeRetail();
    bool InitializeBetaFocusedResearch();
    void StartReadOnlyScanner();
    bool QueueDeveloperCommand(const char* command);
    bool DeveloperCommandReady();
}
