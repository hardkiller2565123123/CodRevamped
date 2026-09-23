#pragma once

#include <cstdint>

namespace alpha_support
{
    bool IsSupported();

    enum class SessionMode : std::uint32_t
    {
        LeaguePlay      = 33,
        OnlineMpCustoms = 4129,
        OfflineZombies  = 8192,
        OfflineMp       = 8193,
        OnlineZombies   = 8224,
        OnlineMp        = 8225,
    };

    bool EnterFrontend();
    bool SwitchZombies();
    bool RestoreMultiplayer();
    bool Disconnect();

    bool ApplyOriginalSessionDefaults();
    bool SetSessionMode(SessionMode mode);
    bool SetSessionInt(std::uint32_t value);
    bool ReadSessionInt(std::uint32_t& value);
    bool SetSessionObjectField98(std::uint32_t value);
    bool ReadSessionObjectField98(std::uint32_t& value);

    bool SetMapName(const char* mapName);
    bool LaunchGame();
    bool FastRestart();
    bool SendCommand(const char* command);

    void Initialize();
}
