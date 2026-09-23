#pragma once

#include <cstdint>

namespace alpha_support
{
    // Exact COD2020 June 4th Alpha profile check.
    bool IsSupported();

    // Session integers recovered from InjectToFixBuild.dll.  These are kept
    // explicit so the old helper DLL is no longer required for mode testing.
    enum class SessionMode : std::uint32_t
    {
        LeaguePlay      = 33,
        OnlineMpCustoms = 4129,
        OfflineZombies  = 8192,
        OfflineMp       = 8193,
        OnlineZombies   = 8224,
        OnlineMp        = 8225,
    };

    // Helper-compatible frontend/session operations.
    bool EnterFrontend();
    bool SwitchZombies();
    bool RestoreMultiplayer();
    bool Disconnect();

    // Original Gombies session-object setup.  This is the important stock
    // PLAY-button compatibility state that was missing from the earlier port.
    bool ApplyOriginalSessionDefaults();
    bool SetSessionMode(SessionMode mode);
    bool SetSessionInt(std::uint32_t value);
    bool ReadSessionInt(std::uint32_t& value);

    // Map-launch path recovered from the original Alpha helper DLL.
    bool SetMapName(const char* mapName);
    bool LaunchGame();
    bool FastRestart();

    // Send an arbitrary command through the exact recovered Cbuf_AddText path.
    bool SendCommand(const char* command);

    // Starts the COD2020 Alpha helper-compatibility worker.  The worker applies
    // the original session-object defaults once the live object exists, but it
    // does not force an early frontend transition before the game is ready.
    //
    // F1       = MP/SP frontend (Gombies ordering)
    // F2 / END = Zombies frontend
    // F3       = prompt for session integer/preset
    // HOME     = set internal map name
    // PGUP/DN  = adjust original helper screen index; NUMPAD1 applies it
    // LEFT/RIGHT = adjust original helper auxiliary debug counter
    // NUMPAD2  = lobbylaunchgame (diagnostic/manual fallback)
    // NUMPAD4  = arbitrary Cbuf command prompt
    // NUMPAD0  = toggle continuous original-session-field enforcement
    // F7       = fast_restart
    // F9       = disconnect
    void Initialize();
}
