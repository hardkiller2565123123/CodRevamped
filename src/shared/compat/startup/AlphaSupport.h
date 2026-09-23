#pragma once

#include <cstdint>

namespace alpha_support
{
    // Exact COD2020 June 4th Alpha profile check.
    bool IsSupported();

    // Session integers recovered from InjectToFixBuild.dll. The helper writes
    // these values directly to COD2020+0x65259E4; this is separate from the
    // session-object field at +0x98.
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

    // Separate field used by InjectToFixBuild's NUMPAD1 path.
    bool SetSessionObjectField98(std::uint32_t value);
    bool ReadSessionObjectField98(std::uint32_t& value);

    // Map-launch path recovered from the original Alpha helper DLL.
    bool SetMapName(const char* mapName);
    bool LaunchGame();
    bool FastRestart();

    // Send an arbitrary command through the exact recovered Cbuf_AddText path.
    bool SendCommand(const char* command);

    // Starts the COD2020 Alpha helper-compatibility worker. Once the live
    // session object is stable, the worker automatically runs the exact
    // InjectToFixBuild MP frontend sequence, so F1 is no longer required.
    // It also watches the recovered sessionInt global and redirects known
    // online MP/ZM mode values to their offline counterparts. A read-only
    // online/QR memory discovery scan runs automatically and can be rerun with F6.
    //
    // F1       = manual MP/frontend retry
    // F2 / END = Zombies frontend
    // F3       = prompt for direct sessionInt (COD2020+0x65259E4)
    // F4       = prompt for sessionObject+0x98 (separate recovered field)
    // F6       = rerun online-service + QR memory discovery scanner
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
