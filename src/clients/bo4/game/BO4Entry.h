#pragma once

namespace bo4_entry
{
    // Called once from the single BO4 version.dll DllMain. Runtime fingerprinting
    // selects Retail, Multiplayer Beta, or Blackout Beta inside the same project.
    void ProcessAttach();
    void ProcessDetach();

    // Kept for older call sites. They now route into the same shared T8 beta
    // bootstrap rather than starting isolated mini-clients.
    void StartBlackoutBetaDedicated();
    void StartMultiplayerBetaDedicated();

    bool IsMultiplayerBetaSupported();
    bool IsBlackoutBetaSupported();
    void StartMultiplayerBetaResearch();
}
