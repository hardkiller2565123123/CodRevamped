extern "C" void DW_LocalBackend_Frame();
extern "C" void Con_DeveloperFrame();
#include "com_debugstates.h"
#include "frontend_freecam.h"
#include "frontend_scene.h"
#include "com_optimized.h"

extern "C" void Sys_UpdateGameWindowTitle();

// CL_Screen_UpdateFrame calls this once after all UI workers finish and before
// R_EndFrame submits the draw commands, for both no-game-mode and game views.
// Keep the native placement lifecycle: SCRMODE_INVALID is 3 in this Replay.
extern "C" void ScrPlace_EndFrame() {
    Com_Optimized_Frame();
    Sys_UpdateGameWindowTitle();
#ifdef REPLAY_COMPILER_FRONTEND_PROBE
    Com_FrontEndScene_RegisterCommands();
    Com_FrontEndScene_SelectionFrame();
#endif
#ifdef REPLAY_COMPILER_FRONTEND_FREECAM
    Com_FrontEndScene_FreeCam_Frame();
#endif
    DW_LocalBackend_Frame();
    Com_DebugStates_Frame(0);
    Con_DeveloperFrame();
    activeScreenPlacementMode = 3;
}
