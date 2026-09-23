#pragma once

namespace coldwar_patches
{
    // Called during DLL_PROCESS_ATTACH before the normal CodRevamped runtime.
    // All Cold War build fingerprints and patch RVAs remain owned here, not by
    // the generic Patches project.
    bool InitializeEarly();
}
