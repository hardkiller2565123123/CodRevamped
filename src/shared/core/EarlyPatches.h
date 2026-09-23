#pragma once

namespace early_patches
{
    // First compatibility action from the final DLL. Each game project checks
    // only its own exact executable profiles and supplies configuration to the
    // generic Patches project when needed.
    void Initialize();
}
