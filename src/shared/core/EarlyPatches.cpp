#include "EarlyPatches.h"

#include "../../clients/coldwar/game/ColdWarPatches.h"
#include "../../clients/mw2019/game/MW2019Patches.h"
#include "../../clients/bo4/game/BO4Patches.h"

namespace early_patches
{
    void Initialize()
    {
        // Cold War pre-release builds currently require the earliest known
        // Win11 compatibility path, so check Cold War first.
        if (coldwar_patches::InitializeEarly())
            return;

        if (mw2019_patches::InitializeEarly())
            return;

        bo4_patches::InitializeEarly();
    }
}
