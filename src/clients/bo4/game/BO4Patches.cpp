#include "BO4Patches.h"

namespace bo4_patches
{
    bool InitializeEarly()
    {
        // BO4-specific early profiles can be registered here later. Generic
        // patch engines stay in the Patches project; BO4 addresses stay here.
        return false;
    }
}
