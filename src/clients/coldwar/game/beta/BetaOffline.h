#pragma once

namespace beta_offline
{
    // Attempts the Season-2-style offline frontend initialization against the
    // exact October Open Beta. Returns true only after all required live
    // signatures resolve, multiplayer mode is applied, and runtime bootstrap
    // completes successfully.
    bool TryActivate();
}
