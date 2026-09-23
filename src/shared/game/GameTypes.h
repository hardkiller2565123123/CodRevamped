#pragma once

// Compatibility include.
//
// The project previously carried a second copy of GameKind/ExecutableInfo in
// this path as well as games/common/GameTypes.h. Translation units that mixed
// old and new module headers could therefore see two distinct C++ types with
// the same fully-qualified name (games::ExecutableInfo), which produced the
// misleading E0312 "ExecutableInfo -> const ExecutableInfo" conversion errors.
// Keep the legacy include path, but make the common definition authoritative.
#include "../compat/games/common/GameTypes.h"
