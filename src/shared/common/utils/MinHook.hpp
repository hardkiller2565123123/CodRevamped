#pragma once

// CodRevamped uses one vendored MinHook implementation.  Keep this wrapper so
// older first-party includes do not need to know the dependency's physical
// location, but never duplicate the MinHook API declarations here.
#include "../../../../third_party/bo4/minhook/include/MinHook.h"
