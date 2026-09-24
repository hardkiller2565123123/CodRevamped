#pragma once

#include "Server/Core/Server.h"

// Module boundary for Server/Lifecycle/Run.
// Its implementation is compiled through ServerTls.cpp so legacy private helper
// linkage/state remains unchanged while the source is physically separated.
