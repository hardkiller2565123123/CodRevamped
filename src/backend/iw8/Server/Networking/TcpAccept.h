#pragma once

#include "Server/Core/Server.h"

// Module boundary for Server/Networking/TcpAccept.
// Its implementation is compiled through Server.cpp so legacy private helper
// linkage/state remains unchanged while the source is physically separated.
