#include "Server.h"
#include "Log.h"
#include "Web/WebAuthService.h"
#include "Demonware/DemonwareTaskRouter.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <atomic>
#include <array>
#include <cstring>
#include <vector>
#include <mutex>
#include <limits>
#include <cstdarg>
#include <cstdio>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

#include "Demonware/Lsg/Diagnostics.cpp"
#include "Demonware/Lsg/TransportPrimitives.cpp"
#include "Demonware/Lsg/CryptoPrimitives.cpp"
#include "Demonware/Lsg/TrafficSigningKeys.cpp"
#include "Demonware/Lsg/LsgSessionHandler.cpp"
