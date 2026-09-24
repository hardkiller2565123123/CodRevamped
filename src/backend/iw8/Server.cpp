#include "Server.h"
#include "Log.h"
#include "Protocol.h"
#include "Web/WebAuthService.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <utility>

#pragma comment(lib, "Ws2_32.lib")

#include "Server/Networking/SocketHelpers.cpp"
#include "Server/Lifecycle/Construction.cpp"
#include "Server/Networking/TcpListener.cpp"
#include "Server/Networking/UdpListener.cpp"
#include "Server/Networking/TcpAccept.cpp"
#include "Server/Networking/UdpReceive.cpp"
