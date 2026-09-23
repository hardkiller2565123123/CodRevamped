#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include "../../game/GameTypes.h"

namespace universal_lan
{
    struct Status
    {
        bool initialized = false;
        games::GameKind game = games::GameKind::Unknown;
        bool publicNetworkBlockerExpected = true;
        std::uint16_t defaultGamePort = 3074;
        std::uint16_t defaultQueryPort = 3075;
    };

    void Initialize(games::GameKind game);
    Status GetStatus();

    bool IsPrivateOrLoopbackIPv4(std::uint32_t hostOrderAddress);
    bool ParsePrivateEndpoint(
        const std::string& text,
        std::string& host,
        std::uint16_t& port,
        std::string& error);

    void PrintStatus();
}
