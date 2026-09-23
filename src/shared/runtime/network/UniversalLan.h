#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include "../../compat/games/common/GameTypes.h"

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

    // Cold War Retail 1.34.0.15931218 LAN bridge, ported from cw-mod-v2.
    // The bridge keeps CodRevamped's public-network blocker in place and only
    // reuses the game's stock LAN/session/join objects.
    bool InitializeColdWarRetailBridge(std::string& message);
    bool ColdWarRetailBridgeReady();
    std::string ColdWarRetailBridgeStatus();

    // PC1: queue a game-thread dump of the live session descriptor. The output
    // includes a single copy/pasteable CWJOIN1 token for PC2.
    bool QueueColdWarHostDescriptor(std::string& message);

    // PC2: queue a game-thread native descriptor join. jointype must be 1 or 4;
    // 4 is the preferred donor default because it leaves playlistid at 255.
    bool QueueColdWarDescriptorJoin(
        const std::string& blob,
        int joinType,
        std::string& message);

    // Read-only game-thread diagnostics from the donor LAN implementation.
    bool QueueColdWarPendingTargetDump(std::string& message);
    bool QueueColdWarJoinStateDump(std::string& message);
    bool QueueColdWarSessionStateDump(std::string& message);
    void StartColdWarJoinWatch();

    // Optional post-decryption lobby-message transcript. This is off by default
    // and calls through to the stock handlers after logging.
    bool InstallColdWarNetMsgTranscript(std::string& message);
    bool RemoveColdWarNetMsgTranscript(std::string& message);
    bool ColdWarNetMsgTranscriptInstalled();
    std::string ColdWarJoinTranscript();
}
