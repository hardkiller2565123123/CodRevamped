#pragma once

#include "BgsRpc.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace revamped::iw8::bgs
{
    inline constexpr std::uint32_t ConnectionServiceHash = 0x65446991u;
    inline constexpr std::uint32_t AuthenticationServiceHash = 0x0DECFC01u;
    inline constexpr std::uint32_t AuthenticationListenerHash = 0x71240E35u;
    inline constexpr std::uint32_t SessionServiceHash = 0x1E688C05u;
    // FNV-1a("bnet.protocol.session.SessionListener"). SessionService uses
    // the same name-hash convention and resolves to the observed 0x1E688C05.
    inline constexpr std::uint32_t SessionListenerHash = 0x7FE36B32u;
    inline constexpr std::uint32_t AccountServiceHash = 0x62DA0891u;
    // FNV-1a("bnet.protocol.account.AccountListener"); observed on the wire as 0x54DFDA17.
    inline constexpr std::uint32_t AccountListenerHash = 0x54DFDA17u;
    inline constexpr std::uint32_t PresenceServiceHash = 0xFA0796FFu;
    inline constexpr std::uint32_t BlockListServiceHash = 0x8E8F5FB0u;
    inline constexpr std::uint32_t RecentPlayersServiceHash = 0xDD1CE7C2u;
    inline constexpr std::uint32_t ChannelMembershipServiceHash = 0x7E525E99u;
    inline constexpr std::uint32_t FriendsServiceHash = 0xA3DDB1BDu;
    // FNV-1a("bnet.protocol.whisper.WhisperService"); observed on the wire as 0xC12828F9.
    inline constexpr std::uint32_t WhisperServiceHash = 0xC12828F9u;
    inline constexpr std::uint32_t GameUtilitiesServiceHash = 0x3FC1274Du;
    inline constexpr std::uint32_t ResourcesServiceHash = 0xECBE75BAu;
    inline constexpr std::uint32_t UserManagerServiceHash = 0x3E19268Au;
    inline constexpr std::uint32_t ReportServiceHash = 0x3A4218FBu;

    inline constexpr std::uint32_t OdinProgramId = 0x4E49444Fu;
    inline constexpr std::uint64_t LocalAccountHigh = 0x0100000000000000ull;
    inline constexpr std::uint64_t LocalAccountLow = 1ull;
    inline constexpr std::uint64_t LocalGameAccountHigh = 0x020000024E49444Full;
    inline constexpr std::uint64_t LocalGameAccountLow = 1ull;

    struct SessionState
    {
        std::uint32_t nextServerRequestToken = 0;
        bool authLogonResponseSent = false;
        bool authLogonCompleteSent = false;
        std::uint32_t authLogonCompleteToken = 0;
        std::vector<Byte> authSessionKey;
        bool authenticated = false;
        bool gameAccountSelected = false;
        bool sessionCreatedNotificationSent = false;
        std::uint32_t sessionCreatedNotificationToken = 0;
        EntityId accountId{LocalAccountHigh, LocalAccountLow, true};
        EntityId gameAccountId{LocalGameAccountHigh, LocalGameAccountLow, true};
        std::string sessionId = "revamped-iw8-session-1";
        std::string clientId = "revamped-iw8-local";

        // Semantic compatibility fingerprint.  These values are learned from
        // normal CreateSession/RPC traffic instead of selecting behavior from
        // an exact captured packet.  Nearby IW8 builds can therefore vary
        // optional fields while sharing the same service implementation.
        bool hasApplicationVersion = false;
        std::uint64_t applicationVersion = 0;
        bool hasPlatform = false;
        std::uint32_t platform = 0;
        bool hasLocale = false;
        std::uint32_t locale = 0;
        std::string userAgent;
        std::string compatibilityProfile = "IW8-semantic";
        std::unordered_map<std::uint64_t, std::uint64_t> requestShapeByRoute;

        std::uint64_t handledRequests = 0;
        std::uint64_t missingRequests = 0;
        std::unordered_set<std::uint64_t> missingKeys;
        std::unordered_map<std::uint32_t, std::string> pendingServerRequests;
    };

    struct OutgoingRpc
    {
        std::vector<Byte> payload;
        std::string label;
        std::uint32_t serviceHash = 0;
        std::uint32_t methodId = 0;
        std::uint32_t token = 0;
        bool serverRequest = false;
    };

    struct RequestContext
    {
        std::uint64_t connectionId = 0;
        const RpcEnvelope& rpc;
        SessionState& session;
        std::vector<OutgoingRpc>& outgoing;
    };

    bool DispatchRequest(RequestContext& context);
    bool HandleClientResponse(std::uint64_t connectionId, const RpcEnvelope& rpc, SessionState& session);
    const char* ServiceName(std::uint32_t serviceHash);

    void QueueResponse(RequestContext& context, const std::vector<Byte>& body,
        const char* label, std::uint32_t status = 0);
    void QueueServerRequest(RequestContext& context, std::uint32_t serviceHash,
        std::uint32_t methodId, const std::vector<Byte>& body, const char* label,
        std::uint32_t* tokenOut = nullptr);
    void QueueServerNotification(RequestContext& context, std::uint32_t serviceHash,
        std::uint32_t methodId, const std::vector<Byte>& body, const char* label,
        std::uint32_t* tokenOut = nullptr);
    void MarkHandled(RequestContext& context, const char* detail);
    void MarkMissing(RequestContext& context, const char* reason);
}
