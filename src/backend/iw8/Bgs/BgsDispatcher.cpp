#include "BgsDispatcher.h"
#include "Common/Logging/Log.h"
#include "ProtocolIntrospection.h"
#include "Services/AccountService.h"
#include "Services/BlockListService.h"
#include "Services/ChannelMembershipService.h"
#include "Services/AuthenticationService.h"
#include "Services/ConnectionService.h"
#include "Services/PresenceService.h"
#include "Services/RecentPlayersService.h"
#include "Services/ResourcesService.h"
#include "Services/SessionService.h"

#include <utility>

namespace revamped::iw8::bgs
{
    namespace
    {
        using ServiceHandler = bool(*)(RequestContext&);

        struct ServiceDefinition
        {
            std::uint32_t hash;
            const char* name;
            ServiceHandler handler;
        };

        bool HandleFriendsService(RequestContext& context)
        {
            // bnet.protocol.friends.FriendsService method 1 is Subscribe.
            // SubscribeResponse contains only optional/repeated state, so a local
            // account with no reconstructed friend graph has a canonical empty body.
            if (context.rpc.header.methodId != 1u)
            {
                MarkMissing(context, "FriendsService method is not implemented yet");
                return true;
            }

            QueueResponse(context, {}, "FriendsService.Subscribe response");
            MarkHandled(context, "Subscribe response: empty local friends view");
            return true;
        }

        bool HandleWhisperService(RequestContext& context)
        {
            // bnet.protocol.whisper.WhisperService method 1 is Subscribe.
            // With no local whisper history/view reconstructed yet, protobuf's
            // canonical SubscribeResponse is the empty message.
            if (context.rpc.header.methodId != 1u)
            {
                MarkMissing(context, "WhisperService method is not implemented yet");
                return true;
            }

            QueueResponse(context, {}, "WhisperService.Subscribe response");
            MarkHandled(context, "Subscribe response: empty local whisper view");
            return true;
        }

        // Protocol constants stay explicit, but packets do not.  Every normal
        // BGS request is decoded first and routed by semantic service/method
        // metadata.  A nearby IW8 build can add optional protobuf fields without
        // requiring a new exact byte-array comparison.
        const ServiceDefinition kServices[] = {
            { ConnectionServiceHash, "ConnectionService", HandleConnectionService },
            { AuthenticationServiceHash, "AuthenticationService", HandleAuthenticationService },
            { AuthenticationListenerHash, "AuthenticationListener", nullptr },
            { SessionServiceHash, "SessionService", HandleSessionService },
            { SessionListenerHash, "SessionListener", nullptr },
            { AccountServiceHash, "AccountService", HandleAccountService },
            { AccountListenerHash, "AccountListener", nullptr },
            { PresenceServiceHash, "PresenceService", HandlePresenceService },
            { BlockListServiceHash, "BlockListService", HandleBlockListService },
            { RecentPlayersServiceHash, "RecentPlayersService", HandleRecentPlayersService },
            { ChannelMembershipServiceHash, "ChannelMembershipService", HandleChannelMembershipService },
            { FriendsServiceHash, "FriendsService", HandleFriendsService },
            { WhisperServiceHash, "WhisperService", HandleWhisperService },
            { GameUtilitiesServiceHash, "GameUtilitiesService", nullptr },
            { ResourcesServiceHash, "ResourcesService", HandleResourcesService },
            { UserManagerServiceHash, "UserManagerService", nullptr },
            { ReportServiceHash, "ReportService", nullptr },
        };

        std::uint64_t RouteKey(std::uint32_t serviceHash, std::uint32_t methodId)
        {
            return (static_cast<std::uint64_t>(serviceHash) << 32) | methodId;
        }

        const ServiceDefinition* FindService(std::uint32_t serviceHash)
        {
            for (const auto& service : kServices)
            {
                if (service.hash == serviceHash)
                    return &service;
            }
            return nullptr;
        }

        void PrintCoverage(const RequestContext& context)
        {
            log::Print("[BGS-COVERAGE] id=%llu handled=%llu missing=%llu uniqueMissing=%llu routes=%llu authenticated=%s gameAccountSelected=%s compat=%s appVersion=%s%llu",
                static_cast<unsigned long long>(context.connectionId),
                static_cast<unsigned long long>(context.session.handledRequests),
                static_cast<unsigned long long>(context.session.missingRequests),
                static_cast<unsigned long long>(context.session.missingKeys.size()),
                static_cast<unsigned long long>(context.session.requestShapeByRoute.size()),
                context.session.authenticated ? "yes" : "no",
                context.session.gameAccountSelected ? "yes" : "no",
                context.session.compatibilityProfile.c_str(),
                context.session.hasApplicationVersion ? "" : "<unknown>/",
                static_cast<unsigned long long>(context.session.applicationVersion));
        }

        void ObserveRequestShape(RequestContext& context)
        {
            ProtoMessageObservation observation{};
            const bool decoded = ObserveProtoMessage(context.rpc.body.data(), context.rpc.body.size(), observation);
            const auto key = RouteKey(context.rpc.header.serviceHash, context.rpc.header.methodId);
            const auto previous = context.session.requestShapeByRoute.find(key);

            if (!decoded)
            {
                log::Print("[BGS-DECODE] id=%llu service=%s method=%u token=%u semanticBody=INVALID bytes=%llu reason=%s",
                    static_cast<unsigned long long>(context.connectionId),
                    ServiceName(context.rpc.header.serviceHash), context.rpc.header.methodId,
                    context.rpc.header.token, static_cast<unsigned long long>(context.rpc.body.size()),
                    observation.error.c_str());
                return;
            }

            const std::string description = DescribeProtoMessage(observation);
            if (previous == context.session.requestShapeByRoute.end())
            {
                context.session.requestShapeByRoute.emplace(key, observation.shapeHash);
                log::Print("[BGS-DECODE] id=%llu serviceHash=0x%08X service=%s method=%u token=%u shape=0x%016llX fields={%s} packetMatching=off",
                    static_cast<unsigned long long>(context.connectionId), context.rpc.header.serviceHash,
                    ServiceName(context.rpc.header.serviceHash), context.rpc.header.methodId,
                    context.rpc.header.token, static_cast<unsigned long long>(observation.shapeHash),
                    description.c_str());
                return;
            }

            if (previous->second != observation.shapeHash)
            {
                log::Print("[BGS-COMPAT] id=%llu service=%s method=%u request-shape changed old=0x%016llX new=0x%016llX fields={%s} action=ACCEPT_AND_ROUTE reason=protobuf optional/extra fields do not require exact packet bytes",
                    static_cast<unsigned long long>(context.connectionId), ServiceName(context.rpc.header.serviceHash),
                    context.rpc.header.methodId, static_cast<unsigned long long>(previous->second),
                    static_cast<unsigned long long>(observation.shapeHash), description.c_str());
                previous->second = observation.shapeHash;
            }
        }
    }

    const char* ServiceName(std::uint32_t serviceHash)
    {
        const auto* service = FindService(serviceHash);
        return service ? service->name : "UnknownService";
    }

    void QueueResponse(RequestContext& context, const std::vector<Byte>& body,
        const char* label, std::uint32_t status)
    {
        OutgoingRpc message;
        message.payload = BuildResponsePayload(context.rpc.header.token, body, status);
        message.label = label ? label : "BGS response";
        message.serviceHash = context.rpc.header.serviceHash;
        message.methodId = context.rpc.header.methodId;
        message.token = context.rpc.header.token;
        message.serverRequest = false;
        context.outgoing.push_back(std::move(message));
    }

    void QueueServerRequest(RequestContext& context, std::uint32_t serviceHash,
        std::uint32_t methodId, const std::vector<Byte>& body, const char* label,
        std::uint32_t* tokenOut)
    {
        const std::uint32_t token = context.session.nextServerRequestToken++;
        OutgoingRpc message;
        message.payload = BuildRequestPayload(serviceHash, methodId, token, body);
        message.label = label ? label : "BGS server request";
        message.serviceHash = serviceHash;
        message.methodId = methodId;
        message.token = token;
        message.serverRequest = true;
        context.session.pendingServerRequests[token] = message.label;
        context.outgoing.push_back(std::move(message));
        if (tokenOut) *tokenOut = token;
    }

    void QueueServerNotification(RequestContext& context, std::uint32_t serviceHash,
        std::uint32_t methodId, const std::vector<Byte>& body, const char* label,
        std::uint32_t* tokenOut)
    {
        const std::uint32_t token = context.session.nextServerRequestToken++;
        OutgoingRpc message;
        message.payload = BuildRequestPayload(serviceHash, methodId, token, body);
        message.label = label ? label : "BGS server notification";
        message.serviceHash = serviceHash;
        message.methodId = methodId;
        message.token = token;
        message.serverRequest = true;
        context.outgoing.push_back(std::move(message));
        if (tokenOut) *tokenOut = token;
    }

    void MarkHandled(RequestContext& context, const char* detail)
    {
        ++context.session.handledRequests;
        log::Print("[BGS-HANDLED] id=%llu serviceHash=0x%08X service=%s method=%u token=%u bodyBytes=%llu detail=%s",
            static_cast<unsigned long long>(context.connectionId), context.rpc.header.serviceHash,
            ServiceName(context.rpc.header.serviceHash), context.rpc.header.methodId,
            context.rpc.header.token, static_cast<unsigned long long>(context.rpc.body.size()),
            detail ? detail : "handled");
        PrintCoverage(context);
    }

    void MarkMissing(RequestContext& context, const char* reason)
    {
        ++context.session.missingRequests;
        const auto key = RouteKey(context.rpc.header.serviceHash, context.rpc.header.methodId);
        const bool first = context.session.missingKeys.insert(key).second;
        log::Print("[BGS-MISSING] id=%llu serviceHash=0x%08X service=%s method=%u token=%u bodyBytes=%llu first=%s need=SEMANTIC_HANDLER reason=%s policy=DO_NOT_GUESS_RESPONSE_BYTES",
            static_cast<unsigned long long>(context.connectionId), context.rpc.header.serviceHash,
            ServiceName(context.rpc.header.serviceHash), context.rpc.header.methodId,
            context.rpc.header.token, static_cast<unsigned long long>(context.rpc.body.size()),
            first ? "yes" : "no", reason ? reason : "unimplemented service/method");
        PrintCoverage(context);
    }

    bool DispatchRequest(RequestContext& context)
    {
        if (context.rpc.header.serviceId != 0u || !context.rpc.header.hasServiceHash || !context.rpc.header.hasMethodId)
        {
            MarkMissing(context, "not a normal service request or missing service/method metadata");
            return true;
        }

        ObserveRequestShape(context);

        const auto* service = FindService(context.rpc.header.serviceHash);
        if (!service)
        {
            MarkMissing(context, "service hash is not in the IW8 semantic registry yet");
            return true;
        }
        if (!service->handler)
        {
            MarkMissing(context, "service is named but no response semantics are implemented yet");
            return true;
        }

        return service->handler(context);
    }

    bool HandleClientResponse(std::uint64_t connectionId, const RpcEnvelope& rpc, SessionState& session)
    {
        if (rpc.header.serviceId != 0xFEu)
            return false;

        // Notifications do not require replies. If the client nevertheless
        // replies, correlate only the same connection's last queued session token.
        // This is diagnostic evidence, not proof that CompleteSignIn executed.
        if (session.sessionCreatedNotificationSent &&
            rpc.header.token == session.sessionCreatedNotificationToken)
        {
            log::Print("[BGS-SESSION-COMPLETION] id=%llu notification=OnSessionCreated token=%u "
                "replyObserved=yes statusPresent=%s status=%u completionExecuted=UNKNOWN",
                static_cast<unsigned long long>(connectionId), rpc.header.token,
                rpc.header.hasStatus ? "yes" : "no", rpc.header.status);
            return true;
        }

        const auto pending = session.pendingServerRequests.find(rpc.header.token);
        if (pending != session.pendingServerRequests.end())
        {
            const std::string label = pending->second;
            session.pendingServerRequests.erase(pending);
            log::Print("[BGS-CALLBACK-ACK] id=%llu token=%u label=%s status=%s%u (%s) pending=%llu",
                static_cast<unsigned long long>(connectionId), rpc.header.token, label.c_str(),
                rpc.header.hasStatus ? "" : "<missing>/", rpc.header.status,
                rpc.header.hasStatus ? StatusName(rpc.header.status) : "unknown",
                static_cast<unsigned long long>(session.pendingServerRequests.size()));
            return true;
        }

        log::Print("[BGS-RPC] id=%llu response token=%u status=%s%u (%s) serviceHash=%s0x%08X; response has no tracked server-request owner",
            static_cast<unsigned long long>(connectionId), rpc.header.token,
            rpc.header.hasStatus ? "" : "<missing>/", rpc.header.status,
            rpc.header.hasStatus ? StatusName(rpc.header.status) : "unknown",
            rpc.header.hasServiceHash ? "" : "<missing>/", rpc.header.serviceHash);
        return true;
    }
}
