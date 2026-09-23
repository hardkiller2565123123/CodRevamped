#include "AccountService.h"
#include "../BgsDispatcher.h"
#include "../../Log.h"

namespace revamped::iw8::bgs
{
    namespace
    {
        std::vector<Byte> BuildAccountStatePayload()
        {
            std::vector<Byte> accountLevel;
            AppendStringField(accountLevel, 5, "US");
            AppendVarintField(accountLevel, 6, 1u);
            AppendStringField(accountLevel, 8, "Revamped#0001");

            std::vector<Byte> privacy;
            AppendVarintField(privacy, 3, 0u); // is_using_rid=false, explicitly present
            AppendVarintField(privacy, 4, 0u); // real-id-visible=false
            AppendVarintField(privacy, 5, 1u); // hidden_from_friend_finder=true

            std::vector<Byte> state;
            AppendBytesField(state, 1, accountLevel);
            AppendBytesField(state, 2, privacy);
            return state;
        }

        std::vector<Byte> BuildAccountTagsPayload()
        {
            std::vector<Byte> tags;
            AppendFixed32Field(tags, 2, 0x52564D50u); // stable local account-level tag
            AppendFixed32Field(tags, 3, 0xD7CA834Du); // common privacy-info tag used by public BGS backends
            return tags;
        }

        std::vector<Byte> BuildAccountStateResponse()
        {
            // GetAccountStateResponse { state=1, tags=2 }
            const auto state = BuildAccountStatePayload();
            const auto tags = BuildAccountTagsPayload();

            std::vector<Byte> response;
            AppendBytesField(response, 1, state);
            AppendBytesField(response, 2, tags);
            return response;
        }

        std::vector<Byte> BuildGameAccountStatePayload()
        {
            std::vector<Byte> level;
            AppendVarintField(level, 3, 0u);              // starter edition=false, explicit
            AppendVarintField(level, 4, 0u);              // trial=false
            AppendVarintField(level, 5, 1u);              // lifetime=true
            AppendVarintField(level, 6, 0u);              // restricted=false
            AppendVarintField(level, 7, 0u);              // beta=false
            AppendStringField(level, 8, "Revamped");
            AppendFixed32Field(level, 9, OdinProgramId);

            std::vector<Byte> time;
            AppendVarintField(time, 3, 1u);               // unlimited play time
            AppendVarintField(time, 6, 0u);               // subscription=false, explicit
            AppendVarintField(time, 7, 0u);               // recurring=false, explicit

            std::vector<Byte> status;
            AppendVarintField(status, 4, 0u);             // suspended=false, explicit
            AppendVarintField(status, 5, 0u);             // banned=false, explicit
            AppendFixed32Field(status, 7, OdinProgramId);

            std::vector<Byte> state;
            AppendBytesField(state, 1, level);
            AppendBytesField(state, 2, time);
            AppendBytesField(state, 3, status);
            return state;
        }

        std::vector<Byte> BuildGameAccountTagsPayload()
        {
            std::vector<Byte> tags;
            AppendFixed32Field(tags, 2, 0x52564D31u);
            AppendFixed32Field(tags, 3, 0x52564D32u);
            AppendFixed32Field(tags, 4, 0x52564D33u);
            return tags;
        }

        std::vector<Byte> BuildGameAccountStateResponse()
        {
            // GetGameAccountStateResponse { state=1, tags=2 }
            const auto state = BuildGameAccountStatePayload();
            const auto tags = BuildGameAccountTagsPayload();

            std::vector<Byte> response;
            AppendBytesField(response, 1, state);
            AppendBytesField(response, 2, tags);
            return response;
        }

        std::vector<Byte> BuildAccountStateNotification()
        {
            // AccountStateNotification {
            //   account_state=1, subscriber_id=2 (deprecated/omitted),
            //   account_tags=3, subscription_completed=4
            // }
            const auto state = BuildAccountStatePayload();
            const auto tags = BuildAccountTagsPayload();

            std::vector<Byte> notification;
            AppendBytesField(notification, 1u, state);
            AppendBytesField(notification, 3u, tags);
            AppendVarintField(notification, 4u, 1u);
            return notification;
        }

        std::vector<Byte> BuildGameAccountStateNotification()
        {
            // GameAccountStateNotification {
            //   game_account_state=1, subscriber_id=2 (deprecated/omitted),
            //   game_account_tags=3, subscription_completed=4
            // }
            const auto state = BuildGameAccountStatePayload();
            const auto tags = BuildGameAccountTagsPayload();

            std::vector<Byte> notification;
            AppendBytesField(notification, 1u, state);
            AppendBytesField(notification, 3u, tags);
            AppendVarintField(notification, 4u, 1u);
            return notification;
        }
    }

    bool HandleAccountService(RequestContext& context)
    {
        const auto method = context.rpc.header.methodId;
        if (!context.session.authenticated)
        {
            log::Print("[BGS-ACCOUNT] id=%llu method=%u arrived before AuthenticationService.Logon completion; still answering local account bootstrap",
                static_cast<unsigned long long>(context.connectionId), method);
        }

        if (method == 25u)
        {
            // AccountService.Subscribe.  IW8 sends SubscriptionUpdateRequest
            // with repeated field 2 (SubscriberReference).  The response uses
            // repeated field 1 with the accepted references.
            std::vector<std::vector<Byte>> refs;
            TryGetBytesFields(context.rpc.body.data(), context.rpc.body.size(), 2u, refs);
            std::vector<Byte> response;
            for (const auto& ref : refs)
                AppendBytesField(response, 1u, ref);
            QueueResponse(context, response, "AccountService.Subscribe response");

            // IW8's post-sign-in fence registers AccountListener method 2 and
            // waits for the account subscription to actually complete. Merely
            // echoing SubscriptionUpdateResponse leaves that fence pending. Send
            // the protocol-defined initial state notifications only in direct
            // response to Subscribe; this is normal BGS server behavior, not a
            // client-side state write or forced fence transition.
            const auto accountNotification = BuildAccountStateNotification();
            const auto gameAccountNotification = BuildGameAccountStateNotification();
            std::uint32_t accountNotificationToken = 0;
            std::uint32_t gameAccountNotificationToken = 0;
            QueueServerNotification(context, AccountListenerHash, 1u, accountNotification,
                "AccountListener.OnAccountStateUpdated subscription-complete",
                &accountNotificationToken);
            QueueServerNotification(context, AccountListenerHash, 2u, gameAccountNotification,
                "AccountListener.OnGameAccountStateUpdated subscription-complete",
                &gameAccountNotificationToken);

            log::Print("[BGS-ACCOUNT] id=%llu Subscribe token=%u refs=%llu responseBytes=%llu",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                static_cast<unsigned long long>(refs.size()),
                static_cast<unsigned long long>(response.size()));
            log::Print("[BGS-POSTFENCE-V18] id=%llu source=AccountService.Subscribe listenerHash=0x%08X "
                "queued={m1:OnAccountStateUpdated/token=%u/bytes=%llu,m2:OnGameAccountStateUpdated/token=%u/bytes=%llu} "
                "subscriptionCompleted=true subscriberId=omitted-deprecated refs=%llu stateWrites=off",
                static_cast<unsigned long long>(context.connectionId), AccountListenerHash,
                accountNotificationToken, static_cast<unsigned long long>(accountNotification.size()),
                gameAccountNotificationToken, static_cast<unsigned long long>(gameAccountNotification.size()),
                static_cast<unsigned long long>(refs.size()));
            MarkHandled(context, "Account subscriptions accepted; initial AccountListener state notifications queued");
            return true;
        }

        if (method == 26u)
        {
            const std::vector<Byte> noData;
            QueueResponse(context, noData, "AccountService.Unsubscribe NoData response");
            MarkHandled(context, "Account subscriptions removed");
            return true;
        }

        if (method == 30u)
        {
            std::uint64_t program = 0;
            std::uint64_t region = 0;
            const bool hasProgram = TryGetVarintField(context.rpc.body.data(), context.rpc.body.size(), 2u, program);
            const bool hasRegion = TryGetVarintField(context.rpc.body.data(), context.rpc.body.size(), 3u, region);
            const auto response = BuildAccountStateResponse();
            QueueResponse(context, response, "AccountService.GetAccountState response");
            log::Print("[BGS-ACCOUNT] id=%llu GetAccountState token=%u program=%s0x%08llX region=%s%llu responseBytes=%llu",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                hasProgram ? "" : "<missing>/", static_cast<unsigned long long>(program),
                hasRegion ? "" : "<missing>/", static_cast<unsigned long long>(region),
                static_cast<unsigned long long>(response.size()));
            MarkHandled(context, "minimal local AccountState + tags queued");
            return true;
        }

        if (method == 31u)
        {
            EntityId requested{};
            const bool hasGameAccount = TryGetEntityIdField(context.rpc.body.data(), context.rpc.body.size(), 2u, requested);
            if (hasGameAccount)
                context.session.gameAccountId = requested;
            const auto response = BuildGameAccountStateResponse();
            QueueResponse(context, response, "AccountService.GetGameAccountState response");
            log::Print("[BGS-ACCOUNT] id=%llu GetGameAccountState token=%u gameAccount=%s high=0x%016llX low=0x%016llX responseBytes=%llu",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                hasGameAccount ? "request" : "local-default",
                static_cast<unsigned long long>(context.session.gameAccountId.high),
                static_cast<unsigned long long>(context.session.gameAccountId.low),
                static_cast<unsigned long long>(response.size()));
            MarkHandled(context, "minimal local GameAccountState + tags queued");
            return true;
        }

        if (method == 44u)
        {
            // AccountService.GetSignedAccountState. IW8 1.44 sends
            // GetSignedAccountStateRequest { account: AccountId } here after the
            // initial online-services bootstrap. The response schema contains only
            // field 1: token (string). This is a local/offline synthetic token; no
            // production Blizzard signing material is used or required by the server.
            std::vector<Byte> account;
            const bool hasAccount = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 1u, account);

            std::vector<Byte> response;
            AppendStringField(response, 1u, "revamped-iw8-local-signed-account-state");
            QueueResponse(context, response, "AccountService.GetSignedAccountState response");
            log::Print("[BGS-ACCOUNT] id=%llu GetSignedAccountState token=%u accountBytes=%llu accountPresent=%s signedTokenBytes=%llu",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                static_cast<unsigned long long>(account.size()), hasAccount ? "yes" : "no",
                static_cast<unsigned long long>(sizeof("revamped-iw8-local-signed-account-state") - 1));
            MarkHandled(context, "local signed-account-state token queued");
            return true;
        }

        MarkMissing(context, "AccountService method not implemented yet; likely post-auth dependency if observed");
        return true;
    }
}
