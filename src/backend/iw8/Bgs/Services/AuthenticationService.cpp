#include "AuthenticationService.h"
#include "../BgsDispatcher.h"
#include "../../Log.h"

#include <random>

namespace revamped::iw8::bgs
{
    namespace
    {
        void EnsureSessionKey(SessionState& session)
        {
            if (session.authSessionKey.size() == 64u)
                return;

            session.authSessionKey.resize(64u);
            std::random_device random;
            for (auto& byte : session.authSessionKey)
                byte = static_cast<Byte>(random() & 0xFFu);
        }

        std::vector<Byte> BuildLogonResult(SessionState& session)
        {
            EnsureSessionKey(session);
            std::vector<Byte> body;

            // bgs.protocol.authentication.v1.LogonResult. Populate every known
            // login-completion field with a local/synthetic value so the stock
            // client does not stall on a missing presence bit.
            AppendVarintField(body, 1, 0u);                              // error_code = ERROR_OK
            AppendEntityIdField(body, 2, session.accountId);             // account_id
            AppendEntityIdField(body, 3, session.gameAccountId);         // game_account_id
            AppendStringField(body, 4, "revamped@local.invalid");       // email
            AppendVarintField(body, 5, 1u);                              // available_region
            AppendVarintField(body, 6, 1u);                              // connected_region
            AppendStringField(body, 7, "Revamped#0001");                // battle_tag
            AppendStringField(body, 8, "US");                           // geoip_country
            AppendBytesField(body, 9, session.authSessionKey);           // session_key
            AppendVarintField(body, 10, 0u);                             // restricted_mode=false, explicitly present
            AppendStringField(body, 11, session.clientId);                 // client_id
            return body;
        }

        std::vector<Byte> BuildGameAccountSelected(const EntityId& gameAccount)
        {
            std::vector<Byte> body;
            AppendVarintField(body, 1, 0u);                  // result = ERROR_OK
            AppendEntityIdField(body, 2, gameAccount);       // selected game account
            return body;
        }

        void QueueNoData(RequestContext& context, const char* label, const char* detail)
        {
            const std::vector<Byte> noData;
            QueueResponse(context, noData, label);
            MarkHandled(context, detail);
        }
    }

    bool HandleAuthenticationService(RequestContext& context)
    {
        const auto method = context.rpc.header.methodId;
        log::Print("[BGS-AUTH] id=%llu AuthenticationService method=%u token=%u bodyBytes=%llu",
            static_cast<unsigned long long>(context.connectionId), method,
            context.rpc.header.token, static_cast<unsigned long long>(context.rpc.body.size()));

        if (method == 1u)
        {
            if (!context.session.authLogonCompleteSent)
            {
                const auto logonResult = BuildLogonResult(context.session);
                std::uint32_t callbackToken = 0;
                QueueServerNotification(context, AuthenticationListenerHash, 5u, logonResult,
                    "AuthenticationListener.OnLogonComplete", &callbackToken);
                context.session.authLogonCompleteSent = true;
                context.session.authLogonCompleteToken = callbackToken;
                context.session.authenticated = true;
                log::Print("[BGS-AUTH] id=%llu queued OnLogonComplete token=%u fields={error,account,gameAccount,email,availableRegion,connectedRegion,battleTag,country,sessionKey,restrictedMode,clientId} sessionKeyBytes=%llu",
                    static_cast<unsigned long long>(context.connectionId), callbackToken,
                    static_cast<unsigned long long>(context.session.authSessionKey.size()));
            }

            const std::vector<Byte> noData;
            QueueResponse(context, noData, "AuthenticationService.Logon NoData response");
            context.session.authLogonResponseSent = true;
            MarkHandled(context, "LogonComplete callback + NoData response queued");
            return true;
        }

        // These methods have NoData responses in the public BGS authentication
        // service. A local backend can acknowledge them without inventing data.
        if (method == 2u)
        {
            QueueNoData(context, "AuthenticationService.ModuleNotify NoData response", "ModuleNotify acknowledged");
            return true;
        }
        if (method == 3u)
        {
            QueueNoData(context, "AuthenticationService.ModuleMessage NoData response", "ModuleMessage acknowledged");
            return true;
        }
        if (method == 4u)
        {
            // Deprecated form sends EntityId directly as the request body.
            EntityId requested{};
            const bool hasHigh = TryGetFixed64Field(context.rpc.body.data(), context.rpc.body.size(), 1u, requested.high);
            const bool hasLow = TryGetFixed64Field(context.rpc.body.data(), context.rpc.body.size(), 2u, requested.low);
            requested.valid = hasHigh && hasLow;
            if (requested.valid)
                context.session.gameAccountId = requested;
            context.session.gameAccountSelected = true;
            QueueNoData(context, "AuthenticationService.SelectGameAccount_DEPRECATED NoData response", "deprecated game account selection acknowledged");
            return true;
        }
        if (method == 6u)
        {
            EntityId selected = context.session.gameAccountId;
            EntityId requested{};
            if (TryGetEntityIdField(context.rpc.body.data(), context.rpc.body.size(), 1u, requested))
                selected = requested;
            context.session.gameAccountId = selected;
            context.session.gameAccountSelected = true;

            const std::vector<Byte> noData;
            QueueResponse(context, noData, "AuthenticationService.SelectGameAccount NoData response");
            const auto callback = BuildGameAccountSelected(selected);
            QueueServerNotification(context, AuthenticationListenerHash, 14u, callback,
                "AuthenticationListener.OnGameAccountSelected");
            log::Print("[BGS-AUTH] id=%llu SelectGameAccount accepted high=0x%016llX low=0x%016llX; queued OnGameAccountSelected result=ERROR_OK",
                static_cast<unsigned long long>(context.connectionId),
                static_cast<unsigned long long>(selected.high), static_cast<unsigned long long>(selected.low));
            MarkHandled(context, "SelectGameAccount response + OnGameAccountSelected queued");
            return true;
        }
        if (method == 7u)
        {
            QueueNoData(context, "AuthenticationService.VerifyWebCredentials NoData response", "local web credentials accepted");
            return true;
        }

        if (method == 5u)
        {
            std::uint32_t program = 0;
            const bool hasProgram = TryGetFixed32Field(context.rpc.body.data(), context.rpc.body.size(), 1u, program);
            std::vector<Byte> response;
            AppendStringField(response, 1u, "revamped-iw8-sso-id");
            AppendStringField(response, 2u, "revamped-iw8-sso-secret");
            QueueResponse(context, response, "AuthenticationService.GenerateSSOToken response");
            log::Print("[BGS-AUTH] id=%llu GenerateSSOToken token=%u program=%s0x%08X -> local SSO pair",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                hasProgram ? "" : "<missing>/", program);
            MarkHandled(context, "GenerateSSOToken returned local synthetic credentials");
            return true;
        }
        if (method == 8u)
        {
            // The exact IW8 descriptor maps method 8 to GenerateWebCredentials.
            // Request field 1 is fixed32 program; response field 1 is bytes web_credentials.
            std::uint32_t program = 0;
            const bool hasProgram = TryGetFixed32Field(context.rpc.body.data(), context.rpc.body.size(), 1u, program);
            const std::string credentials = "revamped-local-web-credentials";
            std::vector<Byte> response;
            AppendBytesField(response, 1u, credentials.data(), credentials.size());
            QueueResponse(context, response, "AuthenticationService.GenerateWebCredentials response");
            log::Print("[BGS-AUTH] id=%llu GenerateWebCredentials token=%u program=%s0x%08X credentialBytes=%llu",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                hasProgram ? "" : "<missing>/", program,
                static_cast<unsigned long long>(credentials.size()));
            MarkHandled(context, "GenerateWebCredentials returned local web credential blob");
            return true;
        }

        MarkMissing(context, "AuthenticationService method requires response data or is not yet observed");
        return true;
    }
}
