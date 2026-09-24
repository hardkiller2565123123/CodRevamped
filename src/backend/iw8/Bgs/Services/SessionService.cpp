#include "SessionService.h"
#include "../BgsDispatcher.h"
#include "../Listeners/SessionListener.h"
#include "Common/Logging/Log.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace revamped::iw8::bgs
{
    namespace
    {
        std::string FourCc(std::uint32_t value)
        {
            std::string out(4, '.');
            for (unsigned i = 0; i < 4; ++i)
            {
                const auto shift = (3u - i) * 8u;
                const auto ch = static_cast<unsigned char>((value >> shift) & 0xFFu);
                out[i] = std::isprint(ch) ? static_cast<char>(ch) : '.';
            }
            return out;
        }

        bool SameBytes(const std::vector<Byte>& left, const std::vector<Byte>& right)
        {
            return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin());
        }
    }

    bool HandleSessionService(RequestContext& context)
    {
        const auto method = context.rpc.header.methodId;
        if (method == 1u)
        {
            // The IW8 BGS descriptors identify method 1 as CreateSession.
            // Request fields:
            // 1 identity (Identity), 2 platform (fixed32), 3 locale (fixed32),
            // 4 client_address, 5 application_version, 6 user_agent,
            // 7 session_key, 8 options, 9 mac_address.
            std::vector<Byte> identity;
            std::vector<Byte> clientAddress;
            std::vector<Byte> requestSessionKey;
            std::vector<Byte> options;
            std::vector<Byte> macAddress;
            std::vector<Byte> userAgentBytes;
            std::uint32_t platform = 0;
            std::uint32_t locale = 0;
            std::uint64_t applicationVersion = 0;

            const bool hasIdentity = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 1u, identity);
            const bool hasPlatform = TryGetFixed32Field(context.rpc.body.data(), context.rpc.body.size(), 2u, platform);
            const bool hasLocale = TryGetFixed32Field(context.rpc.body.data(), context.rpc.body.size(), 3u, locale);
            const bool hasClientAddress = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 4u, clientAddress);
            const bool hasApplicationVersion = TryGetVarintField(context.rpc.body.data(), context.rpc.body.size(), 5u, applicationVersion);
            const bool hasUserAgent = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 6u, userAgentBytes);
            const bool hasSessionKey = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 7u, requestSessionKey);
            const bool hasOptions = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 8u, options);
            const bool hasMacAddress = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 9u, macAddress);

            const bool sessionKeyMatches = hasSessionKey && SameBytes(requestSessionKey, context.session.authSessionKey);
            const std::string platformText = FourCc(platform);
            const std::string localeText = FourCc(locale);
            const std::string userAgent(userAgentBytes.begin(), userAgentBytes.end());

            // Learn the client's compatibility fingerprint from semantic fields.
            // Do not branch on a captured packet blob: 1.44/nearby IW8 builds can
            // carry different optional fields and still hit the same handlers.
            if (hasApplicationVersion)
            {
                context.session.hasApplicationVersion = true;
                context.session.applicationVersion = applicationVersion;
            }
            if (hasPlatform)
            {
                context.session.hasPlatform = true;
                context.session.platform = platform;
            }
            if (hasLocale)
            {
                context.session.hasLocale = true;
                context.session.locale = locale;
            }
            if (hasUserAgent)
                context.session.userAgent = userAgent;

            log::Print("[BGS-SESSION] id=%llu CreateSession token=%u bodyBytes=%llu compat=%s fields={identity:%s%llu platform:%s0x%08X/'%s' locale:%s0x%08X/'%s' clientAddress:%s%llu applicationVersion:%s%llu userAgent:%s'%s' sessionKey:%s%llu keyMatchesAuth:%s options:%s%llu macAddress:%s%llu}",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                static_cast<unsigned long long>(context.rpc.body.size()),
                context.session.compatibilityProfile.c_str(),
                hasIdentity ? "" : "<missing>/", static_cast<unsigned long long>(identity.size()),
                hasPlatform ? "" : "<missing>/", platform, platformText.c_str(),
                hasLocale ? "" : "<missing>/", locale, localeText.c_str(),
                hasClientAddress ? "" : "<missing>/", static_cast<unsigned long long>(clientAddress.size()),
                hasApplicationVersion ? "" : "<missing>/", static_cast<unsigned long long>(applicationVersion),
                hasUserAgent ? "" : "<missing>/", hasUserAgent ? userAgent.c_str() : "",
                hasSessionKey ? "" : "<missing>/", static_cast<unsigned long long>(requestSessionKey.size()),
                sessionKeyMatches ? "YES" : "NO",
                hasOptions ? "" : "<missing>/", static_cast<unsigned long long>(options.size()),
                hasMacAddress ? "" : "<missing>/", static_cast<unsigned long long>(macAddress.size()));

            // CreateSessionResponse contains only field 1: session_id.
            std::vector<Byte> response;
            AppendStringField(response, 1u, context.session.sessionId);
            QueueResponse(context, response, "SessionService.CreateSession response");

            // CreateSessionResponse alone is not the full stock completion flow.
            // IW8 exposes BattleNetAuth::CreateSessionCallback followed by
            // BattleNetAuth::OnSessionCreated and CompleteSignIn, and the BGS
            // descriptors define SessionListener.OnSessionCreated. Send the
            // listener notification with the exact Identity/session key the
            // stock client supplied so the local session is internally coherent.
            if (hasIdentity && hasSessionKey && sessionKeyMatches)
            {
                QueueSessionCreatedNotification(context, identity, requestSessionKey);
                MarkHandled(context, "CreateSession response + OnSessionCreated notification queued");
            }
            else
            {
                MarkMissing(context, "CreateSession request did not carry the expected Identity/auth session key; listener notification withheld");
            }
            return true;
        }

        if (method == 10u)
        {
            // The post-sign-in IW8 method-10 request is exactly the descriptor
            // shape of GetSessionStateRequest: field 1 = GameAccountHandle.
            std::vector<Byte> handle;
            const bool hasHandle = TryGetBytesField(context.rpc.body.data(), context.rpc.body.size(), 1u, handle);
            if (!hasHandle)
            {
                MarkMissing(context, "SessionService method 10 did not contain the expected GameAccountHandle");
                return true;
            }

            // GetSessionStateResponse { handle=1, session=2 }.  SessionState's
            // required identity is its handle; the remaining billing/location
            // fields are optional and should stay absent for a local unlimited
            // preservation session rather than being guessed.
            std::vector<Byte> state;
            AppendBytesField(state, 1u, handle);

            std::vector<Byte> response;
            AppendBytesField(response, 1u, handle);
            AppendBytesField(response, 2u, state);
            QueueResponse(context, response, "SessionService.GetSessionState response");
            log::Print("[BGS-SESSION] id=%llu GetSessionState token=%u handleBytes=%llu sessionId='%s'",
                static_cast<unsigned long long>(context.connectionId), context.rpc.header.token,
                static_cast<unsigned long long>(handle.size()), context.session.sessionId.c_str());
            MarkHandled(context, "GetSessionState returned local active session");
            return true;
        }

        MarkMissing(context, "SessionService method not implemented; do not silently swallow post-auth work");
        return true;
    }
}
