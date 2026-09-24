#include "SessionListener.h"
#include "Common/Logging/Log.h"

namespace revamped::iw8::bgs
{
    void QueueSessionCreatedNotification(RequestContext& context,
        const std::vector<Byte>& identity,
        const std::vector<Byte>& sessionKey)
    {
        // bgs.protocol.session.v1.SessionCreatedNotification
        //   1 identity
        //   2 reason
        //   3 session_id
        //   4 session_key
        //   5 client_id
        // The listener notification is the server-driven completion event the
        // stock BattleNetAuth path expects after CreateSessionCallback.
        std::vector<Byte> body;
        AppendBytesField(body, 1u, identity);
        AppendVarintField(body, 2u, 0u); // normal creation reason
        AppendStringField(body, 3u, context.session.sessionId);
        AppendBytesField(body, 4u, sessionKey);
        AppendStringField(body, 5u, context.session.clientId);

        std::uint32_t token = 0;
        QueueServerNotification(context, SessionListenerHash, 1u, body,
            "SessionListener.OnSessionCreated", &token);
        context.session.sessionCreatedNotificationSent = true;
        context.session.sessionCreatedNotificationToken = token;

        log::Print("[BGS-SESSION-LISTENER] id=%llu OnSessionCreated token=%u fields={identity:%llu reason:0 sessionId:'%s' sessionKey:%llu clientId:'%s'}",
            static_cast<unsigned long long>(context.connectionId), token,
            static_cast<unsigned long long>(identity.size()),
            context.session.sessionId.c_str(),
            static_cast<unsigned long long>(sessionKey.size()),
            context.session.clientId.c_str());
    }
}
