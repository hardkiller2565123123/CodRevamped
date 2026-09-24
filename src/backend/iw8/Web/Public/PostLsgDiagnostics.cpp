#include "PostLsgDiagnostics.h"

namespace revamped::iw8::web
{
    void NotePostLsgTransport(std::uint16_t port, const char* transport)
    {
        if (g_authPipeline.pendingLsgAtMs == 0 || g_authPipeline.postLsgTransportSeen)
            return;
        if (port != 3074u && port != 3075u)
            return;

        const ULONGLONG ageMs = GetTickCount64() - g_authPipeline.pendingLsgAtMs;
        const std::string transportText = transport && *transport ? transport : "?";
        if (transportText.find("UNATTRIBUTED") != std::string::npos)
        {
            ++g_authPipeline.postLsgUnattributedActivity;
            if (g_authPipeline.postLsgUnattributedActivity <= 4u)
            {
                log::Print("[AUTH-PIPELINE] POST-LSG SOCKET ACTIVITY auth3Serial=%llu ageMs=%llu transport=%s port=%u attribution=UNVERIFIED; UDP/3074 can be STUN and does NOT prove mw-lobby routing",
                    static_cast<unsigned long long>(g_authPipeline.pendingLsgSerial),
                    static_cast<unsigned long long>(ageMs), transportText.c_str(), static_cast<unsigned>(port));
            }
            return;
        }

        g_authPipeline.postLsgTransportSeen = true;
        log::Print("[AUTH-PIPELINE] POST-LSG ATTRIBUTED TRANSPORT auth3Serial=%llu ageMs=%llu transport=%s port=%u; attribution supplied by protocol-specific listener",
            static_cast<unsigned long long>(g_authPipeline.pendingLsgSerial),
            static_cast<unsigned long long>(ageMs), transportText.c_str(), static_cast<unsigned>(port));
    }
}
