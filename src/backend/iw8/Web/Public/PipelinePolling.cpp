#include "PipelinePolling.h"

namespace revamped::iw8::web
{
    void PollAuthPipelineDiagnostics()
    {
        if (g_authPipeline.pendingLsgAtMs == 0 || g_authPipeline.postLsgTransportSeen)
            return;

        const ULONGLONG ageMs = GetTickCount64() - g_authPipeline.pendingLsgAtMs;
        if (ageMs >= 3000u && (g_authPipeline.pendingLsgWarnings & 1u) == 0u)
        {
            g_authPipeline.pendingLsgWarnings |= 1u;
            log::Print("[AUTH-PIPELINE] STALL auth3Serial=%llu ageMs=%llu stage=AFTER_LSG_HTTP_200 no ATTRIBUTED lobby transport observed yet; generic UDP/3074 is not sufficient because STUN shares that port",
                static_cast<unsigned long long>(g_authPipeline.pendingLsgSerial),
                static_cast<unsigned long long>(ageMs));
        }
        if (ageMs >= 9000u && (g_authPipeline.pendingLsgWarnings & 2u) == 0u)
        {
            g_authPipeline.pendingLsgWarnings |= 2u;
            log::Print("[AUTH-PIPELINE] STALL-PERSISTENT auth3Serial=%llu ageMs=%llu stage=AFTER_LSG_HTTP_200 no ATTRIBUTED mw-lobby transport observed; correlate client DNS->socket route before changing LSG/Auth3 protocol",
                static_cast<unsigned long long>(g_authPipeline.pendingLsgSerial),
                static_cast<unsigned long long>(ageMs));
        }
    }
}
