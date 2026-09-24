#include "AuthPipelineState.h"

namespace revamped::iw8::web
{
    namespace
    {
        struct AuthPipelineCorrelation
        {
            std::string lastAuth3ClientTicket;
            std::string lastAuth3ServerTicket;
            // V72: preserve only the protocol values needed to test which 24-byte
            // secret the stock client actually feeds into the LSG KDF.  These are
            // never printed raw; ServerLsg compares derived proofs only.
            std::string lastAuth3IvSeed;
            std::string lastUmbrellaInitialVectorSeed;
            std::string lastMintedLsgToken;
            std::uint64_t auth3Serial = 0;
            ULONGLONG auth3IssuedAtMs = 0;
            std::uint32_t auth3TitleId = 0;

            std::uint64_t pendingLsgSerial = 0;
            ULONGLONG pendingLsgAtMs = 0;
            unsigned pendingLsgWarnings = 0;
            unsigned postLsgUnattributedActivity = 0;
            bool postLsgTransportSeen = false;
            volatile LONG umbrellaSweepCount = 0;
        };

        AuthPipelineCorrelation g_authPipeline;

        void AppendAuthPipelineV58(const char* format, ...)
        {
            if (!format) return;
            char message[2048]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
            va_end(args);
            char line[2304]{};
            _snprintf_s(line, sizeof(line), _TRUNCATE, "[%llu] %s\r\n",
                static_cast<unsigned long long>(GetTickCount64()), message);
            log::Print("[AUTH-V60] %s", message);
            HANDLE file = CreateFileA("auth_pipeline_v60.log", FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            DWORD written = 0;
            if (file != INVALID_HANDLE_VALUE)
            {
                WriteFile(file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
                CloseHandle(file);
            }

            // V60: mirror the server-side auth timeline into the same server_emu
            // folder the client research logs use, so one ZIP contains both sides.
            CreateDirectoryA("server_emu", nullptr);
            HANDLE mirror = CreateFileA("server_emu\\auth_pipeline_v60.log", FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (mirror != INVALID_HANDLE_VALUE)
            {
                written = 0;
                WriteFile(mirror, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
                CloseHandle(mirror);
            }
        }

        static constexpr std::uint8_t kLocalAuth3SessionKey[24] = {
            0x13,0x37,0x13,0x37,0x13,0x37,0x13,0x37,
            0x13,0x37,0x13,0x37,0x13,0x37,0x13,0x37,
            0x13,0x37,0x13,0x37,0x13,0x37,0x13,0x37
        };

        void RememberAuth3Tickets(const std::string& clientTicket, const std::string& serverTicket,
            std::uint32_t titleId)
        {
            g_authPipeline.lastAuth3ClientTicket = clientTicket;
            g_authPipeline.lastAuth3ServerTicket = serverTicket;
            g_authPipeline.auth3Serial += 1u;
            g_authPipeline.auth3IssuedAtMs = GetTickCount64();
            g_authPipeline.auth3TitleId = titleId;
            log::Print("[AUTH3-CORRELATION] auth3Serial=%llu clientTicketBytes=%llu serverTicketBytes=%llu titleId=%u values=REDACTED stateWrites=off",
                static_cast<unsigned long long>(g_authPipeline.auth3Serial),
                static_cast<unsigned long long>(clientTicket.size()),
                static_cast<unsigned long long>(serverTicket.size()),
                static_cast<unsigned>(titleId));
            AppendAuthPipelineV58("AUTH3_ISSUED serial=%llu titleId=%u clientTicketB64Bytes=%llu serverTicketB64Bytes=%llu serverTicketRawLayout=first24_session_key_then_zero values=REDACTED",
                static_cast<unsigned long long>(g_authPipeline.auth3Serial), static_cast<unsigned>(titleId),
                static_cast<unsigned long long>(clientTicket.size()), static_cast<unsigned long long>(serverTicket.size()));
        }

        struct Auth3TicketMatch
        {
            std::uint64_t serial = 0;
            ULONGLONG ageMs = 0;
            std::uint32_t titleId = 0;
            bool haveAuth3ClientTicket = false;
            bool haveAuth3ServerTicket = false;
            bool exactClientMatch = false;
            bool exactServerMatch = false;
        };

        Auth3TicketMatch CorrelateUmbrellaTicket(const std::string& ticket)
        {
            Auth3TicketMatch match{};
            match.serial = g_authPipeline.auth3Serial;
            match.titleId = g_authPipeline.auth3TitleId;
            match.haveAuth3ClientTicket = !g_authPipeline.lastAuth3ClientTicket.empty();
            match.haveAuth3ServerTicket = !g_authPipeline.lastAuth3ServerTicket.empty();
            match.exactClientMatch = match.haveAuth3ClientTicket && !ticket.empty() &&
                ticket == g_authPipeline.lastAuth3ClientTicket;
            match.exactServerMatch = match.haveAuth3ServerTicket && !ticket.empty() &&
                ticket == g_authPipeline.lastAuth3ServerTicket;
            if (g_authPipeline.auth3IssuedAtMs != 0)
                match.ageMs = GetTickCount64() - g_authPipeline.auth3IssuedAtMs;
            return match;
        }

        void MarkUmbrellaLsgAccepted(std::uint64_t auth3Serial)
        {
            g_authPipeline.pendingLsgSerial = auth3Serial;
            g_authPipeline.pendingLsgAtMs = GetTickCount64();
            g_authPipeline.pendingLsgWarnings = 0;
            g_authPipeline.postLsgUnattributedActivity = 0;
            g_authPipeline.postLsgTransportSeen = false;
        }
    }
}
