#include "AuthResponseBuilders.h"

namespace revamped::iw8::web
{
    namespace
    {
        #pragma pack(push, 1)
        struct DwAuthTicket

        {
            std::uint32_t magicNumber;
            std::uint8_t type;
            std::uint32_t titleId;
            std::uint32_t timeIssued;
            std::uint32_t timeExpires;
            std::uint64_t licenseId;
            std::uint64_t userId;
            char username[64];
            std::uint8_t sessionKey[24];
            std::uint8_t usingHashMagicNumber[3];
            std::uint8_t hash[4];
        };
        #pragma pack(pop)
        static_assert(sizeof(DwAuthTicket) == 128, "Demonware auth ticket must be 128 bytes");

        // V67: /v1.0/tokens/lsg/ is an exchange, not an echo.  The stock
        // client presents Auth3 server_ticket to Umbrella as its request
        // credential.  That server ticket is intentionally opaque (our local
        // form carries the 24-byte Auth3 key at byte 0), so handing it back as
        // the LSG token leaves bdLobby without a structured ticket/session key
        // to consume.  Mint a fresh 128-byte DW ticket for the LSG handoff,
        // preserving the already-proven Auth3 identity fields when available
        // and binding it to the exact same session key used by ServerLsg.
        std::string BuildLocalLsgTokenV67(std::uint32_t titleId)
        {
            DwAuthTicket ticket{};

            // Reuse the accepted Auth3 client-ticket identity payload when it
            // is available.  Do not trust/copy its timing or key material below.
            std::vector<std::uint8_t> auth3ClientRaw;
            if (!g_authPipeline.lastAuth3ClientTicket.empty() &&
                Base64Decode(g_authPipeline.lastAuth3ClientTicket, auth3ClientRaw) &&
                auth3ClientRaw.size() == sizeof(DwAuthTicket) &&
                ReadPackedU32(auth3ClientRaw, 0u) == 0xEFBDADDEu)
            {
                std::memcpy(&ticket, auth3ClientRaw.data(), sizeof(ticket));
            }

            ticket.magicNumber = 0xEFBDADDEu;
            ticket.type = 0;
            ticket.titleId = titleId;
            ticket.timeIssued = static_cast<std::uint32_t>(std::time(nullptr));
            ticket.timeExpires = ticket.timeIssued + 30000u;
            std::memcpy(ticket.sessionKey, kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const auto* bytes = reinterpret_cast<const std::uint8_t*>(&ticket);
            return Base64Encode(std::vector<std::uint8_t>(bytes, bytes + sizeof(ticket)));
        }

        std::string BuildDwBnetAuthResponse(const std::string& requestTask, const std::string& ivSeed,
            std::uint32_t titleId, const std::string& identity, const std::string& serviceLevel,
            const std::string& sessionToken)
        {
            // V72: remember the exact Auth3 IV-seed representation supplied by
            // stock IW8.  It is only used as a bounded candidate source later.
            g_authPipeline.lastAuth3IvSeed = ivSeed;
            // Battle.net-era Auth3 (T8 and later) uses the same 128-byte ticket
            // container but, unlike the older Steam Auth3 path, returns this
            // client ticket as raw bytes encoded with base64. Keep the session key
            // local and deterministic for the next lobby-service correlation step.
            DwAuthTicket ticket{};
            ticket.magicNumber = 0xEFBDADDEu;
            ticket.type = 0;
            ticket.titleId = titleId;
            ticket.timeIssued = static_cast<std::uint32_t>(std::time(nullptr));
            ticket.timeExpires = ticket.timeIssued + 30000u;
            ticket.licenseId = 0;
            ticket.userId = 0;
            const std::size_t usernameBytes = (std::min)(sessionToken.size(), sizeof(ticket.username) - 1u);
            if (usernameBytes != 0)
                std::memcpy(ticket.username, sessionToken.data(), usernameBytes);
            const std::string ticketUsername(ticket.username, usernameBytes);
            std::memcpy(ticket.sessionKey, kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const auto* ticketBytes = reinterpret_cast<const std::uint8_t*>(&ticket);
            std::vector<std::uint8_t> clientTicket(ticketBytes, ticketBytes + sizeof(ticket));
            std::vector<std::uint8_t> serverTicket(128u, 0u);
            std::memcpy(serverTicket.data(), kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const std::string clientB64 = Base64Encode(clientTicket);
            const std::string serverB64 = Base64Encode(serverTicket);
            const std::string extendedB64 = Base64Encode(std::vector<std::uint8_t>{'l','u','l'});
            RememberAuth3Tickets(clientB64, serverB64, titleId);

            unsigned long taskValue = 84u;
            if (!requestTask.empty())
            {
                char* end = nullptr;
                const unsigned long parsed = std::strtoul(requestTask.c_str(), &end, 10);
                if (end && *end == '\0') taskValue = parsed;
            }
            const std::string responseTask = std::to_string(taskValue + 1u);

            std::ostringstream nested;
            nested << "{\"username\":\"" << JsonEscape(ticketUsername)
                   << "\",\"time_to_live\":9999,\"extended_data\":\"" << extendedB64 << "\"}";

            std::ostringstream json;
            json << "{\"auth_task\":\"" << responseTask
                 << "\",\"code\":\"700\",\"iv_seed\":\"" << JsonEscape(ivSeed)
                 << "\",\"client_ticket\":\"" << clientB64
                 << "\",\"server_ticket\":\"" << serverB64
                  // ModernWarfare.exe 1.44 carries this exact Auth3 client ID.
                  // A project-name expansion looks plausible but is rejected by
                  // the stock response validator before DW state can advance.
                  << "\",\"client_id\":\"iw-cod-iw8-bnet\""
                 << ",\"account_type\":\"bnet\""
                 << ",\"crossplay_enabled\":false"
                 << ",\"loginqueue_eanbled\":false"
                 << ",\"identity\":\"" << JsonEscape(identity) << "\""
                 << ",\"extra_data\":\"" << JsonEscape(nested.str()) << "\""
                 // BNet Auth3 returns the granted service level.  The known T8
                 // implementation returns "paid" even when the incoming request
                 // advertises "free"; IW8 is now probed with that exact behavior.
                 << ",\"service_level\":\"paid\""
                 // The project's known T8 Demonware Auth3 implementation emits
                 // this member as JSON null. IW8 also reaches Umbrella without
                 // ever resolving the hostname we previously injected here, so
                 // stop inventing a lobby route in the Auth3 contract.
                 << ",\"lsg_endpoint\":null}";
            return json.str();
        }

        std::string BuildResponse(int status, const char* reason, const char* contentType,
            const std::string& body)
        {
            std::ostringstream out;
            out << "HTTP/1.1 " << status << ' ' << (reason ? reason : "") << "\r\n"
                << "Content-Type: " << (contentType ? contentType : "application/octet-stream") << "\r\n"
                << "Cache-Control: no-store\r\n"
                << "Pragma: no-cache\r\n"
                << "Content-Length: " << body.size() << "\r\n"
                << "Connection: close\r\n"
                << "\r\n"
                << body;
            return out.str();
        }

        std::string BuildDwAuthResponse(const std::string& body)
        {
            // Match the Battle.net-era Demonware Auth3 HTTP envelope used by the
            // known working T8 emulator.  Keep this isolated to /auth/ so the
            // rest of the local web endpoints retain the stricter no-store policy.
            char date[64]{};
            const std::time_t now = std::time(nullptr);
            std::tm utc{};
#if defined(_WIN32)
            gmtime_s(&utc, &now);
#else
            gmtime_r(&now, &utc);
#endif
            std::strftime(date, sizeof(date), "%a, %d %b %G %T", &utc);

            const std::vector<std::uint8_t> signature = SignAuth3Body(body);
            const std::string signatureB64 = Base64Encode(signature);

            std::ostringstream out;
            out << "HTTP/1.1 200 OK\r\n"
                << "Server: TornadoServer/4.5.3\r\n"
                << "Content-Type: application/json\r\n"
                << "Date: " << date << " GMT\r\n"
                << "X-Signature: " << signatureB64 << "\r\n"
                << "Content-Length: " << body.size() << "\r\n\r\n"
                << body;
            return out.str();
        }
    }
}
