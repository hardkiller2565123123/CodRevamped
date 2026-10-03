namespace revamped::iw8::web
{
    namespace
    {
        std::uint64_t StableLocalAuthUserId(const std::string& identity, std::uint32_t titleId)
        {
            // Deterministic local-only identity. Never depends on Blizzard/Demonware
            // credentials and remains stable for the same stock Auth3 identity.
            std::uint64_t hash = 1469598103934665603ull;
            const auto mix = [&hash](const void* data, std::size_t size)
            {
                const auto* bytes = static_cast<const std::uint8_t*>(data);
                for (std::size_t i = 0; i < size; ++i)
                {
                    hash ^= static_cast<std::uint64_t>(bytes[i]);
                    hash *= 1099511628211ull;
                }
            };

            static constexpr char prefix[] = "codrevamped-iw8-local-user|";
            mix(prefix, sizeof(prefix) - 1u);
            if (!identity.empty())
                mix(identity.data(), identity.size());
            else
            {
                static constexpr char fallback[] = "anonymous-local";
                mix(fallback, sizeof(fallback) - 1u);
            }
            mix(&titleId, sizeof(titleId));

            // bdObjectStore rejects a numeric user id of zero. Keep the value in
            // the positive signed range as well so diagnostics stay readable.
            hash &= 0x7FFFFFFFFFFFFFFFull;
            if (hash == 0)
                hash = 1;
            return hash;
        }

        void WriteLe64At(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value)
        {
            if (offset + 8u > bytes.size())
                return;
            for (std::size_t i = 0; i < 8u; ++i)
                bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8u));
        }

        bool ReplaceJsonStringValue(std::string& json, const char* key, const std::string& value)
        {
            if (!key || !*key)
                return false;

            const std::string marker = std::string("\"") + key + "\":\"";
            const std::size_t beginMarker = json.find(marker);
            if (beginMarker == std::string::npos)
                return false;

            const std::size_t valueBegin = beginMarker + marker.size();
            const std::size_t valueEnd = json.find('"', valueBegin);
            if (valueEnd == std::string::npos)
                return false;

            json.replace(valueBegin, valueEnd - valueBegin, value);
            return true;
        }

        std::string BuildDwBnetAuthResponse(const std::string& requestTask, const std::string& ivSeed,
            std::uint32_t titleId, const std::string& identity, const std::string& serviceLevel,
            const std::string& sessionToken, const std::string& accountToken,
            const std::string& machineId)
        {
            std::string response = BuildDwBnetAuthResponse_UnpatchedIdentity(
                requestTask, ivSeed, titleId, identity, serviceLevel,
                sessionToken, accountToken, machineId);

            std::vector<std::uint8_t> ticket;
            if (g_authPipeline.lastAuth3ClientTicket.empty() ||
                !Base64Decode(g_authPipeline.lastAuth3ClientTicket, ticket) ||
                ticket.size() != 128u)
            {
                AppendAuthPipelineV58(
                    "AUTH3_LOCAL_IDENTITY skipped reason=client_ticket_shape titleId=%u",
                    static_cast<unsigned>(titleId));
                return response;
            }

            // Packed DwAuthTicket layout:
            //   0  magic u32
            //   4  type u8
            //   5  titleId u32
            //   9  timeIssued u32
            //  13  timeExpires u32
            //  17  licenseId u64
            //  25  userId u64
            //  33  username[64]
            //  97  sessionKey[24]
            const std::uint64_t localUserId = StableLocalAuthUserId(identity, titleId);
            WriteLe64At(ticket, 17u, localUserId);
            WriteLe64At(ticket, 25u, localUserId);

            std::fill(ticket.begin() + 33u, ticket.begin() + 97u, 0u);
            static constexpr char localUsername[] = "revamped";
            std::copy(localUsername, localUsername + sizeof(localUsername) - 1u, ticket.begin() + 33u);

            const std::string patchedClientTicket = Base64Encode(ticket);
            if (!ReplaceJsonStringValue(response, "client_ticket", patchedClientTicket))
            {
                AppendAuthPipelineV58(
                    "AUTH3_LOCAL_IDENTITY skipped reason=response_client_ticket_missing titleId=%u",
                    static_cast<unsigned>(titleId));
                return response;
            }

            // The original builder already advanced the Auth3 correlation serial.
            // Replace only the remembered client ticket so the later Umbrella/LSG
            // ticket mint inherits this repaired local identity without creating a
            // second synthetic Auth3 issuance.
            g_authPipeline.lastAuth3ClientTicket = patchedClientTicket;

            AppendAuthPipelineV58(
                "AUTH3_LOCAL_IDENTITY titleId=%u userId=%llu licenseId=%llu username=revamped clientTicketPatched=yes",
                static_cast<unsigned>(titleId),
                static_cast<unsigned long long>(localUserId),
                static_cast<unsigned long long>(localUserId));

            return response;
        }
    }
}
