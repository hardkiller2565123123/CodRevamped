namespace revamped::iw8::web
{
    namespace
    {
        bool ReadPackedTicketU64(const std::string& ticketB64, std::size_t offset, std::uint64_t& value)
        {
            value = 0;

            std::vector<std::uint8_t> raw;
            if (ticketB64.empty() || !Base64Decode(ticketB64, raw) || raw.size() != 128u ||
                offset + 8u > raw.size())
            {
                return false;
            }

            const std::uint32_t magic =
                static_cast<std::uint32_t>(raw[0]) |
                (static_cast<std::uint32_t>(raw[1]) << 8u) |
                (static_cast<std::uint32_t>(raw[2]) << 16u) |
                (static_cast<std::uint32_t>(raw[3]) << 24u);
            if (magic != 0xEFBDADDEu)
                return false;

            for (std::size_t i = 0; i < 8u; ++i)
                value |= static_cast<std::uint64_t>(raw[offset + i]) << (i * 8u);

            return value != 0;
        }

        std::uint64_t CurrentLocalCrossplayUserId()
        {
            // The Umbrella-minted ticket is what the crossplay path actually feeds
            // into the LSG login result. Prefer it, then fall back to the already
            // repaired Auth3 client ticket. Packed bdAuthTicket::m_userID is +25.
            std::uint64_t userId = 0;
            if (ReadPackedTicketU64(g_authPipeline.lastMintedLsgToken, 25u, userId))
                return userId;
            if (ReadPackedTicketU64(g_authPipeline.lastAuth3ClientTicket, 25u, userId))
                return userId;
            return 1u;
        }

        std::string CurrentLocalCrossplayTicket()
        {
            if (!g_authPipeline.lastMintedLsgToken.empty())
                return g_authPipeline.lastMintedLsgToken;
            return g_authPipeline.lastAuth3ClientTicket;
        }
    }

    std::uint64_t GetCurrentLocalUserId()
    {
        return CurrentLocalCrossplayUserId();
    }

    HttpResult TryHandleLocalWebRequest(std::vector<std::uint8_t>& buffer)
    {
        HttpResult result = TryHandleLocalWebRequest_BaseUmbrellaIdentity(buffer);

        // 1.20's crossplay handoff is the path that replaces bdLoginResult's
        // effective account identity. The original handler already validated the
        // request and minted the LSG ticket; only complete its response schema.
        if (!result.handled || result.statusCode != 200 ||
            result.path != "/v1.0/tokens/crossplatform/")
        {
            return result;
        }

        const std::uint64_t userId = CurrentLocalCrossplayUserId();
        const std::string ticket = CurrentLocalCrossplayTicket();

        // IW8 sends initialVectorSeed to Umbrella as base64 text and later decodes
        // the response field before strtoul(). Preserve that exact representation.
        std::string ivSeedB64 = g_authPipeline.lastUmbrellaInitialVectorSeed;
        if (ivSeedB64.empty())
            ivSeedB64 = Base64Encode(std::vector<std::uint8_t>{ '0' });

        const std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));
        const std::uint64_t accessExpires = now + 86400ull;
        const std::uint64_t refreshExpires = now + 604800ull;

        // This is the schema consumed by bdUmbrellaCrossplayAccount /
        // bdUmbrellaCrossplayInfo. With crossplay enabled, bdLoginResult::getUserID
        // and getAccountType read m_crossplayInfo.m_userInfo instead of the Auth3
        // first-party account, so omitting userID/accountType leaves lobby auth at 0.
        const std::string responseBody =
            "{\"umbrellaID\":" + std::to_string(userId) +
            ",\"userID\":" + std::to_string(userId) +
            ",\"accountType\":\"bnet\"" +
            ",\"username\":\"revamped\"" +
            ",\"accessToken\":\"" + JsonEscape(ticket) + "\"" +
            ",\"expires\":" + std::to_string(accessExpires) +
            ",\"accessIssuedAt\":" + std::to_string(now) +
            ",\"initialVectorSeed\":\"" + JsonEscape(ivSeedB64) + "\"" +
            ",\"ticket\":\"" + JsonEscape(ticket) + "\"" +
            ",\"refreshToken\":\"revamped-local-refresh\"" +
            ",\"refreshTokenExpires\":" + std::to_string(refreshExpires) +
            ",\"accounts\":[{\"provider\":\"uno\",\"username\":\"revamped\",\"accountID\":" +
                std::to_string(userId) + ",\"authorized\":true}]" +
            ",\"token\":\"" + JsonEscape(ticket) + "\"" +
            ",\"crossPlatformProgressionEnabled\":true" +
            ",\"lsgEndpoint\":\"127.0.0.1\"}";

        result.response = BuildResponse(
            200, "OK", "application/json; charset=utf-8", responseBody);
        result.label += " umbrellaIdentity=nonzero linkedUno=1 schema=bdUmbrellaCrossplayInfo";

        AppendAuthPipelineV58(
            "UMBRELLA_LOCAL_IDENTITY userId=%llu accountType=bnet username=revamped linkedUno=1 ticketLen=%llu ivSeedPresent=%s schema=bdUmbrellaCrossplayInfo stateWrites=off",
            static_cast<unsigned long long>(userId),
            static_cast<unsigned long long>(ticket.size()),
            ivSeedB64.empty() ? "no" : "yes");

        log::Print(
            "[AUTH-LSG] UMBRELLA_LOCAL_IDENTITY userId=%llu accountType=bnet linkedUno=1 ticketLen=%llu ivSeedPresent=%s schema=bdUmbrellaCrossplayInfo",
            static_cast<unsigned long long>(userId),
            static_cast<unsigned long long>(ticket.size()),
            ivSeedB64.empty() ? "no" : "yes");

        return result;
    }
}
