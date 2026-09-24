#include "LsgKeyMaterial.h"

namespace revamped::iw8::web
{
    // V72 source IDs are intentionally numeric so ServerLsg.cpp can consume this
    // diagnostic API without changing the user's existing WebAuthService.h.
    // 1=local constant, 2=Auth3 client ticket sessionKey, 3=Auth3 server-ticket
    // prefix, 4=minted LSG ticket sessionKey, 5..7=Auth3 iv_seed raw/b64/hex,
    // 8..10=Umbrella initialVectorSeed raw/b64/hex.
    std::size_t GetLsgSessionKeyCandidatesV72(std::uint8_t* outKeys, std::uint32_t* outKinds,
        std::size_t maxKeys, std::uint64_t* auth3Serial)
    {
        if (!outKeys || !outKinds || maxKeys == 0u || g_authPipeline.auth3Serial == 0u)
            return 0u;

        std::size_t count = 0u;
        auto add = [&](std::uint32_t kind, const std::uint8_t key[24])
        {
            if (!key || count >= maxKeys) return;
            std::memcpy(outKeys + count * 24u, key, 24u);
            outKinds[count] = kind;
            ++count;
        };

        add(1u, kLocalAuth3SessionKey);

        std::vector<std::uint8_t> decoded;
        if (Base64Decode(g_authPipeline.lastAuth3ClientTicket, decoded) && decoded.size() == 128u)
            add(2u, decoded.data() + 97u);
        decoded.clear();
        if (Base64Decode(g_authPipeline.lastAuth3ServerTicket, decoded) && decoded.size() >= 24u)
            add(3u, decoded.data());
        decoded.clear();
        if (Base64Decode(g_authPipeline.lastMintedLsgToken, decoded) && decoded.size() == 128u)
            add(4u, decoded.data() + 97u);

        auto addTextForms = [&](const std::string& text, std::uint32_t rawKind,
            std::uint32_t b64Kind, std::uint32_t hexKind)
        {
            std::uint8_t key[24]{};
            if (text.size() == 24u)
            {
                std::memcpy(key, text.data(), 24u);
                add(rawKind, key);
            }
            std::memset(key, 0, sizeof(key));
            if (DecodeBase64Exact24V72(text, key))
                add(b64Kind, key);
            std::memset(key, 0, sizeof(key));
            if (DecodeHex24V72(text, key))
                add(hexKind, key);
        };

        addTextForms(g_authPipeline.lastAuth3IvSeed, 5u, 6u, 7u);
        addTextForms(g_authPipeline.lastUmbrellaInitialVectorSeed, 8u, 9u, 10u);

        if (auth3Serial)
            *auth3Serial = g_authPipeline.auth3Serial;

        log::Print("[AUTH-V72] LSG_KEY_SOURCE_CANDIDATES auth3Serial=%llu candidates=%llu auth3IvChars=%llu umbrellaIvChars=%llu rawValues=REDACTED stateWrites=off",
            static_cast<unsigned long long>(g_authPipeline.auth3Serial),
            static_cast<unsigned long long>(count),
            static_cast<unsigned long long>(g_authPipeline.lastAuth3IvSeed.size()),
            static_cast<unsigned long long>(g_authPipeline.lastUmbrellaInitialVectorSeed.size()));
        return count;
    }


    // V73 exposes the exact byte containers already produced by this emulator so
    // ServerLsg can test packed-layout offsets without logging any raw secrets.
    // Kinds: 101=Auth3 client ticket, 102=Auth3 server ticket, 103=minted LSG
    // ticket, 104=Auth3 iv_seed text, 105=Umbrella initialVectorSeed text.
    std::size_t GetLsgKeyMaterialBlobsV73(std::uint8_t* outBlobs, std::uint32_t* outSizes,
        std::uint32_t* outKinds, std::size_t stride, std::size_t maxBlobs, std::uint64_t* auth3Serial)
    {
        if (!outBlobs || !outSizes || !outKinds || stride == 0u || maxBlobs == 0u ||
            g_authPipeline.auth3Serial == 0u)
            return 0u;

        std::size_t count = 0u;
        auto addBlob = [&](std::uint32_t kind, const std::uint8_t* bytes, std::size_t size)
        {
            if (!bytes || size == 0u || count >= maxBlobs) return;
            const std::size_t copy = (std::min)(size, stride);
            std::memset(outBlobs + count * stride, 0, stride);
            std::memcpy(outBlobs + count * stride, bytes, copy);
            outSizes[count] = static_cast<std::uint32_t>(copy);
            outKinds[count] = kind;
            ++count;
        };

        std::vector<std::uint8_t> decoded;
        if (Base64Decode(g_authPipeline.lastAuth3ClientTicket, decoded) && !decoded.empty())
            addBlob(101u, decoded.data(), decoded.size());
        decoded.clear();
        if (Base64Decode(g_authPipeline.lastAuth3ServerTicket, decoded) && !decoded.empty())
            addBlob(102u, decoded.data(), decoded.size());
        decoded.clear();
        if (Base64Decode(g_authPipeline.lastMintedLsgToken, decoded) && !decoded.empty())
            addBlob(103u, decoded.data(), decoded.size());

        if (!g_authPipeline.lastAuth3IvSeed.empty())
            addBlob(104u, reinterpret_cast<const std::uint8_t*>(g_authPipeline.lastAuth3IvSeed.data()),
                g_authPipeline.lastAuth3IvSeed.size());
        if (!g_authPipeline.lastUmbrellaInitialVectorSeed.empty())
            addBlob(105u, reinterpret_cast<const std::uint8_t*>(g_authPipeline.lastUmbrellaInitialVectorSeed.data()),
                g_authPipeline.lastUmbrellaInitialVectorSeed.size());

        if (auth3Serial) *auth3Serial = g_authPipeline.auth3Serial;
        log::Print("[AUTH-V73] LSG_KEY_MATERIAL_BLOBS auth3Serial=%llu blobs=%llu stride=%llu rawValues=REDACTED stateWrites=off",
            static_cast<unsigned long long>(g_authPipeline.auth3Serial),
            static_cast<unsigned long long>(count), static_cast<unsigned long long>(stride));
        return count;
    }

    bool GetLatestAuth3SessionKey(std::uint8_t outKey[24], std::uint64_t* auth3Serial)
    {
        if (!outKey || g_authPipeline.auth3Serial == 0 ||
            g_authPipeline.lastAuth3ClientTicket.empty() ||
            g_authPipeline.lastAuth3ServerTicket.empty())
        {
            return false;
        }

        std::memcpy(outKey, kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));
        if (auth3Serial)
            *auth3Serial = g_authPipeline.auth3Serial;
        return true;
    }
}
