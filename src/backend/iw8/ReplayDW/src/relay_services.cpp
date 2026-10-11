#include "host_os.h"
#include "relay_services.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>

namespace
{
    using Json = nlohmann::json;
    wire::Bytes issuer;
    constexpr std::array<uint8_t, 8> keyMagic{'R', 'P', 'L', 'Y', 'R', 'L', 'Y', 1};

    uint64_t now()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count());
    }

    void publish(const std::filesystem::path &path, std::span<const uint8_t> bytes)
    {
        std::filesystem::create_directories(path.parent_path());
        auto pending = path;
        pending += ".pending";
        {
            std::ofstream stream(pending, std::ios::binary | std::ios::trunc);
            if (!stream.write(reinterpret_cast<const char *>(bytes.data()),
                              static_cast<std::streamsize>(bytes.size())) ||
                !stream.flush())
                throw std::runtime_error("Relay credential persistence failed");
        }
        if (!MoveFileExW(
                pending.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("Relay credential publication failed");
    }

    wire::Bytes key(const std::string &domain, unsigned bytes)
    {
        wire::require(issuer.size() == 32);
        const wire::Bytes info(domain.begin(), domain.end());
        return crypto::expand(issuer, info, bytes);
    }

    wire::Bytes clientSecret(std::span<const uint8_t> opaque)
    {
        const auto digest = crypto::hmac(key("replay-relay-client-secret-v1", 20), opaque);
        return {digest.begin(), digest.begin() + 16};
    }

    std::string hex(std::span<const uint8_t> bytes)
    {
        std::string out;
        out.reserve(bytes.size() * 2);
        for (const auto b : bytes)
        {
            out.push_back("0123456789abcdef"[b >> 4]);
            out.push_back("0123456789abcdef"[b & 15]);
        }
        return out;
    }
} // namespace

namespace relay
{
    void initialize(const std::filesystem::path &directory)
    {
        const auto path = directory / "relay" / "issuer-key.bin";
        wire::Bytes bytes;
        if (std::filesystem::exists(path))
        {
            if (std::filesystem::file_size(path) != 72)
                throw std::runtime_error("Relay issuer key size invalid; preserve and recover it");
            bytes.resize(72);
            std::ifstream stream(path, std::ios::binary);
            if (!stream.read(reinterpret_cast<char *>(bytes.data()), 72))
                throw std::runtime_error("Relay issuer key read failed");
            if (!std::equal(keyMagic.begin(), keyMagic.end(), bytes.begin()) ||
                !crypto::equal(crypto::sha256(std::span(bytes).first(40)),
                               std::span(bytes).subspan(40)))
                throw std::runtime_error("Relay issuer key damaged; preserve and recover it");
        }
        else
        {
            // An absent key with issued credentials is data loss, not a new realm.
            const auto relayRoot = directory / "relay";
            if (std::filesystem::exists(relayRoot))
                for (const auto &entry : std::filesystem::directory_iterator(relayRoot))
                    if (entry.is_directory() || entry.path().filename() == "issuer-key.bin.pending")
                        throw std::runtime_error("Relay issuer key missing with existing state; "
                                                 "preserve and recover it");
            bytes.assign(keyMagic.begin(), keyMagic.end());
            const auto secret = crypto::random(32);
            bytes.insert(bytes.end(), secret.begin(), secret.end());
            const auto checksum = crypto::sha256(bytes);
            bytes.insert(bytes.end(), checksum.begin(), checksum.end());
            publish(path, bytes);
        }
        if (!issuer.empty())
            SecureZeroMemory(issuer.data(), issuer.size());
        issuer.assign(bytes.begin() + 8, bytes.begin() + 40);
        SecureZeroMemory(bytes.data(), bytes.size());
    }

    ClientCredential verifyClientInit(std::span<const uint8_t> token)
    {
        wire::require(token.size() == 61 && token[0] == 1);
        const auto opaque = token.subspan(1, 56);
        // The SDK treats these 56 bytes as opaque. This local realm authenticates
        // IV[16] + AES-CBC(owner/title/absolute expiry)[16] + session digest[8]
        // with a separate 128-bit truncated HMAC. Neither a retail credential nor
        // a claim of UDP transport: only this issuer can accept/decrypt the token.
        wire::Bytes authenticated(opaque.begin(), opaque.begin() + 40);
        authenticated.insert(authenticated.end(), token.begin() + 57, token.end());
        const auto digest = crypto::hmac(key("replay-relay-client-mac-v1", 20), authenticated);
        wire::require(crypto::equal(std::span(digest).first(16), opaque.subspan(40, 16)));
        const auto claims = crypto::aes(
            key("replay-relay-client-aes-v1", 16), opaque.first(16), opaque.subspan(16, 16), false);
        ClientCredential result;
        result.user = wire::at<uint64_t>(claims, 0);
        result.title = wire::at<uint32_t>(claims, 8);
        result.expires = wire::at<uint32_t>(claims, 12);
        result.expiryDelta = wire::at<uint32_t>(token, 57);
        const auto time = now();
        wire::require(result.user && result.title && result.expiryDelta &&
                      result.expiryDelta <= 3600 && result.expires > time &&
                      result.expires <= time + result.expiryDelta);
        std::copy_n(opaque.begin() + 32, 8, result.session.begin());
        const auto secret = clientSecret(opaque);
        std::copy(secret.begin(), secret.end(), result.secret.begin());
        return result;
    }

    ClientCredential verifyClientToken(std::span<const uint8_t> token)
    {
        wire::require(token.size() == 77);
        wire::Bytes init(token.begin(), token.begin() + 57);
        init.insert(init.end(), token.begin() + 73, token.end());
        const auto result = verifyClientInit(init);
        wire::require(crypto::equal(result.secret, token.subspan(57, 16)));
        return result;
    }

    wire::Bytes issueServerToken(const platform::LobbyIdentity &id,
                                 uint64_t relayId,
                                 std::span<const uint8_t> address)
    {
        wire::require(platform::valid(id) && relayId && address.size() == 6);
        const auto expiry = std::min(now() + 3600, id.expires);
        wire::require(expiry > now() && expiry <= UINT32_MAX);
        wire::Bytes claims;
        wire::raw(claims, id.userId);
        wire::raw(claims, id.titleId);
        wire::raw(claims, static_cast<uint32_t>(expiry));
        wire::raw(claims, relayId);
        const auto nonce = crypto::random(12);
        wire::Bytes opaque(nonce);
        const auto sealed = crypto::gcm(key("replay-relay-server-aes-v1", 16), nonce, claims, true);
        opaque.insert(opaque.end(), sealed.begin(), sealed.end());
        const auto digest = crypto::hmac256(key("replay-relay-server-secret-v1", 32), opaque);
        // Native 1421833C0: version + opaque[52] + secret[16] + IPv4[4]/LE16 port + LE64 relay ID.
        wire::Bytes token{1};
        token.insert(token.end(), opaque.begin(), opaque.end());
        token.insert(token.end(), digest.begin(), digest.begin() + 16);
        token.insert(token.end(), address.begin(), address.end());
        wire::raw(token, relayId);
        wire::require(token.size() == 83);
        return token;
    }

    ServerCredential verifyServerInit(std::span<const uint8_t> token, uint64_t relayId)
    {
        // Vtable 1426AB0D0 +40 -> 1421834F0; 142049AC0 is a false display alias.
        wire::require(token.size() == 53 && token[0] == 1);
        const auto opaque = token.subspan(1);
        const auto claims = crypto::gcm(
            key("replay-relay-server-aes-v1", 16), opaque.first(12), opaque.subspan(12), false);
        ServerCredential out;
        out.user = wire::at<uint64_t>(claims, 0);
        out.title = wire::at<uint32_t>(claims, 8);
        out.expires = wire::at<uint32_t>(claims, 12);
        out.relayId = wire::at<uint64_t>(claims, 16);
        wire::require(out.user && out.title && out.relayId == relayId && out.expires > now() &&
                      out.expires <= now() + 3600);
        const auto digest = crypto::hmac256(key("replay-relay-server-secret-v1", 32), opaque);
        std::copy_n(digest.begin(), 16, out.secret.begin());
        return out;
    }
} // namespace relay

namespace services
{
    std::optional<Reply> relayServices(const std::filesystem::path &directory,
                                       const platform::LobbyIdentity &id,
                                       uint8_t service,
                                       uint8_t task,
                                       wire::Reader &p)
    {
        if (service != 145 || task != 26)
            return std::nullopt;
        p.end();
        if (!platform::valid(id))
            return Reply{101, {}, "relay-client-session-denied"};
        const auto time = now(), expires = std::min(time + 3600, id.expires);
        if (expires <= time || expires > UINT32_MAX)
            return Reply{101, {}, "relay-client-expiry-denied"};
        wire::Bytes claims;
        wire::raw(claims, id.userId);
        wire::raw(claims, id.titleId);
        wire::raw(claims, static_cast<uint32_t>(expires));
        const auto iv = crypto::random(16),
                   encrypted = crypto::aes(key("replay-relay-client-aes-v1", 16), iv, claims, true);
        wire::Bytes opaque(iv);
        opaque.insert(opaque.end(), encrypted.begin(), encrypted.end());
        const auto session = crypto::sha256(id.key);
        opaque.insert(opaque.end(), session.begin(), session.begin() + 8);
        wire::Bytes authenticated(opaque);
        wire::raw(authenticated, static_cast<uint32_t>(expires - time));
        const auto signature = crypto::hmac(key("replay-relay-client-mac-v1", 20), authenticated);
        opaque.insert(opaque.end(), signature.begin(), signature.begin() + 16);
        // Exact Replay reader 142149720 -> virtual 142193110:
        // readBlob(77), version UInt8=1, opaque[56], secret[16], expiryDelta LE32.
        wire::Bytes token{1};
        token.insert(token.end(), opaque.begin(), opaque.end());
        const auto secret = clientSecret(opaque);
        token.insert(token.end(), secret.begin(), secret.end());
        wire::raw(token, static_cast<uint32_t>(expires - time));
        (void)relay::verifyClientToken(token);
        const auto path = directory / "relay" / std::to_string(id.titleId) / "clients" /
                          (std::to_string(id.userId) + ".json");
        Json audit = {{"schema", 1},
                      {"title", id.titleId},
                      {"user", id.userId},
                      {"issued", time},
                      {"expires", expires},
                      {"expiry_delta", expires - time},
                      {"native_wire_sha256", hex(crypto::sha256(token))},
                      {"opaque_sha256", hex(crypto::sha256(opaque))},
                      {"udp_transport_advertised", false}};
        const auto bytes = audit.dump();
        publish(path, std::span(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()));
        wire::Writer result;
        result.blob(token);
        return Reply{0, {std::move(result.data)}, "relay-client-auth-token-issued"};
    }
} // namespace services
