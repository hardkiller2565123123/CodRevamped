#include "host_os.h"
#include "crypto_provider.h"
#include "platform.h"
#include "platform_account_store.h"
#include "platform_resources.h"
#include "services.h"
#include "crypto.h"
#include "executable_updates.h"
#include "shared_protocol/dw_platform_protocol.h"
#include "shared_protocol/dw_client_identity.h"
#include <array>
#include <algorithm>
#include <chrono>
#include <charconv>
#include <cstring>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <vector>
#include <map>
#include <set>
#include "nlohmann/json.hpp"

namespace platform
{
    namespace
    {
        struct Identity
        {
            uint32_t magic = DW_LOCAL_PLATFORM_MAGIC;
            uint32_t version = 1;
            uint64_t userId = 0;
            uint32_t gameAccountId = 0;
            char name[36] = "DWPlayer";
        };

        static_assert(sizeof(Identity) == 56);

        struct Session
        {
            DWLocalPlatformPayload payload;
            std::array<uint8_t, 128> serverTicket{};
            std::array<uint8_t, 24> sessionKey{};
            uint32_t titleId = 0;
            uint32_t ivSeed = 0;
            std::string umbrellaToken;
            std::string unoIDToken, unoAccessToken, unoRefreshToken;
        };

        Identity identity;
        std::map<std::string, Identity> profiles, clientProfiles;

        struct Challenge
        {
            std::array<uint8_t, 32> nonce, value;
            uint64_t expires;
        };

        std::map<std::string, Challenge> challenges;
        std::filesystem::path identityDirectory;
        BCRYPT_ALG_HANDLE rsa = nullptr, sha = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;
        std::mutex mutex;
        std::vector<Session> issuedSessions;
        accounts::Store accountStore;
        unsigned loginCount = 0;
        unsigned authCount = 0;
        unsigned legacyCount = 0;

        void check(NTSTATUS result, const char *operation)
        {
            if (result < 0)
                throw std::runtime_error(std::string("Platform crypto failure: ") + operation);
        }

        std::vector<unsigned char> read(const std::filesystem::path &path, size_t maximum = 16384)
        {
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file || file.tellg() <= 0 || file.tellg() > static_cast<std::streamoff>(maximum))
                throw std::runtime_error("Invalid platform identity/key file");
            std::vector<unsigned char> bytes(static_cast<size_t>(file.tellg()));
            file.seekg(0);
            if (!file.read(reinterpret_cast<char *>(bytes.data()),
                           static_cast<std::streamsize>(bytes.size())))
                throw std::runtime_error("Cannot read platform identity/key file");
            return bytes;
        }

        void write(const std::filesystem::path &path,
                   const void *data,
                   size_t size,
                   bool privateFile = false)
        {
            auto pending = path;
            pending += ".creating";
            {
                std::ofstream file(pending, std::ios::binary | std::ios::trunc);
                if (privateFile && file)
                    std::filesystem::permissions(pending,
                                                 std::filesystem::perms::owner_read |
                                                     std::filesystem::perms::owner_write,
                                                 std::filesystem::perm_options::replace);
                if (!file.write(static_cast<const char *>(data),
                                static_cast<std::streamsize>(size)) ||
                    !file.flush())
                    throw std::runtime_error("Cannot persist platform identity/key");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Cannot publish platform identity/key");
        }

        void saveSessions();

        // Issuer mutation is acknowledged only after the complete signed image
        // is flushed and atomically published. An unacknowledged mutation rolls
        // back in memory; startup accepts only a complete authenticated image.
        struct SessionChanges
        {
            std::vector<Session> previous = issuedSessions;
            bool committed = false;

            ~SessionChanges()
            {
                if (!committed)
                    issuedSessions = std::move(previous);
            }

            void commit()
            {
                saveSessions();
                committed = true;
            }
        };

        void profileKey(const std::string &value)
        {
            if (value.empty() || value.size() > 32)
                throw std::runtime_error("Invalid local profile key");
            for (const char c : value)
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
                    throw std::runtime_error("Invalid local profile key");
        }

        Identity readIdentity(const std::filesystem::path &path)
        {
            const auto bytes = read(path);
            Identity result;
            if (bytes.size() != sizeof(result))
                throw std::runtime_error("Platform identity layout mismatch");
            std::memcpy(&result, bytes.data(), sizeof(result));
            if (result.magic != DW_LOCAL_PLATFORM_MAGIC || result.version != 1 || !result.userId ||
                result.userId == UINT64_MAX || !result.gameAccountId || !result.name[0] ||
                result.name[35])
                throw std::runtime_error("Invalid persisted platform identity");
            const auto name = std::string(result.name);
            for (const unsigned char c : name)
                if (c < 32 || c >= 127)
                    throw std::runtime_error("Invalid local profile name");
            return result;
        }

        void validateName(const std::string &name)
        {
            if (name.empty() || name.size() >= 36 || name.front() == ' ' || name.back() == ' ')
                throw std::runtime_error("Invalid local profile name");
            for (const unsigned char c : name)
                if (c < 32 || c >= 127 || c == '#' || c == '%')
                    throw std::runtime_error("Invalid local profile name");
        }

        std::string folded(std::string value)
        {
            for (auto &c : value)
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c + ('a' - 'A'));
            return value;
        }

        std::string networkName(const std::string &requested)
        {
            validateName(requested);
            auto name = requested;
            // Exact Replay Com_CleanName (0x1413F18A0), consumed by
            // G_ClientMP_UserinfoChanged (0x1411F2390). The signed local name
            // must equal the server's cleaned name or CG_MainMP drops the game.
            // Reach a fixed point: removing an escape can expose another one.
            for (;;)
            {
                std::string cleaned;
                cleaned.reserve(name.size());
                unsigned spaces = 0;
                for (size_t i = 0; i < name.size(); ++i)
                {
                    const auto c = name[i];
                    const auto next = i + 1 < name.size() ? name[i + 1] : '\0';
                    if (c == '^')
                    {
                        if (next >= '\'' && next <= '>')
                            ++i;
                    }
                    else if ((c == '[' && next == '{') || (c == '}' && next == ']'))
                        ++i;
                    else if (c == ' ')
                    {
                        if (!cleaned.empty() && ++spaces <= 3)
                            cleaned += c;
                    }
                    else
                    {
                        spaces = 0;
                        cleaned += c;
                    }
                }
                if (cleaned == name)
                    break;
                name = std::move(cleaned);
            }
            validateName(name);
            return name;
        }

        void availableName(const std::string &name, uint64_t own = 0, bool machineOwned = false)
        {
            validateName(name);
            const auto match = folded(name);
            // Legacy manually selected fixture accounts must not reserve names
            // against the players upgrading to machine-owned identities.
            if (!machineOwned)
            {
                if (identity.userId != own && folded(identity.name) == match)
                    throw std::runtime_error("Local player name already in use");
                for (const auto &[profile, other] : profiles)
                    if (other.userId != own && folded(other.name) == match)
                        throw std::runtime_error("Local player name already in use");
            }
            for (const auto &[fingerprint, other] : clientProfiles)
                if (other.userId != own && folded(other.name) == match)
                    throw std::runtime_error("Local player name already in use");
        }

        struct SelectedProfile
        {
            Identity *value;
            std::filesystem::path path;
            bool machineOwned;
        };

        SelectedProfile selectProfile(uint64_t user)
        {
            if (identity.userId == user)
                return {&identity, identityDirectory / "platform-profile.bin", false};
            for (auto &[name, profile] : profiles)
                if (profile.userId == user)
                    return {
                        &profile, identityDirectory / "platform-profiles" / (name + ".bin"), false};
            for (auto &[keyName, profile] : clientProfiles)
                if (profile.userId == user)
                    return {&profile,
                            identityDirectory / "platform-client-profiles" / (keyName + ".bin"),
                            true};
            throw std::runtime_error("Account has no existing platform profile");
        }

        accounts::Profile accountProfile(uint64_t user)
        {
            const auto selected = selectProfile(user);
            accounts::Profile result{user, selected.path, {}};
            std::memcpy(result.bytes.data(), selected.value, result.bytes.size());
            return result;
        }

        void publishAccountProfile(const accounts::Profile &profile,
                                   bool validateOnly,
                                   bool revokeCredentials)
        {
            const auto selected = selectProfile(profile.user);
            Identity changed;
            std::memcpy(&changed, profile.bytes.data(), sizeof(changed));
            if (profile.path != selected.path ||
                std::memcmp(&changed, selected.value, offsetof(Identity, name)) != 0 ||
                changed.name[35])
                throw std::runtime_error("Account publication changes stable profile fields");
            availableName(changed.name, profile.user, selected.machineOwned);
            const auto persisted = readIdentity(selected.path);
            if (validateOnly)
                return;
            if (std::memcmp(&persisted, &changed, sizeof(changed)) != 0)
                write(selected.path, &changed, sizeof(changed));
            *selected.value = changed;
            if (revokeCredentials)
            {
                SessionChanges mutation;
                for (auto &session : issuedSessions)
                    if (session.payload.userId == profile.user)
                    {
                        session.unoIDToken.clear();
                        session.unoAccessToken.clear();
                        session.unoRefreshToken.clear();
                    }
                mutation.commit();
            }
        }

        void recoverAccounts(uint64_t onlyOwner = 0)
        {
            accountStore.recover(accountProfile, publishAccountProfile, onlyOwner);
        }

        Identity newIdentity(const std::string &name)
        {
            validateName(name);
            Identity result;
            check(BCryptGenRandom(nullptr,
                                  reinterpret_cast<unsigned char *>(&result.userId),
                                  sizeof(result.userId),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG),
                  "identity random");
            result.userId = (result.userId & 0x00000000ffffffffULL) | 0x110000100000000ULL;
            result.gameAccountId = static_cast<uint32_t>(result.userId) | 1;
            std::memset(result.name, 0, sizeof(result.name));
            std::memcpy(result.name, name.data(), name.size());
            return result;
        }

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        Session *liveSession(const LobbyIdentity &owner)
        {
            const auto time = now();
            if (!owner.expires || !owner.userId || !owner.titleId)
                return nullptr;
            for (auto &session : issuedSessions)
                if (session.payload.expires > time && session.titleId == owner.titleId &&
                    session.payload.userId == owner.userId && session.ivSeed == owner.ivSeed &&
                    crypto::equal(session.sessionKey, owner.key))
                    return &session;
            return nullptr;
        }

        bool matchesToken(const std::string &supplied, const std::string &issued)
        {
            return supplied.size() == 64 && issued.size() == 64 &&
                   crypto::equal(
                       std::span(reinterpret_cast<const uint8_t *>(supplied.data()),
                                 supplied.size()),
                       std::span(reinterpret_cast<const uint8_t *>(issued.data()), issued.size()));
        }

        bool accountAccess(const Session *session, const std::string &access)
        {
            return session && (matchesToken(access, session->umbrellaToken) ||
                               matchesToken(access, session->unoAccessToken));
        }

        void token(char (&text)[65])
        {
            unsigned char random[32]{};
            check(BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG),
                  "token random");
            constexpr char hex[] = "0123456789abcdef";
            for (unsigned i = 0; i < sizeof(random); ++i)
            {
                text[i * 2] = hex[random[i] >> 4];
                text[i * 2 + 1] = hex[random[i] & 15];
            }
            text[64] = 0;
            SecureZeroMemory(random, sizeof(random));
        }

        std::string base64(const void *source, size_t length)
        {
            constexpr char alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            const auto *data = static_cast<const uint8_t *>(source);
            std::string out;
            for (size_t i = 0; i < length; i += 3)
            {
                unsigned v = static_cast<unsigned>(data[i]) << 16;
                if (i + 1 < length)
                    v |= static_cast<unsigned>(data[i + 1]) << 8;
                if (i + 2 < length)
                    v |= data[i + 2];
                out += alphabet[(v >> 18) & 63];
                out += alphabet[(v >> 12) & 63];
                out += i + 1 < length ? alphabet[(v >> 6) & 63] : '=';
                out += i + 2 < length ? alphabet[v & 63] : '=';
            }
            return out;
        }

        void sign(const void *bytes, size_t size, uint8_t (&signature)[256], unsigned saltBytes)
        {
            unsigned char digest[32]{};
            BCRYPT_HASH_HANDLE hash = nullptr;
            check(BCryptCreateHash(sha, &hash, nullptr, 0, nullptr, 0, 0), "payload hash creation");
            auto result = BCryptHashData(hash,
                                         static_cast<unsigned char *>(const_cast<void *>(bytes)),
                                         static_cast<unsigned long>(size),
                                         0);
            if (result >= 0)
                result = BCryptFinishHash(hash, digest, sizeof(digest), 0);
            BCryptDestroyHash(hash);
            check(result, "payload hash");
            BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, saltBytes};
            unsigned long written = 0;
            check(BCryptSignHash(key,
                                 &padding,
                                 digest,
                                 sizeof(digest),
                                 signature,
                                 sizeof(signature),
                                 &written,
                                 BCRYPT_PAD_PSS),
                  "payload signature");
            if (written != sizeof(signature))
                throw std::runtime_error("Signature length mismatch");
        }

        void exportKey(const std::filesystem::path &path, const wchar_t *format)
        {
            unsigned long count = 0;
            check(BCryptExportKey(key, nullptr, format, nullptr, 0, &count, 0),
                  "key export length");
            std::vector<unsigned char> blob(count);
            check(BCryptExportKey(key, nullptr, format, blob.data(), count, &count, 0),
                  "key export");
            write(path, blob.data(), count);
            SecureZeroMemory(blob.data(), blob.size());
        }

        struct ClientKey
        {
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_KEY_HANDLE handle = nullptr;

            ~ClientKey()
            {
                if (handle)
                    BCryptDestroyKey(handle);
                if (algorithm)
                    BCryptCloseAlgorithmProvider(algorithm, 0);
            }

            void import(const uint8_t (&bytes)[72])
            {
                BCRYPT_ECCKEY_BLOB header{};
                std::memcpy(&header, bytes, sizeof(header));
                if (header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header.cbKey != 32)
                    throw std::runtime_error("Invalid machine public key format");
                check(BCryptOpenAlgorithmProvider(
                          &algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0),
                      "machine key provider");
                check(BCryptImportKeyPair(algorithm,
                                          nullptr,
                                          BCRYPT_ECCPUBLIC_BLOB,
                                          &handle,
                                          const_cast<uint8_t *>(bytes),
                                          sizeof(bytes),
                                          0),
                      "machine public key import");
            }
        };

        std::string fingerprint(const uint8_t (&publicKey)[72])
        {
            const auto digest = crypto::sha256(publicKey);
            constexpr char hex[] = "0123456789abcdef";
            std::string result;
            for (const auto byte : digest)
            {
                result += hex[byte >> 4];
                result += hex[byte & 15];
            }
            return result;
        }

        bool nonzero(std::span<const uint8_t> bytes)
        {
            for (const auto byte : bytes)
                if (byte)
                    return true;
            return false;
        }

        constexpr size_t sessionStoreLimit = 2 * 1024 * 1024;

        struct SessionStoreHeader
        {
            char magic[8] = {'R', 'P', 'S', 'E', 'S', '0', '0', '1'};
            uint32_t version = 1;
            uint32_t length = 0;
        };

        static_assert(sizeof(SessionStoreHeader) == 16);

        void decodeSessionBytes(const nlohmann::json &value, std::span<uint8_t> target)
        {
            if (!value.is_string())
                throw std::runtime_error("Invalid persisted platform session byte field");
            const auto bytes = wire::base64(value.get_ref<const std::string &>(), target.size());
            if (bytes.size() != target.size())
                throw std::runtime_error("Invalid persisted platform session byte length");
            std::copy(bytes.begin(), bytes.end(), target.begin());
        }

        bool persistedToken(const std::string &value, bool optional = false)
        {
            return (optional && value.empty()) ||
                   (value.size() == 64 &&
                    value.find_first_not_of("0123456789abcdef") == std::string::npos);
        }

        void saveSessions()
        {
            using Json = nlohmann::json;
            if (issuedSessions.size() > 1024)
                throw std::runtime_error("Platform session capacity reached");
            Json rows = Json::array();
            for (const auto &session : issuedSessions)
                rows.push_back({{"payload",
                                 wire::base64Encode(
                                     std::span(reinterpret_cast<const uint8_t *>(&session.payload),
                                               sizeof(session.payload)))},
                                {"ticket", wire::base64Encode(session.serverTicket)},
                                {"key", wire::base64Encode(session.sessionKey)},
                                {"title", session.titleId},
                                {"seed", session.ivSeed},
                                {"umbrella", session.umbrellaToken},
                                {"uno_id", session.unoIDToken},
                                {"uno_access", session.unoAccessToken},
                                {"uno_refresh", session.unoRefreshToken}});
            const auto body = rows.dump();
            if (body.size() > sessionStoreLimit - sizeof(SessionStoreHeader) - 256)
                throw std::runtime_error("Platform session store capacity reached");
            SessionStoreHeader header;
            header.length = static_cast<uint32_t>(body.size());
            std::vector<uint8_t> bytes(sizeof(header) + body.size());
            std::memcpy(bytes.data(), &header, sizeof(header));
            std::memcpy(bytes.data() + sizeof(header), body.data(), body.size());
            uint8_t signature[256]{};
            sign(bytes.data(), bytes.size(), signature, 32);
            bytes.insert(bytes.end(), std::begin(signature), std::end(signature));
            write(identityDirectory / "platform-sessions.bin", bytes.data(), bytes.size(), true);
        }

        void loadSessions()
        {
            const auto path = identityDirectory / "platform-sessions.bin";
            issuedSessions.clear();
            if (!std::filesystem::exists(path))
                return; // Existing installations acquire their first image at login.
            auto bytes = read(path, sessionStoreLimit);
            if (bytes.size() < sizeof(SessionStoreHeader) + 256)
                throw std::runtime_error("Truncated platform session store");
            SessionStoreHeader header;
            std::memcpy(&header, bytes.data(), sizeof(header));
            const SessionStoreHeader expected;
            if (std::memcmp(header.magic, expected.magic, sizeof(header.magic)) ||
                header.version != 1 || header.length != bytes.size() - sizeof(header) - 256)
                throw std::runtime_error("Invalid platform session store header");
            const auto authenticated = std::span(bytes).first(bytes.size() - 256);
            auto digest = crypto::sha256(authenticated);
            BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, 32};
            check(BCryptVerifySignature(key,
                                        &padding,
                                        digest.data(),
                                        static_cast<ULONG>(digest.size()),
                                        bytes.data() + authenticated.size(),
                                        256,
                                        BCRYPT_PAD_PSS),
                  "persisted session signature");
            const auto rows = nlohmann::json::parse(bytes.begin() + sizeof(header),
                                                    bytes.begin() + sizeof(header) + header.length);
            if (!rows.is_array() || rows.size() > 1024)
                throw std::runtime_error("Invalid platform session store count");
            const auto time = now();
            std::set<std::string> tokens;
            std::vector<Session> restored;
            for (const auto &row : rows)
            {
                if (!row.is_object() || row.size() != 9 || !row.at("title").is_number_unsigned() ||
                    !row.at("seed").is_number_unsigned() ||
                    row.at("title").get<uint64_t>() > UINT32_MAX ||
                    row.at("seed").get<uint64_t>() > UINT32_MAX)
                    throw std::runtime_error("Invalid persisted platform session fields");
                Session session{};
                decodeSessionBytes(row.at("payload"),
                                   std::span(reinterpret_cast<uint8_t *>(&session.payload),
                                             sizeof(session.payload)));
                decodeSessionBytes(row.at("ticket"), session.serverTicket);
                decodeSessionBytes(row.at("key"), session.sessionKey);
                session.titleId = row.at("title").get<uint32_t>();
                session.ivSeed = row.at("seed").get<uint32_t>();
                session.umbrellaToken = row.at("umbrella").get<std::string>();
                session.unoIDToken = row.at("uno_id").get<std::string>();
                session.unoAccessToken = row.at("uno_access").get<std::string>();
                session.unoRefreshToken = row.at("uno_refresh").get<std::string>();
                const auto &payload = session.payload;
                if (payload.magic != DW_LOCAL_PLATFORM_MAGIC ||
                    payload.version != DW_LOCAL_PLATFORM_VERSION || !payload.userId ||
                    payload.userId == UINT64_MAX || !payload.gameAccountId || !payload.issued ||
                    payload.issued > time + 30 || payload.expires <= payload.issued ||
                    payload.expires - payload.issued > 3600 || payload.name[35] ||
                    payload.sessionToken[64] || payload.accountToken[64] || payload.licenses != 1 ||
                    payload.region != 1 || payload.age != 21 || payload.accountPolicy ||
                    payload.capabilities != 1 || nonzero(payload.reserved) ||
                    !nonzero(payload.nonce) || !persistedToken(payload.sessionToken) ||
                    !persistedToken(payload.accountToken) ||
                    !tokens.insert(payload.sessionToken).second ||
                    !persistedToken(session.umbrellaToken, true) ||
                    !persistedToken(session.unoIDToken, true) ||
                    !persistedToken(session.unoAccessToken, true) ||
                    !persistedToken(session.unoRefreshToken, true) ||
                    (session.unoIDToken.empty() != session.unoAccessToken.empty()) ||
                    (session.unoIDToken.empty() != session.unoRefreshToken.empty()) ||
                    (session.titleId
                         ? (!nonzero(session.serverTicket) || !nonzero(session.sessionKey))
                         : (session.ivSeed || nonzero(session.serverTicket) ||
                            nonzero(session.sessionKey) || !session.umbrellaToken.empty() ||
                            !session.unoIDToken.empty())))
                    throw std::runtime_error("Invalid persisted platform session state");
                validateName(payload.name);
                if (payload.expires <= time)
                    continue;
                // A removed profile revokes its old grants. Recreating a profile
                // must never adopt another account's persisted credentials.
                Identity *owner = identity.userId == payload.userId ? &identity : nullptr;
                for (auto &[name, profile] : profiles)
                    if (profile.userId == payload.userId)
                        owner = &profile;
                for (auto &[name, profile] : clientProfiles)
                    if (profile.userId == payload.userId)
                        owner = &profile;
                if (owner && owner->gameAccountId != payload.gameAccountId)
                    throw std::runtime_error("Persisted platform session account mismatch");
                if (owner)
                    restored.push_back(std::move(session));
            }
            issuedSessions = std::move(restored);
        }

        // Caller holds the issuer mutex. Login and renewal consume the same
        // single-use server challenge and sign their complete request prefix.
        template <typename Request>
        std::string verifyMachineProof(const Request &request, const std::string &bytes)
        {
            ClientKey publicKey;
            publicKey.import(request.publicKey);
            const auto id = fingerprint(request.publicKey);
            const auto found = challenges.find(id);
            if (found == challenges.end())
                throw std::runtime_error("Machine challenge missing");
            const auto challenge = found->second;
            challenges.erase(found);
            if (challenge.expires <= now() || !crypto::equal(challenge.nonce, request.nonce) ||
                !crypto::equal(challenge.value, request.challenge))
                throw std::runtime_error("Machine challenge invalid or expired");
            auto digest = crypto::sha256(
                std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(bytes.data()),
                                         bytes.size() - sizeof(request.signature)));
            check(BCryptVerifySignature(publicKey.handle,
                                        nullptr,
                                        digest.data(),
                                        static_cast<ULONG>(digest.size()),
                                        const_cast<uint8_t *>(request.signature),
                                        sizeof(request.signature),
                                        0),
                  "machine request signature");
            return id;
        }

        // Caller owns the platform mutex; both fixture and machine logins use
        // the same native signed session ABI and rename persistence.
        std::string issueSession(const std::string &nonce,
                                 Identity *selected,
                                 const std::filesystem::path &path,
                                 const std::string &playerName,
                                 bool machineOwned = false)
        {
            recoverAccounts(selected->userId);
            SessionChanges mutation;
            const auto time = now();
            std::erase_if(issuedSessions,
                          [time](const auto &session)
                          {
                              return session.payload.expires <= time;
                          });
            if (issuedSessions.size() >= 1024)
                throw std::runtime_error("Platform session capacity reached");
            const auto name = networkName(playerName.empty() ? selected->name : playerName);
            if (name != selected->name)
            {
                availableName(name, selected->userId, machineOwned);
                auto renamed = *selected;
                std::memset(renamed.name, 0, sizeof(renamed.name));
                std::memcpy(renamed.name, name.data(), name.size());
                write(path, &renamed, sizeof(renamed));
                *selected = renamed;
            }
            DWLocalPlatformReply reply{};
            auto &p = reply.payload;
            p.magic = DW_LOCAL_PLATFORM_MAGIC;
            p.version = DW_LOCAL_PLATFORM_VERSION;
            std::memcpy(p.nonce, nonce.data(), sizeof(p.nonce));
            p.issued = time;
            p.expires = time + 3600;
            p.userId = selected->userId;
            p.gameAccountId = selected->gameAccountId;
            p.licenses = 1;
            p.region = 1;
            p.age = 21;
            p.accountPolicy = 0;
            p.capabilities = 1;
            std::memcpy(p.name, selected->name, sizeof(p.name));
            token(p.sessionToken);
            token(p.accountToken);
            sign(&p, sizeof(p), reply.signature, 32);
            Session created{};
            created.payload = p;
            issuedSessions.push_back(std::move(created));
            mutation.commit();
            ++loginCount;
            return std::string(reinterpret_cast<const char *>(&reply), sizeof(reply));
        }
    } // namespace

    void initialize(const std::filesystem::path &directory)
    {
        identityDirectory = std::filesystem::absolute(directory);
        check(BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, nullptr, 0), "RSA provider");
        check(BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
              "SHA256 provider");
        const auto privatePath = directory / "platform-private.blob";
        const auto publicPath = directory / "platform-public.blob";
        if (std::filesystem::exists(privatePath))
        {
            auto blob = read(privatePath);
            check(BCryptImportKeyPair(rsa,
                                      nullptr,
                                      BCRYPT_RSAPRIVATE_BLOB,
                                      &key,
                                      blob.data(),
                                      static_cast<unsigned long>(blob.size()),
                                      0),
                  "RSA key import");
            SecureZeroMemory(blob.data(), blob.size());
            // Do not silently change the compiler's pinned key.
            auto publicBlob = read(publicPath);
            unsigned long length = 0;
            check(BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &length, 0),
                  "public export length");
            std::vector<unsigned char> actual(length);
            check(BCryptExportKey(
                      key, nullptr, BCRYPT_RSAPUBLIC_BLOB, actual.data(), length, &length, 0),
                  "public export");
            if (actual != publicBlob)
                throw std::runtime_error("Platform public/private key mismatch");
        }
        else
        {
            if (std::filesystem::exists(publicPath))
                throw std::runtime_error(
                    "Platform private key is missing; recover it before rebuilding trust");
            check(BCryptGenerateKeyPair(rsa, &key, 2048, 0), "RSA generation");
            check(BCryptFinalizeKeyPair(key, 0), "RSA finalization");
            exportKey(privatePath, BCRYPT_RSAPRIVATE_BLOB);
            exportKey(publicPath, BCRYPT_RSAPUBLIC_BLOB);
        }
        const auto profilePath = directory / "platform-profile.bin";
        if (std::filesystem::exists(profilePath))
        {
            identity = readIdentity(profilePath);
        }
        else
        {
            identity = newIdentity("DWPlayer");
            write(profilePath, &identity, sizeof(identity));
        }
        profiles.clear();
        std::set<uint64_t> users{identity.userId};
        std::set<uint32_t> accounts{identity.gameAccountId};
        const auto extras = directory / "platform-profiles";
        if (std::filesystem::exists(extras))
            for (const auto &entry : std::filesystem::directory_iterator(extras))
            {
                if (!entry.is_regular_file() || entry.path().extension() != L".bin")
                    continue;
                const auto name = entry.path().stem().string();
                profileKey(name);
                auto profile = readIdentity(entry.path());
                if (profiles.size() >= 63 || !users.insert(profile.userId).second ||
                    !accounts.insert(profile.gameAccountId).second)
                    throw std::runtime_error("Duplicate or excessive local profiles");
                profiles.emplace(name, profile);
            }
        clientProfiles.clear();
        challenges.clear();
        const auto clients = directory / "platform-client-profiles";
        std::filesystem::create_directories(clients);
        for (const auto &entry : std::filesystem::directory_iterator(clients))
        {
            if (!entry.is_regular_file() || entry.path().extension() != L".bin")
                continue;
            const auto fingerprint = entry.path().stem().string();
            if (fingerprint.size() != 64 ||
                fingerprint.find_first_not_of("0123456789abcdef") != std::string::npos)
                throw std::runtime_error("Invalid machine identity fingerprint");
            auto account = readIdentity(entry.path());
            if (clientProfiles.size() >= 4096 || !users.insert(account.userId).second ||
                !accounts.insert(account.gameAccountId).second)
                throw std::runtime_error("Duplicate or excessive machine profiles");
            clientProfiles.emplace(fingerprint, account);
        }
        accountStore.initialize(directory);
        loadSessions();
        recoverAccounts();
    }

    std::string clientChallenge(const std::string &bytes)
    {
        if (bytes.size() != sizeof(DWLocalClientChallengeRequest))
            throw std::runtime_error("Invalid machine challenge request size");
        DWLocalClientChallengeRequest request{};
        std::memcpy(&request, bytes.data(), sizeof(request));
        if (!nonzero(request.nonce))
            throw std::runtime_error("Invalid machine challenge nonce");
        ClientKey publicKey;
        publicKey.import(request.publicKey);
        const auto id = fingerprint(request.publicKey);
        const auto time = now();
        std::lock_guard lock(mutex);
        std::erase_if(challenges,
                      [time](const auto &entry)
                      {
                          return entry.second.expires <= time;
                      });
        if (challenges.size() >= 1024 && !challenges.contains(id))
            throw std::runtime_error("Machine challenge capacity reached");
        Challenge challenge{};
        std::memcpy(challenge.nonce.data(), request.nonce, sizeof(request.nonce));
        const auto random = crypto::random(32);
        std::copy(random.begin(), random.end(), challenge.value.begin());
        challenge.expires = time + 30;
        challenges[id] = challenge;
        return std::string(reinterpret_cast<const char *>(challenge.value.data()), 32);
    }

    std::string clientLogin(const std::string &bytes)
    {
        const bool extended = bytes.size() == sizeof(DWLocalClientLoginRequestV2);
        if (!extended && bytes.size() != sizeof(DWLocalClientLoginRequest))
            throw std::runtime_error("Invalid machine login request size");
        DWLocalClientLoginRequest request{};
        DWLocalClientLoginRequestV2 local{};
        if (extended)
        {
            std::memcpy(&local, bytes.data(), sizeof(local));
            std::memcpy(&request, &local, offsetof(DWLocalClientLoginRequest, signature));
            std::memcpy(request.signature, local.signature, sizeof(request.signature));
            if (local.options > 1 || local.startingRank > 55 || local.reserved ||
                (!(local.options & 1) && (local.localUserId || local.playerXp)))
                throw std::runtime_error("Invalid local progression login fields");
        }
        else
            std::memcpy(&request, bytes.data(), sizeof(request));
        if (request.magic != DW_LOCAL_CLIENT_MAGIC ||
            request.version !=
                (extended ? DW_LOCAL_CLIENT_LOGIN_VERSION : DW_LOCAL_CLIENT_VERSION) ||
            request.name[35] || !nonzero(request.nonce))
            throw std::runtime_error("Invalid machine login layout");
        const std::string name(request.name);
        for (size_t i = name.size(); i < sizeof(request.name); ++i)
            if (request.name[i])
                throw std::runtime_error("Invalid machine name padding");
        if (!name.empty())
            validateName(name);
        std::unique_lock lock(mutex);
        const auto id = verifyMachineProof(request, bytes);
        const auto path = identityDirectory / "platform-client-profiles" / (id + ".bin");
        auto existing = clientProfiles.find(id);
        if (existing == clientProfiles.end())
        {
            if (clientProfiles.size() >= 4096)
                throw std::runtime_error("Machine profile capacity reached");
            Identity account;
            const auto hash = crypto::sha256(request.publicKey);
            uint32_t user = 0, game = 0;
            std::memcpy(&user, hash.data(), sizeof(user));
            std::memcpy(&game, hash.data() + sizeof(user), sizeof(game));
            account.userId = uint64_t(user) | 0x110000100000000ULL;
            account.gameAccountId = game | 1;
            const auto collides = [&](const Identity &other)
            {
                return account.userId == other.userId ||
                       account.gameAccountId == other.gameAccountId;
            };
            if (collides(identity))
                throw std::runtime_error("Machine identity collision");
            for (const auto *collection : {&profiles, &clientProfiles})
                for (const auto &entry : *collection)
                    if (collides(entry.second))
                        throw std::runtime_error("Machine identity collision");
            const auto initialName = name.empty() ? "ReplayPlayer-" + id.substr(0, 12) : name;
            availableName(initialName, 0, true);
            std::memset(account.name, 0, sizeof(account.name));
            std::memcpy(account.name, initialName.data(), initialName.size());
            write(path, &account, sizeof(account));
            existing = clientProfiles.emplace(id, account).first;
        }
        const auto user = existing->second.userId;
        const auto platformAccount = existing->second.gameAccountId;
        if (extended && (local.options & 1) && local.localUserId != user)
            throw std::runtime_error("Local progression belongs to a different identity");
        auto response = issueSession(std::string(reinterpret_cast<const char *>(request.nonce), 32),
                                     &existing->second,
                                     path,
                                     name,
                                     true);
        // Service dispatch takes storeMutex before consulting platform sessions.
        // Release the issuer lock before restoring its service mirror.
        lock.unlock();
        if (extended)
            services::restoreLocalProgression(5800,
                                              user,
                                              local.playerXp,
                                              (local.options & 1) != 0,
                                              local.startingRank,
                                              platformAccount);
        return response;
    }

    std::string clientRenew(const std::string &bytes)
    {
        if (bytes.size() != sizeof(DWLocalClientRenewRequest))
            throw std::runtime_error("Invalid machine renewal request size");
        DWLocalClientRenewRequest request{};
        std::memcpy(&request, bytes.data(), sizeof(request));
        if (request.magic != DW_LOCAL_CLIENT_MAGIC ||
            request.version != DW_LOCAL_CLIENT_RENEW_VERSION || !nonzero(request.nonce))
            throw std::runtime_error("Invalid machine renewal layout");
        std::lock_guard lock(mutex);
        const auto id = verifyMachineProof(request, bytes);
        const auto owner = clientProfiles.find(id);
        if (owner == clientProfiles.end())
            throw std::runtime_error("Machine renewal owner missing");
        const auto time = now();
        for (auto &session : issuedSessions)
        {
            const auto &current = session.payload;
            if (current.expires <= time || current.userId != owner->second.userId ||
                current.gameAccountId != owner->second.gameAccountId ||
                !crypto::equal(
                    std::span(reinterpret_cast<const uint8_t *>(current.sessionToken), 64),
                    std::span(reinterpret_cast<const uint8_t *>(request.sessionToken), 64)))
                continue;
            DWLocalPlatformReply reply{};
            reply.payload = current;
            std::memcpy(reply.payload.nonce, request.nonce, sizeof(request.nonce));
            reply.payload.issued = time;
            reply.payload.expires = time + 3600;
            sign(&reply.payload, sizeof(reply.payload), reply.signature, 32);
            // Publish only after signing succeeds. The established native lobby,
            // DTLS key, relay digest and account tokens retain their exact values.
            SessionChanges mutation;
            session.payload = reply.payload;
            mutation.commit();
            return std::string(reinterpret_cast<const char *>(&reply), sizeof(reply));
        }
        throw std::runtime_error("Machine renewal session unavailable or expired");
    }

    void provisionProfile(const std::filesystem::path &directory,
                          const std::string &profile,
                          const std::string &name)
    {
        profileKey(profile);
        std::lock_guard lock(mutex);
        const auto path = directory / "platform-profiles" / (profile + ".bin");
        if (std::filesystem::exists(path) || profiles.contains(profile) || profiles.size() >= 63)
            throw std::runtime_error("Local profile already exists or capacity reached");
        availableName(name);
        auto result = newIdentity(name);
        for (unsigned attempt = 0;; ++attempt)
        {
            bool duplicate =
                result.userId == identity.userId || result.gameAccountId == identity.gameAccountId;
            for (const auto &entry : profiles)
                duplicate = duplicate || entry.second.userId == result.userId ||
                            entry.second.gameAccountId == result.gameAccountId;
            if (!duplicate)
                break;
            if (attempt >= 16)
                throw std::runtime_error("Local identity generation failed");
            result = newIdentity(name);
        }
        std::filesystem::create_directories(path.parent_path());
        write(path, &result, sizeof(result));
        profiles.emplace(profile, result);
    }

    std::optional<std::string> accountName(uint64_t user)
    {
        std::lock_guard lock(mutex);
        recoverAccounts(user);
        if (user == identity.userId)
            return std::string(identity.name);
        for (const auto &entry : profiles)
            if (entry.second.userId == user)
                return std::string(entry.second.name);
        for (const auto &entry : clientProfiles)
            if (entry.second.userId == user)
                return std::string(entry.second.name);
        return std::nullopt;
    }

    RenameResult renameAccount(const LobbyIdentity &owner,
                               const std::string &accessToken,
                               const std::string &name)
    {
        std::lock_guard lock(mutex);
        recoverAccounts(owner.userId);
        if (!accountAccess(liveSession(owner), accessToken))
            return RenameResult::Unauthorized;
        const auto selected = selectProfile(owner.userId);
        const auto persisted = readIdentity(selected.path);
        if (std::memcmp(&persisted, selected.value, sizeof(persisted)) != 0)
            throw std::runtime_error("Persisted platform identity changed during the live session");
        std::string cleanedName;
        try
        {
            cleanedName = networkName(name);
            availableName(cleanedName, owner.userId, selected.machineOwned);
        }
        catch (const std::runtime_error &error)
        {
            if (std::string(error.what()) == "Invalid local profile name")
                return RenameResult::InvalidName;
            if (std::string(error.what()) == "Local player name already in use")
                return RenameResult::NameUnavailable;
            throw;
        }
        if (cleanedName == selected.value->name)
            return RenameResult::Unchanged;
        auto changed = *selected.value;
        std::memset(changed.name, 0, sizeof(changed.name));
        std::memcpy(changed.name, cleanedName.data(), cleanedName.size());
        write(selected.path, &changed, sizeof(changed));
        *selected.value = changed;
        return RenameResult::Changed;
    }

    std::vector<Account> findAccounts(const std::string &username, bool prefix)
    {
        std::lock_guard lock(mutex);
        recoverAccounts();
        std::vector<Account> found;
        const auto match = folded(username);
        const auto append = [&](const Identity &account)
        {
            const auto name = folded(account.name), tag = name + "#0";
            if (prefix ? (name.starts_with(match) || tag.starts_with(match))
                       : (name == match || tag == match))
                if (found.size() < 100)
                    found.push_back({account.userId, account.name});
        };
        std::set<std::string> machineNames;
        for (const auto &[id, account] : clientProfiles)
        {
            machineNames.insert(folded(account.name));
            append(account);
        }
        // An upgraded name resolves only to its current machine-owned account.
        // Legacy friends retain their original IDs and account-name lookups.
        if (!machineNames.contains(folded(identity.name)))
            append(identity);
        for (const auto &[profile, account] : profiles)
            if (!machineNames.contains(folded(account.name)))
                append(account);
        return found;
    }

    AccountReply accountRequest(const LobbyIdentity &owner,
                                const std::string &operation,
                                const std::string &accessToken,
                                const std::string &body)
    {
        using Json = nlohmann::json;
        const auto reject = [](uint32_t status, uint32_t code, const char *message)
        {
            return AccountReply{
                status,
                Json{{"error", {{"code", code}, {"name", "LocalAccountError"}, {"msg", message}}}}
                    .dump()};
        };
        const auto input = Json::parse(body, nullptr, false);
        if (!input.is_object())
            return reject(400, 213000, "Invalid account request");
        const auto stringField = [&input](const char *fieldName, size_t maximum)
        {
            if (!input.contains(fieldName) || !input[fieldName].is_string())
                return false;
            const auto &text = input[fieldName].get_ref<const std::string &>();
            return !text.empty() && text.size() <= maximum &&
                   std::none_of(text.begin(),
                                text.end(),
                                [](unsigned char c)
                                {
                                    return c < 32;
                                });
        };
        const auto onlyFields = [&input](std::initializer_list<const char *> allowed)
        {
            for (auto item = input.begin(); item != input.end(); ++item)
                if (std::none_of(allowed.begin(),
                                 allowed.end(),
                                 [&item](const char *name)
                                 {
                                     return item.key() == name;
                                 }))
                    return false;
            return true;
        };
        std::lock_guard lock(mutex);
        auto *session = liveSession(owner);
        if (!session)
            return reject(403, 220000, "Account session is unavailable or expired");
        recoverAccounts(owner.userId);
        // Recovery can revoke the old grant. Check it after publication, so a
        // stale token cannot authorize another update in the same request.
        if (operation == "updatesecuredfields" && !accountAccess(session, accessToken))
            return reject(403, 220000, "Access token is not owned by this account session");
        const auto before = accountProfile(owner.userId);
        auto after = before;
        const auto previous = accountStore.read(owner.userId);
        auto record = previous.value_or(
            Json{{"schema", 1}, {"owner", owner.userId}, {"fields", Json::object()}});
        const auto grants = [&session]()
        {
            if (!session->unoIDToken.empty() && !session->unoAccessToken.empty() &&
                !session->unoRefreshToken.empty())
                return;
            SessionChanges mutation;
            for (auto *target :
                 {&session->unoIDToken, &session->unoAccessToken, &session->unoRefreshToken})
                if (target->empty())
                {
                    char value[65]{};
                    token(value);
                    *target = value;
                    SecureZeroMemory(value, sizeof(value));
                }
            mutation.commit();
        };

        if (operation == "authenticateUser")
        {
            if (!onlyFields({"email", "password", "grantType"}) || !stringField("email", 255) ||
                !stringField("password", 100) || !stringField("grantType", 8) ||
                input["grantType"] != "password")
                return reject(400, 213000, "Invalid password grant");
            if (!previous || previous->at("fields").value("email", "") != folded(input["email"]) ||
                !accountStore.passwordMatches(*previous, input["password"]))
                return reject(403, 220000, "Credentials do not belong to this signed player");
            grants();
            return {200,
                    Json{{"unoID", owner.userId},
                         {"tokens",
                          {{"IDToken", session->unoIDToken},
                           {"accessToken", session->unoAccessToken},
                           {"refreshToken", session->unoRefreshToken}}}}
                        .dump()};
        }

        if (operation == "updatesecuredfields")
        {
            if (!onlyFields({"userName",
                             "email",
                             "password",
                             "accountType",
                             "firstName",
                             "lastName",
                             "dateOfBirth",
                             "country",
                             "subscriptionOptIn"}) ||
                !stringField("accountType", 4) || input["accountType"] != "full" ||
                !input.contains("subscriptionOptIn") || !input["subscriptionOptIn"].is_boolean())
                return reject(400, 213000, "Invalid full-account fields");
            if (input.contains("userName"))
            {
                if (!stringField("userName", 35))
                    return reject(400, 214500, "Invalid local player name");
                const auto name = input["userName"].get<std::string>();
                try
                {
                    availableName(name, owner.userId, selectProfile(owner.userId).machineOwned);
                }
                catch (const std::runtime_error &error)
                {
                    if (std::string(error.what()) == "Invalid local profile name")
                        return reject(400, 214500, "Invalid local player name");
                    if (std::string(error.what()) == "Local player name already in use")
                        return reject(409, 214500, "Local player name already in use");
                    throw;
                }
                std::fill(
                    after.bytes.begin() + offsetof(Identity, name), after.bytes.end(), uint8_t(0));
                std::copy(name.begin(), name.end(), after.bytes.begin() + offsetof(Identity, name));
            }
            for (const auto *field : {"email", "firstName", "lastName", "country", "dateOfBirth"})
                if (input.contains(field))
                {
                    const size_t limit = std::string_view(field) == "email" ? 255 : 400;
                    if (!stringField(field, limit))
                        return reject(400, 214000, "Invalid account field");
                    auto value = input[field].get<std::string>();
                    if (std::string_view(field) == "email")
                    {
                        value = folded(value);
                        const auto at = value.find('@');
                        if (!at || at == std::string::npos || at + 1 == value.size() ||
                            value.find('@', at + 1) != std::string::npos ||
                            value.find_first_of(" \t\r\n") != std::string::npos)
                            return reject(400, 214000, "Invalid local account email");
                        if (!accountStore.emailAvailable(owner.userId, value))
                            return reject(409, 244000, "Local account email already in use");
                    }
                    if (std::string_view(field) == "country" &&
                        (value.size() != 2 ||
                         value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") !=
                             std::string::npos))
                        return reject(400, 214000, "Invalid account country");
                    if (std::string_view(field) == "dateOfBirth")
                    {
                        if (value.size() != 10 || value[4] != '-' || value[7] != '-' ||
                            !std::all_of(value.begin(),
                                         value.end(),
                                         [&value](const char &c)
                                         {
                                             const auto offset = &c - value.data();
                                             return offset == 4 || offset == 7 ||
                                                    (c >= '0' && c <= '9');
                                         }))
                            return reject(400, 214700, "Invalid account date of birth");
                        unsigned year = 0, month = 0, day = 0;
                        if (std::from_chars(value.data(), value.data() + 4, year).ec !=
                                std::errc{} ||
                            std::from_chars(value.data() + 5, value.data() + 7, month).ec !=
                                std::errc{} ||
                            std::from_chars(value.data() + 8, value.data() + 10, day).ec !=
                                std::errc{} ||
                            year < 1900 || month < 1 || month > 12)
                            return reject(400, 214700, "Invalid account date of birth");
                        constexpr unsigned days[] = {
                            31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
                        const auto maximum =
                            days[month - 1] + unsigned(month == 2 && year % 4 == 0 &&
                                                       (year % 100 != 0 || year % 400 == 0));
                        if (!day || day > maximum)
                            return reject(400, 214700, "Invalid account date of birth");
                    }
                    record["fields"][field] = value;
                }
            record["fields"]["accountType"] = "full";
            record["fields"]["subscriptionOptIn"] = input["subscriptionOptIn"];
            if (input.contains("password"))
            {
                if (!stringField("password", 100))
                    return reject(400, 214600, "Invalid account password");
                record = accountStore.withPassword(record, input["password"]);
            }
            const bool credentialsChanged =
                !previous ||
                previous->at("fields").value("email", "") != record["fields"].value("email", "") ||
                previous->value("password", Json()) != record.value("password", Json());
            accountStore.commit(before, after, record, credentialsChanged, publishAccountProfile);
            grants();
            return {200, Json{{"success", true}, {"IDToken", session->unoIDToken}}.dump()};
        }

        if (operation == "linkUser")
        {
            if (!onlyFields({"unoIDToken", "accessToken", "refreshToken"}) ||
                !stringField("unoIDToken", 1023) || !stringField("accessToken", 6783) ||
                !stringField("refreshToken", 6783))
                return reject(400, 213000, "Invalid account link fields");
            if (!matchesToken(accessToken, session->umbrellaToken) ||
                !matchesToken(input["unoIDToken"], session->unoIDToken) ||
                !matchesToken(input["accessToken"], session->unoAccessToken) ||
                !matchesToken(input["refreshToken"], session->unoRefreshToken))
                return reject(403, 220000, "Link tokens do not belong to this account session");
            record["link"] = Json{
                {"accountType", "bnet"}, {"userID", owner.userId}, {"umbrellaID", owner.userId}};
        }
        else if (operation == "updateUmbrellaAccount")
        {
            if (!onlyFields({"accountID", "tokens"}) || !input.contains("accountID") ||
                !input["accountID"].is_number_unsigned() || !input.contains("tokens") ||
                !input["tokens"].is_object() || input["tokens"].size() != 2 ||
                !input["tokens"].contains("accessToken") ||
                !input["tokens"]["accessToken"].is_string() ||
                !input["tokens"].contains("refreshToken") ||
                !input["tokens"]["refreshToken"].is_string())
                return reject(400, 213000, "Invalid umbrella upgrade fields");
            if (input["accountID"].get<uint64_t>() != owner.userId ||
                !matchesToken(input["tokens"]["accessToken"], session->unoAccessToken) ||
                !matchesToken(input["tokens"]["refreshToken"], session->unoRefreshToken))
                return reject(403, 220000, "Upgrade tokens do not belong to this account session");
            record["umbrellaUpgraded"] = true;
        }
        else
            throw std::runtime_error("Unsupported account operation");
        accountStore.commit(before, after, record, false, publishAccountProfile);
        return {200, Json{{"umbrellaID", owner.userId}}.dump()};
    }

    std::string login(const std::string &nonce,
                      const std::string &profile,
                      const std::string &playerName)
    {
        if (nonce.size() != 32)
            throw std::runtime_error("Invalid platform nonce size");
        bool nonzero = false;
        for (auto c : nonce)
            nonzero |= c != 0;
        if (!nonzero)
            throw std::runtime_error("Invalid platform nonce");
        std::lock_guard lock(mutex);
        Identity *selected = &identity;
        if (!profile.empty())
        {
            profileKey(profile);
            const auto found = profiles.find(profile);
            if (found == profiles.end())
                throw std::runtime_error("Unknown local profile");
            selected = &found->second;
        }
        const auto path = profile.empty()
                              ? identityDirectory / "platform-profile.bin"
                              : identityDirectory / "platform-profiles" / (profile + ".bin");
        return issueSession(nonce, selected, path, playerName);
    }

    unsigned sessions()
    {
        std::lock_guard lock(mutex);
        return static_cast<unsigned>(issuedSessions.size());
    }

    std::filesystem::path executablePatchPath(const std::string &digest)
    {
        if (!executable_updates::digestName(digest))
            throw std::runtime_error("Invalid executable patch identity");
        // The path is selected by the same configured data root as the signed
        // catalog. No dependency on optional dashboard/operator state.
        return identityDirectory / "updates" / "patches" / (digest + ".delta");
    }

    std::filesystem::path executableImagePath(const std::string &digest)
    {
        if (!executable_updates::digestName(digest))
            throw std::runtime_error("Invalid executable image identity");
        return identityDirectory / "updates" / "images" / (digest + ".exe");
    }

    std::string executableUpdate(const std::string &bytes)
    {
        if (bytes.size() != sizeof(DWUpdateRequest))
            throw std::runtime_error("Invalid executable update request size");
        DWUpdateRequest request{};
        std::memcpy(&request, bytes.data(), sizeof(request));
        std::lock_guard lock(mutex);
        DWUpdateReply reply{};
        reply.plan = executable_updates::plan(identityDirectory, request, now());
        sign(&reply.plan, sizeof(reply.plan), reply.signature, 32);
        return std::string(reinterpret_cast<const char *>(&reply), sizeof(reply));
    }

    std::string resource(const std::string &bytes)
    {
        if (bytes.size() != sizeof(DWLocalResourceRequest))
            throw std::runtime_error("Invalid resource request size");
        DWLocalResourceRequest request{};
        std::memcpy(&request, bytes.data(), sizeof(request));
        bool nonzero = false;
        for (auto c : request.nonce)
            nonzero |= c != 0;
        if (!nonzero || request.program != 16974 || request.usage != 0x61706674 || request.locale ||
            request.region != 1)
            throw std::runtime_error("Unsupported resource key");
        std::lock_guard lock(mutex);
        DWLocalResourceReply reply{};
        auto &p = reply.payload;
        p.magic = DW_LOCAL_RESOURCE_MAGIC;
        p.version = 1;
        std::memcpy(p.nonce, request.nonce, sizeof(p.nonce));
        p.issued = now();
        p.expires = p.issued + 3600;
        p.program = request.program;
        p.usage = request.usage;
        p.locale = request.locale;
        p.region = request.region;
        const auto &handle = platform_resources::handle();
        const auto &content = platform_resources::content();
        if (handle.empty() || handle.size() > sizeof(p.handle) || content.empty() ||
            content.size() > sizeof(p.content))
            throw std::runtime_error("Resource unavailable");
        p.handleLength = static_cast<uint32_t>(handle.size());
        p.contentLength = static_cast<uint32_t>(content.size());
        std::memcpy(p.handle, handle.data(), handle.size());
        std::memcpy(p.content, content.data(), content.size());
        sign(&p, sizeof(p), reply.signature, 32);
        return std::string(reinterpret_cast<const char *>(&reply), sizeof(reply));
    }

    unsigned logins()
    {
        std::lock_guard lock(mutex);
        return loginCount;
    }

    unsigned authentications()
    {
        std::lock_guard lock(mutex);
        return authCount;
    }

    AuthReply authenticate(const std::string &request)
    {
        // Only the same-build Battle.net login task is supported here. Its native
        // request and reply IDs are 84/85. Other platform families require evidence.
        using Json = nlohmann::json;
        auto input = Json::parse(request);
        const auto number = [&input](const char *name) -> uint64_t
        {
            const auto &value = input.at(name);
            if (value.is_number_unsigned())
                return value.get<uint64_t>();
            if (value.is_number_integer() && value.get<int64_t>() >= 0)
                return static_cast<uint64_t>(value.get<int64_t>());
            if (value.is_string())
            {
                const auto &text = value.get_ref<const std::string &>();
                uint64_t result = 0;
                const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
                if (!text.empty() && parsed.ec == std::errc{} &&
                    parsed.ptr == text.data() + text.size())
                    return result;
            }
            throw std::runtime_error("Invalid unsigned authentication field");
        };
        if (!input.is_object() || number("auth_task") != 84 || number("iv_seed") > 0xffffffffULL)
            throw std::runtime_error("Unsupported native authentication request");
        const auto title = number("title_id");
        if (!title || title > 0xffffffffULL)
            throw std::runtime_error("Invalid title ID");
        auto extra = Json::parse(input.at("extra_data").get<std::string>());
        auto sessionToken = extra.at("session_token").get<std::string>();
        auto accountToken = extra.at("account_token").get<std::string>();
        if (sessionToken.size() != 64 || accountToken.size() != 64)
            throw std::runtime_error("Invalid platform credential size");
        std::lock_guard lock(mutex);
        Session *session = nullptr;
        const auto time = now();
        for (auto &candidate : issuedSessions)
        {
            unsigned difference = 0;
            for (unsigned i = 0; i < 64; ++i)
            {
                difference |= static_cast<uint8_t>(sessionToken[i]) ^
                              static_cast<uint8_t>(candidate.payload.sessionToken[i]);
                difference |= static_cast<uint8_t>(accountToken[i]) ^
                              static_cast<uint8_t>(candidate.payload.accountToken[i]);
            }
            if (!difference && candidate.payload.expires > time)
            {
                session = &candidate;
                break;
            }
        }
        if (!session)
            throw std::runtime_error("Platform credential pair unknown or expired");
        SessionChanges mutation;
        check(BCryptGenRandom(nullptr,
                              session->sessionKey.data(),
                              static_cast<unsigned long>(session->sessionKey.size()),
                              BCRYPT_USE_SYSTEM_PREFERRED_RNG),
              "DW session key random");
        check(BCryptGenRandom(nullptr,
                              session->serverTicket.data(),
                              static_cast<unsigned long>(session->serverTicket.size()),
                              BCRYPT_USE_SYSTEM_PREFERRED_RNG),
              "DW server ticket random");
        session->titleId = static_cast<uint32_t>(title);
        session->ivSeed = static_cast<uint32_t>(number("iv_seed"));
        session->umbrellaToken.clear();
        session->unoIDToken.clear();
        session->unoAccessToken.clear();
        session->unoRefreshToken.clear();
        // Exact packed 128-byte PC auth ticket, proven by Replay's deserialize and
        // processAuthInfo. The native parser validates the signed reply and magic.
        std::array<uint8_t, 128> ticket{};
        const uint32_t magic = 0xefbdaddeU;
        const uint32_t issued = static_cast<uint32_t>(time),
                       expires = static_cast<uint32_t>(session->payload.expires);
        const uint64_t license = 51636;
        std::memcpy(ticket.data(), &magic, 4);
        ticket[4] = 0;
        std::memcpy(ticket.data() + 5, &session->titleId, 4);
        std::memcpy(ticket.data() + 9, &issued, 4);
        std::memcpy(ticket.data() + 13, &expires, 4);
        std::memcpy(ticket.data() + 17, &license, 8);
        std::memcpy(ticket.data() + 25, &session->payload.userId, 8);
        std::memcpy(ticket.data() + 33, session->payload.name, sizeof(session->payload.name));
        std::memcpy(ticket.data() + 97, session->sessionKey.data(), session->sessionKey.size());
        Json output = {
            {"auth_task", 85},
            {"code", 700},
            {"iv_seed", number("iv_seed")},
            {"loginqueue_enabled", false},
            {"crossplay_enabled", false},
            {"client_id", "replaylocal"},
            {"account_type", "bnet"},
            {"service_level", "paid"},
            {"client_ticket", base64(ticket.data(), ticket.size())},
            {"server_ticket", base64(session->serverTicket.data(), session->serverTicket.size())},
            {"identity", "356c4bc3"},
            {"extra_data", Json{{"extended_data", "replay-local-platform-v1"}}.dump()}};
        AuthReply reply;
        reply.body = output.dump();
        uint8_t signature[256]{};
        // Replay calls rsa_verify_hash_ex with PSS and salt length zero. Keep its
        // actual verifier unchanged; the local public key alone is selected in C++.
        sign(reply.body.data(), reply.body.size(), signature, 0);
        reply.signature = base64(signature, sizeof(signature));
        mutation.commit();
        ++authCount;
        return reply;
    }

    LobbyIdentity localIdentity(uint32_t title)
    {
        std::lock_guard lock(mutex);

        LobbyIdentity result{};
        result.userId = identity.userId;
        result.platformAccountId = identity.gameAccountId;
        result.titleId = title;
        result.ivSeed = 0;
        result.name = identity.name;

        // CodRevamped owns the authenticated transport in bridge mode, so there
        // is no ReplayDW-issued lobby ticket/session key to copy here. Services
        // that only need account/title identity can still run normally.
        return result;
    }

    bool authorize(std::span<const uint8_t> ticket,
                   uint32_t title,
                   uint32_t seed,
                   LobbyIdentity &result)
    {
        if (ticket.size() != 128)
            return false;
        std::lock_guard lock(mutex);
        for (const auto &session : issuedSessions)
        {
            if (session.titleId == title && session.ivSeed == seed &&
                session.payload.expires > now() && crypto::equal(ticket, session.serverTicket))
            {
                result.key = session.sessionKey;
                result.userId = session.payload.userId;
                result.expires = session.payload.expires;
                result.titleId = title;
                result.ivSeed = seed;
                result.platformAccountId = session.payload.gameAccountId;
                result.name = session.payload.name;
                return true;
            }
        }
        return false;
    }

    bool valid(const LobbyIdentity &sessionIdentity)
    {
        std::lock_guard lock(mutex);
        return liveSession(sessionIdentity) != nullptr;
    }

    bool refreshLease(LobbyIdentity &sessionIdentity)
    {
        std::lock_guard lock(mutex);
        const auto *session = liveSession(sessionIdentity);
        if (!session)
            return false;
        sessionIdentity.expires = session->payload.expires;
        return true;
    }

    bool relaySessionMatches(uint32_t title, uint64_t user, std::span<const uint8_t> digest)
    {
        if (digest.size() != 8)
            return false;
        std::lock_guard lock(mutex);
        for (const auto &session : issuedSessions)
            if (session.titleId == title && session.payload.userId == user &&
                session.payload.expires > now())
            {
                const auto hash = crypto::sha256(session.sessionKey);
                if (crypto::equal(std::span(hash).first(8), digest))
                    return true;
            }
        return false;
    }

    unsigned legacyLogins()
    {
        std::lock_guard lock(mutex);
        return legacyCount;
    }

    bool sessionTokenMatches(const LobbyIdentity &sessionIdentity, const std::string &text)
    {
        if (text.size() != 64)
            return false;
        std::lock_guard lock(mutex);
        for (const auto &session : issuedSessions)
            if (session.payload.expires > now() && session.titleId == sessionIdentity.titleId &&
                session.payload.userId == sessionIdentity.userId &&
                crypto::equal(session.sessionKey, sessionIdentity.key) &&
                crypto::equal(
                    std::span(reinterpret_cast<const uint8_t *>(text.data()), text.size()),
                    std::span(reinterpret_cast<const uint8_t *>(session.payload.sessionToken),
                              size_t(64))))
                return true;
        return false;
    }

    std::string legacyLogin(const std::string &request)
    {
        using Json = nlohmann::json;
        const auto input = Json::parse(request);
        const auto ticket = input.at("ticket").get<std::string>();
        const auto vector = input.at("initialVectorSeed").get<std::string>();
        const auto title = input.at("titleID").get<uint32_t>();
        std::lock_guard lock(mutex);
        for (auto &session : issuedSessions)
        {
            const auto seed = std::to_string(session.ivSeed);
            const auto expected = base64(session.serverTicket.data(), session.serverTicket.size());
            const auto expectedVector = base64(seed.data(), seed.size());
            if (!session.titleId || session.titleId != title || session.payload.expires <= now() ||
                !crypto::equal(
                    std::span(reinterpret_cast<const uint8_t *>(ticket.data()), ticket.size()),
                    std::span(reinterpret_cast<const uint8_t *>(expected.data()),
                              expected.size())) ||
                vector != expectedVector)
                continue;
            if (session.umbrellaToken.empty())
            {
                SessionChanges mutation;
                char text[65]{};
                token(text);
                session.umbrellaToken = text;
                SecureZeroMemory(text, sizeof(text));
                mutation.commit();
            }
            ++legacyCount;
            // bdUmbrellaAccessInfo::deserializeFromJSON reads these three fields.
            // No UnoID is assigned: the native legacy account flow remains selected.
            return Json{{"accessToken", session.umbrellaToken},
                        {"expires", session.payload.expires},
                        {"umbrellaID", session.payload.userId}}
                .dump();
        }
        throw std::runtime_error("Legacy login ticket is unknown, expired or mismatched");
    }
} // namespace platform
