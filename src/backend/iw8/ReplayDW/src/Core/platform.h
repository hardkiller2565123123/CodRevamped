#pragma once
#include <filesystem>
#include <string>
#include <array>
#include <span>
#include <cstdint>
#include <optional>
#include <vector>

namespace platform
{
    struct AuthReply
    {
        std::string body, signature;
    };

    void initialize(const std::filesystem::path &directory);
    std::string login(const std::string &nonce,
                      const std::string &profile = "",
                      const std::string &playerName = "");
    std::string clientChallenge(const std::string &request);
    std::string clientLogin(const std::string &request);
    std::string clientRenew(const std::string &request);
    void provisionProfile(const std::filesystem::path &directory,
                          const std::string &profile,
                          const std::string &name);
    std::optional<std::string> accountName(uint64_t user);
    // CodRevamped owns authentication when ReplayDW is used behind the native
    // IW8 LSG bridge. Remember those live XUID/name pairs so social, channels,
    // matchmaking and friend lookup can resolve other connected players.
    void rememberHostedAccount(uint64_t user, const std::string &name);

    struct Account
    {
        uint64_t userId;
        std::string name;
    };

    std::vector<Account> findAccounts(const std::string &username, bool prefix);
    std::string resource(const std::string &request);
    std::string executableUpdate(const std::string &request);
    std::filesystem::path executablePatchPath(const std::string &digest);
    std::filesystem::path executableImagePath(const std::string &digest);
    unsigned sessions();
    unsigned logins();
    AuthReply authenticate(const std::string &request);
    unsigned authentications();

    struct LobbyIdentity
    {
        std::array<uint8_t, 24> key{};
        uint64_t userId = 0, expires = 0;
        uint32_t titleId = 0, ivSeed = 0, platformAccountId = 0;
        std::string name;
    };

    bool authorize(std::span<const uint8_t> ticket,
                   uint32_t title,
                   uint32_t seed,
                   LobbyIdentity &result);
    // Build a local service identity from the persisted ReplayDW platform profile.
    // This is used when ReplayDW services are hosted behind CodRevamped's own
    // BGS/Auth3/LSG transport rather than ReplayDW's standalone lobby server.
    LobbyIdentity localIdentity(uint32_t title);
    bool valid(const LobbyIdentity &identity);
    // Update only a still-authorized connection's lease from its issuing session.
    // A renewal retains the ticket, key and identity; copied expiry timestamps
    // must not cap newly issued domain credentials at the original login time.
    bool refreshLease(LobbyIdentity &identity);
    // Relay INIT omits the lobby ticket; bind its signed digest to a live session.
    bool relaySessionMatches(uint32_t title, uint64_t user, std::span<const uint8_t> digest);
    bool sessionTokenMatches(const LobbyIdentity &identity, const std::string &token);

    struct AccountReply
    {
        uint32_t status;
        std::string body;
    };

    AccountReply accountRequest(const LobbyIdentity &identity,
                                const std::string &operation,
                                const std::string &accessToken,
                                const std::string &body);
    enum class RenameResult
    {
        Changed,
        Unchanged,
        Unauthorized,
        InvalidName,
        NameUnavailable
    };
    // Persist only an existing account owned by this live lobby and its issued
    // legacy access token. The signed identity/session payload stays immutable.
    RenameResult renameAccount(const LobbyIdentity &identity,
                               const std::string &accessToken,
                               const std::string &name);
    std::string legacyLogin(const std::string &request);
    unsigned legacyLogins();
} // namespace platform
