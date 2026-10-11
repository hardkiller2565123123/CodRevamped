#include "../src/platform.h"
#include "../src/wire.h"
#include "../src/shared_protocol/dw_platform_protocol.h"
#include "../third_party/nlohmann/json.hpp"
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace services
{
    // This contract executable uses the original version-1 platform login.
    // Progression restore is outside its scope; fail if that boundary is reached.
    void restoreLocalProgression(uint32_t, uint64_t, uint64_t, bool, unsigned, uint32_t)
    {
        throw std::runtime_error("Unexpected progression restore in lease contract test");
    }
}

namespace
{
    using Json = nlohmann::json;

    void require(bool passed, const char *issue)
    {
        if (!passed)
            throw std::runtime_error(issue);
    }

    bool sameIdentity(const platform::LobbyIdentity &a, const platform::LobbyIdentity &b)
    {
        return a.key == b.key && a.userId == b.userId && a.titleId == b.titleId &&
               a.ivSeed == b.ivSeed && a.platformAccountId == b.platformAccountId && a.name == b.name;
    }
}

int main(int argc, char **argv)
{
    try
    {
        require(argc == 2, "Provide a new disposable fixture directory");
        const auto directory = std::filesystem::absolute(argv[1]);
        require(!std::filesystem::exists(directory), "Do not overwrite an existing profile");
        std::filesystem::create_directories(directory);
        platform::initialize(directory);
        const auto signedReply = platform::login(std::string(32, 'L'));
        require(signedReply.size() == sizeof(DWLocalPlatformReply), "Signed login size");
        DWLocalPlatformReply reply{};
        std::memcpy(&reply, signedReply.data(), sizeof(reply));
        const Json request = {
            {"auth_task", 84},
            {"iv_seed", 7148},
            {"title_id", 5800},
            {"extra_data", Json{{"session_token", reply.payload.sessionToken},
                                 {"account_token", reply.payload.accountToken}}.dump()}};
        auto authenticated = Json::parse(platform::authenticate(request.dump()).body);
        platform::LobbyIdentity owner;
        require(platform::authorize(wire::base64(authenticated.at("server_ticket").get<std::string>(), 128),
                                    5800, 7148, owner), "Initial native ticket");
        const auto initial = owner;
        for (const auto copiedExpiry : {uint64_t{1}, UINT64_MAX})
        {
            auto stale = owner;
            stale.expires = copiedExpiry;
            require(platform::valid(stale), "Copied timestamp overrides the issuer lease");
            require(platform::refreshLease(stale) && stale.expires == initial.expires &&
                    sameIdentity(stale, initial), "Refresh changes stable identity fields");
        }
        std::cout << "PASS: past/future copied timestamps resolve to the live issuer lease\n";
        for (unsigned variant = 0; variant != 5; ++variant)
        {
            auto invalid = owner;
            if (variant == 0)
                invalid.expires = 0;
            else if (variant == 1)
                invalid.userId ^= 1;
            else if (variant == 2)
                invalid.titleId ^= 1;
            else if (variant == 3)
                invalid.ivSeed ^= 1;
            else
                invalid.key[0] ^= 1;
            const auto before = invalid;
            require(!platform::valid(invalid) && !platform::refreshLease(invalid) &&
                    invalid.expires == before.expires && sameIdentity(invalid, before),
                    "Unauthorized refresh changes or accepts the identity");
        }
        std::cout << "PASS: absent lease, wrong owner/title/seed/key rejected without mutation\n";
        authenticated = Json::parse(platform::authenticate(request.dump()).body);
        require(!platform::valid(owner) && !platform::refreshLease(owner),
                "Superseded native ticket revived");
        platform::LobbyIdentity replacement;
        require(platform::authorize(wire::base64(authenticated.at("server_ticket").get<std::string>(), 128),
                                    5800, 7148, replacement) &&
                platform::refreshLease(replacement), "Replacement native ticket rejected");
        std::cout << "PASS: reauthentication retires the old key and preserves the new session\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
