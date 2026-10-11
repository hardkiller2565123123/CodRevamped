#pragma once
#include "nlohmann/json.hpp"
#include <array>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace platform::accounts
{
    using Json = nlohmann::json;

    struct Profile
    {
        uint64_t user;
        std::filesystem::path path;
        std::array<uint8_t, 56> bytes;
    };

    using Resolve = std::function<Profile(uint64_t)>;
    using Publish = std::function<void(const Profile &, bool validateOnly, bool revokeCredentials)>;

    // All calls run under the platform mutex, including recovery and publication.
    // Credentials and optional account fields augment an existing machine profile.
    // This store cannot create a player or alter its stable identity fields.
    class Store
    {
      public:
        void initialize(const std::filesystem::path &directory);
        void recover(const Resolve &resolve, const Publish &publish, uint64_t onlyOwner = 0);
        std::optional<Json> read(uint64_t user) const;
        bool emailAvailable(uint64_t owner, const std::string &email) const;
        bool passwordMatches(const Json &record, const std::string &password) const;
        Json withPassword(Json record, const std::string &password) const;
        void commit(const Profile &before,
                    const Profile &after,
                    const Json &record,
                    bool revokeCredentials,
                    const Publish &publish);

      private:
        std::filesystem::path directory;
        void finish(const std::filesystem::path &intent,
                    const Resolve &resolve,
                    const Publish &publish);
    };
} // namespace platform::accounts
