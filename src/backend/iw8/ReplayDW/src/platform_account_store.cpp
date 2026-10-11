#include "host_os.h"
#include "crypto_provider.h"
#include "platform_account_store.h"
#include "crypto.h"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <fstream>
#include <set>
#include <stdexcept>

namespace platform::accounts
{
    namespace
    {
        constexpr uint64_t passwordRounds = 200000;

        std::string hex(std::span<const uint8_t> bytes)
        {
            constexpr char alphabet[] = "0123456789abcdef";
            std::string result;
            result.reserve(bytes.size() * 2);
            for (const auto value : bytes)
            {
                result.push_back(alphabet[value >> 4]);
                result.push_back(alphabet[value & 15]);
            }
            return result;
        }

        crypto::Bytes unhex(const Json &value, size_t length)
        {
            if (!value.is_string())
                throw std::runtime_error("Invalid persisted account byte field");
            const auto text = value.get<std::string>();
            if (text.size() != length * 2 ||
                text.find_first_not_of("0123456789abcdef") != std::string::npos)
                throw std::runtime_error("Invalid persisted account byte field");
            crypto::Bytes bytes(length);
            for (size_t i = 0; i < length; ++i)
            {
                unsigned valueByte = 0;
                const auto parsed =
                    std::from_chars(text.data() + i * 2, text.data() + i * 2 + 2, valueByte, 16);
                if (parsed.ec != std::errc{})
                    throw std::runtime_error("Invalid persisted account byte field");
                bytes[i] = static_cast<uint8_t>(valueByte);
            }
            return bytes;
        }

        crypto::Bytes derive(const std::string &password, const crypto::Bytes &salt)
        {
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            if (BCryptOpenAlgorithmProvider(
                    &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
                throw std::runtime_error("Cannot initialize account password derivation");
            crypto::Bytes result(32);
            const auto status =
                BCryptDeriveKeyPBKDF2(algorithm,
                                      reinterpret_cast<PUCHAR>(const_cast<char *>(password.data())),
                                      static_cast<ULONG>(password.size()),
                                      const_cast<PUCHAR>(salt.data()),
                                      static_cast<ULONG>(salt.size()),
                                      passwordRounds,
                                      result.data(),
                                      static_cast<ULONG>(result.size()),
                                      0);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            if (status < 0)
                throw std::runtime_error("Cannot derive account password verifier");
            return result;
        }

        std::string contents(const std::filesystem::path &path)
        {
            std::ifstream input(path, std::ios::binary | std::ios::ate);
            if (!input || input.tellg() < 0 || input.tellg() > 32768)
                throw std::runtime_error("Invalid persisted account document");
            std::string result(static_cast<size_t>(input.tellg()), '\0');
            input.seekg(0);
            if (!input.read(result.data(), static_cast<std::streamsize>(result.size())))
                throw std::runtime_error("Cannot read persisted account document");
            return result;
        }

        Json document(const std::filesystem::path &path)
        {
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            const auto callback =
                [&keys, &unique](int depth, Json::parse_event_t event, Json &value)
            {
                if (depth > 4)
                    throw std::runtime_error("Persisted account nesting exceeds its schema");
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    unique = keys.back().insert(value.get<std::string>()).second && unique;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            auto result = Json::parse(contents(path), callback, false);
            if (!unique || !result.is_object())
                throw std::runtime_error("Invalid persisted account document");
            return result;
        }

        void publishDocument(const std::filesystem::path &path, const Json &value)
        {
            const auto text = value.dump();
            if (std::filesystem::exists(path) && contents(path) == text)
                return;
            auto pending = path;
            pending += ".creating";
            {
                std::ofstream output(pending, std::ios::binary | std::ios::trunc);
                if (!output.write(text.data(), static_cast<std::streamsize>(text.size())) ||
                    !output.flush())
                    throw std::runtime_error("Cannot flush account publication");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Cannot publish account document");
        }

        uint64_t ownerOf(const Json &record)
        {
            if (!record.contains("owner") || !record["owner"].is_number_unsigned())
                throw std::runtime_error("Invalid persisted account owner");
            const auto owner = record["owner"].get<uint64_t>();
            if (!owner || owner == UINT64_MAX)
                throw std::runtime_error("Invalid persisted account owner");
            return owner;
        }

        void validate(const Json &record, uint64_t owner)
        {
            if (record.value("schema", 0) != 1 || ownerOf(record) != owner ||
                !record.contains("fields") || !record["fields"].is_object())
                throw std::runtime_error("Persisted account schema or owner mismatch");
            for (auto item = record.begin(); item != record.end(); ++item)
                if (item.key() != "schema" && item.key() != "owner" && item.key() != "fields" &&
                    item.key() != "password" && item.key() != "link" &&
                    item.key() != "umbrellaUpgraded")
                    throw std::runtime_error("Unknown persisted account field");
            const auto &fields = record["fields"];
            if (fields.value("accountType", "") != "full" ||
                !fields.contains("subscriptionOptIn") || !fields["subscriptionOptIn"].is_boolean())
                throw std::runtime_error("Invalid persisted full-account fields");
            for (auto item = fields.begin(); item != fields.end(); ++item)
            {
                if (item.key() == "accountType" || item.key() == "subscriptionOptIn")
                    continue;
                if (item.key() != "email" && item.key() != "firstName" &&
                    item.key() != "lastName" && item.key() != "dateOfBirth" &&
                    item.key() != "country")
                    throw std::runtime_error("Unknown persisted account metadata");
                if (!item.value().is_string())
                    throw std::runtime_error("Invalid persisted account metadata");
                const auto text = item.value().get<std::string>();
                const size_t limit = item.key() == "email" ? 255 : 400;
                if (text.empty() || text.size() > limit ||
                    std::any_of(text.begin(),
                                text.end(),
                                [](unsigned char c)
                                {
                                    return c < 32;
                                }))
                    throw std::runtime_error("Invalid persisted account metadata");
            }
            if (record.contains("link"))
            {
                const auto &link = record["link"];
                if (!link.is_object() || link.size() != 3 ||
                    link.value("accountType", "") != "bnet" ||
                    link.value("userID", uint64_t(0)) != owner ||
                    link.value("umbrellaID", uint64_t(0)) != owner)
                    throw std::runtime_error("Persisted account link changes profile ownership");
            }
            if (record.contains("umbrellaUpgraded") && !record["umbrellaUpgraded"].is_boolean())
                throw std::runtime_error("Invalid persisted umbrella upgrade");
            if (record.contains("password"))
            {
                const auto &password = record["password"];
                if (!password.is_object() || password.size() != 4 ||
                    password.value("algorithm", "") != "pbkdf2-sha256" ||
                    password.value("rounds", uint64_t(0)) != passwordRounds)
                    throw std::runtime_error("Invalid persisted account password verifier");
                unhex(password.at("salt"), 16);
                unhex(password.at("digest"), 32);
            }
        }

        uint64_t namedOwner(const std::filesystem::path &path)
        {
            const auto text = path.stem().string();
            uint64_t result = 0;
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
            if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
                text != std::to_string(result) || !result || result == UINT64_MAX)
                throw std::runtime_error("Invalid account document filename");
            return result;
        }
    } // namespace

    void Store::initialize(const std::filesystem::path &root)
    {
        directory = root / "platform-accounts";
        std::filesystem::create_directories(directory / "intents");
        for (const auto &entry : std::filesystem::directory_iterator(directory))
            if (entry.path().extension() == L".json")
                validate(document(entry.path()), namedOwner(entry.path()));
    }

    std::optional<Json> Store::read(uint64_t user) const
    {
        const auto path = directory / (std::to_string(user) + ".json");
        if (!std::filesystem::exists(path))
            return std::nullopt;
        auto result = document(path);
        validate(result, user);
        return result;
    }

    bool Store::emailAvailable(uint64_t owner, const std::string &email) const
    {
        for (const auto &entry : std::filesystem::directory_iterator(directory))
            if (entry.path().extension() == L".json")
            {
                const auto other = namedOwner(entry.path());
                const auto value = read(other).value();
                if (other != owner && value["fields"].value("email", "") == email)
                    return false;
            }
        return true;
    }

    bool Store::passwordMatches(const Json &record, const std::string &password) const
    {
        validate(record, ownerOf(record));
        if (!record.contains("password"))
            return false;
        const auto &value = record["password"];
        return crypto::equal(derive(password, unhex(value["salt"], 16)),
                             unhex(value["digest"], 32));
    }

    Json Store::withPassword(Json record, const std::string &password) const
    {
        // Preserve the salt on exact retries. Password text is never persisted.
        if (!passwordMatches(record, password))
        {
            const auto salt = crypto::random(16);
            record["password"] = Json{{"algorithm", "pbkdf2-sha256"},
                                      {"rounds", passwordRounds},
                                      {"salt", hex(salt)},
                                      {"digest", hex(derive(password, salt))}};
        }
        return record;
    }

    void Store::finish(const std::filesystem::path &intent,
                       const Resolve &resolve,
                       const Publish &publish)
    {
        const auto mutation = document(intent);
        const auto user = namedOwner(intent);
        if (mutation.value("schema", 0) != 1 || ownerOf(mutation) != user)
            throw std::runtime_error("Invalid account publication intent");
        const auto before = unhex(mutation.at("beforeIdentity"), 56);
        const auto after = unhex(mutation.at("afterIdentity"), 56);
        // Only the name bytes at +20 can change. IDs, magic and version stay intact.
        if (!std::equal(before.begin(), before.begin() + 20, after.begin()) || after[55] ||
            std::find(after.begin() + 20, after.end(), uint8_t(0)) == after.end())
            throw std::runtime_error("Account intent changes stable identity fields");
        auto profile = resolve(user);
        const auto disk = contents(profile.path);
        const auto matches = [&disk](const crypto::Bytes &value)
        {
            return disk.size() == value.size() &&
                   std::memcmp(disk.data(), value.data(), value.size()) == 0;
        };
        if (!matches(before) && !matches(after))
            throw std::runtime_error("Account intent belongs to a different persisted identity");
        const auto &record = mutation.at("record");
        validate(record, user);
        if (!mutation.contains("revokeCredentials") || !mutation["revokeCredentials"].is_boolean())
            throw std::runtime_error("Invalid account token revocation intent");
        const auto beforeHash = mutation.at("beforeRecordSHA256").get<std::string>();
        if ((!beforeHash.empty() && beforeHash.size() != 64) ||
            beforeHash.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw std::runtime_error("Invalid account document publication hash");
        const auto path = directory / (std::to_string(user) + ".json");
        const auto textHash = [](const std::string &text)
        {
            return hex(crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(text.data()), text.size())));
        };
        const auto currentHash = std::filesystem::exists(path) ? textHash(contents(path)) : "";
        if (currentHash != beforeHash && currentHash != textHash(record.dump()))
            throw std::runtime_error("Account document changed during pending publication");
        const bool revoke = mutation["revokeCredentials"];
        std::copy(after.begin(), after.end(), profile.bytes.begin());
        publish(profile, true, revoke);
        publishDocument(path, record);
        publish(profile, false, revoke);
        if (!std::filesystem::remove(intent))
            throw std::runtime_error("Cannot retire completed account publication intent");
    }

    void Store::recover(const Resolve &resolve, const Publish &publish, uint64_t onlyOwner)
    {
        const auto intents = directory / "intents";
        for (const auto &entry : std::filesystem::directory_iterator(intents))
            if (entry.path().extension() == L".json" &&
                (!onlyOwner || namedOwner(entry.path()) == onlyOwner))
                finish(entry.path(), resolve, publish);
    }

    void Store::commit(const Profile &before,
                       const Profile &after,
                       const Json &record,
                       bool revokeCredentials,
                       const Publish &publish)
    {
        if (before.user != after.user || before.path != after.path)
            throw std::runtime_error("Account mutation changes profile ownership");
        validate(record, before.user);
        const auto disk = contents(before.path);
        if (disk.size() != before.bytes.size() ||
            std::memcmp(disk.data(), before.bytes.data(), before.bytes.size()) != 0)
            throw std::runtime_error("Persisted account identity changed during the live session");
        const auto intent = directory / "intents" / (std::to_string(before.user) + ".json");
        if (std::filesystem::exists(intent))
            throw std::runtime_error("Account already has a pending publication");
        const auto recordPath = directory / (std::to_string(before.user) + ".json");
        std::string beforeHash;
        if (std::filesystem::exists(recordPath))
        {
            const auto text = contents(recordPath);
            beforeHash = hex(crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(text.data()), text.size())));
        }
        publishDocument(intent,
                        Json{{"schema", 1},
                             {"owner", before.user},
                             {"beforeIdentity", hex(before.bytes)},
                             {"afterIdentity", hex(after.bytes)},
                             {"beforeRecordSHA256", beforeHash},
                             {"revokeCredentials", revokeCredentials},
                             {"record", record}});
        finish(
            intent,
            [&before](uint64_t)
            {
                return before;
            },
            publish);
    }
} // namespace platform::accounts
