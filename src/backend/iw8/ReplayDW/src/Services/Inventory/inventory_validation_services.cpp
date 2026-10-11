#include "inventory_validation_services.h"
#include "crypto.h"
#include "nlohmann/json.hpp"
#include <chrono>
#include <fstream>
#include <set>
#include <tuple>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t tokenCapacity = 10240;
        constexpr size_t documentCapacity = 4 * 1024 * 1024;
        constexpr size_t authorizationCapacity = 4096;

        std::string digest(std::span<const uint8_t> bytes)
        {
            const auto hash = crypto::sha256(bytes);
            std::string value;
            value.reserve(hash.size() * 2);
            for (const auto byte : hash)
            {
                value.push_back("0123456789abcdef"[byte >> 4]);
                value.push_back("0123456789abcdef"[byte & 15]);
            }
            return value;
        }

        bool hashText(const std::string &value)
        {
            return value.size() == 64 &&
                   value.find_first_not_of("0123456789abcdef") == std::string::npos;
        }

        bool nameText(const std::string &value, size_t capacity, bool allowEmpty)
        {
            if ((!allowEmpty && value.empty()) || value.size() >= capacity)
                return false;
            for (const unsigned char c : value)
                if (c < 32 || c >= 127)
                    return false;
            return true;
        }

        Json publication(const std::filesystem::path &path)
        {
            std::ifstream stream(path, std::ios::binary);
            if (!stream)
                throw std::runtime_error("Inventory validation publication read failed");
            // Bound the actual read, including an atomic replacement between
            // lookup and open. A preliminary file_size check cannot cap parsing.
            std::string bytes(documentCapacity + 1, '\0');
            stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
            const auto count = static_cast<size_t>(stream.gcount());
            if (stream.bad() || (!stream.eof() && stream.fail()))
                throw std::runtime_error("Inventory validation publication read failed");
            if (count > documentCapacity)
                throw std::runtime_error("Inventory validation publication exceeds capacity");
            bytes.resize(count);
            return Json::parse(bytes);
        }

        struct ValidationResult
        {
            // Target bdValidationTokenResult::deserialize reads both Int64s
            // before the blob. Their retail semantics are not inferred here.
            int64_t prefix[2]{};
            wire::Bytes token;

            wire::Bytes serialize() const
            {
                wire::Writer out;
                out.i64(prefix[0]);
                out.i64(prefix[1]);
                out.blob(token);
                return std::move(out.data);
            }
        };

        Reply validate(const std::filesystem::path &directory,
                       const platform::LobbyIdentity &id,
                       wire::Reader &request)
        {
            // Target 0x142129190 writes context, filename (128 bytes), and the
            // input token blob, then binds one bdValidationTokenResult.
            const auto context = request.text(16);
            const auto name = request.text(128);
            const auto token = request.blob(tokenCapacity);
            request.end();
            wire::require(nameText(context, 16, true) && nameText(name, 128, false) &&
                          !token.empty());
            const auto tokenHash = digest(token);
            const auto path =
                directory / "inventory-validation" / std::to_string(id.titleId) / "catalog.json";
            if (!std::filesystem::exists(path))
                return {108, {}, "inventory-validation-publication-unavailable"};
            const auto catalog = publication(path);
            const auto time =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
            const Json *selected = nullptr;
            ValidationResult result;
            try
            {
                wire::require(catalog.is_object() && catalog.at("schema") == 1 &&
                              catalog.at("title") == id.titleId &&
                              catalog.at("authorizations").is_array() &&
                              catalog["authorizations"].size() <= authorizationCapacity);
                std::set<std::tuple<std::string, std::string, std::string>> unique;
                for (const auto &row : catalog["authorizations"])
                {
                    const auto scope = row.at("context").get<std::string>();
                    const auto filename = row.at("filename").get<std::string>();
                    const auto hash = row.at("token_sha256").get<std::string>();
                    wire::require(
                        nameText(scope, 16, true) && nameText(filename, 128, false) &&
                        hashText(hash) && unique.emplace(scope, filename, hash).second &&
                        row.at("owner").is_number_unsigned() && row["owner"].get<uint64_t>() != 0 &&
                        row["owner"].get<uint64_t>() != UINT64_MAX &&
                        row.at("enabled").is_boolean() && row.at("starts").is_number_unsigned() &&
                        row.at("expires").is_number_unsigned() &&
                        (!row["expires"].get<uint64_t>() || row["expires"] > row["starts"]));
                    const auto &prefix = row.at("result_prefix_i64");
                    wire::require(prefix.is_array() && prefix.size() == 2);
                    for (const auto &value : prefix)
                        wire::require(value.is_number_integer() &&
                                      (!value.is_number_unsigned() ||
                                       value.get<uint64_t>() <= uint64_t(INT64_MAX)));
                    auto output = wire::base64(row.at("result_token_base64").get<std::string>(),
                                               tokenCapacity);
                    wire::require(!output.empty());
                    if (scope == context && filename == name && hash == tokenHash)
                    {
                        selected = &row;
                        result.prefix[0] = prefix[0].get<int64_t>();
                        result.prefix[1] = prefix[1].get<int64_t>();
                        result.token = std::move(output);
                    }
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Inventory validation publication schema invalid");
            }
            if (!selected)
                return {108, {}, "inventory-validation-token-unavailable"};
            if ((*selected)["owner"] != id.userId)
                return {101, {}, "inventory-validation-owner-denied"};
            if ((*selected)["enabled"] != true || (*selected)["starts"].get<uint64_t>() > time ||
                ((*selected)["expires"].get<uint64_t>() &&
                 (*selected)["expires"].get<uint64_t>() <= time))
                return {108, {}, "inventory-validation-token-inactive"};
            // A trusted local issuer supplies the entire result. Validation never
            // interprets opaque client bytes as inventory writes or stat grants.
            return {0, {result.serialize()}, "inventory-validation-authorized"};
        }
    } // namespace

    std::optional<Reply> inventoryValidationServices(const std::filesystem::path &directory,
                                                     const platform::LobbyIdentity &id,
                                                     uint8_t service,
                                                     uint8_t task,
                                                     wire::Reader &request)
    {
        if (service == 80 && task == 58)
            return validate(directory, id, request);
        return std::nullopt;
    }
} // namespace services
