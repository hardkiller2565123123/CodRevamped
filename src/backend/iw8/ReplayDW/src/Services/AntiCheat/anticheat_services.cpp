#include "host_os.h"
#include "anticheat_services.h"
#include "nlohmann/json.hpp"
#include <chrono>
#include <fstream>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t nativeCapacity = 0x40000, maxReceiptBytes = 4 * 1024 * 1024,
                         maxReceipts = 4096;

        void validStore(bool condition)
        {
            if (!condition)
                throw std::runtime_error("Challenge response receipt schema invalid");
        }

        uint64_t unsignedValue(const Json &value)
        {
            validStore(value.is_number_unsigned());
            return value.get<uint64_t>();
        }

        std::string digest(std::span<const uint8_t> bytes)
        {
            constexpr char digits[] = "0123456789abcdef";
            std::string out;
            for (const auto byte : crypto::sha256(bytes))
            {
                out += digits[byte >> 4];
                out += digits[byte & 15];
            }
            return out;
        }

        wire::Bytes encoded(const Json &responses, const wire::Bytes &log)
        {
            validStore(responses.is_array() && responses.size() <= UINT16_MAX && log.size() <= 64);
            wire::Writer out;
            out.u16(static_cast<uint16_t>(responses.size()));
            std::set<uint64_t> ids;
            for (const auto &row : responses)
            {
                validStore(row.is_object() && row.size() == 2);
                const auto challenge = unsignedValue(row.at("challenge"));
                validStore(challenge != UINT64_MAX && ids.insert(challenge).second);
                out.u64(challenge);
                const auto &response = row.at("response");
                // 0x1420F02F0 emits NAN (20) for the Int64 maximum sentinel.
                // Preserve it separately from every representable signed response.
                if (response.is_null())
                    out.data.push_back(20);
                else
                {
                    validStore(response.is_number_integer());
                    if (response.is_number_unsigned())
                        validStore(response.get<uint64_t>() < static_cast<uint64_t>(INT64_MAX));
                    const auto value = response.get<int64_t>();
                    validStore(value != INT64_MAX);
                    out.data.push_back(9);
                    wire::raw(out.data, value);
                }
            }
            out.blob(log);
            out.data.push_back(0);
            validStore(out.data.size() <= nativeCapacity);
            return out.data;
        }

        Json load(const std::filesystem::path &path,
                  const platform::LobbyIdentity &id,
                  const std::string &hash)
        {
            validStore(std::filesystem::file_size(path) <= maxReceiptBytes);
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Challenge response receipt read failed");
            auto receipt = Json::parse(in);
            validStore(receipt.is_object() && receipt.size() == 7 && receipt.at("schema") == 1);
            validStore(unsignedValue(receipt.at("title")) == id.titleId &&
                       unsignedValue(receipt.at("owner")) == id.userId);
            validStore(receipt.at("request_sha256") == hash);
            (void)unsignedValue(receipt.at("recorded"));
            try
            {
                const auto log = wire::base64(receipt.at("log").get<std::string>(), 64);
                validStore(wire::base64Encode(log) == receipt.at("log").get<std::string>());
                validStore(digest(encoded(receipt.at("responses"), log)) == hash);
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Challenge response receipt schema invalid");
            }
            return receipt;
        }

        void save(const std::filesystem::path &path, const Json &receipt)
        {
            const auto bytes = receipt.dump();
            validStore(bytes.size() <= maxReceiptBytes);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream out(pending, std::ios::binary | std::ios::trunc);
                if (!out.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("Challenge response receipt write failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Challenge response receipt publication failed");
        }
    } // namespace

    std::optional<Reply> anticheatServices(const std::filesystem::path &root,
                                           const platform::LobbyIdentity &id,
                                           uint8_t service,
                                           uint8_t task,
                                           wire::Reader &params)
    {
        if (service != 38 || task != 2)
            return std::nullopt;
        // Same-Replay 0x142115720 binds no result for 38/2. Its exact vtable
        // 0x14269DDC8 selects serializer 0x1420FD8A0: UInt16 count, repeated
        // UInt64 challenge/Int64 response, then an unconditional 0..64-byte blob.
        const auto start = params.offset;
        wire::require(params.data.size() - start <= nativeCapacity);
        const auto count = params.u16();
        Json responses = Json::array();
        std::set<uint64_t> ids;
        for (unsigned i = 0; i < count; ++i)
        {
            const auto challenge = params.value<uint64_t>(10);
            wire::require(challenge != UINT64_MAX && ids.insert(challenge).second);
            Json response = nullptr;
            wire::require(params.offset < params.data.size());
            if (params.data[params.offset] == 20)
                ++params.offset;
            else
            {
                const auto value = params.value<int64_t>(9);
                wire::require(value != INT64_MAX);
                response = value;
            }
            responses.push_back(Json{{"challenge", challenge}, {"response", response}});
        }
        const auto log = params.blob(64);
        params.end();
        const auto hash = digest(params.data.subspan(start, params.offset - start));
        const auto directory =
            root / "anti-cheat" / std::to_string(id.titleId) / std::to_string(id.userId);
        const auto path = directory / (hash + ".json");
        if (std::filesystem::exists(path))
        {
            const auto receipt = load(path, id, hash);
            validStore(receipt.at("responses") == responses &&
                       receipt.at("log") == wire::base64Encode(log));
            return Reply{0, {}, "challenge-responses-already-recorded"};
        }
        size_t receipts = 0;
        if (std::filesystem::exists(directory))
            for (const auto &entry : std::filesystem::directory_iterator(directory))
                if (entry.path().extension() == L".json" && ++receipts >= maxReceipts)
                    return Reply{102, {}, "challenge-response-capacity-exceeded"};
        const auto recorded =
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count());
        save(path,
             Json{{"schema", 1},
                  {"title", id.titleId},
                  {"owner", id.userId},
                  {"request_sha256", hash},
                  {"recorded", recorded},
                  {"responses", responses},
                  {"log", wire::base64Encode(log)}});
        // This acknowledges a local report, not a fabricated challenge verdict,
        // security credential, platform attestation or native fence override.
        return Reply{0, {}, "challenge-responses-recorded"};
    }
} // namespace services
