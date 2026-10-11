#include "startup_services.h"
#include "protobuf.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <cmath>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        std::filesystem::path directoryRoot;

        struct Geography
        {
            std::string code = "US", country = "United States", region = "Local", city = "Local",
                        timezone = "UTC";
            float latitude = 0, longitude = 0;
            uint32_t asn = 0;
        } geography;

        std::string fieldText(const proto::Field &f, size_t limit)
        {
            wire::require(f.type == 2 && f.bytes.size() < limit);
            std::string value(reinterpret_cast<const char *>(f.bytes.data()), f.bytes.size());
            wire::require(value.find('\0') == std::string::npos);
            return value;
        }
    } // namespace

    void initializeStartup(const std::filesystem::path &directory)
    {
        directoryRoot = std::filesystem::absolute(directory);
        geography = Geography{};
        const auto path = directory / "geography.json";
        if (!std::filesystem::exists(path))
            return;
        wire::require(std::filesystem::file_size(path) <= 4096);
        std::ifstream stream(path);
        const auto json = Json::parse(stream);
        geography.code = json.value("country_code", geography.code);
        geography.country = json.value("country", geography.country);
        geography.region = json.value("region", geography.region);
        geography.city = json.value("city", geography.city);
        geography.timezone = json.value("timezone", geography.timezone);
        geography.latitude = json.value("latitude", 0.0f);
        geography.longitude = json.value("longitude", 0.0f);
        geography.asn = json.value("asn", 0u);
        for (const auto &value : {geography.code,
                                  geography.country,
                                  geography.region,
                                  geography.city,
                                  geography.timezone})
            wire::require(value.find('\0') == std::string::npos);
        wire::require(geography.code.size() < 3 && geography.country.size() < 65 &&
                      geography.region.size() < 65 && geography.city.size() < 129 &&
                      geography.timezone.size() < 9 && std::isfinite(geography.latitude) &&
                      std::isfinite(geography.longitude) && std::abs(geography.latitude) <= 90 &&
                      std::abs(geography.longitude) <= 180);
    }

    std::optional<Reply> startup(const platform::LobbyIdentity &id,
                                 uint8_t service,
                                 uint8_t task,
                                 wire::Reader &p)
    {
        if (service == 151 && task == 1)
        {
            // Replay 142136BE0 binds one ordinary bdBoolResult. Registered users
            // are an explicit local publication; absent publication means false.
            p.end();
            const auto path =
                directoryRoot / "esports" / std::to_string(id.titleId) / "registered.json";
            bool registered = false;
            if (std::filesystem::exists(path))
            {
                if (std::filesystem::file_size(path) > 16 * 1024)
                    throw std::runtime_error("Esports publication size invalid");
                std::ifstream in(path);
                if (!in)
                    throw std::runtime_error("Esports publication read failed");
                const auto data = Json::parse(in);
                try
                {
                    wire::require(data.at("schema") == 1 && data.at("registered").is_array() &&
                                  data.at("registered").size() <= 200);
                    std::set<uint64_t> users;
                    for (const auto &value : data.at("registered"))
                    {
                        wire::require(value.is_number_unsigned());
                        const auto user = value.get<uint64_t>();
                        wire::require(user && user != UINT64_MAX && users.insert(user).second);
                        if (user == id.userId)
                            registered = true;
                    }
                }
                catch (const std::runtime_error &)
                {
                    throw std::runtime_error("Esports publication schema invalid");
                }
            }
            wire::Writer out;
            out.boolean(registered);
            return Reply{0, {std::move(out.data)}, "esports-registration-read"};
        }
        if (service == 12 && task == 13)
        {
            // Replay 0x142127960 starts StructTask(12,13). The paired
            // bdSanitizeStringBase writer/reader at 14213CBB0/14213CB60 use
            // exactly field 1 and a 1024-byte UTF-8 string buffer.
            proto::Reader reader{p.structure(2048)};
            proto::Field f;
            std::string value;
            bool seen = false;
            while (reader.next(f))
                if (f.tag == 1)
                {
                    wire::require(!seen);
                    seen = true;
                    value = fieldText(f, 1024);
                }
            wire::require(seen);
            std::string clean;
            for (size_t at = 0; at < value.size();)
            {
                const auto first = static_cast<unsigned char>(value[at]);
                const size_t start = at++;
                uint32_t code = first;
                unsigned tail = 0;
                uint32_t minimum = 0;
                if (first >= 0xc2 && first <= 0xdf)
                {
                    code = first & 0x1f;
                    tail = 1;
                    minimum = 0x80;
                }
                else if (first >= 0xe0 && first <= 0xef)
                {
                    code = first & 0x0f;
                    tail = 2;
                    minimum = 0x800;
                }
                else if (first >= 0xf0 && first <= 0xf4)
                {
                    code = first & 7;
                    tail = 3;
                    minimum = 0x10000;
                }
                else
                    wire::require(first < 0x80);
                wire::require(tail <= value.size() - at);
                for (unsigned i = 0; i < tail; ++i)
                {
                    const auto c = static_cast<unsigned char>(value[at++]);
                    wire::require((c & 0xc0) == 0x80);
                    code = (code << 6) | (c & 0x3f);
                }
                wire::require(code >= minimum && code <= 0x10ffff &&
                              !(code >= 0xd800 && code <= 0xdfff));
                // Local policy removes control characters and preserves printable
                // UTF-8. No claim is made to emulate a commercial profanity list.
                if (code >= 0x20 && !(code >= 0x7f && code <= 0x9f))
                    clean.append(value, start, at - start);
            }
            Reply reply{0, {}, "local-string-sanitized", true, {}};
            proto::text(reply.structure, 1, clean);
            return reply;
        }
        if (service == 12 && task == 1)
        {
            const auto value = p.text(1024);
            p.end();
            // Local string-verification policy: reject empty/control-character
            // strings. Native bdVerifyString consumes a u32 result in [0,2].
            bool accepted = !value.empty();
            for (unsigned char c : value)
                if (c < 32 || c == 127)
                    accepted = false;
            wire::Writer result;
            result.u32(accepted ? 0 : 2);
            return Reply{0, {std::move(result.data)}, "local-string-verification"};
        }
        if (service == 27 && task == 2)
        {
            p.end();
            wire::Writer w;
            w.text(geography.code);
            w.text(geography.country);
            w.text(geography.region);
            w.text(geography.city);
            w.f32(geography.latitude);
            w.f32(geography.longitude);
            w.u32(geography.asn);
            w.text(geography.timezone);
            return Reply{0, {std::move(w.data)}, "dml-local-geography"};
        }
        if (service == 67 && task == 6)
        {
            p.end();
            Reply reply{0, {}, "event-filter-initialized"};
            wire::Writer push;
            push.u32(45);
            push.u32(0); // BD_EVENT_LOG_FILTERED_CATEGORIES + empty deny list
            reply.pushes.push_back(std::move(push.data));
            return reply;
        }
        return std::nullopt;
    }
} // namespace services
