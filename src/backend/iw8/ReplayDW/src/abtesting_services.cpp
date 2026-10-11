#include "host_os.h"
#include "abtesting_services.h"
#include "rest_services.h"
#include "protobuf.h"
#include "../third_party/nlohmann/json.hpp"
#include <chrono>
#include <charconv>
#include <fstream>
#include <map>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        // Original Replay 1420FF640 reads into an 8096-byte string buffer,
        // including its terminator. Both transports share this bounded domain
        // so a REST enrollment remains readable after a legacy refetch.
        constexpr size_t enrollmentBodyCapacity = 8096;

        void valid(bool condition)
        {
            if (!condition)
                throw std::runtime_error("AB testing publication or enrollment invalid");
        }

        uint64_t integer(const Json &row, const char *field)
        {
            valid(row.contains(field) && row.at(field).is_number_unsigned());
            return row.at(field).get<uint64_t>();
        }

        std::string fingerprint(const std::string &bytes)
        {
            const auto hash = crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()));
            std::string out;
            for (const auto value : hash)
            {
                out += "0123456789abcdef"[value >> 4];
                out += "0123456789abcdef"[value & 15];
            }
            return out;
        }

        Json load(const std::filesystem::path &path)
        {
            valid(std::filesystem::file_size(path) <= 4 * 1024 * 1024);
            std::ifstream stream(path);
            valid(static_cast<bool>(stream));
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            auto data = Json::parse(stream,
                                    [&](int depth, Json::parse_event_t event, Json &value)
                                    {
                                        valid(depth <= 32);
                                        if (event == Json::parse_event_t::object_start)
                                            keys.emplace_back();
                                        else if (event == Json::parse_event_t::key)
                                            unique &=
                                                keys.back().insert(value.get<std::string>()).second;
                                        else if (event == Json::parse_event_t::object_end)
                                            keys.pop_back();
                                        return true;
                                    });
            valid(unique);
            return data;
        }

        void publish(const std::filesystem::path &path, const Json &data)
        {
            const auto bytes = data.dump();
            valid(bytes.size() <= 4 * 1024 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream out(pending, std::ios::binary | std::ios::trunc);
                if (!out.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("AB enrollment persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("AB enrollment publication failed");
        }

        std::string decode(const std::string &value)
        {
            auto digit = [](char c) -> int
            {
                if (c >= '0' && c <= '9')
                    return c - '0';
                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;
                if (c >= 'A' && c <= 'F')
                    return c - 'A' + 10;
                return -1;
            };
            std::string out;
            for (size_t i = 0; i < value.size(); ++i)
            {
                unsigned char c = static_cast<unsigned char>(value[i]);
                if (c == '%')
                {
                    wire::require(i + 2 < value.size());
                    const auto high = digit(value[i + 1]), low = digit(value[i + 2]);
                    wire::require(high >= 0 && low >= 0);
                    c = static_cast<unsigned char>(high * 16 + low);
                    i += 2;
                }
                wire::require(c >= 32 && c < 127);
                out += static_cast<char>(c);
            }
            return out;
        }

        void treatments(const Json &rows)
        {
            // Original engine 140F28810 installs one 24-byte treatment per
            // enrollment and a 1024-byte modifier buffer. SDK capacities alone
            // would allow more entries than this game's actual allocation.
            valid(rows.is_array() && rows.size() <= 1);
            for (const auto &row : rows)
            {
                valid(row.is_object() && row.size() == 3 && row.contains("modifiers") &&
                      row.at("modifiers").is_string());
                const auto starts = integer(row, "starts"), ends = integer(row, "ends");
                const auto modifiers = row.at("modifiers").get<std::string>();
                valid(ends > starts && !modifiers.empty() && modifiers.size() < 1024 &&
                      modifiers.find('\0') == std::string::npos);
            }
        }

        void enrollments(const Json &rows)
        {
            valid(rows.is_array() && rows.size() <= 8);
            std::set<uint64_t> tests;
            for (const auto &row : rows)
            {
                valid(row.is_object() && row.size() == 3 && row.contains("clientTreatments"));
                const auto test = integer(row, "testID"), cohort = integer(row, "cohortID");
                valid(test && test != UINT64_MAX && cohort && cohort != UINT64_MAX &&
                      tests.insert(test).second);
                treatments(row.at("clientTreatments"));
            }
        }
    } // namespace

    Reply abTestingEnroll(const std::filesystem::path &root,
                          const platform::LobbyIdentity &id,
                          const std::string &url,
                          std::optional<uint32_t> restVersion)
    {
        wire::require(url.find('#') == std::string::npos);
        const auto route = url.find("/v2/users/");
        wire::require(route != std::string::npos);
        const auto query = url.find('?', route);
        const auto path =
            url.substr(route, query == std::string::npos ? url.size() - route : query - route);
        if (path != "/v2/users/bnet-" + std::to_string(id.userId) + "/enrollments/" &&
            path != "/v2/users/uno-" + std::to_string(id.userId) + "/enrollments/")
            return {101, {}, "ab-enrollment-owner-denied"};
        std::map<std::string, std::string> parameters;
        if (query != std::string::npos)
        {
            size_t position = query + 1;
            while (position < url.size())
            {
                const auto end = url.find('&', position);
                const auto pair =
                    url.substr(position, end == std::string::npos ? end : end - position);
                const auto equal = pair.find('=');
                wire::require(equal != std::string::npos);
                const auto key = decode(pair.substr(0, equal)),
                           value = decode(pair.substr(equal + 1));
                wire::require((key == "client" || key == "context") && !value.empty() &&
                              value.size() < 64 && parameters.emplace(key, value).second);
                if (end == std::string::npos)
                    break;
                position = end + 1;
                wire::require(position < url.size());
            }
        }
        const auto context = parameters.contains("context") ? parameters.at("context") : "iw8";
        wire::require(!context.empty() && context.size() < 16 && context != "." && context != "..");
        for (const auto c : context)
            wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
        const auto clock =
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count());
        auto catalog = Json{{"schema", 1},
                            {"title", id.titleId},
                            {"context", context},
                            {"revision", uint64_t{0}},
                            {"tests", Json::array()}};
        const auto catalogPath =
            root / "ab-testing" / std::to_string(id.titleId) / context / "catalog.json";
        const bool published = std::filesystem::exists(catalogPath);
        if (published)
            catalog = load(catalogPath);
        valid(catalog.is_object() && catalog.size() == 5 && catalog.contains("schema") &&
              catalog.at("schema").is_number_integer() && catalog.at("schema") == 1 &&
              integer(catalog, "title") == id.titleId && catalog.contains("context") &&
              catalog.at("context") == context && catalog.contains("tests") &&
              catalog.at("tests").is_array() && catalog.at("tests").size() <= 256);
        const auto revision = integer(catalog, "revision");
        valid(!published || revision > 0);
        const auto hash = fingerprint(catalog.dump());
        Json selected = Json::array();
        std::set<uint64_t> testIds;
        uint64_t lifetime = 3600;
        for (const auto &test : catalog.at("tests"))
        {
            valid(test.is_object() && test.size() == 3 && test.contains("enabled") &&
                  test.at("enabled").is_boolean() && test.contains("cohorts") &&
                  test.at("cohorts").is_array() && !test.at("cohorts").empty() &&
                  test.at("cohorts").size() <= 128);
            const auto testId = integer(test, "testID");
            valid(testId && testId != UINT64_MAX && testIds.insert(testId).second);
            std::set<uint64_t> cohortIds;
            uint64_t weight = 0;
            for (const auto &cohort : test.at("cohorts"))
            {
                valid(cohort.is_object() && cohort.size() == 3 &&
                      cohort.contains("clientTreatments"));
                const auto cohortId = integer(cohort, "cohortID"),
                           share = integer(cohort, "weight");
                valid(cohortId && cohortId != UINT64_MAX && cohortIds.insert(cohortId).second &&
                      share && share <= UINT32_MAX - weight);
                weight += share;
                treatments(cohort.at("clientTreatments"));
            }
            if (!test.at("enabled").get<bool>())
                continue;
            const auto seed = Json::array({id.titleId, id.userId, context, testId}).dump();
            const auto digest = crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(seed.data()), seed.size()));
            auto bucket = wire::at<uint64_t>(digest, 0) % weight;
            for (const auto &cohort : test.at("cohorts"))
            {
                const auto share = integer(cohort, "weight");
                if (bucket >= share)
                {
                    bucket -= share;
                    continue;
                }
                Json active = Json::array();
                for (const auto &treatment : cohort.at("clientTreatments"))
                {
                    const auto starts = integer(treatment, "starts"),
                               ends = integer(treatment, "ends");
                    if (starts > clock)
                        lifetime = std::min(lifetime, starts - clock);
                    if (ends > clock)
                        lifetime = std::min(lifetime, ends - clock);
                    // 140F290A0 applies every returned modifier immediately. Do
                    // not publish future or expired treatments to that consumer.
                    if (starts <= clock && clock < ends)
                        active.push_back(treatment);
                }
                if (!active.empty())
                    selected.push_back(Json{{"testID", testId},
                                            {"cohortID", cohort.at("cohortID")},
                                            {"clientTreatments", active}});
                break;
            }
        }
        enrollments(selected);
        auto statePath = root / "ab-enrollments" / std::to_string(id.titleId);
        if (context != "iw8")
            statePath /= context;
        statePath /= std::to_string(id.userId) + ".json";
        Json previous = std::filesystem::exists(statePath) ? load(statePath) : Json();
        if (!previous.is_null())
        {
            valid(previous.is_object() && previous.contains("token") &&
                  previous.at("token").is_string() && previous.contains("enrollments"));
            const auto token = previous.at("token").get<std::string>();
            const auto validHash = [](const std::string &value)
            {
                valid(value.size() == 64);
                for (const auto c : value)
                    valid((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
            };
            validHash(token);
            (void)integer(previous, "expires");
            enrollments(previous.at("enrollments"));
            if (previous.contains("schema"))
            {
                valid(previous.size() == 9 && previous.at("schema").is_number_integer() &&
                      previous.at("schema") == 1 && integer(previous, "title") == id.titleId &&
                      integer(previous, "user") == id.userId && previous.at("context") == context &&
                      previous.at("publicationHash").is_string());
                const auto oldRevision = integer(previous, "revision");
                validHash(previous.at("publicationHash").get<std::string>());
                valid(revision >= oldRevision &&
                      (revision != oldRevision || previous.at("publicationHash") == hash));
            }
            else
                valid(previous.size() == 3 && context == "iw8" &&
                      previous.at("enrollments").empty());
        }
        Json state{{"schema", 1},
                   {"title", id.titleId},
                   {"user", id.userId},
                   {"context", context},
                   {"revision", revision},
                   {"publicationHash", hash},
                   {"enrollments", selected}};
        const bool renew = previous.is_null() || integer(previous, "expires") <= clock ||
                           previous.at("enrollments") != selected ||
                           (previous.contains("revision") && previous.at("revision") != revision);
        if (renew)
        {
            const auto random = crypto::random(32);
            state["token"] = fingerprint(std::string(random.begin(), random.end()));
            state["expires"] = clock + lifetime;
        }
        else
        {
            state["token"] = previous.at("token");
            state["expires"] = std::min(integer(previous, "expires"), clock + lifetime);
        }
        Json native = selected;
        for (auto &enrollment : native)
            for (auto &treatment : enrollment.at("clientTreatments"))
            {
                const auto remaining = integer(treatment, "ends") - clock;
                valid(remaining <= UINT32_MAX);
                treatment = Json{{"startsIn", uint32_t{0}},
                                 {"endsIn", remaining},
                                 {"modifiers", treatment.at("modifiers")}};
            }
        const auto bytes = Json{
            {"expiresIn", integer(state, "expires") - clock},
            {"ABToken", state.at("token")},
            {"enrollments",
             native}}.dump();
        valid(bytes.size() < enrollmentBodyCapacity);
        Reply reply{0, {}, "ab-enrollment-read"};
        if (restVersion)
            reply.rest = RESTResult{*restVersion, 200, bytes};
        else
        {
            reply.structured = true;
            wire::Bytes header;
            proto::text(header, 1, "Content-Length");
            proto::text(header, 2, std::to_string(bytes.size()));
            proto::bytes(reply.structure, 1, header);
            proto::integer(reply.structure, 2, 200);
            proto::text(reply.structure, 3, bytes);
        }
        if (previous != state)
            publish(statePath, state);
        return reply;
    }

    std::optional<Reply> abTestingRest(const std::filesystem::path &root,
                                       const platform::LobbyIdentity &id,
                                       const RESTRequest &r)
    {
        if (r.service != "abtesting" || r.resource != "abtesting" || r.operation != "enroll")
            return std::nullopt;
        // Original 1420FFE50 emits a bodyless POST, JSON Accept, and this
        // relative gateway prefix. It omits setServiceName; 142169540 rejects
        // that empty name locally. Require an explicitly addressed request
        // rather than weakening the common envelope to accept that SDK bug.
        wire::require(r.method == 0x504F5354u && r.accept == 1 && r.content == 0 && !r.hasBody &&
                      r.body.empty() && !r.headers.contains("content-type") &&
                      r.uri.starts_with("abtesting/v2/users/"));
        return abTestingEnroll(root, id, r.uri.substr(9), r.version);
    }
} // namespace services
