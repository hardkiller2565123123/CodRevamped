#include "host_os.h"
#include "engagement_services.h"
#include "abtesting_services.h"
#include "protobuf.h"
#include "../third_party/nlohmann/json.hpp"
#include <chrono>
#include <fstream>
#include <set>
#include <tuple>
#include <charconv>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        std::string hex(std::span<const uint8_t> bytes)
        {
            constexpr char digits[] = "0123456789abcdef";
            std::string out;
            for (auto b : bytes)
            {
                out.push_back(digits[b >> 4]);
                out.push_back(digits[b & 15]);
            }
            return out;
        }

        std::string text(const proto::Field &f, size_t capacity)
        {
            wire::require(f.type == 2 && f.bytes.size() < capacity);
            std::string value(reinterpret_cast<const char *>(f.bytes.data()), f.bytes.size());
            wire::require(value.find('\0') == std::string::npos);
            return value;
        }

        struct ProxyRequest
        {
            std::string method, url, body, contentType;
        };

        ProxyRequest proxyRequest(wire::Reader &p)
        {
            proto::Reader reader{p.structure(16384)};
            proto::Field f;
            ProxyRequest result;
            unsigned seen = 0, headers = 0;
            while (reader.next(f))
            {
                if (f.tag >= 1 && f.tag <= 3)
                {
                    const auto bit = 1U << f.tag;
                    wire::require(!(seen & bit));
                    seen |= bit;
                    auto value = text(f, f.tag == 1 ? 16 : 1024);
                    if (f.tag == 1)
                        result.method = std::move(value);
                    else if (f.tag == 2)
                        result.url = std::move(value);
                    else
                        result.body = std::move(value);
                }
                else if (f.tag == 4)
                {
                    wire::require(f.type == 2 && ++headers <= 16);
                    proto::Reader header{f.bytes};
                    proto::Field h;
                    std::string key, value;
                    unsigned fields = 0;
                    while (header.next(h))
                        if (h.tag == 1 || h.tag == 2)
                        {
                            const auto bit = 1U << h.tag;
                            wire::require(!(fields & bit));
                            fields |= bit;
                            auto field = text(h, h.tag == 1 ? 100 : 4096);
                            (h.tag == 1 ? key : value) = std::move(field);
                        }
                    wire::require(fields == 6);
                    if (key == "Content-Type")
                    {
                        wire::require(result.contentType.empty() && !value.empty());
                        result.contentType = std::move(value);
                    }
                }
            }
            wire::require((seen & 6) == 6 && result.method == "POST" && !result.url.empty());
            return result;
        }

        Reply proxyResponse(const Json &body, const char *operation)
        {
            const auto bytes = body.dump();
            // Both Replay HTTP-proxy consumers read into fixed native buffers.
            wire::require(bytes.size() < 16000);
            Reply result{0, {}, operation, true, {}};
            wire::Bytes header;
            proto::text(header, 1, "Content-Length");
            proto::text(header, 2, std::to_string(bytes.size()));
            proto::bytes(result.structure, 1, header);
            proto::integer(result.structure, 2, 200);
            proto::text(result.structure, 3, bytes);
            return result;
        }

        void save(const std::filesystem::path &path, const Json &data)
        {
            const auto bytes = data.dump();
            wire::require(bytes.size() <= 4 * 1024 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream out(pending, std::ios::binary | std::ios::trunc);
                if (!out.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("Engagement persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Engagement publication failed");
        }

        Json load(const std::filesystem::path &path, const Json &initial)
        {
            if (!std::filesystem::exists(path))
                return initial;
            wire::require(std::filesystem::file_size(path) <= 4 * 1024 * 1024);
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Engagement read failed");
            return Json::parse(in);
        }

        std::string publicationContext(const std::string &context)
        {
            if (context.empty())
                return "_default";
            wire::require(context != "." && context != "..");
            for (const auto value : context)
                wire::require((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                              (value >= '0' && value <= '9') || value == '_' || value == '-' ||
                              value == '.');
            return context;
        }

        Reply openLootDrop(const std::filesystem::path &directory,
                           const platform::LobbyIdentity &id,
                           wire::Reader &p)
        {
            // Exact Replay 142139BB0 starts 195/1. Writer 14213EDC0 sends the
            // HTTP-proxy envelope and opaque clientData; reader 14213F0A0 reads
            // an HTTP JSON body's scriptResponse string into 16000 bytes.
            const auto request = proxyRequest(p);
            wire::require(request.contentType == "application/json" && !request.body.empty());
            const auto start = request.url.find("/v1/users/");
            const auto query = request.url.find('?', start);
            wire::require(start != std::string::npos && query != std::string::npos &&
                          request.url.find('#') == std::string::npos);
            const auto path = request.url.substr(start, query - start);
            const auto split = path.find("/loot-drop/", 10);
            wire::require(split != std::string::npos && path.ends_with('/'));
            const auto user = path.substr(10, split - 10);
            if (user != "bnet-" + std::to_string(id.userId) &&
                user != "uno-" + std::to_string(id.userId))
                return {101, {}, "loot-drop-owner-denied"};
            const auto number = path.substr(split + 11, path.size() - split - 12);
            wire::require(!number.empty() && (number.size() == 1 || number.front() != '0'));
            uint32_t drop = 0;
            const auto parsed = std::from_chars(number.data(), number.data() + number.size(), drop);
            wire::require(parsed.ec == std::errc{} && parsed.ptr == number.data() + number.size());
            std::string context, client;
            unsigned fields = 0;
            size_t at = query + 1;
            while (at < request.url.size())
            {
                const auto end = request.url.find('&', at);
                const auto pair = request.url.substr(at, end == std::string::npos ? end : end - at);
                const auto equal = pair.find('=');
                wire::require(equal != std::string::npos);
                const auto key = pair.substr(0, equal);
                wire::require(key == "context" || key == "client");
                const unsigned bit = key == "context" ? 1 : 2;
                wire::require(!(fields & bit));
                fields |= bit;
                std::string value;
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
                for (size_t index = equal + 1; index < pair.size(); ++index)
                {
                    char c = pair[index];
                    if (c == '%')
                    {
                        wire::require(index + 2 < pair.size());
                        const auto high = digit(pair[index + 1]), low = digit(pair[index + 2]);
                        wire::require(high >= 0 && low >= 0);
                        c = static_cast<char>(high * 16 + low);
                        index += 2;
                    }
                    value.push_back(c);
                }
                wire::require(value.size() < (bit == 1 ? 16u : 64u));
                (bit == 1 ? context : client) = std::move(value);
                if (end == std::string::npos)
                    break;
                at = end + 1;
                wire::require(at < request.url.size());
            }
            wire::require(fields == 3 && !client.empty());
            const auto scoped = publicationContext(context);
            (void)publicationContext(client);
            unsigned bodyKeys = 0;
            const auto body = Json::parse(
                request.body,
                [&](int, Json::parse_event_t event, Json &)
                {
                    if (event == Json::parse_event_t::key)
                        wire::require(++bodyKeys == 1);
                    return true;
                },
                false);
            wire::require(body.is_object() && body.size() == 1 && body.contains("clientData") &&
                          body["clientData"].is_string());
            const auto clientData = body["clientData"].get<std::string>();
            wire::require(clientData.size() < 1000 && clientData.find('\0') == std::string::npos);
            const auto fingerprint = hex(crypto::sha256(std::span(
                reinterpret_cast<const uint8_t *>(clientData.data()), clientData.size())));
            const auto root = directory / "loot-generation" / std::to_string(id.titleId) / scoped;
            const auto pathToState = root / "receipts" / (std::to_string(id.userId) + ".json");
            const auto validHash = [](const Json &value)
            {
                return value.is_string() && value.get_ref<const std::string &>().size() == 64 &&
                       value.get_ref<const std::string &>().find_first_not_of("0123456789abcdef") ==
                           std::string::npos;
            };
            const auto validResponse = [](const Json &value)
            {
                return value.is_string() && value.get_ref<const std::string &>().size() < 16000 &&
                       value.get_ref<const std::string &>().find('\0') == std::string::npos &&
                       Json{{"scriptResponse", value}}.dump().size() < 16000;
            };
            auto persisted = [](bool valid)
            {
                if (!valid)
                    throw std::runtime_error("Loot publication or receipt schema invalid");
            };
            auto read = [&](const std::filesystem::path &path, const Json &initial)
            {
                if (std::filesystem::exists(path))
                    persisted(std::filesystem::file_size(path) <= 4 * 1024 * 1024);
                return load(path, initial);
            };
            auto state = read(pathToState,
                              Json{{"schema", 1},
                                   {"title", id.titleId},
                                   {"context", context},
                                   {"owner", id.userId},
                                   {"next_id", uint64_t{1}},
                                   {"receipts", Json::array()}});
            persisted(state.is_object() && state.at("schema") == 1 &&
                      state.at("title") == id.titleId && state.at("context") == context &&
                      state.at("owner") == id.userId && state.at("receipts").is_array() &&
                      state["receipts"].size() <= 4096 && state.at("next_id").is_number_unsigned());
            std::set<std::pair<uint32_t, std::string>> unique;
            uint64_t next = 1;
            for (const auto &row : state["receipts"])
            {
                persisted(row.at("id").is_number_unsigned() && row["id"] == next++ &&
                          row.at("drop").is_number_unsigned() &&
                          row["drop"].get<uint64_t>() <= UINT32_MAX &&
                          validHash(row.at("client_data_sha256")) &&
                          validResponse(row.at("script_response")) &&
                          row.at("recorded").is_number_unsigned());
            }
            persisted(state["next_id"] == next);
            const auto catalogPath = root / "catalog.json";
            if (!std::filesystem::exists(catalogPath))
                return {108, {}, "loot-drop-unpublished"};
            const auto catalog = read(catalogPath, Json::object());
            persisted(catalog.at("schema") == 1 && catalog.at("title") == id.titleId &&
                      catalog.at("context") == context && catalog.at("responses").is_array() &&
                      catalog["responses"].size() <= 512);
            unique.clear();
            const Json *selected = nullptr;
            const auto stamp = now();
            for (const auto &row : catalog["responses"])
            {
                persisted(row.at("drop").is_number_unsigned() &&
                          row["drop"].get<uint64_t>() <= UINT32_MAX &&
                          validHash(row.at("client_data_sha256")) &&
                          validResponse(row.at("script_response")) &&
                          row.at("enabled").is_boolean() && row.at("starts").is_number_unsigned() &&
                          row.at("expires").is_number_unsigned() &&
                          (!row["expires"].get<uint64_t>() || row["expires"] > row["starts"]) &&
                          unique
                              .emplace(row["drop"].get<uint32_t>(),
                                       row["client_data_sha256"].get<std::string>())
                              .second);
                if (row["drop"] == drop && row["client_data_sha256"] == fingerprint &&
                    row["enabled"] == true && row["starts"].get<uint64_t>() <= stamp &&
                    (!row["expires"].get<uint64_t>() || row["expires"].get<uint64_t>() > stamp))
                    selected = &row;
            }
            if (!selected)
                return {108, {}, "loot-drop-rule-unpublished"};
            if (state["receipts"].size() == 4096)
                return {108, {}, "loot-drop-receipt-capacity"};
            auto reply = proxyResponse(Json{{"scriptResponse", (*selected)["script_response"]}},
                                       "loot-drop-opened");
            state["receipts"].push_back({{"id", next},
                                         {"drop", drop},
                                         {"client_data_sha256", fingerprint},
                                         {"script_response", (*selected)["script_response"]},
                                         {"recorded", stamp}});
            state["next_id"] = next + 1;
            persisted(state.dump().size() <= 4 * 1024 * 1024);
            // Exact native game caller 14103E3C0 uses constant clientData for
            // successive crate openings. It is not a transaction/retry identifier.
            // Journal each accepted task separately; preserve its exact response
            // without using a previous opening to override today's publication.
            save(pathToState, state);
            return reply;
        }

        struct MarketingMessage
        {
            uint64_t id = 0, assignment = 0, starts = 0, expires = 0;
            uint32_t location = 0;
            bool enabled = false;
            std::string language;
            wire::Bytes content, metadata, payload, signature;

            wire::Bytes serialize() const
            {
                // Full same-Replay bdCommsMessage reader 142114CF0. All eight
                // fields are present even when a published blob is empty.
                wire::Bytes result;
                proto::integer(result, 1, id);
                proto::text(result, 2, language);
                proto::bytes(result, 3, content);
                proto::bytes(result, 4, metadata);
                proto::bytes(result, 5, payload);
                proto::bytes(result, 6, signature);
                proto::integer(result, 7, assignment);
                proto::integer(result, 8, location);
                return result;
            }
        };

        std::vector<MarketingMessage> publications(const std::filesystem::path &directory,
                                                   uint32_t title,
                                                   const std::string &context)
        {
            const auto path = directory / "marketing" / std::to_string(title) /
                              publicationContext(context) / "catalog.json";
            if (!std::filesystem::exists(path))
                return {};
            try
            {
                const auto document = load(path, Json::object());
                wire::require(
                    document.at("schema") == 1 && document.at("title").is_number_unsigned() &&
                    document.at("title") == title && document.at("context") == context &&
                    document.at("messages").is_array() && document.at("messages").size() <= 512);
                std::vector<MarketingMessage> result;
                std::set<std::tuple<uint64_t, std::string, uint32_t>> unique;
                for (const auto &row : document.at("messages"))
                {
                    MarketingMessage message;
                    for (const auto *key : {"id", "assignment", "location", "starts", "expires"})
                        wire::require(row.at(key).is_number_unsigned());
                    message.id = row.at("id").get<uint64_t>();
                    message.assignment = row.at("assignment").get<uint64_t>();
                    wire::require(message.id && message.id != UINT64_MAX &&
                                  row.at("location").get<uint64_t>() <= UINT32_MAX &&
                                  row.at("enabled").is_boolean());
                    message.location = row.at("location").get<uint32_t>();
                    message.starts = row.at("starts").get<uint64_t>();
                    message.expires = row.at("expires").get<uint64_t>();
                    wire::require(!message.expires || message.expires > message.starts);
                    message.enabled = row.at("enabled").get<bool>();
                    message.language = row.at("language").get<std::string>();
                    wire::require(
                        !message.language.empty() && message.language.size() < 20 &&
                        message.language.find('\0') == std::string::npos &&
                        unique.emplace(message.id, message.language, message.location).second);
                    message.content = wire::base64(row.at("content").get<std::string>(), 4096);
                    message.metadata = wire::base64(row.at("metadata").get<std::string>(), 2048);
                    message.payload = wire::base64(row.at("payload").get<std::string>(), 1024);
                    message.signature = wire::base64(row.at("signature").get<std::string>(), 65);
                    result.push_back(std::move(message));
                }
                return result;
            }
            catch (const std::runtime_error &)
            {
                // Publication corruption is a storage error, not malformed
                // caller parameters. Validate disabled/expired rows as well.
                throw std::runtime_error("Marketing publication schema invalid");
            }
        }

        Reply messages(const std::filesystem::path &directory,
                       const platform::LobbyIdentity &id,
                       wire::Reader &p)
        {
            // Replay 0x142129BC0 -> startStructTask(104,6), request vtable
            // bdCommsGetMessagesRequest: context/language and location/count objects.
            // Native response 0x142114EC0 reads repeated field-1 message objects; an
            // absent collection is a valid empty publication, not invented ads.
            proto::Reader request{p.structure(16384)};
            proto::Field f;
            unsigned seen = 0;
            std::string context, language;
            std::vector<std::pair<uint32_t, uint32_t>> locations;
            std::set<uint32_t> unique;
            while (request.next(f))
            {
                if (f.tag == 1 || f.tag == 2)
                {
                    const auto bit = 1U << f.tag;
                    wire::require(!(seen & bit));
                    seen |= bit;
                    auto value = text(f, f.tag == 1 ? 16 : 20);
                    (f.tag == 1 ? context : language) = std::move(value);
                }
                else if (f.tag == 3)
                {
                    wire::require(f.type == 2 && locations.size() < 64);
                    proto::Reader location{f.bytes};
                    proto::Field l;
                    unsigned fields = 0;
                    uint32_t locationId = 0, count = 0;
                    while (location.next(l))
                        if (l.tag == 1 || l.tag == 2)
                        {
                            const auto bit = 1U << l.tag;
                            wire::require(!(fields & bit) && l.type == 0 && l.value <= UINT32_MAX);
                            fields |= bit;
                            if (l.tag == 2)
                            {
                                wire::require(l.value <= 100);
                                count = static_cast<uint32_t>(l.value);
                            }
                            else
                                locationId = static_cast<uint32_t>(l.value);
                        }
                    wire::require(fields == 6);
                    wire::require(unique.insert(locationId).second);
                    locations.emplace_back(locationId, count);
                }
            }
            wire::require(seen == 6);
            const auto published = publications(directory, id.titleId, context);
            Reply result{0, {}, "marketing-messages-empty", true, {}};
            const auto stamp = now();
            unsigned selected = 0;
            for (const auto &[location, maximum] : locations)
            {
                unsigned count = 0;
                for (const auto &message : published)
                {
                    if (count == maximum)
                        break;
                    if (!message.enabled || message.language != language ||
                        message.location != location || message.starts > stamp ||
                        (message.expires && message.expires <= stamp))
                        continue;
                    proto::bytes(result.structure, 1, message.serialize());
                    if (result.structure.size() > 256 * 1024)
                        return {102, {}, "marketing-response-capacity-exceeded"};
                    ++count;
                    ++selected;
                }
            }
            if (selected)
            {
                result.operation = "marketing-messages-published";
                result.detail = " messages=" + std::to_string(selected);
            }
            return result;
        }

        Reply viewed(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     wire::Reader &p)
        {
            // Same-Replay 104/7 constructor 142129C50. Request writer 142115320:
            // context (1), repeated bdCommsMessageViewed objects (2). Its 80-byte
            // object writer 142115180 emits u64 ID/u32 location/u64 assignment/text.
            proto::Reader reader{p.structure(64 * 1024)};
            proto::Field f;
            std::string context;
            bool seen = false;
            auto incoming = Json::array();
            while (reader.next(f))
            {
                wire::require(f.tag == 1 || f.tag == 2);
                if (f.tag == 1)
                {
                    wire::require(!seen);
                    seen = true;
                    context = text(f, 17);
                }
                else
                {
                    wire::require(f.type == 2 && incoming.size() < 100);
                    proto::Reader item{f.bytes};
                    proto::Field field;
                    unsigned fields = 0;
                    Json row = Json::object();
                    while (item.next(field))
                    {
                        wire::require(field.tag >= 1 && field.tag <= 4 &&
                                      !(fields & (1U << field.tag)));
                        fields |= 1U << field.tag;
                        const auto key = std::to_string(field.tag);
                        if (field.tag == 4)
                            row[key] = text(field, 21);
                        else
                        {
                            wire::require(field.type == 0 &&
                                          (field.tag != 2 || field.value <= UINT32_MAX));
                            row[key] = field.value;
                        }
                    }
                    wire::require(fields == 30);
                    incoming.push_back(std::move(row));
                }
            }
            wire::require(seen);
            // Actual Replay MarkMessagesReadOnBackendAsync constructs this
            // request without setting its context. Preserve its valid empty
            // context in the default realm instead of rejecting every view.
            const auto path = directory / "marketing" / std::to_string(id.titleId) /
                              publicationContext(context) /
                              (std::to_string(id.userId) + ".views.json");
            auto data =
                load(path, Json{{"schema", 1}, {"owner", id.userId}, {"views", Json::object()}});
            try
            {
                wire::require(data.at("schema") == 1 && data.at("owner").is_number_unsigned() &&
                              data.at("owner") == id.userId && data.at("views").is_object() &&
                              data.at("views").size() <= 4096);
                for (auto receipt = data.at("views").begin(); receipt != data.at("views").end();
                     ++receipt)
                {
                    const auto &row = receipt->at("view");
                    wire::require(row.is_object() && row.size() == 4);
                    for (const auto *key : {"1", "2", "3"})
                        wire::require(row.at(key).is_number_unsigned());
                    wire::require(row.at("2").get<uint64_t>() <= UINT32_MAX);
                    const auto language = row.at("4").get<std::string>();
                    wire::require(language.size() <= 20 &&
                                  language.find('\0') == std::string::npos);
                    wire::require(receipt->at("recorded").is_number_unsigned());
                    const auto encoded = row.dump();
                    wire::require(
                        receipt.key() ==
                        hex(crypto::sha256(std::span(
                            reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size()))));
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Marketing receipt store schema invalid");
            }
            for (const auto &row : incoming)
            {
                const auto encoded = row.dump();
                const auto digest = hex(crypto::sha256(
                    std::span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size())));
                auto &views = data["views"];
                if (views.contains(digest))
                    continue;
                if (views.size() >= 4096)
                    return {102, {}, "marketing-view-capacity-exceeded"};
                views[digest] = Json{{"view", row}, {"recorded", now()}};
            }
            if (!incoming.empty())
                save(path, data);
            return {0, {}, "marketing-views-recorded", true, {}};
        }

        Reply enroll(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     wire::Reader &p)
        {
            // Replay 0x142139AD0 starts 194/1 using the full HTTP-proxy envelope.
            // 0x1420FF850 requires expiresIn, ABToken and enrollments JSON, and updates
            // the native lobby token lifetime itself.
            const auto request = proxyRequest(p);
            wire::require(request.body.empty());
            return abTestingEnroll(directory, id, request.url);
        }

        Reply events(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     wire::Reader &p)
        {
            // Same-Replay task constructor 0x14212DE00, serializable 0x1420FB3F0.
            const auto count = p.u32();
            wire::require(count <= 256);
            Json incoming = Json::array();
            // Native recordMixedEvents can submit a zero-event flush.
            if (!count)
            {
                p.end();
                return {0, {}, "events-empty-batch"};
            }
            for (uint32_t i = 0; i < count; ++i)
            {
                const auto category = p.u32();
                const bool binary = p.boolean();
                wire::Bytes bytes;
                // The native task grows up to 0x40000 bytes (0x14212DE00); event
                // payloads are not limited to 8 KiB, and writeBlob accepts length zero.
                if (binary)
                    bytes = p.blob(0x40000);
                else
                {
                    const auto value = p.text(0x40000);
                    bytes.assign(value.begin(), value.end());
                }
                incoming.push_back(
                    {{"category", category}, {"binary", binary}, {"contentHex", hex(bytes)}});
            }
            p.end();
            const auto path = directory / "event-log" / std::to_string(id.titleId) /
                              (std::to_string(id.userId) + ".json");
            auto state = load(path, Json{{"nextId", 1}, {"events", Json::array()}});
            wire::require(state.is_object() && state.at("events").is_array());
            auto next = state.at("nextId").get<uint64_t>();
            wire::require(next > 0 && next <= UINT64_MAX - count);
            Reply reply{0, {}, "events-recorded"};
            // Preserve the pre-archive server's retained records before any eviction.
            if (!state.contains("archive_schema"))
            {
                if (!state.at("events").empty())
                {
                    const auto previous = state.dump();
                    const auto digest = hex(crypto::sha256(std::span(
                        reinterpret_cast<const uint8_t *>(previous.data()), previous.size())));
                    save(path.parent_path() / std::to_string(id.userId) / "batches" /
                             ("legacy-" + digest + ".json"),
                         state);
                }
                state["archive_schema"] = 1;
            }
            const auto first = next;
            for (auto &event : incoming)
            {
                event["id"] = next;
                event["recorded"] = now();
                state["events"].push_back(event);
                wire::Writer result;
                result.u64(next++);
                reply.results.push_back(std::move(result.data));
            }
            // Retain full accepted batches independently of the bounded recent-event
            // window. A native frame is at most 1 MiB, so its hex/JSON batch fits the
            // existing 4 MiB publication bound. Content-addressed names avoid replacing
            // an orphaned batch with a different retry if state publication fails.
            const auto batch = Json{{"schema", 1},
                                    {"title", id.titleId},
                                    {"owner", id.userId},
                                    {"first_id", first},
                                    {"next_id", next},
                                    {"events", incoming}};
            const auto batchBytes = batch.dump();
            const auto digest = hex(crypto::sha256(std::span(
                reinterpret_cast<const uint8_t *>(batchBytes.data()), batchBytes.size())));
            save(path.parent_path() / std::to_string(id.userId) / "batches" /
                     (std::to_string(first) + "-" + std::to_string(next - 1) + "-" + digest +
                      ".json"),
                 batch);
            auto &recorded = state["events"];
            if (recorded.size() > 256)
                recorded.erase(recorded.begin(), recorded.end() - 256);
            // Bound bytes as well as count. Previously valid native menu telemetry
            // repeatedly failed once 256 payloads approached the 4 MiB file limit.
            size_t retainedBytes = 0;
            for (const auto &event : recorded)
                retainedBytes += event.dump().size() + 1;
            size_t removed = 0;
            while (retainedBytes > 4 * 1024 * 1024 - 4096 && removed < recorded.size())
                retainedBytes -= recorded[removed++].dump().size() + 1;
            if (removed)
                recorded.erase(recorded.begin(),
                               recorded.begin() + static_cast<Json::difference_type>(removed));
            state["nextId"] = next;
            save(path, state);
            return reply;
        }
    } // namespace

    std::optional<Reply> engagementServices(const std::filesystem::path &directory,
                                            const platform::LobbyIdentity &id,
                                            uint8_t service,
                                            uint8_t task,
                                            wire::Reader &p)
    {
        if (service == 104 && task == 6)
            return messages(directory, id, p);
        if (service == 104 && task == 7)
            return viewed(directory, id, p);
        if (service == 194 && task == 1)
            return enroll(directory, id, p);
        if (service == 195 && task == 1)
            return openLootDrop(directory, id, p);
        if (service == 67 && task == 5)
            return events(directory, id, p);
        return std::nullopt;
    }
} // namespace services
