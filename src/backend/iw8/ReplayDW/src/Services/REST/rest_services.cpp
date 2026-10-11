#include "host_os.h"
#include "rest_services.h"
#include "protobuf.h"
#include "achievement_services.h"
#include "social_services.h"
#include "regulation_services.h"
#include "objectstore_services.h"
#include "abtesting_services.h"
#include "identity_rest_services.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <set>
#include <map>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        std::string textField(const proto::Field &f, size_t capacity)
        {
            wire::require(f.type == 2 && f.bytes.size() < capacity);
            std::string value(reinterpret_cast<const char *>(f.bytes.data()), f.bytes.size());
            wire::require(value.find('\0') == std::string::npos);
            return value;
        }

        std::string routeName(const std::string &name)
        {
            wire::require(!name.empty() && name.size() < 64 && name != "." && name != "..");
            for (const auto c : name)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            return name;
        }

        std::string friendsContext(const std::string &uri)
        {
            // The native Friends reader requires the requested context and a terminal
            // page string. Decode only this bounded query field; never persist/log URI.
            std::string context = "iw8";
            bool seen = false;
            auto position = uri.find('?');
            if (position == std::string::npos)
                return context;
            ++position;
            while (position < uri.size())
            {
                const auto end = uri.find('&', position);
                const auto pair =
                    uri.substr(position, end == std::string::npos ? end : end - position);
                if (pair.starts_with("context="))
                {
                    wire::require(!seen);
                    seen = true;
                    context.clear();
                    const auto value = pair.substr(8);
                    auto hex = [](char c) -> int
                    {
                        if (c >= '0' && c <= '9')
                            return c - '0';
                        if (c >= 'a' && c <= 'f')
                            return c - 'a' + 10;
                        if (c >= 'A' && c <= 'F')
                            return c - 'A' + 10;
                        return -1;
                    };
                    for (size_t i = 0; i < value.size(); ++i)
                    {
                        unsigned char c = static_cast<unsigned char>(value[i]);
                        if (c == '%')
                        {
                            wire::require(i + 2 < value.size());
                            const auto high = hex(value[i + 1]), low = hex(value[i + 2]);
                            wire::require(high >= 0 && low >= 0);
                            c = static_cast<unsigned char>(high * 16 + low);
                            i += 2;
                        }
                        wire::require(c >= 32 && c < 127 && context.size() < 15);
                        context += static_cast<char>(c);
                    }
                    wire::require(!context.empty());
                }
                if (end == std::string::npos)
                    break;
                position = end + 1;
            }
            return context;
        }

        using Request = RESTRequest;

        std::string achievementContext(const Request &request, const platform::LobbyIdentity &id)
        {
            // Replay 142102A60 / 14216A100 share 142155570: the exact batch
            // path and context/client/titleID query accompany the JSON title.
            constexpr std::string_view prefix = "/v2/user-events/$batch/?";
            wire::require(request.uri.starts_with(prefix) &&
                          request.uri.find('#') == std::string::npos);
            std::map<std::string, std::string> fields;
            auto position = prefix.size();
            while (position < request.uri.size())
            {
                const auto end = request.uri.find('&', position);
                const auto pair =
                    request.uri.substr(position, end == std::string::npos ? end : end - position);
                const auto equal = pair.find('=');
                wire::require(equal != std::string::npos);
                const auto key = pair.substr(0, equal);
                wire::require(key == "context" || key == "client" || key == "titleID");
                std::string value;
                const auto encoded = pair.substr(equal + 1);
                for (size_t i = 0; i < encoded.size(); ++i)
                {
                    auto c = static_cast<unsigned char>(encoded[i]);
                    if (c == '%')
                    {
                        wire::require(i + 2 < encoded.size());
                        const auto digit = [](char x) -> unsigned
                        {
                            if (x >= '0' && x <= '9')
                                return x - '0';
                            if (x >= 'a' && x <= 'f')
                                return x - 'a' + 10;
                            if (x >= 'A' && x <= 'F')
                                return x - 'A' + 10;
                            wire::require(false);
                            return 0;
                        };
                        c = static_cast<unsigned char>((digit(encoded[i + 1]) << 4) |
                                                       digit(encoded[i + 2]));
                        i += 2;
                    }
                    wire::require(c >= 32 && c < 127 && value.size() < 63);
                    value.push_back(static_cast<char>(c));
                }
                wire::require(fields.emplace(key, value).second);
                if (end == std::string::npos)
                    break;
                wire::require(end + 1 < request.uri.size());
                position = end + 1;
            }
            wire::require(fields.size() == 3 &&
                          fields.at("titleID") == std::to_string(id.titleId) &&
                          (fields.at("client") == "replaylocal" || fields.at("client") == "iw8") &&
                          (fields.at("context") == std::to_string(id.titleId) ||
                           fields.at("context") == "iw8"));
            return fields.at("context");
        }

        void request(wire::Reader &p, Request &out)
        {
            out.version = p.u32();
            const auto message = p.blob(16384);
            out.hasBody = p.boolean();
            out.body = p.blob(256 * 1024);
            p.end();
            wire::require(out.hasBody || out.body.empty());
            proto::Reader reader{message};
            proto::Field f;
            bool parameters = false;
            unsigned headers = 0, accepts = 0;
            std::set<uint32_t> scalars;
            while (reader.next(f))
            {
                if (f.tag == 2 || f.tag == 10 || f.tag == 11 || f.tag == 101 || f.tag == 302)
                    wire::require(scalars.insert(f.tag).second);
                if (f.tag == 1)
                {
                    wire::require(f.type == 2 && !parameters);
                    parameters = true;
                    proto::Reader nested{f.bytes};
                    proto::Field n;
                    std::set<uint32_t> fields;
                    while (nested.next(n))
                    {
                        if (n.tag == 1 || n.tag == 2 || n.tag == 3 || n.tag == 100 ||
                            n.tag == 200 || n.tag == 300 || n.tag == 301)
                            wire::require(fields.insert(n.tag).second);
                        if (n.tag == 1 || n.tag == 2)
                            wire::require(n.type == 0 && n.value <= 1);
                        else if (n.tag == 3 || n.tag == 100)
                            wire::require(n.type == 0 && n.value <= UINT32_MAX);
                        else if (n.tag == 200)
                            wire::require(n.type == 2 && n.bytes.size() == 256);
                        else if (n.tag == 300)
                            out.resource = textField(n, 64);
                        else if (n.tag == 301)
                            out.operation = textField(n, 64);
                    }
                }
                else if (f.tag == 2 || f.tag == 10 || f.tag == 302)
                {
                    wire::require(f.type == 0 && f.value <= UINT32_MAX);
                    const auto value = static_cast<uint32_t>(f.value);
                    if (f.tag == 2)
                        out.accept = value;
                    else if (f.tag == 10)
                        out.method = value;
                    else
                        out.content = value;
                }
                else if (f.tag == 11)
                    out.uri = textField(f, 4097);
                else if (f.tag == 101)
                    out.service = textField(f, 64);
                else if (f.tag == 102)
                    wire::require(f.type == 0 && f.value <= 3 && ++accepts <= 3);
                else if (f.tag == 14)
                {
                    wire::require(f.type == 2 && ++headers <= 32);
                    proto::Reader header{f.bytes};
                    proto::Field h;
                    std::set<uint32_t> fields;
                    std::string key, value;
                    while (header.next(h))
                        if (h.tag == 1 || h.tag == 2)
                        {
                            wire::require(fields.insert(h.tag).second);
                            auto text = textField(h, h.tag == 1 ? 64 : 4096);
                            (h.tag == 1 ? key : value) = std::move(text);
                        }
                    wire::require(fields.contains(1) && fields.contains(2) && !key.empty());
                    for (auto &c : key)
                        if (c >= 'A' && c <= 'Z')
                            c = static_cast<char>(c + ('a' - 'A'));
                    if (key == "dw-objectstore-objectids" || key == "authorization" ||
                        key == "content-type")
                        wire::require(out.headers.emplace(key, value).second);
                }
            }
            wire::require(parameters && !out.uri.empty() && out.accept >= 1 && out.accept <= 3);
            // Paths never incorporate URI/query values, headers, retry tokens or bodies.
            out.service = routeName(out.service);
            out.resource = routeName(out.resource);
            out.operation = routeName(out.operation);
        }
    } // namespace

    Reply rest(const std::filesystem::path &directory,
               const platform::LobbyIdentity &id,
               wire::Reader &p)
    {
        Request r;
        try
        {
            request(p, r);
        }
        catch (const std::runtime_error &e)
        {
            if (std::string(e.what()) != "Malformed native task parameters")
                throw;
            // Domain names and scalar envelope fields are safe diagnostics. Never
            // log URLs, headers, request bodies, retry tokens or session material.
            auto label = [](const std::string &name)
            {
                try
                {
                    return routeName(name);
                }
                catch (const std::runtime_error &)
                {
                    return std::string("invalid");
                }
            };
            Reply invalid{106, {}, "rest-envelope-invalid"};
            invalid.detail =
                " rest_service=" + label(r.service) + " resource=" + label(r.resource) +
                " operation_name=" + label(r.operation) + " method=" + std::to_string(r.method) +
                " version=" + std::to_string(r.version) + " accept=" + std::to_string(r.accept) +
                " content=" + std::to_string(r.content) + " has_body=" + std::to_string(r.hasBody) +
                " parameter_offset=" + std::to_string(p.offset) +
                " parameter_bytes=" + std::to_string(p.data.size());
            return invalid;
        }
        Reply reply{0, {}, "rest-route-not-configured"};
        reply.detail = " rest_service=" + r.service + " resource=" + r.resource +
                       " operation_name=" + r.operation + " method=" + std::to_string(r.method);
        if (auto handled = identityRest(id, r))
        {
            handled->detail = reply.detail;
            return *handled;
        }
        if (auto handled = social(directory, id, r))
        {
            handled->detail = reply.detail;
            return *handled;
        }
        if (auto handled = regulations(directory, id, r))
        {
            handled->detail = reply.detail;
            return *handled;
        }
        if (auto handled = objectStoreRest(directory, id, r))
        {
            handled->detail += reply.detail;
            return *handled;
        }
        if (auto handled = abTestingRest(directory, id, r))
        {
            handled->detail = reply.detail;
            return *handled;
        }
        RESTResult result;
        result.version = r.version;
        result.body = Json{{"error",
                            {{"name", "LocalServiceUnavailable"},
                             {"msg", "This local service operation is not configured"}}}}
                          .dump();
        if (r.service == "ae.demonware.net" && r.resource == "user_events" &&
            r.operation == "report_user_events_batch")
        {
            try
            {
                wire::require(r.method == 0x504F5354 && r.accept == 1 && r.hasBody &&
                              r.content == 1 && !r.body.empty());
                auto domain =
                    achievementEventsRest(directory, id, achievementContext(r, id), r.body);
                if (domain.error)
                {
                    domain.detail += reply.detail;
                    return domain;
                }
                // Both original success readers (142158070 / 142169760)
                // require JSON allSucceeded. An empty 204 cannot complete them.
                result.status = 200;
                result.body = Json{{"allSucceeded", true}}.dump();
                // Keep the complete domain result, including cross-player
                // notifications. Adding the REST envelope must not discard
                // earned progression while acknowledging its accepted event.
                auto transportDetail = std::move(reply.detail);
                reply = std::move(domain);
                reply.detail += transportDetail;
            }
            catch (const std::runtime_error &e)
            {
                if (std::string(e.what()) != "Malformed native task parameters")
                    throw;
                reply.error = 106;
                reply.operation = "achievement-rest-domain-invalid";
                reply.detail += " content=" + std::to_string(r.content) +
                                " body_bytes=" + std::to_string(r.body.size());
                return reply;
            }
        }
        const auto path = directory / "rest" / std::to_string(id.titleId) / r.service / r.resource /
                          (r.operation + ".json");
        // Configured routes currently implement read-only GET resources. Mutations
        // need a real domain handler with ownership/lifetime semantics.
        if (r.method == 0x474554 && !r.hasBody && std::filesystem::exists(path))
        {
            wire::require(std::filesystem::file_size(path) <= 256 * 1024);
            std::ifstream stream(path);
            const auto json = Json::parse(stream);
            result.status = json.at("status").get<uint32_t>();
            wire::require(result.status >= 200 && result.status <= 599);
            result.body = json.at("body").dump();
            wire::require(result.body.size() <= 256 * 1024);
            reply.operation = "rest-configured-resource";
        }
        reply.rest = std::move(result);
        return reply;
    }

    wire::Bytes restResult(uint64_t transaction, const RESTResult &result)
    {
        // bdRESTResponseMessage::initFromBuffer consumes a typed version, blob of
        // protobuf response metadata, typed has-body and typed body blob. This is
        // one ordinary bdTaskResult, not a bdStructBufferTask response.
        wire::Bytes metadata, extra;
        proto::integer(metadata, 1, result.status);
        proto::f64(metadata, 203, 0.0);
        proto::integer(metadata, 302, 1);
        proto::integer(metadata, 400, 0); // JSON, nongateway response
        proto::bytes(extra, 1, {});
        proto::bytes(extra, 100, {});
        proto::integer(extra, 101, transaction);
        proto::integer(extra, 102, 0);
        proto::bytes(metadata, 1000, extra);
        wire::Writer w;
        w.u32(result.version);
        w.blob(metadata);
        w.boolean(!result.body.empty());
        w.blob(
            std::span(reinterpret_cast<const uint8_t *>(result.body.data()), result.body.size()));
        return w.data;
    }
} // namespace services
