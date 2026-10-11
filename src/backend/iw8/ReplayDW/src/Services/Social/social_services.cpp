#include "host_os.h"
#include "social_services.h"
#include "crypto.h"
#include "lobby.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>
#include <set>
#include <tuple>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        // Native subscriptions belong to the authenticated connection lifetime.
        // services dispatch/disconnect serializes access with the service-store lock.
        std::map<std::tuple<uint32_t, std::string, uint64_t>, std::vector<Json>> subscriptions;
        using PresenceScope = std::tuple<uint32_t, std::string, uint64_t>;
        std::set<PresenceScope> publishedOnline;
        std::map<PresenceScope, uint64_t> presenceRevisions;
        uint64_t nextPresenceRevision = 0;
        constexpr uint32_t get = 0x474554, put = 0x505554, post = 0x504F5354, del = 0x44454C45;

        std::string digest(const std::string &value)
        {
            const auto bytes =
                crypto::sha256({reinterpret_cast<const uint8_t *>(value.data()), value.size()});
            std::string out;
            for (const auto b : bytes)
            {
                out += "0123456789abcdef"[b >> 4];
                out += "0123456789abcdef"[b & 15];
            }
            return out;
        }

        std::string decode(const std::string &value, size_t capacity)
        {
            std::string out;
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
                    const auto a = hex(value[i + 1]), b = hex(value[i + 2]);
                    wire::require(a >= 0 && b >= 0);
                    c = static_cast<unsigned char>(a * 16 + b);
                    i += 2;
                }
                wire::require(c >= 32 && c < 127 && out.size() < capacity);
                out += static_cast<char>(c);
            }
            return out;
        }

        uint64_t decimal(const std::string &value, uint64_t maximum = UINT64_MAX)
        {
            wire::require(!value.empty() && value.size() <= 20);
            uint64_t out = 0;
            for (const char c : value)
            {
                wire::require(c >= '0' && c <= '9' && static_cast<unsigned>(c - '0') <= maximum &&
                              out <= (maximum - static_cast<unsigned>(c - '0')) / 10);
                out = out * 10 + static_cast<unsigned>(c - '0');
            }
            return out;
        }

        struct URI
        {
            std::vector<std::string> path;
            std::map<std::string, std::string> query;
        };

        URI uri(const std::string &value)
        {
            URI out;
            wire::require(value.starts_with('/') && value.find('#') == std::string::npos);
            const auto q = value.find('?');
            const auto path = value.substr(0, q);
            size_t position = 1;
            while (position < path.size())
            {
                const auto end = path.find('/', position);
                auto part = decode(
                    path.substr(position, end == std::string::npos ? end : end - position), 1024);
                wire::require(!part.empty() && part != "." && part != ".." &&
                              part.find('/') == std::string::npos &&
                              part.find('\\') == std::string::npos && out.path.size() < 16);
                out.path.push_back(std::move(part));
                if (end == std::string::npos)
                    break;
                position = end + 1;
            }
            if (q != std::string::npos)
            {
                position = q + 1;
                while (position < value.size())
                {
                    const auto end = value.find('&', position);
                    const auto pair =
                        value.substr(position, end == std::string::npos ? end : end - position);
                    const auto eq = pair.find('=');
                    wire::require(eq != std::string::npos);
                    const auto key = decode(pair.substr(0, eq), 64),
                               v = decode(pair.substr(eq + 1), 4096);
                    wire::require(!key.empty() && out.query.size() < 32 &&
                                  out.query.emplace(key, v).second);
                    if (end == std::string::npos)
                        break;
                    position = end + 1;
                }
            }
            return out;
        }

        std::string query(const URI &r, const std::string &key, const std::string &fallback = "")
        {
            const auto i = r.query.find(key);
            return i == r.query.end() ? fallback : i->second;
        }

        std::string accountType(const std::string &value)
        {
            wire::require(value == "uno" || value == "bnet");
            return value;
        }

        Json account(const Json &value, const platform::LobbyIdentity &id)
        {
            wire::require(value.is_object() && value.contains("userID") &&
                          value.at("userID").is_number_unsigned() &&
                          value.contains("accountType") && value.at("accountType").is_string());
            const auto uid = value.at("userID").get<uint64_t>();
            wire::require(uid > 0 && uid != UINT64_MAX);
            auto type = accountType(value.at("accountType").get<std::string>());
            if (uid == id.userId || platform::accountName(uid))
                type = "uno";
            return Json{{"userID", uid}, {"accountType", type}};
        }

        Json pathAccount(const std::string &value, const platform::LobbyIdentity &id)
        {
            const auto separator = value.find('-');
            wire::require(separator != std::string::npos);
            return account(Json{{"accountType", value.substr(0, separator)},
                                {"userID", decimal(value.substr(separator + 1))}},
                           id);
        }

        std::string key(const Json &a)
        {
            return a.at("accountType").get<std::string>() + "-" +
                   std::to_string(a.at("userID").get<uint64_t>());
        }

        Json load(const std::filesystem::path &path, Json fallback)
        {
            if (!std::filesystem::exists(path))
                return fallback;
            if (std::filesystem::file_size(path) > 4 * 1024 * 1024)
                throw std::runtime_error("Social store exceeds size limit");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Social store read failed");
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            auto data =
                Json::parse(in,
                            [&](int depth, Json::parse_event_t event, Json &value)
                            {
                                if (depth > 32)
                                    throw std::runtime_error("Social store nesting invalid");
                                if (event == Json::parse_event_t::object_start)
                                    keys.emplace_back();
                                else if (event == Json::parse_event_t::key)
                                    unique &= keys.back().insert(value.get<std::string>()).second;
                                else if (event == Json::parse_event_t::object_end)
                                    keys.pop_back();
                                return true;
                            });
            if (!unique)
                throw std::runtime_error("Social store duplicate keys");
            if (!data.is_object() || data.value("schema", 0) != 1)
                throw std::runtime_error("Social store schema invalid");
            return data;
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
                    throw std::runtime_error("Social store persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Social store publication failed");
        }

        Reply response(const RESTRequest &r,
                       std::string operation,
                       uint32_t status,
                       Json body = Json())
        {
            Reply out{0, {}, std::move(operation)};
            RESTResult result;
            result.version = r.version;
            result.status = status;
            result.body = body.is_null() ? "" : body.dump();
            wire::require(result.body.size() <= 256 * 1024);
            out.rest = std::move(result);
            return out;
        }

        Json page(const Json &rows,
                  size_t maximum,
                  const std::string &token,
                  const std::string &binding,
                  std::string &next)
        {
            const auto hash = digest(binding + rows.dump());
            size_t offset = 0;
            if (!token.empty())
            {
                const auto split = token.find(':');
                wire::require(split != std::string::npos && token.substr(0, split) == hash);
                offset = static_cast<size_t>(decimal(token.substr(split + 1), rows.size()));
            }
            const auto end = std::min(rows.size(), offset + maximum);
            Json result = Json::array();
            for (auto i = offset; i < end; ++i)
                result.push_back(rows[i]);
            next = end < rows.size() ? hash + ":" + std::to_string(end) : "";
            return result;
        }

        Json requestBody(const RESTRequest &r)
        {
            wire::require(r.hasBody && r.content == 1 && !r.body.empty());
            try
            {
                std::vector<std::set<std::string>> keys;
                bool unique = true;
                auto json =
                    Json::parse(r.body.begin(),
                                r.body.end(),
                                [&](int depth, Json::parse_event_t event, Json &value)
                                {
                                    wire::require(depth <= 32);
                                    if (event == Json::parse_event_t::object_start)
                                        keys.emplace_back();
                                    else if (event == Json::parse_event_t::key)
                                        unique &=
                                            keys.back().insert(value.get<std::string>()).second;
                                    else if (event == Json::parse_event_t::object_end)
                                        keys.pop_back();
                                    return true;
                                });
                wire::require(unique);
                return json;
            }
            catch (const Json::exception &)
            {
                // Malformed caller JSON is a parameter failure, not corrupted storage.
                wire::require(false);
                return Json();
            }
        }

        wire::Bytes demonata(const char *sender, const char *schema, const Json &body)
        {
            // Same-Replay bdDemonataPushMessage::initFromBuffer (0x1421515B0):
            // message 199, sender/schema/content type strings, then JSON blob.
            wire::Writer out;
            out.u32(199);
            out.text(sender);
            out.text(schema);
            out.text("application/json");
            const auto bytes = body.dump();
            out.blob({reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()});
            return out.data;
        }

        std::vector<Json> requested(const RESTRequest &r,
                                    const char *field,
                                    size_t maximum,
                                    const platform::LobbyIdentity &id,
                                    bool metadata)
        {
            const auto json = requestBody(r);
            wire::require(json.is_object() && json.contains(field));
            const auto &rows = json.at(field);
            wire::require(rows.is_array() && rows.size() <= maximum);
            std::set<std::string> unique;
            std::vector<Json> out;
            for (const auto &row : rows)
            {
                auto a = account(row, id);
                wire::require(unique.insert(key(a)).second);
                if (metadata)
                {
                    wire::require(row.contains("score") && row.at("score").is_number_unsigned());
                    a["score"] = row.at("score");
                    const auto meta = row.value("metadata", Json::object());
                    wire::require(meta.is_object() && meta.dump().size() <= 1024);
                    a["metadata"] = meta;
                }
                out.push_back(std::move(a));
            }
            return out;
        }

        Reply lists(const std::filesystem::path &root,
                    const platform::LobbyIdentity &id,
                    const RESTRequest &r,
                    const URI &route,
                    const std::string &context)
        {
            // Exact Replay routes: 0x142138030/8600/8CB0/9260. GET is v1 social-
            // service; mutations are v3 userlists. The native entity reader requires
            // userID/accountType/score and accepts optional metadata/name/presence.
            wire::require(route.path.size() >= 5 && route.path[1] == "user" &&
                          route.path[3] == "list");
            const auto owner = pathAccount(route.path[2], id);
            if (owner.at("userID") != id.userId)
                return {101, {}, "user-list-owner-denied"};
            const auto name = route.path[4];
            wire::require(!name.empty() && name.size() < 100);
            const auto path = root / "social" / std::to_string(id.titleId) / digest(context) /
                              std::to_string(id.userId) / "lists.json";
            auto data =
                load(path, Json{{"schema", 1}, {"context", context}, {"lists", Json::object()}});
            auto &all = data.at("lists");
            wire::require(all.is_object() && all.size() <= 64 && data.at("context") == context);
            bool changed = false;
            if (r.operation == "create_user_list")
            {
                wire::require(r.service == "userlists" && r.method == post && !r.hasBody &&
                              route.path.size() == 5 && route.path[0] == "v3");
                if (!all.contains(name))
                {
                    wire::require(all.size() < 64);
                    all[name] = Json::array();
                    changed = true;
                }
            }
            else if (r.operation == "add_or_update_users_in_user_list" ||
                     r.operation == "remove_users_from_user_list")
            {
                const bool add = r.operation == "add_or_update_users_in_user_list";
                wire::require(r.service == "userlists" && r.method == (add ? put : post) &&
                              route.path.size() == 6 && route.path[0] == "v3" &&
                              route.path[5] == (add ? "add" : "remove"));
                const auto rows = requested(r, "userList", 200, id, true);
                Json result = all.value(name, Json::array());
                wire::require(result.is_array() && result.size() <= 2048);
                for (const auto &row : rows)
                {
                    auto found = std::find_if(result.begin(),
                                              result.end(),
                                              [&](const auto &a)
                                              {
                                                  return key(a) == key(row);
                                              });
                    if (add)
                    {
                        if (found == result.end())
                            result.push_back(row);
                        else
                            *found = row;
                    }
                    else if (found != result.end())
                        result.erase(found);
                }
                if (add)
                {
                    const auto trim = decimal(query(route, "trimLength", "0"), 2048);
                    const auto order = query(route, "trimOrder", "ASCENDING");
                    wire::require(order == "ASCENDING" || order == "DESCENDING");
                    // Trim the requested end of the score ordering: ASC removes old
                    // low-score recent-player records; GET sort direction is separate.
                    std::sort(result.begin(),
                              result.end(),
                              [&](const auto &a, const auto &b)
                              {
                                  const auto as = a.at("score").template get<uint64_t>(),
                                             bs = b.at("score").template get<uint64_t>();
                                  return as == bs ? key(a) < key(b)
                                                  : (order == "ASCENDING" ? as < bs : as > bs);
                              });
                    if (trim && result.size() > trim)
                        result.erase(result.begin(),
                                     result.begin() +
                                         static_cast<Json::difference_type>(result.size() - trim));
                }
                wire::require(result.size() <= 2048 && (all.contains(name) || all.size() < 64));
                all[name] = std::move(result);
                changed = true;
            }
            else
            {
                wire::require(r.operation == "get_user_list" && r.service == "social-service" &&
                              r.method == get && !r.hasBody && route.path.size() == 5 &&
                              route.path[0] == "v1");
                auto rows = all.value(name, Json::array());
                wire::require(rows.is_array() && rows.size() <= 2048);
                const auto order = query(route, "sortOrder", "ASCENDING");
                wire::require(order == "ASCENDING" || order == "DESCENDING");
                std::sort(rows.begin(),
                          rows.end(),
                          [&](const auto &a, const auto &b)
                          {
                              const auto as = a.at("score").template get<uint64_t>(),
                                         bs = b.at("score").template get<uint64_t>();
                              return as == bs ? key(a) < key(b)
                                              : (order == "ASCENDING" ? as < bs : as > bs);
                          });
                auto maximum = decimal(query(route, "maxUsersInResponse", "200"), 200);
                if (!maximum)
                    maximum = 200;
                std::string next;
                auto selected = page(rows,
                                     static_cast<size_t>(maximum),
                                     query(route, "pageToken"),
                                     context + key(owner) + name + order + std::to_string(maximum),
                                     next);
                for (auto &row : selected)
                    if (const auto displayName =
                            platform::accountName(row.at("userID").get<uint64_t>()))
                        row["username"] = *displayName + "#0";
                return response(
                    r, "user-list-read", 200, Json{{"pageToken", next}, {"userList", selected}});
            }
            if (changed)
                save(path, data);
            return response(r, "user-list-persisted", 204);
        }

        Json presenceOf(const std::filesystem::path &,
                        const platform::LobbyIdentity &,
                        const Json &,
                        const std::string &);

        Reply usernameSearch(const RESTRequest &r, const URI &route)
        {
            // Replay 0x1420FCBB0 emits this route; 0x1420FD110 reads users[],
            // then 0x14210B940 requires provider/accountID/created/updated.
            wire::require(r.method == get && !r.hasBody &&
                          route.path == std::vector<std::string>{"v1.0", "users"} &&
                          query(route, "searchType") == "username" &&
                          !query(route, "client").empty());
            auto username = query(route, "username");
            wire::require(!username.empty() && username.size() <= 256);
            const bool prefix = username.back() == '%';
            if (prefix)
                username.pop_back();
            wire::require(!username.empty() && username.find('%') == std::string::npos);
            const auto provider = query(route, "provider");
            Json users = Json::array();
            if (provider.empty() || provider == "uno" || provider == "bnet")
                for (const auto &account : platform::findAccounts(username, prefix))
                {
                    Json accounts = Json::array();
                    for (const auto *type : {"uno", "bnet"})
                        accounts.push_back(Json{{"provider", type},
                                                {"accountID", account.userId},
                                                {"username", account.name + "#0"},
                                                {"created", "2026-10-05T00:00:00Z"},
                                                {"updated", "2026-10-05T00:00:00Z"}});
                    users.push_back(Json{{"accounts", accounts}});
                }
            return response(r, "cross-platform-username-search", 200, Json{{"users", users}});
        }

        Reply usernames(const platform::LobbyIdentity &id, const RESTRequest &r, const URI &route)
        {
            // Replay 0x1421479B0 emits GET /v1/users/ with four query fields.
            // Its real response vtable at 0x1424256B0 selects 0x142147CC0,
            // which reads at most 200 userID/accountType/username records.
            wire::require(r.method == get && !r.hasBody &&
                          route.path == std::vector<std::string>{"v1", "users"} &&
                          route.query.size() == 4 && route.query.contains("users") &&
                          !query(route, "client").empty() && query(route, "client").size() < 64 &&
                          decimal(query(route, "context"), UINT32_MAX) == id.titleId &&
                          decimal(query(route, "titleID"), UINT32_MAX) == id.titleId);
            const auto requestedUsers = query(route, "users");
            wire::require(!requestedUsers.empty() && requestedUsers.size() < 4096);
            Json users = Json::array();
            size_t position = 0, count = 0;
            while (position < requestedUsers.size())
            {
                const auto end = requestedUsers.find(',', position);
                const auto entry = requestedUsers.substr(
                    position, end == std::string::npos ? end : end - position);
                const auto separator = entry.find('-');
                wire::require(++count <= 200 && separator != std::string::npos && separator > 0 &&
                              separator < 10);
                const auto type = entry.substr(0, separator);
                for (const char c : type)
                    wire::require((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_');
                const auto user = decimal(entry.substr(separator + 1));
                wire::require(user > 0 && user != UINT64_MAX);
                // Both registered providers carry the same machine-owned universal ID.
                // Preserve the requested provider and order so native resolvers can
                // match the result. Unknown accounts/providers do not invent names.
                if (type == "uno" || type == "bnet")
                    if (const auto name = platform::accountName(user))
                    {
                        wire::require(!name->empty() && name->size() < 64);
                        users.push_back(Json{
                            {"userID", user}, {"accountType", type}, {"username", *name + "#0"}});
                    }
                if (end == std::string::npos)
                    break;
                position = end + 1;
                wire::require(position < requestedUsers.size());
            }
            return response(r, "cross-platform-usernames", 200, Json{{"users", users}});
        }

        void validateFriendStore(Json &data,
                                 const platform::LobbyIdentity &id,
                                 const std::string &context)
        {
            const auto valid = [](bool condition)
            {
                if (!condition)
                    throw std::runtime_error("Friend store layout invalid");
            };
            valid(data.is_object() && data.size() == 4 && data.contains("schema") &&
                  data.at("schema").is_number_integer() && data.at("schema") == 1 &&
                  data.contains("context") && data.at("context") == context &&
                  data.contains("pending") && data.at("pending").is_array() &&
                  data.contains("friends") && data.at("friends").is_array() &&
                  data.at("pending").size() <= 4096 && data.at("friends").size() <= 4096);
            const auto storedAccount = [&](Json &value)
            {
                valid(value.is_object() && value.size() == 2 && value.contains("userID") &&
                      value.at("userID").is_number_unsigned() &&
                      value.at("userID").get<uint64_t>() > 0 &&
                      value.at("userID").get<uint64_t>() != UINT64_MAX &&
                      value.contains("accountType") && value.at("accountType").is_string() &&
                      (value.at("accountType") == "uno" || value.at("accountType") == "bnet"));
                // Reconcile registered provider aliases on the private copy. Reads
                // never rewrite the store; an owned mutation publishes it atomically.
                value = account(value, id);
                return key(value);
            };
            using Pair = std::pair<std::string, std::string>;
            std::set<Pair> relationships, invitations;
            for (auto &row : data.at("friends"))
            {
                valid(row.is_object() && row.size() == 2 && row.contains("a") && row.contains("b"));
                auto a = storedAccount(row.at("a")), b = storedAccount(row.at("b"));
                valid(a != b);
                if (b < a)
                    std::swap(a, b);
                valid(relationships.emplace(a, b).second);
            }
            for (auto &row : data.at("pending"))
            {
                valid(row.is_object() && row.contains("from") && row.contains("to") &&
                      row.size() == (row.contains("from_name") ? 3 : 2));
                auto a = storedAccount(row.at("from")), b = storedAccount(row.at("to"));
                valid(a != b);
                if (row.contains("from_name"))
                {
                    valid(row.at("from_name").is_string());
                    const auto name = row.at("from_name").get<std::string>();
                    // The native username buffer is 64 bytes, including our #0 suffix.
                    valid(!name.empty() && name.size() < 62);
                    for (const unsigned char c : name)
                        valid(c >= 32 && c < 127);
                }
                if (b < a)
                    std::swap(a, b);
                valid(!relationships.contains({a, b}) && invitations.emplace(a, b).second);
            }
        }

        Reply friends(const std::filesystem::path &root,
                      const platform::LobbyIdentity &id,
                      const RESTRequest &r,
                      const URI &route,
                      const std::string &context)
        {
            wire::require(route.path.size() >= 3 && route.path[0] == "v1" &&
                          route.path[1] == "friends");
            const auto own = pathAccount(route.path[2], id);
            if (own.at("userID") != id.userId)
                return {101, {}, "friends-owner-denied"};
            const auto ownKey = key(own);
            const auto path =
                root / "social" / std::to_string(id.titleId) / digest(context) / "friends.json";
            auto data = load(path,
                             Json{{"schema", 1},
                                  {"context", context},
                                  {"pending", Json::array()},
                                  {"friends", Json::array()}});
            validateFriendStore(data, id, context);
            auto &pending = data.at("pending");
            auto &edges = data.at("friends");
            const auto linked = [&](const Json &a, const Json &b)
            {
                return std::any_of(
                    edges.begin(),
                    edges.end(),
                    [&](const auto &e)
                    {
                        return (key(e.at("a")) == key(a) && key(e.at("b")) == key(b)) ||
                               (key(e.at("a")) == key(b) && key(e.at("b")) == key(a));
                    });
            };
            std::vector<Delivery> notifications;
            const auto notify = [&](const Json &target,
                                    const char *schema,
                                    const char *actorField,
                                    bool name = false)
            {
                auto actor = own;
                if (name)
                    actor["username"] = id.name + "#0";
                notifications.push_back(
                    {target.at("userID").get<uint64_t>(),
                     demonata("friends", schema, Json{{"context", context}, {actorField, actor}})});
            };
            if (r.operation == "invite_friend")
            {
                wire::require(r.service == "friends" && r.method == post &&
                              route.path.size() == 4 && route.path[3] == "invitation");
                const auto users = requested(r, "users", 100, id, false);
                Json invited = Json::array(), friended = Json::array();
                for (const auto &target : users)
                {
                    wire::require(key(target) != ownKey);
                    auto incoming = std::find_if(pending.begin(),
                                                 pending.end(),
                                                 [&](const auto &e)
                                                 {
                                                     return key(e.at("from")) == key(target) &&
                                                            key(e.at("to")) == ownKey;
                                                 });
                    if (linked(own, target))
                    {
                        friended.push_back(target);
                        continue;
                    }
                    if (incoming != pending.end())
                    {
                        wire::require(edges.size() < 4096);
                        edges.push_back(Json{{"a", own}, {"b", target}});
                        pending.erase(std::remove_if(pending.begin(),
                                                     pending.end(),
                                                     [&](const auto &e)
                                                     {
                                                         return (key(e.at("from")) == ownKey &&
                                                                 key(e.at("to")) == key(target)) ||
                                                                (key(e.at("from")) == key(target) &&
                                                                 key(e.at("to")) == ownKey);
                                                     }),
                                      pending.end());
                        friended.push_back(target);
                        notify(target, "InviteAcceptedPushMessage", "acceptingUser");
                    }
                    else
                    {
                        const auto exists = std::any_of(pending.begin(),
                                                        pending.end(),
                                                        [&](const auto &e)
                                                        {
                                                            return key(e.at("from")) == ownKey &&
                                                                   key(e.at("to")) == key(target);
                                                        });
                        if (!exists)
                        {
                            wire::require(pending.size() < 4096);
                            pending.push_back(
                                Json{{"from", own}, {"to", target}, {"from_name", id.name}});
                            notify(target, "InviteCreatedPushMessage", "invitingUser", true);
                        }
                        invited.push_back(target);
                    }
                }
                auto reply = response(r,
                                      "friend-invitations-persisted",
                                      200,
                                      Json{{"context", context},
                                           {"pending", invited},
                                           {"friended", friended},
                                           {"errors", Json::array()}});
                validateFriendStore(data, id, context);
                save(path, data);
                reply.deliveries = std::move(notifications);
                return reply;
            }
            if (r.operation == "reject_friend_request")
            {
                wire::require(r.service == "friends" && r.method == del && !r.hasBody &&
                              route.path.size() == 4);
                const auto target = pathAccount(route.path[3], id);
                if (linked(own, target))
                    notify(target, "FriendshipRevokedPushMessage", "revokingUser");
                else if (std::any_of(pending.begin(),
                                     pending.end(),
                                     [&](const auto &e)
                                     {
                                         return key(e.at("to")) == ownKey &&
                                                key(e.at("from")) == key(target);
                                     }))
                    notify(target, "InviteRejectedPushMessage", "rejectingUser");
                pending.erase(std::remove_if(pending.begin(),
                                             pending.end(),
                                             [&](const auto &e)
                                             {
                                                 return (key(e.at("from")) == ownKey &&
                                                         key(e.at("to")) == key(target)) ||
                                                        (key(e.at("to")) == ownKey &&
                                                         key(e.at("from")) == key(target));
                                             }),
                              pending.end());
                edges.erase(std::remove_if(edges.begin(),
                                           edges.end(),
                                           [&](const auto &e)
                                           {
                                               return (key(e.at("a")) == ownKey &&
                                                       key(e.at("b")) == key(target)) ||
                                                      (key(e.at("b")) == ownKey &&
                                                       key(e.at("a")) == key(target));
                                           }),
                            edges.end());
                auto reply = response(r, "friend-relationship-removed", 204);
                validateFriendStore(data, id, context);
                save(path, data);
                reply.deliveries = std::move(notifications);
                return reply;
            }
            wire::require(r.service == "social-service" && r.method == get && !r.hasBody);
            Json rows = Json::array();
            if (r.operation == "get_friends")
            {
                wire::require(route.path.size() == 3);
                for (const auto &edge : edges)
                {
                    if (key(edge.at("a")) == ownKey)
                        rows.push_back(edge.at("b"));
                    else if (key(edge.at("b")) == ownKey)
                        rows.push_back(edge.at("a"));
                }
            }
            else
            {
                wire::require(r.operation == "get_pending_friend_requests" &&
                              route.path.size() == 4 && route.path[3] == "pending");
                const auto direction = query(route, "direction", "INCOMING");
                wire::require(direction == "INCOMING" || direction == "OUTGOING");
                for (const auto &invitation : pending)
                {
                    if (direction == "INCOMING" && key(invitation.at("to")) == ownKey)
                    {
                        auto a = invitation.at("from");
                        if (invitation.contains("from_name"))
                            a["username"] = invitation.at("from_name").get<std::string>() + "#0";
                        rows.push_back(a);
                    }
                    else if (direction == "OUTGOING" && key(invitation.at("from")) == ownKey)
                        rows.push_back(invitation.at("to"));
                }
            }
            std::sort(rows.begin(),
                      rows.end(),
                      [](const auto &a, const auto &b)
                      {
                          return key(a) < key(b);
                      });
            std::string next;
            auto selected = page(rows,
                                 100,
                                 query(route, "page"),
                                 context + ownKey + r.operation + query(route, "direction"),
                                 next);
            for (auto &row : selected)
                if (const auto name = platform::accountName(row.at("userID").get<uint64_t>()))
                {
                    row["username"] = *name + "#0";
                    // Exact Replay bdGetFriendsResponse reader 0x1421121D0 consumes
                    // optional presence using 0x1421404F0. Pending requests have their
                    // own reader and contain user details only.
                    if (r.operation == "get_friends")
                        row["presence"] = presenceOf(root, id, row, context).at("presence");
                }
            return response(r,
                            r.operation == "get_friends" ? "friends-list-read"
                                                         : "friend-invitations-read",
                            200,
                            Json{{"context", context}, {"page", next}, {"users", selected}});
        }

        std::vector<Json> queryUsers(const URI &route, const platform::LobbyIdentity &id)
        {
            const auto list = query(route, "users");
            wire::require(!list.empty());
            std::vector<Json> out;
            std::set<std::string> unique;
            size_t position = 0;
            while (position < list.size())
            {
                const auto end = list.find(',', position);
                const auto user = pathAccount(
                    list.substr(position, end == std::string::npos ? end : end - position), id);
                wire::require(out.size() < 100 && unique.insert(key(user)).second);
                out.push_back(user);
                if (end == std::string::npos)
                    break;
                position = end + 1;
                wire::require(position < list.size());
            }
            return out;
        }

        void validatePresence(const Json &value)
        {
            wire::require(value.is_object() && value.contains("online") &&
                          value.at("online").is_boolean());
            if (value.contains("platform"))
            {
                wire::require(value.at("platform").is_string());
                const auto platform = value.at("platform").get<std::string>();
                wire::require(platform.size() < 16 && platform.find('\0') == std::string::npos);
            }
            if (value.contains("updateTime"))
                wire::require(value.at("updateTime").is_number_unsigned());
            if (value.contains("data"))
                wire::require(value.at("data").is_object() &&
                              value.at("data").dump().size() <= 1024);
        }

        std::filesystem::path presencePath(const std::filesystem::path &root,
                                           uint32_t title,
                                           uint64_t user,
                                           const std::string &context)
        {
            return root / "presence" / std::to_string(title) / digest(context) /
                   (std::to_string(user) + ".json");
        }

        Json presenceOf(const std::filesystem::path &root,
                        const platform::LobbyIdentity &id,
                        const Json &user,
                        const std::string &context)
        {
            auto result = user;
            const auto uid = user.at("userID").get<uint64_t>();
            result["context"] = context;
            Json presence{{"online", false}};
            auto path = presencePath(root, id.titleId, uid, context);
            // The old backend stored only the iw8 context. Keep that publication
            // readable during migration, without leaking it into another context.
            if (context == "iw8" && !std::filesystem::exists(path))
                path = root / "presence" / std::to_string(id.titleId) /
                       (std::to_string(uid) + ".json");
            if (std::filesystem::exists(path))
            {
                wire::require(std::filesystem::file_size(path) <= 65536);
                std::ifstream in(path);
                if (!in)
                    throw std::runtime_error("Presence read failed");
                presence = Json::parse(in);
                validatePresence(presence);
            }
            // Published presence cannot leave a disconnected account marked online.
            presence["online"] = presence.at("online").get<bool>() &&
                                 publishedOnline.contains({id.titleId, context, uid}) &&
                                 lobby::online(id.titleId, uid);
            result["presence"] = presence;
            if (const auto name = platform::accountName(uid))
                result["username"] = *name + "#0";
            return result;
        }

        wire::Bytes presencePush(const Json &user)
        {
            // Exact bdLobbyService::handlePushMessage selects 199, then
            // bdDemonataPushMessage::initFromBuffer (0x1421515B0) reads three typed
            // strings and a blob. The registered sender is "presence" (0x14212F780).
            return demonata("presence", "UserPresenceUpdatedPushMessage", user);
        }

        uint64_t revisePresence(const PresenceScope &scope)
        {
            wire::require(nextPresenceRevision != UINT64_MAX &&
                          (presenceRevisions.contains(scope) || presenceRevisions.size() < 65536));
            return presenceRevisions[scope] = ++nextPresenceRevision;
        }

        std::vector<Delivery> presenceNotifications(uint32_t title,
                                                    const std::string &context,
                                                    uint64_t user,
                                                    uint64_t revision,
                                                    const Json &changed)
        {
            std::vector<Delivery> result;
            for (const auto &[scope, users] : subscriptions)
                if (std::get<0>(scope) == title && std::get<1>(scope) == context &&
                    std::any_of(users.begin(),
                                users.end(),
                                [&](const auto &a)
                                {
                                    return a.at("userID").template get<uint64_t>() == user &&
                                           a.at("accountType") == "uno";
                                }))
                {
                    Delivery notification{std::get<2>(scope), presencePush(changed)};
                    notification.presenceUser = user;
                    notification.presenceRevision = revision;
                    notification.presenceContext = context;
                    result.push_back(std::move(notification));
                }
            return result;
        }

        Reply presence(const std::filesystem::path &root,
                       const platform::LobbyIdentity &id,
                       const RESTRequest &r,
                       const URI &route,
                       const std::string &context)
        {
            if (r.resource == "UserPresence")
            {
                wire::require(r.service == "presence" && r.operation == "set_user_presence" &&
                              r.method == put && route.path.size() == 4 && route.path[0] == "v2" &&
                              route.path[1] == "users" && route.path[3] == "presence");
                const auto owner = pathAccount(route.path[2], id);
                if (owner.at("userID") != id.userId)
                    return {101, {}, "presence-owner-denied"};
                auto body = requestBody(r);
                validatePresence(body);
                body["updateTime"] =
                    static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
                const PresenceScope onlineKey{id.titleId, context, id.userId};
                wire::require(presenceRevisions.contains(onlineKey) ||
                              presenceRevisions.size() < 65536);
                const auto path = presencePath(root, id.titleId, id.userId, context);
                save(path, body);
                const auto revision = revisePresence(onlineKey);
                if (body.at("online").get<bool>())
                    publishedOnline.insert(onlineKey);
                else
                    publishedOnline.erase(onlineKey);
                auto reply = response(r, "presence-updated", 204);
                auto changed = presenceOf(root, id, owner, context);
                reply.deliveries =
                    presenceNotifications(id.titleId, context, id.userId, revision, changed);
                return reply;
            }
            if (r.operation == "get_users_presence")
            {
                wire::require(r.service == "social-service" && r.method == get && !r.hasBody &&
                              route.path == std::vector<std::string>{"v1", "users", "presence"});
                Json users = Json::array();
                for (const auto &user : queryUsers(route, id))
                    users.push_back(presenceOf(root, id, user, context));
                return response(r, "presence-users-read", 200, Json{{"users", users}});
            }
            wire::require(r.service == "presence" && route.path.size() == 5 &&
                          route.path[0] == "v2" && route.path[1] == "users" &&
                          route.path[3] == "subscriptions" && route.path[4] == "presence");
            const auto owner = pathAccount(route.path[2], id);
            if (owner.at("userID") != id.userId)
                return {101, {}, "presence-subscription-owner-denied"};
            const auto scope = std::make_tuple(id.titleId, context, id.userId);
            auto found = subscriptions.find(scope);
            auto result = found == subscriptions.end() ? std::vector<Json>{} : found->second;
            if (r.operation == "unsubscribe_from_users")
            {
                wire::require(r.method == del && !r.hasBody);
                const auto users = queryUsers(route, id);
                for (const auto &user : users)
                    result.erase(std::remove_if(result.begin(),
                                                result.end(),
                                                [&](const auto &a)
                                                {
                                                    return key(a) == key(user);
                                                }),
                                 result.end());
                if (result.empty())
                    subscriptions.erase(scope);
                else
                    subscriptions[scope] = std::move(result);
                // Replay binds the 8048-byte unsubscribe response at 14C3A3230.
                // Its vtable 1426A23A0 selects reader 142141090, which requires a
                // JSON errorUsers array, even when every removal succeeded. Missing
                // JSON makes ProcessUnsubscriptionsComplete (141058C50) retain the
                // pending queue and resend every frame. The complete response holds
                // up to 100 bdUserPresenceError records (account ID/type + error code).
                // All bounded, validated removals above succeed, including retries.
                return response(
                    r, "presence-users-unsubscribed", 200, Json{{"errorUsers", Json::array()}});
            }
            wire::require(r.operation == "subscribe_to_users" && r.method == post);
            const auto users = requested(r, "users", 100, id, false);
            Json snapshots = Json::array();
            for (const auto &user : users)
            {
                if (std::none_of(result.begin(),
                                 result.end(),
                                 [&](const auto &a)
                                 {
                                     return key(a) == key(user);
                                 }))
                    result.push_back(user);
                snapshots.push_back(presenceOf(root, id, user, context));
            }
            wire::require(result.size() <= 1000 &&
                          (found != subscriptions.end() || subscriptions.size() < 1024));
            subscriptions[scope] = std::move(result);
            // Exact Replay reader 0x142140B60 requires both arrays and a single
            // presence object per user; the newer SDK's titles array is incompatible.
            return response(r,
                            "presence-users-subscribed",
                            200,
                            Json{{"errorUsers", Json::array()}, {"users", snapshots}});
        }
    } // namespace

    std::vector<Delivery> socialDisconnected(const std::filesystem::path &root,
                                             uint32_t title,
                                             uint64_t user)
    {
        std::vector<Delivery> notifications;
        for (auto it = subscriptions.begin(); it != subscriptions.end();)
        {
            if (std::get<0>(it->first) == title && std::get<2>(it->first) == user)
                it = subscriptions.erase(it);
            else
                ++it;
        }
        for (auto it = publishedOnline.begin(); it != publishedOnline.end();)
        {
            if (std::get<0>(*it) != title || std::get<2>(*it) != user)
            {
                ++it;
                continue;
            }
            const auto scope = *it;
            it = publishedOnline.erase(it);
            platform::LobbyIdentity id{};
            id.titleId = title;
            auto changed = presenceOf(
                root, id, Json{{"userID", user}, {"accountType", "uno"}}, std::get<1>(scope));
            changed["presence"]["updateTime"] =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
            auto recipients = presenceNotifications(
                title, std::get<1>(scope), user, revisePresence(scope), changed);
            notifications.insert(notifications.end(),
                                 std::make_move_iterator(recipients.begin()),
                                 std::make_move_iterator(recipients.end()));
        }
        return notifications;
    }

    bool socialDeliveryValid(uint32_t title, const Delivery &delivery)
    {
        if (!delivery.presenceUser)
            return true;
        const auto found =
            presenceRevisions.find({title, delivery.presenceContext, delivery.presenceUser});
        return found != presenceRevisions.end() && found->second == delivery.presenceRevision;
    }

    std::optional<Reply> social(const std::filesystem::path &root,
                                const platform::LobbyIdentity &id,
                                const RESTRequest &r)
    {
        const bool isList = r.resource == "UserLists" &&
                            (r.service == "social-service" || r.service == "userlists") &&
                            (r.operation == "get_user_list" || r.operation == "create_user_list" ||
                             r.operation == "add_or_update_users_in_user_list" ||
                             r.operation == "remove_users_from_user_list");
        const bool isFriend =
            r.resource == "Friends" && (r.service == "social-service" || r.service == "friends") &&
            (r.operation == "get_friends" || r.operation == "get_pending_friend_requests" ||
             r.operation == "invite_friend" || r.operation == "reject_friend_request");
        const bool isPresence =
            (r.service == "presence" || r.service == "social-service") &&
            ((r.resource == "UserPresence" && r.operation == "set_user_presence") ||
             (r.resource == "UsersPresence" &&
              (r.operation == "get_users_presence" || r.operation == "subscribe_to_users" ||
               r.operation == "unsubscribe_from_users")));
        const bool isSearch = r.service == "umbrella" && r.resource == "UserResource" &&
                              r.operation == "usernamesearch";
        const bool isUsernames = r.service == "social-service" && r.resource == "Users" &&
                                 r.operation == "get_usernames";
        if (!isList && !isFriend && !isPresence && !isSearch && !isUsernames)
            return std::nullopt;
        const auto route = uri(r.uri);
        if (isSearch)
            return usernameSearch(r, route);
        if (isUsernames)
            return usernames(id, r, route);
        const auto context = query(route, "context", "iw8");
        wire::require(!context.empty() && context.size() < 16);
        if (const auto title = query(route, "titleID"); !title.empty())
            wire::require(decimal(title, UINT32_MAX) == id.titleId);
        if (isPresence)
            return presence(root, id, r, route, context);
        return isList ? lists(root, id, r, route, context) : friends(root, id, r, route, context);
    }
} // namespace services
