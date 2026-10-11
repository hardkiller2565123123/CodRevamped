#include "host_os.h"
#include "objectstore_services.h"
#include "rest_services.h"
#include "protobuf.h"
#include "crypto.h"
#include "network.h"
#include "nlohmann/json.hpp"
#include <chrono>
#include <fstream>
#include <set>
#include <mutex>
#include <charconv>
#include <memory>
#include <map>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        std::filesystem::path contentDirectory;
        unsigned short contentPort = 0;
        std::mutex contentMutex;

        // bdObjectStore's struct-buffer transport carries an HTTP-shaped request.
        // Keep its complete common envelope separate from each domain operation.
        struct Request
        {
            std::string method, url, objectIds, body, contentType;
            std::optional<uint32_t> restVersion;
        };

        std::string text(const proto::Field &f, size_t capacity)
        {
            wire::require(f.type == 2 && f.bytes.size() < capacity);
            std::string value(reinterpret_cast<const char *>(f.bytes.data()), f.bytes.size());
            wire::require(value.find('\0') == std::string::npos);
            return value;
        }

        std::string filename(const Json &json, const char *key, size_t capacity)
        {
            const auto value = json.at(key).get<std::string>();
            wire::require(!value.empty() && value.size() < capacity && value != "." &&
                          value != "..");
            for (auto c : value)
                wire::require((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            return value;
        }

        std::string storageKey(std::string value)
        {
            // Stored object names use the bounded ASCII filename alphabet above.
            // Windows resolves its letter case aliases to the same destination.
            for (auto &c : value)
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c - 'A' + 'a');
            return value;
        }

        std::string contextFromURL(const std::string &url)
        {
            const auto query = url.find('?');
            if (query == std::string::npos)
                return "_default";
            std::string context;
            size_t start = query + 1;
            while (start < url.size())
            {
                auto end = url.find('&', start);
                if (end == std::string::npos)
                    end = url.size();
                const auto part = url.substr(start, end - start);
                if (part.starts_with("context="))
                {
                    wire::require(context.empty());
                    const auto value = part.substr(8);
                    for (size_t i = 0; i < value.size(); ++i)
                    {
                        if (value[i] == '%')
                        {
                            wire::require(i + 2 < value.size());
                            auto digit = [](char c) -> unsigned
                            {
                                if (c >= '0' && c <= '9')
                                    return c - '0';
                                if (c >= 'a' && c <= 'f')
                                    return c - 'a' + 10;
                                if (c >= 'A' && c <= 'F')
                                    return c - 'A' + 10;
                                wire::require(false);
                                return 0;
                            };
                            context.push_back(static_cast<char>((digit(value[i + 1]) << 4) |
                                                                digit(value[i + 2])));
                            i += 2;
                        }
                        else
                            context.push_back(value[i]);
                    }
                }
                start = end + 1;
            }
            if (context.empty())
                return "_default";
            return filename(Json{{"context", context}}, "context", 16);
        }

        void validateRestURL(const std::string &url, bool upload)
        {
            const auto query = url.find('?');
            wire::require(query != std::string::npos && url.find('#') == std::string::npos);
            const auto path = url.substr(0, query);
            wire::require(path == "/v2/core/users/objects/" ||
                          (upload && path == "/v2/users/objects/"));
            std::map<std::string, std::string> fields;
            size_t position = query + 1;
            while (position < url.size())
            {
                const auto end = url.find('&', position);
                const auto pair =
                    url.substr(position, end == std::string::npos ? end : end - position);
                const auto equal = pair.find('=');
                wire::require(equal != std::string::npos);
                const auto key = pair.substr(0, equal), value = pair.substr(equal + 1);
                wire::require((key == "client" || key == "context" || (upload && key == "extra")) &&
                              fields.emplace(key, value).second);
                if (end == std::string::npos)
                    break;
                wire::require(end + 1 < url.size());
                position = end + 1;
            }
            wire::require(fields.contains("client") && fields.contains("context") &&
                          !fields.at("client").empty() && fields.at("client").size() < 64 &&
                          (!fields.contains("extra") || fields.at("extra") == "validationToken"));
            for (const unsigned char c : fields.at("client"))
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            // The common decoder validates the decoded namespace against the
            // complete native 16-byte context layout, including empty context.
            (void)contextFromURL(url);
        }

        Request request(wire::Reader &p)
        {
            proto::Reader reader{p.structure(65535)};
            proto::Field f;
            Request out;
            unsigned headers = 0;
            bool method = false, url = false, body = false;
            while (reader.next(f))
            {
                if (f.tag == 1)
                {
                    wire::require(!method);
                    method = true;
                    out.method = text(f, 16);
                }
                else if (f.tag == 2)
                {
                    wire::require(!url);
                    url = true;
                    out.url = text(f, 1024);
                }
                else if (f.tag == 3)
                {
                    wire::require(!body);
                    body = true;
                    out.body = text(f, 64036);
                }
                else if (f.tag == 4)
                {
                    wire::require(f.type == 2 && ++headers <= 16);
                    proto::Reader header{f.bytes};
                    proto::Field h;
                    std::string key, value;
                    bool haveKey = false, haveValue = false;
                    while (header.next(h))
                    {
                        if (h.tag == 1)
                        {
                            wire::require(!haveKey);
                            haveKey = true;
                            key = text(h, 100);
                        }
                        else if (h.tag == 2)
                        {
                            wire::require(!haveValue);
                            haveValue = true;
                            value = text(h, 4096);
                        }
                    }
                    wire::require(haveKey && haveValue);
                    if (key == "DW-Objectstore-ObjectIDs")
                    {
                        wire::require(out.objectIds.empty());
                        out.objectIds = value;
                    }
                    else if (key == "Content-Type")
                    {
                        wire::require(out.contentType.empty());
                        out.contentType = value;
                    }
                }
            }
            wire::require(method && url && !out.url.empty());
            return out;
        }

        Json parameters(const std::string &data)
        {
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            auto callback = [&](int depth, Json::parse_event_t event, Json &value)
            {
                wire::require(depth <= 32);
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    unique = keys.back().insert(value.get<std::string>()).second && unique;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            auto out = Json::parse(data, callback, false);
            wire::require(!out.is_discarded() && unique);
            return out;
        }

        Reply response(const Json &body,
                       const char *operation,
                       uint32_t status = 200,
                       bool contentDownload = false,
                       std::optional<uint32_t> restVersion = std::nullopt)
        {
            const auto json = body.dump();
            if (restVersion)
            {
                wire::require(json.size() <= 256 * 1024);
                Reply reply{0, {}, operation};
                reply.rest = RESTResult{*restVersion, status, json};
                return reply;
            }
            wire::require(json.size() < 65535);
            Reply reply{0, {}, operation, true, {}};
            wire::Bytes header;
            proto::text(header, 1, "Content-Length");
            proto::text(header, 2, std::to_string(json.size()));
            proto::bytes(reply.structure, 1, header);
            // Replay's large-object reader requires Authorization in addition to the
            // JSON length header. Publisher content is public; the immutable URL is
            // the object identity, and carries no account/session credential.
            if (contentDownload)
            {
                wire::Bytes authorization;
                proto::text(authorization, 1, "Authorization");
                proto::text(authorization, 2, "public");
                proto::bytes(reply.structure, 1, authorization);
            }
            // bdStructBufferDeserializer consumes ascending tags. Keep all repeated
            // headers before status/body; a later field-1 header would be skipped.
            proto::integer(reply.structure, 2, status);
            proto::text(reply.structure, 3, json);
            return reply;
        }

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        wire::Bytes unbase64(const std::string &value, size_t maxBytes)
        {
            wire::require(value.size() % 4 == 0 && value.size() <= 4 * ((maxBytes + 2) / 3));
            wire::Bytes out;
            const auto digit = [](char c) -> unsigned
            {
                if (c >= 'A' && c <= 'Z')
                    return c - 'A';
                if (c >= 'a' && c <= 'z')
                    return c - 'a' + 26;
                if (c >= '0' && c <= '9')
                    return c - '0' + 52;
                if (c == '+')
                    return 62;
                if (c == '/')
                    return 63;
                wire::require(false);
                return 0;
            };
            for (size_t i = 0; i < value.size(); i += 4)
            {
                const unsigned a = digit(value[i]), b = digit(value[i + 1]);
                const bool pad2 = value[i + 2] == '=', pad3 = value[i + 3] == '=';
                wire::require((!pad2 || pad3) && (!(pad2 || pad3) || i + 4 == value.size()));
                const unsigned c = pad2 ? 0 : digit(value[i + 2]),
                               d = pad3 ? 0 : digit(value[i + 3]);
                wire::require((!pad2 || !(b & 15)) && (!pad3 || pad2 || !(c & 3)));
                out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
                if (!pad2)
                    out.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
                if (!pad3)
                    out.push_back(static_cast<uint8_t>((c << 6) | d));
            }
            wire::require(out.size() <= maxBytes);
            return out;
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

        std::string base64(std::span<const uint8_t> bytes)
        {
            constexpr char digits[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            for (size_t at = 0; at < bytes.size(); at += 3)
            {
                const unsigned a = bytes[at], b = at + 1 < bytes.size() ? bytes[at + 1] : 0,
                               c = at + 2 < bytes.size() ? bytes[at + 2] : 0;
                out.push_back(digits[a >> 2]);
                out.push_back(digits[((a & 3) << 4) | (b >> 4)]);
                out.push_back(at + 1 < bytes.size() ? digits[((b & 15) << 2) | (c >> 6)] : '=');
                out.push_back(at + 2 < bytes.size() ? digits[c & 63] : '=');
            }
            return out;
        }

        void publisherChecksum(Json &metadata)
        {
            // Actual Replay 0x14103C060 copies checksum into 29 bytes and passes it
            // to bdBase64::decode. SDK's general 33-byte string capacity alone is
            // insufficient. Normalize old local hex documents before returning them.
            const auto checksum = metadata.at("checksum").get<std::string>();
            wire::Bytes decoded;
            if (checksum.size() == 32 &&
                checksum.find_first_not_of("0123456789abcdef") == std::string::npos)
            {
                auto digit = [](char c) -> unsigned
                {
                    return c <= '9' ? c - '0' : c - 'a' + 10;
                };
                for (size_t i = 0; i < checksum.size(); i += 2)
                    decoded.push_back(
                        static_cast<uint8_t>((digit(checksum[i]) << 4) | digit(checksum[i + 1])));
            }
            else
                decoded = unbase64(checksum, 16);
            wire::require(decoded.size() == 16);
            metadata["checksum"] = base64(decoded);
        }

        void publish(const std::filesystem::path &path, const Json &object)
        {
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            const auto bytes = object.dump();
            wire::require(bytes.size() <= 6 * 1024 * 1024);
            const auto handle = CreateFileW(pending.c_str(),
                                            GENERIC_WRITE,
                                            0,
                                            nullptr,
                                            CREATE_ALWAYS,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Object persistence failed");
            {
                const std::unique_ptr<void, decltype(&CloseHandle)> file(handle, &CloseHandle);
                DWORD written = 0;
                if (!WriteFile(handle,
                               bytes.data(),
                               static_cast<DWORD>(bytes.size()),
                               &written,
                               nullptr) ||
                    written != bytes.size() || !FlushFileBuffers(handle))
                    throw std::runtime_error("Object persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Object publication failed");
        }

        bool publisherCacheMatches(const std::filesystem::path &path,
                                   size_t expectedSize,
                                   const std::string &expectedHash)
        {
            if (!std::filesystem::exists(path))
                return false;
            if (!std::filesystem::is_regular_file(path))
                throw std::runtime_error("Publisher cache destination is not a file");
            if (std::filesystem::file_size(path) != expectedSize)
                return false;
            std::ifstream input(path, std::ios::binary);
            wire::Bytes cached(expectedSize);
            if (!input.read(reinterpret_cast<char *>(cached.data()),
                            static_cast<std::streamsize>(cached.size())))
                throw std::runtime_error("Publisher cache verification read failed");
            return hex(crypto::sha256(cached)) == expectedHash;
        }

        void publishPublisherCache(const std::filesystem::path &path,
                                   std::span<const uint8_t> bytes)
        {
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            const auto handle = CreateFileW(pending.c_str(),
                                            GENERIC_WRITE,
                                            0,
                                            nullptr,
                                            CREATE_ALWAYS,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Publisher cache persistence failed");
            {
                const std::unique_ptr<void, decltype(&CloseHandle)> file(handle, &CloseHandle);
                DWORD written = 0;
                if (!WriteFile(handle,
                               bytes.data(),
                               static_cast<DWORD>(bytes.size()),
                               &written,
                               nullptr) ||
                    written != bytes.size() || !FlushFileBuffers(handle))
                    throw std::runtime_error("Publisher cache persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Publisher cache publication failed");
        }

        std::string owner(const platform::LobbyIdentity &id, const Json &object)
        {
            auto result = filename(object, "owner", 30);
            // Replay OnlineStorage uses platform 6 (uno) and a decimal universal ID.
            // This is distinct from authentication's first-party account_type=bnet.
            if (result == "me")
                result = "uno-" + std::to_string(id.userId);
            return result;
        }

        bool own(const platform::LobbyIdentity &id, const std::string &value)
        {
            const auto suffix = std::to_string(id.userId);
            return value == "uno-" + suffix || value == "bnet-" + suffix;
        }

        std::filesystem::path userPath(const std::filesystem::path &directory,
                                       const platform::LobbyIdentity &id,
                                       const std::string &context,
                                       const std::string &user,
                                       const std::string &name)
        {
            return directory / "objectstore" / "users" / std::to_string(id.titleId) / context /
                   user / (name + ".object.json");
        }

        void tags(const Json &value)
        {
            wire::require(value.is_array() && value.size() <= 150);
            for (const auto &tag : value)
            {
                wire::require(tag.is_object());
                for (const auto *key : {"key", "value"})
                {
                    wire::require(tag.contains(key));
                    if (std::string_view(key) == "key" && tag.at(key).is_null())
                        continue;
                    wire::require(tag.at(key).is_string());
                    const auto textValue = tag.at(key).get<std::string>();
                    wire::require(textValue.size() < 33 &&
                                  textValue.find('\0') == std::string::npos);
                }
            }
        }

        void validateMetadata(const Json &data,
                              const std::string &owner,
                              const std::string &name,
                              const std::string &context)
        {
            auto require = [](bool ok)
            {
                if (!ok)
                    throw std::runtime_error("Configured publisher metadata is invalid");
            };
            require(data.is_object() && data.at("owner") == owner && data.at("name") == name &&
                    data.at("context") == (context == "_default" ? "" : context));
            auto string = [&](const char *key, size_t capacity)
            {
                require(data.at(key).is_string());
                const auto value = data.at(key).get<std::string>();
                require(value.size() < capacity && value.find('\0') == std::string::npos);
                return value;
            };
            (void)string("checksum", 33);
            (void)string("objectVersion", 33);
            const auto acl = string("acl", 100);
            require(acl == "public" || acl == "private");
            for (const auto *key : {"expiresOn", "created", "modified"})
            {
                require(data.at(key).is_number_integer());
                (void)data.at(key).get<int64_t>();
            }
            require(data.at("contentLength").is_number_unsigned());
            require(data.contains("category"));
            if (!data.at("category").is_null())
                (void)string("category", 65);
            if (data.contains("contentURL"))
                (void)string("contentURL", 1024);
            if (data.contains("objectID"))
                require(data.at("objectID").is_number_unsigned());
            if (data.contains("extraData") && !data.at("extraData").is_null())
            {
                (void)string("extraData", 2733);
                require(data.at("extraDataSize").is_number_unsigned() &&
                        data.at("extraDataSize").get<uint32_t>() <= 2048);
            }
            if (data.contains("hasSummary"))
                require(data.at("hasSummary").is_boolean());
            if (data.contains("summaryChecksum") && !data.at("summaryChecksum").is_null())
                (void)string("summaryChecksum", 33);
            if (data.contains("summaryContentLength") && !data.at("summaryContentLength").is_null())
                require(data.at("summaryContentLength").is_number_unsigned());
        }

        std::optional<uint64_t> account(const std::string &owner)
        {
            const auto start = owner.starts_with("uno-") ? 4 : owner.starts_with("bnet-") ? 5 : 0;
            if (!start)
                return std::nullopt;
            const auto suffix = owner.substr(start);
            uint64_t user = 0;
            const auto parsed = std::from_chars(suffix.data(), suffix.data() + suffix.size(), user);
            if (parsed.ec != std::errc{} || parsed.ptr != suffix.data() + suffix.size() || !user ||
                std::to_string(user) != suffix)
                return std::nullopt;
            return user;
        }

        std::filesystem::path uploadJournal(const std::filesystem::path &directory,
                                            uint32_t title,
                                            uint64_t user)
        {
            return directory / "objectstore" / "users" / std::to_string(title) / "_transactions" /
                   (std::to_string(user) + ".json");
        }

        void validateUpload(const Json &entry, uint64_t user)
        {
            wire::require(entry.is_object() && entry.size() == 4);
            const auto owner = filename(entry, "owner", 30);
            const auto context = filename(entry, "context", 16);
            const auto name = filename(entry, "name", 65);
            wire::require(account(owner) == user);
            const auto &stored = entry.at("document");
            wire::require(stored.is_object() && stored.dump().size() < 96000 &&
                          stored.contains("metadata") && stored.contains("content") &&
                          stored.at("content").is_string());
            const auto &metadata = stored.at("metadata");
            validateMetadata(metadata, owner, name, context);
            const auto bytes = unbase64(stored.at("content").get<std::string>(), 48000);
            wire::require(metadata.at("contentLength") == bytes.size() &&
                          metadata.at("checksum") == hex(crypto::md5(bytes)));
            if (metadata.contains("extraData") && !metadata.at("extraData").is_null())
                wire::require(metadata.at("extraDataSize") ==
                              unbase64(metadata.at("extraData").get<std::string>(), 2048).size());
            if (stored.contains("tags"))
                tags(stored.at("tags"));
        }

        void applyUploads(const std::filesystem::path &directory,
                          const platform::LobbyIdentity &id,
                          Json journal)
        {
            // Preflight every namespace and complete metadata/content/tag layout
            // before publishing any snapshot. No journal-supplied filesystem path.
            wire::require(journal.is_object() && journal.size() == 5 && journal.at("schema") == 1 &&
                          journal.at("title") == id.titleId && journal.at("user") == id.userId &&
                          journal.at("writes").is_array());
            const auto &phase = journal.at("phase");
            const auto &writes = journal.at("writes");
            wire::require((phase == "applied" && writes.empty()) ||
                          (phase == "prepared" && !writes.empty() && writes.size() <= 50));
            if (phase == "applied")
                return;
            std::set<std::string> destinations;
            for (const auto &entry : writes)
            {
                validateUpload(entry, id.userId);
                wire::require(destinations
                                  .insert(storageKey(userPath(directory,
                                                              id,
                                                              entry.at("context"),
                                                              entry.at("owner"),
                                                              entry.at("name"))
                                                         .generic_string()))
                                  .second);
            }
            for (const auto &entry : writes)
                publish(
                    userPath(
                        directory, id, entry.at("context"), entry.at("owner"), entry.at("name")),
                    entry.at("document"));
            journal["phase"] = "applied";
            journal["writes"] = Json::array();
            publish(uploadJournal(directory, id.titleId, id.userId), journal);
        }

        void recoverUploads(const std::filesystem::path &directory,
                            const platform::LobbyIdentity &identity,
                            uint64_t user)
        {
            const auto path = uploadJournal(directory, identity.titleId, user);
            if (!std::filesystem::exists(path))
                return;
            try
            {
                wire::require(std::filesystem::file_size(path) <= 6 * 1024 * 1024);
                std::ifstream stream(path, std::ios::binary);
                if (!stream)
                    throw std::runtime_error("Object upload journal read failed");
                std::string bytes((std::istreambuf_iterator<char>(stream)),
                                  std::istreambuf_iterator<char>());
                stream.close();
                auto id = identity;
                id.userId = user;
                applyUploads(directory, id, parameters(bytes));
            }
            catch (const std::exception &)
            {
                // A malformed durable record is storage failure, not invalid
                // native request parameters. Never expose its opaque payload.
                throw std::runtime_error("Object upload recovery failed");
            }
        }

        Json publisherCacheReferences(const std::string &hash)
        {
            const auto path = contentDirectory / (hash + ".references.json");
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"hash", hash}, {"references", Json::array()}};
            try
            {
                wire::require(std::filesystem::is_regular_file(path) &&
                              std::filesystem::file_size(path) <= 256 * 1024);
                std::ifstream input(path, std::ios::binary);
                if (!input)
                    throw std::runtime_error("Publisher cache reference read failed");
                const std::string bytes((std::istreambuf_iterator<char>(input)),
                                        std::istreambuf_iterator<char>());
                auto record = parameters(bytes);
                wire::require(record.is_object() && record.size() == 3 &&
                              record.at("schema") == 1 && record.at("hash") == hash &&
                              record.at("references").is_array() &&
                              record.at("references").size() <= 1024);
                std::set<std::string> identities;
                for (const auto &reference : record.at("references"))
                {
                    wire::require(reference.is_object() && reference.size() == 4 &&
                                  reference.at("title").is_number_unsigned() &&
                                  reference.at("title").get<uint64_t>() <= UINT32_MAX);
                    const auto context = filename(reference, "context", 16);
                    const auto owner = filename(reference, "owner", 30);
                    const auto name = filename(reference, "name", 65);
                    const auto identity = std::to_string(reference.at("title").get<uint32_t>()) +
                                          "/" + context + "/" + owner + "/" + name;
                    wire::require(identities.insert(storageKey(identity)).second);
                }
                return record;
            }
            catch (const std::exception &)
            {
                throw std::runtime_error("Publisher cache reference integrity failure");
            }
        }

        void registerPublisherCache(const std::string &hash,
                                    uint32_t title,
                                    const std::string &context,
                                    const std::string &owner,
                                    const std::string &name)
        {
            auto record = publisherCacheReferences(hash);
            const Json reference{
                {"title", title}, {"context", context}, {"owner", owner}, {"name", name}};
            auto &references = record.at("references");
            if (std::find(references.begin(), references.end(), reference) != references.end())
                return;
            if (references.size() == 1024)
                throw std::runtime_error("Publisher cache reference capacity exceeded");
            references.push_back(reference);
            publish(contentDirectory / (hash + ".references.json"), record);
        }

        bool publisherCachePublished(const std::string &hash,
                                     size_t size,
                                     const std::string &checksum)
        {
            const auto record = publisherCacheReferences(hash);
            for (const auto &reference : record.at("references"))
            {
                const auto title = reference.at("title").get<uint32_t>();
                const auto context = reference.at("context").get<std::string>();
                const auto owner = reference.at("owner").get<std::string>();
                const auto name = reference.at("name").get<std::string>();
                const auto path = contentDirectory.parent_path() / "publisher" /
                                  std::to_string(title) / context / owner /
                                  (name + ".metadata.json");
                if (!std::filesystem::exists(path))
                    continue;
                wire::require(std::filesystem::file_size(path) <= 16384);
                std::ifstream input(path);
                if (!input)
                    throw std::runtime_error("Publisher metadata read failed");
                auto metadata = Json::parse(input);
                validateMetadata(metadata, owner, name, context);
                publisherChecksum(metadata);
                const auto expires = metadata.at("expiresOn").get<int64_t>();
                if (metadata.at("acl") == "public" &&
                    (expires <= 0 || static_cast<uint64_t>(expires) > now()) &&
                    metadata.at("contentLength") == size && metadata.at("checksum") == checksum)
                    return true;
            }
            return false;
        }

        std::optional<Json> publisherDocument(const std::filesystem::path &directory,
                                              uint32_t title,
                                              const std::string &context,
                                              const std::string &owner,
                                              const std::string &name,
                                              bool requireContent)
        {
            const auto parent =
                directory / "objectstore" / "publisher" / std::to_string(title) / context / owner;
            const auto path = parent / (name + ".metadata.json");
            if (!std::filesystem::exists(path))
                return std::nullopt;
            wire::require(std::filesystem::file_size(path) <= 16384);
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Publisher metadata read failed");
            auto metadata = Json::parse(stream);
            validateMetadata(metadata, owner, name, context);
            publisherChecksum(metadata);
            // Replay's cached-content consumer requires a real nonzero objectID; the
            // SDK accepts its omission but leaves the ID zero, so no download starts.
            // Stable identity is separate from payload checksum/version and scoped to
            // the authenticated title, publisher, context and object name.
            if (!metadata.contains("objectID"))
            {
                const auto identity =
                    std::to_string(title) + "/" + context + "/" + owner + "/" + name;
                const auto digest = crypto::sha256(
                    std::span(reinterpret_cast<const uint8_t *>(identity.data()), identity.size()));
                uint64_t object = 0;
                for (size_t i = 0; i < 8; ++i)
                    object = (object << 8) | digest[i];
                metadata["objectID"] = object ? object : 1;
            }
            wire::require(metadata.at("objectID").get<uint64_t>() != 0);
            if (metadata.at("acl") != "public")
                return std::nullopt;
            const auto expires = metadata.at("expiresOn").get<int64_t>();
            if (expires > 0 && static_cast<uint64_t>(expires) <= now())
                return std::nullopt;
            const auto content = parent / (name + ".content.bin");
            if (!std::filesystem::exists(content))
                return requireContent ? std::nullopt : std::optional<Json>(metadata);
            const auto size = std::filesystem::file_size(content);
            wire::require(size <= 64 * 1024 * 1024 && metadata.at("contentLength") == size);
            std::ifstream input(content, std::ios::binary);
            wire::Bytes bytes(static_cast<size_t>(size));
            if (!input.read(reinterpret_cast<char *>(bytes.data()),
                            static_cast<std::streamsize>(size)))
                throw std::runtime_error("Publisher content read failed");
            wire::require(metadata.at("checksum") == base64(crypto::md5(bytes)));
            const auto hash = hex(crypto::sha256(bytes));
            const auto cached = contentDirectory / (hash + ".bin");
            {
                std::lock_guard lock(contentMutex);
                // A successful metadata reply promises the verified immutable
                // content URL. Repair interrupted/truncated/corrupt cache bytes
                // from the checksum-verified publication before making that promise.
                if (!publisherCacheMatches(cached, bytes.size(), hash))
                {
                    publishPublisherCache(cached, bytes);
                }
                registerPublisherCache(hash, title, context, owner, name);
            }
            metadata["contentURL"] =
                network::httpOrigin(contentPort) + "/objectstore/content/" + hash;
            return metadata;
        }

        Reply publisherSingle(const std::filesystem::path &directory,
                              const platform::LobbyIdentity &id,
                              const Request &r)
        {
            // Same-Replay 0x14212A4F0 starts 193/8, then native HTTP streaming uses
            // the contentURL parsed by the large-object response reader 0x142147650.
            wire::require(r.method == "GET" && r.objectIds.empty() && r.body.empty());
            const auto path = r.url.substr(0, r.url.find('?'));
            const auto start = path.find("/publishers/");
            wire::require(start != std::string::npos);
            const auto split = path.find("/objects/", start + 12);
            wire::require(split != std::string::npos);
            const auto user =
                filename(Json{{"owner", path.substr(start + 12, split - start - 12)}}, "owner", 30);
            auto leaf = path.substr(split + 9);
            if (leaf.ends_with("/metadata/"))
                leaf.resize(leaf.size() - 10);
            else if (!leaf.empty() && leaf.back() == '/')
                leaf.pop_back();
            const auto name = filename(Json{{"name", leaf}}, "name", 65);
            const auto context = contextFromURL(r.url);
            const auto document =
                publisherDocument(directory, id.titleId, context, user, name, true);
            if (!document)
            {
                auto missing = response(Json{{"error", "Error:ClientError:NotFound"}},
                                        "publisher-object-not-found",
                                        404,
                                        true);
                missing.detail = " context=" + context + " owner=" + user + " name=" + name;
                return missing;
            }
            auto result = response(*document, "publisher-object-download", 200, true);
            result.detail = " context=" + context + " owner=" + user + " name=" + name;
            return result;
        }

        Reply publisher(const std::filesystem::path &directory,
                        const platform::LobbyIdentity &id,
                        const Request &r)
        {
            wire::require(r.method == "GET" && !r.objectIds.empty() && r.body.empty());
            const auto context = contextFromURL(r.url);
            const auto ids = parameters(r.objectIds);
            wire::require(ids.is_array() && !ids.empty() && ids.size() <= 50);
            Json body = {{"objects", Json::array()}, {"errors", Json::array()}};
            unsigned index = 0;
            std::string requestedNames, requestedOwners;
            for (const auto &object : ids)
            {
                const auto owner = filename(object, "owner", 30),
                           name = filename(object, "name", 65);
                requestedNames += (requestedNames.empty() ? "" : ",") + name;
                requestedOwners += (requestedOwners.empty() ? "" : ",") + owner;
                const auto metadata =
                    publisherDocument(directory, id.titleId, context, owner, name, false);
                if (metadata)
                {
                    body["objects"].push_back({{"requestIndex", index}, {"metadata", *metadata}});
                }
                else
                {
                    // The native reader maps this Replay string to the per-object
                    // not-found state. Each original request index must be represented.
                    body["errors"].push_back({{"requestIndex", index},
                                              {"name", name},
                                              {"owner", owner},
                                              {"error", "Error:ClientError:NotFound"}});
                }
                ++index;
            }
            auto reply = response(body, "publisher-object-metadata", 200, true);
            reply.detail = " requested_objects=" + std::to_string(ids.size()) +
                           " available=" + std::to_string(body["objects"].size()) +
                           " missing=" + std::to_string(body["errors"].size()) +
                           " context=" + context + " names=" + requestedNames +
                           " owners=" + requestedOwners;
            return reply;
        }

        Reply upload(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     const Request &r)
        {
            wire::require(r.method == "PUT" && !r.body.empty() &&
                          r.contentType == "application/json");
            const auto context = contextFromURL(r.url);
            const auto input = parameters(r.body);
            wire::require(input.is_object() && input.contains("objects") &&
                          input.at("objects").is_array());
            const auto &objects = input.at("objects");
            wire::require(!objects.empty() && objects.size() <= 50);
            recoverUploads(directory, id, id.userId);
            // Validate the entire window before publishing any member. Each durable
            // object contains content and metadata together, so a reader never sees a
            // partially published content/metadata pair after a restart.
            std::vector<std::pair<std::filesystem::path, Json>> writes;
            std::set<std::string> names;
            Json body = {{"objects", Json::array()},
                         {"errors", Json::array()},
                         {"validationTokens", Json::array()}};
            for (const auto &object : objects)
            {
                wire::require(object.is_object() && object.contains("metadata") &&
                              object.at("metadata").is_object() && object.contains("content") &&
                              object.at("content").is_string());
                const auto &supplied = object.at("metadata");
                const auto user = owner(id, supplied), name = filename(supplied, "name", 65);
                if (!own(id, user))
                {
                    Reply denied{101, {}, "user-object-owner-denied"};
                    // Identity-only diagnostics; never record profile content/tokens.
                    denied.detail = " supplied_owner=" + user +
                                    " authenticated_universal_id=" + std::to_string(id.userId);
                    return denied;
                }
                wire::require(names.insert(storageKey(name)).second);
                const auto content = object.at("content").get<std::string>();
                const auto bytes = unbase64(content, 48000);
                const auto path = userPath(directory, id, context, user, name);
                auto metadata = supplied;
                const auto recorded = static_cast<int64_t>(now());
                int64_t created = recorded;
                if (std::filesystem::exists(path))
                {
                    wire::require(std::filesystem::file_size(path) < 96000);
                    std::ifstream stream(path);
                    const auto prior = Json::parse(stream);
                    created = prior.at("metadata").at("created").get<int64_t>();
                }
                metadata["owner"] = user;
                metadata["context"] = context == "_default" ? "" : context;
                metadata["contentLength"] = static_cast<uint64_t>(bytes.size());
                metadata["checksum"] = hex(crypto::md5(bytes));
                metadata["objectVersion"] = hex(crypto::random(16));
                metadata["created"] = created;
                metadata["modified"] = recorded;
                if (!metadata.contains("expiresOn"))
                    metadata["expiresOn"] = int64_t{0};
                if (!metadata.contains("acl"))
                    metadata["acl"] = "private";
                if (!metadata.contains("category"))
                    metadata["category"] = nullptr;
                if (metadata.contains("extraData") && !metadata.at("extraData").is_null())
                {
                    wire::require(metadata.at("extraData").is_string());
                    metadata["extraDataSize"] = static_cast<uint32_t>(
                        unbase64(metadata.at("extraData").get<std::string>(), 2048).size());
                }
                validateMetadata(metadata, user, name, context);
                Json stored = {{"metadata", metadata}, {"content", content}};
                Json result = {{"metadata", metadata}};
                if (object.contains("tags"))
                {
                    tags(object.at("tags"));
                    stored["tags"] = object.at("tags");
                    result["tags"] = object.at("tags");
                }
                writes.emplace_back(path, std::move(stored));
                body["objects"].push_back(std::move(result));
            }
            // Both native transports consume the same complete JSON contract.
            // Preflight the reply before publishing any member of the window.
            auto reply = response(body, "user-objects-uploaded", 200, false, r.restVersion);
            Json journal = {{"schema", 1},
                            {"title", id.titleId},
                            {"user", id.userId},
                            {"phase", "prepared"},
                            {"writes", Json::array()}};
            for (const auto &[path, object] : writes)
            {
                (void)path;
                const auto &metadata = object.at("metadata");
                journal["writes"].push_back({{"context", context},
                                             {"owner", metadata.at("owner")},
                                             {"name", metadata.at("name")},
                                             {"document", object}});
            }
            // A prepared intent can roll forward after a process or disk failure.
            // Return native success only after the complete window is durable.
            for (const auto &entry : journal["writes"])
                validateUpload(entry, id.userId);
            publish(uploadJournal(directory, id.titleId, id.userId), journal);
            applyUploads(directory, id, std::move(journal));
            reply.detail = " stored_objects=" + std::to_string(writes.size());
            return reply;
        }

        Reply download(const std::filesystem::path &directory,
                       const platform::LobbyIdentity &id,
                       const Request &r)
        {
            wire::require(r.method == "GET" && !r.objectIds.empty() && r.body.empty());
            const auto context = contextFromURL(r.url);
            const auto ids = parameters(r.objectIds);
            wire::require(ids.is_array() && !ids.empty() && ids.size() <= 50);

            struct Selected
            {
                std::string user, name, cachedVersion, cachedChecksum;
            };

            std::vector<Selected> selected;
            for (const auto &object : ids)
            {
                wire::require(object.is_object());
                for (const auto &entry : object.items())
                    wire::require(entry.key() == "owner" || entry.key() == "name" ||
                                  entry.key() == "objectVersion" || entry.key() == "checksum");
                const auto cacheField = [&](const char *key)
                {
                    if (!object.contains(key))
                        return std::string{};
                    wire::require(object.at(key).is_string());
                    const auto value = object.at(key).get<std::string>();
                    wire::require(value.size() < 33 && value.find('\0') == std::string::npos);
                    return value;
                };
                selected.push_back({owner(id, object),
                                    filename(object, "name", 65),
                                    cacheField("objectVersion"),
                                    cacheField("checksum")});
            }
            Json body = {{"objects", Json::array()}, {"errors", Json::array()}};
            unsigned index = 0;
            for (const auto &object : selected)
            {
                const auto &user = object.user, &name = object.name;
                if (const auto userId = account(user))
                    recoverUploads(directory, id, *userId);
                const auto path = userPath(directory, id, context, user, name);
                std::string error = "Error:ClientError:NotFound";
                bool found = false;
                if (std::filesystem::exists(path))
                {
                    wire::require(std::filesystem::file_size(path) < 96000);
                    std::ifstream stream(path);
                    auto stored = Json::parse(stream);
                    const auto &metadata = stored.at("metadata");
                    validateMetadata(metadata, user, name, context);
                    const auto expires = metadata.at("expiresOn").get<int64_t>();
                    if (!own(id, user) && metadata.at("acl") != "public")
                        error = "Error:ClientError:Forbidden:ACLError";
                    else if (expires <= 0 || static_cast<uint64_t>(expires) > now())
                    {
                        const auto content = stored.at("content").get<std::string>();
                        const auto bytes = unbase64(content, 48000);
                        wire::require(metadata.at("contentLength") == bytes.size() &&
                                      metadata.at("checksum") == hex(crypto::md5(bytes)));
                        // 142145630 emits optional cached version/checksum, not a
                        // request for an old object revision. The real error reader
                        // accepts this exact NotModified string and retains cache.
                        const bool cached =
                            (!object.cachedVersion.empty() || !object.cachedChecksum.empty()) &&
                            (object.cachedVersion.empty() ||
                             metadata.at("objectVersion") == object.cachedVersion) &&
                            (object.cachedChecksum.empty() ||
                             metadata.at("checksum") == object.cachedChecksum);
                        if (cached)
                            error = "Error:ClientError:NotModified";
                        else
                        {
                            stored["requestIndex"] = index;
                            body["objects"].push_back(std::move(stored));
                            found = true;
                        }
                    }
                }
                if (!found)
                    body["errors"].push_back({{"requestIndex", index},
                                              {"owner", user},
                                              {"name", name},
                                              {"error", error}});
                ++index;
            }
            auto reply = response(body, "user-objects-read", 200, false, r.restVersion);
            reply.detail = " requested_objects=" + std::to_string(ids.size()) +
                           " available=" + std::to_string(body["objects"].size()) +
                           " missing=" + std::to_string(body["errors"].size());
            return reply;
        }
    } // namespace

    void initializePublisherContent(const std::filesystem::path &directory, unsigned short port)
    {
        contentDirectory = std::filesystem::absolute(directory) / "objectstore" / "content";
        contentPort = port;
    }

    std::optional<wire::Bytes> publisherContent(const std::string &route)
    {
        constexpr std::string_view prefix = "/objectstore/content/";
        if (!route.starts_with(prefix))
            return std::nullopt;
        const auto hash = route.substr(prefix.size());
        if (hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != std::string::npos)
            return std::nullopt;
        std::lock_guard lock(contentMutex);
        const auto path = contentDirectory / (hash + ".bin");
        if (!std::filesystem::exists(path))
            return std::nullopt;
        const auto size = std::filesystem::file_size(path);
        wire::require(size <= 64 * 1024 * 1024);
        std::ifstream input(path, std::ios::binary);
        wire::Bytes out(static_cast<size_t>(size));
        if (!input.read(reinterpret_cast<char *>(out.data()),
                        static_cast<std::streamsize>(out.size())) ||
            hex(crypto::sha256(out)) != hash)
            throw std::runtime_error("Publisher content cache integrity failure");
        // Cache presence is not publication authority. Retained URLs require a
        // matching public, unexpired publication of these exact bytes.
        if (!publisherCachePublished(hash, out.size(), base64(crypto::md5(out))))
            return std::nullopt;
        return out;
    }

    Reply publisherMetadata(const std::filesystem::path &directory,
                            const platform::LobbyIdentity &id,
                            wire::Reader &p)
    {
        return publisher(directory, id, request(p));
    }

    std::optional<Reply> objectStoreRest(const std::filesystem::path &directory,
                                         const platform::LobbyIdentity &id,
                                         const RESTRequest &r)
    {
        // Same-Replay 1421443E0 strips https:// from these environment hosts;
        // 142145DE0/142146E60 bind the vector GET/PUT resource and operation.
        if ((r.service != "objectstore.dev.demonware.net" &&
             r.service != "objectstore.cert.demonware.net" &&
             r.service != "objectstore.prod.demonware.net") ||
            r.resource != "ObjectsVectorizedResourceUsers" ||
            (r.operation != "get_objects" && r.operation != "put_objects"))
            return std::nullopt;
        const bool writing = r.operation == "put_objects";
        wire::require(r.accept == 1 && r.method == (writing ? 0x505554u : 0x474554u));
        validateRestURL(r.uri, writing);
        Request common;
        common.method = writing ? "PUT" : "GET";
        common.url = r.uri;
        common.restVersion = r.version;
        if (writing)
        {
            wire::require(r.hasBody && r.content == 1 && !r.body.empty() &&
                          !r.headers.contains("dw-objectstore-objectids"));
            common.body.assign(reinterpret_cast<const char *>(r.body.data()), r.body.size());
            wire::require(common.body.find('\0') == std::string::npos);
            if (r.headers.contains("content-type"))
                wire::require(r.headers.at("content-type") == "application/json");
            common.contentType = "application/json";
            return upload(directory, id, common);
        }
        wire::require(!r.hasBody && r.headers.contains("dw-objectstore-objectids"));
        common.objectIds = r.headers.at("dw-objectstore-objectids");
        return download(directory, id, common);
    }

    Reply objectStore(const std::filesystem::path &directory,
                      const platform::LobbyIdentity &id,
                      uint8_t task,
                      wire::Reader &p)
    {
        if (task != 6 && task != 7 && task != 8 && task != 16)
            return {108, {}, "objectstore-task-unimplemented"};
        const auto r = request(p);
        const auto path = r.url.substr(0, r.url.find('?'));
        // Same-Replay startStructTask: 6=user vector download, 7=user vector upload,
        // 16=publisher metadata. Do not inherit another build's labels or IDs.
        if (task == 7)
        {
            wire::require(path.find("/users/objects/") != std::string::npos);
            return upload(directory, id, r);
        }
        if (task == 8)
            return publisherSingle(directory, id, r);
        if (task == 16)
        {
            wire::require(path.find("/publishers/objects/") != std::string::npos);
            return publisher(directory, id, r);
        }
        wire::require(path.find("/users/objects/") != std::string::npos);
        return download(directory, id, r);
    }
} // namespace services
