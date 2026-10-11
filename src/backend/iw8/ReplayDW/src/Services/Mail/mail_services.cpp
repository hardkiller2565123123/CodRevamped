#include "host_os.h"
#include "mail_services.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        uint32_t now()
        {
            return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        std::string context(const std::string &value)
        {
            wire::require(value.size() < 16 && value != "." && value != "..");
            for (const auto c : value)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            return value.empty() ? "_default" : value;
        }

        struct Account
        {
            uint64_t user = 0;
            std::string type;
        };

        Account account(wire::Reader &p, const platform::LobbyIdentity &id)
        {
            auto user = p.u64();
            const auto type = p.text(10);
            wire::require(type.empty() || type == "bnet" || type == "uno");
            if (!user || user == UINT64_MAX)
                user = id.userId;
            return {user, type.empty() ? "uno" : type};
        }

        bool owner(wire::Reader &p, const platform::LobbyIdentity &id)
        {
            bool allowed = true;
            if (p.more())
                allowed = account(p, id).user == id.userId;
            p.end();
            return allowed;
        }

        std::vector<uint64_t> ids(wire::Reader &p)
        {
            // Same-Replay bdMail get/deleteMail call writeArrayStart(type=10,
            // elementSize=8). Packed elements suppress their individual type tags.
            wire::require(p.offset + 10 <= p.data.size() && p.data[p.offset++] == 110 &&
                          p.data[p.offset++] == 8);
            const auto size = wire::at<uint32_t>(p.data, p.offset);
            p.offset += 4;
            const auto count = wire::at<uint32_t>(p.data, p.offset);
            p.offset += 4;
            wire::require(count <= 64 && size == count * 8 && size <= p.data.size() - p.offset);
            std::vector<uint64_t> out;
            std::set<uint64_t> unique;
            for (uint32_t i = 0; i < count; ++i)
            {
                const auto value = wire::at<uint64_t>(p.data, p.offset);
                p.offset += 8;
                wire::require(value && value != UINT64_MAX && unique.insert(value).second);
                out.push_back(value);
            }
            return out;
        }

        void save(const std::filesystem::path &path, const Json &data)
        {
            const auto bytes = data.dump();
            wire::require(bytes.size() <= 8 * 1024 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream out(pending, std::ios::binary | std::ios::trunc);
                if (!out.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("Mail store write failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Mail store publication failed");
        }

        Json load(const std::filesystem::path &path)
        {
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"next_id", 1}, {"messages", Json::array()}};
            if (std::filesystem::file_size(path) > 8 * 1024 * 1024)
                throw std::runtime_error("Mail store bounds invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Mail store read failed");
            auto data = Json::parse(in);
            try
            {
                wire::require(data.at("schema") == 1 && data.at("messages").is_array() &&
                              data.at("messages").size() <= 4096);
                wire::require(data.at("next_id").is_number_unsigned());
                std::set<uint64_t> unique;
                const auto next = data.at("next_id").get<uint64_t>();
                wire::require(next > 0);
                for (const auto &row : data.at("messages"))
                {
                    for (const auto *key : {"id",
                                            "recipient",
                                            "sender",
                                            "category",
                                            "created",
                                            "updated",
                                            "duration"})
                        wire::require(row.at(key).is_number_unsigned());
                    const auto mailId = row.at("id").get<uint64_t>();
                    wire::require(mailId && mailId < next && unique.insert(mailId).second);
                    for (const auto *key : {"recipient", "sender"})
                        wire::require(row.at(key).get<uint64_t>() > 0 &&
                                      row.at(key).get<uint64_t>() != UINT64_MAX);
                    const auto type = row.at("account").get<std::string>();
                    wire::require(type == "bnet" || type == "uno");
                    const auto name = row.at("name").get<std::string>();
                    wire::require(name.size() < 64 && name.find('\0') == std::string::npos);
                    (void)wire::base64(row.at("content").get<std::string>(), 1024);
                    wire::require(row.at("category").get<uint64_t>() <= UINT16_MAX);
                    for (const auto *key : {"created", "updated", "duration"})
                        wire::require(row.at(key).get<uint64_t>() <= UINT32_MAX);
                    for (const auto *key : {"read", "undelivered", "return_on_expiration"})
                        (void)row.at(key).get<bool>();
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Mail store schema invalid");
            }
            return data;
        }

        uint64_t nextId(Json &data)
        {
            const auto id = data.at("next_id").get<uint64_t>();
            wire::require(id > 0 && id < UINT64_MAX);
            data["next_id"] = id + 1;
            return id;
        }

        bool expire(Json &data, const platform::LobbyIdentity &id)
        {
            const auto stamp = now();
            auto kept = Json::array();
            bool changed = false;
            for (const auto &row : data.at("messages"))
            {
                const auto duration = row.at("duration").get<uint32_t>();
                if (!duration || uint64_t(row.at("created").get<uint32_t>()) + duration > stamp)
                {
                    kept.push_back(row);
                    continue;
                }
                changed = true;
                if (row.at("return_on_expiration").get<bool>())
                {
                    auto returned = row;
                    returned["id"] = nextId(data);
                    returned["recipient"] = row.at("sender");
                    returned["sender"] = row.at("recipient");
                    returned["name"] =
                        platform::accountName(row.at("recipient").get<uint64_t>())
                            .value_or(row.at("recipient") == id.userId ? id.name : "");
                    returned["account"] = "uno";
                    returned["read"] = false;
                    returned["undelivered"] = true;
                    returned["duration"] = 0;
                    returned["return_on_expiration"] = false;
                    returned["created"] = stamp;
                    returned["updated"] = stamp;
                    kept.push_back(std::move(returned));
                }
            }
            data["messages"] = std::move(kept);
            return changed;
        }

        wire::Bytes header(const Json &row)
        {
            // Complete same-Replay bdMailInfo::deserialize at 0x14214A3D0.
            wire::Writer out;
            out.u64(row.at("sender").get<uint64_t>());
            out.text(row.at("account").get<std::string>());
            out.text(row.at("name").get<std::string>());
            out.u64(row.at("id").get<uint64_t>());
            out.u32(row.at("created").get<uint32_t>());
            out.u32(static_cast<uint32_t>(
                wire::base64(row.at("content").get<std::string>(), 1024).size()));
            out.u16(row.at("category").get<uint16_t>());
            out.boolean(row.at("read").get<bool>());
            out.boolean(row.at("undelivered").get<bool>());
            out.u32(row.at("updated").get<uint32_t>());
            const auto duration = row.at("duration").get<uint32_t>();
            out.u32(duration);
            const auto end = uint64_t(row.at("created").get<uint32_t>()) + duration;
            const auto stamp = now();
            out.u32(duration && end > stamp ? static_cast<uint32_t>(end - stamp) : 0);
            return std::move(out.data);
        }

        Delivery notification(const std::string &name, const Json &row)
        {
            // Original Replay bdLobbyService::handlePushMessage 0x142122970:
            // event 18 invokes the registered event-handler slot +128 directly.
            // It consumes no context, account, message ID or body from the wire.
            wire::Writer push;
            push.u32(18);
            Delivery out{row.at("recipient").get<uint64_t>(), std::move(push.data), 250};
            out.mailContext = name;
            out.mailId = row.at("id").get<uint64_t>();
            return out;
        }
    } // namespace

    std::vector<Delivery> currentMailDeliveries(const std::filesystem::path &root,
                                                uint32_t title,
                                                uint64_t user)
    {
        const auto directory = root / "mail" / std::to_string(title);
        std::vector<Delivery> deliveries;
        if (!std::filesystem::exists(directory))
            return deliveries;
        platform::LobbyIdentity identity;
        identity.titleId = title;
        identity.userId = user;
        size_t contexts = 0;
        for (const auto &entry : std::filesystem::directory_iterator(directory))
        {
            if (!entry.is_directory())
                continue;
            wire::require(++contexts <= 128);
            try
            {
                const auto name = context(entry.path().filename().string());
                const auto path = entry.path() / "messages.json";
                auto data = load(path);
                if (expire(data, identity))
                    save(path, data);
                const Json *latest = nullptr;
                for (const auto &row : data.at("messages"))
                    if (row.at("recipient") == user && !row.at("read").get<bool>() &&
                        (!latest || row.at("id") > latest->at("id")))
                        latest = &row;
                if (latest)
                    deliveries.push_back(notification(name, *latest));
            }
            catch (const std::exception &)
            {
                // Domain tasks report the storage error. One invalid context
                // cannot notify or starve other valid mailboxes on this account.
            }
        }
        return deliveries;
    }

    bool mailDeliveryValid(const std::filesystem::path &root,
                           uint32_t title,
                           const Delivery &delivery)
    {
        if (!delivery.mailId)
            return true;
        const auto name = context(delivery.mailContext);
        const auto path = root / "mail" / std::to_string(title) / name / "messages.json";
        const auto data = load(path);
        return std::any_of(
            data.at("messages").begin(),
            data.at("messages").end(),
            [&](const Json &row)
            {
                const auto duration = row.at("duration").get<uint32_t>();
                return row.at("id") == delivery.mailId && row.at("recipient") == delivery.user &&
                       !row.at("read").get<bool>() &&
                       (!duration ||
                        uint64_t(row.at("created").get<uint32_t>()) + duration > now());
            });
    }

    std::optional<Reply> mailServices(const std::filesystem::path &root,
                                      const platform::LobbyIdentity &id,
                                      uint8_t service,
                                      uint8_t task,
                                      wire::Reader &p)
    {
        if (service != 29 || (task != 4 && task != 5 && task != 7 && task != 9 && task != 10))
            return std::nullopt;
        Account sender{id.userId, "uno"};
        if (task == 7)
            sender = account(p, id);
        const auto name = context(p.text(16));
        const auto path = root / "mail" / std::to_string(id.titleId) / name / "messages.json";
        if ((task == 7 || task == 9) && !std::filesystem::exists(path.parent_path()) &&
            std::filesystem::exists(path.parent_path().parent_path()))
        {
            size_t contexts = 0;
            for (const auto &entry :
                 std::filesystem::directory_iterator(path.parent_path().parent_path()))
                if (entry.is_directory())
                    wire::require(++contexts < 128);
        }
        auto data = load(path);
        const auto firstNewId = data.at("next_id").get<uint64_t>();
        bool changed = expire(data, id);
        Reply reply{0, {}, "mail"};
        if (task == 7 || task == 9)
        {
            const auto body = p.blob(1024);
            const auto category = p.u16();
            const auto count = p.u32();
            wire::require(count > 0 && count <= 64);
            std::vector<Account> recipients;
            std::set<uint64_t> seen;
            for (uint32_t i = 0; i < count; ++i)
            {
                const auto user = account(p, id);
                wire::require(seen.insert(user.user).second);
                recipients.push_back(user);
            }
            const auto duration = p.u32();
            const bool returnExpired = p.boolean();
            p.end();
            if (sender.user != id.userId)
                return Reply{101, {}, "mail-sender-denied"};
            if (data.at("messages").size() + recipients.size() > 4096)
                return Reply{102, {}, "mail-capacity-exceeded"};
            for (const auto &recipient : recipients)
            {
                data["messages"].push_back(Json{{"id", nextId(data)},
                                                {"recipient", recipient.user},
                                                {"sender", id.userId},
                                                {"account", sender.type},
                                                {"name", id.name},
                                                {"content", wire::base64Encode(body)},
                                                {"category", category},
                                                {"created", now()},
                                                {"updated", now()},
                                                {"duration", duration},
                                                {"return_on_expiration", returnExpired},
                                                {"read", false},
                                                {"undelivered", false}});
            }
            changed = true;
            reply.operation = "mail-sent";
        }
        else if (task == 10)
        {
            const auto start = p.u32(), maximum = p.u32();
            const bool newestFirst = p.boolean();
            wire::require(start <= 1000000 && maximum <= 1024);
            if (!owner(p, id))
                return Reply{101, {}, "mail-owner-denied"};
            std::vector<Json> inbox;
            for (const auto &row : data.at("messages"))
                if (row.at("recipient") == id.userId)
                    inbox.push_back(row);
            std::sort(inbox.begin(),
                      inbox.end(),
                      [newestFirst](const auto &a, const auto &b)
                      {
                          return newestFirst ? a.at("id") > b.at("id") : a.at("id") < b.at("id");
                      });
            const auto end = std::min(inbox.size(), static_cast<size_t>(start) + maximum);
            for (size_t i = start; i < end; ++i)
                reply.results.push_back(header(inbox[i]));
            reply.operation = "mail-headers-read";
        }
        else
        {
            const bool remove = task == 5 || p.boolean();
            const auto requested = ids(p);
            if (!owner(p, id))
                return Reply{101, {}, "mail-owner-denied"};
            auto &rows = data["messages"];
            for (const auto mailId : requested)
            {
                auto found = std::find_if(rows.begin(),
                                          rows.end(),
                                          [&](const auto &row)
                                          {
                                              return row.at("id") == mailId &&
                                                     row.at("recipient") == id.userId;
                                          });
                if (found == rows.end())
                    continue;
                if (task == 4)
                {
                    wire::Writer body;
                    body.u64(mailId);
                    body.blob(wire::base64(found->at("content").get<std::string>(), 1024));
                    reply.results.push_back(std::move(body.data));
                }
                if (remove)
                    rows.erase(found);
                else
                {
                    (*found)["read"] = true;
                    (*found)["updated"] = now();
                }
                changed = true;
            }
            reply.operation = task == 5 ? "mail-deleted" : "mail-bodies-read";
        }
        if (changed)
        {
            save(path, data);
            // The task reply is written before routing. Revalidation and per-lease
            // watermarks suppress a stale/deleted row or a concurrent idle scan.
            for (const auto &row : data.at("messages"))
                if (row.at("id").get<uint64_t>() >= firstNewId && !row.at("read").get<bool>())
                    reply.deliveries.push_back(notification(name, row));
        }
        return reply;
    }
} // namespace services
