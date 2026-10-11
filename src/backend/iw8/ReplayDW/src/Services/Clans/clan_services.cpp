#include "host_os.h"
#include "clan_services.h"
#include "protobuf.h"
#include "lobby.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        using Fields = std::vector<proto::Field>;

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        Fields fields(std::span<const uint8_t> bytes)
        {
            proto::Reader reader{bytes};
            proto::Field f;
            Fields out;
            while (reader.next(f))
            {
                wire::require(out.size() < 256);
                out.push_back(f);
            }
            return out;
        }

        const proto::Field *optional(const Fields &f, unsigned tag)
        {
            const proto::Field *out = nullptr;
            for (const auto &field : f)
                if (field.tag == tag)
                {
                    wire::require(!out);
                    out = &field;
                }
            return out;
        }

        const proto::Field &required(const Fields &f, unsigned tag)
        {
            const auto *out = optional(f, tag);
            wire::require(out != nullptr);
            return *out;
        }

        uint64_t number(const proto::Field &f, uint64_t maximum = UINT64_MAX)
        {
            wire::require(f.type == 0 && f.value <= maximum);
            return f.value;
        }

        std::string text(const proto::Field &f, size_t capacity)
        {
            wire::require(f.type == 2 && f.bytes.size() < capacity);
            std::string out(reinterpret_cast<const char *>(f.bytes.data()), f.bytes.size());
            wire::require(out.find('\0') == std::string::npos);
            for (unsigned char c : out)
                wire::require(c >= 32 && c != 127);
            return out;
        }

        Fields nested(const proto::Field &f)
        {
            wire::require(f.type == 2);
            return fields(f.bytes);
        }

        Json groupId(const Fields &f)
        {
            // bdClansGroupIdentifier: 1 kind, 2 ID, 3 root kind, 4 root ID.
            // Same-Replay group requests and GroupInfo reader at 0x142105C90.
            Json out{{"kind", number(required(f, 1), UINT16_MAX)},
                     {"id", number(required(f, 2))},
                     {"root_kind", uint64_t{0}},
                     {"root_id", uint64_t{0}}};
            if (const auto *v = optional(f, 3))
                out["root_kind"] = number(*v, UINT16_MAX);
            if (const auto *v = optional(f, 4))
                out["root_id"] = number(*v);
            return out;
        }

        uint64_t user(const Fields &f)
        {
            const auto id = number(required(f, 1));
            const auto type = text(required(f, 2), 10);
            // Replay constructs bdUserAccountID from XUID without an account type.
            // The empty type is the same numeric identity alias, not a new owner.
            wire::require(id > 0 && id != UINT64_MAX &&
                          (type.empty() || type == "uno" || type == "bnet"));
            return id;
        }

        wire::Bytes account(uint64_t userId, const std::string &name = "", bool details = false)
        {
            wire::Bytes out;
            proto::integer(out, 1, userId);
            proto::text(out, 2, "uno");
            // bdStructUserDetails requires field 3 even when the display name is
            // unknown. Empty string is explicitly supported by its native reader.
            if (details)
                proto::text(out, 3, name.empty() ? "" : name + "#0");
            return out;
        }

        wire::Bytes identifier(const Json &group)
        {
            wire::Bytes out;
            proto::integer(out, 1, group.at("kind").get<uint64_t>());
            proto::integer(out, 2, group.at("id").get<uint64_t>());
            proto::integer(out, 3, group.at("root_kind").get<uint64_t>());
            proto::integer(out, 4, group.at("root_id").get<uint64_t>());
            return out;
        }

        wire::Bytes info(const Json &group)
        {
            // Full target reader 0x142105C90, including count/time fields absent
            // from the client write request. Field 11 is onlineMemberCount.
            auto out = identifier(group);
            proto::text(out, 5, group.at("name").get<std::string>());
            proto::bytes(out, 6, account(group.at("owner").get<uint64_t>()));
            proto::integer(out, 7, group.at("privacy").get<uint64_t>());
            proto::integer(out, 8, group.at("members").size());
            proto::integer(out, 9, group.at("proposals").size());
            proto::integer(out, 10, group.at("created").get<uint64_t>());
            const auto title = group.at("title").get<uint32_t>();
            unsigned online = 0;
            for (const auto &row : group.at("members"))
                if (lobby::online(title, row.at("user").get<uint64_t>()))
                    ++online;
            proto::integer(out, 11, online);
            proto::text(out, 12, group.at("tag").get<std::string>());
            return out;
        }

        unsigned role(const Json &group, uint64_t owner);

        uint64_t storedNumber(const Json &value, uint64_t maximum = UINT64_MAX)
        {
            wire::require(value.is_number_unsigned() && value.get<uint64_t>() <= maximum);
            return value.get<uint64_t>();
        }

        uint64_t storedUser(const Json &value)
        {
            const auto uid = storedNumber(value);
            wire::require(uid && uid != UINT64_MAX);
            return uid;
        }

        uint64_t userKey(const std::string &key)
        {
            uint64_t uid = 0;
            wire::require(!key.empty() && key.size() <= 20);
            for (const auto c : key)
            {
                wire::require(c >= '0' && c <= '9' &&
                              uid <= (UINT64_MAX - static_cast<unsigned>(c - '0')) / 10);
                uid = uid * 10 + static_cast<unsigned>(c - '0');
            }
            wire::require(uid && uid != UINT64_MAX && std::to_string(uid) == key);
            return uid;
        }

        void storedText(const Json &value, size_t capacity, bool nonempty = false)
        {
            wire::require(value.is_string());
            const auto text = value.get<std::string>();
            wire::require(text.size() < capacity && (!nonempty || !text.empty()) &&
                          text.find('\0') == std::string::npos);
            for (unsigned char c : text)
                wire::require(c >= 32 && c != 127);
        }

        void validateStore(const Json &data)
        {
            wire::require(data.at("schema") == 1 && data.at("groups").is_array() &&
                          data.at("groups").size() <= 1024 && data.at("active").is_object());
            std::set<uint64_t> ids, owners;
            std::set<std::string> tags;
            for (const auto &group : data.at("groups"))
            {
                const auto id = storedUser(group.at("id")), owner = storedUser(group.at("owner"));
                wire::require(id > 0 && owner > 0 && ids.insert(id).second &&
                              owners.insert(owner).second);
                wire::require(storedNumber(group.at("kind"), UINT16_MAX) == 1);
                (void)storedNumber(group.at("root_kind"), UINT16_MAX);
                (void)storedNumber(group.at("root_id"));
                (void)storedNumber(group.at("title"), UINT32_MAX);
                (void)storedNumber(group.at("privacy"), UINT16_MAX);
                (void)storedNumber(group.at("created"));
                for (const auto *name : {"name", "tag"})
                {
                    storedText(group.at(name), 255, true);
                }
                wire::require(tags.insert(group.at("tag").get<std::string>()).second &&
                              group.at("members").is_array() && !group.at("members").empty() &&
                              group.at("members").size() <= 1024);
                std::set<uint64_t> members;
                for (const auto &row : group.at("members"))
                {
                    const auto uid = storedUser(row.at("user"));
                    const auto memberRole = storedNumber(row.at("role"), 3);
                    wire::require(uid > 0 && uid != UINT64_MAX && members.insert(uid).second &&
                                  memberRole >= 1 && memberRole <= 3 &&
                                  (memberRole == 3) == (uid == owner));
                    storedText(row.at("name"), 64);
                    if (row.contains("replacement"))
                    {
                        const auto &replacement = row.at("replacement");
                        wire::require(replacement.is_object());
                        wire::require(storedUser(replacement.at("group")) != id &&
                                      storedNumber(replacement.at("role"), 3) > 0);
                    }
                }
                wire::require(members.contains(owner) && group.at("proposals").is_array() &&
                              group.at("proposals").size() <= 1024);
                std::set<uint64_t> targets;
                for (const auto &proposal : group.at("proposals"))
                {
                    const auto target = storedUser(proposal.at("target")),
                               proposer = storedUser(proposal.at("proposer"));
                    wire::require(target > 0 && target != UINT64_MAX && proposer > 0 &&
                                  targets.insert(target).second && !members.contains(target));
                    const auto proposedRole = storedNumber(proposal.at("role"), 2);
                    wire::require(proposedRole >= 1);
                    (void)wire::base64(proposal.at("attachment").get<std::string>(), 1024);
                    (void)storedNumber(proposal.at("updated"));
                    storedText(proposal.at("target_name"), 64);
                    storedText(proposal.at("proposer_name"), 64);
                }
                wire::require(group.at("files").is_object() && group.at("files").size() <= 128);
                for (auto file = group.at("files").begin(); file != group.at("files").end(); ++file)
                {
                    storedText(Json(file.key()), 255, true);
                    (void)wire::base64(file.value().at("content").get<std::string>(), 128 * 1024);
                    (void)storedNumber(file.value().at("collision"), UINT32_MAX);
                    (void)storedNumber(file.value().at("created"));
                    (void)storedNumber(file.value().at("updated"));
                }
                if (group.contains("cooldowns"))
                {
                    const auto &cooldowns = group.at("cooldowns");
                    wire::require(cooldowns.is_object() && cooldowns.size() <= 4096);
                    for (auto row = cooldowns.begin(); row != cooldowns.end(); ++row)
                    {
                        (void)userKey(row.key());
                        const auto seconds = storedNumber(row.value().at("seconds"), UINT32_MAX);
                        wire::require(seconds > 0);
                        (void)storedNumber(row.value().at("recorded"), UINT64_MAX - seconds);
                    }
                }
            }
            for (auto active = data.at("active").begin(); active != data.at("active").end();
                 ++active)
            {
                const auto uid = userKey(active.key());
                (void)storedUser(active.value());
                bool found = false;
                for (const auto &group : data.at("groups"))
                    if (group.at("id") == active.value() && role(group, uid))
                        found = true;
                wire::require(found);
            }
        }

        Json load(const std::filesystem::path &path)
        {
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"groups", Json::array()}, {"active", Json::object()}};
            if (std::filesystem::file_size(path) > 8 * 1024 * 1024)
                throw std::runtime_error("Clan store bounds invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Clan store read failed");
            auto data = Json::parse(in);
            try
            {
                validateStore(data);
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Clan store schema invalid");
            }
            return data;
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
                    throw std::runtime_error("Clan store persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Clan store publication failed");
        }

        Json *find(Json &data, const Json &selected)
        {
            for (auto &group : data.at("groups"))
                if (group.at("kind") == selected.at("kind") &&
                    group.at("id") == selected.at("id") &&
                    group.at("root_kind") == selected.at("root_kind") &&
                    group.at("root_id") == selected.at("root_id"))
                    return &group;
            return nullptr;
        }

        unsigned role(const Json &group, uint64_t owner)
        {
            for (const auto &row : group.at("members"))
                if (row.at("user") == owner)
                    return row.at("role").get<unsigned>();
            return 0;
        }

        size_t memberships(const Json &data, uint64_t owner)
        {
            return static_cast<size_t>(std::count_if(data.at("groups").begin(),
                                                     data.at("groups").end(),
                                                     [owner](const auto &group)
                                                     {
                                                         return role(group, owner) != 0;
                                                     }));
        }

        wire::Bytes membership(const Json &data, const Json &group, const Json &row)
        {
            // Full bdClansGroupMemberInfo (0x1421070B0) and nested membership
            // (0x142106B90), recovered through the exact linked virtual tables.
            wire::Bytes out;
            const auto owner = row.at("user").get<uint64_t>();
            proto::integer(out, 1, row.at("role").get<unsigned>());
            proto::bytes(out, 2, identifier(group));
            const auto key = std::to_string(owner);
            const auto &active = data.at("active");
            proto::integer(out, 3, active.contains(key) && active.at(key) == group.at("id"));
            return out;
        }

        Reply structured(const std::string &operation, wire::Bytes bytes = {})
        {
            return {0, {}, operation, true, std::move(bytes)};
        }

        wire::Bytes memberInfo(const Json &group, const Json &member)
        {
            // Replay 0x14210B700: GroupIdentifier at 1, UserDetails at 2, role at 3.
            wire::Bytes out;
            proto::bytes(out, 1, identifier(group));
            proto::bytes(out,
                         2,
                         account(member.at("user").get<uint64_t>(),
                                 member.at("name").get<std::string>(),
                                 true));
            proto::integer(out, 3, member.at("role").get<uint64_t>());
            return out;
        }

        void notify(Reply &reply,
                    const platform::LobbyIdentity &id,
                    uint32_t event,
                    const wire::Bytes &body,
                    const std::set<uint64_t> &users,
                    uint64_t group,
                    uint64_t subject = 0,
                    uint32_t memberRole = 0)
        {
            // Replay 0x14210A6F0 dispatches 77..84. The helper at 0x14210A5D0
            // consumes a typed struct start, typed UInt32 length and protobuf body.
            wire::Writer envelope;
            envelope.u32(event);
            envelope.data.push_back(23);
            envelope.u32(static_cast<uint32_t>(body.size()));
            envelope.data.insert(envelope.data.end(), body.begin(), body.end());
            for (const auto uid : users)
                if (uid != id.userId)
                {
                    Delivery delivery;
                    delivery.user = uid;
                    delivery.payload = envelope.data;
                    delivery.clanGroup = group;
                    delivery.clanUser = subject;
                    delivery.clanEvent = event;
                    delivery.clanRole = memberRole;
                    reply.deliveries.push_back(std::move(delivery));
                }
        }

        std::set<uint64_t> members(const Json &group)
        {
            std::set<uint64_t> users;
            for (const auto &row : group.at("members"))
                users.insert(row.at("user").get<uint64_t>());
            return users;
        }

        void roleChanges(Reply &reply,
                         const platform::LobbyIdentity &id,
                         const Json &before,
                         const Json &group)
        {
            const auto recipients = members(group);
            for (const auto &member : group.at("members"))
                if (role(before, member.at("user").get<uint64_t>()) != member.at("role"))
                    notify(reply,
                           id,
                           84,
                           memberInfo(group, member),
                           recipients,
                           group.at("id").get<uint64_t>(),
                           member.at("user").get<uint64_t>(),
                           member.at("role").get<uint32_t>());
        }

        void disband(Reply &reply, const platform::LobbyIdentity &id, const Json &group)
        {
            // Withdrawing proposals also retires the invite cache of non-members.
            std::set<uint64_t> recipients = members(group);
            for (const auto &proposal : group.at("proposals"))
            {
                const auto target = proposal.at("target").get<uint64_t>();
                recipients.insert(target);
                wire::Bytes removed;
                proto::bytes(removed,
                             1,
                             account(target, proposal.at("target_name").get<std::string>(), true));
                proto::bytes(removed, 2, identifier(group));
                proto::integer(removed, 3, 0);
                notify(reply,
                       id,
                       79,
                       removed,
                       {target, proposal.at("proposer").get<uint64_t>()},
                       group.at("id").get<uint64_t>(),
                       target);
            }
            notify(reply, id, 81, identifier(group), recipients, group.at("id").get<uint64_t>());
        }

        uint64_t activeGroup(const Json &data, uint64_t uid)
        {
            const auto key = std::to_string(uid);
            return data.at("active").contains(key) ? data.at("active").at(key).get<uint64_t>() : 0;
        }

        std::set<uint64_t> activePeers(const Json &data, uint64_t uid)
        {
            std::set<uint64_t> out;
            for (const auto &group : data.at("groups"))
                if (role(group, uid))
                {
                    const auto users = members(group);
                    out.insert(users.begin(), users.end());
                }
            return out;
        }

        void activeChanged(Reply &reply,
                           const platform::LobbyIdentity &id,
                           const Json &data,
                           uint64_t uid,
                           uint64_t previous,
                           std::set<uint64_t> recipients,
                           const std::string &name)
        {
            const auto current = activeGroup(data, uid);
            if (current == previous)
                return;
            const auto peers = activePeers(data, uid);
            recipients.insert(peers.begin(), peers.end());
            for (const auto &group : data.at("groups"))
                if (group.at("id") == current)
                    for (const auto &member : group.at("members"))
                        if (member.at("user") == uid)
                        {
                            notify(reply,
                                   id,
                                   82,
                                   memberInfo(group, member),
                                   recipients,
                                   current,
                                   uid,
                                   member.at("role").get<uint32_t>());
                            return;
                        }
            wire::require(!current);
            // Replay's callback compares the new ID against all joined clans. ID 0
            // clears active flags when the selected membership was removed.
            Json group{{"kind", 1u}, {"id", 0u}, {"root_kind", 0u}, {"root_id", 0u}};
            Json member{{"user", uid}, {"name", name}, {"role", 0u}};
            notify(reply, id, 82, memberInfo(group, member), recipients, 0, uid);
        }

        Reply create(const std::filesystem::path &path,
                     Json &data,
                     const platform::LobbyIdentity &id,
                     const Fields &f)
        {
            Json group{{"kind", number(required(f, 1), UINT16_MAX)},
                       {"root_kind", number(required(f, 3), UINT16_MAX)},
                       {"root_id", number(required(f, 4))},
                       {"name", text(required(f, 5), 255)},
                       {"privacy", number(required(f, 7), UINT16_MAX)},
                       {"tag", text(required(f, 12), 255)},
                       {"owner", id.userId},
                       {"title", id.titleId},
                       {"created", now()},
                       {"members",
                        Json::array({Json{{"user", id.userId}, {"role", 3}, {"name", id.name}}})},
                       {"proposals", Json::array()},
                       {"files", Json::object()}};
            wire::require(group.at("kind") == 1 && !group.at("name").get<std::string>().empty() &&
                          !group.at("tag").get<std::string>().empty());
            for (const auto &old : data.at("groups"))
            {
                if (old.at("owner") == id.userId || old.at("tag") == group.at("tag"))
                {
                    if (old.at("owner") == id.userId && old.at("name") == group.at("name") &&
                        old.at("tag") == group.at("tag") &&
                        old.at("root_kind") == group.at("root_kind") &&
                        old.at("root_id") == group.at("root_id") &&
                        old.at("privacy") == group.at("privacy"))
                        return structured("clan-create-idempotent", info(old));
                    return {106, {}, "clan-owner-or-tag-conflict"};
                }
            }
            wire::require(data.at("groups").size() < 1024 && memberships(data, id.userId) < 10);
            uint64_t created = 0;
            // Replay LUI_LuaCall_Clans_AcceptClanInvite (140F041F0) transports the
            // ID through a Lua double, then GetClanInvite compares the UInt64 cache
            // exactly. Issue only integers representable without rounding (53 bits).
            // Existing stored UInt64 identifiers remain readable and are not rewritten.
            do
            {
                created = wire::at<uint64_t>(crypto::random(8), 0) & ((uint64_t{1} << 53) - 1);
            } while (!created || created == UINT64_MAX ||
                     std::any_of(data.at("groups").begin(),
                                 data.at("groups").end(),
                                 [created](const auto &g)
                                 {
                                     return g.at("id") == created;
                                 }));
            group["id"] = created;
            data["groups"].push_back(group);
            const auto key = std::to_string(id.userId);
            if (!data["active"].contains(key))
                data["active"][key] = created;
            save(path, data);
            return structured("clan-created", info(group));
        }

        Reply reads(Json &data, const platform::LobbyIdentity &id, uint8_t task, const Fields &f)
        {
            auto reply = structured(task == 21 ? "clan-group-infos-read" : "clan-memberships-read");
            if (task == 21)
            {
                unsigned count = 0;
                std::set<uint64_t> seen;
                for (const auto &field : f)
                    if (field.tag == 1)
                    {
                        wire::require(++count <= 64);
                        const auto selected = groupId(nested(field));
                        wire::require(seen.insert(selected.at("id").get<uint64_t>()).second);
                        if (const auto *group = find(data, selected))
                            proto::bytes(reply.structure, 1, info(*group));
                    }
                return reply;
            }
            std::set<uint64_t> users;
            std::set<uint16_t> kinds, roles;
            Json selected;
            for (const auto &field : f)
            {
                if (task == 29 && field.tag == 1)
                {
                    wire::require(selected.is_null());
                    selected = groupId(nested(field));
                }
                else if ((task == 30 && field.tag == 1) || (task == 29 && field.tag == 2))
                {
                    wire::require(users.size() < 64);
                    wire::require(users.insert(user(nested(field))).second);
                }
                else if (field.tag == 3)
                {
                    auto &values = task == 30 ? kinds : roles;
                    wire::require(values.size() < 10);
                    values.insert(static_cast<uint16_t>(number(field, UINT16_MAX)));
                }
            }
            if (task == 29)
                wire::require(!selected.is_null());
            std::map<uint64_t, wire::Bytes> results;
            for (const auto &group : data.at("groups"))
            {
                if (task == 29 && (group.at("id") != selected.at("id") ||
                                   group.at("kind") != selected.at("kind") ||
                                   group.at("root_id") != selected.at("root_id") ||
                                   group.at("root_kind") != selected.at("root_kind")))
                    continue;
                if (!kinds.empty() && !kinds.contains(group.at("kind").get<uint16_t>()))
                    continue;
                for (const auto &row : group.at("members"))
                {
                    if (task == 30 && !users.contains(row.at("user").get<uint64_t>()))
                        continue;
                    if (task == 29 && !users.empty() &&
                        !users.contains(row.at("user").get<uint64_t>()))
                        continue;
                    if (!roles.empty() && !roles.contains(row.at("role").get<uint16_t>()))
                        continue;
                    const auto uid = row.at("user").get<uint64_t>();
                    auto [entry, inserted] = results.try_emplace(uid);
                    if (inserted)
                        proto::bytes(entry->second,
                                     1,
                                     account(uid, row.at("name").get<std::string>(), true));
                    proto::bytes(entry->second, 2, membership(data, group, row));
                }
            }
            for (auto &[uid, result] : results)
            {
                proto::integer(result, 3, lobby::online(id.titleId, uid) ? 1 : 0);
                proto::bytes(reply.structure, 1, result);
            }
            wire::require(reply.structure.size() <= 256 * 1024);
            return reply;
        }

        bool ownsOther(const Json &data, uint64_t userId, uint64_t excluded)
        {
            for (const auto &group : data.at("groups"))
                if (group.at("owner") == userId && group.at("id") != excluded)
                    return true;
            return false;
        }

        wire::Bytes proposalInfo(const Json &group, const Json &row)
        {
            // bdClansGroupMembershipProposal, complete Replay reader 0x142107D40.
            wire::Bytes out;
            proto::bytes(out,
                         1,
                         account(row.at("proposer").get<uint64_t>(),
                                 row.at("proposer_name").get<std::string>(),
                                 true));
            proto::bytes(out,
                         2,
                         account(row.at("target").get<uint64_t>(),
                                 row.at("target_name").get<std::string>(),
                                 true));
            proto::integer(out, 3, row.at("role").get<unsigned>());
            proto::bytes(out, 4, identifier(group));
            proto::integer(out, 5, 0);
            proto::bytes(out, 6, wire::base64(row.at("attachment").get<std::string>(), 1024));
            proto::integer(out, 7, row.at("updated").get<uint64_t>());
            return out;
        }

        std::string knownName(const Json &data, uint64_t uid)
        {
            for (const auto &group : data.at("groups"))
                for (const auto &row : group.at("members"))
                    if (row.at("user") == uid)
                        return row.at("name").get<std::string>();
            if (const auto name = platform::accountName(uid))
                return *name;
            return "";
        }

        Reply proposals(const std::filesystem::path &path,
                        Json &data,
                        const platform::LobbyIdentity &id,
                        uint8_t task,
                        const Fields &f)
        {
            if (task == 25)
            {
                const auto selected = groupId(nested(required(f, 1)));
                auto *group = find(data, selected);
                if (!group)
                    return {108, {}, "clan-group-not-found"};
                const auto callerRole = role(*group, id.userId);
                if (callerRole < 2)
                    return {101, {}, "clan-invite-role-denied"};
                auto reply = structured("clan-memberships-proposed");
                std::set<uint64_t> targets;
                for (const auto &field : f)
                    if (field.tag == 2)
                    {
                        const auto value = nested(field);
                        const auto target = user(nested(required(value, 1)));
                        const auto desired = number(required(value, 2), UINT16_MAX);
                        wire::require(targets.size() < 64 && targets.insert(target).second &&
                                      desired >= 1 && desired <= 2);
                        if (desired > callerRole)
                            return {101, {}, "clan-invite-role-denied"};
                        wire::Bytes attachment;
                        if (const auto *blob = optional(value, 3))
                        {
                            wire::require(blob->type == 2 && blob->bytes.size() <= 1024);
                            attachment.assign(blob->bytes.begin(), blob->bytes.end());
                        }
                        if (role(*group, target))
                        {
                            wire::Bytes existing;
                            proto::bytes(
                                existing, 1, account(target, knownName(data, target), true));
                            proto::integer(existing, 2, role(*group, target));
                            proto::bytes(existing, 3, {});
                            proto::bytes(reply.structure, 3, existing);
                            continue;
                        }
                        const auto key = std::to_string(target);
                        if (group->contains("cooldowns") && group->at("cooldowns").contains(key))
                        {
                            const auto &cooldown = group->at("cooldowns").at(key);
                            if (cooldown.at("recorded").get<uint64_t>() +
                                    cooldown.at("seconds").get<uint64_t>() >
                                now())
                                return {106, {}, "clan-invitation-cooldown"};
                            (*group)["cooldowns"].erase(key);
                        }
                        auto &rows = (*group)["proposals"];
                        auto found = std::find_if(rows.begin(),
                                                  rows.end(),
                                                  [target](const auto &row)
                                                  {
                                                      return row.at("target") == target;
                                                  });
                        Json row{{"proposer", id.userId},
                                 {"proposer_name", id.name},
                                 {"target", target},
                                 {"target_name", knownName(data, target)},
                                 {"role", desired},
                                 {"attachment", wire::base64Encode(attachment)},
                                 {"updated", now()}};
                        bool changed = true;
                        if (found == rows.end())
                        {
                            wire::require(rows.size() < 1024);
                            rows.push_back(row);
                        }
                        else
                        {
                            if (found->at("role") == desired &&
                                found->at("attachment") == row.at("attachment") &&
                                found->at("proposer") == id.userId)
                            {
                                row = *found;
                                changed = false;
                            }
                            else
                                *found = row;
                        }
                        const auto payload = proposalInfo(*group, row);
                        proto::bytes(reply.structure, 1, payload);
                        if (changed)
                            notify(reply,
                                   id,
                                   77,
                                   payload,
                                   {target},
                                   group->at("id").get<uint64_t>(),
                                   target,
                                   static_cast<uint32_t>(desired));
                    }
                wire::require(!targets.empty());
                save(path, data);
                return reply;
            }
            if (task == 26)
            {
                auto reply = structured("clan-proposals-removed");
                unsigned count = 0;
                std::set<std::pair<uint64_t, uint64_t>> seen;
                for (const auto &field : f)
                    if (field.tag == 1)
                    {
                        wire::require(++count <= 64);
                        const auto request = nested(field);
                        const auto selected = groupId(nested(required(request, 2)));
                        const auto target =
                            optional(request, 1) ? user(nested(*optional(request, 1))) : id.userId;
                        const auto cooldown = number(required(request, 3), UINT32_MAX);
                        wire::require(
                            seen.emplace(selected.at("id").get<uint64_t>(), target).second);
                        auto *group = find(data, selected);
                        if (!group)
                            return {108, {}, "clan-group-not-found"};
                        if (target != id.userId && role(*group, id.userId) < 2)
                            return {101, {}, "clan-proposal-remove-denied"};
                        auto &rows = (*group)["proposals"];
                        const auto priorSize = rows.size();
                        std::set<uint64_t> recipients{target};
                        for (const auto &row : rows)
                            if (row.at("target") == target)
                                recipients.insert(row.at("proposer").get<uint64_t>());
                        rows.erase(std::remove_if(rows.begin(),
                                                  rows.end(),
                                                  [target](const auto &row)
                                                  {
                                                      return row.at("target") == target;
                                                  }),
                                   rows.end());
                        if (!group->contains("cooldowns"))
                            (*group)["cooldowns"] = Json::object();
                        auto &cooldowns = (*group)["cooldowns"];
                        const auto key = std::to_string(target);
                        // Persist the requested local interval. A retry after the proposal
                        // was removed must not extend the same interval indefinitely.
                        if (cooldown)
                        {
                            if (rows.size() != priorSize || !cooldowns.contains(key) ||
                                cooldowns.at(key).at("seconds") != cooldown)
                            {
                                if (!cooldowns.contains(key) && cooldowns.size() >= 4096)
                                    return {102, {}, "clan-cooldown-capacity"};
                                cooldowns[key] = Json{{"recorded", now()}, {"seconds", cooldown}};
                            }
                        }
                        else
                            cooldowns.erase(key);
                        wire::Bytes removed;
                        proto::bytes(removed, 1, account(target, knownName(data, target), true));
                        proto::bytes(removed, 2, identifier(*group));
                        proto::integer(removed, 3, cooldown);
                        proto::bytes(reply.structure, 1, removed);
                        if (rows.size() != priorSize)
                            notify(reply,
                                   id,
                                   79,
                                   removed,
                                   recipients,
                                   group->at("id").get<uint64_t>(),
                                   target);
                    }
                wire::require(count > 0);
                save(path, data);
                return reply;
            }
            Json selected;
            uint64_t proposer = 0, target = 0;
            uint64_t limit = 0;
            std::string token;
            if (task == 27)
            {
                selected = groupId(nested(required(f, 1)));
                limit = number(required(f, 2), 100);
                token = text(required(f, 3), 128);
                // Replay FetchClanMembersCallback always fetches outgoing proposals
                // for the active clan, including ordinary members. Its next callback
                // (0x140F40230) fails activation on any read error. Membership allows
                // the read; inviting, editing and removing proposals remain privileged.
                const auto *group = find(data, selected);
                if (group && !role(*group, id.userId))
                    return {101, {}, "clan-proposal-read-denied"};
            }
            else
            {
                if (const auto *field = optional(f, 1))
                    proposer = user(nested(*field));
                if (const auto *field = optional(f, 2))
                    target = user(nested(*field));
                if (!proposer && !target)
                    target = id.userId;
                if (proposer != id.userId && target != id.userId)
                    return {101, {}, "clan-proposal-user-denied"};
                limit = number(required(f, 3), 100);
                token = text(required(f, 4), 128);
            }
            // Replay uses the SDK's default constructor (limit=0) in both incoming
            // and outgoing invitation wrappers. Zero requests the default page size.
            if (!limit)
                limit = 100;
            std::vector<wire::Bytes> matches;
            for (const auto &group : data.at("groups"))
            {
                if (task == 27 && identifier(group) != identifier(selected))
                    continue;
                for (const auto &row : group.at("proposals"))
                {
                    if (proposer && row.at("proposer") != proposer)
                        continue;
                    if (target && row.at("target") != target)
                        continue;
                    matches.push_back(proposalInfo(group, row));
                }
            }
            wire::Bytes digestInput;
            for (const auto &entry : matches)
                proto::bytes(digestInput, 1, entry);
            proto::integer(digestInput, 2, id.userId);
            proto::integer(digestInput, 3, task);
            proto::integer(digestInput, 4, proposer);
            proto::integer(digestInput, 5, target);
            if (task == 27)
                proto::bytes(digestInput, 6, identifier(selected));
            const auto digest = wire::base64Encode(crypto::sha256(digestInput));
            size_t offset = 0;
            if (!token.empty())
            {
                const auto delimiter = token.find(':');
                wire::require(delimiter > 0 && delimiter <= 8 &&
                              token.substr(delimiter + 1) == digest);
                for (size_t i = 0; i < delimiter; ++i)
                {
                    wire::require(token[i] >= '0' && token[i] <= '9');
                    offset = offset * 10 + static_cast<unsigned>(token[i] - '0');
                }
                wire::require(offset < matches.size());
            }
            auto reply = structured("clan-proposals-read");
            const auto end = std::min(matches.size(), offset + static_cast<size_t>(limit));
            for (size_t i = offset; i < end; ++i)
                proto::bytes(reply.structure, 1, matches[i]);
            proto::text(
                reply.structure, 2, end < matches.size() ? std::to_string(end) + ":" + digest : "");
            return reply;
        }

        Reply edit(const std::filesystem::path &path,
                   Json &data,
                   const platform::LobbyIdentity &id,
                   uint8_t task,
                   const Fields &f)
        {
            const auto selected = task == 22 ? groupId(f) : groupId(nested(required(f, 1)));
            auto *group = find(data, selected);
            if (!group)
                return {108, {}, "clan-group-not-found"};
            const auto callerRole = role(*group, id.userId);
            if (task == 37)
            {
                if (!callerRole)
                    return {101, {}, "clan-active-group-membership-denied"};
                auto reply = structured("clan-active-group-set");
                const auto key = std::to_string(id.userId);
                const auto previous = activeGroup(data, id.userId);
                const auto recipients = activePeers(data, id.userId);
                data["active"][key] = group->at("id");
                activeChanged(reply, id, data, id.userId, previous, recipients, id.name);
                save(path, data);
                return reply;
            }
            if (task == 22)
            {
                if (group->at("owner") != id.userId)
                    return {101, {}, "clan-update-owner-denied"};
                const auto before = *group;
                if (const auto *name = optional(f, 5))
                {
                    const auto value = text(*name, 255);
                    wire::require(!value.empty());
                    (*group)["name"] = value;
                }
                if (const auto *tag = optional(f, 12))
                {
                    const auto value = text(*tag, 255);
                    wire::require(!value.empty());
                    for (const auto &old : data.at("groups"))
                        if (old.at("id") != group->at("id") && old.at("tag") == value)
                            return {106, {}, "clan-tag-conflict"};
                    (*group)["tag"] = value;
                }
                if (const auto *privacy = optional(f, 7))
                    (*group)["privacy"] = number(*privacy, UINT16_MAX);
                // Owner transfer is explicit, and requires an existing member.
                if (const auto *owner = optional(f, 6))
                {
                    const auto successor = user(nested(*owner));
                    if (!role(*group, successor) ||
                        ownsOther(data, successor, group->at("id").get<uint64_t>()))
                        return {101, {}, "clan-owner-transfer-membership-denied"};
                    for (auto &row : group->at("members"))
                        row["role"] =
                            row.at("user") == successor
                                ? 3
                                : (row.at("role") == 3 ? 2 : row.at("role").get<unsigned>());
                    (*group)["owner"] = successor;
                }
                const auto payload = info(*group);
                auto reply = structured("clan-group-updated", payload);
                if (before != *group)
                {
                    roleChanges(reply, id, before, *group);
                    notify(
                        reply, id, 83, payload, members(*group), group->at("id").get<uint64_t>());
                }
                save(path, data);
                return reply;
            }
            if (task == 23)
            {
                auto reply = structured("clan-member-updated");
                const auto before = *group;
                const auto target = optional(f, 3) ? user(nested(*optional(f, 3))) : id.userId;
                const auto previous = activeGroup(data, target);
                const auto recipients = activePeers(data, target);
                const auto requestedRole = number(required(f, 2), 3);
                auto desired = requestedRole;
                // Replay's AcceptClanInvite wrapper (0x140F6D180) constructs the
                // request with role=0 (0x14213A160), then only sets the user. Zero
                // means retain the existing/offered role, never grant an arbitrary one.
                if (!desired)
                {
                    desired = role(*group, target);
                    if (!desired)
                        for (const auto &proposal : group->at("proposals"))
                            if (proposal.at("target") == target)
                                desired = proposal.at("role").get<uint64_t>();
                    if (!desired)
                        return {101, {}, "clan-member-role-not-established"};
                }
                const auto replaces = number(required(f, 4));
                if (const auto *attachment = optional(f, 5))
                    wire::require(attachment->type == 2 && attachment->bytes.size() <= 1024);
                // Target serializer 0x14213A360 carries replaceGroupID in field 4.
                // Validate both sides before a single groups.json commit. Only the
                // signed user may voluntarily replace their own membership.
                Json *replaced = nullptr;
                bool retry = false;
                if (replaces)
                {
                    wire::require(replaces != UINT64_MAX && replaces != group->at("id"));
                    if (target != id.userId)
                        return {101, {}, "clan-replacement-user-denied"};
                    for (auto &old : data.at("groups"))
                        if (old.at("id") == replaces)
                            replaced = &old;
                    if (!replaced || !role(*replaced, target))
                    {
                        for (const auto &member : group->at("members"))
                            if (member.at("user") == target && member.contains("replacement") &&
                                member.at("replacement").at("group") == replaces &&
                                member.at("replacement").at("role") == desired &&
                                member.at("role") == desired)
                                retry = true;
                        if (!retry)
                            return {108, {}, "clan-replacement-membership-not-found"};
                    }
                    else if (replaced->at("owner") == target && replaced->at("members").size() > 1)
                        return {106, {}, "clan-replacement-owner-successor-required"};
                }
                auto &rows = group->at("members");
                auto row = std::find_if(rows.begin(),
                                        rows.end(),
                                        [target](const auto &r)
                                        {
                                            return r.at("user") == target;
                                        });
                const bool added = row == rows.end();
                const auto oldRole = added ? 0 : row->at("role").get<uint64_t>();
                if (row == rows.end())
                {
                    auto &pending = (*group)["proposals"];
                    auto invitation = std::find_if(pending.begin(),
                                                   pending.end(),
                                                   [target](const auto &r)
                                                   {
                                                       return r.at("target") == target;
                                                   });
                    if (target != id.userId || invitation == pending.end() ||
                        desired > invitation->at("role").get<uint64_t>())
                        return {101, {}, "clan-member-not-admitted"};
                    wire::require(memberships(data, target) -
                                          (replaced && role(*replaced, target) ? 1u : 0u) <
                                      10 &&
                                  rows.size() < 1024);
                    const auto proposer = invitation->at("proposer").get<uint64_t>();
                    wire::Bytes removed;
                    proto::bytes(removed, 1, account(target, id.name, true));
                    proto::bytes(removed, 2, identifier(*group));
                    proto::integer(removed, 3, 0);
                    notify(reply,
                           id,
                           79,
                           removed,
                           {proposer, target},
                           group->at("id").get<uint64_t>(),
                           target);
                    rows.push_back(Json{{"user", target}, {"role", desired}, {"name", id.name}});
                    row = std::prev(rows.end());
                    pending.erase(invitation);
                    const auto key = std::to_string(target);
                    if (!data["active"].contains(key))
                        data["active"][key] = group->at("id");
                }
                else if ((callerRole < 2 && (target != id.userId || desired != callerRole)) ||
                         desired > callerRole ||
                         (group->at("owner") == target && (desired != 3 || target != id.userId)))
                    return {101, {}, "clan-role-change-denied"};
                if (desired == 3 && ownsOther(data, target, group->at("id").get<uint64_t>()))
                    return {101, {}, "clan-owner-transfer-denied"};
                (*row)["role"] = desired;
                if (desired == 3 && target != id.userId)
                {
                    for (auto &old : rows)
                        if (old.at("user") == id.userId)
                            old["role"] = 2;
                    (*group)["owner"] = target;
                }
                if (replaces && !retry)
                {
                    (*row)["replacement"] = Json{{"group", replaces}, {"role", desired}};
                    auto &oldRows = (*replaced)["members"];
                    for (const auto &member : oldRows)
                        if (member.at("user") == target)
                            notify(reply,
                                   id,
                                   80,
                                   memberInfo(*replaced, member),
                                   members(*replaced),
                                   replaces,
                                   target,
                                   member.at("role").get<uint32_t>());
                    oldRows.erase(std::remove_if(oldRows.begin(),
                                                 oldRows.end(),
                                                 [target](const auto &member)
                                                 {
                                                     return member.at("user") == target;
                                                 }),
                                  oldRows.end());
                    const auto key = std::to_string(target);
                    if (data.at("active").contains(key) && data.at("active").at(key) == replaces)
                        data["active"][key] = selected.at("id");
                    if (oldRows.empty())
                    {
                        disband(reply, id, *replaced);
                        auto &groups = data["groups"];
                        groups.erase(std::remove_if(groups.begin(),
                                                    groups.end(),
                                                    [replaces](const auto &old)
                                                    {
                                                        return old.at("id") == replaces;
                                                    }),
                                     groups.end());
                        // Erasing an array entry invalidates pointers to later groups.
                        group = find(data, selected);
                        wire::require(group != nullptr);
                        auto &members = (*group)["members"];
                        row = std::find_if(members.begin(),
                                           members.end(),
                                           [target](const auto &member)
                                           {
                                               return member.at("user") == target;
                                           });
                        wire::require(row != members.end());
                    }
                }
                wire::Bytes response;
                proto::bytes(
                    response, 1, account(target, row->at("name").get<std::string>(), true));
                proto::bytes(response, 2, identifier(*group));
                proto::integer(response, 3, desired);
                if (!retry && added)
                    notify(reply,
                           id,
                           78,
                           memberInfo(*group, *row),
                           members(*group),
                           group->at("id").get<uint64_t>(),
                           target,
                           static_cast<uint32_t>(desired));
                if (!retry && !added && oldRole != desired)
                    roleChanges(reply, id, before, *group);
                if (!retry && before.at("owner") != group->at("owner"))
                    notify(reply,
                           id,
                           83,
                           info(*group),
                           members(*group),
                           group->at("id").get<uint64_t>());
                if (!retry)
                    activeChanged(reply,
                                  id,
                                  data,
                                  target,
                                  previous,
                                  recipients,
                                  row->at("name").get<std::string>());
                if (!retry)
                    save(path, data);
                reply.structure = std::move(response);
                if (retry)
                    reply.operation = "clan-replacement-idempotent";
                return reply;
            }
            // 0x14213A750 optional target and optional replacement-owner IDs.
            const auto target = optional(f, 2) ? user(nested(*optional(f, 2))) : id.userId;
            const auto previous = activeGroup(data, target);
            const auto recipients = activePeers(data, target);
            const auto targetName = knownName(data, target);
            if (!callerRole || (target != id.userId && callerRole < 2) ||
                (target != id.userId && role(*group, target) >= callerRole))
                return {101, {}, "clan-member-remove-denied"};
            auto reply = structured("clan-member-removed");
            const auto before = *group;
            for (const auto &member : group->at("members"))
                if (member.at("user") == target)
                    notify(reply,
                           id,
                           80,
                           memberInfo(*group, member),
                           members(*group),
                           group->at("id").get<uint64_t>(),
                           target,
                           member.at("role").get<uint32_t>());
            if (group->at("owner") == target && group->at("members").size() > 1)
            {
                if (!optional(f, 3))
                    return {106, {}, "clan-owner-successor-required"};
                const auto successor = user(nested(*optional(f, 3)));
                if (successor == target || !role(*group, successor) ||
                    ownsOther(data, successor, group->at("id").get<uint64_t>()))
                    return {101, {}, "clan-owner-successor-denied"};
                (*group)["owner"] = successor;
                for (auto &row : group->at("members"))
                    if (row.at("user") == successor)
                        row["role"] = 3;
            }
            auto &rows = group->at("members");
            rows.erase(std::remove_if(rows.begin(),
                                      rows.end(),
                                      [target](const auto &row)
                                      {
                                          return row.at("user") == target;
                                      }),
                       rows.end());
            const auto key = std::to_string(target);
            if (data.at("active").contains(key) && data.at("active").at(key) == group->at("id"))
                data["active"].erase(key);
            if (rows.empty())
            {
                disband(reply, id, *group);
                auto &groups = data["groups"];
                groups.erase(std::remove_if(groups.begin(),
                                            groups.end(),
                                            [&](const auto &g)
                                            {
                                                return g.at("id") == selected.at("id");
                                            }),
                             groups.end());
            }
            else if (before.at("owner") != group->at("owner"))
            {
                roleChanges(reply, id, before, *group);
                notify(
                    reply, id, 83, info(*group), members(*group), group->at("id").get<uint64_t>());
            }
            activeChanged(reply, id, data, target, previous, recipients, targetName);
            save(path, data);
            return reply;
        }

        Reply groupFile(const std::filesystem::path &path,
                        Json &data,
                        const platform::LobbyIdentity &id,
                        uint8_t task,
                        const Fields &f)
        {
            // Request: wrapper tag 1, then full GroupFile. Native target 0x14213BD30
            // reads group/name/blob/collision/created/updated. Upload serializer
            // 0x14213BE20 sends only fields 1..4; timestamps are server-owned.
            const auto file = nested(required(f, 1));
            const auto selected = groupId(nested(required(file, 1)));
            auto *group = find(data, selected);
            if (!group)
                return {108, {}, "clan-group-not-found"};
            if (!role(*group, id.userId))
                return {101, {}, "clan-file-membership-denied"};
            const auto name = text(required(file, 2), 255);
            wire::require(!name.empty());
            auto &files = (*group)["files"];
            wire::require(files.is_object() && files.size() <= 128);
            if (task == 32)
            {
                if (role(*group, id.userId) < 2)
                    return {101, {}, "clan-file-write-denied"};
                const auto &blob = required(file, 3);
                wire::require(blob.type == 2 && blob.bytes.size() <= 128 * 1024);
                const auto collision = number(required(file, 4), UINT32_MAX);
                // Replay's native upload wrapper initializes collision=0 and never
                // sets it, so zero is an unconditional write. Nonzero is an explicit
                // version check; each successful write publishes a new version.
                if (collision &&
                    (!files.contains(name) || files.at(name).at("collision") != collision))
                    return {106, {}, "clan-file-collision"};
                wire::require(files.contains(name) || files.size() < 128);
                const auto created =
                    files.contains(name) ? files.at(name).at("created").get<uint64_t>() : now();
                const auto version =
                    files.contains(name) ? files.at(name).at("collision").get<uint32_t>() : 0u;
                wire::require(version < UINT32_MAX);
                files[name] = Json{{"content", wire::base64Encode(blob.bytes)},
                                   {"collision", version + 1},
                                   {"created", created},
                                   {"updated", now()}};
            }
            else if (!files.contains(name))
            {
                // Native OnlineClan::GetHappyHourCallback accepts this specific
                // group-file error (19734) to continue activation with default data.
                // Generic storage error 1000 would incorrectly abort that sequence.
                return {19734, {}, "clan-file-not-found"};
            }
            const auto &stored = files.at(name);
            wire::Bytes result = identifier(*group), body;
            proto::bytes(body, 1, result);
            proto::text(body, 2, name);
            proto::bytes(
                body, 3, wire::base64(stored.at("content").get<std::string>(), 128 * 1024));
            proto::integer(body, 4, stored.at("collision").get<uint64_t>());
            proto::integer(body, 5, stored.at("created").get<uint64_t>());
            proto::integer(body, 6, stored.at("updated").get<uint64_t>());
            wire::Bytes response;
            proto::bytes(response, 1, body);
            if (task == 32)
                save(path, data);
            return structured(task == 32 ? "clan-file-uploaded" : "clan-file-read",
                              std::move(response));
        }
    } // namespace

    bool clanDeliveryValid(const std::filesystem::path &root,
                           uint32_t title,
                           const Delivery &delivery)
    {
        if (!delivery.clanEvent)
            return true;
        if (delivery.clanEvent < 77 || delivery.clanEvent > 84 || delivery.payload.size() < 11)
            return false;
        const auto data = load(root / "clans" / std::to_string(title) / "groups.json");
        const Json *group = nullptr;
        for (const auto &row : data.at("groups"))
            if (row.at("id") == delivery.clanGroup)
                group = &row;
        if (delivery.clanEvent == 81)
            return !group;
        if (delivery.clanEvent == 80)
            return !group || !role(*group, delivery.clanUser);
        if (delivery.clanEvent == 79 && !group)
            return true;
        if (delivery.clanEvent == 82)
            return activeGroup(data, delivery.clanUser) == delivery.clanGroup;
        if (!group)
            return false;
        if (delivery.clanEvent == 77 || delivery.clanEvent == 79)
        {
            const auto &rows = group->at("proposals");
            const auto found = std::find_if(rows.begin(),
                                            rows.end(),
                                            [&](const auto &row)
                                            {
                                                return row.at("target") == delivery.clanUser;
                                            });
            if (delivery.clanEvent == 79)
                return found == rows.end();
            return found != rows.end() &&
                   proposalInfo(*group, *found) ==
                       wire::Bytes(delivery.payload.begin() + 11, delivery.payload.end());
        }
        if (delivery.clanEvent == 83)
        {
            // Online count is connection state, not a group edit revision. A peer
            // disconnect must not suppress an otherwise current metadata update.
            const auto stable = [](const wire::Bytes &bytes)
            {
                wire::Bytes out;
                for (const auto &field : fields(bytes))
                    if (field.tag != 11)
                    {
                        if (field.type == 0)
                            proto::integer(out, field.tag, field.value);
                        else
                        {
                            wire::require(field.type == 2);
                            proto::bytes(out, field.tag, field.bytes);
                        }
                    }
                return out;
            };
            return stable(info(*group)) ==
                   stable(wire::Bytes(delivery.payload.begin() + 11, delivery.payload.end()));
        }
        for (const auto &member : group->at("members"))
            if (member.at("user") == delivery.clanUser)
                return member.at("role") == delivery.clanRole &&
                       memberInfo(*group, member) ==
                           wire::Bytes(delivery.payload.begin() + 11, delivery.payload.end());
        return false;
    }

    std::optional<Reply> clanServices(const std::filesystem::path &root,
                                      const platform::LobbyIdentity &id,
                                      uint8_t service,
                                      uint8_t task,
                                      wire::Reader &p)
    {
        if (service != 197 || (task < 20 || (task > 32 && task != 37)))
            return std::nullopt;
        const auto f = fields(p.structure(256 * 1024));
        const auto path = root / "clans" / std::to_string(id.titleId) / "groups.json";
        auto data = load(path);
        if (task == 20)
            return create(path, data, id, f);
        if (task == 21 || task == 29 || task == 30)
            return reads(data, id, task, f);
        if (task >= 25 && task <= 28)
            return proposals(path, data, id, task, f);
        if (task == 31 || task == 32)
            return groupFile(path, data, id, task, f);
        return edit(path, data, id, task, f);
    }
} // namespace services
