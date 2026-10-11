#include "channel_services.h"
#include "channel_store.h"
#include "lobby.h"
#include "protobuf.h"
#include "nlohmann/json.hpp"
#include <chrono>
#include <algorithm>
#include <charconv>
#include <cstring>

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

        std::string instantMessageDetail(uint64_t sender,
                                         uint64_t recipient,
                                         const wire::Bytes &message)
        {
            auto detail = " recipient=" + std::to_string(recipient) +
                          " message_bytes=" + std::to_string(message.size());
            // Original Replay SendDWInvite / OnDWInstantMessage use the
            // five-byte INV:\0 header, followed by the one-byte message type.
            // Keep opaque application bytes intact. Log no body or session keys.
            if (message.size() < 6 || std::memcmp(message.data(), "INV:\0", 5) != 0)
                return detail + " message_kind=opaque";
            switch (message[5])
            {
            case 0:
                return detail + " message_kind=join_info_request";
            case 1:
                return detail + " message_kind=join_info_response";
            case 2:
                break;
            default:
                return detail + " message_kind=unknown_invite_type";
            }
            detail += " message_kind=invitation";
            // Exact 0x140F5A1C0: name (at most 35 bytes plus NUL), UInt32 UTC,
            // UInt64 inviter XUID. 0x140F5A230 reads this complete layout.
            const auto end = std::find(message.begin() + 6, message.end(), uint8_t{});
            const auto nameSize = static_cast<size_t>(end - (message.begin() + 6));
            if (end == message.end() || nameSize > 35 ||
                message.size() != 6 + nameSize + 1 + 12)
                return detail + " invitation_layout=invalid";
            uint32_t timestamp = 0;
            uint64_t inviter = 0;
            std::memcpy(&timestamp, message.data() + 7 + nameSize, sizeof(timestamp));
            std::memcpy(&inviter, message.data() + 11 + nameSize, sizeof(inviter));
            return detail + " invitation_layout=valid inviter_matches_sender=" +
                   (inviter == sender ? "1" : "0") + " invitation_age_seconds=" +
                   std::to_string(static_cast<int64_t>(now()) - timestamp);
        }

        std::string category(const proto::Field &field)
        {
            wire::require(field.type == 2 && !field.bytes.empty() && field.bytes.size() < 16);
            std::string value(reinterpret_cast<const char *>(field.bytes.data()),
                              field.bytes.size());
            for (char c : value)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_');
            return value;
        }

        Delivery context(const Json &channel,
                         uint64_t recipient,
                         uint64_t actor,
                         uint32_t event,
                         uint32_t generation)
        {
            Delivery delivery;
            delivery.user = recipient;
            delivery.channelCategory = channel["category"];
            delivery.channelId = channel["id"].get<uint64_t>();
            delivery.channelMember = actor;
            delivery.channelEvent = event;
            delivery.channelMemberGeneration = generation;
            delivery.channelRecipientGeneration =
                channel["members"].at(std::to_string(recipient)).at("generation").get<uint32_t>();
            return delivery;
        }

        wire::Bytes membershipPacket(const Json &channel,
                                     uint64_t actor,
                                     const Json &member,
                                     bool joined)
        {
            // Exact Replay 0x142120A80 selects subscribed for event 24, then
            // 0x1420FE9A0 reads the complete typed channel-info-with-category DTO.
            wire::Writer push;
            push.u32(joined ? 24 : 25);
            push.u64(actor);
            push.text(member.at("name"));
            push.text(channel.at("category"));
            push.u64(channel.at("id"));
            push.u32(0); // Native bdChannelMember flags.
            push.text(channel.at("category"));
            push.u64(channel.at("id"));
            push.u32(static_cast<uint32_t>(channel["members"].size()));
            push.u32(channel_store::memberLimit);
            push.u64(channel.at("owner"));
            push.boolean(false);
            push.boolean(false);
            push.u32(channel.at("revision"));
            return std::move(push.data);
        }

        void notifyMembership(std::vector<Delivery> &deliveries,
                              const Json &channel,
                              uint64_t actor,
                              const Json &member,
                              bool joined)
        {
            const auto packet = membershipPacket(channel, actor, member, joined);
            for (const auto &recipient : channel["members"].items())
            {
                const auto user = std::stoull(recipient.key()); // Validated canonical UInt64.
                if (user == actor)
                    continue;
                auto delivery = context(channel,
                                        user,
                                        actor,
                                        joined ? 24 : 25,
                                        member.at("generation").get<uint32_t>());
                delivery.payload = packet;
                delivery.delayMs = 250;
                deliveries.push_back(std::move(delivery));
            }
        }

        bool removeMember(Json &channel, uint64_t user, std::vector<Delivery> &deliveries)
        {
            const auto key = std::to_string(user);
            if (!channel["members"].contains(key))
                return false;
            const auto member = channel["members"][key];
            channel_store::advance(channel);
            channel["members"].erase(key);
            notifyMembership(deliveries, channel, user, member, false);
            return true;
        }

        wire::Bytes info(const Json &channel)
        {
            // Replay bdChannelInfo::deserialize 0x1420FE7F0, complete native DTO.
            wire::Bytes out;
            proto::text(out, 1, channel.at("category"));
            proto::integer(out, 2, channel.at("id"));
            proto::integer(out, 3, channel.at("members").size());
            proto::integer(out, 4, channel_store::memberLimit);
            proto::integer(out, 5, channel.at("owner"));
            proto::integer(out, 6, 0);
            proto::integer(out, 7, 0);
            proto::integer(out, 8, channel.at("revision"));
            return out;
        }
    } // namespace

    void initializeChannels(const std::filesystem::path &directory)
    {
        const auto root = directory / "channels";
        if (!std::filesystem::exists(root))
            return;
        std::vector<std::pair<std::filesystem::path, Json>> snapshots;
        for (const auto &entry : std::filesystem::directory_iterator(root))
        {
            if (!entry.is_regular_file() || entry.path().extension() != L".json")
                continue;
            uint32_t title = 0;
            const auto stem = entry.path().stem().string();
            const auto parsed = std::from_chars(stem.data(), stem.data() + stem.size(), title);
            if (parsed.ec != std::errc{} || parsed.ptr != stem.data() + stem.size() || !title ||
                std::to_string(title) != stem || snapshots.size() >= 1024)
                throw std::runtime_error("Invalid channel title directory");
            snapshots.emplace_back(entry.path(), channel_store::load(entry.path(), title));
        }
        // Validate and prepare every title before publishing restart cleanup.
        // A later revision overflow must not leave earlier titles cleared.
        for (auto &[path, state] : snapshots)
        {
            for (auto &channel : state["channels"])
            {
                if (!channel["members"].empty())
                {
                    channel_store::advance(channel);
                    channel["members"] = Json::object();
                }
            }
        }
        for (const auto &[path, state] : snapshots)
            channel_store::save(path, state["title"].get<uint32_t>(), state);
    }

    std::vector<Delivery> disconnectChannels(const std::filesystem::path &directory,
                                             uint32_t title,
                                             uint64_t user)
    {
        const auto path = directory / "channels" / (std::to_string(title) + ".json");
        if (!std::filesystem::exists(path))
            return {};
        auto state = channel_store::load(path, title);
        std::vector<Delivery> deliveries;
        bool changed = false;
        for (auto &channel : state["channels"])
        {
            changed = removeMember(channel, user, deliveries) || changed;
        }
        if (changed)
            channel_store::save(path, title, state);
        return deliveries;
    }

    bool channelDeliveryValid(const std::filesystem::path &directory,
                              uint32_t title,
                              const Delivery &delivery)
    {
        if (!delivery.channelId)
            return true;
        const auto state =
            channel_store::load(directory / "channels" / (std::to_string(title) + ".json"), title);
        const auto key = delivery.channelCategory + ":" + std::to_string(delivery.channelId);
        if (!state["channels"].contains(key))
            return false;
        const auto &members = state["channels"][key]["members"];
        const auto recipient = std::to_string(delivery.user),
                   actor = std::to_string(delivery.channelMember);
        if (!members.contains(recipient) ||
            members[recipient]["generation"] != delivery.channelRecipientGeneration)
            return false;
        // Per-member generations preserve concurrent joins by other members.
        // Requiring the whole channel revision would incorrectly discard them.
        if (delivery.channelEvent == 25)
            return !members.contains(actor);
        return (delivery.channelEvent == 22 || delivery.channelEvent == 23 ||
                delivery.channelEvent == 24) &&
               members.contains(actor) &&
               members[actor]["generation"] == delivery.channelMemberGeneration;
    }

    std::optional<Reply> channelServices(const std::filesystem::path &directory,
                                         const platform::LobbyIdentity &id,
                                         uint8_t service,
                                         uint8_t task,
                                         wire::Reader &p)
    {
        if (service == 6 && task == 14)
        {
            // Actual Replay sendGlobalInstantMessage request 0x14212CC20.
            // Native bdLobbyService::handlePushMessage 0x142122970 selects 21,
            // then reads sender UInt64, sender name[64], and message blob[4096].
            const auto recipient = p.u64();
            const auto message = p.blob(4096);
            p.end();
            wire::require(recipient && recipient != UINT64_MAX);
            if (!platform::accountName(recipient))
                return Reply{108, {}, "instant-message-recipient-not-found"};
            if (!lobby::online(id.titleId, recipient))
                return Reply{108, {}, "instant-message-recipient-offline"};
            wire::Writer push;
            push.u32(21);
            push.u64(id.userId);
            push.text(id.name);
            push.blob(message);
            Reply reply{0, {}, "global-instant-message-routed"};
            reply.detail = instantMessageDetail(id.userId, recipient, message);
            reply.deliveries.push_back({recipient, std::move(push.data)});
            return reply;
        }
        if (service != 198 || (task < 1 || (task > 7 && task != 12)))
            return std::nullopt;
        // Request 0x142163500: category string/1, channel UInt64/2,
        // caller UInt64/3. Task 12 has only category/1. Task 6 creates a channel;
        // it is not getChannelInfo, despite the inaccurate decompiler aliases.
        proto::Reader request{p.structure(4096)};
        proto::Field f;
        unsigned seen = 0;
        std::string cat;
        uint64_t channelId = 0, user = 0;
        std::vector<std::pair<std::string, uint64_t>> queries;
        wire::Bytes message;
        uint32_t messageType = 0;
        while (request.next(f))
        {
            if (task == 7)
            {
                // 0x142163570 writes repeated field-1 request objects.
                wire::require(f.tag == 1 && f.type == 2 && queries.size() < 64);
                proto::Reader item{f.bytes};
                proto::Field part;
                unsigned fields = 0;
                std::string name;
                uint64_t channel = 0;
                while (item.next(part))
                {
                    wire::require(part.tag >= 1 && part.tag <= 3 && !(fields & (1U << part.tag)));
                    fields |= 1U << part.tag;
                    if (part.tag == 1)
                        name = category(part);
                    else
                    {
                        wire::require(part.type == 0);
                        if (part.tag == 2)
                            channel = part.value;
                        else
                            wire::require(part.value == 0);
                    }
                }
                wire::require(fields == 14 && channel != 0 && channel != UINT64_MAX);
                queries.emplace_back(name, channel);
                continue;
            }
            const auto last = task == 3 ? 4U : task == 4 ? 5U : 3U;
            wire::require(f.tag >= 1 && f.tag <= last && !(seen & (1U << f.tag)));
            seen |= 1U << f.tag;
            if (f.tag == 1)
                cat = category(f);
            else if ((task == 3 && f.tag == 3) || (task == 4 && f.tag == 4))
            {
                // The native push consumer 0x14211FF60 has a 1024-byte buffer.
                wire::require(f.type == 2 && f.bytes.size() <= 1024);
                message.assign(f.bytes.begin(), f.bytes.end());
            }
            else if ((task == 3 && f.tag == 4) || (task == 4 && f.tag == 5))
            {
                wire::require(f.type == 0 && f.value <= UINT32_MAX);
                messageType = static_cast<uint32_t>(f.value);
            }
            else
            {
                wire::require(f.type == 0);
                if (f.tag == 2)
                    channelId = f.value;
                else
                    user = f.value;
            }
        }
        wire::require(task == 7 ? !queries.empty()
                                : seen == (task == 12  ? 2U
                                           : task == 3 ? 30U
                                           : task == 4 ? 62U
                                                       : 14U));
        if ((task == 3 || task == 4) && (cat == "chat" || cat == "clanChat"))
        {
            // Original SendMessageToChat (140F3D9D0) passes strlen, excluding
            // the terminator. The receiving game's 500-byte C-string buffer
            // needs one. Normalize here before publishing the native push.
            wire::require(!message.empty() && message.size() <= 500);
            if (message.back() == 0)
                message.pop_back();
            wire::require(!message.empty() && message.size() < 500 &&
                          std::find(message.begin(), message.end(), uint8_t{0}) == message.end());
            message.push_back(0);
        }
        if (task == 5)
            wire::require(user <= 256);
        else if (task != 4 && user && user != id.userId)
            return Reply{101, {}, "channel-subscriber-owner-denied"};
        wire::require(channelId != UINT64_MAX &&
                      (task == 6 || task == 7 || task == 12 || channelId != 0));
        const auto path = directory / "channels" / (std::to_string(id.titleId) + ".json");
        auto state = channel_store::load(path, id.titleId);
        auto &channels = state["channels"];
        wire::require(channels.size() <= 4096);
        const auto time = now();
        const auto member = std::to_string(id.userId);
        bool changed = false;
        Reply reply{0, {}, "channel-category-unsubscribed", true, {}};
        for (auto &channel : channels)
        {
            wire::require(channel.is_object() && channel.at("members").is_object() &&
                          channel.at("members").size() <= channel_store::memberLimit);
            auto &members = channel["members"];
            for (auto it = members.begin(); it != members.end();)
            {
                const auto expired = it.value().at("expires").get<uint64_t>() <= time;
                const auto userId = std::stoull(it.key());
                if (expired && !lobby::online(id.titleId, userId))
                {
                    const auto record = it.value();
                    channel_store::advance(channel);
                    it = members.erase(it);
                    notifyMembership(reply.deliveries, channel, userId, record, false);
                    changed = true;
                }
                else
                    ++it;
            }
            if (task == 12 && channel.at("category") == cat)
                changed = removeMember(channel, id.userId, reply.deliveries) || changed;
        }
        if (task == 7)
        {
            for (const auto &query : queries)
            {
                const auto key = query.first + ":" + std::to_string(query.second);
                if (!channels.contains(key))
                    return Reply{108, {}, "channel-not-found"};
                // Native get-channel-infos response reads repeated field-1 objects
                // using 0x142104C10 and bdChannelInfo's complete deserializer.
                proto::bytes(reply.structure, 1, info(channels[key]));
            }
            reply.operation = "channel-infos-read";
        }
        else if (task != 12)
        {
            if (!channelId)
            {
                do
                {
                    const auto bytes = crypto::random(8);
                    channelId = wire::at<uint64_t>(bytes, 0);
                } while (!channelId || channelId == UINT64_MAX ||
                         channels.contains(cat + ":" + std::to_string(channelId)));
            }
            const auto key = cat + ":" + std::to_string(channelId);
            if (task == 6 && !channels.contains(key))
            {
                wire::require(channels.size() < 4096);
                channels[key] = {{"category", cat},
                                 {"id", channelId},
                                 {"owner", id.userId},
                                 {"created", time},
                                 {"revision", uint32_t{0}},
                                 {"members", Json::object()}};
                changed = true;
            }
            if (!channels.contains(key))
                return Reply{108, {}, "channel-not-found"};
            auto &channel = channels[key];
            auto &members = channel["members"];
            if (task == 3 || task == 4)
            {
                if (!members.contains(member) ||
                    (task == 4 && !members.contains(std::to_string(user))))
                    return Reply{101, {}, "channel-message-membership-denied"};
                // Push IDs 22/23 both use the verified V2 channel message reader.
                // No request body, member names or message bytes enter diagnostics.
                wire::Writer push;
                push.u32(task == 3 ? 22 : 23);
                push.u64(id.userId);
                push.text(id.name);
                push.text(cat);
                push.u64(channelId);
                push.blob(message);
                push.u32(messageType);
                for (auto it = members.begin(); it != members.end(); ++it)
                {
                    const auto target = std::stoull(it.key());
                    if (task == 3 || target == user)
                    {
                        auto delivery = context(channel,
                                                target,
                                                id.userId,
                                                task == 3 ? 22 : 23,
                                                members[member]["generation"].get<uint32_t>());
                        delivery.payload = push.data;
                        // Native OnChatChannelMessage 140F3D410 requires the sender
                        // to exist already. Its delayed join may still be queued.
                        // Carry the same real membership snapshot so the serialized
                        // endpoint writer can publish it before the first message.
                        if (target != id.userId &&
                            delivery.channelMemberGeneration > delivery.channelRecipientGeneration)
                            delivery.channelJoinPayload =
                                membershipPacket(channel, id.userId, members[member], true);
                        reply.deliveries.push_back(std::move(delivery));
                    }
                }
                reply.operation = task == 3 ? "channel-message-routed" : "channel-whisper-routed";
            }
            else if (task == 5)
            {
                uint64_t count = 0;
                for (auto it = members.begin(); it != members.end() && count < user; ++it, ++count)
                {
                    wire::Bytes item;
                    // Native structured member 0x142104B00: UInt64 ID/1,
                    // name/2, UInt32 flags/3; complete bounded 64-byte name.
                    proto::integer(item, 1, std::stoull(it.key()));
                    proto::text(item, 2, it.value().at("name"));
                    proto::integer(item, 3, 0);
                    proto::bytes(reply.structure, 1, item);
                }
                reply.operation = "channel-members-read";
            }
            else if (task == 2)
            {
                changed = removeMember(channel, id.userId, reply.deliveries) || changed;
                reply.operation = "channel-unsubscribed";
            }
            else
            {
                if (!members.contains(member) && members.size() >= channel_store::memberLimit)
                    return Reply{108, {}, "channel-full"};
                const bool joined = !members.contains(member);
                const bool renamed = !joined && members[member]["name"] != id.name;
                const auto generation = joined ? channel_store::advance(channel)
                                               : members[member]["generation"].get<uint32_t>();
                if (renamed)
                    channel_store::advance(channel);
                const auto expires =
                    joined ? id.expires
                           : std::max(id.expires, members[member]["expires"].get<uint64_t>());
                const Json entry = {
                    {"name", id.name}, {"expires", expires}, {"generation", generation}};
                if (!members.contains(member) || members[member] != entry)
                {
                    members[member] = entry;
                    changed = true;
                }
                // Native AddMemberToChat ignores duplicate joins rather than
                // updating a member's name. Renames update queried metadata;
                // the existing native member refreshes on its next real join.
                if (joined)
                    notifyMembership(reply.deliveries, channel, id.userId, entry, true);
                reply.operation = task == 6 ? "channel-created-or-joined" : "channel-subscribed";
                // 0x1420FF500 is the bound create-channel response. It reads
                // one nested field-1 bdChannelInfo at this+32, not flat fields.
                if (task == 6)
                    proto::bytes(reply.structure, 1, info(channel));
            }
        }
        if (changed)
            channel_store::save(path, id.titleId, state);
        return reply;
    }
} // namespace services
