#include "ReplayDwServiceBridge.h"
#include "Replay120MatchmakingCatalog.h"

#include "../ReplayDW/src/Core/lobby.h"
#include "../ReplayDW/src/Core/platform.h"
#include "../ReplayDW/src/Core/services.h"
#include "../ReplayDW/src/Core/wire.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <cstdio>
#include <limits>
#include <map>
#include <mutex>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace revamped::iw8::demonware
{
    namespace
    {
        std::once_flag g_replayDwInit;
        bool g_replayDwReady = false;
        platform::LobbyIdentity g_localIdentity{};

        std::mutex g_bridgeMutex;
        std::map<std::uint64_t, platform::LobbyIdentity> g_hostedClients;

        struct PendingPostReply
        {
            std::uint32_t title = 0;
            std::uint64_t connection = 0;
            std::vector<wire::Bytes> directPushes;
            std::vector<services::Delivery> deliveries;
        };

        std::map<std::pair<std::uint64_t, std::uint64_t>, PendingPostReply>
            g_pendingPostReplies;

        constexpr std::uint64_t HostedConnectionKey(std::uint64_t clientId)
        {
            return 0x8000000000000000ull | clientId;
        }

        void AppendLe32(std::vector<std::uint8_t>& out, std::uint32_t value)
        {
            out.push_back(static_cast<std::uint8_t>(value));
            out.push_back(static_cast<std::uint8_t>(value >> 8));
            out.push_back(static_cast<std::uint8_t>(value >> 16));
            out.push_back(static_cast<std::uint8_t>(value >> 24));
        }

        std::uint32_t ReadLe32(const std::uint8_t* data)
        {
            return static_cast<std::uint32_t>(data[0]) |
                (static_cast<std::uint32_t>(data[1]) << 8u) |
                (static_cast<std::uint32_t>(data[2]) << 16u) |
                (static_cast<std::uint32_t>(data[3]) << 24u);
        }

        std::uint64_t ReadLe64(const std::uint8_t* data)
        {
            std::uint64_t value = 0;
            for (unsigned i = 0; i < 8; ++i)
                value |= static_cast<std::uint64_t>(data[i]) << (i * 8u);
            return value;
        }

        std::uint64_t ReadBits(
            std::span<const std::uint8_t> bytes,
            std::size_t& position,
            unsigned count)
        {
            if (count > 64 || position + count > bytes.size() * 8u)
                throw std::runtime_error("hosted LSG auth bitstream is truncated");
            std::uint64_t value = 0;
            for (unsigned i = 0; i < count; ++i)
                value |= static_cast<std::uint64_t>(
                             (bytes[(position + i) / 8u] >>
                              ((position + i) % 8u)) &
                             1u)
                         << i;
            position += count;
            return value;
        }

        std::filesystem::path RuntimeDirectory()
        {
            wchar_t path[MAX_PATH]{};
            const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
            if (!length || length >= MAX_PATH)
                return std::filesystem::current_path() / L"ReplayDWData";
            return std::filesystem::path(path).parent_path() / L"ReplayDWData";
        }

        // The built-in TU19 playlist definitions must be visible to the
        // authoritative ReplayDW matchmaker.  Previously they existed in a
        // header but were never installed into the service's data directory;
        // "startSearch" could only return a fake success with no lobby.
        // Do not overwrite an operator-supplied catalog.
        void EnsureReplay120PlaylistCatalog(const std::filesystem::path& root)
        {
            const auto directory = root / L"playlists" / L"5800";
            const auto path = directory / L"catalog.json";
            if (std::filesystem::exists(path))
            {
                if (!std::filesystem::is_regular_file(path))
                    throw std::runtime_error("ReplayDW playlist catalog path is not a file");
                std::printf("[DW-MM120-CATALOG] source=existing path=%ls\n", path.c_str());
                return;
            }

            std::filesystem::create_directories(directory);
            const auto pending = directory / L"catalog.json.pending";
            const auto& bytes = matchmaking_catalog_120::CatalogStorage;
            {
                std::ofstream output(pending, std::ios::binary | std::ios::trunc);
                if (!output.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !output.flush())
                    throw std::runtime_error("Failed writing TU19 playlist catalog");
            }
            // Races/restarts must never replace a manually configured catalog.
            if (std::filesystem::exists(path))
            {
                std::filesystem::remove(pending);
                return;
            }
            if (!MoveFileExW(pending.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH))
            {
                std::filesystem::remove(pending);
                if (!std::filesystem::is_regular_file(path))
                    throw std::runtime_error("Failed to publish TU19 playlist catalog");
            }
            std::printf("[DW-MM120-CATALOG] source=built-in-tu19 playlists=%u "
                        "gametypes=%u bytes=%zu path=%ls\n",
                        matchmaking_catalog_120::PlaylistCount,
                        matchmaking_catalog_120::GametypeCount,
                        bytes.size(), path.c_str());
        }

        void InitializeReplayDw()
        {
            try
            {
                const auto root = RuntimeDirectory();
                std::filesystem::create_directories(root);
                platform::initialize(root);
                services::initialize(root);
                EnsureReplay120PlaylistCatalog(root);
                g_localIdentity = platform::localIdentity(5800u);
                g_replayDwReady = true;
            }
            catch (const std::exception& error)
            {
                std::printf("[DW-MM120-INIT] ready=no reason=%s\n", error.what());
                g_replayDwReady = false;
            }
            catch (...)
            {
                std::printf("[DW-MM120-INIT] ready=no reason=unknown\n");
                g_replayDwReady = false;
            }
        }

        bool ParseHostedIdentity(
            const std::uint8_t* authFrame,
            std::size_t authFrameBytes,
            platform::LobbyIdentity& identity,
            std::string& detail)
        {
            if (!authFrame || authFrameBytes != 153u ||
                ReadLe32(authFrame) != 149u ||
                authFrame[4] != 0xABu ||
                authFrame[5] != 0x82u)
            {
                detail = "native-0x82-shape-invalid";
                return false;
            }

            try
            {
                const std::span<const std::uint8_t> blob(authFrame + 6u, 139u);
                std::size_t bit = 0;
                if (ReadBits(blob, bit, 8) != 7u ||
                    ReadBits(blob, bit, 1) != 1u ||
                    ReadBits(blob, bit, 5) != 8u)
                {
                    detail = "native-0x82-prefix-invalid";
                    return false;
                }

                const auto title = static_cast<std::uint32_t>(ReadBits(blob, bit, 32));
                if (ReadBits(blob, bit, 5) != 8u)
                {
                    detail = "native-0x82-title-type-invalid";
                    return false;
                }
                const auto seed = static_cast<std::uint32_t>(ReadBits(blob, bit, 32));

                std::array<std::uint8_t, 128> ticket{};
                for (auto& value : ticket)
                    value = static_cast<std::uint8_t>(ReadBits(blob, bit, 8));
                if (ReadBits(blob, bit, 5) != 0u)
                {
                    detail = "native-0x82-tail-invalid";
                    return false;
                }

                constexpr std::uint32_t kTicketMagic = 0xEFBDADDEu;
                const std::uint32_t ticketTitle = ReadLe32(ticket.data() + 5u);
                const std::uint32_t expires = ReadLe32(ticket.data() + 13u);
                const std::uint64_t user = ReadLe64(ticket.data() + 25u);
                const auto now = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count());

                if (ReadLe32(ticket.data()) != kTicketMagic ||
                    !title || ticketTitle != title ||
                    !user || user == UINT64_MAX ||
                    expires <= now)
                {
                    detail = "native-auth3-ticket-invalid";
                    return false;
                }

                identity = {};
                identity.titleId = title;
                identity.ivSeed = seed;
                identity.userId = user;
                identity.expires = expires;
                identity.platformAccountId =
                    static_cast<std::uint32_t>(user) | 1u;
                std::copy_n(ticket.data() + 97u, identity.key.size(), identity.key.begin());
                if (std::none_of(
                        identity.key.begin(),
                        identity.key.end(),
                        [](std::uint8_t value)
                        {
                            return value != 0;
                        }))
                {
                    detail = "native-auth3-session-key-empty";
                    return false;
                }

                std::size_t nameLength = 0;
                while (nameLength < 64u && ticket[33u + nameLength])
                    ++nameLength;
                identity.name.assign(
                    reinterpret_cast<const char*>(ticket.data() + 33u),
                    nameLength);
                if (identity.name.empty())
                    identity.name = "RevampedPlayer";

                detail = "native-auth3-ticket";
                return true;
            }
            catch (...)
            {
                detail = "native-0x82-parse-failed";
                return false;
            }
        }
    }

    bool RegisterReplayDwLobbyClient(
        std::uint64_t clientId,
        const std::uint8_t* authFrame,
        std::size_t authFrameBytes,
        ReplayDwPushWriter writer,
        std::string* detail)
    {
        std::call_once(g_replayDwInit, InitializeReplayDw);
        if (!g_replayDwReady || !clientId || !writer)
        {
            if (detail)
                *detail = "replaydw-not-ready";
            return false;
        }

        platform::LobbyIdentity identity;
        std::string parsed;
        if (!ParseHostedIdentity(authFrame, authFrameBytes, identity, parsed))
        {
            if (detail)
                *detail = parsed;
            return false;
        }

        UnregisterReplayDwLobbyClient(clientId);

        try
        {
            platform::rememberHostedAccount(identity.userId, identity.name);
            lobby::registerHostedConnection(
                HostedConnectionKey(clientId),
                identity,
                std::move(writer));

            {
                std::lock_guard lock(g_bridgeMutex);
                g_hostedClients[clientId] = identity;
            }

            if (detail)
                *detail = parsed + " user=" + std::to_string(identity.userId) +
                          " title=" + std::to_string(identity.titleId);
            return true;
        }
        catch (...)
        {
            lobby::unregisterHostedConnection(HostedConnectionKey(clientId));
            if (detail)
                *detail = "replaydw-hosted-registration-failed";
            return false;
        }
    }

    void UnregisterReplayDwLobbyClient(std::uint64_t clientId)
    {
        {
            std::lock_guard lock(g_bridgeMutex);
            g_hostedClients.erase(clientId);
            for (auto it = g_pendingPostReplies.begin();
                 it != g_pendingPostReplies.end();)
            {
                if (it->first.first == clientId)
                    it = g_pendingPostReplies.erase(it);
                else
                    ++it;
            }
        }
        lobby::unregisterHostedConnection(HostedConnectionKey(clientId));
    }

    bool TryBuildReplayDwTaskReply(
        std::uint64_t clientId,
        std::uint8_t serviceId,
        std::uint8_t taskId,
        const std::uint8_t* requestPayload,
        std::size_t requestPayloadBytes,
        std::uint64_t transactionId,
        std::vector<std::uint8_t>& replyPlain,
        std::string* operation)
    {
        replyPlain.clear();
        if (requestPayloadBytes && !requestPayload)
            return false;

        std::call_once(g_replayDwInit, InitializeReplayDw);
        if (!g_replayDwReady)
            return false;

        platform::LobbyIdentity identity;
        bool hosted = false;
        {
            std::lock_guard lock(g_bridgeMutex);
            const auto found = g_hostedClients.find(clientId);
            if (found != g_hostedClients.end())
            {
                identity = found->second;
                hosted = true;
            }
            else
            {
                identity = g_localIdentity;
            }
        }

        try
        {
            const std::span<const std::uint8_t> payload(
                requestPayloadBytes ? requestPayload : nullptr,
                requestPayloadBytes);
            wire::Reader reader{payload};
            auto reply = services::dispatch(identity, serviceId, taskId, reader, true);
            if (serviceId == 145u && (taskId == 2u || taskId == 3u || taskId == 18u))
            {
                std::printf("[DW-MM120-NATIVE] task=%u source=ReplayDW result=%u "
                            "operation=%s rows=%zu notifications=%zu\n",
                            static_cast<unsigned>(taskId), reply.error,
                            reply.operation.c_str(), reply.results.size(),
                            reply.pushes.size() + reply.deliveries.size());
            }

            if (reply.error == 108u &&
                (reply.operation.find("unimplemented") != std::string::npos ||
                 reply.operation.find("unsupported") != std::string::npos ||
                 reply.operation == "service-unimplemented"))
                return false;

            if (operation)
                *operation = reply.operation;

            auto serviceReply = services::taskReply(transactionId, taskId, reply);
            if (serviceReply.size() >
                (std::numeric_limits<std::uint32_t>::max)())
                return false;

            AppendLe32(replyPlain, static_cast<std::uint32_t>(serviceReply.size()));
            replyPlain.push_back(0x01u);
            replyPlain.insert(
                replyPlain.end(), serviceReply.begin(), serviceReply.end());
            replyPlain.resize(
                (replyPlain.size() + 15u) & ~static_cast<std::size_t>(15u),
                0u);

            const auto pendingKey = std::make_pair(clientId, transactionId);
            {
                std::lock_guard lock(g_bridgeMutex);
                g_pendingPostReplies.erase(pendingKey);
                if (hosted &&
                    (!reply.pushes.empty() || !reply.deliveries.empty()))
                {
                    PendingPostReply pending;
                    pending.title = identity.titleId;
                    pending.connection = HostedConnectionKey(clientId);
                    pending.directPushes = std::move(reply.pushes);
                    pending.deliveries = std::move(reply.deliveries);
                    g_pendingPostReplies.emplace(
                        pendingKey, std::move(pending));
                }
            }
            return true;
        }
        catch (const std::exception& error)
        {
            if (serviceId == 145u)
                std::printf("[DW-MM120-NATIVE] task=%u source=ReplayDW "
                            "dispatch=FAILED reason=%s\n",
                            static_cast<unsigned>(taskId), error.what());
            replyPlain.clear();
            return false;
        }
        catch (...)
        {
            if (serviceId == 145u)
                std::printf("[DW-MM120-NATIVE] task=%u source=ReplayDW "
                            "dispatch=FAILED reason=unknown\n",
                            static_cast<unsigned>(taskId));
            replyPlain.clear();
            return false;
        }
    }

    void PublishReplayDwPostReply(
        std::uint64_t clientId,
        std::uint64_t transactionId)
    {
        PendingPostReply pending;
        {
            std::lock_guard lock(g_bridgeMutex);
            const auto key = std::make_pair(clientId, transactionId);
            const auto found = g_pendingPostReplies.find(key);
            if (found == g_pendingPostReplies.end())
                return;
            pending = std::move(found->second);
            g_pendingPostReplies.erase(found);
        }

        for (const auto& push : pending.directPushes)
            lobby::publishHostedPush(
                pending.connection,
                std::span<const std::uint8_t>(push.data(), push.size()));

        if (!pending.deliveries.empty())
            lobby::publishOperatorUpdates(
                pending.title,
                std::span<const services::Delivery>(
                    pending.deliveries.data(), pending.deliveries.size()));
    }
}
