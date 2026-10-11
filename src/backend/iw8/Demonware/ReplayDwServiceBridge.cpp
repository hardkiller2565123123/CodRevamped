#include "ReplayDwServiceBridge.h"

#include "../ReplayDW/src/Core/platform.h"
#include "../ReplayDW/src/Core/services.h"
#include "../ReplayDW/src/Core/wire.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <filesystem>
#include <limits>
#include <mutex>

namespace revamped::iw8::demonware
{
    namespace
    {
        std::once_flag g_replayDwInit;
        bool g_replayDwReady = false;
        platform::LobbyIdentity g_localIdentity{};

        void AppendLe32(std::vector<std::uint8_t>& out, std::uint32_t value)
        {
            out.push_back(static_cast<std::uint8_t>(value));
            out.push_back(static_cast<std::uint8_t>(value >> 8));
            out.push_back(static_cast<std::uint8_t>(value >> 16));
            out.push_back(static_cast<std::uint8_t>(value >> 24));
        }

        std::filesystem::path RuntimeDirectory()
        {
            wchar_t path[MAX_PATH]{};
            const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
            if (!length || length >= MAX_PATH)
                return std::filesystem::current_path() / L"ReplayDWData";
            return std::filesystem::path(path).parent_path() / L"ReplayDWData";
        }

        void InitializeReplayDw()
        {
            try
            {
                const auto root = RuntimeDirectory();
                std::filesystem::create_directories(root);

                // The imported backend owns only persistent service state here.
                // CodRevamped still owns sockets, TLS, BGS, Auth3 and LSG crypto.
                platform::initialize(root);
                services::initialize(root);
                g_localIdentity = platform::localIdentity(5800u);
                g_replayDwReady = true;
            }
            catch (...)
            {
                g_replayDwReady = false;
            }
        }
    }

    bool TryBuildReplayDwTaskReply(std::uint8_t serviceId,
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

        try
        {
            const std::span<const std::uint8_t> payload(
                requestPayloadBytes ? requestPayload : nullptr,
                requestPayloadBytes);
            wire::Reader reader{payload};
            auto reply = services::dispatch(g_localIdentity, serviceId, taskId, reader, true);

            // 108 is ReplayDW's explicit "service/task unavailable" result. Do
            // not turn unknown contracts into fake success replies.
            if (reply.error == 108u &&
                (reply.operation.find("unimplemented") != std::string::npos ||
                 reply.operation.find("unsupported") != std::string::npos ||
                 reply.operation == "service-unimplemented"))
                return false;

            if (operation)
                *operation = reply.operation;

            auto serviceReply = services::taskReply(transactionId, taskId, reply);
            if (serviceReply.size() > (std::numeric_limits<std::uint32_t>::max)())
                return false;

            // Match CodRevamped's existing decrypted TASK_REPLY body:
            // LE32 body size, 0x87, typed DW response, AES block padding.
            AppendLe32(replyPlain, static_cast<std::uint32_t>(serviceReply.size()));
            replyPlain.push_back(0x87u);
            replyPlain.insert(replyPlain.end(), serviceReply.begin(), serviceReply.end());
            replyPlain.resize((replyPlain.size() + 15u) & ~static_cast<std::size_t>(15u), 0u);
            return true;
        }
        catch (...)
        {
            replyPlain.clear();
            return false;
        }
    }
}
