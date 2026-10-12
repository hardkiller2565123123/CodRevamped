#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace revamped::iw8::demonware
{
    using ReplayDwPushWriter =
        std::function<bool(std::span<const std::uint8_t>)>;

    bool RegisterReplayDwLobbyClient(
        std::uint64_t clientId,
        const std::uint8_t* authFrame,
        std::size_t authFrameBytes,
        ReplayDwPushWriter writer,
        std::string* detail = nullptr);

    void UnregisterReplayDwLobbyClient(std::uint64_t clientId);

    bool TryBuildReplayDwTaskReply(
        std::uint64_t clientId,
        std::uint8_t serviceId,
        std::uint8_t taskId,
        const std::uint8_t* requestPayload,
        std::size_t requestPayloadBytes,
        std::uint64_t transactionId,
        std::vector<std::uint8_t>& replyPlain,
        std::string* operation = nullptr);

    void PublishReplayDwPostReply(
        std::uint64_t clientId,
        std::uint64_t transactionId);
}
