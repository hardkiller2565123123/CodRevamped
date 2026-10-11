#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace revamped::iw8::demonware
{
    // Fallback into the imported ReplayDW service implementation. The existing
    // CodRevamped transport/TLS/LSG stack remains authoritative; this function
    // only consumes an already-decrypted native DW task and serializes its reply.
    bool TryBuildReplayDwTaskReply(std::uint8_t serviceId,
        std::uint8_t taskId,
        const std::uint8_t* requestPayload,
        std::size_t requestPayloadBytes,
        std::uint64_t transactionId,
        std::vector<std::uint8_t>& replyPlain,
        std::string* operation = nullptr);
}
