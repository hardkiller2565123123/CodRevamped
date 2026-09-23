#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace revamped::iw8::demonware
{
    enum class ReplyPolicy : std::uint8_t
    {
        None = 0,

        // Legacy bdRemoteTask completion for calls which do not bind a task result.
        NoResultSuccess,

        // Legacy bdRemoteTask result shapes.
        LegacyDmlInfo,
        LegacyServerTime,

        // bdStructBufferTask responses. These serialize a typed StructBuffer directly
        // after the common transaction/error/task envelope.
        // Service-specific empty collections/acks. These are not catch-all
        // success payloads: each one maps to the stock response parser contract.
        StructMarketingMessagesEmpty,
        StructClanMembershipsEmpty,
        StructMessagingUnsubscribeAck,
        // bdClansGetGroupInfosResponse: repeated bdClansGroupInfo at StructBuffer tag 1.
        // A fresh local account has zero entries, whose canonical encoding is an empty struct.
        StructClanGroupInfosEmpty,
        StructClanProposalsEmpty,
        StructPublisherVariables,
        StructObjectStoreVectorized,
        StructObjectStoreUploadVectorized,
        StructAchievementsUserState,

        // Demonware REST carried by service 0xFF/task 0x0A.
        RestJsonSuccess,
    };

    struct TaskRequest
    {
        bool valid = false;
        std::uint32_t declaredBytes = 0;
        std::uint8_t innerType = 0;
        std::uint8_t serviceId = 0;
        std::uint8_t taskTypeTag = 0;
        std::uint8_t taskId = 0;
        std::size_t payloadOffset = 0;
        std::size_t payloadBytes = 0;
        std::string error;
    };

    struct TaskRoute
    {
        std::uint8_t serviceId = 0;
        std::uint8_t taskId = 0;
        const char* serviceName = nullptr;
        const char* taskName = nullptr;
        ReplyPolicy replyPolicy = ReplyPolicy::None;
    };

    TaskRequest DecodeTaskRequest(const std::vector<std::uint8_t>& plain);
    const TaskRoute* FindTaskRoute(std::uint8_t serviceId, std::uint8_t taskId);
    std::string DescribeTaskRequest(const TaskRequest& request);

    // Builds the unencrypted Demonware task body carried by the secure 0x85 frame.
    // requestPayload starts immediately after the real task byte. It never includes
    // the service byte or the bdByteBuffer U8 type tag used to encode the task ID.
    bool BuildTaskReply(const TaskRoute& route, const TaskRequest& request,
        const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
        std::uint64_t transactionId, std::vector<std::uint8_t>& replyPlain);
}
