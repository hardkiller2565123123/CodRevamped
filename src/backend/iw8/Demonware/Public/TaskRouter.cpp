#include "TaskRouter.h"

namespace revamped::iw8::demonware
{
    TaskRequest DecodeTaskRequest(const std::vector<std::uint8_t>& plain)
    {
        TaskRequest request{};
        if (plain.size() < 8u)
        {
            request.error = "plaintext shorter than Demonware typed task header";
            return request;
        }

        request.declaredBytes = ReadLe32(plain.data());
        request.innerType = plain[4];
        request.serviceId = plain[5];
        request.taskTypeTag = plain[6];
        request.taskId = plain[7];
        request.payloadOffset = 8u;

        if (request.innerType != kTaskRequestType)
        {
            request.error = "inner message is not TASK_REQUEST (0x86)";
            return request;
        }
        if (request.taskTypeTag != kBbUnsignedChar8)
        {
            request.error = "task id is not encoded as bdByteBuffer typed U8 (0x03)";
            return request;
        }
        if (request.declaredBytes < 3u)
        {
            request.error = "declared task size is smaller than service/type/task header";
            return request;
        }

        const std::size_t availableTaskBody = plain.size() - 5u;
        if (request.declaredBytes > availableTaskBody)
        {
            request.error = "declared task size exceeds decrypted plaintext";
            return request;
        }

        request.payloadBytes = static_cast<std::size_t>(request.declaredBytes - 3u);
        if (request.payloadBytes > plain.size() - request.payloadOffset)
        {
            request.error = "decoded parameter size exceeds decrypted plaintext";
            return request;
        }

        request.valid = true;
        return request;
    }

    const TaskRoute* FindTaskRoute(std::uint8_t serviceId, std::uint8_t taskId)
    {
        for (const auto& route : kRoutes)
        {
            if (route.serviceId == serviceId && route.taskId == taskId)
                return &route;
        }
        return nullptr;
    }

    std::string DescribeTaskRequest(const TaskRequest& request)
    {
        char buffer[384]{};
        const TaskRoute* route = request.valid ? FindTaskRoute(request.serviceId, request.taskId) : nullptr;
        if (!request.valid)
        {
            std::snprintf(buffer, sizeof(buffer),
                "valid=0 innerType=0x%02X service=%u taskType=0x%02X task=%u declared=%u error=%s",
                static_cast<unsigned>(request.innerType), static_cast<unsigned>(request.serviceId),
                static_cast<unsigned>(request.taskTypeTag), static_cast<unsigned>(request.taskId),
                request.declaredBytes, request.error.empty() ? "unknown" : request.error.c_str());
        }
        else
        {
            std::snprintf(buffer, sizeof(buffer),
                "valid=1 innerType=0x%02X service=%u(%s) taskType=0x%02X task=%u(%s) declared=%u payloadBytes=%llu",
                static_cast<unsigned>(request.innerType), static_cast<unsigned>(request.serviceId),
                route && route->serviceName ? route->serviceName : "unknown",
                static_cast<unsigned>(request.taskTypeTag), static_cast<unsigned>(request.taskId),
                route && route->taskName ? route->taskName : "unknown",
                request.declaredBytes, static_cast<unsigned long long>(request.payloadBytes));
        }
        return buffer;
    }

    bool BuildTaskReply(const TaskRoute& route, const TaskRequest& request,
        const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
        std::uint64_t transactionId, std::vector<std::uint8_t>& replyPlain)
    {
        replyPlain.clear();
        if (!request.valid || request.serviceId != route.serviceId || request.taskId != route.taskId)
            return false;
        if (requestPayloadBytes && !requestPayload)
            return false;

        std::vector<std::uint8_t> serviceReply;
        serviceReply.reserve(route.replyPolicy == ReplyPolicy::StructPublisherVariables ||
            route.replyPolicy == ReplyPolicy::StructObjectStoreVectorized ||
            route.replyPolicy == ReplyPolicy::StructObjectStoreUploadVectorized ? 1024u : 256u);

        AppendTypedU64(serviceReply, transactionId);
        AppendTypedU32(serviceReply, 0u); // BD_NO_ERROR
        AppendTypedU8(serviceReply, request.taskId);

        switch (route.replyPolicy)
        {
        case ReplyPolicy::NoResultSuccess:
            AppendTypedU32(serviceReply, 0u);
            break;

        case ReplyPolicy::LegacyDmlInfo:
            AppendLegacyDmlInfo(serviceReply);
            break;

        case ReplyPolicy::LegacyServerTime:
            AppendLegacyServerTime(serviceReply);
            break;

        case ReplyPolicy::StructMarketingMessagesEmpty:
        {
            // bdCommsGetMessagesResponse repeatedly reads bdCommsMessage objects
            // at StructBuffer tag 1 until TAG_NOT_FOUND. A local account with no
            // marketing inbox therefore has a canonical empty StructBuffer body.
            const std::vector<std::uint8_t> emptyBody;
            AppendTypedStruct(serviceReply, emptyBody);
            break;
        }

        case ReplyPolicy::StructClanMembershipsEmpty:
        {
            // bdClansGetMembershipsByUsersResponse reads an object array at tag 1.
            // Zero memberships is encoded by omitting tag 1 entirely.
            const std::vector<std::uint8_t> emptyBody;
            AppendTypedStruct(serviceReply, emptyBody);
            break;
        }

        case ReplyPolicy::StructMessagingUnsubscribeAck:
        {
            // channelUnsubscribeFromCategory is started with no bound response
            // object in stock IW8. Keep the struct-task acknowledgement empty
            // rather than routing it through a generic payload builder.
            const std::vector<std::uint8_t> emptyBody;
            AppendTypedStruct(serviceReply, emptyBody);
            break;
        }

        case ReplyPolicy::StructClanGroupInfosEmpty:
        {
            // Stock IW8 deserializes bdClansGetGroupInfosResponse with
            // readObjectArray<bdClansGroupInfo>(tag=1). Repeated fields encode a
            // zero-length array by omitting tag 1 entirely, so the canonical
            // fresh/local-account response body is an empty StructBuffer.
            const std::vector<std::uint8_t> emptyBody;
            AppendTypedStruct(serviceReply, emptyBody);
            break;
        }

        case ReplyPolicy::StructClanProposalsEmpty:
        {
            std::vector<std::uint8_t> body;
            AppendPbString(body, 2u, ""); // required nextPageToken; no tag-1 proposals
            AppendTypedStruct(serviceReply, body);
            break;
        }

        case ReplyPolicy::StructPublisherVariables:
            if (!AppendPublisherVariablesStruct(serviceReply, requestPayload, requestPayloadBytes))
                return false;
            break;

        case ReplyPolicy::StructObjectStoreVectorized:
            if (!AppendObjectStoreVectorizedStruct(serviceReply, requestPayload, requestPayloadBytes))
                return false;
            break;

        case ReplyPolicy::StructObjectStoreUploadVectorized:
            if (!AppendObjectStoreUploadVectorizedStruct(serviceReply, requestPayload, requestPayloadBytes))
                return false;
            break;

        case ReplyPolicy::StructAchievementsUserState:
            if (!AppendAchievementsUserStateStruct(serviceReply, requestPayload, requestPayloadBytes))
                return false;
            break;

        case ReplyPolicy::RestJsonSuccess:
            if (!AppendRestJsonResult(serviceReply, requestPayload, requestPayloadBytes, transactionId))
                return false;
            break;

        case ReplyPolicy::None:
        default:
            return false;
        }

        if (serviceReply.size() > (std::numeric_limits<std::uint32_t>::max)())
            return false;

        AppendLe32(replyPlain, static_cast<std::uint32_t>(serviceReply.size()));
        replyPlain.push_back(kTaskReplyType);
        replyPlain.insert(replyPlain.end(), serviceReply.begin(), serviceReply.end());
        replyPlain.resize((replyPlain.size() + 15u) & ~static_cast<std::size_t>(15u), 0u);
        return true;
    }
}
