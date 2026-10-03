#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace revamped::iw8::demonware
{

    enum class TaskWireEncoding : std::uint8_t
    {
        Unknown = 0,
        TypedU8,
        RawServiceTask,
    };

    enum class PayloadSchema : std::uint8_t
    {
        Unknown = 0,
        Empty,
        LegacyByteBuffer,
        StructBuffer,
        Opaque,
    };

    enum class TaskSemantic : std::uint8_t
    {
        Generic = 0,
        PublisherVariablesRetrieve,
        RestRequest,
        ProfilesGetPublic,
        ProfilesSetPublic,
        ObjectStoreUserGet,
        ObjectStoreUserUpload,
        ObjectStorePublisherGet,
        ObjectStorePublisherBatchGet,
        PlayerStatsWrite,
        PlayerStatsValidatedWrite,
        DcQos,
        RelayAuth,
    };
    enum class ReplyPolicy : std::uint8_t
    {
        None = 0,
        LegacyUnsupported,

        // Legacy bdRemoteTask completion for calls which do not bind a task result.
        NoResultSuccess,

        // Legacy bdRemoteTask result shapes.
        LegacyDmlInfo,
        LegacyServerTime,

        // bdTitleUtilities::verifyString (service 12 / task 1). The stock
        // bdVerifyString result deserializes exactly one UInt32 where 0 means
        // the supplied string passed verification.
        LegacyVerifyStringClean,

        // bdMail::getMailInfo (service 29 / task 10). The stock call binds an
        // array of bdMailInfo results. A fresh local account has zero messages,
        // represented by numResults=0 and totalNumResults=0.
        LegacyMailInfoEmpty,

        // IW8 1.20 bdPublisherVariables task 1. The request is legacy
        // bdByteBuffer data (context string + namespace string), and the bound
        // result deserializes UInt16/UInt16/String/String rather than the newer
        // StructBuffer object used by later builds.
        LegacyPublisherVariables120,

        // Protocol-native "no public profile yet" bootstrap used by IW8 1.20.
        // This is an error envelope (BD_NO_PROFILE_INFO_EXISTS = 0x320), not
        // a fabricated profile blob; the stock client creates its default DDL.
        LegacyProfileNotFound,

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
        // bdMarketplace::getBalancesV3 (service 80 / task 0xF5).  A fresh
        // local account has no currency rows, whose canonical struct response
        // is an empty StructBuffer.
        StructMarketplaceBalancesEmpty,
        StructObjectStoreVectorized,
        StructObjectStoreUploadVectorized,
        // Publisher-object batch metadata lookup (service 0xC1/task 0x10).
        // For an unavailable local publisher object we return the stock
        // vectorized ObjectStore NotFound shape rather than leaving the task
        // pending forever.
        StructObjectStorePublisherVectorizedNotFound,
        // Legacy bdHTTPProxyResponse used by IW8 AB testing. The response
        // contains HTTP status tag 2 and JSON body tag 3.
        StructABTestingEnrollEmpty,
        // bdAchievementsEngineService::getAchievementStates (service 125 / task 3).
        // A fresh account has no achievement-state rows; the response still
        // carries the required terminal nextPageToken at StructBuffer tag 2.
        StructAchievementStatesEmpty,
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
        TaskWireEncoding wireEncoding = TaskWireEncoding::Unknown;
        PayloadSchema payloadSchema = PayloadSchema::Unknown;
        std::uint64_t shapeFingerprint = 0;
        std::string error;
    };

    struct TaskRoute
    {
        std::uint8_t serviceId = 0;
        std::uint8_t taskId = 0;
        const char* serviceName = nullptr;
        const char* taskName = nullptr;
        ReplyPolicy replyPolicy = ReplyPolicy::None;
        TaskSemantic semantic = TaskSemantic::Generic;
    };

    const char* TaskWireEncodingName(TaskWireEncoding encoding);
    const char* PayloadSchemaName(PayloadSchema schema);
    const char* TaskSemanticName(TaskSemantic semantic);
    void AnalyzeTaskPayload(TaskRequest& request, const std::uint8_t* payload, std::size_t payloadBytes);

    TaskRequest DecodeTaskRequest(const std::vector<std::uint8_t>& plain);
    const TaskRoute* FindTaskRoute(std::uint8_t serviceId, std::uint8_t taskId);
    const TaskRoute* ResolveTaskRoute(const TaskRequest& request,
        const std::uint8_t* requestPayload, std::size_t requestPayloadBytes);
    std::string DescribeTaskRequest(const TaskRequest& request);

    // Builds the unencrypted Demonware task body carried by the secure 0x85 frame.
    // requestPayload starts immediately after the real task byte. It never includes
    // the service byte or the bdByteBuffer U8 type tag used to encode the task ID.
    bool BuildTaskReply(const TaskRoute& route, const TaskRequest& request,
        const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
        std::uint64_t transactionId, std::vector<std::uint8_t>& replyPlain);
}
