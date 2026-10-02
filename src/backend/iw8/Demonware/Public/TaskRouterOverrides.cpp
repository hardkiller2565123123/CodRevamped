namespace revamped::iw8::demonware
{
    namespace
    {
        // MW2019's frontend networking bootstrap uses the async matchmaking
        // service for datacenter/relay discovery. The local preservation
        // backend deliberately advertises no physical Demonware relay: task 16
        // returns a valid empty datacenter preference array, task 24 returns a
        // minimal local datacenter label, and tasks 25/26 use stock error/fallback
        // paths instead of inventing unreachable relay/QoS credentials.
        constexpr TaskRoute kDataCenterPreferencesRoute = {
            145u, 16u, "bdAsyncMatchMaking", "getDataCenterPreferences",
            ReplyPolicy::NoResultSuccess
        };
        constexpr TaskRoute kPreferredServerDetailsRoute = {
            145u, 24u, "bdAsyncMatchMaking", "getPreferredServerDetails",
            ReplyPolicy::NoResultSuccess
        };
        constexpr TaskRoute kInitiateDcQosRoute = {
            145u, 25u, "bdAsyncMatchMaking", "initiateDCQoS",
            ReplyPolicy::NoResultSuccess
        };
        constexpr TaskRoute kRelayClientAuthTokenRoute = {
            145u, 26u, "bdAsyncMatchMaking", "getRelayClientAuthToken",
            ReplyPolicy::NoResultSuccess
        };
        // Stock qosHostsReply writes UInt64 transaction, UInt64 result count,
        // followed by probe records. Only the empty local inventory is supported.
        constexpr TaskRoute kEmptyDcQosReplyRoute = {
            145u, 4u, "bdAsyncMatchMaking", "qosHostsReply",
            ReplyPolicy::NoResultSuccess
        };

        // bdBandwidthTestClient::start uses bdRemoteTaskManager::startLSGTask,
        // whose request header is raw service/task bytes rather than the normal
        // typed-U8 task id. Returning a normal remote-task failure causes the
        // stock Online_BandwidthTest::Frame fallback to select default bandwidth
        // and mark the bandwidth fence complete.
        constexpr TaskRoute kBandwidthTestRoute = {
            18u, 1u, "bdBandwidthTestClient", "startLSGTask",
            ReplyPolicy::NoResultSuccess
        };

        constexpr TaskRoute kPublisherObjectRoute = {
            193u, 8u, "bdObjectStore", "getPublisherObject",
            ReplyPolicy::StructObjectStoreVectorized
        };

        constexpr TaskRoute kPublisherObjectsRoute = {
            193u, 16u, "bdObjectStore", "getPublisherObjects",
            ReplyPolicy::StructObjectStoreVectorized
        };

        // OpenIW8's stock 1.20 client maps service 4/task 14 to
        // bdStats::writeServerValidatedStats.  The request is a single
        // bdValidationTokenResult blob and the call binds no result object, so
        // the protocol-native success reply is the standard zero-result legacy
        // completion rather than an invented payload.
        constexpr TaskRoute kServerValidatedStatsRoute = {
            4u, 14u, "bdStats", "writeServerValidatedStats",
            ReplyPolicy::NoResultSuccess
        };


        // Stock OpenIW8 maps service 4/task 1 to bdStats::writeStats.
        // writeStats serializes one or more bdStatsInfo records and starts the
        // remote task without binding a result object. For the local backend,
        // accepting the write therefore uses the normal zero-result success
        // completion rather than an invented payload.
        constexpr TaskRoute kWriteStatsRoute = {
            4u, 1u, "bdStats", "writeStats",
            ReplyPolicy::NoResultSuccess
        };

        // The loadout-validation fence is service 80/task 58.  The stock
        // client binds one bdValidationTokenResult, whose deserializer reads a
        // single legacy bdByteBuffer blob.  For the local backend the incoming
        // ObjectStore validation token is already backend-owned, so successful
        // validation returns that same opaque token dynamically.
        constexpr TaskRoute kValidateInventoryItemsTokenRoute = {
            80u, 58u, "bdMarketplace", "validateInventoryItemsToken",
            ReplyPolicy::NoResultSuccess
        };


        // OpenIW8 maps service 50/task 2 to
        // bdContentStreaming::listFilesByOwner. The request binds an array of
        // bdFileMetaData results (up to maxNumResults). A fresh/local account
        // with no user-published files is represented by a successful task with
        // zero results; existing Demonware preservation clients use the same
        // empty-success contract.
        constexpr TaskRoute kContentStreamingListFilesByOwnerRoute = {
            50u, 2u, "bdContentStreaming", "listFilesByOwner",
            ReplyPolicy::NoResultSuccess
        };

        constexpr const char* kCanonicalStartupStatsOwner = "bnet-1";
        constexpr const char* kCanonicalStartupStatsNames[6] = {
            "commondata",
            "mpdata",
            "cpdata",
            "rankedloadouts",
            "privateloadouts",
            "nongamedata"
        };

        const TaskRoute* FindRuntimeOverrideRoute(std::uint8_t serviceId, std::uint8_t taskId)
        {
            static constexpr TaskRoute inventory = {80u, 69u, "bdMarketplace", "getInventoryItemInfo", ReplyPolicy::NoResultSuccess};
            if (serviceId == 80u && taskId == 69u)
                return &inventory;
            if (serviceId == 145u && taskId == 16u)
                return &kDataCenterPreferencesRoute;
            if (serviceId == 145u && taskId == 24u)
                return &kPreferredServerDetailsRoute;
            if (serviceId == 145u && taskId == 25u)
                return &kInitiateDcQosRoute;
            if (serviceId == 145u && taskId == 26u)
                return &kRelayClientAuthTokenRoute;
            if (serviceId == 145u && taskId == 4u)
                return &kEmptyDcQosReplyRoute;

            if (serviceId == 18u && taskId == 1u)
                return &kBandwidthTestRoute;

            if (serviceId == 193u)
            {
                if (taskId == 8u)
                    return &kPublisherObjectRoute;
                if (taskId == 16u)
                    return &kPublisherObjectsRoute;
            }

            if (serviceId == 4u && taskId == 14u)
                return &kServerValidatedStatsRoute;

            if (serviceId == 4u && taskId == 1u)
                return &kWriteStatsRoute;

            if (serviceId == 80u && taskId == 58u)
                return &kValidateInventoryItemsTokenRoute;

            if (serviceId == 50u && taskId == 2u)
                return &kContentStreamingListFilesByOwnerRoute;

            return nullptr;
        }

        bool BuildLegacyTaskEnvelope(
            std::vector<std::uint8_t>& serviceReply,
            std::uint64_t transactionId,
            std::uint8_t taskId)
        {
            serviceReply.clear();
            serviceReply.reserve(256u);
            AppendTypedU64(serviceReply, transactionId);
            AppendTypedU32(serviceReply, 0u); // BD_NO_ERROR
            AppendTypedU8(serviceReply, taskId);
            return true;
        }

        bool FinishLegacyTaskReply(
            const std::vector<std::uint8_t>& serviceReply,
            std::vector<std::uint8_t>& replyPlain)
        {
            if (serviceReply.size() >
                (std::numeric_limits<std::uint32_t>::max)())
            {
                return false;
            }

            replyPlain.clear();
            AppendLe32(
                replyPlain,
                static_cast<std::uint32_t>(serviceReply.size()));
            replyPlain.push_back(kTaskReplyType);
            replyPlain.insert(
                replyPlain.end(),
                serviceReply.begin(),
                serviceReply.end());
            replyPlain.resize(
                (replyPlain.size() + 15u) &
                    ~static_cast<std::size_t>(15u),
                0u);
            return true;
        }

        bool ReadLegacyCString(
            const std::uint8_t* payload,
            std::size_t payloadBytes,
            std::size_t& cursor,
            std::string& value)
        {
            value.clear();
            if (!payload || cursor >= payloadBytes ||
                payload[cursor] != kBbString)
            {
                return false;
            }

            ++cursor;
            const std::size_t start = cursor;
            while (cursor < payloadBytes && payload[cursor] != 0u)
                ++cursor;
            if (cursor >= payloadBytes)
                return false;

            value.assign(
                reinterpret_cast<const char*>(payload + start),
                cursor - start);
            ++cursor; // NUL
            return true;
        }

        bool ReadLegacyBlob(
            const std::uint8_t* payload,
            std::size_t payloadBytes,
            std::size_t& cursor,
            std::vector<std::uint8_t>& value)
        {
            value.clear();
            if (!payload || cursor >= payloadBytes ||
                payload[cursor] != kBbBlob)
            {
                return false;
            }

            ++cursor;
            if (cursor + 5u > payloadBytes ||
                payload[cursor] != kBbUnsignedInteger32)
            {
                return false;
            }

            ++cursor;
            const std::uint32_t bytes = ReadLe32(payload + cursor);
            cursor += 4u;

            if (bytes > payloadBytes - cursor)
                return false;

            value.assign(payload + cursor, payload + cursor + bytes);
            cursor += bytes;
            return true;
        }

        bool BuildServerValidatedStatsWriteReply(
            const TaskRequest& request,
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes,
            std::uint64_t transactionId,
            std::vector<std::uint8_t>& replyPlain)
        {
            std::size_t cursor = 0u;
            std::vector<std::uint8_t> validationToken;
            if (!ReadLegacyBlob(
                    requestPayload, requestPayloadBytes, cursor,
                    validationToken) ||
                validationToken.empty())
            {
                return false;
            }

            std::vector<std::uint8_t> serviceReply;
            BuildLegacyTaskEnvelope(
                serviceReply, transactionId, request.taskId);

            // writeServerValidatedStats binds no result object.
            AppendTypedU32(serviceReply, 0u);

            std::printf(
                "[DW-STATS] service=4 task=14 writeServerValidatedStats tokenBytes=%zu accepted response=no-result-success\n",
                validationToken.size());
            return FinishLegacyTaskReply(serviceReply, replyPlain);
        }

        bool BuildValidateInventoryItemsTokenReply(
            const TaskRequest& request,
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes,
            std::uint64_t transactionId,
            std::vector<std::uint8_t>& replyPlain)
        {
            std::size_t cursor = 0u;
            std::string context;
            std::string filename;
            std::vector<std::uint8_t> validationToken;

            if (!ReadLegacyCString(
                    requestPayload, requestPayloadBytes, cursor, context) ||
                !ReadLegacyCString(
                    requestPayload, requestPayloadBytes, cursor, filename) ||
                !ReadLegacyBlob(
                    requestPayload, requestPayloadBytes, cursor,
                    validationToken) ||
                validationToken.empty())
            {
                return false;
            }

            std::vector<std::uint8_t> serviceReply;
            BuildLegacyTaskEnvelope(
                serviceReply, transactionId, request.taskId);

            // Legacy bdRemoteTask result envelope: one result / one total
            // result, followed by bdValidationTokenResult::deserialize(), which
            // reads exactly one typed blob.
            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, 1u);
            AppendTypedBlob(
                serviceReply,
                validationToken.data(),
                validationToken.size());

            std::printf(
                "[DW-MARKETPLACE] service=80 task=58 validateInventoryItemsToken context=%s filename=%s tokenBytes=%zu response=local-token-accepted\n",
                context.c_str(),
                filename.c_str(),
                validationToken.size());

            return FinishLegacyTaskReply(serviceReply, replyPlain);
        }

        bool AllObjectStoreIdsBlank(
            const std::vector<std::pair<std::string, std::string>>& objectIds)
        {
            if (objectIds.empty())
                return false;

            for (const auto& objectId : objectIds)
            {
                if (!objectId.first.empty() || !objectId.second.empty())
                    return false;
            }
            return true;
        }

        bool ExtractObjectStoreRequestHeaderJson(
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes,
            std::string& rawObjectIdsJson)
        {
            rawObjectIdsJson.clear();

            const std::uint8_t* body = nullptr;
            std::size_t bodyBytes = 0;
            if (!ExtractTypedStructBody(
                    requestPayload,
                    requestPayloadBytes,
                    body,
                    bodyBytes))
            {
                return false;
            }

            const std::uint8_t* cursor = body;
            const std::uint8_t* end = body + bodyBytes;
            while (cursor < end)
            {
                PbField field{};
                if (!NextPbField(cursor, end, field))
                    return false;

                if (field.tag != 4u || field.wireType != 2u)
                    continue;

                std::string key;
                std::string value;

                const std::uint8_t* hcur = field.bytes;
                const std::uint8_t* hend =
                    field.bytes + field.bytesSize;

                while (hcur < hend)
                {
                    PbField headerField{};
                    if (!NextPbField(hcur, hend, headerField))
                        return false;

                    if (headerField.wireType != 2u)
                        continue;

                    if (headerField.tag == 1u)
                    {
                        key.assign(
                            reinterpret_cast<const char*>(
                                headerField.bytes),
                            headerField.bytesSize);
                    }
                    else if (headerField.tag == 2u)
                    {
                        value.assign(
                            reinterpret_cast<const char*>(
                                headerField.bytes),
                            headerField.bytesSize);
                    }
                }

                if (key == "DW-Objectstore-ObjectIDs")
                {
                    rawObjectIdsJson = std::move(value);
                    return true;
                }
            }

            return false;
        }

        bool SplitTopLevelJsonArrayObjects(
            const std::string& json,
            std::vector<std::string>& objects)
        {
            objects.clear();

            std::size_t pos = 0u;
            SkipJsonWhitespace(json, pos);
            if (pos >= json.size() || json[pos] != '[')
                return false;

            ++pos;
            for (;;)
            {
                while (pos < json.size() &&
                    (IsJsonWhitespace(json[pos]) ||
                     json[pos] == ','))
                {
                    ++pos;
                }

                if (pos >= json.size())
                    return false;

                if (json[pos] == ']')
                    return true;

                if (json[pos] != '{')
                    return false;

                const std::size_t start = pos;
                bool inString = false;
                bool escaped = false;
                int depth = 0;

                for (; pos < json.size(); ++pos)
                {
                    const char c = json[pos];

                    if (inString)
                    {
                        if (escaped)
                        {
                            escaped = false;
                        }
                        else if (c == '\\')
                        {
                            escaped = true;
                        }
                        else if (c == '"')
                        {
                            inString = false;
                        }
                        continue;
                    }

                    if (c == '"')
                    {
                        inString = true;
                        continue;
                    }

                    if (c == '{')
                    {
                        ++depth;
                    }
                    else if (c == '}')
                    {
                        --depth;
                        if (depth == 0)
                        {
                            ++pos;
                            objects.emplace_back(
                                json.substr(start, pos - start));
                            break;
                        }
                    }
                }

                if (depth != 0)
                    return false;
            }
        }

        std::string FullHexString(
            const std::uint8_t* data,
            std::size_t bytes)
        {
            if (!data || !bytes)
                return {};

            static constexpr char digits[] =
                "0123456789ABCDEF";

            std::string out;
            out.reserve(bytes * 3u);

            for (std::size_t i = 0; i < bytes; ++i)
            {
                if (i)
                    out.push_back(' ');

                out.push_back(digits[(data[i] >> 4u) & 0x0Fu]);
                out.push_back(digits[data[i] & 0x0Fu]);
            }

            return out;
        }

        void LogBlankObjectStoreRequestDetails(
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes,
            std::size_t parsedCount)
        {
            std::string method;
            std::string url;
            std::string unusedBody;
            const bool haveProxy =
                ExtractHttpProxyJsonBody(
                    requestPayload,
                    requestPayloadBytes,
                    method,
                    url,
                    unusedBody);

            std::string rawObjectIdsJson;
            const bool haveRawHeader =
                ExtractObjectStoreRequestHeaderJson(
                    requestPayload,
                    requestPayloadBytes,
                    rawObjectIdsJson);

            std::printf(
                "[DW-OBJECTSTORE-DEBUG] blank-id request payloadBytes=%zu parsedCount=%zu method=%s url=%s rawHeaderPresent=%s\n",
                requestPayloadBytes,
                parsedCount,
                haveProxy && !method.empty()
                    ? method.c_str()
                    : "<unparsed>",
                haveProxy && !url.empty()
                    ? url.c_str()
                    : "<unparsed>",
                haveRawHeader ? "yes" : "no");

            if (haveRawHeader)
            {
                std::printf(
                    "[DW-OBJECTSTORE-DEBUG] DW-Objectstore-ObjectIDs=%s\n",
                    rawObjectIdsJson.c_str());

                std::vector<std::string> rawObjects;
                if (SplitTopLevelJsonArrayObjects(
                        rawObjectIdsJson,
                        rawObjects))
                {
                    for (std::size_t i = 0;
                         i < rawObjects.size();
                         ++i)
                    {
                        std::string owner;
                        std::string name;
                        std::string objectVersion;
                        std::string checksum;

                        const bool hasOwner =
                            ExtractJsonStringField(
                                rawObjects[i],
                                "owner",
                                owner);
                        const bool hasName =
                            ExtractJsonStringField(
                                rawObjects[i],
                                "name",
                                name);
                        const bool hasVersion =
                            ExtractJsonStringField(
                                rawObjects[i],
                                "objectVersion",
                                objectVersion);
                        const bool hasChecksum =
                            ExtractJsonStringField(
                                rawObjects[i],
                                "checksum",
                                checksum);

                        std::printf(
                            "[DW-OBJECTSTORE-DEBUG] object[%zu] owner=%s name=%s objectVersion=%s checksum=%s raw=%s\n",
                            i,
                            hasOwner
                                ? owner.c_str()
                                : "<missing>",
                            hasName
                                ? name.c_str()
                                : "<missing>",
                            hasVersion
                                ? objectVersion.c_str()
                                : "<missing>",
                            hasChecksum
                                ? checksum.c_str()
                                : "<missing>",
                            rawObjects[i].c_str());
                    }
                }
                else
                {
                    std::printf(
                        "[DW-OBJECTSTORE-DEBUG] raw header JSON array parse failed\n");
                }
            }

            const std::string fullHex =
                FullHexString(
                    requestPayload,
                    requestPayloadBytes);

            std::printf(
                "[DW-OBJECTSTORE-DEBUG] fullPayloadHex={%s}\n",
                fullHex.c_str());
        }

        bool AppendBlankObjectStoreNotFoundStruct(
            std::vector<std::uint8_t>& serviceReply,
            const std::vector<std::pair<std::string, std::string>>& objectIds)
        {
            std::string json = "{\"objects\":[],\"errors\":[";
            for (std::size_t i = 0; i < objectIds.size(); ++i)
            {
                if (i)
                    json.push_back(',');

                json += "{\"requestIndex\":" + std::to_string(i) +
                    ",\"owner\":\"" + JsonEscape(objectIds[i].first) +
                    "\",\"name\":\"" + JsonEscape(objectIds[i].second) +
                    "\",\"error\":\"" + kObjectStoreNotFoundError + "\"}";
            }
            json += "]}";

            AppendRestProxyJsonStruct(serviceReply, json);
            return true;
        }

        bool AppendCanonicalStartupStatsGetStruct(
            std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes)
        {
            std::vector<std::pair<std::string, std::string>> objectIds;
            if (!ExtractObjectStoreIds(requestPayload, requestPayloadBytes, objectIds) ||
                !AllObjectStoreIdsBlank(objectIds))
            {
                return false;
            }

            // IW8 1.20 has a second broken stats path that serializes a
            // single cache-aware ObjectStore ID as {"name":"","owner":""}.
            // The observed matching single-object PUT is always the commondata
            // payload (98 bytes in the captured run), so resolve this one-item
            // compatibility path to the same canonical commondata object used
            // by the six-file startup bundle.
            if (objectIds.size() == 1u)
            {
                const std::string owner = kCanonicalStartupStatsOwner;
                const std::string name = kCanonicalStartupStatsNames[0];

                std::string objectReply;
                std::size_t persistedCount = 0;
                {
                    std::lock_guard<std::mutex> lock(g_objectStoreMutex);
                    const auto it =
                        g_objectStoreObjects.find(ObjectStoreKey(owner, name));

                    if (it != g_objectStoreObjects.end())
                    {
                        objectReply =
                            AddRequestIndexToJsonObject(it->second.objectJson, 0u);
                    }

                    persistedCount = g_objectStoreObjects.size();
                }

                LogBlankObjectStoreRequestDetails(
                    requestPayload,
                    requestPayloadBytes,
                    objectIds.size());

                if (!objectReply.empty())
                {
                    const std::string json =
                        "{\"objects\":[" + objectReply + "],\"errors\":[]}";

                    std::printf(
                        "[DW-OBJECTSTORE] GET service=0xC1 task=6 blankIds=1 canonicalized=yes mapped=bnet-1/commondata hit=1 persisted=%zu response=success\n",
                        persistedCount);

                    AppendRestProxyJsonStruct(serviceReply, json);
                    return true;
                }

                std::printf(
                    "[DW-OBJECTSTORE] GET service=0xC1 task=6 blankIds=1 canonicalized=yes mapped=bnet-1/commondata hit=0 persisted=%zu response=notfound\n",
                    persistedCount);

                std::vector<std::pair<std::string, std::string>> canonicalId{
                    {owner, name}
                };
                return AppendBlankObjectStoreNotFoundStruct(
                    serviceReply,
                    canonicalId);
            }

            // Keep all other unexpected partial blank-ID shapes conservative.
            if (objectIds.size() != 6u)
            {
                LogBlankObjectStoreRequestDetails(
                    requestPayload,
                    requestPayloadBytes,
                    objectIds.size());

                std::printf(
                    "[DW-OBJECTSTORE] GET service=0xC1 task=6 blankIds=%zu response=notfound-safe-fallback diagnostic=full-request-captured\n",
                    objectIds.size());
                return AppendBlankObjectStoreNotFoundStruct(
                    serviceReply,
                    objectIds);
            }

            std::vector<std::string> objectReplies;
            std::vector<std::string> errorReplies;
            objectReplies.reserve(6u);
            errorReplies.reserve(6u);

            std::size_t persistedCount = 0;
            {
                std::lock_guard<std::mutex> lock(g_objectStoreMutex);
                for (std::size_t i = 0; i < 6u; ++i)
                {
                    const std::string owner = kCanonicalStartupStatsOwner;
                    const std::string name = kCanonicalStartupStatsNames[i];
                    const auto it = g_objectStoreObjects.find(ObjectStoreKey(owner, name));

                    if (it != g_objectStoreObjects.end())
                    {
                        std::string object =
                            AddRequestIndexToJsonObject(it->second.objectJson, i);
                        if (!object.empty())
                        {
                            objectReplies.emplace_back(std::move(object));
                            continue;
                        }
                    }

                    errorReplies.emplace_back(
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"owner\":\"" + JsonEscape(owner) +
                        "\",\"name\":\"" + JsonEscape(name) +
                        "\",\"error\":\"" + kObjectStoreNotFoundError + "\"}");
                }
                persistedCount = g_objectStoreObjects.size();
            }

            std::string json = "{\"objects\":[";
            for (std::size_t i = 0; i < objectReplies.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += objectReplies[i];
            }
            json += "],\"errors\":[";
            for (std::size_t i = 0; i < errorReplies.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += errorReplies[i];
            }
            json += "]}";

            std::printf(
                "[DW-OBJECTSTORE] GET service=0xC1 task=6 startupStats canonicalized=yes requested=6 hit=%zu miss=%zu persisted=%zu names={commondata,mpdata,cpdata,rankedloadouts,privateloadouts,nongamedata}\n",
                objectReplies.size(), errorReplies.size(), persistedCount);

            if (errorReplies.size() == 6u)
            {
                std::printf(
                    "[DW-OBJECTSTORE] IW8 startup stats requested=6 missing=6 freshDefaultPath=armed canonicalized=yes\n");
            }

            AppendRestProxyJsonStruct(serviceReply, json);
            return true;
        }

        bool ExtractUploadObjectId(
            const std::string& objectJson,
            std::string& owner,
            std::string& name)
        {
            owner.clear();
            name.clear();

            std::string metadataJson;
            if (!ExtractJsonCompositeField(
                    objectJson, "metadata", '{', '}', metadataJson))
            {
                return false;
            }

            if (!ExtractJsonStringField(metadataJson, "owner", owner) ||
                !ExtractJsonStringField(metadataJson, "name", name))
            {
                if (!ExtractJsonStringField(objectJson, "owner", owner) ||
                    !ExtractJsonStringField(objectJson, "name", name))
                {
                    return false;
                }
            }

            return true;
        }

        bool AppendCanonicalStartupStatsUploadStruct(
            std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes)
        {
            std::string method;
            std::string url;
            std::string requestJson;
            if (!ExtractHttpProxyJsonBody(
                    requestPayload, requestPayloadBytes, method, url, requestJson) ||
                method != "PUT" || requestJson.empty())
            {
                return false;
            }

            std::vector<std::string> uploadedObjects;
            if (!ExtractJsonObjectArray(
                    requestJson, "objects", uploadedObjects) ||
                (uploadedObjects.size() != 1u &&
                 uploadedObjects.size() != 6u))
            {
                return false;
            }

            // Only claim the compatibility path when every serialized ID is
            // genuinely blank. Normal/newer builds with valid IDs continue
            // through the generic ObjectStore implementation untouched.
            for (const std::string& objectJson : uploadedObjects)
            {
                std::string owner;
                std::string name;
                if (!ExtractUploadObjectId(objectJson, owner, name) ||
                    !owner.empty() || !name.empty())
                {
                    return false;
                }
            }

            const bool singleCommonDataCompat =
                uploadedObjects.size() == 1u;

            const bool validationRequested =
                url.find("validationToken") != std::string::npos ||
                ContainsAscii(
                    requestPayload, requestPayloadBytes, "validationToken");

            std::vector<StoredObjectStoreObject> storedObjects;
            storedObjects.reserve(uploadedObjects.size());

            std::size_t persistedCount = 0;
            {
                std::lock_guard<std::mutex> lock(g_objectStoreMutex);

                for (std::size_t i = 0; i < uploadedObjects.size(); ++i)
                {
                    const std::string owner = kCanonicalStartupStatsOwner;
                    const std::string name =
                        singleCommonDataCompat
                            ? kCanonicalStartupStatsNames[0]
                            : kCanonicalStartupStatsNames[i];
                    const auto key = ObjectStoreKey(owner, name);

                    const auto existingIt = g_objectStoreObjects.find(key);
                    const StoredObjectStoreObject* existing =
                        existingIt == g_objectStoreObjects.end()
                            ? nullptr
                            : &existingIt->second;

                    StoredObjectStoreObject stored;
                    if (!ParseObjectStoreUploadObject(
                            uploadedObjects[i], url, existing, stored))
                    {
                        return false;
                    }

                    const bool sameAsExisting =
                        existing &&
                        existing->contentBase64 == stored.contentBase64 &&
                        existing->checksum == stored.checksum;

                    stored.owner = owner;
                    stored.name = name;

                    if (!sameAsExisting)
                    {
                        const std::string versionMaterial =
                            stored.owner + std::string(1, '\0') +
                            stored.name + std::string(1, '\0') +
                            stored.checksum + std::string(1, '\0') +
                            stored.contentBase64;
                        stored.objectVersion =
                            StableDigest32(versionMaterial);
                    }

                    stored.metadataJson =
                        BuildObjectStoreMetadataJson(stored);
                    stored.objectJson =
                        BuildObjectStoreObjectJson(stored);

                    g_objectStoreObjects[key] = stored;
                    storedObjects.emplace_back(std::move(stored));

                    std::printf(
                        "[DW-OBJECTSTORE] PUT startupStats object[%zu] canonicalized=yes mode=%s owner=%s name=%s contentLength=%llu replacing=%s\n",
                        i,
                        singleCommonDataCompat
                            ? "single-commondata"
                            : "six-file-startup",
                        owner.c_str(),
                        name.c_str(),
                        static_cast<unsigned long long>(
                            storedObjects.back().contentLength),
                        existing ? "yes" : "no");
                }

                persistedCount = g_objectStoreObjects.size();
            }

            std::string json = "{\"objects\":[";
            for (std::size_t i = 0; i < storedObjects.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += "{\"metadata\":" +
                    storedObjects[i].metadataJson + "}";
            }

            json += "],\"errors\":[],\"validationTokens\":[";
            if (validationRequested)
            {
                for (std::size_t i = 0; i < storedObjects.size(); ++i)
                {
                    if (i)
                        json.push_back(',');

                    json += "{\"owner\":\"" +
                        JsonEscape(storedObjects[i].owner) +
                        "\",\"name\":\"" +
                        JsonEscape(storedObjects[i].name) +
                        "\",\"validationToken\":\"" +
                        JsonEscape(
                            BuildObjectStoreValidationToken(
                                storedObjects[i])) +
                        "\"}";
                }
            }
            json += "]}";

            std::printf(
                "[DW-OBJECTSTORE] PUT startupStats objects=%zu stored=%zu canonicalized=yes mode=%s persisted=%zu validationTokens=%zu\n",
                uploadedObjects.size(),
                storedObjects.size(),
                singleCommonDataCompat
                    ? "single-commondata"
                    : "six-file-startup",
                persistedCount,
                validationRequested ? storedObjects.size() : 0u);

            AppendRestProxyJsonStruct(serviceReply, json);
            return true;
        }

        bool BuildCustomObjectStoreTaskReply(
            const TaskRoute& route,
            const TaskRequest& request,
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes,
            std::uint64_t transactionId,
            std::vector<std::uint8_t>& replyPlain)
        {
            if (route.serviceId != 193u)
                return false;

            bool customHandled = false;
            std::vector<std::uint8_t> serviceReply;
            serviceReply.reserve(4096u);

            AppendTypedU64(serviceReply, transactionId);
            AppendTypedU32(serviceReply, 0u);
            AppendTypedU8(serviceReply, request.taskId);

            if (route.taskId == 6u)
            {
                customHandled = AppendCanonicalStartupStatsGetStruct(
                    serviceReply, requestPayload, requestPayloadBytes);
            }
            else if (route.taskId == 7u)
            {
                customHandled = AppendCanonicalStartupStatsUploadStruct(
                    serviceReply, requestPayload, requestPayloadBytes);
            }
            else if (route.taskId == 8u)
            {
                customHandled = AppendPublisherObjectStruct(
                    serviceReply, requestPayload, requestPayloadBytes);
            }
            else if (route.taskId == 16u)
            {
                customHandled = AppendPublisherObjectMetadatasStruct(
                    serviceReply, requestPayload, requestPayloadBytes);
            }
            else
            {
                return false;
            }

            if (!customHandled)
                return false;

            if (serviceReply.size() >
                (std::numeric_limits<std::uint32_t>::max)())
            {
                return false;
            }

            replyPlain.clear();
            AppendLe32(
                replyPlain,
                static_cast<std::uint32_t>(serviceReply.size()));
            replyPlain.push_back(kTaskReplyType);
            replyPlain.insert(
                replyPlain.end(),
                serviceReply.begin(),
                serviceReply.end());
            replyPlain.resize(
                (replyPlain.size() + 15u) &
                    ~static_cast<std::size_t>(15u),
                0u);
            return true;
        }
    }

    namespace
    {
        bool BuildIntentionalTaskFailure(
            const TaskRequest& request,
            std::uint64_t transactionId,
            std::uint32_t errorCode,
            const char* label,
            std::vector<std::uint8_t>& replyPlain)
        {
            std::vector<std::uint8_t> serviceReply;
            serviceReply.reserve(64u);
            AppendTypedU64(serviceReply, transactionId);
            AppendTypedU32(serviceReply, errorCode);
            AppendTypedU8(serviceReply, request.taskId);
            // Legacy error replies in this backend repeat the transaction id.
            AppendTypedU64(serviceReply, transactionId);
            std::printf(
                "%s service=%u task=%u transaction=%llu response=error-%u stock-fallback=yes\n",
                label ? label : "[DW-FALLBACK]",
                static_cast<unsigned>(request.serviceId),
                static_cast<unsigned>(request.taskId),
                static_cast<unsigned long long>(transactionId),
                errorCode);
            return FinishLegacyTaskReply(serviceReply, replyPlain);
        }

        bool BuildEmptyDataCenterPreferencesReply(
            const TaskRequest& request,
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes,
            std::uint64_t transactionId,
            std::vector<std::uint8_t>& replyPlain)
        {
            // getDataCenterPreferences writes UInt64 count followed by that many
            // UInt64 user ids. MW2019 1.20 currently sends exactly one id.
            if (!requestPayload || requestPayloadBytes < 18u ||
                requestPayload[0] != kBbUnsignedInteger64)
                return false;

            std::uint64_t count = 0u;
            std::memcpy(&count, requestPayload + 1u, sizeof(count));
            if (count == 0u || count > 200u)
                return false;

            std::size_t cursor = 9u;
            for (std::uint64_t i = 0u; i < count; ++i)
            {
                if (cursor + 9u > requestPayloadBytes ||
                    requestPayload[cursor] != kBbUnsignedInteger64)
                    return false;
                cursor += 9u;
            }
            if (cursor != requestPayloadBytes &&
                !(cursor + 1u == requestPayloadBytes && requestPayload[cursor] == 0u))
                return false;

            std::vector<std::uint8_t> serviceReply;
            BuildLegacyTaskEnvelope(serviceReply, transactionId, request.taskId);
            AppendTypedU32(serviceReply, 1u); // one bdDataCenterPreferences result
            AppendTypedU32(serviceReply, 1u);

            // bdDataCenterPreferences::deserialize calls
            // readArrayStart(BD_BB_STRING_TYPE, ...). writeArrayStart for an
            // empty string array is: raw(type+100), typed UInt32 byte-size=0,
            // raw UInt32 element-count=0. readArrayEnd consumes no bytes.
            serviceReply.push_back(static_cast<std::uint8_t>(kBbString + 100u));
            serviceReply.push_back(kBbUnsignedInteger32);
            AppendLe32(serviceReply, 0u);
            AppendLe32(serviceReply, 0u);

            std::printf(
                "[DW-DCQOS] getDataCenterPreferences users=%llu datacenters=0 response=valid-empty-array\n",
                static_cast<unsigned long long>(count));
            return FinishLegacyTaskReply(serviceReply, replyPlain);
        }

        bool BuildLocalPreferredServerDetailsReply(
            const TaskRequest& request,
            const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes,
            std::uint64_t transactionId,
            std::vector<std::uint8_t>& replyPlain)
        {
            std::size_t cursor = 0u;
            std::string buildName;
            std::string context;
            if (!ReadLegacyCString(requestPayload, requestPayloadBytes, cursor, buildName) ||
                !ReadLegacyCString(requestPayload, requestPayloadBytes, cursor, context) ||
                buildName.empty() || context.empty() ||
                (cursor != requestPayloadBytes &&
                 !(cursor + 1u == requestPayloadBytes && requestPayload[cursor] == 0u)))
                return false;

            // Online_DcQos_FetchRelayServerComplete accepts the relay result as
            // valid when the root JSON contains a datacenter string. Omitting
            // server_info/relay_auth_token intentionally avoids advertising a
            // fake remote relay while still finalizing the QoS result.
            const std::string json =
                "{\"datacenter\":\"bG9jYWw=\"}";

            std::vector<std::uint8_t> serviceReply;
            BuildLegacyTaskEnvelope(serviceReply, transactionId, request.taskId);
            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, 1u);
            AppendTypedString(serviceReply, json);

            std::printf(
                "[DW-DCQOS] getPreferredServerDetails build=%s context=%s datacenter=local relayToken=omitted response=success\n",
                buildName.c_str(), context.c_str());
            return FinishLegacyTaskReply(serviceReply, replyPlain);
        }
    }

    const TaskRoute* FindTaskRoute(std::uint8_t serviceId, std::uint8_t taskId)
    {
        if (const TaskRoute* overrideRoute =
                FindRuntimeOverrideRoute(serviceId, taskId))
        {
            return overrideRoute;
        }
        const TaskRoute* base = FindTaskRoute_Base(serviceId, taskId);
        if (base && base->replyPolicy != ReplyPolicy::None)
            return base;
        // Legacy replies are consumed in task submission order. Omitting an
        // unsupported request's reply misattributes subsequent valid replies.
        thread_local TaskRoute unsupported;
        unsupported = {serviceId, taskId, "unimplemented", "explicitFailure",
            ReplyPolicy::LegacyUnsupported};
        return &unsupported;
    }

    std::string DescribeTaskRequest(const TaskRequest& request)
    {
        char buffer[384]{};
        const TaskRoute* route =
            request.valid
                ? FindTaskRoute(request.serviceId, request.taskId)
                : nullptr;

        if (!request.valid)
        {
            std::snprintf(
                buffer,
                sizeof(buffer),
                "valid=0 innerType=0x%02X service=%u taskType=0x%02X task=%u declared=%u error=%s",
                static_cast<unsigned>(request.innerType),
                static_cast<unsigned>(request.serviceId),
                static_cast<unsigned>(request.taskTypeTag),
                static_cast<unsigned>(request.taskId),
                request.declaredBytes,
                request.error.empty()
                    ? "unknown"
                    : request.error.c_str());
        }
        else
        {
            std::snprintf(
                buffer,
                sizeof(buffer),
                "valid=1 innerType=0x%02X service=%u(%s) taskType=0x%02X task=%u(%s) declared=%u payloadBytes=%llu",
                static_cast<unsigned>(request.innerType),
                static_cast<unsigned>(request.serviceId),
                route && route->serviceName
                    ? route->serviceName
                    : "unknown",
                static_cast<unsigned>(request.taskTypeTag),
                static_cast<unsigned>(request.taskId),
                route && route->taskName
                    ? route->taskName
                    : "unknown",
                request.declaredBytes,
                static_cast<unsigned long long>(
                    request.payloadBytes));
        }

        return buffer;
    }

    bool BuildTaskReply(
        const TaskRoute& route,
        const TaskRequest& request,
        const std::uint8_t* requestPayload,
        std::size_t requestPayloadBytes,
        std::uint64_t transactionId,
        std::vector<std::uint8_t>& replyPlain)
    {
        if (!request.valid ||
            request.serviceId != route.serviceId ||
            request.taskId != route.taskId ||
            (requestPayloadBytes && !requestPayload))
        {
            return false;
        }

        if (route.serviceId == 80u && route.taskId == 69u)
        {
            // 1.20 observed request: context, page token, items-per-page.
            // bdGetInventoryItemInfoResponse: account, context, nextPageToken,
            // repeated items. This single-user local backend owns zero items.
            const std::uint8_t* body = nullptr;
            std::size_t bytes = 0;
            if (!ExtractTypedStructBody(requestPayload, requestPayloadBytes, body, bytes))
                return false;
            const auto* cursor = body;
            const auto* end = body + bytes;
            std::string context;
            bool pagePresent = false;
            std::uint64_t pageSize = 0;
            while (cursor < end)
            {
                PbField field{};
                if (!NextPbField(cursor, end, field)) return false;
                if (field.tag == 1 && field.wireType == 2 && field.bytesSize <= 16)
                    context.assign(reinterpret_cast<const char*>(field.bytes), field.bytesSize);
                else if (field.tag == 2 && field.wireType == 2 && field.bytesSize <= 64)
                    pagePresent = true;
                else if (field.tag == 3 && field.wireType == 0)
                    pageSize = field.varint;
                else if (field.tag != 4 || field.wireType != 0)
                    return false;
            }
            if (context != "5800" || !pagePresent || pageSize == 0 || pageSize > 4096)
                return false;
            std::vector<std::uint8_t> account, response, reply;
            AppendPbU64(account, 1u, 1u);
            AppendPbString(account, 2u, "bnet");
            AppendPbObject(response, 1u, account);
            AppendPbString(response, 2u, context);
            AppendPbString(response, 3u, ""); // terminal page, no item records
            BuildLegacyTaskEnvelope(reply, transactionId, request.taskId);
            AppendTypedStruct(reply, response);
            std::printf("[DW-INVENTORY] context=5800 account=bnet-1 items=0 nextPage=empty\n");
            return FinishLegacyTaskReply(reply, replyPlain);
        }

        if (route.serviceId == 18u && route.taskId == 1u)
        {
            // Raw startLSGTask request. The first byte is request/finalize mode
            // and the rest is an opaque bandwidth-test query. The preservation
            // backend intentionally declines the measurement; the stock client
            // then falls back to its default bandwidth and marks the fence done.
            if (!requestPayload || requestPayloadBytes < 1u)
                return false;
            const unsigned mode = static_cast<unsigned>(requestPayload[0]);
            std::printf(
                "[DW-BANDWIDTH] raw-LSG request mode=%u payloadBytes=%zu action=stock-default-bandwidth-fallback\n",
                mode, requestPayloadBytes);
            return BuildIntentionalTaskFailure(
                request, transactionId, 108u, "[DW-BANDWIDTH]", replyPlain);
        }

        if (route.serviceId == 145u && route.taskId == 16u)
        {
            return BuildEmptyDataCenterPreferencesReply(
                request, requestPayload, requestPayloadBytes,
                transactionId, replyPlain);
        }

        if (route.serviceId == 145u && route.taskId == 24u)
        {
            return BuildLocalPreferredServerDetailsReply(
                request, requestPayload, requestPayloadBytes,
                transactionId, replyPlain);
        }

        if (route.serviceId == 145u && route.taskId == 25u)
        {
            // A successful initiateDCQoS reply with an empty hosts array causes
            // stock IW8 to enter Qos::Probe with no destinations. Returning a
            // normal Demonware service-unavailable error instead exercises the
            // client's existing Online_DcQos_Fail/finalization path, which marks
            // the datacenter result final and lets the fence complete offline.
            return BuildIntentionalTaskFailure(
                request, transactionId, 108u, "[DW-DCQOS]", replyPlain);
        }

        if (route.serviceId == 145u && route.taskId == 26u)
        {
            // Do not fabricate a bdClientAuthToken. NetRelay's stock failure path
            // marks the auth-token attempt finished and then falls back to
            // DW_NET_ERROR_NO_RELAY_SERVER; NET_IsRelayStarted treats the failed
            // relay state as terminal for the relay fence.
            return BuildIntentionalTaskFailure(
                request, transactionId, 108u, "[DW-RELAY]", replyPlain);
        }

        if (route.replyPolicy == ReplyPolicy::LegacyUnsupported)
        {
            std::vector<std::uint8_t> serviceReply;
            AppendTypedU64(serviceReply, transactionId);
            AppendTypedU32(serviceReply, 108u); // BD_SERVICE_NOT_AVAILABLE
            AppendTypedU8(serviceReply, request.taskId);
            AppendTypedU64(serviceReply, transactionId);
            std::printf("[DW-UNIMPLEMENTED] service=%u task=%u transaction=%llu response=error-108 fifo=preserved\n",
                request.serviceId, request.taskId, static_cast<unsigned long long>(transactionId));
            return FinishLegacyTaskReply(serviceReply, replyPlain);
        }

        if (route.serviceId == 145u && route.taskId == 4u)
        {
            if (!requestPayload ||
                (requestPayloadBytes != 18u && requestPayloadBytes != 19u) ||
                requestPayload[0] != kBbUnsignedInteger64 ||
                requestPayload[9] != kBbUnsignedInteger64 ||
                (requestPayloadBytes == 19u && requestPayload[18] != 0u))
                return false;
            std::uint64_t qosTransaction = 0u;
            std::uint64_t resultCount = 0u;
            std::memcpy(&qosTransaction, requestPayload + 1u, sizeof(qosTransaction));
            std::memcpy(&resultCount, requestPayload + 10u, sizeof(resultCount));
            if (!qosTransaction || resultCount != 0u)
                return false; // Do not acknowledge unimplemented probe records.
            std::vector<std::uint8_t> serviceReply;
            BuildLegacyTaskEnvelope(serviceReply, transactionId, request.taskId);
            AppendTypedU32(serviceReply, 0u);
            std::printf("[DW-DCQOS] qosHostsReply qosTransaction=%llu results=0 accepted\n",
                static_cast<unsigned long long>(qosTransaction));
            return FinishLegacyTaskReply(serviceReply, replyPlain);
        }

        // These two post-ObjectStore validation calls are now proven directly
        // from the stock OpenIW8 1.20 client contracts.
        if (route.serviceId == 4u && route.taskId == 14u)
        {
            return BuildServerValidatedStatsWriteReply(
                request,
                requestPayload,
                requestPayloadBytes,
                transactionId,
                replyPlain);
        }

        if (route.serviceId == 80u && route.taskId == 58u)
        {
            return BuildValidateInventoryItemsTokenReply(
                request,
                requestPayload,
                requestPayloadBytes,
                transactionId,
                replyPlain);
        }

        // First try the compatibility-safe ObjectStore shims. They only claim
        // task 6/7 when the client actually serialized blank IDs, and task 8/16
        // for the publisher-object handlers we already proved.
        if (route.serviceId == 193u &&
            (route.taskId == 6u ||
             route.taskId == 7u ||
             route.taskId == 8u ||
             route.taskId == 16u))
        {
            if (BuildCustomObjectStoreTaskReply(
                    route,
                    request,
                    requestPayload,
                    requestPayloadBytes,
                    transactionId,
                    replyPlain))
            {
                return true;
            }

            // Task 8/16 are supplied only by the publisher override. For task
            // 6/7, fall through to the normal implementation when this is a
            // build that has real, nonblank ObjectStore IDs.
            if (route.taskId == 8u || route.taskId == 16u)
                return false;
        }

        if (route.serviceId == 4u && route.taskId == 1u)
        {
            std::printf(
                "[DW-STATS] service=4 task=1 writeStats payloadBytes=%zu accepted response=no-result-success\n",
                requestPayloadBytes);
        }

        if (route.serviceId == 50u && route.taskId == 2u)
        {
            // Request layout proven from stock OpenIW8:
            // UInt64 ownerID, UInt32 startDate, UInt16 maxNumResults,
            // UInt16 offset, UInt16 category, optional String fileName.
            // The caller binds bdFileMetaData[maxNumResults], so zero results
            // is the canonical "no user files" state.
            std::uint64_t ownerId = 0u;
            std::uint32_t startDate = 0u;
            std::uint16_t maxResults = 0u;
            std::uint16_t offset = 0u;
            std::uint16_t category = 0u;

            std::size_t cursor = 0u;
            bool parsed = false;
            if (requestPayload && requestPayloadBytes >= 24u &&
                requestPayload[cursor] == kBbUnsignedInteger64)
            {
                ++cursor;
                if (cursor + 8u <= requestPayloadBytes)
                {
                    std::memcpy(&ownerId, requestPayload + cursor, sizeof(ownerId));
                    cursor += 8u;

                    if (cursor < requestPayloadBytes &&
                        requestPayload[cursor] == kBbUnsignedInteger32)
                    {
                        ++cursor;
                        if (cursor + 4u <= requestPayloadBytes)
                        {
                            startDate = ReadLe32(requestPayload + cursor);
                            cursor += 4u;

                            auto readU16 = [&](std::uint16_t& out) -> bool
                            {
                                if (cursor >= requestPayloadBytes ||
                                    requestPayload[cursor] != kBbUnsignedInteger16)
                                    return false;
                                ++cursor;
                                if (cursor + 2u > requestPayloadBytes)
                                    return false;
                                out = static_cast<std::uint16_t>(
                                    requestPayload[cursor] |
                                    (static_cast<std::uint16_t>(requestPayload[cursor + 1u]) << 8u));
                                cursor += 2u;
                                return true;
                            };

                            parsed =
                                readU16(maxResults) &&
                                readU16(offset) &&
                                readU16(category);
                        }
                    }
                }
            }

            std::printf(
                "[DW-CONTENT] service=50 task=2 listFilesByOwner ownerId=%llu startDate=%u maxResults=%u offset=%u category=%u parsed=%s response=empty-success\n",
                static_cast<unsigned long long>(ownerId),
                static_cast<unsigned>(startDate),
                static_cast<unsigned>(maxResults),
                static_cast<unsigned>(offset),
                static_cast<unsigned>(category),
                parsed ? "yes" : "no");
        }

        return BuildTaskReply_Base(
            route,
            request,
            requestPayload,
            requestPayloadBytes,
            transactionId,
            replyPlain);
    }
}
