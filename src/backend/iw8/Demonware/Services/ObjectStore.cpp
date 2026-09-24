#include "ObjectStore.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        std::int64_t UnixTimeSeconds()
        {
            return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        }

        std::string BuildObjectStoreMetadataJson(const StoredObjectStoreObject& object)
        {
            std::string json = "{";
            json += "\"name\":\"" + JsonEscape(object.name) + "\",";
            json += "\"owner\":\"" + JsonEscape(object.owner) + "\",";
            json += "\"checksum\":\"" + JsonEscape(object.checksum) + "\",";
            json += "\"objectVersion\":\"" + JsonEscape(object.objectVersion) + "\",";
            json += "\"expiresOn\":" + std::to_string(object.expiresOn) + ",";
            json += "\"created\":" + std::to_string(object.created) + ",";
            json += "\"modified\":" + std::to_string(object.modified) + ",";
            json += "\"acl\":\"" + JsonEscape(object.acl) + "\",";
            json += "\"contentLength\":" + std::to_string(object.contentLength) + ",";
            json += "\"context\":\"" + JsonEscape(object.context) + "\",";
            if (object.category.empty())
                json += "\"category\":null";
            else
                json += "\"category\":\"" + JsonEscape(object.category) + "\"";
            json += "}";
            return json;
        }

        std::string BuildObjectStoreObjectJson(const StoredObjectStoreObject& object)
        {
            return std::string("{\"content\":\"") + JsonEscape(object.contentBase64) +
                "\",\"metadata\":" + object.metadataJson + "}";
        }

        bool ParseObjectStoreUploadObject(const std::string& objectJson, const std::string& url,
            const StoredObjectStoreObject* existing, StoredObjectStoreObject& stored)
        {
            std::string metadata;
            if (!ExtractJsonCompositeField(objectJson, "metadata", '{', '}', metadata))
                return false;

            std::string owner;
            std::string name;
            if (!ExtractJsonStringField(metadata, "owner", owner) ||
                !ExtractJsonStringField(metadata, "name", name))
            {
                // Some SDK serializers place the ID next to metadata. Accept that
                // stock-compatible form but never invent an owner/name.
                if (!ExtractJsonStringField(objectJson, "owner", owner) ||
                    !ExtractJsonStringField(objectJson, "name", name))
                    return false;
            }

            std::string content;
            if (!ExtractJsonStringField(objectJson, "content", content))
                return false;

            stored = {};
            stored.owner = owner;
            stored.name = name;
            stored.contentBase64 = content;

            ExtractJsonStringField(metadata, "checksum", stored.checksum);
            ExtractJsonStringField(metadata, "objectVersion", stored.objectVersion);
            ExtractJsonStringField(metadata, "context", stored.context);
            ExtractJsonStringField(metadata, "acl", stored.acl);
            ExtractJsonStringField(metadata, "category", stored.category);
            ExtractJsonInt64Field(metadata, "expiresOn", stored.expiresOn);
            ExtractJsonUInt64Field(metadata, "contentLength", stored.contentLength);

            if (stored.context.empty())
            {
                std::string queryContext;
                if (ExtractQueryParam(url, "context", queryContext))
                    stored.context = queryContext;
            }
            if (stored.context.empty())
                stored.context = "cod-shared";
            if (stored.acl.empty())
                stored.acl = "private";
            if (!stored.contentLength)
                stored.contentLength = Base64DecodedLength(stored.contentBase64);
            if (stored.checksum.empty())
                stored.checksum = StableDigest32(stored.contentBase64);

            const std::string versionMaterial = stored.owner + std::string(1, '\0') + stored.name +
                std::string(1, '\0') + stored.checksum + std::string(1, '\0') + stored.contentBase64;
            const std::string generatedVersion = StableDigest32(versionMaterial);

            const std::int64_t now = UnixTimeSeconds();
            if (existing && existing->contentBase64 == stored.contentBase64 && existing->checksum == stored.checksum)
            {
                stored.objectVersion = existing->objectVersion;
                stored.created = existing->created;
                stored.modified = existing->modified;
                if (stored.expiresOn == 0)
                    stored.expiresOn = existing->expiresOn;
            }
            else
            {
                stored.objectVersion = generatedVersion;
                stored.created = existing ? existing->created : now;
                stored.modified = now;
            }

            stored.metadataJson = BuildObjectStoreMetadataJson(stored);
            stored.objectJson = BuildObjectStoreObjectJson(stored);
            return true;
        }

        std::string BuildObjectStoreValidationToken(const StoredObjectStoreObject& object)
        {
            // Validation tokens are opaque to the IW8 client. The stock client only
            // base64-decodes and forwards them; the backend owns their meaning. Use a
            // deterministic local token bound to owner/name/version/checksum so later
            // validation can be implemented without capture replay or guessed bytes.
            const std::string raw = "RV-IW8-OBJVAL-1|" + object.owner + "|" + object.name + "|" +
                object.objectVersion + "|" + object.checksum;
            return Base64Encode(raw);
        }

        bool ParseObjectIdJson(const std::string& json,
            std::vector<std::pair<std::string, std::string>>& objectIds)
        {
            objectIds.clear();
            std::size_t pos = 0;
            SkipJsonWhitespace(json, pos);
            if (pos >= json.size() || json[pos] != '[')
                return false;

            ++pos;
            while (pos < json.size())
            {
                while (pos < json.size() && (IsJsonWhitespace(json[pos]) || json[pos] == ','))
                    ++pos;
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
                            escaped = false;
                        else if (c == '\\')
                            escaped = true;
                        else if (c == '"')
                            inString = false;
                        continue;
                    }
                    if (c == '"')
                    {
                        inString = true;
                        continue;
                    }
                    if (c == '{')
                        ++depth;
                    else if (c == '}')
                    {
                        --depth;
                        if (depth == 0)
                        {
                            ++pos;
                            break;
                        }
                    }
                }
                if (depth != 0)
                    return false;

                const std::string object = json.substr(start, pos - start);
                std::string name;
                std::string owner;
                if (!ExtractJsonStringField(object, "name", name) ||
                    !ExtractJsonStringField(object, "owner", owner))
                    return false;
                objectIds.emplace_back(std::move(owner), std::move(name));
            }
            return false;
        }

        bool ExtractObjectStoreIds(const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
            std::vector<std::pair<std::string, std::string>>& objectIds)
        {
            objectIds.clear();
            const std::uint8_t* body = nullptr;
            std::size_t bodyBytes = 0;
            if (!ExtractTypedStructBody(requestPayload, requestPayloadBytes, body, bodyBytes))
                return false;

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
                const std::uint8_t* hend = field.bytes + field.bytesSize;
                while (hcur < hend)
                {
                    PbField headerField{};
                    if (!NextPbField(hcur, hend, headerField))
                        return false;
                    if (headerField.wireType != 2u)
                        continue;
                    if (headerField.tag == 1u)
                        key.assign(reinterpret_cast<const char*>(headerField.bytes), headerField.bytesSize);
                    else if (headerField.tag == 2u)
                        value.assign(reinterpret_cast<const char*>(headerField.bytes), headerField.bytesSize);
                }

                if (key == "DW-Objectstore-ObjectIDs")
                    return ParseObjectIdJson(value, objectIds);
            }
            return false;
        }

        std::string AddRequestIndexToJsonObject(const std::string& object, std::size_t requestIndex)
        {
            std::size_t pos = 0;
            SkipJsonWhitespace(object, pos);
            if (pos >= object.size() || object[pos] != '{')
                return {};

            std::string out;
            out.reserve(object.size() + 40u);
            out.append(object, 0u, pos + 1u);
            out += "\"requestIndex\":" + std::to_string(requestIndex);
            std::size_t next = pos + 1u;
            SkipJsonWhitespace(object, next);
            if (next < object.size() && object[next] != '}')
                out.push_back(',');
            out.append(object, pos + 1u, std::string::npos);
            return out;
        }

        void AppendRestProxyJsonStruct(std::vector<std::uint8_t>& serviceReply, const std::string& json)
        {
            std::vector<std::uint8_t> responseBody;
            std::vector<std::uint8_t> contentLengthHeader;
            AppendPbString(contentLengthHeader, 1u, "Content-Length");
            AppendPbString(contentLengthHeader, 2u, std::to_string(json.size()));
            AppendPbObject(responseBody, 1u, contentLengthHeader);

            std::vector<std::uint8_t> contentTypeHeader;
            AppendPbString(contentTypeHeader, 1u, "Content-Type");
            AppendPbString(contentTypeHeader, 2u, "application/json");
            AppendPbObject(responseBody, 1u, contentTypeHeader);

            AppendPbU64(responseBody, 2u, kHttpOk);
            AppendPbString(responseBody, 3u, json);
            AppendTypedStruct(serviceReply, responseBody);
        }

        bool AppendObjectStoreVectorizedStruct(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::vector<std::pair<std::string, std::string>> objectIds;
            if (!ExtractObjectStoreIds(requestPayload, requestPayloadBytes, objectIds))
                return false;

            std::vector<std::string> objectReplies;
            std::vector<std::string> errorReplies;
            std::size_t persistedCount = 0;
            {
                std::lock_guard<std::mutex> lock(g_objectStoreMutex);
                objectReplies.reserve(objectIds.size());
                errorReplies.reserve(objectIds.size());
                for (std::size_t i = 0; i < objectIds.size(); ++i)
                {
                    const auto it = g_objectStoreObjects.find(ObjectStoreKey(objectIds[i].first, objectIds[i].second));
                    if (it != g_objectStoreObjects.end())
                    {
                        std::string object = AddRequestIndexToJsonObject(it->second.objectJson, i);
                        if (!object.empty())
                        {
                            objectReplies.emplace_back(std::move(object));
                            continue;
                        }
                    }

                    // Vectorized GET requires exactly one entry across objects+errors
                    // for each requested slot, keyed by requestIndex.
                    errorReplies.emplace_back(
                        "{\"requestIndex\":" + std::to_string(i) +
                        ",\"owner\":\"" + JsonEscape(objectIds[i].first) +
                        "\",\"name\":\"" + JsonEscape(objectIds[i].second) +
                        "\",\"error\":\"Error:ClientError:NotFound\"}");
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

            std::printf("[DW-OBJECTSTORE] GET requested=%zu hit=%zu miss=%zu persisted=%zu canonicalMetadata=yes\n",
                objectIds.size(), objectReplies.size(), errorReplies.size(), persistedCount);
            AppendRestProxyJsonStruct(serviceReply, json);
            return true;
        }

        bool AppendObjectStoreUploadVectorizedStruct(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::string method;
            std::string url;
            std::string requestJson;
            if (!ExtractHttpProxyJsonBody(requestPayload, requestPayloadBytes, method, url, requestJson) ||
                method != "PUT" || requestJson.empty())
                return false;

            std::vector<std::string> uploadedObjects;
            if (!ExtractJsonObjectArray(requestJson, "objects", uploadedObjects) || uploadedObjects.empty())
                return false;

            const bool validationRequested = url.find("validationToken") != std::string::npos ||
                ContainsAscii(requestPayload, requestPayloadBytes, "validationToken");
            std::vector<StoredObjectStoreObject> storedObjects;
            storedObjects.reserve(uploadedObjects.size());
            std::size_t persistedCount = 0;
            {
                std::lock_guard<std::mutex> lock(g_objectStoreMutex);
                for (const std::string& objectJson : uploadedObjects)
                {
                    std::string metadataJson;
                    if (!ExtractJsonCompositeField(objectJson, "metadata", '{', '}', metadataJson))
                        return false;

                    std::string owner;
                    std::string name;
                    if (!ExtractJsonStringField(metadataJson, "owner", owner) ||
                        !ExtractJsonStringField(metadataJson, "name", name))
                    {
                        if (!ExtractJsonStringField(objectJson, "owner", owner) ||
                            !ExtractJsonStringField(objectJson, "name", name))
                            return false;
                    }

                    const auto key = ObjectStoreKey(owner, name);
                    const auto existingIt = g_objectStoreObjects.find(key);
                    const StoredObjectStoreObject* existing = existingIt == g_objectStoreObjects.end()
                        ? nullptr : &existingIt->second;

                    StoredObjectStoreObject stored;
                    if (!ParseObjectStoreUploadObject(objectJson, url, existing, stored))
                        return false;
                    g_objectStoreObjects[key] = stored;
                    storedObjects.emplace_back(std::move(stored));
                }
                persistedCount = g_objectStoreObjects.size();
            }

            std::string json = "{\"objects\":[";
            for (std::size_t i = 0; i < storedObjects.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += "{\"metadata\":" + storedObjects[i].metadataJson + "}";
            }
            json += "],\"errors\":[],\"validationTokens\":[";
            if (validationRequested)
            {
                for (std::size_t i = 0; i < storedObjects.size(); ++i)
                {
                    if (i)
                        json.push_back(',');
                    json += "{\"owner\":\"" + JsonEscape(storedObjects[i].owner) +
                        "\",\"name\":\"" + JsonEscape(storedObjects[i].name) +
                        "\",\"validationToken\":\"" + JsonEscape(BuildObjectStoreValidationToken(storedObjects[i])) + "\"}";
                }
            }
            json += "]}";

            std::printf("[DW-OBJECTSTORE] PUT objects=%zu stored=%zu persisted=%zu metadata=%zu validationTokens=%zu\n",
                uploadedObjects.size(), storedObjects.size(), persistedCount, storedObjects.size(),
                validationRequested ? storedObjects.size() : 0u);

            AppendRestProxyJsonStruct(serviceReply, json);
            return true;
        }
    }
}
