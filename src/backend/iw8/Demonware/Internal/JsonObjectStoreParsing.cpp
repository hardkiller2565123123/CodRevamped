#include "JsonObjectStoreParsing.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        std::string JsonEscape(const std::string& value)
        {
            std::string out;
            out.reserve(value.size() + 8u);
            static const char* hex = "0123456789ABCDEF";
            for (unsigned char c : value)
            {
                switch (c)
                {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20u)
                    {
                        out += "\\u00";
                        out.push_back(hex[(c >> 4u) & 0xFu]);
                        out.push_back(hex[c & 0xFu]);
                    }
                    else
                    {
                        out.push_back(static_cast<char>(c));
                    }
                    break;
                }
            }
            return out;
        }

        struct StoredObjectStoreObject
        {
            std::string owner;
            std::string name;
            std::string contentBase64;
            std::string metadataJson;
            std::string objectJson;
            std::string checksum;
            std::string objectVersion;
            std::string context;
            std::string acl;
            std::string category;
            std::uint64_t contentLength = 0;
            std::int64_t expiresOn = 0;
            std::int64_t created = 0;
            std::int64_t modified = 0;
        };

        std::mutex g_objectStoreMutex;
        std::unordered_map<std::string, StoredObjectStoreObject> g_objectStoreObjects;

        std::string ObjectStoreKey(const std::string& owner, const std::string& name)
        {
            return owner + std::string(1, '\0') + name;
        }

        bool IsJsonWhitespace(char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }

        void SkipJsonWhitespace(const std::string& json, std::size_t& pos)
        {
            while (pos < json.size() && IsJsonWhitespace(json[pos]))
                ++pos;
        }

        bool ExtractHttpProxyJsonBody(const std::uint8_t* requestPayload, std::size_t requestPayloadBytes,
            std::string& method, std::string& url, std::string& jsonBody)
        {
            method.clear();
            url.clear();
            jsonBody.clear();

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
                if (field.wireType != 2u)
                    continue;

                const std::string value(reinterpret_cast<const char*>(field.bytes), field.bytesSize);
                if (field.tag == 1u)
                    method = value;
                else if (field.tag == 2u)
                    url = value;
                else if (field.tag == 3u)
                    jsonBody = value;
            }
            return !method.empty() && !url.empty();
        }

        bool ExtractJsonCompositeField(const std::string& json, const char* key,
            char openChar, char closeChar, std::string& value)
        {
            value.clear();
            if (!key || !*key)
                return false;

            const std::string needle = std::string("\"") + key + "\"";
            std::size_t pos = json.find(needle);
            if (pos == std::string::npos)
                return false;
            pos = json.find(':', pos + needle.size());
            if (pos == std::string::npos)
                return false;
            ++pos;
            SkipJsonWhitespace(json, pos);
            if (pos >= json.size() || json[pos] != openChar)
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
                if (c == openChar)
                    ++depth;
                else if (c == closeChar)
                {
                    --depth;
                    if (depth == 0)
                    {
                        ++pos;
                        value.assign(json, start, pos - start);
                        return true;
                    }
                }
            }
            return false;
        }

        bool ExtractJsonObjectArray(const std::string& json, const char* key,
            std::vector<std::string>& objects)
        {
            objects.clear();
            std::string arrayJson;
            if (!ExtractJsonCompositeField(json, key, '[', ']', arrayJson))
                return false;

            std::size_t pos = 1u;
            while (pos + 1u <= arrayJson.size())
            {
                while (pos < arrayJson.size() &&
                    (IsJsonWhitespace(arrayJson[pos]) || arrayJson[pos] == ','))
                    ++pos;
                if (pos >= arrayJson.size() || arrayJson[pos] == ']')
                    return true;
                if (arrayJson[pos] != '{')
                    return false;

                const std::size_t start = pos;
                bool inString = false;
                bool escaped = false;
                int depth = 0;
                for (; pos < arrayJson.size(); ++pos)
                {
                    const char c = arrayJson[pos];
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
                            objects.emplace_back(arrayJson.substr(start, pos - start));
                            break;
                        }
                    }
                }
                if (depth != 0)
                    return false;
            }
            return true;
        }

        bool ExtractJsonStringField(const std::string& object, const char* key, std::string& value)
        {
            value.clear();
            if (!key || !*key)
                return false;

            const std::string needle = std::string("\"") + key + "\"";
            std::size_t pos = object.find(needle);
            if (pos == std::string::npos)
                return false;
            pos = object.find(':', pos + needle.size());
            if (pos == std::string::npos)
                return false;
            ++pos;
            SkipJsonWhitespace(object, pos);
            if (pos >= object.size() || object[pos] != '"')
                return false;
            ++pos;

            while (pos < object.size())
            {
                char c = object[pos++];
                if (c == '"')
                    return true;
                if (c != '\\')
                {
                    value.push_back(c);
                    continue;
                }
                if (pos >= object.size())
                    return false;
                const char e = object[pos++];
                switch (e)
                {
                case '"': value.push_back('"'); break;
                case '\\': value.push_back('\\'); break;
                case '/': value.push_back('/'); break;
                case 'b': value.push_back('\b'); break;
                case 'f': value.push_back('\f'); break;
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                default:
                    // The ObjectStore identifiers/metadata used by IW8 startup are ASCII.
                    return false;
                }
            }
            return false;
        }

        bool ExtractJsonInt64Field(const std::string& object, const char* key, std::int64_t& value)
        {
            value = 0;
            if (!key || !*key)
                return false;
            const std::string needle = std::string("\"") + key + "\"";
            std::size_t pos = object.find(needle);
            if (pos == std::string::npos)
                return false;
            pos = object.find(':', pos + needle.size());
            if (pos == std::string::npos)
                return false;
            ++pos;
            SkipJsonWhitespace(object, pos);
            if (pos >= object.size())
                return false;

            bool negative = false;
            if (object[pos] == '-')
            {
                negative = true;
                ++pos;
            }
            if (pos >= object.size() || object[pos] < '0' || object[pos] > '9')
                return false;

            std::uint64_t parsed = 0;
            while (pos < object.size() && object[pos] >= '0' && object[pos] <= '9')
            {
                const std::uint64_t digit = static_cast<std::uint64_t>(object[pos++] - '0');
                if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10u)
                    return false;
                parsed = parsed * 10u + digit;
            }
            if (negative)
            {
                if (parsed > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1u)
                    return false;
                value = parsed == static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1u
                    ? (std::numeric_limits<std::int64_t>::min)()
                    : -static_cast<std::int64_t>(parsed);
            }
            else
            {
                if (parsed > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
                    return false;
                value = static_cast<std::int64_t>(parsed);
            }
            return true;
        }

        bool ExtractJsonUInt64Field(const std::string& object, const char* key, std::uint64_t& value)
        {
            std::int64_t signedValue = 0;
            if (!ExtractJsonInt64Field(object, key, signedValue) || signedValue < 0)
                return false;
            value = static_cast<std::uint64_t>(signedValue);
            return true;
        }

        bool ExtractQueryParam(const std::string& url, const char* key, std::string& value)
        {
            value.clear();
            if (!key || !*key)
                return false;
            const std::string needle = std::string(key) + "=";
            std::size_t pos = url.find('?');
            if (pos == std::string::npos)
                return false;
            ++pos;
            while (pos < url.size())
            {
                const std::size_t amp = url.find('&', pos);
                const std::size_t end = amp == std::string::npos ? url.size() : amp;
                if (url.compare(pos, needle.size(), needle) == 0)
                {
                    value.assign(url, pos + needle.size(), end - (pos + needle.size()));
                    return true;
                }
                if (amp == std::string::npos)
                    break;
                pos = amp + 1u;
            }
            return false;
        }

        std::uint64_t Fnv1a64(const std::string& value, std::uint64_t seed = 1469598103934665603ull)
        {
            std::uint64_t hash = seed;
            for (unsigned char c : value)
            {
                hash ^= static_cast<std::uint64_t>(c);
                hash *= 1099511628211ull;
            }
            return hash;
        }

        std::string HexU64(std::uint64_t value)
        {
            static const char* digits = "0123456789abcdef";
            std::string out(16u, '0');
            for (int i = 15; i >= 0; --i)
            {
                out[static_cast<std::size_t>(i)] = digits[value & 0xFu];
                value >>= 4u;
            }
            return out;
        }

        std::string StableDigest32(const std::string& value)
        {
            const std::uint64_t h1 = Fnv1a64(value);
            const std::uint64_t h2 = Fnv1a64(value, 1099511628211ull ^ h1);
            return HexU64(h1) + HexU64(h2);
        }

        std::string Base64Encode(const std::string& bytes)
        {
            static const char table[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            out.reserve(((bytes.size() + 2u) / 3u) * 4u);
            std::size_t i = 0;
            while (i + 3u <= bytes.size())
            {
                const std::uint32_t n =
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16u) |
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1u])) << 8u) |
                    static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 2u]));
                out.push_back(table[(n >> 18u) & 63u]);
                out.push_back(table[(n >> 12u) & 63u]);
                out.push_back(table[(n >> 6u) & 63u]);
                out.push_back(table[n & 63u]);
                i += 3u;
            }
            const std::size_t remain = bytes.size() - i;
            if (remain == 1u)
            {
                const std::uint32_t n = static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16u;
                out.push_back(table[(n >> 18u) & 63u]);
                out.push_back(table[(n >> 12u) & 63u]);
                out += "==";
            }
            else if (remain == 2u)
            {
                const std::uint32_t n =
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16u) |
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1u])) << 8u);
                out.push_back(table[(n >> 18u) & 63u]);
                out.push_back(table[(n >> 12u) & 63u]);
                out.push_back(table[(n >> 6u) & 63u]);
                out.push_back('=');
            }
            return out;
        }

        std::size_t Base64DecodedLength(const std::string& base64)
        {
            if (base64.empty())
                return 0u;
            std::size_t useful = 0u;
            for (char c : base64)
            {
                if (!IsJsonWhitespace(c))
                    ++useful;
            }
            if (!useful)
                return 0u;
            std::size_t padding = 0u;
            for (std::size_t i = base64.size(); i > 0u && padding < 2u; --i)
            {
                const char c = base64[i - 1u];
                if (IsJsonWhitespace(c))
                    continue;
                if (c == '=')
                    ++padding;
                else
                    break;
            }
            return (useful / 4u) * 3u - (std::min)(padding, static_cast<std::size_t>(2u));
        }
    }
}
