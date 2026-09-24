#include "JsonParsing.h"

namespace revamped::iw8::web
{
    namespace
    {
        bool LooksLikeJsonObject(std::string_view text)

        {
            std::size_t pos = 0;
            while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
            return pos < text.size() && text[pos] == '{';
        }

        bool SkipJsonString(std::string_view json, std::size_t& pos, std::string* decoded = nullptr)
        {
            if (pos >= json.size() || json[pos] != '"') return false;
            ++pos;
            if (decoded) decoded->clear();
            while (pos < json.size())
            {
                const char c = json[pos++];
                if (c == '"') return true;
                if (c == '\\')
                {
                    if (pos >= json.size()) return false;
                    const char escaped = json[pos++];
                    if (decoded)
                    {
                        switch (escaped)
                        {
                        case '"': decoded->push_back('"'); break;
                        case '\\': decoded->push_back('\\'); break;
                        case '/': decoded->push_back('/'); break;
                        case 'b': decoded->push_back('\b'); break;
                        case 'f': decoded->push_back('\f'); break;
                        case 'n': decoded->push_back('\n'); break;
                        case 'r': decoded->push_back('\r'); break;
                        case 't': decoded->push_back('\t'); break;
                        case 'u':
                        {
                            // Decode JSON \uXXXX escapes so nested Demonware fields are
                            // preserved exactly enough for local protocol emulation. Values
                            // still remain internal and are never printed by diagnostics.
                            unsigned value = 0;
                            bool valid = true;
                            for (int i = 0; i < 4; ++i)
                            {
                                if (pos >= json.size()) { valid = false; break; }
                                const unsigned char h = static_cast<unsigned char>(json[pos++]);
                                value <<= 4;
                                if (h >= '0' && h <= '9') value |= h - '0';
                                else if (h >= 'a' && h <= 'f') value |= 10u + h - 'a';
                                else if (h >= 'A' && h <= 'F') value |= 10u + h - 'A';
                                else { valid = false; break; }
                            }
                            if (!valid) { decoded->push_back('?'); break; }
                            if (value <= 0x7Fu)
                            {
                                decoded->push_back(static_cast<char>(value));
                            }
                            else if (value <= 0x7FFu)
                            {
                                decoded->push_back(static_cast<char>(0xC0u | (value >> 6)));
                                decoded->push_back(static_cast<char>(0x80u | (value & 0x3Fu)));
                            }
                            else
                            {
                                decoded->push_back(static_cast<char>(0xE0u | (value >> 12)));
                                decoded->push_back(static_cast<char>(0x80u | ((value >> 6) & 0x3Fu)));
                                decoded->push_back(static_cast<char>(0x80u | (value & 0x3Fu)));
                            }
                            break;
                        }
                        default: decoded->push_back('?'); break;
                        }
                    }
                    else if (escaped == 'u')
                    {
                        for (int i = 0; i < 4 && pos < json.size(); ++i) ++pos;
                    }
                    continue;
                }
                if (decoded) decoded->push_back(c);
            }
            return false;
        }

        std::size_t SkipWhitespace(std::string_view text, std::size_t pos)
        {
            while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
            return pos;
        }

        bool FindTopLevelJsonValue(std::string_view json, const char* wantedKey,
            std::size_t& valueStart, std::size_t& valueEnd, char& valueType)
        {
            if (!wantedKey) return false;
            std::size_t pos = SkipWhitespace(json, 0);
            if (pos >= json.size() || json[pos] != '{') return false;
            ++pos;
            while (pos < json.size())
            {
                pos = SkipWhitespace(json, pos);
                if (pos >= json.size() || json[pos] == '}') return false;
                std::string key;
                if (!SkipJsonString(json, pos, &key)) return false;
                pos = SkipWhitespace(json, pos);
                if (pos >= json.size() || json[pos] != ':') return false;
                pos = SkipWhitespace(json, pos + 1);
                if (pos >= json.size()) return false;

                const std::size_t start = pos;
                const char first = json[pos];
                std::size_t end = pos;
                if (first == '"')
                {
                    if (!SkipJsonString(json, end, nullptr)) return false;
                    valueType = 's';
                }
                else if (first == '{' || first == '[')
                {
                    const char open = first;
                    const char close = first == '{' ? '}' : ']';
                    int depth = 0;
                    bool inString = false;
                    bool escaped = false;
                    for (; end < json.size(); ++end)
                    {
                        const char c = json[end];
                        if (inString)
                        {
                            if (escaped) escaped = false;
                            else if (c == '\\') escaped = true;
                            else if (c == '"') inString = false;
                            continue;
                        }
                        if (c == '"') { inString = true; continue; }
                        if (c == open) ++depth;
                        else if (c == close && --depth == 0) { ++end; break; }
                    }
                    if (depth != 0) return false;
                    valueType = first == '{' ? 'o' : 'a';
                }
                else
                {
                    while (end < json.size() && json[end] != ',' && json[end] != '}') ++end;
                    while (end > start && std::isspace(static_cast<unsigned char>(json[end - 1]))) --end;
                    valueType = (first == 't' || first == 'f') ? 'b' : (first == 'n' ? '0' : 'n');
                }

                if (key == wantedKey)
                {
                    valueStart = start;
                    valueEnd = end;
                    return true;
                }

                pos = SkipWhitespace(json, end);
                if (pos < json.size() && json[pos] == ',') { ++pos; continue; }
                if (pos < json.size() && json[pos] == '}') return false;
            }
            return false;
        }

        std::string JsonTopLevelKeys(std::string_view json)
        {
            std::ostringstream out;
            bool firstOut = true;
            std::size_t pos = SkipWhitespace(json, 0);
            if (pos >= json.size() || json[pos] != '{') return {};
            ++pos;
            while (pos < json.size())
            {
                pos = SkipWhitespace(json, pos);
                if (pos >= json.size() || json[pos] == '}') break;
                std::string key;
                if (!SkipJsonString(json, pos, &key)) break;
                for (char& c : key)
                {
                    const unsigned char uc = static_cast<unsigned char>(c);
                    if (!(std::isalnum(uc) || c == '_' || c == '-' || c == '.')) c = '?';
                }
                if (!key.empty())
                {
                    if (!firstOut) out << ',';
                    firstOut = false;
                    out << key;
                }
                pos = SkipWhitespace(json, pos);
                if (pos >= json.size() || json[pos] != ':') break;
                pos = SkipWhitespace(json, pos + 1);
                if (pos >= json.size()) break;
                // Walk over the value without decoding it; only field names are surfaced.
                const char first = json[pos];
                if (first == '"')
                {
                    if (!SkipJsonString(json, pos, nullptr)) break;
                }
                else if (first == '{' || first == '[')
                {
                    const char open = first, close = first == '{' ? '}' : ']';
                    int depth = 0; bool inString = false; bool escaped = false;
                    for (; pos < json.size(); ++pos)
                    {
                        const char c = json[pos];
                        if (inString)
                        {
                            if (escaped) escaped = false;
                            else if (c == '\\') escaped = true;
                            else if (c == '"') inString = false;
                            continue;
                        }
                        if (c == '"') { inString = true; continue; }
                        if (c == open) ++depth;
                        else if (c == close && --depth == 0) { ++pos; break; }
                    }
                }
                else
                {
                    while (pos < json.size() && json[pos] != ',' && json[pos] != '}') ++pos;
                }
                pos = SkipWhitespace(json, pos);
                if (pos < json.size() && json[pos] == ',') ++pos;
            }
            return out.str();
        }

        bool JsonUnsignedText(std::string_view json, const char* key, std::string& value)
        {
            std::size_t start = 0, end = 0; char type = 0;
            if (!FindTopLevelJsonValue(json, key, start, end, type)) return false;
            if (type == 's')
            {
                std::size_t p = start;
                std::string decoded;
                if (!SkipJsonString(json, p, &decoded)) return false;
                if (decoded.empty() || !std::all_of(decoded.begin(), decoded.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) return false;
                value = decoded;
                return true;
            }
            if (type != 'n' || end <= start) return false;
            value.assign(json.substr(start, end - start));
            return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
        }

        std::size_t JsonStringLength(std::string_view json, const char* key)
        {
            std::size_t start = 0, end = 0; char type = 0;
            if (!FindTopLevelJsonValue(json, key, start, end, type) || type != 's') return 0;
            std::size_t p = start;
            std::string decoded;
            return SkipJsonString(json, p, &decoded) ? decoded.size() : 0;
        }

        bool JsonStringValue(std::string_view json, const char* key, std::string& value)
        {
            std::size_t start = 0, end = 0; char type = 0;
            if (!FindTopLevelJsonValue(json, key, start, end, type) || type != 's') return false;
            std::size_t p = start;
            return SkipJsonString(json, p, &value);
        }

        std::string JsonEscape(std::string_view value)
        {
            static constexpr char hex[] = "0123456789ABCDEF";
            std::string out;
            out.reserve(value.size() + 16);
            for (const unsigned char c : value)
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
                        out.push_back(hex[(c >> 4) & 0x0F]);
                        out.push_back(hex[c & 0x0F]);
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

        char JsonValueType(std::string_view json, const char* key)
        {
            std::size_t start = 0, end = 0; char type = 0;
            return FindTopLevelJsonValue(json, key, start, end, type) ? type : '-';
        }
    }
}
