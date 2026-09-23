#include "WebAuthService.h"
#include "../Log.h"

#include <Windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdarg>
#include <cstdio>
#include <sstream>
#include <string_view>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Ncrypt.lib")

namespace revamped::iw8::web
{
    namespace
    {
        struct AuthPipelineCorrelation
        {
            std::string lastAuth3ClientTicket;
            std::string lastAuth3ServerTicket;
            // V72: preserve only the protocol values needed to test which 24-byte
            // secret the stock client actually feeds into the LSG KDF.  These are
            // never printed raw; ServerLsg compares derived proofs only.
            std::string lastAuth3IvSeed;
            std::string lastUmbrellaInitialVectorSeed;
            std::string lastMintedLsgToken;
            std::uint64_t auth3Serial = 0;
            ULONGLONG auth3IssuedAtMs = 0;
            std::uint32_t auth3TitleId = 0;

            std::uint64_t pendingLsgSerial = 0;
            ULONGLONG pendingLsgAtMs = 0;
            unsigned pendingLsgWarnings = 0;
            unsigned postLsgUnattributedActivity = 0;
            bool postLsgTransportSeen = false;
            volatile LONG umbrellaSweepCount = 0;
        };

        AuthPipelineCorrelation g_authPipeline;

        void AppendAuthPipelineV58(const char* format, ...)
        {
            if (!format) return;
            char message[2048]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
            va_end(args);
            char line[2304]{};
            _snprintf_s(line, sizeof(line), _TRUNCATE, "[%llu] %s\r\n",
                static_cast<unsigned long long>(GetTickCount64()), message);
            log::Print("[AUTH-V60] %s", message);
            HANDLE file = CreateFileA("auth_pipeline_v60.log", FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            DWORD written = 0;
            if (file != INVALID_HANDLE_VALUE)
            {
                WriteFile(file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
                CloseHandle(file);
            }

            // V60: mirror the server-side auth timeline into the same server_emu
            // folder the client research logs use, so one ZIP contains both sides.
            CreateDirectoryA("server_emu", nullptr);
            HANDLE mirror = CreateFileA("server_emu\\auth_pipeline_v60.log", FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (mirror != INVALID_HANDLE_VALUE)
            {
                written = 0;
                WriteFile(mirror, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
                CloseHandle(mirror);
            }
        }

        static constexpr std::uint8_t kLocalAuth3SessionKey[24] = {
            0x13,0x37,0x13,0x37,0x13,0x37,0x13,0x37,
            0x13,0x37,0x13,0x37,0x13,0x37,0x13,0x37,
            0x13,0x37,0x13,0x37,0x13,0x37,0x13,0x37
        };

        void RememberAuth3Tickets(const std::string& clientTicket, const std::string& serverTicket,
            std::uint32_t titleId)
        {
            g_authPipeline.lastAuth3ClientTicket = clientTicket;
            g_authPipeline.lastAuth3ServerTicket = serverTicket;
            g_authPipeline.auth3Serial += 1u;
            g_authPipeline.auth3IssuedAtMs = GetTickCount64();
            g_authPipeline.auth3TitleId = titleId;
            log::Print("[AUTH3-CORRELATION] auth3Serial=%llu clientTicketBytes=%llu serverTicketBytes=%llu titleId=%u values=REDACTED stateWrites=off",
                static_cast<unsigned long long>(g_authPipeline.auth3Serial),
                static_cast<unsigned long long>(clientTicket.size()),
                static_cast<unsigned long long>(serverTicket.size()),
                static_cast<unsigned>(titleId));
            AppendAuthPipelineV58("AUTH3_ISSUED serial=%llu titleId=%u clientTicketB64Bytes=%llu serverTicketB64Bytes=%llu serverTicketRawLayout=first24_session_key_then_zero values=REDACTED",
                static_cast<unsigned long long>(g_authPipeline.auth3Serial), static_cast<unsigned>(titleId),
                static_cast<unsigned long long>(clientTicket.size()), static_cast<unsigned long long>(serverTicket.size()));
        }

        struct Auth3TicketMatch
        {
            std::uint64_t serial = 0;
            ULONGLONG ageMs = 0;
            std::uint32_t titleId = 0;
            bool haveAuth3ClientTicket = false;
            bool haveAuth3ServerTicket = false;
            bool exactClientMatch = false;
            bool exactServerMatch = false;
        };

        Auth3TicketMatch CorrelateUmbrellaTicket(const std::string& ticket)
        {
            Auth3TicketMatch match{};
            match.serial = g_authPipeline.auth3Serial;
            match.titleId = g_authPipeline.auth3TitleId;
            match.haveAuth3ClientTicket = !g_authPipeline.lastAuth3ClientTicket.empty();
            match.haveAuth3ServerTicket = !g_authPipeline.lastAuth3ServerTicket.empty();
            match.exactClientMatch = match.haveAuth3ClientTicket && !ticket.empty() &&
                ticket == g_authPipeline.lastAuth3ClientTicket;
            match.exactServerMatch = match.haveAuth3ServerTicket && !ticket.empty() &&
                ticket == g_authPipeline.lastAuth3ServerTicket;
            if (g_authPipeline.auth3IssuedAtMs != 0)
                match.ageMs = GetTickCount64() - g_authPipeline.auth3IssuedAtMs;
            return match;
        }

        void MarkUmbrellaLsgAccepted(std::uint64_t auth3Serial)
        {
            g_authPipeline.pendingLsgSerial = auth3Serial;
            g_authPipeline.pendingLsgAtMs = GetTickCount64();
            g_authPipeline.pendingLsgWarnings = 0;
            g_authPipeline.postLsgUnattributedActivity = 0;
            g_authPipeline.postLsgTransportSeen = false;
        }

        std::string Lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return value;
        }

        std::string Trim(std::string value)
        {
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
            return value;
        }

        std::string HeaderValue(const std::string& headers, const char* wanted)
        {
            if (!wanted) return {};
            const std::string wantedLower = Lower(wanted);
            std::size_t lineStart = 0;
            while (lineStart < headers.size())
            {
                const std::size_t lineEnd = headers.find("\r\n", lineStart);
                const std::size_t end = lineEnd == std::string::npos ? headers.size() : lineEnd;
                const std::string line = headers.substr(lineStart, end - lineStart);
                const std::size_t colon = line.find(':');
                if (colon != std::string::npos && Lower(Trim(line.substr(0, colon))) == wantedLower)
                    return Trim(line.substr(colon + 1));
                if (lineEnd == std::string::npos) break;
                lineStart = lineEnd + 2;
            }
            return {};
        }

        std::string FieldKeys(std::string_view encoded)
        {
            std::ostringstream out;
            bool first = true;
            std::size_t pos = 0;
            while (pos < encoded.size())
            {
                const std::size_t amp = encoded.find('&', pos);
                const std::size_t end = amp == std::string_view::npos ? encoded.size() : amp;
                const std::size_t eq = encoded.find('=', pos);
                const std::size_t keyEnd = eq != std::string_view::npos && eq < end ? eq : end;
                std::string key(encoded.substr(pos, keyEnd - pos));
                if (!key.empty())
                {
                    // Keep diagnostics printable and deliberately never include values.
                    for (char& c : key)
                    {
                        const unsigned char uc = static_cast<unsigned char>(c);
                        if (!(std::isalnum(uc) || c == '_' || c == '-' || c == '.')) c = '?';
                    }
                    if (!first) out << ',';
                    first = false;
                    out << key;
                }
                if (amp == std::string_view::npos) break;
                pos = amp + 1;
            }
            return out.str();
        }

        bool HasFormKey(std::string_view encoded, const char* wanted)
        {
            if (!wanted) return false;
            const std::string target = Lower(wanted);
            std::size_t pos = 0;
            while (pos < encoded.size())
            {
                const std::size_t amp = encoded.find('&', pos);
                const std::size_t end = amp == std::string_view::npos ? encoded.size() : amp;
                const std::size_t eq = encoded.find('=', pos);
                const std::size_t keyEnd = eq != std::string_view::npos && eq < end ? eq : end;
                if (Lower(std::string(encoded.substr(pos, keyEnd - pos))) == target)
                    return true;
                if (amp == std::string_view::npos) break;
                pos = amp + 1;
            }
            return false;
        }


        bool HasFormPair(std::string_view encoded, const char* wantedKey, const char* wantedValue)
        {
            if (!wantedKey || !wantedValue) return false;
            const std::string keyTarget = Lower(wantedKey);
            const std::string valueTarget = Lower(wantedValue);
            std::size_t pos = 0;
            while (pos < encoded.size())
            {
                const std::size_t amp = encoded.find('&', pos);
                const std::size_t end = amp == std::string_view::npos ? encoded.size() : amp;
                const std::size_t eq = encoded.find('=', pos);
                if (eq != std::string_view::npos && eq < end)
                {
                    const std::string key = Lower(std::string(encoded.substr(pos, eq - pos)));
                    const std::string value = Lower(std::string(encoded.substr(eq + 1, end - eq - 1)));
                    if (key == keyTarget && value == valueTarget)
                        return true;
                }
                if (amp == std::string_view::npos) break;
                pos = amp + 1;
            }
            return false;
        }

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

        std::string Base64Encode(const std::vector<std::uint8_t>& bytes)
        {
            static constexpr char alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            out.reserve(((bytes.size() + 2) / 3) * 4);
            for (std::size_t i = 0; i < bytes.size(); i += 3)
            {
                const unsigned a = bytes[i];
                const unsigned b = i + 1 < bytes.size() ? bytes[i + 1] : 0;
                const unsigned c = i + 2 < bytes.size() ? bytes[i + 2] : 0;
                const unsigned triple = (a << 16) | (b << 8) | c;
                out.push_back(alphabet[(triple >> 18) & 0x3F]);
                out.push_back(alphabet[(triple >> 12) & 0x3F]);
                out.push_back(i + 1 < bytes.size() ? alphabet[(triple >> 6) & 0x3F] : '=');
                out.push_back(i + 2 < bytes.size() ? alphabet[triple & 0x3F] : '=');
            }
            return out;
        }

        NCRYPT_PROV_HANDLE g_auth3SignerProvider = 0;
        NCRYPT_KEY_HANDLE g_auth3SignerKey = 0;
        bool g_auth3SignerReady = false;

        std::wstring ServerSiblingPath(const wchar_t* fileName)
        {
            if (!fileName || !*fileName)
                return {};
            wchar_t modulePath[32768]{};
            const DWORD length = GetModuleFileNameW(nullptr, modulePath,
                static_cast<DWORD>(sizeof(modulePath) / sizeof(modulePath[0])));
            if (!length || length >= sizeof(modulePath) / sizeof(modulePath[0]))
                return {};
            wchar_t* slash = wcsrchr(modulePath, L'\\');
            if (!slash)
                return {};
            slash[1] = L'\0';
            std::wstring path(modulePath);
            path += fileName;
            return path;
        }

        bool WriteBinaryFile(const std::wstring& path, const std::vector<std::uint8_t>& bytes)
        {
            if (path.empty() || bytes.empty() || bytes.size() > MAXDWORD)
                return false;
            HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;
            DWORD written = 0;
            const BOOL ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
            CloseHandle(file);
            return ok && written == bytes.size();
        }

        bool Sha256(const void* data, std::size_t size, std::array<std::uint8_t, 32>& digest)
        {
            digest.fill(0);
            if ((!data && size) || size > MAXDWORD)
                return false;
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            DWORD objectSize = 0;
            DWORD resultSize = 0;
            bool ok = false;
            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
                BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &resultSize, 0) >= 0)
            {
                std::vector<std::uint8_t> object(objectSize);
                if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) >= 0 &&
                    BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<void*>(data)),
                        static_cast<ULONG>(size), 0) >= 0 &&
                    BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0)
                {
                    ok = true;
                }
            }
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            return ok;
        }

        std::string Sha256Prefix(const std::string& value)
        {
            if (value.empty())
                return "none";
            std::array<std::uint8_t, 32> digest{};
            if (!Sha256(value.data(), value.size(), digest))
                return "sha256-error";
            static constexpr char hex[] = "0123456789ABCDEF";
            std::string out;
            out.reserve(16);
            for (std::size_t i = 0; i < 8; ++i)
            {
                out.push_back(hex[(digest[i] >> 4) & 0x0F]);
                out.push_back(hex[digest[i] & 0x0F]);
            }
            return out;
        }

        int Base64Value(unsigned char c)
        {
            if (c >= 'A' && c <= 'Z') return static_cast<int>(c - 'A');
            if (c >= 'a' && c <= 'z') return static_cast<int>(c - 'a') + 26;
            if (c >= '0' && c <= '9') return static_cast<int>(c - '0') + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        }

        bool Base64Decode(std::string_view text, std::vector<std::uint8_t>& out)
        {
            out.clear();
            if (text.empty() || (text.size() % 4u) != 0u)
                return false;
            out.reserve((text.size() / 4u) * 3u);
            for (std::size_t i = 0; i < text.size(); i += 4u)
            {
                const unsigned char c0 = static_cast<unsigned char>(text[i + 0]);
                const unsigned char c1 = static_cast<unsigned char>(text[i + 1]);
                const unsigned char c2 = static_cast<unsigned char>(text[i + 2]);
                const unsigned char c3 = static_cast<unsigned char>(text[i + 3]);
                const int v0 = Base64Value(c0);
                const int v1 = Base64Value(c1);
                const bool pad2 = c2 == '=';
                const bool pad3 = c3 == '=';
                const int v2 = pad2 ? 0 : Base64Value(c2);
                const int v3 = pad3 ? 0 : Base64Value(c3);
                if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0 || (pad2 && !pad3))
                    return false;
                if ((pad2 || pad3) && i + 4u != text.size())
                    return false;
                const unsigned triple = (static_cast<unsigned>(v0) << 18) |
                    (static_cast<unsigned>(v1) << 12) |
                    (static_cast<unsigned>(v2) << 6) | static_cast<unsigned>(v3);
                out.push_back(static_cast<std::uint8_t>((triple >> 16) & 0xFFu));
                if (!pad2) out.push_back(static_cast<std::uint8_t>((triple >> 8) & 0xFFu));
                if (!pad3) out.push_back(static_cast<std::uint8_t>(triple & 0xFFu));
            }
            return true;
        }

        std::uint32_t ReadPackedU32(const std::vector<std::uint8_t>& bytes, std::size_t offset)
        {
            std::uint32_t value = 0;
            if (offset + sizeof(value) <= bytes.size())
                std::memcpy(&value, bytes.data() + offset, sizeof(value));
            return value;
        }

        struct UmbrellaTicketShape
        {
            bool base64Ok = false;
            std::size_t decodedBytes = 0;
            bool dwAuthTicketMagic = false;
            std::uint8_t type = 0;
            std::uint32_t titleId = 0;
            std::uint32_t timeIssued = 0;
            std::uint32_t timeExpires = 0;
            unsigned sessionKeyNonZero = 0;
        };

        UmbrellaTicketShape DescribeUmbrellaTicket(const std::string& ticket)
        {
            UmbrellaTicketShape shape{};
            std::vector<std::uint8_t> decoded;
            shape.base64Ok = Base64Decode(ticket, decoded);
            shape.decodedBytes = decoded.size();
            if (!shape.base64Ok || decoded.size() < 128u)
                return shape;
            shape.dwAuthTicketMagic = ReadPackedU32(decoded, 0u) == 0xEFBDADDEu;
            shape.type = decoded[4];
            shape.titleId = ReadPackedU32(decoded, 5u);
            shape.timeIssued = ReadPackedU32(decoded, 9u);
            shape.timeExpires = ReadPackedU32(decoded, 13u);
            // Packed DwAuthTicket sessionKey starts at byte 97 and is 24 bytes.
            for (std::size_t i = 97u; i < 121u && i < decoded.size(); ++i)
                if (decoded[i] != 0u) ++shape.sessionKeyNonZero;
            return shape;
        }

        std::vector<std::uint8_t> BuildRsa2048SubjectPublicKeyInfo(
            const std::vector<std::uint8_t>& publicBlob)
        {
            if (publicBlob.size() < sizeof(BCRYPT_RSAKEY_BLOB))
                return {};
            const auto* rsa = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(publicBlob.data());
            if (rsa->Magic != BCRYPT_RSAPUBLIC_MAGIC || rsa->BitLength != 2048u ||
                rsa->cbModulus != 256u || rsa->cbPublicExp != 3u || rsa->cbPrime1 || rsa->cbPrime2)
            {
                return {};
            }
            const std::size_t payloadBytes = sizeof(BCRYPT_RSAKEY_BLOB) +
                static_cast<std::size_t>(rsa->cbPublicExp) + rsa->cbModulus;
            if (payloadBytes > publicBlob.size())
                return {};
            const auto* exponent = publicBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
            const auto* modulus = exponent + rsa->cbPublicExp;
            if (exponent[0] != 0x01u || exponent[1] != 0x00u || exponent[2] != 0x01u)
                return {};

            static constexpr std::uint8_t prefix[] = {
                0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,
                0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,
                0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,
                0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01,0x00
            };
            static constexpr std::uint8_t suffix[] = {0x02,0x03,0x01,0x00,0x01};
            std::vector<std::uint8_t> der;
            der.reserve(sizeof(prefix) + rsa->cbModulus + sizeof(suffix));
            der.insert(der.end(), std::begin(prefix), std::end(prefix));
            der.insert(der.end(), modulus, modulus + rsa->cbModulus);
            der.insert(der.end(), std::begin(suffix), std::end(suffix));
            return der.size() == 294u ? der : std::vector<std::uint8_t>{};
        }

        bool InitializeLocalAuthSignerInternal()
        {
            if (g_auth3SignerReady)
                return true;

            SECURITY_STATUS status = NCryptOpenStorageProvider(
                &g_auth3SignerProvider, MS_KEY_STORAGE_PROVIDER, 0);
            if (status != ERROR_SUCCESS)
            {
                log::Print("[AUTH3-TRUST] NCryptOpenStorageProvider failed status=0x%08lX",
                    static_cast<unsigned long>(status));
                return false;
            }

            static constexpr wchar_t keyName[] = L"CodRevamped_IW8_Auth3_ResponseSigner";
            status = NCryptOpenKey(g_auth3SignerProvider, &g_auth3SignerKey, keyName, 0, NCRYPT_SILENT_FLAG);
            if (status != ERROR_SUCCESS)
            {
                status = NCryptCreatePersistedKey(g_auth3SignerProvider, &g_auth3SignerKey,
                    NCRYPT_RSA_ALGORITHM, keyName, 0, 0);
                DWORD bits = 2048u;
                if (status == ERROR_SUCCESS)
                    status = NCryptSetProperty(g_auth3SignerKey, NCRYPT_LENGTH_PROPERTY,
                        reinterpret_cast<PBYTE>(&bits), sizeof(bits), 0);
                if (status == ERROR_SUCCESS)
                    status = NCryptFinalizeKey(g_auth3SignerKey, NCRYPT_SILENT_FLAG);
            }
            if (status != ERROR_SUCCESS || !g_auth3SignerKey)
            {
                log::Print("[AUTH3-TRUST] persistent RSA key setup failed status=0x%08lX",
                    static_cast<unsigned long>(status));
                return false;
            }

            DWORD publicBytes = 0;
            status = NCryptExportKey(g_auth3SignerKey, 0, BCRYPT_RSAPUBLIC_BLOB,
                nullptr, nullptr, 0, &publicBytes, 0);
            if (status != ERROR_SUCCESS || !publicBytes)
            {
                log::Print("[AUTH3-TRUST] public-key size export failed status=0x%08lX",
                    static_cast<unsigned long>(status));
                return false;
            }
            std::vector<std::uint8_t> publicBlob(publicBytes);
            status = NCryptExportKey(g_auth3SignerKey, 0, BCRYPT_RSAPUBLIC_BLOB,
                nullptr, publicBlob.data(), publicBytes, &publicBytes, 0);
            if (status != ERROR_SUCCESS)
            {
                log::Print("[AUTH3-TRUST] public-key export failed status=0x%08lX",
                    static_cast<unsigned long>(status));
                return false;
            }
            publicBlob.resize(publicBytes);
            const std::vector<std::uint8_t> der = BuildRsa2048SubjectPublicKeyInfo(publicBlob);
            const std::wstring publicPath = ServerSiblingPath(L"auth3-response-signing-public.der");
            if (der.size() != 294u || !WriteBinaryFile(publicPath, der))
            {
                log::Print("[AUTH3-TRUST] failed exporting 294-byte DER public key win32=%lu",
                    GetLastError());
                return false;
            }

            std::array<std::uint8_t, 32> fingerprint{};
            if (!Sha256(der.data(), der.size(), fingerprint))
                return false;
            char prefix[17]{};
            for (std::size_t i = 0; i < 8u; ++i)
                _snprintf_s(prefix + i * 2u, sizeof(prefix) - i * 2u, _TRUNCATE, "%02X", fingerprint[i]);

            g_auth3SignerReady = true;
            log::Print("[AUTH3-TRUST] local RSA-PSS/SHA-256 response signer ready publicDerBytes=%llu sha256Prefix=%s file=auth3-response-signing-public.der",
                static_cast<unsigned long long>(der.size()), prefix);
            return true;
        }

        std::vector<std::uint8_t> SignAuth3Body(const std::string& body)
        {
            if (!InitializeLocalAuthSignerInternal() || body.empty())
                return {};
            std::array<std::uint8_t, 32> digest{};
            if (!Sha256(body.data(), body.size(), digest))
                return {};
            BCRYPT_PSS_PADDING_INFO padding{};
            padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            // IW8's bdRSAKey verifier forwards saltLength=0 to
            // rsa_verify_hash_ex, so the response must use zero-length PSS salt.
            padding.cbSalt = 0;
            DWORD signatureBytes = 0;
            SECURITY_STATUS status = NCryptSignHash(g_auth3SignerKey, &padding,
                digest.data(), static_cast<DWORD>(digest.size()), nullptr, 0,
                &signatureBytes, NCRYPT_PAD_PSS_FLAG);
            if (status != ERROR_SUCCESS || signatureBytes != 256u)
                return {};
            std::vector<std::uint8_t> signature(signatureBytes);
            status = NCryptSignHash(g_auth3SignerKey, &padding,
                digest.data(), static_cast<DWORD>(digest.size()), signature.data(),
                signatureBytes, &signatureBytes, NCRYPT_PAD_PSS_FLAG);
            if (status != ERROR_SUCCESS || signatureBytes != signature.size())
                return {};
            if (NCryptVerifySignature(g_auth3SignerKey, &padding, digest.data(),
                    static_cast<DWORD>(digest.size()), signature.data(), signatureBytes,
                    NCRYPT_PAD_PSS_FLAG) != ERROR_SUCCESS)
            {
                return {};
            }
            return signature;
        }

        #pragma pack(push, 1)
        struct DwAuthTicket
        {
            std::uint32_t magicNumber;
            std::uint8_t type;
            std::uint32_t titleId;
            std::uint32_t timeIssued;
            std::uint32_t timeExpires;
            std::uint64_t licenseId;
            std::uint64_t userId;
            char username[64];
            std::uint8_t sessionKey[24];
            std::uint8_t usingHashMagicNumber[3];
            std::uint8_t hash[4];
        };
        #pragma pack(pop)
        static_assert(sizeof(DwAuthTicket) == 128, "Demonware auth ticket must be 128 bytes");

        // V67: /v1.0/tokens/lsg/ is an exchange, not an echo.  The stock
        // client presents Auth3 server_ticket to Umbrella as its request
        // credential.  That server ticket is intentionally opaque (our local
        // form carries the 24-byte Auth3 key at byte 0), so handing it back as
        // the LSG token leaves bdLobby without a structured ticket/session key
        // to consume.  Mint a fresh 128-byte DW ticket for the LSG handoff,
        // preserving the already-proven Auth3 identity fields when available
        // and binding it to the exact same session key used by ServerLsg.
        std::string BuildLocalLsgTokenV67(std::uint32_t titleId)
        {
            DwAuthTicket ticket{};

            // Reuse the accepted Auth3 client-ticket identity payload when it
            // is available.  Do not trust/copy its timing or key material below.
            std::vector<std::uint8_t> auth3ClientRaw;
            if (!g_authPipeline.lastAuth3ClientTicket.empty() &&
                Base64Decode(g_authPipeline.lastAuth3ClientTicket, auth3ClientRaw) &&
                auth3ClientRaw.size() == sizeof(DwAuthTicket) &&
                ReadPackedU32(auth3ClientRaw, 0u) == 0xEFBDADDEu)
            {
                std::memcpy(&ticket, auth3ClientRaw.data(), sizeof(ticket));
            }

            ticket.magicNumber = 0xEFBDADDEu;
            ticket.type = 0;
            ticket.titleId = titleId;
            ticket.timeIssued = static_cast<std::uint32_t>(std::time(nullptr));
            ticket.timeExpires = ticket.timeIssued + 30000u;
            std::memcpy(ticket.sessionKey, kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const auto* bytes = reinterpret_cast<const std::uint8_t*>(&ticket);
            return Base64Encode(std::vector<std::uint8_t>(bytes, bytes + sizeof(ticket)));
        }

        std::string BuildDwBnetAuthResponse(const std::string& requestTask, const std::string& ivSeed,
            std::uint32_t titleId, const std::string& identity, const std::string& serviceLevel,
            const std::string& sessionToken)
        {
            // V72: remember the exact Auth3 IV-seed representation supplied by
            // stock IW8.  It is only used as a bounded candidate source later.
            g_authPipeline.lastAuth3IvSeed = ivSeed;
            // Battle.net-era Auth3 (T8 and later) uses the same 128-byte ticket
            // container but, unlike the older Steam Auth3 path, returns this
            // client ticket as raw bytes encoded with base64. Keep the session key
            // local and deterministic for the next lobby-service correlation step.
            DwAuthTicket ticket{};
            ticket.magicNumber = 0xEFBDADDEu;
            ticket.type = 0;
            ticket.titleId = titleId;
            ticket.timeIssued = static_cast<std::uint32_t>(std::time(nullptr));
            ticket.timeExpires = ticket.timeIssued + 30000u;
            ticket.licenseId = 0;
            ticket.userId = 0;
            const std::size_t usernameBytes = (std::min)(sessionToken.size(), sizeof(ticket.username) - 1u);
            if (usernameBytes != 0)
                std::memcpy(ticket.username, sessionToken.data(), usernameBytes);
            const std::string ticketUsername(ticket.username, usernameBytes);
            std::memcpy(ticket.sessionKey, kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const auto* ticketBytes = reinterpret_cast<const std::uint8_t*>(&ticket);
            std::vector<std::uint8_t> clientTicket(ticketBytes, ticketBytes + sizeof(ticket));
            std::vector<std::uint8_t> serverTicket(128u, 0u);
            std::memcpy(serverTicket.data(), kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const std::string clientB64 = Base64Encode(clientTicket);
            const std::string serverB64 = Base64Encode(serverTicket);
            const std::string extendedB64 = Base64Encode(std::vector<std::uint8_t>{'l','u','l'});
            RememberAuth3Tickets(clientB64, serverB64, titleId);

            unsigned long taskValue = 84u;
            if (!requestTask.empty())
            {
                char* end = nullptr;
                const unsigned long parsed = std::strtoul(requestTask.c_str(), &end, 10);
                if (end && *end == '\0') taskValue = parsed;
            }
            const std::string responseTask = std::to_string(taskValue + 1u);

            std::ostringstream nested;
            nested << "{\"username\":\"" << JsonEscape(ticketUsername)
                   << "\",\"time_to_live\":9999,\"extended_data\":\"" << extendedB64 << "\"}";

            std::ostringstream json;
            json << "{\"auth_task\":\"" << responseTask
                 << "\",\"code\":\"700\",\"iv_seed\":\"" << JsonEscape(ivSeed)
                 << "\",\"client_ticket\":\"" << clientB64
                 << "\",\"server_ticket\":\"" << serverB64
                  // ModernWarfare.exe 1.44 carries this exact Auth3 client ID.
                  // A project-name expansion looks plausible but is rejected by
                  // the stock response validator before DW state can advance.
                  << "\",\"client_id\":\"iw-cod-iw8-bnet\""
                 << ",\"account_type\":\"bnet\""
                 << ",\"crossplay_enabled\":false"
                 << ",\"loginqueue_eanbled\":false"
                 << ",\"identity\":\"" << JsonEscape(identity) << "\""
                 << ",\"extra_data\":\"" << JsonEscape(nested.str()) << "\""
                 // BNet Auth3 returns the granted service level.  The known T8
                 // implementation returns "paid" even when the incoming request
                 // advertises "free"; IW8 is now probed with that exact behavior.
                 << ",\"service_level\":\"paid\""
                 // The project's known T8 Demonware Auth3 implementation emits
                 // this member as JSON null. IW8 also reaches Umbrella without
                 // ever resolving the hostname we previously injected here, so
                 // stop inventing a lobby route in the Auth3 contract.
                 << ",\"lsg_endpoint\":null}";
            return json.str();
        }

        std::string BuildResponse(int status, const char* reason, const char* contentType,
            const std::string& body)
        {
            std::ostringstream out;
            out << "HTTP/1.1 " << status << ' ' << (reason ? reason : "") << "\r\n"
                << "Content-Type: " << (contentType ? contentType : "application/octet-stream") << "\r\n"
                << "Cache-Control: no-store\r\n"
                << "Pragma: no-cache\r\n"
                << "Content-Length: " << body.size() << "\r\n"
                << "Connection: close\r\n"
                << "\r\n"
                << body;
            return out.str();
        }

        std::string BuildDwAuthResponse(const std::string& body)
        {
            // Match the Battle.net-era Demonware Auth3 HTTP envelope used by the
            // known working T8 emulator.  Keep this isolated to /auth/ so the
            // rest of the local web endpoints retain the stricter no-store policy.
            char date[64]{};
            const std::time_t now = std::time(nullptr);
            std::tm utc{};
#if defined(_WIN32)
            gmtime_s(&utc, &now);
#else
            gmtime_r(&now, &utc);
#endif
            std::strftime(date, sizeof(date), "%a, %d %b %G %T", &utc);

            const std::vector<std::uint8_t> signature = SignAuth3Body(body);
            const std::string signatureB64 = Base64Encode(signature);

            std::ostringstream out;
            out << "HTTP/1.1 200 OK\r\n"
                << "Server: TornadoServer/4.5.3\r\n"
                << "Content-Type: application/json\r\n"
                << "Date: " << date << " GMT\r\n"
                << "X-Signature: " << signatureB64 << "\r\n"
                << "Content-Length: " << body.size() << "\r\n\r\n"
                << body;
            return out.str();
        }
    }

    bool InitializeLocalAuthSigner()
    {
        return InitializeLocalAuthSignerInternal();
    }

    HttpResult TryHandleLocalWebRequest(std::vector<std::uint8_t>& buffer)
    {
        HttpResult result{};
        if (buffer.empty()) return result;

        const std::string all(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        const std::size_t headerEndMarker = all.find("\r\n\r\n");
        if (headerEndMarker == std::string::npos)
            return result;

        const std::size_t headerBytes = headerEndMarker + 4;
        const std::string headers = all.substr(0, headerEndMarker + 2);
        const std::string contentLengthText = HeaderValue(headers, "Content-Length");
        std::size_t contentLength = 0;
        if (!contentLengthText.empty())
        {
            char* end = nullptr;
            const unsigned long long parsed = std::strtoull(contentLengthText.c_str(), &end, 10);
            if (!end || end == contentLengthText.c_str() || *end != '\0' || parsed > 1024ull * 1024ull)
            {
                result.complete = true;
                result.handled = false;
                result.statusCode = 400;
                result.label = "invalid Content-Length";
                result.response = BuildResponse(400, "Bad Request", "application/json", "{\"error\":\"bad_request\"}");
                buffer.clear();
                return result;
            }
            contentLength = static_cast<std::size_t>(parsed);
        }

        const std::size_t totalBytes = headerBytes + contentLength;
        if (buffer.size() < totalBytes)
            return result;

        result.complete = true;
        result.requestBytes = totalBytes;

        const std::size_t firstLineEnd = headers.find("\r\n");
        if (firstLineEnd == std::string::npos)
        {
            result.statusCode = 400;
            result.label = "malformed request line";
            result.response = BuildResponse(400, "Bad Request", "application/json", "{\"error\":\"bad_request\"}");
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(totalBytes));
            return result;
        }

        const std::string requestLine = headers.substr(0, firstLineEnd);
        const std::size_t firstSpace = requestLine.find(' ');
        const std::size_t secondSpace = firstSpace == std::string::npos ? std::string::npos : requestLine.find(' ', firstSpace + 1);
        if (firstSpace == std::string::npos || secondSpace == std::string::npos)
        {
            result.statusCode = 400;
            result.label = "malformed request line";
            result.response = BuildResponse(400, "Bad Request", "application/json", "{\"error\":\"bad_request\"}");
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(totalBytes));
            return result;
        }

        result.method = requestLine.substr(0, firstSpace);
        std::string target = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        result.host = HeaderValue(headers, "Host");
        // Be tolerant of absolute-form HTTP request targets as well as normal
        // origin-form paths; redirected clients can use either.
        const std::string targetLower = Lower(target);
        if (targetLower.rfind("https://", 0) == 0 || targetLower.rfind("http://", 0) == 0)
        {
            const std::size_t authorityStart = target.find("//") + 2;
            const std::size_t pathStart = target.find('/', authorityStart);
            if (result.host.empty())
                result.host = target.substr(authorityStart, pathStart == std::string::npos ? std::string::npos : pathStart - authorityStart);
            target = pathStart == std::string::npos ? "/" : target.substr(pathStart);
        }
        const std::size_t question = target.find('?');
        result.path = target.substr(0, question);
        const std::string hostLower = Lower(result.host);
        const std::string pathLower = Lower(result.path);
        const std::string query = question == std::string::npos ? std::string{} : target.substr(question + 1);
        const std::string body = contentLength ? all.substr(headerBytes, contentLength) : std::string{};

        const std::string contentTypeLower = Lower(HeaderValue(headers, "Content-Type"));
        const bool bodyIsJson = contentTypeLower.find("application/json") != std::string::npos || LooksLikeJsonObject(body);
        const bool bodyIsForm = !bodyIsJson &&
            (contentTypeLower.find("application/x-www-form-urlencoded") != std::string::npos || body.find('=') != std::string::npos);
        const std::string queryKeys = FieldKeys(query);
        const std::string bodyKeys = bodyIsJson ? JsonTopLevelKeys(body) : (bodyIsForm ? FieldKeys(body) : std::string{});
        if (!queryKeys.empty() && !bodyKeys.empty()) result.formKeys = queryKeys + "," + bodyKeys;
        else result.formKeys = !queryKeys.empty() ? queryKeys : bodyKeys;

        // MW2019 obtains a short-lived OAuth access token immediately after
        // AuthenticationService.GenerateWebCredentials.  Accept only the local
        // synthetic client_sso shape; no Blizzard username/password is accepted.
        const bool oauthHost = hostLower.find("oauth-") == 0 || hostLower.find("battle.net") != std::string::npos;
        const bool oauthPath = pathLower == "/oauth" || pathLower.find("/oauth/") == 0;
        const bool clientSso = HasFormPair(query, "grant_type", "client_sso") ||
            HasFormPair(body, "grant_type", "client_sso");
        if ((oauthPath || oauthHost) && clientSso)
        {
            const std::string responseBody =
                "{\"access_token\":\"revamped-iw8-local-access-token\","
                "\"token_type\":\"bearer\",\"expires_in\":86400,"
                "\"scope\":\"account.standard\"}";
            result.handled = true;
            result.statusCode = 200;
            result.label = "local OAuth client_sso access token";
            result.response = BuildResponse(200, "OK", "application/json; charset=utf-8", responseBody);
        }
        else if (result.method == "POST" &&
            hostLower == "prod.umbrella.demonware.net" &&
            pathLower == "/v1.0/tokens/lsg/")
        {
            // Stock IW8 reaches this exchange only after the signed Auth3 response
            // has been accepted far enough to request an LSG token.  Keep this
            // server-driven: validate the captured request shape and issue a local
            // deterministic token; no client login/fence state is modified.
            // IW8 1.44 sends these values on the URL query for this POST.  The
            // generic request logger intentionally reports query + body keys as
            // one formKeys list, so validate both sources here as well.  Other
            // builds may choose a normal urlencoded body, so keep that accepted.
            const bool queryHasClient = HasFormKey(query, "client");
            const bool queryHasTicket = HasFormKey(query, "ticket");
            const bool queryHasIvSeed = HasFormKey(query, "initialVectorSeed");
            const bool queryHasTitleId = HasFormKey(query, "titleID");
            const bool formHasClient = bodyIsForm && HasFormKey(body, "client");
            const bool formHasTicket = bodyIsForm && HasFormKey(body, "ticket");
            const bool formHasIvSeed = bodyIsForm && HasFormKey(body, "initialVectorSeed");
            const bool formHasTitleId = bodyIsForm && HasFormKey(body, "titleID");

            // IW8 1.44 actually splits this POST across sources: `client` is
            // carried by the URL query while the ticket/IV/title fields are a
            // JSON object in the request body.  The generic formKeys logger has
            // always merged query keys with JSON top-level keys, which is why it
            // could see all four while the v15 endpoint validator only saw
            // `client`.  Use the same accepted sources here so diagnostics and
            // endpoint validation cannot disagree again.
            const bool jsonHasClient = bodyIsJson && JsonValueType(body, "client") != '-';
            const bool jsonHasTicket = bodyIsJson && JsonValueType(body, "ticket") != '-';
            const bool jsonHasIvSeed = bodyIsJson && JsonValueType(body, "initialVectorSeed") != '-';
            const bool jsonHasTitleId = bodyIsJson && JsonValueType(body, "titleID") != '-';

            const bool hasClient = queryHasClient || formHasClient || jsonHasClient;
            const bool hasTicket = queryHasTicket || formHasTicket || jsonHasTicket;
            const bool hasIvSeed = queryHasIvSeed || formHasIvSeed || jsonHasIvSeed;
            const bool hasTitleId = queryHasTitleId || formHasTitleId || jsonHasTitleId;

            const char* bodyStyle = bodyIsJson ? "json" : (bodyIsForm ? "form" : "none");
            const char* fieldSource = !query.empty() && bodyIsJson ? "query+json" :
                (!query.empty() && bodyIsForm ? "query+form" :
                (!query.empty() ? "query" : (bodyIsJson ? "json" : (bodyIsForm ? "form" : "none"))));
            std::ostringstream detail;
            detail << "local Demonware Umbrella LSG token exchange"
                   << " fieldSource=" << fieldSource
                   << " bodyStyle=" << bodyStyle
                   << " client=" << (hasClient ? "present" : "missing")
                   << " ticket=" << (hasTicket ? "present" : "missing")
                   << " initialVectorSeed=" << (hasIvSeed ? "present" : "missing")
                   << " titleID=" << (hasTitleId ? "present" : "missing")
                   << " values=REDACTED responseStyle=UMBRELLA_STOCK_NAMED_V15 stateWrites=off";

            result.handled = true;
            if (!hasClient || !hasTicket || !hasIvSeed || !hasTitleId)
            {
                result.statusCode = 400;
                result.label = detail.str();
                AppendAuthPipelineV58("UMBRELLA_REJECT shape client=%s ticket=%s iv=%s title=%s source=%s",
                    hasClient ? "present" : "missing", hasTicket ? "present" : "missing",
                    hasIvSeed ? "present" : "missing", hasTitleId ? "present" : "missing", fieldSource);
                result.response = BuildResponse(400, "Bad Request",
                    "application/json; charset=utf-8",
                    "{\"error\":\"revamped_bad_umbrella_lsg_shape\"}");
            }
            else
            {
                // The stock 1.44 request carries its Umbrella `ticket` as a JSON
                // string. Returning a made-up printable token proved insufficient.
                // The stock request itself is useful here as the Auth3 credential
                // presented to Umbrella; V67 mints a separate structured LSG token
                // below instead of echoing this request credential back to the client.
                std::string requestTicket;
                const char ticketValueType = bodyIsJson ? JsonValueType(body, "ticket") : '-';
                bool requestTicketExtracted = false;
                if (bodyIsJson && ticketValueType == 's')
                    requestTicketExtracted = JsonStringValue(body, "ticket", requestTicket);
                else if (bodyIsJson && ticketValueType != '-')
                    requestTicketExtracted = JsonUnsignedText(body, "ticket", requestTicket);

                // V72: IW8 1.44 carries initialVectorSeed in the JSON body on the
                // proven path.  Preserve its exact textual representation without
                // logging it so the LSG oracle can test raw/base64/hex 24-byte
                // interpretations alongside the ticket-carried session keys.
                std::string umbrellaInitialVectorSeed;
                if (bodyIsJson)
                {
                    const char ivType = JsonValueType(body, "initialVectorSeed");
                    if (ivType == 's')
                        JsonStringValue(body, "initialVectorSeed", umbrellaInitialVectorSeed);
                    else if (ivType != '-')
                        JsonUnsignedText(body, "initialVectorSeed", umbrellaInitialVectorSeed);
                }
                g_authPipeline.lastUmbrellaInitialVectorSeed = umbrellaInitialVectorSeed;

                const Auth3TicketMatch ticketMatch = CorrelateUmbrellaTicket(requestTicket);

                // V67: the request's Auth3 server_ticket is the credential used
                // to authorize this exchange, but it is not the credential we
                // return to bdLobby.  V61 proved the host-only endpoint reaches
                // native LSG; V66 then proved the echoed server_ticket has no DW
                // ticket magic/session key at the packed ticket offsets.  Mint a
                // structured LSG ticket tied to the same Auth3 session key.
                const bool requestServerTicketVerified =
                    requestTicketExtracted &&
                    !requestTicket.empty() &&
                    ticketMatch.exactServerMatch;
                const std::uint32_t lsgTitleId = ticketMatch.titleId != 0u
                    ? ticketMatch.titleId
                    : 5800u;
                std::string localLsgToken = BuildLocalLsgTokenV67(lsgTitleId);
                if (localLsgToken.empty() && ticketMatch.haveAuth3ClientTicket)
                    localLsgToken = g_authPipeline.lastAuth3ClientTicket;
                g_authPipeline.lastMintedLsgToken = localLsgToken;

                const UmbrellaTicketShape ticketShape = DescribeUmbrellaTicket(requestTicket);
                const UmbrellaTicketShape responseTicketShape = DescribeUmbrellaTicket(localLsgToken);
                const std::string requestTicketHash = Sha256Prefix(requestTicket);
                const std::string auth3ClientHash = Sha256Prefix(g_authPipeline.lastAuth3ClientTicket);
                const std::string auth3ServerHash = Sha256Prefix(g_authPipeline.lastAuth3ServerTicket);
                AppendAuthPipelineV58("UMBRELLA_REQUEST auth3Serial=%llu ageMs=%llu ticketType=%c ticketLen=%llu requestHash=%s auth3ClientHash=%s auth3ServerHash=%s exactClient=%s exactServer=%s decodedBytes=%llu dwAuthMagic=%s titleId=%u values=REDACTED",
                    static_cast<unsigned long long>(ticketMatch.serial), static_cast<unsigned long long>(ticketMatch.ageMs),
                    ticketValueType, static_cast<unsigned long long>(requestTicket.size()), requestTicketHash.c_str(),
                    auth3ClientHash.c_str(), auth3ServerHash.c_str(), ticketMatch.exactClientMatch ? "YES" : "NO",
                    ticketMatch.exactServerMatch ? "YES" : "NO", static_cast<unsigned long long>(ticketShape.decodedBytes),
                    ticketShape.dwAuthTicketMagic ? "YES" : "NO", static_cast<unsigned>(ticketShape.titleId));

                detail << " ticketType=" << ticketValueType
                       << " ticketLen=" << requestTicket.size()
                       << " tokenSource="
                       << (!localLsgToken.empty() ? "mintedDwAuthTicketV67" : "fallback")
                       << " auth3Serial=" << ticketMatch.serial
                       << " auth3AgeMs=" << static_cast<unsigned long long>(ticketMatch.ageMs)
                       << " ticketMatchesAuth3Client=" << (ticketMatch.exactClientMatch ? "YES" : "NO")
                       << " ticketMatchesAuth3Server=" << (ticketMatch.exactServerMatch ? "YES" : "NO")
                       << " auth3ClientPresent=" << (ticketMatch.haveAuth3ClientTicket ? "yes" : "no")
                       << " auth3ServerPresent=" << (ticketMatch.haveAuth3ServerTicket ? "yes" : "no")
                       << " responseStyle=UMBRELLA_STOCK_NAMED_V15";

                log::Print("[LSG-TICKET-CORRELATION] auth3Serial=%llu requestHash=%s auth3ClientHash=%s auth3ServerHash=%s exactClient=%s exactServer=%s base64=%s decodedBytes=%llu dwAuthMagic=%s type=%u titleId=%u issued=%u expires=%u sessionKeyNonZero=%u values=REDACTED stateWrites=off",
                    static_cast<unsigned long long>(ticketMatch.serial),
                    requestTicketHash.c_str(), auth3ClientHash.c_str(), auth3ServerHash.c_str(),
                    ticketMatch.exactClientMatch ? "YES" : "NO",
                    ticketMatch.exactServerMatch ? "YES" : "NO",
                    ticketShape.base64Ok ? "yes" : "no",
                    static_cast<unsigned long long>(ticketShape.decodedBytes),
                    ticketShape.dwAuthTicketMagic ? "YES" : "NO",
                    static_cast<unsigned>(ticketShape.type),
                    static_cast<unsigned>(ticketShape.titleId),
                    static_cast<unsigned>(ticketShape.timeIssued),
                    static_cast<unsigned>(ticketShape.timeExpires),
                    ticketShape.sessionKeyNonZero);

                log::Print("[AUTH-V67] LSG_TOKEN_MINTED auth3Serial=%llu requestServerTicketVerified=%s rawBytes=%llu dwAuthMagic=%s type=%u titleId=%u issued=%u expires=%u sessionKeyNonZero=%u tokenHash=%s values=REDACTED stateWrites=off",
                    static_cast<unsigned long long>(ticketMatch.serial),
                    requestServerTicketVerified ? "YES" : "NO",
                    static_cast<unsigned long long>(responseTicketShape.decodedBytes),
                    responseTicketShape.dwAuthTicketMagic ? "YES" : "NO",
                    static_cast<unsigned>(responseTicketShape.type),
                    static_cast<unsigned>(responseTicketShape.titleId),
                    static_cast<unsigned>(responseTicketShape.timeIssued),
                    static_cast<unsigned>(responseTicketShape.timeExpires),
                    responseTicketShape.sessionKeyNonZero,
                    Sha256Prefix(localLsgToken).c_str());
                AppendAuthPipelineV58("AUTH_V67_LSG_TOKEN_MINTED auth3Serial=%llu requestServerTicketVerified=%s rawBytes=%llu dwAuthMagic=%s titleId=%u sessionKeyNonZero=%u tokenHash=%s next=expect_native_0x82",
                    static_cast<unsigned long long>(ticketMatch.serial),
                    requestServerTicketVerified ? "YES" : "NO",
                    static_cast<unsigned long long>(responseTicketShape.decodedBytes),
                    responseTicketShape.dwAuthTicketMagic ? "YES" : "NO",
                    static_cast<unsigned>(responseTicketShape.titleId),
                    responseTicketShape.sessionKeyNonZero,
                    Sha256Prefix(localLsgToken).c_str());

                // V15 keeps only field names that are actually present in the
                // stock 1.44 image: the proven legacy bdUmbrellaUserAccount names,
                // generic `token`, and camel-case `lsgEndpoint`.  V14 proved that
                // `expires_in` and snake-case `lsg_endpoint` are not present as exact
                // stock strings, so do not keep emitting those speculative names.
                // This remains a server-protocol compatibility probe only.
                //
                // Do not claim stock accepted this result until a lobby DNS/socket
                // transition is actually observed.
                // V61: V60 produced the first runtime LSG stream attempts, but the stock
                // client resolved the host:port string "127.0.0.1:3075" to the invalid
                // sentinel 0.255.0.255 and then used its own fixed TCP port 3074.  Test the
                // stock-shaped endpoint as a host/IP only while preserving every proven
                // stock field name. V67 keeps that endpoint fix and replaces only the
                // response token material. This changes only the
                // emulated server response; no client login/DW state is forced.
                const LONG responseOrdinal = InterlockedIncrement(&g_authPipeline.umbrellaSweepCount);
                const std::string responseToken = localLsgToken;
                const std::string localLobbyEndpoint = "127.0.0.1";
                const std::string responseBody =
                    "{\"umbrellaID\":1,\"accessToken\":\"" + JsonEscape(responseToken) +
                    "\",\"expires\":86400,\"accounts\":[],"
                    "\"token\":\"" + JsonEscape(responseToken) +
                    "\",\"lsgEndpoint\":\"" + JsonEscape(localLobbyEndpoint) + "\"}";
                result.statusCode = 200;
                result.label = detail.str();
                result.response = BuildResponse(200, "OK", "application/json; charset=utf-8", responseBody);
                MarkUmbrellaLsgAccepted(ticketMatch.serial);

                log::Print("[AUTH-V67] UMBRELLA_RESPONSE ordinal=%ld auth3Serial=%llu exactServer=%s schema=FULL_STOCK_NAMED tokenSource=%s tokenLen=%llu endpoint=%s endpointFormat=HOST_ONLY clientPortPolicy=FIXED_3074 deterministic=yes next=expect_TCP_LSG_HELLO",
                    static_cast<long>(responseOrdinal), static_cast<unsigned long long>(ticketMatch.serial),
                    ticketMatch.exactServerMatch ? "YES" : "NO",
                    "mintedDwAuthTicketV67",
                    static_cast<unsigned long long>(responseToken.size()), localLobbyEndpoint.c_str());
                AppendAuthPipelineV58("AUTH_V67_UMBRELLA_RESPONSE ordinal=%ld auth3Serial=%llu exactServer=%s schema=FULL_STOCK_NAMED tokenSource=%s tokenLen=%llu endpoint=%s endpointFormat=HOST_ONLY clientPortPolicy=FIXED_3074 deterministic=yes next=expect_TCP_LSG_HELLO",
                    static_cast<long>(responseOrdinal), static_cast<unsigned long long>(ticketMatch.serial),
                    ticketMatch.exactServerMatch ? "YES" : "NO",
                    "mintedDwAuthTicketV67",
                    static_cast<unsigned long long>(responseToken.size()), localLobbyEndpoint.c_str());
            }
        }
        else if (result.method == "POST" && pathLower == "/auth/" &&
            hostLower.find("demonware.net") != std::string::npos)
        {
            std::string authTask;
            std::string titleIdText;
            std::string ivSeed;
            std::string identity;
            std::string serviceLevel;
            std::string extraData;
            const std::string transactionId = HeaderValue(headers, "X-TransactionID");
            const std::string requestSignature = HeaderValue(headers, "X-Signature");
            const std::string acceptType = HeaderValue(headers, "Accept");
            const std::string userAgent = HeaderValue(headers, "User-Agent");
            const bool taskOk = bodyIsJson && JsonUnsignedText(body, "auth_task", authTask);
            const bool titleOk = bodyIsJson && JsonUnsignedText(body, "title_id", titleIdText);
            const bool ivOk = bodyIsJson && JsonUnsignedText(body, "iv_seed", ivSeed);
            const bool identityOk = bodyIsJson && JsonStringValue(body, "identity", identity);
            const bool serviceLevelOk = bodyIsJson && JsonStringValue(body, "service_level", serviceLevel);
            const bool extraDataOk = bodyIsJson && JsonStringValue(body, "extra_data", extraData) && LooksLikeJsonObject(extraData);

            std::string sessionToken;
            std::string accountToken;
            std::string machineId;
            std::string version;
            if (extraDataOk)
            {
                JsonStringValue(extraData, "session_token", sessionToken);
                JsonStringValue(extraData, "account_token", accountToken);
                JsonStringValue(extraData, "machine_id", machineId);
                JsonStringValue(extraData, "version", version);
            }

            const bool sessionTokenPrintableAscii = !sessionToken.empty() &&
                std::all_of(sessionToken.begin(), sessionToken.end(), [](const unsigned char c) {
                    return c >= 0x20u && c <= 0x7Eu;
                });
            const std::size_t sessionTokenControlBytes = static_cast<std::size_t>(
                std::count_if(sessionToken.begin(), sessionToken.end(), [](const unsigned char c) {
                    return c < 0x20u || c == 0x7Fu;
                }));

            std::uint32_t titleId = 0;
            if (titleOk)
            {
                const unsigned long parsed = std::strtoul(titleIdText.c_str(), nullptr, 10);
                titleId = static_cast<std::uint32_t>(parsed & 0xFFFFFFFFu);
            }

            std::ostringstream detail;
            detail << "IW8 Demonware BNet auth json=" << (bodyIsJson ? "yes" : "no")
                   << " task=" << (taskOk ? authTask : "?")
                   << " responseTask=" << (taskOk ? std::to_string(std::strtoul(authTask.c_str(), nullptr, 10) + 1u) : "?")
                   << " title=" << (titleOk ? titleIdText : "?")
                   << " ivSeed=" << (ivOk ? "present" : "missing")
                   << " identityLen=" << (identityOk ? identity.size() : 0u)
                   << " serviceLevel=" << (serviceLevelOk ? serviceLevel : "?")
                   << " extraDataJson=" << (extraDataOk ? "yes" : "no")
                   << " nestedKeys=" << (extraDataOk ? JsonTopLevelKeys(extraData) : "")
                   << " versionLen=" << version.size()
                   << " sessionTokenLen=" << sessionToken.size()
                   << " sessionTokenPrintableAscii=" << (sessionTokenPrintableAscii ? "yes" : "no")
                   << " sessionTokenControlBytes=" << sessionTokenControlBytes
                   << " accountTokenLen=" << accountToken.size()
                   << " machineIdLen=" << machineId.size()
                   << " transactionId=" << (transactionId.empty() ? "missing" : "present")
                   << " transactionIdLen=" << transactionId.size()
                   << " requestSignature=" << (requestSignature.empty() ? "missing" : "present")
                   << " requestSignatureLen=" << requestSignature.size()
                   << " accept=" << (acceptType.empty() ? "missing" : acceptType)
                   << " userAgentLen=" << userAgent.size()
                   << " ticketMode=BNET_RAW_128 responseStyle=TASK_PLUS_ONE clientIdOut=iw-cod-iw8-bnet serviceLevelOut=paid"
                   << " responseSignature=RSA_PSS_SHA256"
                   << " httpStyle=TornadoServer/4.5.3 stateWrites=off";

            if (!bodyIsJson || !taskOk || !titleOk || !ivOk || !extraDataOk || sessionToken.empty())
            {
                result.handled = true;
                result.statusCode = 400;
                result.label = detail.str();
                AppendAuthPipelineV58("AUTH3_REJECT task=%s title=%s iv=%s extraData=%s sessionTokenLen=%llu",
                    taskOk ? authTask.c_str() : "?", titleOk ? titleIdText.c_str() : "?", ivOk ? "present" : "missing",
                    extraDataOk ? "yes" : "no", static_cast<unsigned long long>(sessionToken.size()));
                result.response = BuildResponse(400, "Bad Request", "application/json; charset=utf-8",
                    "{\"auth_task\":\"85\",\"code\":\"701\",\"error\":\"revamped_bad_dw_bnet_auth_shape\"}");
            }
            else
            {
                result.handled = true;
                result.statusCode = 200;
                result.label = detail.str();
                result.response = BuildDwAuthResponse(
                    BuildDwBnetAuthResponse(authTask, ivSeed, titleId, identity, serviceLevel, sessionToken));
                AppendAuthPipelineV58("AUTH3_RESPONSE status=200 requestTask=%s responseTask=%lu titleId=%u clientId=iw-cod-iw8-bnet accountType=bnet serviceLevel=paid lsg_endpoint=null signed=RSA_PSS_SHA256",
                    authTask.c_str(), std::strtoul(authTask.c_str(), nullptr, 10) + 1u, static_cast<unsigned>(titleId));
            }
        }
        else if (pathLower == "/optinservice/v1/getaccountoptins")
        {
            // Empty local consent collection: structurally valid and intentionally
            // contains no synthetic marketing/account-consent choices.
            result.handled = true;
            result.statusCode = 200;
            result.label = "local empty account opt-ins";
            result.response = BuildResponse(200, "OK", "application/json; charset=utf-8", "{\"optInSelections\":[]}");
        }
        else
        {
            result.handled = false;
            result.statusCode = 404;
            result.label = "unimplemented local HTTPS endpoint";
            result.response = BuildResponse(404, "Not Found", "application/json; charset=utf-8", "{\"error\":\"revamped_unimplemented\"}");
        }

        buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(totalBytes));
        return result;
    }

    void NotePostLsgTransport(std::uint16_t port, const char* transport)
    {
        if (g_authPipeline.pendingLsgAtMs == 0 || g_authPipeline.postLsgTransportSeen)
            return;
        if (port != 3074u && port != 3075u)
            return;

        const ULONGLONG ageMs = GetTickCount64() - g_authPipeline.pendingLsgAtMs;
        const std::string transportText = transport && *transport ? transport : "?";
        if (transportText.find("UNATTRIBUTED") != std::string::npos)
        {
            ++g_authPipeline.postLsgUnattributedActivity;
            if (g_authPipeline.postLsgUnattributedActivity <= 4u)
            {
                log::Print("[AUTH-PIPELINE] POST-LSG SOCKET ACTIVITY auth3Serial=%llu ageMs=%llu transport=%s port=%u attribution=UNVERIFIED; UDP/3074 can be STUN and does NOT prove mw-lobby routing",
                    static_cast<unsigned long long>(g_authPipeline.pendingLsgSerial),
                    static_cast<unsigned long long>(ageMs), transportText.c_str(), static_cast<unsigned>(port));
            }
            return;
        }

        g_authPipeline.postLsgTransportSeen = true;
        log::Print("[AUTH-PIPELINE] POST-LSG ATTRIBUTED TRANSPORT auth3Serial=%llu ageMs=%llu transport=%s port=%u; attribution supplied by protocol-specific listener",
            static_cast<unsigned long long>(g_authPipeline.pendingLsgSerial),
            static_cast<unsigned long long>(ageMs), transportText.c_str(), static_cast<unsigned>(port));
    }

    namespace
    {
        bool DecodeHex24V72(std::string_view text, std::uint8_t out[24])
        {
            if (!out) return false;
            if (text.size() == 50u && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
                text.remove_prefix(2u);
            if (text.size() != 48u)
                return false;

            auto nibble = [](char c) -> int
            {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
                return -1;
            };

            for (std::size_t i = 0; i < 24u; ++i)
            {
                const int hi = nibble(text[i * 2u]);
                const int lo = nibble(text[i * 2u + 1u]);
                if (hi < 0 || lo < 0)
                    return false;
                out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
            }
            return true;
        }

        bool DecodeBase64Exact24V72(std::string_view text, std::uint8_t out[24])
        {
            if (!out || text.empty()) return false;
            std::vector<std::uint8_t> decoded;
            if (!Base64Decode(text, decoded) || decoded.size() != 24u)
                return false;
            std::memcpy(out, decoded.data(), 24u);
            return true;
        }
    }

    // V72 source IDs are intentionally numeric so ServerLsg.cpp can consume this
    // diagnostic API without changing the user's existing WebAuthService.h.
    // 1=local constant, 2=Auth3 client ticket sessionKey, 3=Auth3 server-ticket
    // prefix, 4=minted LSG ticket sessionKey, 5..7=Auth3 iv_seed raw/b64/hex,
    // 8..10=Umbrella initialVectorSeed raw/b64/hex.
    std::size_t GetLsgSessionKeyCandidatesV72(std::uint8_t* outKeys, std::uint32_t* outKinds,
        std::size_t maxKeys, std::uint64_t* auth3Serial)
    {
        if (!outKeys || !outKinds || maxKeys == 0u || g_authPipeline.auth3Serial == 0u)
            return 0u;

        std::size_t count = 0u;
        auto add = [&](std::uint32_t kind, const std::uint8_t key[24])
        {
            if (!key || count >= maxKeys) return;
            std::memcpy(outKeys + count * 24u, key, 24u);
            outKinds[count] = kind;
            ++count;
        };

        add(1u, kLocalAuth3SessionKey);

        std::vector<std::uint8_t> decoded;
        if (Base64Decode(g_authPipeline.lastAuth3ClientTicket, decoded) && decoded.size() == 128u)
            add(2u, decoded.data() + 97u);
        decoded.clear();
        if (Base64Decode(g_authPipeline.lastAuth3ServerTicket, decoded) && decoded.size() >= 24u)
            add(3u, decoded.data());
        decoded.clear();
        if (Base64Decode(g_authPipeline.lastMintedLsgToken, decoded) && decoded.size() == 128u)
            add(4u, decoded.data() + 97u);

        auto addTextForms = [&](const std::string& text, std::uint32_t rawKind,
            std::uint32_t b64Kind, std::uint32_t hexKind)
        {
            std::uint8_t key[24]{};
            if (text.size() == 24u)
            {
                std::memcpy(key, text.data(), 24u);
                add(rawKind, key);
            }
            std::memset(key, 0, sizeof(key));
            if (DecodeBase64Exact24V72(text, key))
                add(b64Kind, key);
            std::memset(key, 0, sizeof(key));
            if (DecodeHex24V72(text, key))
                add(hexKind, key);
        };

        addTextForms(g_authPipeline.lastAuth3IvSeed, 5u, 6u, 7u);
        addTextForms(g_authPipeline.lastUmbrellaInitialVectorSeed, 8u, 9u, 10u);

        if (auth3Serial)
            *auth3Serial = g_authPipeline.auth3Serial;

        log::Print("[AUTH-V72] LSG_KEY_SOURCE_CANDIDATES auth3Serial=%llu candidates=%llu auth3IvChars=%llu umbrellaIvChars=%llu rawValues=REDACTED stateWrites=off",
            static_cast<unsigned long long>(g_authPipeline.auth3Serial),
            static_cast<unsigned long long>(count),
            static_cast<unsigned long long>(g_authPipeline.lastAuth3IvSeed.size()),
            static_cast<unsigned long long>(g_authPipeline.lastUmbrellaInitialVectorSeed.size()));
        return count;
    }


    // V73 exposes the exact byte containers already produced by this emulator so
    // ServerLsg can test packed-layout offsets without logging any raw secrets.
    // Kinds: 101=Auth3 client ticket, 102=Auth3 server ticket, 103=minted LSG
    // ticket, 104=Auth3 iv_seed text, 105=Umbrella initialVectorSeed text.
    std::size_t GetLsgKeyMaterialBlobsV73(std::uint8_t* outBlobs, std::uint32_t* outSizes,
        std::uint32_t* outKinds, std::size_t stride, std::size_t maxBlobs, std::uint64_t* auth3Serial)
    {
        if (!outBlobs || !outSizes || !outKinds || stride == 0u || maxBlobs == 0u ||
            g_authPipeline.auth3Serial == 0u)
            return 0u;

        std::size_t count = 0u;
        auto addBlob = [&](std::uint32_t kind, const std::uint8_t* bytes, std::size_t size)
        {
            if (!bytes || size == 0u || count >= maxBlobs) return;
            const std::size_t copy = (std::min)(size, stride);
            std::memset(outBlobs + count * stride, 0, stride);
            std::memcpy(outBlobs + count * stride, bytes, copy);
            outSizes[count] = static_cast<std::uint32_t>(copy);
            outKinds[count] = kind;
            ++count;
        };

        std::vector<std::uint8_t> decoded;
        if (Base64Decode(g_authPipeline.lastAuth3ClientTicket, decoded) && !decoded.empty())
            addBlob(101u, decoded.data(), decoded.size());
        decoded.clear();
        if (Base64Decode(g_authPipeline.lastAuth3ServerTicket, decoded) && !decoded.empty())
            addBlob(102u, decoded.data(), decoded.size());
        decoded.clear();
        if (Base64Decode(g_authPipeline.lastMintedLsgToken, decoded) && !decoded.empty())
            addBlob(103u, decoded.data(), decoded.size());

        if (!g_authPipeline.lastAuth3IvSeed.empty())
            addBlob(104u, reinterpret_cast<const std::uint8_t*>(g_authPipeline.lastAuth3IvSeed.data()),
                g_authPipeline.lastAuth3IvSeed.size());
        if (!g_authPipeline.lastUmbrellaInitialVectorSeed.empty())
            addBlob(105u, reinterpret_cast<const std::uint8_t*>(g_authPipeline.lastUmbrellaInitialVectorSeed.data()),
                g_authPipeline.lastUmbrellaInitialVectorSeed.size());

        if (auth3Serial) *auth3Serial = g_authPipeline.auth3Serial;
        log::Print("[AUTH-V73] LSG_KEY_MATERIAL_BLOBS auth3Serial=%llu blobs=%llu stride=%llu rawValues=REDACTED stateWrites=off",
            static_cast<unsigned long long>(g_authPipeline.auth3Serial),
            static_cast<unsigned long long>(count), static_cast<unsigned long long>(stride));
        return count;
    }

    bool GetLatestAuth3SessionKey(std::uint8_t outKey[24], std::uint64_t* auth3Serial)
    {
        if (!outKey || g_authPipeline.auth3Serial == 0 ||
            g_authPipeline.lastAuth3ClientTicket.empty() ||
            g_authPipeline.lastAuth3ServerTicket.empty())
        {
            return false;
        }

        std::memcpy(outKey, kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));
        if (auth3Serial)
            *auth3Serial = g_authPipeline.auth3Serial;
        return true;
    }

    void PollAuthPipelineDiagnostics()
    {
        if (g_authPipeline.pendingLsgAtMs == 0 || g_authPipeline.postLsgTransportSeen)
            return;

        const ULONGLONG ageMs = GetTickCount64() - g_authPipeline.pendingLsgAtMs;
        if (ageMs >= 3000u && (g_authPipeline.pendingLsgWarnings & 1u) == 0u)
        {
            g_authPipeline.pendingLsgWarnings |= 1u;
            log::Print("[AUTH-PIPELINE] STALL auth3Serial=%llu ageMs=%llu stage=AFTER_LSG_HTTP_200 no ATTRIBUTED lobby transport observed yet; generic UDP/3074 is not sufficient because STUN shares that port",
                static_cast<unsigned long long>(g_authPipeline.pendingLsgSerial),
                static_cast<unsigned long long>(ageMs));
        }
        if (ageMs >= 9000u && (g_authPipeline.pendingLsgWarnings & 2u) == 0u)
        {
            g_authPipeline.pendingLsgWarnings |= 2u;
            log::Print("[AUTH-PIPELINE] STALL-PERSISTENT auth3Serial=%llu ageMs=%llu stage=AFTER_LSG_HTTP_200 no ATTRIBUTED mw-lobby transport observed; correlate client DNS->socket route before changing LSG/Auth3 protocol",
                static_cast<unsigned long long>(g_authPipeline.pendingLsgSerial),
                static_cast<unsigned long long>(ageMs));
        }
    }
}
