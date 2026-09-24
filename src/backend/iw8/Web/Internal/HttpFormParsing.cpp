#include "HttpFormParsing.h"

namespace revamped::iw8::web
{
    namespace
    {
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
    }
}
