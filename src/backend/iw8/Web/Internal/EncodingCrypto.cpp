#include "EncodingCrypto.h"

namespace revamped::iw8::web
{
    namespace
    {
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
    }
}
