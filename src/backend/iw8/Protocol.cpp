#include "Protocol.h"

#include <algorithm>
#include <cstdio>

namespace revamped::iw8::protocol
{
    std::string HexPrefix(const void* data, std::size_t size, std::size_t limit)
    {
        if (!data || !size) return {};
        const auto* bytes = static_cast<const unsigned char*>(data);
        const std::size_t count = (std::min)(size, limit);
        std::string out;
        out.reserve(count * 3);
        char tmp[8]{};
        for (std::size_t i = 0; i < count; ++i)
        {
            std::snprintf(tmp, sizeof(tmp), "%02X ", bytes[i]);
            out += tmp;
        }
        return out;
    }

    std::string AsciiPrefix(const void* data, std::size_t size, std::size_t limit)
    {
        if (!data || !size) return {};
        const auto* bytes = static_cast<const unsigned char*>(data);
        const std::size_t count = (std::min)(size, limit);
        std::string out;
        out.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
            out.push_back(bytes[i] >= 32 && bytes[i] <= 126 ? static_cast<char>(bytes[i]) : '.');
        return out;
    }

    bool LooksLikeTlsClientHello(const void* data, std::size_t size)
    {
        if (!data || size < 6) return false;
        const auto* p = static_cast<const unsigned char*>(data);
        return p[0] == 0x16 && p[1] == 0x03 && p[5] == 0x01;
    }

    static std::uint16_t Read16(const unsigned char* p)
    {
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
    }

    static std::uint32_t Read24(const unsigned char* p)
    {
        return (static_cast<std::uint32_t>(p[0]) << 16) |
               (static_cast<std::uint32_t>(p[1]) << 8) |
               static_cast<std::uint32_t>(p[2]);
    }

    std::string TryExtractTlsSni(const void* data, std::size_t size)
    {
        if (!LooksLikeTlsClientHello(data, size)) return {};
        const auto* p = static_cast<const unsigned char*>(data);
        if (size < 9) return {};

        const std::size_t recordLength = Read16(p + 3);
        if (recordLength + 5 > size) return {};
        if (Read24(p + 6) + 9 > size) return {};

        std::size_t off = 9;
        if (off + 2 + 32 > size) return {};
        off += 2 + 32; // legacy version + random

        if (off + 1 > size) return {};
        const std::size_t sessionLen = p[off++];
        if (off + sessionLen > size) return {};
        off += sessionLen;

        if (off + 2 > size) return {};
        const std::size_t cipherLen = Read16(p + off);
        off += 2;
        if (off + cipherLen > size) return {};
        off += cipherLen;

        if (off + 1 > size) return {};
        const std::size_t compressionLen = p[off++];
        if (off + compressionLen > size) return {};
        off += compressionLen;

        if (off + 2 > size) return {};
        const std::size_t extensionsLen = Read16(p + off);
        off += 2;
        const std::size_t extensionsEnd = (std::min)(size, off + extensionsLen);

        while (off + 4 <= extensionsEnd)
        {
            const std::uint16_t type = Read16(p + off);
            const std::size_t len = Read16(p + off + 2);
            off += 4;
            if (off + len > extensionsEnd) break;
            if (type == 0x0000 && len >= 5)
            {
                std::size_t sni = off;
                const std::size_t listLen = Read16(p + sni);
                sni += 2;
                const std::size_t listEnd = (std::min)(off + len, sni + listLen);
                while (sni + 3 <= listEnd)
                {
                    const unsigned char nameType = p[sni++];
                    const std::size_t nameLen = Read16(p + sni);
                    sni += 2;
                    if (sni + nameLen > listEnd) break;
                    if (nameType == 0)
                        return std::string(reinterpret_cast<const char*>(p + sni), nameLen);
                    sni += nameLen;
                }
            }
            off += len;
        }
        return {};
    }

    std::string Classify(const void* data, std::size_t size)
    {
        if (!data || !size) return "empty";
        const auto* p = static_cast<const unsigned char*>(data);
        if (LooksLikeTlsClientHello(data, size)) return "tls-client-hello";
        if (size >= 4 && p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ') return "http";
        if (size >= 5 && p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T' && p[4] == ' ') return "http";
        if (size >= 8 && std::equal(p, p + 8, reinterpret_cast<const unsigned char*>("CRIW8PNG"))) return "revamped-probe";
        return "binary";
    }
}
