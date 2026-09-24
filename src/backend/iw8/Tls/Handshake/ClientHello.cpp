#include "ClientHello.h"

namespace revamped::iw8
{
    namespace
    {
        std::uint16_t ReadBe16(const unsigned char* p)
        {
            return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
        }

        std::uint32_t ReadBe24(const unsigned char* p)
        {
            return (static_cast<std::uint32_t>(p[0]) << 16) |
                   (static_cast<std::uint32_t>(p[1]) << 8) |
                   static_cast<std::uint32_t>(p[2]);
        }

        const char* TlsVersionName(std::uint16_t version)
        {
            switch (version)
            {
            case 0x0301: return "TLS1.0";
            case 0x0302: return "TLS1.1";
            case 0x0303: return "TLS1.2";
            case 0x0304: return "TLS1.3";
            default: return "unknown";
            }
        }

        std::string Hex16(std::uint16_t value)
        {
            char out[16]{};
            _snprintf_s(out, sizeof(out), _TRUNCATE, "0x%04X", static_cast<unsigned>(value));
            return out;
        }

        bool LogTlsClientHello(std::uint64_t id, std::uint16_t localPort, const unsigned char* data, std::size_t size, std::string* sniOut = nullptr)
        {
            if (!data || size < 9 || data[0] != 0x16 || data[5] != 0x01) return false;
            const std::size_t recordLength = ReadBe16(data + 3);
            if (recordLength + 5 > size) return false;
            const std::size_t helloLength = ReadBe24(data + 6);
            if (helloLength + 9 > size) return false;

            const std::uint16_t recordVersion = ReadBe16(data + 1);
            std::size_t off = 9;
            if (off + 34 > size) return false;
            const std::uint16_t legacyVersion = ReadBe16(data + off);
            off += 34; // version + random

            if (off + 1 > size) return false;
            const std::size_t sessionLength = data[off++];
            if (off + sessionLength > size) return false;
            off += sessionLength;

            if (off + 2 > size) return false;
            const std::size_t cipherLength = ReadBe16(data + off);
            off += 2;
            if (off + cipherLength > size || (cipherLength & 1u)) return false;
            std::ostringstream ciphers;
            for (std::size_t i = 0; i < cipherLength; i += 2)
            {
                if (i) ciphers << ',';
                ciphers << Hex16(ReadBe16(data + off + i));
            }
            off += cipherLength;

            if (off + 1 > size) return false;
            const std::size_t compressionLength = data[off++];
            if (off + compressionLength > size) return false;
            off += compressionLength;

            std::string sni;
            std::string alpn;
            std::ostringstream extensions;
            std::ostringstream supportedVersions;
            if (off + 2 <= size)
            {
                const std::size_t extensionsLength = ReadBe16(data + off);
                off += 2;
                const std::size_t extensionsEnd = (std::min)(size, off + extensionsLength);
                bool firstExtension = true;
                while (off + 4 <= extensionsEnd)
                {
                    const std::uint16_t type = ReadBe16(data + off);
                    const std::size_t length = ReadBe16(data + off + 2);
                    off += 4;
                    if (off + length > extensionsEnd) break;
                    if (!firstExtension) extensions << ',';
                    firstExtension = false;
                    extensions << Hex16(type);

                    if (type == 0x0000 && length >= 5)
                    {
                        std::size_t pos = off;
                        const std::size_t listLength = ReadBe16(data + pos);
                        pos += 2;
                        const std::size_t listEnd = (std::min)(off + length, pos + listLength);
                        while (pos + 3 <= listEnd)
                        {
                            const unsigned char nameType = data[pos++];
                            const std::size_t nameLength = ReadBe16(data + pos);
                            pos += 2;
                            if (pos + nameLength > listEnd) break;
                            if (nameType == 0)
                            {
                                sni.assign(reinterpret_cast<const char*>(data + pos), nameLength);
                                break;
                            }
                            pos += nameLength;
                        }
                    }
                    else if (type == 0x0010 && length >= 2)
                    {
                        std::size_t pos = off;
                        const std::size_t listLength = ReadBe16(data + pos);
                        pos += 2;
                        const std::size_t listEnd = (std::min)(off + length, pos + listLength);
                        bool first = true;
                        while (pos < listEnd)
                        {
                            const std::size_t itemLength = data[pos++];
                            if (pos + itemLength > listEnd) break;
                            if (!first) alpn += ',';
                            first = false;
                            alpn.append(reinterpret_cast<const char*>(data + pos), itemLength);
                            pos += itemLength;
                        }
                    }
                    else if (type == 0x002B && length >= 3)
                    {
                        std::size_t pos = off;
                        const std::size_t listLength = data[pos++];
                        const std::size_t listEnd = (std::min)(off + length, pos + listLength);
                        bool first = true;
                        while (pos + 2 <= listEnd)
                        {
                            const std::uint16_t version = ReadBe16(data + pos);
                            pos += 2;
                            if (!first) supportedVersions << ',';
                            first = false;
                            supportedVersions << TlsVersionName(version) << '(' << Hex16(version) << ')';
                        }
                    }
                    off += length;
                }
            }

            log::Print("[TLS%u] id=%llu ClientHello record=%s(%s) legacy=%s(%s) recordBytes=%llu helloBytes=%llu",
                static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), TlsVersionName(recordVersion), Hex16(recordVersion).c_str(),
                TlsVersionName(legacyVersion), Hex16(legacyVersion).c_str(),
                static_cast<unsigned long long>(recordLength + 5), static_cast<unsigned long long>(helloLength));
            log::Print("[TLS%u] id=%llu sni=%s alpn=%s supportedVersions=%s",
                static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), sni.empty() ? "<none>" : sni.c_str(),
                alpn.empty() ? "<none>" : alpn.c_str(), supportedVersions.str().empty() ? "<legacy-only>" : supportedVersions.str().c_str());
            log::Print("[TLS%u] id=%llu cipherSuites=%s", static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), ciphers.str().c_str());
            log::Print("[TLS%u] id=%llu extensions=%s", static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), extensions.str().c_str());
            if (sniOut)
                *sniOut = sni;
            return true;
        }
    }
}
