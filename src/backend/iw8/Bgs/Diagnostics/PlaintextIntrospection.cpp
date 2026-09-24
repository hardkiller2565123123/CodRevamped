#include "PlaintextIntrospection.h"

namespace revamped::iw8
{
    namespace
    {
        std::string HexPrefix(const void* data, std::size_t size, std::size_t limit)
        {
            if (!data || !size) return "<empty>";
            const auto* bytes = static_cast<const BYTE*>(data);
            const std::size_t shown = (std::min)(size, limit);
            std::ostringstream out;
            out << std::hex << std::uppercase << std::setfill('0');
            for (std::size_t i = 0; i < shown; ++i)
            {
                if (i) out << ' ';
                out << std::setw(2) << static_cast<unsigned>(bytes[i]);
            }
            if (shown < size) out << " ...";
            return out.str();
        }

        std::uint32_t ReadLe32(const BYTE* p)
        {
            return static_cast<std::uint32_t>(p[0]) |
                (static_cast<std::uint32_t>(p[1]) << 8) |
                (static_cast<std::uint32_t>(p[2]) << 16) |
                (static_cast<std::uint32_t>(p[3]) << 24);
        }

        std::uint32_t ReadBe32(const BYTE* p)
        {
            return (static_cast<std::uint32_t>(p[0]) << 24) |
                (static_cast<std::uint32_t>(p[1]) << 16) |
                (static_cast<std::uint32_t>(p[2]) << 8) |
                static_cast<std::uint32_t>(p[3]);
        }

        bool ReadProtoVarint(const BYTE* data, std::size_t size, std::size_t& offset, std::uint64_t& value)
        {
            value = 0;
            unsigned shift = 0;
            for (unsigned i = 0; i < 10 && offset < size; ++i)
            {
                const BYTE b = data[offset++];
                value |= (static_cast<std::uint64_t>(b & 0x7Fu) << shift);
                if ((b & 0x80u) == 0) return true;
                shift += 7;
            }
            return false;
        }

        struct ProtoCandidate
        {
            std::size_t start = 0;
            std::size_t consumed = 0;
            unsigned fields = 0;
            std::string description;
        };

        ProtoCandidate ParseProtoCandidate(const BYTE* data, std::size_t size, std::size_t start)
        {
            ProtoCandidate result{};
            result.start = start;
            if (!data || start >= size) return result;

            std::size_t offset = start;
            std::ostringstream desc;
            for (unsigned item = 0; item < 12 && offset < size; ++item)
            {
                const std::size_t fieldStart = offset;
                std::uint64_t key = 0;
                if (!ReadProtoVarint(data, size, offset, key)) break;
                const std::uint64_t field = key >> 3;
                const unsigned wire = static_cast<unsigned>(key & 7u);
                if (field == 0 || field > 4096 || wire == 3 || wire == 4 || wire > 5)
                {
                    offset = fieldStart;
                    break;
                }

                if (result.fields) desc << ", ";
                desc << 'f' << field << "/w" << wire;

                if (wire == 0)
                {
                    std::uint64_t value = 0;
                    if (!ReadProtoVarint(data, size, offset, value)) { offset = fieldStart; break; }
                    desc << "=" << value;
                }
                else if (wire == 1)
                {
                    if (offset + 8 > size) { offset = fieldStart; break; }
                    desc << "[8]";
                    offset += 8;
                }
                else if (wire == 2)
                {
                    std::uint64_t length = 0;
                    if (!ReadProtoVarint(data, size, offset, length) || length > size - offset)
                    {
                        offset = fieldStart;
                        break;
                    }
                    desc << "[len=" << length << ']';
                    offset += static_cast<std::size_t>(length);
                }
                else if (wire == 5)
                {
                    if (offset + 4 > size) { offset = fieldStart; break; }
                    desc << "[4]";
                    offset += 4;
                }
                ++result.fields;
            }

            result.consumed = offset >= start ? offset - start : 0;
            result.description = desc.str();
            return result;
        }

        std::string DescribeBestProtoCandidate(const void* payload, std::size_t size)
        {
            if (!payload || !size) return "<none>";
            const auto* data = static_cast<const BYTE*>(payload);
            ProtoCandidate best{};
            const std::size_t maxStart = (std::min)(size, static_cast<std::size_t>(12));
            for (std::size_t start = 0; start < maxStart; ++start)
            {
                const ProtoCandidate candidate = ParseProtoCandidate(data, size, start);
                if (candidate.fields > best.fields ||
                    (candidate.fields == best.fields && candidate.consumed > best.consumed))
                    best = candidate;
            }
            if (!best.fields) return "<none>";

            std::ostringstream out;
            out << "offset=" << best.start << " fields=" << best.fields
                << " consumed=" << best.consumed << " {" << best.description << '}';
            return out.str();
        }

        void LogBgsApplicationPlaintext(TlsSession& session, std::uint64_t id, const std::string& peer, const void* payload, std::size_t size)
        {
            if (!payload || !size) return;
            const auto* bytes = static_cast<const BYTE*>(payload);
            session.bgsApplicationSeen = true;
            ++session.decryptedApplicationCount;

            log::Payload(id, "TLS-PLAIN-IN", 1119, peer, payload, size);
            log::Print("[BGS1119] id=%llu app#%llu decrypted application bytes=%llu",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                static_cast<unsigned long long>(size));
            log::Print("[BGS1119] id=%llu app#%llu header[0..31]=%s",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                HexPrefix(payload, size, 32).c_str());

            if (size >= 4)
            {
                log::Print("[BGS1119] id=%llu app#%llu frameHints u16be=%u u16le=%u u32be=%lu u32le=%lu firstByte=0x%02X",
                    static_cast<unsigned long long>(id),
                    static_cast<unsigned long long>(session.decryptedApplicationCount),
                    static_cast<unsigned>(ReadBe16(bytes)),
                    static_cast<unsigned>(static_cast<std::uint16_t>(bytes[0] | (static_cast<std::uint16_t>(bytes[1]) << 8))),
                    static_cast<unsigned long>(ReadBe32(bytes)),
                    static_cast<unsigned long>(ReadLe32(bytes)),
                    static_cast<unsigned>(bytes[0]));
            }
            else
            {
                log::Print("[BGS1119] id=%llu app#%llu frameHints short-payload firstByte=0x%02X",
                    static_cast<unsigned long long>(id),
                    static_cast<unsigned long long>(session.decryptedApplicationCount),
                    static_cast<unsigned>(bytes[0]));
            }

            log::Print("[BGS1119] id=%llu app#%llu hexPrefix=%s",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                HexPrefix(payload, size, 512).c_str());
            log::Print("[BGS1119] id=%llu app#%llu asciiPrefix=%s",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                protocol::AsciiPrefix(payload, size, 512).c_str());
            log::Print("[BGS1119] id=%llu app#%llu protobufCandidate=%s",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                DescribeBestProtoCandidate(payload, size).c_str());
        }
    }
}
