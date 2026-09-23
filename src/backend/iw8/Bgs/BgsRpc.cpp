#include "BgsRpc.h"

#include <chrono>

namespace revamped::iw8::bgs
{
    namespace
    {
        std::uint16_t ReadBe16(const Byte* data)
        {
            return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
        }

        std::uint32_t ReadLe32(const Byte* data)
        {
            return static_cast<std::uint32_t>(data[0]) |
                (static_cast<std::uint32_t>(data[1]) << 8) |
                (static_cast<std::uint32_t>(data[2]) << 16) |
                (static_cast<std::uint32_t>(data[3]) << 24);
        }

        std::uint64_t ReadLe64(const Byte* data)
        {
            std::uint64_t value = 0;
            for (unsigned i = 0; i < 8; ++i)
                value |= static_cast<std::uint64_t>(data[i]) << (i * 8);
            return value;
        }

        bool SkipField(const Byte* data, std::size_t size, std::size_t& offset, unsigned wire)
        {
            switch (wire)
            {
            case 0:
            {
                std::uint64_t ignored = 0;
                return ReadProtoVarint(data, size, offset, ignored);
            }
            case 1:
                if (offset + 8 > size) return false;
                offset += 8;
                return true;
            case 2:
            {
                std::uint64_t length = 0;
                if (!ReadProtoVarint(data, size, offset, length) || length > size - offset) return false;
                offset += static_cast<std::size_t>(length);
                return true;
            }
            case 5:
                if (offset + 4 > size) return false;
                offset += 4;
                return true;
            default:
                return false;
            }
        }
    }

    bool ReadProtoVarint(const Byte* data, std::size_t size, std::size_t& offset, std::uint64_t& value)
    {
        value = 0;
        unsigned shift = 0;
        while (offset < size && shift < 64)
        {
            const Byte byte = data[offset++];
            value |= static_cast<std::uint64_t>(byte & 0x7Fu) << shift;
            if ((byte & 0x80u) == 0)
                return true;
            shift += 7;
        }
        return false;
    }

    bool ParseRpcHeader(const Byte* data, std::size_t size, RpcHeader& out)
    {
        out = {};
        if (!data || !size) return false;

        std::size_t offset = 0;
        while (offset < size)
        {
            std::uint64_t key = 0;
            if (!ReadProtoVarint(data, size, offset, key)) return false;
            const std::uint32_t field = static_cast<std::uint32_t>(key >> 3);
            const unsigned wire = static_cast<unsigned>(key & 7u);
            if (!field) return false;

            if (wire == 0)
            {
                std::uint64_t value = 0;
                if (!ReadProtoVarint(data, size, offset, value)) return false;
                switch (field)
                {
                case 1: out.serviceId = static_cast<std::uint32_t>(value); out.hasServiceId = true; break;
                case 2: out.methodId = static_cast<std::uint32_t>(value); out.hasMethodId = true; break;
                case 3: out.token = static_cast<std::uint32_t>(value); out.hasToken = true; break;
                case 5: out.size = static_cast<std::uint32_t>(value); out.hasSize = true; break;
                case 6: out.status = static_cast<std::uint32_t>(value); out.hasStatus = true; break;
                default: break;
                }
                continue;
            }

            if (wire == 5 && field == 11)
            {
                if (offset + 4 > size) return false;
                out.serviceHash = ReadLe32(data + offset);
                out.hasServiceHash = true;
                offset += 4;
                continue;
            }

            if (!SkipField(data, size, offset, wire))
                return false;
        }

        out.valid = out.hasServiceId && out.hasToken;
        return out.valid;
    }

    bool ParseRpcPayload(const std::vector<Byte>& payload, RpcEnvelope& out)
    {
        out = {};
        if (payload.size() < 2) return false;
        const std::uint16_t headerSize = ReadBe16(payload.data());
        if (headerSize > payload.size() - 2) return false;

        RpcHeader header{};
        if (!ParseRpcHeader(payload.data() + 2, headerSize, header))
            return false;

        out.header = header;
        out.headerSize = headerSize;
        out.body.assign(payload.begin() + 2 + headerSize, payload.end());
        return true;
    }

    bool TryGetVarintField(const Byte* data, std::size_t size, std::uint32_t wantedField, std::uint64_t& valueOut)
    {
        valueOut = 0;
        if (!data) return false;
        std::size_t offset = 0;
        while (offset < size)
        {
            std::uint64_t key = 0;
            if (!ReadProtoVarint(data, size, offset, key)) return false;
            const auto field = static_cast<std::uint32_t>(key >> 3);
            const unsigned wire = static_cast<unsigned>(key & 7u);
            if (wire == 0)
            {
                std::uint64_t value = 0;
                if (!ReadProtoVarint(data, size, offset, value)) return false;
                if (field == wantedField)
                {
                    valueOut = value;
                    return true;
                }
                continue;
            }
            if (!SkipField(data, size, offset, wire)) return false;
        }
        return false;
    }

    bool TryGetBytesField(const Byte* data, std::size_t size, std::uint32_t wantedField, std::vector<Byte>& valueOut)
    {
        valueOut.clear();
        if (!data) return false;
        std::size_t offset = 0;
        while (offset < size)
        {
            std::uint64_t key = 0;
            if (!ReadProtoVarint(data, size, offset, key)) return false;
            const auto field = static_cast<std::uint32_t>(key >> 3);
            const unsigned wire = static_cast<unsigned>(key & 7u);
            if (wire == 2)
            {
                std::uint64_t length = 0;
                if (!ReadProtoVarint(data, size, offset, length) || length > size - offset) return false;
                if (field == wantedField)
                {
                    valueOut.assign(data + offset, data + offset + static_cast<std::size_t>(length));
                    return true;
                }
                offset += static_cast<std::size_t>(length);
                continue;
            }
            if (!SkipField(data, size, offset, wire)) return false;
        }
        return false;
    }

    bool TryGetBytesFields(const Byte* data, std::size_t size, std::uint32_t wantedField, std::vector<std::vector<Byte>>& valuesOut)
    {
        valuesOut.clear();
        if (!data) return false;
        std::size_t offset = 0;
        while (offset < size)
        {
            std::uint64_t key = 0;
            if (!ReadProtoVarint(data, size, offset, key)) return false;
            const auto field = static_cast<std::uint32_t>(key >> 3);
            const unsigned wire = static_cast<unsigned>(key & 7u);
            if (wire == 2)
            {
                std::uint64_t length = 0;
                if (!ReadProtoVarint(data, size, offset, length) || length > size - offset) return false;
                if (field == wantedField)
                    valuesOut.emplace_back(data + offset, data + offset + static_cast<std::size_t>(length));
                offset += static_cast<std::size_t>(length);
                continue;
            }
            if (!SkipField(data, size, offset, wire)) return false;
        }
        return !valuesOut.empty();
    }

    bool TryGetFixed32Field(const Byte* data, std::size_t size, std::uint32_t wantedField, std::uint32_t& valueOut)
    {
        valueOut = 0;
        if (!data) return false;
        std::size_t offset = 0;
        while (offset < size)
        {
            std::uint64_t key = 0;
            if (!ReadProtoVarint(data, size, offset, key)) return false;
            const auto field = static_cast<std::uint32_t>(key >> 3);
            const unsigned wire = static_cast<unsigned>(key & 7u);
            if (wire == 5)
            {
                if (offset + 4 > size) return false;
                if (field == wantedField)
                {
                    valueOut = ReadLe32(data + offset);
                    return true;
                }
                offset += 4;
                continue;
            }
            if (!SkipField(data, size, offset, wire)) return false;
        }
        return false;
    }

    bool TryGetFixed64Field(const Byte* data, std::size_t size, std::uint32_t wantedField, std::uint64_t& valueOut)
    {
        valueOut = 0;
        if (!data) return false;
        std::size_t offset = 0;
        while (offset < size)
        {
            std::uint64_t key = 0;
            if (!ReadProtoVarint(data, size, offset, key)) return false;
            const auto field = static_cast<std::uint32_t>(key >> 3);
            const unsigned wire = static_cast<unsigned>(key & 7u);
            if (wire == 1)
            {
                if (offset + 8 > size) return false;
                if (field == wantedField)
                {
                    valueOut = ReadLe64(data + offset);
                    return true;
                }
                offset += 8;
                continue;
            }
            if (!SkipField(data, size, offset, wire)) return false;
        }
        return false;
    }

    bool TryGetEntityIdField(const Byte* data, std::size_t size, std::uint32_t wantedField, EntityId& valueOut)
    {
        valueOut = {};
        std::vector<Byte> nested;
        if (!TryGetBytesField(data, size, wantedField, nested))
            return false;
        std::uint64_t high = 0;
        std::uint64_t low = 0;
        const bool hasHigh = TryGetFixed64Field(nested.data(), nested.size(), 1, high);
        const bool hasLow = TryGetFixed64Field(nested.data(), nested.size(), 2, low);
        if (!hasHigh || !hasLow)
            return false;
        valueOut = {high, low, true};
        return true;
    }

    void AppendVarint(std::vector<Byte>& out, std::uint64_t value)
    {
        while (value >= 0x80u)
        {
            out.push_back(static_cast<Byte>((value & 0x7Fu) | 0x80u));
            value >>= 7;
        }
        out.push_back(static_cast<Byte>(value));
    }

    void AppendKey(std::vector<Byte>& out, std::uint32_t field, std::uint32_t wire)
    {
        AppendVarint(out, (static_cast<std::uint64_t>(field) << 3) | wire);
    }

    void AppendVarintField(std::vector<Byte>& out, std::uint32_t field, std::uint64_t value)
    {
        AppendKey(out, field, 0);
        AppendVarint(out, value);
    }

    void AppendFixed32Field(std::vector<Byte>& out, std::uint32_t field, std::uint32_t value)
    {
        AppendKey(out, field, 5);
        out.push_back(static_cast<Byte>(value & 0xFFu));
        out.push_back(static_cast<Byte>((value >> 8) & 0xFFu));
        out.push_back(static_cast<Byte>((value >> 16) & 0xFFu));
        out.push_back(static_cast<Byte>((value >> 24) & 0xFFu));
    }

    void AppendFixed64Field(std::vector<Byte>& out, std::uint32_t field, std::uint64_t value)
    {
        AppendKey(out, field, 1);
        for (unsigned shift = 0; shift < 64; shift += 8)
            out.push_back(static_cast<Byte>((value >> shift) & 0xFFu));
    }

    void AppendBytesField(std::vector<Byte>& out, std::uint32_t field, const void* data, std::size_t size)
    {
        AppendKey(out, field, 2);
        AppendVarint(out, size);
        const auto* bytes = static_cast<const Byte*>(data);
        if (bytes && size)
            out.insert(out.end(), bytes, bytes + size);
    }

    void AppendBytesField(std::vector<Byte>& out, std::uint32_t field, const std::vector<Byte>& value)
    {
        AppendBytesField(out, field, value.data(), value.size());
    }

    void AppendStringField(std::vector<Byte>& out, std::uint32_t field, const std::string& value)
    {
        AppendBytesField(out, field, value.data(), value.size());
    }

    void AppendEntityIdField(std::vector<Byte>& out, std::uint32_t field, const EntityId& value)
    {
        std::vector<Byte> nested;
        AppendFixed64Field(nested, 1, value.high);
        AppendFixed64Field(nested, 2, value.low);
        AppendBytesField(out, field, nested);
    }

    std::vector<Byte> BuildResponsePayload(std::uint32_t token, const std::vector<Byte>& body, std::uint32_t status)
    {
        std::vector<Byte> header;
        AppendVarintField(header, 1, 0xFEu);
        AppendVarintField(header, 3, token);
        AppendVarintField(header, 5, body.size());
        if (status != 0)
            AppendVarintField(header, 6, status);

        std::vector<Byte> frame;
        frame.reserve(2 + header.size() + body.size());
        const auto headerSize = static_cast<std::uint16_t>(header.size());
        frame.push_back(static_cast<Byte>((headerSize >> 8) & 0xFFu));
        frame.push_back(static_cast<Byte>(headerSize & 0xFFu));
        frame.insert(frame.end(), header.begin(), header.end());
        frame.insert(frame.end(), body.begin(), body.end());
        return frame;
    }

    std::vector<Byte> BuildRequestPayload(std::uint32_t serviceHash, std::uint32_t methodId,
        std::uint32_t token, const std::vector<Byte>& body)
    {
        std::vector<Byte> header;
        AppendVarintField(header, 1, 0u);
        AppendVarintField(header, 2, methodId);
        AppendVarintField(header, 3, token);
        AppendVarintField(header, 5, body.size());
        AppendFixed32Field(header, 11, serviceHash);

        std::vector<Byte> frame;
        frame.reserve(2 + header.size() + body.size());
        const auto headerSize = static_cast<std::uint16_t>(header.size());
        frame.push_back(static_cast<Byte>((headerSize >> 8) & 0xFFu));
        frame.push_back(static_cast<Byte>(headerSize & 0xFFu));
        frame.insert(frame.end(), header.begin(), header.end());
        frame.insert(frame.end(), body.begin(), body.end());
        return frame;
    }

    const char* StatusName(std::uint32_t status)
    {
        switch (status)
        {
        case 0: return "ERROR_OK";
        case 0x00000BC2u: return "ERROR_RPC_INVALID_SERVICE";
        case 0x00000BC3u: return "ERROR_RPC_INVALID_METHOD";
        case 0x00000BC4u: return "ERROR_RPC_INVALID_OBJECT";
        case 0x00000BC5u: return "ERROR_RPC_MALFORMED_REQUEST";
        case 0x00000BC6u: return "ERROR_RPC_INVALID_RESPONSE";
        case 0x00000BC7u: return "ERROR_RPC_NOT_IMPLEMENTED";
        case 0x00000BCDu: return "ERROR_RPC_NOT_READY";
        default: return "UNKNOWN";
        }
    }

    std::uint64_t UnixTimeMilliseconds()
    {
        using namespace std::chrono;
        return static_cast<std::uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    }
}
