#include "ProtocolIntrospection.h"

#include <cstdio>

namespace revamped::iw8::bgs
{
    namespace
    {
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

        void HashByte(std::uint64_t& hash, std::uint8_t byte)
        {
            hash ^= byte;
            hash *= 1099511628211ull;
        }

        void Hash32(std::uint64_t& hash, std::uint32_t value)
        {
            HashByte(hash, static_cast<std::uint8_t>(value & 0xFFu));
            HashByte(hash, static_cast<std::uint8_t>((value >> 8) & 0xFFu));
            HashByte(hash, static_cast<std::uint8_t>((value >> 16) & 0xFFu));
            HashByte(hash, static_cast<std::uint8_t>((value >> 24) & 0xFFu));
        }

        const char* WireName(std::uint32_t wire)
        {
            switch (wire)
            {
            case 0: return "varint";
            case 1: return "fixed64";
            case 2: return "bytes";
            case 5: return "fixed32";
            default: return "unsupported";
            }
        }
    }

    bool ObserveProtoMessage(const Byte* data, std::size_t size, ProtoMessageObservation& out)
    {
        out = {};
        out.shapeHash = 1469598103934665603ull;

        if (!size)
        {
            out.valid = true;
            return true;
        }
        if (!data)
        {
            out.error = "null body";
            return false;
        }

        std::size_t offset = 0;
        while (offset < size)
        {
            std::uint64_t key = 0;
            if (!ReadProtoVarint(data, size, offset, key))
            {
                out.error = "invalid field key varint";
                return false;
            }

            ProtoFieldObservation field{};
            field.number = static_cast<std::uint32_t>(key >> 3);
            field.wireType = static_cast<std::uint32_t>(key & 7u);
            if (!field.number)
            {
                out.error = "field number zero";
                return false;
            }

            Hash32(out.shapeHash, field.number);
            HashByte(out.shapeHash, static_cast<std::uint8_t>(field.wireType));

            switch (field.wireType)
            {
            case 0:
            {
                if (!ReadProtoVarint(data, size, offset, field.numericValue))
                {
                    out.error = "invalid varint field";
                    return false;
                }
                break;
            }
            case 1:
            {
                if (offset + 8 > size)
                {
                    out.error = "truncated fixed64 field";
                    return false;
                }
                field.numericValue = ReadLe64(data + offset);
                offset += 8;
                break;
            }
            case 2:
            {
                std::uint64_t length = 0;
                if (!ReadProtoVarint(data, size, offset, length) || length > size - offset)
                {
                    out.error = "invalid length-delimited field";
                    return false;
                }
                field.byteLength = static_cast<std::size_t>(length);
                offset += field.byteLength;
                break;
            }
            case 5:
            {
                if (offset + 4 > size)
                {
                    out.error = "truncated fixed32 field";
                    return false;
                }
                field.numericValue = ReadLe32(data + offset);
                offset += 4;
                break;
            }
            default:
                out.error = "protobuf group/reserved wire type is not supported by the IW8 semantic decoder";
                return false;
            }

            out.fields.push_back(field);
        }

        out.valid = true;
        return true;
    }

    std::string DescribeProtoMessage(const ProtoMessageObservation& observation, std::size_t maxFields)
    {
        if (!observation.valid)
            return observation.error.empty() ? "<invalid>" : std::string("<invalid:") + observation.error + ">";
        if (observation.fields.empty())
            return "<empty>";

        std::string out;
        char tmp[128]{};
        const std::size_t count = observation.fields.size() < maxFields ? observation.fields.size() : maxFields;
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto& field = observation.fields[i];
            if (!out.empty()) out += ' ';

            if (field.wireType == 2)
            {
                std::snprintf(tmp, sizeof(tmp), "f%u:%s[%llu]", field.number, WireName(field.wireType),
                    static_cast<unsigned long long>(field.byteLength));
            }
            else
            {
                std::snprintf(tmp, sizeof(tmp), "f%u:%s=0x%llX", field.number, WireName(field.wireType),
                    static_cast<unsigned long long>(field.numericValue));
            }
            out += tmp;
        }

        if (observation.fields.size() > count)
        {
            std::snprintf(tmp, sizeof(tmp), " ...(+%llu fields)",
                static_cast<unsigned long long>(observation.fields.size() - count));
            out += tmp;
        }
        return out;
    }
}
