#pragma once
#include "wire.h"

namespace proto
{
    using wire::Bytes;

    inline void varint(Bytes &out, uint64_t value)
    {
        while (value >= 128)
        {
            out.push_back(static_cast<uint8_t>(value) | 128);
            value >>= 7;
        }
        out.push_back(static_cast<uint8_t>(value));
    }

    inline void integer(Bytes &out, unsigned tag, uint64_t value)
    {
        varint(out, uint64_t(tag) << 3);
        varint(out, value);
    }

    // Same-Replay 0x142150020 uses ZigZag for signed structured integers.
    inline void signedInteger(Bytes &out, unsigned tag, int64_t value)
    {
        integer(
            out, tag, (static_cast<uint64_t>(value) << 1) ^ static_cast<uint64_t>(-(value < 0)));
    }

    inline void f64(Bytes &out, unsigned tag, double value)
    {
        varint(out, (uint64_t(tag) << 3) | 1);
        wire::raw(out, value);
    }

    inline void bytes(Bytes &out, unsigned tag, std::span<const uint8_t> value)
    {
        varint(out, (uint64_t(tag) << 3) | 2);
        varint(out, value.size());
        out.insert(out.end(), value.begin(), value.end());
    }

    inline void text(Bytes &out, unsigned tag, const std::string &value)
    {
        bytes(out, tag, std::span(reinterpret_cast<const uint8_t *>(value.data()), value.size()));
    }

    struct Field
    {
        unsigned tag = 0, type = 0;
        uint64_t value = 0;
        std::span<const uint8_t> bytes;
    };

    struct Reader
    {
        std::span<const uint8_t> data;
        size_t at = 0;

        uint64_t varint()
        {
            uint64_t v = 0;
            for (unsigned shift = 0; shift < 64; shift += 7)
            {
                wire::require(at < data.size());
                auto b = data[at++];
                if (shift == 63)
                    wire::require(b <= 1);
                v |= uint64_t(b & 127) << shift;
                if (!(b & 128))
                    return v;
            }
            wire::require(false);
            return 0;
        }

        bool next(Field &f)
        {
            if (at == data.size())
                return false;
            const auto key = varint();
            wire::require(key > 7 && (key >> 3) <= 0x1fffffff);
            f = {};
            f.tag = static_cast<unsigned>(key >> 3);
            f.type = static_cast<unsigned>(key & 7);
            if (f.type == 0)
                f.value = varint();
            else if (f.type == 2)
            {
                const auto size = varint();
                wire::require(size <= data.size() - at);
                f.bytes = data.subspan(at, static_cast<size_t>(size));
                at += static_cast<size_t>(size);
            }
            else if (f.type == 1 || f.type == 5)
            {
                const auto size = f.type == 1 ? 8u : 4u;
                wire::require(size <= data.size() - at);
                f.bytes = data.subspan(at, size);
                at += size;
            }
            else
                wire::require(false);
            return true;
        }
    };
} // namespace proto
