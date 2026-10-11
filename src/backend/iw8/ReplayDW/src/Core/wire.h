#pragma once
#include "crypto.h"
#include <string>
#include <stdexcept>
#include <cstring>

namespace wire
{
    using crypto::Bytes;

    inline void require(bool ok)
    {
        if (!ok)
            throw std::runtime_error("Malformed native task parameters");
    }

    inline std::string base64Encode(std::span<const uint8_t> bytes)
    {
        constexpr char alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(4 * ((bytes.size() + 2) / 3));
        for (size_t i = 0; i < bytes.size(); i += 3)
        {
            const auto a = bytes[i];
            const auto b = i + 1 < bytes.size() ? bytes[i + 1] : 0;
            const auto c = i + 2 < bytes.size() ? bytes[i + 2] : 0;
            out += alphabet[a >> 2];
            out += alphabet[((a & 3) << 4) | (b >> 4)];
            out += i + 1 < bytes.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
            out += i + 2 < bytes.size() ? alphabet[c & 63] : '=';
        }
        return out;
    }

    inline Bytes base64(const std::string &value, size_t capacity)
    {
        require(value.size() % 4 == 0 && value.size() <= 4 * ((capacity + 2) / 3));
        Bytes out;
        auto digit = [](char c) -> unsigned
        {
            if (c >= 'A' && c <= 'Z')
                return c - 'A';
            if (c >= 'a' && c <= 'z')
                return c - 'a' + 26;
            if (c >= '0' && c <= '9')
                return c - '0' + 52;
            if (c == '+')
                return 62;
            if (c == '/')
                return 63;
            require(false);
            return 0;
        };
        for (size_t i = 0; i < value.size(); i += 4)
        {
            const auto a = digit(value[i]), b = digit(value[i + 1]);
            const bool pad2 = value[i + 2] == '=', pad3 = value[i + 3] == '=';
            require((!pad2 || pad3) && (!(pad2 || pad3) || i + 4 == value.size()));
            const auto c = pad2 ? 0 : digit(value[i + 2]), d = pad3 ? 0 : digit(value[i + 3]);
            require((!pad2 || !(b & 15)) && (!pad3 || pad2 || !(c & 3)));
            out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
            if (!pad2)
                out.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
            if (!pad3)
                out.push_back(static_cast<uint8_t>((c << 6) | d));
        }
        require(out.size() <= capacity);
        return out;
    }

    template <class T> inline void raw(Bytes &out, T value)
    {
        const auto *p = reinterpret_cast<const uint8_t *>(&value);
        out.insert(out.end(), p, p + sizeof(value));
    }

    template <class T> inline T at(std::span<const uint8_t> bytes, size_t offset)
    {
        require(offset <= bytes.size() && sizeof(T) <= bytes.size() - offset);
        T result;
        std::memcpy(&result, bytes.data() + offset, sizeof(T));
        return result;
    }

    struct Writer
    {
        Bytes data;

        void u8(uint8_t value)
        {
            data.push_back(3);
            data.push_back(value);
        }

        void u16(uint16_t value)
        {
            data.push_back(6);
            raw(data, value);
        }

        void u32(uint32_t value)
        {
            data.push_back(8);
            raw(data, value);
        }

        void u64(uint64_t value)
        {
            data.push_back(10);
            raw(data, value);
        }

        void i64(int64_t value)
        {
            data.push_back(9);
            raw(data, value);
        }

        void f32(float value)
        {
            data.push_back(13);
            raw(data, value);
        }

        void boolean(bool value)
        {
            data.push_back(1);
            data.push_back(value ? 1 : 0);
        }

        void text(const std::string &value)
        {
            require(value.find('\0') == std::string::npos);
            data.push_back(16);
            data.insert(data.end(), value.begin(), value.end());
            data.push_back(0);
        }

        void blob(std::span<const uint8_t> value)
        {
            data.push_back(19);
            u32(static_cast<uint32_t>(value.size()));
            data.insert(data.end(), value.begin(), value.end());
        }
    };

    struct Reader
    {
        std::span<const uint8_t> data;
        size_t offset = 0;

        template <class T> T value(uint8_t tag)
        {
            require(offset < data.size() && data[offset++] == tag);
            T out = at<T>(data, offset);
            offset += sizeof(T);
            return out;
        }

        uint8_t u8()
        {
            return value<uint8_t>(3);
        }

        uint16_t u16()
        {
            return value<uint16_t>(6);
        }

        uint32_t u32()
        {
            if (offset < data.size() && data[offset] == 20)
            {
                ++offset;
                return UINT32_MAX;
            }
            return value<uint32_t>(8);
        }

        uint64_t u64()
        {
            if (offset < data.size() && data[offset] == 20)
            {
                ++offset;
                return UINT64_MAX;
            }
            return value<uint64_t>(10);
        }

        bool boolean()
        {
            const auto v = value<uint8_t>(1);
            require(v <= 1);
            return v != 0;
        }

        std::string text(size_t limit = 128)
        {
            require(offset < data.size() && data[offset++] == 16);
            const auto start = offset;
            while (offset < data.size() && data[offset])
            {
                require(offset - start + 1 < limit);
                ++offset;
            }
            require(offset < data.size());
            std::string out(reinterpret_cast<const char *>(data.data() + start), offset - start);
            ++offset;
            return out;
        }

        Bytes blob(size_t limit = 256 * 1024)
        {
            require(offset < data.size() && data[offset++] == 19);
            const auto size = u32();
            require(size <= limit && size <= data.size() - offset);
            Bytes out(data.begin() + offset, data.begin() + offset + size);
            offset += size;
            return out;
        }

        std::span<const uint8_t> structure(size_t limit = 256 * 1024)
        {
            require(offset < data.size() && data[offset++] == 23);
            const auto size = u32();
            require(size <= limit && size <= data.size() - offset);
            auto out = data.subspan(offset, size);
            offset += size;
            end();
            return out;
        }

        void end()
        {
            require(offset + 1 == data.size() && data[offset] == 0);
            ++offset;
        }

        bool more() const
        {
            return offset < data.size() && data[offset] != 0;
        }
    };
} // namespace wire
