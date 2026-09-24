#include "LsgKeyDecoding.h"

namespace revamped::iw8::web
{
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
}
