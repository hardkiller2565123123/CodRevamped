#pragma once
#include <cstdint>
#include <span>
#include <vector>

namespace crypto
{
    using Bytes = std::vector<uint8_t>;
    Bytes random(unsigned size);
    Bytes sha1(std::span<const uint8_t> bytes);
    Bytes sha256(std::span<const uint8_t> bytes);
    Bytes md5(std::span<const uint8_t> bytes);
    Bytes hmac(std::span<const uint8_t> key, std::span<const uint8_t> bytes);
    Bytes hmac256(std::span<const uint8_t> key, std::span<const uint8_t> bytes);
    Bytes expand(std::span<const uint8_t> key, std::span<const uint8_t> info, unsigned size);
    Bytes expand256(std::span<const uint8_t> key, std::span<const uint8_t> info, unsigned size);
    Bytes aes(std::span<const uint8_t> key,
              std::span<const uint8_t> iv,
              std::span<const uint8_t> bytes,
              bool encrypt);
    // AES-GCM uses a 12-byte nonce and appends/validates the 16-byte tag.
    Bytes gcm(std::span<const uint8_t> key,
              std::span<const uint8_t> nonce,
              std::span<const uint8_t> bytes,
              bool encrypt);
    bool equal(std::span<const uint8_t> a, std::span<const uint8_t> b);
} // namespace crypto
