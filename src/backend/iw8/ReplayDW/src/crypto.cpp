#include "host_os.h"
#include "crypto_provider.h"
#include "crypto.h"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace crypto
{
    namespace
    {
        void check(NTSTATUS result)
        {
            if (result < 0)
                throw std::runtime_error("Lobby cryptographic operation failed");
        }

        struct Algorithm
        {
            BCRYPT_ALG_HANDLE value{};

            Algorithm(const wchar_t *name, unsigned flags = 0)
            {
                check(BCryptOpenAlgorithmProvider(&value, name, nullptr, flags));
            }

            ~Algorithm()
            {
                if (value)
                    BCryptCloseAlgorithmProvider(value, 0);
            }
        };

        struct Hash
        {
            BCRYPT_HASH_HANDLE value{};

            ~Hash()
            {
                if (value)
                    BCryptDestroyHash(value);
            }
        };

        struct Key
        {
            BCRYPT_KEY_HANDLE value{};

            ~Key()
            {
                if (value)
                    BCryptDestroyKey(value);
            }
        };

        Bytes digest(std::span<const uint8_t> bytes, std::span<const uint8_t> key, bool keyed)
        {
            Algorithm algorithm(BCRYPT_SHA1_ALGORITHM, keyed ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
            Hash hash;
            check(BCryptCreateHash(algorithm.value,
                                   &hash.value,
                                   nullptr,
                                   0,
                                   const_cast<uint8_t *>(key.data()),
                                   static_cast<ULONG>(key.size()),
                                   0));
            check(BCryptHashData(hash.value,
                                 const_cast<uint8_t *>(bytes.data()),
                                 static_cast<ULONG>(bytes.size()),
                                 0));
            Bytes result(20);
            check(BCryptFinishHash(hash.value, result.data(), 20, 0));
            return result;
        }
    } // namespace

    Bytes random(unsigned size)
    {
        Bytes out(size);
        check(BCryptGenRandom(nullptr, out.data(), size, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
        return out;
    }

    Bytes sha1(std::span<const uint8_t> bytes)
    {
        return digest(bytes, {}, false);
    }

    Bytes sha256(std::span<const uint8_t> bytes)
    {
        Algorithm algorithm(BCRYPT_SHA256_ALGORITHM);
        Hash hash;
        check(BCryptCreateHash(algorithm.value, &hash.value, nullptr, 0, nullptr, 0, 0));
        check(BCryptHashData(
            hash.value, const_cast<uint8_t *>(bytes.data()), static_cast<ULONG>(bytes.size()), 0));
        Bytes out(32);
        check(BCryptFinishHash(hash.value, out.data(), 32, 0));
        return out;
    }

    Bytes md5(std::span<const uint8_t> bytes)
    {
        Algorithm algorithm(BCRYPT_MD5_ALGORITHM);
        Hash hash;
        check(BCryptCreateHash(algorithm.value, &hash.value, nullptr, 0, nullptr, 0, 0));
        check(BCryptHashData(
            hash.value, const_cast<uint8_t *>(bytes.data()), static_cast<ULONG>(bytes.size()), 0));
        Bytes out(16);
        check(BCryptFinishHash(hash.value, out.data(), 16, 0));
        return out;
    }

    Bytes hmac(std::span<const uint8_t> key, std::span<const uint8_t> bytes)
    {
        return digest(bytes, key, true);
    }

    Bytes hmac256(std::span<const uint8_t> key, std::span<const uint8_t> bytes)
    {
        Algorithm algorithm(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        Hash hash;
        check(BCryptCreateHash(algorithm.value,
                               &hash.value,
                               nullptr,
                               0,
                               const_cast<uint8_t *>(key.data()),
                               static_cast<ULONG>(key.size()),
                               0));
        check(BCryptHashData(
            hash.value, const_cast<uint8_t *>(bytes.data()), static_cast<ULONG>(bytes.size()), 0));
        Bytes out(32);
        check(BCryptFinishHash(hash.value, out.data(), 32, 0));
        return out;
    }

    Bytes expand(std::span<const uint8_t> key, std::span<const uint8_t> info, unsigned size)
    {
        if (size > 255 * 20)
            throw std::runtime_error("HKDF output exceeds RFC bound");
        Bytes result, previous;
        for (unsigned count = 1; result.size() < size; ++count)
        {
            Bytes input(previous);
            input.insert(input.end(), info.begin(), info.end());
            input.push_back(static_cast<uint8_t>(count));
            previous = hmac(key, input);
            const auto amount = std::min<size_t>(previous.size(), size - result.size());
            result.insert(result.end(), previous.begin(), previous.begin() + amount);
            SecureZeroMemory(input.data(), input.size());
        }
        SecureZeroMemory(previous.data(), previous.size());
        return result;
    }

    Bytes expand256(std::span<const uint8_t> key, std::span<const uint8_t> info, unsigned size)
    {
        if (size > 255 * 32)
            throw std::runtime_error("SHA256 HKDF output exceeds RFC bound");
        Bytes result, previous;
        for (unsigned count = 1; result.size() < size; ++count)
        {
            Bytes input(previous);
            input.insert(input.end(), info.begin(), info.end());
            input.push_back(static_cast<uint8_t>(count));
            previous = hmac256(key, input);
            const auto amount = std::min<size_t>(previous.size(), size - result.size());
            result.insert(result.end(), previous.begin(), previous.begin() + amount);
            SecureZeroMemory(input.data(), input.size());
        }
        SecureZeroMemory(previous.data(), previous.size());
        return result;
    }

    Bytes aes(std::span<const uint8_t> keyBytes,
              std::span<const uint8_t> ivBytes,
              std::span<const uint8_t> bytes,
              bool encrypt)
    {
        if (keyBytes.size() != 16 || ivBytes.size() != 16 || bytes.empty() || bytes.size() % 16)
            throw std::runtime_error("Invalid native AES-CBC record size");
        Algorithm algorithm(BCRYPT_AES_ALGORITHM);
        check(BCryptSetProperty(
            algorithm.value,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_CBC)),
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0));
        Key key;
        check(BCryptGenerateSymmetricKey(algorithm.value,
                                         &key.value,
                                         nullptr,
                                         0,
                                         const_cast<uint8_t *>(keyBytes.data()),
                                         16,
                                         0));
        Bytes iv(ivBytes.begin(), ivBytes.end()), out(bytes.size());
        ULONG written = 0;
        auto operation = encrypt ? BCryptEncrypt : BCryptDecrypt;
        check(operation(key.value,
                        const_cast<uint8_t *>(bytes.data()),
                        static_cast<ULONG>(bytes.size()),
                        nullptr,
                        iv.data(),
                        16,
                        out.data(),
                        static_cast<ULONG>(out.size()),
                        &written,
                        0));
        if (written != out.size())
            throw std::runtime_error("Native AES-CBC output length mismatch");
        return out;
    }

    Bytes gcm(std::span<const uint8_t> keyBytes,
              std::span<const uint8_t> nonce,
              std::span<const uint8_t> bytes,
              bool encrypt)
    {
        if (keyBytes.size() != 16 || nonce.size() != 12 || bytes.empty() ||
            (!encrypt && bytes.size() <= 16))
            throw std::runtime_error("Invalid native AES-GCM record size");
        Algorithm algorithm(BCRYPT_AES_ALGORITHM);
        check(BCryptSetProperty(
            algorithm.value,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM),
            0));
        Key key;
        check(BCryptGenerateSymmetricKey(algorithm.value,
                                         &key.value,
                                         nullptr,
                                         0,
                                         const_cast<uint8_t *>(keyBytes.data()),
                                         16,
                                         0));
        std::array<uint8_t, 16> tag{};
        const auto size = bytes.size() - (encrypt ? 0 : 16);
        if (!encrypt)
            std::copy(bytes.end() - 16, bytes.end(), tag.begin());
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<uint8_t *>(nonce.data());
        info.cbNonce = 12;
        info.pbTag = tag.data();
        info.cbTag = 16;
        Bytes out(size);
        ULONG written = 0;
        auto operation = encrypt ? BCryptEncrypt : BCryptDecrypt;
        const auto status = operation(key.value,
                                      const_cast<uint8_t *>(bytes.data()),
                                      static_cast<ULONG>(size),
                                      &info,
                                      nullptr,
                                      0,
                                      out.data(),
                                      static_cast<ULONG>(out.size()),
                                      &written,
                                      0);
        if (status < 0 || written != out.size())
        {
            SecureZeroMemory(out.data(), out.size());
            throw std::runtime_error("Native AES-GCM authentication failed");
        }
        if (encrypt)
            out.insert(out.end(), tag.begin(), tag.end());
        return out;
    }

    bool equal(std::span<const uint8_t> a, std::span<const uint8_t> b)
    {
        if (a.size() != b.size())
            return false;
        unsigned difference = 0;
        for (size_t i = 0; i < a.size(); ++i)
            difference |= a[i] ^ b[i];
        return difference == 0;
    }
} // namespace crypto
