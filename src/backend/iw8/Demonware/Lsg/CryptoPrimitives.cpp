#include "CryptoPrimitives.h"

namespace revamped::iw8
{
    namespace
    {
        bool BCryptAesCbcCrypt(bool encrypt, const std::uint8_t key[16], const std::uint8_t iv[16],
            const std::uint8_t* input, std::size_t inputSize, std::vector<std::uint8_t>& output)
        {
            output.clear();
            if (!key || !iv || !input || !inputSize || (inputSize & 15u) != 0u || inputSize > 0xFFFFFFFFu)
                return false;

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_KEY_HANDLE keyHandle = nullptr;
            DWORD objectBytes = 0;
            DWORD returned = 0;
            bool ok = false;

            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
                goto done;
            if (BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                    reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                    static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_CBC)), 0) != 0)
                goto done;
            if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &returned, 0) != 0 || !objectBytes)
                goto done;

            {
                std::vector<std::uint8_t> keyObject(objectBytes);
                if (BCryptGenerateSymmetricKey(algorithm, &keyHandle, keyObject.data(), objectBytes,
                        const_cast<PUCHAR>(key), 16, 0) != 0)
                    goto done;

                std::array<std::uint8_t, 16> ivCopy{};
                std::memcpy(ivCopy.data(), iv, ivCopy.size());
                output.resize(inputSize);
                ULONG outputBytes = 0;
                const NTSTATUS status = encrypt
                    ? BCryptEncrypt(keyHandle, const_cast<PUCHAR>(input), static_cast<ULONG>(inputSize), nullptr,
                        ivCopy.data(), static_cast<ULONG>(ivCopy.size()), output.data(), static_cast<ULONG>(output.size()),
                        &outputBytes, 0)
                    : BCryptDecrypt(keyHandle, const_cast<PUCHAR>(input), static_cast<ULONG>(inputSize), nullptr,
                        ivCopy.data(), static_cast<ULONG>(ivCopy.size()), output.data(), static_cast<ULONG>(output.size()),
                        &outputBytes, 0);
                if (status != 0 || outputBytes != inputSize)
                    goto done;
                output.resize(outputBytes);
                ok = true;
            }

        done:
            if (keyHandle) BCryptDestroyKey(keyHandle);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            if (!ok) output.clear();
            return ok;
        }

        bool BCryptSha1(const std::uint8_t* data, std::size_t size, std::uint8_t out[20])
        {
            if (!out || (size && !data) || size > 0xFFFFFFFFu)
                return false;

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            DWORD objectBytes = 0;
            DWORD returned = 0;
            bool ok = false;

            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
                goto done;
            if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &returned, 0) != 0 || !objectBytes)
                goto done;

            {
                std::vector<std::uint8_t> object(objectBytes);
                if (BCryptCreateHash(algorithm, &hash, object.data(), objectBytes, nullptr, 0, 0) != 0)
                    goto done;
                if (size && BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) != 0)
                    goto done;
                if (BCryptFinishHash(hash, out, 20, 0) != 0)
                    goto done;
                ok = true;
            }

        done:
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            return ok;
        }

        bool BCryptHmacSha1(const std::uint8_t* key, std::size_t keySize,
            const std::uint8_t* data, std::size_t dataSize, std::uint8_t out[20])
        {
            if (!out || (keySize && !key) || (dataSize && !data) ||
                keySize > 0xFFFFFFFFu || dataSize > 0xFFFFFFFFu)
                return false;

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            DWORD objectBytes = 0;
            DWORD returned = 0;
            bool ok = false;

            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr,
                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
                goto done;
            if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &returned, 0) != 0 || !objectBytes)
                goto done;

            {
                std::vector<std::uint8_t> object(objectBytes);
                if (BCryptCreateHash(algorithm, &hash, object.data(), objectBytes,
                        const_cast<PUCHAR>(key), static_cast<ULONG>(keySize), 0) != 0)
                    goto done;
                if (dataSize && BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(dataSize), 0) != 0)
                    goto done;
                if (BCryptFinishHash(hash, out, 20, 0) != 0)
                    goto done;
                ok = true;
            }

        done:
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            return ok;
        }

        bool HkdfExpandSha1Key(const std::uint8_t* prk, std::size_t prkSize,
            const std::uint8_t* info, std::size_t infoSize, std::uint8_t* out, std::size_t outSize)
        {
            if (!prk || !prkSize || !out || (infoSize && !info) || outSize > 20u * 255u)
                return false;

            std::array<std::uint8_t, 20> previous{};
            std::size_t previousSize = 0;
            std::size_t written = 0;
            std::uint8_t counter = 1;
            while (written < outSize)
            {
                std::vector<std::uint8_t> message;
                message.reserve(previousSize + infoSize + 1u);
                if (previousSize)
                    message.insert(message.end(), previous.begin(), previous.begin() + static_cast<std::ptrdiff_t>(previousSize));
                if (infoSize)
                    message.insert(message.end(), info, info + infoSize);
                message.push_back(counter++);

                if (!BCryptHmacSha1(prk, prkSize, message.data(), message.size(), previous.data()))
                    return false;
                previousSize = previous.size();
                const std::size_t chunk = (std::min)(previousSize, outSize - written);
                std::memcpy(out + written, previous.data(), chunk);
                written += chunk;
            }
            return true;
        }

        bool HkdfExpandSha1(const std::uint8_t prk[20], const std::uint8_t* info,
            std::size_t infoSize, std::uint8_t* out, std::size_t outSize)
        {
            return HkdfExpandSha1Key(prk, 20u, info, infoSize, out, outSize);
        }
    }
}
