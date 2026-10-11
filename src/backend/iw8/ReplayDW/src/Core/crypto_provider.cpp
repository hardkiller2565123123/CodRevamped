#include "crypto_provider.h"
#ifndef _WIN32
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <array>
#include <climits>
#include <memory>
#include <stdexcept>

namespace
{
    template <class T, void (*Free)(T *)> using Owned = std::unique_ptr<T, decltype(Free)>;
    using Number = Owned<BIGNUM, BN_free>;
    using Params = Owned<OSSL_PARAM_BLD, OSSL_PARAM_BLD_free>;
    using KeyContext = Owned<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;

    void require(bool value)
    {
        if (!value)
            throw std::runtime_error("OpenSSL operation failed");
    }

    const EVP_MD *digest(const HostAlgorithm &algorithm)
    {
        if (algorithm.name == L"SHA256")
            return EVP_sha256();
        if (algorithm.name == L"SHA1")
            return EVP_sha1();
        if (algorithm.name == L"MD5")
            return EVP_md5();
        throw std::runtime_error("Unsupported digest");
    }

    Number readNumber(const uint8_t *&cursor, const uint8_t *end, unsigned size)
    {
        require(size && size <= 512 && size <= static_cast<size_t>(end - cursor));
        Number number(BN_bin2bn(cursor, size, nullptr), BN_free);
        require(bool(number));
        cursor += size;
        return number;
    }

    Number parameter(EVP_PKEY *key, const char *name)
    {
        BIGNUM *value = nullptr;
        require(EVP_PKEY_get_bn_param(key, name, &value) == 1);
        return Number(value, BN_free);
    }

    void append(std::vector<uint8_t> &bytes, const BIGNUM *value, int size)
    {
        const auto offset = bytes.size();
        bytes.resize(offset + size);
        require(BN_bn2binpad(value, bytes.data() + offset, size) == size);
    }

    void rsaPadding(EVP_PKEY_CTX *context, void *info, ULONG flags)
    {
        require(info && flags == BCRYPT_PAD_PSS);
        const auto &padding = *static_cast<BCRYPT_PSS_PADDING_INFO *>(info);
        require(std::wstring(padding.pszAlgId) == L"SHA256" && padding.cbSalt <= 32);
        require(EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) == 1 &&
                EVP_PKEY_CTX_set_signature_md(context, EVP_sha256()) == 1 &&
                EVP_PKEY_CTX_set_rsa_pss_saltlen(context, padding.cbSalt) == 1 &&
                EVP_PKEY_CTX_set_rsa_mgf1_md(context, EVP_sha256()) == 1);
    }

    struct RsaHeader
    {
        uint32_t magic, bits, exponent, modulus, prime1, prime2;
    };

    static_assert(sizeof(RsaHeader) == 24);

    NTSTATUS cipher(BCRYPT_KEY_HANDLE key,
                    PUCHAR input,
                    ULONG size,
                    void *padding,
                    PUCHAR iv,
                    ULONG ivSize,
                    PUCHAR output,
                    ULONG capacity,
                    ULONG *written,
                    bool encrypt)
    {
        try
        {
            require(key && key->secret.size() == 16 && size <= INT_MAX && capacity >= size);
            const bool gcm = key->mode == BCRYPT_CHAIN_MODE_GCM;
            require(gcm || key->mode == BCRYPT_CHAIN_MODE_CBC);
            auto *auth = static_cast<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *>(padding);
            require(gcm ? auth && auth->cbNonce == 12 && auth->cbTag == 16
                        : iv && ivSize == 16 && size % 16 == 0);
            Owned<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> context(EVP_CIPHER_CTX_new(),
                                                               EVP_CIPHER_CTX_free);
            require(bool(context));
            require(EVP_CipherInit_ex(context.get(),
                                      gcm ? EVP_aes_128_gcm() : EVP_aes_128_cbc(),
                                      nullptr,
                                      key->secret.data(),
                                      gcm ? auth->pbNonce : iv,
                                      encrypt ? 1 : 0) == 1);
            require(EVP_CIPHER_CTX_set_padding(context.get(), 0) == 1);
            if (gcm && !encrypt)
                require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, 16, auth->pbTag) ==
                        1);
            int count = 0, final = 0;
            require(EVP_CipherUpdate(context.get(), output, &count, input, size) == 1);
            require(EVP_CipherFinal_ex(context.get(), output + count, &final) == 1);
            require(static_cast<ULONG>(count + final) == size);
            if (gcm && encrypt)
                require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, 16, auth->pbTag) ==
                        1);
            *written = count + final;
            return 0;
        }
        catch (...)
        {
            return -1;
        }
    }
} // namespace

NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *out,
                                     const wchar_t *name,
                                     void *,
                                     ULONG flags)
{
    try
    {
        *out = new HostAlgorithm{name, bool(flags & BCRYPT_ALG_HANDLE_HMAC_FLAG), {}};
        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE value, ULONG)
{
    delete value;
    return 0;
}

NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE algorithm,
                          BCRYPT_HASH_HANDLE *out,
                          PUCHAR,
                          ULONG,
                          PUCHAR secret,
                          ULONG size,
                          ULONG)
{
    try
    {
        auto value = std::make_unique<HostHash>();
        value->algorithm = *algorithm;
        if (size)
            value->secret.assign(secret, secret + size);
        *out = value.release();
        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE value, PUCHAR data, ULONG size, ULONG)
{
    try
    {
        if (size)
            value->bytes.insert(value->bytes.end(), data, data + size);
        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE value, PUCHAR out, ULONG size, ULONG)
{
    try
    {
        const auto md = digest(value->algorithm);
        require(size == static_cast<ULONG>(EVP_MD_get_size(md)));
        unsigned count = 0;
        if (value->algorithm.hmac)
            require(HMAC(md,
                         value->secret.data(),
                         value->secret.size(),
                         value->bytes.data(),
                         value->bytes.size(),
                         out,
                         &count) != nullptr);
        else
            require(EVP_Digest(
                        value->bytes.data(), value->bytes.size(), out, &count, md, nullptr) == 1);
        require(count == size);
        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE value)
{
    if (value)
        OPENSSL_cleanse(value->secret.data(), value->secret.size());
    delete value;
    return 0;
}

NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE, PUCHAR out, ULONG size, ULONG)
{
    return size <= INT_MAX && RAND_bytes(out, size) == 1 ? 0 : -1;
}

NTSTATUS BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE algorithm,
                               PUCHAR password,
                               ULONG size,
                               PUCHAR salt,
                               ULONG saltSize,
                               uint64_t rounds,
                               PUCHAR out,
                               ULONG length,
                               ULONG)
{
    if (size > INT_MAX || saltSize > INT_MAX || rounds > INT_MAX || length > INT_MAX)
        return -1;
    return PKCS5_PBKDF2_HMAC(reinterpret_cast<char *>(password),
                             size,
                             salt,
                             saltSize,
                             rounds,
                             digest(*algorithm),
                             length,
                             out) == 1
               ? 0
               : -1;
}

NTSTATUS BCryptImportKeyPair(BCRYPT_ALG_HANDLE,
                             void *,
                             const wchar_t *format,
                             BCRYPT_KEY_HANDLE *out,
                             PUCHAR bytes,
                             ULONG size,
                             ULONG)
{
    try
    {
        auto key = std::make_unique<HostKey>();
        Params parameters(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
        require(bool(parameters));
        const auto cursorStart = bytes;
        const auto end = bytes + size;
        const uint8_t *cursor = cursorStart;
        const bool ec = std::wstring(format) == BCRYPT_ECCPUBLIC_BLOB;
        std::vector<Number> numbers;
        std::array<uint8_t, 65> point{};
        if (ec)
        {
            require(size == 72);
            BCRYPT_ECCKEY_BLOB header;
            std::memcpy(&header, bytes, 8);
            require(header.dwMagic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC && header.cbKey == 32);
            point[0] = 4;
            std::memcpy(point.data() + 1, bytes + 8, 64);
            require(OSSL_PARAM_BLD_push_utf8_string(
                        parameters.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) == 1 &&
                    OSSL_PARAM_BLD_push_octet_string(
                        parameters.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()) ==
                        1);
        }
        else
        {
            const bool privateKey = std::wstring(format) == BCRYPT_RSAPRIVATE_BLOB;
            require(privateKey || std::wstring(format) == BCRYPT_RSAPUBLIC_BLOB);
            require(size >= sizeof(RsaHeader));
            RsaHeader header;
            std::memcpy(&header, bytes, sizeof(header));
            require(header.magic == (privateKey ? 0x32415352u : 0x31415352u) &&
                    header.bits == 2048 && header.modulus == 256 && header.exponent <= 8 &&
                    (privateKey ? header.prime1 == 128 && header.prime2 == 128
                                : !header.prime1 && !header.prime2));
            cursor += sizeof(header);
            numbers.push_back(readNumber(cursor, end, header.exponent));
            numbers.push_back(readNumber(cursor, end, header.modulus));
            const auto e = numbers[0].get(), n = numbers[1].get();
            require(OSSL_PARAM_BLD_push_BN(parameters.get(), OSSL_PKEY_PARAM_RSA_E, e) == 1 &&
                    OSSL_PARAM_BLD_push_BN(parameters.get(), OSSL_PKEY_PARAM_RSA_N, n) == 1);
            if (privateKey)
            {
                numbers.push_back(readNumber(cursor, end, header.prime1));
                numbers.push_back(readNumber(cursor, end, header.prime2));
                const auto p = numbers[2].get(), q = numbers[3].get();
                Owned<BN_CTX, BN_CTX_free> context(BN_CTX_new(), BN_CTX_free);
                Number pm(BN_dup(p), BN_free), qm(BN_dup(q), BN_free), phi(BN_new(), BN_free);
                require(context && pm && qm && phi && BN_sub_word(pm.get(), 1) &&
                        BN_sub_word(qm.get(), 1) &&
                        BN_mul(phi.get(), pm.get(), qm.get(), context.get()));
                numbers.emplace_back(BN_mod_inverse(nullptr, e, phi.get(), context.get()), BN_free);
                numbers.emplace_back(BN_new(), BN_free);
                numbers.emplace_back(BN_new(), BN_free);
                numbers.emplace_back(BN_mod_inverse(nullptr, q, p, context.get()), BN_free);
                require(numbers[4] && numbers[5] && numbers[6] && numbers[7] &&
                        BN_mod(numbers[5].get(), numbers[4].get(), pm.get(), context.get()) &&
                        BN_mod(numbers[6].get(), numbers[4].get(), qm.get(), context.get()));
                constexpr const char *names[] = {OSSL_PKEY_PARAM_RSA_FACTOR1,
                                                 OSSL_PKEY_PARAM_RSA_FACTOR2,
                                                 OSSL_PKEY_PARAM_RSA_D,
                                                 OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                                 OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                                 OSSL_PKEY_PARAM_RSA_COEFFICIENT1};
                for (unsigned i = 0; i < 6; ++i)
                    require(OSSL_PARAM_BLD_push_BN(
                                parameters.get(), names[i], numbers[i + 2].get()) == 1);
            }
            require(cursor == end);
        }
        Owned<OSSL_PARAM, OSSL_PARAM_free> values(OSSL_PARAM_BLD_to_param(parameters.get()),
                                                  OSSL_PARAM_free);
        KeyContext context(EVP_PKEY_CTX_new_from_name(nullptr, ec ? "EC" : "RSA", nullptr),
                           EVP_PKEY_CTX_free);
        require(context && values && EVP_PKEY_fromdata_init(context.get()) == 1 &&
                EVP_PKEY_fromdata(context.get(),
                                  &key->asymmetric,
                                  !ec && std::wstring(format) == BCRYPT_RSAPRIVATE_BLOB
                                      ? EVP_PKEY_KEYPAIR
                                      : EVP_PKEY_PUBLIC_KEY,
                                  values.get()) == 1);
        KeyContext check(EVP_PKEY_CTX_new(key->asymmetric, nullptr), EVP_PKEY_CTX_free);
        require(check && EVP_PKEY_public_check(check.get()) == 1);
        if (!ec && std::wstring(format) == BCRYPT_RSAPRIVATE_BLOB)
            require(EVP_PKEY_private_check(check.get()) == 1 &&
                    EVP_PKEY_pairwise_check(check.get()) == 1);
        *out = key.release();
        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptExportKey(BCRYPT_KEY_HANDLE key,
                         void *,
                         const wchar_t *format,
                         PUCHAR output,
                         ULONG capacity,
                         ULONG *written,
                         ULONG)
{
    try
    {
        const bool privateKey = std::wstring(format) == BCRYPT_RSAPRIVATE_BLOB;
        require(privateKey || std::wstring(format) == BCRYPT_RSAPUBLIC_BLOB);
        auto n = parameter(key->asymmetric, OSSL_PKEY_PARAM_RSA_N);
        auto e = parameter(key->asymmetric, OSSL_PKEY_PARAM_RSA_E);
        RsaHeader header{privateKey ? 0x32415352u : 0x31415352u,
                         2048,
                         static_cast<uint32_t>(BN_num_bytes(e.get())),
                         256,
                         privateKey ? 128u : 0u,
                         privateKey ? 128u : 0u};
        std::vector<uint8_t> blob(sizeof(header));
        std::memcpy(blob.data(), &header, sizeof(header));
        append(blob, e.get(), header.exponent);
        append(blob, n.get(), 256);
        if (privateKey)
        {
            auto p = parameter(key->asymmetric, OSSL_PKEY_PARAM_RSA_FACTOR1);
            auto q = parameter(key->asymmetric, OSSL_PKEY_PARAM_RSA_FACTOR2);
            append(blob, p.get(), 128);
            append(blob, q.get(), 128);
        }
        *written = blob.size();
        if (output)
        {
            require(capacity >= blob.size());
            std::memcpy(output, blob.data(), blob.size());
        }
        OPENSSL_cleanse(blob.data(), blob.size());
        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptGenerateKeyPair(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *out, ULONG bits, ULONG)
{
    auto key = std::make_unique<HostKey>();
    key->asymmetric = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(bits));
    if (!key->asymmetric)
        return -1;
    *out = key.release();
    return 0;
}

NTSTATUS BCryptFinalizeKeyPair(BCRYPT_KEY_HANDLE key, ULONG)
{
    return key && key->asymmetric ? 0 : -1;
}

NTSTATUS BCryptDestroyKey(BCRYPT_KEY_HANDLE key)
{
    delete key;
    return 0;
}

NTSTATUS BCryptSignHash(BCRYPT_KEY_HANDLE key,
                        void *padding,
                        PUCHAR digestBytes,
                        ULONG size,
                        PUCHAR out,
                        ULONG capacity,
                        ULONG *written,
                        ULONG flags)
{
    try
    {
        KeyContext context(EVP_PKEY_CTX_new(key->asymmetric, nullptr), EVP_PKEY_CTX_free);
        require(context && size == 32 && EVP_PKEY_sign_init(context.get()) == 1);
        rsaPadding(context.get(), padding, flags);
        size_t count = capacity;
        require(EVP_PKEY_sign(context.get(), out, &count, digestBytes, size) == 1);
        *written = count;
        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptVerifySignature(BCRYPT_KEY_HANDLE key,
                               void *padding,
                               PUCHAR digestBytes,
                               ULONG size,
                               PUCHAR signature,
                               ULONG signatureSize,
                               ULONG flags)
{
    try
    {
        KeyContext context(EVP_PKEY_CTX_new(key->asymmetric, nullptr), EVP_PKEY_CTX_free);
        require(context && size == 32 && EVP_PKEY_verify_init(context.get()) == 1);
        std::vector<uint8_t> encoded;
        if (EVP_PKEY_is_a(key->asymmetric, "EC"))
        {
            require(!padding && !flags && signatureSize == 64);
            Owned<ECDSA_SIG, ECDSA_SIG_free> sig(ECDSA_SIG_new(), ECDSA_SIG_free);
            Number r(BN_bin2bn(signature, 32, nullptr), BN_free),
                s(BN_bin2bn(signature + 32, 32, nullptr), BN_free);
            require(sig && r && s && ECDSA_SIG_set0(sig.get(), r.get(), s.get()) == 1);
            r.release();
            s.release();
            const auto length = i2d_ECDSA_SIG(sig.get(), nullptr);
            require(length > 0);
            encoded.resize(length);
            auto cursor = encoded.data();
            require(i2d_ECDSA_SIG(sig.get(), &cursor) == length);
            signature = encoded.data();
            signatureSize = encoded.size();
            require(EVP_PKEY_CTX_set_signature_md(context.get(), EVP_sha256()) == 1);
        }
        else
            rsaPadding(context.get(), padding, flags);
        return EVP_PKEY_verify(context.get(), signature, signatureSize, digestBytes, size) == 1
                   ? 0
                   : -1;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptSetProperty(
    BCRYPT_ALG_HANDLE algorithm, const wchar_t *property, PUCHAR value, ULONG, ULONG)
{
    if (std::wstring(property) != BCRYPT_CHAINING_MODE)
        return -1;
    algorithm->mode = reinterpret_cast<wchar_t *>(value);
    return 0;
}

NTSTATUS BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE algorithm,
                                    BCRYPT_KEY_HANDLE *out,
                                    PUCHAR,
                                    ULONG,
                                    PUCHAR secret,
                                    ULONG size,
                                    ULONG)
{
    if (size != 16)
        return -1;
    try
    {
        *out = new HostKey{nullptr, {secret, secret + size}, algorithm->mode};
        return 0;
    }
    catch (...)
    {
        return -1;
    }
}

NTSTATUS BCryptEncrypt(BCRYPT_KEY_HANDLE key,
                       PUCHAR bytes,
                       ULONG size,
                       void *padding,
                       PUCHAR iv,
                       ULONG ivSize,
                       PUCHAR out,
                       ULONG capacity,
                       ULONG *written,
                       ULONG)
{
    return cipher(key, bytes, size, padding, iv, ivSize, out, capacity, written, true);
}

NTSTATUS BCryptDecrypt(BCRYPT_KEY_HANDLE key,
                       PUCHAR bytes,
                       ULONG size,
                       void *padding,
                       PUCHAR iv,
                       ULONG ivSize,
                       PUCHAR out,
                       ULONG capacity,
                       ULONG *written,
                       ULONG)
{
    return cipher(key, bytes, size, padding, iv, ivSize, out, capacity, written, false);
}
#endif
