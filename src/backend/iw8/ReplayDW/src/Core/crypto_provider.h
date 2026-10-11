#pragma once
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include "host_os.h"
#include <string>
#include <vector>
#include <openssl/evp.h>

// Narrow CNG format adapter: retained Replay platform/auth code uses these
// operations. OpenSSL owns cryptography; persisted/wire CNG blobs stay exact.
using NTSTATUS = int;
using ULONG = unsigned long;
using PUCHAR = unsigned char *;

struct HostAlgorithm
{
    std::wstring name;
    bool hmac;
    std::wstring mode;
};

struct HostHash
{
    HostAlgorithm algorithm;
    std::vector<uint8_t> bytes, secret;
};

struct HostKey
{
    EVP_PKEY *asymmetric = nullptr;
    std::vector<uint8_t> secret;
    std::wstring mode;

    ~HostKey()
    {
        EVP_PKEY_free(asymmetric);
        OPENSSL_cleanse(secret.data(), secret.size());
    }
};

using BCRYPT_ALG_HANDLE = HostAlgorithm *;
using BCRYPT_HASH_HANDLE = HostHash *;
using BCRYPT_KEY_HANDLE = HostKey *;
constexpr auto BCRYPT_SHA1_ALGORITHM = L"SHA1";
constexpr auto BCRYPT_SHA256_ALGORITHM = L"SHA256";
constexpr auto BCRYPT_MD5_ALGORITHM = L"MD5";
constexpr auto BCRYPT_RSA_ALGORITHM = L"RSA";
constexpr auto BCRYPT_AES_ALGORITHM = L"AES";
constexpr auto BCRYPT_ECDSA_P256_ALGORITHM = L"ECDSA_P256";
constexpr auto BCRYPT_RSAPUBLIC_BLOB = L"RSAPUBLICBLOB";
constexpr auto BCRYPT_RSAPRIVATE_BLOB = L"RSAPRIVATEBLOB";
constexpr auto BCRYPT_ECCPUBLIC_BLOB = L"ECCPUBLICBLOB";
constexpr auto BCRYPT_CHAINING_MODE = L"ChainingMode";
constexpr wchar_t BCRYPT_CHAIN_MODE_CBC[] = L"ChainingModeCBC";
constexpr wchar_t BCRYPT_CHAIN_MODE_GCM[] = L"ChainingModeGCM";
constexpr ULONG BCRYPT_ALG_HANDLE_HMAC_FLAG = 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG = 2,
                BCRYPT_PAD_PSS = 8;
constexpr DWORD BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345;

struct BCRYPT_ECCKEY_BLOB
{
    DWORD dwMagic, cbKey;
};

struct BCRYPT_PSS_PADDING_INFO
{
    const wchar_t *pszAlgId;
    ULONG cbSalt;
};

struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
{
    PUCHAR pbNonce = nullptr;
    ULONG cbNonce = 0;
    PUCHAR pbTag = nullptr;
    ULONG cbTag = 0;
};

#define BCRYPT_INIT_AUTH_MODE_INFO(info) (info = {})
NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *, const wchar_t *, void *, ULONG);
NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
NTSTATUS BCryptCreateHash(
    BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE);
NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptDeriveKeyPBKDF2(
    BCRYPT_ALG_HANDLE, PUCHAR, ULONG, PUCHAR, ULONG, uint64_t, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptImportKeyPair(
    BCRYPT_ALG_HANDLE, void *, const wchar_t *, BCRYPT_KEY_HANDLE *, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptExportKey(BCRYPT_KEY_HANDLE, void *, const wchar_t *, PUCHAR, ULONG, ULONG *, ULONG);
NTSTATUS BCryptGenerateKeyPair(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *, ULONG, ULONG);
NTSTATUS BCryptFinalizeKeyPair(BCRYPT_KEY_HANDLE, ULONG);
NTSTATUS BCryptDestroyKey(BCRYPT_KEY_HANDLE);
NTSTATUS BCryptSignHash(BCRYPT_KEY_HANDLE, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);
NTSTATUS BCryptVerifySignature(BCRYPT_KEY_HANDLE, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptSetProperty(BCRYPT_ALG_HANDLE, const wchar_t *, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptGenerateSymmetricKey(
    BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
NTSTATUS BCryptEncrypt(
    BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);
NTSTATUS BCryptDecrypt(
    BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);
#endif
