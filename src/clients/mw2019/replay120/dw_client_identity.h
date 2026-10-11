#pragma once
#include "dw_platform_protocol.h"

// A machine-local P-256 key proves ownership of a player. The server nonce is
// short-lived and single-use; the signature binds the client nonce and name.
struct DWLocalClientChallengeRequest
{
    uint8_t publicKey[72]; // Windows BCRYPT_ECCPUBLIC_BLOB, ECDSA P-256.
    uint8_t nonce[32];
};

struct DWLocalClientLoginRequest
{
    uint32_t magic;
    uint32_t version;
    uint8_t nonce[32];
    uint8_t challenge[32];
    uint8_t publicKey[72];
    char name[36];
    uint8_t signature[64]; // CNG ECDSA r || s over SHA-256 of the prefix.
};

constexpr uint32_t DW_LOCAL_CLIENT_MAGIC = 0x31494452;
constexpr uint32_t DW_LOCAL_CLIENT_VERSION = 1;
static_assert(sizeof(DWLocalClientChallengeRequest) == 104);
static_assert(sizeof(DWLocalClientLoginRequest) == 244);
static_assert(offsetof(DWLocalClientLoginRequest, signature) == 180);

// Version 2 signs the locally owned progression and INI starting-rank fields.
// Keep version 1's wire and identity-file format valid for older clients.
struct DWLocalClientLoginRequestV2
{
    uint32_t magic;
    uint32_t version;
    uint8_t nonce[32];
    uint8_t challenge[32];
    uint8_t publicKey[72];
    char name[36];
    uint32_t options; // bit 0: restore a locally stored progression record
    uint64_t localUserId;
    uint64_t playerXp;
    uint32_t startingRank; // 0 automatic; 1..55 is Replay's career rank floor
    uint32_t reserved;
    uint8_t signature[64];
};
static_assert(sizeof(DWLocalClientLoginRequestV2) == 272);
static_assert(offsetof(DWLocalClientLoginRequestV2, signature) == 208);
constexpr uint32_t DW_LOCAL_CLIENT_LOGIN_VERSION = 2;

// Renewal proves the same machine key and the specific active platform session.
// It carries no rename, rank, inventory or progression mutation.
struct DWLocalClientRenewRequest
{
    uint32_t magic;
    uint32_t version;
    uint8_t nonce[32];
    uint8_t challenge[32];
    uint8_t publicKey[72];
    char sessionToken[64];
    uint8_t signature[64];
};
static_assert(sizeof(DWLocalClientRenewRequest) == 272);
static_assert(offsetof(DWLocalClientRenewRequest, signature) == 208);
constexpr uint32_t DW_LOCAL_CLIENT_RENEW_VERSION = 3;

using DWLocalIdentityPost = bool (*)(const wchar_t *, void *, unsigned, void *, unsigned);
extern "C"
{
    bool DW_LocalIdentity_Login(const char *, const uint8_t *, DWLocalPlatformReply *,
                                DWLocalIdentityPost);
    bool DW_LocalIdentity_PublicKey(uint8_t *);
    bool DW_LocalIdentity_Renew(const uint8_t *, const char *, DWLocalPlatformReply *,
                               DWLocalIdentityPost);
    const char *DW_LocalIdentity_Error();
}
