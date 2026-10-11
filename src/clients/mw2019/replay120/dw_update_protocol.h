#pragma once
#include <stdint.h>

// Preserve the version-1 wire layout for existing clients. Version 2 downloads
// the complete executable; its payload hash/size equal the target hash/size.
constexpr uint64_t DW_UPDATE_MAGIC = 0x3155505744594C50ULL;
constexpr uint64_t DW_UPDATE_MAX_IMAGE = 512ULL * 1024 * 1024;
#pragma pack(push, 1)

struct DWUpdateRequest
{
    uint64_t magic;
    uint32_t version;
    uint32_t reserved;
    uint8_t nonce[32];
    uint8_t baseHash[32];
};

struct DWUpdatePlan
{
    uint64_t magic;
    uint32_t version;
    uint32_t status; // 0 current, 1 update, 2 unrecognized build
    uint64_t issued;
    uint64_t expires;
    uint8_t nonce[32];
    uint8_t baseHash[32];
    uint8_t targetHash[32];
    uint8_t patchHash[32]; // v1 delta hash; v2 full executable hash
    uint64_t baseSize;
    uint64_t targetSize;
    uint64_t patchSize; // v1 delta size; v2 full executable size
    uint64_t release;
};

struct DWUpdateReply
{
    DWUpdatePlan plan;
    uint8_t signature[256]; // Existing pinned platform key, RSA-PSS/SHA256.
};

#pragma pack(pop)
static_assert(sizeof(DWUpdateRequest) == 80);
static_assert(sizeof(DWUpdatePlan) == 192);
static_assert(sizeof(DWUpdateReply) == 448);
