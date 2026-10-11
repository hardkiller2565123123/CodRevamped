#pragma once
#include <stdint.h>
#include <stddef.h>

// Local platform-provider protocol, distinct from Demonware's wire protocol.
// Little-endian, fixed-size, nonce-bound and RSA-PSS/SHA-256 authenticated.
struct DWLocalPlatformPayload {
    uint32_t magic;
    uint32_t version;
    uint8_t nonce[32];
    uint64_t issued;
    uint64_t expires;
    uint64_t userId;
    uint32_t gameAccountId;
    uint32_t licenses; // bit 0: Replay base-game license
    char name[36];
    uint32_t region; // local provider: US = 1
    char sessionToken[65];
    char accountToken[65];
    uint8_t age; // local account profile; adult provider policy
    uint8_t accountPolicy; // 0: unrestricted local account
    uint32_t capabilities; // bit 0: account profile supplied by this provider
    uint8_t reserved[8];
};
struct DWLocalPlatformReply {
    DWLocalPlatformPayload payload;
    uint8_t signature[256];
};
static_assert(sizeof(DWLocalPlatformPayload) == 256);
static_assert(sizeof(DWLocalPlatformReply) == 512);
static_assert(offsetof(DWLocalPlatformPayload, sessionToken) == 112);
static_assert(offsetof(DWLocalPlatformPayload, age) == 242);
static_assert(offsetof(DWLocalPlatformPayload, capabilities) == 244);
static_assert(offsetof(DWLocalPlatformReply, signature) == 256);
constexpr uint32_t DW_LOCAL_PLATFORM_MAGIC = 0x31505744;
constexpr uint32_t DW_LOCAL_PLATFORM_VERSION = 2;

// Public platform resource publication. The issuer authenticates the complete
// native protobuf handle and compressed content, including unused zero padding.
// This stays separate from the login protocol so saved identity/session ABI is
// unchanged. A universal locale (0) applies to this local server's filter policy.
struct DWLocalResourceRequest {
    uint8_t nonce[32];
    uint32_t program;
    uint32_t usage;
    uint32_t locale;
    uint32_t region;
};
struct DWLocalResourcePayload {
    uint32_t magic;
    uint32_t version;
    uint8_t nonce[32];
    uint64_t issued;
    uint64_t expires;
    uint32_t program;
    uint32_t usage;
    uint32_t locale;
    uint32_t region;
    uint32_t handleLength;
    uint32_t contentLength;
    uint8_t handle[256]; // original SDK ResourceHandle protobuf
    uint8_t content[4096]; // original ZpmC envelope + zlib WordFilters protobuf
};
struct DWLocalResourceReply {
    DWLocalResourcePayload payload;
    uint8_t signature[256];
};
static_assert(sizeof(DWLocalResourceRequest) == 48);
static_assert(sizeof(DWLocalResourcePayload) == 4432);
static_assert(sizeof(DWLocalResourceReply) == 4688);
static_assert(offsetof(DWLocalResourcePayload, handle) == 80);
static_assert(offsetof(DWLocalResourcePayload, content) == 336);
constexpr uint32_t DW_LOCAL_RESOURCE_MAGIC = 0x31525744;
