#pragma once
#include <stdint.h>
#include <stddef.h>

// Original Replay 1.20 evidence: native constructors, getters, callbacks and
// token-task pump. These are ABI offsets, never runtime RVAs or guessed casts.
struct DWPlatformString {
    char* data;
    uint64_t length;
    uint64_t capacityAndOwnership;
    char local[16];
};
static_assert(sizeof(DWPlatformString) == 40);
struct DWPlatformProtectedFlag {
    uint32_t encoded;
    uint8_t shift;
    uint8_t reserved[3];
    uint32_t key;
    uint32_t initialization;
};
struct DWPlatformAuth {
    uint32_t state;
    uint32_t padding;
    DWPlatformString ssoToken;
    uint8_t nativeServices[120];
    uint8_t accountId[32];
    uint8_t gameAccountId[40];
    DWPlatformString battleTag;
    DWPlatformString clientId;
    DWPlatformString extra;
    DWPlatformString email;
    DWPlatformString geoIp;
    uint8_t queued;
    uint8_t queuePadding[3];
    uint32_t queuePosition;
    uint64_t queueWait;
    uint32_t failure;
    uint32_t licenses[64];
    uint32_t licenseCount;
    uint8_t tokenProcessed;
    uint8_t tokenPadding[3];
    DWPlatformProtectedFlag ownership[4];
    uint8_t disconnected;
    uint8_t callbackPadding[3];
    void (*signedInCallback)();
    uint64_t callbackCount;
};
static_assert(sizeof(DWPlatformAuth) == 808);
static_assert(offsetof(DWPlatformAuth, accountId) == 168);
static_assert(offsetof(DWPlatformAuth, gameAccountId) == 200);
static_assert(offsetof(DWPlatformAuth, battleTag) == 240);
static_assert(offsetof(DWPlatformAuth, failure) == 456);
static_assert(offsetof(DWPlatformAuth, licenseCount) == 716);
static_assert(offsetof(DWPlatformAuth, ownership) == 724);
static_assert(offsetof(DWPlatformAuth, signedInCallback) == 792);
struct DWPlatformConnection {
    uint32_t state;
    uint32_t padding;
    void* nativeClient;
    uint8_t nativeCallbacks[100];
    uint32_t lastAttempt;
    uint32_t retryCount;
    uint32_t tailPadding;
    DWPlatformString serverName;
    uint32_t disconnectReason;
    uint32_t reasonPadding;
    void (*disconnectedCallback)(uint32_t);
    uint64_t callbackCount;
};
static_assert(sizeof(DWPlatformConnection) == 192);
static_assert(offsetof(DWPlatformConnection, nativeClient) == 8);
static_assert(offsetof(DWPlatformConnection, nativeCallbacks) == 16);
static_assert(offsetof(DWPlatformConnection, lastAttempt) == 116);
static_assert(offsetof(DWPlatformConnection, retryCount) == 120);
static_assert(offsetof(DWPlatformConnection, serverName) == 128);
static_assert(offsetof(DWPlatformConnection, disconnectReason) == 168);
static_assert(offsetof(DWPlatformConnection, disconnectedCallback) == 176);
static_assert(offsetof(DWPlatformConnection, callbackCount) == 184);
struct DWPlatformUser {
    int32_t signInState;
    char name[36];
    uint32_t reserved28;
    char platformName[64];
    char fullName[36];
    uint64_t xuid;
    char xuidText[21];
    uint8_t reservedAD[11];
    uint64_t platformId;
    char platformIdText[21];
    uint8_t reservedD5[19];
};
static_assert(sizeof(DWPlatformUser) == 232);
static_assert(offsetof(DWPlatformUser, xuid) == 144);
static_assert(offsetof(DWPlatformUser, platformId) == 184);
// Same-Replay common service constructor, ACCOUNT constructor/destructor and
// account-state consumers. Preserve the SDK cache's native constructor/storage.
struct DWPlatformService {
    const void* vtable;
    const char* name;
    uint32_t state; // 0 pending, 1 completed, 2 failed
    uint32_t group;
    uint8_t initialized;
    uint8_t padding[7];
    uint8_t nativeNotifications[16];
    void* callbacks;
    uint64_t callbackCount;
};
static_assert(sizeof(DWPlatformService) == 64);
static_assert(offsetof(DWPlatformService, state) == 16);
static_assert(offsetof(DWPlatformService, group) == 20);
struct DWPlatformAccount {
    DWPlatformService service;
    uint8_t nativeAccountCache[64];
    uint32_t gameTimeReady;
    uint8_t native132[8];
    uint32_t country;
    uint32_t age;
    uint32_t padding;
};
static_assert(sizeof(DWPlatformAccount) == 152);
static_assert(offsetof(DWPlatformAccount, gameTimeReady) == 128);
static_assert(offsetof(DWPlatformAccount, country) == 140);
static_assert(offsetof(DWPlatformAccount, age) == 144);
struct DWPlatformTokenTask {
    const void* vtable;
    uint32_t state;
    uint32_t padding;
    uint64_t stopwatch;
    void* config;
    void* result;
    uint32_t stage;
    char message[1024];
    uint32_t tailPadding;
};
static_assert(sizeof(DWPlatformTokenTask) == 1072);
static_assert(offsetof(DWPlatformTokenTask, result) == 32);
static_assert(offsetof(DWPlatformTokenTask, message) == 44);

// Same-Replay Battle.net web-credential manager constructor and request path
// 0x140C859F0/0x140C85BF0. Each pending request is three native words. The local
// provider owns its own completion queue, but keeps the native request counter.
struct DWPlatformWebRequest {
    uint32_t id;
    uint32_t audience;
    void (*callback)(int, const DWPlatformString*, void*);
    void* context;
};
static_assert(sizeof(DWPlatformWebRequest) == 24);
struct DWPlatformWebCredentials {
    uint8_t sdkState[264];
    DWPlatformWebRequest queued[8];
    uint64_t queuedCount;
    uint8_t native464[104];
    DWPlatformWebRequest pending[4];
    uint64_t pendingCount;
    uint32_t native672;
    uint32_t nextRequest;
    uint64_t sdkRequests[4];
    uint64_t sdkRequestCount;
};
static_assert(sizeof(DWPlatformWebCredentials) == 720);
static_assert(offsetof(DWPlatformWebCredentials, nextRequest) == 676);
static_assert(offsetof(DWPlatformWebCredentials, sdkRequestCount) == 712);

// Replay's original generated ResourcesService protobuf messages. Shared empty
// strings, owned strings and unknown fields remain native parser/DTOR-owned.
struct DWPlatformResourceRequest {
    const void* vtable;
    void* unknownFields;
    uint32_t fields;
    uint32_t cachedSize;
    uint32_t program;
    uint32_t usage;
    uint32_t locale;
    uint32_t padding;
};
struct DWPlatformResourceHandle {
    const void* vtable;
    void* unknownFields;
    uint32_t fields;
    uint32_t cachedSize;
    uint32_t region;
    uint32_t usage;
    DWPlatformString* hash;
    DWPlatformString* url;
};
static_assert(sizeof(DWPlatformResourceRequest) == 40);
static_assert(sizeof(DWPlatformResourceHandle) == 48);
static_assert(offsetof(DWPlatformResourceRequest, program) == 24);
static_assert(offsetof(DWPlatformResourceHandle, hash) == 32);
