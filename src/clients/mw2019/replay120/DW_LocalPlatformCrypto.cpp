#include "dw_platform_protocol.h"
#include "dw_local_trust.h"

extern "C" {
__declspec(dllimport) void* __stdcall LoadLibraryA(const char*);
__declspec(dllimport) void* __stdcall GetProcAddress(void*, const char*);
__declspec(dllimport) int __stdcall FreeLibrary(void*);
__declspec(dllimport) void __stdcall GetSystemTimeAsFileTime(uint64_t*);
}

extern "C" uint64_t DW_LocalPlatform_Time() {
    uint64_t ticks = 0;
    GetSystemTimeAsFileTime(&ticks);
    return ticks / 10000000ULL - 11644473600ULL;
}
extern "C" bool DW_LocalPlatform_ValidatePayload(const DWLocalPlatformPayload* p,
                                                const uint8_t* nonce, uint64_t now) {
    if (!p || !nonce || p->magic != DW_LOCAL_PLATFORM_MAGIC || p->version != DW_LOCAL_PLATFORM_VERSION ||
        !p->userId || !p->gameAccountId || p->licenses != 1 || p->region != 1 ||
        p->age < 18 || p->age > 120 || p->accountPolicy != 0 || p->capabilities != 1 ||
        p->issued > now + 30 || p->expires <= now || p->expires <= p->issued ||
        p->expires - p->issued > 3600 || !p->name[0] || p->name[35]) return false;
    unsigned differences = 0, nonzero = 0;
    for (unsigned i = 0; i < 32; ++i) { differences |= p->nonce[i] ^ nonce[i]; nonzero |= nonce[i]; }
    if (differences || !nonzero) return false;
    bool ended = false;
    for (unsigned i = 0; i < 36; ++i) {
        unsigned c = static_cast<uint8_t>(p->name[i]);
        if (!c) ended = true;
        else if (ended || c < 32 || c > 126) return false;
    }
    for (unsigned i = 0; i < 64; ++i) {
        unsigned a = static_cast<uint8_t>(p->accountToken[i]), s = static_cast<uint8_t>(p->sessionToken[i]);
        if (!((a >= '0' && a <= '9') || (a >= 'a' && a <= 'f')) ||
            !((s >= '0' && s <= '9') || (s >= 'a' && s <= 'f'))) return false;
    }
    if (p->accountToken[64] || p->sessionToken[64]) return false;
    for (auto c : p->reserved) if (c) return false;
    return true;
}

extern "C" bool DW_LocalPlatform_MakeNonce(uint8_t* nonce) {
    using Random = long (__stdcall*)(void*, uint8_t*, unsigned long, unsigned long);
    auto library = LoadLibraryA("bcrypt.dll");
    if (!library) return false;
    auto random = reinterpret_cast<Random>(GetProcAddress(library, "BCryptGenRandom"));
    bool result = random && random(nullptr, nonce, 32, 2) >= 0;
    FreeLibrary(library);
    return result;
}

extern "C" bool DW_LocalPlatform_VerifyBytes(const void* bytes, unsigned size, const uint8_t* signature) {
    using Open = long (__stdcall*)(void**, const wchar_t*, const wchar_t*, unsigned long);
    using Close = long (__stdcall*)(void*, unsigned long);
    using Import = long (__stdcall*)(void*, void*, const wchar_t*, void**, uint8_t*, unsigned long, unsigned long);
    using Destroy = long (__stdcall*)(void*);
    using CreateHash = long (__stdcall*)(void*, void**, uint8_t*, unsigned long, uint8_t*, unsigned long, unsigned long);
    using HashData = long (__stdcall*)(void*, uint8_t*, unsigned long, unsigned long);
    using FinishHash = long (__stdcall*)(void*, uint8_t*, unsigned long, unsigned long);
    using Verify = long (__stdcall*)(void*, void*, uint8_t*, unsigned long, uint8_t*, unsigned long, unsigned long);
    struct PssPadding { const wchar_t* algorithm; unsigned long saltBytes; };
    auto library = LoadLibraryA("bcrypt.dll");
    if (!library || !bytes || !size || !signature) { if (library) FreeLibrary(library); return false; }
    auto open = reinterpret_cast<Open>(GetProcAddress(library, "BCryptOpenAlgorithmProvider"));
    auto close = reinterpret_cast<Close>(GetProcAddress(library, "BCryptCloseAlgorithmProvider"));
    auto import = reinterpret_cast<Import>(GetProcAddress(library, "BCryptImportKeyPair"));
    auto destroyKey = reinterpret_cast<Destroy>(GetProcAddress(library, "BCryptDestroyKey"));
    auto createHash = reinterpret_cast<CreateHash>(GetProcAddress(library, "BCryptCreateHash"));
    auto hashData = reinterpret_cast<HashData>(GetProcAddress(library, "BCryptHashData"));
    auto finishHash = reinterpret_cast<FinishHash>(GetProcAddress(library, "BCryptFinishHash"));
    auto destroyHash = reinterpret_cast<Destroy>(GetProcAddress(library, "BCryptDestroyHash"));
    auto verify = reinterpret_cast<Verify>(GetProcAddress(library, "BCryptVerifySignature"));
    void* rsa = nullptr; void* sha = nullptr; void* key = nullptr; void* hash = nullptr;
    bool ok = false;
    if (open && close && import && destroyKey && createHash && hashData && finishHash && destroyHash && verify &&
        open(&rsa, L"RSA", nullptr, 0) >= 0 && open(&sha, L"SHA256", nullptr, 0) >= 0 &&
        import(rsa, nullptr, L"RSAPUBLICBLOB", &key, const_cast<uint8_t*>(s_dwLocalPlatformPublicKey),
               sizeof(s_dwLocalPlatformPublicKey), 0) >= 0 &&
        createHash(sha, &hash, nullptr, 0, nullptr, 0, 0) >= 0) {
        uint8_t digest[32]{};
        PssPadding padding{L"SHA256", 32};
        ok = hashData(hash, reinterpret_cast<uint8_t*>(const_cast<void*>(bytes)), size, 0) >= 0 &&
             finishHash(hash, digest, sizeof(digest), 0) >= 0 &&
             verify(key, &padding, digest, sizeof(digest), const_cast<uint8_t*>(signature), 256, 8) >= 0;
    }
    if (hash && destroyHash) destroyHash(hash);
    if (key && destroyKey) destroyKey(key);
    if (sha && close) close(sha, 0);
    if (rsa && close) close(rsa, 0);
    FreeLibrary(library);
    return ok;
}

extern "C" bool DW_LocalPlatform_VerifyReply(const DWLocalPlatformReply* reply, const uint8_t* nonce, uint64_t now) {
    return reply && DW_LocalPlatform_ValidatePayload(&reply->payload, nonce, now) &&
           DW_LocalPlatform_VerifyBytes(&reply->payload, sizeof(reply->payload), reply->signature);
}

extern "C" bool DW_LocalPlatform_VerifyResourceReply(const DWLocalResourceReply* reply,
    const DWLocalResourceRequest* request, uint64_t now) {
    if (!reply || !request) return false;
    const auto& p = reply->payload;
    if (p.magic != DW_LOCAL_RESOURCE_MAGIC || p.version != 1 ||
        request->program != 16974 || request->usage != 0x61706674 || request->region != 1 || request->locale != 0 ||
        p.program != request->program || p.usage != request->usage || p.region != request->region || p.locale != request->locale ||
        p.issued > now + 30 || p.expires <= now || p.expires <= p.issued || p.expires - p.issued > 3600 ||
        !p.handleLength || p.handleLength > sizeof(p.handle) || p.contentLength < 27 || p.contentLength > sizeof(p.content)) return false;
    unsigned differences = 0, nonzero = 0;
    for (unsigned i = 0; i < 32; ++i) { differences |= p.nonce[i] ^ request->nonce[i]; nonzero |= request->nonce[i]; }
    if (differences || !nonzero) return false;
    for (unsigned i = p.handleLength; i < sizeof(p.handle); ++i) if (p.handle[i]) return false;
    for (unsigned i = p.contentLength; i < sizeof(p.content); ++i) if (p.content[i]) return false;
    return DW_LocalPlatform_VerifyBytes(&p, sizeof(p), reply->signature);
}
