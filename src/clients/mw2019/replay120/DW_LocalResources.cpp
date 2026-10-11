#include "com_debugstates.h"
#include "dw_platform_abi.h"
#include "dw_platform_protocol.h"

extern "C" {
bool DW_LocalBackend_IsEnabled();
bool DW_LocalPlatform_Post(const wchar_t*, void*, unsigned, void*, unsigned);
bool DW_LocalPlatform_MakeNonce(uint8_t*);
uint64_t DW_LocalPlatform_Time();
bool DW_LocalPlatform_VerifyResourceReply(const DWLocalResourceReply*, const DWLocalResourceRequest*, uint64_t);
void DW_LocalPlatform_RecordStage(const char*);
void func_140467210(DWPlatformResourceHandle*);
void* func_1404672F0(DWPlatformResourceHandle*);
uint8_t func_140659070(const void*, int, void*);
uint8_t func_14046AF00(const DWPlatformResourceHandle*, const void*, size_t);
DWPlatformString* func_140528CA0(DWPlatformString*);
DWPlatformString* func_14046AC10(DWPlatformString*, const DWPlatformResourceHandle*, const DWPlatformString*);
void* func_140640AE0(void*);
extern uint8_t gl_14272B4C8[];
__declspec(dllimport) void* __stdcall LoadLibraryA(const char*);
__declspec(dllimport) void* __stdcall GetProcAddress(void*, const char*);
__declspec(dllimport) int __stdcall FreeLibrary(void*);
__declspec(dllimport) void* __stdcall CreateFileA(const char*, unsigned long, unsigned long, void*, unsigned long, unsigned long, void*);
__declspec(dllimport) int __stdcall WriteFile(void*, const void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) int __stdcall ReadFile(void*, void*, unsigned long, unsigned long*, void*);
__declspec(dllimport) int __stdcall CloseHandle(void*);
}

namespace {
DWLocalResourceReply s_resource{}; // published before platform login's release
unsigned s_verified = 0;
bool s_cached = false; // main thread only; hash addressed immutable publication
void FreeString(DWPlatformString* value) {
    if (value->data && !(value->capacityAndOwnership >> 63)) {
        void* allocator = func_140640AE0(nullptr);
        auto table = *reinterpret_cast<void***>(allocator);
        reinterpret_cast<void (*)(void*, void*)>(table[4])(allocator, value->data);
    }
}
bool Cache(const DWPlatformResourceHandle* handle) {
    if (s_cached) return true;
    using Directory = int (__stdcall*)(const char*, void*);
    using Flush = int (__stdcall*)(void*);
    auto library = LoadLibraryA("kernel32.dll");
    if (!library) return false;
    auto directory = reinterpret_cast<Directory>(GetProcAddress(library, "CreateDirectoryA"));
    auto flush = reinterpret_cast<Flush>(GetProcAddress(library, "FlushFileBuffers"));
    if (!directory || !flush) { FreeLibrary(library); return false; }
    DWPlatformString prefix{}, path{};
    func_140528CA0(&prefix);
    func_14046AC10(&path, handle, &prefix);
    bool ok = false;
    // Native cache key is SHA256-derived. Keep its native directory selection
    // and never replace an existing resource with mismatching content.
    if (prefix.length && path.length > prefix.length && path.length < 900) {
        char name[900]{};
        for (unsigned i = 0; i < path.length; ++i) name[i] = path.data[i];
        for (unsigned i = 3; i < path.length; ++i) {
            if (name[i] != '/' && name[i] != '\\') continue;
            const char delimiter = name[i]; name[i] = 0;
            directory(name, nullptr); name[i] = delimiter;
        }
        auto file = CreateFileA(name, 0x80000000, 3, nullptr, 3, 0x80, nullptr);
        if (file != reinterpret_cast<void*>(~uintptr_t{0})) {
            uint8_t bytes[4097]{}; unsigned long received = 0;
            ok = ReadFile(file, bytes, sizeof(bytes), &received, nullptr) &&
                 received == s_resource.payload.contentLength && func_14046AF00(handle, bytes, received);
            CloseHandle(file);
        } else {
            file = CreateFileA(name, 0x40000000, 0, nullptr, 1, 0x80, nullptr); // CREATE_NEW
            if (file != reinterpret_cast<void*>(~uintptr_t{0})) {
                unsigned long written = 0;
                ok = WriteFile(file, s_resource.payload.content, s_resource.payload.contentLength, &written, nullptr) &&
                     written == s_resource.payload.contentLength && flush(file);
                CloseHandle(file);
            }
        }
    }
    FreeString(&path); FreeString(&prefix);
    FreeLibrary(library);
    s_cached = ok;
    return ok;
}
}

// Called on the engine thread only after the previous provider worker joined.
// Keep content-addressed disk files, but revalidate/refetch their publication.
extern "C" void DW_LocalResource_Reset() {
    __atomic_store_n(&s_verified, 0U, __ATOMIC_RELEASE);
    s_cached = false;
}

extern "C" bool DW_LocalResource_Fetch() {
    DWLocalResourceRequest request{};
    request.program = 16974; request.usage = 0x61706674; request.region = 1;
    // The resource buffer is not used by the engine until signed-login state is
    // release-published. No native engine objects are touched on this worker.
    const bool ok = DW_LocalPlatform_MakeNonce(request.nonce) &&
        DW_LocalPlatform_Post(L"/platform/resource", &request, sizeof(request), &s_resource, sizeof(s_resource)) &&
        DW_LocalPlatform_VerifyResourceReply(&s_resource, &request, DW_LocalPlatform_Time());
    __atomic_store_n(&s_verified, ok ? 1U : 0U, __ATOMIC_RELEASE);
    DW_LocalPlatform_RecordStage(ok ? "DW_LOCAL_RESOURCE_VERIFIED signed BN/apft publication received" :
                                     "DW_LOCAL_RESOURCE_FAILED provider exchange/signature rejected");
    return ok;
}

// Actual SDK ResourcesService::GetContentHandle boundary. The original wrapper
// owns the tagged callback and destroys it after returning, so synchronous
// completion matches the original SDK's missing-client/error path lifetime.
extern "C" void* func_140469380(uint32_t, const DWPlatformResourceRequest* request,
    uintptr_t taggedCallback, uintptr_t) {
    DWPlatformResourceHandle handle{};
    handle.vtable = gl_14272B4C8;
    func_140467210(&handle);
    int error = 3; // native unsupported resource; never acknowledge unknown keys
    const auto& p = s_resource.payload;
    if (DW_LocalBackend_IsEnabled() && __atomic_load_n(&s_verified, __ATOMIC_ACQUIRE) && Sys_IsMainThread() && request &&
        (request->fields & 7) == 7 && request->program == p.program && request->usage == p.usage &&
        p.magic == DW_LOCAL_RESOURCE_MAGIC && DW_LocalPlatform_Time() < p.expires) {
        const bool parsed = func_140659070(p.handle, static_cast<int>(p.handleLength), &handle) != 0;
        const bool valid = parsed && (handle.fields & 15) == 15 && handle.region == p.region && handle.usage == p.usage &&
            handle.hash && handle.hash->length == 32 && handle.url && handle.url->length > 0 && handle.url->length < 200 &&
            func_14046AF00(&handle, p.content, p.contentLength);
        error = valid && Cache(&handle) ? 0 : 4;
        DW_LocalPlatform_RecordStage(error ? "DW_LOCAL_RESOURCE_NATIVE_FAILED handle/hash/cache rejected" :
            "DW_LOCAL_RESOURCE_NATIVE SDK callback completed; native filter loader remains authoritative");
    }
    if (taggedCallback) {
        auto callback = reinterpret_cast<void*>(taggedCallback);
        const uintptr_t storage = *reinterpret_cast<uintptr_t*>(callback);
        if (storage & 1) callback = reinterpret_cast<void*>(storage & ~uintptr_t{1});
        if (callback) {
            auto table = *reinterpret_cast<void***>(callback);
            reinterpret_cast<void (*)(void*, int*, const DWPlatformResourceHandle*)>(table[1])(callback, &error, &handle);
        }
    }
    return func_1404672F0(&handle);
}
