#include "com_debugstates.h"
#include "dw_local_trust.h"

// Replay's CachedContentCrypto::RSAVerify_SHA256 imports a libtomcrypt key,
// verifies a 32-byte digest with a 256-byte RSA-PSS signature and eight salt
// bytes, and releases the key. Preserve that entire native validation path.
// The local DW executable selects its provisioned publisher key; ordinary
// Replay continues to import its original CCC key.
struct DWNativeCachedRsaKey {
    int type;
    unsigned padding;
    void* e;
    void* d;
    void* n;
    void* p;
    void* q;
    void* dP;
    void* dQ;
    void* qP;
};
static_assert(sizeof(DWNativeCachedRsaKey) == 72);
static_assert(offsetof(DWNativeCachedRsaKey, n) == 24);

extern "C" {
bool DW_LocalBackend_IsEnabled();
extern const uint8_t gl_142416200[];
int func_1420566F0(const char*); // find_hash
int func_142056C00(const uint8_t*, unsigned, void*); // rsa_import
int func_142056870(const uint8_t*, unsigned, const uint8_t*, unsigned,
                 int, int, unsigned, int*, void*); // rsa_verify_hash_ex
void func_142056820(void*); // rsa_free
void* func_14103D460(); // Online_ErrorReporting::GetInstancePtr
void func_14103D4A0(void*, uint64_t, const char*); // ReportError
}

extern "C" uint8_t func_141038500(void*, const uint8_t* digest, const uint8_t* signature) {
    const int hash = func_1420566F0("sha256");
    if (hash == -1) {
        func_14103D4A0(func_14103D460(), 0x1000, nullptr);
        return 0;
    }
    DWNativeCachedRsaKey key{};
    const bool local = DW_LocalBackend_IsEnabled();
    const uint8_t* der = local ? s_dwLocalAuthDer : gl_142416200;
    const unsigned bytes = local ? sizeof(s_dwLocalAuthDer) : 270;
    const int imported = func_142056C00(der, bytes, &key);
    char context[16]{};
    if (imported) {
        Com_sprintf(context, sizeof(context), "%d", imported);
        func_14103D4A0(func_14103D460(), 0x2000, context);
        return 0;
    }
    int valid = 0;
    const int result = func_142056870(signature, 256, digest, 32, 3, hash, 8, &valid, &key);
    func_142056820(&key);
    if (!result && valid == 1) return 1;
    Com_sprintf(context, sizeof(context), "%d", result);
    func_14103D4A0(func_14103D460(), 0x4000, context);
    return 0;
}
