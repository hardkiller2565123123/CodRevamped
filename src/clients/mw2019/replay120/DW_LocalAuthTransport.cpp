#include "com_debugstates.h"
#include "dw_local_trust.h"
#include "DW_LocalConfig.h"

// Reconstructed native object layouts from Replay constructors and methods.
struct DWNativeHttp
{
    const uintptr_t *vtable;
    uint32_t state;
    uint32_t padding;
    uint8_t native16[48];
    void *curl;
    uint8_t native72[8];
    void *headers;
    void *responseHeaders;
    uint8_t native96[48];
    uint8_t headerData[1024];
    uint8_t native1168[72];
};

static_assert(sizeof(DWNativeHttp) == 1240);
static_assert(offsetof(DWNativeHttp, curl) == 64);
static_assert(offsetof(DWNativeHttp, headers) == 80);
static_assert(offsetof(DWNativeHttp, headerData) == 144);

struct DWNativeRsaKey
{
    uint32_t state;
    uint32_t padding;
    uint8_t nativeKey[72];
    int32_t bytes;
    uint8_t reserved[12];
};

static_assert(sizeof(DWNativeRsaKey) == 96);

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    void DW_LocalPlatform_RecordStage(const char *);
    void func_1420E3780(DWNativeHttp *);
    int func_1422EACE0(void *, int, uintptr_t); // native curl_easy_setopt
    void func_1420E31A0();                      // CURLOPT_HEADERFUNCTION callback; address only
    void *func_1422E87C0(void *, const char *); // native curl_slist_append
    uint8_t func_1420E2940(const char *, void *, uint64_t *, int *);
    int func_142056C00(const uint8_t *, unsigned, void *); // native rsa_import
    extern int (*gl_152E9F6D8)(const void *);              // native multiprecision count_bits
    extern const uint8_t gl_1426A84F0[];                   // original authentication SPKI
}

namespace
{
    bool Equal(const uint8_t *a, const uint8_t *b, unsigned length)
    {
        unsigned difference = 0;
        for (unsigned i = 0; i < length; ++i)
            difference |= a[i] ^ b[i];
        return difference == 0;
    }

    bool LocalAuth(const char *url)
    {
        const char *expected = DW_LocalConfig_NativeAuthUrl();
        if (!url)
            return false;
        unsigned i = 0;
        while (expected[i] && url[i] == expected[i])
            ++i;
        return !expected[i] && !url[i];
    }

    bool LocalLegacy(const char *url)
    {
        constexpr const char *allowed[] = {
            "https://dev.umbrella.demonware.net/v1.0/tokens/lsg/?client=replaylocal",
            "https://cert.umbrella.demonware.net/v1.0/tokens/lsg/?client=replaylocal",
            "https://prod.umbrella.demonware.net/v1.0/tokens/lsg/?client=replaylocal"};
        if (!url)
            return false;
        for (const auto *expected : allowed)
        {
            unsigned i = 0;
            while (expected[i] && url[i] == expected[i])
                ++i;
            if (!expected[i] && !url[i])
                return true;
        }
        return false;
    }
} // namespace

// bdHTTP::initRequest. Keep native Curl buffers, callbacks, lifecycle, method
// handling and timeout behavior. Only the DW loopback auth URL is selected as
// plain HTTP; its application response remains RSA authenticated. No global
// certificate exceptions or disabled signature checks are installed.
extern "C" uint8_t func_1420E34D0(DWNativeHttp *http,
                                  int method,
                                  const char *nativeUrl,
                                  unsigned timeout)
{
    if (!http || !nativeUrl)
        return 0;
    const bool local = DW_LocalBackend_IsEnabled();
    const char *url = local && LocalAuth(nativeUrl)     ? DW_LocalConfig_AuthUrl()
                      : local && LocalLegacy(nativeUrl) ? DW_LocalConfig_LegacyUrl()
                                                        : nativeUrl;
    if (url != nativeUrl)
        DW_LocalPlatform_RecordStage(
            LocalAuth(nativeUrl) ? "DW_LOCAL_AUTH_HTTP_INIT native auth request initializing"
                                 : "DW_LOCAL_LEGACY_HTTP_INIT native account request initializing");
    using Check = uint8_t (*)(DWNativeHttp *, unsigned);
    if (!reinterpret_cast<Check>(http->vtable[22])(http, 4) &&
        !reinterpret_cast<Check>(http->vtable[22])(http, 0))
        return 0;
    func_1420E3780(http);
    if (!http->curl)
        return 0;
    auto option = [http](int name, uintptr_t value)
    {
        return func_1422EACE0(http->curl, name, value) == 0;
    };
    bool ok = option(41, 0) && option(20094, reinterpret_cast<uintptr_t>(&func_1420E31A0)) &&
              option(10010, reinterpret_cast<uintptr_t>(http->headerData)) &&
              option(10002, reinterpret_cast<uintptr_t>(url));
    switch (method)
    {
    case 1:
        ok = ok && option(80, 1);
        break;
    case 4:
        ok = ok && option(54, 1);
        http->headers = func_1422E87C0(http->headers, "Expect:");
        break;
    case 5:
        ok = ok && option(44, 1) && option(10036, reinterpret_cast<uintptr_t>("DELETE"));
        break;
    case 6:
    {
        ok = ok && option(10036, reinterpret_cast<uintptr_t>("COPY"));
        char host[1024]{};
        uint64_t size = 0;
        int port = 0;
        if (!func_1420E2940(url, host, &size, &port))
            ok = false;
        char header[1040]{};
        if (port == 80 || port == 443)
            Com_sprintf(header, sizeof(header), "Host: %s", host);
        else
            Com_sprintf(header, sizeof(header), "Host: %s:%d", host, port);
        http->headers = func_1422E87C0(http->headers, header);
        http->headers = func_1422E87C0(http->headers, "Overwrite: T");
        break;
    }
    default:
        ok = ok && option(47, 1);
        break;
    }
    http->state = 2;
    if (ok && reinterpret_cast<Check>(http->vtable[9])(http, timeout))
    {
        if (url != nativeUrl)
            DW_LocalPlatform_RecordStage("DW_LOCAL_HTTP_READY native loopback request initialized");
        return 1;
    }
    func_1420E3780(http);
    return 0;
}

// bdRSAKey::import. For this auth key only, select the pinned local SPKI in the
// DW image. Native rsa_import and all subsequent signature verification remain
// real. Other keys and ordinary executable names retain the original import.
extern "C" uint8_t func_1420F1AD0(DWNativeRsaKey *key, const uint8_t *der, unsigned size)
{
    if (!key || !der || key->state)
        return 0;
    if (DW_LocalBackend_IsEnabled() && size == 294 && Equal(der, gl_1426A84F0, 294))
    {
        der = s_dwLocalAuthDer;
        size = sizeof(s_dwLocalAuthDer);
    }
    if (func_142056C00(der, size, key->nativeKey))
        return 0;
    const void *modulus = *reinterpret_cast<const void *const *>(key->nativeKey + 24);
    key->bytes = gl_152E9F6D8(modulus) / 8;
    key->state = 1;
    return 1;
}
