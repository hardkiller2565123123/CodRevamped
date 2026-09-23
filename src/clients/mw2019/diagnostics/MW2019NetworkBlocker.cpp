#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <winhttp.h>
#include <wininet.h>

#include "MW2019NetworkBlocker.hpp"
#include "MW2019Shared.hpp"

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <cstdlib>
#include <cctype>

namespace
{
    template <typename T, size_t N> constexpr size_t CountOf(const T (&)[N]) noexcept { return N; }

    volatile LONG g_enabled = 0;
    unsigned long long g_lastPatch = 0;
    wchar_t g_gameDir[32768]{};

    // Build377: public Activision/Demonware traffic stays isolated, while one
    // user-selected Revamped backend host is allowed in addition to LAN/loopback.
    SRWLOCK g_customHostLock = SRWLOCK_INIT;
    char g_customHost[256] = "127.0.0.1";
    std::uint32_t g_customV4[16]{};
    unsigned g_customV4Count = 0;
    IN6_ADDR g_customV6[8]{};
    unsigned g_customV6Count = 0;

    using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
    using WSAConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
    using SendToFn = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
    using GetAddrInfoAFn = int (WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
    using GetAddrInfoWFn = INT (WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
    using WinHttpSendRequestFn = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    using WinHttpQueryOptionFn = BOOL (WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD);
    using InternetQueryOptionAFn = BOOL (WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD);
    using HttpSendRequestAFn = BOOL (WINAPI*)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
    using HttpSendRequestWFn = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
    using InternetOpenUrlAFn = HINTERNET (WINAPI*)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    using InternetOpenUrlWFn = HINTERNET (WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);

    ConnectFn g_connect = nullptr;
    WSAConnectFn g_wsaConnect = nullptr;
    SendToFn g_sendto = nullptr;
    GetAddrInfoAFn g_getaddrinfoA = nullptr;
    GetAddrInfoWFn g_getaddrinfoW = nullptr;
    WinHttpSendRequestFn g_winHttpSendRequest = nullptr;
    WinHttpQueryOptionFn g_winHttpQueryOption = nullptr;
    InternetQueryOptionAFn g_internetQueryOptionA = nullptr;
    HttpSendRequestAFn g_httpSendRequestA = nullptr;
    HttpSendRequestWFn g_httpSendRequestW = nullptr;
    InternetOpenUrlAFn g_internetOpenUrlA = nullptr;
    InternetOpenUrlWFn g_internetOpenUrlW = nullptr;

    bool Enabled() { return InterlockedCompareExchange(&g_enabled, 0, 0) != 0; }

    bool IsAllowedIPv4(const sockaddr_in* in)
    {
        if (!in) return false;
        const unsigned char* b = reinterpret_cast<const unsigned char*>(&in->sin_addr.S_un.S_addr);
        return b[0] == 127 || b[0] == 10 || (b[0] == 192 && b[1] == 168) ||
               (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 169 && b[1] == 254);
    }

    bool IsAllowedIPv6(const sockaddr_in6* in)
    {
        if (!in) return false;
        const unsigned char* b = reinterpret_cast<const unsigned char*>(&in->sin6_addr);
        bool loop = true;
        for (int i = 0; i < 15; ++i) if (b[i] != 0) loop = false;
        if (loop && b[15] == 1) return true;
        if ((b[0] & 0xFE) == 0xFC) return true; // fc00::/7
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true; // fe80::/10
        return false;
    }

    bool IsCustomSockaddr(const sockaddr* addr)
    {
        if (!addr) return false;
        bool allowed = false;
        AcquireSRWLockShared(&g_customHostLock);
        if (addr->sa_family == AF_INET)
        {
            const auto value = reinterpret_cast<const sockaddr_in*>(addr)->sin_addr.S_un.S_addr;
            for (unsigned i = 0; i < g_customV4Count; ++i)
                if (g_customV4[i] == value) { allowed = true; break; }
        }
        else if (addr->sa_family == AF_INET6)
        {
            const auto* value = &reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr;
            for (unsigned i = 0; i < g_customV6Count; ++i)
                if (memcmp(&g_customV6[i], value, sizeof(IN6_ADDR)) == 0) { allowed = true; break; }
        }
        ReleaseSRWLockShared(&g_customHostLock);
        return allowed;
    }

    bool IsAllowedSockaddr(const sockaddr* addr)
    {
        if (!addr) return false;
        if (addr->sa_family == AF_INET)
            return IsAllowedIPv4(reinterpret_cast<const sockaddr_in*>(addr)) || IsCustomSockaddr(addr);
        if (addr->sa_family == AF_INET6)
            return IsAllowedIPv6(reinterpret_cast<const sockaddr_in6*>(addr)) || IsCustomSockaddr(addr);
        return false;
    }

    void FormatAddress(const sockaddr* addr, char* out, size_t outCount)
    {
        if (!out || !outCount) return;
        out[0] = 0;
        if (!addr) { strcpy_s(out, outCount, "<null>"); return; }
        if (addr->sa_family == AF_INET)
        {
            const auto* in = reinterpret_cast<const sockaddr_in*>(addr);
            const unsigned char* b = reinterpret_cast<const unsigned char*>(&in->sin_addr.S_un.S_addr);
            const unsigned port = (static_cast<unsigned>(reinterpret_cast<const unsigned char*>(&in->sin_port)[0]) << 8) |
                                  reinterpret_cast<const unsigned char*>(&in->sin_port)[1];
            _snprintf_s(out, outCount, _TRUNCATE, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], port);
        }
        else if (addr->sa_family == AF_INET6) strcpy_s(out, outCount, "<ipv6>");
        else _snprintf_s(out, outCount, _TRUNCATE, "<af=%d>", addr->sa_family);
    }

    bool StartsWithI(const wchar_t* text, const wchar_t* prefix)
    {
        if (!text || !prefix) return false;
        while (*prefix) { if (!*text || towlower(*text) != towlower(*prefix)) return false; ++text; ++prefix; }
        return true;
    }

    bool IsPrivateHostA(const char* host)
    {
        if (!host || !*host) return true;
        if (_stricmp(host, "localhost") == 0 || _strnicmp(host, "127.", 4) == 0 || _strnicmp(host, "10.", 3) == 0 ||
            _strnicmp(host, "192.168.", 8) == 0 || _stricmp(host, "::1") == 0 || _strnicmp(host, "fe80:", 5) == 0 ||
            _strnicmp(host, "fc", 2) == 0 || _strnicmp(host, "fd", 2) == 0) return true;
        if (_strnicmp(host, "172.", 4) == 0)
        {
            const int second = atoi(host + 4);
            if (second >= 16 && second <= 31) return true;
        }
        const size_t n = strlen(host);
        return n >= 6 && _stricmp(host + n - 6, ".local") == 0;
    }

    bool IsPrivateHostW(const wchar_t* host)
    {
        if (!host || !*host) return true;
        char temp[1024]{};
        WideCharToMultiByte(CP_UTF8, 0, host, -1, temp, static_cast<int>(CountOf(temp)), nullptr, nullptr);
        return IsPrivateHostA(temp);
    }

    bool IsCustomHostA(const char* host)
    {
        if (!host || !*host) return false;
        bool match = false;
        AcquireSRWLockShared(&g_customHostLock);
        match = g_customHost[0] && _stricmp(host, g_customHost) == 0;
        ReleaseSRWLockShared(&g_customHostLock);
        return match;
    }

    bool IsCustomHostW(const wchar_t* host)
    {
        if (!host || !*host) return false;
        char temp[512]{};
        WideCharToMultiByte(CP_UTF8, 0, host, -1, temp, static_cast<int>(CountOf(temp)), nullptr, nullptr);
        return IsCustomHostA(temp);
    }

    void CacheAddrInfoA(const ADDRINFOA* result)
    {
        if (!result) return;
        AcquireSRWLockExclusive(&g_customHostLock);
        g_customV4Count = 0;
        g_customV6Count = 0;
        for (auto* it = result; it; it = it->ai_next)
        {
            if (it->ai_family == AF_INET && it->ai_addr && g_customV4Count < CountOf(g_customV4))
                g_customV4[g_customV4Count++] = reinterpret_cast<const sockaddr_in*>(it->ai_addr)->sin_addr.S_un.S_addr;
            else if (it->ai_family == AF_INET6 && it->ai_addr && g_customV6Count < CountOf(g_customV6))
                g_customV6[g_customV6Count++] = reinterpret_cast<const sockaddr_in6*>(it->ai_addr)->sin6_addr;
        }
        ReleaseSRWLockExclusive(&g_customHostLock);
    }

    void CacheAddrInfoW(const ADDRINFOW* result)
    {
        if (!result) return;
        AcquireSRWLockExclusive(&g_customHostLock);
        g_customV4Count = 0;
        g_customV6Count = 0;
        for (auto* it = result; it; it = it->ai_next)
        {
            if (it->ai_family == AF_INET && it->ai_addr && g_customV4Count < CountOf(g_customV4))
                g_customV4[g_customV4Count++] = reinterpret_cast<const sockaddr_in*>(it->ai_addr)->sin_addr.S_un.S_addr;
            else if (it->ai_family == AF_INET6 && it->ai_addr && g_customV6Count < CountOf(g_customV6))
                g_customV6[g_customV6Count++] = reinterpret_cast<const sockaddr_in6*>(it->ai_addr)->sin6_addr;
        }
        ReleaseSRWLockExclusive(&g_customHostLock);
    }

    bool UrlContainsCustomHostA(const char* url)
    {
        if (!url || !*url) return false;
        char host[256]{};
        AcquireSRWLockShared(&g_customHostLock);
        strcpy_s(host, g_customHost);
        ReleaseSRWLockShared(&g_customHostLock);
        if (!host[0]) return false;
        for (const char* p = url; *p; ++p)
        {
            const char* a = p; const char* b = host;
            while (*a && *b && tolower(static_cast<unsigned char>(*a)) == tolower(static_cast<unsigned char>(*b))) { ++a; ++b; }
            if (!*b) return true;
        }
        return false;
    }

    bool UrlContainsCustomHostW(const wchar_t* url)
    {
        if (!url || !*url) return false;
        wchar_t host[256]{};
        AcquireSRWLockShared(&g_customHostLock);
        MultiByteToWideChar(CP_UTF8, 0, g_customHost, -1, host, static_cast<int>(CountOf(host)));
        ReleaseSRWLockShared(&g_customHostLock);
        if (!host[0]) return false;
        for (const wchar_t* p = url; *p; ++p)
        {
            const wchar_t* a = p; const wchar_t* b = host;
            while (*a && *b && towlower(*a) == towlower(*b)) { ++a; ++b; }
            if (!*b) return true;
        }
        return false;
    }

    void ResolveUrlQueryFunctions()
    {
        if (!g_winHttpQueryOption)
        {
            HMODULE mod = GetModuleHandleW(L"winhttp.dll");
            if (!mod) mod = LoadLibraryW(L"winhttp.dll");
            if (mod)
                g_winHttpQueryOption = reinterpret_cast<WinHttpQueryOptionFn>(GetProcAddress(mod, "WinHttpQueryOption"));
        }

        if (!g_internetQueryOptionA)
        {
            HMODULE mod = GetModuleHandleW(L"wininet.dll");
            if (!mod) mod = LoadLibraryW(L"wininet.dll");
            if (mod)
                g_internetQueryOptionA = reinterpret_cast<InternetQueryOptionAFn>(GetProcAddress(mod, "InternetQueryOptionA"));
        }
    }

    bool WinHttpHandleIsCustom(HINTERNET h)
    {
        if (!h) return false;
        ResolveUrlQueryFunctions();
        if (!g_winHttpQueryOption) return false;

        wchar_t url[2048]{};
        DWORD bytes = sizeof(url);
        if (!g_winHttpQueryOption(h, WINHTTP_OPTION_URL, url, &bytes)) return false;
        return UrlContainsCustomHostW(url);
    }

    bool InternetHandleIsCustom(HINTERNET h)
    {
        if (!h) return false;
        ResolveUrlQueryFunctions();
        if (!g_internetQueryOptionA) return false;

        char url[2048]{};
        DWORD bytes = sizeof(url);
        if (!g_internetQueryOptionA(h, INTERNET_OPTION_URL, url, &bytes)) return false;
        return UrlContainsCustomHostA(url);
    }

    int WSAAPI ConnectStub(SOCKET s, const sockaddr* name, int namelen)
    {
        if (!Enabled() || IsAllowedSockaddr(name)) return g_connect ? g_connect(s, name, namelen) : SOCKET_ERROR;
        WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR;
    }
    int WSAAPI WSAConnectStub(SOCKET s, const sockaddr* name, int namelen, LPWSABUF a, LPWSABUF b, LPQOS c, LPQOS d)
    {
        if (!Enabled() || IsAllowedSockaddr(name)) return g_wsaConnect ? g_wsaConnect(s, name, namelen, a, b, c, d) : SOCKET_ERROR;
        WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR;
    }
    int WSAAPI SendToStub(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
    {
        if (!Enabled() || IsAllowedSockaddr(to)) return g_sendto ? g_sendto(s, buf, len, flags, to, tolen) : SOCKET_ERROR;
        WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR;
    }
    int WSAAPI GetAddrInfoAStub(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result)
    {
        if (!Enabled() || IsPrivateHostA(node))
            return g_getaddrinfoA ? g_getaddrinfoA(node, service, hints, result) : WSAHOST_NOT_FOUND;
        if (IsCustomHostA(node) && g_getaddrinfoA)
        {
            const int rc = g_getaddrinfoA(node, service, hints, result);
            if (rc == 0 && result && *result) CacheAddrInfoA(*result);
            return rc;
        }
        WSASetLastError(WSAHOST_NOT_FOUND); return WSAHOST_NOT_FOUND;
    }
    INT WSAAPI GetAddrInfoWStub(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result)
    {
        if (!Enabled() || IsPrivateHostW(node))
            return g_getaddrinfoW ? g_getaddrinfoW(node, service, hints, result) : WSAHOST_NOT_FOUND;
        if (IsCustomHostW(node) && g_getaddrinfoW)
        {
            const INT rc = g_getaddrinfoW(node, service, hints, result);
            if (rc == 0 && result && *result) CacheAddrInfoW(*result);
            return rc;
        }
        WSASetLastError(WSAHOST_NOT_FOUND); return WSAHOST_NOT_FOUND;
    }
    BOOL WINAPI WinHttpSendRequestStub(HINTERNET h, LPCWSTR headers, DWORD headersLen, LPVOID optional, DWORD optionalLen, DWORD totalLen, DWORD_PTR ctx)
    {
        if (!Enabled() || WinHttpHandleIsCustom(h))
            return g_winHttpSendRequest ? g_winHttpSendRequest(h, headers, headersLen, optional, optionalLen, totalLen, ctx) : FALSE;
        SetLastError(ERROR_WINHTTP_CANNOT_CONNECT); return FALSE;
    }
    BOOL WINAPI HttpSendRequestAStub(HINTERNET h, LPCSTR headers, DWORD len, LPVOID opt, DWORD optLen)
    {
        if (!Enabled() || InternetHandleIsCustom(h))
            return g_httpSendRequestA ? g_httpSendRequestA(h, headers, len, opt, optLen) : FALSE;
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return FALSE;
    }
    BOOL WINAPI HttpSendRequestWStub(HINTERNET h, LPCWSTR headers, DWORD len, LPVOID opt, DWORD optLen)
    {
        if (!Enabled() || InternetHandleIsCustom(h))
            return g_httpSendRequestW ? g_httpSendRequestW(h, headers, len, opt, optLen) : FALSE;
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return FALSE;
    }
    HINTERNET WINAPI InternetOpenUrlAStub(HINTERNET h, LPCSTR url, LPCSTR headers, DWORD len, DWORD flags, DWORD_PTR ctx)
    {
        if (!Enabled() || UrlContainsCustomHostA(url))
            return g_internetOpenUrlA ? g_internetOpenUrlA(h, url, headers, len, flags, ctx) : nullptr;
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return nullptr;
    }
    HINTERNET WINAPI InternetOpenUrlWStub(HINTERNET h, LPCWSTR url, LPCWSTR headers, DWORD len, DWORD flags, DWORD_PTR ctx)
    {
        if (!Enabled() || UrlContainsCustomHostW(url))
            return g_internetOpenUrlW ? g_internetOpenUrlW(h, url, headers, len, flags, ctx) : nullptr;
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return nullptr;
    }

    bool ReplaceSlot(void** slot, void* replacement, void** original, const char* moduleName, const char* functionName)
    {
        if (!slot || !*slot || *slot == replacement) return false;
        DWORD old{};
        if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) return false;
        void* previous = InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(slot), replacement);
        DWORD dummy{}; VirtualProtect(slot, sizeof(void*), old, &dummy);
        FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
        if (original && !*original) *original = previous;
        (void)moduleName;
        (void)functionName;
        return true;
    }

    void PatchFunction(void** slot, const char* dll, const char* fn, const char* moduleName)
    {
        const bool ws = dll && (_stricmp(dll, "WS2_32.dll") == 0 || _stricmp(dll, "WSOCK32.dll") == 0);
        const bool wh = dll && _stricmp(dll, "WINHTTP.dll") == 0;
        const bool wi = dll && _stricmp(dll, "WININET.dll") == 0;
        if (ws && _stricmp(fn, "connect") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(ConnectStub), reinterpret_cast<void**>(&g_connect), moduleName, fn);
        else if (ws && _stricmp(fn, "WSAConnect") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(WSAConnectStub), reinterpret_cast<void**>(&g_wsaConnect), moduleName, fn);
        else if (ws && _stricmp(fn, "sendto") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(SendToStub), reinterpret_cast<void**>(&g_sendto), moduleName, fn);
        else if (ws && _stricmp(fn, "getaddrinfo") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(GetAddrInfoAStub), reinterpret_cast<void**>(&g_getaddrinfoA), moduleName, fn);
        else if (ws && _stricmp(fn, "GetAddrInfoW") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(GetAddrInfoWStub), reinterpret_cast<void**>(&g_getaddrinfoW), moduleName, fn);
        else if (wh && _stricmp(fn, "WinHttpSendRequest") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(WinHttpSendRequestStub), reinterpret_cast<void**>(&g_winHttpSendRequest), moduleName, fn);
        else if (wi && _stricmp(fn, "HttpSendRequestA") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(HttpSendRequestAStub), reinterpret_cast<void**>(&g_httpSendRequestA), moduleName, fn);
        else if (wi && _stricmp(fn, "HttpSendRequestW") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(HttpSendRequestWStub), reinterpret_cast<void**>(&g_httpSendRequestW), moduleName, fn);
        else if (wi && _stricmp(fn, "InternetOpenUrlA") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(InternetOpenUrlAStub), reinterpret_cast<void**>(&g_internetOpenUrlA), moduleName, fn);
        else if (wi && _stricmp(fn, "InternetOpenUrlW") == 0) ReplaceSlot(slot, reinterpret_cast<void*>(InternetOpenUrlWStub), reinterpret_cast<void**>(&g_internetOpenUrlW), moduleName, fn);
    }

    void PatchModule(HMODULE module, const char* moduleName)
    {
        const auto base = reinterpret_cast<std::uintptr_t>(module);
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return;
            const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!dir.VirtualAddress || !dir.Size) return;
            auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
            for (; desc->Name; ++desc)
            {
                const char* importedDll = reinterpret_cast<const char*>(base + desc->Name);
                auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);
                auto* original = desc->OriginalFirstThunk ? reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->OriginalFirstThunk) : nullptr;
                if (!original) continue;
                for (; original->u1.AddressOfData && thunk->u1.Function; ++original, ++thunk)
                {
                    if (IMAGE_SNAP_BY_ORDINAL64(original->u1.Ordinal)) continue;
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + original->u1.AddressOfData);
                    PatchFunction(reinterpret_cast<void**>(&thunk->u1.Function), importedDll, reinterpret_cast<const char*>(ibn->Name), moduleName);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    void PatchGameModules()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snap == INVALID_HANDLE_VALUE) return;
        MODULEENTRY32W e{}; e.dwSize = sizeof(e);
        if (Module32FirstW(snap, &e))
        {
            do
            {
                if (!StartsWithI(e.szExePath, g_gameDir)) continue;
                char name[512]{}; WideCharToMultiByte(CP_UTF8, 0, e.szModule, -1, name, static_cast<int>(CountOf(name)), nullptr, nullptr);
                PatchModule(e.hModule, name);
            } while (Module32NextW(snap, &e));
        }
        CloseHandle(snap);
    }
}

namespace mw2019_network
{
    void SetCustomServer(const char* host) noexcept
    {
        if (!host || !*host) host = "127.0.0.1";
        AcquireSRWLockExclusive(&g_customHostLock);
        strncpy_s(g_customHost, host, _TRUNCATE);
        g_customV4Count = 0;
        g_customV6Count = 0;
        in_addr v4{};
        if (InetPtonA(AF_INET, g_customHost, &v4) == 1)
            g_customV4[g_customV4Count++] = v4.S_un.S_addr;
        IN6_ADDR v6{};
        if (InetPtonA(AF_INET6, g_customHost, &v6) == 1)
            g_customV6[g_customV6Count++] = v6;
        ReleaseSRWLockExclusive(&g_customHostLock);
    }

    void GetCustomServer(char* out, std::size_t outCount) noexcept
    {
        if (!out || !outCount) return;
        AcquireSRWLockShared(&g_customHostLock);
        strncpy_s(out, outCount, g_customHost, _TRUNCATE);
        ReleaseSRWLockShared(&g_customHostLock);
    }

    void Initialize() noexcept
    {
        wchar_t exe[32768]{};
        GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(CountOf(exe)));
        wcsncpy_s(g_gameDir, exe, _TRUNCATE);
        if (wchar_t* slash = wcsrchr(g_gameDir, L'\\')) *slash = 0;

        SetCustomServer("127.0.0.1");
        InterlockedExchange(&g_enabled, 1);
        PatchGameModules();
        g_lastPatch = GetTickCount64();
    }

    void Tick(unsigned long long uptimeMs) noexcept
    {
        if (!Enabled()) return;
        if (uptimeMs - g_lastPatch < 2000) return;
        g_lastPatch = uptimeMs;
        PatchGameModules();
    }

    bool IsEnabled() noexcept
    {
        return Enabled();
    }
}
