#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#pragma comment(linker, "/export:CreateDXGIFactory=Proxy_CreateDXGIFactory,@1")
#pragma comment(linker, "/export:CreateDXGIFactory1=Proxy_CreateDXGIFactory1,@2")
#pragma comment(linker, "/export:CreateDXGIFactory2=Proxy_CreateDXGIFactory2,@3")
#pragma comment(linker, "/export:DXGIDeclareAdapterRemovalSupport=Proxy_DXGIDeclareAdapterRemovalSupport,@4")
#pragma comment(linker, "/export:DXGIGetDebugInterface1=Proxy_DXGIGetDebugInterface1,@5")

namespace
{
    HMODULE g_self = nullptr;
    HMODULE g_realDxgi = nullptr;
    HMODULE g_version = nullptr;
    INIT_ONCE g_dxgiOnce = INIT_ONCE_STATIC_INIT;
    volatile LONG g_versionState = 0; // 0=not started, 1=loading, 2=loaded

    bool AppendName(wchar_t* path, DWORD capacity, const wchar_t* name) noexcept
    {
        if (!path || !capacity || !name)
            return false;

        DWORD length = static_cast<DWORD>(lstrlenW(path));
        const DWORD add = static_cast<DWORD>(lstrlenW(name));
        if (length + add + 1 > capacity)
            return false;

        lstrcatW(path, name);
        return true;
    }

    bool GetOwnDirectory(wchar_t* path, DWORD capacity) noexcept
    {
        if (!g_self || !path || capacity < 2)
            return false;

        const DWORD length = GetModuleFileNameW(g_self, path, capacity);
        if (!length || length >= capacity)
            return false;

        for (DWORD i = length; i > 0; --i)
        {
            const wchar_t ch = path[i - 1];
            if (ch == L'\\' || ch == L'/')
            {
                path[i] = L'\0';
                return true;
            }
        }

        return false;
    }

    void LoadLocalVersion() noexcept
    {
        if (InterlockedCompareExchange(&g_versionState, 1, 0) != 0)
            return;

        wchar_t path[MAX_PATH]{};
        if (GetOwnDirectory(path, MAX_PATH) && AppendName(path, MAX_PATH, L"version.dll"))
            g_version = LoadLibraryW(path);

        if (g_version)
            InterlockedExchange(&g_versionState, 2);
        else
            InterlockedExchange(&g_versionState, 0); // allow a later retry
    }

    DWORD WINAPI BootstrapThread(LPVOID) noexcept
    {
        LoadLocalVersion();
        return 0;
    }

    BOOL CALLBACK LoadRealDxgi(PINIT_ONCE, PVOID, PVOID*) noexcept
    {
        wchar_t path[MAX_PATH]{};
        const UINT length = GetSystemDirectoryW(path, MAX_PATH);
        if (!length || length >= MAX_PATH)
            return TRUE;

        if (!AppendName(path, MAX_PATH, L"\\dxgi.dll"))
            return TRUE;

        g_realDxgi = LoadLibraryW(path);
        return TRUE;
    }

    HMODULE RealDxgi() noexcept
    {
        InitOnceExecuteOnce(&g_dxgiOnce, LoadRealDxgi, nullptr, nullptr);
        return g_realDxgi;
    }

    template <typename T>
    T ResolveReal(const char* name) noexcept
    {
        const HMODULE module = RealDxgi();
        return module ? reinterpret_cast<T>(GetProcAddress(module, name)) : nullptr;
    }
}

extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory(REFIID riid, void** factory)
{
    using Fn = HRESULT(WINAPI*)(REFIID, void**);
    const auto real = ResolveReal<Fn>("CreateDXGIFactory");
    LoadLocalVersion();
    return real ? real(riid, factory) : E_FAIL;
}

extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory1(REFIID riid, void** factory)
{
    using Fn = HRESULT(WINAPI*)(REFIID, void**);
    const auto real = ResolveReal<Fn>("CreateDXGIFactory1");
    LoadLocalVersion();
    return real ? real(riid, factory) : E_FAIL;
}

extern "C" HRESULT WINAPI Proxy_CreateDXGIFactory2(UINT flags, REFIID riid, void** factory)
{
    using Fn = HRESULT(WINAPI*)(UINT, REFIID, void**);
    const auto real = ResolveReal<Fn>("CreateDXGIFactory2");
    LoadLocalVersion();
    return real ? real(flags, riid, factory) : E_FAIL;
}

extern "C" HRESULT WINAPI Proxy_DXGIDeclareAdapterRemovalSupport()
{
    using Fn = HRESULT(WINAPI*)();
    const auto real = ResolveReal<Fn>("DXGIDeclareAdapterRemovalSupport");
    LoadLocalVersion();
    return real ? real() : E_FAIL;
}

extern "C" HRESULT WINAPI Proxy_DXGIGetDebugInterface1(UINT flags, REFIID riid, void** debug)
{
    using Fn = HRESULT(WINAPI*)(UINT, REFIID, void**);
    const auto real = ResolveReal<Fn>("DXGIGetDebugInterface1");
    LoadLocalVersion();
    return real ? real(flags, riid, debug) : E_FAIL;
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = module;
        DisableThreadLibraryCalls(module);

        // Keep the proxy minimal and avoid doing LoadLibrary work under loader lock.
        // The worker loads the real Revamped version.dll immediately after attach.
        if (HANDLE thread = CreateThread(nullptr, 0, BootstrapThread, nullptr, 0, nullptr))
            CloseHandle(thread);
    }

    return TRUE;
}
