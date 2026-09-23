#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#pragma comment(linker, "/export:GetFileVersionInfoA=Proxy_GetFileVersionInfoA,@1")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=Proxy_GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/export:GetFileVersionInfoExA=Proxy_GetFileVersionInfoExA,@3")
#pragma comment(linker, "/export:GetFileVersionInfoExW=Proxy_GetFileVersionInfoExW,@4")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=Proxy_GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=Proxy_GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=Proxy_GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=Proxy_GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/export:GetFileVersionInfoW=Proxy_GetFileVersionInfoW,@9")
#pragma comment(linker, "/export:VerFindFileA=Proxy_VerFindFileA,@10")
#pragma comment(linker, "/export:VerFindFileW=Proxy_VerFindFileW,@11")
#pragma comment(linker, "/export:VerInstallFileA=Proxy_VerInstallFileA,@12")
#pragma comment(linker, "/export:VerInstallFileW=Proxy_VerInstallFileW,@13")
#pragma comment(linker, "/export:VerLanguageNameA=Proxy_VerLanguageNameA,@14")
#pragma comment(linker, "/export:VerLanguageNameW=Proxy_VerLanguageNameW,@15")
#pragma comment(linker, "/export:VerQueryValueA=Proxy_VerQueryValueA,@16")
#pragma comment(linker, "/export:VerQueryValueW=Proxy_VerQueryValueW,@17")

namespace
{
    INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
    HMODULE g_realVersion = nullptr;

    BOOL CALLBACK LoadVersion(PINIT_ONCE, PVOID, PVOID*) noexcept
    {
        wchar_t systemDir[MAX_PATH]{};
        const UINT length = GetSystemDirectoryW(systemDir, MAX_PATH);
        if (!length || length >= MAX_PATH)
            return TRUE;
        wchar_t path[MAX_PATH]{};
        lstrcpyW(path, systemDir);
        lstrcatW(path, L"\\version.dll");
        g_realVersion = LoadLibraryW(path);
        return TRUE;
    }

    HMODULE RealVersion() noexcept
    {
        InitOnceExecuteOnce(&g_once, LoadVersion, nullptr, nullptr);
        return g_realVersion;
    }

    template <typename T>
    T Resolve(const char* name) noexcept
    {
        HMODULE module = RealVersion();
        return module ? reinterpret_cast<T>(GetProcAddress(module, name)) : nullptr;
    }
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR a,DWORD b,DWORD c,LPVOID d){using F=BOOL(WINAPI*)(LPCSTR,DWORD,DWORD,LPVOID);auto f=Resolve<F>("GetFileVersionInfoA");return f?f(a,b,c,d):FALSE;}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoByHandle(DWORD a,HANDLE b,LPVOID c){using F=DWORD(WINAPI*)(DWORD,HANDLE,LPVOID);auto f=Resolve<F>("GetFileVersionInfoByHandle");return f?f(a,b,c):0;}
extern "C" BOOL WINAPI Proxy_GetFileVersionInfoExA(DWORD a,LPCSTR b,DWORD c,DWORD d,LPVOID e){using F=BOOL(WINAPI*)(DWORD,LPCSTR,DWORD,DWORD,LPVOID);auto f=Resolve<F>("GetFileVersionInfoExA");return f?f(a,b,c,d,e):FALSE;}
extern "C" BOOL WINAPI Proxy_GetFileVersionInfoExW(DWORD a,LPCWSTR b,DWORD c,DWORD d,LPVOID e){using F=BOOL(WINAPI*)(DWORD,LPCWSTR,DWORD,DWORD,LPVOID);auto f=Resolve<F>("GetFileVersionInfoExW");return f?f(a,b,c,d,e):FALSE;}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR a,LPDWORD b){using F=DWORD(WINAPI*)(LPCSTR,LPDWORD);auto f=Resolve<F>("GetFileVersionInfoSizeA");return f?f(a,b):0;}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(DWORD a,LPCSTR b,LPDWORD c){using F=DWORD(WINAPI*)(DWORD,LPCSTR,LPDWORD);auto f=Resolve<F>("GetFileVersionInfoSizeExA");return f?f(a,b,c):0;}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(DWORD a,LPCWSTR b,LPDWORD c){using F=DWORD(WINAPI*)(DWORD,LPCWSTR,LPDWORD);auto f=Resolve<F>("GetFileVersionInfoSizeExW");return f?f(a,b,c):0;}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR a,LPDWORD b){using F=DWORD(WINAPI*)(LPCWSTR,LPDWORD);auto f=Resolve<F>("GetFileVersionInfoSizeW");return f?f(a,b):0;}
extern "C" BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR a,DWORD b,DWORD c,LPVOID d){using F=BOOL(WINAPI*)(LPCWSTR,DWORD,DWORD,LPVOID);auto f=Resolve<F>("GetFileVersionInfoW");return f?f(a,b,c,d):FALSE;}
extern "C" DWORD WINAPI Proxy_VerFindFileA(DWORD a,LPCSTR b,LPCSTR c,LPCSTR d,LPSTR e,PUINT f,LPSTR g,PUINT h){using F=DWORD(WINAPI*)(DWORD,LPCSTR,LPCSTR,LPCSTR,LPSTR,PUINT,LPSTR,PUINT);auto x=Resolve<F>("VerFindFileA");return x?x(a,b,c,d,e,f,g,h):0;}
extern "C" DWORD WINAPI Proxy_VerFindFileW(DWORD a,LPCWSTR b,LPCWSTR c,LPCWSTR d,LPWSTR e,PUINT f,LPWSTR g,PUINT h){using F=DWORD(WINAPI*)(DWORD,LPCWSTR,LPCWSTR,LPCWSTR,LPWSTR,PUINT,LPWSTR,PUINT);auto x=Resolve<F>("VerFindFileW");return x?x(a,b,c,d,e,f,g,h):0;}
extern "C" DWORD WINAPI Proxy_VerInstallFileA(DWORD a,LPCSTR b,LPCSTR c,LPCSTR d,LPCSTR e,LPCSTR f,LPSTR g,PUINT h){using F=DWORD(WINAPI*)(DWORD,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPSTR,PUINT);auto x=Resolve<F>("VerInstallFileA");return x?x(a,b,c,d,e,f,g,h):0;}
extern "C" DWORD WINAPI Proxy_VerInstallFileW(DWORD a,LPCWSTR b,LPCWSTR c,LPCWSTR d,LPCWSTR e,LPCWSTR f,LPWSTR g,PUINT h){using F=DWORD(WINAPI*)(DWORD,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPWSTR,PUINT);auto x=Resolve<F>("VerInstallFileW");return x?x(a,b,c,d,e,f,g,h):0;}
extern "C" DWORD WINAPI Proxy_VerLanguageNameA(DWORD a,LPSTR b,DWORD c){using F=DWORD(WINAPI*)(DWORD,LPSTR,DWORD);auto f=Resolve<F>("VerLanguageNameA");return f?f(a,b,c):0;}
extern "C" DWORD WINAPI Proxy_VerLanguageNameW(DWORD a,LPWSTR b,DWORD c){using F=DWORD(WINAPI*)(DWORD,LPWSTR,DWORD);auto f=Resolve<F>("VerLanguageNameW");return f?f(a,b,c):0;}
extern "C" BOOL WINAPI Proxy_VerQueryValueA(LPCVOID a,LPCSTR b,LPVOID* c,PUINT d){using F=BOOL(WINAPI*)(LPCVOID,LPCSTR,LPVOID*,PUINT);auto f=Resolve<F>("VerQueryValueA");return f?f(a,b,c,d):FALSE;}
extern "C" BOOL WINAPI Proxy_VerQueryValueW(LPCVOID a,LPCWSTR b,LPVOID* c,PUINT d){using F=BOOL(WINAPI*)(LPCVOID,LPCWSTR,LPVOID*,PUINT);auto f=Resolve<F>("VerQueryValueW");return f?f(a,b,c,d):FALSE;}
