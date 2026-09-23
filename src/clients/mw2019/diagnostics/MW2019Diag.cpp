#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <Windows.h>
#include <WinHttp.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <Security.h>
#include <wincrypt.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include <utility>

#include "MW2019Shared.hpp"
#include "MW2019MemoryScanner.hpp"
#include "MW2019NetworkBlocker.hpp"
#include "../game/IW8144Compat.h"
#include "../../../shared/common/utils/MinHook.hpp"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Winhttp.lib")

// Dedicated MW2019 1.44 VERSION proxy/profile entry.
// This project is link-time isolated from 1.28 and 1.69 game runtimes.

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

    template <typename T, size_t N>
    constexpr size_t ArrayCount(const T (&)[N]) noexcept
    {
        return N;
    }
    HMODULE g_self = nullptr;
    HMODULE g_realVersion = nullptr;
    INIT_ONCE g_realVersionOnce = INIT_ONCE_STATIC_INIT;
    HANDLE g_consoleOut = INVALID_HANDLE_VALUE;
    wchar_t g_logPath[32768]{};
    volatile LONG g_logPathState = 0; // 0=not ready, 1=building, 2=ready
    volatile LONG g_warzoneBeta2019Profile = 0;

    constexpr std::uint32_t kWarzoneBeta2019Timestamp = 0x5D84138Cu;
    constexpr std::uint32_t kWarzoneBeta2019ImageSize = 0x16801800u;
    constexpr std::uint32_t kWarzoneBeta2019EntryPoint = 0x02752D50u;


    using BetaCreateFileWFn = HANDLE (WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using BetaCreateFileAFn = HANDLE (WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

    BetaCreateFileWFn g_betaCreateFileWOriginal = nullptr;
    BetaCreateFileAFn g_betaCreateFileAOriginal = nullptr;
    volatile LONG g_betaFileHooksInstalled = 0;
    volatile LONG g_betaFailedAssetOpenCount = 0;
    volatile LONG g_betaRemappedAssetOpenCount = 0;
    volatile LONG g_beta6036BranchPatched = 0;
    volatile LONG g_betaRecursiveFallbackLogged = 0;

    constexpr std::uintptr_t kWarzoneBetaDevErrorFormatRva = 0x029387F8u; // "DEV ERROR %u"
    constexpr std::uintptr_t kWarzoneBeta6036FatalBranchRva = 0x005E28ECu;
    constexpr std::uintptr_t kWarzoneBeta6036PrecheckCallTargetRva = 0x001F9100u;

    HANDLE WINAPI BetaCreateFileWDetour(
        LPCWSTR fileName,
        DWORD desiredAccess,
        DWORD shareMode,
        LPSECURITY_ATTRIBUTES securityAttributes,
        DWORD creationDisposition,
        DWORD flagsAndAttributes,
        HANDLE templateFile) noexcept;

    HANDLE WINAPI BetaCreateFileADetour(
        LPCSTR fileName,
        DWORD desiredAccess,
        DWORD shareMode,
        LPSECURITY_ATTRIBUTES securityAttributes,
        DWORD creationDisposition,
        DWORD flagsAndAttributes,
        HANDLE templateFile) noexcept;

    bool ReadMainImageFingerprint(
        HMODULE module,
        std::uint32_t& timestamp,
        std::uint32_t& imageSize,
        std::uint32_t& entryPoint,
        std::uint64_t& preferredBase) noexcept
    {
        timestamp = 0;
        imageSize = 0;
        entryPoint = 0;
        preferredBase = 0;

        const auto base = reinterpret_cast<std::uintptr_t>(
            module ? module : GetModuleHandleW(nullptr));
        if (!base)
            return false;

        __try
        {
            const auto* dos =
                reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
                dos->e_lfanew <= 0)
            {
                return false;
            }

            const auto* nt =
                reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                    base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                return false;
            }

            timestamp = nt->FileHeader.TimeDateStamp;
            imageSize = nt->OptionalHeader.SizeOfImage;
            entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
            preferredBase = nt->OptionalHeader.ImageBase;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool IsExactWarzoneBeta2019(HMODULE module) noexcept
    {
        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;
        std::uint64_t preferredBase = 0;
        if (!ReadMainImageFingerprint(
                module,
                timestamp,
                imageSize,
                entryPoint,
                preferredBase))
        {
            return false;
        }

        return timestamp == kWarzoneBeta2019Timestamp &&
               imageSize == kWarzoneBeta2019ImageSize &&
               entryPoint == kWarzoneBeta2019EntryPoint;
    }

    bool BuildLogPath() noexcept
    {
        const LONG previous = InterlockedCompareExchange(&g_logPathState, 1, 0);
        if (previous == 2)
            return true;

        if (previous == 1)
        {
            for (unsigned i = 0; i < 200 && InterlockedCompareExchange(&g_logPathState, 0, 0) == 1; ++i)
                Sleep(0);
            return InterlockedCompareExchange(&g_logPathState, 0, 0) == 2;
        }

        wchar_t exePath[32768]{};
        const DWORD length = GetModuleFileNameW(nullptr, exePath, static_cast<DWORD>(ArrayCount(exePath)));
        if (!length || length >= ArrayCount(exePath))
        {
            InterlockedExchange(&g_logPathState, 0);
            return false;
        }

        wchar_t gameDir[32768]{};
        wcsncpy_s(gameDir, exePath, _TRUNCATE);
        if (wchar_t* slash = wcsrchr(gameDir, L'\\'))
            *slash = L'\0';

        wchar_t revampedDir[32768]{};
        wchar_t profileDir[32768]{};
        _snwprintf_s(
            revampedDir,
            ArrayCount(revampedDir),
            _TRUNCATE,
            L"%s\\CodRevamped",
            gameDir);

        const bool warzoneBeta =
            InterlockedCompareExchange(
                &g_warzoneBeta2019Profile,
                0,
                0) != 0;

        if (warzoneBeta)
        {
            _snwprintf_s(
                profileDir,
                ArrayCount(profileDir),
                _TRUNCATE,
                L"%s\\IW8Beta",
                revampedDir);
            _snwprintf_s(
                g_logPath,
                ArrayCount(g_logPath),
                _TRUNCATE,
                L"%s\\warzone_beta_loader.log",
                profileDir);
        }
        else
        {
            _snwprintf_s(
                profileDir,
                ArrayCount(profileDir),
                _TRUNCATE,
                L"%s\\MW2019",
                revampedDir);
            _snwprintf_s(
                g_logPath,
                ArrayCount(g_logPath),
                _TRUNCATE,
                L"%s\\mw2019_loader.log",
                profileDir);
        }

        CreateDirectoryW(revampedDir, nullptr);
        CreateDirectoryW(profileDir, nullptr);
        InterlockedExchange(&g_logPathState, 2);
        return true;
    }

    void AppendRaw(const char* text) noexcept
    {
        if (!text || !*text || !BuildLogPath())
            return;

        const DWORD bytes = static_cast<DWORD>(lstrlenA(text));
        DWORD written = 0;

        HANDLE file = CreateFileW(
            g_logPath,
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file != INVALID_HANDLE_VALUE)
        {
            WriteFile(file, text, bytes, &written, nullptr);
            FlushFileBuffers(file);
            CloseHandle(file);
        }

        if (g_consoleOut != INVALID_HANDLE_VALUE)
            WriteFile(g_consoleOut, text, bytes, &written, nullptr);
    }

    void InternalLog(const char* format, ...) noexcept
    {
        char buffer[4096]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        va_end(args);
        AppendRaw(buffer);
    }

    void WideToUtf8(const wchar_t* input, char* output, int outputCount) noexcept
    {
        if (!output || outputCount <= 0)
            return;
        output[0] = '\0';
        if (!input)
            return;
        WideCharToMultiByte(CP_UTF8, 0, input, -1, output, outputCount, nullptr, nullptr);
    }

    void LogMainImageFingerprint() noexcept
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
        {
            InternalLog("[PE] main module unavailable\r\n");
            return;
        }

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                InternalLog("[PE] invalid DOS signature\r\n");
                return;
            }

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                InternalLog("[PE] invalid NT signature\r\n");
                return;
            }

            InternalLog("[PE] base=%p timestamp=0x%08lX imageSize=0x%08lX entryPointRva=0x%08lX preferredBase=0x%llX\r\n",
                reinterpret_cast<void*>(base),
                nt->FileHeader.TimeDateStamp,
                nt->OptionalHeader.SizeOfImage,
                nt->OptionalHeader.AddressOfEntryPoint,
                static_cast<unsigned long long>(nt->OptionalHeader.ImageBase));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            InternalLog("[PE] exception while reading main image headers code=0x%08lX\r\n", GetExceptionCode());
        }
    }

    bool SeenModule(const std::uintptr_t* seen, unsigned count, std::uintptr_t base) noexcept
    {
        for (unsigned i = 0; i < count; ++i)
        {
            if (seen[i] == base)
                return true;
        }
        return false;
    }

    void LogNewModules(std::uintptr_t* seen, unsigned& seenCount, unsigned capacity) noexcept
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE)
            return;

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot, &entry))
        {
            do
            {
                const auto base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                if (!SeenModule(seen, seenCount, base))
                {
                    if (seenCount < capacity)
                        seen[seenCount++] = base;

                    char name[512]{};
                    char path[2048]{};
                    WideToUtf8(entry.szModule, name, static_cast<int>(ArrayCount(name)));
                    WideToUtf8(entry.szExePath, path, static_cast<int>(ArrayCount(path)));
                    InternalLog("[MODULE+] base=%p size=0x%08lX name=%s path=%s\r\n",
                        entry.modBaseAddr,
                        entry.modBaseSize,
                        name,
                        path);
                }
            } while (Module32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    void OpenProfileConsole(const wchar_t* title) noexcept
    {
        if (!GetConsoleWindow())
            AllocConsole();

        if (!GetConsoleWindow())
            return;

        if (title && *title)
            SetConsoleTitleW(title);

        HANDLE output = CreateFileW(
            L"CONOUT$",
            GENERIC_WRITE | GENERIC_READ,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);

        if (output == INVALID_HANDLE_VALUE)
            output = GetStdHandle(STD_OUTPUT_HANDLE);

        if (g_consoleOut != INVALID_HANDLE_VALUE &&
            g_consoleOut != output)
        {
            CloseHandle(g_consoleOut);
        }

        g_consoleOut = output;

        FILE* stream = nullptr;
        freopen_s(&stream, "CONOUT$", "w", stdout);
        freopen_s(&stream, "CONOUT$", "w", stderr);
        freopen_s(&stream, "CONIN$", "r", stdin);
    }

    struct BetaWindowSnapshot
    {
        DWORD processId = 0;
        unsigned count = 0;
    };

    BOOL CALLBACK EnumWarzoneBetaWindows(
        HWND hwnd,
        LPARAM param) noexcept
    {
        auto* snapshot =
            reinterpret_cast<BetaWindowSnapshot*>(param);
        if (!snapshot)
            return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != snapshot->processId || !IsWindowVisible(hwnd))
            return TRUE;

        wchar_t title[512]{};
        wchar_t className[256]{};
        GetWindowTextW(
            hwnd,
            title,
            static_cast<int>(ArrayCount(title)));
        GetClassNameW(
            hwnd,
            className,
            static_cast<int>(ArrayCount(className)));

        char titleUtf8[2048]{};
        char classUtf8[1024]{};
        WideToUtf8(
            title,
            titleUtf8,
            static_cast<int>(ArrayCount(titleUtf8)));
        WideToUtf8(
            className,
            classUtf8,
            static_cast<int>(ArrayCount(classUtf8)));

        InternalLog(
            "[IW8-BETA][WINDOW] hwnd=%p class=%s title=%s\r\n",
            hwnd,
            classUtf8[0] ? classUtf8 : "<none>",
            titleUtf8[0] ? titleUtf8 : "<none>");
        ++snapshot->count;
        return TRUE;
    }


    bool IsBetaAssetPathW(const wchar_t* path) noexcept
    {
        if (!path || !*path)
            return false;

        const wchar_t* dot = wcsrchr(path, L'.');
        if (!dot)
            return false;

        return _wcsicmp(dot, L".ff") == 0 ||
               _wcsicmp(dot, L".xpak") == 0 ||
               _wcsicmp(dot, L".xsub") == 0 ||
               _wcsicmp(dot, L".pak") == 0 ||
               _wcsicmp(dot, L".idx") == 0 ||
               _wcsicmp(dot, L".toc") == 0 ||
               _wcsicmp(dot, L".fd") == 0;
    }

    const wchar_t* BaseNameW(const wchar_t* path) noexcept
    {
        if (!path)
            return nullptr;
        const wchar_t* slashA = wcsrchr(path, L'\\');
        const wchar_t* slashB = wcsrchr(path, L'/');
        const wchar_t* slash = slashA;
        if (!slash || (slashB && slashB > slash))
            slash = slashB;
        return slash ? slash + 1 : path;
    }

    bool GetWarzoneBetaGameDir(wchar_t* out, size_t outCount) noexcept
    {
        if (!out || outCount == 0)
            return false;
        out[0] = L'\0';
        if (!GetModuleFileNameW(nullptr, out, static_cast<DWORD>(outCount)))
            return false;
        if (wchar_t* slash = wcsrchr(out, L'\\'))
            *slash = L'\0';
        return out[0] != L'\0';
    }

    bool IsExistingRegularFileW(const wchar_t* path) noexcept
    {
        if (!path || !*path)
            return false;
        const DWORD attr = GetFileAttributesW(path);
        return attr != INVALID_FILE_ATTRIBUTES &&
               (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    bool ShouldSkipBetaRecursiveDir(const wchar_t* name) noexcept
    {
        if (!name || !*name)
            return true;
        return _wcsicmp(name, L".") == 0 ||
               _wcsicmp(name, L"..") == 0 ||
               _wcsicmp(name, L"CodRevamped") == 0 ||
               _wcsicmp(name, L"battle.net") == 0 ||
               _wcsicmp(name, L"BlizzardBrowser") == 0 ||
               _wcsicmp(name, L"Data") == 0;
    }

    bool FindBetaAssetFallbackRecursive(
        const wchar_t* directory,
        const wchar_t* baseName,
        unsigned depth,
        unsigned& visitedDirectories,
        wchar_t* out,
        size_t outCount) noexcept
    {
        if (!directory || !*directory || !baseName || !*baseName ||
            !out || outCount == 0 || depth > 5 || visitedDirectories >= 2048)
        {
            return false;
        }

        ++visitedDirectories;

        wchar_t direct[32768]{};
        _snwprintf_s(
            direct,
            ArrayCount(direct),
            _TRUNCATE,
            L"%s\\%s",
            directory,
            baseName);
        if (IsExistingRegularFileW(direct))
        {
            wcsncpy_s(out, outCount, direct, _TRUNCATE);
            return true;
        }

        if (depth == 5)
            return false;

        wchar_t wildcard[32768]{};
        _snwprintf_s(
            wildcard,
            ArrayCount(wildcard),
            _TRUNCATE,
            L"%s\\*",
            directory);

        WIN32_FIND_DATAW findData{};
        HANDLE find = FindFirstFileW(wildcard, &findData);
        if (find == INVALID_HANDLE_VALUE)
            return false;

        bool found = false;
        do
        {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                ShouldSkipBetaRecursiveDir(findData.cFileName))
            {
                continue;
            }

            wchar_t child[32768]{};
            _snwprintf_s(
                child,
                ArrayCount(child),
                _TRUNCATE,
                L"%s\\%s",
                directory,
                findData.cFileName);

            if (FindBetaAssetFallbackRecursive(
                    child,
                    baseName,
                    depth + 1,
                    visitedDirectories,
                    out,
                    outCount))
            {
                found = true;
                break;
            }
        } while (FindNextFileW(find, &findData) && visitedDirectories < 2048);

        FindClose(find);
        return found;
    }

    void LogBetaRecursiveFastfileTree(
        const wchar_t* directory,
        unsigned depth,
        unsigned& visitedDirectories,
        unsigned& fastfileCount,
        unsigned& loggedFastfiles) noexcept
    {
        if (!directory || !*directory || depth > 4 || visitedDirectories >= 4096)
            return;

        ++visitedDirectories;

        wchar_t wildcard[32768]{};
        _snwprintf_s(
            wildcard,
            ArrayCount(wildcard),
            _TRUNCATE,
            L"%s\\*",
            directory);

        WIN32_FIND_DATAW findData{};
        HANDLE find = FindFirstFileW(wildcard, &findData);
        if (find == INVALID_HANDLE_VALUE)
            return;

        do
        {
            if (wcscmp(findData.cFileName, L".") == 0 ||
                wcscmp(findData.cFileName, L"..") == 0)
            {
                continue;
            }

            wchar_t fullPath[32768]{};
            _snwprintf_s(
                fullPath,
                ArrayCount(fullPath),
                _TRUNCATE,
                L"%s\\%s",
                directory,
                findData.cFileName);

            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                    !ShouldSkipBetaRecursiveDir(findData.cFileName))
                {
                    LogBetaRecursiveFastfileTree(
                        fullPath,
                        depth + 1,
                        visitedDirectories,
                        fastfileCount,
                        loggedFastfiles);
                }
                continue;
            }

            const wchar_t* extension = wcsrchr(findData.cFileName, L'.');
            if (!extension || _wcsicmp(extension, L".ff") != 0)
                continue;

            ++fastfileCount;
            if (loggedFastfiles < 64)
            {
                char pathUtf8[32768]{};
                WideToUtf8(fullPath, pathUtf8, static_cast<int>(ArrayCount(pathUtf8)));
                InternalLog(
                    "[IW8-BETA][6036][FF-RECURSE] file=%s size=%llu\r\n",
                    pathUtf8,
                    (static_cast<unsigned long long>(findData.nFileSizeHigh) << 32) |
                        findData.nFileSizeLow);
                ++loggedFastfiles;
            }
        } while (FindNextFileW(find, &findData) && visitedDirectories < 4096);

        FindClose(find);
    }

    void LogBetaRecursiveFastfileInventory() noexcept
    {
        wchar_t gameDir[32768]{};
        if (!GetWarzoneBetaGameDir(gameDir, ArrayCount(gameDir)))
            return;

        unsigned visitedDirectories = 0;
        unsigned fastfileCount = 0;
        unsigned loggedFastfiles = 0;
        LogBetaRecursiveFastfileTree(
            gameDir,
            0,
            visitedDirectories,
            fastfileCount,
            loggedFastfiles);

        InternalLog(
            "[IW8-BETA][6036][FF-RECURSE] complete dirs=%u total_ff=%u logged=%u\r\n",
            visitedDirectories,
            fastfileCount,
            loggedFastfiles);
    }

    bool FindBetaAssetFallback(
        const wchar_t* requested,
        wchar_t* out,
        size_t outCount) noexcept
    {
        if (!requested || !out || outCount == 0)
            return false;
        out[0] = L'\0';

        const wchar_t* baseName = BaseNameW(requested);
        if (!baseName || !*baseName || !IsBetaAssetPathW(baseName))
            return false;

        wchar_t gameDir[32768]{};
        if (!GetWarzoneBetaGameDir(gameDir, ArrayCount(gameDir)))
            return false;

        static const wchar_t* const subdirs[] = {
            L"",
            L"main",
            L"zone",
            L"Data",
            L"Data\\data",
            L"patch",
            L"patch_cache",
            L"patch_result"
        };

        for (const wchar_t* subdir : subdirs)
        {
            wchar_t candidate[32768]{};
            if (subdir && *subdir)
            {
                _snwprintf_s(
                    candidate,
                    ArrayCount(candidate),
                    _TRUNCATE,
                    L"%s\\%s\\%s",
                    gameDir,
                    subdir,
                    baseName);
            }
            else
            {
                _snwprintf_s(
                    candidate,
                    ArrayCount(candidate),
                    _TRUNCATE,
                    L"%s\\%s",
                    gameDir,
                    baseName);
            }

            if (_wcsicmp(candidate, requested) != 0 &&
                IsExistingRegularFileW(candidate))
            {
                wcsncpy_s(out, outCount, candidate, _TRUNCATE);
                return true;
            }
        }

        // One shallow folder pass catches beta layouts such as language/zone
        // directories without recursively crawling the very large Data tree.
        wchar_t wildcard[32768]{};
        _snwprintf_s(
            wildcard,
            ArrayCount(wildcard),
            _TRUNCATE,
            L"%s\\*",
            gameDir);

        WIN32_FIND_DATAW findData{};
        HANDLE find = FindFirstFileW(wildcard, &findData);
        if (find != INVALID_HANDLE_VALUE)
        {
            do
            {
                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                    wcscmp(findData.cFileName, L".") == 0 ||
                    wcscmp(findData.cFileName, L"..") == 0)
                {
                    continue;
                }

                wchar_t candidate[32768]{};
                _snwprintf_s(
                    candidate,
                    ArrayCount(candidate),
                    _TRUNCATE,
                    L"%s\\%s\\%s",
                    gameDir,
                    findData.cFileName,
                    baseName);

                if (_wcsicmp(candidate, requested) != 0 &&
                    IsExistingRegularFileW(candidate))
                {
                    wcsncpy_s(out, outCount, candidate, _TRUNCATE);
                    FindClose(find);
                    return true;
                }
            } while (FindNextFileW(find, &findData));
            FindClose(find);
        }

        // The beta folder supplied for preservation may itself contain a nested
        // install root.  Do a bounded recursive search only after the cheap
        // direct/shallow probes fail.  Data/CASC is intentionally skipped.
        unsigned visitedDirectories = 0;
        if (FindBetaAssetFallbackRecursive(
                gameDir,
                baseName,
                0,
                visitedDirectories,
                out,
                outCount) &&
            _wcsicmp(out, requested) != 0)
        {
            if (InterlockedCompareExchange(&g_betaRecursiveFallbackLogged, 1, 0) == 0)
            {
                char requestedUtf8[32768]{};
                char foundUtf8[32768]{};
                WideToUtf8(requested, requestedUtf8, static_cast<int>(ArrayCount(requestedUtf8)));
                WideToUtf8(out, foundUtf8, static_cast<int>(ArrayCount(foundUtf8)));
                InternalLog(
                    "[IW8-BETA][6036][RECURSIVE-HIT] dirs=%u requested=%s found=%s\r\n",
                    visitedDirectories,
                    requestedUtf8,
                    foundUtf8);
            }
            return true;
        }

        return false;
    }

    bool PatchBetaIatImport(
        HMODULE module,
        const char* functionName,
        void* replacement,
        void** originalOut) noexcept
    {
        if (!module || !functionName || !replacement || !originalOut)
            return false;

        const auto base = reinterpret_cast<std::uintptr_t>(module);
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;

            const auto& importDir =
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!importDir.VirtualAddress || !importDir.Size)
                return false;

            auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                base + importDir.VirtualAddress);
            for (; descriptor->Name; ++descriptor)
            {
                auto* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                    base + descriptor->FirstThunk);
                auto* originalThunk = descriptor->OriginalFirstThunk
                    ? reinterpret_cast<IMAGE_THUNK_DATA64*>(
                        base + descriptor->OriginalFirstThunk)
                    : nullptr;

                for (size_t index = 0; firstThunk[index].u1.Function; ++index)
                {
                    bool nameMatch = false;
                    if (originalThunk &&
                        originalThunk[index].u1.AddressOfData &&
                        (originalThunk[index].u1.Ordinal & IMAGE_ORDINAL_FLAG64) == 0)
                    {
                        const auto* byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            base + originalThunk[index].u1.AddressOfData);
                        nameMatch = strcmp(
                            reinterpret_cast<const char*>(byName->Name),
                            functionName) == 0;
                    }

                    if (!nameMatch)
                        continue;

                    void** slot = reinterpret_cast<void**>(&firstThunk[index].u1.Function);
                    DWORD oldProtect = 0;
                    if (!VirtualProtect(
                            slot,
                            sizeof(void*),
                            PAGE_READWRITE,
                            &oldProtect))
                    {
                        return false;
                    }

                    *originalOut = *slot;
                    *slot = replacement;
                    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
                    DWORD ignored = 0;
                    VirtualProtect(slot, sizeof(void*), oldProtect, &ignored);
                    return *originalOut != nullptr;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        return false;
    }

    bool InstallWarzoneBetaFileHooks(HMODULE game) noexcept
    {
        if (InterlockedCompareExchange(&g_betaFileHooksInstalled, 0, 0) != 0)
            return true;

        // Seed callable originals before touching the game IAT so another game
        // thread cannot enter a freshly patched slot while our globals are null.
        if (HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll"))
        {
            g_betaCreateFileWOriginal = reinterpret_cast<BetaCreateFileWFn>(
                GetProcAddress(kernel32, "CreateFileW"));
            g_betaCreateFileAOriginal = reinterpret_cast<BetaCreateFileAFn>(
                GetProcAddress(kernel32, "CreateFileA"));
        }

        void* originalW = nullptr;
        void* originalA = nullptr;
        const bool hookW = PatchBetaIatImport(
            game,
            "CreateFileW",
            reinterpret_cast<void*>(&BetaCreateFileWDetour),
            &originalW);
        const bool hookA = PatchBetaIatImport(
            game,
            "CreateFileA",
            reinterpret_cast<void*>(&BetaCreateFileADetour),
            &originalA);

        if (hookW)
            g_betaCreateFileWOriginal = reinterpret_cast<BetaCreateFileWFn>(originalW);
        if (hookA)
            g_betaCreateFileAOriginal = reinterpret_cast<BetaCreateFileAFn>(originalA);

        if (hookW || hookA)
        {
            InterlockedExchange(&g_betaFileHooksInstalled, 1);
            InternalLog(
                "[IW8-BETA][6036] content open hooks installed CreateFileW=%s CreateFileA=%s\r\n",
                hookW ? "yes" : "no",
                hookA ? "yes" : "no");
            return true;
        }

        InternalLog(
            "[IW8-BETA][6036] content open hooks NOT installed; IAT imports were not resolved\r\n");
        return false;
    }

    HANDLE WINAPI BetaCreateFileWDetour(
        LPCWSTR fileName,
        DWORD desiredAccess,
        DWORD shareMode,
        LPSECURITY_ATTRIBUTES securityAttributes,
        DWORD creationDisposition,
        DWORD flagsAndAttributes,
        HANDLE templateFile) noexcept
    {
        const auto original = g_betaCreateFileWOriginal;
        if (!original)
            return INVALID_HANDLE_VALUE;

        HANDLE handle = original(
            fileName,
            desiredAccess,
            shareMode,
            securityAttributes,
            creationDisposition,
            flagsAndAttributes,
            templateFile);
        if (handle != INVALID_HANDLE_VALUE || !IsBetaAssetPathW(fileName))
            return handle;

        const DWORD originalError = GetLastError();
        const LONG failureNumber = InterlockedIncrement(&g_betaFailedAssetOpenCount);

        char requestedUtf8[32768]{};
        WideToUtf8(fileName, requestedUtf8, static_cast<int>(ArrayCount(requestedUtf8)));
        InternalLog(
            "[IW8-BETA][6036][OPEN-FAIL] #%ld winerr=%lu disposition=%lu access=0x%08lX path=%s\r\n",
            failureNumber,
            originalError,
            creationDisposition,
            desiredAccess,
            requestedUtf8[0] ? requestedUtf8 : "<null>");

        // Only redirect read-only OPEN_EXISTING asset requests. Never fabricate
        // a handle for genuinely absent content and never redirect writes.
        if (creationDisposition == OPEN_EXISTING &&
            (desiredAccess & GENERIC_WRITE) == 0)
        {
            wchar_t fallback[32768]{};
            if (FindBetaAssetFallback(fileName, fallback, ArrayCount(fallback)))
            {
                HANDLE retry = original(
                    fallback,
                    desiredAccess,
                    shareMode,
                    securityAttributes,
                    creationDisposition,
                    flagsAndAttributes,
                    templateFile);
                if (retry != INVALID_HANDLE_VALUE)
                {
                    const LONG remapNumber = InterlockedIncrement(&g_betaRemappedAssetOpenCount);
                    char fallbackUtf8[32768]{};
                    WideToUtf8(fallback, fallbackUtf8, static_cast<int>(ArrayCount(fallbackUtf8)));
                    InternalLog(
                        "[IW8-BETA][6036][REMAP] #%ld requested=%s -> %s\r\n",
                        remapNumber,
                        requestedUtf8,
                        fallbackUtf8);
                    return retry;
                }
            }
        }

        SetLastError(originalError);
        return INVALID_HANDLE_VALUE;
    }

    HANDLE WINAPI BetaCreateFileADetour(
        LPCSTR fileName,
        DWORD desiredAccess,
        DWORD shareMode,
        LPSECURITY_ATTRIBUTES securityAttributes,
        DWORD creationDisposition,
        DWORD flagsAndAttributes,
        HANDLE templateFile) noexcept
    {
        const auto original = g_betaCreateFileAOriginal;
        if (!original)
            return INVALID_HANDLE_VALUE;

        HANDLE handle = original(
            fileName,
            desiredAccess,
            shareMode,
            securityAttributes,
            creationDisposition,
            flagsAndAttributes,
            templateFile);
        if (handle != INVALID_HANDLE_VALUE || !fileName || !*fileName)
            return handle;

        wchar_t widePath[32768]{};
        const int converted = MultiByteToWideChar(
            CP_ACP,
            0,
            fileName,
            -1,
            widePath,
            static_cast<int>(ArrayCount(widePath)));
        if (converted <= 0 || !IsBetaAssetPathW(widePath))
            return handle;

        const DWORD originalError = GetLastError();
        const LONG failureNumber = InterlockedIncrement(&g_betaFailedAssetOpenCount);
        InternalLog(
            "[IW8-BETA][6036][OPEN-FAIL-A] #%ld winerr=%lu disposition=%lu access=0x%08lX path=%s\r\n",
            failureNumber,
            originalError,
            creationDisposition,
            desiredAccess,
            fileName);

        if (creationDisposition == OPEN_EXISTING &&
            (desiredAccess & GENERIC_WRITE) == 0)
        {
            wchar_t fallbackW[32768]{};
            if (FindBetaAssetFallback(widePath, fallbackW, ArrayCount(fallbackW)))
            {
                char fallbackA[32768]{};
                WideCharToMultiByte(
                    CP_ACP,
                    0,
                    fallbackW,
                    -1,
                    fallbackA,
                    static_cast<int>(ArrayCount(fallbackA)),
                    nullptr,
                    nullptr);
                HANDLE retry = original(
                    fallbackA,
                    desiredAccess,
                    shareMode,
                    securityAttributes,
                    creationDisposition,
                    flagsAndAttributes,
                    templateFile);
                if (retry != INVALID_HANDLE_VALUE)
                {
                    const LONG remapNumber = InterlockedIncrement(&g_betaRemappedAssetOpenCount);
                    InternalLog(
                        "[IW8-BETA][6036][REMAP-A] #%ld requested=%s -> %s\r\n",
                        remapNumber,
                        fileName,
                        fallbackA);
                    return retry;
                }
            }
        }

        SetLastError(originalError);
        return INVALID_HANDLE_VALUE;
    }

    bool TryPatchWarzoneBeta6036FatalBranch(HMODULE game) noexcept
    {
        if (!game)
            return false;
        if (InterlockedCompareExchange(&g_beta6036BranchPatched, 0, 0) != 0)
            return true;

        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(game);
        const std::uintptr_t branch = base + kWarzoneBeta6036FatalBranchRva;
        const std::uintptr_t formatString = base + kWarzoneBetaDevErrorFormatRva;
        const auto* code = reinterpret_cast<const unsigned char*>(branch);

        bool verified = false;
        __try
        {
            // Runtime-decrypted sequence:
            //   call <precheck>; test al,al; jne +50
            //   mov r8d,6036; lea rdx,"DEV ERROR %u"; ... fatal error call
            // We change only JNE -> JMP, preserving the stock success target.
            std::int32_t precheckRel = 0;
            std::int32_t formatRel = 0;
            memcpy(&precheckRel, code - 6, sizeof(precheckRel));
            memcpy(&formatRel, code + 11, sizeof(formatRel));
            const std::uintptr_t precheckTarget =
                branch - 2 + static_cast<std::intptr_t>(precheckRel);
            const std::uintptr_t formatTarget =
                branch + 15 + static_cast<std::intptr_t>(formatRel);

            verified =
                code[-7] == 0xE8 &&
                code[-2] == 0x84 && code[-1] == 0xC0 &&
                code[0] == 0x75 && code[1] == 0x50 &&
                code[2] == 0x41 && code[3] == 0xB8 &&
                code[4] == 0x94 && code[5] == 0x17 &&
                code[6] == 0x00 && code[7] == 0x00 &&
                code[8] == 0x48 && code[9] == 0x8D && code[10] == 0x15 &&
                precheckTarget == base + kWarzoneBeta6036PrecheckCallTargetRva &&
                formatTarget == formatString &&
                memcmp(
                    reinterpret_cast<const void*>(formatString),
                    "DEV ERROR %u",
                    sizeof("DEV ERROR %u") - 1) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            verified = false;
        }

        if (!verified)
            return false;

        DWORD oldProtect = 0;
        if (!VirtualProtect(
                reinterpret_cast<void*>(branch),
                1,
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            return false;
        }

        *reinterpret_cast<unsigned char*>(branch) = 0xEB; // JNE +50 -> JMP +50
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(branch), 1);
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(branch), 1, oldProtect, &ignored);

        InterlockedExchange(&g_beta6036BranchPatched, 1);
        InternalLog(
            "[IW8-BETA][6036][BYPASS] exact fatal branch patched rva=0x%llX old=75 new=EB precheck_target_rva=0x%llX success_skip=+0x50\r\n",
            static_cast<unsigned long long>(kWarzoneBeta6036FatalBranchRva),
            static_cast<unsigned long long>(kWarzoneBeta6036PrecheckCallTargetRva));
        InternalLog(
            "[IW8-BETA][6036][BYPASS] scope=beta-only; only the verified DEV ERROR 6036 branch is skipped; other errors remain stock\r\n");
        return true;
    }

    void LogBetaFastfileInventory() noexcept
    {
        wchar_t gameDir[32768]{};
        if (!GetWarzoneBetaGameDir(gameDir, ArrayCount(gameDir)))
            return;

        static const wchar_t* const dirs[] = {
            L"main",
            L"zone",
            L"Data",
            L"Data\\data"
        };

        for (const wchar_t* dir : dirs)
        {
            wchar_t wildcard[32768]{};
            _snwprintf_s(
                wildcard,
                ArrayCount(wildcard),
                _TRUNCATE,
                L"%s\\%s\\*.ff",
                gameDir,
                dir);

            WIN32_FIND_DATAW findData{};
            HANDLE find = FindFirstFileW(wildcard, &findData);
            unsigned count = 0;
            if (find != INVALID_HANDLE_VALUE)
            {
                do
                {
                    if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        ++count;
                        if (count <= 32)
                        {
                            char name[1024]{};
                            WideToUtf8(findData.cFileName, name, static_cast<int>(ArrayCount(name)));
                            InternalLog(
                                "[IW8-BETA][6036][FF] dir=%ls file=%s size=%llu\r\n",
                                dir,
                                name,
                                (static_cast<unsigned long long>(findData.nFileSizeHigh) << 32) |
                                    findData.nFileSizeLow);
                        }
                    }
                } while (FindNextFileW(find, &findData));
                FindClose(find);
            }
            InternalLog(
                "[IW8-BETA][6036][FF] dir=%ls total_ff=%u\r\n",
                dir,
                count);
        }
    }

    void LogBeta6036CandidateBytes(
        const char* kind,
        unsigned pass,
        std::uintptr_t address,
        std::uintptr_t imageBase) noexcept
    {
        if (!address || !imageBase)
            return;

        char hex[512]{};
        size_t out = 0;
        const std::uintptr_t start = address > imageBase + 16 ? address - 16 : imageBase;
        __try
        {
            for (size_t i = 0; i < 48 && out + 4 < ArrayCount(hex); ++i)
            {
                const unsigned value = *reinterpret_cast<const unsigned char*>(start + i);
                const int written = _snprintf_s(
                    hex + out,
                    ArrayCount(hex) - out,
                    _TRUNCATE,
                    "%02X%s",
                    value,
                    (i + 1 == 48) ? "" : " ");
                if (written <= 0)
                    break;
                out += static_cast<size_t>(written);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            strncpy_s(hex, "<unreadable>", _TRUNCATE);
        }

        InternalLog(
            "[IW8-BETA][6036][CODE] pass=%u kind=%s center=%p rva=0x%llX bytes=%s\r\n",
            pass,
            kind ? kind : "?",
            reinterpret_cast<void*>(address),
            static_cast<unsigned long long>(address - imageBase),
            hex);
    }

    void ScanBeta6036Runtime(HMODULE game, unsigned pass) noexcept
    {
        if (!game)
            return;

        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(game);
        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;
        std::uint64_t preferredBase = 0;
        if (!ReadMainImageFingerprint(game, timestamp, imageSize, entryPoint, preferredBase) || !imageSize)
            return;

        const std::uintptr_t devErrorString = base + kWarzoneBetaDevErrorFormatRva;
        bool stringVerified = false;
        __try
        {
            stringVerified = memcmp(
                reinterpret_cast<const void*>(devErrorString),
                "DEV ERROR %u",
                sizeof("DEV ERROR %u") - 1) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            stringVerified = false;
        }

        InternalLog(
            "[IW8-BETA][6036][SCAN] pass=%u devErrorFormat=%p verified=%s\r\n",
            pass,
            reinterpret_cast<void*>(devErrorString),
            stringVerified ? "yes" : "no");

        const std::uintptr_t imageEnd = base + imageSize;
        unsigned immediateHits = 0;
        unsigned formatXrefs = 0;
        MEMORY_BASIC_INFORMATION mbi{};
        for (std::uintptr_t p = base; p < imageEnd;)
        {
            if (!VirtualQuery(reinterpret_cast<void*>(p), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionStart + mbi.RegionSize;
            const bool executable =
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            const bool readable =
                mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;

            const std::uintptr_t scanStart = regionStart < base ? base : regionStart;
            const std::uintptr_t scanEnd = regionEnd > imageEnd ? imageEnd : regionEnd;
            if (readable && executable && scanEnd > scanStart)
            {
                __try
                {
                    const auto* bytes = reinterpret_cast<const unsigned char*>(scanStart);
                    const size_t size = static_cast<size_t>(scanEnd - scanStart);
                    for (size_t i = 0; i + 4 <= size; ++i)
                    {
                        std::uint32_t raw = 0;
                        memcpy(&raw, bytes + i, sizeof(raw));
                        const std::uintptr_t field = scanStart + i;

                        if (raw == 6036u && immediateHits < 64)
                        {
                            ++immediateHits;
                            InternalLog(
                                "[IW8-BETA][6036][IMM] pass=%u address=%p rva=0x%llX\r\n",
                                pass,
                                reinterpret_cast<void*>(field),
                                static_cast<unsigned long long>(field - base));
                            if (immediateHits <= 16)
                                LogBeta6036CandidateBytes("imm6036", pass, field, base);
                        }

                        const std::int32_t displacement = static_cast<std::int32_t>(raw);
                        if (stringVerified &&
                            field + 4 + static_cast<std::intptr_t>(displacement) == devErrorString &&
                            formatXrefs < 64)
                        {
                            ++formatXrefs;
                            InternalLog(
                                "[IW8-BETA][6036][FORMAT-XREF] pass=%u dispField=%p rva=0x%llX\r\n",
                                pass,
                                reinterpret_cast<void*>(field),
                                static_cast<unsigned long long>(field - base));
                            if (formatXrefs <= 16)
                                LogBeta6036CandidateBytes("dev_error_format_xref", pass, field, base);
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    InternalLog(
                        "[IW8-BETA][6036][SCAN] pass=%u unreadable_exec_region base=%p size=0x%llX\r\n",
                        pass,
                        reinterpret_cast<void*>(scanStart),
                        static_cast<unsigned long long>(scanEnd - scanStart));
                }
            }

            p = regionEnd > p ? regionEnd : p + 0x1000;
        }

        InternalLog(
            "[IW8-BETA][6036][SCAN] pass=%u complete immediate6036=%u format_xrefs=%u failed_asset_opens=%ld remaps=%ld\r\n",
            pass,
            immediateHits,
            formatXrefs,
            InterlockedCompareExchange(&g_betaFailedAssetOpenCount, 0, 0),
            InterlockedCompareExchange(&g_betaRemappedAssetOpenCount, 0, 0));
    }

    DWORD WINAPI WarzoneBeta2019Thread(LPVOID) noexcept
    {
        const HMODULE game = GetModuleHandleW(nullptr);
        if (!IsExactWarzoneBeta2019(game))
            return 1;

        OpenProfileConsole(
            L"CodRevamped - IW8 Warzone Beta 2019");

        InstallWarzoneBetaFileHooks(game);
        LogBetaFastfileInventory();
        LogBetaRecursiveFastfileInventory();

        AppendRaw(
            "\r\n"
            "============================================================\r\n"
            " CodRevamped - IW8 Warzone Beta 2019\r\n"
            "============================================================\r\n");
        AppendRaw(
            "[IW8-BETA] Exact beta executable matched.\r\n"
            "[IW8-BETA] Dedicated CMD + file logging is ACTIVE.\r\n"
            "[IW8-BETA] Beta-only 6036 recovery active: no 1.44 hooks, no retail addresses, no network forcing.\r\n"
            "[IW8-BETA] Failed asset opens are logged; exact-basename files may be remapped from nested beta folders.\r\n"
            "[IW8-BETA] Exact verified 6036 fatal branch will be redirected to its stock success path after runtime decode.\r\n"
            "[IW8-BETA] Log: CodRevamped\\IW8Beta\\warzone_beta_loader.log\r\n");

        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;
        std::uint64_t preferredBase = 0;
        ReadMainImageFingerprint(
            game,
            timestamp,
            imageSize,
            entryPoint,
            preferredBase);

        InternalLog(
            "[IW8-BETA] fingerprint timestamp=0x%08lX imageSize=0x%08lX entryPointRva=0x%08lX preferredBase=0x%llX runtimeBase=%p\r\n",
            timestamp,
            imageSize,
            entryPoint,
            static_cast<unsigned long long>(preferredBase),
            game);

        wchar_t exePath[32768]{};
        const DWORD pathLength =
            GetModuleFileNameW(
                nullptr,
                exePath,
                static_cast<DWORD>(ArrayCount(exePath)));
        if (pathLength &&
            pathLength < ArrayCount(exePath))
        {
            char exeUtf8[32768]{};
            WideToUtf8(
                exePath,
                exeUtf8,
                static_cast<int>(ArrayCount(exeUtf8)));
            InternalLog(
                "[IW8-BETA] exe=%s\r\n",
                exeUtf8);
        }

        std::uintptr_t seenModules[512]{};
        unsigned seenCount = 0;

        const ULONGLONG start = GetTickCount64();
        ULONGLONG lastWindowDump = 0;
        ULONGLONG lastHeartbeat = 0;
        bool firstHeartbeat = true;
        bool firstWindowDump = true;
        unsigned beta6036ScanPass = 0;
        ULONGLONG last6036Scan = 0;

        while (GetTickCount64() - start < 120000ull)
        {
            const ULONGLONG uptime =
                GetTickCount64() - start;

            LogNewModules(
                seenModules,
                seenCount,
                static_cast<unsigned>(ArrayCount(seenModules)));

            if (firstHeartbeat ||
                uptime - lastHeartbeat >= 2000ull)
            {
                InternalLog(
                    "[IW8-BETA] startup_alive uptime_ms=%llu modules=%u\r\n",
                    static_cast<unsigned long long>(uptime),
                    seenCount);
                lastHeartbeat = uptime;
                firstHeartbeat = false;
            }

            if (firstWindowDump ||
                uptime - lastWindowDump >= 2500ull)
            {
                BetaWindowSnapshot snapshot{};
                snapshot.processId = GetCurrentProcessId();
                EnumWindows(
                    &EnumWarzoneBetaWindows,
                    reinterpret_cast<LPARAM>(&snapshot));
                InternalLog(
                    "[IW8-BETA] window_snapshot uptime_ms=%llu visible_windows=%u\r\n",
                    static_cast<unsigned long long>(uptime),
                    snapshot.count);
                lastWindowDump = uptime;
                firstWindowDump = false;
            }

            if (InterlockedCompareExchange(&g_beta6036BranchPatched, 0, 0) == 0 &&
                uptime >= 250ull)
            {
                TryPatchWarzoneBeta6036FatalBranch(game);
            }

            if (beta6036ScanPass < 4 &&
                (beta6036ScanPass == 0 ? uptime >= 1500ull : uptime - last6036Scan >= 5000ull))
            {
                ++beta6036ScanPass;
                ScanBeta6036Runtime(game, beta6036ScanPass);
                last6036Scan = uptime;
            }

            Sleep(250);
        }

        AppendRaw(
            "[IW8-BETA] 120 second startup observation finished; console remains owned by the process.\r\n");
        return 0;
    }


    #include "IW8ServerEmuBridge.inl"

    char* TrimAiBridgeText144(char* text) noexcept
    {
        if (!text) return nullptr;
        while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') ++text;
        char* end = text + strlen(text);
        while (end > text && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) --end;
        *end = '\0';
        return text;
    }

    bool ReadAiBridgeCommand144(char* out, std::size_t outCount) noexcept
    {
        if (!out || outCount < 8u) return false;
        out[0] = '\0';
        wchar_t path[32768]{};
        if (!BuildServerEmuPath(L"ai_command.txt", path, ArrayCount(path)))
            return false;
        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        DWORD read = 0;
        const DWORD wanted = static_cast<DWORD>((std::min)(outCount - 1u, static_cast<std::size_t>(4095u)));
        const BOOL ok = ReadFile(file, out, wanted, &read, nullptr);
        CloseHandle(file);
        if (!ok || !read)
            return false;
        out[read < outCount ? read : outCount - 1u] = '\0';
        DeleteFileW(path); // single-slot queue; successful read is the acknowledgement boundary
        return true;
    }

    void WriteAiBridgeResponse144(const char* id, const char* command, const char* status,
        const char* detail, unsigned long long uptimeMs) noexcept
    {
        ServerEmuAppend(L"ai_response.jsonl",
            "{\"id\":\"%s\",\"command\":\"%s\",\"status\":\"%s\",\"detail\":\"%s\",\"uptime_ms\":%llu,\"pure_emulation\":true,\"state_writes\":false}\r\n",
            id && *id ? id : "0", command && *command ? command : "?", status ? status : "error",
            detail ? detail : "", uptimeMs);
    }

    bool ParseAiBridgeRva144(const char* arg, std::uintptr_t& out) noexcept
    {
        out = 0;
        if (!arg || !*arg) return false;
        char* end = nullptr;
        unsigned long long value = _strtoui64(arg, &end, 0);
        if (end == arg)
        {
            value = _strtoui64(arg, &end, 16);
            if (end == arg) return false;
        }
        while (end && (*end == ' ' || *end == '\t')) ++end;
        if (end && *end) return false;
        out = static_cast<std::uintptr_t>(value);
        return out != 0;
    }

    void PollAiResearchBridge144(unsigned long long uptimeMs) noexcept
    {
        static unsigned long long lastPoll = 0;
        static bool readyLogged = false;
        if (uptimeMs - lastPoll < 250ull) return;
        lastPoll = uptimeMs;

        if (!readyLogged)
        {
            readyLogged = true;
            wchar_t commandPath[32768]{};
            BuildServerEmuPath(L"ai_command.txt", commandPath, ArrayCount(commandPath));
            InternalLog("[AI-BRIDGE144] ready single_slot=yes commandFile='%ls' response=ai_response.jsonl research=ai_research.log pure_emulation=yes stateWrites=off\r\n",
                commandPath);
            ServerEmuAppend(L"ai_response.jsonl",
                "{\"id\":\"startup\",\"command\":\"bridge\",\"status\":\"ready\",\"detail\":\"MW2019 1.44 read-only research bridge ready\",\"uptime_ms\":%llu,\"pure_emulation\":true,\"state_writes\":false}\r\n",
                uptimeMs);
        }

        char buffer[4096]{};
        if (!ReadAiBridgeCommand144(buffer, ArrayCount(buffer)))
            return;

        char* line = TrimAiBridgeText144(buffer);
        if (!line || !*line) return;
        char* id = line;
        char* separator1 = strchr(line, '|');
        if (!separator1)
        {
            WriteAiBridgeResponse144("0", "parse", "error", "expected id|command|arg", uptimeMs);
            return;
        }
        *separator1++ = '\0';
        char* command = TrimAiBridgeText144(separator1);
        char* arg = nullptr;
        if (char* separator2 = strchr(command, '|'))
        {
            *separator2++ = '\0';
            arg = TrimAiBridgeText144(separator2);
        }
        id = TrimAiBridgeText144(id);
        command = TrimAiBridgeText144(command);
        if (!id || !*id) id = const_cast<char*>("0");
        if (!command || !*command)
        {
            WriteAiBridgeResponse144(id, "parse", "error", "missing command", uptimeMs);
            return;
        }

        InternalLog("[AI-BRIDGE144] command id=%s name=%s arg='%s' read_only=yes\r\n",
            id, command, arg && *arg ? arg : "");

        if (_stricmp(command, "ping") == 0 || _stricmp(command, "status") == 0 || _stricmp(command, "snapshot") == 0)
        {
            iw8_144::PrintStatus();
            PrintServerEmuStatus();
            WriteAiBridgeResponse144(id, command, "complete", "status snapshot logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "offsets") == 0)
        {
            iw8_144::PrintOffsets();
            WriteAiBridgeResponse144(id, command, "complete", "known auth offsets logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "authscan") == 0)
        {
            mw2019_diag::RunServerEmuAuthScan();
            WriteAiBridgeResponse144(id, command, "complete", "protocol/auth surface scan completed", uptimeMs);
            return;
        }
        if (_stricmp(command, "protocol_scan") == 0)
        {
            static std::atomic_uint aiProtocolPass{900};
            const unsigned pass = aiProtocolPass.fetch_add(1, std::memory_order_relaxed);
            ScanServerEmuProtocolSurface(GetModuleHandleW(nullptr), pass);
            WriteAiBridgeResponse144(id, command, "complete", "focused protocol scan completed", uptimeMs);
            return;
        }
        if (_stricmp(command, "auth_topology") == 0)
        {
            DumpAuthGateTopology144();
            WriteAiBridgeResponse144(id, command, "complete", "auth gate topology logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "stock_auth_gates") == 0)
        {
            ProbeStockAuthGates144();
            ProbeBNetEarlyGateState144();
            WriteAiBridgeResponse144(id, command, "complete", "stock auth gate snapshot logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "frontend_backtrace") == 0)
        {
            DumpFrontendBacktrace144();
            WriteAiBridgeResponse144(id, command, "complete", "frontend backtrace logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "frontend_writer") == 0)
        {
            DumpFrontendWriterBacktrace144V17();
            WriteAiBridgeResponse144(id, command, "complete", "frontend writer backtrace logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "postfence_consumers") == 0)
        {
            DumpPostFencePointerConsumers144V18();
            WriteAiBridgeResponse144(id, command, "complete", "post-fence consumers logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "bnet_prereq") == 0)
        {
            TraceBNetNativePrereqV51();
            WriteAiBridgeResponse144(id, command, "complete", "native prerequisite trace logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "postfence_state") == 0)
        {
            TraceBNetPostFenceStateV52();
            WriteAiBridgeResponse144(id, command, "complete", "V52 post-fence state trace logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "fence_writer") == 0)
        {
            TraceBNetFenceStateWriterV53();
            WriteAiBridgeResponse144(id, command, "complete", "V53 fence writer trace logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "fence_state1") == 0)
        {
            TraceBNetFenceState1ConditionV54();
            WriteAiBridgeResponse144(id, command, "complete", "V54 state1 condition trace logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "fence_field80") == 0)
        {
            TraceBNetFenceField80ProducerV55();
            WriteAiBridgeResponse144(id, command, "complete", "V55 field80 producer trace logged", uptimeMs);
            return;
        }
        if (_stricmp(command, "fence_dispatch") == 0)
        {
            QueueBNetFenceDispatchV56();
            WriteAiBridgeResponse144(id, command, "accepted", "V56 dispatch worker queued", uptimeMs);
            return;
        }
        if (_stricmp(command, "fence_registration") == 0)
        {
            QueueBNetFenceRegistrationV58();
            WriteAiBridgeResponse144(id, command, "accepted", "V58 registration worker queued", uptimeMs);
            return;
        }
        if (_stricmp(command, "fence_event_path") == 0 || _stricmp(command, "v62") == 0)
        {
            QueueBNetFenceEventPathTraceV62();
            WriteAiBridgeResponse144(id, command, "accepted", "V62 event-path worker queued", uptimeMs);
            return;
        }
        if (_stricmp(command, "auth_sampler") == 0)
        {
            QueueDwAuthResultSampler144("ai_bridge");
            WriteAiBridgeResponse144(id, command, "accepted", "auth result sampler queued", uptimeMs);
            return;
        }
        if (_stricmp(command, "tls_scan") == 0)
        {
            QueueRawDemonwareTlsScan144("ai_bridge");
            WriteAiBridgeResponse144(id, command, "accepted", "Demonware TLS scan queued", uptimeMs);
            return;
        }
        if (_stricmp(command, "source3") == 0 || _stricmp(command, "source3test") == 0)
        {
            if (!arg || !*arg)
            {
                V97PrintSource3TestStatus144();
                WriteAiBridgeResponse144(id, command, "complete", "Source3/task status logged; use source3|1 only for manual test forcing", uptimeMs);
            }
            else if (strcmp(arg, "0") == 0 || strcmp(arg, "1") == 0)
            {
                const unsigned value = static_cast<unsigned>(arg[0] - '0');
                const bool ok = V97SetSource3ManualTest144(value);
                WriteAiBridgeResponse144(id, command, ok ? "complete" : "error",
                    ok ? "manual TEST-ONLY Source3 write completed through stock setter" : "manual Source3 test write failed", uptimeMs);
            }
            else
            {
                WriteAiBridgeResponse144(id, command, "error", "usage: source3|0 or source3|1; omit arg for status", uptimeMs);
            }
            return;
        }
        if (_stricmp(command, "read") == 0 || _stricmp(command, "memory") == 0)
        {
            std::uintptr_t rva = 0;
            if (!ParseAiBridgeRva144(arg, rva))
                WriteAiBridgeResponse144(id, command, "error", "usage: read|0xRVA", uptimeMs);
            else
            {
                AgentResearchReadRva144(rva);
                WriteAiBridgeResponse144(id, command, "complete", "RVA bytes logged to ai_research.log", uptimeMs);
            }
            return;
        }
        if (_stricmp(command, "find_string") == 0 || _stricmp(command, "string") == 0)
        {
            if (!arg || strlen(arg) < 2u)
                WriteAiBridgeResponse144(id, command, "error", "usage: find_string|text", uptimeMs);
            else
            {
                AgentResearchFindString144(arg);
                WriteAiBridgeResponse144(id, command, "complete", "string search logged to ai_research.log", uptimeMs);
            }
            return;
        }
        if (_stricmp(command, "inspect") == 0 || _stricmp(command, "function") == 0)
        {
            std::uintptr_t rva = 0;
            if (!ParseAiBridgeRva144(arg, rva))
                WriteAiBridgeResponse144(id, command, "error", "usage: inspect|0xRVA", uptimeMs);
            else
            {
                AgentResearchInspectRva144(rva);
                WriteAiBridgeResponse144(id, command, "complete", "RVA inspection logged to ai_research.log", uptimeMs);
            }
            return;
        }
        if (_stricmp(command, "xref") == 0 || _stricmp(command, "xrefs") == 0 ||
            _stricmp(command, "callers") == 0 || _stricmp(command, "readers") == 0 ||
            _stricmp(command, "writers") == 0)
        {
            std::uintptr_t rva = 0;
            if (!ParseAiBridgeRva144(arg, rva))
                WriteAiBridgeResponse144(id, command, "error", "usage: xref/readers/writers|0xRVA", uptimeMs);
            else
            {
                const char* filter = _stricmp(command, "readers") == 0 ? "READ" :
                    (_stricmp(command, "writers") == 0 ? "WRITE" : nullptr);
                AgentResearchFindXrefs144(rva, filter);
                WriteAiBridgeResponse144(id, command, "complete",
                    filter ? "filtered RVA references logged to ai_research.log" : "RVA xrefs logged to ai_research.log", uptimeMs);
            }
            return;
        }

        WriteAiBridgeResponse144(id, command, "error",
            "unknown read-only command; use status/authscan/find_string/read/xref/readers/writers/inspect/frontend_backtrace/fence_event_path", uptimeMs);
    }

    DWORD WINAPI Steam144Thread(LPVOID) noexcept
    {
        const HMODULE game = GetModuleHandleW(nullptr);
        if (!iw8_144::IsExactBuild(game))
            return 1;

        // Automated research runs are intentionally stopped after a bounded
        // capture window, which makes the stock client show its previous-run
        // Safe Mode prompt on the next launch. Decline only that exact prompt;
        // all other message boxes retain their normal behavior.
        InstallSafeModePromptHandler144();

        if (!GetConsoleWindow())
            AllocConsole();
        if (GetConsoleWindow())
        {
            SetConsoleTitleW(L"CodRevamped - MW2019 1.44 Server Emulation");
            g_consoleOut = CreateFileW(
                L"CONOUT$",
                GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr);
            if (g_consoleOut == INVALID_HANDLE_VALUE)
                g_consoleOut = GetStdHandle(STD_OUTPUT_HANDLE);
        }

        mw2019_scanner::Initialize();
        mw2019_scanner::StartConsole();
        AppendRaw("[1.44] CodRevamped MW2019 1.44 SERVER-EMULATION research profile started - phase 1\r\n");
        AppendRaw("[SERVER-EMU144] PURE EMULATION: no sign-in/fence/content/LUI/menu truth patches will be installed\r\n");
        AppendRaw("[SERVER-EMU144] installing endpoint + Winsock + WinHTTP tracing/redirection before stock online startup\r\n");
        InstallServerEmuNetworkHooks(game);
        AppendRaw("[AUTH-SCAN] automatic full-image scans are disabled to avoid startup/intro stalls; use the authscan console command manually when research data is needed\r\n");

        std::string message;
        if (!iw8_144::Initialize(game, message))
        {
            InternalLog("[1.44] initialize failed: %s\r\n", message.c_str());
            Sleep(6000);
            message.clear();
            if (!iw8_144::Initialize(game, message))
            {
                InternalLog("[1.44] retry failed: %s\r\n", message.c_str());
                return 2;
            }
        }

        InternalLog("[1.44] %s\r\n", message.c_str());
        iw8_144::PrintStatus();
        AppendRaw("[SERVER-EMU144] discovery logs: auth_surface.log | network_trace.log | network_payloads.log | protocol_callers.log\r\n");
        AppendRaw("[1.44] Console is now login-emulation research only. Type help for authscan/authstatus/netstatus.\r\n");

        const ULONGLONG start = GetTickCount64();
        for (;;)
        {
            const ULONGLONG uptime = GetTickCount64() - start;
            iw8_144::Tick(uptime);
            PollAiResearchBridge144(uptime);
            V95TargetedGateTick144(uptime);
            V97Source3TraceTick144(uptime);
            V98FrontendCompletionTick144(uptime);

            static ULONGLONG lastEmuStatus = 0;
            if (uptime - lastEmuStatus >= 5000)
            {
                lastEmuStatus = uptime;
                PrintServerEmuStatus();
            }

            // Pure server emulation intentionally does not inspect or hook Lua/LUI.
            // Login progress is learned from the focused auth/protocol scan and
            // from real traffic between the stock client and Revamped server.

            Sleep(250);
        }
    }

    BOOL CALLBACK LoadRealVersionOnce(PINIT_ONCE, PVOID, PVOID*) noexcept
    {
        wchar_t systemDir[MAX_PATH]{};
        const UINT len = GetSystemDirectoryW(systemDir, static_cast<UINT>(ArrayCount(systemDir)));
        if (!len || len >= ArrayCount(systemDir))
        {
            InternalLog("[PROXY] GetSystemDirectoryW failed error=%lu\r\n", GetLastError());
            return TRUE;
        }

        wchar_t realPath[MAX_PATH]{};
        _snwprintf_s(realPath, ArrayCount(realPath), _TRUNCATE, L"%s\\version.dll", systemDir);
        g_realVersion = LoadLibraryW(realPath);

        if (!g_realVersion)
            InternalLog("[PROXY-ERROR] LoadLibrary system VERSION failed error=%lu\r\n", GetLastError());
        return TRUE;
    }

    HMODULE RealVersion() noexcept
    {
        InitOnceExecuteOnce(&g_realVersionOnce, LoadRealVersionOnce, nullptr, nullptr);
        return g_realVersion;
    }

    template <typename T>
    T Resolve(const char* name) noexcept
    {
        const HMODULE module = RealVersion();
        const auto proc = module ? GetProcAddress(module, name) : nullptr;
        if (!proc)
            InternalLog("[PROXY-ERROR] export=%s error=%lu\r\n", name ? name : "?", GetLastError());
        return reinterpret_cast<T>(proc);
    }

    void ProxyCall(const char* name) noexcept
    {
        (void)name;
    }
}

namespace mw2019_diag
{
    void Log(const char* format, ...) noexcept
    {
        char body[4096]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(body, sizeof(body), _TRUNCATE, format, args);
        va_end(args);

        // The per-game MW2019 DLL keeps scanner/console output under the same
        // compact build tag as the dedicated profile logger. No wall-clock or
        // INFO/TRACE prefix is added here.
        const HMODULE game = GetModuleHandleW(nullptr);
        const char* prefix = iw8_144::IsExactBuild(game) ? "[1.44] " : "";

        char line[4608]{};
        if (prefix[0] && strncmp(body, prefix, strlen(prefix)) != 0)
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%s%s", prefix, body);
        else
            strncpy_s(line, body, _TRUNCATE);

        // 1.69 allocates the console in the dedicated profile logger rather
        // than DiagnosticThread. Attach lazily so scanner command output still
        // appears in that same console window.
        if (g_consoleOut == INVALID_HANDLE_VALUE && GetConsoleWindow())
        {
            HANDLE out = CreateFileW(
                L"CONOUT$",
                GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr);
            if (out == INVALID_HANDLE_VALUE)
                out = GetStdHandle(STD_OUTPUT_HANDLE);
            g_consoleOut = out;
        }

        AppendRaw(line);
    }

    void RunServerEmuAuthScan(unsigned pass) noexcept
    {
        const HMODULE game = GetModuleHandleW(nullptr);
        if (!iw8_144::IsExactBuild(game) || !iw8_144::IsPureServerEmulationMode())
        {
            Log("[AUTH-SCAN] available only for the MW2019 1.44 pure server-emulation profile\r\n");
            return;
        }

        static std::atomic_uint manualPass{100};
        const unsigned resolvedPass = pass ? pass : manualPass.fetch_add(1, std::memory_order_relaxed);
        Log("[AUTH-SCAN] manual pass %u starting\r\n", resolvedPass);
        ScanServerEmuProtocolSurface(game, resolvedPass);
    }

    void PrintServerEmuNetworkStatus() noexcept
    {
        PrintServerEmuStatus();
    }

    void PrintSource3TestStatus() noexcept
    {
        V97PrintSource3TestStatus144();
    }

    bool SetSource3TestValue(unsigned value) noexcept
    {
        return V97SetSource3ManualTest144(static_cast<std::uint32_t>(value));
    }

    bool EnsureDirectoryTree(const wchar_t* path) noexcept
    {
        if (!path || !*path) return false;
        wchar_t temp[32768]{};
        wcsncpy_s(temp, path, _TRUNCATE);
        for (wchar_t* p = temp + 3; *p; ++p)
        {
            if (*p == L'\\') { const wchar_t old = *p; *p = 0; CreateDirectoryW(temp, nullptr); *p = old; }
        }
        CreateDirectoryW(temp, nullptr);
        return true;
    }

    bool GetOutputRoot(wchar_t* out, std::size_t outCount) noexcept
    {
        if (!out || !outCount) return false;
        wchar_t exe[32768]{};
        if (!GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(ArrayCount(exe)))) return false;
        if (wchar_t* slash = wcsrchr(exe, L'\\')) *slash = 0;
        _snwprintf_s(out, outCount, _TRUNCATE, L"%s\\CodRevamped\\MW2019", exe);
        EnsureDirectoryTree(out);
        return true;
    }

    bool BuildOutputPath(const wchar_t* relativePath, wchar_t* out, std::size_t outCount) noexcept
    {
        if (!relativePath || !out || !outCount) return false;
        wchar_t root[32768]{};
        if (!GetOutputRoot(root, ArrayCount(root))) return false;
        _snwprintf_s(out, outCount, _TRUNCATE, L"%s\\%s", root, relativePath);
        wchar_t parent[32768]{};
        wcsncpy_s(parent, out, _TRUNCATE);
        if (wchar_t* slash = wcsrchr(parent, L'\\')) { *slash = 0; EnsureDirectoryTree(parent); }
        return true;
    }
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR file, DWORD handle, DWORD len, LPVOID data)
{
    ProxyCall("GetFileVersionInfoA");
    using Fn = BOOL(WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID);
    const auto fn = Resolve<Fn>("GetFileVersionInfoA");
    return fn ? fn(file, handle, len, data) : FALSE;
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoByHandle(DWORD flags, HANDLE file, LPVOID* data, PDWORD len)
{
    ProxyCall("GetFileVersionInfoByHandle");
    using Fn = BOOL(WINAPI*)(DWORD, HANDLE, LPVOID*, PDWORD);
    const auto fn = Resolve<Fn>("GetFileVersionInfoByHandle");
    return fn ? fn(flags, file, data, len) : FALSE;
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoExA(DWORD flags, LPCSTR file, DWORD handle, DWORD len, LPVOID data)
{
    ProxyCall("GetFileVersionInfoExA");
    using Fn = BOOL(WINAPI*)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    const auto fn = Resolve<Fn>("GetFileVersionInfoExA");
    return fn ? fn(flags, file, handle, len, data) : FALSE;
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoExW(DWORD flags, LPCWSTR file, DWORD handle, DWORD len, LPVOID data)
{
    ProxyCall("GetFileVersionInfoExW");
    using Fn = BOOL(WINAPI*)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    const auto fn = Resolve<Fn>("GetFileVersionInfoExW");
    return fn ? fn(flags, file, handle, len, data) : FALSE;
}

extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR file, LPDWORD handle)
{
    ProxyCall("GetFileVersionInfoSizeA");
    using Fn = DWORD(WINAPI*)(LPCSTR, LPDWORD);
    const auto fn = Resolve<Fn>("GetFileVersionInfoSizeA");
    return fn ? fn(file, handle) : 0;
}

extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(DWORD flags, LPCSTR file, LPDWORD handle)
{
    ProxyCall("GetFileVersionInfoSizeExA");
    using Fn = DWORD(WINAPI*)(DWORD, LPCSTR, LPDWORD);
    const auto fn = Resolve<Fn>("GetFileVersionInfoSizeExA");
    return fn ? fn(flags, file, handle) : 0;
}

extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(DWORD flags, LPCWSTR file, LPDWORD handle)
{
    ProxyCall("GetFileVersionInfoSizeExW");
    using Fn = DWORD(WINAPI*)(DWORD, LPCWSTR, LPDWORD);
    const auto fn = Resolve<Fn>("GetFileVersionInfoSizeExW");
    return fn ? fn(flags, file, handle) : 0;
}

extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR file, LPDWORD handle)
{
    ProxyCall("GetFileVersionInfoSizeW");
    using Fn = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
    const auto fn = Resolve<Fn>("GetFileVersionInfoSizeW");
    return fn ? fn(file, handle) : 0;
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR file, DWORD handle, DWORD len, LPVOID data)
{
    ProxyCall("GetFileVersionInfoW");
    using Fn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID);
    const auto fn = Resolve<Fn>("GetFileVersionInfoW");
    return fn ? fn(file, handle, len, data) : FALSE;
}

extern "C" DWORD WINAPI Proxy_VerFindFileA(DWORD flags, LPCSTR fileName, LPCSTR winDir, LPCSTR appDir,
    LPSTR curDir, PUINT curDirLen, LPSTR destDir, PUINT destDirLen)
{
    ProxyCall("VerFindFileA");
    using Fn = DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
    const auto fn = Resolve<Fn>("VerFindFileA");
    return fn ? fn(flags, fileName, winDir, appDir, curDir, curDirLen, destDir, destDirLen) : 0;
}

extern "C" DWORD WINAPI Proxy_VerFindFileW(DWORD flags, LPCWSTR fileName, LPCWSTR winDir, LPCWSTR appDir,
    LPWSTR curDir, PUINT curDirLen, LPWSTR destDir, PUINT destDirLen)
{
    ProxyCall("VerFindFileW");
    using Fn = DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    const auto fn = Resolve<Fn>("VerFindFileW");
    return fn ? fn(flags, fileName, winDir, appDir, curDir, curDirLen, destDir, destDirLen) : 0;
}

extern "C" DWORD WINAPI Proxy_VerInstallFileA(DWORD flags, LPCSTR srcFile, LPCSTR destFile, LPCSTR srcDir,
    LPCSTR destDir, LPCSTR curDir, LPSTR tmpFile, PUINT tmpFileLen)
{
    ProxyCall("VerInstallFileA");
    using Fn = DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
    const auto fn = Resolve<Fn>("VerInstallFileA");
    return fn ? fn(flags, srcFile, destFile, srcDir, destDir, curDir, tmpFile, tmpFileLen) : 0;
}

extern "C" DWORD WINAPI Proxy_VerInstallFileW(DWORD flags, LPCWSTR srcFile, LPCWSTR destFile, LPCWSTR srcDir,
    LPCWSTR destDir, LPCWSTR curDir, LPWSTR tmpFile, PUINT tmpFileLen)
{
    ProxyCall("VerInstallFileW");
    using Fn = DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
    const auto fn = Resolve<Fn>("VerInstallFileW");
    return fn ? fn(flags, srcFile, destFile, srcDir, destDir, curDir, tmpFile, tmpFileLen) : 0;
}

extern "C" DWORD WINAPI Proxy_VerLanguageNameA(DWORD lang, LPSTR text, DWORD chars)
{
    ProxyCall("VerLanguageNameA");
    using Fn = DWORD(WINAPI*)(DWORD, LPSTR, DWORD);
    const auto fn = Resolve<Fn>("VerLanguageNameA");
    return fn ? fn(lang, text, chars) : 0;
}

extern "C" DWORD WINAPI Proxy_VerLanguageNameW(DWORD lang, LPWSTR text, DWORD chars)
{
    ProxyCall("VerLanguageNameW");
    using Fn = DWORD(WINAPI*)(DWORD, LPWSTR, DWORD);
    const auto fn = Resolve<Fn>("VerLanguageNameW");
    return fn ? fn(lang, text, chars) : 0;
}

extern "C" BOOL WINAPI Proxy_VerQueryValueA(LPCVOID block, LPCSTR subBlock, LPVOID* buffer, PUINT len)
{
    ProxyCall("VerQueryValueA");
    using Fn = BOOL(WINAPI*)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    const auto fn = Resolve<Fn>("VerQueryValueA");
    return fn ? fn(block, subBlock, buffer, len) : FALSE;
}

extern "C" BOOL WINAPI Proxy_VerQueryValueW(LPCVOID block, LPCWSTR subBlock, LPVOID* buffer, PUINT len)
{
    ProxyCall("VerQueryValueW");
    using Fn = BOOL(WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    const auto fn = Resolve<Fn>("VerQueryValueW");
    return fn ? fn(block, subBlock, buffer, len) : FALSE;
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = module;
        DisableThreadLibraryCalls(module);

        const HMODULE game = GetModuleHandleW(nullptr);

        // The exact 2019 IW8/Warzone-beta executable gets its own loader path
        // before the 1.44 gate. This profile is deliberately passive and only
        // opens a console/file logger plus read-only startup observations.
        if (IsExactWarzoneBeta2019(game))
        {
            InterlockedExchange(
                &g_warzoneBeta2019Profile,
                1);

            AppendRaw(
                "[DLLMAIN] PROCESS_ATTACH reached - IW8 Warzone Beta 2019 exact profile\r\n");

            if (HANDLE thread =
                    CreateThread(
                        nullptr,
                        0,
                        WarzoneBeta2019Thread,
                        nullptr,
                        0,
                        nullptr))
            {
                CloseHandle(thread);
            }
            else
            {
                AppendRaw(
                    "[IW8-BETA] CreateThread failed; beta CMD/startup logger was not started\r\n");
            }
            return TRUE;
        }

        // Normal MW2019 research remains exact-1.44-only. Other builds are
        // VERSION forwarding only so beta/1.28/1.69 addresses cannot bleed
        // into this DLL.
        if (!iw8_144::IsExactBuild(game))
            return TRUE;

        if (HANDLE thread = CreateThread(nullptr, 0, Steam144Thread, nullptr, 0, nullptr))
            CloseHandle(thread);
        else
            AppendRaw("[1.44] CreateThread failed; exact 1.44 profile was not started\r\n");
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        AppendRaw("[DLLMAIN] PROCESS_DETACH\r\n");
    }
    return TRUE;
}
