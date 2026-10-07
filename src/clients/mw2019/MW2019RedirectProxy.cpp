#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <Windows.h>
#include <Wincrypt.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cstdarg>
#include <cstdio>
#include <array>
#include <vector>
#include "../../backend/iw8/LocalManifestData.h"
#include "../../shared/common/utils/MinHook.hpp"

#pragma comment(lib, "Ws2_32.lib")
#pragma intrinsic(_ReturnAddress)

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
    HMODULE g_self = nullptr;
    HMODULE g_realVersion = nullptr;
    INIT_ONCE g_realVersionOnce = INIT_ONCE_STATIC_INIT;

    using GetAddrInfoAFn = INT (WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
    using GetAddrInfoWFn = INT (WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
    using GetHostByNameFn = hostent* (WSAAPI*)(const char*);
    using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
    using WSAConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
    using SocketFn = SOCKET (WSAAPI*)(int, int, int);
    using SelectFn = int (WSAAPI*)(int, fd_set*, fd_set*, fd_set*, const timeval*);
    using WSASocketAFn = SOCKET (WSAAPI*)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
    using WSASocketWFn = SOCKET (WSAAPI*)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
    using WSAIoctlFn = int (WSAAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    using ConnectExFn = BOOL (PASCAL*)(SOCKET, const sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using GetProcAddressFn = FARPROC (WINAPI*)(HMODULE, LPCSTR);
    using GetVersionFn = DWORD (WINAPI*)();
    using GetVersionExAFn = BOOL (WINAPI*)(LPOSVERSIONINFOA);
    using GetVersionExWFn = BOOL (WINAPI*)(LPOSVERSIONINFOW);

    struct CompatRtlOsVersionInfoW
    {
        ULONG dwOSVersionInfoSize;
        ULONG dwMajorVersion;
        ULONG dwMinorVersion;
        ULONG dwBuildNumber;
        ULONG dwPlatformId;
        WCHAR szCSDVersion[128];
    };
    using RtlGetVersionFn = LONG (WINAPI*)(CompatRtlOsVersionInfoW*);
    using RtlGetNtVersionNumbersFn = VOID (WINAPI*)(LPDWORD, LPDWORD, LPDWORD);
    using VerifyVersionInfoAFn = BOOL (WINAPI*)(LPOSVERSIONINFOEXA, DWORD, DWORDLONG);
    using VerifyVersionInfoWFn = BOOL (WINAPI*)(LPOSVERSIONINFOEXW, DWORD, DWORDLONG);
    using GetCommandLineAFn = LPSTR (WINAPI*)();
    using GetCommandLineWFn = LPWSTR (WINAPI*)();
    using RegOpenKeyExAFn = LSTATUS (WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    using RegOpenKeyExWFn = LSTATUS (WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    using RegQueryValueExAFn = LSTATUS (WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    using RegQueryValueExWFn = LSTATUS (WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    using RegCloseKeyFn = LSTATUS (WINAPI*)(HKEY);
    using ExitProcessFn = VOID (WINAPI*)(UINT);
    using TerminateProcessFn = BOOL (WINAPI*)(HANDLE, UINT);
    using RaiseExceptionFn = VOID (WINAPI*)(DWORD, DWORD, DWORD, const ULONG_PTR*);
    using ExitThreadFn = VOID (WINAPI*)(DWORD);
    using FreeLibraryAndExitThreadFn = VOID (WINAPI*)(HMODULE, DWORD);
    using SetUnhandledExceptionFilterFn = LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER);
    using UnhandledExceptionFilterFn = LONG (WINAPI*)(PEXCEPTION_POINTERS);
    using RtlExitUserProcessFn = VOID (WINAPI*)(LONG);
    using RtlExitUserThreadFn = VOID (WINAPI*)(LONG);
    using NtTerminateProcessFn = LONG (WINAPI*)(HANDLE, LONG);
    using NtRaiseHardErrorFn = LONG (WINAPI*)(LONG, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
    using RaiseFailFastExceptionFn = VOID (WINAPI*)(PEXCEPTION_RECORD, PCONTEXT, DWORD);
    using CryptUnprotectDataFn = BOOL (WINAPI*)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
    using MessageBoxAFn = int (WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
    using MessageBoxWFn = int (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);

    // Early IW8 startup fingerprints observed from the user's local builds.
    // 1.16 is the 2019-10 retail image that was previously falling through the
    // unknown-retail path and crashing before useful startup diagnostics.  Keep
    // it on the same conservative pre-entry compatibility path as 1.20/1.23:
    // Windows-version + launcher shims, ordinary IAT network hooks, and no WS2
    // export-table rewriting.  Build-specific Auth3/manifest RVAs remain scoped
    // to the exact builds where they were proven.
    constexpr std::uint32_t kMW116Timestamp = 0x5DAF7AF7u;
    constexpr std::uint32_t kMW116ImageSize = 0x168C6E00u;
    constexpr std::uint32_t kMW116EntryPoint = 0x02B53550u;

    constexpr std::uint32_t kMW120Timestamp = 0x5E9BAF80u;
    constexpr std::uint32_t kMW120ImageSize = 0x1324B000u;
    constexpr std::uint32_t kMW120EntryPoint = 0x021CDC10u;

    constexpr std::uint32_t kMW123Timestamp = 0x5EFCF351u;
    constexpr std::uint32_t kMW123ImageSize = 0x19A42C00u;
    constexpr std::uint32_t kMW123EntryPoint = 0x0493E908u;

    // Exact 1.28 fingerprint from the user's live 1.28 run.  The older
    // 0x5EB05998/0x19465000 observation was a different early executable and
    // must not be mislabeled as 1.28.
    constexpr std::uint32_t kMW128Timestamp = 0x5F8DEF10u;
    constexpr std::uint32_t kMW128ImageSize = 0x1D02BC00u;
    constexpr std::uint32_t kMW128EntryPoint = 0x048D8F78u;

    enum class StartupCompatBuild : LONG
    {
        None = 0,
        MW116 = 116,
        MW120 = 120,
        MW123 = 123,
        MW128 = 128
    };

    constexpr DWORD kCompatMajor = 10;
    constexpr DWORD kCompatMinor = 0;
    constexpr DWORD kCompatBuild = 19041;

    GetAddrInfoAFn g_getAddrInfoA = nullptr;
    GetAddrInfoWFn g_getAddrInfoW = nullptr;
    GetHostByNameFn g_getHostByName = nullptr;
    ConnectFn g_connect = nullptr;
    WSAConnectFn g_wsaConnect = nullptr;
    SocketFn g_socket = nullptr;
    SelectFn g_select = nullptr;
    WSASocketAFn g_wsaSocketA = nullptr;
    WSASocketWFn g_wsaSocketW = nullptr;
    WSAIoctlFn g_wsaIoctl = nullptr;
    ConnectExFn g_connectEx = nullptr;
    GetProcAddressFn g_realGetProcAddress = nullptr;
    GetVersionFn g_realGetVersion = nullptr;
    GetVersionExAFn g_realGetVersionExA = nullptr;
    GetVersionExWFn g_realGetVersionExW = nullptr;
    RtlGetVersionFn g_realRtlGetVersion = nullptr;
    RtlGetNtVersionNumbersFn g_realRtlGetNtVersionNumbers = nullptr;
    VerifyVersionInfoAFn g_realVerifyVersionInfoA = nullptr;
    VerifyVersionInfoWFn g_realVerifyVersionInfoW = nullptr;
    GetCommandLineAFn g_realGetCommandLineA = nullptr;
    GetCommandLineWFn g_realGetCommandLineW = nullptr;
    RegOpenKeyExAFn g_realRegOpenKeyExA = nullptr;
    RegOpenKeyExWFn g_realRegOpenKeyExW = nullptr;
    RegQueryValueExAFn g_realRegQueryValueExA = nullptr;
    RegQueryValueExWFn g_realRegQueryValueExW = nullptr;
    RegCloseKeyFn g_realRegCloseKey = nullptr;
    ExitProcessFn g_realExitProcess = nullptr;
    TerminateProcessFn g_realTerminateProcess = nullptr;
    RaiseExceptionFn g_realRaiseException = nullptr;
    ExitThreadFn g_realExitThread = nullptr;
    FreeLibraryAndExitThreadFn g_realFreeLibraryAndExitThread = nullptr;
    SetUnhandledExceptionFilterFn g_realSetUnhandledExceptionFilter = nullptr;
    UnhandledExceptionFilterFn g_realUnhandledExceptionFilter = nullptr;
    RtlExitUserProcessFn g_realRtlExitUserProcess = nullptr;
    RtlExitUserThreadFn g_realRtlExitUserThread = nullptr;
    NtTerminateProcessFn g_realNtTerminateProcess = nullptr;
    NtRaiseHardErrorFn g_realNtRaiseHardError = nullptr;
    RaiseFailFastExceptionFn g_realRaiseFailFastException = nullptr;
    CryptUnprotectDataFn g_realCryptUnprotectData = nullptr;
    MessageBoxAFn g_realMessageBoxA = nullptr;
    MessageBoxWFn g_realMessageBoxW = nullptr;

    char g_compat123CommandLine[32768]{};
    wchar_t g_compat123CommandLineW[32768]{};
    PVOID g_compat123Veh = nullptr;
    volatile LONG g_compat123VehCount = 0;
    volatile LONG g_compat123VehGuard = 0;
    volatile LONG g_compat123NullExecRecoveries = 0;
    std::uint32_t g_liveTimestamp = 0;
    std::uint32_t g_liveImageSize = 0;
    std::uint32_t g_liveEntryPoint = 0;
    volatile LONG g_liveFingerprintValid = 0;
    volatile LONG g_compat123LauncherPatched = 0;
    volatile LONG g_compat123ExitTracePatched = 0;
    volatile LONG g_compat123SafeModePatched = 0;
    int g_fakeLaunchOptionsKeyTag = 0;
    int g_fakeOdinKeyTag = 0;
    HKEY g_fakeLaunchOptionsKey = reinterpret_cast<HKEY>(&g_fakeLaunchOptionsKeyTag);
    HKEY g_fakeOdinKey = reinterpret_cast<HKEY>(&g_fakeOdinKeyTag);
    const BYTE g_fakeWebTokenBlob[] = { 'C','R','V','1','W','E','B','T','O','K','E','N' };
    volatile LONG g_compat123Detected = 0; // nonzero for any supported early startup build
    volatile LONG g_startupCompatBuild = static_cast<LONG>(StartupCompatBuild::None);
    volatile LONG g_compat123Patched = 0;
    volatile LONG g_compat116DynamicVersionPatched = 0;
    volatile LONG g_mw116ExternalMonitorStarted = 0;
    volatile LONG g_mw116MonitorHost = 0;
    DWORD g_processAttachThreadId = 0;
    HMODULE g_ws2 = nullptr;
    void* g_ws2RelayPage = nullptr;
    std::size_t g_ws2RelayOffset = 0;

    ULONGLONG g_traceStartTick = 0;
    PVOID g_retailCrashVeh = nullptr;
    volatile LONG g_retailCrashSeen = 0;
    volatile LONG g_retailCrashGuard = 0;

    constexpr const char* kLoopbackA = "127.0.0.1";
    constexpr const wchar_t* kLoopbackW = L"127.0.0.1";
    const GUID kConnectExGuid = WSAID_CONNECTEX;

    void WriteRedirectLog(const char* text) noexcept;
    void Write123StartupLog(const char* format, ...) noexcept;

    ULONGLONG TraceElapsedMs() noexcept
    {
        const ULONGLONG now = GetTickCount64();
        return g_traceStartTick ? (now - g_traceStartTick) : 0;
    }

    void ConsolePrint(const char* format, ...) noexcept
    {
        if (!format)
            return;
        char text[2048]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(text, sizeof(text), _TRUNCATE, format, args);
        va_end(args);

        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (output && output != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteConsoleA(output, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        }
        WriteRedirectLog(text);
    }

    void TracePrint(const char* format, ...) noexcept
    {
        if (!format)
            return;

        char body[1600]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(body, sizeof(body), _TRUNCATE, format, args);
        va_end(args);

        SYSTEMTIME local{};
        GetLocalTime(&local);
        ConsolePrint("[NET-TRACE %02u:%02u:%02u.%03u +%llums tid=%lu] %s\r\n",
            static_cast<unsigned>(local.wHour),
            static_cast<unsigned>(local.wMinute),
            static_cast<unsigned>(local.wSecond),
            static_cast<unsigned>(local.wMilliseconds),
            static_cast<unsigned long long>(TraceElapsedMs()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            body);
    }

    void OpenResearchConsole() noexcept
    {
        if (!GetConsoleWindow())
            AllocConsole();
        SetConsoleTitleW(L"CodRevamped MW2019 - Safe Network Redirect");
        HANDLE output = CreateFileW(L"CONOUT$", GENERIC_WRITE | GENERIC_READ,
            FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (output != INVALID_HANDLE_VALUE)
        {
            SetStdHandle(STD_OUTPUT_HANDLE, output);
            SetStdHandle(STD_ERROR_HANDLE, output);
        }
        ConsolePrint("============================================================\r\n");
        ConsolePrint(" CodRevamped MW2019 - safe DNS redirect + adaptive Winsock trace\r\n");
        ConsolePrint(" DNS redirect stays unchanged; Winsock transport hooks are LOGGING-ONLY\r\n");
        ConsolePrint(" Traces dynamic WS2_32 exports plus static IAT calls; no destination/result changes\r\n");
        ConsolePrint(" ConnectEx is LOGGING-ONLY via WSAIoctl extension capture; no sendto/WSASendTo hooks or game-state hooks\r\n");
        ConsolePrint("============================================================\r\n");
    }

    void WriteRedirectLog(const char* text) noexcept
    {
        if (!text)
            return;
        wchar_t exePath[32768]{};
        if (!GetModuleFileNameW(nullptr, exePath, static_cast<DWORD>(sizeof(exePath) / sizeof(exePath[0]))))
            return;
        wchar_t* slash = wcsrchr(exePath, L'\\');
        if (!slash)
            return;
        slash[1] = L'\0';
        wcscat_s(exePath, sizeof(exePath) / sizeof(exePath[0]), L"mw2019_redirect.log");
        HANDLE file = CreateFileW(exePath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;
        DWORD written = 0;
        WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        CloseHandle(file);
    }

    void WriteRetailCrashLog(const char* format, ...) noexcept
    {
        if (!format)
            return;

        char text[4096]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(text, sizeof(text), _TRUNCATE, format, args);
        va_end(args);

        wchar_t exePath[32768]{};
        constexpr size_t exePathCount = sizeof(exePath) / sizeof(exePath[0]);
        if (!GetModuleFileNameW(nullptr, exePath, static_cast<DWORD>(exePathCount)))
            return;
        wchar_t* slash = wcsrchr(exePath, L'\\');
        if (!slash)
            return;
        slash[1] = L'\0';
        wcscat_s(exePath, exePathCount, L"mw2019_retail_crash.log");

        HANDLE file = CreateFileW(exePath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;
        DWORD written = 0;
        WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        FlushFileBuffers(file);
        CloseHandle(file);
    }

    std::uintptr_t ModuleRvaFromAddress(void* address, char* moduleName, std::size_t moduleNameSize) noexcept
    {
        if (moduleName && moduleNameSize)
            strcpy_s(moduleName, moduleNameSize, "<unknown>");
        if (!address)
            return 0;

        HMODULE module = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(address), &module) || !module)
            return 0;

        if (moduleName && moduleNameSize)
        {
            char path[MAX_PATH * 4]{};
            if (GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path))))
            {
                const char* slash = std::strrchr(path, '\\');
                strcpy_s(moduleName, moduleNameSize, slash ? slash + 1 : path);
            }
        }
        return reinterpret_cast<std::uintptr_t>(address) - reinterpret_cast<std::uintptr_t>(module);
    }

    bool IsExactRetailSteamImage() noexcept
    {
        return InterlockedCompareExchange(&g_liveFingerprintValid, 0, 0) != 0 &&
            g_liveTimestamp == 0x69DD404Eu && g_liveImageSize == 0x21679200u &&
            g_liveEntryPoint == 0x06E4931Cu;
    }

    bool RetailProbeReadableProtection(DWORD protection) noexcept
    {
        if (protection & (PAGE_GUARD | PAGE_NOACCESS))
            return false;
        switch (protection & 0xFFu)
        {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    bool RetailProbeExecutableProtection(DWORD protection) noexcept
    {
        if (protection & (PAGE_GUARD | PAGE_NOACCESS))
            return false;
        switch (protection & 0xFFu)
        {
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    constexpr DWORD kRetailRuntimeDumpDelayMs = 50000u;

    bool RetailDumpWriteAt(HANDLE file, const std::uint64_t offset, const void* data,
        const std::size_t size) noexcept
    {
        if (!file || file == INVALID_HANDLE_VALUE || (!data && size))
            return false;

        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN))
            return false;

        const auto* bytes = static_cast<const unsigned char*>(data);
        std::size_t writtenTotal = 0;
        while (writtenTotal < size)
        {
            const std::size_t remaining = size - writtenTotal;
            const DWORD chunk = static_cast<DWORD>(remaining > (16u * 1024u * 1024u) ?
                (16u * 1024u * 1024u) : remaining);
            DWORD written = 0;
            if (!WriteFile(file, bytes + writtenTotal, chunk, &written, nullptr) || written != chunk)
                return false;
            writtenTotal += written;
        }
        return true;
    }

    bool RetailDumpWriteText(HANDLE file, const char* format, ...) noexcept
    {
        if (!file || file == INVALID_HANDLE_VALUE || !format)
            return false;
        char text[2048]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(text, sizeof(text), _TRUNCATE, format, args);
        va_end(args);
        const DWORD bytes = static_cast<DWORD>(std::strlen(text));
        DWORD written = 0;
        return WriteFile(file, text, bytes, &written, nullptr) && written == bytes;
    }

    bool RetailRuntimeDumpBuildPaths(wchar_t* dumpDirectory, const std::size_t dumpDirectoryCount,
        wchar_t* pePath, const std::size_t pePathCount,
        wchar_t* metadataPath, const std::size_t metadataPathCount) noexcept
    {
        if (!dumpDirectory || !dumpDirectoryCount || !pePath || !pePathCount ||
            !metadataPath || !metadataPathCount)
            return false;

        wchar_t modulePath[32768]{};
        const DWORD moduleLength = GetModuleFileNameW(nullptr, modulePath,
            static_cast<DWORD>(std::size(modulePath)));
        if (!moduleLength || moduleLength >= std::size(modulePath))
            return false;
        wchar_t* slash = std::wcsrchr(modulePath, L'\\');
        if (!slash)
            return false;
        *slash = L'\0';

        if (_snwprintf_s(dumpDirectory, dumpDirectoryCount, _TRUNCATE,
            L"%ls\\CodRevampedRuntimeDump", modulePath) < 0)
            return false;
        if (!CreateDirectoryW(dumpDirectory, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
            return false;

        if (_snwprintf_s(pePath, pePathCount, _TRUNCATE,
            L"%ls\\ModernWarfare_runtime_dump.exe", dumpDirectory) < 0)
            return false;
        if (_snwprintf_s(metadataPath, metadataPathCount, _TRUNCATE,
            L"%ls\\runtime_sections.txt", dumpDirectory) < 0)
            return false;
        return true;
    }

    DWORD RetailAlignUp(const DWORD value, const DWORD alignment) noexcept
    {
        if (!alignment)
            return value;
        const DWORD remainder = value % alignment;
        return remainder ? value + (alignment - remainder) : value;
    }

    bool RetailRuntimeDumpMainImage() noexcept
    {
        if (!IsExactRetailSteamImage())
            return false;

        const std::uintptr_t imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const std::size_t imageSize = static_cast<std::size_t>(g_liveImageSize);
        if (!imageBase || imageSize < sizeof(IMAGE_DOS_HEADER))
            return false;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(imageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
            static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > imageSize)
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=headers reason=invalid-dos-or-nt\r\n");
            return false;
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(imageBase +
            static_cast<std::uintptr_t>(dos->e_lfanew));
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=headers reason=invalid-pe64\r\n");
            return false;
        }

        const DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
        const DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
        if (!sizeOfImage || sizeOfImage > g_liveImageSize || !sizeOfHeaders || sizeOfHeaders > sizeOfImage)
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=headers reason=invalid-image-sizing sizeOfImage=0x%08X sizeOfHeaders=0x%08X\r\n",
                sizeOfImage, sizeOfHeaders);
            return false;
        }

        wchar_t dumpDirectory[32768]{};
        wchar_t pePath[32768]{};
        wchar_t metadataPath[32768]{};
        if (!RetailRuntimeDumpBuildPaths(dumpDirectory, std::size(dumpDirectory),
            pePath, std::size(pePath), metadataPath, std::size(metadataPath)))
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=paths win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
            return false;
        }

        HANDLE peFile = CreateFileW(pePath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (peFile == INVALID_HANDLE_VALUE)
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=create-pe win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
            return false;
        }

        HANDLE metadataFile = CreateFileW(metadataPath, GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (metadataFile == INVALID_HANDLE_VALUE)
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=create-metadata win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
            CloseHandle(peFile);
            return false;
        }

        LARGE_INTEGER end{};
        end.QuadPart = sizeOfImage;
        if (!SetFilePointerEx(peFile, end, nullptr, FILE_BEGIN) || !SetEndOfFile(peFile))
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=resize-pe win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
            CloseHandle(metadataFile);
            CloseHandle(peFile);
            return false;
        }

        RetailDumpWriteText(metadataFile,
            "CodRevamped MW2019 Steam Retail runtime image dump\r\n"
            "imageBase=0x%016llX\r\nimageSize=0x%08X\r\n"
            "timestamp=0x%08X\r\nentryPointRva=0x%08X\r\n"
            "dumpLayout=memory-layout PE; section PointerToRawData rewritten to RVA\r\n"
            "processWrites=none; imagePagesReadOnlyCopied=yes\r\n\r\n",
            static_cast<unsigned long long>(imageBase), sizeOfImage,
            g_liveTimestamp, g_liveEntryPoint);

        std::uint64_t copiedBytes = 0;
        std::uint64_t skippedBytes = 0;
        unsigned copiedRegions = 0;
        unsigned skippedRegions = 0;
        const std::uintptr_t imageEnd = imageBase + sizeOfImage;
        std::uintptr_t cursor = imageBase;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t rawRegionEnd = regionBase + mbi.RegionSize;
            const std::uintptr_t regionStart = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t regionEnd = rawRegionEnd < imageEnd ? rawRegionEnd : imageEnd;
            if (regionEnd <= regionStart)
                break;

            const std::size_t regionSize = static_cast<std::size_t>(regionEnd - regionStart);
            const bool readable = mbi.State == MEM_COMMIT && RetailProbeReadableProtection(mbi.Protect);
            RetailDumpWriteText(metadataFile,
                "region rva=0x%08llX bytes=0x%llX state=0x%08lX protect=0x%08lX copied=%s\r\n",
                static_cast<unsigned long long>(regionStart - imageBase),
                static_cast<unsigned long long>(regionSize),
                static_cast<unsigned long>(mbi.State),
                static_cast<unsigned long>(mbi.Protect), readable ? "yes" : "no");
            if (readable)
            {
                if (!RetailDumpWriteAt(peFile, static_cast<std::uint64_t>(regionStart - imageBase),
                    reinterpret_cast<const void*>(regionStart), regionSize))
                {
                    ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=copy-region rva=0x%08llX bytes=%llu win32=%lu\r\n",
                        static_cast<unsigned long long>(regionStart - imageBase),
                        static_cast<unsigned long long>(regionSize),
                        static_cast<unsigned long>(GetLastError()));
                    CloseHandle(metadataFile);
                    CloseHandle(peFile);
                    return false;
                }
                copiedBytes += regionSize;
                ++copiedRegions;
            }
            else
            {
                skippedBytes += regionSize;
                ++skippedRegions;
            }

            if (rawRegionEnd <= cursor)
                break;
            cursor = rawRegionEnd;
        }

        std::vector<unsigned char> headers(sizeOfHeaders);
        std::memcpy(headers.data(), reinterpret_cast<const void*>(imageBase), sizeOfHeaders);
        auto* dumpDos = reinterpret_cast<IMAGE_DOS_HEADER*>(headers.data());
        auto* dumpNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(headers.data() + dumpDos->e_lfanew);
        auto* sections = IMAGE_FIRST_SECTION(dumpNt);
        const std::size_t sectionTableOffset = reinterpret_cast<unsigned char*>(sections) - headers.data();
        const std::size_t sectionTableBytes = static_cast<std::size_t>(dumpNt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableOffset > headers.size() || sectionTableBytes > headers.size() - sectionTableOffset)
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=patch-headers reason=section-table-out-of-range\r\n");
            CloseHandle(metadataFile);
            CloseHandle(peFile);
            return false;
        }
        const DWORD fileAlignment = dumpNt->OptionalHeader.FileAlignment ? dumpNt->OptionalHeader.FileAlignment : 0x200u;

        RetailDumpWriteText(metadataFile,
            "sections=%u fileAlignment=0x%X sectionAlignment=0x%X\r\n",
            static_cast<unsigned>(dumpNt->FileHeader.NumberOfSections), fileAlignment,
            dumpNt->OptionalHeader.SectionAlignment);
        for (unsigned index = 0; index < dumpNt->FileHeader.NumberOfSections; ++index)
        {
            auto& section = sections[index];
            char name[9]{};
            std::memcpy(name, section.Name, 8);
            const DWORD oldRawPointer = section.PointerToRawData;
            const DWORD oldRawSize = section.SizeOfRawData;
            DWORD memoryBytes = section.Misc.VirtualSize > oldRawSize ? section.Misc.VirtualSize : oldRawSize;
            if (section.VirtualAddress >= sizeOfImage)
                memoryBytes = 0;
            else if (memoryBytes > sizeOfImage - section.VirtualAddress)
                memoryBytes = sizeOfImage - section.VirtualAddress;
            DWORD newRawSize = RetailAlignUp(memoryBytes, fileAlignment);
            if (section.VirtualAddress < sizeOfImage && newRawSize > sizeOfImage - section.VirtualAddress)
                newRawSize = sizeOfImage - section.VirtualAddress;
            section.PointerToRawData = section.VirtualAddress;
            section.SizeOfRawData = newRawSize;

            RetailDumpWriteText(metadataFile,
                "section[%u] name=%s va=0x%08X virtualSize=0x%08X oldRaw=0x%08X/0x%08X newRaw=0x%08X/0x%08X characteristics=0x%08X\r\n",
                index, name, section.VirtualAddress, section.Misc.VirtualSize,
                oldRawPointer, oldRawSize, section.PointerToRawData, section.SizeOfRawData,
                section.Characteristics);
        }
        dumpNt->OptionalHeader.CheckSum = 0;

        if (!RetailDumpWriteAt(peFile, 0, headers.data(), headers.size()))
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] failed stage=patch-headers win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
            CloseHandle(metadataFile);
            CloseHandle(peFile);
            return false;
        }

        RetailDumpWriteText(metadataFile,
            "\r\ncopySummary readableRegions=%u copiedBytes=%llu skippedRegions=%u skippedBytes=%llu\r\n",
            copiedRegions, static_cast<unsigned long long>(copiedBytes),
            skippedRegions, static_cast<unsigned long long>(skippedBytes));
        FlushFileBuffers(peFile);
        FlushFileBuffers(metadataFile);
        CloseHandle(metadataFile);
        CloseHandle(peFile);

        char dumpDirectoryA[32768]{};
        WideCharToMultiByte(CP_UTF8, 0, dumpDirectory, -1, dumpDirectoryA,
            static_cast<int>(sizeof(dumpDirectoryA)), nullptr, nullptr);
        ConsolePrint("[RETAIL-RUNTIME-DUMP] complete directory=%s file=ModernWarfare_runtime_dump.exe metadata=runtime_sections.txt imageBase=%p size=0x%08X copiedBytes=%llu skippedBytes=%llu\r\n",
            dumpDirectoryA[0] ? dumpDirectoryA : "<conversion-failed>",
            reinterpret_cast<void*>(imageBase), sizeOfImage,
            static_cast<unsigned long long>(copiedBytes),
            static_cast<unsigned long long>(skippedBytes));
        return true;
    }

    DWORD WINAPI RetailRuntimeDumpWorker(LPVOID) noexcept
    {
        Sleep(kRetailRuntimeDumpDelayMs);
        if (!IsExactRetailSteamImage())
            return 0;

        wchar_t disabled[8]{};
        if (GetEnvironmentVariableW(L"CODREVAMPED_RETAIL_NO_RUNTIME_DUMP", disabled,
            static_cast<DWORD>(std::size(disabled))) && disabled[0] == L'1')
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] disabled by CODREVAMPED_RETAIL_NO_RUNTIME_DUMP=1\r\n");
            return 0;
        }

        ConsolePrint("[RETAIL-RUNTIME-DUMP] begin delayMs=%lu mode=READ_ONLY processWrites=0 outputLayout=memory-pe\r\n",
            static_cast<unsigned long>(kRetailRuntimeDumpDelayMs));
        RetailRuntimeDumpMainImage();
        return 0;
    }

    void QueueRetailRuntimeDump() noexcept
    {
        if (!IsExactRetailSteamImage())
            return;
        HANDLE thread = CreateThread(nullptr, 0, RetailRuntimeDumpWorker, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
            ConsolePrint("[RETAIL-RUNTIME-DUMP] scheduled delayMs=%lu output=CodRevampedRuntimeDump\\ModernWarfare_runtime_dump.exe mode=READ_ONLY\r\n",
                static_cast<unsigned long>(kRetailRuntimeDumpDelayMs));
        }
        else
        {
            ConsolePrint("[RETAIL-RUNTIME-DUMP] schedule failed win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
        }
    }


    bool RetailProbeRangeReadable(const std::uintptr_t address, const std::size_t size) noexcept;

    // -------------------------------------------------------------------------
    // Steam Retail ONLINE "general" live diagnostic.
    // Logging-only: does not alter return values, callback arguments, records,
    // or any game state.
    // -------------------------------------------------------------------------
    constexpr std::uintptr_t kRetailOnlineRecordsRva = 0x12A75330ull;
    constexpr std::uintptr_t kRetailStorageRawStateRva = 0x06D12E90ull;      // F3562E90
    constexpr std::uintptr_t kRetailStorageMappedStateRva = 0x02CBF790ull;   // EF50F790
    constexpr std::uintptr_t kRetailStorageLookupRva = 0x02CBD770ull;        // EF50D770
    constexpr std::uintptr_t kRetailStorageReadRva = 0x02CBD800ull;          // EF50D800
    constexpr std::uintptr_t kRetailOnlineFailCallbackRva = 0x02E8C540ull;   // DC540
    constexpr std::uintptr_t kRetailOnlineMainTickRva = 0x02E8A2A0ull;        // DA2A0
    constexpr std::uintptr_t kRetailOnlineSlotStartRva = 0x02E8D380ull;       // DD380

    using RetailStorageRawStateFn = int (__fastcall*)(void*);
    using RetailStorageMappedStateFn = int (__fastcall*)(void*);
    using RetailStorageLookupFn = bool (__fastcall*)(void*, const char*, void*);
    using RetailStorageReadFn = bool (__fastcall*)(void*, const void*, void*, std::uint32_t, std::uintptr_t, std::uint32_t);
    using RetailOnlineFailCallbackFn = void (__fastcall*)(void*, std::uint32_t, std::uintptr_t, std::uintptr_t);
    using RetailOnlineMainTickFn = void (__fastcall*)();
    using RetailOnlineSlotStartFn = bool (__fastcall*)(int);

    RetailStorageRawStateFn g_retailStorageRawStateOriginal = nullptr;
    RetailStorageMappedStateFn g_retailStorageMappedStateOriginal = nullptr;
    RetailStorageLookupFn g_retailStorageLookupOriginal = nullptr;
    RetailStorageReadFn g_retailStorageReadOriginal = nullptr;
    RetailOnlineFailCallbackFn g_retailOnlineFailCallbackOriginal = nullptr;
    RetailOnlineMainTickFn g_retailOnlineMainTickOriginal = nullptr;
    RetailOnlineSlotStartFn g_retailOnlineSlotStartOriginal = nullptr;

    volatile LONG g_retailOnlineLiveTraceInstalled = 0;
    volatile LONG g_retailLastRawStorageState = LONG_MIN;
    volatile LONG g_retailLastMappedStorageState = LONG_MIN;
    volatile LONG g_retailOnlinePollStarted = 0;

    bool RetailLiveCopyAscii(const char* source, char* out, const std::size_t outSize) noexcept
    {
        if (!out || !outSize)
            return false;
        out[0] = '\0';
        if (!source)
            return false;

        __try
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(source, &mbi, sizeof(mbi)) ||
                mbi.State != MEM_COMMIT || !RetailProbeReadableProtection(mbi.Protect))
                return false;

            const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const auto sourceAddress = reinterpret_cast<std::uintptr_t>(source);
            if (sourceAddress >= regionEnd)
                return false;

            const std::size_t available = static_cast<std::size_t>(regionEnd - sourceAddress);
            const std::size_t limit = (outSize - 1 < available) ? outSize - 1 : available;
            std::size_t index = 0;
            for (; index < limit; ++index)
            {
                const unsigned char ch = static_cast<unsigned char>(source[index]);
                if (!ch)
                    break;
                if (ch < 0x20 || ch > 0x7E)
                    return false;
                out[index] = static_cast<char>(ch);
            }
            out[index] = '\0';
            return index != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            out[0] = '\0';
            return false;
        }
    }

    void RetailLiveDumpOnlineRecords(const char* reason) noexcept
    {
        if (!IsExactRetailSteamImage())
            return;

        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const std::uintptr_t records = base + kRetailOnlineRecordsRva;
        if (!RetailProbeRangeReadable(records, 7u * 0x10u))
        {
            ConsolePrint("[RETAIL-ONLINE-LIVE] records-unreadable reason=%s address=%p\r\n",
                reason ? reason : "<none>", reinterpret_cast<void*>(records));
            return;
        }

        ConsolePrint("[RETAIL-ONLINE-LIVE] records reason=%s", reason ? reason : "<none>");
        for (unsigned index = 0; index < 7; ++index)
        {
            const std::uintptr_t rec = records + static_cast<std::uintptr_t>(index) * 0x10u;
            std::uint32_t state = 0, dword4 = 0;
            std::uint16_t word8 = 0, wordA = 0;
            unsigned char b0C = 0, b0D = 0;
            std::memcpy(&state, reinterpret_cast<const void*>(rec + 0x00), sizeof(state));
            std::memcpy(&dword4, reinterpret_cast<const void*>(rec + 0x04), sizeof(dword4));
            std::memcpy(&word8, reinterpret_cast<const void*>(rec + 0x08), sizeof(word8));
            std::memcpy(&wordA, reinterpret_cast<const void*>(rec + 0x0A), sizeof(wordA));
            std::memcpy(&b0C, reinterpret_cast<const void*>(rec + 0x0C), sizeof(b0C));
            std::memcpy(&b0D, reinterpret_cast<const void*>(rec + 0x0D), sizeof(b0D));

            ConsolePrint(" s%u={state=%u,v4=%u,v8=%u,vA=%u,c=%u,d=%u}",
                index, state, dword4, static_cast<unsigned>(word8),
                static_cast<unsigned>(wordA), static_cast<unsigned>(b0C),
                static_cast<unsigned>(b0D));
        }
        ConsolePrint("\r\n");
    }


    bool RetailLiveReadRecordSnapshot(unsigned char* out, const std::size_t size) noexcept
    {
        if (!out || size < 7u * 0x10u || !IsExactRetailSteamImage())
            return false;

        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const std::uintptr_t records = base + kRetailOnlineRecordsRva;
        if (!RetailProbeRangeReadable(records, 7u * 0x10u))
            return false;

        __try
        {
            std::memcpy(out, reinterpret_cast<const void*>(records), 7u * 0x10u);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    DWORD WINAPI RetailOnlinePollWorker(LPVOID) noexcept
    {
        if (InterlockedCompareExchange(&g_retailOnlinePollStarted, 1, 0) != 0)
            return 0;

        unsigned char previous[7u * 0x10u]{};
        bool havePrevious = RetailLiveReadRecordSnapshot(previous, sizeof(previous));

        ConsolePrint("[RETAIL-ONLINE-POLL] begin intervalMs=500 durationMs=120000 changeOnly=1\r\n");

        for (unsigned tick = 0; tick < 240; ++tick)
        {
            Sleep(500);

            unsigned char current[7u * 0x10u]{};
            if (!RetailLiveReadRecordSnapshot(current, sizeof(current)))
                continue;

            if (!havePrevious || std::memcmp(previous, current, sizeof(current)) != 0)
            {
                ConsolePrint("[RETAIL-ONLINE-POLL] change tick=%u elapsedMs=%u\r\n",
                    tick + 1u, (tick + 1u) * 500u);
                RetailLiveDumpOnlineRecords("poll-change");
                std::memcpy(previous, current, sizeof(previous));
                havePrevious = true;
            }
        }

        ConsolePrint("[RETAIL-ONLINE-POLL] end\r\n");
        return 0;
    }

    void __fastcall RetailOnlineMainTickDetour()
    {
        static volatile LONG calls = 0;
        const LONG callNumber = InterlockedIncrement(&calls);

        if (callNumber <= 8 || (callNumber % 120) == 0)
        {
            ConsolePrint("[RETAIL-ONLINE-LIVE] main-tick call=%ld returnAddress=%p\r\n",
                static_cast<long>(callNumber), _ReturnAddress());
            RetailLiveDumpOnlineRecords("main-tick");
        }

        if (g_retailOnlineMainTickOriginal)
            g_retailOnlineMainTickOriginal();
    }

    bool __fastcall RetailOnlineSlotStartDetour(int slot)
    {
        ConsolePrint("[RETAIL-ONLINE-LIVE] slot-start-enter slot=%d returnAddress=%p\r\n",
            slot, _ReturnAddress());
        RetailLiveDumpOnlineRecords("slot-start-before");

        const bool result = g_retailOnlineSlotStartOriginal ?
            g_retailOnlineSlotStartOriginal(slot) : false;

        ConsolePrint("[RETAIL-ONLINE-LIVE] slot-start-exit slot=%d result=%u\r\n",
            slot, result ? 1u : 0u);
        RetailLiveDumpOnlineRecords("slot-start-after");
        return result;
    }

    int __fastcall RetailStorageRawStateDetour(void* object)
    {
        const int result = g_retailStorageRawStateOriginal ?
            g_retailStorageRawStateOriginal(object) : 0;
        const LONG previous = InterlockedExchange(
            &g_retailLastRawStorageState, static_cast<LONG>(result));

        if (previous != result)
            ConsolePrint("[RETAIL-ONLINE-LIVE] storage-raw-state object=%p previous=%ld current=%d expectedReadyRaw=2\r\n",
                object, static_cast<long>(previous), result);
        return result;
    }

    int __fastcall RetailStorageMappedStateDetour(void* object)
    {
        const int result = g_retailStorageMappedStateOriginal ?
            g_retailStorageMappedStateOriginal(object) : 0;
        const LONG previous = InterlockedExchange(
            &g_retailLastMappedStorageState, static_cast<LONG>(result));

        if (previous != result)
        {
            ConsolePrint("[RETAIL-ONLINE-LIVE] storage-mapped-state object=%p previous=%ld current=%d expectedReadyMapped=4\r\n",
                object, static_cast<long>(previous), result);
            RetailLiveDumpOnlineRecords("mapped-state-change");
        }
        return result;
    }

    bool __fastcall RetailStorageLookupDetour(void* object, const char* name, void* output)
    {
        char safeName[128]{};
        const bool hasName = RetailLiveCopyAscii(name, safeName, sizeof(safeName));

        ConsolePrint("[RETAIL-ONLINE-LIVE] lookup-enter object=%p namePtr=%p name=%s output=%p mappedState=%ld\r\n",
            object, name, hasName ? safeName : "<non-ascii/unreadable>", output,
            static_cast<long>(InterlockedCompareExchange(&g_retailLastMappedStorageState, 0, 0)));
        RetailLiveDumpOnlineRecords("lookup-enter");

        const bool result = g_retailStorageLookupOriginal ?
            g_retailStorageLookupOriginal(object, name, output) : false;

        ConsolePrint("[RETAIL-ONLINE-LIVE] lookup-exit name=%s result=%u\r\n",
            hasName ? safeName : "<non-ascii/unreadable>", result ? 1u : 0u);
        RetailLiveDumpOnlineRecords("lookup-exit");
        return result;
    }

    bool __fastcall RetailStorageReadDetour(
        void* object, const void* descriptor, void* buffer, std::uint32_t bufferSize,
        std::uintptr_t arg5, std::uint32_t arg6)
    {
        ConsolePrint("[RETAIL-ONLINE-LIVE] read-enter object=%p descriptor=%p buffer=%p bufferSize=%u arg5=0x%llX arg6=%u mappedState=%ld\r\n",
            object, descriptor, buffer, bufferSize,
            static_cast<unsigned long long>(arg5), arg6,
            static_cast<long>(InterlockedCompareExchange(&g_retailLastMappedStorageState, 0, 0)));
        RetailLiveDumpOnlineRecords("read-enter");

        const bool result = g_retailStorageReadOriginal ?
            g_retailStorageReadOriginal(object, descriptor, buffer, bufferSize, arg5, arg6) : false;

        ConsolePrint("[RETAIL-ONLINE-LIVE] read-exit result=%u descriptor=%p buffer=%p bufferSize=%u\r\n",
            result ? 1u : 0u, descriptor, buffer, bufferSize);
        RetailLiveDumpOnlineRecords("read-exit");
        return result;
    }

    void __fastcall RetailOnlineFailCallbackDetour(
        void* context, std::uint32_t status, std::uintptr_t arg3, std::uintptr_t arg4)
    {
        ConsolePrint("[RETAIL-ONLINE-LIVE] callback-enter context=%p status=%u arg3=0x%llX arg4=0x%llX returnAddress=%p\r\n",
            context, status,
            static_cast<unsigned long long>(arg3),
            static_cast<unsigned long long>(arg4),
            _ReturnAddress());
        RetailLiveDumpOnlineRecords("callback-before");

        if (g_retailOnlineFailCallbackOriginal)
            g_retailOnlineFailCallbackOriginal(context, status, arg3, arg4);

        ConsolePrint("[RETAIL-ONLINE-LIVE] callback-exit status=%u\r\n", status);
        RetailLiveDumpOnlineRecords("callback-after");
    }

    bool RetailInstallOneLiveHook(
        const char* label, const std::uintptr_t target, void* detour, void** original) noexcept
    {
        const MH_STATUS create = MH_CreateHook(reinterpret_cast<void*>(target), detour, original);
        if (create != MH_OK && create != MH_ERROR_ALREADY_CREATED)
        {
            ConsolePrint("[RETAIL-ONLINE-LIVE] hook-create-failed label=%s target=%p status=%d\r\n",
                label, reinterpret_cast<void*>(target), static_cast<int>(create));
            return false;
        }

        const MH_STATUS enable = MH_EnableHook(reinterpret_cast<void*>(target));
        if (enable != MH_OK && enable != MH_ERROR_ENABLED)
        {
            ConsolePrint("[RETAIL-ONLINE-LIVE] hook-enable-failed label=%s target=%p status=%d\r\n",
                label, reinterpret_cast<void*>(target), static_cast<int>(enable));
            return false;
        }

        ConsolePrint("[RETAIL-ONLINE-LIVE] hook-installed label=%s target=%p\r\n",
            label, reinterpret_cast<void*>(target));
        return true;
    }

    DWORD WINAPI RetailOnlineLiveTraceWorker(LPVOID) noexcept
    {
        Sleep(2500);
        if (!IsExactRetailSteamImage())
            return 0;
        if (InterlockedCompareExchange(&g_retailOnlineLiveTraceInstalled, 1, 0) != 0)
            return 0;

        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return 0;

        ConsolePrint("[RETAIL-ONLINE-LIVE] begin mode=LOGGING_ONLY stateWrites=off resultOverrides=off "
            "rawStateRva=0x%llX mappedStateRva=0x%llX lookupRva=0x%llX readRva=0x%llX callbackRva=0x%llX mainTickRva=0x%llX slotStartRva=0x%llX earlyManagerHooks=disabled\r\n",
            static_cast<unsigned long long>(kRetailStorageRawStateRva),
            static_cast<unsigned long long>(kRetailStorageMappedStateRva),
            static_cast<unsigned long long>(kRetailStorageLookupRva),
            static_cast<unsigned long long>(kRetailStorageReadRva),
            static_cast<unsigned long long>(kRetailOnlineFailCallbackRva),
            static_cast<unsigned long long>(kRetailOnlineMainTickRva),
            static_cast<unsigned long long>(kRetailOnlineSlotStartRva));

        const MH_STATUS init = MH_Initialize();
        if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
        {
            ConsolePrint("[RETAIL-ONLINE-LIVE] MH_Initialize failed status=%d\r\n",
                static_cast<int>(init));
            return 0;
        }

        unsigned installed = 0;
        installed += RetailInstallOneLiveHook("raw-state", base + kRetailStorageRawStateRva,
            reinterpret_cast<void*>(&RetailStorageRawStateDetour),
            reinterpret_cast<void**>(&g_retailStorageRawStateOriginal)) ? 1u : 0u;
        installed += RetailInstallOneLiveHook("mapped-state", base + kRetailStorageMappedStateRva,
            reinterpret_cast<void*>(&RetailStorageMappedStateDetour),
            reinterpret_cast<void**>(&g_retailStorageMappedStateOriginal)) ? 1u : 0u;
        installed += RetailInstallOneLiveHook("lookup", base + kRetailStorageLookupRva,
            reinterpret_cast<void*>(&RetailStorageLookupDetour),
            reinterpret_cast<void**>(&g_retailStorageLookupOriginal)) ? 1u : 0u;
        installed += RetailInstallOneLiveHook("read", base + kRetailStorageReadRva,
            reinterpret_cast<void*>(&RetailStorageReadDetour),
            reinterpret_cast<void**>(&g_retailStorageReadOriginal)) ? 1u : 0u;
        installed += RetailInstallOneLiveHook("callback", base + kRetailOnlineFailCallbackRva,
            reinterpret_cast<void*>(&RetailOnlineFailCallbackDetour),
            reinterpret_cast<void**>(&g_retailOnlineFailCallbackOriginal)) ? 1u : 0u;

        ConsolePrint("[RETAIL-ONLINE-LIVE] armed installed=%u/5 earlyManagerHooks=disabled\r\n", installed);
        RetailLiveDumpOnlineRecords("initial");

        HANDLE pollThread = CreateThread(nullptr, 0, RetailOnlinePollWorker, nullptr, 0, nullptr);
        if (pollThread)
            CloseHandle(pollThread);
        else
            ConsolePrint("[RETAIL-ONLINE-POLL] create-failed win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));

        return 0;
    }

    void QueueRetailOnlineLiveTrace() noexcept
    {
        if (!IsExactRetailSteamImage())
            return;

        HANDLE thread = CreateThread(nullptr, 0, RetailOnlineLiveTraceWorker, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
            ConsolePrint("[RETAIL-ONLINE-LIVE] scheduled delayMs=2500 mode=LOGGING_ONLY\r\n");
        }
        else
        {
            ConsolePrint("[RETAIL-ONLINE-LIVE] schedule-failed win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
        }
    }

    struct RetailProbeAnchor
    {
        const char* label;
        const char* text;
    };

    constexpr RetailProbeAnchor kRetailProbeAnchors[] = {
        { "root-fence-status", "USAGE: Fences.GetStatusStringForRootFenceNotPassingForOnlineData( <controllerIndex>, <gamemode> )" },
        { "all-fence-status", "USAGE: Fences.PrintStatusStringForAllFences( <controllerIndex> )" },
        { "root-fence-dvar", "online_fences_should_show_root_fence_not_passing_in_popups" },
        { "resolve-universal-ids", "Starting DW Resolve Universal Id's task with %u ids." },
        { "resolve-platform-ids", "Starting DW Resolve Platform Id's task with %u ids." },
        { "extended-auth-ok", "Successfully reported ExtendedAuthInfo" },
        { "extended-auth-fail", "Error encountered while reporting extended auth info" },
        { "online-fence-reset", "Live_OnlineServicesFence_ResetState" },
        // Retail strips many debug/USAGE strings, but these short names are part of
        // the Lua registration surface and are therefore much more likely to remain
        // in the live decrypted image.  A luaL_Reg entry is { name*, function* }, so
        // a data-pointer reference to one of these strings can recover the wrapper
        // function without any patching or build-specific RVA.
        { "lua-root-fence-name", "GetStatusStringForRootFenceNotPassingForOnlineData" },
        { "lua-all-fences-name", "GetStatusStringForAllFences" },
        { "lua-print-fences-name", "PrintStatusStringForAllFences" },
    };

    using RetailProbeAnchorHits = std::array<std::uintptr_t, std::size(kRetailProbeAnchors)>;
    using RetailProbeXrefHits = std::array<std::array<std::uintptr_t, 3>, std::size(kRetailProbeAnchors)>;
    using RetailProbeXrefCounts = std::array<unsigned, std::size(kRetailProbeAnchors)>;
    using RetailProbeDataRefHits = std::array<std::array<std::uintptr_t, 8>, std::size(kRetailProbeAnchors)>;
    using RetailProbeDataRefCounts = std::array<unsigned, std::size(kRetailProbeAnchors)>;

    void RetailProbeFindAnchors(const std::uintptr_t imageBase, const std::size_t imageSize,
        RetailProbeAnchorHits& hits) noexcept
    {
        const std::uintptr_t imageEnd = imageBase + imageSize;
        std::uintptr_t cursor = imageBase;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t regionStart = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t regionEnd = regionEndRaw < imageEnd ? regionEndRaw : imageEnd;
            if (mbi.State == MEM_COMMIT && RetailProbeReadableProtection(mbi.Protect) && regionEnd > regionStart)
            {
                const auto* bytes = reinterpret_cast<const unsigned char*>(regionStart);
                const std::size_t size = static_cast<std::size_t>(regionEnd - regionStart);
                for (std::size_t i = 0; i < size; ++i)
                {
                    const char first = static_cast<char>(bytes[i]);
                    const auto checkAnchor = [&](const std::size_t index) noexcept
                    {
                        if (hits[index])
                            return;
                        const char* text = kRetailProbeAnchors[index].text;
                        const std::size_t length = std::strlen(text);
                        if (i + length <= size && std::memcmp(bytes + i, text, length) == 0)
                            hits[index] = regionStart + i;
                    };

                    switch (first)
                    {
                    case 'U':
                        checkAnchor(0);
                        checkAnchor(1);
                        break;
                    case 'o':
                        checkAnchor(2);
                        break;
                    case 'S':
                        checkAnchor(3);
                        checkAnchor(4);
                        checkAnchor(5);
                        break;
                    case 'E':
                        checkAnchor(6);
                        break;
                    case 'L':
                        checkAnchor(7);
                        break;
                    case 'G':
                        checkAnchor(8);
                        checkAnchor(9);
                        break;
                    case 'P':
                        checkAnchor(10);
                        break;
                    default:
                        break;
                    }
                }
            }

            if (regionEndRaw <= cursor)
                break;
            cursor = regionEndRaw;
        }
    }

    void RetailProbeFindRipXrefs(const std::uintptr_t imageBase, const std::size_t imageSize,
        const RetailProbeAnchorHits& anchors, RetailProbeXrefHits& xrefs,
        RetailProbeXrefCounts& xrefCounts) noexcept
    {
        const std::uintptr_t imageEnd = imageBase + imageSize;
        std::uintptr_t cursor = imageBase;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t regionStart = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t regionEnd = regionEndRaw < imageEnd ? regionEndRaw : imageEnd;
            if (mbi.State == MEM_COMMIT && RetailProbeExecutableProtection(mbi.Protect) && regionEnd > regionStart)
            {
                const auto* code = reinterpret_cast<const unsigned char*>(regionStart);
                const std::size_t size = static_cast<std::size_t>(regionEnd - regionStart);
                for (std::size_t i = 0; i + 7 <= size; ++i)
                {
                    std::size_t displacementOffset = 0;
                    std::size_t instructionLength = 0;
                    if ((code[i] & 0xF0u) == 0x40u &&
                        (code[i + 1] == 0x8Du || code[i + 1] == 0x8Bu) &&
                        (code[i + 2] & 0xC7u) == 0x05u)
                    {
                        displacementOffset = 3;
                        instructionLength = 7;
                    }
                    else if ((code[i] == 0x8Du || code[i] == 0x8Bu) &&
                        (code[i + 1] & 0xC7u) == 0x05u)
                    {
                        displacementOffset = 2;
                        instructionLength = 6;
                    }
                    else
                    {
                        continue;
                    }

                    std::int32_t displacement = 0;
                    std::memcpy(&displacement, code + i + displacementOffset, sizeof(displacement));
                    const std::uintptr_t instruction = regionStart + i;
                    const std::uintptr_t resolved = instruction + instructionLength +
                        static_cast<std::intptr_t>(displacement);
                    for (std::size_t anchorIndex = 0; anchorIndex < anchors.size(); ++anchorIndex)
                    {
                        if (!anchors[anchorIndex] || anchors[anchorIndex] != resolved || xrefCounts[anchorIndex] >= 3)
                            continue;
                        xrefs[anchorIndex][xrefCounts[anchorIndex]++] = instruction;
                    }
                }
            }

            if (regionEndRaw <= cursor)
                break;
            cursor = regionEndRaw;
        }
    }

    void RetailProbeDumpFunction(const char* label, const std::uintptr_t xref) noexcept;

    void RetailProbeFindDataPointerRefs(const std::uintptr_t imageBase, const std::size_t imageSize,
        const RetailProbeAnchorHits& anchors, RetailProbeDataRefHits& refs,
        RetailProbeDataRefCounts& refCounts) noexcept
    {
        const std::uintptr_t imageEnd = imageBase + imageSize;
        std::uintptr_t cursor = imageBase;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t regionStart = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t regionEnd = regionEndRaw < imageEnd ? regionEndRaw : imageEnd;
            if (mbi.State == MEM_COMMIT && RetailProbeReadableProtection(mbi.Protect) && regionEnd > regionStart)
            {
                const auto* bytes = reinterpret_cast<const unsigned char*>(regionStart);
                const std::size_t size = static_cast<std::size_t>(regionEnd - regionStart);
                for (std::size_t i = 0; i + sizeof(std::uintptr_t) <= size; i += sizeof(std::uintptr_t))
                {
                    std::uintptr_t value = 0;
                    std::memcpy(&value, bytes + i, sizeof(value));
                    for (std::size_t anchorIndex = 0; anchorIndex < anchors.size(); ++anchorIndex)
                    {
                        if (!anchors[anchorIndex] || value != anchors[anchorIndex] || refCounts[anchorIndex] >= 8)
                            continue;
                        refs[anchorIndex][refCounts[anchorIndex]++] = regionStart + i;
                    }
                }
            }

            if (regionEndRaw <= cursor)
                break;
            cursor = regionEndRaw;
        }
    }

    bool RetailProbeAddressIsExecutable(const std::uintptr_t address) noexcept
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!address || !VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)))
            return false;
        return mbi.State == MEM_COMMIT && RetailProbeExecutableProtection(mbi.Protect);
    }

    bool RetailProbeWritableProtection(DWORD protection) noexcept
    {
        if (protection & (PAGE_GUARD | PAGE_NOACCESS))
            return false;
        switch (protection & 0xFFu)
        {
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    bool RetailProbeRangeReadable(const std::uintptr_t address, const std::size_t size) noexcept
    {
        if (!address || !size || address + size < address)
            return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT || !RetailProbeReadableProtection(mbi.Protect))
            return false;
        const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uintptr_t regionEnd = regionBase + mbi.RegionSize;
        return address >= regionBase && address + size <= regionEnd;
    }

    constexpr std::size_t kRetailFenceCount = 31;
    constexpr std::size_t kRetailFenceControllerCount = 8;
    constexpr std::size_t kRetailFenceRowBytes = kRetailFenceCount * sizeof(std::uintptr_t);
    constexpr const char* kRetailFenceNames[kRetailFenceCount] = {
        "SIGNED_IN_TO_LIVE", "DEMONWARE", "NETWORKING", "ONLINE", "PUBLISHER_VARS",
        "DW_TIME", "ACHIEVEMENTENGINE", "PLAYLISTS", "PATCH", "ONLINE_DAILY_LOGIN",
        "ONLINE_LOOT", "DEDICATED", "PLAYERSTATS", "BLUEPRINTS", "FILTERED_PLAYLISTS",
        "PRIVATE_PARTY_PLATFORM_SESSION", "GAME_LOBBY_PLATFORM_SESSION", "PLAYTOGETHER_HOST",
        "GUNSMITH", "DCQOS", "DW_RECONCILIATION", "RELAY", "BANDWIDTH_TEST",
        "ONLINE_PERMISSIONS", "STORE", "AB_TESTING", "CLOUD_FILES_SYNC",
        "MAIN_ONLINE_DATA", "MP_ONLINE_DATA", "CP_ONLINE_DATA", "SP_ONLINE_DATA"
    };

    struct RetailFenceSnapshot
    {
        std::uintptr_t object = 0;
        std::uintptr_t vtable = 0;
        std::uint32_t controller = 0xFFFFFFFFu;
        std::uint8_t dependenciesMet = 0;
        std::uint8_t isPassing = 0;
        std::uint8_t failed = 0;
        std::uint8_t ignoreIfGuest = 0;
        std::uint64_t dependencies = 0;
        std::uint32_t inferredErrorCode = 0;
    };

    bool RetailProbeReadFenceObject(const std::uintptr_t object, const unsigned expectedController,
        RetailFenceSnapshot& snapshot) noexcept
    {
        if (!RetailProbeRangeReadable(object, 32))
            return false;

        std::memcpy(&snapshot.vtable, reinterpret_cast<const void*>(object + 0), sizeof(snapshot.vtable));
        std::memcpy(&snapshot.controller, reinterpret_cast<const void*>(object + 8), sizeof(snapshot.controller));
        std::memcpy(&snapshot.dependenciesMet, reinterpret_cast<const void*>(object + 12), sizeof(snapshot.dependenciesMet));
        std::memcpy(&snapshot.isPassing, reinterpret_cast<const void*>(object + 13), sizeof(snapshot.isPassing));
        std::memcpy(&snapshot.failed, reinterpret_cast<const void*>(object + 14), sizeof(snapshot.failed));
        std::memcpy(&snapshot.ignoreIfGuest, reinterpret_cast<const void*>(object + 15), sizeof(snapshot.ignoreIfGuest));
        std::memcpy(&snapshot.dependencies, reinterpret_cast<const void*>(object + 16), sizeof(snapshot.dependencies));
        std::memcpy(&snapshot.inferredErrorCode, reinterpret_cast<const void*>(object + 24), sizeof(snapshot.inferredErrorCode));
        snapshot.object = object;

        if (snapshot.controller != expectedController || snapshot.dependenciesMet > 1 ||
            snapshot.isPassing > 1 || snapshot.failed > 1 || snapshot.ignoreIfGuest > 1)
            return false;
        if (!RetailProbeRangeReadable(snapshot.vtable, sizeof(std::uintptr_t)))
            return false;
        std::uintptr_t firstVirtual = 0;
        std::memcpy(&firstVirtual, reinterpret_cast<const void*>(snapshot.vtable), sizeof(firstVirtual));
        return RetailProbeAddressIsExecutable(firstVirtual);
    }

    bool RetailProbeValidateFenceTable(const std::uintptr_t table,
        std::array<std::array<RetailFenceSnapshot, kRetailFenceCount>, kRetailFenceControllerCount>& snapshots) noexcept
    {
        if (!RetailProbeRangeReadable(table, kRetailFenceRowBytes * kRetailFenceControllerCount))
            return false;

        for (unsigned controller = 0; controller < kRetailFenceControllerCount; ++controller)
        {
            for (unsigned index = 0; index < kRetailFenceCount; ++index)
            {
                std::uintptr_t object = 0;
                const std::uintptr_t slot = table +
                    (static_cast<std::uintptr_t>(controller) * kRetailFenceCount + index) * sizeof(std::uintptr_t);
                std::memcpy(&object, reinterpret_cast<const void*>(slot), sizeof(object));
                if (!object || !RetailProbeReadFenceObject(object, controller, snapshots[controller][index]))
                    return false;
            }
        }
        return true;
    }

    bool RetailProbeFastFenceTableFingerprint(const std::uintptr_t candidate,
        const std::uintptr_t regionEnd, const std::uintptr_t imageBase, const std::uintptr_t imageEnd,
        std::array<std::uintptr_t, 8>* inferredSampleStrides = nullptr) noexcept
    {
        constexpr unsigned sampleIndices[] = { 0, 1, 2, 3, 4, 12, 27, 28 };
        const std::uintptr_t tableBytes = kRetailFenceRowBytes * kRetailFenceControllerCount;
        if (!candidate || candidate + tableBytes < candidate || candidate + tableBytes > regionEnd)
            return false;

        std::array<std::uintptr_t, 8> sampleStrides{};
        unsigned sampleNumber = 0;
        for (const unsigned index : sampleIndices)
        {
            std::uintptr_t objects[kRetailFenceControllerCount]{};
            for (unsigned controller = 0; controller < kRetailFenceControllerCount; ++controller)
            {
                const std::uintptr_t slot = candidate +
                    (static_cast<std::uintptr_t>(controller) * kRetailFenceCount + index) * sizeof(std::uintptr_t);
                std::memcpy(&objects[controller], reinterpret_cast<const void*>(slot), sizeof(objects[controller]));
            }

            // OpenIW8 uses 0x50-byte concrete fence objects, but Retail is allowed to
            // change that size. The stable property is stronger: for each concrete
            // fence type, the eight controller instances are an array, so its pointer
            // progression must be arithmetic across controller rows. Infer the stride
            // independently for each sampled fence instead of hardcoding 0x50.
            if (!objects[0] || !objects[1] || objects[1] <= objects[0])
                return false;
            const std::uintptr_t stride = objects[1] - objects[0];
            if (stride < 0x20u || stride > 0x400u || (stride & 7u) != 0)
                return false;
            if (objects[2] != objects[0] + stride * 2u ||
                objects[7] != objects[0] + stride * 7u)
                return false;

            // Fence arrays are static Retail image data in the reference layout. Keep
            // this as a cheap range check only; the full validator below verifies every
            // object's controller/flags/vtable without assuming any concrete stride.
            if (objects[0] < imageBase || objects[7] + 32u < objects[7] || objects[7] + 32u > imageEnd)
                return false;

            sampleStrides[sampleNumber++] = stride;
        }

        // Do two structural reads only after the cheap arithmetic-array fingerprint.
        RetailFenceSnapshot c0{};
        RetailFenceSnapshot c1{};
        std::uintptr_t first0 = 0;
        std::uintptr_t first1 = 0;
        std::memcpy(&first0, reinterpret_cast<const void*>(candidate), sizeof(first0));
        std::memcpy(&first1, reinterpret_cast<const void*>(candidate + kRetailFenceRowBytes), sizeof(first1));
        if (!RetailProbeReadFenceObject(first0, 0, c0) || !RetailProbeReadFenceObject(first1, 1, c1))
            return false;

        if (inferredSampleStrides)
            *inferredSampleStrides = sampleStrides;
        return true;
    }

    std::uintptr_t RetailProbeFindFenceTable(const std::uintptr_t imageBase, const std::size_t imageSize,
        std::array<std::array<RetailFenceSnapshot, kRetailFenceCount>, kRetailFenceControllerCount>& snapshots) noexcept
    {
        const std::uintptr_t imageEnd = imageBase + imageSize;
        const ULONGLONG started = GetTickCount64();
        unsigned long long candidates = 0;
        unsigned long long fastHits = 0;
        unsigned writableRegions = 0;
        ConsolePrint("[RETAIL-FENCE-TABLE] scan-begin strategy=dynamic-controller-array-stride-prefilter imageSize=0x%08llX mode=READ_ONLY\r\n",
            static_cast<unsigned long long>(imageSize));

        std::uintptr_t cursor = imageBase;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
                break;
            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEndRaw = regionBase + mbi.RegionSize;
            const std::uintptr_t regionStart = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t regionEnd = regionEndRaw < imageEnd ? regionEndRaw : imageEnd;
            if (mbi.State == MEM_COMMIT && RetailProbeWritableProtection(mbi.Protect) &&
                regionEnd > regionStart && regionEnd - regionStart >= kRetailFenceRowBytes * kRetailFenceControllerCount)
            {
                ++writableRegions;
                std::uintptr_t candidate = (regionStart + sizeof(std::uintptr_t) - 1) & ~(sizeof(std::uintptr_t) - 1);
                const std::uintptr_t last = regionEnd - kRetailFenceRowBytes * kRetailFenceControllerCount;
                for (; candidate <= last; candidate += sizeof(std::uintptr_t))
                {
                    ++candidates;
                    std::array<std::uintptr_t, 8> inferredStrides{};
                    if (!RetailProbeFastFenceTableFingerprint(candidate, regionEnd, imageBase, imageEnd, &inferredStrides))
                        continue;
                    ++fastHits;
                    if (RetailProbeValidateFenceTable(candidate, snapshots))
                    {
                        ConsolePrint("[RETAIL-FENCE-TABLE] scan-hit candidateRva=0x%08llX candidates=%llu fastHits=%llu writableRegions=%u elapsedMs=%llu sampleStrides={0x%llX,0x%llX,0x%llX,0x%llX,0x%llX,0x%llX,0x%llX,0x%llX}\r\n",
                            static_cast<unsigned long long>(candidate - imageBase), candidates, fastHits, writableRegions,
                            static_cast<unsigned long long>(GetTickCount64() - started),
                            static_cast<unsigned long long>(inferredStrides[0]),
                            static_cast<unsigned long long>(inferredStrides[1]),
                            static_cast<unsigned long long>(inferredStrides[2]),
                            static_cast<unsigned long long>(inferredStrides[3]),
                            static_cast<unsigned long long>(inferredStrides[4]),
                            static_cast<unsigned long long>(inferredStrides[5]),
                            static_cast<unsigned long long>(inferredStrides[6]),
                            static_cast<unsigned long long>(inferredStrides[7]));
                        return candidate;
                    }
                }
            }
            if (regionEndRaw <= cursor)
                break;
            cursor = regionEndRaw;
        }

        ConsolePrint("[RETAIL-FENCE-TABLE] scan-end result=not-found candidates=%llu fastHits=%llu writableRegions=%u elapsedMs=%llu\r\n",
            candidates, fastHits, writableRegions,
            static_cast<unsigned long long>(GetTickCount64() - started));
        return 0;
    }

    int RetailProbeRootFenceNotPassing(
        const std::array<RetailFenceSnapshot, kRetailFenceCount>& fences, int index) noexcept
    {
        if (index < 0 || index >= static_cast<int>(kRetailFenceCount))
            return -1;
        if (fences[index].isPassing)
            return -1;

        for (unsigned guard = 0; guard < kRetailFenceCount; ++guard)
        {
            const std::uint64_t dependencies = fences[index].dependencies;
            if (!dependencies)
                return index;
            int child = -1;
            for (int bit = 0; bit < static_cast<int>(kRetailFenceCount); ++bit)
            {
                if ((dependencies & (1ull << bit)) && !fences[bit].isPassing)
                {
                    child = bit;
                    break;
                }
            }
            if (child < 0 || child == index)
                return index;
            index = child;
        }
        return index;
    }

    void RetailProbeDumpFenceTable(const std::uintptr_t imageBase, const std::size_t imageSize) noexcept
    {
        std::array<std::array<RetailFenceSnapshot, kRetailFenceCount>, kRetailFenceControllerCount> snapshots{};
        const std::uintptr_t table = RetailProbeFindFenceTable(imageBase, imageSize, snapshots);
        if (!table)
        {
            ConsolePrint("[RETAIL-FENCE-TABLE] result=not-found strategy=dynamic-controller-array-stride-prefilter mode=READ_ONLY\r\n");
            return;
        }

        ConsolePrint("[RETAIL-FENCE-TABLE] result=found tableRva=0x%08llX controllers=8 fences=31 objectStride=inferred-per-fence mode=READ_ONLY\r\n",
            static_cast<unsigned long long>(table - imageBase));

        const auto& fences = snapshots[0];
        for (unsigned index = 0; index < kRetailFenceCount; ++index)
        {
            const auto& fence = fences[index];
            const char* state = fence.isPassing ? "PASS" : (fence.failed ? "FAIL" :
                (fence.dependenciesMet ? "ACTIVE" : "WAIT_DEPS"));
            ConsolePrint("[RETAIL-FENCE] controller=0 index=%u name=%s state=%s depsMet=%u passing=%u failed=%u ignoreGuest=%u deps=0x%08llX errorGuess=%u objectRva=%s0x%08llX vtableRva=%s0x%08llX\r\n",
                index, kRetailFenceNames[index], state,
                static_cast<unsigned>(fence.dependenciesMet), static_cast<unsigned>(fence.isPassing),
                static_cast<unsigned>(fence.failed), static_cast<unsigned>(fence.ignoreIfGuest),
                static_cast<unsigned long long>(fence.dependencies), fence.inferredErrorCode,
                (fence.object >= imageBase && fence.object < imageBase + imageSize) ? "" : "outside-image:",
                static_cast<unsigned long long>((fence.object >= imageBase && fence.object < imageBase + imageSize) ?
                    fence.object - imageBase : fence.object),
                (fence.vtable >= imageBase && fence.vtable < imageBase + imageSize) ? "" : "outside-image:",
                static_cast<unsigned long long>((fence.vtable >= imageBase && fence.vtable < imageBase + imageSize) ?
                    fence.vtable - imageBase : fence.vtable));
        }

        constexpr int targets[] = { 3, 27, 28, 29, 30 };
        for (const int target : targets)
        {
            const int root = RetailProbeRootFenceNotPassing(fences, target);
            ConsolePrint("[RETAIL-FENCE-ROOT] controller=0 target=%d(%s) passing=%u root=%d(%s)\r\n",
                target, kRetailFenceNames[target], static_cast<unsigned>(fences[target].isPassing), root,
                root >= 0 && root < static_cast<int>(kRetailFenceCount) ? kRetailFenceNames[root] : "NONE");
        }
    }

    void RetailProbeDumpDirectCalls(const char* label, const std::uintptr_t functionAddress) noexcept
    {
        DWORD64 runtimeImageBase = 0;
        PRUNTIME_FUNCTION runtimeFunction = RtlLookupFunctionEntry(static_cast<DWORD64>(functionAddress),
            &runtimeImageBase, nullptr);
        if (!runtimeFunction || !runtimeImageBase)
            return;

        const std::uintptr_t begin = static_cast<std::uintptr_t>(runtimeImageBase) + runtimeFunction->BeginAddress;
        const std::uintptr_t end = static_cast<std::uintptr_t>(runtimeImageBase) + runtimeFunction->EndAddress;
        const std::uintptr_t mainBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const std::uintptr_t mainEnd = mainBase + static_cast<std::uintptr_t>(g_liveImageSize);
        if (end <= begin)
            return;

        unsigned callIndex = 0;
        for (std::uintptr_t cursor = begin; cursor + 5 <= end && callIndex < 20; ++cursor)
        {
            const auto* code = reinterpret_cast<const unsigned char*>(cursor);
            if (code[0] != 0xE8)
                continue;
            std::int32_t displacement = 0;
            std::memcpy(&displacement, code + 1, sizeof(displacement));
            const std::uintptr_t target = cursor + 5 + static_cast<std::intptr_t>(displacement);
            if (target < mainBase || target >= mainEnd || !RetailProbeAddressIsExecutable(target))
                continue;

            DWORD64 calleeImageBase = 0;
            PRUNTIME_FUNCTION calleeFunction = RtlLookupFunctionEntry(static_cast<DWORD64>(target),
                &calleeImageBase, nullptr);
            std::uintptr_t calleeBegin = target;
            std::uintptr_t calleeEnd = target;
            if (calleeFunction && calleeImageBase)
            {
                calleeBegin = static_cast<std::uintptr_t>(calleeImageBase) + calleeFunction->BeginAddress;
                calleeEnd = static_cast<std::uintptr_t>(calleeImageBase) + calleeFunction->EndAddress;
            }

            char head[24 * 3 + 1]{};
            std::size_t out = 0;
            const auto* targetBytes = reinterpret_cast<const unsigned char*>(calleeBegin);
            for (std::size_t i = 0; i < 24 && out + 3 < sizeof(head); ++i)
                out += static_cast<std::size_t>(_snprintf_s(head + out, sizeof(head) - out, _TRUNCATE,
                    "%02X%s", static_cast<unsigned>(targetBytes[i]), (i + 1 == 24) ? "" : " "));

            ConsolePrint("[RETAIL-FRONTEND-PROBE] luaCallGraph anchor=%s call=%u siteRva=0x%08llX targetRva=0x%08llX calleeRva=0x%08llX..0x%08llX head={%s}\r\n",
                label ? label : "<null>", callIndex,
                static_cast<unsigned long long>(cursor - mainBase),
                static_cast<unsigned long long>(target - mainBase),
                static_cast<unsigned long long>(calleeBegin - mainBase),
                static_cast<unsigned long long>(calleeEnd - mainBase), head);
            ++callIndex;
        }
    }

    void RetailProbeInspectLuaRegEntry(const char* label, const std::uintptr_t ref,
        const std::uintptr_t imageBase, const std::size_t imageSize) noexcept
    {
        const std::uintptr_t imageEnd = imageBase + imageSize;
        if (ref < imageBase || ref + 2 * sizeof(std::uintptr_t) > imageEnd)
            return;

        std::uintptr_t candidate = 0;
        std::memcpy(&candidate, reinterpret_cast<const void*>(ref + sizeof(std::uintptr_t)), sizeof(candidate));
        ConsolePrint("[RETAIL-FRONTEND-PROBE] luaReg anchor=%s dataRefRva=0x%08llX functionCandidateRva=%s0x%08llX executable=%s\r\n",
            label ? label : "<null>",
            static_cast<unsigned long long>(ref - imageBase),
            (candidate >= imageBase && candidate < imageEnd) ? "" : "outside-image:",
            static_cast<unsigned long long>((candidate >= imageBase && candidate < imageEnd) ? (candidate - imageBase) : candidate),
            RetailProbeAddressIsExecutable(candidate) ? "yes" : "no");

        if (!RetailProbeAddressIsExecutable(candidate) || candidate < imageBase || candidate >= imageEnd)
            return;
        RetailProbeDumpFunction(label, candidate);
        RetailProbeDumpDirectCalls(label, candidate);
    }

    void RetailProbeDumpFunction(const char* label, const std::uintptr_t xref) noexcept
    {
        DWORD64 runtimeImageBase = 0;
        PRUNTIME_FUNCTION runtimeFunction = RtlLookupFunctionEntry(static_cast<DWORD64>(xref),
            &runtimeImageBase, nullptr);
        if (!runtimeFunction || !runtimeImageBase)
        {
            ConsolePrint("[RETAIL-FRONTEND-PROBE] anchor=%s xrefRva=0x%08llX function=unwind-not-found\r\n",
                label ? label : "<null>",
                static_cast<unsigned long long>(xref - reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr))));
            return;
        }

        const std::uintptr_t begin = static_cast<std::uintptr_t>(runtimeImageBase) + runtimeFunction->BeginAddress;
        const std::uintptr_t end = static_cast<std::uintptr_t>(runtimeImageBase) + runtimeFunction->EndAddress;
        const std::uintptr_t mainBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        ConsolePrint("[RETAIL-FRONTEND-PROBE] anchor=%s xrefRva=0x%08llX functionRva=0x%08llX..0x%08llX functionBytes=%llu\r\n",
            label ? label : "<null>",
            static_cast<unsigned long long>(xref - mainBase),
            static_cast<unsigned long long>(begin - mainBase),
            static_cast<unsigned long long>(end - mainBase),
            static_cast<unsigned long long>(end > begin ? end - begin : 0));

        if (end <= begin)
            return;
        const std::size_t dumpBytes = static_cast<std::size_t>((end - begin) < 192 ? (end - begin) : 192);
        for (std::size_t offset = 0; offset < dumpBytes; offset += 48)
        {
            const std::size_t chunk = (dumpBytes - offset) < 48 ? (dumpBytes - offset) : 48;
            char hex[48 * 3 + 1]{};
            std::size_t out = 0;
            const auto* bytes = reinterpret_cast<const unsigned char*>(begin + offset);
            for (std::size_t i = 0; i < chunk && out + 3 < sizeof(hex); ++i)
                out += static_cast<std::size_t>(_snprintf_s(hex + out, sizeof(hex) - out, _TRUNCATE,
                    "%02X%s", static_cast<unsigned>(bytes[i]), (i + 1 == chunk) ? "" : " "));
            ConsolePrint("[RETAIL-FRONTEND-PROBE] functionDump anchor=%s rva=0x%08llX+0x%03llX bytes={%s}\r\n",
                label ? label : "<null>",
                static_cast<unsigned long long>(begin - mainBase),
                static_cast<unsigned long long>(offset), hex);
        }
    }

    DWORD WINAPI RetailFrontendProbeWorker(LPVOID) noexcept
    {
        Sleep(42000);
        if (!IsExactRetailSteamImage())
            return 0;

        wchar_t disabled[8]{};
        if (GetEnvironmentVariableW(L"CODREVAMPED_RETAIL_NO_FRONTEND_PROBE", disabled,
            static_cast<DWORD>(std::size(disabled))) && disabled[0] == L'1')
        {
            ConsolePrint("[RETAIL-FRONTEND-PROBE] disabled by CODREVAMPED_RETAIL_NO_FRONTEND_PROBE=1\r\n");
            return 0;
        }

        const std::uintptr_t imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const std::size_t imageSize = static_cast<std::size_t>(g_liveImageSize);
        ConsolePrint("[RETAIL-FRONTEND-PROBE] begin delayMs=42000 imageBase=%p imageSize=0x%08X mode=READ_ONLY writes=0 hooks=0 protectChanges=0\r\n",
            reinterpret_cast<void*>(imageBase), g_liveImageSize);

        RetailProbeAnchorHits anchorHits{};
        RetailProbeXrefHits xrefHits{};
        RetailProbeXrefCounts xrefCounts{};
        RetailProbeDataRefHits dataRefHits{};
        RetailProbeDataRefCounts dataRefCounts{};
        RetailProbeFindAnchors(imageBase, imageSize, anchorHits);
        RetailProbeFindRipXrefs(imageBase, imageSize, anchorHits, xrefHits, xrefCounts);
        RetailProbeFindDataPointerRefs(imageBase, imageSize, anchorHits, dataRefHits, dataRefCounts);

        unsigned foundAnchors = 0;
        unsigned foundXrefs = 0;
        unsigned foundDataRefs = 0;
        for (std::size_t index = 0; index < anchorHits.size(); ++index)
        {
            const auto& anchor = kRetailProbeAnchors[index];
            if (!anchorHits[index])
            {
                ConsolePrint("[RETAIL-FRONTEND-PROBE] anchor=%s result=not-found text=\"%s\"\r\n",
                    anchor.label, anchor.text);
                continue;
            }

            ++foundAnchors;
            ConsolePrint("[RETAIL-FRONTEND-PROBE] anchor=%s result=found rva=0x%08llX address=%p codeXrefs=%u dataRefs=%u\r\n",
                anchor.label,
                static_cast<unsigned long long>(anchorHits[index] - imageBase),
                reinterpret_cast<void*>(anchorHits[index]), xrefCounts[index], dataRefCounts[index]);
            for (unsigned xrefIndex = 0; xrefIndex < xrefCounts[index]; ++xrefIndex)
            {
                ++foundXrefs;
                RetailProbeDumpFunction(anchor.label, xrefHits[index][xrefIndex]);
            }
            for (unsigned dataIndex = 0; dataIndex < dataRefCounts[index]; ++dataIndex)
            {
                ++foundDataRefs;
                RetailProbeInspectLuaRegEntry(anchor.label, dataRefHits[index][dataIndex], imageBase, imageSize);
            }
            if (!xrefCounts[index] && !dataRefCounts[index])
                ConsolePrint("[RETAIL-FRONTEND-PROBE] anchor=%s refs=0 note=string-present-but-no-code-or-data-reference\r\n", anchor.label);
        }

        RetailProbeDumpFenceTable(imageBase, imageSize);
        ConsolePrint("[RETAIL-FRONTEND-PROBE] complete anchorsFound=%u/%u codeXrefsFound=%u dataRefsFound=%u scans=2-readable+1-executable+1-fast-writable-fence-table mode=READ_ONLY writes=0 hooks=0 protectChanges=0\r\n",
            foundAnchors, static_cast<unsigned>(std::size(kRetailProbeAnchors)), foundXrefs, foundDataRefs);
        return 0;
    }

    void QueueRetailFrontendProbe() noexcept
    {
        if (!IsExactRetailSteamImage())
            return;
        HANDLE thread = CreateThread(nullptr, 0, RetailFrontendProbeWorker, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
            ConsolePrint("[RETAIL-FRONTEND-PROBE] scheduled delayMs=42000 probe=v11 mode=READ_ONLY no-state-writes\r\n");
        }
        else
        {
            ConsolePrint("[RETAIL-FRONTEND-PROBE] schedule failed win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
        }
    }

    bool IsCrashLikeException(DWORD code) noexcept
    {
        switch (code)
        {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_DATATYPE_MISALIGNMENT:
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        case EXCEPTION_FLT_INVALID_OPERATION:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_INT_OVERFLOW:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_STACK_OVERFLOW:
        case 0xC0000409u: // STATUS_STACK_BUFFER_OVERRUN / fail-fast family
        case 0xC0000374u: // STATUS_HEAP_CORRUPTION
        case 0xC000000Du: // STATUS_INVALID_PARAMETER
            return true;
        default:
            return false;
        }
    }

    LONG CALLBACK TraceRetailCrashVectored(PEXCEPTION_POINTERS info) noexcept
    {
        if (!info || !info->ExceptionRecord || !IsCrashLikeException(info->ExceptionRecord->ExceptionCode))
            return EXCEPTION_CONTINUE_SEARCH;

        const LONG seen = InterlockedIncrement(&g_retailCrashSeen);
        // Keep first-chance diagnostics passive and bounded.  We deliberately
        // never consume or modify the exception/context.
        if (seen > 64 || InterlockedCompareExchange(&g_retailCrashGuard, 1, 0) != 0)
            return EXCEPTION_CONTINUE_SEARCH;

        const DWORD code = info->ExceptionRecord->ExceptionCode;
        void* rip = info->ExceptionRecord->ExceptionAddress;
        unsigned long long rsp = 0;
        char moduleName[MAX_PATH]{};
        std::uintptr_t rva = 0;

#if defined(_M_X64)
        if (info->ContextRecord)
        {
            rip = reinterpret_cast<void*>(info->ContextRecord->Rip);
            rsp = static_cast<unsigned long long>(info->ContextRecord->Rsp);
        }
#endif
        rva = ModuleRvaFromAddress(rip, moduleName, sizeof(moduleName));

        SYSTEMTIME local{};
        GetLocalTime(&local);
        WriteRetailCrashLog("[RETAIL-VEH %02u:%02u:%02u.%03u] seen=%ld code=0x%08lX flags=0x%08lX rip=%p module=%s rva=0x%llX rsp=0x%llX params=%lu\r\n",
            static_cast<unsigned>(local.wHour), static_cast<unsigned>(local.wMinute),
            static_cast<unsigned>(local.wSecond), static_cast<unsigned>(local.wMilliseconds),
            static_cast<long>(seen), static_cast<unsigned long>(code),
            static_cast<unsigned long>(info->ExceptionRecord->ExceptionFlags), rip,
            moduleName, static_cast<unsigned long long>(rva), rsp,
            static_cast<unsigned long>(info->ExceptionRecord->NumberParameters));

        if (code == EXCEPTION_ACCESS_VIOLATION && info->ExceptionRecord->NumberParameters >= 2)
        {
            WriteRetailCrashLog("[RETAIL-VEH] access operation=%llu target=0x%llX\r\n",
                static_cast<unsigned long long>(info->ExceptionRecord->ExceptionInformation[0]),
                static_cast<unsigned long long>(info->ExceptionRecord->ExceptionInformation[1]));
        }

#if defined(_M_X64)
        if (info->ContextRecord)
        {
            const CONTEXT* c = info->ContextRecord;
            WriteRetailCrashLog("[RETAIL-VEH] regs rax=%016llX rbx=%016llX rcx=%016llX rdx=%016llX rsi=%016llX rdi=%016llX rbp=%016llX rsp=%016llX\r\n",
                static_cast<unsigned long long>(c->Rax), static_cast<unsigned long long>(c->Rbx),
                static_cast<unsigned long long>(c->Rcx), static_cast<unsigned long long>(c->Rdx),
                static_cast<unsigned long long>(c->Rsi), static_cast<unsigned long long>(c->Rdi),
                static_cast<unsigned long long>(c->Rbp), static_cast<unsigned long long>(c->Rsp));
            WriteRetailCrashLog("[RETAIL-VEH] regs r8=%016llX r9=%016llX r10=%016llX r11=%016llX r12=%016llX r13=%016llX r14=%016llX r15=%016llX\r\n",
                static_cast<unsigned long long>(c->R8), static_cast<unsigned long long>(c->R9),
                static_cast<unsigned long long>(c->R10), static_cast<unsigned long long>(c->R11),
                static_cast<unsigned long long>(c->R12), static_cast<unsigned long long>(c->R13),
                static_cast<unsigned long long>(c->R14), static_cast<unsigned long long>(c->R15));

            // A small raw stack candidate list is far more useful than a guessed
            // unwind when symbols are unavailable. Resolve only values that map
            // into loaded modules and leave the process state untouched.
            const auto stack = reinterpret_cast<const std::uintptr_t*>(c->Rsp);
            for (unsigned i = 0; i < 32; ++i)
            {
                std::uintptr_t candidate = 0;
                __try
                {
                    candidate = stack[i];
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    break;
                }
                if (!candidate)
                    continue;
                char candidateModule[MAX_PATH]{};
                const std::uintptr_t candidateRva = ModuleRvaFromAddress(reinterpret_cast<void*>(candidate), candidateModule, sizeof(candidateModule));
                if (candidateRva || std::strcmp(candidateModule, "<unknown>") != 0)
                {
                    WriteRetailCrashLog("[RETAIL-STACK] +0x%03X value=%p module=%s rva=0x%llX\r\n",
                        i * static_cast<unsigned>(sizeof(std::uintptr_t)), reinterpret_cast<void*>(candidate),
                        candidateModule, static_cast<unsigned long long>(candidateRva));
                }
            }
        }
#endif
        WriteRetailCrashLog("[RETAIL-VEH] action=continue-search contextModified=no\r\n");
        InterlockedExchange(&g_retailCrashGuard, 0);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void InstallRetailCrashTrace() noexcept
    {
        if (InterlockedCompareExchange(&g_compat123Detected, 0, 0) != 0 || g_retailCrashVeh)
            return;
        g_retailCrashVeh = AddVectoredExceptionHandler(1, &TraceRetailCrashVectored);
        WriteRetailCrashLog("\r\n[RETAIL-CRASH-TRACE] session-start timestamp=0x%08X imageSize=0x%08X entryPoint=0x%08X veh=%s passive=yes\r\n",
            g_liveTimestamp, g_liveImageSize, g_liveEntryPoint, g_retailCrashVeh ? "installed" : "FAILED");
        ConsolePrint("[CRASH-TRACE] retail passive VEH=%s output=mw2019_retail_crash.log exceptionsConsumed=no contextWrites=no\r\n",
            g_retailCrashVeh ? "installed" : "FAILED");
    }

    bool EqualsNoCase(const char* a, const char* b) noexcept
    {
        return a && b && _stricmp(a, b) == 0;
    }

    bool EndsWithNoCase(const char* text, const char* suffix) noexcept
    {
        if (!text || !suffix)
            return false;
        const std::size_t textLength = std::strlen(text);
        const std::size_t suffixLength = std::strlen(suffix);
        if (suffixLength > textLength)
            return false;
        return _stricmp(text + textLength - suffixLength, suffix) == 0;
    }

    bool ShouldRedirectHost(const char* host) noexcept
    {
        if (!host || !*host)
            return false;

        // Keep this intentionally narrow.  Redirect only endpoints our local IW8
        // server actually handles; unrelated Blizzard CDN/telemetry hosts remain native.
        return EqualsNoCase(host, "cod-assets.cdn.blizzard.com") ||
               EqualsNoCase(host, "us.actual.battle.net") ||
               EqualsNoCase(host, "us.battle.net") ||
               EqualsNoCase(host, "us.api.blizzard.com") ||
               EqualsNoCase(host, "iw8-bnet-auth3.prod.demonware.net") ||
               EqualsNoCase(host, "prod.umbrella.demonware.net") ||
               EndsWithNoCase(host, ".demonware.net");
    }

    bool ShouldRedirectHost(const wchar_t* host) noexcept
    {
        if (!host || !*host)
            return false;
        char utf8[1024]{};
        const int count = WideCharToMultiByte(CP_UTF8, 0, host, -1, utf8,
            static_cast<int>(sizeof(utf8)), nullptr, nullptr);
        return count > 0 && ShouldRedirectHost(utf8);
    }

    volatile LONG g_auth3VerifierTrustPatched = 0;
    volatile LONG g_auth3VerifierTrustAttempts = 0;

    // Exact 294-byte RSA SubjectPublicKeyInfo consumed by the native 1.20
    // Auth3 reply verifier at unk_1426A84F0.  This is public verification
    // material only.  We use the complete blob as the scan fingerprint so an
    // early-build trust write can never land on a merely similar DER object.
    static constexpr unsigned char kStockAuth3VerifierDer[294] = {
        0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,
        0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01,
        0x00,0xC0,0xA2,0x0B,0x1F,0x6C,0xB8,0x1B,0x12,0x70,0xED,0x1A,0xEF,0x30,0x6C,0x75,
        0x9D,0xC1,0x08,0x89,0x99,0xF0,0x2A,0xC8,0xAC,0x2F,0xC7,0xD5,0xD0,0x3B,0x61,0x29,
        0x39,0xF3,0x8F,0x62,0x39,0xDA,0xF1,0x20,0x11,0xE7,0x92,0xE9,0x16,0x24,0x22,0x96,
        0x09,0x9E,0xAC,0x19,0xCD,0x24,0x3E,0x58,0xC6,0x40,0x86,0x78,0xD7,0xDF,0x70,0x77,
        0xCB,0xDE,0x80,0x42,0xB1,0x38,0xF3,0x1D,0x6A,0x3C,0x98,0xE4,0x85,0xDB,0xFB,0x53,
        0x3A,0x86,0x47,0xCE,0x58,0xB1,0xD3,0xD7,0x0B,0x83,0x3D,0x14,0x6B,0xDA,0x40,0x24,
        0x1F,0x16,0x2B,0x0E,0x49,0x22,0xE4,0xB7,0x63,0xFF,0xAA,0x40,0xC2,0x44,0xDF,0xDC,
        0x3F,0x8C,0x1E,0x60,0xB4,0x6F,0x3E,0xDA,0xB2,0x4E,0x50,0xCA,0xFC,0x62,0x4B,0x62,
        0xC7,0xE1,0x77,0x5E,0x83,0xCD,0xE0,0xB5,0xFC,0xC6,0xAA,0xA0,0xC2,0x6B,0x28,0xCC,
        0x8A,0xA7,0x95,0x7B,0x1E,0x67,0xE0,0x5B,0xAF,0xC6,0x54,0x49,0xE6,0xAC,0x7A,0x8D,
        0x1D,0xE6,0x7D,0x12,0x04,0x94,0xC3,0x23,0x4A,0x00,0x60,0x58,0x33,0x6F,0xE7,0x94,
        0x19,0xFF,0xF6,0xE0,0xC6,0x40,0x50,0xB7,0x9D,0x0E,0xCD,0xDF,0xE7,0x92,0x5D,0x84,
        0x94,0x13,0x06,0x61,0xBC,0x44,0x75,0x54,0x70,0x54,0x77,0x4C,0xC0,0x28,0x7D,0xFC,
        0xC9,0x9A,0x92,0x38,0xD4,0xD5,0xEE,0xF3,0x27,0x44,0x66,0x13,0x2C,0x06,0xF0,0x64,
        0xE7,0xEC,0xF8,0x75,0xFD,0x15,0xD4,0x1B,0x91,0x45,0x9D,0x4A,0x3F,0x40,0xE9,0x35,
        0x53,0x7F,0xFC,0x96,0x61,0xE1,0x48,0x74,0x21,0xF0,0x04,0x20,0x41,0x30,0x02,0xD2,
        0xF9,0x02,0x03,0x01,0x00,0x01
    };

    bool IsAuth3Host(const char* host) noexcept
    {
        return host && (EqualsNoCase(host, "iw8-bnet-auth3.prod.demonware.net") ||
            EqualsNoCase(host, "auth3.prod.demonware.net") ||
            EqualsNoCase(host, "auth3-login.prod.demonware.net"));
    }

    bool ReadGameSiblingAuth3PublicKey(unsigned char (&key)[294], wchar_t* resolvedPath,
        std::size_t resolvedCount) noexcept
    {
        if (resolvedPath && resolvedCount)
            resolvedPath[0] = L'\0';

        wchar_t path[32768]{};
        const DWORD length = GetModuleFileNameW(nullptr, path,
            static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
        if (!length || length >= (sizeof(path) / sizeof(path[0])))
            return false;
        wchar_t* slash = wcsrchr(path, L'\\');
        if (!slash)
            return false;
        slash[1] = L'\0';
        if (wcscat_s(path, sizeof(path) / sizeof(path[0]), L"auth3-response-signing-public.der") != 0)
            return false;

        HANDLE file = CreateFileW(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;

        LARGE_INTEGER size{};
        DWORD read = 0;
        const BOOL sizeOk = GetFileSizeEx(file, &size) && size.QuadPart == static_cast<LONGLONG>(sizeof(key));
        const BOOL readOk = sizeOk && ReadFile(file, key, static_cast<DWORD>(sizeof(key)), &read, nullptr);
        CloseHandle(file);
        if (!readOk || read != sizeof(key))
            return false;

        if (resolvedPath && resolvedCount)
            wcsncpy_s(resolvedPath, resolvedCount, path, _TRUNCATE);
        return true;
    }

    void InstallLocalManifestTrust() noexcept
    {
        // The local 8.19 manifests are part of the exact MW2019 1.20 compatibility
        // path. Do not require an external environment variable: the function is
        // already fingerprint/build scoped below and still verifies the stock key
        // bytes before replacing the embedded public key.
        if (static_cast<StartupCompatBuild>(InterlockedCompareExchange(&g_startupCompatBuild, 0, 0)) != StartupCompatBuild::MW120)
            return;
        wchar_t exe[MAX_PATH]{};
        if (!GetModuleFileNameW(nullptr, exe, MAX_PATH))
            return;
        const wchar_t* name = wcsrchr(exe, L'\\');
        if (!name || _wcsicmp(name + 1, L"game_dx12_ship_replay.exe") != 0)
            return;
        using namespace revamped::iw8::localmanifestdata;
        auto* target = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr)) + 0x02416200;
        if (std::memcmp(target, LocalKey, sizeof(LocalKey)) == 0)
            return;
        if (std::memcmp(target, StockKey, sizeof(StockKey)) != 0)
        {
            ConsolePrint("[MANIFEST-TRUST] REFUSED stock key mismatch; no write\r\n");
            return;
        }
        DWORD previous = 0;
        if (!VirtualProtect(target, sizeof(LocalKey), PAGE_READWRITE, &previous))
        {
            ConsolePrint("[MANIFEST-TRUST] REFUSED protection change error=%lu\r\n", GetLastError());
            return;
        }
        std::memcpy(target, LocalKey, sizeof(LocalKey));
        DWORD ignored = 0;
        const BOOL restored = VirtualProtect(target, sizeof(LocalKey), previous, &ignored);
        ConsolePrint("[MANIFEST-TRUST] local RSA key installed rva=02416200 bytes=270 protectionRestored=%u; signature verification active; no code/state patches\r\n", restored);
    }

    static constexpr std::uintptr_t kMW120Auth3VerifierRva = 0x026A84F0ull;

    bool InstallEarlyAuth3LocalSigningTrust(const char* trigger) noexcept
    {
        if (InterlockedCompareExchange(&g_auth3VerifierTrustPatched, 0, 0) != 0)
            return true;

        const auto build = static_cast<StartupCompatBuild>(
            InterlockedCompareExchange(&g_startupCompatBuild, 0, 0));
        // Keep startup compatibility classification unchanged for retail 1.44.
        // Its existing diagnostic profile identifies this exact response key.
        const bool is144 = g_liveTimestamp == 0x61671CE8u &&
            g_liveImageSize == 0x22C1BA00u && g_liveEntryPoint == 0x06D429F8u;
        if (build != StartupCompatBuild::MW120 && !is144)
            return false;
        const std::uintptr_t verifierRva = is144 ? 0x0708E2B0ull : kMW120Auth3VerifierRva;
        ConsolePrint("[AUTH3-PROFILE] build=%s verifierRva=0x%llX trigger=%s\r\n",
            is144 ? "1.44" : "1.20", static_cast<unsigned long long>(verifierRva),
            trigger ? trigger : "unknown");

        const LONG attempt = InterlockedIncrement(&g_auth3VerifierTrustAttempts);
        unsigned char localKey[294]{};
        wchar_t keyPath[32768]{};
        if (!ReadGameSiblingAuth3PublicKey(localKey, keyPath, sizeof(keyPath) / sizeof(keyPath[0])))
        {
            if (attempt <= 3 || (attempt % 5) == 0)
                ConsolePrint("[AUTH3-TRUST] fingerprint-scoped attempt=%ld trigger=%s waiting for auth3-response-signing-public.der; start RevampedIW8Server.exe first\r\n",
                    attempt, trigger ? trigger : "unknown");
            return false;
        }

        // Refuse malformed or stock-key input. A locally generated signer must
        // provide a different RSA-2048 SPKI while retaining the native 294-byte
        // shape. The server owns the matching private key.
        if (localKey[0] != 0x30 || localKey[1] != 0x82 ||
            localKey[292] != 0x00 || localKey[293] != 0x01 ||
            std::memcmp(localKey, kStockAuth3VerifierDer, sizeof(localKey)) == 0)
        {
            ConsolePrint("[AUTH3-TRUST] fingerprint-scoped refused malformed/stock local signer DER trigger=%s\r\n",
                trigger ? trigger : "unknown");
            return false;
        }

        const auto base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
        if (!base)
        {
            ConsolePrint("[AUTH3-TRUST] fingerprint-scoped unable to resolve main module trigger=%s\r\n",
                trigger ? trigger : "unknown");
            return false;
        }

        // IDA confirmed the Auth3 parser at sub_14216C2A0 references the
        // verifier at VA 0x1426A84F0 in the exact 1.20 image.  The image base
        // is 0x140000000, therefore the ASLR-safe RVA is 0x026A84F0.
        //
        // The stock DER occurs five times in .rdata, so a uniqueness scan is
        // intentionally wrong for this build.  Patch only the proven Auth3
        // verifier location and validate the entire 294-byte blob before write.
        unsigned char* target = base + verifierRva;
        bool alreadyPatched = false;
        bool stockMatches = false;
        __try
        {
            alreadyPatched = std::memcmp(target, localKey, sizeof(localKey)) == 0;
            stockMatches = std::memcmp(target, kStockAuth3VerifierDer, sizeof(localKey)) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ConsolePrint("[AUTH3-TRUST] fingerprint-scoped exact verifier RVA unreadable rva=0x%llX trigger=%s\r\n",
                static_cast<unsigned long long>(verifierRva),
                trigger ? trigger : "unknown");
            return false;
        }

        if (alreadyPatched)
        {
            InterlockedExchange(&g_auth3VerifierTrustPatched, 1);
            ConsolePrint("[AUTH3-TRUST] fingerprint-scoped already patched exact verifier DER rva=0x%llX trigger=%s\r\n",
                static_cast<unsigned long long>(verifierRva),
                trigger ? trigger : "unknown");
            return true;
        }

        if (!stockMatches)
        {
            ConsolePrint("[AUTH3-TRUST] fingerprint-scoped REFUSED exact verifier mismatch rva=0x%llX trigger=%s; no write performed\r\n",
                static_cast<unsigned long long>(verifierRva),
                trigger ? trigger : "unknown");
            return false;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(target, sizeof(localKey), PAGE_READWRITE, &oldProtect))
        {
            ConsolePrint("[AUTH3-TRUST] fingerprint-scoped VirtualProtect failed rva=0x%llX win32=%lu trigger=%s\r\n",
                static_cast<unsigned long long>(verifierRva), GetLastError(),
                trigger ? trigger : "unknown");
            return false;
        }

        std::memcpy(target, localKey, sizeof(localKey));
        DWORD ignored = 0;
        VirtualProtect(target, sizeof(localKey), oldProtect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), target, sizeof(localKey));

        bool writePersisted = false;
        __try
        {
            writePersisted = std::memcmp(target, localKey, sizeof(localKey)) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            writePersisted = false;
        }
        if (!writePersisted)
        {
            ConsolePrint("[AUTH3-TRUST] fingerprint-scoped exact verifier DER write did not persist rva=0x%llX trigger=%s\r\n",
                static_cast<unsigned long long>(verifierRva),
                trigger ? trigger : "unknown");
            return false;
        }

        char pathUtf8[32768]{};
        if (keyPath[0])
            WideCharToMultiByte(CP_UTF8, 0, keyPath, -1, pathUtf8, static_cast<int>(sizeof(pathUtf8)), nullptr, nullptr);

        InterlockedExchange(&g_auth3VerifierTrustPatched, 1);
        ConsolePrint("[AUTH3-TRUST] fingerprint-scoped PATCHED exact native Auth3 response verifier DER rva=0x%llX bytes=294 source=%s trigger=%s\r\n",
            static_cast<unsigned long long>(verifierRva),
            pathUtf8[0] ? pathUtf8 : "<game-root>", trigger ? trigger : "unknown");
        ConsolePrint("[AUTH3-TRUST] scope=RSA-PSS/SHA-256 response authenticity only; no auth/login/fence state is modified\r\n");
        return true;
    }

    void ModuleNameFromAddress(void* address, char* output, std::size_t outputSize) noexcept
    {
        if (!output || !outputSize)
            return;
        strcpy_s(output, outputSize, "<unknown>");
        if (!address)
            return;

        HMODULE module = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(address), &module) || !module)
            return;

        char path[MAX_PATH * 4]{};
        if (!GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path))))
            return;
        const char* slash = std::strrchr(path, '\\');
        strcpy_s(output, outputSize, slash ? slash + 1 : path);
    }

    const char* SocketFamilyName(int family) noexcept
    {
        switch (family)
        {
        case AF_INET: return "AF_INET";
        case AF_INET6: return "AF_INET6";
        default: return "AF_OTHER";
        }
    }

    int SocketFamilySafe(const sockaddr* address) noexcept
    {
        if (!address)
            return AF_UNSPEC;
        __try
        {
            return address->sa_family;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return AF_UNSPEC;
        }
    }

    void FormatSockaddr(const sockaddr* address, int addressLength, char* output, std::size_t outputSize) noexcept
    {
        if (!output || !outputSize)
            return;
        output[0] = '\0';
        if (!address || addressLength < static_cast<int>(sizeof(address->sa_family)))
        {
            strcpy_s(output, outputSize, "<null-or-short>");
            return;
        }

        __try
        {
            char host[INET6_ADDRSTRLEN]{};
            unsigned short port = 0;
            if (address->sa_family == AF_INET && addressLength >= static_cast<int>(sizeof(sockaddr_in)))
            {
                const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
                if (!InetNtopA(AF_INET, const_cast<IN_ADDR*>(&v4->sin_addr), host, static_cast<DWORD>(sizeof(host))))
                    strcpy_s(host, sizeof(host), "<invalid-ipv4>");
                port = ntohs(v4->sin_port);
                _snprintf_s(output, outputSize, _TRUNCATE, "%s:%hu", host, port);
                return;
            }
            if (address->sa_family == AF_INET6 && addressLength >= static_cast<int>(sizeof(sockaddr_in6)))
            {
                const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
                if (!InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&v6->sin6_addr), host, static_cast<DWORD>(sizeof(host))))
                    strcpy_s(host, sizeof(host), "<invalid-ipv6>");
                port = ntohs(v6->sin6_port);
                _snprintf_s(output, outputSize, _TRUNCATE, "[%s]:%hu", host, port);
                return;
            }

            _snprintf_s(output, outputSize, _TRUNCATE, "family=%d", static_cast<int>(address->sa_family));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            strcpy_s(output, outputSize, "<unreadable-sockaddr>");
        }
    }

    INT WSAAPI RedirectGetAddrInfoA(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result) noexcept
    {
        if (IsAuth3Host(node))
            InstallEarlyAuth3LocalSigningTrust("getaddrinfoA-auth3");
        void* caller = _ReturnAddress();
        char callerModule[260]{};
        ModuleNameFromAddress(caller, callerModule, sizeof(callerModule));
        const bool redirect = ShouldRedirectHost(node);
        TracePrint("DNS getaddrinfoA module=%s host=%s service=%s redirect=%s target=%s",
            callerModule, node ? node : "<null>", service ? service : "<null>", redirect ? "yes" : "no",
            redirect ? kLoopbackA : (node ? node : "<null>"));
        if (redirect)
            ConsolePrint("[DNS] %s -> 127.0.0.1\r\n", node ? node : "<null>");
        return g_getAddrInfoA ? g_getAddrInfoA(redirect ? kLoopbackA : node, service, hints, result) : WSAHOST_NOT_FOUND;
    }

    INT WSAAPI RedirectGetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result) noexcept
    {
        void* caller = _ReturnAddress();
        char callerModule[260]{};
        ModuleNameFromAddress(caller, callerModule, sizeof(callerModule));
        const bool redirect = ShouldRedirectHost(node);
        char host[1024]{};
        char serviceText[256]{};
        strcpy_s(host, sizeof(host), "<null>");
        strcpy_s(serviceText, sizeof(serviceText), "<null>");
        if (node)
            WideCharToMultiByte(CP_UTF8, 0, node, -1, host, static_cast<int>(sizeof(host)), nullptr, nullptr);
        if (service)
            WideCharToMultiByte(CP_UTF8, 0, service, -1, serviceText, static_cast<int>(sizeof(serviceText)), nullptr, nullptr);
        if (node && IsAuth3Host(host))
            InstallEarlyAuth3LocalSigningTrust("GetAddrInfoW-auth3");
        TracePrint("DNS GetAddrInfoW module=%s host=%s service=%s redirect=%s target=%s",
            callerModule, host, serviceText, redirect ? "yes" : "no", redirect ? "127.0.0.1" : host);
        if (redirect)
            ConsolePrint("[DNS] %s -> 127.0.0.1\r\n", host);
        return g_getAddrInfoW ? g_getAddrInfoW(redirect ? kLoopbackW : node, service, hints, result) : WSAHOST_NOT_FOUND;
    }

    hostent* WSAAPI RedirectGetHostByName(const char* name) noexcept
    {
        if (IsAuth3Host(name))
            InstallEarlyAuth3LocalSigningTrust("gethostbyname-auth3");
        void* caller = _ReturnAddress();
        char callerModule[260]{};
        ModuleNameFromAddress(caller, callerModule, sizeof(callerModule));
        const bool redirect = ShouldRedirectHost(name);
        TracePrint("DNS gethostbyname module=%s host=%s redirect=%s target=%s",
            callerModule, name ? name : "<null>", redirect ? "yes" : "no",
            redirect ? kLoopbackA : (name ? name : "<null>"));
        if (redirect)
            ConsolePrint("[DNS] %s -> 127.0.0.1\r\n", name ? name : "<null>");
        return g_getHostByName ? g_getHostByName(redirect ? kLoopbackA : name) : nullptr;
    }

    int WSAAPI TraceConnect(SOCKET socketValue, const sockaddr* name, int nameLength) noexcept
    {
        void* caller = _ReturnAddress();
        char callerModule[260]{};
        ModuleNameFromAddress(caller, callerModule, sizeof(callerModule));
        char destination[192]{};
        FormatSockaddr(name, nameLength, destination, sizeof(destination));

        const int incomingWsa = WSAGetLastError();
        const DWORD incomingWin32 = GetLastError();
        TracePrint("connect begin module=%s socket=%llu family=%s dst=%s len=%d passthrough=yes",
            callerModule, static_cast<unsigned long long>(socketValue),
            SocketFamilyName(SocketFamilySafe(name)), destination, nameLength);
        SetLastError(incomingWin32);
        WSASetLastError(incomingWsa);

        const ULONGLONG started = GetTickCount64();
        const int result = g_connect ? g_connect(socketValue, name, nameLength) : SOCKET_ERROR;
        int resultWsa = WSAGetLastError();
        DWORD resultWin32 = GetLastError();
        if (!g_connect)
            resultWsa = WSAEFAULT;

        TracePrint("connect end module=%s socket=%llu dst=%s result=%d wsa=%d win32=%lu durationMs=%llu passthrough=yes",
            callerModule, static_cast<unsigned long long>(socketValue), destination, result, resultWsa,
            static_cast<unsigned long>(resultWin32),
            static_cast<unsigned long long>(GetTickCount64() - started));
        SetLastError(resultWin32);
        WSASetLastError(resultWsa);
        return result;
    }

    int WSAAPI TraceWSAConnect(SOCKET socketValue, const sockaddr* name, int nameLength,
        LPWSABUF callerData, LPWSABUF calleeData, LPQOS socketQos, LPQOS groupQos) noexcept
    {
        void* caller = _ReturnAddress();
        char callerModule[260]{};
        ModuleNameFromAddress(caller, callerModule, sizeof(callerModule));
        char destination[192]{};
        FormatSockaddr(name, nameLength, destination, sizeof(destination));

        const int incomingWsa = WSAGetLastError();
        const DWORD incomingWin32 = GetLastError();
        TracePrint("WSAConnect begin module=%s socket=%llu family=%s dst=%s len=%d callerData=%s calleeData=%s passthrough=yes",
            callerModule, static_cast<unsigned long long>(socketValue),
            SocketFamilyName(SocketFamilySafe(name)), destination, nameLength,
            callerData ? "yes" : "no", calleeData ? "yes" : "no");
        SetLastError(incomingWin32);
        WSASetLastError(incomingWsa);

        const ULONGLONG started = GetTickCount64();
        const int result = g_wsaConnect
            ? g_wsaConnect(socketValue, name, nameLength, callerData, calleeData, socketQos, groupQos)
            : SOCKET_ERROR;
        int resultWsa = WSAGetLastError();
        DWORD resultWin32 = GetLastError();
        if (!g_wsaConnect)
            resultWsa = WSAEFAULT;

        TracePrint("WSAConnect end module=%s socket=%llu dst=%s result=%d wsa=%d win32=%lu durationMs=%llu passthrough=yes",
            callerModule, static_cast<unsigned long long>(socketValue), destination, result, resultWsa,
            static_cast<unsigned long>(resultWin32),
            static_cast<unsigned long long>(GetTickCount64() - started));
        SetLastError(resultWin32);
        WSASetLastError(resultWsa);
        return result;
    }

    unsigned FdSetCountSafe(const fd_set* set) noexcept
    {
        if (!set)
            return 0;
        __try
        {
            return static_cast<unsigned>(set->fd_count);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    void FormatFdSet(const fd_set* set, char* output, std::size_t outputSize) noexcept
    {
        if (!output || !outputSize)
            return;
        output[0] = '\0';
        if (!set)
        {
            strcpy_s(output, outputSize, "<null>");
            return;
        }

        __try
        {
            const unsigned count = static_cast<unsigned>(set->fd_count);
            std::size_t used = 0;
            const int prefix = _snprintf_s(output, outputSize, _TRUNCATE, "count=%u sockets=", count);
            if (prefix < 0)
                return;
            used = static_cast<std::size_t>(prefix);
            const unsigned shown = count < 4u ? count : 4u;
            for (unsigned i = 0; i < shown && used + 32 < outputSize; ++i)
            {
                const int wrote = _snprintf_s(output + used, outputSize - used, _TRUNCATE,
                    "%s%llu", i ? "," : "", static_cast<unsigned long long>(set->fd_array[i]));
                if (wrote < 0)
                    break;
                used += static_cast<std::size_t>(wrote);
            }
            if (count > shown && used + 8 < outputSize)
                strcat_s(output, outputSize, ",...");
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            strcpy_s(output, outputSize, "<unreadable>");
        }
    }

    SOCKET WSAAPI TraceSocket(int af, int type, int protocol) noexcept
    {
        void* caller = _ReturnAddress();
        char callerModule[260]{};
        ModuleNameFromAddress(caller, callerModule, sizeof(callerModule));

        const int incomingWsa = WSAGetLastError();
        const DWORD incomingWin32 = GetLastError();
        TracePrint("socket begin module=%s af=%d type=%d protocol=%d passthrough=yes",
            callerModule, af, type, protocol);
        SetLastError(incomingWin32);
        WSASetLastError(incomingWsa);

        const SOCKET result = g_socket ? g_socket(af, type, protocol) : INVALID_SOCKET;
        int resultWsa = WSAGetLastError();
        DWORD resultWin32 = GetLastError();
        if (!g_socket)
            resultWsa = WSAEFAULT;

        TracePrint("socket end module=%s af=%d type=%d protocol=%d result=%llu wsa=%d win32=%lu passthrough=yes",
            callerModule, af, type, protocol, static_cast<unsigned long long>(result), resultWsa,
            static_cast<unsigned long>(resultWin32));
        SetLastError(resultWin32);
        WSASetLastError(resultWsa);
        return result;
    }


    SOCKET WSAAPI TraceWSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA protocolInfo, GROUP group, DWORD flags) noexcept
    {
        char callerModule[260]{};
        ModuleNameFromAddress(_ReturnAddress(), callerModule, sizeof(callerModule));
        const int incomingWsa = WSAGetLastError();
        const DWORD incomingWin32 = GetLastError();
        TracePrint("WSASocketA begin module=%s af=%d type=%d protocol=%d protocolInfo=%s group=%llu flags=0x%08lX passthrough=yes",
            callerModule, af, type, protocol, protocolInfo ? "yes" : "no",
            static_cast<unsigned long long>(group), static_cast<unsigned long>(flags));
        SetLastError(incomingWin32);
        WSASetLastError(incomingWsa);

        const SOCKET result = g_wsaSocketA ? g_wsaSocketA(af, type, protocol, protocolInfo, group, flags) : INVALID_SOCKET;
        int resultWsa = WSAGetLastError();
        DWORD resultWin32 = GetLastError();
        if (!g_wsaSocketA)
            resultWsa = WSAEFAULT;
        TracePrint("WSASocketA end module=%s result=%llu wsa=%d win32=%lu passthrough=yes",
            callerModule, static_cast<unsigned long long>(result), resultWsa, static_cast<unsigned long>(resultWin32));
        SetLastError(resultWin32);
        WSASetLastError(resultWsa);
        return result;
    }

    SOCKET WSAAPI TraceWSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW protocolInfo, GROUP group, DWORD flags) noexcept
    {
        char callerModule[260]{};
        ModuleNameFromAddress(_ReturnAddress(), callerModule, sizeof(callerModule));
        const int incomingWsa = WSAGetLastError();
        const DWORD incomingWin32 = GetLastError();
        TracePrint("WSASocketW begin module=%s af=%d type=%d protocol=%d protocolInfo=%s group=%llu flags=0x%08lX passthrough=yes",
            callerModule, af, type, protocol, protocolInfo ? "yes" : "no",
            static_cast<unsigned long long>(group), static_cast<unsigned long>(flags));
        SetLastError(incomingWin32);
        WSASetLastError(incomingWsa);

        const SOCKET result = g_wsaSocketW ? g_wsaSocketW(af, type, protocol, protocolInfo, group, flags) : INVALID_SOCKET;
        int resultWsa = WSAGetLastError();
        DWORD resultWin32 = GetLastError();
        if (!g_wsaSocketW)
            resultWsa = WSAEFAULT;
        TracePrint("WSASocketW end module=%s result=%llu wsa=%d win32=%lu passthrough=yes",
            callerModule, static_cast<unsigned long long>(result), resultWsa, static_cast<unsigned long>(resultWin32));
        SetLastError(resultWin32);
        WSASetLastError(resultWsa);
        return result;
    }

    void FormatGuid(const GUID* guid, char* output, std::size_t outputSize) noexcept
    {
        if (!output || !outputSize)
            return;
        output[0] = '\0';
        if (!guid)
        {
            strcpy_s(output, outputSize, "<null>");
            return;
        }
        __try
        {
            _snprintf_s(output, outputSize, _TRUNCATE,
                "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                static_cast<unsigned long>(guid->Data1), guid->Data2, guid->Data3,
                guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
                guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            strcpy_s(output, outputSize, "<unreadable-guid>");
        }
    }

    BOOL PASCAL TraceConnectEx(SOCKET socketValue, const sockaddr* name, int nameLength,
        PVOID sendBuffer, DWORD sendDataLength, LPDWORD bytesSent, LPOVERLAPPED overlapped) noexcept
    {
        char callerModule[260]{};
        ModuleNameFromAddress(_ReturnAddress(), callerModule, sizeof(callerModule));
        char destination[192]{};
        FormatSockaddr(name, nameLength, destination, sizeof(destination));

        const int incomingWsa = WSAGetLastError();
        const DWORD incomingWin32 = GetLastError();
        TracePrint("ConnectEx begin module=%s socket=%llu family=%s dst=%s len=%d sendBytes=%lu overlapped=%s passthrough=yes",
            callerModule, static_cast<unsigned long long>(socketValue), SocketFamilyName(SocketFamilySafe(name)),
            destination, nameLength, static_cast<unsigned long>(sendDataLength), overlapped ? "yes" : "no");
        SetLastError(incomingWin32);
        WSASetLastError(incomingWsa);

        const ULONGLONG started = GetTickCount64();
        const BOOL result = g_connectEx
            ? g_connectEx(socketValue, name, nameLength, sendBuffer, sendDataLength, bytesSent, overlapped)
            : FALSE;
        int resultWsa = WSAGetLastError();
        DWORD resultWin32 = GetLastError();
        if (!g_connectEx)
        {
            resultWsa = WSAEFAULT;
            resultWin32 = ERROR_INVALID_FUNCTION;
        }

        DWORD sentValue = 0;
        bool sentReadable = false;
        if (bytesSent)
        {
            __try
            {
                sentValue = *bytesSent;
                sentReadable = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                sentReadable = false;
            }
        }
        TracePrint("ConnectEx end module=%s socket=%llu dst=%s result=%s wsa=%d win32=%lu bytesSent=%s%lu durationMs=%llu passthrough=yes",
            callerModule, static_cast<unsigned long long>(socketValue), destination, result ? "TRUE" : "FALSE",
            resultWsa, static_cast<unsigned long>(resultWin32), sentReadable ? "" : "<n/a>",
            static_cast<unsigned long>(sentReadable ? sentValue : 0),
            static_cast<unsigned long long>(GetTickCount64() - started));
        SetLastError(resultWin32);
        WSASetLastError(resultWsa);
        return result;
    }

    int WSAAPI TraceWSAIoctl(SOCKET socketValue, DWORD controlCode, LPVOID inBuffer, DWORD inBufferBytes,
        LPVOID outBuffer, DWORD outBufferBytes, LPDWORD bytesReturned, LPWSAOVERLAPPED overlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine) noexcept
    {
        char callerModule[260]{};
        ModuleNameFromAddress(_ReturnAddress(), callerModule, sizeof(callerModule));

        GUID extensionGuid{};
        bool hasGuid = false;
        if (controlCode == SIO_GET_EXTENSION_FUNCTION_POINTER && inBuffer && inBufferBytes >= sizeof(GUID))
        {
            __try
            {
                extensionGuid = *reinterpret_cast<const GUID*>(inBuffer);
                hasGuid = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                hasGuid = false;
            }
        }
        char guidText[96]{};
        FormatGuid(hasGuid ? &extensionGuid : nullptr, guidText, sizeof(guidText));
        const bool asksConnectEx = hasGuid && IsEqualGUID(extensionGuid, kConnectExGuid);

        const int incomingWsa = WSAGetLastError();
        const DWORD incomingWin32 = GetLastError();
        TracePrint("WSAIoctl begin module=%s socket=%llu code=0x%08lX inBytes=%lu outBytes=%lu extensionGuid=%s connectExRequest=%s overlapped=%s completion=%s passthrough=yes",
            callerModule, static_cast<unsigned long long>(socketValue), static_cast<unsigned long>(controlCode),
            static_cast<unsigned long>(inBufferBytes), static_cast<unsigned long>(outBufferBytes), guidText,
            asksConnectEx ? "yes" : "no", overlapped ? "yes" : "no", completionRoutine ? "yes" : "no");
        SetLastError(incomingWin32);
        WSASetLastError(incomingWsa);

        const int result = g_wsaIoctl
            ? g_wsaIoctl(socketValue, controlCode, inBuffer, inBufferBytes, outBuffer, outBufferBytes,
                bytesReturned, overlapped, completionRoutine)
            : SOCKET_ERROR;
        int resultWsa = WSAGetLastError();
        DWORD resultWin32 = GetLastError();
        if (!g_wsaIoctl)
            resultWsa = WSAEFAULT;

        DWORD returned = 0;
        bool returnedReadable = false;
        if (bytesReturned)
        {
            __try
            {
                returned = *bytesReturned;
                returnedReadable = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                returnedReadable = false;
            }
        }

        void* originalExtension = nullptr;
        bool wrappedConnectEx = false;
        if (result == 0 && asksConnectEx && outBuffer && outBufferBytes >= sizeof(void*))
        {
            __try
            {
                auto** functionSlot = reinterpret_cast<void**>(outBuffer);
                originalExtension = *functionSlot;
                if (originalExtension && originalExtension != reinterpret_cast<void*>(&TraceConnectEx))
                {
                    g_connectEx = reinterpret_cast<ConnectExFn>(originalExtension);
                    *functionSlot = reinterpret_cast<void*>(&TraceConnectEx);
                    wrappedConnectEx = true;
                }
                else if (originalExtension == reinterpret_cast<void*>(&TraceConnectEx))
                {
                    wrappedConnectEx = true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                originalExtension = nullptr;
                wrappedConnectEx = false;
            }
        }

        TracePrint("WSAIoctl end module=%s socket=%llu code=0x%08lX result=%d wsa=%d win32=%lu bytesReturned=%s%lu extensionGuid=%s originalFn=%p wrappedConnectEx=%s passthrough=yes",
            callerModule, static_cast<unsigned long long>(socketValue), static_cast<unsigned long>(controlCode), result,
            resultWsa, static_cast<unsigned long>(resultWin32), returnedReadable ? "" : "<n/a>",
            static_cast<unsigned long>(returnedReadable ? returned : 0), guidText, originalExtension,
            wrappedConnectEx ? "yes" : "no");

        // WSAIoctl's status/error is preserved exactly. The only test instrumentation
        // change is replacing a successfully returned ConnectEx function pointer with
        // our passthrough logger; the logger immediately calls the real provider pointer.
        SetLastError(resultWin32);
        WSASetLastError(resultWsa);
        return result;
    }

    int WSAAPI TraceSelect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const timeval* timeout) noexcept
    {
        const unsigned readCount = FdSetCountSafe(readfds);
        const unsigned writeCount = FdSetCountSafe(writefds);
        const unsigned exceptCount = FdSetCountSafe(exceptfds);

        // IW8's nonblocking connect completion path is the interesting use of
        // select(). Avoid flooding the log with unrelated read-only polling.
        const bool traceThisCall = writeCount != 0 || exceptCount != 0;
        char callerModule[260]{};
        char readText[192]{};
        char writeText[192]{};
        char exceptText[192]{};
        if (traceThisCall)
        {
            ModuleNameFromAddress(_ReturnAddress(), callerModule, sizeof(callerModule));
            FormatFdSet(readfds, readText, sizeof(readText));
            FormatFdSet(writefds, writeText, sizeof(writeText));
            FormatFdSet(exceptfds, exceptText, sizeof(exceptText));
        }

        long timeoutSec = -1;
        long timeoutUsec = -1;
        if (timeout)
        {
            __try
            {
                timeoutSec = timeout->tv_sec;
                timeoutUsec = timeout->tv_usec;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                timeoutSec = -2;
                timeoutUsec = -2;
            }
        }

        const int incomingWsa = WSAGetLastError();
        const DWORD incomingWin32 = GetLastError();
        if (traceThisCall)
        {
            TracePrint("select begin module=%s nfds=%d read={%s} write={%s} except={%s} timeout=%ld.%06ld passthrough=yes",
                callerModule, nfds, readText, writeText, exceptText, timeoutSec, timeoutUsec);
        }
        SetLastError(incomingWin32);
        WSASetLastError(incomingWsa);

        const int result = g_select ? g_select(nfds, readfds, writefds, exceptfds, timeout) : SOCKET_ERROR;
        int resultWsa = WSAGetLastError();
        DWORD resultWin32 = GetLastError();
        if (!g_select)
            resultWsa = WSAEFAULT;

        if (traceThisCall)
        {
            FormatFdSet(readfds, readText, sizeof(readText));
            FormatFdSet(writefds, writeText, sizeof(writeText));
            FormatFdSet(exceptfds, exceptText, sizeof(exceptText));
            TracePrint("select end module=%s result=%d wsa=%d win32=%lu read={%s} write={%s} except={%s} passthrough=yes",
                callerModule, result, resultWsa, static_cast<unsigned long>(resultWin32), readText, writeText, exceptText);
        }
        SetLastError(resultWin32);
        WSASetLastError(resultWsa);
        return result;
    }

    bool RvaInImage(std::uintptr_t rva, std::size_t size, std::size_t imageSize) noexcept
    {
        return rva < imageSize && size <= imageSize - rva;
    }

    bool PatchImport(HMODULE module, const char* importedDll, const char* functionName, void* replacement) noexcept
    {
        if (!module || module == g_self || !importedDll || !functionName || !replacement)
            return false;

        const auto base = reinterpret_cast<std::uintptr_t>(module);
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;
            const auto ntRva = static_cast<std::uintptr_t>(dos->e_lfanew);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + ntRva);
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return false;

            const std::size_t imageSize = nt->OptionalHeader.SizeOfImage;
            const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!directory.VirtualAddress || !directory.Size ||
                !RvaInImage(directory.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR), imageSize))
                return false;

            auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
            for (; descriptor->Name; ++descriptor)
            {
                if (!RvaInImage(descriptor->Name, 1, imageSize))
                    return false;
                const char* dllName = reinterpret_cast<const char*>(base + descriptor->Name);
                if (!EqualsNoCase(dllName, importedDll))
                    continue;

                // Never treat a resolved FirstThunk as IMAGE_IMPORT_BY_NAME data.
                // If OriginalFirstThunk is absent, skip it instead of guessing.
                if (!descriptor->OriginalFirstThunk || !descriptor->FirstThunk)
                    return false;
                if (!RvaInImage(descriptor->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA64), imageSize) ||
                    !RvaInImage(descriptor->FirstThunk, sizeof(IMAGE_THUNK_DATA64), imageSize))
                    return false;

                auto* nameThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + descriptor->OriginalFirstThunk);
                auto* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + descriptor->FirstThunk);
                for (;; ++nameThunk, ++firstThunk)
                {
                    const auto nameThunkRva = reinterpret_cast<std::uintptr_t>(nameThunk) - base;
                    const auto firstThunkRva = reinterpret_cast<std::uintptr_t>(firstThunk) - base;
                    if (!RvaInImage(nameThunkRva, sizeof(*nameThunk), imageSize) ||
                        !RvaInImage(firstThunkRva, sizeof(*firstThunk), imageSize))
                        return false;
                    if (!nameThunk->u1.AddressOfData)
                        break;
                    if (IMAGE_SNAP_BY_ORDINAL64(nameThunk->u1.Ordinal))
                        continue;
                    if (!RvaInImage(nameThunk->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME), imageSize))
                        continue;
                    const auto* byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + nameThunk->u1.AddressOfData);
                    if (std::strcmp(reinterpret_cast<const char*>(byName->Name), functionName) != 0)
                        continue;

                    void** slot = reinterpret_cast<void**>(&firstThunk->u1.Function);
                    if (*slot == replacement)
                        return false;
                    DWORD oldProtect = 0;
                    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
                        return false;
                    *slot = replacement;
                    DWORD ignored = 0;
                    VirtualProtect(slot, sizeof(void*), oldProtect, &ignored);
                    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
                    return true;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return false;
    }

    bool ReadMainFingerprint(std::uint32_t& timestamp, std::uint32_t& imageSize, std::uint32_t& entryPoint) noexcept
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return false;

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return false;

            timestamp = nt->FileHeader.TimeDateStamp;
            imageSize = nt->OptionalHeader.SizeOfImage;
            entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    StartupCompatBuild DetectStartupCompatBuild(std::uint32_t timestamp, std::uint32_t imageSize,
        std::uint32_t entryPoint) noexcept
    {
        if (timestamp == kMW116Timestamp && imageSize == kMW116ImageSize && entryPoint == kMW116EntryPoint)
            return StartupCompatBuild::MW116;
        if (timestamp == kMW120Timestamp && imageSize == kMW120ImageSize && entryPoint == kMW120EntryPoint)
            return StartupCompatBuild::MW120;
        if (timestamp == kMW123Timestamp && imageSize == kMW123ImageSize && entryPoint == kMW123EntryPoint)
            return StartupCompatBuild::MW123;
        if (timestamp == kMW128Timestamp && imageSize == kMW128ImageSize && entryPoint == kMW128EntryPoint)
            return StartupCompatBuild::MW128;
        return StartupCompatBuild::None;
    }

    StartupCompatBuild CurrentStartupCompatBuild() noexcept
    {
        return static_cast<StartupCompatBuild>(InterlockedCompareExchange(&g_startupCompatBuild, 0, 0));
    }

    const char* StartupCompatBuildName(StartupCompatBuild build) noexcept
    {
        switch (build)
        {
        case StartupCompatBuild::MW116: return "1.16";
        case StartupCompatBuild::MW120: return "1.20";
        case StartupCompatBuild::MW123: return "1.23";
        case StartupCompatBuild::MW128: return "1.28";
        default: return "none";
        }
    }

    bool IsSupportedStartupCompatBuild() noexcept
    {
        return CurrentStartupCompatBuild() != StartupCompatBuild::None;
    }

    DWORD CompatWindowsBuild() noexcept
    {
        // 1.16 predates Windows 10 2004.  Running the launch-era executable while
        // advertising build 19041 changes several old bootstrap/version branches
        // before renderer initialization.  Keep newer preserved builds on the
        // existing 19041 compatibility target, but present 1.16 with the Windows
        // 10 1903-era build contemporaneous with this October 2019 executable.
        return CurrentStartupCompatBuild() == StartupCompatBuild::MW116 ? 18362u : kCompatBuild;
    }

    bool FullNetworkTraceRequested() noexcept
    {
        // Transport hooks are diagnostics only.  New/unknown retail builds can
        // resolve Winsock through provider-specific paths that are sensitive to
        // IAT/EAT wrapping, so make the invasive trace opt-in for those builds.
        char value[8]{};
        const DWORD count = GetEnvironmentVariableA(
            "CODREVAMPED_FULL_NET_TRACE", value, static_cast<DWORD>(sizeof(value)));
        return count != 0 && value[0] == '1';
    }

    bool MW116DeepTraceRequested() noexcept
    {
        char value[8]{};
        const DWORD count = GetEnvironmentVariableA(
            "CODREVAMPED_MW116_TRACE", value, static_cast<DWORD>(sizeof(value)));
        return count != 0 && value[0] == '1';
    }

    bool MW116ProductionMode() noexcept
    {
        return CurrentStartupCompatBuild() == StartupCompatBuild::MW116 && !MW116DeepTraceRequested();
    }

    bool MW123DeepTraceRequested() noexcept
    {
        char value[8]{};
        const DWORD count = GetEnvironmentVariableA(
            "CODREVAMPED_MW123_TRACE", value, static_cast<DWORD>(sizeof(value)));
        return count != 0 && value[0] == '1';
    }

    bool MW123ProductionMode() noexcept
    {
        return CurrentStartupCompatBuild() == StartupCompatBuild::MW123 && !MW123DeepTraceRequested();
    }

    bool UseDnsOnlyNetworkHooks() noexcept
    {
        const auto build = CurrentStartupCompatBuild();
        // Transport wrappers are diagnostic-only.  1.16 and 1.23 both run
        // old Battle.net/bootstrap code that is sensitive to Winsock IAT
        // replacement.  Keep those builds on DNS-only routing by default.
        // Full transport tracing remains opt-in for research.
        return (build == StartupCompatBuild::None ||
                build == StartupCompatBuild::MW116 ||
                build == StartupCompatBuild::MW123) &&
            !FullNetworkTraceRequested();
    }

    DWORD WINAPI CompatGetVersion() noexcept
    {
        // GetVersion encodes major/minor in LOWORD and the NT build in HIWORD.
        return (CompatWindowsBuild() << 16) | (kCompatMinor << 8) | kCompatMajor;
    }

    void FillCompatVersionA(LPOSVERSIONINFOA info) noexcept
    {
        if (!info)
            return;
        info->dwMajorVersion = kCompatMajor;
        info->dwMinorVersion = kCompatMinor;
        info->dwBuildNumber = CompatWindowsBuild();
        info->dwPlatformId = VER_PLATFORM_WIN32_NT;
        info->szCSDVersion[0] = '\0';

        if (info->dwOSVersionInfoSize >= sizeof(OSVERSIONINFOEXA))
        {
            auto* ex = reinterpret_cast<LPOSVERSIONINFOEXA>(info);
            ex->wServicePackMajor = 0;
            ex->wServicePackMinor = 0;
            ex->wSuiteMask = 0;
            ex->wProductType = VER_NT_WORKSTATION;
            ex->wReserved = 0;
        }
    }

    BOOL WINAPI CompatGetVersionExA(LPOSVERSIONINFOA info) noexcept
    {
        if (!info ||
            (info->dwOSVersionInfoSize != sizeof(OSVERSIONINFOA) &&
             info->dwOSVersionInfoSize != sizeof(OSVERSIONINFOEXA)))
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        if (g_realGetVersionExA)
            g_realGetVersionExA(info);
        FillCompatVersionA(info);
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }

    void FillCompatVersionW(LPOSVERSIONINFOW info) noexcept
    {
        if (!info)
            return;
        info->dwMajorVersion = kCompatMajor;
        info->dwMinorVersion = kCompatMinor;
        info->dwBuildNumber = CompatWindowsBuild();
        info->dwPlatformId = VER_PLATFORM_WIN32_NT;
        info->szCSDVersion[0] = L'\0';

        if (info->dwOSVersionInfoSize >= sizeof(OSVERSIONINFOEXW))
        {
            auto* ex = reinterpret_cast<LPOSVERSIONINFOEXW>(info);
            ex->wServicePackMajor = 0;
            ex->wServicePackMinor = 0;
            ex->wSuiteMask = 0;
            ex->wProductType = VER_NT_WORKSTATION;
            ex->wReserved = 0;
        }
    }

    BOOL WINAPI CompatGetVersionExW(LPOSVERSIONINFOW info) noexcept
    {
        if (!info ||
            (info->dwOSVersionInfoSize != sizeof(OSVERSIONINFOW) &&
             info->dwOSVersionInfoSize != sizeof(OSVERSIONINFOEXW)))
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        if (g_realGetVersionExW)
            g_realGetVersionExW(info);
        FillCompatVersionW(info);
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }

    LONG WINAPI CompatRtlGetVersion(CompatRtlOsVersionInfoW* info) noexcept
    {
        if (!info || info->dwOSVersionInfoSize < sizeof(CompatRtlOsVersionInfoW))
        {
            Write123StartupLog("[MW116-VERSION] RtlGetVersion invalid-buffer info=%p size=%lu\r\n",
                info, info ? static_cast<unsigned long>(info->dwOSVersionInfoSize) : 0ul);
            return static_cast<LONG>(0xC000000DL); // STATUS_INVALID_PARAMETER
        }

        // Do not call the host RtlGetVersion for the 1.16 compatibility path.
        // The whole point of this adapter is to give the 2019 binary one
        // deterministic OS view regardless of the Windows 11 host.
        info->dwMajorVersion = kCompatMajor;
        info->dwMinorVersion = kCompatMinor;
        info->dwBuildNumber = CompatWindowsBuild();
        info->dwPlatformId = VER_PLATFORM_WIN32_NT;
        info->szCSDVersion[0] = L'\0';
        Write123StartupLog("[MW116-VERSION] RtlGetVersion call -> 10.0.%lu status=0\r\n",
            static_cast<unsigned long>(CompatWindowsBuild()));
        return 0; // STATUS_SUCCESS
    }

    VOID WINAPI CompatRtlGetNtVersionNumbers(LPDWORD major, LPDWORD minor, LPDWORD build) noexcept
    {
        if (major) *major = kCompatMajor;
        if (minor) *minor = kCompatMinor;
        if (build) *build = CompatWindowsBuild();
    }

    bool IsProcNameString(LPCSTR name) noexcept
    {
        return reinterpret_cast<std::uintptr_t>(name) > 0xFFFFu;
    }

    BOOL WINAPI CompatVerifyVersionInfoA(LPOSVERSIONINFOEXA info, DWORD typeMask, DWORDLONG conditionMask) noexcept;
    BOOL WINAPI CompatVerifyVersionInfoW(LPOSVERSIONINFOEXW info, DWORD typeMask, DWORDLONG conditionMask) noexcept;
    VOID WINAPI Trace116RtlExitUserProcess(LONG status) noexcept;
    VOID WINAPI Trace116RtlExitUserThread(LONG status) noexcept;
    LONG WINAPI Trace116NtTerminateProcess(HANDLE process, LONG status) noexcept;
    LONG WINAPI Trace116NtRaiseHardError(LONG errorStatus, ULONG parameterCount, ULONG unicodeMask, PULONG_PTR parameters, ULONG responseOption, PULONG response) noexcept;
    VOID WINAPI Trace116RaiseFailFastException(PEXCEPTION_RECORD record, PCONTEXT context, DWORD flags) noexcept;

    FARPROC WINAPI Compat116GetProcAddress(HMODULE module, LPCSTR procName) noexcept
    {
        const StartupCompatBuild build = CurrentStartupCompatBuild();
        const bool versionCompatBuild =
            build == StartupCompatBuild::MW116 || build == StartupCompatBuild::MW123;
        if (versionCompatBuild && module && procName && IsProcNameString(procName))
        {
            HMODULE kernel32 = GetModuleHandleW(L"KERNEL32.dll");
            HMODULE kernelBase = GetModuleHandleW(L"KERNELBASE.dll");
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

            FARPROC replacement = nullptr;
            if (module == ntdll)
            {
                if (std::strcmp(procName, "RtlGetVersion") == 0)
                    replacement = reinterpret_cast<FARPROC>(&CompatRtlGetVersion);
                else if (std::strcmp(procName, "RtlGetNtVersionNumbers") == 0)
                    replacement = reinterpret_cast<FARPROC>(&CompatRtlGetNtVersionNumbers);
                else if (build == StartupCompatBuild::MW116 && MW116DeepTraceRequested() && std::strcmp(procName, "RtlExitUserProcess") == 0)
                    replacement = reinterpret_cast<FARPROC>(&Trace116RtlExitUserProcess);
                else if (build == StartupCompatBuild::MW116 && MW116DeepTraceRequested() && std::strcmp(procName, "RtlExitUserThread") == 0)
                    replacement = reinterpret_cast<FARPROC>(&Trace116RtlExitUserThread);
                else if (build == StartupCompatBuild::MW116 && MW116DeepTraceRequested() &&
                    (std::strcmp(procName, "NtTerminateProcess") == 0 || std::strcmp(procName, "ZwTerminateProcess") == 0))
                    replacement = reinterpret_cast<FARPROC>(&Trace116NtTerminateProcess);
                else if (build == StartupCompatBuild::MW116 && MW116DeepTraceRequested() && std::strcmp(procName, "NtRaiseHardError") == 0)
                    replacement = reinterpret_cast<FARPROC>(&Trace116NtRaiseHardError);
            }
            else if (module == kernel32 || module == kernelBase)
            {
                if (std::strcmp(procName, "GetVersion") == 0)
                    replacement = reinterpret_cast<FARPROC>(&CompatGetVersion);
                else if (std::strcmp(procName, "GetVersionExA") == 0)
                    replacement = reinterpret_cast<FARPROC>(&CompatGetVersionExA);
                else if (std::strcmp(procName, "GetVersionExW") == 0)
                    replacement = reinterpret_cast<FARPROC>(&CompatGetVersionExW);
                else if (std::strcmp(procName, "VerifyVersionInfoA") == 0)
                    replacement = reinterpret_cast<FARPROC>(&CompatVerifyVersionInfoA);
                else if (std::strcmp(procName, "VerifyVersionInfoW") == 0)
                    replacement = reinterpret_cast<FARPROC>(&CompatVerifyVersionInfoW);
                else if (build == StartupCompatBuild::MW116 && MW116DeepTraceRequested() && std::strcmp(procName, "RaiseFailFastException") == 0)
                    replacement = reinterpret_cast<FARPROC>(&Trace116RaiseFailFastException);
            }

            if (replacement)
            {
                Write123StartupLog("[COMPAT-VERSION] build=%s dynamic resolve %s -> compat target=10.0.%lu\r\n",
                    StartupCompatBuildName(build), procName, static_cast<unsigned long>(CompatWindowsBuild()));
                return replacement;
            }
        }
        return g_realGetProcAddress ? g_realGetProcAddress(module, procName) : nullptr;
    }

    BYTE VersionConditionFor(DWORDLONG mask, DWORD type) noexcept
    {
        DWORDLONG fieldMask = 0;
        for (BYTE condition = VER_EQUAL; condition <= VER_LESS_EQUAL; ++condition)
            fieldMask |= VerSetConditionMask(0, type, condition);

        const DWORDLONG field = mask & fieldMask;
        for (BYTE condition = VER_EQUAL; condition <= VER_LESS_EQUAL; ++condition)
        {
            if (field == VerSetConditionMask(0, type, condition))
                return condition;
        }
        return 0;
    }

    bool VersionCompare(ULONGLONG current, ULONGLONG requested, BYTE condition) noexcept
    {
        switch (condition)
        {
        case VER_EQUAL: return current == requested;
        case VER_GREATER: return current > requested;
        case VER_GREATER_EQUAL: return current >= requested;
        case VER_LESS: return current < requested;
        case VER_LESS_EQUAL: return current <= requested;
        default: return false;
        }
    }

    template <typename T>
    bool CompatVersionSatisfies(const T* requested, DWORD typeMask, DWORDLONG conditionMask) noexcept
    {
        if (!requested)
            return false;

        if (typeMask & VER_MAJORVERSION)
        {
            const BYTE c = VersionConditionFor(conditionMask, VER_MAJORVERSION);
            if (!c || !VersionCompare(kCompatMajor, requested->dwMajorVersion, c)) return false;
        }
        if (typeMask & VER_MINORVERSION)
        {
            const BYTE c = VersionConditionFor(conditionMask, VER_MINORVERSION);
            if (!c || !VersionCompare(kCompatMinor, requested->dwMinorVersion, c)) return false;
        }
        if (typeMask & VER_BUILDNUMBER)
        {
            const BYTE c = VersionConditionFor(conditionMask, VER_BUILDNUMBER);
            if (!c || !VersionCompare(CompatWindowsBuild(), requested->dwBuildNumber, c)) return false;
        }
        if (typeMask & VER_PLATFORMID)
        {
            const BYTE c = VersionConditionFor(conditionMask, VER_PLATFORMID);
            if (!c || !VersionCompare(VER_PLATFORM_WIN32_NT, requested->dwPlatformId, c)) return false;
        }
        if (typeMask & VER_PRODUCT_TYPE)
        {
            const BYTE c = VersionConditionFor(conditionMask, VER_PRODUCT_TYPE);
            if (!c || !VersionCompare(VER_NT_WORKSTATION, requested->wProductType, c)) return false;
        }
        if (typeMask & VER_SUITENAME)
            return false;
        return true;
    }

    BOOL WINAPI CompatVerifyVersionInfoA(LPOSVERSIONINFOEXA info, DWORD typeMask, DWORDLONG conditionMask) noexcept
    {
        if (g_realVerifyVersionInfoA && g_realVerifyVersionInfoA(info, typeMask, conditionMask))
            return TRUE;
        if (GetLastError() == ERROR_OLD_WIN_VERSION && CompatVersionSatisfies(info, typeMask, conditionMask))
        {
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }
        return FALSE;
    }

    BOOL WINAPI CompatVerifyVersionInfoW(LPOSVERSIONINFOEXW info, DWORD typeMask, DWORDLONG conditionMask) noexcept
    {
        if (g_realVerifyVersionInfoW && g_realVerifyVersionInfoW(info, typeMask, conditionMask))
            return TRUE;
        if (GetLastError() == ERROR_OLD_WIN_VERSION && CompatVersionSatisfies(info, typeMask, conditionMask))
        {
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }
        return FALSE;
    }


    void Write123StartupLog(const char* format, ...) noexcept
    {
        if (!format)
            return;

        char text[2048]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(text, sizeof(text), _TRUNCATE, format, args);
        va_end(args);

        wchar_t exePath[32768]{};
        constexpr size_t exePathCount = sizeof(exePath) / sizeof(exePath[0]);
        if (!GetModuleFileNameW(nullptr, exePath, static_cast<DWORD>(exePathCount)))
            return;
        wchar_t* slash = wcsrchr(exePath, L'\\');
        if (!slash)
            return;
        slash[1] = L'\0';
        const StartupCompatBuild build = CurrentStartupCompatBuild();
        if (build == StartupCompatBuild::MW116)
            wcscat_s(exePath, exePathCount, L"mw2019_116_startup.log");
        else if (build == StartupCompatBuild::MW120)
            wcscat_s(exePath, exePathCount, L"mw2019_120_startup.log");
        else if (build == StartupCompatBuild::MW128)
            wcscat_s(exePath, exePathCount, L"mw2019_128_startup.log");
        else
            wcscat_s(exePath, exePathCount, L"mw2019_123_startup.log");

        HANDLE file = CreateFileW(exePath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;
        DWORD written = 0;
        WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        CloseHandle(file);
    }

    bool ContainsNoCase(const char* text, const char* needle) noexcept
    {
        if (!text || !needle || !*needle)
            return false;
        const std::size_t needleLen = std::strlen(needle);
        for (const char* p = text; *p; ++p)
        {
            if (_strnicmp(p, needle, needleLen) == 0)
                return true;
        }
        return false;
    }

    bool EqualsPathNoCase(const char* text, const char* expected) noexcept
    {
        if (!text || !expected)
            return false;
        while (*text == '\\')
            ++text;
        while (*expected == '\\')
            ++expected;
        return _stricmp(text, expected) == 0;
    }

    bool EqualsPathNoCase(const wchar_t* text, const wchar_t* expected) noexcept
    {
        if (!text || !expected)
            return false;
        while (*text == L'\\')
            ++text;
        while (*expected == L'\\')
            ++expected;
        return _wcsicmp(text, expected) == 0;
    }

    LPSTR WINAPI CompatGetCommandLineA() noexcept
    {
        if (g_compat123CommandLine[0])
            return g_compat123CommandLine;
        return g_realGetCommandLineA ? g_realGetCommandLineA() : const_cast<LPSTR>("");
    }

    LPWSTR WINAPI CompatGetCommandLineW() noexcept
    {
        if (g_compat123CommandLineW[0])
            return g_compat123CommandLineW;
        return g_realGetCommandLineW ? g_realGetCommandLineW() : const_cast<LPWSTR>(L"");
    }

    bool IsFakeLaunchKey(HKEY key) noexcept
    {
        return key == g_fakeLaunchOptionsKey || key == g_fakeOdinKey;
    }

    LSTATUS WINAPI CompatRegOpenKeyExA(HKEY key, LPCSTR subKey, DWORD options, REGSAM sam, PHKEY result) noexcept
    {
        if (!result)
            return ERROR_INVALID_PARAMETER;

        constexpr const char* kBase = "Software\\Blizzard Entertainment\\Battle.net\\Launch Options";
        constexpr const char* kOdin = "Software\\Blizzard Entertainment\\Battle.net\\Launch Options\\ODIN";

        if (key == HKEY_CURRENT_USER && subKey)
        {
            if (EqualsPathNoCase(subKey, kOdin))
            {
                *result = g_fakeOdinKey;
                Write123StartupLog("[REG] RegOpenKeyExA synthesized HKCU\\%s -> ODIN\r\n", subKey);
                return ERROR_SUCCESS;
            }
            if (EqualsPathNoCase(subKey, kBase))
            {
                *result = g_fakeLaunchOptionsKey;
                Write123StartupLog("[REG] RegOpenKeyExA synthesized HKCU\\%s -> LaunchOptions\r\n", subKey);
                return ERROR_SUCCESS;
            }
        }
        if (key == g_fakeLaunchOptionsKey && subKey && _stricmp(subKey, "ODIN") == 0)
        {
            *result = g_fakeOdinKey;
            Write123StartupLog("[REG] RegOpenKeyExA synthesized LaunchOptions\\ODIN\r\n");
            return ERROR_SUCCESS;
        }

        return g_realRegOpenKeyExA ? g_realRegOpenKeyExA(key, subKey, options, sam, result) : ERROR_FILE_NOT_FOUND;
    }

    LSTATUS WINAPI CompatRegOpenKeyExW(HKEY key, LPCWSTR subKey, DWORD options, REGSAM sam, PHKEY result) noexcept
    {
        if (!result)
            return ERROR_INVALID_PARAMETER;

        constexpr const wchar_t* kBase = L"Software\\Blizzard Entertainment\\Battle.net\\Launch Options";
        constexpr const wchar_t* kOdin = L"Software\\Blizzard Entertainment\\Battle.net\\Launch Options\\ODIN";

        if (key == HKEY_CURRENT_USER && subKey)
        {
            if (EqualsPathNoCase(subKey, kOdin))
            {
                *result = g_fakeOdinKey;
                Write123StartupLog("[REG] RegOpenKeyExW synthesized ODIN key\r\n");
                return ERROR_SUCCESS;
            }
            if (EqualsPathNoCase(subKey, kBase))
            {
                *result = g_fakeLaunchOptionsKey;
                Write123StartupLog("[REG] RegOpenKeyExW synthesized LaunchOptions key\r\n");
                return ERROR_SUCCESS;
            }
        }
        if (key == g_fakeLaunchOptionsKey && subKey && _wcsicmp(subKey, L"ODIN") == 0)
        {
            *result = g_fakeOdinKey;
            Write123StartupLog("[REG] RegOpenKeyExW synthesized LaunchOptions\\ODIN\r\n");
            return ERROR_SUCCESS;
        }

        return g_realRegOpenKeyExW ? g_realRegOpenKeyExW(key, subKey, options, sam, result) : ERROR_FILE_NOT_FOUND;
    }

    LSTATUS CopyFakeRegBytes(DWORD type, const void* bytes, DWORD byteCount, LPDWORD reserved, LPDWORD outType,
        LPBYTE data, LPDWORD dataSize) noexcept
    {
        if (reserved)
            *reserved = 0;
        if (outType)
            *outType = type;
        if (!dataSize)
            return ERROR_SUCCESS;

        const DWORD capacity = *dataSize;
        *dataSize = byteCount;
        if (!data)
            return ERROR_SUCCESS;
        if (capacity < byteCount)
            return ERROR_MORE_DATA;

        if (byteCount)
            std::memcpy(data, bytes, byteCount);
        return ERROR_SUCCESS;
    }

    LSTATUS FakeOdinValueA(LPCSTR valueName, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD dataSize) noexcept
    {
        if (!valueName)
            return ERROR_FILE_NOT_FOUND;

        struct StringValue { const char* name; const char* value; };
        static const StringValue values[] = {
            { "REGION", "US" },
            { "LOCALE", "enUS" },
            { "LOCALE_AUDIO", "enUS" },
            { "GAME_ACCOUNT", "" },
            { "LAUNCH_64BIT", "0" },
            { "ACCOUNT", "revamped-local" },
            { "ACCOUNT_TS", "0" }
        };

        if (_stricmp(valueName, "WEB_TOKEN") == 0)
        {
            Write123StartupLog("[REG] WEB_TOKEN -> local DPAPI shim marker bytes=%u\r\n",
                static_cast<unsigned>(sizeof(g_fakeWebTokenBlob)));
            return CopyFakeRegBytes(REG_BINARY, g_fakeWebTokenBlob, static_cast<DWORD>(sizeof(g_fakeWebTokenBlob)),
                reserved, type, data, dataSize);
        }

        for (const auto& item : values)
        {
            if (_stricmp(valueName, item.name) == 0)
            {
                const DWORD bytes = static_cast<DWORD>(std::strlen(item.value) + 1);
                Write123StartupLog("[REG] %s -> '%s'\r\n", item.name, item.value);
                return CopyFakeRegBytes(REG_SZ, item.value, bytes, reserved, type, data, dataSize);
            }
        }

        Write123StartupLog("[REG] unknown ODIN value requested: %s\r\n", valueName);
        return ERROR_FILE_NOT_FOUND;
    }

    LSTATUS FakeOdinValueW(LPCWSTR valueName, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD dataSize) noexcept
    {
        if (!valueName)
            return ERROR_FILE_NOT_FOUND;

        if (_wcsicmp(valueName, L"WEB_TOKEN") == 0)
        {
            Write123StartupLog("[REG] WEB_TOKEN(W) -> local DPAPI shim marker bytes=%u\r\n",
                static_cast<unsigned>(sizeof(g_fakeWebTokenBlob)));
            return CopyFakeRegBytes(REG_BINARY, g_fakeWebTokenBlob, static_cast<DWORD>(sizeof(g_fakeWebTokenBlob)),
                reserved, type, data, dataSize);
        }

        struct StringValueW { const wchar_t* name; const wchar_t* value; };
        static const StringValueW values[] = {
            { L"REGION", L"US" },
            { L"LOCALE", L"enUS" },
            { L"LOCALE_AUDIO", L"enUS" },
            { L"GAME_ACCOUNT", L"" },
            { L"LAUNCH_64BIT", L"0" },
            { L"ACCOUNT", L"revamped-local" },
            { L"ACCOUNT_TS", L"0" }
        };

        for (const auto& item : values)
        {
            if (_wcsicmp(valueName, item.name) == 0)
            {
                const DWORD bytes = static_cast<DWORD>((std::wcslen(item.value) + 1) * sizeof(wchar_t));
                Write123StartupLog("[REG] synthesized wide ODIN launch value\r\n");
                return CopyFakeRegBytes(REG_SZ, item.value, bytes, reserved, type, data, dataSize);
            }
        }
        return ERROR_FILE_NOT_FOUND;
    }

    LSTATUS WINAPI CompatRegQueryValueExA(HKEY key, LPCSTR valueName, LPDWORD reserved, LPDWORD type,
        LPBYTE data, LPDWORD dataSize) noexcept
    {
        if (key == g_fakeOdinKey)
            return FakeOdinValueA(valueName, reserved, type, data, dataSize);
        return g_realRegQueryValueExA ? g_realRegQueryValueExA(key, valueName, reserved, type, data, dataSize) : ERROR_FILE_NOT_FOUND;
    }

    LSTATUS WINAPI CompatRegQueryValueExW(HKEY key, LPCWSTR valueName, LPDWORD reserved, LPDWORD type,
        LPBYTE data, LPDWORD dataSize) noexcept
    {
        if (key == g_fakeOdinKey)
            return FakeOdinValueW(valueName, reserved, type, data, dataSize);
        return g_realRegQueryValueExW ? g_realRegQueryValueExW(key, valueName, reserved, type, data, dataSize) : ERROR_FILE_NOT_FOUND;
    }

    LSTATUS WINAPI CompatRegCloseKey(HKEY key) noexcept
    {
        if (IsFakeLaunchKey(key))
            return ERROR_SUCCESS;
        return g_realRegCloseKey ? g_realRegCloseKey(key) : ERROR_SUCCESS;
    }

    BOOL WINAPI CompatCryptUnprotectData(DATA_BLOB* dataIn, LPWSTR* description, DATA_BLOB* optionalEntropy,
        PVOID reserved, CRYPTPROTECT_PROMPTSTRUCT* prompt, DWORD flags, DATA_BLOB* dataOut) noexcept
    {
        if (dataIn && dataOut && dataIn->cbData == sizeof(g_fakeWebTokenBlob) && dataIn->pbData &&
            std::memcmp(dataIn->pbData, g_fakeWebTokenBlob, sizeof(g_fakeWebTokenBlob)) == 0)
        {
            static const char kLocalToken[] = "revamped-local-web-token";
            const DWORD tokenBytes = static_cast<DWORD>(sizeof(kLocalToken) - 1);
            BYTE* output = static_cast<BYTE*>(LocalAlloc(LPTR, tokenBytes));
            if (!output)
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return FALSE;
            }
            std::memcpy(output, kLocalToken, tokenBytes);
            dataOut->pbData = output;
            dataOut->cbData = tokenBytes;
            if (description)
                *description = nullptr;
            Write123StartupLog("[DPAPI] decoded local WEB_TOKEN marker to local-only token bytes=%lu\r\n",
                static_cast<unsigned long>(tokenBytes));
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }

        return g_realCryptUnprotectData ?
            g_realCryptUnprotectData(dataIn, description, optionalEntropy, reserved, prompt, flags, dataOut) : FALSE;
    }

    VOID WINAPI Trace123ExitProcess(UINT exitCode) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        Write123StartupLog("[EXIT] ExitProcess code=%u caller=%p module=%s\r\n",
            exitCode, _ReturnAddress(), moduleName);
        if (g_realExitProcess)
            g_realExitProcess(exitCode);
    }

    BOOL WINAPI Trace123TerminateProcess(HANDLE process, UINT exitCode) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        Write123StartupLog("[EXIT] TerminateProcess process=%p code=%u caller=%p module=%s\r\n",
            process, exitCode, _ReturnAddress(), moduleName);
        return g_realTerminateProcess ? g_realTerminateProcess(process, exitCode) : FALSE;
    }

    VOID WINAPI Trace123RaiseException(DWORD code, DWORD flags, DWORD count, const ULONG_PTR* args) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        Write123StartupLog("[EXCEPTION] RaiseException code=0x%08lX flags=0x%08lX args=%lu caller=%p module=%s\r\n",
            static_cast<unsigned long>(code), static_cast<unsigned long>(flags),
            static_cast<unsigned long>(count), _ReturnAddress(), moduleName);
        if (g_realRaiseException)
            g_realRaiseException(code, flags, count, args);
    }

    VOID WINAPI Trace123ExitThread(DWORD exitCode) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        Write123StartupLog("[EXIT] ExitThread tid=%lu code=%lu caller=%p module=%s\r\n",
            static_cast<unsigned long>(GetCurrentThreadId()), static_cast<unsigned long>(exitCode),
            _ReturnAddress(), moduleName);
        if (g_realExitThread)
            g_realExitThread(exitCode);
    }

    VOID WINAPI Trace123FreeLibraryAndExitThread(HMODULE module, DWORD exitCode) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        Write123StartupLog("[EXIT] FreeLibraryAndExitThread target=%p tid=%lu code=%lu caller=%p module=%s\r\n",
            module, static_cast<unsigned long>(GetCurrentThreadId()), static_cast<unsigned long>(exitCode),
            _ReturnAddress(), moduleName);
        if (g_realFreeLibraryAndExitThread)
            g_realFreeLibraryAndExitThread(module, exitCode);
    }

    bool IsAddressInMainImage(std::uintptr_t address, std::uintptr_t* outRva = nullptr) noexcept
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base)
            return false;

        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;
        if (!ReadMainFingerprint(timestamp, imageSize, entryPoint))
            return false;

        if (address < base || address >= base + static_cast<std::uintptr_t>(imageSize))
            return false;

        if (outRva)
            *outRva = address - base;
        return true;
    }

    bool TryRecover123NullExecute(PEXCEPTION_POINTERS info) noexcept
    {
#if !defined(_M_X64)
        (void)info;
        return false;
#else
        if (!info || !info->ExceptionRecord || !info->ContextRecord || !IsSupportedStartupCompatBuild())
            return false;

        const auto* record = info->ExceptionRecord;
        if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
            record->NumberParameters < 2 ||
            record->ExceptionInformation[0] != 8 ||
            record->ExceptionInformation[1] != 0 ||
            info->ContextRecord->Rip != 0)
            return false;

        const auto rsp = static_cast<std::uintptr_t>(info->ContextRecord->Rsp);
        if (!rsp)
            return false;

        std::uintptr_t returnAddress = 0;
        __try
        {
            returnAddress = *reinterpret_cast<const std::uintptr_t*>(rsp);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        std::uintptr_t returnRva = 0;
        if (!IsAddressInMainImage(returnAddress, &returnRva))
        {
            char returnModule[MAX_PATH]{};
            ModuleNameFromAddress(reinterpret_cast<void*>(returnAddress), returnModule, sizeof(returnModule));
            Write123StartupLog("[NULLCALL-%s] execute-null NOT recovered rsp=0x%llX stackReturn=%p module=%s reason=return-not-in-main-image\r\n",
                StartupCompatBuildName(CurrentStartupCompatBuild()),
                static_cast<unsigned long long>(rsp), reinterpret_cast<void*>(returnAddress), returnModule);
            return false;
        }

        const LONG recovery = InterlockedIncrement(&g_compat123NullExecRecoveries);
        if (recovery > 8)
        {
            Write123StartupLog("[NULLCALL-%s] execute-null NOT recovered recovery=%ld returnRva=0x%llX reason=recovery-limit\r\n",
                StartupCompatBuildName(CurrentStartupCompatBuild()),
                static_cast<long>(recovery), static_cast<unsigned long long>(returnRva));
            return false;
        }

        Write123StartupLog("[NULLCALL-%s] recovery=%ld execute-null rsp=0x%llX stackReturn=%p returnRva=0x%llX action=simulate-ret-return-zero\r\n",
            StartupCompatBuildName(CurrentStartupCompatBuild()),
            static_cast<long>(recovery), static_cast<unsigned long long>(rsp),
            reinterpret_cast<void*>(returnAddress), static_cast<unsigned long long>(returnRva));

        info->ContextRecord->Rip = static_cast<DWORD64>(returnAddress);
        info->ContextRecord->Rsp += sizeof(std::uintptr_t);
        info->ContextRecord->Rax = 0;
        return true;
#endif
    }

    LONG CALLBACK Trace123VectoredException(PEXCEPTION_POINTERS info) noexcept
    {
        if (!info || !info->ExceptionRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        if (TryRecover123NullExecute(info))
            return EXCEPTION_CONTINUE_EXECUTION;

        // 1.23 production mode keeps this VEH installed only because the
        // preserved executable makes one known execute-null bootstrap call
        // that must be recovered.  Do not perform file/module/CRT work from
        // unrelated first-chance exceptions; that instrumentation is research
        // only and can perturb the old runtime while it is already unwinding.
        if (MW123ProductionMode())
            return EXCEPTION_CONTINUE_SEARCH;

        const LONG seen = InterlockedIncrement(&g_compat123VehCount);
        const DWORD code = info->ExceptionRecord->ExceptionCode;
        // Preserve the stock diagnostic text as well as its exception envelope.
        // Do not consume the exception or alter the game's result/state.
        if (code == 0x40010006u && info->ExceptionRecord->NumberParameters >= 2 &&
            InterlockedCompareExchange(&g_compat123VehGuard, 1, 0) == 0)
        {
            char debugText[2048]{};
            __try
            {
                const auto length = info->ExceptionRecord->ExceptionInformation[0];
                const auto source = reinterpret_cast<const char*>(info->ExceptionRecord->ExceptionInformation[1]);
                const auto count = length < sizeof(debugText) ? length : sizeof(debugText) - 1;
                if (source && count) std::memcpy(debugText, source, count);
                debugText[sizeof(debugText) - 1] = '\0';
                Write123StartupLog("[STOCK-DEBUG] %s\r\n", debugText);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            InterlockedExchange(&g_compat123VehGuard, 0);
        }
        const bool important =
            code == EXCEPTION_ACCESS_VIOLATION ||
            code == EXCEPTION_ILLEGAL_INSTRUCTION ||
            code == EXCEPTION_PRIV_INSTRUCTION ||
            code == EXCEPTION_STACK_OVERFLOW ||
            code == 0xC0000409u || /* STATUS_STACK_BUFFER_OVERRUN / fail-fast */
            code == 0xC000001Du;  /* STATUS_ILLEGAL_INSTRUCTION */

        if ((seen <= 24 || important) && InterlockedCompareExchange(&g_compat123VehGuard, 1, 0) == 0)
        {
            void* rip = info->ExceptionRecord->ExceptionAddress;
            unsigned long long rsp = 0;
#if defined(_M_X64)
            if (info->ContextRecord)
            {
                rip = reinterpret_cast<void*>(info->ContextRecord->Rip);
                rsp = static_cast<unsigned long long>(info->ContextRecord->Rsp);
            }
#endif
            char moduleName[MAX_PATH]{};
            ModuleNameFromAddress(rip, moduleName, sizeof(moduleName));
            Write123StartupLog("[VEH] firstChance=%ld code=0x%08lX flags=0x%08lX address=%p rsp=0x%llX module=%s params=%lu\r\n",
                static_cast<long>(seen), static_cast<unsigned long>(code),
                static_cast<unsigned long>(info->ExceptionRecord->ExceptionFlags), rip, rsp,
                moduleName, static_cast<unsigned long>(info->ExceptionRecord->NumberParameters));
            if (code == EXCEPTION_ACCESS_VIOLATION && info->ExceptionRecord->NumberParameters >= 2)
            {
                Write123StartupLog("[VEH] accessViolation operation=%llu target=0x%llX\r\n",
                    static_cast<unsigned long long>(info->ExceptionRecord->ExceptionInformation[0]),
                    static_cast<unsigned long long>(info->ExceptionRecord->ExceptionInformation[1]));
            }
            InterlockedExchange(&g_compat123VehGuard, 0);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    VOID WINAPI Trace116RtlExitUserProcess(LONG status) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        std::uintptr_t rva = 0;
        IsAddressInMainImage(reinterpret_cast<std::uintptr_t>(_ReturnAddress()), &rva);
        Write123StartupLog("[MW116-EXIT] RtlExitUserProcess status=0x%08lX caller=%p module=%s callerRva=0x%llX\r\n",
            static_cast<unsigned long>(status), _ReturnAddress(), moduleName, static_cast<unsigned long long>(rva));
        if (g_realRtlExitUserProcess)
            g_realRtlExitUserProcess(status);
    }

    VOID WINAPI Trace116RtlExitUserThread(LONG status) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        Write123StartupLog("[MW116-EXIT] RtlExitUserThread tid=%lu status=0x%08lX caller=%p module=%s\r\n",
            static_cast<unsigned long>(GetCurrentThreadId()), static_cast<unsigned long>(status),
            _ReturnAddress(), moduleName);
        if (g_realRtlExitUserThread)
            g_realRtlExitUserThread(status);
    }

    LONG WINAPI Trace116NtTerminateProcess(HANDLE process, LONG status) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        std::uintptr_t rva = 0;
        IsAddressInMainImage(reinterpret_cast<std::uintptr_t>(_ReturnAddress()), &rva);
        Write123StartupLog("[MW116-EXIT] NtTerminateProcess process=%p status=0x%08lX caller=%p module=%s callerRva=0x%llX\r\n",
            process, static_cast<unsigned long>(status), _ReturnAddress(), moduleName,
            static_cast<unsigned long long>(rva));
        return g_realNtTerminateProcess ? g_realNtTerminateProcess(process, status) : static_cast<LONG>(0xC0000002L);
    }

    LONG WINAPI Trace116NtRaiseHardError(LONG errorStatus, ULONG parameterCount, ULONG unicodeMask,
        PULONG_PTR parameters, ULONG responseOption, PULONG response) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        Write123StartupLog("[MW116-EXIT] NtRaiseHardError status=0x%08lX params=%lu option=%lu caller=%p module=%s\r\n",
            static_cast<unsigned long>(errorStatus), static_cast<unsigned long>(parameterCount),
            static_cast<unsigned long>(responseOption), _ReturnAddress(), moduleName);
        return g_realNtRaiseHardError ? g_realNtRaiseHardError(errorStatus, parameterCount, unicodeMask, parameters, responseOption, response)
            : static_cast<LONG>(0xC0000002L);
    }

    VOID WINAPI Trace116RaiseFailFastException(PEXCEPTION_RECORD record, PCONTEXT context, DWORD flags) noexcept
    {
        char moduleName[MAX_PATH]{};
        ModuleNameFromAddress(_ReturnAddress(), moduleName, sizeof(moduleName));
        Write123StartupLog("[MW116-EXIT] RaiseFailFastException code=0x%08lX flags=0x%08lX caller=%p module=%s\r\n",
            static_cast<unsigned long>(record ? record->ExceptionCode : 0), static_cast<unsigned long>(flags),
            _ReturnAddress(), moduleName);
        if (g_realRaiseFailFastException)
            g_realRaiseFailFastException(record, context, flags);
    }

    LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Trace123SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER filter) noexcept
    {
        Write123StartupLog("[EXCEPTION] SetUnhandledExceptionFilter filter=%p caller=%p\r\n", filter, _ReturnAddress());
        return g_realSetUnhandledExceptionFilter ? g_realSetUnhandledExceptionFilter(filter) : nullptr;
    }

    LONG WINAPI Trace123UnhandledExceptionFilter(PEXCEPTION_POINTERS info) noexcept
    {
        const DWORD code = (info && info->ExceptionRecord) ? info->ExceptionRecord->ExceptionCode : 0;
        const void* address = (info && info->ExceptionRecord) ? info->ExceptionRecord->ExceptionAddress : nullptr;
        Write123StartupLog("[EXCEPTION] UnhandledExceptionFilter code=0x%08lX address=%p caller=%p\r\n",
            static_cast<unsigned long>(code), address, _ReturnAddress());
        return g_realUnhandledExceptionFilter ? g_realUnhandledExceptionFilter(info) : EXCEPTION_CONTINUE_SEARCH;
    }

    bool IsStockSafeModePrompt(const char* text, const char* caption) noexcept
    {
        return text && caption &&
            std::strstr(text, "did not quit properly") != nullptr &&
            std::strstr(text, "safe mode") != nullptr &&
            std::strstr(caption, "Safe Mode") != nullptr;
    }

    bool IsStockSafeModePrompt(const wchar_t* text, const wchar_t* caption) noexcept
    {
        return text && caption &&
            std::wcsstr(text, L"did not quit properly") != nullptr &&
            std::wcsstr(text, L"safe mode") != nullptr &&
            std::wcsstr(caption, L"Safe Mode") != nullptr;
    }

    int WINAPI CompatMessageBoxA(HWND owner, LPCSTR text, LPCSTR caption, UINT type) noexcept
    {
        if ((type & MB_TYPEMASK) == MB_YESNO && text && caption &&
            std::strcmp(caption, "Recommended Settings Updated") == 0 &&
            std::strstr(text, "configure itself optimally with these new settings"))
        {
            if (CurrentStartupCompatBuild() == StartupCompatBuild::MW116)
            {
                Write123StartupLog("[SETTINGS-PROMPT] build=1.16 recommended-settings update accepted result=IDYES reason=startup-recovery\r\n");
                return IDYES;
            }
            Write123StartupLog("[SETTINGS-PROMPT] recommended-settings update declined result=IDNO settingsUntouched=yes\r\n");
            return IDNO;
        }
        if (IsStockSafeModePrompt(text, caption))
        {
            if (CurrentStartupCompatBuild() == StartupCompatBuild::MW116)
            {
                Write123StartupLog("[SAFE-MODE] build=1.16 stock previous-run prompt auto-accepted api=MessageBoxA result=IDYES action=reset-safe-startup-settings\r\n");
                return IDYES;
            }
            Write123StartupLog("[SAFE-MODE] stock previous-run prompt auto-declined api=MessageBoxA result=IDNO settingsUntouched=yes\r\n");
            return IDNO;
        }
        Write123StartupLog("[STOCK-DIALOG] api=MessageBoxA type=0x%X caption=%s text=%s action=unchanged\r\n",
            type, caption ? caption : "", text ? text : "");
        return g_realMessageBoxA ? g_realMessageBoxA(owner, text, caption, type) : 0;
    }

    int WINAPI CompatMessageBoxW(HWND owner, LPCWSTR text, LPCWSTR caption, UINT type) noexcept
    {
        if ((type & MB_TYPEMASK) == MB_YESNO && text && caption &&
            std::wcscmp(caption, L"Recommended Settings Updated") == 0 &&
            std::wcsstr(text, L"configure itself optimally with these new settings"))
        {
            if (CurrentStartupCompatBuild() == StartupCompatBuild::MW116)
            {
                Write123StartupLog("[SETTINGS-PROMPT] build=1.16 recommended-settings update accepted result=IDYES reason=startup-recovery\r\n");
                return IDYES;
            }
            Write123StartupLog("[SETTINGS-PROMPT] recommended-settings update declined result=IDNO settingsUntouched=yes\r\n");
            return IDNO;
        }
        if (IsStockSafeModePrompt(text, caption))
        {
            if (CurrentStartupCompatBuild() == StartupCompatBuild::MW116)
            {
                Write123StartupLog("[SAFE-MODE] build=1.16 stock previous-run prompt auto-accepted api=MessageBoxW result=IDYES action=reset-safe-startup-settings\r\n");
                return IDYES;
            }
            Write123StartupLog("[SAFE-MODE] stock previous-run prompt auto-declined api=MessageBoxW result=IDNO settingsUntouched=yes\r\n");
            return IDNO;
        }
        Write123StartupLog("[STOCK-DIALOG] api=MessageBoxW type=0x%X caption=%ls text=%ls action=unchanged\r\n",
            type, caption ? caption : L"", text ? text : L"");
        return g_realMessageBoxW ? g_realMessageBoxW(owner, text, caption, type) : 0;
    }

    void Install123StartupCompatibility() noexcept
    {
        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;
        const bool fingerprintOk = ReadMainFingerprint(timestamp, imageSize, entryPoint);
        if (fingerprintOk)
        {
            g_liveTimestamp = timestamp;
            g_liveImageSize = imageSize;
            g_liveEntryPoint = entryPoint;
            InterlockedExchange(&g_liveFingerprintValid, 1);
        }

        const StartupCompatBuild build = fingerprintOk ?
            DetectStartupCompatBuild(timestamp, imageSize, entryPoint) : StartupCompatBuild::None;
        InterlockedExchange(&g_startupCompatBuild, static_cast<LONG>(build));

        Write123StartupLog("[BOOT] live fingerprint ok=%s timestamp=0x%08X imageSize=0x%08X entryPoint=0x%08X startupCompat=%s\r\n",
            fingerprintOk ? "yes" : "no", timestamp, imageSize, entryPoint, StartupCompatBuildName(build));

        if (build == StartupCompatBuild::None)
        {
            // Exact retail profiles use only the existing dialog handlers,
            // never the older builds' OS/launcher compatibility hooks.
            const bool retail144 = fingerprintOk && timestamp == 0x61671CE8u &&
                imageSize == 0x22C1BA00u && entryPoint == 0x06D429F8u;
            const bool retailSteam = fingerprintOk && timestamp == 0x69DD404Eu &&
                imageSize == 0x21679200u && entryPoint == 0x06E4931Cu;
            if (retail144 || retailSteam)
            {
                HMODULE user32 = GetModuleHandleW(L"user32.dll");
                if (!user32) user32 = LoadLibraryW(L"user32.dll");
                if (user32)
                {
                    g_realMessageBoxA = reinterpret_cast<MessageBoxAFn>(GetProcAddress(user32, "MessageBoxA"));
                    g_realMessageBoxW = reinterpret_cast<MessageBoxWFn>(GetProcAddress(user32, "MessageBoxW"));
                    const unsigned patched =
                        (PatchImport(GetModuleHandleW(nullptr), "USER32.dll", "MessageBoxA", reinterpret_cast<void*>(&CompatMessageBoxA)) ? 1u : 0u) +
                        (PatchImport(GetModuleHandleW(nullptr), "USER32.dll", "MessageBoxW", reinterpret_cast<void*>(&CompatMessageBoxW)) ? 1u : 0u);
                    Write123StartupLog("[%s-PROMPT] exact-text handlers=%u/2 settings-preserved=yes\r\n",
                        retailSteam ? "STEAM-RETAIL" : "MW144", patched);
                }
            }
            return;
        }

        InterlockedExchange(&g_compat123Detected, 1);

        HMODULE kernel32 = GetModuleHandleW(L"KERNEL32.dll");
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        HMODULE advapi32 = GetModuleHandleW(L"ADVAPI32.dll");
        HMODULE crypt32 = GetModuleHandleW(L"CRYPT32.dll");
        HMODULE user32 = GetModuleHandleW(L"USER32.dll");
        if (!user32)
            user32 = LoadLibraryW(L"USER32.dll");
        HMODULE mainModule = GetModuleHandleW(nullptr);
        if (!kernel32 || !advapi32 || !mainModule)
            return;

        g_realGetProcAddress = reinterpret_cast<GetProcAddressFn>(GetProcAddress(kernel32, "GetProcAddress"));
        g_realGetVersion = reinterpret_cast<GetVersionFn>(GetProcAddress(kernel32, "GetVersion"));
        g_realGetVersionExA = reinterpret_cast<GetVersionExAFn>(GetProcAddress(kernel32, "GetVersionExA"));
        g_realGetVersionExW = reinterpret_cast<GetVersionExWFn>(GetProcAddress(kernel32, "GetVersionExW"));
        if (ntdll)
        {
            g_realRtlGetVersion = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
            g_realRtlGetNtVersionNumbers = reinterpret_cast<RtlGetNtVersionNumbersFn>(GetProcAddress(ntdll, "RtlGetNtVersionNumbers"));
            g_realRtlExitUserProcess = reinterpret_cast<RtlExitUserProcessFn>(GetProcAddress(ntdll, "RtlExitUserProcess"));
            g_realRtlExitUserThread = reinterpret_cast<RtlExitUserThreadFn>(GetProcAddress(ntdll, "RtlExitUserThread"));
            g_realNtTerminateProcess = reinterpret_cast<NtTerminateProcessFn>(GetProcAddress(ntdll, "NtTerminateProcess"));
            g_realNtRaiseHardError = reinterpret_cast<NtRaiseHardErrorFn>(GetProcAddress(ntdll, "NtRaiseHardError"));
        }
        g_realVerifyVersionInfoA = reinterpret_cast<VerifyVersionInfoAFn>(GetProcAddress(kernel32, "VerifyVersionInfoA"));
        g_realVerifyVersionInfoW = reinterpret_cast<VerifyVersionInfoWFn>(GetProcAddress(kernel32, "VerifyVersionInfoW"));
        g_realGetCommandLineA = reinterpret_cast<GetCommandLineAFn>(GetProcAddress(kernel32, "GetCommandLineA"));
        g_realGetCommandLineW = reinterpret_cast<GetCommandLineWFn>(GetProcAddress(kernel32, "GetCommandLineW"));
        g_realExitProcess = reinterpret_cast<ExitProcessFn>(GetProcAddress(kernel32, "ExitProcess"));
        g_realTerminateProcess = reinterpret_cast<TerminateProcessFn>(GetProcAddress(kernel32, "TerminateProcess"));
        g_realRaiseException = reinterpret_cast<RaiseExceptionFn>(GetProcAddress(kernel32, "RaiseException"));
        g_realExitThread = reinterpret_cast<ExitThreadFn>(GetProcAddress(kernel32, "ExitThread"));
        g_realFreeLibraryAndExitThread = reinterpret_cast<FreeLibraryAndExitThreadFn>(GetProcAddress(kernel32, "FreeLibraryAndExitThread"));
        g_realSetUnhandledExceptionFilter = reinterpret_cast<SetUnhandledExceptionFilterFn>(GetProcAddress(kernel32, "SetUnhandledExceptionFilter"));
        g_realUnhandledExceptionFilter = reinterpret_cast<UnhandledExceptionFilterFn>(GetProcAddress(kernel32, "UnhandledExceptionFilter"));
        g_realRaiseFailFastException = reinterpret_cast<RaiseFailFastExceptionFn>(GetProcAddress(kernel32, "RaiseFailFastException"));

        g_realRegOpenKeyExA = reinterpret_cast<RegOpenKeyExAFn>(GetProcAddress(advapi32, "RegOpenKeyExA"));
        g_realRegOpenKeyExW = reinterpret_cast<RegOpenKeyExWFn>(GetProcAddress(advapi32, "RegOpenKeyExW"));
        g_realRegQueryValueExA = reinterpret_cast<RegQueryValueExAFn>(GetProcAddress(advapi32, "RegQueryValueExA"));
        g_realRegQueryValueExW = reinterpret_cast<RegQueryValueExWFn>(GetProcAddress(advapi32, "RegQueryValueExW"));
        g_realRegCloseKey = reinterpret_cast<RegCloseKeyFn>(GetProcAddress(advapi32, "RegCloseKey"));

        if (crypt32)
            g_realCryptUnprotectData = reinterpret_cast<CryptUnprotectDataFn>(GetProcAddress(crypt32, "CryptUnprotectData"));
        if (user32)
        {
            g_realMessageBoxA = reinterpret_cast<MessageBoxAFn>(GetProcAddress(user32, "MessageBoxA"));
            g_realMessageBoxW = reinterpret_cast<MessageBoxWFn>(GetProcAddress(user32, "MessageBoxW"));
        }

        if (g_realGetCommandLineA)
        {
            const char* original = g_realGetCommandLineA();
            if (original)
            {
                strncpy_s(g_compat123CommandLine, original, _TRUNCATE);
                if (!ContainsNoCase(g_compat123CommandLine, "-uid"))
                    strcat_s(g_compat123CommandLine, " -uid odin");
                Write123StartupLog("[LAUNCH] original command line: %s\r\n", original);
                Write123StartupLog("[LAUNCH] effective command line: %s\r\n", g_compat123CommandLine);
            }
        }

        if (g_realGetCommandLineW)
        {
            const wchar_t* originalW = g_realGetCommandLineW();
            if (originalW)
            {
                wcsncpy_s(g_compat123CommandLineW, originalW, _TRUNCATE);
                if (!wcsstr(g_compat123CommandLineW, L"-uid") && !wcsstr(g_compat123CommandLineW, L"-UID"))
                    wcscat_s(g_compat123CommandLineW, L" -uid odin");
                Write123StartupLog("[LAUNCH] GetCommandLineW shim prepared chars=%u uidOdin=%s\r\n",
                    static_cast<unsigned>(wcslen(g_compat123CommandLineW)),
                    wcsstr(g_compat123CommandLineW, L"-uid odin") ? "yes" : "no");
            }
        }

        const bool mw116Production = build == StartupCompatBuild::MW116 && !MW116DeepTraceRequested();
        const bool mw123Production = build == StartupCompatBuild::MW123 && !MW123DeepTraceRequested();
        if (!mw116Production)
        {
            g_compat123Veh = AddVectoredExceptionHandler(1, &Trace123VectoredException);
            if (mw123Production)
                Write123StartupLog("[MW123-PROD] minimal VEH=%s purpose=null-execute-recovery-only unrelatedExceptionLogging=off\r\n",
                    g_compat123Veh ? "installed" : "FAILED");
            else
                Write123StartupLog("[BOOT] vectored exception trace=%s\r\n", g_compat123Veh ? "installed" : "FAILED");
        }
        else
        {
            g_compat123Veh = nullptr;
            Write123StartupLog("[MW116-PROD] intrusive startup tracing disabled: VEH=off threadSuspend=off exitIATHooks=off console=off\r\n");
        }

        unsigned versionPatched = 0;
        versionPatched += PatchImport(mainModule, "KERNEL32.dll", "GetVersion", reinterpret_cast<void*>(&CompatGetVersion)) ? 1u : 0u;
        versionPatched += PatchImport(mainModule, "KERNEL32.dll", "GetVersionExA", reinterpret_cast<void*>(&CompatGetVersionExA)) ? 1u : 0u;
        versionPatched += PatchImport(mainModule, "KERNEL32.dll", "VerifyVersionInfoA", reinterpret_cast<void*>(&CompatVerifyVersionInfoA)) ? 1u : 0u;
        versionPatched += PatchImport(mainModule, "KERNEL32.dll", "VerifyVersionInfoW", reinterpret_cast<void*>(&CompatVerifyVersionInfoW)) ? 1u : 0u;
        if (build == StartupCompatBuild::MW116 || build == StartupCompatBuild::MW123)
        {
            PatchImport(mainModule, "KERNEL32.dll", "GetVersionExW", reinterpret_cast<void*>(&CompatGetVersionExW));
            PatchImport(mainModule, "ntdll.dll", "RtlGetVersion", reinterpret_cast<void*>(&CompatRtlGetVersion));
            const bool dynamicPatched = g_realGetProcAddress &&
                PatchImport(mainModule, "KERNEL32.dll", "GetProcAddress", reinterpret_cast<void*>(&Compat116GetProcAddress));
            InterlockedExchange(&g_compat116DynamicVersionPatched, dynamicPatched ? 1 : 0);
            if (build == StartupCompatBuild::MW123)
            {
                Write123StartupLog("[MW123-COMPAT] extended Windows-version compatibility enabled: GetVersionExW + RtlGetVersion + dynamic GetProcAddress\r\n");
            }
        }
        InterlockedExchange(&g_compat123Patched, static_cast<LONG>(versionPatched));

        unsigned launcherPatched = 0;
        launcherPatched += PatchImport(mainModule, "KERNEL32.dll", "GetCommandLineA", reinterpret_cast<void*>(&CompatGetCommandLineA)) ? 1u : 0u;
        launcherPatched += PatchImport(mainModule, "KERNEL32.dll", "GetCommandLineW", reinterpret_cast<void*>(&CompatGetCommandLineW)) ? 1u : 0u;
        launcherPatched += PatchImport(mainModule, "ADVAPI32.dll", "RegOpenKeyExA", reinterpret_cast<void*>(&CompatRegOpenKeyExA)) ? 1u : 0u;
        launcherPatched += PatchImport(mainModule, "ADVAPI32.dll", "RegOpenKeyExW", reinterpret_cast<void*>(&CompatRegOpenKeyExW)) ? 1u : 0u;
        launcherPatched += PatchImport(mainModule, "ADVAPI32.dll", "RegQueryValueExA", reinterpret_cast<void*>(&CompatRegQueryValueExA)) ? 1u : 0u;
        launcherPatched += PatchImport(mainModule, "ADVAPI32.dll", "RegQueryValueExW", reinterpret_cast<void*>(&CompatRegQueryValueExW)) ? 1u : 0u;
        launcherPatched += PatchImport(mainModule, "ADVAPI32.dll", "RegCloseKey", reinterpret_cast<void*>(&CompatRegCloseKey)) ? 1u : 0u;
        if (g_realCryptUnprotectData)
            launcherPatched += PatchImport(mainModule, "CRYPT32.dll", "CryptUnprotectData", reinterpret_cast<void*>(&CompatCryptUnprotectData)) ? 1u : 0u;
        InterlockedExchange(&g_compat123LauncherPatched, static_cast<LONG>(launcherPatched));

        unsigned safeModePatched = 0;
        // Let 1.16 own its stock safe-mode/recommended-settings flow.  Forcing a
        // MessageBox result here did not advance this build and added another
        // launcher-era behavior difference before the render window existed.
        if (build != StartupCompatBuild::MW116)
        {
            if (g_realMessageBoxA)
                safeModePatched += PatchImport(mainModule, "USER32.dll", "MessageBoxA", reinterpret_cast<void*>(&CompatMessageBoxA)) ? 1u : 0u;
            if (g_realMessageBoxW)
                safeModePatched += PatchImport(mainModule, "USER32.dll", "MessageBoxW", reinterpret_cast<void*>(&CompatMessageBoxW)) ? 1u : 0u;
        }
        InterlockedExchange(&g_compat123SafeModePatched, static_cast<LONG>(safeModePatched));

        if (build == StartupCompatBuild::MW116)
        {
            Write123StartupLog("[MW116-STABILITY] windowsTarget=10.0.%lu safeMode=stock-passthrough networkHooks=dns-only fullNetTrace=%s\r\n",
                static_cast<unsigned long>(CompatWindowsBuild()), FullNetworkTraceRequested() ? "yes" : "no");
        }
        else if (build == StartupCompatBuild::MW123)
        {
            Write123StartupLog("[MW123-STABILITY] mode=%s windowsTarget=10.0.%lu networkHooks=%s exitIATHooks=%s exceptionLogging=%s\r\n",
                mw123Production ? "production" : "diagnostic",
                static_cast<unsigned long>(CompatWindowsBuild()),
                UseDnsOnlyNetworkHooks() ? "dns-only" : "full-diagnostic",
                mw123Production ? "off" : "on",
                mw123Production ? "null-recovery-only" : "full");
        }

        unsigned exitPatched = 0;
        if (!mw116Production && !mw123Production)
        {
            exitPatched += PatchImport(mainModule, "KERNEL32.dll", "ExitProcess", reinterpret_cast<void*>(&Trace123ExitProcess)) ? 1u : 0u;
            exitPatched += PatchImport(mainModule, "KERNEL32.dll", "TerminateProcess", reinterpret_cast<void*>(&Trace123TerminateProcess)) ? 1u : 0u;
            exitPatched += PatchImport(mainModule, "KERNEL32.dll", "RaiseException", reinterpret_cast<void*>(&Trace123RaiseException)) ? 1u : 0u;
            exitPatched += PatchImport(mainModule, "KERNEL32.dll", "ExitThread", reinterpret_cast<void*>(&Trace123ExitThread)) ? 1u : 0u;
            exitPatched += PatchImport(mainModule, "KERNEL32.dll", "FreeLibraryAndExitThread", reinterpret_cast<void*>(&Trace123FreeLibraryAndExitThread)) ? 1u : 0u;
            exitPatched += PatchImport(mainModule, "KERNEL32.dll", "SetUnhandledExceptionFilter", reinterpret_cast<void*>(&Trace123SetUnhandledExceptionFilter)) ? 1u : 0u;
            exitPatched += PatchImport(mainModule, "KERNEL32.dll", "UnhandledExceptionFilter", reinterpret_cast<void*>(&Trace123UnhandledExceptionFilter)) ? 1u : 0u;
            if (build == StartupCompatBuild::MW116)
            {
                const unsigned lowLevelExitPatched =
                    (PatchImport(mainModule, "ntdll.dll", "RtlExitUserProcess", reinterpret_cast<void*>(&Trace116RtlExitUserProcess)) ? 1u : 0u) +
                    (PatchImport(mainModule, "ntdll.dll", "RtlExitUserThread", reinterpret_cast<void*>(&Trace116RtlExitUserThread)) ? 1u : 0u) +
                    (PatchImport(mainModule, "ntdll.dll", "NtTerminateProcess", reinterpret_cast<void*>(&Trace116NtTerminateProcess)) ? 1u : 0u) +
                    (PatchImport(mainModule, "ntdll.dll", "NtRaiseHardError", reinterpret_cast<void*>(&Trace116NtRaiseHardError)) ? 1u : 0u) +
                    (PatchImport(mainModule, "KERNEL32.dll", "RaiseFailFastException", reinterpret_cast<void*>(&Trace116RaiseFailFastException)) ? 1u : 0u);
                Write123StartupLog("[MW116-EXIT] low-level passive exit hooks installed=%u/5 dynamicResolver=yes behavior=passthrough\r\n",
                    lowLevelExitPatched);
            }
        }
        InterlockedExchange(&g_compat123ExitTracePatched, static_cast<LONG>(exitPatched));

        const unsigned versionExpected = 4u;
        Write123StartupLog("[BOOT] startup compatibility build=%s hooks: versionDirect=%u/%u dynamicVersionResolver=%ld/1 launcher=%u/8 safeMode=%u/2 exitTrace=%u/7 nullExecRecovery=%s\r\n",
            StartupCompatBuildName(build), versionPatched, versionExpected,
            InterlockedCompareExchange(&g_compat116DynamicVersionPatched, 0, 0), launcherPatched, safeModePatched, exitPatched,
            mw116Production ? "off(production)" :
            (mw123Production ? "armed(null-call-only,production)" : "armed(max=8,main-image-return-only)"));
        if (build == StartupCompatBuild::MW123)
        {
            Write123StartupLog("[MW123-CRT] debugUcrtLoaded=%s releaseUcrtLoaded=%s expected=debug-no/release-yes\r\n",
                GetModuleHandleW(L"ucrtbased.dll") ? "YES" : "no",
                GetModuleHandleW(L"ucrtbase.dll") ? "yes" : "NO");
        }
    }

    struct ModulePatchCounts
    {
        unsigned dns = 0;
        unsigned connect = 0;
        unsigned socket = 0;
        unsigned select = 0;
        unsigned extendedSocket = 0;
        unsigned ioctl = 0;
    };

    bool IsUnsafeSystemNetworkModule(HMODULE module) noexcept
    {
        if (!module)
            return true;
        wchar_t path[MAX_PATH]{};
        if (!GetModuleFileNameW(module, path, static_cast<DWORD>(sizeof(path) / sizeof(path[0]))))
            return false;
        const wchar_t* name = wcsrchr(path, L'\\');
        name = name ? (name + 1) : path;

        static const wchar_t* blocked[] = {
            L"ws2_32.dll", L"mswsock.dll", L"dnsapi.dll", L"winhttp.dll", L"wininet.dll",
            L"secur32.dll", L"schannel.dll", L"crypt32.dll", L"kernel32.dll",
            L"kernelbase.dll", L"ntdll.dll", L"iphlpapi.dll"
        };
        for (const auto* item : blocked)
        {
            if (_wcsicmp(name, item) == 0)
                return true;
        }
        return false;
    }

    ModulePatchCounts PatchNetworkImportsForModule(HMODULE module) noexcept
    {
        ModulePatchCounts counts{};
        if (!module || module == g_self || IsUnsafeSystemNetworkModule(module))
            return counts;

        // DNS redirection is the only behavior required by the local backend.
        // Keep it enabled on every build.
        counts.dns += PatchImport(module, "WS2_32.dll", "getaddrinfo", reinterpret_cast<void*>(&RedirectGetAddrInfoA)) ? 1u : 0u;
        counts.dns += PatchImport(module, "WS2_32.dll", "GetAddrInfoW", reinterpret_cast<void*>(&RedirectGetAddrInfoW)) ? 1u : 0u;
        counts.dns += PatchImport(module, "WS2_32.dll", "gethostbyname", reinterpret_cast<void*>(&RedirectGetHostByName)) ? 1u : 0u;
        counts.dns += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "getaddrinfo", reinterpret_cast<void*>(&RedirectGetAddrInfoA)) ? 1u : 0u;
        counts.dns += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "GetAddrInfoW", reinterpret_cast<void*>(&RedirectGetAddrInfoW)) ? 1u : 0u;
        counts.dns += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "gethostbyname", reinterpret_cast<void*>(&RedirectGetHostByName)) ? 1u : 0u;

        // Unknown/current retail defaults to DNS-only.  These hooks are purely
        // observational and are not required for local routing; avoiding them
        // removes a provider-call compatibility variable from new Steam builds.
        if (UseDnsOnlyNetworkHooks())
            return counts;

        counts.connect += PatchImport(module, "WS2_32.dll", "connect", reinterpret_cast<void*>(&TraceConnect)) ? 1u : 0u;
        counts.connect += PatchImport(module, "WS2_32.dll", "WSAConnect", reinterpret_cast<void*>(&TraceWSAConnect)) ? 1u : 0u;
        counts.socket += PatchImport(module, "WS2_32.dll", "socket", reinterpret_cast<void*>(&TraceSocket)) ? 1u : 0u;
        counts.extendedSocket += PatchImport(module, "WS2_32.dll", "WSASocketA", reinterpret_cast<void*>(&TraceWSASocketA)) ? 1u : 0u;
        counts.extendedSocket += PatchImport(module, "WS2_32.dll", "WSASocketW", reinterpret_cast<void*>(&TraceWSASocketW)) ? 1u : 0u;
        counts.ioctl += PatchImport(module, "WS2_32.dll", "WSAIoctl", reinterpret_cast<void*>(&TraceWSAIoctl)) ? 1u : 0u;
        counts.select += PatchImport(module, "WS2_32.dll", "select", reinterpret_cast<void*>(&TraceSelect)) ? 1u : 0u;

        // Some older game/runtime DLLs import Winsock through the downlevel API set.
        counts.connect += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "connect", reinterpret_cast<void*>(&TraceConnect)) ? 1u : 0u;
        counts.connect += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "WSAConnect", reinterpret_cast<void*>(&TraceWSAConnect)) ? 1u : 0u;
        counts.socket += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "socket", reinterpret_cast<void*>(&TraceSocket)) ? 1u : 0u;
        counts.extendedSocket += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "WSASocketA", reinterpret_cast<void*>(&TraceWSASocketA)) ? 1u : 0u;
        counts.extendedSocket += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "WSASocketW", reinterpret_cast<void*>(&TraceWSASocketW)) ? 1u : 0u;
        counts.ioctl += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "WSAIoctl", reinterpret_cast<void*>(&TraceWSAIoctl)) ? 1u : 0u;
        counts.select += PatchImport(module, "api-ms-win-downlevel-winsock-l1-1-0.dll", "select", reinterpret_cast<void*>(&TraceSelect)) ? 1u : 0u;
        return counts;
    }

    void OneShotLoadedModuleNetworkPass() noexcept
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            ConsolePrint("[NET-MODULE] ERROR: module snapshot failed win32=%lu\r\n", static_cast<unsigned long>(GetLastError()));
            return;
        }

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        unsigned modulesVisited = 0;
        unsigned modulesPatched = 0;
        unsigned dnsPatched = 0;
        unsigned connectPatched = 0;
        unsigned socketPatched = 0;
        unsigned selectPatched = 0;
        unsigned extendedSocketPatched = 0;
        unsigned ioctlPatched = 0;
        if (Module32FirstW(snapshot, &entry))
        {
            do
            {
                ++modulesVisited;
                HMODULE module = entry.hModule;
                if (!module || module == g_self)
                    continue;

                const auto counts = PatchNetworkImportsForModule(module);
                if (!counts.dns && !counts.connect && !counts.socket && !counts.select && !counts.extendedSocket && !counts.ioctl)
                    continue;

                ++modulesPatched;
                dnsPatched += counts.dns;
                connectPatched += counts.connect;
                socketPatched += counts.socket;
                selectPatched += counts.select;
                extendedSocketPatched += counts.extendedSocket;
                ioctlPatched += counts.ioctl;
                char moduleName[512]{};
                WideCharToMultiByte(CP_UTF8, 0, entry.szModule, -1, moduleName, static_cast<int>(sizeof(moduleName)), nullptr, nullptr);
                ConsolePrint("[NET-MODULE] module=%s dns=%u connectTrace=%u socketTrace=%u wsaSocketTrace=%u ioctlTrace=%u selectTrace=%u\r\n",
                    moduleName[0] ? moduleName : "<unknown>", counts.dns, counts.connect, counts.socket,
                    counts.extendedSocket, counts.ioctl, counts.select);
            } while (Module32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        ConsolePrint("[NET-MODULE] one-shot loaded-module pass complete visited=%u patchedModules=%u dns=%u connectTrace=%u socketTrace=%u wsaSocketTrace=%u ioctlTrace=%u selectTrace=%u\r\n",
            modulesVisited, modulesPatched, dnsPatched, connectPatched, socketPatched, extendedSocketPatched, ioctlPatched, selectPatched);
    }

    std::uintptr_t AlignUp(std::uintptr_t value, std::uintptr_t alignment) noexcept
    {
        if (!alignment)
            return value;
        return (value + alignment - 1) & ~(alignment - 1);
    }

    void* AllocateWs2RelayPage(HMODULE ws2, std::size_t imageSize) noexcept
    {
        if (g_ws2RelayPage)
            return g_ws2RelayPage;
        if (!ws2 || !imageSize)
            return nullptr;

        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        const std::uintptr_t granularity = info.dwAllocationGranularity ?
            static_cast<std::uintptr_t>(info.dwAllocationGranularity) : 0x10000u;
        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(ws2);
        const std::uintptr_t maxUser = reinterpret_cast<std::uintptr_t>(info.lpMaximumApplicationAddress);
        const std::uintptr_t rvaLimit = base + static_cast<std::uintptr_t>(0xFFFFFFFFu);
        const std::uintptr_t searchEnd = rvaLimit < maxUser ? rvaLimit : maxUser;
        std::uintptr_t cursor = AlignUp(base + imageSize, granularity);

        while (cursor < searchEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi)))
                break;
            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + mbi.RegionSize;
            if (mbi.State == MEM_FREE)
            {
                const std::uintptr_t candidate = AlignUp(regionBase < cursor ? cursor : regionBase, granularity);
                if (candidate >= base && candidate + 0x1000u > candidate &&
                    candidate + 0x1000u <= regionEnd && candidate + 0x1000u <= searchEnd)
                {
                    void* page = VirtualAlloc(reinterpret_cast<void*>(candidate), 0x1000u,
                        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    if (page)
                    {
                        g_ws2RelayPage = page;
                        g_ws2RelayOffset = 0;
                        return page;
                    }
                }
            }
            if (regionEnd <= cursor)
                break;
            cursor = AlignUp(regionEnd, granularity);
        }
        return nullptr;
    }

    void* MakeWs2ExportTarget(HMODULE ws2, std::size_t imageSize, void* replacement) noexcept
    {
        if (!ws2 || !replacement)
            return nullptr;
        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(ws2);
        const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(replacement);
        if (target >= base && target - base <= static_cast<std::uintptr_t>(0xFFFFFFFFu))
            return replacement;

        auto* page = static_cast<unsigned char*>(AllocateWs2RelayPage(ws2, imageSize));
        if (!page || g_ws2RelayOffset + 16u > 0x1000u)
            return nullptr;

        unsigned char* relay = page + g_ws2RelayOffset;
        g_ws2RelayOffset += 16u;
        relay[0] = 0x48; // mov rax, imm64
        relay[1] = 0xB8;
        const std::uint64_t absolute = static_cast<std::uint64_t>(target);
        std::memcpy(relay + 2, &absolute, sizeof(absolute));
        relay[10] = 0xFF; // jmp rax
        relay[11] = 0xE0;
        relay[12] = 0xCC;
        relay[13] = 0xCC;
        relay[14] = 0xCC;
        relay[15] = 0xCC;
        FlushInstructionCache(GetCurrentProcess(), relay, 16u);
        return relay;
    }

    bool PatchWs2Export(const char* functionName, void* replacement) noexcept
    {
        if (!g_ws2 || !functionName || !replacement)
            return false;

        const auto base = reinterpret_cast<std::uintptr_t>(g_ws2);
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return false;

            const std::size_t imageSize = nt->OptionalHeader.SizeOfImage;
            const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!directory.VirtualAddress || !directory.Size ||
                !RvaInImage(directory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), imageSize))
                return false;

            const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + directory.VirtualAddress);
            if (!exports->AddressOfNames || !exports->AddressOfNameOrdinals || !exports->AddressOfFunctions ||
                !RvaInImage(exports->AddressOfNames, exports->NumberOfNames * sizeof(DWORD), imageSize) ||
                !RvaInImage(exports->AddressOfNameOrdinals, exports->NumberOfNames * sizeof(WORD), imageSize) ||
                !RvaInImage(exports->AddressOfFunctions, exports->NumberOfFunctions * sizeof(DWORD), imageSize))
                return false;

            const auto* names = reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
            const auto* ordinals = reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
            auto* functions = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);
            for (DWORD i = 0; i < exports->NumberOfNames; ++i)
            {
                if (!RvaInImage(names[i], 1, imageSize))
                    continue;
                const char* name = reinterpret_cast<const char*>(base + names[i]);
                if (std::strcmp(name, functionName) != 0)
                    continue;
                const WORD ordinal = ordinals[i];
                if (ordinal >= exports->NumberOfFunctions)
                    return false;

                void* exportTarget = MakeWs2ExportTarget(g_ws2, imageSize, replacement);
                if (!exportTarget)
                    return false;
                const std::uintptr_t targetAddress = reinterpret_cast<std::uintptr_t>(exportTarget);
                if (targetAddress < base || targetAddress - base > static_cast<std::uintptr_t>(0xFFFFFFFFu))
                    return false;
                const DWORD replacementRva = static_cast<DWORD>(targetAddress - base);
                DWORD* slot = &functions[ordinal];
                if (*slot == replacementRva)
                    return true;

                DWORD oldProtect = 0;
                if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &oldProtect))
                    return false;
                *slot = replacementRva;
                DWORD ignored = 0;
                VirtualProtect(slot, sizeof(*slot), oldProtect, &ignored);
                FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return false;
    }

    void InstallWs2ExportTrace() noexcept
    {
        struct ExportHook
        {
            const char* name;
            void* replacement;
        };
        const ExportHook hooks[] = {
            { "getaddrinfo", reinterpret_cast<void*>(&RedirectGetAddrInfoA) },
            { "GetAddrInfoW", reinterpret_cast<void*>(&RedirectGetAddrInfoW) },
            { "gethostbyname", reinterpret_cast<void*>(&RedirectGetHostByName) },
            { "socket", reinterpret_cast<void*>(&TraceSocket) },
            { "WSASocketA", reinterpret_cast<void*>(&TraceWSASocketA) },
            { "WSASocketW", reinterpret_cast<void*>(&TraceWSASocketW) },
            { "WSAIoctl", reinterpret_cast<void*>(&TraceWSAIoctl) },
            { "connect", reinterpret_cast<void*>(&TraceConnect) },
            { "WSAConnect", reinterpret_cast<void*>(&TraceWSAConnect) },
            { "select", reinterpret_cast<void*>(&TraceSelect) },
        };

        const bool dnsOnly = UseDnsOnlyNetworkHooks();
        unsigned installed = 0;
        unsigned selected = 0;
        for (const auto& hook : hooks)
        {
            const bool isDns = EqualsNoCase(hook.name, "getaddrinfo") ||
                EqualsNoCase(hook.name, "GetAddrInfoW") || EqualsNoCase(hook.name, "gethostbyname");
            if (dnsOnly && !isDns)
                continue;
            ++selected;
            const bool ok = PatchWs2Export(hook.name, hook.replacement);
            ConsolePrint("[WS2-EXPORT] export=%s hook=%s mode=EAT-future-GetProcAddress passthrough=%s\r\n",
                hook.name, ok ? "installed" : "failed", isDns ? "dns-redirect-only" : "yes");
            installed += ok ? 1u : 0u;
        }
        if (dnsOnly)
            ConsolePrint("[WS2-EXPORT] safe retail mode: DNS-only; transport trace hooks disabled (set CODREVAMPED_FULL_NET_TRACE=1 to opt in)\r\n");
        ConsolePrint("[WS2-EXPORT] global dynamic-resolution trace ready installed=%u/%u relay=%p; existing static imports are covered separately by IAT hooks\r\n",
            installed, selected, g_ws2RelayPage);
    }

    bool ResolveWinsock() noexcept
    {
        g_ws2 = GetModuleHandleW(L"WS2_32.dll");
        if (!g_ws2)
            g_ws2 = LoadLibraryW(L"WS2_32.dll");
        if (!g_ws2)
            return false;
        // Resolve and keep the real entrypoints BEFORE changing WS2_32's export table.
        // Our detours always call these original addresses, so the export-table hook
        // cannot recurse back into itself.
        g_getAddrInfoA = reinterpret_cast<GetAddrInfoAFn>(GetProcAddress(g_ws2, "getaddrinfo"));
        g_getAddrInfoW = reinterpret_cast<GetAddrInfoWFn>(GetProcAddress(g_ws2, "GetAddrInfoW"));
        g_getHostByName = reinterpret_cast<GetHostByNameFn>(GetProcAddress(g_ws2, "gethostbyname"));
        g_connect = reinterpret_cast<ConnectFn>(GetProcAddress(g_ws2, "connect"));
        g_wsaConnect = reinterpret_cast<WSAConnectFn>(GetProcAddress(g_ws2, "WSAConnect"));
        g_socket = reinterpret_cast<SocketFn>(GetProcAddress(g_ws2, "socket"));
        g_wsaSocketA = reinterpret_cast<WSASocketAFn>(GetProcAddress(g_ws2, "WSASocketA"));
        g_wsaSocketW = reinterpret_cast<WSASocketWFn>(GetProcAddress(g_ws2, "WSASocketW"));
        g_wsaIoctl = reinterpret_cast<WSAIoctlFn>(GetProcAddress(g_ws2, "WSAIoctl"));
        g_select = reinterpret_cast<SelectFn>(GetProcAddress(g_ws2, "select"));
        return g_getAddrInfoA && g_getAddrInfoW && g_getHostByName && g_connect && g_wsaConnect && g_socket &&
            g_wsaSocketA && g_wsaSocketW && g_wsaIoctl && g_select;
    }

    struct LsgKey3CandidateDiskV79
    {
        unsigned long long fileOffset = 0;
        std::array<unsigned char, 294> der{};
    };

    bool LooksLikeRsaSpki294DiskV79(const unsigned char* p, std::size_t available) noexcept
    {
        if (!p || available < 294u)
            return false;
        static const unsigned char prefix[] =
        {
            0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,
            0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,
            0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,
            0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01
        };
        if (std::memcmp(p, prefix, sizeof(prefix)) != 0)
            return false;
        return p[32] == 0x00u &&
            p[289] == 0x02u && p[290] == 0x03u &&
            p[291] == 0x01u && p[292] == 0x00u && p[293] == 0x01u;
    }

    bool BuildSiblingPathV79(const wchar_t* fileName, wchar_t* out, std::size_t outCount) noexcept
    {
        if (!fileName || !*fileName || !out || outCount < 2u)
            return false;
        wchar_t exePath[32768]{};
        const DWORD chars = GetModuleFileNameW(nullptr, exePath,
            static_cast<DWORD>(sizeof(exePath) / sizeof(exePath[0])));
        if (!chars || chars >= (sizeof(exePath) / sizeof(exePath[0])))
            return false;
        wchar_t* slash = std::wcsrchr(exePath, L'\\');
        wchar_t* slash2 = std::wcsrchr(exePath, L'/');
        if (!slash || (slash2 && slash2 > slash))
            slash = slash2;
        if (slash)
            slash[1] = L'\0';
        else
            exePath[0] = L'\0';
        return _snwprintf_s(out, outCount, _TRUNCATE, L"%s%s", exePath, fileName) > 0;
    }

    bool WriteLsgKey3CandidatePackV79(const wchar_t* path,
        const std::vector<LsgKey3CandidateDiskV79>& candidates) noexcept
    {
        if (!path || !*path || candidates.empty() || candidates.size() > 128u)
            return false;

        std::vector<unsigned char> bytes;
        bytes.reserve(16u + candidates.size() * (8u + 294u));
        static const unsigned char magic[8] = {'I','W','8','K','3','V','7','8'};
        bytes.insert(bytes.end(), magic, magic + sizeof(magic));
        const auto append32 = [&bytes](unsigned long value)
        {
            bytes.push_back(static_cast<unsigned char>(value));
            bytes.push_back(static_cast<unsigned char>(value >> 8));
            bytes.push_back(static_cast<unsigned char>(value >> 16));
            bytes.push_back(static_cast<unsigned char>(value >> 24));
        };
        const auto append64 = [&bytes](unsigned long long value)
        {
            for (unsigned shift = 0; shift < 64u; shift += 8u)
                bytes.push_back(static_cast<unsigned char>(value >> shift));
        };
        append32(1u);
        append32(static_cast<unsigned long>(candidates.size()));
        for (const auto& candidate : candidates)
        {
            append64(candidate.fileOffset);
            bytes.insert(bytes.end(), candidate.der.begin(), candidate.der.end());
        }

        HANDLE file = CreateFileW(path, GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        DWORD written = 0;
        const BOOL ok = bytes.size() <= 0xFFFFFFFFu &&
            WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
        CloseHandle(file);
        return ok && written == static_cast<DWORD>(bytes.size());
    }

    DWORD WINAPI LsgKey3DiskScanWorkerV79(LPVOID) noexcept
    {
        // Research-only helper: scan the executable FILE on disk for structurally
        // valid 294-byte RSA SPKI values.  No process memory/code pages or game
        // state are read or modified.  The backend uses the resulting candidates
        // as an oracle against the stock client's native 0x82 proof.
        wchar_t exePath[32768]{};
        const DWORD chars = GetModuleFileNameW(nullptr, exePath,
            static_cast<DWORD>(sizeof(exePath) / sizeof(exePath[0])));
        if (!chars || chars >= (sizeof(exePath) / sizeof(exePath[0])))
        {
            ConsolePrint("[LSG-KEY3] disk scan failed stage=module-path win32=%lu stateWrites=off\r\n", GetLastError());
            return 0;
        }

        HANDLE file = CreateFileW(exePath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            ConsolePrint("[LSG-KEY3] disk scan failed stage=open-exe win32=%lu stateWrites=off\r\n", GetLastError());
            return 0;
        }

        LARGE_INTEGER fileSize{};
        if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 294)
        {
            const DWORD error = GetLastError();
            CloseHandle(file);
            ConsolePrint("[LSG-KEY3] disk scan failed stage=file-size win32=%lu stateWrites=off\r\n", error);
            return 0;
        }

        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping)
        {
            const DWORD error = GetLastError();
            CloseHandle(file);
            ConsolePrint("[LSG-KEY3] disk scan failed stage=file-map win32=%lu stateWrites=off\r\n", error);
            return 0;
        }
        const auto* view = static_cast<const unsigned char*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
        if (!view)
        {
            const DWORD error = GetLastError();
            CloseHandle(mapping);
            CloseHandle(file);
            ConsolePrint("[LSG-KEY3] disk scan failed stage=map-view win32=%lu stateWrites=off\r\n", error);
            return 0;
        }

        const unsigned long long fileBytes64 = static_cast<unsigned long long>(fileSize.QuadPart);
        if (fileBytes64 > static_cast<unsigned long long>(static_cast<std::size_t>(-1)))
        {
            UnmapViewOfFile(view);
            CloseHandle(mapping);
            CloseHandle(file);
            ConsolePrint("[LSG-KEY3] disk scan failed stage=size-overflow stateWrites=off\r\n");
            return 0;
        }
        const std::size_t fileBytes = static_cast<std::size_t>(fileBytes64);
        std::vector<LsgKey3CandidateDiskV79> candidates;
        candidates.reserve(16u);
        std::size_t cursor = 0;
        while (cursor + 294u <= fileBytes && candidates.size() < 128u)
        {
            const void* found = std::memchr(view + cursor, 0x30, fileBytes - cursor - 293u);
            if (!found)
                break;
            const auto* p = static_cast<const unsigned char*>(found);
            const std::size_t offset = static_cast<std::size_t>(p - view);
            cursor = offset + 1u;
            if (!LooksLikeRsaSpki294DiskV79(p, fileBytes - offset))
                continue;

            bool duplicate = false;
            for (const auto& prior : candidates)
            {
                if (std::memcmp(prior.der.data(), p, prior.der.size()) == 0)
                {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate)
                continue;

            LsgKey3CandidateDiskV79 candidate{};
            candidate.fileOffset = static_cast<unsigned long long>(offset);
            std::memcpy(candidate.der.data(), p, candidate.der.size());
            candidates.push_back(candidate);
        }

        UnmapViewOfFile(view);
        CloseHandle(mapping);
        CloseHandle(file);

        wchar_t outputPath[32768]{};
        const bool pathReady = BuildSiblingPathV79(L"iw8-auth-traffic-signing-key3-candidates.bin",
            outputPath, sizeof(outputPath) / sizeof(outputPath[0]));
        const bool wrote = pathReady && WriteLsgKey3CandidatePackV79(outputPath, candidates);
        ConsolePrint("[LSG-KEY3] disk scan complete build=%s candidates=%llu exeBytes=%llu pack=%s path=%ls runtimeMemoryScan=off codePagesTouched=none stateWrites=off\r\n",
            StartupCompatBuildName(CurrentStartupCompatBuild()),
            static_cast<unsigned long long>(candidates.size()),
            fileBytes64, wrote ? "ready" : "FAILED", pathReady ? outputPath : L"<unresolved>");
        return 0;
    }

    void QueueLsgKey3DiskScanV79() noexcept
    {
        static volatile LONG queued = 0;
        if (InterlockedExchange(&queued, 1) != 0)
            return;
        HANDLE thread = CreateThread(nullptr, 0, &LsgKey3DiskScanWorkerV79, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
        else
        {
            InterlockedExchange(&queued, 0);
            ConsolePrint("[LSG-KEY3] disk scan queue failed win32=%lu stateWrites=off\r\n", GetLastError());
        }
    }

    using EnumWindowsFn = BOOL (WINAPI*)(WNDENUMPROC, LPARAM);
    using GetWindowThreadProcessIdFn = DWORD (WINAPI*)(HWND, LPDWORD);
    using IsWindowVisibleFn = BOOL (WINAPI*)(HWND);
    using GetClassNameWFn = int (WINAPI*)(HWND, LPWSTR, int);
    using GetWindowTextWFn = int (WINAPI*)(HWND, LPWSTR, int);

    struct MW116WindowProbe
    {
        DWORD pid = 0;
        unsigned total = 0;
        unsigned visible = 0;
        HWND first = nullptr;
        HWND firstVisible = nullptr;
        GetWindowThreadProcessIdFn getWindowThreadProcessId = nullptr;
        IsWindowVisibleFn isWindowVisible = nullptr;
    };

    BOOL CALLBACK MW116EnumWindowsProc(HWND hwnd, LPARAM param) noexcept
    {
        auto* probe = reinterpret_cast<MW116WindowProbe*>(param);
        if (!probe || !probe->getWindowThreadProcessId || !probe->isWindowVisible)
            return TRUE;
        DWORD pid = 0;
        probe->getWindowThreadProcessId(hwnd, &pid);
        if (pid != probe->pid)
            return TRUE;
        ++probe->total;
        if (!probe->first)
            probe->first = hwnd;
        if (probe->isWindowVisible(hwnd))
        {
            ++probe->visible;
            if (!probe->firstVisible)
                probe->firstVisible = hwnd;
        }
        return TRUE;
    }

    void MW116ProbeWindows(unsigned sample) noexcept
    {
        HMODULE user32 = GetModuleHandleW(L"USER32.dll");
        if (!user32 || !g_realGetProcAddress)
        {
            Write123StartupLog("[MW116-STAGE] sample=%u windows=unavailable user32=no dxgi=%s d3d12=%s d3d11=%s winhttp=%s wininet=%s\r\n",
                sample,
                GetModuleHandleW(L"dxgi.dll") ? "yes" : "no",
                GetModuleHandleW(L"d3d12.dll") ? "yes" : "no",
                GetModuleHandleW(L"d3d11.dll") ? "yes" : "no",
                GetModuleHandleW(L"winhttp.dll") ? "yes" : "no",
                GetModuleHandleW(L"wininet.dll") ? "yes" : "no");
            return;
        }

        const auto enumWindows = reinterpret_cast<EnumWindowsFn>(g_realGetProcAddress(user32, "EnumWindows"));
        const auto getWindowThreadProcessId = reinterpret_cast<GetWindowThreadProcessIdFn>(g_realGetProcAddress(user32, "GetWindowThreadProcessId"));
        const auto isWindowVisible = reinterpret_cast<IsWindowVisibleFn>(g_realGetProcAddress(user32, "IsWindowVisible"));
        const auto getClassNameW = reinterpret_cast<GetClassNameWFn>(g_realGetProcAddress(user32, "GetClassNameW"));
        const auto getWindowTextW = reinterpret_cast<GetWindowTextWFn>(g_realGetProcAddress(user32, "GetWindowTextW"));
        if (!enumWindows || !getWindowThreadProcessId || !isWindowVisible)
        {
            Write123StartupLog("[MW116-STAGE] sample=%u windows=unavailable user32=yes reason=resolve-failed\r\n", sample);
            return;
        }

        MW116WindowProbe probe{};
        probe.pid = GetCurrentProcessId();
        probe.getWindowThreadProcessId = getWindowThreadProcessId;
        probe.isWindowVisible = isWindowVisible;
        enumWindows(&MW116EnumWindowsProc, reinterpret_cast<LPARAM>(&probe));

        HWND picked = probe.firstVisible ? probe.firstVisible : probe.first;
        wchar_t className[128]{};
        wchar_t title[256]{};
        if (picked && getClassNameW)
            getClassNameW(picked, className, static_cast<int>(sizeof(className) / sizeof(className[0])));
        if (picked && getWindowTextW)
            getWindowTextW(picked, title, static_cast<int>(sizeof(title) / sizeof(title[0])));
        char classUtf8[256]{};
        char titleUtf8[512]{};
        if (className[0])
            WideCharToMultiByte(CP_UTF8, 0, className, -1, classUtf8, static_cast<int>(sizeof(classUtf8)), nullptr, nullptr);
        if (title[0])
            WideCharToMultiByte(CP_UTF8, 0, title, -1, titleUtf8, static_cast<int>(sizeof(titleUtf8)), nullptr, nullptr);
        Write123StartupLog("[MW116-STAGE] sample=%u windows=%u visible=%u hwnd=%p class=\"%s\" title=\"%s\" user32=yes dxgi=%s d3d12=%s d3d11=%s winhttp=%s wininet=%s\r\n",
            sample, probe.total, probe.visible, picked,
            classUtf8[0] ? classUtf8 : "<none>", titleUtf8[0] ? titleUtf8 : "<none>",
            GetModuleHandleW(L"dxgi.dll") ? "yes" : "no",
            GetModuleHandleW(L"d3d12.dll") ? "yes" : "no",
            GetModuleHandleW(L"d3d11.dll") ? "yes" : "no",
            GetModuleHandleW(L"winhttp.dll") ? "yes" : "no",
            GetModuleHandleW(L"wininet.dll") ? "yes" : "no");
    }

    void MW116ProbeChildProcesses(unsigned sample) noexcept
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return;
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        unsigned children = 0;
        char childText[768]{};
        size_t used = 0;
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (entry.th32ParentProcessID != GetCurrentProcessId())
                    continue;
                ++children;
                char name[260]{};
                WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, name, static_cast<int>(sizeof(name)), nullptr, nullptr);
                if (used + 48 < sizeof(childText))
                {
                    const int wrote = _snprintf_s(childText + used, sizeof(childText) - used, _TRUNCATE,
                        "%s%lu:%s", used ? "," : "", static_cast<unsigned long>(entry.th32ProcessID), name);
                    if (wrote > 0)
                        used += static_cast<size_t>(wrote);
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        Write123StartupLog("[MW116-STAGE] sample=%u childProcesses=%u children=%s\r\n",
            sample, children, childText[0] ? childText : "<none>");
    }

    void MW116BuildStackRvas(const CONTEXT& context, std::uintptr_t mainBase, std::uintptr_t mainEnd,
        char* out, size_t outSize) noexcept
    {
        if (!out || !outSize)
            return;
        out[0] = 0;
        size_t used = 0;
        unsigned found = 0;
        __try
        {
            const auto* stack = reinterpret_cast<const std::uintptr_t*>(context.Rsp);
            for (unsigned i = 0; i < 96 && found < 8; ++i)
            {
                const std::uintptr_t candidate = stack[i];
                if (!mainBase || candidate < mainBase || candidate >= mainEnd)
                    continue;
                const auto rva = candidate - mainBase;
                const int wrote = _snprintf_s(out + used, outSize - used, _TRUNCATE,
                    "%s0x%llX", found ? "," : "", static_cast<unsigned long long>(rva));
                if (wrote <= 0)
                    break;
                used += static_cast<size_t>(wrote);
                ++found;
                if (used + 24 >= outSize)
                    break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (!out[0])
            strncpy_s(out, outSize, "<none>", _TRUNCATE);
    }

    DWORD WINAPI MW116StartupWatchdog(LPVOID) noexcept
    {
#if !defined(_M_X64)
        return 0;
#else
        if (CurrentStartupCompatBuild() != StartupCompatBuild::MW116 || !g_processAttachThreadId)
            return 0;
        Sleep(25);

        const auto mainBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const auto mainEnd = mainBase + static_cast<std::uintptr_t>(g_liveImageSize);
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            FALSE, g_processAttachThreadId);
        if (!thread)
        {
            Write123StartupLog("[MW116-WATCH] OpenThread failed tid=%lu win32=%lu\r\n",
                static_cast<unsigned long>(g_processAttachThreadId), static_cast<unsigned long>(GetLastError()));
            return 0;
        }

        ULONGLONG baseKernelMs = 0;
        ULONGLONG baseUserMs = 0;
        FILETIME createTime{}, exitTime{}, kernelTime{}, userTime{};
        if (GetThreadTimes(thread, &createTime, &exitTime, &kernelTime, &userTime))
        {
            baseKernelMs = (static_cast<ULONGLONG>(kernelTime.dwHighDateTime) << 32 | kernelTime.dwLowDateTime) / 10000ULL;
            baseUserMs = (static_cast<ULONGLONG>(userTime.dwHighDateTime) << 32 | userTime.dwLowDateTime) / 10000ULL;
        }

        for (unsigned sample = 1; sample <= 100; ++sample)
        {
            if (SuspendThread(thread) == static_cast<DWORD>(-1))
            {
                Write123StartupLog("[MW116-WATCH] suspend failed sample=%u tid=%lu win32=%lu\r\n",
                    sample, static_cast<unsigned long>(g_processAttachThreadId), static_cast<unsigned long>(GetLastError()));
                break;
            }

            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            bool gotContext = GetThreadContext(thread, &context) != FALSE;
            std::uintptr_t firstMainReturn = 0;
            std::uintptr_t firstMainReturnRva = 0;
            if (gotContext)
            {
                __try
                {
                    const auto* stack = reinterpret_cast<const std::uintptr_t*>(context.Rsp);
                    for (unsigned i = 0; i < 40; ++i)
                    {
                        const std::uintptr_t candidate = stack[i];
                        if (mainBase && candidate >= mainBase && candidate < mainEnd)
                        {
                            firstMainReturn = candidate;
                            firstMainReturnRva = candidate - mainBase;
                            break;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            char stackRvas[512]{};
            if (gotContext)
                MW116BuildStackRvas(context, mainBase, mainEnd, stackRvas, sizeof(stackRvas));

            // Resume before module-name lookup or file I/O so the sampler never
            // asks for loader state while the startup thread is suspended.
            ResumeThread(thread);

            ULONGLONG kernelMs = 0;
            ULONGLONG userMs = 0;
            FILETIME nowCreate{}, nowExit{}, nowKernel{}, nowUser{};
            if (GetThreadTimes(thread, &nowCreate, &nowExit, &nowKernel, &nowUser))
            {
                kernelMs = (static_cast<ULONGLONG>(nowKernel.dwHighDateTime) << 32 | nowKernel.dwLowDateTime) / 10000ULL;
                userMs = (static_cast<ULONGLONG>(nowUser.dwHighDateTime) << 32 | nowUser.dwLowDateTime) / 10000ULL;
            }

            if (gotContext)
            {
                char ripModule[MAX_PATH]{};
                ModuleNameFromAddress(reinterpret_cast<void*>(context.Rip), ripModule, sizeof(ripModule));
                const bool ripInMain = mainBase && context.Rip >= mainBase && context.Rip < mainEnd;
                const std::uintptr_t ripRva = ripInMain ? static_cast<std::uintptr_t>(context.Rip) - mainBase : 0;
                Write123StartupLog("[MW116-WATCH] sample=%u tid=%lu rip=%p module=%s mainRva=%s0x%llX rsp=0x%llX cpuKernelDeltaMs=%llu cpuUserDeltaMs=%llu firstMainReturn=%p returnRva=0x%llX stackMainRvas=%s\r\n",
                    sample, static_cast<unsigned long>(g_processAttachThreadId),
                    reinterpret_cast<void*>(context.Rip), ripModule,
                    ripInMain ? "" : "n/a:", static_cast<unsigned long long>(ripRva),
                    static_cast<unsigned long long>(context.Rsp),
                    static_cast<unsigned long long>(kernelMs >= baseKernelMs ? kernelMs - baseKernelMs : 0),
                    static_cast<unsigned long long>(userMs >= baseUserMs ? userMs - baseUserMs : 0),
                    reinterpret_cast<void*>(firstMainReturn), static_cast<unsigned long long>(firstMainReturnRva),
                    stackRvas);
            }
            else
            {
                Write123StartupLog("[MW116-WATCH] GetThreadContext failed sample=%u tid=%lu win32=%lu\r\n",
                    sample, static_cast<unsigned long>(g_processAttachThreadId), static_cast<unsigned long>(GetLastError()));
            }
            if (sample == 1 || (sample % 5) == 0)
            {
                MW116ProbeWindows(sample);
                MW116ProbeChildProcesses(sample);
            }
            Sleep(200);
        }

        CloseHandle(thread);
        return 0;
#endif
    }

    void QueueMW116StartupWatchdog() noexcept
    {
        if (CurrentStartupCompatBuild() != StartupCompatBuild::MW116 || !MW116DeepTraceRequested())
            return;
        static volatile LONG queued = 0;
        if (InterlockedExchange(&queued, 1) != 0)
            return;
        HANDLE thread = CreateThread(nullptr, 0, &MW116StartupWatchdog, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
            Write123StartupLog("[MW116-WATCH] queued startup-thread sampler tid=%lu delayMs=25 samples=100 intervalMs=200 stageProbeEvery=5 stateWrites=none\r\n",
                static_cast<unsigned long>(g_processAttachThreadId));
        }
        else
            Write123StartupLog("[MW116-WATCH] queue failed win32=%lu\r\n", static_cast<unsigned long>(GetLastError()));
    }

    void Write116MonitorLogLine(const char* format, ...) noexcept
    {
        if (!format)
            return;
        char line[1024]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(line, sizeof(line), _TRUNCATE, format, args);
        va_end(args);

        wchar_t modulePath[32768]{};
        if (!g_self || !GetModuleFileNameW(g_self, modulePath, static_cast<DWORD>(sizeof(modulePath) / sizeof(modulePath[0]))))
            return;
        wchar_t* slash = wcsrchr(modulePath, L'\\');
        if (slash)
            *(slash + 1) = L'\0';
        wcscat_s(modulePath, L"mw2019_116_exit.log");

        HANDLE file = CreateFileW(modulePath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;
        DWORD written = 0;
        WriteFile(file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
        CloseHandle(file);
    }

    bool IsRundll32Process() noexcept
    {
        wchar_t path[MAX_PATH]{};
        if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(sizeof(path) / sizeof(path[0]))))
            return false;
        const wchar_t* name = wcsrchr(path, L'\\');
        name = name ? name + 1 : path;
        return _wcsicmp(name, L"rundll32.exe") == 0;
    }

    void StartMW116ExternalExitMonitor() noexcept
    {
        if (CurrentStartupCompatBuild() != StartupCompatBuild::MW116 ||
            InterlockedExchange(&g_mw116ExternalMonitorStarted, 1) != 0)
            return;

        wchar_t dllPath[32768]{};
        wchar_t systemDir[MAX_PATH]{};
        if (!g_self ||
            !GetModuleFileNameW(g_self, dllPath, static_cast<DWORD>(sizeof(dllPath) / sizeof(dllPath[0]))) ||
            !GetSystemDirectoryW(systemDir, static_cast<UINT>(sizeof(systemDir) / sizeof(systemDir[0]))))
        {
            Write123StartupLog("[MW116-EXT] external exit monitor launch skipped reason=path-resolution-failed win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
            return;
        }

        wchar_t command[65536]{};
        _snwprintf_s(command, sizeof(command) / sizeof(command[0]), _TRUNCATE,
            L"\"%ls\\rundll32.exe\" \"%ls\",MW116Monitor %lu",
            systemDir, dllPath, static_cast<unsigned long>(GetCurrentProcessId()));

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        const BOOL created = CreateProcessW(nullptr, command, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (!created)
        {
            Write123StartupLog("[MW116-EXT] external exit monitor launch FAILED win32=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
            return;
        }

        Write123StartupLog("[MW116-EXT] external exit monitor pid=%lu targetPid=%lu mode=out-of-process no-target-thread-suspend\r\n",
            static_cast<unsigned long>(pi.dwProcessId), static_cast<unsigned long>(GetCurrentProcessId()));
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    DWORD WINAPI RedirectWorker(LPVOID) noexcept
    {
        DeleteFileW(L"mw2019_redirect.log");
        g_traceStartTick = GetTickCount64();
        wchar_t backgroundTest[8]{};
        const bool hideConsole = GetEnvironmentVariableW(L"CODREVAMPED_BACKGROUND_TEST",
            backgroundTest, static_cast<DWORD>(std::size(backgroundTest))) && backgroundTest[0] == L'1';
        if (!MW116ProductionMode() && !hideConsole)
            OpenResearchConsole();
        StartMW116ExternalExitMonitor();
        ConsolePrint("[REDIRECT] version.dll loaded; safe DNS redirect + adaptive WS2_32 logging trace\r\n");
        if (MW116ProductionMode())
            ConsolePrint("[MW116-PROD] minimal startup mode active console=off VEH=off startupThreadSampler=off exitIATHooks=off externalExitMonitor=on\r\n");
        if (MW123ProductionMode())
            ConsolePrint("[MW123-PROD] minimal startup mode active nullRecovery=on exceptionLogging=off exitIATHooks=off networkHooks=dns-only\r\n");
        if (InterlockedCompareExchange(&g_liveFingerprintValid, 0, 0) != 0)
        {
            ConsolePrint("[STARTUP] live exe fingerprint timestamp=0x%08X imageSize=0x%08X entryPoint=0x%08X startupCompat=%s\r\n",
                g_liveTimestamp, g_liveImageSize, g_liveEntryPoint,
                StartupCompatBuildName(CurrentStartupCompatBuild()));
        }
        QueueRetailFrontendProbe();
        QueueRetailRuntimeDump();
        QueueRetailOnlineLiveTrace();
        if (InterlockedCompareExchange(&g_compat123Detected, 0, 0) != 0)
        {
            const StartupCompatBuild build = CurrentStartupCompatBuild();
            const char* startupLog = build == StartupCompatBuild::MW116 ? "mw2019_116_startup.log" :
                (build == StartupCompatBuild::MW120 ? "mw2019_120_startup.log" :
                (build == StartupCompatBuild::MW128 ? "mw2019_128_startup.log" : "mw2019_123_startup.log"));
            ConsolePrint("[COMPAT-STARTUP] supported early build=%s fingerprint timestamp=0x%08X imageSize=0x%08X entryPoint=0x%08X\r\n",
                StartupCompatBuildName(build), g_liveTimestamp, g_liveImageSize, g_liveEntryPoint);
            const unsigned versionExpected = 4u;
            ConsolePrint("[COMPAT-STARTUP] Windows-version direct IAT hooks installed=%ld/%u target=10.0.%lu\r\n",
                InterlockedCompareExchange(&g_compat123Patched, 0, 0), versionExpected, static_cast<unsigned long>(CompatWindowsBuild()));
            if (build == StartupCompatBuild::MW116 || build == StartupCompatBuild::MW123)
                ConsolePrint("[COMPAT-VERSION] build=%s dynamic GetProcAddress resolver installed=%ld/1 covers=version%s\r\n",
                    StartupCompatBuildName(build),
                    InterlockedCompareExchange(&g_compat116DynamicVersionPatched, 0, 0),
                    (build == StartupCompatBuild::MW116 && MW116DeepTraceRequested()) ? "+exit-diagnostics" : "");
            ConsolePrint("[COMPAT-STARTUP] launcher shim hooks installed=%ld/8: -uid odin (A+W) + local ODIN launch-options + local WEB_TOKEN DPAPI shim\r\n",
                InterlockedCompareExchange(&g_compat123LauncherPatched, 0, 0));
            if (build == StartupCompatBuild::MW116)
            {
                ConsolePrint("[COMPAT-STARTUP] Safe Mode/recommended-settings dialogs=stock-passthrough (no MessageBox override)\r\n");
                ConsolePrint("[MW116-STABILITY] Windows target=10.0.%lu networkHooks=%s\r\n",
                    static_cast<unsigned long>(CompatWindowsBuild()),
                    UseDnsOnlyNetworkHooks() ? "dns-only" : "full-diagnostic");
            }
            else
            {
                ConsolePrint("[COMPAT-STARTUP] previous-run Safe Mode prompt handler installed=%ld/2 exactTextMatch=yes result=IDNO\r\n",
                    InterlockedCompareExchange(&g_compat123SafeModePatched, 0, 0));
            }
            if (build == StartupCompatBuild::MW116 && !MW116DeepTraceRequested())
                ConsolePrint("[COMPAT-STARTUP] intrusive exit/exception tracing disabled for 1.16 production mode; external exit-code monitor enabled\r\n");
            else if (build == StartupCompatBuild::MW123 && !MW123DeepTraceRequested())
                ConsolePrint("[COMPAT-STARTUP] 1.23 production tracing: null-execute recovery only; exit IAT hooks and unrelated VEH logging disabled\r\n");
            else
                ConsolePrint("[COMPAT-STARTUP] early exit/exception tracing installed=%ld/7 + VEH; details go to %s\r\n",
                    InterlockedCompareExchange(&g_compat123ExitTracePatched, 0, 0), startupLog);
            ConsolePrint("[COMPAT-STARTUP] compatibility is fingerprint-scoped; no login/fence/game-state patch is applied\r\n");
        }

        QueueMW116StartupWatchdog();

        wchar_t skipCrashTrace[8]{};
        const bool skipRetailCrashTrace = g_liveTimestamp == 0x69DD404Eu &&
            g_liveImageSize == 0x21679200u && g_liveEntryPoint == 0x06E4931Cu &&
            GetEnvironmentVariableW(L"CODREVAMPED_RETAIL_NO_VEH", skipCrashTrace,
                static_cast<DWORD>(std::size(skipCrashTrace))) && skipCrashTrace[0] == L'1';
        if (!skipRetailCrashTrace)
            InstallRetailCrashTrace();
        else
            ConsolePrint("[CRASH-TRACE] Steam retail diagnostic: VEH logging disabled\r\n");

        if (!ResolveWinsock())
        {
            ConsolePrint("[REDIRECT] ERROR: required WS2_32 DNS/socket/connect/WSASocket/WSAIoctl/select exports could not be resolved\r\n");
            return 0;
        }

        // The early 1.16/1.20/1.23/1.28 builds are sensitive during bootstrap.
        // For those exact fingerprints, stay on ordinary IAT hooks only; do not
        // rewrite WS2_32's export table or patch Winsock provider DLLs.  1.16
        // previously took the unknown-retail EAT path before crashing.
        wchar_t iatOnlyRequested[8]{};
        const bool retailIatOnly = g_liveTimestamp == 0x69DD404Eu &&
            g_liveImageSize == 0x21679200u && g_liveEntryPoint == 0x06E4931Cu &&
            GetEnvironmentVariableW(L"CODREVAMPED_RETAIL_IAT_ONLY", iatOnlyRequested,
                static_cast<DWORD>(std::size(iatOnlyRequested))) && iatOnlyRequested[0] == L'1';
        if (retailIatOnly)
        {
            ConsolePrint("[WS2-EXPORT] Steam retail diagnostic: EAT hooks disabled; DNS IAT hooks retained\r\n");
        }
        else if (IsSupportedStartupCompatBuild())
        {
            ConsolePrint("[WS2-EXPORT] skipped for early startup build=%s; using stable main/app IAT hooks only\r\n",
                StartupCompatBuildName(CurrentStartupCompatBuild()));
        }
        else
        {
            InstallWs2ExportTrace();
        }

        // Let the loader/anti-tamper/bootstrap work finish before touching the
        // executable's IAT.  The keylist request happens much later than this.
        Sleep(1500);

        // Early builds authenticate Auth3 replies with a 294-byte RSA public
        // key embedded in .rdata.  The local server owns a separate persisted
        // signing key, so adapt only that public verifier before Auth3 traffic.
        // DNS hooks retry at the exact auth3 hostname if the server had not yet
        // produced auth3-response-signing-public.der at this first attempt.
        if (IsSupportedStartupCompatBuild())
        {
            // These trust RVAs are proven only for 1.20.  Do not copy them into
            // 1.16 just because it now shares the safe startup compatibility
            // path; doing so would turn a startup fix into a build-specific crash.
            if (CurrentStartupCompatBuild() == StartupCompatBuild::MW120)
            {
                InstallEarlyAuth3LocalSigningTrust("worker-pre-IAT");
                InstallLocalManifestTrust();
            }
            QueueLsgKey3DiskScanV79();
        }
        else if (g_liveTimestamp == 0x69DD404Eu && g_liveImageSize == 0x21679200u &&
            g_liveEntryPoint == 0x06E4931Cu)
        {
            // Reuse the public-SPKI disk scanner for this retail build. No
            // verifier replacement: the server checks candidates against the
            // client's own lobby proof before accepting a key derivation.
            QueueLsgKey3DiskScanV79();
        }

        HMODULE mainModule = GetModuleHandleW(nullptr);
        const auto mainCounts = PatchNetworkImportsForModule(mainModule);

        ConsolePrint("[REDIRECT] one-time main-EXE hook pass complete dns=%u connectTrace=%u socketTrace=%u wsaSocketTrace=%u ioctlTrace=%u selectTrace=%u\r\n",
            mainCounts.dns, mainCounts.connect, mainCounts.socket, mainCounts.extendedSocket, mainCounts.ioctl, mainCounts.select);
        if (UseDnsOnlyNetworkHooks())
        {
            ConsolePrint("[REDIRECT] safe retail mode: DNS redirection only; socket/connect/WSAIoctl/select trace hooks are disabled\r\n");
            ConsolePrint("[REDIRECT] set CODREVAMPED_FULL_NET_TRACE=1 only when invasive transport diagnostics are needed\r\n");
        }
        else
        {
            ConsolePrint("[REDIRECT] socket/WSASocket/connect/WSAConnect/WSAIoctl/select tracing is passthrough-only; destination, sockaddr, return value, and WSA error are not modified\r\n");
            ConsolePrint("[REDIRECT] WSAID_CONNECTEX results are wrapped only for logging, then forwarded to the real provider ConnectEx pointer\r\n");
        }
        if (IsSupportedStartupCompatBuild() || retailIatOnly)
            ConsolePrint("[REDIRECT] IAT-only mode: WS2_32 EAT hooks disabled; one delayed app-module IAT pass will run once\r\n");
        else if (UseDnsOnlyNetworkHooks())
            ConsolePrint("[REDIRECT] current/unknown retail stability mode: WS2_32 EAT is DNS-only; one delayed DNS-only app-module IAT pass will run once\r\n");
        else
            ConsolePrint("[REDIRECT] WS2_32 EAT hooks cover future dynamic resolutions; no permanent module scanner; one delayed loaded-module IAT pass will run once\r\n");
        ConsolePrint("[REDIRECT] no sendto/WSASendTo hooks; no game-state hooks\r\n");
        if (!mainCounts.dns)
            ConsolePrint("[REDIRECT] WARNING: main EXE has no matching WS2_32 DNS imports\r\n");
        if (!mainCounts.connect)
            ConsolePrint("[REDIRECT] main EXE has no direct connect/WSAConnect imports; waiting for one-shot loaded-module pass\r\n");

        // One delayed pass only.  This catches Battle.net/Demonware helper DLLs
        // that are loaded after the executable starts, without running a module scanner.
        Sleep(18000);
        OneShotLoadedModuleNetworkPass();
        return 0;
    }

    BOOL CALLBACK LoadRealVersionOnce(PINIT_ONCE, PVOID, PVOID*) noexcept
    {
        wchar_t systemDir[MAX_PATH]{};
        const UINT length = GetSystemDirectoryW(systemDir, MAX_PATH);
        if (!length || length >= MAX_PATH)
            return TRUE;
        wchar_t path[MAX_PATH]{};
        _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\version.dll", systemDir);
        g_realVersion = LoadLibraryW(path);
        return TRUE;
    }

    HMODULE RealVersion() noexcept
    {
        InitOnceExecuteOnce(&g_realVersionOnce, LoadRealVersionOnce, nullptr, nullptr);
        return g_realVersion;
    }

    template <typename T>
    T ResolveVersion(const char* name) noexcept
    {
        HMODULE module = RealVersion();
        return reinterpret_cast<T>(module ? GetProcAddress(module, name) : nullptr);
    }
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR file, DWORD handle, DWORD len, LPVOID data)
{
    using Fn = BOOL(WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoA");
    return fn ? fn(file, handle, len, data) : FALSE;
}
extern "C" BOOL WINAPI Proxy_GetFileVersionInfoByHandle(DWORD flags, HANDLE file, LPVOID* data, PDWORD len)
{
    using Fn = BOOL(WINAPI*)(DWORD, HANDLE, LPVOID*, PDWORD);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoByHandle");
    return fn ? fn(flags, file, data, len) : FALSE;
}
extern "C" BOOL WINAPI Proxy_GetFileVersionInfoExA(DWORD flags, LPCSTR file, DWORD handle, DWORD len, LPVOID data)
{
    using Fn = BOOL(WINAPI*)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoExA");
    return fn ? fn(flags, file, handle, len, data) : FALSE;
}
extern "C" BOOL WINAPI Proxy_GetFileVersionInfoExW(DWORD flags, LPCWSTR file, DWORD handle, DWORD len, LPVOID data)
{
    using Fn = BOOL(WINAPI*)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoExW");
    return fn ? fn(flags, file, handle, len, data) : FALSE;
}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR file, LPDWORD handle)
{
    using Fn = DWORD(WINAPI*)(LPCSTR, LPDWORD);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoSizeA");
    return fn ? fn(file, handle) : 0;
}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(DWORD flags, LPCSTR file, LPDWORD handle)
{
    using Fn = DWORD(WINAPI*)(DWORD, LPCSTR, LPDWORD);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoSizeExA");
    return fn ? fn(flags, file, handle) : 0;
}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(DWORD flags, LPCWSTR file, LPDWORD handle)
{
    using Fn = DWORD(WINAPI*)(DWORD, LPCWSTR, LPDWORD);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoSizeExW");
    return fn ? fn(flags, file, handle) : 0;
}
extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR file, LPDWORD handle)
{
    using Fn = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoSizeW");
    return fn ? fn(file, handle) : 0;
}
extern "C" BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR file, DWORD handle, DWORD len, LPVOID data)
{
    using Fn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID);
    const auto fn = ResolveVersion<Fn>("GetFileVersionInfoW");
    return fn ? fn(file, handle, len, data) : FALSE;
}
extern "C" DWORD WINAPI Proxy_VerFindFileA(DWORD flags, LPCSTR fileName, LPCSTR winDir, LPCSTR appDir, LPSTR curDir, PUINT curDirLen, LPSTR destDir, PUINT destDirLen)
{
    using Fn = DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
    const auto fn = ResolveVersion<Fn>("VerFindFileA");
    return fn ? fn(flags, fileName, winDir, appDir, curDir, curDirLen, destDir, destDirLen) : 0;
}
extern "C" DWORD WINAPI Proxy_VerFindFileW(DWORD flags, LPCWSTR fileName, LPCWSTR winDir, LPCWSTR appDir, LPWSTR curDir, PUINT curDirLen, LPWSTR destDir, PUINT destDirLen)
{
    using Fn = DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    const auto fn = ResolveVersion<Fn>("VerFindFileW");
    return fn ? fn(flags, fileName, winDir, appDir, curDir, curDirLen, destDir, destDirLen) : 0;
}
extern "C" DWORD WINAPI Proxy_VerInstallFileA(DWORD flags, LPCSTR srcFile, LPCSTR destFile, LPCSTR srcDir, LPCSTR destDir, LPCSTR curDir, LPSTR tmpFile, PUINT tmpFileLen)
{
    using Fn = DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
    const auto fn = ResolveVersion<Fn>("VerInstallFileA");
    return fn ? fn(flags, srcFile, destFile, srcDir, destDir, curDir, tmpFile, tmpFileLen) : 0;
}
extern "C" DWORD WINAPI Proxy_VerInstallFileW(DWORD flags, LPCWSTR srcFile, LPCWSTR destFile, LPCWSTR srcDir, LPCWSTR destDir, LPCWSTR curDir, LPWSTR tmpFile, PUINT tmpFileLen)
{
    using Fn = DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
    const auto fn = ResolveVersion<Fn>("VerInstallFileW");
    return fn ? fn(flags, srcFile, destFile, srcDir, destDir, curDir, tmpFile, tmpFileLen) : 0;
}
extern "C" DWORD WINAPI Proxy_VerLanguageNameA(DWORD lang, LPSTR text, DWORD chars)
{
    using Fn = DWORD(WINAPI*)(DWORD, LPSTR, DWORD);
    const auto fn = ResolveVersion<Fn>("VerLanguageNameA");
    return fn ? fn(lang, text, chars) : 0;
}
extern "C" DWORD WINAPI Proxy_VerLanguageNameW(DWORD lang, LPWSTR text, DWORD chars)
{
    using Fn = DWORD(WINAPI*)(DWORD, LPWSTR, DWORD);
    const auto fn = ResolveVersion<Fn>("VerLanguageNameW");
    return fn ? fn(lang, text, chars) : 0;
}
extern "C" BOOL WINAPI Proxy_VerQueryValueA(LPCVOID block, LPCSTR subBlock, LPVOID* buffer, PUINT len)
{
    using Fn = BOOL(WINAPI*)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    const auto fn = ResolveVersion<Fn>("VerQueryValueA");
    return fn ? fn(block, subBlock, buffer, len) : FALSE;
}
extern "C" BOOL WINAPI Proxy_VerQueryValueW(LPCVOID block, LPCWSTR subBlock, LPVOID* buffer, PUINT len)
{
    using Fn = BOOL(WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    const auto fn = ResolveVersion<Fn>("VerQueryValueW");
    return fn ? fn(block, subBlock, buffer, len) : FALSE;
}

extern "C" __declspec(dllexport) void CALLBACK MW116Monitor(HWND, HINSTANCE, LPSTR commandLine, int)
{
    unsigned long pid = 0;
    if (!commandLine || sscanf_s(commandLine, "%lu", &pid) != 1 || pid == 0)
        return;

    const ULONGLONG started = GetTickCount64();
    HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!process)
    {
        Write116MonitorLogLine("[MW116-EXT] targetPid=%lu OpenProcess FAILED win32=%lu\r\n",
            pid, static_cast<unsigned long>(GetLastError()));
        return;
    }

    Write116MonitorLogLine("[MW116-EXT] monitor-start targetPid=%lu\r\n", pid);
    const DWORD wait = WaitForSingleObject(process, INFINITE);
    DWORD exitCode = STILL_ACTIVE;
    const BOOL gotExit = GetExitCodeProcess(process, &exitCode);
    const ULONGLONG lifetimeMs = GetTickCount64() - started;
    Write116MonitorLogLine("[MW116-EXT] targetPid=%lu wait=0x%08lX exitCode=%s0x%08lX monitorLifetimeMs=%llu\r\n",
        pid, static_cast<unsigned long>(wait), gotExit ? "" : "unknown:",
        static_cast<unsigned long>(exitCode), static_cast<unsigned long long>(lifetimeMs));
    CloseHandle(process);
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = module;
        g_processAttachThreadId = GetCurrentThreadId();
        DisableThreadLibraryCalls(module);

        // The out-of-process 1.16 exit-code monitor is hosted by rundll32 using
        // this same DLL. Never initialize the game proxy from that helper.
        if (IsRundll32Process())
        {
            InterlockedExchange(&g_mw116MonitorHost, 1);
            return TRUE;
        }

        // Supported early IW8 builds (including the 1.16 fingerprint) perform
        // launcher/bootstrap checks before the normal game flow. Detect by exact
        // live fingerprint and install the scoped compatibility path before the
        // EXE entry point runs.
        Install123StartupCompatibility();

        if (HANDLE thread = CreateThread(nullptr, 0, RedirectWorker, nullptr, 0, nullptr))
            CloseHandle(thread);
    }
    else if (reason == DLL_PROCESS_DETACH && InterlockedCompareExchange(&g_compat123Detected, 0, 0) != 0)
    {
        Write123StartupLog("[DETACH] version.dll process detach reserved=%p mode=%s\r\n",
            reserved, reserved ? "process-termination" : "FreeLibrary/unload");
    }
    return TRUE;
}
