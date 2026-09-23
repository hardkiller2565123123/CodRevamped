#include "MW2019Patches.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace
{
    constexpr std::uint32_t kMW128Timestamp = 0x5F8DEF10u;
    constexpr std::uint32_t kMW128ImageSize = 0x1D02BC00u;
    constexpr std::uint32_t kMW128EntryPoint = 0x048D8F78u;

    constexpr DWORD kCompatMajor = 10;
    constexpr DWORD kCompatMinor = 0;
    constexpr DWORD kCompatBuild = 19041;

    using GetVersionExAFn = BOOL (WINAPI*)(LPOSVERSIONINFOA);
    using VerifyVersionInfoAFn = BOOL (WINAPI*)(LPOSVERSIONINFOEXA, DWORD, DWORDLONG);
    using VerifyVersionInfoWFn = BOOL (WINAPI*)(LPOSVERSIONINFOEXW, DWORD, DWORDLONG);

    // POD/zero-initialized only: these remain valid even when 1.28 bypasses
    // this DLL's C/C++ CRT constructors.
    std::uintptr_t g_mainBase = 0;
    GetVersionExAFn g_realGetVersionExA = nullptr;
    VerifyVersionInfoAFn g_realVerifyVersionInfoA = nullptr;
    VerifyVersionInfoWFn g_realVerifyVersionInfoW = nullptr;
    volatile LONG g_installState = 0; // 0=not installed, 1=installing, 2=installed
    volatile LONG g_retryQueued = 0;

    bool AsciiEqualInsensitive(const char* a, const char* b) noexcept
    {
        if (!a || !b)
            return false;

        for (;; ++a, ++b)
        {
            unsigned char ca = static_cast<unsigned char>(*a);
            unsigned char cb = static_cast<unsigned char>(*b);
            if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca + ('a' - 'A'));
            if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb + ('a' - 'A'));
            if (ca != cb)
                return false;
            if (!ca)
                return true;
        }
    }

    bool AsciiEqual(const char* a, const char* b) noexcept
    {
        if (!a || !b)
            return false;
        while (*a && *b)
        {
            if (*a++ != *b++)
                return false;
        }
        return *a == *b;
    }

    bool ReadFingerprint(
        std::uintptr_t& base,
        std::uint32_t& timestamp,
        std::uint32_t& imageSize,
        std::uint32_t& entryPoint) noexcept
    {
        base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
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
            {
                return false;
            }

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

    bool WritePointer(void** slot, void* value) noexcept
    {
        if (!slot || !value)
            return false;

        DWORD oldProtect = 0;
        if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
            return false;

        InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(slot),
            value);

        DWORD ignored = 0;
        VirtualProtect(slot, sizeof(void*), oldProtect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
        return true;
    }

    bool PatchMainImport(
        const char* wantedDll,
        const char* wantedName,
        void* replacement,
        void** original) noexcept
    {
        if (!g_mainBase || !wantedDll || !wantedName || !replacement)
            return false;

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_mainBase);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                g_mainBase + static_cast<std::uintptr_t>(dos->e_lfanew));
            const auto& importDir =
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!importDir.VirtualAddress || !importDir.Size)
                return false;

            auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                g_mainBase + importDir.VirtualAddress);

            for (; descriptor->Name; ++descriptor)
            {
                const char* dllName = reinterpret_cast<const char*>(
                    g_mainBase + descriptor->Name);
                if (!AsciiEqualInsensitive(dllName, wantedDll))
                    continue;

                auto* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                    g_mainBase + descriptor->FirstThunk);
                auto* originalThunk = descriptor->OriginalFirstThunk
                    ? reinterpret_cast<IMAGE_THUNK_DATA64*>(
                        g_mainBase + descriptor->OriginalFirstThunk)
                    : nullptr;
                if (!originalThunk)
                    return false;

                for (std::size_t i = 0; originalThunk[i].u1.AddressOfData; ++i)
                {
                    if (IMAGE_SNAP_BY_ORDINAL64(originalThunk[i].u1.Ordinal))
                        continue;

                    const auto* byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        g_mainBase + originalThunk[i].u1.AddressOfData);
                    const char* importName = reinterpret_cast<const char*>(byName->Name);
                    if (!AsciiEqual(importName, wantedName))
                        continue;

                    void** slot = reinterpret_cast<void**>(&firstThunk[i].u1.Function);
                    if (original)
                        *original = *slot;
                    return WritePointer(slot, replacement);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        return false;
    }

    void FillCompatVersionA(LPOSVERSIONINFOA info) noexcept
    {
        if (!info)
            return;

        info->dwMajorVersion = kCompatMajor;
        info->dwMinorVersion = kCompatMinor;
        info->dwBuildNumber = kCompatBuild;
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

    BOOL WINAPI HookGetVersionExA(LPOSVERSIONINFOA info) noexcept
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

    BYTE ConditionFor(DWORDLONG mask, DWORD type) noexcept
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

    bool CompareValue(ULONGLONG current, ULONGLONG requested, BYTE condition) noexcept
    {
        switch (condition)
        {
        case VER_EQUAL:         return current == requested;
        case VER_GREATER:       return current > requested;
        case VER_GREATER_EQUAL: return current >= requested;
        case VER_LESS:          return current < requested;
        case VER_LESS_EQUAL:    return current <= requested;
        default:                return false;
        }
    }

    template <typename T>
    bool CompatVersionSatisfies(
        const T* requested,
        DWORD typeMask,
        DWORDLONG conditionMask) noexcept
    {
        if (!requested)
            return false;

        if (typeMask & VER_MAJORVERSION)
        {
            const BYTE c = ConditionFor(conditionMask, VER_MAJORVERSION);
            if (!c || !CompareValue(kCompatMajor, requested->dwMajorVersion, c))
                return false;
        }
        if (typeMask & VER_MINORVERSION)
        {
            const BYTE c = ConditionFor(conditionMask, VER_MINORVERSION);
            if (!c || !CompareValue(kCompatMinor, requested->dwMinorVersion, c))
                return false;
        }
        if (typeMask & VER_BUILDNUMBER)
        {
            const BYTE c = ConditionFor(conditionMask, VER_BUILDNUMBER);
            if (!c || !CompareValue(kCompatBuild, requested->dwBuildNumber, c))
                return false;
        }
        if (typeMask & VER_PLATFORMID)
        {
            const BYTE c = ConditionFor(conditionMask, VER_PLATFORMID);
            if (!c || !CompareValue(VER_PLATFORM_WIN32_NT, requested->dwPlatformId, c))
                return false;
        }
        if (typeMask & VER_PRODUCT_TYPE)
        {
            const BYTE c = ConditionFor(conditionMask, VER_PRODUCT_TYPE);
            if (!c || !CompareValue(VER_NT_WORKSTATION, requested->wProductType, c))
                return false;
        }
        if (typeMask & VER_SUITENAME)
            return false;

        return true;
    }

    BOOL WINAPI HookVerifyVersionInfoA(
        LPOSVERSIONINFOEXA info,
        DWORD typeMask,
        DWORDLONG conditionMask) noexcept
    {
        if (g_realVerifyVersionInfoA &&
            g_realVerifyVersionInfoA(info, typeMask, conditionMask))
        {
            return TRUE;
        }

        if (GetLastError() == ERROR_OLD_WIN_VERSION &&
            CompatVersionSatisfies(info, typeMask, conditionMask))
        {
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }
        return FALSE;
    }

    BOOL WINAPI HookVerifyVersionInfoW(
        LPOSVERSIONINFOEXW info,
        DWORD typeMask,
        DWORDLONG conditionMask) noexcept
    {
        if (g_realVerifyVersionInfoW &&
            g_realVerifyVersionInfoW(info, typeMask, conditionMask))
        {
            return TRUE;
        }

        if (GetLastError() == ERROR_OLD_WIN_VERSION &&
            CompatVersionSatisfies(info, typeMask, conditionMask))
        {
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }
        return FALSE;
    }
}

namespace mw2019_patches
{
    bool IsExact128LoaderSafe() noexcept
    {
        std::uintptr_t base = 0;
        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;
        if (!ReadFingerprint(base, timestamp, imageSize, entryPoint))
            return false;

        return timestamp == kMW128Timestamp &&
               imageSize == kMW128ImageSize &&
               entryPoint == kMW128EntryPoint;
    }

    bool Initialize128LoaderSafe() noexcept
    {
        const LONG state = InterlockedCompareExchange(&g_installState, 1, 0);
        if (state == 2)
            return true;
        if (state == 1)
            return false;

        std::uintptr_t base = 0;
        std::uint32_t timestamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t entryPoint = 0;
        if (!ReadFingerprint(base, timestamp, imageSize, entryPoint) ||
            timestamp != kMW128Timestamp ||
            imageSize != kMW128ImageSize ||
            entryPoint != kMW128EntryPoint)
        {
            InterlockedExchange(&g_installState, 0);
            return false;
        }

        g_mainBase = base;
        unsigned patched = 0;
        void* original = nullptr;

        if (PatchMainImport(
                "KERNEL32.dll",
                "GetVersionExA",
                reinterpret_cast<void*>(&HookGetVersionExA),
                &original))
        {
            g_realGetVersionExA = reinterpret_cast<GetVersionExAFn>(original);
            ++patched;
        }

        original = nullptr;
        if (PatchMainImport(
                "KERNEL32.dll",
                "VerifyVersionInfoA",
                reinterpret_cast<void*>(&HookVerifyVersionInfoA),
                &original))
        {
            g_realVerifyVersionInfoA = reinterpret_cast<VerifyVersionInfoAFn>(original);
            ++patched;
        }

        original = nullptr;
        if (PatchMainImport(
                "KERNEL32.dll",
                "VerifyVersionInfoW",
                reinterpret_cast<void*>(&HookVerifyVersionInfoW),
                &original))
        {
            g_realVerifyVersionInfoW = reinterpret_cast<VerifyVersionInfoWFn>(original);
            ++patched;
        }

        if (patched != 0)
        {
            InterlockedExchange(&g_installState, 2);
            return true;
        }

        // The protected image can still be settling during DLL_PROCESS_ATTACH.
        // Leave the state retryable so the patch-only worker can try again
        // after Windows releases loader lock.
        InterlockedExchange(&g_installState, 0);
        return false;
    }

    bool InitializeEarly()
    {
        if (IsExact128LoaderSafe())
            return Initialize128LoaderSafe();
        return false;
    }

    namespace
    {
        DWORD WINAPI Win11PatchRetryThread(LPVOID) noexcept
        {
            // Nothing except the 1.28 Win11 compatibility patch runs here.
            // Retry for ~5 seconds so Arxan/protected startup has time to settle.
            for (unsigned attempt = 0; attempt < 100; ++attempt)
            {
                if (Initialize128LoaderSafe())
                    break;
                Sleep(50);
            }

            InterlockedExchange(&g_retryQueued, 0);
            return 0;
        }
    }

    void QueueDeferredInitialize() noexcept
    {
        if (!IsExact128LoaderSafe())
            return;

        // Always try immediately. If that succeeds there is no thread at all.
        if (Initialize128LoaderSafe())
            return;

        if (InterlockedCompareExchange(&g_retryQueued, 1, 0) != 0)
            return;

        HANDLE thread = CreateThread(nullptr, 0, Win11PatchRetryThread, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
        else
        {
            InterlockedExchange(&g_retryQueued, 0);
        }
    }
}
