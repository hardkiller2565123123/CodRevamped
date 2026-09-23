#include "Win11Patch.h"

#include <Windows.h>
#include "../../../third_party/bo4/minhook/include/MinHook.h"

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{
    using patches::win11::Profile;
    using SetUnhandledExceptionFilterFn =
        LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER);

    std::atomic_bool g_initialized{ false };
    std::atomic_bool g_armed{ false };
    std::atomic_bool g_applied{ false };
    std::atomic_uint32_t g_filterCallCount{ 0 };
    std::atomic_uint32_t g_exceptionProbeCount{ 0 };
    std::atomic_uint32_t g_runtimeRestoreByte{ 0xFFFFFFFFu };
    std::atomic_bool g_probeDumpWritten{ false };

    Profile g_profile{};
    bool g_hasProfile = false;
    bool g_discoveryOnly = false;

    std::uintptr_t g_base = 0;
    std::uintptr_t g_filterAddress = 0;
    std::uintptr_t g_breakpointAddress = 0;
    std::uintptr_t g_resumeAddress = 0;

    void* g_setUnhandledTarget = nullptr;
    SetUnhandledExceptionFilterFn g_originalSetUnhandledExceptionFilter = nullptr;
    PVOID g_veh = nullptr;

    void WriteLog(const char* fmt, ...)
    {
        // Keep this deliberately lightweight because Win11Patch can run before
        // the normal CodRevamped storage/logging runtime is initialized.
        CreateDirectoryW(L"logs", nullptr);
        CreateDirectoryW(L"logs\\win11_patch", nullptr);

        FILE* f = nullptr;
        if (fopen_s(&f, "logs\\win11_patch\\win11_patch.log", "a") != 0 || !f)
            return;

        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(f, fmt, ap);
        va_end(ap);
        std::fputc('\n', f);
        std::fflush(f);
        std::fclose(f);
    }

    bool ReadCurrentFingerprint(
        patches::win11::ExecutableFingerprint& fingerprint,
        std::uintptr_t& base)
    {
        const auto module = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!module)
            return false;

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                module + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return false;

            fingerprint.timestamp = nt->FileHeader.TimeDateStamp;
            fingerprint.imageSize = nt->OptionalHeader.SizeOfImage;
            fingerprint.entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
            base = module;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool FingerprintMatches(
        const patches::win11::ExecutableFingerprint& actual,
        const patches::win11::ExecutableFingerprint& expected)
    {
        return actual.timestamp == expected.timestamp &&
               actual.imageSize == expected.imageSize &&
               actual.entryPointRva == expected.entryPointRva;
    }

    bool IsReadableExecutableAddress(std::uintptr_t address)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
            return false;

        if (mbi.State != MEM_COMMIT ||
            (mbi.Protect & PAGE_GUARD) ||
            (mbi.Protect & PAGE_NOACCESS))
            return false;

        const DWORD protection = mbi.Protect & 0xFFu;
        return protection == PAGE_EXECUTE ||
               protection == PAGE_EXECUTE_READ ||
               protection == PAGE_EXECUTE_READWRITE ||
               protection == PAGE_EXECUTE_WRITECOPY;
    }

    bool IsInsideGameAddress(std::uintptr_t address)
    {
        if (!g_base || !g_profile.executable.imageSize)
            return false;

        const auto end = g_base + g_profile.executable.imageSize;
        return address >= g_base && address < end;
    }

    bool ReadByte(std::uintptr_t address, std::uint8_t& value)
    {
        SIZE_T got = 0;
        return ReadProcessMemory(
                   GetCurrentProcess(),
                   reinterpret_cast<const void*>(address),
                   &value,
                   sizeof(value),
                   &got) &&
               got == sizeof(value);
    }

    std::size_t ReadBytes(
        std::uintptr_t address,
        std::uint8_t* out,
        std::size_t count)
    {
        if (!address || !out || !count)
            return 0;

        SIZE_T got = 0;
        if (!ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(address),
                out,
                count,
                &got))
        {
            return 0;
        }

        return static_cast<std::size_t>(got);
    }

    void FormatBytes(
        const std::uint8_t* bytes,
        std::size_t count,
        char* out,
        std::size_t outSize)
    {
        if (!out || !outSize)
            return;

        out[0] = '\0';
        std::size_t pos = 0;
        for (std::size_t i = 0; i < count && pos + 4 < outSize; ++i)
        {
            const int written = std::snprintf(
                out + pos,
                outSize - pos,
                "%s%02X",
                i ? " " : "",
                static_cast<unsigned>(bytes[i]));

            if (written <= 0)
                break;

            pos += static_cast<std::size_t>(written);
        }
    }

    void WriteProbeDump()
    {
        if (!g_profile.probeDumpRva ||
            !g_profile.probeDumpSize ||
            g_probeDumpWritten.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }

        const auto start = g_base + g_profile.probeDumpRva;
        const auto size = g_profile.probeDumpSize;
        if (!IsInsideGameAddress(start) ||
            !IsInsideGameAddress(start + size - 1))
        {
            WriteLog(
                "event=probe_dump_failed profile=%s reason=range_outside_image "
                "rva=0x%llX size=0x%llX",
                g_profile.name ? g_profile.name : "unnamed",
                static_cast<unsigned long long>(g_profile.probeDumpRva),
                static_cast<unsigned long long>(size));
            return;
        }

        char path[MAX_PATH]{};
        std::snprintf(
            path,
            sizeof(path),
            "logs\\win11_patch\\probe_%08llX_%08llX.bin",
            static_cast<unsigned long long>(g_profile.probeDumpRva),
            static_cast<unsigned long long>(size));

        FILE* f = nullptr;
        if (fopen_s(&f, path, "wb") != 0 || !f)
        {
            WriteLog(
                "event=probe_dump_failed profile=%s reason=open_failed",
                g_profile.name ? g_profile.name : "unnamed");
            return;
        }

        std::uint8_t buffer[4096]{};
        std::size_t written = 0;
        while (written < size)
        {
            std::size_t chunk = size - written;
            if (chunk > sizeof(buffer))
                chunk = sizeof(buffer);

            const std::size_t got =
                ReadBytes(start + written, buffer, chunk);
            if (!got)
                break;

            std::fwrite(buffer, 1, got, f);
            written += got;
            if (got != chunk)
                break;
        }

        std::fclose(f);
        WriteLog(
            "event=probe_dump profile=%s rva=0x%llX size=0x%llX written=0x%llX path=%s",
            g_profile.name ? g_profile.name : "unnamed",
            static_cast<unsigned long long>(g_profile.probeDumpRva),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(written),
            path);
    }

    bool WriteByte(std::uintptr_t address, std::uint8_t value)
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect(
                reinterpret_cast<void*>(address),
                sizeof(value),
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
            return false;

        *reinterpret_cast<volatile std::uint8_t*>(address) = value;
        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<const void*>(address),
            sizeof(value));

        DWORD ignored = 0;
        VirtualProtect(
            reinterpret_cast<void*>(address),
            sizeof(value),
            oldProtect,
            &ignored);
        return true;
    }

    void LogExceptionProbe(EXCEPTION_POINTERS* exceptionPointers)
    {
        if (!g_hasProfile ||
            !exceptionPointers ||
            !exceptionPointers->ExceptionRecord ||
            !exceptionPointers->ContextRecord ||
            g_applied.load(std::memory_order_acquire))
        {
            return;
        }

        const std::uint32_t index =
            g_exceptionProbeCount.fetch_add(1, std::memory_order_relaxed) + 1;
        if (index > 64)
            return;

        const auto* record = exceptionPointers->ExceptionRecord;
        const auto* context = exceptionPointers->ContextRecord;
        const auto code = record->ExceptionCode;
        const auto exceptionAddress =
            reinterpret_cast<std::uintptr_t>(record->ExceptionAddress);
        const auto rip = static_cast<std::uintptr_t>(context->Rip);
        const auto faultAddress =
            record->NumberParameters > 1
                ? static_cast<std::uintptr_t>(record->ExceptionInformation[1])
                : 0;
        const bool exceptionInside = IsInsideGameAddress(exceptionAddress);
        const bool ripInside = IsInsideGameAddress(rip);
        const bool faultInside = IsInsideGameAddress(faultAddress);

        std::uint8_t bytes[32]{};
        const std::size_t got = ReadBytes(rip, bytes, sizeof(bytes));
        char byteText[128]{};
        FormatBytes(bytes, got, byteText, sizeof(byteText));

        WriteLog(
            "event=exception_probe profile=%s index=%u code=0x%08lX "
            "exception=0x%llX exception_rva=0x%llX exception_in_game=%u "
            "rip=0x%llX rip_rva=0x%llX rip_in_game=%u "
            "fault=0x%llX fault_rva=0x%llX fault_in_game=%u "
            "armed=%u applied=%u rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX "
            "rax=0x%llX rbx=0x%llX rsp=0x%llX bytes=%s",
            g_profile.name ? g_profile.name : "unnamed",
            static_cast<unsigned>(index),
            static_cast<unsigned long>(code),
            static_cast<unsigned long long>(exceptionAddress),
            static_cast<unsigned long long>(
                exceptionInside ? exceptionAddress - g_base : 0),
            exceptionInside ? 1u : 0u,
            static_cast<unsigned long long>(rip),
            static_cast<unsigned long long>(ripInside ? rip - g_base : 0),
            ripInside ? 1u : 0u,
            static_cast<unsigned long long>(faultAddress),
            static_cast<unsigned long long>(
                faultInside ? faultAddress - g_base : 0),
            faultInside ? 1u : 0u,
            g_armed.load(std::memory_order_acquire) ? 1u : 0u,
            g_applied.load(std::memory_order_acquire) ? 1u : 0u,
            static_cast<unsigned long long>(context->Rcx),
            static_cast<unsigned long long>(context->Rdx),
            static_cast<unsigned long long>(context->R8),
            static_cast<unsigned long long>(context->R9),
            static_cast<unsigned long long>(context->Rax),
            static_cast<unsigned long long>(context->Rbx),
            static_cast<unsigned long long>(context->Rsp),
            got ? byteText : "unreadable");
    }

    LONG CALLBACK OneShotBreakpointHandler(EXCEPTION_POINTERS* exceptionPointers)
    {
        if (!exceptionPointers ||
            !exceptionPointers->ExceptionRecord ||
            !exceptionPointers->ContextRecord ||
            !g_hasProfile)
            return EXCEPTION_CONTINUE_SEARCH;

        if (exceptionPointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        {
            LogExceptionProbe(exceptionPointers);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (g_discoveryOnly ||
            static_cast<std::uintptr_t>(exceptionPointers->ContextRecord->Rip) !=
                g_breakpointAddress)
        {
            LogExceptionProbe(exceptionPointers);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        const auto runtimeRestore =
            g_runtimeRestoreByte.load(std::memory_order_acquire);
        const auto restoreByte =
            runtimeRestore <= 0xFFu
                ? static_cast<std::uint8_t>(runtimeRestore)
                : g_profile.restoreByte;

        WriteLog(
            "event=breakpoint_hit profile=%s rip=0x%llX "
            "action=restore_%02X_and_redirect profile_restore=0x%02X runtime_restore=0x%02X",
            g_profile.name ? g_profile.name : "unnamed",
            static_cast<unsigned long long>(exceptionPointers->ContextRecord->Rip),
            static_cast<unsigned>(restoreByte),
            static_cast<unsigned>(g_profile.restoreByte),
            runtimeRestore <= 0xFFu ? static_cast<unsigned>(runtimeRestore) : 0xFFFFFFFFu);

        if (!WriteByte(g_breakpointAddress, restoreByte))
        {
            WriteLog(
                "event=breakpoint_restore_failed profile=%s",
                g_profile.name ? g_profile.name : "unnamed");
            return EXCEPTION_CONTINUE_SEARCH;
        }

        exceptionPointers->ContextRecord->Rip = static_cast<DWORD64>(g_resumeAddress);
        g_armed.store(false, std::memory_order_release);
        g_applied.store(true, std::memory_order_release);

        WriteLog(
            "event=redirect profile=%s rip=0x%llX result=continue_execution applied=1",
            g_profile.name ? g_profile.name : "unnamed",
            static_cast<unsigned long long>(g_resumeAddress));

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    LPTOP_LEVEL_EXCEPTION_FILTER WINAPI HookSetUnhandledExceptionFilter(
        LPTOP_LEVEL_EXCEPTION_FILTER filter)
    {
        const auto requested = reinterpret_cast<std::uintptr_t>(filter);
        const std::uint32_t callIndex =
            g_filterCallCount.fetch_add(1, std::memory_order_relaxed) + 1;

        if (callIndex <= 128 && g_hasProfile)
        {
            const bool insideGame = g_base != 0 && requested >= g_base;
            const std::uintptr_t rva = insideGame ? (requested - g_base) : 0;
            WriteLog(
                "event=SetUnhandledExceptionFilter_call profile=%s index=%u "
                "filter=0x%llX inside_game=%u rva=0x%llX expected=0x%llX match=%u",
                g_profile.name ? g_profile.name : "unnamed",
                static_cast<unsigned>(callIndex),
                static_cast<unsigned long long>(requested),
                insideGame ? 1u : 0u,
                static_cast<unsigned long long>(rva),
                static_cast<unsigned long long>(g_profile.exceptionFilterRva),
                requested == g_filterAddress ? 1u : 0u);
        }

        if (g_hasProfile && requested == g_filterAddress &&
            !g_armed.exchange(true, std::memory_order_acq_rel))
        {
            if (g_discoveryOnly)
            {
                WriteLog(
                    "event=observed_target_exception_filter profile=%s address=0x%llX "
                    "action=probe_only",
                    g_profile.name ? g_profile.name : "unnamed",
                    static_cast<unsigned long long>(requested));
                WriteProbeDump();
                return g_originalSetUnhandledExceptionFilter
                    ? g_originalSetUnhandledExceptionFilter(filter)
                    : nullptr;
            }

            std::uint8_t current = 0;
            const bool readOk = ReadByte(g_breakpointAddress, current);
            if (readOk)
                g_runtimeRestoreByte.store(current, std::memory_order_release);

            WriteLog(
                "event=observed_target_exception_filter profile=%s address=0x%llX "
                "action=arm_int3 prepatch_byte=0x%02X prepatch_read=%u",
                g_profile.name ? g_profile.name : "unnamed",
                static_cast<unsigned long long>(requested),
                static_cast<unsigned>(current),
                readOk ? 1u : 0u);

            if (!g_veh || !WriteByte(g_breakpointAddress, 0xCC))
            {
                g_armed.store(false, std::memory_order_release);
                WriteLog(
                    "event=arm_failed profile=%s",
                    g_profile.name ? g_profile.name : "unnamed");
            }
            else
            {
                WriteLog(
                    "event=armed profile=%s breakpoint=0x%llX restore_byte=0x%02X",
                    g_profile.name ? g_profile.name : "unnamed",
                    static_cast<unsigned long long>(g_breakpointAddress),
                    static_cast<unsigned>(g_profile.restoreByte));
            }
        }

        return g_originalSetUnhandledExceptionFilter
            ? g_originalSetUnhandledExceptionFilter(filter)
            : nullptr;
    }
}

namespace patches::win11
{
    bool Initialize(const Profile& profile)
    {
        if (!profile.name ||
            !profile.exceptionFilterRva ||
            (!profile.discoveryOnly &&
                (!profile.breakpointRva || !profile.resumeRva)))
        {
            return false;
        }

        if (g_initialized.load(std::memory_order_acquire))
        {
            return g_hasProfile &&
                   g_profile.name &&
                   std::strcmp(g_profile.name, profile.name) == 0;
        }

        ExecutableFingerprint actual{};
        std::uintptr_t base = 0;
        if (!ReadCurrentFingerprint(actual, base) ||
            !FingerprintMatches(actual, profile.executable))
        {
            return false;
        }

        if (g_initialized.exchange(true, std::memory_order_acq_rel))
            return g_hasProfile;

        g_profile = profile;
        g_hasProfile = true;
        g_discoveryOnly = g_profile.discoveryOnly;
        g_base = base;
        g_filterAddress = g_base + g_profile.exceptionFilterRva;
        g_breakpointAddress =
            g_profile.breakpointRva ? g_base + g_profile.breakpointRva : 0;
        g_resumeAddress =
            g_profile.resumeRva ? g_base + g_profile.resumeRva : 0;
        g_armed.store(false, std::memory_order_release);
        g_applied.store(false, std::memory_order_release);
        g_filterCallCount.store(0, std::memory_order_release);
        g_exceptionProbeCount.store(0, std::memory_order_release);
        g_runtimeRestoreByte.store(0xFFFFFFFFu, std::memory_order_release);
        g_probeDumpWritten.store(false, std::memory_order_release);

        if (!IsReadableExecutableAddress(g_filterAddress) ||
            (!g_discoveryOnly &&
                (!IsReadableExecutableAddress(g_breakpointAddress) ||
                 !IsReadableExecutableAddress(g_resumeAddress))))
        {
            WriteLog(
                "profile=%s match=1 result=skip reason=target_not_executable",
                g_profile.name);
            g_hasProfile = false;
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        if (g_discoveryOnly)
        {
            WriteLog(
                "profile=%s match=1 base=0x%llX filter_rva=0x%llX "
                "breakpoint_rva=0x%llX resume_rva=0x%llX discovery_only=1 "
                "probe_dump_rva=0x%llX probe_dump_size=0x%llX",
                g_profile.name,
                static_cast<unsigned long long>(g_base),
                static_cast<unsigned long long>(g_profile.exceptionFilterRva),
                static_cast<unsigned long long>(g_profile.breakpointRva),
                static_cast<unsigned long long>(g_profile.resumeRva),
                static_cast<unsigned long long>(g_profile.probeDumpRva),
                static_cast<unsigned long long>(g_profile.probeDumpSize));
        }
        else
        {
            std::uint8_t current = 0;
            ReadByte(g_breakpointAddress, current);
            WriteLog(
                "profile=%s match=1 base=0x%llX filter_rva=0x%llX "
                "breakpoint_rva=0x%llX resume_rva=0x%llX restore=0x%02X initial_byte=0x%02X",
                g_profile.name,
                static_cast<unsigned long long>(g_base),
                static_cast<unsigned long long>(g_profile.exceptionFilterRva),
                static_cast<unsigned long long>(g_profile.breakpointRva),
                static_cast<unsigned long long>(g_profile.resumeRva),
                static_cast<unsigned>(g_profile.restoreByte),
                static_cast<unsigned>(current));
        }

        // This stays synchronous and minimal because callers use it as an
        // early-process compatibility layer before normal CodRevamped startup.
        g_veh = AddVectoredExceptionHandler(1, &OneShotBreakpointHandler);
        if (!g_veh)
        {
            WriteLog("veh=install_failed profile=%s error=%lu",
                g_profile.name,
                static_cast<unsigned long>(GetLastError()));
            g_hasProfile = false;
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        const MH_STATUS init = MH_Initialize();
        if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
        {
            WriteLog("minhook=initialize_failed profile=%s status=%d",
                g_profile.name,
                static_cast<int>(init));
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = nullptr;
            g_hasProfile = false;
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        HMODULE kernel32 = GetModuleHandleW(L"KERNEL32.dll");
        if (!kernel32)
        {
            WriteLog("hook=resolve_failed profile=%s module=KERNEL32.dll error=%lu",
                g_profile.name,
                static_cast<unsigned long>(GetLastError()));
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = nullptr;
            g_hasProfile = false;
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        g_setUnhandledTarget = reinterpret_cast<void*>(
            GetProcAddress(kernel32, "SetUnhandledExceptionFilter"));
        if (!g_setUnhandledTarget)
        {
            WriteLog("hook=resolve_failed profile=%s symbol=SetUnhandledExceptionFilter error=%lu",
                g_profile.name,
                static_cast<unsigned long>(GetLastError()));
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = nullptr;
            g_hasProfile = false;
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        const MH_STATUS create = MH_CreateHook(
            g_setUnhandledTarget,
            reinterpret_cast<LPVOID>(&HookSetUnhandledExceptionFilter),
            reinterpret_cast<LPVOID*>(&g_originalSetUnhandledExceptionFilter));
        if (create != MH_OK && create != MH_ERROR_ALREADY_CREATED)
        {
            WriteLog("minhook=create_failed profile=%s status=%d",
                g_profile.name,
                static_cast<int>(create));
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = nullptr;
            g_hasProfile = false;
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        const MH_STATUS enable = MH_EnableHook(g_setUnhandledTarget);
        if (enable != MH_OK && enable != MH_ERROR_ENABLED)
        {
            WriteLog("minhook=enable_failed profile=%s status=%d",
                g_profile.name,
                static_cast<int>(enable));
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = nullptr;
            g_hasProfile = false;
            g_initialized.store(false, std::memory_order_release);
            return false;
        }

        WriteLog(
            "status=ready profile=%s veh=early hook=SetUnhandledExceptionFilter "
            "write_policy=%s",
            g_profile.name,
            g_discoveryOnly ? "probe_only" : "one_shot_only");
        return true;
    }

    bool IsArmed()
    {
        return g_armed.load(std::memory_order_acquire);
    }

    bool HasApplied()
    {
        return g_applied.load(std::memory_order_acquire);
    }

    const char* ActiveProfileName()
    {
        return g_hasProfile && g_profile.name ? g_profile.name : "none";
    }
}
