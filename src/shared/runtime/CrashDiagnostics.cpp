#include "CrashDiagnostics.h"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace crash_diagnostics
{
    namespace
    {
        // Exact June 4th COD2020 Alpha fingerprint used by GameManager/AlphaSupport.
        constexpr std::uint32_t kAlphaTimestamp = 0x5F1B8329u;
        constexpr std::uint32_t kAlphaImageSize = 0x10C4A200u;
        constexpr std::uint32_t kAlphaEntryPoint = 0x02128E60u;

        // These two exception sites already existed in the legacy T9 address table.
        // The 2026-08-22 Alpha crash logs prove that +0x17794C3 is reached by both
        // MP and Zombies map launch and faults while writing into the kernel-side
        // KUSER_SHARED_DATA mapping (FFFFF78000000xxx).
        constexpr std::uintptr_t kKnownExceptionRipA = 0x017794C3ull;
        constexpr std::uintptr_t kKnownExceptionRipB = 0x010DF720ull;
        constexpr std::uintptr_t kKernelSharedDataPage = 0xFFFFF78000000000ull;
        constexpr std::uintptr_t kPageMask = ~static_cast<std::uintptr_t>(0xFFFull);
        constexpr DWORD64 kTrapFlag = 0x100ull;

        PVOID g_vectored = nullptr;
        LPTOP_LEVEL_EXCEPTION_FILTER g_previous = nullptr;
        std::mutex g_logMutex;
        std::unordered_map<std::uintptr_t, std::chrono::steady_clock::time_point> g_recentVeh;
        std::unordered_map<std::uintptr_t, unsigned long long> g_suppressedVeh;
        std::atomic_bool g_alphaSharedDataCompat{ false };

        enum class RegisterSlot : std::uint8_t
        {
            None,
            Rax,
            Rbx,
            Rcx,
            Rdx,
            Rsi,
            Rdi,
            R8,
            R9,
            R10,
            R11,
            R12,
            R13,
            R14,
            R15
        };

        struct PendingRedirect
        {
            bool active = false;
            RegisterSlot slot = RegisterSlot::None;
            DWORD64 originalValue = 0;
            DWORD64 redirectedValue = 0;
            DWORD64 originalEFlags = 0;
            std::uintptr_t faultRip = 0;
            std::uintptr_t faultTarget = 0;
            alignas(64) unsigned char scratch[128]{};
        };

        thread_local PendingRedirect g_pendingRedirect;

        DWORD64* RegisterPointer(CONTEXT* context, RegisterSlot slot)
        {
            if (!context)
                return nullptr;

            switch (slot)
            {
            case RegisterSlot::Rax: return &context->Rax;
            case RegisterSlot::Rbx: return &context->Rbx;
            case RegisterSlot::Rcx: return &context->Rcx;
            case RegisterSlot::Rdx: return &context->Rdx;
            case RegisterSlot::Rsi: return &context->Rsi;
            case RegisterSlot::Rdi: return &context->Rdi;
            case RegisterSlot::R8:  return &context->R8;
            case RegisterSlot::R9:  return &context->R9;
            case RegisterSlot::R10: return &context->R10;
            case RegisterSlot::R11: return &context->R11;
            case RegisterSlot::R12: return &context->R12;
            case RegisterSlot::R13: return &context->R13;
            case RegisterSlot::R14: return &context->R14;
            case RegisterSlot::R15: return &context->R15;
            default: return nullptr;
            }
        }

        const char* RegisterName(RegisterSlot slot)
        {
            switch (slot)
            {
            case RegisterSlot::Rax: return "RAX";
            case RegisterSlot::Rbx: return "RBX";
            case RegisterSlot::Rcx: return "RCX";
            case RegisterSlot::Rdx: return "RDX";
            case RegisterSlot::Rsi: return "RSI";
            case RegisterSlot::Rdi: return "RDI";
            case RegisterSlot::R8:  return "R8";
            case RegisterSlot::R9:  return "R9";
            case RegisterSlot::R10: return "R10";
            case RegisterSlot::R11: return "R11";
            case RegisterSlot::R12: return "R12";
            case RegisterSlot::R13: return "R13";
            case RegisterSlot::R14: return "R14";
            case RegisterSlot::R15: return "R15";
            default: return "NONE";
            }
        }

        bool IsExactAlphaImage()
        {
            const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            if (!base)
                return false;

            __try
            {
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                    return false;

                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE)
                    return false;

                return nt->FileHeader.TimeDateStamp == kAlphaTimestamp &&
                    nt->OptionalHeader.SizeOfImage == kAlphaImageSize &&
                    nt->OptionalHeader.AddressOfEntryPoint == kAlphaEntryPoint;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }


        void CopyInstructionBytes(std::uintptr_t rip, unsigned char* bytes, std::size_t size)
        {
            if (!bytes || size == 0)
                return;

            std::memset(bytes, 0, size);
            if (!rip)
                return;

            __try
            {
                std::memcpy(bytes, reinterpret_cast<const void*>(rip), size);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                std::memset(bytes, 0, size);
            }
        }

        bool GetExecutableImageRange(std::uintptr_t& base, std::uintptr_t& end)
        {
            base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            end = 0;
            if (!base)
                return false;

            __try
            {
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                    return false;

                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                    base + static_cast<std::uintptr_t>(dos->e_lfanew));
                if (nt->Signature != IMAGE_NT_SIGNATURE || !nt->OptionalHeader.SizeOfImage)
                    return false;

                end = base + nt->OptionalHeader.SizeOfImage;
                return end > base;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                base = 0;
                end = 0;
                return false;
            }
        }

        bool TryReadStackQword(std::uintptr_t address, DWORD64& value)
        {
            value = 0;
            if (!address)
                return false;

            __try
            {
                value = *reinterpret_cast<const volatile DWORD64*>(address);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                value = 0;
                return false;
            }
        }

        bool IsBenignDiagnosticException(DWORD code)
        {
            switch (code)
            {
            case 0x40010006: // DBG_PRINTEXCEPTION_C
            case 0x4001000A: // DBG_PRINTEXCEPTION_WIDE_C
            case 0x406D1388: // MSVC thread-name exception
            case 0x80000003: // EXCEPTION_BREAKPOINT (first-chance/debug instrumentation)
            case 0x80000004: // EXCEPTION_SINGLE_STEP (first-chance/debug instrumentation)
            case 0xE06D7363: // handled MSVC C++ exception (VEH first chance)
                return true;
            default:
                return false;
            }
        }

        void AppendCompatLine(const char* phase, RegisterSlot slot, std::intptr_t delta,
            std::uintptr_t rip, std::uintptr_t target, const CONTEXT* context)
        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            FILE* file = nullptr;
            fopen_s(&file, "logs\\runtime\\crash_diagnostics.log", "a");
            if (!file)
                return;

            SYSTEMTIME st{};
            GetLocalTime(&st);

            unsigned char bytes[12]{};
            CopyInstructionBytes(rip, bytes, sizeof(bytes));

            fprintf(file,
                "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ALPHA-COMPAT phase=%s rip=%p target=%p reg=%s delta=%lld bytes=",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                phase ? phase : "unknown",
                reinterpret_cast<void*>(rip),
                reinterpret_cast<void*>(target),
                RegisterName(slot),
                static_cast<long long>(delta));

            for (unsigned char byte : bytes)
                fprintf(file, "%02X", static_cast<unsigned>(byte));

            if (context)
            {
                fprintf(file,
                    " rax=%llX rbx=%llX rcx=%llX rdx=%llX rsi=%llX rdi=%llX r8=%llX r9=%llX r10=%llX r11=%llX r12=%llX r13=%llX r14=%llX r15=%llX",
                    static_cast<unsigned long long>(context->Rax),
                    static_cast<unsigned long long>(context->Rbx),
                    static_cast<unsigned long long>(context->Rcx),
                    static_cast<unsigned long long>(context->Rdx),
                    static_cast<unsigned long long>(context->Rsi),
                    static_cast<unsigned long long>(context->Rdi),
                    static_cast<unsigned long long>(context->R8),
                    static_cast<unsigned long long>(context->R9),
                    static_cast<unsigned long long>(context->R10),
                    static_cast<unsigned long long>(context->R11),
                    static_cast<unsigned long long>(context->R12),
                    static_cast<unsigned long long>(context->R13),
                    static_cast<unsigned long long>(context->R14),
                    static_cast<unsigned long long>(context->R15));
            }

            fprintf(file, "\n");
            fclose(file);
        }

        void WriteLine(EXCEPTION_POINTERS* info, const char* origin)
        {
            if (!info || !info->ExceptionRecord || !info->ContextRecord)
                return;
            if (origin && strcmp(origin, "VEH") == 0 &&
                IsBenignDiagnosticException(info->ExceptionRecord->ExceptionCode))
                return;
            std::lock_guard<std::mutex> lock(g_logMutex);
            if (origin && strcmp(origin, "VEH") == 0)
            {
                const auto rip = static_cast<std::uintptr_t>(info->ContextRecord->Rip);
                const auto now = std::chrono::steady_clock::now();
                const auto it = g_recentVeh.find(rip);
                if (it != g_recentVeh.end() && now - it->second < std::chrono::seconds(5))
                {
                    ++g_suppressedVeh[rip];
                    return;
                }
                g_recentVeh[rip] = now;
            }
            FILE* file = nullptr;
            fopen_s(&file, "logs\\runtime\\crash_diagnostics.log", "a");
            if (!file)
                return;
            SYSTEMTIME st{};
            GetLocalTime(&st);
            const auto rip = static_cast<std::uintptr_t>(info->ContextRecord->Rip);
            std::uintptr_t exeBase = 0;
            std::uintptr_t exeEnd = 0;
            (void)GetExecutableImageRange(exeBase, exeEnd);
            std::uintptr_t exeRva = 0;
            if (exeBase && rip >= exeBase && (!exeEnd || rip < exeEnd))
                exeRva = rip - exeBase;

            HMODULE faultModule = nullptr;
            wchar_t modulePath[MAX_PATH]{};
            if (GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCWSTR>(rip), &faultModule) && faultModule)
            {
                GetModuleFileNameW(faultModule, modulePath, MAX_PATH);
            }

            fprintf(file,
                "[%04u-%02u-%02u %02u:%02u:%02u.%03u] %s code=0x%08lX flags=0x%08lX params=%lu address=%p rip=%p rsp=%p thread=%lu exeBase=%p exeRva=0x%llX",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                origin ? origin : "exception",
                info->ExceptionRecord->ExceptionCode,
                info->ExceptionRecord->ExceptionFlags,
                info->ExceptionRecord->NumberParameters,
                info->ExceptionRecord->ExceptionAddress,
                reinterpret_cast<void*>(info->ContextRecord->Rip),
                reinterpret_cast<void*>(info->ContextRecord->Rsp),
                GetCurrentThreadId(),
                reinterpret_cast<void*>(exeBase),
                static_cast<unsigned long long>(exeRva));

            if (modulePath[0])
                fprintf(file, " module=%ls", modulePath);

            if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                info->ExceptionRecord->NumberParameters >= 2)
            {
                const ULONG_PTR accessType = info->ExceptionRecord->ExceptionInformation[0];
                const ULONG_PTR target = info->ExceptionRecord->ExceptionInformation[1];
                const char* access = accessType == 0 ? "read" : (accessType == 1 ? "write" : (accessType == 8 ? "execute" : "unknown"));
                fprintf(file, " access=%s target=%p", access, reinterpret_cast<void*>(target));
            }

            const ULONG parameterCount =
                info->ExceptionRecord->NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS
                    ? EXCEPTION_MAXIMUM_PARAMETERS
                    : info->ExceptionRecord->NumberParameters;
            for (ULONG i = 0; i < parameterCount; ++i)
            {
                fprintf(file, " p%lu=0x%llX", i,
                    static_cast<unsigned long long>(info->ExceptionRecord->ExceptionInformation[i]));
            }

            fprintf(file,
                " rcx=%llX rdx=%llX r8=%llX r9=%llX rax=%llX rbx=%llX",
                static_cast<unsigned long long>(info->ContextRecord->Rcx),
                static_cast<unsigned long long>(info->ContextRecord->Rdx),
                static_cast<unsigned long long>(info->ContextRecord->R8),
                static_cast<unsigned long long>(info->ContextRecord->R9),
                static_cast<unsigned long long>(info->ContextRecord->Rax),
                static_cast<unsigned long long>(info->ContextRecord->Rbx));

            // RaiseException-style failures land in KERNELBASE, which hid the
            // actual Alpha call site in earlier logs. Scan a small, read-only
            // window of the captured stack and report values that point back
            // inside COD2020.exe. This works against the mapped/decrypted image
            // and does not require the packed on-disk EXE to be disassemblable.
            if (exeBase && exeEnd > exeBase)
            {
                unsigned int gameStackCount = 0;
                const std::uintptr_t rsp = static_cast<std::uintptr_t>(info->ContextRecord->Rsp);
                for (std::size_t slot = 0; slot < 256 && gameStackCount < 16; ++slot)
                {
                    DWORD64 value = 0;
                    const std::uintptr_t stackAddress = rsp + slot * sizeof(DWORD64);
                    if (!TryReadStackQword(stackAddress, value))
                        break;

                    const std::uintptr_t candidate = static_cast<std::uintptr_t>(value);
                    if (candidate >= exeBase && candidate < exeEnd)
                    {
                        fprintf(file, " gameStack%u=[rsp+0x%zX]->+0x%llX",
                            gameStackCount,
                            slot * sizeof(DWORD64),
                            static_cast<unsigned long long>(candidate - exeBase));
                        ++gameStackCount;
                    }
                }
                if (!gameStackCount)
                    fprintf(file, " gameStack=none-in-first-0x800");
            }

            fprintf(file, "\n");
            fclose(file);
        }

        bool TryRestoreRedirectAfterSingleStep(EXCEPTION_POINTERS* info)
        {
            if (!g_pendingRedirect.active || !info || !info->ExceptionRecord || !info->ContextRecord)
                return false;

            if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
                return false;

            auto* reg = RegisterPointer(info->ContextRecord, g_pendingRedirect.slot);
            if (!reg)
            {
                g_pendingRedirect.active = false;
                return false;
            }

            // Preserve register auto-increment/decrement from string instructions.
            // Ordinary MOV-style writes leave this delta at zero.
            const auto movement = static_cast<std::intptr_t>(*reg - g_pendingRedirect.redirectedValue);
            *reg = static_cast<DWORD64>(g_pendingRedirect.originalValue + movement);

            if ((g_pendingRedirect.originalEFlags & kTrapFlag) == 0)
                info->ContextRecord->EFlags &= ~static_cast<DWORD>(kTrapFlag);
            else
                info->ContextRecord->EFlags |= static_cast<DWORD>(kTrapFlag);

            AppendCompatLine(
                "restored-after-single-step",
                g_pendingRedirect.slot,
                movement,
                g_pendingRedirect.faultRip,
                g_pendingRedirect.faultTarget,
                info->ContextRecord);

            g_pendingRedirect.active = false;
            return true;
        }

        bool TryRedirectAlphaSharedDataWrite(EXCEPTION_POINTERS* info)
        {
            // The June 4th Alpha executes `sidt [rax]` at +0x17794C3 with
            // RAX = FFFFF78000000900.  On current Windows this KUSER shared-data
            // mapping is readable from user mode but not writable, so SIDT raises
            // STATUS_ACCESS_VIOLATION before the instruction can complete.
            //
            // Do NOT redirect the write and execute SIDT against scratch memory:
            // doing that manufactures an IDTR result that this old Alpha never
            // successfully wrote on modern Windows and changes the probe's
            // semantics.  Instead, for this exact image + RVA + opcode + target,
            // advance RIP over the 3-byte probe and leave every GPR/EFLAGS value
            // untouched.  The following instruction (`mov dl, 1`) then executes
            // normally.
            if (!g_alphaSharedDataCompat.load(std::memory_order_acquire) ||
                !info || !info->ExceptionRecord || !info->ContextRecord)
            {
                return false;
            }

            const auto* record = info->ExceptionRecord;
            auto* context = info->ContextRecord;

            if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
                record->NumberParameters < 2 ||
                record->ExceptionInformation[0] != 1)
            {
                return false;
            }

            const auto target = static_cast<std::uintptr_t>(record->ExceptionInformation[1]);
            if (target != (kKernelSharedDataPage + 0x900ull))
                return false;

            const auto exeBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            const auto rip = static_cast<std::uintptr_t>(context->Rip);
            if (!exeBase || rip < exeBase || (rip - exeBase) != kKnownExceptionRipA)
                return false;

            unsigned char opcode[3]{};
            CopyInstructionBytes(rip, opcode, sizeof(opcode));
            if (opcode[0] != 0x0F || opcode[1] != 0x01 || opcode[2] != 0x08)
            {
                AppendCompatLine("sidt-opcode-mismatch", RegisterSlot::None, 0, rip, target, context);
                return false;
            }

            AppendCompatLine("skip-sidt-shared-data-probe", RegisterSlot::None, 3, rip, target, context);
            context->Rip += 3;
            return true;
        }

        LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* info)
        {
            if (TryRestoreRedirectAfterSingleStep(info))
                return EXCEPTION_CONTINUE_EXECUTION;

            WriteLine(info, "VEH");

            if (TryRedirectAlphaSharedDataWrite(info))
                return EXCEPTION_CONTINUE_EXECUTION;

            return EXCEPTION_CONTINUE_SEARCH;
        }

        LONG WINAPI TopLevelHandler(EXCEPTION_POINTERS* info)
        {
            WriteLine(info, "UEF");
            return g_previous ? g_previous(info) : EXCEPTION_CONTINUE_SEARCH;
        }
    }

    void InstallVectoredOnly()
    {
        CreateDirectoryW(L"logs", nullptr);
        CreateDirectoryW(L"logs\\runtime", nullptr);

        g_alphaSharedDataCompat.store(IsExactAlphaImage(), std::memory_order_release);

        if (!g_vectored)
            g_vectored = AddVectoredExceptionHandler(1, VectoredHandler);

        if (g_alphaSharedDataCompat.load(std::memory_order_acquire))
            std::printf("[ALPHA-COMPAT] known shared-data exception bridge armed\n");
    }

    void Install()
    {
        InstallVectoredOnly();
        if (!g_previous)
            g_previous = SetUnhandledExceptionFilter(TopLevelHandler);
    }

    void Uninstall()
    {
        if (g_vectored)
        {
            RemoveVectoredExceptionHandler(g_vectored);
            g_vectored = nullptr;
        }
        SetUnhandledExceptionFilter(g_previous);
        g_previous = nullptr;
        g_alphaSharedDataCompat.store(false, std::memory_order_release);
    }
}
