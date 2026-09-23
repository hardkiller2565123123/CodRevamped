#include "AlphaSupport.h"
#include "../../../../shared/runtime/StoragePaths.h"
#include "../../../../shared/runtime/ClientIdentity.h"
#include "../../../../shared/patches/Win11Patch.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
    // ---------------------------------------------------------------------
    // June 4th COD2020 Alpha addresses recovered from the supplied helpers.
    // These are RVAs and are always resolved from the live module base.
    // ---------------------------------------------------------------------
    constexpr std::uintptr_t kCbufAddTextRva   = 0x016F3A10u;
    constexpr std::uintptr_t kParseKeysTxtRva  = 0x01011720u;
    constexpr std::uintptr_t kParseKeysTxt2Rva = 0x01012900u;
    constexpr std::uintptr_t kSetScreenRva     = 0x0105D9C0u;
    // Discovered from the completed live scan:
    // +0x10D63D0 is a tiny pass-through wrapper that calls SetScreen with RCX intact.
    // +0x105D9E0 is called immediately before one SetScreen site and returns the
    // screen ID in EAX.
    constexpr std::uintptr_t kSetScreenThunkRva = 0x010D63D0u;
    constexpr std::uintptr_t kScreenProviderRva = 0x0105D9E0u;

    // QR/account-link investigation anchors recovered from the live Alpha.
    // None of these are being patched. They are only used to discover the
    // UI/login state that changes when the linking QR popup appears.
    constexpr std::uintptr_t kQrSignInStateRva      = 0x0110EA9Cu;
    constexpr std::uintptr_t kQrBdLoginStartRva     = 0x01E58A79u;
    constexpr std::uintptr_t kQrLoginQueueRva       = 0x01E5B1A0u;
    constexpr std::uintptr_t kQrLoginCompleteRvaA   = 0x01E5C172u;
    constexpr std::uintptr_t kQrLoginCompleteRvaB   = 0x01E5C238u;
    constexpr std::uintptr_t kQrAccountLinkingRva   = 0x01E61EF7u;

    // Exact UI/account strings recovered by the exhaustive whole-process scan.
    // These are data/string RVAs, not code patches.
    constexpr std::uintptr_t kQrUiAccountManagementRva = 0x04F32B2Bu; // cod_account_management_options
    constexpr std::uintptr_t kQrUiAccountRegisterRva   = 0x04F32B7Bu; // cod_account_register_options
    constexpr std::uintptr_t kQrUiSignInInfoBasicRva   = 0x05039C8Bu; // cod_account_sign_in_info_basic
    constexpr std::uintptr_t kQrUiFocusableWebViewRva  = 0x023C5D40u; // isFocusableWebView
    constexpr std::uintptr_t kQrUiWebViewDoneRva       = 0x023C5DB0u; // webviewKeyboardDone
    constexpr std::uintptr_t kQrUiWebViewCharRva       = 0x023C5DC8u; // webviewKeyboardChar
    constexpr std::uintptr_t kQrUiWebViewKeyDownRva    = 0x023C5DE0u; // webviewKeyboardKeyDown

    // Login-flow strings/XREF neighborhoods recovered from this run.
    constexpr std::uintptr_t kQrFlowStartingCrossplayXrefRva = 0x01E5B6C2u;
    constexpr std::uintptr_t kQrFlowNoAccountXrefRva         = 0x01E5B9D8u;
    constexpr std::uintptr_t kQrFlowLinkStateXrefRvaA        = 0x01E5BBC3u;
    constexpr std::uintptr_t kQrFlowLinkStateXrefRvaB        = 0x01E5BCBEu;
    constexpr std::uintptr_t kQrFlowLinkStateXrefRvaC        = 0x01E5BD6Du;

    // Exact write that places the crossplay state-machine object into state 5:
    //   mov dword ptr [rsi+0x1C], 5
    // The previous whole-process scanner proved RSI is the object base here.
    // A one-shot software breakpoint lets us capture that object directly instead
    // of walking every writable private page in the process.
    constexpr std::uintptr_t kQrState5ObjectWriteRva          = 0x01E5BC9Cu;

    constexpr std::uintptr_t kMpFrontendStateRva = 0x0A8609C8u;
    // InjectToFixBuild calls this value "sessionInt" and writes it directly
    // at COD2020+0x65259E4. It is NOT the same field as sessionObject+0x98.
    constexpr std::uintptr_t kFrontendSessionStateRva = 0x065259E4u;

    // Live Alpha code at +0xACEDE0 reads +0x65259E4, extracts bits 6..9,
    // and maps them to 0=Offline, 1=System_link, 2=Online, other=Invalid.
    constexpr std::uint32_t kNetworkSelectorMask = 0x000003C0u;
    constexpr unsigned kNetworkSelectorShift = 6u;
    constexpr std::uint32_t kNetworkSelectorOffline = 0u;
    constexpr std::uint32_t kNetworkSelectorSystemLink = 1u;
    constexpr std::uint32_t kNetworkSelectorOnline = 2u;

    // InjectToFixBuild's recovered sessionInt values prove that the actual
    // online/offline session field is bits 4..5, not the label selector above:
    //   0x2021 (8225, online MP) - 0x2001 (8193, offline MP) = 0x20
    //   0x2020 (8224, online ZM) - 0x2000 (8192, offline ZM) = 0x20
    // Keep both packed fields as diagnostics only. Changing either field after
    // SetScreen(10) does not replace the LAN/custom-games frontend.
    constexpr std::uint32_t kSessionConnectivityMask = 0x00000030u;
    constexpr unsigned kSessionConnectivityShift = 4u;
    constexpr std::uint32_t kSessionConnectivityOffline = 0u;
    constexpr std::uint32_t kSessionConnectivityOnline = 2u;

    constexpr std::uintptr_t kZmStateRvaB        = 0x0B7D18A0u;
    constexpr std::uintptr_t kZmStateRvaC        = 0x0B3333A9u;

    // Gombies/InjectToFixBuild share this live session-object root.
    constexpr std::uintptr_t kSessionObjectPtrRva = 0x067BA9E0u;
    constexpr std::uintptr_t kSessionControllerStride = 0x0000B0E0u;

    // Exact field writes performed by Gombies immediately before it enters
    // the frontend.  They are deliberately named by behavior, not guessed
    // engine field names.
    constexpr std::uintptr_t kSessionIntOffset      = 0x0098u;
    constexpr std::uintptr_t kOriginalFlagAOffset   = 0x5A34u;
    constexpr std::uintptr_t kOriginalFlagBOffset   = 0x12E0u;
    constexpr std::uintptr_t kOriginalFlagCOffset   = 0x0D83u;
    constexpr std::uint32_t  kOriginalFlagAValue    = 0x001469B1u;
    constexpr std::uint32_t  kOriginalFlagBValue    = 0x000000FFu;
    constexpr std::uint8_t   kOriginalFlagCValue    = 0xA0u;

    // Original Gombies map-name destinations.  Its first destination pointer
    // was never initialized, so only the five real Alpha globals are copied.
    constexpr std::uintptr_t kMapNameRvas[] =
    {
        0x0822429Fu,
        0x082242E8u,
        0x08224324u,
        0x0B3333E9u,
        0x0B369D69u,
    };
    constexpr std::size_t kOriginalMapObjectBytes = 0x20u;
    constexpr std::size_t kOriginalMapSsoLimit = 15u;

    // Byte-for-byte key blob from for_mp_sp.dll/Gombies.
    constexpr char kAlphaKeys[] =
        "mp_common,1,LKBcjAtLFtrhGQqXZP3GQN2MXbGe4yBA4CJ8KK+Tmyw=\n"
        "zm_common,1,uVkxOTxN2vKCJHt2piY5tGqy33LKZ0dKlKizutZifuI=\n"
        "wz_common,1,qYOw3RHpf/4LoNqha7D8w0l1uJs1a8f1GXvz9RSlcpc=\n"
        "cp_common,1,1Xms8bivDnvtle9GlNy3IHsDBYi5q6kSJTqMJUZbUBo=";

    using CbufAddTextFn = void(*)(int localClientNum, const char* text);
    using ParseKeysFn = void(*)(const char* text);
    using SetScreenFn = void(*)(int screen);
    using GetScreenFn = int(*)();

    std::atomic_bool g_started{false};
    std::atomic_bool g_scanRunning{false};
    std::atomic_bool g_scanCompleted{false};
    std::atomic_bool g_autoFrontendApplied{false};
    std::uintptr_t g_base = 0;
    CbufAddTextFn g_cbufAddText = nullptr;
    ParseKeysFn g_parseKeysTxt = nullptr;
    ParseKeysFn g_parseKeysTxt2 = nullptr;
    SetScreenFn g_setScreen = nullptr;
    GetScreenFn g_getScreen = nullptr;

    // Filled only when the scanner finds a strong run of exact, NUL-terminated
    // Player1 fields at the 0x48-byte record stride observed in the live Alpha.
    std::atomic<std::uintptr_t> g_nameClusterBase{0};
    std::atomic<std::uint32_t> g_nameClusterCount{0};

    // Published only when the QR/login scanner finds a state-machine object
    // matching the actual large-object layout used by the live Alpha code.
    std::atomic<std::uintptr_t> g_crossplayStateObject{0};

    // One-shot state-5 capture probe. This is intentionally separate from the
    // generic online trace probes: it is Alpha-specific and only exists long
    // enough to capture RSI at the proven state-5 write.
    std::atomic_bool g_qrState5ProbeInstalled{false};
    std::atomic_bool g_qrState5ProbeCaptured{false};
    std::uintptr_t g_qrState5ProbeAddress = 0;
    unsigned char g_qrState5ProbeOriginalByte = 0;
    PVOID g_qrState5ProbeVeh = nullptr;

    struct QrWatchSnapshot
    {
        std::uintptr_t address = 0;
        std::uint64_t value = 0;
    };

    struct FullPageFingerprint
    {
        std::uintptr_t address = 0;
        std::uint32_t size = 0;
        std::uint64_t hash = 0;
        DWORD protect = 0;
        DWORD type = 0;
    };

    std::vector<FullPageFingerprint> g_fullQrBaselinePages;
    std::atomic<bool> g_fullQrBaselineArmed{false};
    std::atomic<bool> g_fullMemoryScanRunning{false};

    // Written once by the scanner, then published with g_qrWatchReady.
    std::vector<std::uintptr_t> g_qrWatchAddresses;
    std::vector<QrWatchSnapshot> g_qrBaseline;
    std::atomic<bool> g_qrWatchReady{false};
    std::atomic<bool> g_qrBaselineArmed{false};

    volatile LONG g_modeSwitchActive = 0;
    volatile LONG g_keepOriginalSessionFields = 0;
    volatile LONG g_screenIndex = 10;
    volatile LONG g_auxDebugIndex = 0;

    void EnsureAlphaLogDirectories()
    {
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"scanner");
    }

    void AlphaStatePrintf(const char* format, ...)
    {
        char buffer[2048]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        va_end(args);

        std::fputs(buffer, stdout);
        std::fflush(stdout);

        EnsureAlphaLogDirectories();
        FILE* file = nullptr;
        const std::string stateLogPath = storage_paths::PathA("logs\\scanner\\alpha_state_watch.log");
        if (fopen_s(&file, stateLogPath.c_str(), "a") == 0 && file)
        {
            SYSTEMTIME st{};
            GetLocalTime(&st);
            std::fprintf(file, "[%02u:%02u:%02u.%03u] %s",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buffer);
            std::fclose(file);
        }
    }

    bool IsCommittedAddress(const void* ptr, std::size_t requiredBytes = 1)
    {
        if (!ptr || requiredBytes == 0)
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(ptr, &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
            return false;

        const auto address = reinterpret_cast<std::uintptr_t>(ptr);
        const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return address <= regionEnd && requiredBytes <= (regionEnd - address);
    }

    bool IsExecutableAddress(const void* ptr)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!ptr || !VirtualQuery(ptr, &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
            return false;
        const DWORD p = mbi.Protect & 0xFFu;
        return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    bool LooksLikeCodeBytes(std::uintptr_t address, std::uintptr_t imageStart, std::uintptr_t imageEnd)
    {
        if (!IsExecutableAddress(reinterpret_cast<const void*>(address)))
            return false;

        unsigned char bytes[32]{};
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                               bytes, sizeof(bytes), &got) || got < 16)
            return false;

        // The Alpha maps some data as executable. Reject obvious strings and
        // pointer arrays so the table scanner does not call them callbacks.
        std::size_t printable = 0;
        std::size_t zero = 0;
        for (std::size_t i = 0; i < static_cast<std::size_t>(got); ++i)
        {
            if (bytes[i] == 0) ++zero;
            else if (bytes[i] >= 0x20 && bytes[i] <= 0x7E) ++printable;
        }
        if (printable >= 10 && printable + zero >= static_cast<std::size_t>(got) * 3 / 4)
            return false;

        std::size_t imagePointers = 0;
        const std::size_t qwords = std::min<std::size_t>(4, static_cast<std::size_t>(got) / 8);
        for (std::size_t i = 0; i < qwords; ++i)
        {
            std::uintptr_t q = 0;
            std::memcpy(&q, bytes + i * 8, sizeof(q));
            if (q >= imageStart && q < imageEnd)
                ++imagePointers;
        }
        if (imagePointers >= 3)
            return false;

        return true;
    }

    template <typename T>
    bool ReadValue(std::uintptr_t address, T& value)
    {
        if (!IsCommittedAddress(reinterpret_cast<const void*>(address), sizeof(T)))
            return false;
        __try
        {
            value = *reinterpret_cast<const volatile T*>(address);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    template <typename T>
    bool WriteValue(std::uintptr_t address, const T& value)
    {
        if (!IsCommittedAddress(reinterpret_cast<const void*>(address), sizeof(T)))
            return false;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_READWRITE, &oldProtect))
            return false;

        bool ok = true;
        __try
        {
            *reinterpret_cast<volatile T*>(address) = value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = false;
        }

        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &ignored);
        return ok;
    }

    bool WriteBytes(std::uintptr_t address, const void* data, std::size_t size)
    {
        if (!data || size == 0 || !IsCommittedAddress(reinterpret_cast<const void*>(address), size))
            return false;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_READWRITE, &oldProtect))
            return false;

        bool ok = true;
        __try
        {
            std::memcpy(reinterpret_cast<void*>(address), data, size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = false;
        }

        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(address), size, oldProtect, &ignored);
        return ok;
    }

    bool WriteExecutableByte(std::uintptr_t address, unsigned char value)
    {
        if (!address || !IsCommittedAddress(reinterpret_cast<const void*>(address), 1))
            return false;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(address), 1, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        *reinterpret_cast<volatile unsigned char*>(address) = value;
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<const void*>(address), 1);

        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(address), 1, oldProtect, &ignored);
        return true;
    }

    LONG CALLBACK AlphaQrState5ProbeVeh(EXCEPTION_POINTERS* exceptionInfo)
    {
        if (!exceptionInfo || !exceptionInfo->ExceptionRecord || !exceptionInfo->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        auto* record = exceptionInfo->ExceptionRecord;
        auto* context = exceptionInfo->ContextRecord;
        if (record->ExceptionCode != EXCEPTION_BREAKPOINT ||
            !g_qrState5ProbeInstalled.load(std::memory_order_acquire))
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        const std::uintptr_t address =
            reinterpret_cast<std::uintptr_t>(record->ExceptionAddress);
        if (!g_qrState5ProbeAddress || address != g_qrState5ProbeAddress)
            return EXCEPTION_CONTINUE_SEARCH;

        // One-shot: restore the real C7 opcode before resuming at the same RIP.
        // The original instruction then executes normally and writes state 5.
        if (!WriteExecutableByte(g_qrState5ProbeAddress, g_qrState5ProbeOriginalByte))
            return EXCEPTION_CONTINUE_SEARCH;

        g_qrState5ProbeInstalled.store(false, std::memory_order_release);
        context->Rip = g_qrState5ProbeAddress;

        const std::uintptr_t object = static_cast<std::uintptr_t>(context->Rsi);
        if (object >= 0x10000ull && object < 0x0000800000000000ull &&
            IsCommittedAddress(reinterpret_cast<const void*>(object), 0x1AE28u))
        {
            g_crossplayStateObject.store(object, std::memory_order_release);
            g_qrState5ProbeCaptured.store(true, std::memory_order_release);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    bool InstallQrState5CaptureProbe()
    {
        if (!g_base)
            return false;

        const std::uintptr_t address = g_base + kQrState5ObjectWriteRva;
        constexpr unsigned char expected[] = { 0xC7, 0x46, 0x1C, 0x05, 0x00, 0x00, 0x00 };
        unsigned char actual[sizeof(expected)]{};
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                               actual, sizeof(actual), &got) || got != sizeof(actual))
        {
            std::printf("[ALPHA-QRSTATE] state-5 capture probe could not read +0x%llX\n",
                static_cast<unsigned long long>(kQrState5ObjectWriteRva));
            return false;
        }

        if (std::memcmp(actual, expected, sizeof(expected)) != 0)
        {
            std::printf("[ALPHA-QRSTATE] state-5 capture probe signature mismatch at +0x%llX; leaving code untouched\n",
                static_cast<unsigned long long>(kQrState5ObjectWriteRva));
            return false;
        }

        if (!g_qrState5ProbeVeh)
        {
            g_qrState5ProbeVeh = AddVectoredExceptionHandler(1, &AlphaQrState5ProbeVeh);
            if (!g_qrState5ProbeVeh)
            {
                std::printf("[ALPHA-QRSTATE] failed to install state-5 VEH probe (%lu)\n",
                    static_cast<unsigned long>(GetLastError()));
                return false;
            }
        }

        g_qrState5ProbeAddress = address;
        g_qrState5ProbeOriginalByte = actual[0];
        g_qrState5ProbeInstalled.store(true, std::memory_order_release);
        if (!WriteExecutableByte(address, 0xCC))
        {
            g_qrState5ProbeInstalled.store(false, std::memory_order_release);
            std::printf("[ALPHA-QRSTATE] failed to arm state-5 capture breakpoint\n");
            return false;
        }

        std::printf("[ALPHA-QRSTATE] one-shot state-5 object capture armed at +0x%llX\n",
            static_cast<unsigned long long>(kQrState5ObjectWriteRva));
        return true;
    }

    bool SafeSetScreen(int screen)
    {
        if (!g_setScreen) return false;
        __try { g_setScreen(screen); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    bool SafeGetScreen(int& screen)
    {
        if (!g_getScreen)
            return false;
        __try
        {
            screen = g_getScreen();
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool SafeParse(ParseKeysFn fn, const char* text)
    {
        if (!fn || !text) return false;
        __try { fn(text); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    bool SafeCbuf(const char* text)
    {
        if (!g_cbufAddText || !text || !*text) return false;
        __try { g_cbufAddText(0, text); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    bool BeginModeSwitch()
    {
        return InterlockedCompareExchange(&g_modeSwitchActive, 1, 0) == 0;
    }

    void EndModeSwitch()
    {
        InterlockedExchange(&g_modeSwitchActive, 0);
    }

    bool Resolve()
    {
        g_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!g_base) return false;

        g_cbufAddText = reinterpret_cast<CbufAddTextFn>(g_base + kCbufAddTextRva);
        g_parseKeysTxt = reinterpret_cast<ParseKeysFn>(g_base + kParseKeysTxtRva);
        g_parseKeysTxt2 = reinterpret_cast<ParseKeysFn>(g_base + kParseKeysTxt2Rva);
        g_setScreen = reinterpret_cast<SetScreenFn>(g_base + kSetScreenRva);
        g_getScreen = reinterpret_cast<GetScreenFn>(g_base + kScreenProviderRva);

        if (!IsExecutableAddress(reinterpret_cast<const void*>(g_cbufAddText)) ||
            !IsExecutableAddress(reinterpret_cast<const void*>(g_parseKeysTxt)) ||
            !IsExecutableAddress(reinterpret_cast<const void*>(g_parseKeysTxt2)) ||
            !IsExecutableAddress(reinterpret_cast<const void*>(g_setScreen)) ||
            !IsExecutableAddress(reinterpret_cast<const void*>(g_getScreen)))
        {
            std::printf("[ALPHA] helper function RVA validation failed\n");
            return false;
        }

        std::printf("[ALPHA] base=0x%llX Cbuf=+0x%llX SetScreen=+0x%llX Keys=+0x%llX/+0x%llX\n",
            static_cast<unsigned long long>(g_base),
            static_cast<unsigned long long>(kCbufAddTextRva),
            static_cast<unsigned long long>(kSetScreenRva),
            static_cast<unsigned long long>(kParseKeysTxtRva),
            static_cast<unsigned long long>(kParseKeysTxt2Rva));

        // Do NOT arm the QR execution breakpoint here. Resolve() runs at the
        // beginning of the Alpha helper thread, which is still close to the
        // fragile Win11 compatibility transition. The hotkey loop arms the
        // probe later, only after the Win11 one-shot is confirmed complete and
        // an additional stabilization delay has elapsed.
        return true;
    }

    std::uintptr_t GetSessionObject(unsigned controller = 0)
    {
        if (!g_base)
            return 0;

        std::uintptr_t root = 0;
        if (!ReadValue(g_base + kSessionObjectPtrRva, root))
            return 0;

        // Same validity envelope used by the supplied helpers, plus a real
        // committed-region check before any field access.
        if (root < 0x10000ull || root >= 0x0000800000000000ull)
            return 0;

        const std::uintptr_t object = root +
            static_cast<std::uintptr_t>(controller) * kSessionControllerStride;
        if (!IsCommittedAddress(reinterpret_cast<const void*>(object), kOriginalFlagAOffset + sizeof(std::uint32_t)))
            return 0;
        return object;
    }

    bool ApplyOriginalSessionDefaultsInternal(bool verbose)
    {
        const std::uintptr_t object = GetSessionObject(0);
        if (!object)
        {
            if (verbose) std::printf("[ALPHA-PLAY] session object not ready\n");
            return false;
        }

        const bool a = WriteValue(object + kOriginalFlagAOffset, kOriginalFlagAValue);
        const bool b = WriteValue(object + kOriginalFlagBOffset, kOriginalFlagBValue);
        const bool c = WriteValue(object + kOriginalFlagCOffset, kOriginalFlagCValue);

        std::uint32_t field98 = 0;
        const bool fieldRead = ReadValue(object + kSessionIntOffset, field98);

        if (verbose)
        {
            std::printf(
                "[ALPHA-PLAY] object=0x%llX original fields: +5A34=%s +12E0=%s +D83=%s +98=%s%u\n",
                static_cast<unsigned long long>(object),
                a ? "OK" : "FAIL",
                b ? "OK" : "FAIL",
                c ? "OK" : "FAIL",
                fieldRead ? "" : "?",
                fieldRead ? field98 : 0u);
        }
        return a && b && c;
    }

    // InjectToFixBuild F2 writes the named "sessionInt" directly to
    // COD2020+0x65259E4. Earlier AlphaSupport builds accidentally wrote the
    // same values to sessionObject+0x98 instead. Keep the two locations
    // separate because the recovered DLL clearly treats them as independent.
    bool SetFrontendSessionStateInternal(std::uint32_t value, bool verbose = true)
    {
        if (!g_base)
            return false;

        const bool ok = WriteValue(g_base + kFrontendSessionStateRva, value);
        if (verbose)
        {
            std::printf("[ALPHA-SESSION] COD2020+0x%llX <- %u (0x%X) %s\n",
                static_cast<unsigned long long>(kFrontendSessionStateRva),
                value, value, ok ? "OK" : "FAIL");
        }
        return ok;
    }

    bool ReadFrontendSessionStateInternal(std::uint32_t& value)
    {
        return g_base && ReadValue(g_base + kFrontendSessionStateRva, value);
    }

    bool SetSessionObjectField98Internal(std::uint32_t value, bool verbose = true)
    {
        const std::uintptr_t object = GetSessionObject(0);
        if (!object)
        {
            if (verbose) std::printf("[ALPHA-SESSION] session object not ready for +0x98 write\n");
            return false;
        }

        const bool ok = WriteValue(object + kSessionIntOffset, value);
        if (verbose)
        {
            std::printf("[ALPHA-SESSION] object=0x%llX +0x98 <- %u (0x%X) %s\n",
                static_cast<unsigned long long>(object), value, value, ok ? "OK" : "FAIL");
        }
        return ok;
    }

    bool ReadSessionObjectField98Internal(std::uint32_t& value)
    {
        const std::uintptr_t object = GetSessionObject(0);
        return object && ReadValue(object + kSessionIntOffset, value);
    }

    bool DisconnectToFrontend()
    {
        return SafeCbuf("disconnect");
    }

    bool ActivateMpSp()
    {
        if (!BeginModeSwitch())
        {
            std::printf("[ALPHA-FRONTEND] mode switch already active; ignored duplicate request\n");
            return false;
        }

        // Exact InjectToFixBuild startup ordering recovered from sub_180017410:
        //   state=1 -> SetScreen(10) -> ParseKeysTxt -> ParseKeysTxt2 -> disconnect.
        // Gombies' three session-object fields are applied independently when
        // the live session object appears; they are not inserted into this call
        // order so the recovered InjectToFixBuild sequence stays intact.
        std::printf("[ALPHA-FRONTEND] InjectToFixBuild-compatible MP sequence\n");
        const bool stateOk = WriteValue(g_base + kMpFrontendStateRva, std::uint32_t{1u});
        const bool screenOk = SafeSetScreen(10);
        const bool keys1Ok = SafeParse(g_parseKeysTxt, kAlphaKeys);
        const bool keys2Ok = SafeParse(g_parseKeysTxt2, kAlphaKeys);
        const bool disconnectOk = DisconnectToFrontend();

        std::printf("[ALPHA-FRONTEND] state=%s screen=%s keys1=%s keys2=%s disconnect=%s\n",
            stateOk ? "OK" : "FAIL",
            screenOk ? "OK" : "FAIL",
            keys1Ok ? "OK" : "FAIL",
            keys2Ok ? "OK" : "FAIL",
            disconnectOk ? "OK" : "FAIL");

        EndModeSwitch();
        return stateOk && screenOk && keys1Ok && keys2Ok && disconnectOk;
    }

    bool ActivateZombies()
    {
        if (!BeginModeSwitch())
        {
            std::printf("[ZM] mode switch already active; ignored duplicate request\n");
            return false;
        }

        // Exact for_zombies/Gombies state writes.
        const bool a = WriteValue(g_base + kFrontendSessionStateRva, std::uint32_t{0x40C0u});
        const bool b = WriteValue(g_base + kZmStateRvaB, std::uint32_t{0u});
        const bool c = WriteValue(g_base + kZmStateRvaC, std::uint32_t{0x616C637Au});
        const bool disconnectOk = DisconnectToFrontend();
        std::printf("[ZM] stateA=%s stateB=%s stateC=%s disconnect=%s\n",
            a ? "OK" : "FAIL", b ? "OK" : "FAIL", c ? "OK" : "FAIL",
            disconnectOk ? "OK" : "FAIL");
        EndModeSwitch();
        return a && b && c && disconnectOk;
    }

    bool SetMapNameFromOriginalHelper(const char* mapName)
    {
        if (!mapName || !*mapName)
        {
            std::printf("[ALPHA-MAP] map name is empty\n");
            return false;
        }

        const std::size_t len = std::strlen(mapName);
        if (len > kOriginalMapSsoLimit)
        {
            std::printf("[ALPHA-MAP] '%s' is %zu chars; original helper copy is safe only for <= %zu\n",
                mapName, len, kOriginalMapSsoLimit);
            return false;
        }

        // The original helper copied the 32-byte MSVC x64 release std::string
        // object directly into these globals.  Do not use this toolchain's
        // std::string object here: VS debug iterator settings can make it a
        // different size/layout.  Build the recovered SSO representation
        // explicitly instead.  We intentionally accept only <=15-byte map
        // names, so the union always contains inline characters and never a
        // process-local heap pointer.
        struct RecoveredMsvcString32
        {
            union
            {
                char inlineBuffer[16];
                std::uintptr_t heapPointer;
            };
            std::uint64_t size;
            std::uint64_t capacity;
        };
        static_assert(sizeof(RecoveredMsvcString32) == kOriginalMapObjectBytes,
            "Recovered Alpha string object must remain exactly 32 bytes");

        RecoveredMsvcString32 helperStyleObject{};
        std::memcpy(helperStyleObject.inlineBuffer, mapName, len);
        helperStyleObject.inlineBuffer[len] = '\0';
        helperStyleObject.size = static_cast<std::uint64_t>(len);
        helperStyleObject.capacity = static_cast<std::uint64_t>(kOriginalMapSsoLimit);

        bool allOk = true;
        for (const auto rva : kMapNameRvas)
        {
            const bool ok = WriteBytes(g_base + rva, &helperStyleObject, sizeof(helperStyleObject));
            std::printf("[ALPHA-MAP] write +0x%llX %s\n",
                static_cast<unsigned long long>(rva), ok ? "OK" : "FAIL");
            allOk = allOk && ok;
        }
        std::printf("[ALPHA-MAP] map '%s' %s\n", mapName, allOk ? "SET" : "PARTIAL/FAILED");
        return allOk;
    }

    bool LaunchLobbyGame()
    {
        const bool ok = SafeCbuf("lobbylaunchgame");
        std::printf("[ALPHA-MAP] lobbylaunchgame %s\n", ok ? "SENT" : "FAILED");
        return ok;
    }

    bool FastRestartMap()
    {
        const bool ok = SafeCbuf("fast_restart");
        std::printf("[ALPHA-MAP] fast_restart %s\n", ok ? "SENT" : "FAILED");
        return ok;
    }

    void PromptForMapName()
    {
        std::printf("[ALPHA-MAP] Please Enter Map Name! (example: mp_miami): ");
        std::fflush(stdout);
        char buffer[64]{};
        if (!std::fgets(buffer, static_cast<int>(sizeof(buffer)), stdin)) return;
        buffer[std::strcspn(buffer, "\r\n")] = '\0';
        (void)SetMapNameFromOriginalHelper(buffer);
    }

    void PromptForCommand()
    {
        std::printf("[ALPHA-CBUF] Please Enter Command! : ");
        std::fflush(stdout);
        char buffer[512]{};
        if (!std::fgets(buffer, static_cast<int>(sizeof(buffer)), stdin)) return;
        buffer[std::strcspn(buffer, "\r\n")] = '\0';
        if (!*buffer) return;
        const bool ok = SafeCbuf(buffer);
        std::printf("[ALPHA-CBUF] '%s' %s\n", buffer, ok ? "SENT" : "FAILED");
    }

    void PromptForSessionInt()
    {
        std::printf(
            "[ALPHA-SESSION] presets: 33=league 4129=online_mp_customs 8192=offline_zm "
            "8193=offline_mp 8224=online_zm 8225=online_mp\n"
            "[ALPHA-SESSION] enter sessionInt: ");
        std::fflush(stdout);

        char buffer[64]{};
        if (!std::fgets(buffer, static_cast<int>(sizeof(buffer)), stdin)) return;
        char* end = nullptr;
        const unsigned long value = std::strtoul(buffer, &end, 0);
        if (end == buffer)
        {
            std::printf("[ALPHA-SESSION] invalid integer\n");
            return;
        }
        (void)SetFrontendSessionStateInternal(static_cast<std::uint32_t>(value));
    }

    struct AlphaScanCandidate
    {
        std::uintptr_t address = 0;
        std::size_t byteLength = 0;
        bool online = false;
        bool menu = false;
        bool qr = false;
        bool utf16 = false;
        std::string text;
    };

    bool IsReadableProtection(DWORD protect)
    {
        if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS))
            return false;
        const DWORD p = protect & 0xFFu;
        return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
               p == PAGE_EXECUTE_WRITECOPY;
    }

    bool IsExecutableProtection(DWORD protect)
    {
        if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS))
            return false;
        const DWORD p = protect & 0xFFu;
        return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    bool IsWritableProtection(DWORD protect)
    {
        if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS))
            return false;
        const DWORD p = protect & 0xFFu;
        return p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    bool ReadMemoryBlock(std::uintptr_t address, void* output, std::size_t size, std::size_t& bytesRead)
    {
        bytesRead = 0;
        SIZE_T got = 0;
        const BOOL ok = ReadProcessMemory(
            GetCurrentProcess(), reinterpret_cast<const void*>(address), output, size, &got);
        bytesRead = static_cast<std::size_t>(got);
        return ok != FALSE && got != 0;
    }

    void ScanPrintf(FILE* file, const char* format, ...)
    {
        char buffer[4096]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        va_end(args);

        std::fputs(buffer, stdout);
        std::fflush(stdout);
        if (file)
        {
            std::fputs(buffer, file);
            std::fflush(file);
        }
    }

    void ScanLogOnlyPrintf(FILE* file, const char* format, ...)
    {
        if (!file)
            return;

        char buffer[4096]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        va_end(args);

        std::fputs(buffer, file);
        std::fflush(file);
    }

    std::string LowerAscii(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
        {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    void ClassifyAlphaString(const std::string& text, bool& online, bool& menu, bool& qr)
    {
        const std::string lower = LowerAscii(text);
        const auto has = [&](const char* token) { return lower.find(token) != std::string::npos; };

        // Prefer user-facing menu text over compiler/source-path noise. The
        // first broad scan matched thousands of Demonware .cpp/.inl paths.
        const bool developerNoise =
            has("\\code\\") || has(".cpp") || has(".hpp") || has(".inl") ||
            has("source\\") || has("external\\demonware\\");

        menu = !developerNoise &&
            (lower == "online" || has("online services") || has("online multiplayer") ||
             has("online zombies") || has("connecting to") || has("connect to online") ||
             has("play online") || has("go online") || has("multiplayer") ||
             has("zombies") || has("custom games") || has("offline") ||
             has("sign in") || has("signin") || has("log in") || has("login") ||
             has("account linking") || has("link account") || has("link your account") ||
             has("callofduty.com") || has("activision.com") ||
             has("crossplay account") || has("crossplay login"));

        online = menu || (!developerNoise &&
            (has("demonware") || has("bdlogin") || has("authentication") ||
             has("auth service") || has("online service") || has("uno account") ||
             has("callofduty.com") || has("activision.com") || has("crossplay")));

        // Strict QR classification. Account-linking/login text by itself is NOT
        // a QR hit; the previous scanner incorrectly counted a normal UnoID
        // account-linking log string as QR.
        qr = !developerNoise &&
            (has("qr code") || has("qrcode") || has("qr_code") || has("qr-code") ||
             has("scan this code") || has("scan the code") || has("scan qr") ||
             has("device code") || has("activation code") || has("barcode"));
    }

    bool IsPriorityAlphaCandidate(const std::string& text)
    {
        const std::string lower = LowerAscii(text);
        return lower == "online" || lower == "offline" ||
               lower == "startmultiplayer;" || lower == "startzombies;" ||
               lower == "signinstate" || lower == "forceoffline" ||
               lower == "navigatedtoofflinefromonline" ||
               lower == "disconnectfromdemonware" ||
               lower == "disableconnectingtodemonware" ||
               lower == "enableconnectingtodemonware" ||
               lower == "connectingtodemonware" ||
               lower == "bdlogin::start" || lower == "login complete" ||
               lower == "joining login queue" ||
               lower.find("qr code") != std::string::npos ||
               lower.find("qrcode") != std::string::npos ||
               lower.find("qr_code") != std::string::npos ||
               lower.find("scan this code") != std::string::npos ||
               lower.find("device code") != std::string::npos ||
               lower.find("activation code") != std::string::npos ||
               lower.find("account linking") != std::string::npos ||
               lower.find("callofduty.com") != std::string::npos ||
               lower.find("activision.com") != std::string::npos ||
               lower.find("link your account") != std::string::npos ||
               lower.find("link account") != std::string::npos;
    }

    bool GetAlphaImageRange(std::uintptr_t& imageStart, std::uintptr_t& imageEnd)
    {
        imageStart = g_base;
        imageEnd = 0;
        if (!imageStart)
            return false;

        IMAGE_DOS_HEADER dos{};
        std::size_t got = 0;
        if (!ReadMemoryBlock(imageStart, &dos, sizeof(dos), got) || got != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
            return false;

        IMAGE_NT_HEADERS64 nt{};
        if (!ReadMemoryBlock(imageStart + static_cast<std::uintptr_t>(dos.e_lfanew),
                &nt, sizeof(nt), got) || got != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE)
            return false;

        imageEnd = imageStart + nt.OptionalHeader.SizeOfImage;
        return imageEnd > imageStart;
    }

    bool IsPrintableScanByte(unsigned char c)
    {
        return c >= 0x20 && c <= 0x7E;
    }

    void AddAlphaCandidate(
        std::vector<AlphaScanCandidate>& candidates,
        std::unordered_set<std::uintptr_t>& seen,
        FILE* log,
        std::uintptr_t address,
        std::size_t byteLength,
        bool utf16,
        const std::string& text)
    {
        bool online = false;
        bool menu = false;
        bool qr = false;
        ClassifyAlphaString(text, online, menu, qr);
        if (!online && !menu && !qr)
            return;
        if (!seen.insert(address).second)
            return;

        AlphaScanCandidate candidate{};
        candidate.address = address;
        candidate.byteLength = byteLength;
        candidate.online = online;
        candidate.menu = menu;
        candidate.qr = qr;
        candidate.utf16 = utf16;
        candidate.text = text;
        candidates.push_back(candidate);

        const char* tag =
            menu && qr ? "ONLINE-MENU+QR" :
            menu ? "ONLINE-MENU" :
            qr ? "QR" :
            "ONLINE";
        ScanLogOnlyPrintf(log, "[ALPHA-SCAN] %s string RVA=+0x%llX %s \"%s\"\n",
            tag,
            static_cast<unsigned long long>(address - g_base),
            utf16 ? "UTF16" : "ASCII",
            text.c_str());
    }

    void ScanAlphaStrings(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        std::vector<AlphaScanCandidate>& candidates)
    {
        constexpr std::size_t kChunkSize = 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);
        std::unordered_set<std::uintptr_t> seen;
        unsigned int lastPercent = 0;

        ScanPrintf(log, "[ALPHA-SCAN] Phase 1/5: online-menu + online-service + strict QR strings...\n");
        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart = std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;
                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i < got; )
                        {
                            if (IsPrintableScanByte(buffer[i]))
                            {
                                std::size_t len = 1;
                                while (i + len < got && len < 1024 && IsPrintableScanByte(buffer[i + len]))
                                    ++len;
                                if (len >= 4 && i + len < got && buffer[i + len] == 0)
                                {
                                    const std::string text(reinterpret_cast<const char*>(buffer.data() + i), len);
                                    AddAlphaCandidate(candidates, seen, log, block + i, len + 1, false, text);
                                    i += len + 1;
                                    continue;
                                }
                            }

                            if (i + 3 < got && IsPrintableScanByte(buffer[i]) && buffer[i + 1] == 0)
                            {
                                std::size_t chars = 1;
                                while (i + chars * 2 + 1 < got && chars < 1024 &&
                                       IsPrintableScanByte(buffer[i + chars * 2]) &&
                                       buffer[i + chars * 2 + 1] == 0)
                                {
                                    ++chars;
                                }
                                const std::size_t end = i + chars * 2;
                                if (chars >= 4 && end + 1 < got && buffer[end] == 0 && buffer[end + 1] == 0)
                                {
                                    std::string text;
                                    text.reserve(chars);
                                    for (std::size_t c = 0; c < chars; ++c)
                                        text.push_back(static_cast<char>(buffer[i + c * 2]));
                                    AddAlphaCandidate(candidates, seen, log, block + i, chars * 2 + 2, true, text);
                                    i = end + 2;
                                    continue;
                                }
                            }
                            ++i;
                        }
                    }
                    block += wanted ? wanted : 0x1000u;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
            const unsigned int percent = static_cast<unsigned int>(
                ((cursor - imageStart) * 100ull) / (imageEnd - imageStart));
            if (percent >= lastPercent + 10 || percent == 100)
            {
                lastPercent = percent;
                ScanPrintf(log, "[ALPHA-SCAN] strings %u%% candidates=%zu\n", percent, candidates.size());
            }
        }
    }

    const AlphaScanCandidate* FindCandidateAt(
        const std::vector<AlphaScanCandidate>& candidates,
        std::uintptr_t target)
    {
        for (const auto& candidate : candidates)
        {
            if (candidate.address == target)
                return &candidate;
        }
        return nullptr;
    }

    void LogPriorityCodeWindow(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t instruction,
        const char* reason)
    {
        if (!log || !instruction)
            return;

        constexpr std::size_t kBefore = 32;
        constexpr std::size_t kWindow = 96;
        const std::uintptr_t start = instruction > kBefore ? instruction - kBefore : instruction;
        unsigned char bytes[kWindow]{};
        std::size_t got = 0;
        if (!ReadMemoryBlock(start, bytes, sizeof(bytes), got) || got == 0)
            return;

        char hex[(kWindow * 3) + 1]{};
        std::size_t out = 0;
        for (std::size_t i = 0; i < got && out + 4 < sizeof(hex); ++i)
        {
            const int wrote = _snprintf_s(hex + out, sizeof(hex) - out, _TRUNCATE,
                i + 1 == got ? "%02X" : "%02X ", bytes[i]);
            if (wrote <= 0)
                break;
            out += static_cast<std::size_t>(wrote);
        }

        ScanLogOnlyPrintf(log,
            "[ALPHA-SCAN] BYTES PRIORITY reason=%s startRVA=+0x%llX hitRVA=+0x%llX bytes=%s\n",
            reason ? reason : "unknown",
            static_cast<unsigned long long>(start - imageStart),
            static_cast<unsigned long long>(instruction - imageStart),
            hex);
    }

    std::size_t ScanAlphaXrefs(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        const std::vector<AlphaScanCandidate>& candidates)
    {
        constexpr std::size_t kChunkSize = 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);
        std::unordered_set<std::uintptr_t> seenXrefs;
        std::size_t xrefs = 0;
        unsigned int lastPercent = 0;

        ScanPrintf(log, "[ALPHA-SCAN] Phase 2/5: direct executable RIP-relative xrefs...\n");
        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart = std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect) && IsExecutableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;
                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 7 <= got; ++i)
                        {
                            std::size_t instructionLength = 0;
                            std::size_t displacementOffset = 0;

                            if (buffer[i] >= 0x40 && buffer[i] <= 0x4F &&
                                (buffer[i + 1] == 0x8D || buffer[i + 1] == 0x8B || buffer[i + 1] == 0x89) &&
                                (buffer[i + 2] & 0xC7u) == 0x05u)
                            {
                                instructionLength = 7;
                                displacementOffset = 3;
                            }
                            else if ((buffer[i] == 0x8D || buffer[i] == 0x8B || buffer[i] == 0x89) &&
                                     (buffer[i + 1] & 0xC7u) == 0x05u)
                            {
                                instructionLength = 6;
                                displacementOffset = 2;
                            }

                            if (!instructionLength || i + instructionLength > got)
                                continue;

                            std::int32_t disp = 0;
                            std::memcpy(&disp, buffer.data() + i + displacementOffset, sizeof(disp));
                            const std::uintptr_t instruction = block + i;
                            const std::uintptr_t target = instruction + instructionLength + static_cast<std::intptr_t>(disp);
                            const AlphaScanCandidate* candidate = FindCandidateAt(candidates, target);
                            if (!candidate || !seenXrefs.insert(instruction).second)
                                continue;

                            ++xrefs;
                            const char* tag =
                                candidate->menu && candidate->qr ? "ONLINE-MENU+QR" :
                                candidate->menu ? "ONLINE-MENU" :
                                candidate->qr ? "QR" :
                                "ONLINE";
                            ScanLogOnlyPrintf(log,
                                "[ALPHA-SCAN] XREF %s codeRVA=+0x%llX -> stringRVA=+0x%llX \"%s\"\n",
                                tag,
                                static_cast<unsigned long long>(instruction - imageStart),
                                static_cast<unsigned long long>(candidate->address - imageStart),
                                candidate->text.c_str());
                            if (IsPriorityAlphaCandidate(candidate->text))
                            {
                                ScanPrintf(log,
                                    "[ALPHA-SCAN] PRIORITY direct codeRVA=+0x%llX stringRVA=+0x%llX \"%s\"\n",
                                    static_cast<unsigned long long>(instruction - imageStart),
                                    static_cast<unsigned long long>(candidate->address - imageStart),
                                    candidate->text.c_str());
                                LogPriorityCodeWindow(log, imageStart, instruction, candidate->text.c_str());
                            }
                        }
                    }
                    block += wanted ? wanted : 0x1000u;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
            const unsigned int percent = static_cast<unsigned int>(
                ((cursor - imageStart) * 100ull) / (imageEnd - imageStart));
            if (percent >= lastPercent + 10 || percent == 100)
            {
                lastPercent = percent;
                ScanPrintf(log, "[ALPHA-SCAN] xrefs %u%% found=%zu\n", percent, xrefs);
            }
        }
        return xrefs;
    }

    struct AlphaPointerCandidateRef
    {
        std::uintptr_t slot = 0;
        const AlphaScanCandidate* candidate = nullptr;
    };

    std::vector<AlphaPointerCandidateRef> ScanPriorityPointerSlots(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        const std::vector<AlphaScanCandidate>& candidates)
    {
        std::unordered_map<std::uintptr_t, const AlphaScanCandidate*> targets;
        for (const auto& candidate : candidates)
        {
            if (candidate.qr || IsPriorityAlphaCandidate(candidate.text))
                targets.emplace(candidate.address, &candidate);
        }

        std::vector<AlphaPointerCandidateRef> refs;
        std::unordered_set<std::uintptr_t> seenSlots;
        if (targets.empty())
            return refs;

        constexpr std::size_t kChunkSize = 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);
        unsigned int lastPercent = 0;
        ScanPrintf(log, "[ALPHA-SCAN] Phase 3/5: priority pointer-table references (aligned fast scan)...\n");

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart = std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;
                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        const std::size_t firstAligned = static_cast<std::size_t>(
                            (sizeof(std::uintptr_t) - (block & (sizeof(std::uintptr_t) - 1))) &
                            (sizeof(std::uintptr_t) - 1));
                        for (std::size_t i = firstAligned; i + sizeof(std::uintptr_t) <= got;
                             i += sizeof(std::uintptr_t))
                        {
                            std::uintptr_t value = 0;
                            std::memcpy(&value, buffer.data() + i, sizeof(value));
                            const auto it = targets.find(value);
                            if (it == targets.end())
                                continue;

                            const std::uintptr_t slot = block + i;
                            if (slot == value || !seenSlots.insert(slot).second)
                                continue;

                            refs.push_back({slot, it->second});
                            ScanLogOnlyPrintf(log,
                                "[ALPHA-SCAN] PTR PRIORITY slotRVA=+0x%llX -> stringRVA=+0x%llX \"%s\"\n",
                                static_cast<unsigned long long>(slot - imageStart),
                                static_cast<unsigned long long>(value - imageStart),
                                it->second->text.c_str());
                        }
                    }
                    block += wanted ? wanted : 0x1000u;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
            const unsigned int percent = static_cast<unsigned int>(
                ((cursor - imageStart) * 100ull) / (imageEnd - imageStart));
            if (percent >= lastPercent + 20 || percent == 100)
            {
                lastPercent = percent;
                ScanPrintf(log, "[ALPHA-SCAN] pointer tables %u%% refs=%zu\n", percent, refs.size());
            }
        }
        return refs;
    }

    std::size_t ScanPriorityPointerXrefs(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        const std::vector<AlphaPointerCandidateRef>& refs)
    {
        std::unordered_map<std::uintptr_t, const AlphaScanCandidate*> slots;
        for (const auto& ref : refs)
            if (ref.candidate) slots.emplace(ref.slot, ref.candidate);

        if (slots.empty())
        {
            ScanPrintf(log, "[ALPHA-SCAN] Phase 4/5: no priority pointer slots to trace\n");
            return 0;
        }

        constexpr std::size_t kChunkSize = 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);
        std::unordered_set<std::uintptr_t> seen;
        std::unordered_set<std::uintptr_t> announcedStrings;
        std::size_t count = 0;
        unsigned int lastPercent = 0;
        ScanPrintf(log, "[ALPHA-SCAN] Phase 4/5: executable xrefs to priority pointer tables...\n");

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart = std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect) && IsExecutableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;
                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 7 <= got; ++i)
                        {
                            std::size_t instructionLength = 0;
                            std::size_t displacementOffset = 0;
                            if (buffer[i] >= 0x40 && buffer[i] <= 0x4F &&
                                (buffer[i + 1] == 0x8D || buffer[i + 1] == 0x8B || buffer[i + 1] == 0x89) &&
                                (buffer[i + 2] & 0xC7u) == 0x05u)
                            {
                                instructionLength = 7;
                                displacementOffset = 3;
                            }
                            else if ((buffer[i] == 0x8D || buffer[i] == 0x8B || buffer[i] == 0x89) &&
                                     (buffer[i + 1] & 0xC7u) == 0x05u)
                            {
                                instructionLength = 6;
                                displacementOffset = 2;
                            }
                            if (!instructionLength || i + instructionLength > got)
                                continue;

                            std::int32_t disp = 0;
                            std::memcpy(&disp, buffer.data() + i + displacementOffset, sizeof(disp));
                            const std::uintptr_t instruction = block + i;
                            const std::uintptr_t target = instruction + instructionLength + static_cast<std::intptr_t>(disp);
                            const auto it = slots.find(target);
                            if (it == slots.end() || !seen.insert(instruction).second)
                                continue;

                            ++count;
                            const AlphaScanCandidate* candidate = it->second;
                            ScanLogOnlyPrintf(log,
                                "[ALPHA-SCAN] XREF2 PRIORITY codeRVA=+0x%llX -> slotRVA=+0x%llX -> stringRVA=+0x%llX \"%s\"\n",
                                static_cast<unsigned long long>(instruction - imageStart),
                                static_cast<unsigned long long>(target - imageStart),
                                static_cast<unsigned long long>(candidate->address - imageStart),
                                candidate->text.c_str());
                            if (announcedStrings.insert(candidate->address).second)
                            {
                                ScanPrintf(log,
                                    "[ALPHA-SCAN] PRIORITY indirect codeRVA=+0x%llX \"%s\"\n",
                                    static_cast<unsigned long long>(instruction - imageStart),
                                    candidate->text.c_str());
                                LogPriorityCodeWindow(log, imageStart, instruction, candidate->text.c_str());
                            }
                        }
                    }
                    block += wanted ? wanted : 0x1000u;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
            const unsigned int percent = static_cast<unsigned int>(
                ((cursor - imageStart) * 100ull) / (imageEnd - imageStart));
            if (percent >= lastPercent + 20 || percent == 100)
            {
                lastPercent = percent;
                ScanPrintf(log, "[ALPHA-SCAN] indirect xrefs %u%% found=%zu\n", percent, count);
            }
        }
        return count;
    }

    std::size_t DumpPriorityPointerNeighborhoods(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        const std::vector<AlphaPointerCandidateRef>& refs,
        const std::vector<AlphaScanCandidate>& candidates)
    {
        ScanPrintf(log, "[ALPHA-SCAN] Phase 5/6: priority table structure/code dump...\n");

        if (refs.empty())
        {
            ScanPrintf(log, "[ALPHA-SCAN] no priority table structures to dump\n");
            return 0;
        }

        std::unordered_set<std::uintptr_t> seenSlots;
        std::size_t dumped = 0;
        for (const auto& ref : refs)
        {
            if (!ref.candidate || !seenSlots.insert(ref.slot).second)
                continue;

            const std::uintptr_t before = 0x80u;
            const std::uintptr_t after = 0x180u;
            const std::uintptr_t start = ref.slot > imageStart + before ? ref.slot - before : imageStart;
            const std::uintptr_t end = std::min(imageEnd, ref.slot + after);
            if (end <= start)
                continue;

            const std::size_t wanted = static_cast<std::size_t>(end - start);
            std::vector<unsigned char> bytes(wanted);
            std::size_t got = 0;
            if (!ReadMemoryBlock(start, bytes.data(), wanted, got) || !got)
                continue;

            ++dumped;
            ScanLogOnlyPrintf(log,
                "[ALPHA-SCAN] TABLE PRIORITY slotRVA=+0x%llX reason=\"%s\" windowRVA=+0x%llX..+0x%llX\n",
                static_cast<unsigned long long>(ref.slot - imageStart),
                ref.candidate->text.c_str(),
                static_cast<unsigned long long>(start - imageStart),
                static_cast<unsigned long long>(start + got - imageStart));

            // Compact raw bytes make it possible to reconstruct mixed-width
            // registration records without assuming a structure layout first.
            for (std::size_t row = 0; row < got; row += 16)
            {
                char hex[16 * 3 + 1]{};
                char* out = hex;
                const std::size_t rowBytes = std::min<std::size_t>(16, got - row);
                for (std::size_t i = 0; i < rowBytes; ++i)
                {
                    const std::size_t remaining = sizeof(hex) - static_cast<std::size_t>(out - hex);
                    const int n = sprintf_s(out, remaining, "%02X%s", bytes[row + i], i + 1 == rowBytes ? "" : " ");
                    if (n > 0) out += n;
                }
                ScanLogOnlyPrintf(log,
                    "[ALPHA-SCAN] TABLE BYTES rva=+0x%llX %s\n",
                    static_cast<unsigned long long>((start + row) - imageStart), hex);
            }

            // Interpret aligned qwords around the slot. Highlight values that
            // point back into the image, especially executable callbacks and
            // already-discovered strings.
            const std::uintptr_t alignedStart = (start + 7u) & ~static_cast<std::uintptr_t>(7u);
            for (std::uintptr_t address = alignedStart;
                 address + sizeof(std::uintptr_t) <= start + got;
                 address += sizeof(std::uintptr_t))
            {
                const std::size_t offset = static_cast<std::size_t>(address - start);
                std::uintptr_t value = 0;
                std::memcpy(&value, bytes.data() + offset, sizeof(value));
                if (!value)
                    continue;

                if (value >= imageStart && value < imageEnd)
                {
                    const AlphaScanCandidate* pointed = FindCandidateAt(candidates, value);
                    const bool executable = LooksLikeCodeBytes(value, imageStart, imageEnd);
                    if (pointed)
                    {
                        ScanLogOnlyPrintf(log,
                            "[ALPHA-SCAN] TABLE QWORD fieldRVA=+0x%llX valueRVA=+0x%llX kind=STRING text=\"%s\"%s\n",
                            static_cast<unsigned long long>(address - imageStart),
                            static_cast<unsigned long long>(value - imageStart),
                            pointed->text.c_str(),
                            address == ref.slot ? " <ROOT>" : "");
                    }
                    else if (executable)
                    {
                        ScanPrintf(log,
                            "[ALPHA-SCAN] TABLE CODE fieldRVA=+0x%llX codeRVA=+0x%llX reason=\"%s\"\n",
                            static_cast<unsigned long long>(address - imageStart),
                            static_cast<unsigned long long>(value - imageStart),
                            ref.candidate->text.c_str());
                        LogPriorityCodeWindow(log, imageStart, value, "table-callback");
                    }
                    else
                    {
                        ScanLogOnlyPrintf(log,
                            "[ALPHA-SCAN] TABLE QWORD fieldRVA=+0x%llX valueRVA=+0x%llX kind=IMAGE%s\n",
                            static_cast<unsigned long long>(address - imageStart),
                            static_cast<unsigned long long>(value - imageStart),
                            address == ref.slot ? " <ROOT>" : "");
                    }
                }
                else if (address >= ref.slot - 0x40u && address <= ref.slot + 0x80u)
                {
                    ScanLogOnlyPrintf(log,
                        "[ALPHA-SCAN] TABLE QWORD fieldRVA=+0x%llX raw=0x%llX%s\n",
                        static_cast<unsigned long long>(address - imageStart),
                        static_cast<unsigned long long>(value),
                        address == ref.slot ? " <ROOT>" : "");
                }
            }
        }

        ScanPrintf(log, "[ALPHA-SCAN] priority table dumps complete=%zu\n", dumped);
        return dumped;
    }

    std::uint64_t HashMemory64(const unsigned char* data, std::size_t size)
    {
        // Fast non-cryptographic page fingerprint used only for change detection.
        std::uint64_t hash = 1469598103934665603ull;
        for (std::size_t i = 0; i < size; ++i)
        {
            hash ^= static_cast<std::uint64_t>(data[i]);
            hash *= 1099511628211ull;
        }
        return hash;
    }

    const char* MemoryTypeName(DWORD type)
    {
        if (type == MEM_IMAGE) return "IMAGE";
        if (type == MEM_MAPPED) return "MAPPED";
        if (type == MEM_PRIVATE) return "PRIVATE";
        return "UNKNOWN";
    }

    void WriteFullScanString(
        FILE* out,
        const char* encoding,
        std::uintptr_t address,
        const unsigned char* data,
        std::size_t length,
        DWORD protect,
        DWORD type)
    {
        if (!out || !data || !length)
            return;

        std::fprintf(out,
            "0x%016llX\t%s\t0x%08lX\t%s\t",
            static_cast<unsigned long long>(address),
            encoding,
            static_cast<unsigned long>(protect),
            MemoryTypeName(type));

        for (std::size_t i = 0; i < length; ++i)
        {
            const unsigned char ch = data[i];
            if (ch == '\\' || ch == '"')
            {
                std::fputc('\\', out);
                std::fputc(static_cast<int>(ch), out);
            }
            else if (ch == '\t') std::fputs("\\t", out);
            else if (ch == '\r') std::fputs("\\r", out);
            else if (ch == '\n') std::fputs("\\n", out);
            else std::fputc(static_cast<int>(ch), out);
        }
        std::fputc('\n', out);
    }

    void ExtractEveryPrintableString(
        FILE* stringsLog,
        std::uintptr_t blockAddress,
        const unsigned char* data,
        std::size_t size,
        DWORD protect,
        DWORD type,
        std::size_t& asciiCount,
        std::size_t& utf16Count)
    {
        constexpr std::size_t kMinLength = 4;
        constexpr std::size_t kMaxLength = 4096;

        for (std::size_t i = 0; i < size;)
        {
            if (!IsPrintableScanByte(data[i]))
            {
                ++i;
                continue;
            }

            const std::size_t begin = i;
            while (i < size && IsPrintableScanByte(data[i]) &&
                   (i - begin) < kMaxLength)
            {
                ++i;
            }

            const std::size_t length = i - begin;
            if (length >= kMinLength)
            {
                WriteFullScanString(
                    stringsLog, "ASCII", blockAddress + begin,
                    data + begin, length, protect, type);
                ++asciiCount;
            }

            if (i == begin)
                ++i;
        }

        unsigned char utf8ish[kMaxLength + 1]{};
        for (std::size_t i = 0; i + 1 < size;)
        {
            if (!IsPrintableScanByte(data[i]) || data[i + 1] != 0)
            {
                ++i;
                continue;
            }

            const std::size_t begin = i;
            std::size_t chars = 0;
            while (i + 1 < size &&
                   IsPrintableScanByte(data[i]) && data[i + 1] == 0 &&
                   chars < kMaxLength)
            {
                utf8ish[chars++] = data[i];
                i += 2;
            }

            if (chars >= kMinLength)
            {
                WriteFullScanString(
                    stringsLog, "UTF16LE", blockAddress + begin,
                    utf8ish, chars, protect, type);
                ++utf16Count;
            }

            if (i == begin)
                ++i;
        }
    }

    struct FullMemoryScanStats
    {
        std::size_t regions = 0;
        std::size_t readableRegions = 0;
        std::size_t pages = 0;
        std::size_t asciiStrings = 0;
        std::size_t utf16Strings = 0;
        std::uint64_t bytesRead = 0;
    };

    FullMemoryScanStats RunFullProcessMemoryDiscovery()
    {
        FullMemoryScanStats stats{};

        bool expected = false;
        if (!g_fullMemoryScanRunning.compare_exchange_strong(expected, true))
        {
            std::printf("[ALPHA-FULLSCAN] already running\n");
            return stats;
        }

        EnsureAlphaLogDirectories();
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"scanner" / L"full_memory");

        FILE* regions = nullptr;
        FILE* pages = nullptr;
        FILE* strings = nullptr;
        const std::string regionsPath = storage_paths::PathA("logs\\scanner\\full_memory\\regions.tsv");
        const std::string pagesPath = storage_paths::PathA("logs\\scanner\\full_memory\\pages.tsv");
        const std::string stringsPath = storage_paths::PathA("logs\\scanner\\full_memory\\strings.tsv");
        (void)fopen_s(&regions, regionsPath.c_str(), "wb");
        (void)fopen_s(&pages, pagesPath.c_str(), "wb");
        (void)fopen_s(&strings, stringsPath.c_str(), "wb");

        if (!regions || !pages || !strings)
        {
            if (regions) std::fclose(regions);
            if (pages) std::fclose(pages);
            if (strings) std::fclose(strings);
            std::printf("[ALPHA-FULLSCAN] failed to create output files\n");
            g_fullMemoryScanRunning.store(false, std::memory_order_release);
            return stats;
        }

        std::fprintf(regions,
            "base\tend\tsize\tstate\tprotect\ttype\tallocationBase\treadable\twritable\texecutable\n");
        std::fprintf(pages,
            "address\tsize\thash64\tprotect\ttype\n");
        std::fprintf(strings,
            "address\tencoding\tprotect\ttype\ttext\n");

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const std::uintptr_t processStart =
            reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const std::uintptr_t processEnd =
            reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        constexpr std::size_t kChunkSize = 4u * 1024u * 1024u;
        constexpr std::size_t kPageSize = 0x1000u;
        std::vector<unsigned char> buffer(kChunkSize);
        std::uint64_t nextProgress = 256ull * 1024ull * 1024ull;

        std::printf("[ALPHA-FULLSCAN] walking every committed readable memory region in this process...\n");

        std::uintptr_t cursor = processStart;
        while (cursor < processEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionStart + mbi.RegionSize;

            const bool committed = mbi.State == MEM_COMMIT;
            const bool readable = committed && IsReadableProtection(mbi.Protect);
            const bool writable = readable && IsWritableProtection(mbi.Protect);
            const bool executable = readable && IsExecutableProtection(mbi.Protect);

            ++stats.regions;
            if (readable)
                ++stats.readableRegions;

            std::fprintf(regions,
                "0x%016llX\t0x%016llX\t0x%llX\t0x%08lX\t0x%08lX\t%s\t0x%016llX\t%d\t%d\t%d\n",
                static_cast<unsigned long long>(regionStart),
                static_cast<unsigned long long>(regionEnd),
                static_cast<unsigned long long>(mbi.RegionSize),
                static_cast<unsigned long>(mbi.State),
                static_cast<unsigned long>(mbi.Protect),
                MemoryTypeName(mbi.Type),
                static_cast<unsigned long long>(
                    reinterpret_cast<std::uintptr_t>(mbi.AllocationBase)),
                readable ? 1 : 0,
                writable ? 1 : 0,
                executable ? 1 : 0);

            if (readable)
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (wanted && ReadMemoryBlock(block, buffer.data(), wanted, got) && got)
                    {
                        stats.bytesRead += got;

                        // Every readable byte is consumed by the string extractor.
                        ExtractEveryPrintableString(
                            strings, block, buffer.data(), got,
                            mbi.Protect, mbi.Type,
                            stats.asciiStrings, stats.utf16Strings);

                        // Every readable page gets a fingerprint and address in pages.tsv.
                        for (std::size_t offset = 0; offset < got; offset += kPageSize)
                        {
                            const std::size_t pageBytes =
                                std::min<std::size_t>(kPageSize, got - offset);
                            const std::uint64_t hash =
                                HashMemory64(buffer.data() + offset, pageBytes);
                            std::fprintf(pages,
                                "0x%016llX\t0x%zX\t0x%016llX\t0x%08lX\t%s\n",
                                static_cast<unsigned long long>(block + offset),
                                pageBytes,
                                static_cast<unsigned long long>(hash),
                                static_cast<unsigned long>(mbi.Protect),
                                MemoryTypeName(mbi.Type));
                            ++stats.pages;
                        }

                        if (stats.bytesRead >= nextProgress)
                        {
                            std::printf(
                                "[ALPHA-FULLSCAN] read=%llu MB pages=%zu strings=%zu\n",
                                static_cast<unsigned long long>(
                                    stats.bytesRead / (1024ull * 1024ull)),
                                stats.pages,
                                stats.asciiStrings + stats.utf16Strings);
                            nextProgress += 256ull * 1024ull * 1024ull;
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + kPageSize;
        }

        std::fprintf(regions,
            "# COMPLETE regions=%zu readableRegions=%zu bytesRead=%llu pages=%zu ascii=%zu utf16=%zu\n",
            stats.regions,
            stats.readableRegions,
            static_cast<unsigned long long>(stats.bytesRead),
            stats.pages,
            stats.asciiStrings,
            stats.utf16Strings);

        std::fclose(strings);
        std::fclose(pages);
        std::fclose(regions);

        std::printf(
            "[ALPHA-FULLSCAN] COMPLETE read=%llu MB pages=%zu ASCII=%zu UTF16=%zu\n",
            static_cast<unsigned long long>(stats.bytesRead / (1024ull * 1024ull)),
            stats.pages,
            stats.asciiStrings,
            stats.utf16Strings);
        std::printf(
            "[ALPHA-FULLSCAN] logs\\scanner\\full_memory\\regions.tsv / pages.tsv / strings.tsv\n");

        g_fullMemoryScanRunning.store(false, std::memory_order_release);
        return stats;
    }

    DWORD WINAPI FullProcessMemoryDiscoveryThread(void*)
    {
        (void)RunFullProcessMemoryDiscovery();
        return 0;
    }

    void StartFullProcessMemoryDiscoveryAsync()
    {
        if (g_fullMemoryScanRunning.load(std::memory_order_acquire))
        {
            std::printf("[ALPHA-FULLSCAN] already running\n");
            return;
        }

        HANDLE thread = CreateThread(
            nullptr, 0, &FullProcessMemoryDiscoveryThread, nullptr, 0, nullptr);
        if (!thread)
        {
            std::printf("[ALPHA-FULLSCAN] failed to create thread (%lu)\n",
                static_cast<unsigned long>(GetLastError()));
            return;
        }
        CloseHandle(thread);
    }

    void CaptureOrDiffAllWritableMemory()
    {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const std::uintptr_t processStart =
            reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const std::uintptr_t processEnd =
            reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        constexpr std::size_t kPageSize = 0x1000u;
        std::vector<unsigned char> page(kPageSize);

        EnsureAlphaLogDirectories();
        FILE* log = nullptr;
        const std::string fullDiffPath = storage_paths::PathA("logs\\scanner\\alpha_qr_full_memory_diff.log");
        (void)fopen_s(&log, fullDiffPath.c_str(), "ab");
        if (!log)
        {
            std::printf("[ALPHA-QR-FULL] could not open full-memory diff log\n");
            return;
        }

        if (!g_fullQrBaselineArmed.load(std::memory_order_acquire))
        {
            g_fullQrBaselinePages.clear();
            std::uintptr_t cursor = processStart;

            while (cursor < processEnd)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                    break;

                const std::uintptr_t regionStart =
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::uintptr_t regionEnd = regionStart + mbi.RegionSize;

                if (mbi.State == MEM_COMMIT &&
                    IsReadableProtection(mbi.Protect) &&
                    IsWritableProtection(mbi.Protect))
                {
                    for (std::uintptr_t at = regionStart; at < regionEnd; at += kPageSize)
                    {
                        const std::size_t wanted = static_cast<std::size_t>(
                            std::min<std::uintptr_t>(kPageSize, regionEnd - at));
                        std::size_t got = 0;
                        if (!ReadMemoryBlock(at, page.data(), wanted, got) || !got)
                            continue;

                        g_fullQrBaselinePages.push_back({
                            at,
                            static_cast<std::uint32_t>(got),
                            HashMemory64(page.data(), got),
                            mbi.Protect,
                            mbi.Type
                        });
                    }
                }

                cursor = regionEnd > cursor ? regionEnd : cursor + kPageSize;
            }

            std::fprintf(log,
                "[ALPHA-QR-FULL] BASELINE writablePages=%zu\n",
                g_fullQrBaselinePages.size());
            std::fclose(log);
            g_fullQrBaselineArmed.store(true, std::memory_order_release);

            std::printf(
                "[ALPHA-QR-FULL] baseline=%zu writable pages. Make QR visible, then F10 again.\n",
                g_fullQrBaselinePages.size());
            return;
        }

        std::size_t changed = 0;
        std::size_t unreadable = 0;
        for (const auto& baseline : g_fullQrBaselinePages)
        {
            std::size_t got = 0;
            if (!ReadMemoryBlock(
                    baseline.address, page.data(), baseline.size, got) ||
                got != baseline.size)
            {
                ++unreadable;
                continue;
            }

            const std::uint64_t nowHash = HashMemory64(page.data(), got);
            if (nowHash == baseline.hash)
                continue;

            ++changed;
            MEMORY_BASIC_INFORMATION mbi{};
            (void)VirtualQuery(
                reinterpret_cast<const void*>(baseline.address),
                &mbi, sizeof(mbi));

            std::fprintf(log,
                "[ALPHA-QR-FULL] CHANGED page=0x%016llX size=0x%X oldHash=0x%016llX newHash=0x%016llX protect=0x%08lX type=%s\n",
                static_cast<unsigned long long>(baseline.address),
                baseline.size,
                static_cast<unsigned long long>(baseline.hash),
                static_cast<unsigned long long>(nowHash),
                static_cast<unsigned long>(mbi.Protect),
                MemoryTypeName(mbi.Type));

            // Current strings from every changed page are written immediately
            // below the CHANGED line, regardless of what the popup is called.
            std::size_t ascii = 0;
            std::size_t utf16 = 0;
            ExtractEveryPrintableString(
                log, baseline.address, page.data(), got,
                mbi.Protect, mbi.Type, ascii, utf16);
        }

        int screen = -1;
        (void)SafeGetScreen(screen);
        std::uint32_t packed = 0;
        std::uint32_t mpFrontend = 0;
        (void)ReadFrontendSessionStateInternal(packed);
        (void)ReadValue(g_base + kMpFrontendStateRva, mpFrontend);

        std::fprintf(log,
            "[ALPHA-QR-FULL] DIFF COMPLETE changedPages=%zu unreadablePages=%zu screen=%d packed=0x%X mpFrontend=0x%X\n",
            changed, unreadable, screen, packed, mpFrontend);
        std::fclose(log);

        g_fullQrBaselinePages.clear();
        g_fullQrBaselineArmed.store(false, std::memory_order_release);

        std::printf(
            "[ALPHA-QR-FULL] diff complete changedPages=%zu unreadable=%zu -> logs\\scanner\\alpha_qr_full_memory_diff.log\n",
            changed, unreadable);
    }

    void AddQrWatchCandidate(
        FILE* log,
        std::vector<std::uintptr_t>& addresses,
        std::unordered_set<std::uintptr_t>& seen,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        std::uintptr_t source,
        std::uintptr_t target,
        const char* anchor,
        const char* kind)
    {
        if (target < imageStart || target + sizeof(std::uint64_t) > imageEnd)
            return;
        if (!IsCommittedAddress(reinterpret_cast<const void*>(target), sizeof(std::uint64_t)))
            return;

        // We want data/state, not another function body.
        if (IsExecutableAddress(reinterpret_cast<const void*>(target)))
            return;

        if (!seen.insert(target).second)
            return;

        addresses.push_back(target);

        std::uint64_t value = 0;
        (void)ReadValue(target, value);

        ScanPrintf(log,
            "[ALPHA-QR] WATCH-CANDIDATE anchor=%s kind=%s sourceRVA=+0x%llX targetRVA=+0x%llX qword=0x%llX\n",
            anchor,
            kind,
            static_cast<unsigned long long>(source - imageStart),
            static_cast<unsigned long long>(target - imageStart),
            static_cast<unsigned long long>(value));
    }

    std::size_t ScanQrPopupTriggerCandidates(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd)
    {
        struct QrAnchor
        {
            std::uintptr_t rva;
            const char* label;
        };

        constexpr QrAnchor anchors[] =
        {
            { kQrSignInStateRva,    "signInState" },
            { kQrBdLoginStartRva,   "bdLogin-start" },
            { kQrLoginQueueRva,     "login-queue" },
            { kQrLoginCompleteRvaA, "login-complete-A" },
            { kQrLoginCompleteRvaB, "login-complete-B" },
            { kQrAccountLinkingRva, "account-linking" },
        };

        std::vector<std::uintptr_t> addresses;
        std::unordered_set<std::uintptr_t> seen;

        // Always include the frontend/session state we already know changes
        // during the transition, so the diff log can correlate them.
        seen.insert(imageStart + kFrontendSessionStateRva);
        addresses.push_back(imageStart + kFrontendSessionStateRva);
        seen.insert(imageStart + kMpFrontendStateRva);
        addresses.push_back(imageStart + kMpFrontendStateRva);

        ScanPrintf(log,
            "[ALPHA-QR] focused popup-trigger scan started (runs before slow string/XREF scans)\n");

        for (const auto& anchor : anchors)
        {
            const std::uintptr_t hit = imageStart + anchor.rva;
            if (hit < imageStart || hit >= imageEnd)
                continue;

            constexpr std::uintptr_t kBefore = 0x180u;
            constexpr std::uintptr_t kAfter  = 0x380u;
            const std::uintptr_t start =
                hit > imageStart + kBefore ? hit - kBefore : imageStart;
            const std::uintptr_t end =
                std::min(imageEnd, hit + kAfter);
            const std::size_t wanted =
                static_cast<std::size_t>(end - start);

            if (!wanted)
                continue;

            std::vector<unsigned char> bytes(wanted);
            std::size_t got = 0;
            if (!ReadMemoryBlock(start, bytes.data(), wanted, got) || got < 8)
                continue;

            ScanPrintf(log,
                "[ALPHA-QR] TRACE anchor=%s hitRVA=+0x%llX window=+0x%llX..+0x%llX\n",
                anchor.label,
                static_cast<unsigned long long>(anchor.rva),
                static_cast<unsigned long long>(start - imageStart),
                static_cast<unsigned long long>(start + got - imageStart));

            for (std::size_t i = 0; i + 7 <= got; ++i)
            {
                const std::uintptr_t at = start + i;

                // CALL/JMP targets are logged because a common callee shared by
                // multiple linking anchors is a strong UI-trigger candidate.
                if ((bytes[i] == 0xE8 || bytes[i] == 0xE9) && i + 5 <= got)
                {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, bytes.data() + i + 1, sizeof(disp));
                    const std::uintptr_t target = static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(at + 5) +
                        static_cast<std::intptr_t>(disp));

                    if (target >= imageStart && target < imageEnd)
                    {
                        ScanLogOnlyPrintf(log,
                            "[ALPHA-QR] %s anchor=%s sourceRVA=+0x%llX targetRVA=+0x%llX\n",
                            bytes[i] == 0xE8 ? "CALL" : "JMP",
                            anchor.label,
                            static_cast<unsigned long long>(at - imageStart),
                            static_cast<unsigned long long>(target - imageStart));
                    }
                    i += 4;
                    continue;
                }

                // REX + RIP-relative LEA/MOV.
                if ((bytes[i] & 0xF8u) == 0x48u &&
                    (bytes[i + 1] == 0x8D ||
                     bytes[i + 1] == 0x8B ||
                     bytes[i + 1] == 0x89) &&
                    (bytes[i + 2] & 0xC7u) == 0x05u)
                {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, bytes.data() + i + 3, sizeof(disp));
                    const std::uintptr_t target = static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(at + 7) +
                        static_cast<std::intptr_t>(disp));

                    AddQrWatchCandidate(
                        log, addresses, seen, imageStart, imageEnd,
                        at, target, anchor.label, "RIPREF");
                    i += 6;
                    continue;
                }

                // Common RIP-relative 32-bit MOV/CMP forms.
                if ((bytes[i] == 0x8B ||
                     bytes[i] == 0x89 ||
                     bytes[i] == 0x39 ||
                     bytes[i] == 0x3B) &&
                    (bytes[i + 1] & 0xC7u) == 0x05u)
                {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, bytes.data() + i + 2, sizeof(disp));
                    const std::uintptr_t target = static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(at + 6) +
                        static_cast<std::intptr_t>(disp));

                    AddQrWatchCandidate(
                        log, addresses, seen, imageStart, imageEnd,
                        at, target, anchor.label, "RIPDATA");
                    i += 5;
                    continue;
                }

                // RIP-relative byte flag tests/writes.
                if ((bytes[i] == 0x80 ||
                     bytes[i] == 0xC6 ||
                     bytes[i] == 0xF6) &&
                    (bytes[i + 1] & 0xC7u) == 0x05u)
                {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, bytes.data() + i + 2, sizeof(disp));
                    const std::uintptr_t target = static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(at + 7) +
                        static_cast<std::intptr_t>(disp));

                    AddQrWatchCandidate(
                        log, addresses, seen, imageStart, imageEnd,
                        at, target, anchor.label, "RIPFLAG");
                    i += 6;
                    continue;
                }

                // Log nearby conditional branches. These do not reveal state
                // themselves, but identify the branch that gates the popup path.
                if ((bytes[i] >= 0x70 && bytes[i] <= 0x7F) ||
                    (i + 2 < got && bytes[i] == 0x0F &&
                     bytes[i + 1] >= 0x80 && bytes[i + 1] <= 0x8F))
                {
                    ScanLogOnlyPrintf(log,
                        "[ALPHA-QR] BRANCH anchor=%s sourceRVA=+0x%llX opcode=%02X %02X\n",
                        anchor.label,
                        static_cast<unsigned long long>(at - imageStart),
                        bytes[i],
                        i + 1 < got ? bytes[i + 1] : 0);
                }
            }
        }

        std::sort(addresses.begin(), addresses.end());
        addresses.erase(
            std::unique(addresses.begin(), addresses.end()),
            addresses.end());

        // Publish only after the vector is completely built.
        g_qrWatchAddresses = addresses;
        g_qrBaseline.clear();
        g_qrBaselineArmed.store(false, std::memory_order_release);
        g_qrWatchReady.store(true, std::memory_order_release);

        ScanPrintf(log,
            "[ALPHA-QR] focused popup-trigger scan complete watchCandidates=%zu\n",
            addresses.size());
        std::printf(
            "[ALPHA-QR] watch ready: %zu focused candidates. F10 now also snapshots EVERY writable process page.\n",
            addresses.size());

        return addresses.size();
    }

    void CaptureOrDiffQrState()
    {
        if (!g_qrWatchReady.load(std::memory_order_acquire) ||
            g_qrWatchAddresses.empty())
        {
            std::printf("[ALPHA-QR] watch list not ready yet; wait for '[ALPHA-QR] watch ready'\n");
            return;
        }

        EnsureAlphaLogDirectories();

        FILE* log = nullptr;
        const std::string qrWatchPath = storage_paths::PathA("logs\\scanner\\alpha_qr_watch.log");
        (void)fopen_s(&log, qrWatchPath.c_str(), "ab");
        if (!log)
        {
            std::printf("[ALPHA-QR] could not open logs\\scanner\\alpha_qr_watch.log\n");
            return;
        }

        SYSTEMTIME st{};
        GetLocalTime(&st);

        if (!g_qrBaselineArmed.load(std::memory_order_acquire))
        {
            g_qrBaseline.clear();
            g_qrBaseline.reserve(g_qrWatchAddresses.size());

            for (const std::uintptr_t address : g_qrWatchAddresses)
            {
                std::uint64_t value = 0;
                if (ReadValue(address, value))
                    g_qrBaseline.push_back({ address, value });
            }

            int screen = -1;
            (void)SafeGetScreen(screen);

            std::uint32_t packed = 0;
            std::uint32_t mpFrontend = 0;
            (void)ReadFrontendSessionStateInternal(packed);
            (void)ReadValue(g_base + kMpFrontendStateRva, mpFrontend);

            std::fprintf(log,
                "[%02u:%02u:%02u.%03u] BASELINE screen=%d packed=0x%X mpFrontend=0x%X candidates=%zu\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                screen, packed, mpFrontend, g_qrBaseline.size());
            std::fclose(log);

            g_qrBaselineArmed.store(true, std::memory_order_release);
            std::printf(
                "[ALPHA-QR] baseline captured (%zu values). Now make the QR popup appear, then press F10 again.\n",
                g_qrBaseline.size());
            return;
        }

        std::size_t changed = 0;
        int screen = -1;
        (void)SafeGetScreen(screen);

        std::uint32_t packed = 0;
        std::uint32_t mpFrontend = 0;
        (void)ReadFrontendSessionStateInternal(packed);
        (void)ReadValue(g_base + kMpFrontendStateRva, mpFrontend);

        std::fprintf(log,
            "[%02u:%02u:%02u.%03u] DIFF screen=%d packed=0x%X mpFrontend=0x%X\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            screen, packed, mpFrontend);

        for (const auto& oldValue : g_qrBaseline)
        {
            std::uint64_t now = 0;
            if (!ReadValue(oldValue.address, now) || now == oldValue.value)
                continue;

            ++changed;
            std::fprintf(log,
                "[ALPHA-QR] CHANGED rva=+0x%llX old=0x%016llX new=0x%016llX\n",
                static_cast<unsigned long long>(oldValue.address - g_base),
                static_cast<unsigned long long>(oldValue.value),
                static_cast<unsigned long long>(now));
        }

        std::fprintf(log, "[ALPHA-QR] DIFF complete changed=%zu\n", changed);
        std::fclose(log);

        g_qrBaselineArmed.store(false, std::memory_order_release);
        std::printf(
            "[ALPHA-QR] diff complete: %zu candidate values changed. Saved to logs\\scanner\\alpha_qr_watch.log\n",
            changed);
    }

    struct AlphaTraceAnchor
    {
        std::uintptr_t rva;
        const char* label;
    };

    void TraceKnownAlphaAnchor(FILE* log, std::uintptr_t imageStart, std::uintptr_t imageEnd,
                               const AlphaTraceAnchor& anchor,
                               const std::vector<AlphaScanCandidate>& candidates)
    {
        const std::uintptr_t hit = imageStart + anchor.rva;
        if (hit < imageStart || hit >= imageEnd)
            return;

        const std::uintptr_t before = 0x80u;
        const std::uintptr_t after = 0x180u;
        const std::uintptr_t start = hit > imageStart + before ? hit - before : imageStart;
        const std::uintptr_t end = std::min(imageEnd, hit + after);
        const std::size_t wanted = static_cast<std::size_t>(end - start);
        if (!wanted)
            return;

        std::vector<unsigned char> bytes(wanted);
        std::size_t got = 0;
        if (!ReadMemoryBlock(start, bytes.data(), wanted, got) || got < 8)
            return;

        ScanPrintf(log, "[ALPHA-SCAN] TRACE anchor=%s hitRVA=+0x%llX window=+0x%llX..+0x%llX\n",
            anchor.label,
            static_cast<unsigned long long>(anchor.rva),
            static_cast<unsigned long long>(start - imageStart),
            static_cast<unsigned long long>(start + got - imageStart));

        LogPriorityCodeWindow(log, imageStart, hit, anchor.label);

        auto logTarget = [&](const char* kind, std::uintptr_t at, std::uintptr_t target)
        {
            if (target < imageStart || target >= imageEnd)
                return;

            const AlphaScanCandidate* pointed = FindCandidateAt(candidates, target);
            std::uintptr_t raw = 0;
            const bool haveRaw = ReadValue(target, raw);
            if (pointed)
            {
                ScanLogOnlyPrintf(log,
                    "[ALPHA-SCAN] TRACE %s anchor=%s atRVA=+0x%llX targetRVA=+0x%llX STRING=\"%s\"\n",
                    kind, anchor.label,
                    static_cast<unsigned long long>(at - imageStart),
                    static_cast<unsigned long long>(target - imageStart),
                    pointed->text.c_str());
            }
            else if (haveRaw)
            {
                ScanLogOnlyPrintf(log,
                    "[ALPHA-SCAN] TRACE %s anchor=%s atRVA=+0x%llX targetRVA=+0x%llX qword=0x%llX\n",
                    kind, anchor.label,
                    static_cast<unsigned long long>(at - imageStart),
                    static_cast<unsigned long long>(target - imageStart),
                    static_cast<unsigned long long>(raw));
            }
            else
            {
                ScanLogOnlyPrintf(log,
                    "[ALPHA-SCAN] TRACE %s anchor=%s atRVA=+0x%llX targetRVA=+0x%llX\n",
                    kind, anchor.label,
                    static_cast<unsigned long long>(at - imageStart),
                    static_cast<unsigned long long>(target - imageStart));
            }
        };

        for (std::size_t i = 0; i + 7 <= got; ++i)
        {
            const std::uintptr_t at = start + i;
            if ((bytes[i] == 0xE8 || bytes[i] == 0xE9) && i + 5 <= got)
            {
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data() + i + 1, sizeof(disp));
                const std::uintptr_t target = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(at + 5) + static_cast<std::intptr_t>(disp));
                logTarget(bytes[i] == 0xE8 ? "CALL" : "JMP", at, target);
                i += 4;
                continue;
            }

            if (i + 7 <= got && (bytes[i] & 0xF8u) == 0x48u &&
                (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B || bytes[i + 1] == 0x89) &&
                (bytes[i + 2] & 0xC7u) == 0x05u)
            {
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data() + i + 3, sizeof(disp));
                const std::uintptr_t target = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(at + 7) + static_cast<std::intptr_t>(disp));
                logTarget("RIPREF", at, target);
                i += 6;
                continue;
            }
            if (i + 6 <= got && (bytes[i] == 0x8B || bytes[i] == 0x89) &&
                (bytes[i + 1] & 0xC7u) == 0x05u)
            {
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data() + i + 2, sizeof(disp));
                const std::uintptr_t target = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(at + 6) + static_cast<std::intptr_t>(disp));
                logTarget("RIPREF", at, target);
                i += 5;
                continue;
            }
            if (i + 7 <= got && (bytes[i] == 0x80 || bytes[i] == 0xC6) &&
                (bytes[i + 1] & 0xC7u) == 0x05u)
            {
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data() + i + 2, sizeof(disp));
                const std::uintptr_t target = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(at + 7) + static_cast<std::intptr_t>(disp));
                logTarget("RIPFLAG", at, target);
                i += 6;
            }
        }
    }

    std::size_t TraceKnownAlphaAnchors(FILE* log, std::uintptr_t imageStart, std::uintptr_t imageEnd,
                                       const std::vector<AlphaScanCandidate>& candidates)
    {
        ScanPrintf(log, "[ALPHA-SCAN] Phase 6/6: targeted online/QR/name control-flow trace...\n");
        constexpr AlphaTraceAnchor anchors[] =
        {
            { 0x00ACEDE0u, "network-label-selector-function" },
            { 0x00ACEE02u, "Online-label-selector" },
            { 0x00ACEE12u, "Offline-label-selector" },
            { 0x00ACEF20u, "frontend-mode-check" },
            { 0x00FF5881u, "startMultiplayer-selector" },
            { 0x00FF589Eu, "startZombies-selector" },
            { 0x00FC67BFu, "online-table-reader-A" },
            { 0x00FC6D09u, "online-table-reader-B" },
            { 0x00FC6DA9u, "online-table-reader-C" },
            { 0x0110EA9Cu, "signInState-path" },
            { 0x01E58A79u, "bdLogin-start-path" },
            { 0x01E61EF7u, "account-linking-path" },
            { kQrFlowStartingCrossplayXrefRva, "Starting-crossplay-login-xref" },
            { kQrFlowNoAccountXrefRva, "No-crossplay-account-xref" },
            { kQrFlowLinkStateXrefRvaA, "Crossplay-login-link-xref-A" },
            { kQrFlowLinkStateXrefRvaB, "Crossplay-login-link-xref-B" },
            { kQrFlowLinkStateXrefRvaC, "Crossplay-login-link-xref-C" },
            { 0x0087B131u, "playerName-binding-A" },
            { 0x010ECF8Au, "playerName-binding-B" },
            { 0x010EE09Au, "playerName-binding-C" },
            { 0x01106DD9u, "displayName-binding" },
        };

        for (const auto& anchor : anchors)
            TraceKnownAlphaAnchor(log, imageStart, imageEnd, anchor, candidates);

        const std::size_t count = sizeof(anchors) / sizeof(anchors[0]);
        ScanPrintf(log, "[ALPHA-SCAN] targeted traces complete=%zu\n", count);
        return count;
    }

    struct AlphaExactTarget
    {
        std::uintptr_t rva;
        const char* label;
    };

    bool DecodeRipRelativeReference(const unsigned char* bytes, std::size_t available,
                                    std::size_t& instructionLength, std::size_t& displacementOffset)
    {
        instructionLength = 0;
        displacementOffset = 0;
        if (!bytes || available < 6)
            return false;

        std::size_t prefix = 0;
        if (bytes[0] >= 0x40 && bytes[0] <= 0x4F)
            prefix = 1;
        if (available <= prefix + 5)
            return false;

        const unsigned char op = bytes[prefix];
        const unsigned char modrm = bytes[prefix + 1];
        if ((modrm & 0xC7u) != 0x05u)
        {
            if (op == 0x0F && available >= prefix + 7)
            {
                const unsigned char op2 = bytes[prefix + 1];
                const unsigned char mr = bytes[prefix + 2];
                if ((op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) &&
                    (mr & 0xC7u) == 0x05u)
                {
                    instructionLength = prefix + 7;
                    displacementOffset = prefix + 3;
                    return true;
                }
            }
            return false;
        }

        switch (op)
        {
        case 0x8B:
        case 0x89:
        case 0x8D:
            instructionLength = prefix + 6;
            displacementOffset = prefix + 2;
            return true;
        case 0x80:
        case 0x83:
        case 0xC6:
        case 0xF6:
            instructionLength = prefix + 7;
            displacementOffset = prefix + 2;
            return true;
        case 0x81:
        case 0xC7:
        case 0xF7:
            instructionLength = prefix + 10;
            displacementOffset = prefix + 2;
            return true;
        default:
            return false;
        }
    }


    struct AlphaNameLabelHit
    {
        std::uintptr_t address = 0;
        std::string text;
    };

    struct AlphaNameScanStats
    {
        std::size_t runtimeMatches = 0;
        std::size_t writableRuntimeMatches = 0;
        std::size_t identityLabels = 0;
        std::size_t identityXrefs = 0;
    };

    const AlphaNameLabelHit* FindNameLabelAt(
        const std::vector<AlphaNameLabelHit>& labels,
        std::uintptr_t address)
    {
        for (const auto& label : labels)
        {
            if (label.address == address)
                return &label;
        }
        return nullptr;
    }

    bool IsIdentityLabel(const std::string& text)
    {
        const std::string lower = LowerAscii(text);
        constexpr const char* tokens[] =
        {
            "playername",
            "player_name",
            "username",
            "user_name",
            "displayname",
            "display_name",
            "gamertag",
            "clantag",
            "clan_tag",
            "set_username",
            "profilename",
            "profile_name",
            "personaname",
            "persona_name",
            "accountname",
            "account_name",
            "localclientname",
            "local_client_name",
        };

        for (const char* token : tokens)
        {
            if (lower.find(token) != std::string::npos)
                return true;
        }
        return false;
    }

    void LogNameMemoryContext(
        FILE* log,
        std::uintptr_t address,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd)
    {
        constexpr std::size_t kBefore = 32;
        constexpr std::size_t kBytes = 96;
        const std::uintptr_t start = address > kBefore ? address - kBefore : address;

        unsigned char bytes[kBytes]{};
        std::size_t got = 0;
        if (!ReadMemoryBlock(start, bytes, sizeof(bytes), got) || !got)
            return;

        char ascii[kBytes + 1]{};
        for (std::size_t i = 0; i < got; ++i)
            ascii[i] = IsPrintableScanByte(bytes[i]) ? static_cast<char>(bytes[i]) : '.';

        MEMORY_BASIC_INFORMATION mbi{};
        VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi));
        const bool inImage = address >= imageStart && address < imageEnd;

        ScanLogOnlyPrintf(log,
            "[ALPHA-NAME] CONTEXT address=0x%llX%s protect=0x%lX type=0x%lX ascii=\"%s\"\n",
            static_cast<unsigned long long>(address),
            inImage ? " image" : "",
            static_cast<unsigned long>(mbi.Protect),
            static_cast<unsigned long>(mbi.Type),
            ascii);
    }

    void ScanIdentityLabelsInImage(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        std::vector<AlphaNameLabelHit>& labels)
    {
        constexpr std::size_t kChunkSize = 1024u * 1024u;
        constexpr std::size_t kMinString = 4;
        constexpr std::size_t kMaxString = 256;

        std::vector<unsigned char> buffer(kChunkSize);
        std::unordered_set<std::uintptr_t> seen;

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i < got;)
                        {
                            if (!IsPrintableScanByte(buffer[i]))
                            {
                                ++i;
                                continue;
                            }

                            const std::size_t begin = i;
                            while (i < got && IsPrintableScanByte(buffer[i]) &&
                                   (i - begin) < kMaxString)
                            {
                                ++i;
                            }

                            const std::size_t len = i - begin;
                            if (len >= kMinString)
                            {
                                std::string value(
                                    reinterpret_cast<const char*>(buffer.data() + begin), len);
                                if (IsIdentityLabel(value))
                                {
                                    const std::uintptr_t at = block + begin;
                                    if (seen.insert(at).second)
                                    {
                                        labels.push_back({ at, value });
                                        ScanPrintf(log,
                                            "[ALPHA-NAME] LABEL stringRVA=+0x%llX \"%s\"\n",
                                            static_cast<unsigned long long>(at - imageStart),
                                            value.c_str());
                                    }
                                }
                            }
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }
    }

    std::size_t ScanIdentityLabelXrefs(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        const std::vector<AlphaNameLabelHit>& labels)
    {
        if (labels.empty())
            return 0;

        constexpr std::size_t kChunkSize = 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);
        std::unordered_set<std::uintptr_t> seen;
        std::size_t count = 0;

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT &&
                IsReadableProtection(mbi.Protect) &&
                IsExecutableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 7 <= got; ++i)
                        {
                            std::size_t instructionLength = 0;
                            std::size_t displacementOffset = 0;

                            if (buffer[i] >= 0x40 && buffer[i] <= 0x4F &&
                                (buffer[i + 1] == 0x8D || buffer[i + 1] == 0x8B || buffer[i + 1] == 0x89) &&
                                (buffer[i + 2] & 0xC7u) == 0x05u)
                            {
                                instructionLength = 7;
                                displacementOffset = 3;
                            }
                            else if ((buffer[i] == 0x8D || buffer[i] == 0x8B || buffer[i] == 0x89) &&
                                     (buffer[i + 1] & 0xC7u) == 0x05u)
                            {
                                instructionLength = 6;
                                displacementOffset = 2;
                            }

                            if (!instructionLength || i + instructionLength > got)
                                continue;

                            std::int32_t disp = 0;
                            std::memcpy(&disp, buffer.data() + i + displacementOffset, sizeof(disp));
                            const std::uintptr_t instruction = block + i;
                            const std::uintptr_t target =
                                instruction + instructionLength + static_cast<std::intptr_t>(disp);
                            const AlphaNameLabelHit* label = FindNameLabelAt(labels, target);

                            if (!label || !seen.insert(instruction).second)
                                continue;

                            ++count;
                            ScanPrintf(log,
                                "[ALPHA-NAME] XREF codeRVA=+0x%llX -> stringRVA=+0x%llX \"%s\"\n",
                                static_cast<unsigned long long>(instruction - imageStart),
                                static_cast<unsigned long long>(label->address - imageStart),
                                label->text.c_str());
                            LogPriorityCodeWindow(log, imageStart, instruction, "name-identity");
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        return count;
    }

    void FindRuntimeNameInBuffer(
        FILE* log,
        std::uintptr_t block,
        const unsigned char* data,
        std::size_t size,
        bool writable,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        std::unordered_set<std::uintptr_t>& seen,
        std::vector<std::uintptr_t>& exactAsciiHits,
        AlphaNameScanStats& stats)
    {
        constexpr char kName[] = "Player1";
        constexpr unsigned char kNameUtf16[] =
        {
            'P', 0, 'l', 0, 'a', 0, 'y', 0, 'e', 0, 'r', 0, '1', 0
        };

        for (std::size_t i = 0; i + sizeof(kName) <= size; ++i)
        {
            if (std::memcmp(data + i, kName, sizeof(kName) - 1) != 0 ||
                data[i + sizeof(kName) - 1] != 0)
            {
                continue;
            }

            if (i > 0)
            {
                const unsigned char previous = data[i - 1];
                if (std::isalnum(static_cast<unsigned char>(previous)) || previous == '_')
                    continue;
            }

            const std::uintptr_t at = block + i;
            if (!seen.insert(at).second)
                continue;

            exactAsciiHits.push_back(at);
            ++stats.runtimeMatches;
            if (writable)
                ++stats.writableRuntimeMatches;

            const bool inImage = at >= imageStart && at < imageEnd;
            if (inImage)
            {
                ScanPrintf(log,
                    "[ALPHA-NAME] CANDIDATE ASCII address=0x%llX rva=+0x%llX %s\n",
                    static_cast<unsigned long long>(at),
                    static_cast<unsigned long long>(at - imageStart),
                    writable ? "writable=YES" : "writable=NO");
            }
            else
            {
                ScanPrintf(log,
                    "[ALPHA-NAME] CANDIDATE ASCII address=0x%llX %s\n",
                    static_cast<unsigned long long>(at),
                    writable ? "writable=YES" : "writable=NO");
            }
            LogNameMemoryContext(log, at, imageStart, imageEnd);
        }

        for (std::size_t i = 0; i + sizeof(kNameUtf16) + 2 <= size; ++i)
        {
            if (std::memcmp(data + i, kNameUtf16, sizeof(kNameUtf16)) != 0 ||
                data[i + sizeof(kNameUtf16)] != 0 ||
                data[i + sizeof(kNameUtf16) + 1] != 0)
            {
                continue;
            }

            if (i >= 2)
            {
                const unsigned char previous = data[i - 2];
                if (std::isalnum(static_cast<unsigned char>(previous)) || previous == '_')
                    continue;
            }

            const std::uintptr_t at = block + i;
            if (!seen.insert(at).second)
                continue;

            ++stats.runtimeMatches;
            if (writable)
                ++stats.writableRuntimeMatches;

            const bool inImage = at >= imageStart && at < imageEnd;
            if (inImage)
            {
                ScanPrintf(log,
                    "[ALPHA-NAME] CANDIDATE UTF16 address=0x%llX rva=+0x%llX %s\n",
                    static_cast<unsigned long long>(at),
                    static_cast<unsigned long long>(at - imageStart),
                    writable ? "writable=YES" : "writable=NO");
            }
            else
            {
                ScanPrintf(log,
                    "[ALPHA-NAME] CANDIDATE UTF16 address=0x%llX %s\n",
                    static_cast<unsigned long long>(at),
                    writable ? "writable=YES" : "writable=NO");
            }
            LogNameMemoryContext(log, at, imageStart, imageEnd);
        }
    }

    bool IsExactStandalonePlayer1Field(std::uintptr_t address)
    {
        constexpr char kExactName[8] = { 'P','l','a','y','e','r','1','\0' };
        char value[8]{};
        std::size_t got = 0;
        if (!ReadMemoryBlock(address, value, sizeof(value), got) ||
            got != sizeof(value) ||
            std::memcmp(value, kExactName, sizeof(kExactName)) != 0)
        {
            return false;
        }

        // Do not accept the "Player1" part of a longer identifier.
        if (address > 0)
        {
            unsigned char previous = 0;
            std::size_t previousGot = 0;
            if (ReadMemoryBlock(address - 1, &previous, 1, previousGot) &&
                previousGot == 1 &&
                (std::isalnum(static_cast<unsigned char>(previous)) || previous == '_'))
            {
                return false;
            }
        }

        return true;
    }

    bool FindFastPlayerNameCluster(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        AlphaNameScanStats& stats)
    {
        constexpr std::uintptr_t kStride = 0x48u;
        constexpr std::uint32_t kRequiredRun = 4;
        constexpr std::uint32_t kMaxCount = 64;
        constexpr std::size_t kChunkSize = 2u * 1024u * 1024u;
        constexpr std::size_t kMaxScanBytes = 3ull * 1024ull * 1024ull * 1024ull;
        constexpr char kNeedle[8] = { 'P','l','a','y','e','r','1','\0' };

        HMODULE self = GetModuleHandleW(L"version.dll");
        SYSTEM_INFO si{};
        GetSystemInfo(&si);

        std::vector<unsigned char> buffer(kChunkSize);
        std::size_t scannedBytes = 0;

        ScanPrintf(log,
            "[ALPHA-NAME] FAST cluster scan started: exact Player1 fields, stride=0x48\n");

        std::uintptr_t cursor =
            reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const std::uintptr_t processEnd =
            reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        while (cursor < processEnd && scannedBytes < kMaxScanBytes)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionStart + mbi.RegionSize;

            const bool readable =
                mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect);
            const bool writable =
                readable && IsWritableProtection(mbi.Protect);
            const bool useful =
                mbi.Type == MEM_PRIVATE ||
                (regionStart >= imageStart && regionStart < imageEnd);
            const bool isSelf =
                self && mbi.AllocationBase == reinterpret_cast<void*>(self);

            if (writable && useful && !isSelf)
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd && scannedBytes < kMaxScanBytes)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        scannedBytes += got;

                        for (std::size_t i = 0; i + sizeof(kNeedle) <= got; ++i)
                        {
                            if (std::memcmp(buffer.data() + i, kNeedle, sizeof(kNeedle)) != 0)
                                continue;

                            const std::uintptr_t candidate = block + i;
                            if (!IsExactStandalonePlayer1Field(candidate))
                                continue;

                            bool run = true;
                            for (std::uint32_t n = 1; n < kRequiredRun; ++n)
                            {
                                if (!IsExactStandalonePlayer1Field(
                                        candidate + static_cast<std::uintptr_t>(n) * kStride))
                                {
                                    run = false;
                                    break;
                                }
                            }

                            if (!run)
                                continue;

                            std::uint32_t count = kRequiredRun;
                            while (count < kMaxCount &&
                                   IsExactStandalonePlayer1Field(
                                       candidate + static_cast<std::uintptr_t>(count) * kStride))
                            {
                                ++count;
                            }

                            g_nameClusterBase.store(candidate, std::memory_order_release);
                            g_nameClusterCount.store(count, std::memory_order_release);

                            stats.runtimeMatches += count;
                            stats.writableRuntimeMatches += count;

                            ScanPrintf(log,
                                "[ALPHA-NAME] FAST CLUSTER base=0x%llX count=%u stride=0x%llX fieldBytes=8 confidence=HIGH scannedMB=%zu\n",
                                static_cast<unsigned long long>(candidate),
                                count,
                                static_cast<unsigned long long>(kStride),
                                scannedBytes / (1024u * 1024u));

                            LogNameMemoryContext(log, candidate, imageStart, imageEnd);
                            return true;
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        ScanPrintf(log,
            "[ALPHA-NAME] FAST cluster scan did not find a 4-record 0x48 run after %zu MB\n",
            scannedBytes / (1024u * 1024u));
        return false;
    }

    AlphaNameScanStats ScanAlphaNameCandidates(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd)
    {
        AlphaNameScanStats stats{};
        std::vector<AlphaNameLabelHit> labels;
        std::unordered_set<std::uintptr_t> seenRuntime;
        std::vector<std::uintptr_t> exactAsciiHits;

        ScanPrintf(log,
            "[ALPHA-NAME] scan started: fast live Player1 cluster + identity fields\n");

        const bool fastClusterFound =
            FindFastPlayerNameCluster(log, imageStart, imageEnd, stats);

        ScanIdentityLabelsInImage(log, imageStart, imageEnd, labels);
        stats.identityLabels = labels.size();
        stats.identityXrefs = ScanIdentityLabelXrefs(
            log, imageStart, imageEnd, labels);

        // A high-confidence 0x48-stride cluster is enough for the F8 test.
        // Skip the old multi-gigabyte fallback sweep when we already have it.
        if (fastClusterFound)
        {
            ScanPrintf(log,
                "[ALPHA-NAME] scan complete fastCluster=YES runtimeMatches=%zu writableMatches=%zu identityLabels=%zu identityXrefs=%zu\n",
                stats.runtimeMatches,
                stats.writableRuntimeMatches,
                stats.identityLabels,
                stats.identityXrefs);
            return stats;
        }

        HMODULE self = GetModuleHandleW(L"version.dll");
        SYSTEM_INFO si{};
        GetSystemInfo(&si);

        constexpr std::size_t kChunkSize = 1024u * 1024u;
        constexpr std::size_t kMaxTotalBytes = 2ull * 1024ull * 1024ull * 1024ull;
        std::vector<unsigned char> buffer(kChunkSize);
        std::size_t scannedBytes = 0;

        std::uintptr_t cursor =
            reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const std::uintptr_t processEnd =
            reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        while (cursor < processEnd && scannedBytes < kMaxTotalBytes)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionStart + mbi.RegionSize;
            const bool readable =
                mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect);
            const bool writable = readable && IsWritableProtection(mbi.Protect);
            const bool usefulType =
                mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED ||
                (regionStart >= imageStart && regionStart < imageEnd);
            const bool isSelf =
                self && mbi.AllocationBase == reinterpret_cast<void*>(self);

            if (readable && writable && usefulType && !isSelf)
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd && scannedBytes < kMaxTotalBytes)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        FindRuntimeNameInBuffer(
                            log, block, buffer.data(), got, writable,
                            imageStart, imageEnd, seenRuntime, exactAsciiHits, stats);
                        scannedBytes += got;
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        std::sort(exactAsciiHits.begin(), exactAsciiHits.end());

        std::uintptr_t bestBase = 0;
        std::uint32_t bestCount = 0;
        constexpr std::uintptr_t kPlayerRecordStride = 0x48u;

        for (std::size_t i = 0; i < exactAsciiHits.size(); ++i)
        {
            std::uint32_t count = 1;
            std::uintptr_t expected = exactAsciiHits[i] + kPlayerRecordStride;
            std::size_t j = i + 1;
            while (j < exactAsciiHits.size() && exactAsciiHits[j] == expected)
            {
                ++count;
                expected += kPlayerRecordStride;
                ++j;
            }

            if (count > bestCount)
            {
                bestCount = count;
                bestBase = exactAsciiHits[i];
            }
        }

        if (bestCount >= 4)
        {
            g_nameClusterBase.store(bestBase, std::memory_order_release);
            g_nameClusterCount.store(bestCount, std::memory_order_release);
            ScanPrintf(log,
                "[ALPHA-NAME] CLUSTER base=0x%llX count=%u stride=0x%llX fieldBytes=8 confidence=HIGH\n",
                static_cast<unsigned long long>(bestBase),
                bestCount,
                static_cast<unsigned long long>(kPlayerRecordStride));
        }
        else
        {
            g_nameClusterBase.store(0, std::memory_order_release);
            g_nameClusterCount.store(0, std::memory_order_release);
            ScanPrintf(log,
                "[ALPHA-NAME] CLUSTER not found (need >=4 exact standalone Player1 fields at stride 0x48)\n");
        }

        ScanPrintf(log,
            "[ALPHA-NAME] scan complete runtimeMatches=%zu writableMatches=%zu identityLabels=%zu identityXrefs=%zu scannedWritableMB=%zu\n",
            stats.runtimeMatches,
            stats.writableRuntimeMatches,
            stats.identityLabels,
            stats.identityXrefs,
            scannedBytes / (1024u * 1024u));

        return stats;
    }

    std::size_t ScanSetScreenCallsFast(FILE* log, std::uintptr_t imageStart, std::uintptr_t imageEnd)
    {
        struct Target
        {
            std::uintptr_t address;
            const char* label;
            bool carriesScreenArgument;
        };

        const Target targets[] =
        {
            { imageStart + kSetScreenRva, "SetScreen-direct", true },
            { imageStart + kSetScreenThunkRva, "SetScreen-thunk", true },
            { imageStart + kScreenProviderRva, "ScreenProvider", false },
        };

        constexpr std::size_t kChunkSize = 4u * 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);
        std::unordered_set<std::uintptr_t> seen;
        std::size_t found = 0;

        ScanPrintf(log,
            "[ALPHA-SCAN] FAST SetScreen call-graph scan (direct + thunk callers + provider)...\n");

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT &&
                IsReadableProtection(mbi.Protect) &&
                IsExecutableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 5 <= got; ++i)
                        {
                            if (buffer[i] != 0xE8)
                                continue;

                            std::int32_t disp = 0;
                            std::memcpy(&disp, buffer.data() + i + 1, sizeof(disp));
                            const std::uintptr_t at = block + i;
                            const std::uintptr_t target = static_cast<std::uintptr_t>(
                                static_cast<std::intptr_t>(at + 5) +
                                static_cast<std::intptr_t>(disp));

                            const Target* matched = nullptr;
                            for (const auto& candidate : targets)
                            {
                                if (target == candidate.address)
                                {
                                    matched = &candidate;
                                    break;
                                }
                            }

                            if (!matched || !seen.insert(at).second)
                                continue;

                            ++found;

                            if (!matched->carriesScreenArgument)
                            {
                                ScanPrintf(log,
                                    "[ALPHA-SCAN] SCREEN-PROVIDER-CALL codeRVA=+0x%llX targetRVA=+0x%llX\n",
                                    static_cast<unsigned long long>(at - imageStart),
                                    static_cast<unsigned long long>(target - imageStart));

                                // GetScreen() returns EAX. Collect nearby comparisons
                                // made against EAX so we learn screen IDs the stock
                                // Alpha actually recognizes instead of brute forcing.
                                const std::size_t inspectEnd =
                                    std::min<std::size_t>(got, i + 5 + 48);

                                for (std::size_t p = i + 5; p < inspectEnd; ++p)
                                {
                                    // cmp eax, imm8  => 83 F8 xx
                                    if (p + 3 <= inspectEnd &&
                                        buffer[p] == 0x83 && buffer[p + 1] == 0xF8)
                                    {
                                        const std::uint32_t screenId = buffer[p + 2];
                                        ScanPrintf(log,
                                            "[ALPHA-SCAN] SCREEN-ID-CANDIDATE sourceRVA=+0x%llX id=%u (0x%X) form=cmp-eax-imm8\n",
                                            static_cast<unsigned long long>(at - imageStart),
                                            screenId,
                                            screenId);
                                    }

                                    // cmp eax, imm32 => 3D xx xx xx xx
                                    if (p + 5 <= inspectEnd && buffer[p] == 0x3D)
                                    {
                                        std::uint32_t screenId = 0;
                                        std::memcpy(&screenId, buffer.data() + p + 1, sizeof(screenId));
                                        ScanPrintf(log,
                                            "[ALPHA-SCAN] SCREEN-ID-CANDIDATE sourceRVA=+0x%llX id=%u (0x%X) form=cmp-eax-imm32\n",
                                            static_cast<unsigned long long>(at - imageStart),
                                            screenId,
                                            screenId);
                                    }
                                }

                                LogPriorityCodeWindow(log, imageStart, at, matched->label);
                                continue;
                            }

                            bool immediate = false;
                            std::uint32_t screen = 0;

                            if (i >= 5 && buffer[i - 5] == 0xB9)
                            {
                                std::memcpy(&screen, buffer.data() + i - 4, sizeof(screen));
                                immediate = true;
                            }
                            else if (i >= 2 &&
                                     buffer[i - 2] == 0x33 &&
                                     buffer[i - 1] == 0xC9)
                            {
                                screen = 0;
                                immediate = true;
                            }

                            // The second direct caller discovered in the previous
                            // scan is:
                            //     call ScreenProvider
                            //     mov ecx,eax
                            //     call SetScreen
                            // Record that dependency explicitly.
                            bool providerResult = false;
                            if (!immediate && i >= 7 &&
                                buffer[i - 7] == 0xE8 &&
                                buffer[i - 2] == 0x8B &&
                                buffer[i - 1] == 0xC8)
                            {
                                std::int32_t providerDisp = 0;
                                std::memcpy(&providerDisp, buffer.data() + i - 6, sizeof(providerDisp));
                                const std::uintptr_t providerCall = block + i - 7;
                                const std::uintptr_t providerTarget = static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(providerCall + 5) +
                                    static_cast<std::intptr_t>(providerDisp));
                                providerResult = providerTarget == imageStart + kScreenProviderRva;
                            }

                            if (immediate)
                            {
                                ScanPrintf(log,
                                    "[ALPHA-SCAN] %s-CALL codeRVA=+0x%llX screen=%u (0x%X)\n",
                                    matched->label,
                                    static_cast<unsigned long long>(at - imageStart),
                                    screen,
                                    screen);
                            }
                            else if (providerResult)
                            {
                                ScanPrintf(log,
                                    "[ALPHA-SCAN] %s-CALL codeRVA=+0x%llX screen=ScreenProvider(+0x%llX)\n",
                                    matched->label,
                                    static_cast<unsigned long long>(at - imageStart),
                                    static_cast<unsigned long long>(kScreenProviderRva));
                            }
                            else if (target == imageStart + kSetScreenRva &&
                                     at == imageStart + kSetScreenThunkRva + 4)
                            {
                                ScanPrintf(log,
                                    "[ALPHA-SCAN] %s-CALL codeRVA=+0x%llX screen=passthrough wrapper=+0x%llX\n",
                                    matched->label,
                                    static_cast<unsigned long long>(at - imageStart),
                                    static_cast<unsigned long long>(kSetScreenThunkRva));
                            }
                            else
                            {
                                ScanPrintf(log,
                                    "[ALPHA-SCAN] %s-CALL codeRVA=+0x%llX screen=dynamic\n",
                                    matched->label,
                                    static_cast<unsigned long long>(at - imageStart));
                            }

                            LogPriorityCodeWindow(log, imageStart, at, matched->label);
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        ScanPrintf(log,
            "[ALPHA-SCAN] FAST SetScreen call-graph scan complete refs=%zu\n",
            found);
        return found;
    }

    struct QrUiAnchor
    {
        std::uintptr_t rva;
        const char* label;
    };

    void TraceQrFlowWriteWindow(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        std::uintptr_t hitRva,
        const char* label)
    {
        const std::uintptr_t hit = imageStart + hitRva;
        if (hit < imageStart || hit >= imageEnd)
            return;

        constexpr std::uintptr_t kBefore = 0xA0u;
        constexpr std::uintptr_t kAfter = 0x160u;
        const std::uintptr_t start =
            hit > imageStart + kBefore ? hit - kBefore : imageStart;
        const std::uintptr_t end = std::min(imageEnd, hit + kAfter);
        const std::size_t wanted = static_cast<std::size_t>(end - start);
        if (!wanted)
            return;

        std::vector<unsigned char> bytes(wanted);
        std::size_t got = 0;
        if (!ReadMemoryBlock(start, bytes.data(), wanted, got) || got < 8)
            return;

        ScanPrintf(log,
            "[ALPHA-QRUI] FLOW anchor=%s hitRVA=+0x%llX window=+0x%llX..+0x%llX\n",
            label,
            static_cast<unsigned long long>(hitRva),
            static_cast<unsigned long long>(start - imageStart),
            static_cast<unsigned long long>(start + got - imageStart));

        LogPriorityCodeWindow(log, imageStart, hit, label);

        for (std::size_t i = 0; i + 7 <= got; ++i)
        {
            std::size_t p = i;
            bool rex = false;
            if (bytes[p] >= 0x40 && bytes[p] <= 0x4F)
            {
                rex = true;
                ++p;
                if (p + 6 >= got)
                    continue;
            }

            // mov dword ptr [base+disp], imm32 (C7 /0).
            if (bytes[p] == 0xC7 && p + 2 < got)
            {
                const unsigned char modrm = bytes[p + 1];
                if ((modrm & 0x38u) == 0)
                {
                    const unsigned char mod = modrm & 0xC0u;
                    const unsigned char baseReg = modrm & 0x07u;

                    // Ignore RSP/SIB stack locals; we want object/global state writes.
                    if (baseReg != 4)
                    {
                        if (mod == 0x40u && p + 7 <= got)
                        {
                            const std::int8_t disp8 =
                                static_cast<std::int8_t>(bytes[p + 2]);
                            std::uint32_t imm = 0;
                            std::memcpy(&imm, bytes.data() + p + 3, sizeof(imm));

                            ScanPrintf(log,
                                "[ALPHA-QRUI] STATE-WRITE anchor=%s atRVA=+0x%llX width=32 baseReg=%u disp=%d imm=%u (0x%X)\n",
                                label,
                                static_cast<unsigned long long>((start + i) - imageStart),
                                static_cast<unsigned int>(baseReg),
                                static_cast<int>(disp8),
                                imm,
                                imm);
                        }
                        else if (mod == 0x80u && p + 10 <= got)
                        {
                            std::int32_t disp32 = 0;
                            std::uint32_t imm = 0;
                            std::memcpy(&disp32, bytes.data() + p + 2, sizeof(disp32));
                            std::memcpy(&imm, bytes.data() + p + 6, sizeof(imm));

                            ScanPrintf(log,
                                "[ALPHA-QRUI] STATE-WRITE anchor=%s atRVA=+0x%llX width=32 baseReg=%u disp=0x%X imm=%u (0x%X)\n",
                                label,
                                static_cast<unsigned long long>((start + i) - imageStart),
                                static_cast<unsigned int>(baseReg),
                                static_cast<unsigned int>(disp32),
                                imm,
                                imm);
                        }
                    }
                }
            }

            // mov byte ptr [base+disp], imm8 (C6 /0).
            if (bytes[p] == 0xC6 && p + 3 < got)
            {
                const unsigned char modrm = bytes[p + 1];
                if ((modrm & 0x38u) == 0)
                {
                    const unsigned char mod = modrm & 0xC0u;
                    const unsigned char baseReg = modrm & 0x07u;
                    if (baseReg != 4)
                    {
                        if (mod == 0x40u && p + 4 <= got)
                        {
                            const std::int8_t disp8 =
                                static_cast<std::int8_t>(bytes[p + 2]);
                            const unsigned int imm = bytes[p + 3];

                            ScanPrintf(log,
                                "[ALPHA-QRUI] STATE-WRITE anchor=%s atRVA=+0x%llX width=8 baseReg=%u disp=%d imm=%u (0x%X)\n",
                                label,
                                static_cast<unsigned long long>((start + i) - imageStart),
                                static_cast<unsigned int>(baseReg),
                                static_cast<int>(disp8),
                                imm,
                                imm);
                        }
                        else if (mod == 0x80u && p + 7 <= got)
                        {
                            std::int32_t disp32 = 0;
                            std::memcpy(&disp32, bytes.data() + p + 2, sizeof(disp32));
                            const unsigned int imm = bytes[p + 6];

                            ScanPrintf(log,
                                "[ALPHA-QRUI] STATE-WRITE anchor=%s atRVA=+0x%llX width=8 baseReg=%u disp=0x%X imm=%u (0x%X)\n",
                                label,
                                static_cast<unsigned long long>((start + i) - imageStart),
                                static_cast<unsigned int>(baseReg),
                                static_cast<unsigned int>(disp32),
                                imm,
                                imm);
                        }
                    }
                }
            }

            (void)rex;
        }
    }

    std::size_t ScanQrUiAssetReferences(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd)
    {
        constexpr QrUiAnchor anchors[] =
        {
            { kQrUiAccountManagementRva, "cod_account_management_options" },
            { kQrUiAccountRegisterRva,   "cod_account_register_options" },
            { kQrUiSignInInfoBasicRva,   "cod_account_sign_in_info_basic" },
            { kQrUiFocusableWebViewRva,  "isFocusableWebView" },
            { kQrUiWebViewDoneRva,       "webviewKeyboardDone" },
            { kQrUiWebViewCharRva,       "webviewKeyboardChar" },
            { kQrUiWebViewKeyDownRva,    "webviewKeyboardKeyDown" },
        };

        ScanPrintf(log,
            "[ALPHA-QRUI] exact account-registration/WebView XREF scan started\n");

        std::unordered_map<std::uintptr_t, const char*> absoluteAnchors;
        for (const auto& anchor : anchors)
            absoluteAnchors.emplace(imageStart + anchor.rva, anchor.label);

        struct PointerSlot
        {
            std::uintptr_t address = 0;
            const char* label = nullptr;
            std::uintptr_t target = 0;
        };
        std::vector<PointerSlot> pointerSlots;
        pointerSlots.reserve(256);

        // First find direct 64-bit pointer-table entries that point at the
        // recovered account/UI strings.
        constexpr std::size_t kChunkSize = 2u * 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + sizeof(std::uintptr_t) <= got; i += sizeof(std::uintptr_t))
                        {
                            std::uintptr_t value = 0;
                            std::memcpy(&value, buffer.data() + i, sizeof(value));
                            const auto it = absoluteAnchors.find(value);
                            if (it == absoluteAnchors.end())
                                continue;

                            const std::uintptr_t slot = block + i;
                            pointerSlots.push_back({ slot, it->second, value });

                            if (pointerSlots.size() <= 512)
                            {
                                ScanPrintf(log,
                                    "[ALPHA-QRUI] POINTER label=%s slotRVA=+0x%llX -> stringRVA=+0x%llX\n",
                                    it->second,
                                    static_cast<unsigned long long>(slot - imageStart),
                                    static_cast<unsigned long long>(value - imageStart));
                            }
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        std::unordered_map<std::uintptr_t, const char*> pointerSlotMap;
        for (const auto& slot : pointerSlots)
            pointerSlotMap.emplace(slot.address, slot.label);

        std::unordered_set<std::uintptr_t> seen;
        std::size_t directXrefs = 0;
        std::size_t indirectXrefs = 0;

        // Now walk executable memory for RIP-relative references directly to
        // the UI strings or to pointer-table entries that reference them.
        cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT &&
                IsReadableProtection(mbi.Protect) &&
                IsExecutableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 6 <= got; ++i)
                        {
                            std::size_t instructionLength = 0;
                            std::size_t displacementOffset = 0;
                            if (!DecodeRipRelativeReference(
                                    buffer.data() + i,
                                    got - i,
                                    instructionLength,
                                    displacementOffset) ||
                                i + instructionLength > got)
                            {
                                continue;
                            }

                            std::int32_t disp = 0;
                            std::memcpy(
                                &disp,
                                buffer.data() + i + displacementOffset,
                                sizeof(disp));

                            const std::uintptr_t at = block + i;
                            const std::uintptr_t target =
                                static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(at + instructionLength) +
                                    static_cast<std::intptr_t>(disp));

                            const auto direct = absoluteAnchors.find(target);
                            if (direct != absoluteAnchors.end() &&
                                seen.insert(at).second)
                            {
                                ++directXrefs;
                                ScanPrintf(log,
                                    "[ALPHA-QRUI] DIRECT-XREF label=%s codeRVA=+0x%llX stringRVA=+0x%llX\n",
                                    direct->second,
                                    static_cast<unsigned long long>(at - imageStart),
                                    static_cast<unsigned long long>(target - imageStart));
                                LogPriorityCodeWindow(log, imageStart, at, direct->second);
                                continue;
                            }

                            const auto indirect = pointerSlotMap.find(target);
                            if (indirect != pointerSlotMap.end() &&
                                seen.insert(at).second)
                            {
                                ++indirectXrefs;
                                ScanPrintf(log,
                                    "[ALPHA-QRUI] TABLE-XREF label=%s codeRVA=+0x%llX slotRVA=+0x%llX\n",
                                    indirect->second,
                                    static_cast<unsigned long long>(at - imageStart),
                                    static_cast<unsigned long long>(target - imageStart));
                                LogPriorityCodeWindow(log, imageStart, at, indirect->second);
                            }
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        constexpr AlphaTraceAnchor flowAnchors[] =
        {
            { kQrFlowStartingCrossplayXrefRva, "Starting-crossplay-login" },
            { kQrFlowNoAccountXrefRva,         "NO-CROSSPLAY-ACCOUNT" },
            { kQrFlowLinkStateXrefRvaA,        "CROSSPLAY-LOG-IN-LINK-A" },
            { kQrFlowLinkStateXrefRvaB,        "CROSSPLAY-LOG-IN-LINK-B" },
            { kQrFlowLinkStateXrefRvaC,        "CROSSPLAY-LOG-IN-LINK-C" },
        };

        for (const auto& flow : flowAnchors)
            TraceQrFlowWriteWindow(log, imageStart, imageEnd, flow.rva, flow.label);

        ScanPrintf(log,
            "[ALPHA-QRUI] scan complete pointers=%zu directXrefs=%zu tableXrefs=%zu flowAnchors=%zu\n",
            pointerSlots.size(),
            directXrefs,
            indirectXrefs,
            sizeof(flowAnchors) / sizeof(flowAnchors[0]));

        return directXrefs + indirectXrefs;
    }


    struct CrossplayStateString
    {
        std::uintptr_t rva;
        const char* name;
    };

    std::size_t ScanCrossplayStateMachineMap(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd)
    {
        // Recovered from the exhaustive whole-process string catalog.
        constexpr CrossplayStateString states[] =
        {
            { 0x0254DC78u, "FETCHING_FIRST_PARTY_TOKEN" },
            { 0x0254DCE8u, "FIRST_PARTY_AUTHED" },
            { 0x0254DD88u, "LOGIN_DELAY" },
            { 0x0254DDE0u, "AUTHENTICATING" },
            { 0x0254DE48u, "AUTHENTICATED" },
            { 0x0254DEB8u, "JOINING_LOGIN_QUEUE" },
            { 0x0254DF00u, "CROSSPLAY_LOG_IN" },
            { 0x0254DF40u, "LEGACY_LOG_IN" },
            { 0x0254E058u, "POLLING_LOGIN_QUEUE" },
            { 0x0254E0C8u, "FLOW_PAUSED" },
            { 0x0254E100u, "CONNECTING_TO_LSG" },
            { 0x0254E150u, "CREATING_UNO_ANONYMOUS_ACCOUNT" },
            { 0x0254E1C0u, "RESUME_FLOW" },
            { 0x0254E278u, "CREATING_UNO_ACCOUNT" },
            { 0x0254E2D0u, "AUTHENTICATING_UNO_ACCOUNT" },
            { 0x0254E328u, "UPDATING_UNO_ACCOUNT" },
            { 0x0254E390u, "CROSSPLAY_LOG_IN_LINK" },
            { 0x0254E438u, "REPORTING_EXTENDED_AUTH_INFO" },
            { 0x0254E4A0u, "FETCHING_UNO_ACCOUNT" },
            { 0x0254E530u, "COMPLETED" },
        };

        std::unordered_map<std::uintptr_t, const char*> targets;
        for (const auto& state : states)
            targets.emplace(imageStart + state.rva, state.name);

        ScanPrintf(log,
            "[ALPHA-QRSTATE] state-map scan started: %zu named crossplay states\n",
            sizeof(states) / sizeof(states[0]));

        constexpr std::size_t kChunkSize = 2u * 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);
        std::unordered_set<std::uintptr_t> seenXrefs;
        std::unordered_set<std::uintptr_t> seenWrites;
        std::size_t xrefs = 0;
        std::size_t writes = 0;

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT &&
                IsReadableProtection(mbi.Protect) &&
                IsExecutableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 6 <= got; ++i)
                        {
                            std::size_t instructionLength = 0;
                            std::size_t displacementOffset = 0;
                            if (!DecodeRipRelativeReference(
                                    buffer.data() + i,
                                    got - i,
                                    instructionLength,
                                    displacementOffset) ||
                                i + instructionLength > got)
                            {
                                continue;
                            }

                            std::int32_t disp = 0;
                            std::memcpy(
                                &disp,
                                buffer.data() + i + displacementOffset,
                                sizeof(disp));

                            const std::uintptr_t at = block + i;
                            const std::uintptr_t target =
                                static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(at + instructionLength) +
                                    static_cast<std::intptr_t>(disp));

                            const auto stateIt = targets.find(target);
                            if (stateIt == targets.end() ||
                                !seenXrefs.insert(at).second)
                            {
                                continue;
                            }

                            ++xrefs;
                            ScanPrintf(log,
                                "[ALPHA-QRSTATE] STRING-XREF state=%s codeRVA=+0x%llX stringRVA=+0x%llX\n",
                                stateIt->second,
                                static_cast<unsigned long long>(at - imageStart),
                                static_cast<unsigned long long>(target - imageStart));

                            LogPriorityCodeWindow(log, imageStart, at, stateIt->second);

                            // The login state machine observed in this build stores
                            // its current state at object+0x1C. Search a tight window
                            // around each state-name XREF for:
                            //     mov dword ptr [base+1Ch], imm32
                            constexpr std::uintptr_t kBefore = 0x120u;
                            constexpr std::uintptr_t kAfter  = 0x180u;
                            const std::uintptr_t localStart =
                                at > imageStart + kBefore ? at - kBefore : imageStart;
                            const std::uintptr_t localEnd =
                                std::min(imageEnd, at + kAfter);
                            const std::size_t localSize =
                                static_cast<std::size_t>(localEnd - localStart);

                            std::vector<unsigned char> local(localSize);
                            std::size_t localGot = 0;
                            if (!ReadMemoryBlock(
                                    localStart,
                                    local.data(),
                                    localSize,
                                    localGot))
                            {
                                continue;
                            }

                            for (std::size_t p = 0; p + 7 <= localGot; ++p)
                            {
                                std::size_t op = p;
                                unsigned int rexB = 0;

                                if (local[op] >= 0x40 && local[op] <= 0x4F)
                                {
                                    rexB = local[op] & 0x01u;
                                    ++op;
                                }

                                if (op + 7 > localGot ||
                                    local[op] != 0xC7)
                                {
                                    continue;
                                }

                                const unsigned char modrm = local[op + 1];
                                const unsigned char mod = modrm & 0xC0u;
                                const unsigned char reg = (modrm >> 3) & 0x07u;
                                const unsigned char rm = modrm & 0x07u;

                                if (reg != 0 || mod != 0x40u || rm == 4)
                                    continue;

                                const std::int8_t disp8 =
                                    static_cast<std::int8_t>(local[op + 2]);
                                if (disp8 != 0x1C)
                                    continue;

                                std::uint32_t imm = 0;
                                std::memcpy(
                                    &imm,
                                    local.data() + op + 3,
                                    sizeof(imm));

                                const std::uintptr_t writeAt = localStart + p;
                                if (!seenWrites.insert(writeAt).second)
                                    continue;

                                ++writes;
                                const unsigned int baseRegister =
                                    static_cast<unsigned int>(rm) + (rexB ? 8u : 0u);

                                const long long delta =
                                    static_cast<long long>(writeAt) -
                                    static_cast<long long>(at);

                                ScanPrintf(log,
                                    "[ALPHA-QRSTATE] STATE-WRITE near=%s codeRVA=+0x%llX delta=%lld objectBaseReg=%u field=+0x1C value=%u (0x%X)\n",
                                    stateIt->second,
                                    static_cast<unsigned long long>(writeAt - imageStart),
                                    delta,
                                    baseRegister,
                                    imm,
                                    imm);
                            }
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        // Trace how RSI (register 6), used by the known +0x1C writes, is sourced
        // in the surrounding login-state-machine code. This is read-only and
        // helps us locate the actual live state object on the next pass.
        constexpr std::uintptr_t kFlowCenter = kQrFlowNoAccountXrefRva;
        const std::uintptr_t flowStart =
            imageStart + (kFlowCenter > 0x1800u ? kFlowCenter - 0x1800u : 0u);
        const std::uintptr_t flowEnd =
            std::min(imageEnd, imageStart + kFlowCenter + 0x1800u);
        const std::size_t flowSize =
            static_cast<std::size_t>(flowEnd - flowStart);

        std::vector<unsigned char> flow(flowSize);
        std::size_t flowGot = 0;
        if (ReadMemoryBlock(flowStart, flow.data(), flowSize, flowGot))
        {
            for (std::size_t i = 0; i + 7 <= flowGot; ++i)
            {
                const std::uintptr_t at = flowStart + i;

                // mov rsi, rcx
                if (i + 3 <= flowGot &&
                    flow[i] == 0x48 &&
                    flow[i + 1] == 0x8B &&
                    flow[i + 2] == 0xF1)
                {
                    ScanPrintf(log,
                        "[ALPHA-QRSTATE] RSI-SOURCE codeRVA=+0x%llX form=mov-rsi-rcx\n",
                        static_cast<unsigned long long>(at - imageStart));
                }

                // mov rsi, [rip+disp32]
                if (i + 7 <= flowGot &&
                    flow[i] == 0x48 &&
                    flow[i + 1] == 0x8B &&
                    flow[i + 2] == 0x35)
                {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, flow.data() + i + 3, sizeof(disp));
                    const std::uintptr_t target =
                        static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(at + 7) +
                            static_cast<std::intptr_t>(disp));

                    ScanPrintf(log,
                        "[ALPHA-QRSTATE] RSI-SOURCE codeRVA=+0x%llX form=mov-rsi-rip targetRVA=+0x%llX\n",
                        static_cast<unsigned long long>(at - imageStart),
                        static_cast<unsigned long long>(target - imageStart));
                }
            }
        }

        ScanPrintf(log,
            "[ALPHA-QRSTATE] state-map scan complete stringXrefs=%zu stateWrites=%zu\n",
            xrefs,
            writes);
        return xrefs + writes;
    }

    std::size_t ScanAccountUiRvaReferences(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd)
    {
        struct RvaTarget
        {
            std::uint32_t rva;
            const char* label;
        };

        constexpr RvaTarget targets[] =
        {
            { static_cast<std::uint32_t>(kQrUiAccountManagementRva), "cod_account_management_options" },
            { static_cast<std::uint32_t>(kQrUiAccountRegisterRva),   "cod_account_register_options" },
            { static_cast<std::uint32_t>(kQrUiSignInInfoBasicRva),   "cod_account_sign_in_info_basic" },
        };

        ScanPrintf(log,
            "[ALPHA-QRUI] 32-bit RVA/table scan started for account UI names\n");

        constexpr std::size_t kChunkSize = 2u * 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);

        struct Slot
        {
            std::uintptr_t address = 0;
            const char* label = nullptr;
            std::uint32_t value = 0;
        };
        std::vector<Slot> slots;
        std::unordered_set<std::uintptr_t> seenSlots;

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 4 <= got; ++i)
                        {
                            const unsigned char first = buffer[i];
                            bool possible = false;
                            for (const auto& target : targets)
                            {
                                if (first == static_cast<unsigned char>(target.rva & 0xFFu))
                                {
                                    possible = true;
                                    break;
                                }
                            }
                            if (!possible)
                                continue;

                            std::uint32_t value = 0;
                            std::memcpy(&value, buffer.data() + i, sizeof(value));

                            for (const auto& target : targets)
                            {
                                if (value != target.rva)
                                    continue;

                                const std::uintptr_t slot = block + i;
                                if (!seenSlots.insert(slot).second)
                                    continue;

                                slots.push_back({ slot, target.label, value });
                                ScanPrintf(log,
                                    "[ALPHA-QRUI] RVA-SLOT label=%s slotRVA=+0x%llX value=+0x%X\n",
                                    target.label,
                                    static_cast<unsigned long long>(slot - imageStart),
                                    value);
                            }
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        // Find executable references to any discovered RVA-table slot.
        std::unordered_map<std::uintptr_t, const char*> slotMap;
        for (const auto& slot : slots)
            slotMap.emplace(slot.address, slot.label);

        std::unordered_set<std::uintptr_t> seenXrefs;
        std::size_t xrefs = 0;

        cursor = imageStart;
        while (!slotMap.empty() && cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT &&
                IsReadableProtection(mbi.Protect) &&
                IsExecutableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 6 <= got; ++i)
                        {
                            std::size_t instructionLength = 0;
                            std::size_t displacementOffset = 0;
                            if (!DecodeRipRelativeReference(
                                    buffer.data() + i,
                                    got - i,
                                    instructionLength,
                                    displacementOffset) ||
                                i + instructionLength > got)
                            {
                                continue;
                            }

                            std::int32_t disp = 0;
                            std::memcpy(
                                &disp,
                                buffer.data() + i + displacementOffset,
                                sizeof(disp));

                            const std::uintptr_t at = block + i;
                            const std::uintptr_t target =
                                static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(at + instructionLength) +
                                    static_cast<std::intptr_t>(disp));

                            const auto slot = slotMap.find(target);
                            if (slot == slotMap.end() ||
                                !seenXrefs.insert(at).second)
                            {
                                continue;
                            }

                            ++xrefs;
                            ScanPrintf(log,
                                "[ALPHA-QRUI] RVA-SLOT-XREF label=%s codeRVA=+0x%llX slotRVA=+0x%llX\n",
                                slot->second,
                                static_cast<unsigned long long>(at - imageStart),
                                static_cast<unsigned long long>(target - imageStart));
                            LogPriorityCodeWindow(log, imageStart, at, slot->second);
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        ScanPrintf(log,
            "[ALPHA-QRUI] 32-bit RVA/table scan complete slots=%zu xrefs=%zu\n",
            slots.size(),
            xrefs);
        return slots.size() + xrefs;
    }

    bool LooksLikeVirtualSubobject(std::uintptr_t address)
    {
        std::uintptr_t vtable = 0;
        if (!ReadValue(address, vtable) ||
            vtable < 0x10000u ||
            !IsCommittedAddress(reinterpret_cast<const void*>(vtable), 0x28u))
        {
            return false;
        }

        std::uintptr_t fn0 = 0;
        std::uintptr_t fn20 = 0;
        (void)ReadValue(vtable, fn0);
        (void)ReadValue(vtable + 0x20u, fn20);

        return (fn0 && IsExecutableAddress(reinterpret_cast<const void*>(fn0))) ||
               (fn20 && IsExecutableAddress(reinterpret_cast<const void*>(fn20)));
    }

    bool LooksLikeCrossplayStateMachineObject(
        std::uintptr_t object,
        std::uint32_t expectedState)
    {
        // This object is large. The real state-machine path accesses virtual
        // subobjects at +0x1A8E0 and +0x1AE20, plus object pointers at +0x40/+0x48.
        // Requiring those features eliminates the huge number of random
        // "integer 5 at +0x1C" false positives.
        if (!IsCommittedAddress(
                reinterpret_cast<const void*>(object),
                0x1AE28u))
        {
            return false;
        }

        std::uint32_t state = 0;
        if (!ReadValue(object + 0x1Cu, state) || state != expectedState)
            return false;

        std::uintptr_t ptr40 = 0;
        std::uintptr_t ptr48 = 0;
        if (!ReadValue(object + 0x40u, ptr40) ||
            !ReadValue(object + 0x48u, ptr48) ||
            ptr40 < 0x10000u ||
            ptr48 < 0x10000u ||
            !IsCommittedAddress(reinterpret_cast<const void*>(ptr40), 1) ||
            !IsCommittedAddress(reinterpret_cast<const void*>(ptr48), 1))
        {
            return false;
        }

        if (!LooksLikeVirtualSubobject(object + 0x1A8E0u))
            return false;
        if (!LooksLikeVirtualSubobject(object + 0x1AE20u))
            return false;

        return true;
    }

    void LogCrossplayObjectDetails(FILE* log, std::uintptr_t object)
    {
        std::uint32_t state = 0;
        std::uintptr_t ptr40 = 0;
        std::uintptr_t ptr48 = 0;
        std::uintptr_t vtA8E0 = 0;
        std::uintptr_t vtAE20 = 0;

        (void)ReadValue(object + 0x1Cu, state);
        (void)ReadValue(object + 0x40u, ptr40);
        (void)ReadValue(object + 0x48u, ptr48);
        (void)ReadValue(object + 0x1A8E0u, vtA8E0);
        (void)ReadValue(object + 0x1AE20u, vtAE20);

        ScanPrintf(log,
            "[ALPHA-QRSTATE] STRONG-OBJECT object=0x%llX state=%u ptr40=0x%llX ptr48=0x%llX vt1A8E0=0x%llX vt1AE20=0x%llX\n",
            static_cast<unsigned long long>(object),
            state,
            static_cast<unsigned long long>(ptr40),
            static_cast<unsigned long long>(ptr48),
            static_cast<unsigned long long>(vtA8E0),
            static_cast<unsigned long long>(vtAE20));

        constexpr std::size_t kDumpBytes = 0x80;
        unsigned char bytes[kDumpBytes]{};
        std::size_t got = 0;
        if (ReadMemoryBlock(object, bytes, sizeof(bytes), got) && got)
        {
            char line[(kDumpBytes * 3) + 1]{};
            std::size_t pos = 0;
            for (std::size_t i = 0; i < got && pos + 4 < sizeof(line); ++i)
            {
                const int written = sprintf_s(
                    line + pos,
                    sizeof(line) - pos,
                    "%02X ",
                    bytes[i]);
                if (written <= 0)
                    break;
                pos += static_cast<std::size_t>(written);
            }

            ScanPrintf(log,
                "[ALPHA-QRSTATE] STRONG-OBJECT-BYTES object=0x%llX first0x80=%s\n",
                static_cast<unsigned long long>(object),
                line);
        }
    }

    struct StatePathCall
    {
        std::uintptr_t callRva = 0;
        std::uintptr_t targetRva = 0;
        const char* path = nullptr;
    };

    void CollectCallsNearRva(
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd,
        std::uintptr_t centerRva,
        const char* path,
        std::vector<StatePathCall>& out)
    {
        constexpr std::uintptr_t kBefore = 0xA0u;
        constexpr std::uintptr_t kAfter = 0x120u;

        const std::uintptr_t center = imageStart + centerRva;
        if (center < imageStart || center >= imageEnd)
            return;

        const std::uintptr_t start =
            center > imageStart + kBefore ? center - kBefore : imageStart;
        const std::uintptr_t end =
            std::min(imageEnd, center + kAfter);
        const std::size_t size =
            static_cast<std::size_t>(end - start);

        if (!size)
            return;

        std::vector<unsigned char> bytes(size);
        std::size_t got = 0;
        if (!ReadMemoryBlock(start, bytes.data(), size, got) || got < 5)
            return;

        for (std::size_t i = 0; i + 5 <= got; ++i)
        {
            if (bytes[i] != 0xE8)
                continue;

            std::int32_t disp = 0;
            std::memcpy(&disp, bytes.data() + i + 1, sizeof(disp));

            const std::uintptr_t at = start + i;
            const std::uintptr_t target = static_cast<std::uintptr_t>(
                static_cast<std::intptr_t>(at + 5) +
                static_cast<std::intptr_t>(disp));

            if (target < imageStart || target >= imageEnd)
                continue;

            out.push_back({
                at - imageStart,
                target - imageStart,
                path
            });

            i += 4;
        }
    }

    std::size_t ScanState5UniqueCalls(
        FILE* log,
        std::uintptr_t imageStart,
        std::uintptr_t imageEnd)
    {
        struct Center
        {
            std::uintptr_t rva;
            const char* label;
        };

        constexpr Center linkCenters[] =
        {
            { kQrFlowLinkStateXrefRvaA, "LINK-A" },
            { kQrFlowLinkStateXrefRvaB, "LINK-B" },
            { kQrFlowLinkStateXrefRvaC, "LINK-C" },
        };

        constexpr Center comparisonCenters[] =
        {
            { 0x01E5BAF4u, "UPDATING-UNO" },
            { 0x01E5BE07u, "CONNECTING-LSG" },
            { 0x01E5C143u, "FETCHING-UNO" },
            { 0x01E5C1BCu, "COMPLETED" },
        };

        std::vector<StatePathCall> linkCalls;
        std::vector<StatePathCall> comparisonCalls;

        for (const auto& center : linkCenters)
            CollectCallsNearRva(
                imageStart, imageEnd, center.rva, center.label, linkCalls);

        for (const auto& center : comparisonCenters)
            CollectCallsNearRva(
                imageStart, imageEnd, center.rva, center.label, comparisonCalls);

        std::unordered_set<std::uintptr_t> comparisonTargets;
        for (const auto& call : comparisonCalls)
            comparisonTargets.insert(call.targetRva);

        std::unordered_set<std::uintptr_t> seen;
        std::size_t unique = 0;

        ScanPrintf(log,
            "[ALPHA-QRSTATE] state-5 unique-call comparison started linkCalls=%zu comparisonCalls=%zu\n",
            linkCalls.size(),
            comparisonCalls.size());

        for (const auto& call : linkCalls)
        {
            if (comparisonTargets.find(call.targetRva) != comparisonTargets.end())
                continue;
            if (!seen.insert(call.targetRva).second)
                continue;

            ++unique;
            ScanPrintf(log,
                "[ALPHA-QRSTATE] STATE5-UNIQUE-CALL path=%s callRVA=+0x%llX targetRVA=+0x%llX\n",
                call.path,
                static_cast<unsigned long long>(call.callRva),
                static_cast<unsigned long long>(call.targetRva));

            LogPriorityCodeWindow(
                log,
                imageStart,
                imageStart + call.targetRva,
                "state5-unique-target");
        }

        ScanPrintf(log,
            "[ALPHA-QRSTATE] state-5 unique-call comparison complete uniqueTargets=%zu\n",
            unique);

        return unique;
    }

    std::size_t ScanLiveCrossplayState5Objects(FILE* log)
    {
        ScanPrintf(log,
            "[ALPHA-QRSTATE] live state=5 STRUCTURAL object scan started\n");

        // Preferred path: the one-shot breakpoint at the proven state-5 write
        // captured RSI directly. This turns the old multi-gigabyte heap walk into
        // an immediate validation/dump on normal Alpha startup.
        const std::uintptr_t captured =
            g_crossplayStateObject.load(std::memory_order_acquire);
        if (captured)
        {
            std::uint32_t state = 0;
            if (ReadValue(captured + 0x1Cu, state) && state == 5 &&
                LooksLikeCrossplayStateMachineObject(captured, 5))
            {
                ScanPrintf(log,
                    "[ALPHA-QRSTATE] state-5 object supplied by execution probe object=0x%llX; skipping full private-memory sweep\n",
                    static_cast<unsigned long long>(captured));
                LogCrossplayObjectDetails(log, captured);
                ScanPrintf(log,
                    "[ALPHA-QRSTATE] live state=5 STRUCTURAL scan complete strongCandidates=1 logged=1 scannedMB=0 source=execution-probe\n");
                return 1;
            }

            ScanPrintf(log,
                "[ALPHA-QRSTATE] execution-probe candidate=0x%llX was not state-5/structurally valid at scan time; using fallback sweep\n",
                static_cast<unsigned long long>(captured));
        }

        SYSTEM_INFO si{};
        GetSystemInfo(&si);

        constexpr std::size_t kChunkSize = 4u * 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);

        std::uintptr_t cursor =
            reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const std::uintptr_t processEnd =
            reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        std::unordered_set<std::uintptr_t> seen;
        std::size_t candidates = 0;
        std::size_t logged = 0;
        std::uint64_t scanned = 0;

        while (cursor < processEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionStart =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionStart + mbi.RegionSize;

            if (mbi.State == MEM_COMMIT &&
                mbi.Type == MEM_PRIVATE &&
                IsReadableProtection(mbi.Protect) &&
                IsWritableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;

                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        scanned += got;

                        const unsigned char* begin = buffer.data();
                        const unsigned char* end = buffer.data() + got;
                        const unsigned char* pos = begin;

                        while (pos + 4 <= end)
                        {
                            const void* hit = std::memchr(
                                pos,
                                0x05,
                                static_cast<std::size_t>(end - pos));
                            if (!hit)
                                break;

                            const unsigned char* p =
                                static_cast<const unsigned char*>(hit);
                            if (p + 4 <= end &&
                                p[0] == 0x05 &&
                                p[1] == 0x00 &&
                                p[2] == 0x00 &&
                                p[3] == 0x00)
                            {
                                const std::uintptr_t stateAddress =
                                    block + static_cast<std::uintptr_t>(p - begin);

                                if (stateAddress >= 0x1Cu)
                                {
                                    const std::uintptr_t object =
                                        stateAddress - 0x1Cu;

                                    if ((object & 0x7u) == 0 &&
                                        seen.insert(object).second)
                                    {
                                        std::uintptr_t ptr40 = 0;
                                        std::uintptr_t ptr48 = 0;
                                        std::uint32_t confirm = 0;

                                        if (ReadValue(object + 0x1Cu, confirm) &&
                                            confirm == 5 &&
                                            LooksLikeCrossplayStateMachineObject(object, 5))
                                        {
                                            ++candidates;

                                            // Publish the first structurally valid object.
                                            std::uintptr_t expected = 0;
                                            if (g_crossplayStateObject.compare_exchange_strong(
                                                    expected,
                                                    object,
                                                    std::memory_order_acq_rel))
                                            {
                                                ScanPrintf(log,
                                                    "[ALPHA-QRSTATE] published high-confidence crossplay object=0x%llX\n",
                                                    static_cast<unsigned long long>(object));
                                            }

                                            if (logged < 16)
                                            {
                                                ++logged;
                                                LogCrossplayObjectDetails(log, object);
                                            }
                                        }
                                    }
                                }
                            }

                            pos = p + 1;
                        }
                    }

                    if (!wanted)
                        break;
                    block += wanted;
                }
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        ScanPrintf(log,
            "[ALPHA-QRSTATE] live state=5 STRUCTURAL scan complete strongCandidates=%zu logged=%zu scannedMB=%llu\n",
            candidates,
            logged,
            static_cast<unsigned long long>(scanned / (1024ull * 1024ull)));
        return candidates;
    }

    std::size_t ScanExactAlphaControlReferences(FILE* log, std::uintptr_t imageStart, std::uintptr_t imageEnd)
    {
        constexpr AlphaExactTarget targets[] =
        {
            { kFrontendSessionStateRva, "session-state-65259E4" },
            { kMpFrontendStateRva, "mp-frontend-A8609C8" },
            { 0x0C995E53u, "start-zombies-flag" },
            { 0x0C995E54u, "start-multiplayer-flag" },
            { 0x0C995E55u, "start-campaign-flag" },
            { 0x0C995E56u, "start-warzone-flag" },
            { 0x0C995E57u, "start-selector-state" },
            { 0x0A3FDA50u, "online-registration-table" },
        };
        constexpr AlphaExactTarget calls[] =
        {
            { 0x00ACEDE0u, "network-label-selector" },
            { 0x00ACEF20u, "frontend-mode-check" },
            { kSetScreenRva, "SetScreen" },
        };

        ScanPrintf(log, "[ALPHA-SCAN] Phase 7/7: exact online-control global/caller xrefs...\n");
        constexpr std::size_t kChunkSize = 1024u * 1024u;
        std::vector<unsigned char> buffer(kChunkSize);
        std::unordered_set<std::uintptr_t> seen;
        std::size_t found = 0;

        std::uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;
            const std::uintptr_t regionStart = std::max(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const std::uintptr_t rawRegionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const std::uintptr_t regionEnd = std::min(imageEnd, rawRegionEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect) && IsExecutableProtection(mbi.Protect))
            {
                std::uintptr_t block = regionStart;
                while (block < regionEnd)
                {
                    const std::size_t wanted = static_cast<std::size_t>(
                        std::min<std::uintptr_t>(kChunkSize, regionEnd - block));
                    std::size_t got = 0;
                    if (ReadMemoryBlock(block, buffer.data(), wanted, got))
                    {
                        for (std::size_t i = 0; i + 6 <= got; ++i)
                        {
                            const std::uintptr_t at = block + i;
                            if (buffer[i] == 0xE8 && i + 5 <= got)
                            {
                                std::int32_t disp = 0;
                                std::memcpy(&disp, buffer.data() + i + 1, sizeof(disp));
                                const std::uintptr_t target = static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(at + 5) + static_cast<std::intptr_t>(disp));
                                for (const auto& call : calls)
                                {
                                    if (target == imageStart + call.rva && seen.insert(at).second)
                                    {
                                        ++found;
                                        if (call.rva == kSetScreenRva)
                                        {
                                            // Common x64 call form used by the Alpha:
                                            //   mov ecx, <screen-id> ; call SetScreen
                                            // Record the immediate screen ID when it is directly
                                            // visible, otherwise keep the callsite/code window so
                                            // the remaining dynamic argument can be traced later.
                                            bool hasImmediateScreen = false;
                                            std::uint32_t screenId = 0;
                                            if (i >= 5 && buffer[i - 5] == 0xB9)
                                            {
                                                std::memcpy(&screenId, buffer.data() + i - 4, sizeof(screenId));
                                                hasImmediateScreen = true;
                                            }
                                            else if (i >= 2 && buffer[i - 2] == 0x33 && buffer[i - 1] == 0xC9)
                                            {
                                                screenId = 0;
                                                hasImmediateScreen = true;
                                            }

                                            if (hasImmediateScreen)
                                            {
                                                ScanPrintf(log,
                                                    "[ALPHA-SCAN] SETSCREEN-CALL codeRVA=+0x%llX screen=%u (0x%X) targetRVA=+0x%llX\n",
                                                    static_cast<unsigned long long>(at - imageStart),
                                                    screenId, screenId,
                                                    static_cast<unsigned long long>(call.rva));
                                            }
                                            else
                                            {
                                                ScanPrintf(log,
                                                    "[ALPHA-SCAN] SETSCREEN-CALL codeRVA=+0x%llX screen=dynamic targetRVA=+0x%llX\n",
                                                    static_cast<unsigned long long>(at - imageStart),
                                                    static_cast<unsigned long long>(call.rva));
                                            }
                                        }
                                        else
                                        {
                                            ScanPrintf(log,
                                                "[ALPHA-SCAN] CALL-XREF %s codeRVA=+0x%llX targetRVA=+0x%llX\n",
                                                call.label,
                                                static_cast<unsigned long long>(at - imageStart),
                                                static_cast<unsigned long long>(call.rva));
                                        }
                                        LogPriorityCodeWindow(log, imageStart, at, call.label);
                                    }
                                }
                            }

                            std::size_t instructionLength = 0;
                            std::size_t displacementOffset = 0;
                            if (!DecodeRipRelativeReference(buffer.data() + i, got - i,
                                    instructionLength, displacementOffset) ||
                                i + instructionLength > got)
                                continue;

                            std::int32_t disp = 0;
                            std::memcpy(&disp, buffer.data() + i + displacementOffset, sizeof(disp));
                            const std::uintptr_t target = static_cast<std::uintptr_t>(
                                static_cast<std::intptr_t>(at + instructionLength) + static_cast<std::intptr_t>(disp));
                            for (const auto& item : targets)
                            {
                                if (target != imageStart + item.rva || !seen.insert(at).second)
                                    continue;
                                ++found;
                                ScanPrintf(log,
                                    "[ALPHA-SCAN] GLOBAL-XREF %s codeRVA=+0x%llX targetRVA=+0x%llX\n",
                                    item.label,
                                    static_cast<unsigned long long>(at - imageStart),
                                    static_cast<unsigned long long>(item.rva));
                                LogPriorityCodeWindow(log, imageStart, at, item.label);
                            }
                        }
                    }
                    block += wanted ? wanted : 0x1000u;
                }
            }
            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        ScanPrintf(log, "[ALPHA-SCAN] exact online-control xrefs complete=%zu\n", found);
        return found;
    }

    DWORD WINAPI AlphaDiscoveryScanThread(void*)
    {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        EnsureAlphaLogDirectories();

        FILE* log = nullptr;
        const std::string scannerLogPath = storage_paths::PathA("logs\\scanner\\alpha_memory_scanner.log");
        (void)fopen_s(&log, scannerLogPath.c_str(), "wb");
        ScanPrintf(log, "[ALPHA-SCAN] read-only discovery started: FULL PROCESS MEMORY + QR TRIGGER + FRONTEND + NAME/IDENTITY + ONLINE\n");

        std::uintptr_t imageStart = 0;
        std::uintptr_t imageEnd = 0;
        if (!GetAlphaImageRange(imageStart, imageEnd))
        {
            ScanPrintf(log, "[ALPHA-SCAN] FAILED: could not resolve mapped COD2020 image range\n");
            if (log) std::fclose(log);
            g_scanRunning.store(false);
            return 0;
        }

        ScanPrintf(log, "[ALPHA-SCAN] image=0x%llX..0x%llX size=0x%llX\n",
            static_cast<unsigned long long>(imageStart),
            static_cast<unsigned long long>(imageEnd),
            static_cast<unsigned long long>(imageEnd - imageStart));

        const std::size_t qrUiXrefs =
            ScanQrUiAssetReferences(log, imageStart, imageEnd);
        const std::size_t qrStateMapHits =
            ScanCrossplayStateMachineMap(log, imageStart, imageEnd);
        const std::size_t qrState5UniqueCalls =
            ScanState5UniqueCalls(log, imageStart, imageEnd);
        const std::size_t qrUiRvaRefs =
            ScanAccountUiRvaReferences(log, imageStart, imageEnd);
        const std::size_t qrLiveState5Objects =
            ScanLiveCrossplayState5Objects(log);
        const std::size_t qrWatchCandidates =
            ScanQrPopupTriggerCandidates(log, imageStart, imageEnd);
        const std::size_t fastSetScreenXrefs =
            ScanSetScreenCallsFast(log, imageStart, imageEnd);
        const AlphaNameScanStats nameStats =
            ScanAlphaNameCandidates(log, imageStart, imageEnd);

        ScanPrintf(log, "[ALPHA-SCAN] exhaustive whole-process memory pass starting...\n");
        const FullMemoryScanStats fullMemoryStats =
            RunFullProcessMemoryDiscovery();

        std::vector<AlphaScanCandidate> candidates;
        ScanAlphaStrings(log, imageStart, imageEnd, candidates);
        const std::size_t xrefs = ScanAlphaXrefs(log, imageStart, imageEnd, candidates);
        const auto priorityPointers = ScanPriorityPointerSlots(log, imageStart, imageEnd, candidates);
        const std::size_t indirectXrefs = ScanPriorityPointerXrefs(
            log, imageStart, imageEnd, priorityPointers);
        const std::size_t priorityTableDumps = DumpPriorityPointerNeighborhoods(
            log, imageStart, imageEnd, priorityPointers, candidates);
        const std::size_t targetedTraces = TraceKnownAlphaAnchors(
            log, imageStart, imageEnd, candidates);
        const std::size_t exactControlXrefs = ScanExactAlphaControlReferences(
            log, imageStart, imageEnd);

        std::size_t onlineCount = 0;
        std::size_t menuCount = 0;
        std::size_t qrCount = 0;
        for (const auto& candidate : candidates)
        {
            if (candidate.online) ++onlineCount;
            if (candidate.menu) ++menuCount;
            if (candidate.qr) ++qrCount;
        }
        ScanPrintf(log,
            "[ALPHA-SCAN] COMPLETE onlineStrings=%zu onlineMenuStrings=%zu qrStrings=%zu qrUiXrefs=%zu qrStateMapHits=%zu qrState5UniqueCalls=%zu qrUiRvaRefs=%zu qrLiveState5Objects=%zu qrWatchCandidates=%zu directXrefs=%zu priorityPtrs=%zu indirectXrefs=%zu tableDumps=%zu targetedTraces=%zu fastScreenRefs=%zu nameMatches=%zu writableNameMatches=%zu nameLabels=%zu nameXrefs=%zu fullReadMB=%llu fullPages=%zu fullStrings=%zu exactControlXrefs=%zu log=logs\\scanner\\alpha_memory_scanner.log\n",
            onlineCount, menuCount, qrCount, qrUiXrefs, qrStateMapHits, qrState5UniqueCalls, qrUiRvaRefs, qrLiveState5Objects, qrWatchCandidates, xrefs, priorityPointers.size(), indirectXrefs, priorityTableDumps, targetedTraces, fastSetScreenXrefs,
            nameStats.runtimeMatches, nameStats.writableRuntimeMatches, nameStats.identityLabels, nameStats.identityXrefs,
            static_cast<unsigned long long>(fullMemoryStats.bytesRead / (1024ull * 1024ull)),
            fullMemoryStats.pages, fullMemoryStats.asciiStrings + fullMemoryStats.utf16Strings,
            exactControlXrefs);
        if (log) std::fclose(log);
        g_scanCompleted.store(true);
        g_scanRunning.store(false);
        return 0;
    }

    void StartAlphaDiscoveryScanAsync()
    {
        bool expected = false;
        if (!g_scanRunning.compare_exchange_strong(expected, true))
        {
            std::printf("[ALPHA-SCAN] scan already running\n");
            return;
        }

        g_scanCompleted.store(false);
        HANDLE thread = CreateThread(nullptr, 0, &AlphaDiscoveryScanThread, nullptr, 0, nullptr);
        if (!thread)
        {
            g_scanRunning.store(false);
            std::printf("[ALPHA-SCAN] failed to create scanner thread (%lu)\n",
                static_cast<unsigned long>(GetLastError()));
            return;
        }
        CloseHandle(thread);
    }

    bool RisingEdge(int vk, bool& wasDown)
    {
        const bool down = (GetAsyncKeyState(vk) & 0x8000) != 0;
        const bool edge = down && !wasDown;
        wasDown = down;
        return edge;
    }

    std::uint32_t GetNetworkSelector(std::uint32_t value)
    {
        return (value & kNetworkSelectorMask) >> kNetworkSelectorShift;
    }

    const char* DescribeNetworkSelector(std::uint32_t selector)
    {
        switch (selector)
        {
        case kNetworkSelectorOffline: return "Offline";
        case kNetworkSelectorSystemLink: return "System_link";
        case kNetworkSelectorOnline: return "Online";
        default: return "Invalid";
        }
    }

    std::uint32_t GetSessionConnectivity(std::uint32_t value)
    {
        return (value & kSessionConnectivityMask) >> kSessionConnectivityShift;
    }

    const char* DescribeSessionConnectivity(std::uint32_t value)
    {
        switch (value)
        {
        case kSessionConnectivityOffline: return "Offline";
        case kSessionConnectivityOnline: return "Online";
        default: return "Other";
        }
    }

    const char* DescribeFrontendSessionState(std::uint32_t value)
    {
        switch (value)
        {
        case 8225u: return "online_mp";
        case 8224u: return "online_zm";
        case 4129u: return "online_mp_customs";
        case 33u: return "league_play";
        case 8193u: return "offline_mp";
        case 8192u: return "offline_zm";
        case 0x40C0u: return "zombies_menu";
        default: return "unknown";
        }
    }

    void PromptForDiscoveredCustomName()
    {
        const std::uintptr_t base =
            g_nameClusterBase.load(std::memory_order_acquire);
        const std::uint32_t count =
            g_nameClusterCount.load(std::memory_order_acquire);

        if (!base || count < 4)
        {
            std::printf("[ALPHA-NAME] no high-confidence name cluster yet; wait for '[ALPHA-NAME] FAST CLUSTER' then press F8\n");
            return;
        }

        std::printf("[ALPHA-NAME] custom name (1-7 chars): ");
        std::fflush(stdout);

        char input[64]{};
        if (!std::fgets(input, static_cast<int>(sizeof(input)), stdin))
            return;

        input[std::strcspn(input, "\r\n")] = '\0';
        const std::size_t length = std::strlen(input);
        if (length == 0 || length > 7)
        {
            std::printf("[ALPHA-NAME] rejected: discovered field is 8 bytes, max visible name is 7 chars\n");
            return;
        }

        char field[8]{};
        std::memcpy(field, input, length);

        constexpr std::uintptr_t kPlayerRecordStride = 0x48u;
        std::uint32_t written = 0;
        for (std::uint32_t i = 0; i < count; ++i)
        {
            const std::uintptr_t address =
                base + static_cast<std::uintptr_t>(i) * kPlayerRecordStride;
            if (WriteBytes(address, field, sizeof(field)))
                ++written;
        }

        std::string saveMessage;
        const bool saved = client_identity::SaveNameForGame(
            games::GameKind::Alpha, input, saveMessage);

        std::printf("[ALPHA-NAME] wrote \"%s\" to %u/%u discovered player-name slots; t9.ini %s (%s)\n",
            input, written, count, saved ? "saved" : "save failed", saveMessage.c_str());
    }

    DWORD WINAPI HotkeyThread(void*)
    {
        if (!Resolve())
        {
            std::printf("[ALPHA] helper compatibility initialization FAILED\n");
            return 0;
        }

        std::printf("[ALPHA] integrating for_mp_sp + for_zombies + Gombies + InjectToFixBuild behavior\n");
        std::printf("[ALPHA] waiting for live session object used by the original PLAY path...\n");

        // version.dll loads earlier than the original injected helpers. Keep
        // applying the recovered one-shot Gombies session defaults when the live
        // object appears, but reproduce the user-confirmed F1 timing separately:
        // exactly 40 seconds after this helper starts, call the same F1 routine once.
        std::uintptr_t lastSessionObject = 0;
        std::uintptr_t initialSessionObject = 0;
        bool defaultsAppliedOnce = false;
        bool stockLaunchPhase = false;
        std::uint32_t lastField98 = 0xFFFFFFFFu;
        std::uint32_t lastFrontendSessionState = 0xFFFFFFFFu;
        std::uint32_t lastMpFrontendState = 0xFFFFFFFFu;
        int lastLiveScreen = -0x7FFFFFFF;
        std::uintptr_t lastCrossplayObject = 0;
        std::uint32_t lastCrossplayState = 0xFFFFFFFFu;
        ULONGLONG sessionReadySince = 0;
        const ULONGLONG autoStartTick = GetTickCount64();
        constexpr ULONGLONG kAutoF1DelayMs = 40000ull;
        constexpr ULONGLONG kQrProbeStabilizeMs = 3000ull;
        bool autoF1Attempted = false;
        bool automaticScanStarted = false;
        bool qrProbeAttempted = false;

        std::printf("[ALPHA-WATCH] watching recovered session state at +0x%llX (diagnostic only; no automatic rewrite)\n",
            static_cast<unsigned long long>(kFrontendSessionStateRva));

        bool f1WasDown = false;
        bool f2WasDown = false;
        bool f3WasDown = false;
        bool f4WasDown = false;
        bool f5WasDown = false;
        bool f6WasDown = false;
        bool homeWasDown = false;
        bool num0WasDown = false;
        bool num2WasDown = false;
        bool num4WasDown = false;
        bool f7WasDown = false;
        bool f8WasDown = false;
        bool f9WasDown = false;
        bool f10WasDown = false;
        bool f11WasDown = false;
        bool endWasDown = false;
        bool pageUpWasDown = false;
        bool pageDownWasDown = false;
        bool leftWasDown = false;
        bool rightWasDown = false;
        bool num1WasDown = false;

        for (;;)
        {
            const ULONGLONG nowTick = GetTickCount64();

            // Win11 first, QR tracing second. The direct state-5 capture modifies
            // one instruction byte temporarily, so never arm it until the
            // recovered Win11 redirect is complete and the process has had a
            // quiet stabilization window.
            if (!qrProbeAttempted &&
                patches::win11::HasApplied() &&
                (nowTick - autoStartTick) >= kQrProbeStabilizeMs)
            {
                qrProbeAttempted = true;
                (void)InstallQrState5CaptureProbe();
            }

            int liveScreen = 0;
            if (SafeGetScreen(liveScreen) && liveScreen != lastLiveScreen)
            {
                lastLiveScreen = liveScreen;

                std::uint32_t packedSession = 0;
                std::uint32_t mpFrontend = 0xFFFFFFFFu;
                (void)ReadFrontendSessionStateInternal(packedSession);
                (void)ReadValue(g_base + kMpFrontendStateRva, mpFrontend);

                AlphaStatePrintf(
                    "[ALPHA-SCREEN] current screen changed: %d (0x%X) packed=0x%X [%s] mpFrontend=0x%X\n",
                    liveScreen,
                    static_cast<unsigned int>(liveScreen),
                    packedSession,
                    DescribeFrontendSessionState(packedSession),
                    mpFrontend);
            }

            const std::uintptr_t crossplayObject =
                g_crossplayStateObject.load(std::memory_order_acquire);
            if (crossplayObject)
            {
                if (g_qrState5ProbeCaptured.exchange(false, std::memory_order_acq_rel))
                {
                    AlphaStatePrintf(
                        "[ALPHA-QRSTATE] EXECUTION-CAPTURE object=0x%llX from RSI at state-5 write +0x%llX\n",
                        static_cast<unsigned long long>(crossplayObject),
                        static_cast<unsigned long long>(kQrState5ObjectWriteRva));
                }

                std::uint32_t crossplayState = 0;
                if (ReadValue(crossplayObject + 0x1Cu, crossplayState))
                {
                    if (crossplayObject != lastCrossplayObject ||
                        crossplayState != lastCrossplayState)
                    {
                        lastCrossplayObject = crossplayObject;
                        lastCrossplayState = crossplayState;

                        AlphaStatePrintf(
                            "[ALPHA-QRSTATE] LIVE object=0x%llX state=%u (0x%X)\n",
                            static_cast<unsigned long long>(crossplayObject),
                            crossplayState,
                            crossplayState);
                    }
                }
            }

            const std::uintptr_t sessionObject = GetSessionObject(0);
            if (sessionObject && sessionObject != lastSessionObject)
            {
                const std::uintptr_t previousSessionObject = lastSessionObject;
                lastSessionObject = sessionObject;
                lastField98 = 0xFFFFFFFFu;

                if (!initialSessionObject)
                {
                    initialSessionObject = sessionObject;
                    sessionReadySince = nowTick;
                }

                // Gombies writes these three recovered fields once on the initial
                // frontend session object. It does not follow later session-object
                // replacements and rewrite the fields during stock map launch.
                // Doing that here was our main behavioral difference from the
                // original helper and could corrupt a newly-created match session.
                if (!defaultsAppliedOnce)
                {
                    defaultsAppliedOnce = ApplyOriginalSessionDefaultsInternal(true);
                    if (defaultsAppliedOnce)
                    {
                        AlphaStatePrintf(
                            "[ALPHA-PLAY] original one-shot session defaults armed object=0x%llX\n",
                            static_cast<unsigned long long>(sessionObject));
                    }
                }
                else if (previousSessionObject && sessionObject != initialSessionObject &&
                         g_autoFrontendApplied.load())
                {
                    if (!stockLaunchPhase)
                    {
                        stockLaunchPhase = true;
                        AlphaStatePrintf(
                            "[ALPHA-PLAY] session object changed 0x%llX -> 0x%llX; stock launch phase detected, automatic session WRITES paused\n",
                            static_cast<unsigned long long>(previousSessionObject),
                            static_cast<unsigned long long>(sessionObject));
                    }
                }
            }
            else if (sessionObject && !defaultsAppliedOnce)
            {
                defaultsAppliedOnce = ApplyOriginalSessionDefaultsInternal(false);
                if (!sessionReadySince) sessionReadySince = nowTick;
            }
            else if (!sessionObject)
            {
                sessionReadySince = 0;
            }

            if (sessionObject)
            {
                std::uint32_t currentField98 = 0;
                if (ReadValue(sessionObject + kSessionIntOffset, currentField98) &&
                    currentField98 != lastField98)
                {
                    AlphaStatePrintf("[ALPHA-WATCH] sessionObject+0x98 changed: %u (0x%X)\n",
                        currentField98, currentField98);
                    lastField98 = currentField98;
                }

                if (InterlockedCompareExchange(&g_keepOriginalSessionFields, 0, 0) != 0)
                    (void)ApplyOriginalSessionDefaultsInternal(false);
            }

            // InjectToFixBuild's F2 "sessionInt" is COD2020+0x65259E4, not
            // sessionObject+0x98. Keep watching it for diagnostics, but do NOT
            // rewrite it automatically. The user-confirmed working path was a
            // manual F1 press during Connecting to Online Services, so the auto
            // path below does exactly that same F1 action once after 40 seconds.
            std::uint32_t frontendSessionState = 0;
            if (ReadFrontendSessionStateInternal(frontendSessionState) &&
                frontendSessionState != lastFrontendSessionState)
            {
                const std::uint32_t selector = GetNetworkSelector(frontendSessionState);
                const std::uint32_t connectivity = GetSessionConnectivity(frontendSessionState);
                AlphaStatePrintf("[ALPHA-WATCH] +0x%llX changed: %u (0x%X) [%s] selector=%u(%s) session=%u(%s)\n",
                    static_cast<unsigned long long>(kFrontendSessionStateRva),
                    frontendSessionState, frontendSessionState,
                    DescribeFrontendSessionState(frontendSessionState),
                    selector, DescribeNetworkSelector(selector),
                    connectivity, DescribeSessionConnectivity(connectivity));
                lastFrontendSessionState = frontendSessionState;
            }

            std::uint32_t mpFrontendState = 0;
            if (ReadValue(g_base + kMpFrontendStateRva, mpFrontendState) &&
                mpFrontendState != lastMpFrontendState)
            {
                AlphaStatePrintf("[ALPHA-WATCH] MP frontend +0x%llX changed: %u (0x%X)\n",
                    static_cast<unsigned long long>(kMpFrontendStateRva),
                    mpFrontendState, mpFrontendState);
                lastMpFrontendState = mpFrontendState;
            }

            // Automatic F1 replacement: one attempt at 40 seconds. A successful
            // manual F1 before then cancels the automatic attempt. The scanner is
            // started only after this transition so its full-image walk cannot
            // compete with the fragile frontend switch.
            if (!autoF1Attempted && !g_autoFrontendApplied.load() &&
                (nowTick - autoStartTick) >= kAutoF1DelayMs)
            {
                autoF1Attempted = true;
                stockLaunchPhase = false;
                initialSessionObject = sessionObject;
                if (ActivateMpSp())
                    g_autoFrontendApplied.store(true);

                if (!automaticScanStarted)
                {
                    automaticScanStarted = true;
                    StartAlphaDiscoveryScanAsync();
                }
            }

            // Original Gombies debug navigation controls.  They are kept as
            // optional diagnostics and never run unless the key is pressed.
            if (RisingEdge(VK_PRIOR, pageUpWasDown))
            {
                const LONG value = InterlockedIncrement(&g_screenIndex);
                std::printf("[ALPHA-SCREEN] index=%ld\n", static_cast<long>(value));
            }
            if (RisingEdge(VK_NEXT, pageDownWasDown))
            {
                const LONG value = InterlockedDecrement(&g_screenIndex);
                std::printf("[ALPHA-SCREEN] index=%ld\n", static_cast<long>(value));
            }
            if (RisingEdge(VK_LEFT, leftWasDown))
            {
                const LONG value = InterlockedDecrement(&g_auxDebugIndex);
                std::printf("[ALPHA-DEBUG] aux=%ld\n", static_cast<long>(value));
            }
            if (RisingEdge(VK_RIGHT, rightWasDown))
            {
                const LONG value = InterlockedIncrement(&g_auxDebugIndex);
                std::printf("[ALPHA-DEBUG] aux=%ld\n", static_cast<long>(value));
            }
            if (RisingEdge(VK_NUMPAD1, num1WasDown))
            {
                std::printf("[ALPHA-SCREEN] manual SetScreen disabled in trace build\n");
            }

            if (RisingEdge(VK_F1, f1WasDown))
            {
                // The recovered F1 sequence is a one-shot frontend transition.
                // Replaying SetScreen/ParseKeys/disconnect after it has already
                // succeeded can destabilize the Alpha, so later F1 presses do
                // nothing instead of replaying the sequence.
                if (!autoF1Attempted && !g_autoFrontendApplied.load() && !stockLaunchPhase)
                {
                    autoF1Attempted = true;
                    stockLaunchPhase = false;
                    initialSessionObject = sessionObject;
                    if (ActivateMpSp())
                        g_autoFrontendApplied.store(true);

                    if (!automaticScanStarted)
                    {
                        automaticScanStarted = true;
                        StartAlphaDiscoveryScanAsync();
                    }
                }
            }
            if (RisingEdge(VK_F2, f2WasDown))
            {
                stockLaunchPhase = false;
                initialSessionObject = sessionObject;
                (void)ActivateZombies();
            }
            if (RisingEdge(VK_END, endWasDown))
            {
                stockLaunchPhase = false;
                initialSessionObject = sessionObject;
                (void)ActivateZombies();
            }
            if (RisingEdge(VK_F3, f3WasDown)) PromptForSessionInt();
            if (RisingEdge(VK_F4, f4WasDown))
            {
                std::printf("[ALPHA-SESSION] enter sessionObject+0x98 value: ");
                std::fflush(stdout);
                char buffer[64]{};
                if (std::fgets(buffer, static_cast<int>(sizeof(buffer)), stdin))
                {
                    char* end = nullptr;
                    const unsigned long value = std::strtoul(buffer, &end, 0);
                    if (end != buffer) (void)SetSessionObjectField98Internal(static_cast<std::uint32_t>(value));
                }
            }
            if (RisingEdge(VK_F5, f5WasDown))
            {
                std::printf("[ALPHA-SCREEN] F5 disabled until scanner identifies game-used screen IDs\n");
            }
            if (RisingEdge(VK_F6, f6WasDown)) StartAlphaDiscoveryScanAsync();
            if (RisingEdge(VK_HOME, homeWasDown)) PromptForMapName();
            if (RisingEdge(VK_NUMPAD2, num2WasDown)) (void)LaunchLobbyGame();
            if (RisingEdge(VK_NUMPAD4, num4WasDown)) PromptForCommand();
            if (RisingEdge(VK_F7, f7WasDown)) (void)FastRestartMap();
            if (RisingEdge(VK_F8, f8WasDown)) PromptForDiscoveredCustomName();
            if (RisingEdge(VK_F9, f9WasDown))
            {
                const bool ok = DisconnectToFrontend();
                std::printf("[ALPHA] disconnect %s\n", ok ? "SENT" : "FAILED");
            }
            if (RisingEdge(VK_F10, f10WasDown))
            {
                CaptureOrDiffAllWritableMemory();
                CaptureOrDiffQrState();
            }
            if (RisingEdge(VK_F11, f11WasDown))
            {
                StartFullProcessMemoryDiscoveryAsync();
            }
            if (RisingEdge(VK_NUMPAD0, num0WasDown))
            {
                const LONG now = InterlockedCompareExchange(&g_keepOriginalSessionFields, 0, 0);
                InterlockedExchange(&g_keepOriginalSessionFields, now ? 0 : 1);
                std::printf("[ALPHA-PLAY] continuous original-session-field enforcement %s\n",
                    now ? "OFF" : "ON");
            }

            Sleep(15);
        }
    }
}

namespace alpha_support
{
    bool IsSupported()
    {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return false;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            return nt->Signature == IMAGE_NT_SIGNATURE &&
                   nt->FileHeader.TimeDateStamp == 0x5F1B8329u &&
                   nt->OptionalHeader.SizeOfImage == 0x10C4A200u &&
                   nt->OptionalHeader.AddressOfEntryPoint == 0x02128E60u;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    bool EnterFrontend()
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return ActivateMpSp();
    }

    bool SwitchZombies()
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return ActivateZombies();
    }

    bool RestoreMultiplayer()
    {
        return EnterFrontend();
    }

    bool Disconnect()
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        if (!BeginModeSwitch()) return false;
        const bool ok = DisconnectToFrontend();
        EndModeSwitch();
        return ok;
    }

    bool ApplyOriginalSessionDefaults()
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return ApplyOriginalSessionDefaultsInternal(true);
    }

    bool SetSessionMode(SessionMode mode)
    {
        return SetSessionInt(static_cast<std::uint32_t>(mode));
    }

    bool SetSessionInt(std::uint32_t value)
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return SetFrontendSessionStateInternal(value);
    }

    bool ReadSessionInt(std::uint32_t& value)
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return ReadFrontendSessionStateInternal(value);
    }

    bool SetSessionObjectField98(std::uint32_t value)
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return SetSessionObjectField98Internal(value);
    }

    bool ReadSessionObjectField98(std::uint32_t& value)
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return ReadSessionObjectField98Internal(value);
    }

    bool SetMapName(const char* mapName)
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return SetMapNameFromOriginalHelper(mapName);
    }

    bool LaunchGame()
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return LaunchLobbyGame();
    }

    bool FastRestart()
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return FastRestartMap();
    }

    bool SendCommand(const char* command)
    {
        if (!IsSupported()) return false;
        if (!g_base && !Resolve()) return false;
        return SafeCbuf(command);
    }

    void Initialize()
    {
        if (g_started.exchange(true)) return;
        if (!IsSupported())
        {
            g_started.store(false);
            return;
        }

        HANDLE thread = CreateThread(nullptr, 0, &HotkeyThread, nullptr, 0, nullptr);
        if (!thread)
        {
            std::printf("[ALPHA] failed to create helper worker (%lu)\n",
                static_cast<unsigned long>(GetLastError()));
            g_started.store(false);
            return;
        }
        CloseHandle(thread);
    }
}
