#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace t8_mp_beta
{
    namespace
    {
        constexpr std::uint32_t kTimestamp = 0x5B6CB2BBu;
        constexpr std::uint32_t kImageSize = 0x105D1C00u;
        constexpr std::uint32_t kEntryRva  = 0x01C97AD0u;
        constexpr std::uintptr_t kPreferredBase = 0x140000000ull;

        // Recovered directly from the original beta unlocker's version
        // guard: preferred VA 0x141F004D8 -> runtime RVA 0x01F004D8.
        constexpr std::uintptr_t kBuildMarkerRva = 0x01F004D8ull;
        constexpr std::uint32_t kExpectedBuildMarker = 0x002EB289u; // 3,060,361

        constexpr char kProfileSha256[] =
            "db0a85191f73ea84ab33ee744c2043e4ac5f5c6f1b827d33d29923b65bbacb76";
        constexpr char kUnlockerSha256[] =
            "9752fb5a6a11aa5c914d762920e7092dbc4f632d5eae6b3bd21f8f375d2f5210";

        std::atomic_bool g_started{ false };
        PVOID g_crashVeh = nullptr;

        using ExitProcessFn = VOID (WINAPI*)(UINT);
        using TerminateProcessFn = BOOL (WINAPI*)(HANDLE, UINT);
        using RtlExitUserProcessFn = VOID (NTAPI*)(LONG);
        using NtTerminateProcessFn = LONG (NTAPI*)(HANDLE, LONG);

        void* g_originalExitProcess = nullptr;
        void* g_originalTerminateProcess = nullptr;
        void* g_originalRtlExitUserProcess = nullptr;
        void* g_originalNtTerminateProcess = nullptr;

        struct UnlockerRef
        {
            std::uintptr_t preferredVa;
            const char* category;
            const char* recoveredAction;
        };

        // All non-base absolute BlackOps4 references recovered from the original
        // beta unlocker. v1 is read-only: these are audited, never written.
        constexpr UnlockerRef kUnlockerRefs[] = {
            {0x1410BD110ull, "unknown", "original unlocker reference"},
            {0x140FB9C60ull, "unknown", "original unlocker reference"},
            {0x1412D0900ull, "unknown", "original unlocker reference"},
            {0x140F8C9A0ull, "unknown", "original unlocker reference"},
            {0x140800470ull, "unknown", "original unlocker reference"},
            {0x141225140ull, "unknown", "original unlocker reference"},
            {0x141224C10ull, "unknown", "original unlocker reference"},
            {0x141226890ull, "unknown", "original unlocker reference"},
            {0x1412267F0ull, "unknown", "original unlocker reference"},
            {0x141226750ull, "unknown", "original unlocker reference"},
            {0x141226840ull, "unknown", "original unlocker reference"},
            {0x14081AC00ull, "unknown", "original unlocker reference"},
            {0x14DDEFB58ull, "protected_or_dynamic", "original unlocker reference outside PE image"},
            {0x14112A200ull, "unknown", "original unlocker reference"},
            {0x143063440ull, "protected_or_dynamic", "original unlocker reference outside PE image"},
            {0x14CF797C4ull, "protected_or_dynamic", "original unlocker reference outside PE image"},
            {0x147A3F4DCull, "protected_or_dynamic", "original unlocker reference outside PE image"},
            {0x14116F840ull, "unknown", "original unlocker reference"},
            {0x1412D66E0ull, "unknown", "original unlocker reference"},
            {0x1416E1869ull, "patch_site", "write 00 (recovered from unlocker)"},
            {0x1416E1855ull, "patch_site", "write AF (recovered from unlocker)"},
            {0x141F61EE4ull, "patch_site", "write 00 (recovered from unlocker)"},
            {0x141F61198ull, "patch_site", "copy 0x23 bytes (payload not enabled in v1)"},
            {0x141F617D0ull, "patch_site", "copy 0x23 bytes (payload not enabled in v1)"},
            {0x141F5F4D0ull, "patch_site", "copy 0x13 bytes (payload not enabled in v1)"},
            {0x1406D88B0ull, "patch_site", "write B0 01"},
            {0x1406D88C0ull, "patch_site", "write B0 01 C3 90"},
            {0x1406BDE20ull, "patch_site", "write C3"},
            {0x14109FC44ull, "patch_site", "NOP 13"},
            {0x1416AD170ull, "patch_site", "write B0 01 C3 00"},
            {0x1416C0530ull, "patch_site", "write B0 01 C3 00"},
            {0x14110BDFBull, "patch_site", "NOP 24"},
            {0x14112CDD6ull, "patch_site", "NOP 22"},
            {0x1406D7CC0ull, "detour_site", "original unlocker redirects to local stub"},
            {0x1406D7CD0ull, "detour_site", "original unlocker redirects to local stub"},
            {0x14081498Full, "patch_site", "NOP 6"},
            {0x140BD3260ull, "patch_site", "write EB DE"},
            {0x1407A9742ull, "patch_site", "write C3"},
            {0x140799B84ull, "patch_site", "NOP 5"},
            {0x140842C94ull, "patch_site", "write 45 31 C0 90"},
            {0x1406B6672ull, "patch_site", "NOP 2"},
            {0x1406B6650ull, "patch_site", "write EB"},
            {0x1406D3F20ull, "hook_target", "original unlocker hook -> local wrapper"},
            {0x141AA16C0ull, "hook_target", "original unlocker hook -> local wrapper; then called"},
            {0x141A7A2D0ull, "hook_target", "original unlocker hook -> local wrapper"},
            {0x1408142E8ull, "patch_site", "NOP 6"},
            {0x140AE0F0Cull, "patch_site", "write 00"},
            {0x140AE1188ull, "patch_site", "write 00"},
            {0x147EE2E44ull, "protected_or_dynamic", "write 00 outside PE image"},
            {0x140814ED0ull, "unknown", "original unlocker reference"},
            {0x140FBACD0ull, "unknown", "original unlocker reference"},
            {0x141F004D8ull, "build_marker", "must equal 0x002EB289 (3060361)"},
        };

        constexpr std::string_view kTerms[] = {
            "byzantium",
            "connected to live",
            "user has multiplayer privs",
            "connected to demonware",
            "bnet initialized",
            "demonware",
            "battle.net",
            "bnet",
            "offline",
            "multiplayer",
            "lobby",
            "auth",
            "signin",
            "signed in",
            "disconnect",
            "frontend",
            "fence",
        };

        std::uintptr_t Base()
        {
            return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        }

        bool ReadBytes(std::uintptr_t address, void* out, std::size_t size);
        bool ReadU32(std::uintptr_t address, std::uint32_t& value);
        std::string HexBytes(std::uintptr_t address, std::size_t count);

        bool IsProcessName(const wchar_t* wanted)
        {
            wchar_t path[MAX_PATH]{};
            const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
            if (!length || length >= MAX_PATH)
                return false;

            const wchar_t* base = path;
            for (DWORD i = 0; i < length; ++i)
                if (path[i] == L'\\' || path[i] == L'/')
                    base = path + i + 1;
            return lstrcmpiW(base, wanted) == 0;
        }

        bool ReadPeFingerprint(std::uint32_t& timestamp, std::uint32_t& imageSize, std::uint32_t& entryRva)
        {
            const auto base = Base();
            if (!base)
                return false;

            __try
            {
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                    return false;
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                    base + static_cast<std::uintptr_t>(dos->e_lfanew));
                if (nt->Signature != IMAGE_NT_SIGNATURE)
                    return false;

                timestamp = nt->FileHeader.TimeDateStamp;
                imageSize = nt->OptionalHeader.SizeOfImage;
                entryRva = nt->OptionalHeader.AddressOfEntryPoint;
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        void EnsureLogDirectory()
        {
            std::error_code ec;
            fs::create_directories("logs\\t8_mp_beta", ec);
        }

        void LogTermination(const char* api, unsigned long long status, HANDLE process = nullptr)
        {
            EnsureLogDirectory();
            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_mp_beta\\termination.log", "a") != 0 || !f)
                return;

            const auto base = Base();
            const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
            const bool selfTarget = !process || process == GetCurrentProcess() ||
                process == reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1));
            void* frames[12]{};
            const USHORT frameCount = CaptureStackBackTrace(1, 12, frames, nullptr);

            std::fprintf(f, "api=%s status=0x%llX pid=%lu tid=%lu caller_rva=0x%llX self_target=%d\n",
                api ? api : "unknown", status, GetCurrentProcessId(), GetCurrentThreadId(),
                static_cast<unsigned long long>(caller >= base ? caller - base : 0), selfTarget ? 1 : 0);
            std::fprintf(f, "stack_rvas=");
            for (USHORT i = 0; i < frameCount; ++i)
            {
                const auto a = reinterpret_cast<std::uintptr_t>(frames[i]);
                if (i) std::fprintf(f, ";");
                if (a >= base && a < base + kImageSize)
                    std::fprintf(f, "0x%llX", static_cast<unsigned long long>(a - base));
                else
                    std::fprintf(f, "abs:%p", frames[i]);
            }
            std::fprintf(f, "\n");
            std::fflush(f);
            std::fclose(f);
        }

        VOID WINAPI HookExitProcess(UINT code)
        {
            LogTermination("ExitProcess", code);
            if (g_originalExitProcess)
                reinterpret_cast<ExitProcessFn>(g_originalExitProcess)(code);
            for (;;) Sleep(INFINITE);
        }

        BOOL WINAPI HookTerminateProcess(HANDLE process, UINT code)
        {
            LogTermination("TerminateProcess", code, process);
            return g_originalTerminateProcess
                ? reinterpret_cast<TerminateProcessFn>(g_originalTerminateProcess)(process, code) : FALSE;
        }

        VOID NTAPI HookRtlExitUserProcess(LONG status)
        {
            LogTermination("RtlExitUserProcess", static_cast<unsigned long long>(static_cast<unsigned long>(status)));
            if (g_originalRtlExitUserProcess)
                reinterpret_cast<RtlExitUserProcessFn>(g_originalRtlExitUserProcess)(status);
            for (;;) Sleep(INFINITE);
        }

        LONG NTAPI HookNtTerminateProcess(HANDLE process, LONG status)
        {
            LogTermination("NtTerminateProcess", static_cast<unsigned long long>(static_cast<unsigned long>(status)), process);
            return g_originalNtTerminateProcess
                ? reinterpret_cast<NtTerminateProcessFn>(g_originalNtTerminateProcess)(process, status) : status;
        }

        bool PatchImport(const char* wantedName, void* replacement, void** original)
        {
            const auto base = Base();
            if (!base || !wantedName || !replacement || !original)
                return false;

            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!dir.VirtualAddress || !dir.Size)
                return false;

            auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
            for (std::size_t d = 0; desc->Name && d < 512; ++desc, ++d)
            {
                auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);
                auto* names = desc->OriginalFirstThunk
                    ? reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->OriginalFirstThunk) : nullptr;
                if (!iat || !names)
                    continue;

                for (std::size_t i = 0; names[i].u1.AddressOfData && i < 65536; ++i)
                {
                    if (IMAGE_SNAP_BY_ORDINAL64(names[i].u1.Ordinal))
                        continue;
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names[i].u1.AddressOfData);
                    if (!ibn || std::strcmp(reinterpret_cast<const char*>(ibn->Name), wantedName) != 0)
                        continue;

                    auto** slot = reinterpret_cast<void**>(&iat[i].u1.Function);
                    DWORD oldProtect = 0;
                    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
                        return false;
                    *original = *slot;
                    *slot = replacement;
                    DWORD ignored = 0;
                    VirtualProtect(slot, sizeof(void*), oldProtect, &ignored);
                    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
                    return true;
                }
            }
            return false;
        }

        LONG CALLBACK CrashVeh(EXCEPTION_POINTERS* info)
        {
            if (!info || !info->ExceptionRecord || !info->ContextRecord)
                return EXCEPTION_CONTINUE_SEARCH;

            const DWORD code = info->ExceptionRecord->ExceptionCode;
            if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
                code != EXCEPTION_STACK_OVERFLOW && code != 0xC0000374u && code != 0xC0000409u)
                return EXCEPTION_CONTINUE_SEARCH;

            EnsureLogDirectory();
            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_mp_beta\\crash_exit.log", "a") == 0 && f)
            {
                const auto base = Base();
                const auto address = reinterpret_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionAddress);
                std::fprintf(f, "event=exception code=0x%08lX address=%p rva=0x%llX tid=%lu\n",
                    code, info->ExceptionRecord->ExceptionAddress,
                    static_cast<unsigned long long>(address >= base ? address - base : 0), GetCurrentThreadId());
#ifdef _M_X64
                const auto& c = *info->ContextRecord;
                std::fprintf(f, "RIP=%016llX RSP=%016llX RBP=%016llX RAX=%016llX RBX=%016llX RCX=%016llX RDX=%016llX\n",
                    c.Rip, c.Rsp, c.Rbp, c.Rax, c.Rbx, c.Rcx, c.Rdx);
#endif
                std::fflush(f);
                std::fclose(f);
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }

        void InstallStartupDiagnostics()
        {
            EnsureLogDirectory();
            if (!g_crashVeh)
                g_crashVeh = AddVectoredExceptionHandler(1, &CrashVeh);

            const bool exitProcess = PatchImport("ExitProcess", reinterpret_cast<void*>(&HookExitProcess), &g_originalExitProcess);
            const bool terminateProcess = PatchImport("TerminateProcess", reinterpret_cast<void*>(&HookTerminateProcess), &g_originalTerminateProcess);
            const bool rtlExit = PatchImport("RtlExitUserProcess", reinterpret_cast<void*>(&HookRtlExitUserProcess), &g_originalRtlExitUserProcess);
            const bool ntTerminate = PatchImport("NtTerminateProcess", reinterpret_cast<void*>(&HookNtTerminateProcess), &g_originalNtTerminateProcess);

            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_mp_beta\\termination.log", "a") == 0 && f)
            {
                std::fprintf(f, "diagnostics=armed ExitProcess=%d TerminateProcess=%d RtlExitUserProcess=%d NtTerminateProcess=%d veh=%d\n",
                    exitProcess ? 1 : 0, terminateProcess ? 1 : 0, rtlExit ? 1 : 0, ntTerminate ? 1 : 0, g_crashVeh ? 1 : 0);
                std::fflush(f);
                std::fclose(f);
            }
        }

        bool WriteExactPatch(const char* name, std::uintptr_t rva,
            const unsigned char* expected, std::size_t expectedSize,
            const unsigned char* replacement, std::size_t replacementSize, FILE* log)
        {
            if (!expected || !replacement || !expectedSize || !replacementSize || replacementSize > expectedSize)
                return false;

            auto* address = reinterpret_cast<unsigned char*>(Base() + rva);
            std::array<unsigned char, 16> current{};
            if (expectedSize > current.size() || !ReadBytes(reinterpret_cast<std::uintptr_t>(address), current.data(), expectedSize))
                return false;

            if (std::memcmp(current.data(), replacement, replacementSize) == 0)
            {
                if (log) std::fprintf(log, "patch=%s rva=0x%llX result=already-applied\n", name, static_cast<unsigned long long>(rva));
                return true;
            }
            if (std::memcmp(current.data(), expected, expectedSize) != 0)
            {
                if (log) std::fprintf(log, "patch=%s rva=0x%llX result=byte-mismatch current=%s\n",
                    name, static_cast<unsigned long long>(rva), HexBytes(reinterpret_cast<std::uintptr_t>(address), expectedSize).c_str());
                return false;
            }

            DWORD oldProtect = 0;
            if (!VirtualProtect(address, replacementSize, PAGE_EXECUTE_READWRITE, &oldProtect))
                return false;
            std::memcpy(address, replacement, replacementSize);
            FlushInstructionCache(GetCurrentProcess(), address, replacementSize);
            DWORD ignored = 0;
            VirtualProtect(address, replacementSize, oldProtect, &ignored);
            if (log) std::fprintf(log, "patch=%s rva=0x%llX result=applied\n", name, static_cast<unsigned long long>(rva));
            return true;
        }

        bool ApplyValidatedStartupCompatibility()
        {
            EnsureLogDirectory();
            FILE* log = nullptr;
            fopen_s(&log, "logs\\t8_mp_beta\\startup_patch.log", "a");

            std::uint32_t marker = 0;
            if (!ReadU32(Base() + kBuildMarkerRva, marker) || marker != kExpectedBuildMarker)
            {
                if (log)
                {
                    std::fprintf(log, "startup_patch=skipped marker=0x%08X expected=0x%08X\n", marker, kExpectedBuildMarker);
                    std::fclose(log);
                }
                return false;
            }

            static constexpr unsigned char kAExpected[] = {0x32, 0xC0, 0xC3};
            static constexpr unsigned char kAReplacement[] = {0xB0, 0x01};
            static constexpr unsigned char kBExpected[] = {0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x0D, 0xD5};
            static constexpr unsigned char kBReplacement[] = {0xB0, 0x01, 0xC3, 0x90};
            static constexpr unsigned char kCrashExpected[] = {0x40, 0x53, 0x56, 0x57, 0x48, 0x83, 0xEC, 0x60};
            static constexpr unsigned char kCrashReplacement[] = {0xC3};

            const bool a = WriteExactPatch("BattleNet_IsDisabled", 0x006D88B0ull,
                kAExpected, sizeof(kAExpected), kAReplacement, sizeof(kAReplacement), log);
            const bool b = WriteExactPatch("BattleNet_IsConnected", 0x006D88C0ull,
                kBExpected, sizeof(kBExpected), kBReplacement, sizeof(kBReplacement), log);
            const bool c = WriteExactPatch("BattleNet_early_crash_gate", 0x006BDE20ull,
                kCrashExpected, sizeof(kCrashExpected), kCrashReplacement, sizeof(kCrashReplacement), log);

            if (log)
            {
                std::fprintf(log, "startup_patch_summary marker=matched applied=%d/3 exact_byte_guard=yes\n",
                    (a ? 1 : 0) + (b ? 1 : 0) + (c ? 1 : 0));
                std::fflush(log);
                std::fclose(log);
            }
            return a && b && c;
        }

        void EnsureConsole()
        {
            bool available = GetConsoleWindow() != nullptr;
            if (!available && AttachConsole(ATTACH_PARENT_PROCESS))
                available = true;
            if (!available && AllocConsole())
                available = true;
            if (!available)
                return;

            FILE* stream = nullptr;
            freopen_s(&stream, "CONOUT$", "w", stdout);
            freopen_s(&stream, "CONOUT$", "w", stderr);
            freopen_s(&stream, "CONIN$", "r", stdin);
            SetConsoleTitleW(L"CodRevamped - BO4 Multiplayer Beta Research");
        }

        const char* ProtectionName(DWORD protect)
        {
            protect &= 0xFFu;
            switch (protect)
            {
            case PAGE_NOACCESS: return "NOACCESS";
            case PAGE_READONLY: return "R";
            case PAGE_READWRITE: return "RW";
            case PAGE_WRITECOPY: return "WC";
            case PAGE_EXECUTE: return "X";
            case PAGE_EXECUTE_READ: return "XR";
            case PAGE_EXECUTE_READWRITE: return "XRW";
            case PAGE_EXECUTE_WRITECOPY: return "XWC";
            default: return "OTHER";
            }
        }

        bool IsReadable(DWORD protect)
        {
            if (protect & PAGE_GUARD)
                return false;
            switch (protect & 0xFFu)
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

        bool IsExecutable(DWORD protect)
        {
            switch (protect & 0xFFu)
            {
            case PAGE_EXECUTE:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
            }
        }

        bool ReadBytes(std::uintptr_t address, void* out, std::size_t size)
        {
            if (!address || !out || !size)
                return false;
            SIZE_T got = 0;
            return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), out, size, &got) && got == size;
        }

        bool ReadU32(std::uintptr_t address, std::uint32_t& value)
        {
            return ReadBytes(address, &value, sizeof(value));
        }

        std::string HexBytes(std::uintptr_t address, std::size_t count)
        {
            std::array<unsigned char, 32> bytes{};
            count = (std::min)(count, bytes.size());
            if (!ReadBytes(address, bytes.data(), count))
                return {};

            std::ostringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0');
            for (std::size_t i = 0; i < count; ++i)
            {
                if (i) ss << ' ';
                ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
            }
            return ss.str();
        }

        std::string CsvEscape(std::string value)
        {
            std::string out = "\"";
            for (const char c : value)
            {
                if (c == '"') out += '"';
                out += c;
            }
            out += '"';
            return out;
        }

        void WriteProfileLog()
        {
            EnsureLogDirectory();
            std::ofstream out("logs\\t8_mp_beta\\profile.log", std::ios::app);
            if (!out)
                return;

            std::uint32_t ts = 0, image = 0, entry = 0;
            ReadPeFingerprint(ts, image, entry);
            out << "profile=T8_BO4_MULTIPLAYER_BETA_AUG2018\n";
            out << "mode=PASSIVE_UNLOCKER_RESEARCH_V1\n";
            out << "runtime_base=0x" << std::hex << std::uppercase << Base() << "\n";
            out << "timestamp=0x" << ts << "\n";
            out << "image_size=0x" << image << "\n";
            out << "entry_rva=0x" << entry << "\n";
            out << "exe_sha256=" << kProfileSha256 << "\n";
            out << "original_unlocker_sha256=" << kUnlockerSha256 << "\n";
            out << "build_marker_rva=0x" << kBuildMarkerRva << " expected=0x" << kExpectedBuildMarker
                << " decimal=" << std::dec << kExpectedBuildMarker << "\n";
            out << "writes_enabled=startup_compat_exact_bytes_only\nretail_shield_enabled=no\nblackout_beta_code_enabled=no\n";
        }

        bool WaitForBuildMarker()
        {
            EnsureLogDirectory();
            std::ofstream out("logs\\t8_mp_beta\\build_marker.log", std::ios::app);
            const auto address = Base() + kBuildMarkerRva;
            std::uint32_t previous = 0xFFFFFFFFu;
            bool hadValue = false;

            std::printf("[T8-MP-BETA] waiting for unlocker build marker RVA 0x%llX -> 0x%08X (%u)\n",
                static_cast<unsigned long long>(kBuildMarkerRva), kExpectedBuildMarker, kExpectedBuildMarker);

            const ULONGLONG deadline = GetTickCount64() + 30000ull;
            while (GetTickCount64() < deadline)
            {
                std::uint32_t value = 0;
                if (ReadU32(address, value))
                {
                    if (!hadValue || value != previous)
                    {
                        out << "uptime_ms=" << GetTickCount64() << " address=0x" << std::hex << std::uppercase << address
                            << " value=0x" << value << " decimal=" << std::dec << value << "\n";
                        out.flush();
                        std::printf("[T8-MP-BETA] build marker now 0x%08X (%u)%s\n",
                            value, value, value == kExpectedBuildMarker ? " MATCH" : "");
                        previous = value;
                        hadValue = true;
                    }
                    if (value == kExpectedBuildMarker)
                        return true;
                }
                Sleep(100);
            }

            std::printf("[T8-MP-BETA] build marker did not reach expected value in 30s; continuing read-only research.\n");
            return false;
        }

        void WriteMemoryMap()
        {
            EnsureLogDirectory();
            std::ofstream out("logs\\t8_mp_beta\\memory_map.csv", std::ios::trunc);
            out << "base,end,size,state,type,protect,inside_pe_image\n";

            const auto imageBase = Base();
            const auto imageEnd = imageBase + kImageSize;
            std::uintptr_t cursor = imageBase;
            while (cursor < imageEnd)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                    break;
                const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto regionEnd = regionBase + mbi.RegionSize;
                out << "0x" << std::hex << std::uppercase << regionBase
                    << ",0x" << regionEnd
                    << ",0x" << mbi.RegionSize
                    << ",0x" << mbi.State
                    << ",0x" << mbi.Type
                    << ',' << ProtectionName(mbi.Protect)
                    << ',' << ((regionBase < imageEnd && regionEnd > imageBase) ? 1 : 0) << "\n";
                if (regionEnd <= cursor)
                    break;
                cursor = regionEnd;
            }
        }

        void AuditUnlockerReferences()
        {
            EnsureLogDirectory();
            std::ofstream out("logs\\t8_mp_beta\\unlocker_refs.csv", std::ios::trunc);
            out << "preferred_va,rva,runtime_address,in_pe_image,committed,protect,readable,executable,category,recovered_action,bytes16\n";

            const auto runtimeBase = Base();
            std::size_t readable = 0;
            std::size_t executable = 0;
            std::size_t inside = 0;

            for (const auto& ref : kUnlockerRefs)
            {
                const auto rva = ref.preferredVa - kPreferredBase;
                const auto runtimeAddress = runtimeBase + rva;
                const bool inImage = rva < kImageSize;
                if (inImage) ++inside;

                MEMORY_BASIC_INFORMATION mbi{};
                const bool queried = VirtualQuery(reinterpret_cast<const void*>(runtimeAddress), &mbi, sizeof(mbi)) != 0;
                const bool committed = queried && mbi.State == MEM_COMMIT;
                const bool canRead = committed && IsReadable(mbi.Protect);
                const bool canExec = committed && IsExecutable(mbi.Protect);
                if (canRead) ++readable;
                if (canExec) ++executable;

                out << "0x" << std::hex << std::uppercase << ref.preferredVa
                    << ",0x" << rva
                    << ",0x" << runtimeAddress
                    << ',' << std::dec << (inImage ? 1 : 0)
                    << ',' << (committed ? 1 : 0)
                    << ',' << (queried ? ProtectionName(mbi.Protect) : "UNMAPPED")
                    << ',' << (canRead ? 1 : 0)
                    << ',' << (canExec ? 1 : 0)
                    << ',' << CsvEscape(ref.category)
                    << ',' << CsvEscape(ref.recoveredAction)
                    << ',' << CsvEscape(canRead ? HexBytes(runtimeAddress, 16) : std::string{})
                    << "\n";
            }

            out.flush();
            std::printf("[T8-MP-BETA] original unlocker audit: refs=%zu in_pe=%zu readable=%zu executable=%zu\n",
                std::size(kUnlockerRefs), inside, readable, executable);
            std::printf("[T8-MP-BETA] log: logs\\t8_mp_beta\\unlocker_refs.csv\n");
        }

        std::string SanitizeContext(const unsigned char* data, std::size_t size, std::size_t center)
        {
            const std::size_t begin = center > 48 ? center - 48 : 0;
            const std::size_t end = (std::min)(size, center + 96);
            std::string out;
            out.reserve(end - begin);
            for (std::size_t i = begin; i < end; ++i)
            {
                const unsigned char c = data[i];
                if (c >= 0x20 && c < 0x7F)
                    out.push_back(static_cast<char>(c));
                else
                    out.push_back('.');
            }
            return out;
        }

        std::string LowerAscii(const unsigned char* data, std::size_t size)
        {
            std::string out(size, '\0');
            for (std::size_t i = 0; i < size; ++i)
            {
                const unsigned char c = data[i];
                out[i] = static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
            }
            return out;
        }

        void ScanRuntimeStrings()
        {
            EnsureLogDirectory();
            std::ofstream out("logs\\t8_mp_beta\\runtime_strings.csv", std::ios::trunc);
            out << "term,address,rva,protect,context\n";

            const auto imageBase = Base();
            const auto imageEnd = imageBase + kImageSize;
            std::array<std::size_t, std::size(kTerms)> counts{};
            constexpr std::size_t kPerTermCap = 200;
            constexpr std::size_t kChunk = 1024 * 1024;
            std::vector<unsigned char> buffer(kChunk);

            std::uintptr_t cursor = imageBase;
            std::size_t totalHits = 0;
            while (cursor < imageEnd)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                    break;

                const auto regionBase = (std::max)(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
                const auto regionEnd = (std::min)(imageEnd,
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);

                if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect) && regionEnd > regionBase)
                {
                    for (std::uintptr_t pos = regionBase; pos < regionEnd; )
                    {
                        const std::size_t want = static_cast<std::size_t>((std::min<std::uintptr_t>)(kChunk, regionEnd - pos));
                        SIZE_T got = 0;
                        if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(pos), buffer.data(), want, &got) && got)
                        {
                            const auto lower = LowerAscii(buffer.data(), static_cast<std::size_t>(got));
                            for (std::size_t t = 0; t < std::size(kTerms); ++t)
                            {
                                if (counts[t] >= kPerTermCap)
                                    continue;
                                const std::string needle(kTerms[t]);
                                std::size_t at = 0;
                                while (counts[t] < kPerTermCap && (at = lower.find(needle, at)) != std::string::npos)
                                {
                                    const auto address = pos + at;
                                    out << CsvEscape(needle)
                                        << ",0x" << std::hex << std::uppercase << address
                                        << ",0x" << (address - imageBase)
                                        << ',' << ProtectionName(mbi.Protect)
                                        << ',' << CsvEscape(SanitizeContext(buffer.data(), static_cast<std::size_t>(got), at))
                                        << "\n";
                                    ++counts[t];
                                    ++totalHits;
                                    at += needle.size();
                                }
                            }
                        }
                        pos += want ? want : 1;
                    }
                }

                const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= cursor)
                    break;
                cursor = next;
            }

            out.flush();
            std::printf("[T8-MP-BETA] runtime string scan complete: hits=%zu -> logs\\t8_mp_beta\\runtime_strings.csv\n", totalHits);
        }

        void MonitorRecoveredReferences()
        {
            EnsureLogDirectory();
            std::ofstream out("logs\\t8_mp_beta\\unlocker_ref_changes.csv", std::ios::trunc);
            out << "elapsed_ms,rva,runtime_address,category,before,after\n";

            struct Snapshot
            {
                bool valid = false;
                std::array<unsigned char, 8> bytes{};
            };
            std::array<Snapshot, std::size(kUnlockerRefs)> snapshots{};
            const auto base = Base();

            for (std::size_t i = 0; i < std::size(kUnlockerRefs); ++i)
            {
                const auto rva = kUnlockerRefs[i].preferredVa - kPreferredBase;
                snapshots[i].valid = ReadBytes(base + rva, snapshots[i].bytes.data(), snapshots[i].bytes.size());
            }

            const ULONGLONG start = GetTickCount64();
            for (int pass = 0; pass < 60; ++pass)
            {
                Sleep(1000);
                for (std::size_t i = 0; i < std::size(kUnlockerRefs); ++i)
                {
                    const auto rva = kUnlockerRefs[i].preferredVa - kPreferredBase;
                    const auto address = base + rva;
                    std::array<unsigned char, 8> now{};
                    const bool valid = ReadBytes(address, now.data(), now.size());
                    if (valid && snapshots[i].valid && now != snapshots[i].bytes)
                    {
                        auto ToHex = [](const std::array<unsigned char, 8>& v)
                        {
                            std::ostringstream ss;
                            ss << std::hex << std::uppercase << std::setfill('0');
                            for (std::size_t n = 0; n < v.size(); ++n)
                            {
                                if (n) ss << ' ';
                                ss << std::setw(2) << static_cast<unsigned int>(v[n]);
                            }
                            return ss.str();
                        };

                        out << (GetTickCount64() - start)
                            << ",0x" << std::hex << std::uppercase << rva
                            << ",0x" << address
                            << ',' << CsvEscape(kUnlockerRefs[i].category)
                            << ',' << CsvEscape(ToHex(snapshots[i].bytes))
                            << ',' << CsvEscape(ToHex(now)) << "\n";
                        out.flush();
                        std::printf("[T8-MP-BETA] recovered ref changed rva=0x%llX category=%s\n",
                            static_cast<unsigned long long>(rva), kUnlockerRefs[i].category);
                    }
                    if (valid)
                    {
                        snapshots[i].valid = true;
                        snapshots[i].bytes = now;
                    }
                }
            }
        }

        DWORD WINAPI ResearchThread(LPVOID)
        {
            EnsureConsole();
            EnsureLogDirectory();

            std::printf(
                "\n============================================================\n"
                " CodRevamped - Black Ops 4 Multiplayer Beta (Aug 2018)\n"
                "============================================================\n"
                "[T8-MP-BETA] Exact profile matched.\n"
                "[T8-MP-BETA] Mode: RETAIL-BASE + VALIDATED STARTUP COMPATIBILITY + PASSIVE RESEARCH v4\n"
                "[T8-MP-BETA] Retail common/pre_start infrastructure is ACTIVE; address-dependent post_unpack hooks stay gated until beta RVAs are mapped.\n"
                "[T8-MP-BETA] Only the three exact-byte-validated original startup compatibility patches are enabled; all other recovered writes remain passive.\n"
                "[T8-MP-BETA] Original unlocker endpoints include byzantium-pc-beta-auth3/lobby.\n"
                "[T8-MP-BETA] EXE SHA256: %s\n"
                "[T8-MP-BETA] Unlocker SHA256: %s\n",
                kProfileSha256, kUnlockerSha256);

            std::uint32_t ts = 0, image = 0, entry = 0;
            ReadPeFingerprint(ts, image, entry);
            std::printf("[T8-MP-BETA] PE timestamp=0x%08X imageSize=0x%08X entryRva=0x%08X base=%p\n",
                ts, image, entry, reinterpret_cast<void*>(Base()));

            WriteProfileLog();
            const bool startupCompat = ApplyValidatedStartupCompatibility();
            std::printf("[T8-MP-BETA] startup compatibility patches: %s\n", startupCompat ? "APPLIED" : "NOT APPLIED");
            InstallStartupDiagnostics();
            WriteMemoryMap();
            const bool markerMatched = WaitForBuildMarker();
            std::printf("[T8-MP-BETA] build marker status: %s\n", markerMatched ? "MATCHED" : "NOT MATCHED YET");

            AuditUnlockerReferences();
            std::printf("[T8-MP-BETA] deep runtime string scan deferred during startup so the beta can finish booting first.\n");

            std::printf(
                "[T8-MP-BETA] Initial startup probe complete.\n"
                "[T8-MP-BETA] Watching recovered unlocker targets for 60 seconds; leave the game open.\n"
                "[T8-MP-BETA] Only the three validated startup compatibility sites are modified; all other recovered sites stay read-only.\n");
            MonitorRecoveredReferences();
            std::printf("[T8-MP-BETA] 60-second recovered-reference watch complete.\n");
            return 0;
        }
    }

    bool IsSupportedExecutable()
    {
        if (!IsProcessName(L"BlackOps4.exe"))
            return false;

        std::uint32_t timestamp = 0, imageSize = 0, entryRva = 0;
        if (!ReadPeFingerprint(timestamp, imageSize, entryRva))
            return false;

        return timestamp == kTimestamp &&
               imageSize == kImageSize &&
               entryRva == kEntryRva;
    }

    void StartAutomatic()
    {
        if (!IsSupportedExecutable())
            return;
        if (g_started.exchange(true))
            return;

        HANDLE thread = CreateThread(nullptr, 0, &ResearchThread, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
        else
            g_started.store(false);
    }
}
