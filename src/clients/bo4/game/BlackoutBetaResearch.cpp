#include "BlackoutBetaResearch.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <winnt.h>

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
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace t8_blackout_beta
{
    namespace
    {
        constexpr std::uint32_t kTimestamp = 0x5B9999E4u;
        constexpr std::uint32_t kImageSize = 0x121A0A00u;
        constexpr std::uint32_t kEntryRva  = 0x036828A0u;

        std::atomic_bool g_started{ false };
        std::atomic_int g_stage{ 0 };
        PVOID g_vehHandle = nullptr;
        std::mutex g_dumpMutex;
        std::unordered_set<std::uintptr_t> g_dumpedLua;

        struct Section
        {
            std::string name;
            std::uintptr_t begin{};
            std::size_t size{};
            DWORD characteristics{};
        };

        struct Anchor
        {
            std::uintptr_t address{};
            std::string text;
            std::string category;
        };

        const char* StageName(int stage);

        std::uintptr_t Base()
        {
            return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        }

        using ExitProcessFn = VOID (WINAPI*)(UINT);
        using TerminateProcessFn = BOOL (WINAPI*)(HANDLE, UINT);
        using RtlExitUserProcessFn = VOID (NTAPI*)(LONG);
        using NtTerminateProcessFn = LONG (NTAPI*)(HANDLE, LONG);
        using LoadLibraryAFn = HMODULE (WINAPI*)(LPCSTR);
        using LoadLibraryWFn = HMODULE (WINAPI*)(LPCWSTR);
        using GetProcAddressFn = FARPROC (WINAPI*)(HMODULE, LPCSTR);
        using RaiseFailFastExceptionFn = VOID (WINAPI*)(PEXCEPTION_RECORD, PCONTEXT, DWORD);
        using FatalAppExitAFn = VOID (WINAPI*)(UINT, LPCSTR);
        using FatalAppExitWFn = VOID (WINAPI*)(UINT, LPCWSTR);
        using NtQueryInformationThreadFn = LONG (NTAPI*)(HANDLE, LONG, PVOID, ULONG, PULONG);

        void* g_originalExitProcess = nullptr;
        void* g_originalTerminateProcess = nullptr;
        void* g_originalRtlExitUserProcess = nullptr;
        void* g_originalNtTerminateProcess = nullptr;
        void* g_originalLoadLibraryA = nullptr;
        void* g_originalLoadLibraryW = nullptr;
        void* g_originalGetProcAddress = nullptr;
        void* g_originalRaiseFailFastException = nullptr;
        void* g_originalFatalAppExitA = nullptr;
        void* g_originalFatalAppExitW = nullptr;

        bool IsInterestingResolvedApi(const char* name)
        {
            if (!name || reinterpret_cast<std::uintptr_t>(name) <= 0xFFFFu) return false;
            static constexpr const char* kNames[] = {
                "ExitProcess", "TerminateProcess", "RtlExitUserProcess", "NtTerminateProcess",
                "RaiseFailFastException", "FatalAppExitA", "FatalAppExitW",
                "abort", "_exit", "_Exit", "quick_exit"
            };
            for (const auto* wanted : kNames)
                if (_stricmp(name, wanted) == 0) return true;
            return false;
        }

        void LogRuntimeEvent(const char* kind, const char* detail, std::uintptr_t result = 0)
        {
            CreateDirectoryW(L"logs", nullptr);
            CreateDirectoryW(L"logs\\t8_blackout_beta", nullptr);
            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_blackout_beta\\runtime_watch.log", "a") != 0 || !f)
                return;
            const auto base = Base();
            const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
            SYSTEMTIME st{}; GetLocalTime(&st);
            std::fprintf(f,
                "%04u-%02u-%02u %02u:%02u:%02u.%03u kind=%s detail=\"%s\" result=0x%llX caller_rva=0x%llX tid=%lu stage=%d(%s)\n",
                st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds,
                kind?kind:"unknown", detail?detail:"",
                static_cast<unsigned long long>(result),
                static_cast<unsigned long long>(caller>=base && caller<base+kImageSize ? caller-base : 0),
                GetCurrentThreadId(), g_stage.load(std::memory_order_relaxed),
                StageName(g_stage.load(std::memory_order_relaxed)));
            std::fflush(f);
            std::fclose(f);
        }

        void LogTerminationRequest(const char* api, unsigned long long status, HANDLE processHandle = nullptr)
        {
            CreateDirectoryW(L"logs", nullptr);
            CreateDirectoryW(L"logs\\t8_blackout_beta", nullptr);
            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_blackout_beta\\termination.log", "a") != 0 || !f)
                return;

            SYSTEMTIME st{};
            GetLocalTime(&st);
            const auto base = Base();
            const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
            const auto stage = g_stage.load(std::memory_order_relaxed);
            const bool selfTarget = !processHandle || processHandle == GetCurrentProcess() ||
                processHandle == reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1));

            void* frames[12]{};
            const USHORT frameCount = CaptureStackBackTrace(1, 12, frames, nullptr);
            std::fprintf(f,
                "%04u-%02u-%02u %02u:%02u:%02u.%03u api=%s status=0x%llX pid=%lu tid=%lu "
                "stage=%d(%s) caller=0x%p caller_rva=0x%llX self_target=%d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                api ? api : "unknown", status, GetCurrentProcessId(), GetCurrentThreadId(),
                stage, StageName(stage), reinterpret_cast<void*>(caller),
                static_cast<unsigned long long>(caller >= base ? caller - base : 0), selfTarget ? 1 : 0);
            std::fprintf(f, "stack_rvas=");
            for (USHORT i = 0; i < frameCount; ++i)
            {
                const auto a = reinterpret_cast<std::uintptr_t>(frames[i]);
                if (i) std::fprintf(f, ";");
                if (a >= base && a < base + kImageSize)
                    std::fprintf(f, "0x%llX", static_cast<unsigned long long>(a - base));
                else
                    std::fprintf(f, "abs:0x%p", frames[i]);
            }
            std::fprintf(f, "\n");
            std::fflush(f);
            std::fclose(f);
        }

        VOID WINAPI HookExitProcess(UINT code)
        {
            LogTerminationRequest("ExitProcess", code);
            if (g_originalExitProcess) reinterpret_cast<ExitProcessFn>(g_originalExitProcess)(code);
            for (;;) Sleep(INFINITE);
        }

        BOOL WINAPI HookTerminateProcess(HANDLE process, UINT code)
        {
            LogTerminationRequest("TerminateProcess", code, process);
            return g_originalTerminateProcess ? reinterpret_cast<TerminateProcessFn>(g_originalTerminateProcess)(process, code) : FALSE;
        }

        VOID NTAPI HookRtlExitUserProcess(LONG status)
        {
            LogTerminationRequest("RtlExitUserProcess", static_cast<unsigned long long>(static_cast<unsigned long>(status)));
            if (g_originalRtlExitUserProcess) reinterpret_cast<RtlExitUserProcessFn>(g_originalRtlExitUserProcess)(status);
            for (;;) Sleep(INFINITE);
        }

        LONG NTAPI HookNtTerminateProcess(HANDLE process, LONG status)
        {
            LogTerminationRequest("NtTerminateProcess", static_cast<unsigned long long>(static_cast<unsigned long>(status)), process);
            return g_originalNtTerminateProcess ? reinterpret_cast<NtTerminateProcessFn>(g_originalNtTerminateProcess)(process, status) : status;
        }

        HMODULE WINAPI HookLoadLibraryA(LPCSTR name)
        {
            LogRuntimeEvent("LoadLibraryA", name ? name : "");
            return g_originalLoadLibraryA
                ? reinterpret_cast<LoadLibraryAFn>(g_originalLoadLibraryA)(name) : nullptr;
        }

        HMODULE WINAPI HookLoadLibraryW(LPCWSTR name)
        {
            char narrow[512]{};
            if (name)
                WideCharToMultiByte(CP_UTF8, 0, name, -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr);
            LogRuntimeEvent("LoadLibraryW", narrow);
            return g_originalLoadLibraryW
                ? reinterpret_cast<LoadLibraryWFn>(g_originalLoadLibraryW)(name) : nullptr;
        }

        FARPROC WINAPI HookGetProcAddress(HMODULE module, LPCSTR name)
        {
            FARPROC result = g_originalGetProcAddress
                ? reinterpret_cast<GetProcAddressFn>(g_originalGetProcAddress)(module, name) : nullptr;
            if (IsInterestingResolvedApi(name))
                LogRuntimeEvent("GetProcAddress", name, reinterpret_cast<std::uintptr_t>(result));
            return result;
        }

        VOID WINAPI HookRaiseFailFastException(PEXCEPTION_RECORD record, PCONTEXT context, DWORD flags)
        {
            LogRuntimeEvent("RaiseFailFastException", "called");
            if (g_originalRaiseFailFastException)
                reinterpret_cast<RaiseFailFastExceptionFn>(g_originalRaiseFailFastException)(record, context, flags);
        }

        VOID WINAPI HookFatalAppExitA(UINT action, LPCSTR message)
        {
            LogRuntimeEvent("FatalAppExitA", message ? message : "");
            if (g_originalFatalAppExitA)
                reinterpret_cast<FatalAppExitAFn>(g_originalFatalAppExitA)(action, message);
        }

        VOID WINAPI HookFatalAppExitW(UINT action, LPCWSTR message)
        {
            char narrow[512]{};
            if (message)
                WideCharToMultiByte(CP_UTF8, 0, message, -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr);
            LogRuntimeEvent("FatalAppExitW", narrow);
            if (g_originalFatalAppExitW)
                reinterpret_cast<FatalAppExitWFn>(g_originalFatalAppExitW)(action, message);
        }

        bool PatchTerminationImport(const char* wantedName, void* replacement, void** original)
        {
            const auto base = Base();
            if (!base || !wantedName || !replacement || !original) return false;
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
            const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (!dir.VirtualAddress || !dir.Size) return false;

            auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
            std::size_t descriptors = 0;
            for (; desc->Name && descriptors < 512; ++desc, ++descriptors)
            {
                auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);
                auto* names = desc->OriginalFirstThunk ? reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->OriginalFirstThunk) : nullptr;
                if (!iat || !names) continue;
                for (std::size_t i = 0; names[i].u1.AddressOfData && i < 65536; ++i)
                {
                    if (IMAGE_SNAP_BY_ORDINAL64(names[i].u1.Ordinal)) continue;
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names[i].u1.AddressOfData);
                    if (!ibn || std::strcmp(reinterpret_cast<const char*>(ibn->Name), wantedName) != 0) continue;
                    auto** slot = reinterpret_cast<void**>(&iat[i].u1.Function);
                    DWORD oldProtect = 0;
                    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) return false;
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

        void InstallTerminationDiagnostics()
        {
            CreateDirectoryW(L"logs", nullptr);
            CreateDirectoryW(L"logs\\t8_blackout_beta", nullptr);
            const bool a = PatchTerminationImport("ExitProcess", reinterpret_cast<void*>(&HookExitProcess), &g_originalExitProcess);
            const bool b = PatchTerminationImport("TerminateProcess", reinterpret_cast<void*>(&HookTerminateProcess), &g_originalTerminateProcess);
            const bool c = PatchTerminationImport("RtlExitUserProcess", reinterpret_cast<void*>(&HookRtlExitUserProcess), &g_originalRtlExitUserProcess);
            const bool d = PatchTerminationImport("NtTerminateProcess", reinterpret_cast<void*>(&HookNtTerminateProcess), &g_originalNtTerminateProcess);
            const bool e = PatchTerminationImport("LoadLibraryA", reinterpret_cast<void*>(&HookLoadLibraryA), &g_originalLoadLibraryA);
            const bool fLoad = PatchTerminationImport("LoadLibraryW", reinterpret_cast<void*>(&HookLoadLibraryW), &g_originalLoadLibraryW);
            const bool g = PatchTerminationImport("GetProcAddress", reinterpret_cast<void*>(&HookGetProcAddress), &g_originalGetProcAddress);
            const bool h = PatchTerminationImport("RaiseFailFastException", reinterpret_cast<void*>(&HookRaiseFailFastException), &g_originalRaiseFailFastException);
            const bool i = PatchTerminationImport("FatalAppExitA", reinterpret_cast<void*>(&HookFatalAppExitA), &g_originalFatalAppExitA);
            const bool j = PatchTerminationImport("FatalAppExitW", reinterpret_cast<void*>(&HookFatalAppExitW), &g_originalFatalAppExitW);
            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_blackout_beta\\termination.log", "a") == 0 && f)
            {
                std::fprintf(f, "termination_diagnostics=armed ExitProcess=%d TerminateProcess=%d RtlExitUserProcess=%d NtTerminateProcess=%d LoadLibraryA=%d LoadLibraryW=%d GetProcAddress=%d RaiseFailFastException=%d FatalAppExitA=%d FatalAppExitW=%d\n",
                    a?1:0,b?1:0,c?1:0,d?1:0,e?1:0,fLoad?1:0,g?1:0,h?1:0,i?1:0,j?1:0);
                std::fflush(f);
                std::fclose(f);
            }
        }

        const char* StageName(int stage)
        {
            switch (stage)
            {
            case 0: return "startup";
            case 1: return "sleep-before-scan";
            case 2: return "collect-sections-anchors";
            case 3: return "scan-xrefs";
            case 4: return "menu-flow-callgraph";
            case 5: return "scan-complete-heartbeat";
            default: return "unknown";
            }
        }

        bool IsSeriousException(DWORD code)
        {
            switch (code)
            {
            case EXCEPTION_ACCESS_VIOLATION:
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            case EXCEPTION_ILLEGAL_INSTRUCTION:
            case EXCEPTION_IN_PAGE_ERROR:
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
            case EXCEPTION_PRIV_INSTRUCTION:
            case EXCEPTION_STACK_OVERFLOW:
            case 0xC0000374u: // heap corruption
            case 0xC0000409u: // stack buffer overrun / fail-fast family
                return true;
            default:
                return false;
            }
        }

        LONG CALLBACK CrashVeh(EXCEPTION_POINTERS* info)
        {
            if (!info || !info->ExceptionRecord || !info->ContextRecord)
                return EXCEPTION_CONTINUE_SEARCH;
            const DWORD code = info->ExceptionRecord->ExceptionCode;
            if (!IsSeriousException(code))
                return EXCEPTION_CONTINUE_SEARCH;

            CreateDirectoryW(L"logs", nullptr);
            CreateDirectoryW(L"logs\\t8_blackout_beta", nullptr);
            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_blackout_beta\\crash_exit.log", "a") == 0 && f)
            {
                SYSTEMTIME st{}; GetLocalTime(&st);
                const auto base = Base();
                const auto address = reinterpret_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionAddress);
                const auto stage = g_stage.load(std::memory_order_relaxed);
                std::fprintf(f,
                    "%04u-%02u-%02u %02u:%02u:%02u.%03u event=exception code=0x%08lX address=0x%p rva=0x%llX tid=%lu stage=%d(%s) flags=0x%08lX\n",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    code, info->ExceptionRecord->ExceptionAddress,
                    static_cast<unsigned long long>(address >= base ? address - base : 0),
                    GetCurrentThreadId(), stage, StageName(stage), info->ExceptionRecord->ExceptionFlags);
#ifdef _M_X64
                const auto& c = *info->ContextRecord;
                std::fprintf(f,
                    "RIP=%016llX RSP=%016llX RBP=%016llX RAX=%016llX RBX=%016llX RCX=%016llX RDX=%016llX RSI=%016llX RDI=%016llX R8=%016llX R9=%016llX R10=%016llX R11=%016llX R12=%016llX R13=%016llX R14=%016llX R15=%016llX\n",
                    c.Rip,c.Rsp,c.Rbp,c.Rax,c.Rbx,c.Rcx,c.Rdx,c.Rsi,c.Rdi,c.R8,c.R9,c.R10,c.R11,c.R12,c.R13,c.R14,c.R15);
#endif
                std::fflush(f);
                std::fclose(f);
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }

        void InstallCrashDiagnostics()
        {
            if (!g_vehHandle)
                g_vehHandle = AddVectoredExceptionHandler(1, &CrashVeh);
            CreateDirectoryW(L"logs", nullptr);
            CreateDirectoryW(L"logs\\t8_blackout_beta", nullptr);
            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_blackout_beta\\crash_exit.log", "a") == 0 && f)
            {
                std::fprintf(f, "diagnostics=armed pid=%lu tid=%lu moduleBase=0x%p\n",
                    GetCurrentProcessId(), GetCurrentThreadId(), reinterpret_cast<void*>(Base()));
                std::fflush(f);
                std::fclose(f);
            }
        }

        bool ReadBytes(std::uintptr_t address, void* dst, std::size_t size)
        {
            SIZE_T got = 0;
            return address && dst && size &&
                ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), dst, size, &got) &&
                got == size;
        }

        template <typename T>
        bool ReadValue(std::uintptr_t address, T& value)
        {
            return ReadBytes(address, &value, sizeof(value));
        }

        bool ReadPe(std::uint32_t& timestamp, std::uint32_t& imageSize, std::uint32_t& entryRva)
        {
            const auto base = Base();
            IMAGE_DOS_HEADER dos{};
            if (!ReadValue(base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
                return false;
            IMAGE_NT_HEADERS64 nt{};
            if (!ReadValue(base + static_cast<std::uintptr_t>(dos.e_lfanew), nt) || nt.Signature != IMAGE_NT_SIGNATURE)
                return false;
            timestamp = nt.FileHeader.TimeDateStamp;
            imageSize = nt.OptionalHeader.SizeOfImage;
            entryRva = nt.OptionalHeader.AddressOfEntryPoint;
            return true;
        }

        std::vector<Section> Sections()
        {
            std::vector<Section> out;
            const auto base = Base();
            IMAGE_DOS_HEADER dos{};
            if (!ReadValue(base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
                return out;
            IMAGE_NT_HEADERS64 nt{};
            const auto ntAddr = base + static_cast<std::uintptr_t>(dos.e_lfanew);
            if (!ReadValue(ntAddr, nt) || nt.Signature != IMAGE_NT_SIGNATURE)
                return out;
            auto sh = ntAddr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
            for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
            {
                IMAGE_SECTION_HEADER s{};
                if (!ReadValue(sh + i * sizeof(s), s))
                    break;
                char name[9]{};
                std::memcpy(name, s.Name, 8);
                const auto span = static_cast<std::size_t>((std::max)(s.Misc.VirtualSize, s.SizeOfRawData));
                out.push_back({ name, base + s.VirtualAddress, span, s.Characteristics });
            }
            return out;
        }

        std::string Lower(std::string s)
        {
            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }

        std::string Category(const std::string& s)
        {
            const auto l = Lower(s);
            auto has = [&](std::string_view x) { return l.find(x) != std::string::npos; };
            if (has("blackout") || has("battle_royale") || has("battle royale") || has("br_") || has("wz_")) return "blackout";
            if (has("anticheat") || has("anti-cheat") || has("integrity") || has("watchdog") ||
                has("arxan") || has("guardit") || has("code protection") || has("tamper") ||
                has("emergency shutdown") || has("ffotdshutdown") || has("shutdownmatchmaking") ||
                has("failfast") || has("terminateprocess") || has("exitprocess")) return "watchdog_shutdown";
            if (has("lua") || has("lui") || has("engine.")) return "lua_lui";
            if (has("dvar") || has("developer") || has("playlist") || has("gametype") || has("game_mode") || has("sessionmode")) return "dvar_mode";
            if (has("cmd") || has("command") || has("cbuf") || has("exec ") || has("bind")) return "command";
            if (has("frontend") || has("menu") || has("online") || has("offline") || has("party") || has("matchmaking") || has("lobby")) return "frontend";
            if (has("font") || has("drawtext") || has("material") || has("stretchpic") || has("keyboard") || has("keyevent") || has("charevent")) return "render_input";
            return {};
        }

        bool UsefulChar(unsigned char c)
        {
            return c >= 0x20 && c <= 0x7E;
        }

        void WriteLuaEngineCandidates(
            const std::vector<Section>& sections,
            const std::vector<Anchor>& anchors);

        std::vector<Anchor> CollectAnchors(const std::vector<Section>& sections)
        {
            std::vector<Anchor> out;
            std::set<std::pair<std::uintptr_t, std::string>> seen;
            for (const auto& sec : sections)
            {
                if (!sec.size || sec.size > 512ull * 1024ull * 1024ull)
                    continue;
                std::vector<unsigned char> buf(sec.size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(sec.begin), buf.data(), buf.size(), &got) || got < 8)
                    continue;
                buf.resize(got);
                for (std::size_t i = 0; i < buf.size();)
                {
                    if (!UsefulChar(buf[i])) { ++i; continue; }
                    const auto start = i;
                    while (i < buf.size() && UsefulChar(buf[i])) ++i;
                    const auto len = i - start;
                    if (len < 5 || len > 240) continue;
                    std::string s(reinterpret_cast<const char*>(buf.data() + start), len);
                    auto cat = Category(s);
                    if (cat.empty()) continue;
                    if (seen.emplace(sec.begin + start, s).second)
                        out.push_back({ sec.begin + start, std::move(s), std::move(cat) });
                    if (out.size() >= 50000) return out;
                }
            }
            return out;
        }

        std::uintptr_t ContainingFunction(std::uintptr_t address)
        {
            DWORD64 imageBase = 0;
            auto* entry = RtlLookupFunctionEntry(static_cast<DWORD64>(address), &imageBase, nullptr);
            return entry ? static_cast<std::uintptr_t>(imageBase + entry->BeginAddress) : 0;
        }

        bool IsMenuFlowAnchor(const Anchor& a)
        {
            const auto l = Lower(a.text);

            // Build443: only the highest-value Blackout frontend/session anchors.
            // Avoid broad "online", "frontend", "gametype", etc. matches that
            // produced hundreds of unrelated functions in Build442.
            for (auto token : {
                "unlocksessionmode",
                "sessionmode",
                "playlistentry",
                "playlist_entry",
                "lobbyvm",
                "initmatchmaking",
                "startmatchmaking",
                "cancelmatchmaking",
                "shutdownmatchmaking",
                "lobbyhostdoc",
                "lobbybackenddoc",
                "synclobbydocuments",
                "open_hud_menu",
                "lobbyroot.anticheat",
                "lobby emergency shutdown complete",
                "ffotdshutdown"
            })
            {
                if (l.find(token) != std::string::npos) return true;
            }
            return false;
        }

        struct MenuFunctionSeed
        {
            std::uintptr_t function{};
            std::uintptr_t xref{};
            std::uintptr_t stringAddress{};
            std::string text;
        };

        void WriteMenuFlowCallgraph(const std::vector<MenuFunctionSeed>& seeds)
        {
            g_stage.store(4, std::memory_order_relaxed);
            const auto base = Base();
            std::ofstream out("logs\\t8_blackout_beta\\menu_flow_candidates.csv", std::ios::trunc);
            out << "anchor,string_rva,xref_rva,function_rva,call_site_rva,call_target_rva\n";

            std::set<std::pair<std::uintptr_t,std::string>> unique;
            std::size_t functionCount = 0;
            for (const auto& seed : seeds)
            {
                if (!seed.function) continue;
                if (!unique.emplace(seed.function, seed.text).second) continue;
                if (++functionCount > 48) break;

                DWORD64 imageBase = 0;
                auto* rf = RtlLookupFunctionEntry(static_cast<DWORD64>(seed.function), &imageBase, nullptr);
                std::uintptr_t fnEnd = seed.function + 0x1000;
                if (rf)
                    fnEnd = (std::min)(static_cast<std::uintptr_t>(imageBase + rf->EndAddress), seed.function + static_cast<std::uintptr_t>(0x2000));
                if (fnEnd <= seed.function) continue;

                const auto span = static_cast<std::size_t>(fnEnd - seed.function);
                std::vector<unsigned char> buf(span);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(seed.function), buf.data(), buf.size(), &got) || !got)
                    continue;
                buf.resize(got);

                std::string escaped = seed.text;
                std::replace(escaped.begin(), escaped.end(), '"', '\'');
                bool emitted = false;
                std::size_t calls = 0;
                for (std::size_t i = 0; i + 5 <= buf.size() && calls < 24; ++i)
                {
                    if (buf[i] != 0xE8) continue;
                    std::int32_t rel = 0; std::memcpy(&rel, buf.data()+i+1, 4);
                    const auto site = seed.function + i;
                    const auto target = site + 5 + rel;
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(reinterpret_cast<const void*>(target), &mbi, sizeof(mbi))) continue;
                    const DWORD prot = mbi.Protect & 0xFF;
                    const bool exec = mbi.State == MEM_COMMIT &&
                        (prot==PAGE_EXECUTE || prot==PAGE_EXECUTE_READ || prot==PAGE_EXECUTE_READWRITE || prot==PAGE_EXECUTE_WRITECOPY);
                    if (!exec) continue;
                    out << "\"" << escaped << "\",0x" << std::hex << std::uppercase << (seed.stringAddress-base)
                        << ",0x" << (seed.xref-base) << ",0x" << (seed.function-base)
                        << ",0x" << (site-base) << ",0x" << (target-base) << std::dec << "\n";
                    emitted = true; ++calls;
                }
                if (!emitted)
                    out << "\"" << escaped << "\",0x" << std::hex << std::uppercase << (seed.stringAddress-base)
                        << ",0x" << (seed.xref-base) << ",0x" << (seed.function-base)
                        << ",0x0,0x0" << std::dec << "\n";
            }
        }

        struct KnownMenuTarget
        {
            const char* name;
            std::uint32_t rva;
        };

        void WriteKnownMenuTargets(const std::vector<Section>& sections)
        {
            const auto base = Base();
            static constexpr KnownMenuTarget targets[] = {
                { "unlockSessionMode", 0x002F24ECu },
                { "playlistEntry", 0x00208D91u },
                { "LobbyVM", 0x018B52E0u },
                { "cancelMatchMaking", 0x018B5510u },
                { "initMatchMaking", 0x018B5C80u },
                { "startMatchMaking", 0x018B6DE0u },
                { "shutdownMatchMaking", 0x018B6C60u },
                { "open_hud_menu_A", 0x00B10740u },
                { "open_hud_menu_B", 0x00B17250u },
                { "emergencyShutdown_A", 0x0267B2A0u },
                { "emergencyShutdown_B", 0x02689ED0u },
                { "emergencyShutdown_C", 0x026969E0u },
                { "OnGetAnticheatReputation", 0x027E0810u },
                { "OnPopAnticheatMessage", 0x027E66A0u },
                { "OnPushAnticheatMessageToUI", 0x027E6AC0u },
                { "threadEntry_017D7C0", 0x0017D7C0u },
                { "threadEntry_2977E10", 0x02977E10u },
                { "threadEntry_36C9AE0", 0x036C9AE0u },
            };

            std::ofstream out("logs\\t8_blackout_beta\\known_menu_targets.csv", std::ios::trunc);
            out << "relation,name,target_rva,site_rva,owner_function_rva,other_rva\n";

            for (const auto& t : targets)
            {
                const auto fn = base + t.rva;
                DWORD64 imageBase = 0;
                auto* rf = RtlLookupFunctionEntry(static_cast<DWORD64>(fn), &imageBase, nullptr);
                if (!rf) continue;
                const auto fnBegin = static_cast<std::uintptr_t>(imageBase + rf->BeginAddress);
                const auto fnEnd = static_cast<std::uintptr_t>(imageBase + rf->EndAddress);
                if (fnEnd <= fnBegin || fnEnd - fnBegin > 0x6000) continue;
                std::vector<unsigned char> buf(static_cast<std::size_t>(fnEnd - fnBegin));
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(fnBegin), buf.data(), buf.size(), &got) || !got) continue;
                buf.resize(got);
                std::size_t calls = 0;
                for (std::size_t i = 0; i + 5 <= buf.size() && calls < 48; ++i)
                {
                    if (buf[i] != 0xE8) continue;
                    std::int32_t rel = 0; std::memcpy(&rel, buf.data()+i+1, 4);
                    const auto site = fnBegin+i;
                    const auto dest = site+5+rel;
                    out << "callee," << t.name << ",0x" << std::hex << std::uppercase << t.rva
                        << ",0x" << (site-base) << ",0x" << (fnBegin-base)
                        << ",0x" << (dest>=base?dest-base:0) << std::dec << "\n";
                    ++calls;
                }
            }

            // Build450: normalize each seed RVA to its true unwind function
            // start before looking for incoming CALL rel32 references. Some
            // Build449 RVAs point inside the owning function, so exact matching
            // against base+rva missed legitimate callers.
            struct NormalizedTarget
            {
                const KnownMenuTarget* target{};
                std::uintptr_t requested{};
                std::uintptr_t functionBegin{};
                std::uintptr_t functionEnd{};
            };

            std::vector<NormalizedTarget> normalized;
            for (const auto& t : targets)
            {
                const auto requested = base + t.rva;
                DWORD64 imageBase = 0;
                auto* rf = RtlLookupFunctionEntry(static_cast<DWORD64>(requested), &imageBase, nullptr);
                if (!rf) continue;
                normalized.push_back({
                    &t,
                    requested,
                    static_cast<std::uintptr_t>(imageBase + rf->BeginAddress),
                    static_cast<std::uintptr_t>(imageBase + rf->EndAddress)
                });
            }

            std::ofstream callers("logs\\t8_blackout_beta\\known_menu_callers.csv", std::ios::trunc);
            callers << "name,requested_rva,function_begin_rva,function_end_rva,call_site_rva,caller_function_rva\\n";

            std::unordered_map<std::uintptr_t, const NormalizedTarget*> targetMap;
            for (const auto& n : normalized)
                targetMap.emplace(n.functionBegin, &n);

            std::size_t rows = 0;
            for (const auto& sec : sections)
            {
                if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE) || !sec.size ||
                    sec.size > 384ull*1024ull*1024ull) continue;

                std::vector<unsigned char> buf(sec.size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(sec.begin), buf.data(), buf.size(), &got) || got < 5)
                    continue;
                buf.resize(got);

                for (std::size_t i=0; i+5<=buf.size() && rows<512; ++i)
                {
                    if (buf[i] != 0xE8) continue;
                    std::int32_t rel=0;
                    std::memcpy(&rel,buf.data()+i+1,4);
                    const auto site=sec.begin+i;
                    const auto dest=site+5+rel;
                    auto hit=targetMap.find(dest);
                    if (hit==targetMap.end()) continue;

                    const auto owner=ContainingFunction(site);
                    const auto* n=hit->second;
                    callers << n->target->name
                        << ",0x" << std::hex << std::uppercase << n->target->rva
                        << ",0x" << (n->functionBegin-base)
                        << ",0x" << (n->functionEnd-base)
                        << ",0x" << (site-base)
                        << ",0x" << (owner>=base?owner-base:0)
                        << std::dec << "\\n";

                    out << "caller," << n->target->name
                        << ",0x" << std::hex << std::uppercase << n->target->rva
                        << ",0x" << (site-base)
                        << ",0x" << (owner>=base?owner-base:0)
                        << ",0x" << (n->functionBegin-base)
                        << std::dec << "\\n";
                    ++rows;
                }
                if (rows>=512) break;
            }

            // Small read-only byte snapshots of the exact target functions.
            // These make the next pass deterministic without rescanning huge
            // sections and are suitable for offline disassembly.
            std::ofstream bytes("logs\\t8_blackout_beta\\known_menu_bytes.csv", std::ios::trunc);
            bytes << "name,requested_rva,function_begin_rva,function_end_rva,bytes_hex\\n";
            static constexpr char kHex[]="0123456789ABCDEF";
            for (const auto& n : normalized)
            {
                if (n.functionEnd<=n.functionBegin) continue;
                const auto want=(std::min<std::size_t>)(
                    static_cast<std::size_t>(n.functionEnd-n.functionBegin), 1024u);
                std::vector<unsigned char> b(want);
                SIZE_T got=0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(n.functionBegin), b.data(), b.size(), &got) || !got)
                    continue;
                b.resize(got);

                bytes << n.target->name
                    << ",0x" << std::hex << std::uppercase << n.target->rva
                    << ",0x" << (n.functionBegin-base)
                    << ",0x" << (n.functionEnd-base)
                    << ",\"";
                for (const auto v : b)
                    bytes << kHex[v>>4] << kHex[v&0xF];
                bytes << "\"\\n";
            }
        }

        void WriteMenuParentContext(const std::vector<Section>& sections)
        {
            const auto base = Base();

            static constexpr KnownMenuTarget targets[] = {
                { "unlockSessionMode", 0x002F24ECu },
                { "playlistEntry", 0x00208D91u },
                { "LobbyVM", 0x018B52E0u },
                { "cancelMatchMaking", 0x018B5510u },
                { "initMatchMaking", 0x018B5C80u },
                { "startMatchMaking", 0x018B6DE0u },
                { "shutdownMatchMaking", 0x018B6C60u },
                { "open_hud_menu_A", 0x00B10740u },
                { "open_hud_menu_B", 0x00B17250u },
                { "emergencyShutdown_A", 0x0267B2A0u },
                { "emergencyShutdown_B", 0x02689ED0u },
                { "emergencyShutdown_C", 0x026969E0u },
                { "OnGetAnticheatReputation", 0x027E0810u },
                { "OnPopAnticheatMessage", 0x027E66A0u },
                { "OnPushAnticheatMessageToUI", 0x027E6AC0u },
            };

            std::set<std::uintptr_t> targetStarts;
            for (const auto& t : targets)
            {
                DWORD64 imageBase = 0;
                const auto requested = base + t.rva;
                auto* rf = RtlLookupFunctionEntry(static_cast<DWORD64>(requested), &imageBase, nullptr);
                if (rf)
                    targetStarts.insert(static_cast<std::uintptr_t>(imageBase + rf->BeginAddress));
            }

            std::set<std::uintptr_t> parentFunctions;
            for (const auto& sec : sections)
            {
                if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE) || !sec.size ||
                    sec.size > 384ull * 1024ull * 1024ull) continue;

                std::vector<unsigned char> buf(sec.size);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(sec.begin), buf.data(), buf.size(), &got) || got < 5)
                    continue;
                buf.resize(got);

                for (std::size_t i = 0; i + 5 <= buf.size(); ++i)
                {
                    if (buf[i] != 0xE8) continue;
                    std::int32_t rel = 0;
                    std::memcpy(&rel, buf.data() + i + 1, 4);
                    const auto site = sec.begin + i;
                    const auto dest = site + 5 + rel;
                    if (!targetStarts.count(dest)) continue;

                    const auto owner = ContainingFunction(site);
                    if (owner) parentFunctions.insert(owner);
                    if (parentFunctions.size() >= 128) break;
                }
                if (parentFunctions.size() >= 128) break;
            }

            std::ofstream summary("logs\\t8_blackout_beta\\menu_parent_context.csv", std::ios::trunc);
            std::ofstream calls("logs\\t8_blackout_beta\\menu_parent_calls.csv", std::ios::trunc);
            std::ofstream strings("logs\\t8_blackout_beta\\menu_parent_strings.csv", std::ios::trunc);

            summary << "parent_function_rva,function_end_rva,direct_calls,conditional_branches,rip_string_refs\\n";
            calls << "parent_function_rva,call_site_rva,call_target_rva\\n";
            strings << "parent_function_rva,instruction_rva,string_rva,string\\n";

            for (const auto parent : parentFunctions)
            {
                DWORD64 imageBase = 0;
                auto* rf = RtlLookupFunctionEntry(static_cast<DWORD64>(parent), &imageBase, nullptr);
                if (!rf) continue;

                const auto begin = static_cast<std::uintptr_t>(imageBase + rf->BeginAddress);
                const auto end = static_cast<std::uintptr_t>(imageBase + rf->EndAddress);
                if (end <= begin || end - begin > 0x10000) continue;

                std::vector<unsigned char> b(static_cast<std::size_t>(end - begin));
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(begin), b.data(), b.size(), &got) || !got)
                    continue;
                b.resize(got);

                std::size_t directCalls = 0;
                std::size_t branches = 0;
                std::size_t stringRefs = 0;

                for (std::size_t i = 0; i < b.size(); ++i)
                {
                    if (i + 5 <= b.size() && b[i] == 0xE8)
                    {
                        std::int32_t rel = 0;
                        std::memcpy(&rel, b.data() + i + 1, 4);
                        const auto site = begin + i;
                        const auto dest = site + 5 + rel;
                        calls << "0x" << std::hex << std::uppercase << (begin - base)
                              << ",0x" << (site - base)
                              << ",0x" << (dest >= base ? dest - base : 0)
                              << std::dec << "\\n";
                        ++directCalls;
                    }

                    if ((b[i] >= 0x70 && b[i] <= 0x7F) ||
                        (i + 2 <= b.size() && b[i] == 0x0F && b[i+1] >= 0x80 && b[i+1] <= 0x8F))
                        ++branches;

                    if (i + 7 <= b.size() &&
                        (b[i] == 0x48 || b[i] == 0x4C) &&
                        (b[i+1] == 0x8D || b[i+1] == 0x8B) &&
                        ((b[i+2] & 0xC7) == 0x05))
                    {
                        std::int32_t disp = 0;
                        std::memcpy(&disp, b.data() + i + 3, 4);
                        const auto instr = begin + i;
                        const auto addr = instr + 7 + disp;
                        if (addr < base || addr >= base + kImageSize) continue;

                        char s[193]{};
                        SIZE_T sgot = 0;
                        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(addr),
                            s, sizeof(s)-1, &sgot) || sgot < 4)
                            continue;

                        std::size_t len = 0;
                        while (len < sgot && len < sizeof(s)-1 && s[len] >= 0x20 && s[len] <= 0x7E) ++len;
                        if (len < 4) continue;
                        s[len] = 0;

                        std::string escaped(s, len);
                        std::replace(escaped.begin(), escaped.end(), '"', '\'');
                        strings << "0x" << std::hex << std::uppercase << (begin - base)
                                << ",0x" << (instr - base)
                                << ",0x" << (addr - base)
                                << std::dec << ",\"" << escaped << "\"\\n";
                        ++stringRefs;
                    }
                }

                summary << "0x" << std::hex << std::uppercase << (begin - base)
                        << ",0x" << (end - base)
                        << std::dec << "," << directCalls
                        << "," << branches
                        << "," << stringRefs << "\\n";
            }

            static constexpr std::uint32_t threadRvas[] = {
                0x0017D7C0u, 0x02977E10u, 0x036C9AE0u
            };
            std::ofstream threadBytes("logs\\t8_blackout_beta\\thread_entry_bytes.csv", std::ios::trunc);
            threadBytes << "thread_entry_rva,bytes_hex\\n";
            static constexpr char kHex[] = "0123456789ABCDEF";
            for (const auto rva : threadRvas)
            {
                std::array<unsigned char, 512> b{};
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(base + rva), b.data(), b.size(), &got) || !got)
                    continue;

                threadBytes << "0x" << std::hex << std::uppercase << rva << ",\"";
                for (SIZE_T i = 0; i < got; ++i)
                    threadBytes << kHex[b[i] >> 4] << kHex[b[i] & 0xF];
                threadBytes << "\"\\n";
            }
        }


        void WriteStaticScan()
        {
            const auto base = Base();
            g_stage.store(2, std::memory_order_relaxed);
            const auto sections = Sections();
            auto anchors = CollectAnchors(sections);
            std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b){ return a.address < b.address; });
            // Build441 crash isolation: all Lua-specific analysis is disabled.

            fs::create_directories("logs");
            fs::create_directories("logs\\t8_blackout_beta");

            WriteKnownMenuTargets(sections);
            WriteMenuParentContext(sections);

            {
                std::ofstream out("logs\\t8_blackout_beta\\profile.txt", std::ios::trunc);
                std::uint32_t ts=0, sz=0, ep=0;
                ReadPe(ts,sz,ep);
                out << "profile=T8 Black Ops 4 Blackout Beta (Sep 2018)\n";
                out << "moduleBase=0x" << std::hex << std::uppercase << base << "\n";
                out << "timestamp=0x" << ts << "\nimageSize=0x" << sz << "\nentryRva=0x" << ep << "\n";
                out << "fingerprintMatch=" << std::dec << ((ts==kTimestamp && sz==kImageSize && ep==kEntryRva)?1:0) << "\n";
                out << "mode=read-only automatic research\n";
#ifdef CODREVAMPED_T8_BLACKOUT_BETA_PROFILE
                out << "compileProfile=BLACKOUT_BETA_COMPILE_ISOLATED\n";
#else
                out << "compileProfile=unified-runtime\n";
#endif
                out << "note=modern 2023 T8/Shield RVAs are intentionally not used for this beta\n";\
                out << "build452=isolated beta profile; expanded menu parent graph + Arxan/integrity diagnostics; Lua disabled\n\n";
                for (const auto& s : sections)
                    out << s.name << " rva=0x" << std::hex << (s.begin-base) << " size=0x" << s.size << " characteristics=0x" << s.characteristics << "\n";
            }

            std::ofstream strings("logs\\t8_blackout_beta\\anchors.csv", std::ios::trunc);
            strings << "category,string_rva,string\n";
            for (const auto& a : anchors)
            {
                std::string escaped=a.text;
                std::replace(escaped.begin(), escaped.end(), '"', '\'');
                strings << a.category << ",0x" << std::hex << std::uppercase << (a.address-base) << std::dec << ",\"" << escaped << "\"\n";
            }

            std::vector<Section> code;
            for (const auto& s : sections)
                if (s.characteristics & IMAGE_SCN_MEM_EXECUTE) code.push_back(s);

            std::ofstream xrefs("logs\\t8_blackout_beta\\anchor_xrefs.csv", std::ios::trunc);
            std::ofstream gates("logs\\t8_blackout_beta\\gate_candidates.csv", std::ios::trunc);
            std::ofstream watchdog("logs\\t8_blackout_beta\\watchdog_shutdown_candidates.csv", std::ios::trunc);
            xrefs << "category,string_rva,xref_rva,function_rva,string\n";
            gates << "category,string_rva,xref_rva,function_rva,string\n";
            watchdog << "category,string_rva,xref_rva,function_rva,string\n";
            std::size_t xrefCount=0;
            std::vector<MenuFunctionSeed> menuSeeds;
            menuSeeds.reserve(1024);
            g_stage.store(3, std::memory_order_relaxed);
            for (const auto& sec : code)
            {
                std::vector<unsigned char> buf(sec.size);
                SIZE_T got=0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(sec.begin), buf.data(), buf.size(), &got)) continue;
                buf.resize(got);
                for (std::size_t i=0; i+7<=buf.size(); ++i)
                {
                    // Common x64 RIP-relative LEA/MOV forms: 48/4C 8D/8B modrm disp32.
                    const auto b0=buf[i], b1=buf[i+1], b2=buf[i+2];
                    if (!((b0==0x48 || b0==0x4C) && (b1==0x8D || b1==0x8B) && ((b2 & 0xC7)==0x05))) continue;
                    std::int32_t disp=0; std::memcpy(&disp, buf.data()+i+3, 4);
                    const auto instr=sec.begin+i;
                    const auto target=instr+7+disp;
                    auto it=std::lower_bound(anchors.begin(), anchors.end(), target, [](const Anchor& a,std::uintptr_t v){return a.address<v;});
                    if (it==anchors.end() || it->address!=target) continue;
                    const auto fn=ContainingFunction(instr);
                    std::string escaped=it->text; std::replace(escaped.begin(),escaped.end(),'"','\'');
                    xrefs << it->category << ",0x" << std::hex << std::uppercase << (it->address-base)
                          << ",0x" << (instr-base) << ",0x" << (fn?fn-base:0) << std::dec << ",\"" << escaped << "\"\n";
                    if (it->category == "blackout" || it->category == "frontend" || it->category == "dvar_mode" || it->category == "command")
                        gates << it->category << ",0x" << std::hex << std::uppercase << (it->address-base)
                              << ",0x" << (instr-base) << ",0x" << (fn?fn-base:0) << std::dec << ",\"" << escaped << "\"\n";
                    if (it->category == "watchdog_shutdown")
                        watchdog << it->category << ",0x" << std::hex << std::uppercase << (it->address-base)
                                 << ",0x" << (instr-base) << ",0x" << (fn?fn-base:0) << std::dec << ",\"" << escaped << "\"\n";
                    if (fn && IsMenuFlowAnchor(*it) && menuSeeds.size() < 256)
                        menuSeeds.push_back({fn, instr, it->address, it->text});
                    ++xrefCount;
                }
            }

            WriteMenuFlowCallgraph(menuSeeds);

            std::printf("[T8-BLACKOUT] automatic static scan complete: anchors=%llu xrefs=%llu menuSeeds=%llu\n",
                static_cast<unsigned long long>(anchors.size()), static_cast<unsigned long long>(xrefCount),
                static_cast<unsigned long long>(menuSeeds.size()));
            std::fflush(stdout);
        }


        void WriteLuaEngineCandidates(const std::vector<Section>& sections, const std::vector<Anchor>& anchors)
        {
            const auto base = Base();

            struct LuaTarget
            {
                std::uintptr_t address{};
                std::string text;
            };

            std::vector<LuaTarget> targets;
            targets.reserve(256);
            for (const auto& a : anchors)
            {
                if (a.category != "lua_lui") continue;
                const auto l = Lower(a.text);
                if (l.find("bytecode") != std::string::npos ||
                    l.find("lua_state") != std::string::npos ||
                    l.find("lua function") != std::string::npos ||
                    l.find("lua closure") != std::string::npos ||
                    l.find("lua_cfunction") != std::string::npos ||
                    l.find("lua_cod_") != std::string::npos ||
                    l.find("lua error") != std::string::npos ||
                    l.find("lua memory") != std::string::npos ||
                    l.find("luaopen_") != std::string::npos ||
                    l.find("?.lua;") != std::string::npos)
                {
                    targets.push_back({a.address, a.text});
                    if (targets.size() >= 256) break;
                }
            }

            fs::create_directories("logs\\t8_blackout_beta");
            std::ofstream out("logs\\t8_blackout_beta\\lua_engine_candidates.csv", std::ios::trunc);
            out << "anchor,string_rva,xref_rva,function_rva,call_site_rva,call_target_rva\n";
            if (targets.empty()) return;

            std::unordered_map<std::uintptr_t, std::size_t> targetIndex;
            targetIndex.reserve(targets.size() * 2);
            for (std::size_t i = 0; i < targets.size(); ++i)
                targetIndex.emplace(targets[i].address, i);

            struct Match
            {
                std::size_t target{};
                std::uintptr_t xref{};
                std::uintptr_t function{};
            };
            std::vector<Match> matches;
            matches.reserve(1024);

            // IMPORTANT: one pass per executable section. Build436/437 accidentally
            // reread every executable section once per Lua anchor, which was far too
            // expensive for this beta and could terminate the process during startup.
            for (const auto& sec : sections)
            {
                if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                if (!sec.size || sec.size > 384ull * 1024ull * 1024ull) continue;

                std::vector<unsigned char> buf;
                try { buf.resize(sec.size); }
                catch (...) { continue; }

                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(sec.begin),
                    buf.data(), buf.size(), &got) || got < 7) continue;
                buf.resize(got);

                for (std::size_t i = 0; i + 7 <= buf.size(); ++i)
                {
                    const auto b0 = buf[i], b1 = buf[i+1], b2 = buf[i+2];
                    if (!((b0==0x48 || b0==0x4C) && (b1==0x8D || b1==0x8B) && ((b2 & 0xC7)==0x05)))
                        continue;

                    std::int32_t disp = 0;
                    std::memcpy(&disp, buf.data()+i+3, 4);
                    const auto xref = sec.begin+i;
                    const auto target = xref+7+disp;
                    const auto it = targetIndex.find(target);
                    if (it == targetIndex.end()) continue;

                    const auto fn = ContainingFunction(xref);
                    if (!fn) continue;
                    matches.push_back({it->second, xref, fn});
                    if (matches.size() >= 4096) break;
                }
                if (matches.size() >= 4096) break;
            }

            std::set<std::pair<std::size_t,std::uintptr_t>> emittedFns;
            for (const auto& m : matches)
            {
                if (!emittedFns.emplace(m.target, m.function).second) continue;

                const auto& t = targets[m.target];
                DWORD64 imageBase = 0;
                auto* rf = RtlLookupFunctionEntry(static_cast<DWORD64>(m.xref), &imageBase, nullptr);
                if (!rf) continue;

                const auto fnEnd = static_cast<std::uintptr_t>(imageBase + rf->EndAddress);
                if (fnEnd <= m.function) continue;
                const auto walkEnd = (std::min)(fnEnd, m.function + static_cast<std::uintptr_t>(0x4000));
                const auto span = static_cast<std::size_t>(walkEnd - m.function);
                if (!span || span > 0x4000) continue;

                std::vector<unsigned char> fbuf;
                try { fbuf.resize(span); }
                catch (...) { continue; }
                SIZE_T fgot = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(m.function),
                    fbuf.data(), fbuf.size(), &fgot) || !fgot) continue;
                fbuf.resize(fgot);

                std::size_t callsWritten = 0;
                for (std::size_t k=0; k+5<=fbuf.size() && callsWritten<32; ++k)
                {
                    if (fbuf[k] != 0xE8) continue;
                    std::int32_t rel=0;
                    std::memcpy(&rel, fbuf.data()+k+1, 4);
                    const auto site = m.function+k;
                    const auto dest = site+5+rel;

                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(reinterpret_cast<const void*>(dest), &mbi, sizeof(mbi))) continue;
                    const DWORD prot = mbi.Protect & 0xFF;
                    const bool exec = mbi.State==MEM_COMMIT &&
                        (prot==PAGE_EXECUTE || prot==PAGE_EXECUTE_READ ||
                         prot==PAGE_EXECUTE_READWRITE || prot==PAGE_EXECUTE_WRITECOPY);
                    if (!exec) continue;

                    std::string escaped=t.text;
                    std::replace(escaped.begin(),escaped.end(),'"','\'');
                    out << "\"" << escaped << "\",0x" << std::hex << std::uppercase << (t.address-base)
                        << ",0x" << (m.xref-base)
                        << ",0x" << (m.function-base)
                        << ",0x" << (site-base)
                        << ",0x" << (dest-base)
                        << std::dec << "\n";
                    ++callsWritten;
                }

                if (!callsWritten)
                {
                    std::string escaped=t.text;
                    std::replace(escaped.begin(),escaped.end(),'"','\'');
                    out << "\"" << escaped << "\",0x" << std::hex << std::uppercase << (t.address-base)
                        << ",0x" << (m.xref-base)
                        << ",0x" << (m.function-base)
                        << ",0x0,0x0" << std::dec << "\n";
                }
            }
        }

        bool ValidLua51Header(const unsigned char* p, std::size_t n)
        {
            if (!p || n < 12) return false;
            if (!(p[0]==0x1B && p[1]=='L' && p[2]=='u' && p[3]=='a')) return false;
            // T8-era standard Lua candidates are expected to identify a sane Lua
            // bytecode version/format. This rejects random "\x1bLua" collisions.
            const unsigned char version = p[4];
            const unsigned char format = p[5];
            return (version==0x51 || version==0x52 || version==0x53) && format<=1;
        }

        bool ValidLuaJitHeader(const unsigned char* p, std::size_t n)
        {
            if (!p || n < 5) return false;
            if (!(p[0]==0x1B && p[1]=='L' && p[2]=='J')) return false;
            // LuaJIT bytecode version byte is small (v1/v2); 0x9B from Build435
            // was a random collision in high-entropy process memory.
            return p[3]==1 || p[3]==2;
        }

        bool LooksLuaText(const unsigned char* p, std::size_t n)
        {
            if (!p || n < 128) return false;
            std::string_view s(reinterpret_cast<const char*>(p), n);

            // Require CoD/LUI identity, not generic programming/debug strings.
            const bool codUi = s.find("LUI.") != std::string_view::npos ||
                               s.find("Engine.") != std::string_view::npos ||
                               s.find("registerEventHandler") != std::string_view::npos;
            if (!codUi) return false;

            int luaSyntax=0;
            for (auto token : {"function ","local ","require(","require ","return "," then"," end"," = "})
                if (s.find(token)!=std::string_view::npos) ++luaSyntax;

            std::size_t printable=0, newlines=0;
            const auto sample=(std::min<std::size_t>)(n,8192);
            for(std::size_t i=0;i<sample;++i)
            {
                const auto c=p[i];
                if ((c>=0x20&&c<=0x7E)||c=='\r'||c=='\n'||c=='\t') ++printable;
                if (c=='\n') ++newlines;
            }
            const double ratio=sample?static_cast<double>(printable)/static_cast<double>(sample):0.0;
            return luaSyntax>=2 && newlines>=2 && ratio>=0.80;
        }

        void DumpBlob(std::uintptr_t address, const unsigned char* data, std::size_t size, const char* kind)
        {
            std::lock_guard<std::mutex> lock(g_dumpMutex);
            if (!g_dumpedLua.insert(address).second) return;
            fs::create_directories("logs\\t8_blackout_beta\\lua");
            std::ostringstream name;
            name << "logs\\t8_blackout_beta\\lua\\" << kind << "_" << std::hex << std::uppercase << address << ".bin";
            std::ofstream out(name.str(), std::ios::binary | std::ios::trunc);
            if (out) out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
            std::ofstream index("logs\\t8_blackout_beta\\lua_index.csv", std::ios::app);
            if (index) index << kind << ",0x" << std::hex << std::uppercase << address << std::dec << "," << size << "," << name.str() << "\n";
        }

        void ScanLiveLua()
        {
            SYSTEM_INFO si{}; GetSystemInfo(&si);
            auto p=reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
            const auto end=reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
            std::size_t dumps=0;
            while (p<end && dumps<512)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(p), &mbi, sizeof(mbi))) break;
                const auto next=p+mbi.RegionSize;
                const DWORD prot=mbi.Protect & 0xFF;
                const bool readable=mbi.State==MEM_COMMIT && !(mbi.Protect&(PAGE_GUARD|PAGE_NOACCESS)) &&
                    (prot==PAGE_READONLY||prot==PAGE_READWRITE||prot==PAGE_WRITECOPY||prot==PAGE_EXECUTE_READ||prot==PAGE_EXECUTE_READWRITE||prot==PAGE_EXECUTE_WRITECOPY);
                const bool liveDataMapping = mbi.Type==MEM_PRIVATE || mbi.Type==MEM_MAPPED;
                if (readable && liveDataMapping && mbi.RegionSize<=128ull*1024ull*1024ull)
                {
                    constexpr std::size_t chunk=1<<20;
                    std::vector<unsigned char> buf((std::min<std::size_t>)(chunk,mbi.RegionSize));
                    for (std::size_t off=0; off<mbi.RegionSize && dumps<512; off+=chunk)
                    {
                        const auto want=(std::min<std::size_t>)(chunk,mbi.RegionSize-off);
                        if (buf.size()<want) buf.resize(want);
                        SIZE_T got=0;
                        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(p+off), buf.data(), want, &got) || got<16) continue;
                        for (std::size_t i=0;i+8<got;++i)
                        {
                            const auto addr=p+off+i;
                            if (ValidLua51Header(buf.data()+i,got-i))
                            {
                                const auto len=(std::min<std::size_t>)(got-i,256*1024);
                                DumpBlob(addr,buf.data()+i,len,"lua51"); ++dumps; i+=(std::min<std::size_t>)(len,4096);
                            }
                            else if (ValidLuaJitHeader(buf.data()+i,got-i))
                            {
                                const auto len=(std::min<std::size_t>)(got-i,256*1024);
                                DumpBlob(addr,buf.data()+i,len,"luajit"); ++dumps; i+=(std::min<std::size_t>)(len,4096);
                            }
                            else if ((i%4096)==0 && LooksLuaText(buf.data()+i,(std::min<std::size_t>)(got-i,16384)))
                            {
                                const auto len=(std::min<std::size_t>)(got-i,64*1024);
                                DumpBlob(addr,buf.data()+i,len,"lua_text_candidate"); ++dumps;
                            }
                        }
                    }
                }
                if (next<=p) break;
                p=next;
            }
            std::printf("[T8-BLACKOUT] live Lua scan pass complete; total unique dumps=%llu\n", static_cast<unsigned long long>(g_dumpedLua.size()));
            std::fflush(stdout);
        }

        DWORD WINAPI RuntimeObserverWorker(void*)
        {
            std::unordered_set<std::wstring> seenModules;
            std::unordered_set<unsigned long long> seenThreads;

            auto* ntdll = GetModuleHandleW(L"ntdll.dll");
            auto ntQueryThread = ntdll
                ? reinterpret_cast<NtQueryInformationThreadFn>(GetProcAddress(ntdll, "NtQueryInformationThread"))
                : nullptr;

            for (;;)
            {
                const DWORD pid = GetCurrentProcessId();

                HANDLE ms = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
                if (ms != INVALID_HANDLE_VALUE)
                {
                    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
                    if (Module32FirstW(ms, &me))
                    {
                        do
                        {
                            std::wstring key = me.szExePath;
                            key += L"@";
                            key += std::to_wstring(reinterpret_cast<std::uintptr_t>(me.modBaseAddr));
                            if (seenModules.insert(key).second)
                            {
                                char path[1024]{};
                                WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, path, static_cast<int>(sizeof(path)), nullptr, nullptr);
                                FILE* f = nullptr;
                                if (fopen_s(&f, "logs\\t8_blackout_beta\\modules.log", "a") == 0 && f)
                                {
                                    std::fprintf(f, "module=%s base=0x%p size=0x%lX\\n",
                                        path, me.modBaseAddr, me.modBaseSize);
                                    std::fclose(f);
                                }
                            }
                        } while (Module32NextW(ms, &me));
                    }
                    CloseHandle(ms);
                }

                HANDLE ts = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (ts != INVALID_HANDLE_VALUE)
                {
                    THREADENTRY32 te{}; te.dwSize = sizeof(te);
                    if (Thread32First(ts, &te))
                    {
                        do
                        {
                            if (te.th32OwnerProcessID != pid) continue;
                            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                            if (!th) continue;

                            void* start = nullptr;
                            if (ntQueryThread)
                                ntQueryThread(th, 9, &start, sizeof(start), nullptr);
                            CloseHandle(th);

                            const auto startAddr = reinterpret_cast<std::uintptr_t>(start);
                            const unsigned long long key =
                                (static_cast<unsigned long long>(te.th32ThreadID) << 32) ^
                                static_cast<unsigned long long>(startAddr);
                            if (!seenThreads.insert(key).second) continue;

                            FILE* f = nullptr;
                            if (fopen_s(&f, "logs\\t8_blackout_beta\\threads.log", "a") == 0 && f)
                            {
                                const auto base = Base();
                                std::fprintf(f, "tid=%lu start=0x%p start_rva=0x%llX\\n",
                                    te.th32ThreadID, start,
                                    static_cast<unsigned long long>(
                                        startAddr >= base && startAddr < base + kImageSize ? startAddr - base : 0));
                                std::fclose(f);
                            }
                        } while (Thread32Next(ts, &te));
                    }
                    CloseHandle(ts);
                }

                Sleep(2000);
            }
        }

        DWORD WINAPI HeartbeatWorker(void*)
        {
            const ULONGLONG start = GetTickCount64();
            for (;;)
            {
                FILE* f = nullptr;
                if (fopen_s(&f, "logs\\t8_blackout_beta\\heartbeat.log", "a") == 0 && f)
                {
                    const auto alive = GetTickCount64() - start;
                    const auto stage = g_stage.load(std::memory_order_relaxed);
                    std::fprintf(f, "alive_ms=%llu pid=%lu tid=%lu stage=%d(%s)\n",
                        static_cast<unsigned long long>(alive), GetCurrentProcessId(), GetCurrentThreadId(),
                        stage, StageName(stage));
                    std::fflush(f);
                    std::fclose(f);
                }
                Sleep(2000);
            }
        }

        void WriteTinyMenuScan()
        {
            const auto base = Base();
            CreateDirectoryW(L"logs", nullptr);
            CreateDirectoryW(L"logs\\t8_blackout_beta", nullptr);

            struct Target { const char* name; std::uint32_t rva; };
            static constexpr Target targets[] = {
                { "unlockSessionMode", 0x002F24ECu },
                { "playlistEntry", 0x00208D91u },
                { "LobbyVM", 0x018B52E0u },
                { "shutdownMatchMaking", 0x018B6C60u },
                { "open_hud_menu_A", 0x00B10740u },
                { "open_hud_menu_B", 0x00B17250u },
            };

            std::ofstream out("logs\\t8_blackout_beta\\tiny_menu_scan.csv", std::ios::trunc);
            out << "name,requested_rva,function_begin_rva,function_end_rva,direct_calls,conditional_branches,bytes_hex\n";
            static constexpr char kHex[] = "0123456789ABCDEF";

            for (const auto& t : targets)
            {
                const auto requested = base + t.rva;
                DWORD64 imageBase = 0;
                auto* rf = RtlLookupFunctionEntry(static_cast<DWORD64>(requested), &imageBase, nullptr);
                if (!rf)
                {
                    out << t.name << ",0x" << std::hex << std::uppercase << t.rva
                        << ",0x0,0x0,0,0,\"\"\n";
                    continue;
                }

                const auto begin = static_cast<std::uintptr_t>(imageBase + rf->BeginAddress);
                const auto end = static_cast<std::uintptr_t>(imageBase + rf->EndAddress);
                if (end <= begin || end - begin > 0x10000)
                    continue;

                const auto want = (std::min<std::size_t>)(
                    static_cast<std::size_t>(end - begin), 1024u);
                std::vector<unsigned char> b(want);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(begin), b.data(), b.size(), &got) || !got)
                    continue;
                b.resize(got);

                std::size_t calls = 0;
                std::size_t branches = 0;
                for (std::size_t i = 0; i < b.size(); ++i)
                {
                    if (i + 5 <= b.size() && b[i] == 0xE8) ++calls;
                    if ((b[i] >= 0x70 && b[i] <= 0x7F) ||
                        (i + 2 <= b.size() && b[i] == 0x0F &&
                         b[i+1] >= 0x80 && b[i+1] <= 0x8F))
                        ++branches;
                }

                out << t.name
                    << ",0x" << std::hex << std::uppercase << t.rva
                    << ",0x" << (begin - base)
                    << ",0x" << (end - base)
                    << std::dec << "," << calls
                    << "," << branches
                    << ",\"";
                for (const auto v : b)
                    out << kHex[v >> 4] << kHex[v & 0xF];
                out << "\"\n";
            }

            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_blackout_beta\\build455_status.log", "a") == 0 && f)
            {
                std::fprintf(f, "tiny_scan_complete pid=%lu tid=%lu\n",
                    GetCurrentProcessId(), GetCurrentThreadId());
                std::fclose(f);
            }
        }

        DWORD WINAPI Worker(void*)
        {
            CreateDirectoryW(L"logs", nullptr);
            CreateDirectoryW(L"logs\\t8_blackout_beta", nullptr);

            FILE* f = nullptr;
            if (fopen_s(&f, "logs\\t8_blackout_beta\\build455_status.log", "a") == 0 && f)
            {
                std::fprintf(f, "waiting_30_seconds pid=%lu tid=%lu\n",
                    GetCurrentProcessId(), GetCurrentThreadId());
                std::fclose(f);
            }

            Sleep(30000);

            if (fopen_s(&f, "logs\\t8_blackout_beta\\build455_status.log", "a") == 0 && f)
            {
                std::fprintf(f, "starting_tiny_menu_scan\n");
                std::fclose(f);
            }

            WriteTinyMenuScan();
            return 0;
        }
    }

    bool IsSupportedExecutable()
    {
        std::uint32_t ts=0,sz=0,ep=0;
        return ReadPe(ts,sz,ep) && ts==kTimestamp && sz==kImageSize && ep==kEntryRva;
    }

    void StartAutomatic()
    {
        if (g_started.exchange(true)) return;

        // Build455: one delayed worker only.
        // Intentionally no VEH, heartbeat, IAT hooks, module/thread observer,
        // Lua, whole-image string scan, or broad callgraph.
        CreateThread(nullptr, 0, &Worker, nullptr, 0, nullptr);

        std::printf(
            "[T8-BLACKOUT] Build455 delayed tiny menu scanner armed. "
            "No scan work for the first 30 seconds.\n");
        std::fflush(stdout);
    }
}
