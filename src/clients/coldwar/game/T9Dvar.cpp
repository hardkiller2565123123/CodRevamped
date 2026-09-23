#include "T9Dvar.h"
#include "T9Addresses.h"
#include "../../../shared/core/functions.hpp"
#include "../../../shared/core/Main.hpp"
#include "../../../shared/common/utils/MinHook.hpp"
#include <intrin.h>

#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <map>
#include <mutex>
#include <sstream>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>
#include <unordered_set>
#include <cmath>
#include <cfloat>


struct FloatProbeContext
{
    std::uint64_t rcx;
    std::uint64_t rdx;
    std::uint64_t r8;
    std::uint64_t r9;
    std::uint64_t rax;
    std::uint64_t r10;
    std::uint64_t r11;
    std::uint64_t returnAddress;
    float xmm[6][4];
    std::uint64_t stackPointer;
};

extern "C" void* g_FloatProbeOriginal1 = nullptr;
extern "C" void* g_FloatProbeOriginal2 = nullptr;
extern "C" void* g_FloatProbeOriginal3 = nullptr;
extern "C" void FloatProbeDetour1();
extern "C" void FloatProbeDetour2();
extern "C" void FloatProbeDetour3();

namespace
{
    enum class ProbeKind { None, Float, IntEnum, Variant, Vector, Lookup, Command };
    std::atomic_bool g_floatProbeRunning{ false };
    std::atomic_ullong g_floatProbeCalls{ 0 };
    std::atomic_ullong g_floatProbeInteresting{ 0 };
    std::mutex g_floatProbeMutex;
    std::unordered_map<std::string, std::uint64_t> g_floatProbeSeen;

    struct CommandProbePairStats
    {
        std::uint64_t count = 0, changedArgs = 0, stringHits = 0, commandLikeHits = 0;
        std::uint64_t lastRcx = 0, lastRdx = 0, lastR8 = 0, lastR9 = 0;
        bool hasLast = false;
    };
    std::unordered_map<std::string, CommandProbePairStats> g_commandPairStats;
    std::atomic_ullong g_commandStringHits{ 0 };
    std::atomic_ullong g_commandSuppressed{ 0 };

    ProbeKind g_probeKind = ProbeKind::None;
    std::uintptr_t g_probeRvas[3]{};

    const char* ProbeName(ProbeKind kind)
    {
        switch (kind) {
        case ProbeKind::Float: return "FLOAT";
        case ProbeKind::IntEnum: return "INT";
        case ProbeKind::Variant: return "VARIANT";
        case ProbeKind::Vector: return "VECTOR";
        case ProbeKind::Lookup: return "LOOKUP";
        case ProbeKind::Command: return "COMMAND";
        default: return "PROBE";
        }
    }

    const char* ProbeFile(ProbeKind kind)
    {
        switch (kind) {
        case ProbeKind::Float: return "logs\\scanner\\float_probe.csv";
        case ProbeKind::IntEnum: return "logs\\scanner\\int_probe.csv";
        case ProbeKind::Variant: return "logs\\scanner\\variant_probe.csv";
        case ProbeKind::Vector: return "logs\\scanner\\vector_probe.csv";
        case ProbeKind::Lookup: return "logs\\scanner\\lookup_probe.csv";
        case ProbeKind::Command: return "logs\\scanner\\command_probe.csv";
        default: return "logs\\scanner\\dvar_probe.csv";
        }
    }

    bool TryReadAsciiProbeString(std::uint64_t address, char* out, std::size_t outSize)
    {
        if (!address || !out || outSize < 2) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return false;
        __try
        {
            std::size_t n = 0;
            const char* src = reinterpret_cast<const char*>(address);
            for (; n + 1 < outSize; ++n)
            {
                const unsigned char c = static_cast<unsigned char>(src[n]);
                if (!c) break;
                if (c < 0x20 || c > 0x7E) return false;
                out[n] = static_cast<char>(c);
            }
            out[n] = 0;
            return n >= 2 && n < outSize - 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            out[0] = 0;
            return false;
        }
    }

    const char* ProbeMemoryClass(std::uint64_t address, std::uintptr_t gameBase)
    {
        if (!address) return "NULL";
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) return "INVALID";
        if (gameBase)
        {
            MEMORY_BASIC_INFORMATION gameMbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(gameBase), &gameMbi, sizeof(gameMbi)) &&
                mbi.AllocationBase == gameMbi.AllocationBase)
                return "GAME";
        }
        if (mbi.Type == MEM_IMAGE) return "IMAGE";
        if (mbi.Type == MEM_MAPPED) return "MAPPED";
        if (mbi.Type == MEM_PRIVATE) return "PRIVATE";
        return "OTHER";
    }

    std::string CsvEscapeProbe(const char* text)
    {
        if (!text || !*text) return {};
        std::string out = "\"";
        for (const char* q = text; *q; ++q) { if (*q == '"') out += "\"\""; else out += *q; }
        out += '"';
        return out;
    }

    bool IsCommandLikeText(const char* text)
    {
        if (!text || !*text) return false;
        std::string v(text);
        for (char& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        // Explicitly ignore the UI/input/localization strings that dominated the
        // last capture; they are useful anchors but not command evidence.
        static const char* kIgnore[] = {
            "keyarrow", "space", "ui_contextual", "ui_confirm", "^s", "^bkey", "[{ui_"
        };
        for (const char* k : kIgnore)
            if (v.find(k) != std::string::npos) return false;

        static const char* kCommandTokens[] = {
            "exec", "disconnect", "map", "devmap", "quit", "set ", "seta ",
            "bind", "unbind", "toggle", "reset", "vstr", "wait", "echo",
            "cg_", "com_", "r_", "ui_", "cl_", "sv_", "g_", "dvar",
            "cmd", "cbuf"
        };
        for (const char* k : kCommandTokens)
            if (v.find(k) != std::string::npos) return true;
        return false;
    }

    std::uintptr_t TryGetParentReturnAddress(const FloatProbeContext*)
    {
        // Disabled for stability. Walking arbitrary stack slots from a hot entry
        // probe caused faults on worker threads with nonstandard/temporary frames.
        // We keep caller_rva, which is captured safely from the real return address.
        return 0;
    }

    void WriteCommandProbeSummary()
    {
        CreateDirectoryA("logs", nullptr);
        std::ofstream file("logs\\scanner\\command_probe_summary.csv", std::ios::trunc);
        if (!file) return;
        file << "target_rva,caller_rva,count,changed_args,string_hits,command_like_hits\n";
        std::lock_guard<std::mutex> lock(g_floatProbeMutex);
        for (const auto& item : g_commandPairStats)
        {
            const auto sep = item.first.find(':');
            const std::string target = sep == std::string::npos ? item.first : item.first.substr(0, sep);
            const std::string caller = sep == std::string::npos ? "" : item.first.substr(sep + 1);
            file << target << ',' << caller << ',' << item.second.count << ','
                 << item.second.changedArgs << ',' << item.second.stringHits << ','
                 << item.second.commandLikeHits << "\n";
        }
    }

    void WriteCommandParentHints()
    {
        CreateDirectoryA("logs", nullptr);
        std::ifstream in("logs\\scanner\\command_probe.csv");
        std::ofstream out("logs\\scanner\\command_parent_hints.csv", std::ios::trunc);
        if (!out) return;
        out << "note\n";
        out << "\"Review COMMAND_LIKE rows in command_probe.csv; parent_rva is the caller-of-caller candidate to prioritize next.\"\n";
    }

    bool IsInterestingForProbe(ProbeKind kind, const FloatProbeContext* ctx, const float* values)
    {
        if (kind == ProbeKind::Lookup || kind == ProbeKind::Command)
            return ctx->rcx || ctx->rdx || ctx->r8 || ctx->r9;
        if (kind == ProbeKind::IntEnum)
            return ctx->rdx <= 0x100000 || ctx->r8 <= 0x100000 || ctx->r9 <= 0x100000;
        if (kind == ProbeKind::Vector)
            return std::isfinite(values[2]) && std::isfinite(values[3]) &&
                (values[2] != 0.0f || values[3] != 0.0f || values[4] != 0.0f || values[5] != 0.0f);
        if (kind == ProbeKind::Variant)
            return true;
        for (int i = 0; i < 8; ++i)
            if (std::isfinite(values[i]) && values[i] >= -10000.0f && values[i] <= 10000.0f)
                return true;
        return false;
    }

    void RecordFloatProbe(unsigned index, const FloatProbeContext* ctx)
    {
        if (!g_floatProbeRunning.load() || !ctx || index >= 3 || g_probeKind == ProbeKind::None) return;
        ++g_floatProbeCalls;

        float values[8]{};
        std::memcpy(&values[0], &ctx->rdx, sizeof(float));
        std::memcpy(&values[1], &ctx->r8, sizeof(float));
        values[2] = ctx->xmm[0][0]; values[3] = ctx->xmm[1][0];
        values[4] = ctx->xmm[2][0]; values[5] = ctx->xmm[3][0];
        values[6] = ctx->xmm[4][0]; values[7] = ctx->xmm[5][0];
        if (!IsInterestingForProbe(g_probeKind, ctx, values)) return;

        const auto base = g_Addrs.ModuleBase;
        const auto callerRva = base && ctx->returnAddress >= base ? ctx->returnAddress - base : 0;

        if (g_probeKind == ProbeKind::Command)
        {
            char rcxText[160]{}, rdxText[160]{}, r8Text[160]{}, r9Text[160]{};
            const bool rcxString = TryReadAsciiProbeString(ctx->rcx, rcxText, sizeof(rcxText));
            const bool rdxString = TryReadAsciiProbeString(ctx->rdx, rdxText, sizeof(rdxText));
            const bool r8String = TryReadAsciiProbeString(ctx->r8, r8Text, sizeof(r8Text));
            const bool r9String = TryReadAsciiProbeString(ctx->r9, r9Text, sizeof(r9Text));
            const bool hasString = rcxString || rdxString || r8String || r9String;
            const bool commandLike =
                (rcxString && IsCommandLikeText(rcxText)) ||
                (rdxString && IsCommandLikeText(rdxText)) ||
                (r8String && IsCommandLikeText(r8Text)) ||
                (r9String && IsCommandLikeText(r9Text));

            const auto parentReturn = TryGetParentReturnAddress(ctx);
            const auto parentCallerRva = static_cast<std::uintptr_t>(0);

            char pairKey[96]{};
            std::snprintf(pairKey, sizeof(pairKey), "0x%llX:0x%llX",
                static_cast<unsigned long long>(g_probeRvas[index]),
                static_cast<unsigned long long>(callerRva));

            std::uint64_t pairCount = 0, changedCount = 0;
            bool argsChanged = false;
            {
                std::lock_guard<std::mutex> lock(g_floatProbeMutex);
                auto& stats = g_commandPairStats[pairKey];
                ++stats.count;
                pairCount = stats.count;
                if (stats.hasLast)
                {
                    argsChanged = stats.lastRcx != ctx->rcx || stats.lastRdx != ctx->rdx ||
                                  stats.lastR8 != ctx->r8 || stats.lastR9 != ctx->r9;
                    if (argsChanged) ++stats.changedArgs;
                }
                else argsChanged = true;
                if (hasString) ++stats.stringHits;
                if (commandLike) ++stats.commandLikeHits;
                changedCount = stats.changedArgs;
                stats.lastRcx = ctx->rcx; stats.lastRdx = ctx->rdx;
                stats.lastR8 = ctx->r8; stats.lastR9 = ctx->r9; stats.hasLast = true;
            }

            if (hasString) ++g_commandStringHits;
            const bool periodic = (pairCount % 1000) == 0;
            const bool early = pairCount <= 4;
            const bool changedSample = argsChanged && pairCount <= 64;
            if (!(commandLike || hasString || early || changedSample || periodic))
            {
                ++g_commandSuppressed;
                return;
            }

            ++g_floatProbeInteresting;
            const char* rcxClass = ProbeMemoryClass(ctx->rcx, base);
            const char* rdxClass = ProbeMemoryClass(ctx->rdx, base);
            const char* r8Class = ProbeMemoryClass(ctx->r8, base);
            const char* r9Class = ProbeMemoryClass(ctx->r9, base);
            const char* classification = commandLike ? "COMMAND_LIKE" :
                (hasString ? "STRING_CANDIDATE" :
                (periodic ? "PERIODIC_NOISE" : (argsChanged ? "ARG_CHANGE" : "NO_STRING")));

            std::printf("[COMMAND-PROBE] class=%s target=0x%llX caller_rva=0x%llX parent_rva=0x%llX count=%llu changed=%llu "
                        "rcx=%p(%s) rdx=0x%llX(%s) r8=0x%llX(%s) r9=0x%llX(%s)",
                classification, static_cast<unsigned long long>(g_probeRvas[index]),
                static_cast<unsigned long long>(callerRva), static_cast<unsigned long long>(parentCallerRva),
                static_cast<unsigned long long>(pairCount),
                static_cast<unsigned long long>(changedCount), reinterpret_cast<void*>(ctx->rcx), rcxClass,
                static_cast<unsigned long long>(ctx->rdx), rdxClass,
                static_cast<unsigned long long>(ctx->r8), r8Class,
                static_cast<unsigned long long>(ctx->r9), r9Class);
            if (rcxString) std::printf(" rcx_text=\"%s\"", rcxText);
            if (rdxString) std::printf(" rdx_text=\"%s\"", rdxText);
            if (r8String) std::printf(" r8_text=\"%s\"", r8Text);
            if (r9String) std::printf(" r9_text=\"%s\"", r9Text);
            std::printf("\n");
            std::fflush(stdout);

            CreateDirectoryA("logs", nullptr);
            const char* path = ProbeFile(g_probeKind);
            const bool header = GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
            std::ofstream file(path, std::ios::app);
            if (!file) return;
            if (header)
                file << "probe,target_rva,caller,caller_rva,parent_rva,pair_count,args_changed_count,classification,"
                        "rcx,rcx_class,rcx_string,rdx,rdx_class,rdx_string,r8,r8_class,r8_string,"
                        "r9,r9_class,r9_string,xmm0,xmm1,xmm2,xmm3\n";
            file << "COMMAND,0x" << std::hex << std::uppercase << g_probeRvas[index]
                 << ",0x" << ctx->returnAddress << ",0x" << callerRva
                 << ",0x" << parentCallerRva << std::dec
                 << ',' << pairCount << ',' << changedCount << ',' << classification
                 << ",0x" << std::hex << ctx->rcx << std::dec << ',' << rcxClass << ',' << CsvEscapeProbe(rcxText)
                 << ",0x" << std::hex << ctx->rdx << std::dec << ',' << rdxClass << ',' << CsvEscapeProbe(rdxText)
                 << ",0x" << std::hex << ctx->r8 << std::dec << ',' << r8Class << ',' << CsvEscapeProbe(r8Text)
                 << ",0x" << std::hex << ctx->r9 << std::dec << ',' << r9Class << ',' << CsvEscapeProbe(r9Text)
                 << ',' << values[2] << ',' << values[3] << ',' << values[4] << ',' << values[5] << "\n";
            return;
        }

        char key[320]{};
        std::snprintf(key, sizeof(key), "%u:%d:%llX:%llX:%llX:%llX:%08X:%08X:%08X:%08X", index,
            static_cast<int>(g_probeKind), static_cast<unsigned long long>(ctx->rcx),
            static_cast<unsigned long long>(ctx->rdx), static_cast<unsigned long long>(ctx->r8),
            static_cast<unsigned long long>(callerRva), *reinterpret_cast<std::uint32_t*>(&values[2]),
            *reinterpret_cast<std::uint32_t*>(&values[3]), *reinterpret_cast<std::uint32_t*>(&values[4]),
            *reinterpret_cast<std::uint32_t*>(&values[5]));
        {
            std::lock_guard<std::mutex> lock(g_floatProbeMutex);
            auto& count = g_floatProbeSeen[key];
            ++count;
            if (count > 1 && (count % 500) != 0) return;
        }
        ++g_floatProbeInteresting;
        std::printf("[%s-PROBE] target=0x%llX caller_rva=0x%llX rcx=%p rdx=0x%llX r8=0x%llX r9=0x%llX xmm0=%g xmm1=%g xmm2=%g xmm3=%g\n",
            ProbeName(g_probeKind), static_cast<unsigned long long>(g_probeRvas[index]),
            static_cast<unsigned long long>(callerRva), reinterpret_cast<void*>(ctx->rcx),
            static_cast<unsigned long long>(ctx->rdx), static_cast<unsigned long long>(ctx->r8),
            static_cast<unsigned long long>(ctx->r9), values[2], values[3], values[4], values[5]);
        std::fflush(stdout);

        CreateDirectoryA("logs", nullptr);
        const char* path = ProbeFile(g_probeKind);
        const bool header = GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
        std::ofstream file(path, std::ios::app);
        if (!file) return;
        if (header) file << "probe,target_rva,caller,caller_rva,rcx,rdx,r8,r9,rdx_float,r8_float,xmm0,xmm1,xmm2,xmm3,xmm4,xmm5\n";
        file << ProbeName(g_probeKind) << ",0x" << std::hex << std::uppercase << g_probeRvas[index] << ",0x" << ctx->returnAddress
             << ",0x" << callerRva << ",0x" << ctx->rcx << ",0x" << ctx->rdx << ",0x" << ctx->r8
             << ",0x" << ctx->r9 << std::dec << ',' << values[0] << ',' << values[1] << ',' << values[2]
             << ',' << values[3] << ',' << values[4] << ',' << values[5] << ',' << values[6] << ',' << values[7] << "\n";
    }
}

extern "C" void FloatProbeRecord1(const FloatProbeContext* ctx) { RecordFloatProbe(0, ctx); }
extern "C" void FloatProbeRecord2(const FloatProbeContext* ctx) { RecordFloatProbe(1, ctx); }
extern "C" void FloatProbeRecord3(const FloatProbeContext* ctx) { RecordFloatProbe(2, ctx); }

namespace t9_dvars
{
    namespace
    {
        int DvarStatusPrintf(const char* format, ...)
        {
            if (!format)
                return -1;

            va_list args;
            va_start(args, format);
            const int result = vfprintf(stdout, format, args);
            va_end(args);
            fflush(stdout);
            return result;
        }

        std::mutex g_mutex;
        std::map<std::string, Entry> g_entries;
        std::atomic_bool g_liveCaptureRunning{ false };
        std::atomic_bool g_liveCaptureStop{ false };
        std::atomic_ullong g_liveCapturePasses{ 0 };
        std::atomic_ullong g_liveCaptureResolved{ 0 };
        std::atomic_ullong g_liveCaptureEvents{ 0 };
        std::mutex g_liveCaptureFileMutex;
        std::uint64_t g_captureSessionId = 0;

        std::uint64_t MakeCaptureSessionId()
        {
            FILETIME ft{};
            GetSystemTimeAsFileTime(&ft);
            ULARGE_INTEGER value{};
            value.LowPart = ft.dwLowDateTime;
            value.HighPart = ft.dwHighDateTime;
            return (value.QuadPart ^ (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32));
        }

        std::string CsvEscape(std::string value);

        using DvarSetBoolFn = void(*)(std::uintptr_t, bool, int);
        using DvarSetStringFn = void(*)(std::uintptr_t, const char*, int);
        DvarSetBoolFn g_originalSetBool = nullptr;
        DvarSetStringFn g_originalSetString = nullptr;
        std::atomic_bool g_setterHooksInstalled{ false };
        std::atomic_bool g_boolHookInstalled{ false };
        std::atomic_bool g_stringHookInstalled{ false };
        std::atomic_bool g_engineHooksInstalled{ false };
        std::atomic_bool g_findVarHookInstalled{ false };
        std::atomic_bool g_registerIntHookInstalled{ false };
        std::atomic_bool g_setIntHookInstalled{ false };
        std::atomic_bool g_setVariantHookInstalled{ false };
        std::atomic_bool g_commandRegisterHookInstalled{ false };
        std::atomic_bool g_discoveryComplete{ false };
        std::atomic_ullong g_discoveryCallsites{ 0 };
        std::atomic_ullong g_discoveryTargets{ 0 };
        std::mutex g_engineEventMutex;

        struct SetterTrack
        {
            std::uint32_t stableId = 0;
            std::uintptr_t dvarAddress = 0;
            std::string lastValue;
            std::uint64_t totalCalls = 0;
            std::uint64_t changedCalls = 0;
            std::uint64_t suppressedCalls = 0;
            std::unordered_map<std::uintptr_t, std::uint64_t> callerCounts;
            std::chrono::steady_clock::time_point lastSummary{};
            std::uintptr_t allocationBase = 0;
        };

        std::mutex g_setterTrackMutex;
        std::unordered_map<std::string, SetterTrack> g_setterTracks;
        std::atomic_uint32_t g_nextStableDvarId{ 1 };
        std::mutex g_settingChangeMutex;
        std::uint64_t g_nextSettingGroupId = 1;
        std::uint64_t g_activeSettingGroupId = 0;
        std::chrono::steady_clock::time_point g_lastSettingChange{};
        constexpr auto kSettingGroupWindow = std::chrono::milliseconds(750);

        std::mutex g_labelMutex;
        std::unordered_map<std::uint64_t, std::string> g_manualLabelsByRva;

        std::string BuiltinSettingLabel(std::uint64_t dvarRva, std::uint64_t callerRva)
        {
            switch (dvarRva)
            {
            case 0x0EBBEA80: return "window";
            case 0x0EBB7C00: return "mute_sound";
            case 0x0EB82280: return "voice_chat_enabled";
            case 0x0EB82580: return "microphone_activation";
            case 0x0EBB7AC0: return "subtitles";
            case 0x0EB7FF80: return "intro_movie";
            default: break;
            }
            switch (callerRva)
            {
            case 0x0B74217F: return "window";
            case 0x09ED28D0: return "voice_chat_enabled";
            default: return {};
            }
        }

        void LoadManualLabels()
        {
            std::lock_guard<std::mutex> lock(g_labelMutex);
            g_manualLabelsByRva.clear();
            std::ifstream file("logs\\scanner\\dvar_labels.csv");
            std::string line;
            if (!file || !std::getline(file, line)) return;
            while (std::getline(file, line))
            {
                const auto comma = line.find(',');
                if (comma == std::string::npos) continue;
                try
                {
                    const std::uint64_t rva = std::stoull(line.substr(0, comma), nullptr, 0);
                    std::string label = line.substr(comma + 1);
                    if (!label.empty() && label.front() == '"' && label.back() == '"')
                        label = label.substr(1, label.size() - 2);
                    if (!label.empty()) g_manualLabelsByRva[rva] = label;
                }
                catch (...) {}
            }
        }

        void SaveManualLabelsUnlocked()
        {
            CreateDirectoryA("logs", nullptr);
            std::ofstream file("logs\\scanner\\dvar_labels.csv", std::ios::trunc);
            if (!file) return;
            file << "dvar_rva,label\n";
            for (const auto& item : g_manualLabelsByRva)
                file << "0x" << std::hex << std::uppercase << item.first << std::dec << ",\"" << CsvEscape(item.second) << "\"\n";
        }

        std::set<std::uint64_t> g_seenFindHashes;
        std::set<std::uint64_t> g_seenRegisteredHashes;
        std::set<std::uint64_t> g_seenCommandHashes;

        using DvarFindVarFn = dvar_t*(*)(__int64);
        using DvarRegisterIntFn = const dvar_t*(*)(__int64, const char*, int, int, int, unsigned int);
        using DvarSetIntFn = void(*)(dvar_t*, int, int);
        using DvarSetVariantFn = void(*)(dvar_t*, DvarValue, int);
        using CmdAddCommandInternalFn = void(*)(__int64, xcommand_t, cmd_function_t*);

        DvarFindVarFn g_originalFindVar = nullptr;
        DvarRegisterIntFn g_originalRegisterInt = nullptr;
        DvarSetIntFn g_originalSetInt = nullptr;
        DvarSetVariantFn g_originalSetVariant = nullptr;
        CmdAddCommandInternalFn g_originalCmdAddCommandInternal = nullptr;

        bool IsExecutableAddress(std::uintptr_t address)
        {
            if (!address) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return false;
            const DWORD p = mbi.Protect & 0xFF;
            return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        void AppendEngineEvent(const char* kind, std::uint64_t hash, std::uintptr_t object, const char* value, std::uintptr_t caller)
        {
            if (!g_liveCaptureRunning.load()) return;
            const auto base = g_Addrs.ModuleBase;
            const auto rva = base && caller >= base ? caller - base : 0;
            DvarStatusPrintf("[ENGINE-HOOK] %s hash=0x%llX object=%p value=\"%s\" caller=%p rva=0x%llX\n",
                kind, static_cast<unsigned long long>(hash), reinterpret_cast<void*>(object), value ? value : "",
                reinterpret_cast<void*>(caller), static_cast<unsigned long long>(rva));
            CreateDirectoryA("logs", nullptr);
            std::lock_guard<std::mutex> lock(g_liveCaptureFileMutex);
            const char* path = "logs\\scanner\\live_engine_hooks.csv";
            const bool header = GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
            std::ofstream file(path, std::ios::app);
            if (!file) return;
            if (header) file << "session_id,kind,hash,object,value,caller,caller_rva\n";
            file << "0x" << std::hex << std::uppercase << g_captureSessionId << std::dec << ",\"" << kind << "\",0x" << std::hex << std::uppercase << hash << ",0x" << object
                 << ",\"" << CsvEscape(value ? value : "") << "\",0x" << caller << ",0x" << rva << std::dec << "\n";
            file.flush();
            ++g_liveCaptureEvents;
        }

        dvar_t* DvarFindVarDetour(__int64 hash)
        {
            dvar_t* result = g_originalFindVar ? g_originalFindVar(hash) : nullptr;
            if (g_liveCaptureRunning.load() && result)
            {
                std::lock_guard<std::mutex> lock(g_engineEventMutex);
                if (g_seenFindHashes.insert(static_cast<std::uint64_t>(hash)).second)
                    AppendEngineEvent("Dvar_FindVar", static_cast<std::uint64_t>(hash), reinterpret_cast<std::uintptr_t>(result), "resolved", reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
            }
            return result;
        }

        const dvar_t* DvarRegisterIntDetour(__int64 hash, const char* name, int value, int min, int max, unsigned int flags)
        {
            const dvar_t* result = g_originalRegisterInt ? g_originalRegisterInt(hash, name, value, min, max, flags) : nullptr;
            char details[256]{};
            std::snprintf(details, sizeof(details), "name=%s value=%d min=%d max=%d flags=0x%X", name ? name : "<hashed>", value, min, max, flags);
            AppendEngineEvent("Dvar_RegisterInt", static_cast<std::uint64_t>(hash), reinterpret_cast<std::uintptr_t>(result), details, reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
            return result;
        }

        void DvarSetIntDetour(dvar_t* dvar, int value, int source)
        {
            char details[96]{}; std::snprintf(details, sizeof(details), "%d source=%d", value, source);
            AppendEngineEvent("Dvar_SetInt", 0, reinterpret_cast<std::uintptr_t>(dvar), details, reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
            if (g_originalSetInt) g_originalSetInt(dvar, value, source);
        }

        void DvarSetVariantDetour(dvar_t* dvar, DvarValue value, int source)
        {
            char details[128]{};
            std::snprintf(details, sizeof(details), "encrypted=0x%llX source=%d", static_cast<unsigned long long>(value.encrypted), source);
            AppendEngineEvent("Dvar_SetVariant", 0, reinterpret_cast<std::uintptr_t>(dvar), details, reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
            if (g_originalSetVariant) g_originalSetVariant(dvar, value, source);
        }

        void CmdAddCommandInternalDetour(__int64 hash, xcommand_t function, cmd_function_t* command)
        {
            char details[160]{}; std::snprintf(details, sizeof(details), "function=%p node=%p", reinterpret_cast<void*>(function), command);
            {
                std::lock_guard<std::mutex> lock(g_engineEventMutex);
                if (g_seenCommandHashes.insert(static_cast<std::uint64_t>(hash)).second)
                    AppendEngineEvent("Cmd_AddCommandInternal", static_cast<std::uint64_t>(hash), reinterpret_cast<std::uintptr_t>(command), details, reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
            }
            if (g_originalCmdAddCommandInternal) g_originalCmdAddCommandInternal(hash, function, command);
        }

        __declspec(noinline) bool SafeReadBytes(std::uintptr_t address, unsigned char* output, std::size_t size) noexcept
        {
            if (!address || !output || !size) return false;
            __try
            {
                std::memcpy(output, reinterpret_cast<const void*>(address), size);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        std::string PrintableRuns(const unsigned char* data, std::size_t size)
        {
            std::string result;
            std::string current;
            for (std::size_t i = 0; i < size; ++i)
            {
                const unsigned char c = data[i];
                if (c >= 32 && c <= 126)
                {
                    current.push_back(static_cast<char>(c));
                }
                else
                {
                    if (current.size() >= 4)
                    {
                        if (!result.empty()) result += " | ";
                        result += current;
                    }
                    current.clear();
                }
            }
            if (current.size() >= 4)
            {
                if (!result.empty()) result += " | ";
                result += current;
            }
            if (result.size() > 512) result.resize(512);
            return result;
        }

        void InspectNewDvarPointer(std::uint32_t stableId, std::uintptr_t dvar, const char* setter,
            const char* value, std::uintptr_t caller)
        {
            constexpr std::size_t kBefore = 0x80;
            constexpr std::size_t kSize = 0x180;
            unsigned char bytes[kSize]{};
            const std::uintptr_t start = dvar > kBefore ? dvar - kBefore : dvar;
            MEMORY_BASIC_INFORMATION mbi{};
            VirtualQuery(reinterpret_cast<void*>(dvar), &mbi, sizeof(mbi));
            const bool readable = SafeReadBytes(start, bytes, sizeof(bytes));
            const std::string strings = readable ? PrintableRuns(bytes, sizeof(bytes)) : std::string{};

            CreateDirectoryA("logs", nullptr);
            std::lock_guard<std::mutex> lock(g_liveCaptureFileMutex);
            const char* path = "logs\\scanner\\dvar_pointer_inspection.csv";
            const bool header = GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
            std::ofstream file(path, std::ios::app);
            if (!file) return;
            if (header)
                file << "session_id,stable_id,setter,dvar_address,allocation_base,region_size,value,caller,caller_rva,printable_strings,readable\n";
            const auto base = g_Addrs.ModuleBase;
            const auto rva = base && caller >= base ? caller - base : 0;
            file << "0x" << std::hex << std::uppercase << g_captureSessionId << std::dec << ',' << stableId
                 << ",\"" << CsvEscape(setter ? setter : "") << "\",0x" << std::hex << std::uppercase << dvar
                 << ",0x" << reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) << ",0x" << mbi.RegionSize
                 << ",\"" << CsvEscape(value ? value : "") << "\",0x" << caller << ",0x" << rva << std::dec
                 << ",\"" << CsvEscape(strings) << "\"," << (readable ? 1 : 0) << "\n";
        }

        std::string GuessSettingLabel(const char* setter, const char* value, std::uint32_t stableId,
            std::uintptr_t dvar, std::uint64_t callerRva)
        {
            const auto base = g_Addrs.ModuleBase;
            const std::uint64_t dvarRva = base && dvar >= base ? dvar - base : 0;
            {
                std::lock_guard<std::mutex> lock(g_labelMutex);
                const auto it = g_manualLabelsByRva.find(dvarRva);
                if (it != g_manualLabelsByRva.end()) return it->second;
            }
            const std::string builtin = BuiltinSettingLabel(dvarRva, callerRva);
            if (!builtin.empty()) return builtin;
            const std::string v = value ? value : "";
            if (setter && std::strstr(setter, "String"))
            {
                if (v.rfind("mp_", 0) == 0 || v.rfind("zm_", 0) == 0 || v.rfind("cp_", 0) == 0) return "map_or_mode";
                if (v == "tdm" || v == "dom" || v == "dm" || v == "hardpoint" || v == "ctf") return "gametype";
                if (v.find("System Device") != std::string::npos) return "audio_device";
                if (v == "frontend" || v == "core_frontend") return "frontend_state";
                if (v == "Revampedplayer" || v == "T9Player" || v == "Player1") return "player_name";
            }
            char fallback[48]{};
            std::snprintf(fallback, sizeof(fallback), "UnknownSetting#%04u", stableId);
            return fallback;
        }

        std::string CaptureShortBacktrace()
        {
            void* frames[8]{};
            const USHORT count = RtlCaptureStackBackTrace(1, 8, frames, nullptr);
            std::ostringstream out;
            for (USHORT i = 0; i < count; ++i)
            {
                const auto address = reinterpret_cast<std::uintptr_t>(frames[i]);
                const auto base = g_Addrs.ModuleBase;
                const auto rva = base && address >= base ? address - base : 0;
                if (i) out << '|';
                out << "0x" << std::hex << std::uppercase << address;
                if (rva) out << "(rva=0x" << rva << ')';
            }
            return out.str();
        }

        std::uint64_t AllocateSettingGroup(bool& newGroup)
        {
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(g_settingChangeMutex);
            newGroup = !g_activeSettingGroupId || g_lastSettingChange.time_since_epoch().count() == 0 || now - g_lastSettingChange > kSettingGroupWindow;
            if (newGroup) g_activeSettingGroupId = g_nextSettingGroupId++;
            g_lastSettingChange = now;
            return g_activeSettingGroupId;
        }

        void AppendSettingChange(std::uint64_t groupId, bool newGroup, std::uint32_t stableId,
            const char* setter, std::uintptr_t dvar, const std::string& oldValue, const char* newValue,
            std::uintptr_t caller, std::uint64_t callerRva, std::uint64_t totalCalls, std::uint64_t suppressedCalls)
        {
            const std::string label = GuessSettingLabel(setter, newValue, stableId, dvar, callerRva);
            const std::string stack = CaptureShortBacktrace();
            const char* confidence = suppressedCalls < 8 ? "high" : (suppressedCalls < 100 ? "medium" : "low");
            if (newGroup) DvarStatusPrintf("[SETTING-CHANGE] group=%llu started\n", static_cast<unsigned long long>(groupId));
            DvarStatusPrintf("[SETTING-CHANGE] group=%llu %s DVAR#%04u old=\"%s\" new=\"%s\" confidence=%s caller_rva=0x%llX\n",
                static_cast<unsigned long long>(groupId), label.c_str(), stableId, oldValue.c_str(), newValue ? newValue : "", confidence,
                static_cast<unsigned long long>(callerRva));

            CreateDirectoryA("logs", nullptr);
            std::lock_guard<std::mutex> fileLock(g_liveCaptureFileMutex);
            const char* path = "logs\\scanner\\setting_changes.csv";
            const bool header = GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
            std::ofstream file(path, std::ios::app);
            if (file)
            {
                if (header) file << "session_id,group_id,stable_id,possible_label,confidence,setter,dvar_address,old_value,new_value,caller,caller_rva,total_calls,suppressed_calls,stack\n";
                file << "0x" << std::hex << std::uppercase << g_captureSessionId << std::dec << ',' << groupId << ',' << stableId
                     << ",\"" << CsvEscape(label) << "\",\"" << confidence << "\",\"" << CsvEscape(setter ? setter : "")
                     << "\",0x" << std::hex << std::uppercase << dvar << ",\"" << CsvEscape(oldValue) << "\",\""
                     << CsvEscape(newValue ? newValue : "") << "\",0x" << caller << ",0x" << callerRva << std::dec
                     << ',' << totalCalls << ',' << suppressedCalls << ",\"" << CsvEscape(stack) << "\"\n";
                file.flush();
            }
            const char* groupsPath = "logs\\scanner\\setting_change_groups.csv";
            const bool groupsHeader = GetFileAttributesA(groupsPath) == INVALID_FILE_ATTRIBUTES;
            std::ofstream groups(groupsPath, std::ios::app);
            if (groups)
            {
                if (groupsHeader) groups << "session_id,group_id,event,stable_id,possible_label,confidence,caller_rva\n";
                groups << "0x" << std::hex << std::uppercase << g_captureSessionId << std::dec << ',' << groupId << ','
                       << (newGroup ? "group_start" : "related_change") << ',' << stableId << ",\"" << CsvEscape(label)
                       << "\",\"" << confidence << "\",0x" << std::hex << std::uppercase << callerRva << std::dec << "\n";
                groups.flush();
            }
        }

        void AppendSetterEvent(const char* setter, std::uintptr_t dvar, const char* value, int source, std::uintptr_t caller)
        {
            if (!g_liveCaptureRunning.load())
                return;

            const char* safeValue = value ? value : "<null>";
            const auto moduleBase = g_Addrs.ModuleBase;
            const auto callerRva = moduleBase && caller >= moduleBase ? caller - moduleBase : 0;
            const std::string key = std::string(setter ? setter : "<unknown>") + ":" + std::to_string(dvar);

            bool shouldPrint = false;
            bool isNew = false;
            bool isChange = false;
            bool shouldSummarize = false;
            std::uint32_t stableId = 0;
            std::uint64_t totalCalls = 0;
            std::uint64_t suppressedCalls = 0;
            std::string oldValue;

            {
                std::lock_guard<std::mutex> lock(g_setterTrackMutex);
                auto [it, inserted] = g_setterTracks.try_emplace(key);
                SetterTrack& track = it->second;
                if (inserted)
                {
                    track.stableId = g_nextStableDvarId.fetch_add(1);
                    track.dvarAddress = dvar;
                    track.lastValue = safeValue;
                    track.lastSummary = std::chrono::steady_clock::now();
                    isNew = true;
                    shouldPrint = true;
                }
                else if (track.lastValue != safeValue)
                {
                    oldValue = track.lastValue;
                    track.lastValue = safeValue;
                    ++track.changedCalls;
                    isChange = true;
                    shouldPrint = true;
                }

                ++track.totalCalls;
                ++track.callerCounts[caller];
                if (!shouldPrint)
                    ++track.suppressedCalls;

                const auto now = std::chrono::steady_clock::now();
                if (!shouldPrint && track.suppressedCalls && now - track.lastSummary >= std::chrono::seconds(10))
                {
                    shouldSummarize = true;
                    track.lastSummary = now;
                }

                stableId = track.stableId;
                totalCalls = track.totalCalls;
                suppressedCalls = track.suppressedCalls;
            }

            if (!shouldPrint && !shouldSummarize)
                return;

            if (shouldSummarize)
            {
                DvarStatusPrintf("[DVAR-HOOK] DVAR#%04u unchanged value=\"%s\" calls=%llu suppressed=%llu ptr=%p\n",
                    stableId, safeValue, static_cast<unsigned long long>(totalCalls),
                    static_cast<unsigned long long>(suppressedCalls), reinterpret_cast<void*>(dvar));
                return;
            }

            const std::string detectedLabel = GuessSettingLabel(setter, safeValue, stableId, dvar, callerRva);

            if (isChange)
            {
                DvarStatusPrintf("[DVAR-HOOK] DVAR#%04u CHANGED label=%s %s ptr=%p old=\"%s\" new=\"%s\" source=%d caller=%p rva=0x%llX calls=%llu\n",
                    stableId, detectedLabel.c_str(), setter, reinterpret_cast<void*>(dvar), oldValue.c_str(), safeValue, source,
                    reinterpret_cast<void*>(caller), static_cast<unsigned long long>(callerRva),
                    static_cast<unsigned long long>(totalCalls));
            }
            else
            {
                DvarStatusPrintf("[DVAR-HOOK] DVAR#%04u NEW label=%s %s ptr=%p value=\"%s\" source=%d caller=%p rva=0x%llX\n",
                    stableId, detectedLabel.c_str(), setter, reinterpret_cast<void*>(dvar), safeValue, source,
                    reinterpret_cast<void*>(caller), static_cast<unsigned long long>(callerRva));
            }

            if (isNew)
                InspectNewDvarPointer(stableId, dvar, setter, safeValue, caller);

            if (isChange)
            {
                bool newGroup = false;
                const std::uint64_t groupId = AllocateSettingGroup(newGroup);
                AppendSettingChange(groupId, newGroup, stableId, setter, dvar, oldValue, safeValue,
                    caller, callerRva, totalCalls, suppressedCalls);
            }

            CreateDirectoryA("logs", nullptr);
            std::lock_guard<std::mutex> fileLock(g_liveCaptureFileMutex);
            const char* path = "logs\\scanner\\live_dvar_setters.csv";
            const bool header = GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES;
            std::ofstream file(path, std::ios::app);
            if (!file) return;
            if (header)
                file << "session_id,stable_id,event,setter,dvar_address,old_value,new_value,source,caller,caller_rva,total_calls,suppressed_calls\n";
            file << "0x" << std::hex << std::uppercase << g_captureSessionId << std::dec << ',' << stableId << ',' << (isNew ? "new" : "changed") << ",\"" << setter << "\",0x"
                 << std::hex << std::uppercase << dvar << ",\"" << CsvEscape(oldValue) << "\",\""
                 << CsvEscape(safeValue) << "\"," << std::dec << source << ",0x" << std::hex << std::uppercase
                 << caller << ",0x" << callerRva << std::dec << ',' << totalCalls << ',' << suppressedCalls << "\n";
            file.flush();
            ++g_liveCaptureEvents;
        }

        void WriteSetterSummary()
        {
            CreateDirectoryA("logs", nullptr);
            std::ofstream file("logs\\scanner\\live_dvar_summary.csv", std::ios::trunc);
            if (!file) return;
            file << "session_id,stable_id,setter_key,last_value,total_calls,changed_calls,suppressed_calls,unique_callers,top_caller,top_caller_calls\n";
            std::lock_guard<std::mutex> lock(g_setterTrackMutex);
            for (const auto& [key, track] : g_setterTracks)
            {
                std::uintptr_t topCaller = 0;
                std::uint64_t topCount = 0;
                for (const auto& [callerAddress, count] : track.callerCounts)
                {
                    if (count > topCount) { topCaller = callerAddress; topCount = count; }
                }
                file << "0x" << std::hex << std::uppercase << g_captureSessionId << std::dec << ',' << track.stableId << ",\"" << CsvEscape(key) << "\",\"" << CsvEscape(track.lastValue)
                     << "\"," << track.totalCalls << ',' << track.changedCalls << ',' << track.suppressedCalls
                     << ',' << track.callerCounts.size() << ",0x" << std::hex << std::uppercase << topCaller
                     << std::dec << ',' << topCount << "\n";
            }
        }

        void DvarSetBoolDetour(std::uintptr_t dvar, bool value, int source)
        {
            const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
            AppendSetterEvent("Dvar_SetBoolFromSource", dvar, value ? "1" : "0", source, caller);
            if (g_originalSetBool)
                g_originalSetBool(dvar, value, source);
        }

        void DvarSetStringDetour(std::uintptr_t dvar, const char* value, int source)
        {
            const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
            char safeValue[256]{};
            __try
            {
                std::snprintf(safeValue, sizeof(safeValue), "%s", value ? value : "<null>");
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                std::snprintf(safeValue, sizeof(safeValue), "<unreadable:%p>", value);
            }
            AppendSetterEvent("Dvar_SetStringFromSource", dvar, safeValue, source, caller);
            if (g_originalSetString)
                g_originalSetString(dvar, value, source);
        }

        struct DiscoveryHit
        {
            const char* anchor = nullptr;
            std::uintptr_t callsite = 0;
            std::uintptr_t functionStart = 0;
            std::vector<std::uintptr_t> nearbyTargets;
        };

        bool IsInsideModule(std::uintptr_t address, std::uintptr_t base, std::size_t size)
        {
            return base && address >= base && address < base + size;
        }

        std::size_t ModuleImageSize(std::uintptr_t base)
        {
            if (!base) return 0;
            __try
            {
                const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
                const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
                return nt->OptionalHeader.SizeOfImage;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 0;
            }
        }


        bool TryDecodeDirectCall(std::uintptr_t address, std::uintptr_t& target)
        {
            target = 0;
            __try
            {
                if (*reinterpret_cast<const unsigned char*>(address) != 0xE8)
                    return false;
                const auto rel = *reinterpret_cast<const std::int32_t*>(address + 1);
                target = address + 5 + static_cast<std::intptr_t>(rel);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                target = 0;
                return false;
            }
        }

        std::uintptr_t GuessFunctionStart(std::uintptr_t address, std::uintptr_t sectionStart)
        {
            const std::uintptr_t lower = address > 0x300 ? std::max(sectionStart, address - 0x300) : sectionStart;
            for (std::uintptr_t p = address; p >= lower + 4; --p)
            {
                __try
                {
                    const auto b = reinterpret_cast<const unsigned char*>(p);
                    const bool common =
                        (b[0] == 0x40 && (b[1] == 0x53 || b[1] == 0x55 || b[1] == 0x56 || b[1] == 0x57)) ||
                        (b[0] == 0x48 && b[1] == 0x89 && (b[2] == 0x5C || b[2] == 0x6C || b[2] == 0x74 || b[2] == 0x7C) && b[3] == 0x24) ||
                        (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC) ||
                        (b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC);
                    if (common) return p;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
                if (p == lower) break;
            }
            return 0;
        }

        void CollectNearbyCalls(std::uintptr_t center, std::uintptr_t moduleBase, std::size_t moduleSize,
            std::uintptr_t textStart, std::uintptr_t textEnd, std::vector<std::uintptr_t>& out)
        {
            const auto begin = center > 0x180 ? std::max(textStart, center - 0x180) : textStart;
            const auto end = std::min(textEnd, center + 0x180);
            std::unordered_set<std::uintptr_t> unique;
            for (std::uintptr_t p = begin; p + 5 <= end; ++p)
            {
                std::uintptr_t target = 0;
                if (!TryDecodeDirectCall(p, target))
                    continue;
                if (IsInsideModule(target, moduleBase, moduleSize) && IsExecutableAddress(target))
                    unique.insert(target);
            }
            out.assign(unique.begin(), unique.end());
            std::sort(out.begin(), out.end());
        }

        void RunAnchorDiscovery()
        {
            if (g_discoveryComplete.exchange(true)) return;
            const auto base = g_Addrs.ModuleBase;
            const auto imageSize = ModuleImageSize(base);
            if (!base || !imageSize)
            {
                DvarStatusPrintf("[ENGINE-DISCOVERY] Failed: module image is unavailable.\n");
                return;
            }

            const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            const auto first = IMAGE_FIRST_SECTION(nt);
            std::vector<DiscoveryHit> hits;
            const struct Anchor { const char* name; std::uintptr_t address; } anchors[] = {
                {"Dvar_SetBoolFromSource", g_Addrs.Dvar_SetBoolFromSource},
                {"Dvar_SetStringFromSource", g_Addrs.Dvar_SetStringFromSource},
            };

            DvarStatusPrintf("[ENGINE-DISCOVERY] Starting safe anchor scan; unknown functions will NOT be executed or hooked.\n");
            CreateDirectoryA("logs", nullptr);
            std::ofstream csv("logs\\scanner\\engine_discovery.csv", std::ios::trunc);
            csv << "anchor,callsite,callsite_rva,function_start,function_rva,nearby_target,nearby_target_rva\n";

            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            {
                const auto& sec = first[i];
                if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                const auto start = base + sec.VirtualAddress;
                const auto size = std::max<std::size_t>(sec.Misc.VirtualSize, sec.SizeOfRawData);
                const auto end = std::min(base + imageSize, start + size);
                for (const auto& anchor : anchors)
                {
                    if (!IsExecutableAddress(anchor.address))
                    {
                        DvarStatusPrintf("[ENGINE-DISCOVERY] Anchor %s unavailable (%p).\n", anchor.name, reinterpret_cast<void*>(anchor.address));
                        continue;
                    }
                    for (std::uintptr_t p = start; p + 5 <= end; ++p)
                    {
                        std::uintptr_t target = 0;
                        if (!TryDecodeDirectCall(p, target))
                            continue;
                        if (target != anchor.address)
                            continue;

                        DiscoveryHit hit{};
                        hit.anchor = anchor.name;
                        hit.callsite = p;
                        hit.functionStart = GuessFunctionStart(p, start);
                        CollectNearbyCalls(p, base, imageSize, start, end, hit.nearbyTargets);
                        hits.push_back(hit);
                        DvarStatusPrintf("[ENGINE-DISCOVERY] %s caller=%p rva=0x%llX function=%p nearby_calls=%zu\n",
                            anchor.name, reinterpret_cast<void*>(p), static_cast<unsigned long long>(p - base),
                            reinterpret_cast<void*>(hit.functionStart), hit.nearbyTargets.size());
                        for (const auto t : hit.nearbyTargets)
                            csv << '"' << anchor.name << "\",0x" << std::hex << std::uppercase << p << ",0x" << (p-base)
                                << ",0x" << hit.functionStart << ",0x" << (hit.functionStart ? hit.functionStart-base : 0)
                                << ",0x" << t << ",0x" << (t-base) << std::dec << "\n";
                    }
                }
            }
            csv.flush();

            std::unordered_map<std::uintptr_t, std::uint64_t> targetFrequency;
            for (const auto& hit : hits)
                for (const auto target : hit.nearbyTargets)
                    ++targetFrequency[target];
            std::vector<std::pair<std::uintptr_t, std::uint64_t>> rankedTargets(targetFrequency.begin(), targetFrequency.end());
            std::sort(rankedTargets.begin(), rankedTargets.end(), [](const auto& a, const auto& b)
            {
                return a.second > b.second;
            });
            std::ofstream candidates("logs\\scanner\\engine_candidates.csv", std::ios::trunc);
            candidates << "rank,target,target_rva,frequency,executable,status\n";
            std::size_t rank = 0;
            for (const auto& [target, frequency] : rankedTargets)
            {
                const bool executable = IsExecutableAddress(target);
                const char* status = target == g_Addrs.Dvar_SetBoolFromSource ? "known-bool-setter" :
                    (target == g_Addrs.Dvar_SetStringFromSource ? "known-string-setter" : "candidate-not-hooked");
                candidates << ++rank << ",0x" << std::hex << std::uppercase << target << ",0x"
                           << (target >= base ? target - base : 0) << std::dec << ',' << frequency << ','
                           << (executable ? 1 : 0) << ',' << status << "\n";
                if (rank <= 12)
                    DvarStatusPrintf("[ENGINE-CANDIDATE] rank=%zu target=%p rva=0x%llX frequency=%llu status=%s\n",
                        rank, reinterpret_cast<void*>(target), static_cast<unsigned long long>(target >= base ? target - base : 0),
                        static_cast<unsigned long long>(frequency), status);
            }
            candidates.flush();

            g_discoveryCallsites.store(hits.size());
            unsigned long long targets = 0; for (const auto& h : hits) targets += h.nearbyTargets.size();
            g_discoveryTargets.store(targets);
            DvarStatusPrintf("[ENGINE-DISCOVERY] Complete: callsites=%llu nearby_targets=%llu output=logs\\scanner\\engine_discovery.csv\n",
                g_discoveryCallsites.load(), g_discoveryTargets.load());
            DvarStatusPrintf("[ENGINE-DISCOVERY] Change FOV and other settings while capture runs; live setter callers remain in logs\\scanner\\live_dvar_setters.csv.\n");
        }

        bool InstallOneHook(const char* label, std::uintptr_t address, void* detour, void** original, std::atomic_bool& installed)
        {
            if (!IsExecutableAddress(address))
            {
                DvarStatusPrintf("[ENGINE-HOOK] %s unresolved or non-executable (address=%p).\n", label, reinterpret_cast<void*>(address));
                return false;
            }
            const auto create = MH_CreateHook(reinterpret_cast<void*>(address), detour, original);
            const auto enable = (create == MH_OK || create == MH_ERROR_ALREADY_CREATED) ? MH_EnableHook(reinterpret_cast<void*>(address)) : create;
            if ((create == MH_OK || create == MH_ERROR_ALREADY_CREATED) && (enable == MH_OK || enable == MH_ERROR_ENABLED))
            {
                installed.store(true);
                DvarStatusPrintf("[ENGINE-HOOK] Installed %s at %p.\n", label, reinterpret_cast<void*>(address));
                return true;
            }
            DvarStatusPrintf("[ENGINE-HOOK] %s failed: create=%s enable=%s\n", label, MH_StatusToString(create), MH_StatusToString(enable));
            return false;
        }

        bool InstallEngineHooks()
        {
            if (g_engineHooksInstalled.exchange(true))
                return g_findVarHookInstalled.load();

            const MH_STATUS init = MH_Initialize();
            if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
            {
                DvarStatusPrintf("[ENGINE-HOOK] MinHook initialization failed: %s\n", MH_StatusToString(init));
                return false;
            }

            bool any = false;
            // Only hook addresses resolved for this exact running build. Previous
            // absolute addresses belonged to another build and caused crashes.
            any |= InstallOneHook("Dvar_FindVar", g_Addrs.Dvar_FindVar,
                reinterpret_cast<void*>(&DvarFindVarDetour), reinterpret_cast<void**>(&g_originalFindVar), g_findVarHookInstalled);
            DvarStatusPrintf("[ENGINE-HOOK] Guessed RegisterInt/SetInt/SetVariant/Cmd_AddCommand addresses are disabled.\n");
            DvarStatusPrintf("[ENGINE-HOOK] Safe anchor discovery will map candidates before any new hook is installed.\n");
            RunAnchorDiscovery();
            return any;
        }

        bool InstallSetterHooks()
        {
            if (g_setterHooksInstalled.load())
                return g_boolHookInstalled.load() || g_stringHookInstalled.load();

            const MH_STATUS init = MH_Initialize();
            if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
            {
                DvarStatusPrintf("[DVAR-HOOK] MinHook initialization failed: %s\n", MH_StatusToString(init));
                return false;
            }

            bool any = false;
            if (g_Addrs.Dvar_SetBoolFromSource)
            {
                const auto create = MH_CreateHook(reinterpret_cast<void*>(g_Addrs.Dvar_SetBoolFromSource),
                    reinterpret_cast<void*>(&DvarSetBoolDetour), reinterpret_cast<void**>(&g_originalSetBool));
                const auto enable = create == MH_OK ? MH_EnableHook(reinterpret_cast<void*>(g_Addrs.Dvar_SetBoolFromSource)) : create;
                if (create == MH_OK && (enable == MH_OK || enable == MH_ERROR_ENABLED))
                {
                    g_boolHookInstalled.store(true); any = true;
                    DvarStatusPrintf("[DVAR-HOOK] Installed bool setter hook at %p.\n", reinterpret_cast<void*>(g_Addrs.Dvar_SetBoolFromSource));
                }
                else DvarStatusPrintf("[DVAR-HOOK] Bool setter hook failed: create=%s enable=%s\n", MH_StatusToString(create), MH_StatusToString(enable));
            }
            else DvarStatusPrintf("[DVAR-HOOK] Bool setter address is unresolved.\n");

            if (g_Addrs.Dvar_SetStringFromSource)
            {
                const auto create = MH_CreateHook(reinterpret_cast<void*>(g_Addrs.Dvar_SetStringFromSource),
                    reinterpret_cast<void*>(&DvarSetStringDetour), reinterpret_cast<void**>(&g_originalSetString));
                const auto enable = create == MH_OK ? MH_EnableHook(reinterpret_cast<void*>(g_Addrs.Dvar_SetStringFromSource)) : create;
                if (create == MH_OK && (enable == MH_OK || enable == MH_ERROR_ENABLED))
                {
                    g_stringHookInstalled.store(true); any = true;
                    DvarStatusPrintf("[DVAR-HOOK] Installed string setter hook at %p.\n", reinterpret_cast<void*>(g_Addrs.Dvar_SetStringFromSource));
                }
                else DvarStatusPrintf("[DVAR-HOOK] String setter hook failed: create=%s enable=%s\n", MH_StatusToString(create), MH_StatusToString(enable));
            }
            else DvarStatusPrintf("[DVAR-HOOK] String setter address is unresolved.\n");

            g_setterHooksInstalled.store(true);
            return any;
        }

        const char* kSeedNames[] = {
            "sv_cheats", "developer", "developer_script", "cg_fov", "cg_fovScale", "cg_fovscale",
            "cg_drawFps", "cg_draw2D", "cg_drawGun", "cg_thirdPerson", "cg_thirdPersonAngle",
            "cg_drawSpectatorMessages", "com_maxfps", "com_maxfps_menu", "com_sv_running",
            "r_vsync", "r_fullscreen", "r_mode", "r_dof_enable", "r_fog", "r_picmip", "r_dlssEnable",
            "timescale", "g_speed", "g_gravity", "g_gameskill", "g_gameEnded", "jump_height",
            "player_sprintSpeedScale", "player_health_regen_time", "player_num_lives",
            "ui_mapname", "ui_gametype", "ui_openstore", "ui_opensettings", "ui_openQuarterMaster",
            "party_maxplayers", "party_privacyStatus", "sv_hostname", "sv_maxclients", "sv_running",
            "sv_enableMultiplayerHostMigration", "sv_enableZombiesHostMigration", "sv_mapRotation", "sv_pure",
            "sv_fps", "scr_game_allowkillcam", "scr_game_timelimit", "scr_game_scorelimit",
            "scr_player_forcerespawn", "scr_team_fftype", "onlinegame", "xblive_privatematch",
            "xblive_rankedmatch", "cl_maxpackets", "cl_packetdup", "rate", "sensitivity", "m_filter",
            "m_pitch", "m_yaw", "r_lodBiasRigid", "r_lodBiasSkinned", "lobby_open", "lobby_id",
            "lobby_forceBalanced", "lobby_open_for_pres_join", "lobby_slots", "noclip", "NoTarget"
        };

        #include "../../../shared/diagnostics/RuntimeDiscoveredCandidates.generated.inl"

        std::string Lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });
            return value;
        }

        std::string Trim(std::string value)
        {
            const auto notSpace = [](unsigned char c) { return !std::isspace(c); };
            value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
            value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
            return value;
        }

        const char* TypeName(dvarType_t type)
        {
            switch (type)
            {
            case DVAR_TYPE_BOOL: return "bool";
            case DVAR_TYPE_FLOAT: return "float";
            case DVAR_TYPE_FLOAT_2: return "float2";
            case DVAR_TYPE_FLOAT_3: return "float3";
            case DVAR_TYPE_FLOAT_4: return "float4";
            case DVAR_TYPE_INT: return "int";
            case DVAR_TYPE_ENUM: return "enum";
            case DVAR_TYPE_STRING: return "string";
            case DVAR_TYPE_COLOR: return "color";
            case DVAR_TYPE_INT64: return "int64";
            case DVAR_TYPE_UINT64: return "uint64";
            default: return "other";
            }
        }

        struct RawSnapshot
        {
            bool valid = false;
            dvarType_t type = DVAR_TYPE_INVALID;
            unsigned int flags = 0;
            char value[160]{};
        };

        __declspec(noinline) dvar_t* SafeFind(std::uint64_t hash) noexcept
        {
            dvar_t* result = nullptr;
            __try
            {
                result = Dvar_FindVar(static_cast<__int64>(hash));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                result = nullptr;
            }
            return result;
        }

        __declspec(noinline) RawSnapshot SafeSnapshot(const dvar_t* dvar) noexcept
        {
            RawSnapshot result{};
            if (!dvar)
                return result;

            __try
            {
                result.type = dvar->type;
                result.flags = dvar->flags;
                if (!dvar->value)
                {
                    std::snprintf(result.value, sizeof(result.value), "registered");
                    result.valid = true;
                    return result;
                }

                switch (dvar->type)
                {
                case DVAR_TYPE_BOOL:
                    std::snprintf(result.value, sizeof(result.value), "%s",
                        dvar->value->current.naked.enabled ? "1" : "0");
                    break;
                case DVAR_TYPE_FLOAT:
                    std::snprintf(result.value, sizeof(result.value), "%.6g",
                        dvar->value->current.naked.value);
                    break;
                case DVAR_TYPE_FLOAT_2:
                    std::snprintf(result.value, sizeof(result.value), "%.6g %.6g",
                        dvar->value->current.naked.vector[0], dvar->value->current.naked.vector[1]);
                    break;
                case DVAR_TYPE_FLOAT_3:
                case DVAR_TYPE_LINEAR_COLOR_RGB:
                case DVAR_TYPE_COLOR_XYZ:
                case DVAR_TYPE_COLOR_LAB:
                    std::snprintf(result.value, sizeof(result.value), "%.6g %.6g %.6g",
                        dvar->value->current.naked.vector[0], dvar->value->current.naked.vector[1],
                        dvar->value->current.naked.vector[2]);
                    break;
                case DVAR_TYPE_FLOAT_4:
                    std::snprintf(result.value, sizeof(result.value), "%.6g %.6g %.6g %.6g",
                        dvar->value->current.naked.vector[0], dvar->value->current.naked.vector[1],
                        dvar->value->current.naked.vector[2], dvar->value->current.naked.vector[3]);
                    break;
                case DVAR_TYPE_INT:
                case DVAR_TYPE_ENUM:
                    std::snprintf(result.value, sizeof(result.value), "%d",
                        dvar->value->current.naked.integer);
                    break;
                case DVAR_TYPE_INT64:
                    std::snprintf(result.value, sizeof(result.value), "%lld",
                        static_cast<long long>(dvar->value->current.naked.integer64));
                    break;
                case DVAR_TYPE_UINT64:
                    std::snprintf(result.value, sizeof(result.value), "%llu",
                        static_cast<unsigned long long>(dvar->value->current.naked.unsignedInt64));
                    break;
                case DVAR_TYPE_STRING:
                    std::snprintf(result.value, sizeof(result.value), "%s",
                        dvar->value->current.naked.string ? dvar->value->current.naked.string : "");
                    break;
                case DVAR_TYPE_COLOR:
                    std::snprintf(result.value, sizeof(result.value), "%u %u %u %u",
                        static_cast<unsigned int>(dvar->value->current.naked.color[0]),
                        static_cast<unsigned int>(dvar->value->current.naked.color[1]),
                        static_cast<unsigned int>(dvar->value->current.naked.color[2]),
                        static_cast<unsigned int>(dvar->value->current.naked.color[3]));
                    break;
                default:
                    std::snprintf(result.value, sizeof(result.value), "registered");
                    break;
                }
                result.valid = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                result.valid = false;
            }
            return result;
        }

        __declspec(noinline) bool SafeSetBool(dvar_t* dvar, bool value) noexcept
        {
            if (!dvar || !g_Addrs.Dvar_SetBoolFromSource)
                return false;
            bool ok = false;
            __try
            {
                Dvar_SetBoolFromSource(reinterpret_cast<std::uintptr_t>(dvar), value, 0);
                ok = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ok = false;
            }
            return ok;
        }

        __declspec(noinline) bool SafeSetString(dvar_t* dvar, const char* value) noexcept
        {
            if (!dvar || !value || !g_Addrs.Dvar_SetStringFromSource)
                return false;
            bool ok = false;
            __try
            {
                Dvar_SetStringFromSource(reinterpret_cast<std::uintptr_t>(dvar), value, 0);
                ok = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ok = false;
            }
            return ok;
        }


        bool ResolveEntryThroughConsolePath(const std::string& rawName, Entry& out)
        {
            std::string name = Trim(rawName);
            if (name.empty())
                return false;

            {
                std::lock_guard<std::mutex> lock(g_mutex);
                const auto known = g_entries.find(Lower(name));
                if (known != g_entries.end())
                {
                    if (known->second.verified)
                    {
                        out = known->second;
                        return true;
                    }
                    name = known->second.name;
                }
            }

            Entry entry{};
            entry.name = name;
            entry.hash = fnvHash(name.c_str());
            entry.source = Source::RuntimeDump;

            dvar_t* dvar = SafeFind(entry.hash);
            if (!dvar)
                return false;

            const RawSnapshot snapshot = SafeSnapshot(dvar);
            if (!snapshot.valid)
                return false;

            entry.verified = true;
            entry.source = Source::Verified;
            entry.address = reinterpret_cast<std::uintptr_t>(dvar);
            entry.type = TypeName(snapshot.type);
            entry.flags = snapshot.flags;
            entry.value = snapshot.value;
            out = std::move(entry);
            return true;
        }

        std::string CsvEscape(std::string value)
        {
            std::string escaped;
            escaped.reserve(value.size() + 8);
            for (char c : value)
            {
                if (c == '"') escaped += "\"\"";
                else if (c == '\r' || c == '\n') escaped += ' ';
                else escaped += c;
            }
            return escaped;
        }

        void AppendLiveCaptureEvent(const char* eventName, const Entry& entry,
            const std::string& oldValue, const std::string& newValue)
        {
            SYSTEMTIME now{};
            GetLocalTime(&now);
            char timestamp[64]{};
            std::snprintf(timestamp, sizeof(timestamp), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
                now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);

            DvarStatusPrintf("[DVAR-LIVE] %s name=%s ptr=%p type=%s flags=0x%X old=\"%s\" new=\"%s\"\n",
                eventName, entry.name.c_str(), reinterpret_cast<void*>(entry.address), entry.type.c_str(),
                entry.flags, oldValue.c_str(), newValue.c_str());

            CreateDirectoryA("logs", nullptr);
            std::lock_guard<std::mutex> fileLock(g_liveCaptureFileMutex);
            const char* path = "logs\\scanner\\live_dvar_capture.csv";
            bool writeHeader = false;
            WIN32_FILE_ATTRIBUTE_DATA attributes{};
            if (!GetFileAttributesExA(path, GetFileExInfoStandard, &attributes) ||
                (attributes.nFileSizeHigh == 0 && attributes.nFileSizeLow == 0))
                writeHeader = true;

            std::ofstream file(path, std::ios::app);
            if (!file) return;
            if (writeHeader)
                file << "timestamp,event,name,hash,address,type,flags,old_value,new_value\n";
            file << '"' << timestamp << "\",\"" << CsvEscape(eventName) << "\",\""
                 << CsvEscape(entry.name) << "\",0x" << std::hex << std::uppercase << entry.hash
                 << ",0x" << entry.address << std::dec << ",\"" << CsvEscape(entry.type)
                 << "\",0x" << std::hex << std::uppercase << entry.flags << std::dec << ",\""
                 << CsvEscape(oldValue) << "\",\"" << CsvEscape(newValue) << "\"\n";
            file.flush();
            ++g_liveCaptureEvents;
        }

        DWORD WINAPI LiveCaptureThread(LPVOID)
        {
            struct SeenValue
            {
                std::uintptr_t address = 0;
                std::string type;
                std::string value;
                unsigned int flags = 0;
            };
            std::unordered_map<std::string, SeenValue> seen;

            DvarStatusPrintf("[DVAR-LIVE] Continuous capture started. Change settings or enter gameplay now.\n");
            DvarStatusPrintf("[DVAR-LIVE] Logging all resolved initial values and subsequent changes to CMD and logs\\scanner\\live_dvar_capture.csv.\n");
            DvarStatusPrintf("[DVAR-LIVE] Capture will not auto-stop. Use /scan stop to end it.\n");

            unsigned long long heartbeat = 0;
            while (!g_liveCaptureStop.load())
            {
                const auto candidates = Entries();
                unsigned long long resolvedThisPass = 0;
                if (g_Addrs.Dvar_FindVar)
                for (const Entry& candidate : candidates)
                {
                    if (g_liveCaptureStop.load()) break;
                    dvar_t* dvar = SafeFind(candidate.hash);
                    if (!dvar) continue;
                    const RawSnapshot snapshot = SafeSnapshot(dvar);
                    if (!snapshot.valid) continue;

                    Entry live = candidate;
                    live.verified = true;
                    live.source = Source::Verified;
                    live.address = reinterpret_cast<std::uintptr_t>(dvar);
                    live.type = TypeName(snapshot.type);
                    live.flags = snapshot.flags;
                    live.value = snapshot.value;
                    ++resolvedThisPass;

                    {
                        std::lock_guard<std::mutex> lock(g_mutex);
                        g_entries[Lower(live.name)] = live;
                    }

                    const std::string key = Lower(live.name);
                    const auto found = seen.find(key);
                    if (found == seen.end())
                    {
                        AppendLiveCaptureEvent("resolved", live, "", live.value);
                        seen.emplace(key, SeenValue{ live.address, live.type, live.value, live.flags });
                    }
                    else if (found->second.address != live.address || found->second.type != live.type ||
                             found->second.flags != live.flags || found->second.value != live.value)
                    {
                        const std::string oldValue = found->second.value;
                        AppendLiveCaptureEvent("changed", live, oldValue, live.value);
                        found->second = SeenValue{ live.address, live.type, live.value, live.flags };
                    }
                }

                g_liveCaptureResolved.store(resolvedThisPass);
                ++g_liveCapturePasses;
                if ((++heartbeat % 10) == 1)
                {
                    DvarStatusPrintf("[DVAR-LIVE] active passes=%llu findvar=%s bool_hook=%s string_hook=%s events=%llu. Use /scan stop to stop.\n",
                        g_liveCapturePasses.load(), g_Addrs.Dvar_FindVar ? "yes" : "no",
                        g_boolHookInstalled.load() ? "yes" : "no", g_stringHookInstalled.load() ? "yes" : "no",
                        g_liveCaptureEvents.load());
                    DvarStatusPrintf("[ENGINE-HOOK] find=%s guessed_hooks=disabled discovery=%s callsites=%llu nearby_targets=%llu\n",
                        g_findVarHookInstalled.load() ? "yes" : "no", g_discoveryComplete.load() ? "complete" : "pending",
                        g_discoveryCallsites.load(), g_discoveryTargets.load());
                }
                for (int slice = 0; slice < 5 && !g_liveCaptureStop.load(); ++slice)
                    Sleep(100);
            }

            WriteReport();
            DvarStatusPrintf("[DVAR-LIVE] Continuous capture stopped: passes=%llu currently_resolved=%llu events=%llu.\n",
                g_liveCapturePasses.load(), g_liveCaptureResolved.load(), g_liveCaptureEvents.load());
            DvarStatusPrintf("[DVAR-LIVE] Final reports: logs\\scanner\\live_dvar_capture.csv and logs\\scanner\\t9_dvars.csv\n");
            g_liveCaptureRunning.store(false);
            return 0;
        }

        void AddCandidate(std::map<std::string, Entry>& entries, const char* name, Source source)
        {
            if (!name || !*name)
                return;
            std::string display = Trim(name);
            if (display.empty())
                return;
            const std::string key = Lower(display);
            auto [it, inserted] = entries.emplace(key, Entry{});
            if (inserted)
            {
                it->second.name = display;
                it->second.hash = fnvHash(display.c_str());
                it->second.source = source;
            }
            else if (source == Source::RuntimeDump && it->second.source == Source::Seed)
            {
                it->second.source = source;
            }
        }
    }

    void Refresh()
    {
        std::map<std::string, Entry> rebuilt;
        for (const char* name : kSeedNames)
            AddCandidate(rebuilt, name, Source::Seed);
        for (const char* name : kRuntimeDiscoveredCandidates)
            AddCandidate(rebuilt, name, Source::RuntimeDump);

        for (auto& pair : rebuilt)
        {
            Entry& entry = pair.second;
            dvar_t* dvar = SafeFind(entry.hash);
            if (!dvar)
                continue;

            const RawSnapshot snapshot = SafeSnapshot(dvar);
            entry.verified = true;
            entry.source = Source::Verified;
            entry.address = reinterpret_cast<std::uintptr_t>(dvar);
            entry.type = snapshot.valid ? TypeName(snapshot.type) : "unknown";
            entry.flags = snapshot.valid ? snapshot.flags : 0;
            entry.value = snapshot.valid ? snapshot.value : "unreadable";
        }

        std::lock_guard<std::mutex> lock(g_mutex);
        g_entries.swap(rebuilt);
    }

    std::vector<Entry> Entries(const std::string& filter, bool verifiedOnly)
    {
        const std::string needle = Lower(filter);
        std::vector<Entry> result;
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& pair : g_entries)
        {
            const Entry& entry = pair.second;
            if (verifiedOnly && !entry.verified)
                continue;
            if (!needle.empty() && Lower(entry.name).find(needle) == std::string::npos)
                continue;
            result.push_back(entry);
        }
        return result;
    }

    std::vector<std::string> Suggestions(const std::string& input, std::size_t limit)
    {
        std::string needle = Lower(Trim(input));
        if (!needle.empty() && needle.front() == '/')
            needle.erase(needle.begin());

        struct Ranked { int rank; std::string text; };
        std::vector<Ranked> ranked;
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& pair : g_entries)
        {
            const Entry& entry = pair.second;
            const std::string lowered = Lower(entry.name);
            const std::size_t pos = lowered.find(needle);
            if (!needle.empty() && pos == std::string::npos)
                continue;
            const int rank = (pos == 0 ? 0 : 20) + (entry.verified ? 0 : 5) + static_cast<int>(lowered.size());
            ranked.push_back({ rank, "/" + entry.name + " " });
        }
        std::sort(ranked.begin(), ranked.end(), [](const Ranked& a, const Ranked& b)
        {
            if (a.rank != b.rank) return a.rank < b.rank;
            return Lower(a.text) < Lower(b.text);
        });
        std::vector<std::string> result;
        for (const Ranked& item : ranked)
        {
            result.push_back(item.text);
            if (result.size() >= limit)
                break;
        }
        return result;
    }

    ExecuteResult Execute(const std::string& rawName, const std::string& rawValue, std::string& message)
    {
        std::string name = Trim(rawName);
        const std::string value = Trim(rawValue);
        if (name.empty())
            return ExecuteResult::NotFound;

        Entry resolved{};
        if (!ResolveEntryThroughConsolePath(name, resolved))
            return ExecuteResult::NotFound;

        name = resolved.name;
        dvar_t* dvar = reinterpret_cast<dvar_t*>(resolved.address);
        const RawSnapshot before = SafeSnapshot(dvar);
        if (!before.valid)
        {
            message = "[DVAR] " + name + " is registered but unreadable.";
            return ExecuteResult::Fault;
        }

        if (value.empty())
        {
            std::ostringstream stream;
            stream << "[DVAR] " << name << " = " << before.value << " (" << TypeName(before.type)
                   << ", flags=0x" << std::hex << before.flags << ")";
            message = stream.str();
            return ExecuteResult::Read;
        }

        bool set = false;
        if (before.type == DVAR_TYPE_BOOL)
        {
            const std::string lowered = Lower(value);
            if (lowered == "1" || lowered == "true" || lowered == "on" || lowered == "yes")
                set = SafeSetBool(dvar, true);
            else if (lowered == "0" || lowered == "false" || lowered == "off" || lowered == "no")
                set = SafeSetBool(dvar, false);
            else
            {
                message = "[DVAR] " + name + " expects 0/1, false/true, or off/on.";
                return ExecuteResult::Rejected;
            }
        }
        else
        {
            set = SafeSetString(dvar, value.c_str());
        }

        if (!set)
        {
            message = "[DVAR] Failed to set " + name + "; the native setter is unavailable or faulted.";
            return ExecuteResult::Fault;
        }

        const RawSnapshot after = SafeSnapshot(dvar);
        message = "[DVAR] " + name + " = " + (after.valid ? std::string(after.value) : value);
        return ExecuteResult::Set;
    }


    bool VerifyCandidate(const std::string& rawName, Entry& result)
    {
        return ResolveEntryThroughConsolePath(rawName, result);
    }

    bool ProbeConsoleDvar(const std::string& rawName, Entry& result, std::string* message)
    {
        if (!ResolveEntryThroughConsolePath(rawName, result))
        {
            if (message)
                *message = "[DVAR] " + Trim(rawName) + " was not found by the dev-console dvar resolver.";
            return false;
        }

        if (message)
        {
            std::ostringstream stream;
            stream << "[DVAR] " << result.name << " = " << result.value
                   << " (" << result.type << ", flags=0x" << std::hex << result.flags << ")";
            *message = stream.str();
        }
        return true;
    }

    void MergeCandidates(const std::vector<std::string>& names, Source source)
    {
        std::map<std::string, Entry> additions;
        for (const std::string& name : names)
            AddCandidate(additions, name.c_str(), source);

        for (auto& pair : additions)
        {
            Entry verified{};
            if (VerifyCandidate(pair.second.name, verified))
                pair.second = std::move(verified);
        }

        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto& pair : additions)
        {
            auto existing = g_entries.find(pair.first);
            if (existing == g_entries.end())
            {
                g_entries.emplace(pair.first, std::move(pair.second));
                continue;
            }

            Entry& destination = existing->second;
            Entry& incoming = pair.second;
            if (incoming.verified || !destination.verified)
                destination = std::move(incoming);
        }
    }

    bool IsKnownName(const std::string& name)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_entries.find(Lower(Trim(name))) != g_entries.end();
    }

    bool IsVerified(const std::string& name)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const auto it = g_entries.find(Lower(Trim(name)));
        return it != g_entries.end() && it->second.verified;
    }

    void WriteReport()
    {
        std::ofstream file("logs\\scanner\\t9_dvars.csv", std::ios::trunc);
        file << "name,hash,address,type,flags,value,verified,source\n";
        for (const Entry& entry : Entries())
        {
            const char* source = entry.source == Source::Verified ? "verified" :
                (entry.source == Source::RuntimeDump ? "runtime-dump" : "seed");
            file << entry.name << ",0x" << std::hex << entry.hash << ",0x" << entry.address << std::dec
                 << ',' << entry.type << ',' << entry.flags << ",\"" << entry.value << "\"," <<
                 (entry.verified ? 1 : 0) << ',' << source << "\n";
        }
    }

    bool StartLiveCapture()
    {
        if (g_liveCaptureRunning.exchange(true))
        {
            DvarStatusPrintf("[DVAR-LIVE] Continuous capture is already running.\n");
            return false;
        }

        if (!g_Addrs.Dvar_FindVar)
            DvarStatusPrintf("[DVAR-LIVE] Dvar_FindVar is unresolved; registry polling is unavailable, but setter-hook capture will remain active.\n");

        const bool hooksReady = InstallSetterHooks();
        const bool engineHooksReady = InstallEngineHooks();
        if (!hooksReady && !engineHooksReady && !g_Addrs.Dvar_FindVar)
            DvarStatusPrintf("[DVAR-LIVE] WARNING: no setter hook or FindVar path is available yet. Capture remains active and will print heartbeats.\n");

        g_liveCaptureStop.store(false);
        g_captureSessionId = MakeCaptureSessionId();
        LoadManualLabels();
        {
            std::lock_guard<std::mutex> lock(g_settingChangeMutex);
            g_nextSettingGroupId = 1;
            g_activeSettingGroupId = 0;
            g_lastSettingChange = {};
        }
        DvarStatusPrintf("[DVAR-LIVE] session=0x%llX always-on capture active.\n", static_cast<unsigned long long>(g_captureSessionId));
        {
            std::lock_guard<std::mutex> lock(g_setterTrackMutex);
            g_setterTracks.clear();
            g_nextStableDvarId.store(1);
        }
        g_liveCapturePasses.store(0);
        g_liveCaptureResolved.store(0);
        g_liveCaptureEvents.store(0);
        Refresh();
        HANDLE thread = CreateThread(nullptr, 0, LiveCaptureThread, nullptr, 0, nullptr);
        if (!thread)
        {
            g_liveCaptureRunning.store(false);
            DvarStatusPrintf("[DVAR-LIVE] Failed to create capture thread (error %lu).\n", GetLastError());
            return false;
        }
        CloseHandle(thread);
        return true;
    }

    void StopLiveCapture()
    {
        if (!g_liveCaptureRunning.load())
        {
            DvarStatusPrintf("[DVAR-LIVE] Continuous dvar capture is not running.\n");
            return;
        }
        g_liveCaptureStop.store(true);
        WriteSetterSummary();
        DvarStatusPrintf("[DVAR-LIVE] Stop requested. Change-only log and summary flushed to logs\\scanner\\live_dvar_setters.csv and logs\\scanner\\live_dvar_summary.csv.\n");
    }

    bool SetCapturedLabel(std::uint32_t stableId, const std::string& label, std::string& message)
    {
        if (!stableId || label.empty())
        {
            message = "Usage: /dvarlabel <stable_id> <label>";
            return false;
        }
        std::uintptr_t dvar = 0;
        {
            std::lock_guard<std::mutex> lock(g_setterTrackMutex);
            for (const auto& item : g_setterTracks)
            {
                if (item.second.stableId == stableId)
                {
                    dvar = item.second.dvarAddress;
                    break;
                }
            }
        }
        if (!dvar)
        {
            message = "DVAR stable ID was not observed in this session.";
            return false;
        }
        const auto base = g_Addrs.ModuleBase;
        if (!base || dvar < base)
        {
            message = "Unable to calculate a module-relative dvar address.";
            return false;
        }
        const std::uint64_t rva = dvar - base;
        {
            std::lock_guard<std::mutex> lock(g_labelMutex);
            g_manualLabelsByRva[rva] = label;
            SaveManualLabelsUnlocked();
        }
        std::ostringstream out;
        out << "DVAR#" << std::setfill('0') << std::setw(4) << stableId
            << " labeled '" << label << "' at RVA 0x" << std::hex << std::uppercase << rva;
        message = out.str();
        return true;
    }

    bool IsLiveCaptureRunning()
    {
        return g_liveCaptureRunning.load();
    }

    static bool StartProbeInternal(ProbeKind kind, const std::uintptr_t (&rvas)[3])
    {
        if (g_floatProbeRunning.exchange(true))
        {
            DvarStatusPrintf("[%s-PROBE] Another probe is already running. Stop it first.\n", ProbeName(g_probeKind));
            return false;
        }
        g_probeKind = kind;
        std::copy(std::begin(rvas), std::end(rvas), std::begin(g_probeRvas));
        g_floatProbeCalls.store(0); g_floatProbeInteresting.store(0);
        g_commandStringHits.store(0); g_commandSuppressed.store(0);
        {
            std::lock_guard<std::mutex> lock(g_floatProbeMutex);
            g_floatProbeSeen.clear();
            g_commandPairStats.clear();
        }
        const MH_STATUS init = MH_Initialize();
        if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
        {
            g_floatProbeRunning.store(false); g_probeKind = ProbeKind::None;
            DvarStatusPrintf("[%s-PROBE] MinHook initialization failed: %s\n", ProbeName(kind), MH_StatusToString(init));
            return false;
        }
        void* detours[3] = { reinterpret_cast<void*>(&FloatProbeDetour1), reinterpret_cast<void*>(&FloatProbeDetour2), reinterpret_cast<void*>(&FloatProbeDetour3) };
        void** originals[3] = { &g_FloatProbeOriginal1, &g_FloatProbeOriginal2, &g_FloatProbeOriginal3 };
        bool any = false;
        for (unsigned i = 0; i < 3; ++i)
        {
            const auto address = g_Addrs.ModuleBase + g_probeRvas[i];
            if (!IsExecutableAddress(address)) { DvarStatusPrintf("[%s-PROBE] Candidate 0x%llX is not executable.\n", ProbeName(kind), static_cast<unsigned long long>(g_probeRvas[i])); continue; }
            MH_RemoveHook(reinterpret_cast<void*>(address));
            auto create = MH_CreateHook(reinterpret_cast<void*>(address), detours[i], originals[i]);
            auto enable = (create == MH_OK || create == MH_ERROR_ALREADY_CREATED) ? MH_EnableHook(reinterpret_cast<void*>(address)) : create;
            if ((create == MH_OK || create == MH_ERROR_ALREADY_CREATED) && (enable == MH_OK || enable == MH_ERROR_ENABLED))
            { any = true; DvarStatusPrintf("[%s-PROBE] Observing RVA 0x%llX at %p.\n", ProbeName(kind), static_cast<unsigned long long>(g_probeRvas[i]), reinterpret_cast<void*>(address)); }
            else DvarStatusPrintf("[%s-PROBE] Candidate 0x%llX failed: create=%s enable=%s\n", ProbeName(kind), static_cast<unsigned long long>(g_probeRvas[i]), MH_StatusToString(create), MH_StatusToString(enable));
        }
        if (!any) { g_floatProbeRunning.store(false); g_probeKind = ProbeKind::None; }
        else DvarStatusPrintf("[%s-PROBE] Running until stopped. Output: %s\n", ProbeName(kind), ProbeFile(kind));
        return any;
    }

    bool StartProbe(const std::string& mode)
    {
        static constexpr std::uintptr_t floatRvas[3] =
    {
        t9_addresses::Retail.Dvar_SetFloatCandidateA,
        t9_addresses::Retail.Dvar_SetFloatFromSource,
        t9_addresses::Retail.Dvar_SetFloatCandidateC
    };
        static constexpr std::uintptr_t intRvas[3]     = { 0x0D2B7820, 0x01A3AD50, 0x0C070530 };
        static constexpr std::uintptr_t variantRvas[3] = { 0x0D2B7820, 0x0D2B7740, 0x0C070530 };
        static constexpr std::uintptr_t vectorRvas[3]  = { 0x0C06B8D0, 0x0C58FB50, 0x0C070530 };
        static constexpr std::uintptr_t lookupRvas[3]  = { 0x0D2B7820, 0x0D2B7740, 0x0D2DE840 };
        static constexpr std::uintptr_t commandRvas[3] = { 0x01A3AD50, 0x00E525E0, 0x01A5E7B0 };
        if (mode == "float") return StartProbeInternal(ProbeKind::Float, floatRvas);
        if (mode == "int" || mode == "enum") return StartProbeInternal(ProbeKind::IntEnum, intRvas);
        if (mode == "variant") return StartProbeInternal(ProbeKind::Variant, variantRvas);
        if (mode == "vector") return StartProbeInternal(ProbeKind::Vector, vectorRvas);
        if (mode == "lookup") return StartProbeInternal(ProbeKind::Lookup, lookupRvas);
        if (mode == "command") return StartProbeInternal(ProbeKind::Command, commandRvas);
        return false;
    }

    void StopProbe()
    {
        if (!g_floatProbeRunning.exchange(false)) { DvarStatusPrintf("[DVAR-PROBE] No dedicated probe is running.\n"); return; }
        const auto kind = g_probeKind;
        for (auto rva : g_probeRvas) {
            auto* target = reinterpret_cast<void*>(g_Addrs.ModuleBase + rva);
            MH_DisableHook(target);
            MH_RemoveHook(target);
        }
        if (kind == ProbeKind::Command)
        {
            WriteCommandProbeSummary();
            WriteCommandParentHints();
            DvarStatusPrintf("[COMMAND-PROBE] Stopped. calls=%llu emitted=%llu string_hits=%llu suppressed=%llu output=%s summary=logs\\scanner\\command_probe_summary.csv parent_hints=logs\\scanner\\command_parent_hints.csv\n",
                g_floatProbeCalls.load(), g_floatProbeInteresting.load(), g_commandStringHits.load(),
                g_commandSuppressed.load(), ProbeFile(kind));
        }
        else
            DvarStatusPrintf("[%s-PROBE] Stopped. calls=%llu interesting=%llu output=%s\n", ProbeName(kind), g_floatProbeCalls.load(), g_floatProbeInteresting.load(), ProbeFile(kind));
        g_probeKind = ProbeKind::None;
    }

    void PrintProbeStatus()
    {
        if (g_probeKind == ProbeKind::Command)
        {
            DvarStatusPrintf(
                "[COMMAND-PROBE] status=%s calls=%llu emitted=%llu string_hits=%llu suppressed=%llu candidates=0x%llX,0x%llX,0x%llX output=%s\n",
                g_floatProbeRunning.load() ? "running" : "idle",
                g_floatProbeCalls.load(),
                g_floatProbeInteresting.load(),
                g_commandStringHits.load(),
                g_commandSuppressed.load(),
                static_cast<unsigned long long>(g_probeRvas[0]),
                static_cast<unsigned long long>(g_probeRvas[1]),
                static_cast<unsigned long long>(g_probeRvas[2]),
                ProbeFile(g_probeKind));
        }
        else
        {
            DvarStatusPrintf(
                "[DVAR-PROBE] status=%s mode=%s calls=%llu interesting=%llu candidates=0x%llX,0x%llX,0x%llX output=%s\n",
                g_floatProbeRunning.load() ? "running" : "idle",
                ProbeName(g_probeKind),
                g_floatProbeCalls.load(),
                g_floatProbeInteresting.load(),
                static_cast<unsigned long long>(g_probeRvas[0]),
                static_cast<unsigned long long>(g_probeRvas[1]),
                static_cast<unsigned long long>(g_probeRvas[2]),
                ProbeFile(g_probeKind));
        }
    }

    bool StartFloatProbe() { return StartProbe("float"); }
    void StopFloatProbe() { StopProbe(); }
    void PrintFloatProbeStatus() { PrintProbeStatus(); }

    void PrintLiveCaptureStatus()
    {
        DvarStatusPrintf("[DVAR-LIVE] session=0x%llX status=%s passes=%llu resolved=%llu events=%llu findvar=%s bool_hook=%s string_hook=%s outputs=logs\\scanner\\live_dvar_capture.csv,logs\\scanner\\live_dvar_setters.csv\n",
            static_cast<unsigned long long>(g_captureSessionId), g_liveCaptureRunning.load() ? "running" : "idle", g_liveCapturePasses.load(),
            g_liveCaptureResolved.load(), g_liveCaptureEvents.load(), g_Addrs.Dvar_FindVar ? "yes" : "no",
            g_boolHookInstalled.load() ? "yes" : "no", g_stringHookInstalled.load() ? "yes" : "no");
        DvarStatusPrintf("[ENGINE-HOOK] find=%s guessed_hooks=disabled discovery=%s callsites=%llu nearby_targets=%llu\n",
            g_findVarHookInstalled.load() ? "yes" : "no", g_discoveryComplete.load() ? "complete" : "pending",
            g_discoveryCallsites.load(), g_discoveryTargets.load());
    }

    struct FloatDomainPair
    {
        std::size_t offset = 0;
        float minimum = 0.0f;
        float maximum = 0.0f;
    };

    bool TryExpandCgFovDomain(std::uintptr_t dvar, std::string& detail)
    {
        // We do not assume a dvar_t layout. Search only the first 0x100 bytes for
        // ONE adjacent float min/max pair matching the menu's observed FOV limits.
        // If the match is ambiguous we leave memory untouched.
        unsigned char bytes[0x100]{};
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(dvar),
            bytes, sizeof(bytes), &got) || got != sizeof(bytes))
        {
            detail = "domain inspection unavailable";
            return false;
        }

        std::vector<FloatDomainPair> matches;
        for (std::size_t off = 0; off + 8 <= sizeof(bytes); off += 4)
        {
            float lo = 0.0f, hi = 0.0f;
            std::memcpy(&lo, bytes + off, sizeof(float));
            std::memcpy(&hi, bytes + off + 4, sizeof(float));
            if (!std::isfinite(lo) || !std::isfinite(hi)) continue;

            const bool plausibleLow = lo >= 40.0f && lo <= 80.0f;
            const bool plausibleHigh = hi >= 100.0f && hi <= 130.0f;
            if (plausibleLow && plausibleHigh && lo < hi)
                matches.push_back({ off, lo, hi });
        }

        if (matches.size() != 1)
        {
            std::ostringstream out;
            out << "FOV domain pair not uniquely identified (matches=" << matches.size() << ")";
            detail = out.str();
            return false;
        }

        const float unlockedMin = -FLT_MAX;
        const float unlockedMax = FLT_MAX;
        SIZE_T wrote = 0;
        const auto loAddress = dvar + matches[0].offset;
        const auto hiAddress = dvar + matches[0].offset + 4;

        if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(loAddress),
                &unlockedMin, sizeof(unlockedMin), &wrote) || wrote != sizeof(unlockedMin))
        {
            detail = "could not write FOV minimum domain";
            return false;
        }
        if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(hiAddress),
                &unlockedMax, sizeof(unlockedMax), &wrote) || wrote != sizeof(unlockedMax))
        {
            detail = "could not write FOV maximum domain";
            return false;
        }

        std::ostringstream out;
        out << "domain expanded at +0x" << std::hex << std::uppercase << matches[0].offset
            << std::dec << " from " << matches[0].minimum << "-" << matches[0].maximum
            << " to full finite float range";
        detail = out.str();
        return true;
    }

    ExecuteResult ExecuteBuiltinSlashDvar(const std::string& rawName, const std::string& rawValue, std::string& message)
    {
        std::string name = Lower(Trim(rawName));
        const std::string valueText = Trim(rawValue);
        if (name.empty()) return ExecuteResult::NotFound;

        struct KnownDvar
        {
            const char* name;
            std::uintptr_t rva;
            enum class Kind { Bool, Float } kind;
        };

        static constexpr KnownDvar known[] =
        {
            { "cg_fov",                0x0EB82B80, KnownDvar::Kind::Float },
                        { "mute_sound",            0x0EBB7C00, KnownDvar::Kind::Bool  },
            { "voice_chat_enabled",    0x0EB82280, KnownDvar::Kind::Bool  },
            { "microphone_activation", 0x0EB82580, KnownDvar::Kind::Bool  },
            { "subtitles",             0x0EBB7AC0, KnownDvar::Kind::Bool  },
            { "intro_movie",           0x0EB7FF80, KnownDvar::Kind::Bool  },
        };

        const KnownDvar* item = nullptr;
        for (const auto& candidate : known)
            if (name == candidate.name) { item = &candidate; break; }
        if (!item) return ExecuteResult::NotFound;

        if (!g_Addrs.ModuleBase)
        {
            message = "game module base is unavailable";
            return ExecuteResult::Fault;
        }

        const std::uintptr_t dvar = g_Addrs.ModuleBase + item->rva;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(dvar), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || mbi.Protect == PAGE_NOACCESS)
        {
            message = std::string(item->name) + " dvar address is unreadable";
            return ExecuteResult::Fault;
        }

        if (valueText.empty())
        {
            std::ostringstream out;
            out << item->name << " address=" << reinterpret_cast<const void*>(dvar)
                << " rva=0x" << std::hex << std::uppercase << item->rva;
            message = out.str();
            return ExecuteResult::Read;
        }

        if (item->kind == KnownDvar::Kind::Bool)
        {
            std::string lowered = Lower(valueText);
            if (lowered != "0" && lowered != "1" && lowered != "on" && lowered != "off" &&
                lowered != "true" && lowered != "false")
            {
                message = std::string(item->name) + " expects 0|1|on|off";
                return ExecuteResult::Rejected;
            }
            const bool enabled = lowered == "1" || lowered == "on" || lowered == "true";
            Dvar_SetBoolFromSource(dvar, enabled, 0);
            message = std::string(item->name) + " set to " + (enabled ? "1" : "0");
            return ExecuteResult::Set;
        }

        char* end = nullptr;
        errno = 0;
        const float value = std::strtof(valueText.c_str(), &end);
        if (errno != 0 || !end || *end != '\0' || !std::isfinite(value) || value < 1.0f || value > 180.0f)
        {
            message = "cg_fov expects any finite numeric value";
            return ExecuteResult::Rejected;
        }

        const std::uintptr_t setterAddress = t9_addresses::Resolve(g_Addrs.ModuleBase, t9_addresses::Retail.Dvar_SetFloatFromSource);
        if (!IsExecutableAddress(setterAddress))
        {
            message = "Dvar_SetFloatFromSource from T9Addresses is unavailable";
            return ExecuteResult::Fault;
        }

        std::string domainDetail;
        const bool domainExpanded = TryExpandCgFovDomain(dvar, domainDetail);

        using DvarSetFloatFromSourceFn = void(*)(std::uintptr_t, float, int);
        reinterpret_cast<DvarSetFloatFromSourceFn>(setterAddress)(dvar, value, 0);
        std::ostringstream out;
        out << "cg_fov requested=" << value << " using dvar=" << reinterpret_cast<const void*>(dvar)
            << " setter=" << reinterpret_cast<const void*>(setterAddress)
            << " [" << domainDetail << "]";
        if (!domainExpanded)
            out << " (setter may still clamp; no guessed layout was written)";
        message = out.str();
        return ExecuteResult::Set;
    }

}
