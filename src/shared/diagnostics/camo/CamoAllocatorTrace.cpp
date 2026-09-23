#include "CamoAllocatorTrace.h"

#include "../../features/camo/CamoManager.h"
#include "../../core/Main.hpp"
#include "../../features/CamoPrototype1.h"
#include "../../runtime/LogPaths.h"

#include <Windows.h>
#include <fstream>
#include <sstream>
#include <mutex>
#include <atomic>
#include <cctype>
#include <string>
#include <cstddef>
#include <iomanip>
#include <cstring>
#include <map>
#include <algorithm>
#include <unordered_set>
#include <vector>
#include <TlHelp32.h>

namespace
{
    constexpr DWORD kCaptureDurationMs = 10u * 60u * 1000u;
    constexpr DWORD kPrePoolPollMs = 100u;
    constexpr DWORD kActivePollMs = 25u;

    struct WatchedState
    {
        std::uintptr_t camoPool = 0;
        std::uintptr_t bindingPool = 0;
        std::uintptr_t camoFreeHead = 0;
        unsigned int camoAllocCount = 0;
        std::uintptr_t bindingFreeHead = 0;
        unsigned int bindingAllocCount = 0;
    };

    std::atomic<bool> g_startedOnce{false};
    std::atomic<bool> g_running{false};
    std::atomic<bool> g_stop{false};
    std::atomic<DWORD> g_startTick{0};
    std::atomic<unsigned int> g_changes{0};
    std::atomic<unsigned int> g_missedSnapshots{0};

    std::mutex g_startStopMutex;
    std::string g_sessionDir;
    std::mutex g_stateMutex;
    WatchedState g_last{};
    bool g_haveBaseline = false;

    std::string Hex(std::uintptr_t v)
    {
        std::ostringstream o;
        o << "0x" << std::hex << std::uppercase << v;
        return o.str();
    }

    std::string Stamp()
    {
        SYSTEMTIME st{};
        GetLocalTime(&st);

        char b[64]{};
        sprintf_s(
            b,
            "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            st.wMilliseconds);
        return b;
    }

    void PrepareSessionDirectory()
    {
        log_paths::EnsureAll();

        SYSTEMTIME st{};
        GetLocalTime(&st);

        char folder[256]{};
        sprintf_s(
            folder,
            "logs\\camo\\research_%04u%02u%02u-%02u%02u%02u-%03u_pid%lu_tick%lu",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetTickCount()));

        CreateDirectoryA("logs", nullptr);
        CreateDirectoryA("logs\\camo", nullptr);
        CreateDirectoryA(folder, nullptr);

        g_sessionDir = folder;
    }

    std::string CapturePath(const char* fileName)
    {
        if (g_sessionDir.empty())
            return std::string("logs\\camo\\") + (fileName ? fileName : "capture.log");

        return g_sessionDir + "\\" + (fileName ? fileName : "capture.log");
    }

    bool ReadCurrent(WatchedState& out)
    {
        camo_manager::AllocatorResearchSnapshot s{};

        // This path works before delayed runtime services and before /scan camo.
        if (!camo_manager::TryResolveAllocatorResearchSnapshotEarly(s))
        {
            // Once the normal camo runtime/scanner/runtime has populated its snapshot,
            // it remains a valid fallback.
            if (!camo_manager::GetAllocatorResearchSnapshot(s))
                return false;
        }

        out.camoPool = s.weaponCamoPool;
        out.bindingPool = s.weaponCamoBindingPool;
        out.camoFreeHead = s.weaponCamoFreeHead;
        out.camoAllocCount = s.weaponCamoItemAllocCount;
        out.bindingFreeHead = s.weaponCamoBindingFreeHead;
        out.bindingAllocCount = s.weaponCamoBindingItemAllocCount;

        return true;
    }

    void Lifecycle(const char* event, const char* note)
    {
        log_paths::EnsureAll();

        std::ofstream f(
            CapturePath("startup_capture.log"),
            std::ios::app);

        if (!f)
            return;

        f << '[' << Stamp() << "] " << event;

        if (note && *note)
            f << " - " << note;

        f << '\n';
    }

    void Snapshot(const char* reason, const WatchedState& s)
    {
        log_paths::EnsureAll();

        std::ofstream f(
            CapturePath("startup_allocator_snapshot.txt"),
            std::ios::trunc);

        if (!f)
            return;

        f << "[STARTUP CAMO ALLOCATOR CAPTURE]\n";
        f << "reason=" << (reason ? reason : "") << "\n";
        f << "timestamp=" << Stamp() << "\n";
        f << "running=" << (g_running.load() ? "yes" : "no") << "\n";
        f << "changes=" << g_changes.load() << "\n";
        f << "missedSnapshots=" << g_missedSnapshots.load() << "\n";
        f << "WeaponCamoPool=" << Hex(s.camoPool) << "\n";
        f << "WeaponCamo.freeHead=" << Hex(s.camoFreeHead) << "\n";
        f << "WeaponCamo.itemAllocCount=" << s.camoAllocCount << "\n";
        f << "BindingPool=" << Hex(s.bindingPool) << "\n";
        f << "Binding.freeHead=" << Hex(s.bindingFreeHead) << "\n";
        f << "Binding.itemAllocCount=" << s.bindingAllocCount << "\n";
    }

    void Change(
        const char* label,
        const WatchedState& before,
        const WatchedState& after)
    {
        log_paths::EnsureAll();

        std::ofstream f(
            CapturePath("startup_allocator_changes.csv"),
            std::ios::app);

        if (!f)
            return;

        if (f.tellp() == 0)
        {
            f << "timestamp,label,"
                 "camo_free_before,camo_free_after,"
                 "camo_alloc_before,camo_alloc_after,"
                 "binding_free_before,binding_free_after,"
                 "binding_alloc_before,binding_alloc_after\n";
        }

        f << Stamp() << ','
          << label << ','
          << Hex(before.camoFreeHead) << ','
          << Hex(after.camoFreeHead) << ','
          << before.camoAllocCount << ','
          << after.camoAllocCount << ','
          << Hex(before.bindingFreeHead) << ','
          << Hex(after.bindingFreeHead) << ','
          << before.bindingAllocCount << ','
          << after.bindingAllocCount << '\n';

        ++g_changes;
    }


    PVOID g_writerVeh = nullptr;
    std::mutex g_watchMutex;
    std::atomic<unsigned int> g_writerEvents{0};
    std::atomic<unsigned int> g_threadsArmed{0};
    constexpr unsigned int kMaxSamplesPerWriter = 6;
    constexpr unsigned int kMaxUnwindFrames = 10;
    std::mutex g_sampleMutex;
    std::map<std::string, unsigned int> g_writerSampleCounts;
    std::atomic<unsigned int> g_uniqueWriterPaths{0};
    std::atomic<unsigned int> g_callerSamples{0};
    std::atomic<bool> g_registrationReportWritten{false};
    std::atomic<bool> g_registrationReportStartupAttempted{false};
    std::atomic<bool> g_registrationReportStartupSucceeded{false};
    std::atomic<unsigned int> g_wrapperProbeEvents{0};
    std::atomic<unsigned int> g_camoInitialPost{0};
    std::atomic<unsigned int> g_camoPreparePost{0};
    std::atomic<unsigned int> g_camoDbPost{0};
    std::atomic<unsigned int> g_camoFinalStage{0};
    constexpr unsigned int kMaxCamoStageSamples = 16;
    std::atomic<bool> g_wrapperProbeComplete{false};
    std::atomic<bool> g_runtimeParentCaptured{false};
    std::atomic<unsigned int> g_runtimeParentCaptures{0};
    std::atomic<bool> g_bridgeCaptured{false};
    std::atomic<unsigned int> g_bridgeCaptures{0};
    std::atomic<bool> g_prototypeReady{false};
    std::unordered_set<DWORD> g_seenThreads;

    struct WatchAddresses
    {
        std::uintptr_t initialPost = 0;
        std::uintptr_t preparePost = 0;
        std::uintptr_t dbPost = 0;
        std::uintptr_t finalStage = 0;
        bool valid = false;
    };

    WatchAddresses g_watch{};

    bool BuildWatchAddresses(WatchAddresses& out)
    {
        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
            return false;

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        // WeaponCamo wrapper function: RVA 0x01C0A515 .. 0x01C0A552
        //
        // +0x00 CALL shared setup
        // +0x05 first instruction after setup CALL
        // +0x1E CALL WeaponCamo prepare helper (0x01C0A030)
        // +0x23 first instruction after prepare helper
        // +0x28 CALL shared DB allocation wrapper (0x0B2C90B0)
        // +0x2D first instruction after DB call
        // +0x38 final register restore / end-stage region
        //
        // Using POST addresses avoids the unreliable function-entry breakpoint
        // observed in 174b while still exposing each transformation stage.
        out.initialPost = base + 0x01C0A51A;

        out.preparePost =
            base + 0x01C0A538;

        out.dbPost =
            base + 0x01C0A542;

        out.finalStage =
            base + 0x01C0A54D;

        out.valid =
            out.initialPost &&
            out.preparePost &&
            out.dbPost &&
            out.finalStage;

        return out.valid;
    }

    const char* WatchLabelForDr6(DWORD64 dr6)
    {
        if (dr6 & 0x1) return "WEAPONCAMO_STAGE1_INITIAL_POST";
        if (dr6 & 0x2) return "WEAPONCAMO_STAGE2_PREPARE_POST";
        if (dr6 & 0x4) return "WEAPONCAMO_STAGE3_DB_POST";
        if (dr6 & 0x8) return "WEAPONCAMO_STAGE4_FINAL";
        return "UNKNOWN_DEBUG_EVENT";
    }

    std::uintptr_t WatchFieldForDr6(DWORD64 dr6)
    {
        std::lock_guard<std::mutex> lock(g_watchMutex);

        if (dr6 & 0x1) return g_watch.initialPost;
        if (dr6 & 0x2) return g_watch.preparePost;
        if (dr6 & 0x4) return g_watch.dbPost;
        if (dr6 & 0x8) return g_watch.finalStage;
        return 0;
    }



    struct RegistrationTarget
    {
        const char* label;
        std::uintptr_t rva;
    };

    constexpr RegistrationTarget kRegistrationTargets[] =
    {
        { "WeaponCamo_TypeSpecific",      0x01C0A542 },
        { "WeaponCamoBinding_TypeSpecific", 0x01C0A382 },
        { "WeaponCamo_PrepareHelper",       0x01C0A030 },
        { "WeaponCamoBinding_PrepareHelper", 0x01C0A110 },
        { "Shared_DB_Core",                    0x0B2CBC40 },
        { "Shared_PreAllocator",          0x0B2C90B9 },
        { "Shared_Mid",                   0x0B2CBD73 },
        { "Shared_NearAllocator",         0x0B2C9232 },
        { "Shared_Upper",                 0x0AAA8B1A },
        { "Shared_Post1",                 0x0B2CC762 },
        { "Shared_Post2",                 0x0B2CC27F },
        { "Shared_Post3",                 0x0B2CD3BC }
    };

    bool ReadBytes(
        std::uintptr_t address,
        std::vector<unsigned char>& bytes,
        std::size_t size)
    {
        bytes.assign(size, 0);
        SIZE_T got = 0;

        if (!ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(address),
                bytes.data(),
                bytes.size(),
                &got) ||
            got == 0)
        {
            bytes.clear();
            return false;
        }

        bytes.resize(static_cast<std::size_t>(got));
        return true;
    }

    void DumpDirectRel32Targets(
        std::ofstream& out,
        std::uintptr_t start,
        const std::vector<unsigned char>& bytes)
    {
        out << "  [direct rel32 branches]\n";

        unsigned int count = 0;

        for (std::size_t i = 0; i + 5 <= bytes.size(); ++i)
        {
            const unsigned char op = bytes[i];

            if (op != 0xE8 && op != 0xE9)
                continue;

            std::int32_t disp = 0;
            std::memcpy(&disp, bytes.data() + i + 1, sizeof(disp));

            const auto target =
                static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(start + i + 5) +
                    disp);

            out
                << "    +0x" << std::hex << i
                << " " << (op == 0xE8 ? "CALL" : "JMP")
                << " -> " << Hex(target)
                << std::dec << '\n';

            ++count;
        }

        if (!count)
            out << "    none\n";
    }

    void DumpRipRelativeCandidates(
        std::ofstream& out,
        std::uintptr_t start,
        const std::vector<unsigned char>& bytes)
    {
        out << "  [RIP-relative candidates]\n";

        unsigned int count = 0;

        for (std::size_t i = 0; i + 7 <= bytes.size(); ++i)
        {
            std::size_t opPos = i;

            // Optional REX prefix.
            if ((bytes[opPos] & 0xF0) == 0x40)
            {
                ++opPos;

                if (opPos + 6 > bytes.size())
                    continue;
            }

            const unsigned char opcode = bytes[opPos];

            // Common one-byte opcodes that use ModRM and frequently carry
            // RIP-relative memory operands in x64.
            if (opcode != 0x8B &&
                opcode != 0x89 &&
                opcode != 0x8D &&
                opcode != 0x83 &&
                opcode != 0x81 &&
                opcode != 0xC7 &&
                opcode != 0xFF &&
                opcode != 0x3B &&
                opcode != 0x39 &&
                opcode != 0x85)
            {
                continue;
            }

            const std::size_t modrmPos = opPos + 1;

            if (modrmPos >= bytes.size())
                continue;

            const unsigned char modrm = bytes[modrmPos];

            if ((modrm & 0xC7) != 0x05)
                continue;

            const std::size_t dispPos = modrmPos + 1;

            if (dispPos + 4 > bytes.size())
                continue;

            std::int32_t disp = 0;
            std::memcpy(
                &disp,
                bytes.data() + dispPos,
                sizeof(disp));

            const std::size_t instructionEnd =
                dispPos + 4;

            const auto target =
                static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(
                        start + instructionEnd) +
                    disp);

            out
                << "    +0x" << std::hex << i
                << " opcode=0x"
                << static_cast<unsigned int>(opcode)
                << " -> " << Hex(target)
                << std::dec << '\n';

            ++count;
        }

        if (!count)
            out << "    none\n";
    }

    bool DumpOneRegistrationTarget(
        std::ofstream& out,
        HMODULE module,
        const RegistrationTarget& target)
    {
        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        const auto address =
            base + target.rva;

        out
            << "[" << target.label << "]\n"
            << "targetRva=0x"
            << std::hex << std::uppercase
            << target.rva
            << "\n"
            << "targetAddress="
            << Hex(address)
            << std::dec << '\n';

        DWORD64 imageBase = 0;

        PRUNTIME_FUNCTION rf =
            RtlLookupFunctionEntry(
                static_cast<DWORD64>(address),
                &imageBase,
                nullptr);

        std::uintptr_t functionStart = 0;
        std::uintptr_t functionEnd = 0;

        if (rf)
        {
            functionStart =
                static_cast<std::uintptr_t>(
                    imageBase + rf->BeginAddress);

            functionEnd =
                static_cast<std::uintptr_t>(
                    imageBase + rf->EndAddress);
        }
        else
        {
            // Fallback window if unwind metadata is unavailable.
            functionStart =
                address >= 0x200
                    ? address - 0x200
                    : address;

            functionEnd =
                address + 0x400;
        }

        if (functionEnd <= functionStart)
        {
            out << "invalid function range\n\n";
            return false;
        }

        std::size_t size =
            static_cast<std::size_t>(
                functionEnd - functionStart);

        constexpr std::size_t kMaxFunctionBytes =
            0x20000;

        if (size > kMaxFunctionBytes)
            size = kMaxFunctionBytes;

        std::vector<unsigned char> bytes;

        if (!ReadBytes(
                functionStart,
                bytes,
                size))
        {
            out << "function bytes unreadable\n\n";
            return false;
        }

        out
            << "functionStart="
            << Hex(functionStart)
            << "\nfunctionEnd="
            << Hex(functionStart + bytes.size())
            << "\nfunctionSize=0x"
            << std::hex << bytes.size()
            << "\ntargetOffset=0x"
            << (address - functionStart)
            << std::dec << '\n';

        DumpDirectRel32Targets(
            out,
            functionStart,
            bytes);

        DumpRipRelativeCandidates(
            out,
            functionStart,
            bytes);

        out << "  [function bytes]\n";

        for (std::size_t i = 0;
             i < bytes.size();
             ++i)
        {
            if ((i % 16) == 0)
            {
                out
                    << "    "
                    << Hex(functionStart + i)
                    << ": ";
            }

            out
                << std::hex
                << std::uppercase
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned int>(bytes[i])
                << ' ';

            if ((i % 16) == 15)
                out << '\n';
        }

        if ((bytes.size() % 16) != 0)
            out << '\n';

        out << std::dec << '\n';
        return true;
    }

    bool GenerateRegistrationFunctionReport(
        std::string* message)
    {
        HMODULE module =
            GetModuleHandleW(nullptr);

        if (!module)
        {
            if (message)
                *message = "main module is unavailable.";
            return false;
        }

        log_paths::EnsureAll();

        std::ofstream out(
            CapturePath(
                "registration_function_compare.txt"),
            std::ios::trunc);

        if (!out)
        {
            if (message)
                *message =
                    "could not create registration_function_compare.txt";
            return false;
        }

        out
            << "[T9 CAMO REGISTRATION CALLER COMPARISON]\n"
            << "Generated=" << Stamp() << "\n"
            << "Purpose: compare the type-specific WeaponCamo and "
               "WeaponCamoBinding caller functions and their shared "
               "allocator chain.\n\n";

        unsigned int dumped = 0;

        for (const auto& target :
             kRegistrationTargets)
        {
            if (DumpOneRegistrationTarget(
                    out,
                    module,
                    target))
            {
                ++dumped;
            }
        }

        // Compact side-by-side target windows around the two branch-specific
        // points seen in the caller chains.
        out << "[TYPE-SPECIFIC SIDE-BY-SIDE WINDOW]\n";

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        const auto camoAddress =
            base + 0x01C0A542;

        const auto bindingAddress =
            base + 0x01C0A382;

        constexpr std::size_t kCompareBefore = 0x80;
        constexpr std::size_t kCompareSize = 0x180;

        std::vector<unsigned char> camoBytes;
        std::vector<unsigned char> bindingBytes;

        ReadBytes(
            camoAddress - kCompareBefore,
            camoBytes,
            kCompareSize);

        ReadBytes(
            bindingAddress - kCompareBefore,
            bindingBytes,
            kCompareSize);

        const std::size_t rows =
            std::min(
                camoBytes.size(),
                bindingBytes.size());

        for (std::size_t i = 0;
             i < rows;
             i += 16)
        {
            out
                << "C "
                << Hex(
                    camoAddress -
                    kCompareBefore + i)
                << "  ";

            for (std::size_t j = 0;
                 j < 16 && i + j < camoBytes.size();
                 ++j)
            {
                out
                    << std::hex
                    << std::uppercase
                    << std::setw(2)
                    << std::setfill('0')
                    << static_cast<unsigned int>(
                        camoBytes[i + j])
                    << ' ';
            }

            out << "\nB "
                << Hex(
                    bindingAddress -
                    kCompareBefore + i)
                << "  ";

            for (std::size_t j = 0;
                 j < 16 && i + j < bindingBytes.size();
                 ++j)
            {
                out
                    << std::hex
                    << std::uppercase
                    << std::setw(2)
                    << std::setfill('0')
                    << static_cast<unsigned int>(
                        bindingBytes[i + j])
                    << ' ';
            }

            out << "\n\n";
        }

        out << std::dec
            << "[SUMMARY]\n"
            << "targetsDumped=" << dumped
            << "/" << std::size(kRegistrationTargets)
            << "\n";

        if (message)
        {
            std::ostringstream status;
            status
                << "registration caller report dumped "
                << dumped
                << "/"
                << std::size(kRegistrationTargets)
                << " targets to "
                << CapturePath(
                    "registration_function_compare.txt");

            *message = status.str();
        }

        return dumped != 0;
    }


    bool WrapperProbeHasEnoughSamples()
    {
        return
            g_camoInitialPost.load() >= kMaxCamoStageSamples &&
            g_camoPreparePost.load() >= kMaxCamoStageSamples &&
            g_camoDbPost.load() >= kMaxCamoStageSamples &&
            g_camoFinalStage.load() >= kMaxCamoStageSamples;
    }



    std::vector<std::uintptr_t> UnwindCallerChainRuntime(
        const CONTEXT& source)
    {
        constexpr unsigned int kFrames = 12;

        std::vector<std::uintptr_t> frames;
        frames.reserve(kFrames);

        CONTEXT ctx = source;

        for (unsigned int depth = 0;
             depth < kFrames;
             ++depth)
        {
            if (!ctx.Rip)
                break;

            frames.push_back(
                static_cast<std::uintptr_t>(ctx.Rip));

            DWORD64 imageBase = 0;
            PRUNTIME_FUNCTION fn =
                RtlLookupFunctionEntry(
                    ctx.Rip,
                    &imageBase,
                    nullptr);

            if (fn)
            {
                PVOID handlerData = nullptr;
                DWORD64 establisherFrame = 0;
                KNONVOLATILE_CONTEXT_POINTERS nv{};

                RtlVirtualUnwind(
                    UNW_FLAG_NHANDLER,
                    imageBase,
                    ctx.Rip,
                    fn,
                    &ctx,
                    &handlerData,
                    &establisherFrame,
                    &nv);
            }
            else
            {
                // Leaf-function fallback: saved return address is at RSP.
                DWORD64 nextRip = 0;
                SIZE_T got = 0;

                if (!ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(ctx.Rsp),
                        &nextRip,
                        sizeof(nextRip),
                        &got) ||
                    got != sizeof(nextRip))
                {
                    break;
                }

                ctx.Rip = nextRip;
                ctx.Rsp += sizeof(DWORD64);
            }
        }

        return frames;
    }

    bool AddressInsideWeaponCamoWrapper(std::uintptr_t address)
    {
        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
            return false;

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        const auto begin = base + 0x01C0A515;
        const auto end = base + 0x01C0A552;

        return address >= begin && address < end;
    }

    bool DumpContainingFunction(
        std::ofstream& out,
        std::uintptr_t address,
        const char* label)
    {
        if (!address)
            return false;

        DWORD64 imageBase = 0;
        PRUNTIME_FUNCTION rf =
            RtlLookupFunctionEntry(
                static_cast<DWORD64>(address),
                &imageBase,
                nullptr);

        std::uintptr_t functionStart = 0;
        std::uintptr_t functionEnd = 0;

        if (rf)
        {
            functionStart =
                static_cast<std::uintptr_t>(
                    imageBase + rf->BeginAddress);

            functionEnd =
                static_cast<std::uintptr_t>(
                    imageBase + rf->EndAddress);
        }
        else
        {
            functionStart =
                address >= 0x200
                    ? address - 0x200
                    : address;

            functionEnd = address + 0x400;
        }

        if (functionEnd <= functionStart)
            return false;

        std::size_t size =
            static_cast<std::size_t>(
                functionEnd - functionStart);

        if (size > 0x20000)
            size = 0x20000;

        std::vector<unsigned char> bytes;
        if (!ReadBytes(functionStart, bytes, size))
            return false;

        out << '[' << label << "]\n"
            << "address=" << Hex(address) << "\n"
            << "functionStart=" << Hex(functionStart) << "\n"
            << "functionEnd=" << Hex(functionStart + bytes.size()) << "\n"
            << "offset=0x" << std::hex << (address - functionStart)
            << std::dec << "\n";

        DumpDirectRel32Targets(out, functionStart, bytes);
        DumpRipRelativeCandidates(out, functionStart, bytes);

        out << "  [function bytes]\n";
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            if ((i % 16) == 0)
                out << "    " << Hex(functionStart + i) << ": ";

            out << std::hex
                << std::uppercase
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned int>(bytes[i])
                << ' ';

            if ((i % 16) == 15)
                out << '\n';
        }

        if ((bytes.size() % 16) != 0)
            out << '\n';

        out << std::dec << "\n";
        return true;
    }


    bool IsMainModuleAddress(std::uintptr_t address)
    {
        HMODULE module = GetModuleHandleW(nullptr);
        if (!module || !address)
            return false;

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        const auto dos =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        const auto nt =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                base + dos->e_lfanew);

        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        const auto end =
            base +
            static_cast<std::uintptr_t>(
                nt->OptionalHeader.SizeOfImage);

        return address >= base && address < end;
    }

    void DumpMemoryRegion(
        std::ofstream& out,
        const char* label,
        std::uintptr_t address,
        std::size_t size)
    {
        out << "  " << label
            << "_address=" << Hex(address)
            << "\n";

        if (!address || !size)
            return;

        std::vector<unsigned char> bytes(
            size,
            0);

        SIZE_T got = 0;

        if (!ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(address),
                bytes.data(),
                bytes.size(),
                &got) ||
            !got)
        {
            out << "  " << label
                << "_bytes=unreadable\n";
            return;
        }

        out << "  " << label
            << "_bytes=";

        for (SIZE_T i = 0; i < got; ++i)
        {
            out << std::hex
                << std::uppercase
                << std::setw(2)
                << std::setfill('0')
                << static_cast<unsigned int>(
                    bytes[i]);

            if (i + 1 < got)
                out << ' ';
        }

        out << std::dec << "\n";
    }

    void CaptureBridgeReadiness(CONTEXT* ctx)
    {
        if (!ctx)
            return;

        const unsigned int captureIndex =
            ++g_bridgeCaptures;

        if (captureIndex > 12)
            return;

        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
            return;

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        constexpr std::uintptr_t kBridgeRva =
            0x01C0DB20;

        const auto bridgeAddress =
            base + kBridgeRva;

        log_paths::EnsureAll();

        std::ofstream out(
            CapturePath(
                "weaponcamo_bridge_readiness.txt"),
            std::ios::app);

        if (!out)
            return;

        out
            << '[' << Stamp() << "] capture="
            << captureIndex
            << " bridge=" << Hex(bridgeAddress)
            << " breakpointRIP="
            << Hex(static_cast<std::uintptr_t>(ctx->Rip))
            << " thread=" << GetCurrentThreadId()
            << "\n";

        out
            << "  liveRegisters:"
            << " RAX=" << Hex(static_cast<std::uintptr_t>(ctx->Rax))
            << " RBX=" << Hex(static_cast<std::uintptr_t>(ctx->Rbx))
            << " RDI=" << Hex(static_cast<std::uintptr_t>(ctx->Rdi))
            << " RSI=" << Hex(static_cast<std::uintptr_t>(ctx->Rsi))
            << " RCX=" << Hex(static_cast<std::uintptr_t>(ctx->Rcx))
            << " RDX=" << Hex(static_cast<std::uintptr_t>(ctx->Rdx))
            << " R8=" << Hex(static_cast<std::uintptr_t>(ctx->R8))
            << " R9=" << Hex(static_cast<std::uintptr_t>(ctx->R9))
            << " RSP=" << Hex(static_cast<std::uintptr_t>(ctx->Rsp))
            << "\n";

        DumpContainingFunction(
            out,
            bridgeAddress,
            "BRIDGE_FUNCTION_0x01C0DB20");

        // Record key live pointer candidates and stack state without
        // dereferencing arbitrary deep chains.
        DumpMemoryRegion(
            out,
            "stack",
            static_cast<std::uintptr_t>(ctx->Rsp),
            0x100);

        DumpMemoryRegion(
            out,
            "rbx_region",
            static_cast<std::uintptr_t>(ctx->Rbx),
            0x80);

        DumpMemoryRegion(
            out,
            "rdi_region",
            static_cast<std::uintptr_t>(ctx->Rdi),
            0x80);

        DumpMemoryRegion(
            out,
            "rdx_region",
            static_cast<std::uintptr_t>(ctx->Rdx),
            0x80);

        // The bridge itself being a valid in-module executable function plus
        // a live parent chain and the proven 0x2E DB path is enough to mark the
        // research phase ready for a guarded prototype scaffold. This flag does
        // NOT insert an asset; it only records readiness.
        MEMORY_BASIC_INFORMATION mbi{};
        bool executable = false;

        if (VirtualQuery(
                reinterpret_cast<const void*>(bridgeAddress),
                &mbi,
                sizeof(mbi)))
        {
            const DWORD p =
                mbi.Protect & 0xFFu;

            executable =
                mbi.State == MEM_COMMIT &&
                (p == PAGE_EXECUTE ||
                 p == PAGE_EXECUTE_READ ||
                 p == PAGE_EXECUTE_READWRITE ||
                 p == PAGE_EXECUTE_WRITECOPY);
        }

        const bool ready =
            executable &&
            IsMainModuleAddress(bridgeAddress) &&
            g_runtimeParentCaptured.load();

        out
            << "  bridgeExecutable="
            << (executable ? "yes" : "no")
            << "\n"
            << "  runtimeParentCaptured="
            << (g_runtimeParentCaptured.load() ? "yes" : "no")
            << "\n"
            << "  prototypeReadiness="
            << (ready ? "READY_FOR_GUARDED_SCAFFOLD"
                      : "NOT_READY")
            << "\n\n";

        g_bridgeCaptured.store(true);

        if (ready)
            g_prototypeReady.store(true);
    }

    void CaptureRuntimeParentFromContext(CONTEXT* ctx)
    {
        if (!ctx)
            return;

        // We only need a few captures; the first clean one is authoritative.
        const unsigned int captureIndex =
            ++g_runtimeParentCaptures;

        if (captureIndex > 8)
            return;

        const auto frames =
            UnwindCallerChainRuntime(*ctx);

        std::uintptr_t parentReturn = 0;
        std::size_t parentFrameIndex = 0;

        for (std::size_t i = 0; i < frames.size(); ++i)
        {
            if (!AddressInsideWeaponCamoWrapper(frames[i]))
            {
                // frame[0] is the breakpoint RIP itself. Skip it if unwind
                // returned a non-wrapper address unexpectedly.
                if (i == 0)
                    continue;

                parentReturn = frames[i];
                parentFrameIndex = i;
                break;
            }
        }

        log_paths::EnsureAll();

        std::ofstream out(
            CapturePath("weaponcamo_runtime_parent.txt"),
            std::ios::app);

        if (!out)
            return;

        out << '[' << Stamp() << "] capture=" << captureIndex
            << " breakpointRIP="
            << Hex(static_cast<std::uintptr_t>(ctx->Rip))
            << " thread=" << GetCurrentThreadId()
            << "\n";

        out << "  registers:"
            << " RAX=" << Hex(static_cast<std::uintptr_t>(ctx->Rax))
            << " RBX=" << Hex(static_cast<std::uintptr_t>(ctx->Rbx))
            << " RDI=" << Hex(static_cast<std::uintptr_t>(ctx->Rdi))
            << " RSI=" << Hex(static_cast<std::uintptr_t>(ctx->Rsi))
            << " RCX=" << Hex(static_cast<std::uintptr_t>(ctx->Rcx))
            << " RDX=" << Hex(static_cast<std::uintptr_t>(ctx->Rdx))
            << " R8=" << Hex(static_cast<std::uintptr_t>(ctx->R8))
            << " R9=" << Hex(static_cast<std::uintptr_t>(ctx->R9))
            << " RSP=" << Hex(static_cast<std::uintptr_t>(ctx->Rsp))
            << "\n";

        out << "  unwindFrames=" << frames.size() << "\n";
        for (std::size_t i = 0; i < frames.size(); ++i)
        {
            out << "    frame[" << i << "]="
                << Hex(frames[i]);

            if (i == parentFrameIndex && parentReturn)
                out << "  <parent-return>";

            out << '\n';
        }

        // Snapshot stack around the live wrapper context. This catches parent
        // shadow-space / stack arguments without assuming a prototype.
        unsigned char stackBytes[0x100]{};
        SIZE_T got = 0;
        if (ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(ctx->Rsp),
                stackBytes,
                sizeof(stackBytes),
                &got) &&
            got)
        {
            out << "  stackBytes=";
            for (SIZE_T i = 0; i < got; ++i)
            {
                out << std::hex
                    << std::uppercase
                    << std::setw(2)
                    << std::setfill('0')
                    << static_cast<unsigned int>(stackBytes[i]);
                if (i + 1 < got)
                    out << ' ';
            }
            out << std::dec << "\n";
        }

        if (parentReturn)
        {
            DumpContainingFunction(
                out,
                parentReturn,
                "RUNTIME_PARENT_FUNCTION");

            // Record a probable direct CALL site only when it actually validates.
            // This is diagnostic; parent discovery itself does NOT depend on it.
            if (parentReturn >= 5)
            {
                unsigned char callBytes[5]{};
                SIZE_T read = 0;

                if (ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(parentReturn - 5),
                        callBytes,
                        sizeof(callBytes),
                        &read) &&
                    read == sizeof(callBytes) &&
                    callBytes[0] == 0xE8)
                {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, callBytes + 1, sizeof(disp));

                    const auto target =
                        static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(parentReturn) + disp);

                    HMODULE module = GetModuleHandleW(nullptr);
                    const auto expected =
                        module
                            ? reinterpret_cast<std::uintptr_t>(module) + 0x01C0A515
                            : 0;

                    out << "  probableDirectCallSite="
                        << Hex(parentReturn - 5)
                        << " target=" << Hex(target)
                        << " matchesWrapper="
                        << (target == expected ? "yes" : "no")
                        << "\n";
                }
            }
        }
        else
        {
            out << "  parentReturn=not_resolved\n";
        }

        out << '\n';

        if (parentReturn)
            g_runtimeParentCaptured.store(true);
    }

    void WriteWrapperProbeEvent(
        const char* label,
        std::uintptr_t address,
        CONTEXT* ctx)
    {
        if (!ctx)
            return;

        ++g_wrapperProbeEvents;

        const bool stage1 = (ctx->Dr6 & 0x1) != 0;
        const bool stage2 = (ctx->Dr6 & 0x2) != 0;
        const bool stage3 = (ctx->Dr6 & 0x4) != 0;
        const bool stage4 = (ctx->Dr6 & 0x8) != 0;

        unsigned int sample = 0;

        if (stage1)
            sample = ++g_camoInitialPost;
        else if (stage2)
            sample = ++g_camoPreparePost;
        else if (stage3)
            sample = ++g_camoDbPost;
        else if (stage4)
            sample = ++g_camoFinalStage;

        if (WrapperProbeHasEnoughSamples())
            g_wrapperProbeComplete.store(true);

        if (sample > kMaxCamoStageSamples)
            return;

        log_paths::EnsureAll();

        auto readPointer =
            [](std::uintptr_t address)
                -> std::uintptr_t
            {
                if (!address)
                    return 0;

                std::uintptr_t value = 0;
                SIZE_T got = 0;

                if (!ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(address),
                        &value,
                        sizeof(value),
                        &got) ||
                    got != sizeof(value))
                {
                    return 0;
                }

                return value;
            };

        const auto rbxAddress =
            static_cast<std::uintptr_t>(ctx->Rbx);

        const auto rdiAddress =
            static_cast<std::uintptr_t>(ctx->Rdi);

        const auto rbxSlotValue =
            readPointer(rbxAddress);

        const auto rdiSlotValue =
            readPointer(rdiAddress);

        std::ofstream csv(
            CapturePath(
                "weaponcamo_stage_probe.csv"),
            std::ios::app);

        if (csv)
        {
            if (csv.tellp() == 0)
            {
                csv
                    << "timestamp,label,address,thread_id,"
                       "rip,rax,rbx,rdi,rsi,rcx,rdx,r8,r9,rsp,"
                       "rbx_slot,rdi_slot\n";
            }

            csv
                << Stamp() << ','
                << label << ','
                << Hex(address) << ','
                << GetCurrentThreadId() << ','
                << Hex(static_cast<std::uintptr_t>(ctx->Rip)) << ','
                << Hex(static_cast<std::uintptr_t>(ctx->Rax)) << ','
                << Hex(static_cast<std::uintptr_t>(ctx->Rbx)) << ','
                << Hex(static_cast<std::uintptr_t>(ctx->Rdi)) << ','
                << Hex(static_cast<std::uintptr_t>(ctx->Rcx)) << ','
                << Hex(static_cast<std::uintptr_t>(ctx->Rdx)) << ','
                << Hex(static_cast<std::uintptr_t>(ctx->R8)) << ','
                << Hex(static_cast<std::uintptr_t>(ctx->R9)) << ','
                << Hex(static_cast<std::uintptr_t>(ctx->Rsp)) << ','
                << Hex(rbxSlotValue) << ','
                << Hex(rdiSlotValue)
                << '\n';
        }

        std::ofstream detail(
            CapturePath(
                "weaponcamo_stage_samples.txt"),
            std::ios::app);

        if (!detail)
            return;

        auto dumpMemory =
            [&](const char* name,
                std::uintptr_t memoryAddress,
                std::size_t size)
            {
                detail
                    << "  " << name
                    << "_address="
                    << Hex(memoryAddress)
                    << '\n';

                if (!memoryAddress || size == 0)
                    return;

                std::vector<unsigned char> bytes(
                    size,
                    0);

                SIZE_T got = 0;

                if (!ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(
                            memoryAddress),
                        bytes.data(),
                        bytes.size(),
                        &got) ||
                    !got)
                {
                    detail
                        << "  " << name
                        << "_bytes=unreadable\n";
                    return;
                }

                detail
                    << "  " << name
                    << "_bytes=";

                for (SIZE_T i = 0; i < got; ++i)
                {
                    detail
                        << std::hex
                        << std::uppercase
                        << std::setw(2)
                        << std::setfill('0')
                        << static_cast<unsigned int>(
                            bytes[i]);

                    if (i + 1 < got)
                        detail << ' ';
                }

                detail << std::dec << '\n';
            };

        detail
            << '[' << Stamp() << "] "
            << label
            << " sample=" << sample
            << " thread=" << GetCurrentThreadId()
            << "\n"
            << "  RIP="
            << Hex(static_cast<std::uintptr_t>(ctx->Rip))
            << " RAX="
            << Hex(static_cast<std::uintptr_t>(ctx->Rax))
            << " RBX="
            << Hex(static_cast<std::uintptr_t>(ctx->Rbx))
            << " RDI="
            << Hex(static_cast<std::uintptr_t>(ctx->Rdi))
            << " RSI="
            << Hex(static_cast<std::uintptr_t>(ctx->Rsi))
            << " RCX="
            << Hex(static_cast<std::uintptr_t>(ctx->Rcx))
            << " RDX="
            << Hex(static_cast<std::uintptr_t>(ctx->Rdx))
            << " R8="
            << Hex(static_cast<std::uintptr_t>(ctx->R8))
            << " R9="
            << Hex(static_cast<std::uintptr_t>(ctx->R9))
            << " RSP="
            << Hex(static_cast<std::uintptr_t>(ctx->Rsp))
            << "\n"
            << "  [RBX]=" << Hex(rbxSlotValue)
            << " [RDI]=" << Hex(rdiSlotValue)
            << "\n";

        // The wrapper uses RBX as its writable asset-pointer slot.
        dumpMemory(
            "rbx_slot_region",
            rbxAddress,
            0x40);

        if (rbxSlotValue)
        {
            dumpMemory(
                "rbx_pointee",
                rbxSlotValue,
                0x80);
        }

        // RDI is conditionally written with the final returned entry.
        if (rdiAddress)
        {
            dumpMemory(
                "rdi_slot_region",
                rdiAddress,
                0x40);
        }

        if (rdiSlotValue)
        {
            dumpMemory(
                "rdi_pointee",
                rdiSlotValue,
                0x80);
        }

        if (stage3 || stage4)
        {
            detail
                << "  stage_transition_slot=[RBX] returned_or_final_RAX"
                << " old_slot=" << Hex(rbxSlotValue)
                << " returned="
                << Hex(static_cast<std::uintptr_t>(
                    ctx->Rax))
                << "\n";

            if (ctx->Rax)
            {
                dumpMemory(
                    "returned_entry",
                    static_cast<std::uintptr_t>(
                        ctx->Rax),
                    0x80);
            }
        }

        detail << '\n';
    }

    void WriteWriterEvent(
        const char* label,
        std::uintptr_t field,
        CONTEXT* ctx)
    {
        if (!ctx)
            return;

        log_paths::EnsureAll();

        std::ofstream f(
            CapturePath("allocator_writer_trace.csv"),
            std::ios::app);

        if (!f)
            return;

        if (f.tellp() == 0)
        {
            f << "timestamp,label,field_address,rip,rsp,thread_id,"
                 "rax,rbx,rcx,rdx,rsi,rdi,r8,r9,r10,r11\n";
        }

        f << Stamp() << ','
          << label << ','
          << Hex(field) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->Rip)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->Rsp)) << ','
          << GetCurrentThreadId() << ','
          << Hex(static_cast<std::uintptr_t>(ctx->Rax)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->Rbx)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->Rcx)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->Rdx)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->Rsi)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->Rdi)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->R8)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->R9)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->R10)) << ','
          << Hex(static_cast<std::uintptr_t>(ctx->R11))
          << '\n';

        ++g_writerEvents;

        // Also save a small code window around RIP for later static analysis.
        unsigned char code[64]{};
        SIZE_T got = 0;
        const auto start =
            ctx->Rip >= 24
                ? static_cast<std::uintptr_t>(ctx->Rip - 24)
                : static_cast<std::uintptr_t>(ctx->Rip);

        if (ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(start),
                code,
                sizeof(code),
                &got) &&
            got)
        {
            std::ofstream w(
                CapturePath("allocator_writer_windows.txt"),
                std::ios::app);

            if (w)
            {
                w << '[' << Stamp() << "] "
                  << label
                  << " RIP=" << Hex(static_cast<std::uintptr_t>(ctx->Rip))
                  << " field=" << Hex(field)
                  << " thread=" << GetCurrentThreadId()
                  << "\n";

                for (SIZE_T i = 0; i < got; ++i)
                {
                    if ((i % 16) == 0)
                    {
                        w << "  " << Hex(start + i) << ": ";
                    }

                    w << std::hex
                      << std::uppercase
                      << std::setw(2)
                      << std::setfill('0')
                      << static_cast<unsigned int>(code[i])
                      << ' ';

                    if ((i % 16) == 15)
                        w << '\n';
                }

                w << std::dec << "\n\n";
            }
        }
    }

    LONG CALLBACK WriterVeh(EXCEPTION_POINTERS* ep)
    {
        if (!ep ||
            !ep->ExceptionRecord ||
            !ep->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
            return EXCEPTION_CONTINUE_SEARCH;

        const DWORD64 dr6 = ep->ContextRecord->Dr6;
        if ((dr6 & 0xF) == 0)
            return EXCEPTION_CONTINUE_SEARCH;


        // Prototype 1 template capture:
        // Parent bytes at RVA 0x0AAA8B10 are:
        //   mov rdx, rbx
        //   xor ecx, ecx
        //   call 0x01C0DB20
        // Therefore at the CALL instruction, RDX is the native 16-byte
        // loader record. CamoPrototype1 keeps it only when record+8 is type 0x2E.
        // Stage1 is logging-only in Build 180.

        // Stage2: WeaponCamo prepare helper has returned.
        // RBX points at the wrapper's source-pointer slot; [RBX] is the fully
        // prepared source object that the stock DB call is about to consume.
        if (dr6 & 0x2)
        {
            std::uintptr_t preparedSource = 0;
            SIZE_T got = 0;

            if (ep->ContextRecord->Rbx &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(
                        ep->ContextRecord->Rbx),
                    &preparedSource,
                    sizeof(preparedSource),
                    &got) &&
                got == sizeof(preparedSource) &&
                preparedSource)
            {
                camo_prototype1::CapturePreparedSource(
                    reinterpret_cast<const void*>(
                        preparedSource),
                    static_cast<std::uintptr_t>(
                        ep->ContextRecord->Rip));
            }
        }

        // Stage4: the game's ORIGINAL WeaponCamo registration is already done,
        // RAX is the stock result, and [RBX] has already been updated.
        // Only now do we make the extra DB-registration attempt.
        if ((dr6 & 0x8) &&
            camo_prototype1::IsPending())
        {
            camo_prototype1::ExecuteAfterStockRegistration(
                static_cast<std::uintptr_t>(
                    ep->ContextRecord->Rax),
                static_cast<std::uintptr_t>(
                    ep->ContextRecord->Rip));
        }

        // All four stage probes are now low-frequency WeaponCamo-only points.
        if (dr6 & 0xFu)
        {
            WriteWrapperProbeEvent(
                WatchLabelForDr6(dr6),
                WatchFieldForDr6(dr6),
                ep->ContextRecord);
        }

        // DR1 is the proven WeaponCamo prepare-helper POST point (0x1C0A538).
        // Unwind the real saved context here instead of scanning the image for
        // a guessed direct parent CALL.
        if (dr6 & 0x2)
            CaptureRuntimeParentFromContext(ep->ContextRecord);
        if (dr6 & 0x2)
            CaptureBridgeReadiness(ep->ContextRecord);

        // Critical for execute hardware breakpoints:
        // RF suppresses the same debug breakpoint for the next instruction
        // execution so the trapped CALL/return instruction can actually run.
        ep->ContextRecord->EFlags |= (1u << 16);
        ep->ContextRecord->Dr6 = 0;

        // After enough complete PRE/POST pairs, disable all four local
        // breakpoint enables on the current thread. Other threads are cleaned
        // up by the existing research-stop path.
        if (g_wrapperProbeComplete.load())
        {
            ep->ContextRecord->Dr7 &= ~0x55ull;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    bool ArmThreadWatchpoints(DWORD threadId)
    {
        if (!g_running.load() ||
            g_wrapperProbeComplete.load())
            return false;

        if (threadId == GetCurrentThreadId())
            return false;

        HANDLE thread =
            OpenThread(
                THREAD_GET_CONTEXT |
                THREAD_SET_CONTEXT |
                THREAD_SUSPEND_RESUME |
                THREAD_QUERY_INFORMATION,
                FALSE,
                threadId);

        if (!thread)
            return false;

        bool ok = false;

        if (SuspendThread(thread) != static_cast<DWORD>(-1))
        {
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (GetThreadContext(thread, &ctx))
            {
                WatchAddresses watch{};

                {
                    std::lock_guard<std::mutex> lock(g_watchMutex);
                    watch = g_watch;
                }

                if (watch.valid)
                {
                    ctx.Dr0 = watch.initialPost;
                    ctx.Dr1 = watch.preparePost;
                    ctx.Dr2 = watch.dbPost;
                    ctx.Dr3 = watch.finalStage;

                    // Four low-frequency WeaponCamo stage execute breakpoints.
                    ctx.Dr7 = 0;
                    ctx.Dr7 |= (1ull << 0);
                    ctx.Dr7 |= (1ull << 2);
                    ctx.Dr7 |= (1ull << 4);
                    ctx.Dr7 |= (1ull << 6);
                    ctx.Dr6 = 0;

                    if (SetThreadContext(thread, &ctx))
                        ok = true;
                }
            }

            ResumeThread(thread);
        }

        CloseHandle(thread);
        return ok;
    }

    void RefreshThreadWatchpoints()
    {
        HANDLE snapshot =
            CreateToolhelp32Snapshot(
                TH32CS_SNAPTHREAD,
                0);

        if (snapshot == INVALID_HANDLE_VALUE)
            return;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);

        const DWORD pid = GetCurrentProcessId();

        if (Thread32First(snapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != pid)
                    continue;

                bool shouldArm = false;

                {
                    std::lock_guard<std::mutex> lock(g_watchMutex);
                    shouldArm =
                        g_seenThreads.insert(
                            te.th32ThreadID).second;
                }

                if (shouldArm &&
                    ArmThreadWatchpoints(
                        te.th32ThreadID))
                {
                    ++g_threadsArmed;
                }
            }
            while (Thread32Next(snapshot, &te));
        }

        CloseHandle(snapshot);
    }

    void DisableWatchpointsOnKnownThreads()
    {
        std::vector<DWORD> tids;

        {
            std::lock_guard<std::mutex> lock(g_watchMutex);
            tids.assign(
                g_seenThreads.begin(),
                g_seenThreads.end());
        }

        for (DWORD tid : tids)
        {
            if (tid == GetCurrentThreadId())
                continue;

            HANDLE thread =
                OpenThread(
                    THREAD_GET_CONTEXT |
                    THREAD_SET_CONTEXT |
                    THREAD_SUSPEND_RESUME,
                    FALSE,
                    tid);

            if (!thread)
                continue;

            if (SuspendThread(thread) != static_cast<DWORD>(-1))
            {
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                if (GetThreadContext(thread, &ctx))
                {
                    ctx.Dr0 = 0;
                    ctx.Dr1 = 0;
                    ctx.Dr2 = 0;
                    ctx.Dr3 = 0;
                    ctx.Dr6 = 0;
                    ctx.Dr7 = 0;
                    SetThreadContext(thread, &ctx);
                }

                ResumeThread(thread);
            }

            CloseHandle(thread);
        }
    }

    DWORD WINAPI Worker(LPVOID)
    {
        g_startTick.store(GetTickCount());
        g_stop.store(false);
        g_changes.store(0);
        g_missedSnapshots.store(0);

        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            g_haveBaseline = false;
            g_last = {};
        }

        PrepareSessionDirectory();

        Lifecycle(
            "START",
            "stable executable reached; 10-minute capture started before delayed build initialization");


        g_registrationReportStartupAttempted.store(true);

        {
            std::string registrationMessage;
            const bool registrationOk =
                GenerateRegistrationFunctionReport(
                    &registrationMessage);

            g_registrationReportStartupSucceeded.store(
                registrationOk);

            g_registrationReportWritten.store(
                registrationOk);

            Lifecycle(
                registrationOk
                    ? "REGISTRATION_REPORT_OK"
                    : "REGISTRATION_REPORT_FAILED",
                registrationMessage.c_str());
        }


        {
            std::lock_guard<std::mutex> lock(g_watchMutex);
            g_seenThreads.clear();
            g_watch = {};
            BuildWatchAddresses(g_watch);
        }

        g_writerEvents.store(0);
        g_threadsArmed.store(0);
        g_wrapperProbeEvents.store(0);
        g_camoInitialPost.store(0);
        g_camoPreparePost.store(0);
        g_camoDbPost.store(0);
        g_camoFinalStage.store(0);
        g_wrapperProbeComplete.store(false);
        g_runtimeParentCaptured.store(false);
        g_runtimeParentCaptures.store(0);
        g_bridgeCaptured.store(false);
        g_bridgeCaptures.store(0);
        g_prototypeReady.store(false);
        g_uniqueWriterPaths.store(0);
        g_callerSamples.store(0);
        g_registrationReportWritten.store(false);
        g_registrationReportStartupAttempted.store(false);
        g_registrationReportStartupSucceeded.store(false);
        {
            std::lock_guard<std::mutex> lock(g_sampleMutex);
            g_writerSampleCounts.clear();
        }

        if (!g_writerVeh)
        {
            g_writerVeh =
                AddVectoredExceptionHandler(
                    1,
                    WriterVeh);
        }

        RefreshThreadWatchpoints();


        DWORD lastThreadRefresh = 0;

        while (!g_stop.load())
        {
            const DWORD elapsed =
                GetTickCount() - g_startTick.load();

            if (elapsed - lastThreadRefresh >= 500u)
            {
                RefreshThreadWatchpoints();
                lastThreadRefresh = elapsed;
            }

            if (elapsed >= kCaptureDurationMs)
                break;

            WatchedState current{};

            if (!ReadCurrent(current))
            {
                ++g_missedSnapshots;
                const bool poolsActive =
                current.camoPool != 0 ||
                current.bindingPool != 0 ||
                current.camoAllocCount != 0 ||
                current.bindingAllocCount != 0;

            Sleep(poolsActive ? kActivePollMs : kPrePoolPollMs);
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(g_stateMutex);

                if (!g_haveBaseline)
                {
                    g_last = current;
                    g_haveBaseline = true;
                    Snapshot("first live allocator snapshot", current);
                    Lifecycle("POOLS_READY", "allocator snapshot available");
                }
                else
                {
                    const bool camoChanged =
                        current.camoFreeHead != g_last.camoFreeHead ||
                        current.camoAllocCount != g_last.camoAllocCount;

                    const bool bindingChanged =
                        current.bindingFreeHead != g_last.bindingFreeHead ||
                        current.bindingAllocCount != g_last.bindingAllocCount;

                    if (camoChanged)
                        Change("WEAPONCAMO_ALLOCATOR_CHANGED", g_last, current);

                    if (bindingChanged)
                        Change("CAMOBINDING_ALLOCATOR_CHANGED", g_last, current);

                    if (camoChanged || bindingChanged)
                    {
                        Snapshot("allocator changed", current);
                        g_last = current;
                    }
                }
            }

            const bool poolsActive =
                current.camoPool != 0 ||
                current.bindingPool != 0 ||
                current.camoAllocCount != 0 ||
                current.bindingAllocCount != 0;

            Sleep(poolsActive ? kActivePollMs : kPrePoolPollMs);
        }

        WatchedState finalState{};
        if (ReadCurrent(finalState))
            Snapshot(
                g_stop.load() ? "manual stop" : "10-minute automatic stop",
                finalState);

        Lifecycle(
            "STOP",
            g_stop.load()
                ? "capture stopped manually"
                : "10-minute capture completed");

        DisableWatchpointsOnKnownThreads();

        if (g_writerVeh)
        {
            RemoveVectoredExceptionHandler(
                g_writerVeh);
            g_writerVeh = nullptr;
        }

        g_running.store(false);
        return 0;
    }

    bool Start(std::string* message, bool forceRestart)
    {
        // Build 179: arm before startup asset registration reaches type 0x2E.
        camo_prototype1::ArmAutomaticStartupAttempt();

        std::lock_guard<std::mutex> startLock(g_startStopMutex);

        if (g_running.load())
        {
            if (!forceRestart)
            {
                if (message)
                    *message = "camo research capture is already running; duplicate start ignored.";
                return true;
            }

            g_stop.store(true);

            for (unsigned int i = 0;
                 i < 300 && g_running.load();
                 ++i)
            {
                Sleep(10);
            }

            if (g_running.load())
            {
                if (message)
                    *message = "previous camo research capture did not stop in time; restart cancelled.";
                return false;
            }
        }

        bool expected = false;
        if (!g_running.compare_exchange_strong(expected, true))
        {
            if (message)
                *message = "camo research capture start raced with another starter; duplicate ignored.";
            return true;
        }

        g_stop.store(false);

        HANDLE thread =
            CreateThread(
                nullptr,
                0,
                Worker,
                nullptr,
                0,
                nullptr);

        if (!thread)
        {
            g_running.store(false);

            if (message)
                *message = "failed to start camo research worker.";

            return false;
        }

        CloseHandle(thread);

        if (message)
            *message = "10-minute camo research capture started in a fresh per-run log folder.";

        return true;
    }

}

namespace camo_allocator_trace
{
    void StartEarly()
    {
        bool expected = false;

        if (!g_startedOnce.compare_exchange_strong(
                expected,
                true))
            return;

        std::string ignored;
        Start(&ignored, false);
    }

    void NotifyImageReady()
    {
        // Compatibility fallback only. In build 166 the normal path starts
        // earlier from GameManager immediately after stable-image detection.
        StartEarly();
    }

    bool IsRunning()
    {
        return g_running.load();
    }

    bool Command(
        const std::string& rawAction,
        std::string& message)
    {
        std::string action = rawAction;

        for (char& c : action)
            c = static_cast<char>(
                std::tolower(
                    static_cast<unsigned char>(c)));

        if (action.empty() || action == "status")
        {
            const DWORD elapsed =
                g_running.load()
                    ? GetTickCount() - g_startTick.load()
                    : 0;

            const DWORD remain =
                g_running.load() &&
                elapsed < kCaptureDurationMs
                    ? kCaptureDurationMs - elapsed
                    : 0;

            std::ostringstream o;
            o << "running="
              << (g_running.load() ? "yes" : "no")
              << " changes=" << g_changes.load()
              << " writerEvents=" << g_writerEvents.load()
              << " uniqueWriters=" << g_uniqueWriterPaths.load()
              << " callerSamples=" << g_callerSamples.load()
              << " registrationReport="
              << (g_registrationReportStartupAttempted.load()
                      ? (g_registrationReportStartupSucceeded.load()
                             ? "ok"
                             : "failed")
                      : "not_attempted")
              << " threadsArmed=" << g_threadsArmed.load()
              << " missedSnapshots=" << g_missedSnapshots.load()
              << " remainingSeconds=" << (remain / 1000u);

            message = o.str();
            return true;
        }

        if (action == "restart" || action == "start")
            return Start(&message, true);

        if (action == "stop" || action == "off")
        {
            g_stop.store(true);
            message = "camo research capture stop requested.";
            return true;
        }

        message =
            "usage: /camo research [status|restart|stop]";
        return false;
    }

    bool WriterWatchStatus(std::string& message)
    {
        WatchAddresses w{};

        {
            std::lock_guard<std::mutex> lock(g_watchMutex);
            w = g_watch;
        }

        std::ostringstream o;
        o << "weaponCamoStageProbe="
          << (w.valid ? "ready" : "unavailable")
          << " events=" << g_wrapperProbeEvents.load()
          << " stage1=" << g_camoInitialPost.load()
          << " stage2=" << g_camoPreparePost.load()
          << " stage3=" << g_camoDbPost.load()
          << " stage4=" << g_camoFinalStage.load()
          << " complete=" << (g_wrapperProbeComplete.load() ? "yes" : "no")
          << " runtimeParent=" << (g_runtimeParentCaptured.load() ? "captured" : "pending")
          << " parentCaptures=" << g_runtimeParentCaptures.load()
          << " bridge=" << (g_bridgeCaptured.load() ? "captured" : "pending")
          << " bridgeCaptures=" << g_bridgeCaptures.load()
          << " prototypeReady=" << (g_prototypeReady.load() ? "yes" : "no")
          << " threadsArmed=" << g_threadsArmed.load()
          << " initialPost=" << Hex(w.initialPost)
          << " preparePost=" << Hex(w.preparePost)
          << " dbPost=" << Hex(w.dbPost)
          << " finalStage=" << Hex(w.finalStage);

        message = o.str();
        return w.valid;
    }


    bool DumpRegistrationFunctions(
        std::string& message)
    {
        g_registrationReportStartupAttempted.store(true);

        const bool ok =
            GenerateRegistrationFunctionReport(
                &message);

        g_registrationReportStartupSucceeded.store(ok);
        g_registrationReportWritten.store(ok);

        Lifecycle(
            ok
                ? "REGISTRATION_REPORT_MANUAL_OK"
                : "REGISTRATION_REPORT_MANUAL_FAILED",
            message.c_str());

        return ok;
    }

}
