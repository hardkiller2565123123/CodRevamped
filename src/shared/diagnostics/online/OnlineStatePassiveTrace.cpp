#include "OnlineStatePassiveTrace.h"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>

namespace online_state_passive_trace
{
    namespace
    {
        std::atomic_bool g_running{ false };
        HANDLE g_worker = nullptr;

        std::uintptr_t g_networkModeAddress = 0;
        std::uintptr_t g_initedAddress = 0;
        std::uintptr_t g_authManagerAddress = 0;
        char g_modeLabel[32]{ "unknown" };
        std::uintptr_t g_serviceObjectGlobal = 0;

        bool SafeRead(
            std::uintptr_t address,
            void* output,
            SIZE_T size)
        {
            SIZE_T got = 0;
            return address &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    output,
                    size,
                    &got) &&
                got == size;
        }

        void Append(const char* line)
        {
            char path[MAX_PATH]{};
            sprintf_s(
                path,
                "logs\\online\\gate_diff_%s_%lu.log",
                g_modeLabel,
                static_cast<unsigned long>(GetCurrentProcessId()));

            HANDLE file = CreateFileA(
                path,
                FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (file == INVALID_HANDLE_VALUE)
                return;

            DWORD written = 0;
            WriteFile(
                file,
                line,
                static_cast<DWORD>(strlen(line)),
                &written,
                nullptr);
            CloseHandle(file);
        }

        void ScanFocusedXrefs()
        {
            const auto module = GetModuleHandleW(nullptr);
            if (!module)
                return;

            const auto base =
                reinterpret_cast<std::uintptr_t>(module);

            IMAGE_DOS_HEADER dos{};
            IMAGE_NT_HEADERS64 nt{};

            if (!SafeRead(base, &dos, sizeof(dos)) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE ||
                !SafeRead(
                    base + static_cast<std::uintptr_t>(dos.e_lfanew),
                    &nt,
                    sizeof(nt)) ||
                nt.Signature != IMAGE_NT_SIGNATURE)
            {
                return;
            }

            const auto moduleEnd =
                base +
                static_cast<std::uintptr_t>(
                    nt.OptionalHeader.SizeOfImage);

            const auto sectionHeaders =
                base +
                static_cast<std::uintptr_t>(dos.e_lfanew) +
                sizeof(DWORD) +
                sizeof(IMAGE_FILE_HEADER) +
                nt.FileHeader.SizeOfOptionalHeader;

            char path[MAX_PATH]{};
            sprintf_s(
                path,
                "logs\\online\\online_state_xrefs_%s_%lu.log",
                g_modeLabel,
                static_cast<unsigned long>(
                    GetCurrentProcessId()));

            HANDLE file = CreateFileA(
                path,
                GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (file == INVALID_HANDLE_VALUE)
                return;

            auto WriteLine = [&](const char* text)
            {
                DWORD written = 0;
                WriteFile(
                    file,
                    text,
                    static_cast<DWORD>(strlen(text)),
                    &written,
                    nullptr);
            };

            WriteLine(
                "[BUILD239 FAST ONLINE SCAN]\r\n"
                "mode=current D33D state cluster only\r\n"
                "skipped=Build231..Build237 legacy passes\r\n\r\n");

            char header[512]{};
            sprintf_s(
                header,
                "moduleBase=0x%llX\r\n"
                "s_networkMode_rva=0x%llX\r\n"
                "s_inited_rva=0x%llX\r\n"
                "g_auth_manager_rva=0x%llX\r\n\r\n",
                static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(
                    g_networkModeAddress - base),
                static_cast<unsigned long long>(
                    g_initedAddress - base),
                static_cast<unsigned long long>(
                    g_authManagerAddress - base));
            WriteLine(header);

            auto FindLikelyFunctionStart =
                [&](std::uintptr_t site) -> std::uintptr_t
            {
                constexpr std::size_t kBack = 0x300;
                const auto begin =
                    site > base + kBack
                        ? site - kBack
                        : base;

                const auto size =
                    static_cast<std::size_t>(
                        site - begin);

                if (!size)
                    return site;

                std::vector<unsigned char> bytes(size);

                if (!SafeRead(
                        begin,
                        bytes.data(),
                        bytes.size()))
                {
                    return site;
                }

                for (std::size_t i = bytes.size();
                     i-- > 1;)
                {
                    if (bytes[i - 1] == 0xCC ||
                        bytes[i - 1] == 0xC3 ||
                        bytes[i - 1] == 0xC2)
                    {
                        return begin + i;
                    }
                }

                return site;
            };

            struct FocusSite
            {
                const char* name;
                std::uintptr_t rva;
            };

            auto DumpFocusedFunction =
                [&](const FocusSite& focus)
            {
                const auto site =
                    base + focus.rva;

                const auto functionStart =
                    FindLikelyFunctionStart(site);

                constexpr std::size_t kBefore = 0x80;
                constexpr std::size_t kAfter = 0x700;

                const auto start =
                    functionStart > base + kBefore
                        ? functionStart - kBefore
                        : base;

                constexpr std::size_t kSize =
                    kBefore + kAfter;

                std::vector<unsigned char> bytes(kSize);

                char title[512]{};
                sprintf_s(
                    title,
                    "\r\n[%s] siteRva=0x%llX likelyStartRva=0x%llX\r\n",
                    focus.name,
                    static_cast<unsigned long long>(
                        focus.rva),
                    static_cast<unsigned long long>(
                        functionStart - base));
                WriteLine(title);

                if (!SafeRead(
                        start,
                        bytes.data(),
                        bytes.size()))
                {
                    WriteLine("  unreadable\r\n");
                    return;
                }

                WriteLine("  [CODE]\r\n");

                for (std::size_t off = 0;
                     off < bytes.size();
                     off += 16)
                {
                    char line[320]{};
                    int used = sprintf_s(
                        line,
                        "    rva=0x%llX: ",
                        static_cast<unsigned long long>(
                            start + off - base));

                    for (std::size_t j = 0;
                         j < 16 &&
                         off + j < bytes.size();
                         ++j)
                    {
                        used += sprintf_s(
                            line + used,
                            sizeof(line) - used,
                            "%02X ",
                            static_cast<unsigned int>(
                                bytes[off + j]));
                    }

                    used += sprintf_s(
                        line + used,
                        sizeof(line) - used,
                        "\r\n");
                    WriteLine(line);
                }

                WriteLine("  [CALL/JMP/JCC MAP]\r\n");

                for (std::size_t off = 0;
                     off + 6 <= bytes.size();
                     ++off)
                {
                    const auto here =
                        start + off;

                    if (bytes[off] == 0xE8 ||
                        bytes[off] == 0xE9)
                    {
                        std::int32_t rel = 0;
                        std::memcpy(
                            &rel,
                            bytes.data() + off + 1,
                            sizeof(rel));

                        const auto target =
                            static_cast<std::uintptr_t>(
                                static_cast<std::intptr_t>(
                                    here + 5) + rel);

                        char line[280]{};
                        sprintf_s(
                            line,
                            "    %s at=0x%llX target=%s0x%llX\r\n",
                            bytes[off] == 0xE8
                                ? "CALL"
                                : "JMP",
                            static_cast<unsigned long long>(
                                here - base),
                            target >= base &&
                                target < moduleEnd
                                ? "gameRva="
                                : "abs=",
                            static_cast<unsigned long long>(
                                target >= base &&
                                    target < moduleEnd
                                    ? target - base
                                    : target));
                        WriteLine(line);
                    }
                    else if (bytes[off] >= 0x70 &&
                             bytes[off] <= 0x7F)
                    {
                        const auto rel =
                            static_cast<std::int8_t>(
                                bytes[off + 1]);

                        const auto target =
                            static_cast<std::uintptr_t>(
                                static_cast<std::intptr_t>(
                                    here + 2) + rel);

                        char line[256]{};
                        sprintf_s(
                            line,
                            "    JCC8 op=%02X at=0x%llX targetRva=0x%llX\r\n",
                            static_cast<unsigned int>(
                                bytes[off]),
                            static_cast<unsigned long long>(
                                here - base),
                            static_cast<unsigned long long>(
                                target - base));
                        WriteLine(line);
                    }
                    else if (bytes[off] == 0x0F &&
                             bytes[off + 1] >= 0x80 &&
                             bytes[off + 1] <= 0x8F)
                    {
                        std::int32_t rel = 0;
                        std::memcpy(
                            &rel,
                            bytes.data() + off + 2,
                            sizeof(rel));

                        const auto target =
                            static_cast<std::uintptr_t>(
                                static_cast<std::intptr_t>(
                                    here + 6) + rel);

                        char line[256]{};
                        sprintf_s(
                            line,
                            "    JCC32 op=0F%02X at=0x%llX targetRva=0x%llX\r\n",
                            static_cast<unsigned int>(
                                bytes[off + 1]),
                            static_cast<unsigned long long>(
                                here - base),
                            static_cast<unsigned long long>(
                                target - base));
                        WriteLine(line);
                    }
                }

                WriteLine("  [DIRECT CALLERS]\r\n");

                unsigned int callers = 0;

                for (unsigned int si = 0;
                     si < nt.FileHeader.NumberOfSections;
                     ++si)
                {
                    IMAGE_SECTION_HEADER sh{};

                    if (!SafeRead(
                            sectionHeaders +
                            static_cast<std::uintptr_t>(si) *
                                sizeof(sh),
                            &sh,
                            sizeof(sh)))
                    {
                        continue;
                    }

                    if (!(sh.Characteristics &
                          IMAGE_SCN_MEM_EXECUTE) ||
                        !(sh.Characteristics &
                          IMAGE_SCN_MEM_READ))
                    {
                        continue;
                    }

                    const auto sectionStart =
                        base + sh.VirtualAddress;

                    const auto sectionSize =
                        static_cast<std::size_t>(
                            (std::max)(
                                sh.Misc.VirtualSize,
                                sh.SizeOfRawData));

                    if (sectionSize < 5 ||
                        sectionSize >
                            512ull * 1024ull * 1024ull)
                    {
                        continue;
                    }

                    constexpr std::size_t kChunk =
                        1024 * 1024;

                    std::vector<unsigned char>
                        scan(kChunk + 8);

                    const auto sectionEnd =
                        sectionStart + sectionSize;

                    for (auto cursor = sectionStart;
                         cursor < sectionEnd;)
                    {
                        const auto want =
                            (std::min<std::size_t>)(
                                kChunk,
                                static_cast<std::size_t>(
                                    sectionEnd - cursor));

                        if (SafeRead(
                                cursor,
                                scan.data(),
                                want))
                        {
                            for (std::size_t off = 0;
                                 off + 5 <= want;
                                 ++off)
                            {
                                if (scan[off] != 0xE8 &&
                                    scan[off] != 0xE9)
                                {
                                    continue;
                                }

                                std::int32_t rel = 0;
                                std::memcpy(
                                    &rel,
                                    scan.data() + off + 1,
                                    sizeof(rel));

                                const auto here =
                                    cursor + off;

                                const auto target =
                                    static_cast<std::uintptr_t>(
                                        static_cast<std::intptr_t>(
                                            here + 5) + rel);

                                if (target != functionStart)
                                    continue;

                                char line[256]{};
                                sprintf_s(
                                    line,
                                    "    %s callerRva=0x%llX\r\n",
                                    scan[off] == 0xE8
                                        ? "CALL"
                                        : "JMP",
                                    static_cast<unsigned long long>(
                                        here - base));
                                WriteLine(line);
                                ++callers;
                            }
                        }

                        if (want == 0)
                            break;

                        cursor += want;
                    }
                }

                char summary[128]{};
                sprintf_s(
                    summary,
                    "    directCallerCount=%u\r\n",
                    callers);
                WriteLine(summary);
            };

            WriteLine("[LOCAL D33D FIELD CORRELATION]\r\n");

            constexpr std::uintptr_t kClusterStartRva =
                0xD33C000;
            constexpr std::uintptr_t kClusterEndRva =
                0xD33F000;

            const std::uint32_t fields[] =
            {
                0x38, 0xB0, 0xD0,
                0x704, 0x738, 0x740,
                0x748, 0x750, 0x754,
                0x758, 0x9E9, 0xA58
            };

            const auto clusterStart =
                base + kClusterStartRva;

            const auto clusterEnd =
                (std::min)(
                    base + kClusterEndRva,
                    moduleEnd);

            unsigned int fieldHits = 0;

            if (clusterEnd > clusterStart)
            {
                const auto size =
                    static_cast<std::size_t>(
                        clusterEnd - clusterStart);

                std::vector<unsigned char> bytes(size);

                if (SafeRead(
                        clusterStart,
                        bytes.data(),
                        bytes.size()))
                {
                    for (std::size_t off = 0;
                         off + 8 <= bytes.size();
                         ++off)
                    {
                        for (const auto field : fields)
                        {
                            bool hit = false;
                            std::size_t dispSize = 0;

                            std::uint32_t d32 = 0;
                            std::memcpy(
                                &d32,
                                bytes.data() + off,
                                sizeof(d32));

                            if (d32 == field)
                            {
                                hit = true;
                                dispSize = 4;
                            }
                            else if (field <= 0xFF &&
                                     bytes[off] ==
                                        static_cast<unsigned char>(
                                            field))
                            {
                                hit = true;
                                dispSize = 1;
                            }

                            if (!hit)
                                continue;

                            const auto back =
                                off >= 5 ? off - 5 : 0;

                            bool instructionLike = false;

                            for (std::size_t j = back;
                                 j < off;
                                 ++j)
                            {
                                const auto op = bytes[j];

                                if (op == 0x8B ||
                                    op == 0x89 ||
                                    op == 0x8D ||
                                    op == 0x80 ||
                                    op == 0x81 ||
                                    op == 0x83 ||
                                    op == 0xC6 ||
                                    op == 0xC7 ||
                                    op == 0x0F ||
                                    op == 0xFF)
                                {
                                    instructionLike = true;
                                    break;
                                }
                            }

                            if (!instructionLike)
                                continue;

                            char line[512]{};
                            sprintf_s(
                                line,
                                "  field=+0x%X candidateRva=0x%llX size=%llu context=",
                                field,
                                static_cast<unsigned long long>(
                                    clusterStart + off - base),
                                static_cast<unsigned long long>(
                                    dispSize));

                            std::string full = line;

                            const auto ctxStart =
                                off >= 10 ? off - 10 : 0;

                            const auto ctxEnd =
                                (std::min<std::size_t>)(
                                    bytes.size(),
                                    off + dispSize + 14);

                            char b[8]{};

                            for (std::size_t i = ctxStart;
                                 i < ctxEnd;
                                 ++i)
                            {
                                sprintf_s(
                                    b,
                                    "%02X ",
                                    static_cast<unsigned int>(
                                        bytes[i]));
                                full += b;
                            }

                            full += "\r\n";
                            WriteLine(full.c_str());
                            ++fieldHits;
                        }
                    }
                }
            }

            {
                char line[160]{};
                sprintf_s(
                    line,
                    "localClusterFieldHits=%u\r\n\r\n",
                    fieldHits);
                WriteLine(line);
            }

            WriteLine(
                "[BUILD240 SERVICE STATE MACHINE FOCUS]\r\n");

            // The build239 run showed the useful activity has moved above the
            // resolver into this compact service-state region.
            constexpr std::uintptr_t kStateWindowStartRva =
                0xD33D900;
            constexpr std::uintptr_t kStateWindowEndRva =
                0xD33DD20;

            const auto stateWindowStart =
                base + kStateWindowStartRva;
            const auto stateWindowEnd =
                (std::min)(
                    base + kStateWindowEndRva,
                    moduleEnd);

            WriteLine(
                "\r\n[CONTIGUOUS D33D900-D33DD20]\r\n");

            if (stateWindowEnd > stateWindowStart)
            {
                const auto size =
                    static_cast<std::size_t>(
                        stateWindowEnd -
                        stateWindowStart);

                std::vector<unsigned char>
                    bytes(size);

                if (SafeRead(
                        stateWindowStart,
                        bytes.data(),
                        bytes.size()))
                {
                    for (std::size_t off = 0;
                         off < bytes.size();
                         off += 16)
                    {
                        char line[320]{};
                        int used = sprintf_s(
                            line,
                            "  rva=0x%llX: ",
                            static_cast<unsigned long long>(
                                stateWindowStart +
                                off - base));

                        for (std::size_t j = 0;
                             j < 16 &&
                             off + j < bytes.size();
                             ++j)
                        {
                            used += sprintf_s(
                                line + used,
                                sizeof(line) - used,
                                "%02X ",
                                static_cast<unsigned int>(
                                    bytes[off + j]));
                        }

                        used += sprintf_s(
                            line + used,
                            sizeof(line) - used,
                            "\r\n");
                        WriteLine(line);
                    }

                    WriteLine(
                        "  [LOCAL CALL/JMP/JCC MAP]\r\n");

                    for (std::size_t off = 0;
                         off + 6 <= bytes.size();
                         ++off)
                    {
                        const auto here =
                            stateWindowStart + off;

                        if (bytes[off] == 0xE8 ||
                            bytes[off] == 0xE9)
                        {
                            std::int32_t rel = 0;
                            std::memcpy(
                                &rel,
                                bytes.data() +
                                    off + 1,
                                sizeof(rel));

                            const auto target =
                                static_cast<
                                    std::uintptr_t>(
                                    static_cast<
                                        std::intptr_t>(
                                        here + 5) +
                                    rel);

                            char line[300]{};
                            sprintf_s(
                                line,
                                "    %s at=0x%llX target=%s0x%llX\r\n",
                                bytes[off] == 0xE8
                                    ? "CALL"
                                    : "JMP",
                                static_cast<
                                    unsigned long long>(
                                    here - base),
                                target >= base &&
                                    target < moduleEnd
                                    ? "gameRva="
                                    : "abs=",
                                static_cast<
                                    unsigned long long>(
                                    target >= base &&
                                        target <
                                            moduleEnd
                                        ? target - base
                                        : target));
                            WriteLine(line);
                        }
                        else if (
                            bytes[off] >= 0x70 &&
                            bytes[off] <= 0x7F)
                        {
                            const auto rel =
                                static_cast<std::int8_t>(
                                    bytes[off + 1]);

                            const auto target =
                                static_cast<
                                    std::uintptr_t>(
                                    static_cast<
                                        std::intptr_t>(
                                        here + 2) +
                                    rel);

                            char line[280]{};
                            sprintf_s(
                                line,
                                "    JCC8 op=%02X at=0x%llX targetRva=0x%llX\r\n",
                                static_cast<
                                    unsigned int>(
                                    bytes[off]),
                                static_cast<
                                    unsigned long long>(
                                    here - base),
                                static_cast<
                                    unsigned long long>(
                                    target - base));
                            WriteLine(line);
                        }
                        else if (
                            bytes[off] == 0x0F &&
                            bytes[off + 1] >= 0x80 &&
                            bytes[off + 1] <= 0x8F)
                        {
                            std::int32_t rel = 0;
                            std::memcpy(
                                &rel,
                                bytes.data() +
                                    off + 2,
                                sizeof(rel));

                            const auto target =
                                static_cast<
                                    std::uintptr_t>(
                                    static_cast<
                                        std::intptr_t>(
                                        here + 6) +
                                    rel);

                            char line[280]{};
                            sprintf_s(
                                line,
                                "    JCC32 op=0F%02X at=0x%llX targetRva=0x%llX\r\n",
                                static_cast<
                                    unsigned int>(
                                    bytes[off + 1]),
                                static_cast<
                                    unsigned long long>(
                                    here - base),
                                static_cast<
                                    unsigned long long>(
                                    target - base));
                            WriteLine(line);
                        }
                    }
                }
            }

            // High-value state sites/callers from build239. These get the
            // full function-start + direct-caller treatment.
            WriteLine(
                "\r\n[HIGH VALUE FUNCTION DISSECTION]\r\n");

            const FocusSite highValueSites[] =
            {
                { "state_9E9_caller_local", 0xD33D961 },
                { "state_9E9_caller_update", 0xD33DC49 },
                { "external_state_9E9_caller", 0xD34CB42 },
                { "A58_path_owner", 0xD352980 }
            };

            for (const auto& site :
                 highValueSites)
            {
                DumpFocusedFunction(site);
            }

            // The local update block chooses among these helpers. Dump compact
            // neighborhoods around each without doing another whole-image caller
            // search for every helper.
            WriteLine(
                "\r\n[SELECTED SERVICE HELPERS]\r\n");

            struct HelperSite
            {
                const char* name;
                std::uintptr_t rva;
            };

            const HelperSite helpers[] =
            {
                { "service_helper_A", 0xD356C50 },
                { "service_helper_B", 0xD356C90 },
                { "service_path_D357750", 0xD357750 },
                { "local_state_D33DAD0", 0xD33DAD0 },
                { "next_state_D33E010", 0xD33E010 }
            };

            for (const auto& helper : helpers)
            {
                const auto center =
                    base + helper.rva;

                const auto start =
                    center > base + 0x100
                        ? center - 0x100
                        : base;

                unsigned char bytes[0x500]{};

                if (!SafeRead(
                        start,
                        bytes,
                        sizeof(bytes)))
                {
                    continue;
                }

                char title[320]{};
                sprintf_s(
                    title,
                    "\r\n  [%s centerRva=0x%llX]\r\n",
                    helper.name,
                    static_cast<
                        unsigned long long>(
                        helper.rva));
                WriteLine(title);

                for (std::size_t off = 0;
                     off < sizeof(bytes);
                     off += 16)
                {
                    char line[320]{};
                    int used = sprintf_s(
                        line,
                        "    rva=0x%llX: ",
                        static_cast<
                            unsigned long long>(
                            start + off -
                            base));

                    for (std::size_t j = 0;
                         j < 16 &&
                         off + j <
                            sizeof(bytes);
                         ++j)
                    {
                        used += sprintf_s(
                            line + used,
                            sizeof(line) -
                                used,
                            "%02X ",
                            static_cast<
                                unsigned int>(
                                bytes[off + j]));
                    }

                    used += sprintf_s(
                        line + used,
                        sizeof(line) -
                            used,
                        "\r\n");
                    WriteLine(line);
                }

                WriteLine(
                    "    [HELPER CALL/JMP/JCC]\r\n");

                for (std::size_t off = 0;
                     off + 6 <= sizeof(bytes);
                     ++off)
                {
                    const auto here =
                        start + off;

                    if (bytes[off] == 0xE8 ||
                        bytes[off] == 0xE9)
                    {
                        std::int32_t rel = 0;
                        std::memcpy(
                            &rel,
                            bytes + off + 1,
                            sizeof(rel));

                        const auto target =
                            static_cast<
                                std::uintptr_t>(
                                static_cast<
                                    std::intptr_t>(
                                    here + 5) +
                                rel);

                        if (target >= base &&
                            target < moduleEnd)
                        {
                            char line[280]{};
                            sprintf_s(
                                line,
                                "      %s at=0x%llX targetGameRva=0x%llX\r\n",
                                bytes[off] == 0xE8
                                    ? "CALL"
                                    : "JMP",
                                static_cast<
                                    unsigned long long>(
                                    here - base),
                                static_cast<
                                    unsigned long long>(
                                    target - base));
                            WriteLine(line);
                        }
                    }
                    else if (
                        bytes[off] >= 0x70 &&
                        bytes[off] <= 0x7F)
                    {
                        const auto rel =
                            static_cast<std::int8_t>(
                                bytes[off + 1]);

                        const auto target =
                            static_cast<
                                std::uintptr_t>(
                                static_cast<
                                    std::intptr_t>(
                                    here + 2) +
                                rel);

                        char line[280]{};
                        sprintf_s(
                            line,
                            "      JCC8 op=%02X at=0x%llX targetRva=0x%llX\r\n",
                            static_cast<
                                unsigned int>(
                                bytes[off]),
                            static_cast<
                                unsigned long long>(
                                here - base),
                            static_cast<
                                unsigned long long>(
                                target - base));
                        WriteLine(line);
                    }
                    else if (
                        bytes[off] == 0x0F &&
                        bytes[off + 1] >=
                            0x80 &&
                        bytes[off + 1] <=
                            0x8F)
                    {
                        std::int32_t rel = 0;
                        std::memcpy(
                            &rel,
                            bytes + off + 2,
                            sizeof(rel));

                        const auto target =
                            static_cast<
                                std::uintptr_t>(
                                static_cast<
                                    std::intptr_t>(
                                    here + 6) +
                                rel);

                        char line[280]{};
                        sprintf_s(
                            line,
                            "      JCC32 op=0F%02X at=0x%llX targetRva=0x%llX\r\n",
                            static_cast<
                                unsigned int>(
                                bytes[off + 1]),
                            static_cast<
                                unsigned long long>(
                                here - base),
                            static_cast<
                                unsigned long long>(
                                target - base));
                        WriteLine(line);
                    }
                }
            }

            // Explicitly map the conditions around the three known local calls
            // inside D33DCxx so the next log shows which branch selects each
            // service path.
            WriteLine(
                "\r\n[BRANCH CONTEXT AROUND D33DC38-D33DCE0]\r\n");

            {
                constexpr std::uintptr_t kStartRva =
                    0xD33DBF0;
                constexpr std::uintptr_t kEndRva =
                    0xD33DD10;

                const auto startAddress =
                    base + kStartRva;

                const auto endAddress =
                    (std::min)(
                        base + kEndRva,
                        moduleEnd);

                if (endAddress >
                    startAddress)
                {
                    const auto size =
                        static_cast<
                            std::size_t>(
                            endAddress -
                            startAddress);

                    std::vector<
                        unsigned char>
                        bytes(size);

                    if (SafeRead(
                            startAddress,
                            bytes.data(),
                            bytes.size()))
                    {
                        for (std::size_t off = 0;
                             off < bytes.size();
                             off += 16)
                        {
                            char line[320]{};
                            int used = sprintf_s(
                                line,
                                "  rva=0x%llX: ",
                                static_cast<
                                    unsigned long long>(
                                    startAddress +
                                    off - base));

                            for (std::size_t j = 0;
                                 j < 16 &&
                                 off + j <
                                    bytes.size();
                                 ++j)
                            {
                                used += sprintf_s(
                                    line + used,
                                    sizeof(line) -
                                        used,
                                    "%02X ",
                                    static_cast<
                                        unsigned int>(
                                        bytes[
                                            off + j]));
                            }

                            used += sprintf_s(
                                line + used,
                                sizeof(line) -
                                    used,
                                "\r\n");
                            WriteLine(line);
                        }
                    }
                }
            }

            WriteLine(
                "\r\n[BUILD241 SERVICE DISPATCH FOCUS]\r\n");

            const FocusSite dispatchSites[] =
            {
                { "service_entry_caller", 0xD33CFB5 },
                { "service_entry_target", 0xD34CAE0 },
                { "service_dispatch_A", 0xD356C50 },
                { "service_dispatch_B", 0xD356C90 },
                { "service_path_750", 0xD357750 },
                { "service_path_C40", 0xD357C40 }
            };

            for (const auto& site : dispatchSites)
                DumpFocusedFunction(site);

            // Inspect all local accesses to [object + 0xD0] in the D33C-D33E
            // service cluster and dump nearby bytes so we can identify the
            // dispatch-object layout and call sites.
            WriteLine("\r\n[OBJECT +0xD0 LOCAL ACCESS MAP]\r\n");

            {
                constexpr std::uintptr_t kStartRva = 0xD33C000;
                constexpr std::uintptr_t kEndRva   = 0xD33F000;

                const auto start =
                    base + kStartRva;
                const auto end =
                    (std::min)(base + kEndRva, moduleEnd);

                if (end > start)
                {
                    const auto size =
                        static_cast<std::size_t>(end - start);
                    std::vector<unsigned char> bytes(size);

                    if (SafeRead(start, bytes.data(), bytes.size()))
                    {
                        unsigned int hits = 0;

                        for (std::size_t off = 0;
                             off + 8 <= bytes.size();
                             ++off)
                        {
                            bool match = false;
                            std::size_t dispSize = 0;

                            std::uint32_t d32 = 0;
                            std::memcpy(
                                &d32,
                                bytes.data() + off,
                                sizeof(d32));

                            if (d32 == 0xD0)
                            {
                                match = true;
                                dispSize = 4;
                            }
                            else if (bytes[off] == 0xD0)
                            {
                                match = true;
                                dispSize = 1;
                            }

                            if (!match)
                                continue;

                            const auto back =
                                off >= 6 ? off - 6 : 0;

                            bool instructionLike = false;
                            for (std::size_t j = back;
                                 j < off;
                                 ++j)
                            {
                                const auto op = bytes[j];
                                if (op == 0x8B || op == 0x89 ||
                                    op == 0x8D || op == 0x80 ||
                                    op == 0x81 || op == 0x83 ||
                                    op == 0xC6 || op == 0xC7 ||
                                    op == 0xFF || op == 0x0F)
                                {
                                    instructionLike = true;
                                    break;
                                }
                            }

                            if (!instructionLike)
                                continue;

                            char line[512]{};
                            sprintf_s(
                                line,
                                "  candidateRva=0x%llX dispSize=%llu context=",
                                static_cast<unsigned long long>(
                                    start + off - base),
                                static_cast<unsigned long long>(
                                    dispSize));

                            std::string full = line;

                            const auto ctxStart =
                                off >= 12 ? off - 12 : 0;
                            const auto ctxEnd =
                                (std::min<std::size_t>)(
                                    bytes.size(),
                                    off + dispSize + 18);

                            char b[8]{};
                            for (std::size_t i = ctxStart;
                                 i < ctxEnd;
                                 ++i)
                            {
                                sprintf_s(
                                    b,
                                    "%02X ",
                                    static_cast<unsigned int>(bytes[i]));
                                full += b;
                            }

                            full += "\r\n";
                            WriteLine(full.c_str());
                            ++hits;
                        }

                        char summary[128]{};
                        sprintf_s(
                            summary,
                            "objectD0AccessHits=%u\r\n",
                            hits);
                        WriteLine(summary);
                    }
                }
            }

            // Dump the compact state block where D356C50/D356C90 are selected
            // and where D357750/D357C40 are called.
            WriteLine(
                "\r\n[DISPATCH DECISION WINDOW D33DBF0-D33DCE0]\r\n");

            {
                constexpr std::uintptr_t kStartRva = 0xD33DBF0;
                constexpr std::uintptr_t kEndRva   = 0xD33DCE0;

                const auto start =
                    base + kStartRva;
                const auto end =
                    (std::min)(base + kEndRva, moduleEnd);

                if (end > start)
                {
                    const auto size =
                        static_cast<std::size_t>(end - start);
                    std::vector<unsigned char> bytes(size);

                    if (SafeRead(start, bytes.data(), bytes.size()))
                    {
                        for (std::size_t off = 0;
                             off < bytes.size();
                             off += 16)
                        {
                            char line[320]{};
                            int used = sprintf_s(
                                line,
                                "  rva=0x%llX: ",
                                static_cast<unsigned long long>(
                                    start + off - base));

                            for (std::size_t j = 0;
                                 j < 16 &&
                                 off + j < bytes.size();
                                 ++j)
                            {
                                used += sprintf_s(
                                    line + used,
                                    sizeof(line) - used,
                                    "%02X ",
                                    static_cast<unsigned int>(
                                        bytes[off + j]));
                            }

                            used += sprintf_s(
                                line + used,
                                sizeof(line) - used,
                                "\r\n");
                            WriteLine(line);
                        }
                    }
                }
            }

            WriteLine(
                "\r\n[END BUILD241 FAST SCAN]\r\n");

            CloseHandle(file);
        }

        std::uintptr_t ResolveServiceObjectGlobal(
            std::uintptr_t base,
            std::uintptr_t moduleEnd)
        {
            struct Candidate
            {
                std::uintptr_t globalAddress = 0;
                unsigned int hits = 0;
                std::uintptr_t object = 0;
            };

            std::vector<Candidate> candidates;

            const std::uintptr_t sites[] =
            {
                0xD33D2F0,
                0xD33D5A0,
                0xD33D650,
                0xD33D961,
                0xD33DC49
            };

            for (const auto siteRva : sites)
            {
                const auto center = base + siteRva;
                const auto start =
                    center > base + 0x180
                        ? center - 0x180
                        : base;

                unsigned char bytes[0x500]{};
                if (!SafeRead(
                        start,
                        bytes,
                        sizeof(bytes)))
                {
                    continue;
                }

                for (std::size_t off = 0;
                     off + 7 <= sizeof(bytes);
                     ++off)
                {
                    std::size_t op = off;

                    if ((bytes[op] & 0xF0) == 0x40)
                        ++op;

                    if (op + 6 > sizeof(bytes))
                        continue;

                    // Only MOV reg,[rip+disp32] / LEA reg,[rip+disp32].
                    const auto opcode = bytes[op];
                    const auto modrm = bytes[op + 1];

                    if (opcode != 0x8B &&
                        opcode != 0x8D)
                    {
                        continue;
                    }

                    if ((modrm & 0xC7) != 0x05)
                        continue;

                    std::int32_t disp = 0;
                    std::memcpy(
                        &disp,
                        bytes + op + 2,
                        sizeof(disp));

                    const auto instrLen =
                        (op - off) + 6;
                    const auto here =
                        start + off;

                    const auto globalAddress =
                        static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(
                                here + instrLen) +
                            disp);

                    if (globalAddress < base ||
                        globalAddress >= moduleEnd)
                    {
                        continue;
                    }

                    std::uintptr_t object = 0;
                    if (!SafeRead(
                            globalAddress,
                            &object,
                            sizeof(object)) ||
                        !object ||
                        (object >= base &&
                         object < moduleEnd))
                    {
                        continue;
                    }

                    MEMORY_BASIC_INFORMATION mbi{};
                    if (!VirtualQuery(
                            reinterpret_cast<const void*>(object),
                            &mbi,
                            sizeof(mbi)) ||
                        mbi.State != MEM_COMMIT ||
                        (mbi.Protect &
                         (PAGE_NOACCESS | PAGE_GUARD)))
                    {
                        continue;
                    }

                    auto it =
                        std::find_if(
                            candidates.begin(),
                            candidates.end(),
                            [&](const Candidate& c)
                            {
                                return
                                    c.globalAddress ==
                                    globalAddress;
                            });

                    if (it == candidates.end())
                    {
                        candidates.push_back(
                            { globalAddress, 1, object });
                    }
                    else
                    {
                        ++it->hits;
                        it->object = object;
                    }
                }
            }

            if (candidates.empty())
                return 0;

            std::sort(
                candidates.begin(),
                candidates.end(),
                [](const Candidate& a,
                   const Candidate& b)
                {
                    return a.hits > b.hits;
                });

            char line[2048]{};
            int used = sprintf_s(
                line,
                "[SERVICE-OBJECT-CANDIDATES] mode=%s count=%llu",
                g_modeLabel,
                static_cast<unsigned long long>(
                    candidates.size()));

            for (std::size_t i = 0;
                 i < candidates.size() &&
                 i < 8 &&
                 used <
                    static_cast<int>(
                        sizeof(line) - 160);
                 ++i)
            {
                used += sprintf_s(
                    line + used,
                    sizeof(line) - used,
                    " candidate%llu={globalRva=0x%llX hits=%u object=0x%llX}",
                    static_cast<unsigned long long>(i),
                    static_cast<unsigned long long>(
                        candidates[i].globalAddress - base),
                    candidates[i].hits,
                    static_cast<unsigned long long>(
                        candidates[i].object));
            }

            used += sprintf_s(
                line + used,
                sizeof(line) - used,
                "\r\n");

            Append(line);

            return candidates.front().globalAddress;
        }

        struct DiffField
        {
            const char* name;
            std::uint32_t offset;
            std::uint32_t size;
            std::uint64_t value;
            bool valid;
        };

        void PollServiceObject(
            std::uintptr_t serviceGlobal,
            std::uintptr_t& lastObject,
            DiffField* fields,
            std::size_t fieldCount,
            std::uint32_t networkMode,
            unsigned char inited,
            std::uintptr_t auth)
        {
            if (!serviceGlobal ||
                !fields ||
                !fieldCount)
            {
                return;
            }

            std::uintptr_t object = 0;
            if (!SafeRead(
                    serviceGlobal,
                    &object,
                    sizeof(object)) ||
                !object)
            {
                return;
            }

            const bool objectChanged =
                object != lastObject;

            if (objectChanged)
            {
                char line[512]{};
                sprintf_s(
                    line,
                    "[SERVICE-OBJECT] mode=%s 0x%llX->0x%llX networkMode=0x%X inited=%u auth=0x%llX\r\n",
                    g_modeLabel,
                    static_cast<unsigned long long>(
                        lastObject),
                    static_cast<unsigned long long>(
                        object),
                    networkMode,
                    static_cast<unsigned int>(inited),
                    static_cast<unsigned long long>(
                        auth));
                Append(line);

                for (std::size_t i = 0;
                     i < fieldCount;
                     ++i)
                {
                    fields[i].valid = false;
                    fields[i].value = 0;
                }

                lastObject = object;
            }

            for (std::size_t i = 0;
                 i < fieldCount;
                 ++i)
            {
                std::uint64_t value = 0;
                SIZE_T got = 0;

                if (!ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(
                            object +
                            fields[i].offset),
                        &value,
                        fields[i].size,
                        &got) ||
                    got != fields[i].size)
                {
                    continue;
                }

                if (fields[i].valid &&
                    fields[i].value == value)
                {
                    continue;
                }

                SYSTEMTIME st{};
                GetLocalTime(&st);

                char line[768]{};
                sprintf_s(
                    line,
                    "[%02u:%02u:%02u.%03u] mode=%s SERVICE_FIELD %s(+0x%X) 0x%llX->0x%llX object=0x%llX networkMode=0x%X inited=%u auth=0x%llX\r\n",
                    st.wHour,
                    st.wMinute,
                    st.wSecond,
                    st.wMilliseconds,
                    g_modeLabel,
                    fields[i].name,
                    fields[i].offset,
                    static_cast<unsigned long long>(
                        fields[i].valid
                            ? fields[i].value
                            : 0),
                    static_cast<unsigned long long>(
                        value),
                    static_cast<unsigned long long>(
                        object),
                    networkMode,
                    static_cast<unsigned int>(inited),
                    static_cast<unsigned long long>(
                        auth));

                Append(line);

                fields[i].value = value;
                fields[i].valid = true;
            }
        }

        void ScanRuntimeFunctionGraph()
        {
            const auto module = GetModuleHandleW(nullptr);
            if (!module)
                return;

            const auto base =
                reinterpret_cast<std::uintptr_t>(module);

            IMAGE_DOS_HEADER dos{};
            IMAGE_NT_HEADERS64 nt{};

            if (!SafeRead(base, &dos, sizeof(dos)) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE ||
                !SafeRead(
                    base + static_cast<std::uintptr_t>(dos.e_lfanew),
                    &nt,
                    sizeof(nt)) ||
                nt.Signature != IMAGE_NT_SIGNATURE)
            {
                printf("[SCAN] FAILED: unable to read PE headers.\n");
                fflush(stdout);
                return;
            }

            const auto moduleEnd =
                base +
                static_cast<std::uintptr_t>(
                    nt.OptionalHeader.SizeOfImage);

            const auto sectionHeaders =
                base +
                static_cast<std::uintptr_t>(dos.e_lfanew) +
                sizeof(DWORD) +
                sizeof(IMAGE_FILE_HEADER) +
                nt.FileHeader.SizeOfOptionalHeader;

            char path[MAX_PATH]{};
            sprintf_s(
                path,
                "logs\\online\\runtime_upstream_graph_%s_%lu.log",
                g_modeLabel,
                static_cast<unsigned long>(
                    GetCurrentProcessId()));

            HANDLE file = CreateFileA(
                path,
                GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (file == INVALID_HANDLE_VALUE)
            {
                printf("[SCAN] FAILED: could not open upstream graph log.\n");
                fflush(stdout);
                return;
            }

            auto WriteLine =
                [&](const char* text)
            {
                DWORD written = 0;
                WriteFile(
                    file,
                    text,
                    static_cast<DWORD>(strlen(text)),
                    &written,
                    nullptr);
            };

            auto Console =
                [&](const char* fmt, ...)
            {
                char buffer[2048]{};
                va_list args;
                va_start(args, fmt);
                vsprintf_s(
                    buffer,
                    sizeof(buffer),
                    fmt,
                    args);
                va_end(args);
                printf("%s", buffer);
                fflush(stdout);
            };

            Console(
                "\n[SCAN] ========================================\n"
                "[SCAN] BUILD247 UPSTREAM-ONLY graph START\n"
                "[SCAN] This run prioritizes callers/table owners only.\n"
                "[SCAN] mode=%s\n",
                g_modeLabel);

            WriteLine(
                "[BUILD247 UPSTREAM-ONLY RUNTIME GRAPH]\r\n");

            char header[1024]{};
            sprintf_s(
                header,
                "mode=%s moduleBase=0x%llX imageSize=0x%llX\r\n"
                "seed_setter_exact=0xAF20CB0\r\n"
                "seed_wrapper=0xAEA1256\r\n"
                "seed_callsite=0xAEA1264\r\n"
                "prior_candidate_1=0x998AA2\r\n"
                "prior_candidate_2=0x146A039\r\n"
                "maxDepth=8 maxFunctions=512 direction=UPSTREAM_ONLY\r\n\r\n",
                g_modeLabel,
                static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(moduleEnd - base));
            WriteLine(header);

            struct Range
            {
                std::uintptr_t start = 0;
                std::uintptr_t end = 0;
                bool executable = false;
                bool readable = false;
                char name[9]{};
            };

            std::vector<Range> ranges;

            for (unsigned int si = 0;
                 si < nt.FileHeader.NumberOfSections;
                 ++si)
            {
                IMAGE_SECTION_HEADER sh{};

                if (!SafeRead(
                        sectionHeaders +
                            static_cast<std::uintptr_t>(si) *
                                sizeof(sh),
                        &sh,
                        sizeof(sh)))
                {
                    continue;
                }

                const auto size =
                    static_cast<std::size_t>(
                        (std::max)(
                            sh.Misc.VirtualSize,
                            sh.SizeOfRawData));

                if (!size ||
                    size > 512ull * 1024ull * 1024ull)
                    continue;

                Range r{};
                r.start = base + sh.VirtualAddress;
                r.end = r.start + size;
                r.executable =
                    (sh.Characteristics &
                     IMAGE_SCN_MEM_EXECUTE) != 0;
                r.readable =
                    (sh.Characteristics &
                     IMAGE_SCN_MEM_READ) != 0;
                std::memcpy(r.name, sh.Name, 8);
                ranges.push_back(r);
            }

            auto IsGame =
                [&](std::uintptr_t a)
                {
                    return a >= base && a < moduleEnd;
                };

            auto IsExec =
                [&](std::uintptr_t a)
                {
                    for (const auto& r : ranges)
                    {
                        if (r.executable &&
                            r.readable &&
                            a >= r.start &&
                            a < r.end)
                        {
                            return true;
                        }
                    }
                    return false;
                };

            enum : unsigned char
            {
                EDGE_DIRECT_CALL = 1,
                EDGE_DIRECT_JMP = 2,
                EDGE_INDIRECT_CALL = 3,
                EDGE_INDIRECT_JMP = 4,
                EDGE_RIP_REF = 5,
                EDGE_DATA_QWORD = 6,
                EDGE_DATA_RVA32 = 7
            };

            struct Edge
            {
                std::uintptr_t from = 0;
                std::uintptr_t target = 0;
                std::uintptr_t slot = 0;
                unsigned char kind = 0;
            };

            std::vector<Edge> codeEdges;
            std::vector<Edge> dataEdges;
            codeEdges.reserve(8000000);
            dataEdges.reserve(2500000);

            constexpr std::size_t kChunk =
                1024 * 1024;

            std::size_t scannedExecBytes = 0;
            std::size_t scannedDataBytes = 0;

            Console(
                "[SCAN] Phase 1/4: one executable-image index pass...\n");

            for (const auto& range : ranges)
            {
                if (!range.executable ||
                    !range.readable)
                    continue;

                const auto total =
                    static_cast<std::size_t>(
                        range.end - range.start);

                Console(
                    "[SCAN]   code %-8s %.2f MB\n",
                    range.name,
                    static_cast<double>(total) /
                        (1024.0 * 1024.0));

                std::vector<unsigned char>
                    bytes(kChunk + 16);

                for (std::size_t consumed = 0;
                     consumed < total;)
                {
                    const auto want =
                        (std::min<std::size_t>)(
                            kChunk,
                            total - consumed);

                    const auto cursor =
                        range.start + consumed;

                    if (SafeRead(
                            cursor,
                            bytes.data(),
                            want))
                    {
                        for (std::size_t off = 0;
                             off + 7 <= want;
                             ++off)
                        {
                            const auto here =
                                cursor + off;

                            if (bytes[off] == 0xE8 ||
                                bytes[off] == 0xE9)
                            {
                                std::int32_t rel = 0;
                                std::memcpy(
                                    &rel,
                                    bytes.data() + off + 1,
                                    sizeof(rel));

                                const auto target =
                                    static_cast<std::uintptr_t>(
                                        static_cast<std::intptr_t>(
                                            here + 5) + rel);

                                if (IsGame(target))
                                {
                                    codeEdges.push_back(
                                        {
                                            here,
                                            target,
                                            0,
                                            bytes[off] == 0xE8
                                                ? EDGE_DIRECT_CALL
                                                : EDGE_DIRECT_JMP
                                        });
                                }
                            }

                            if (bytes[off] == 0xFF &&
                                (bytes[off + 1] == 0x15 ||
                                 bytes[off + 1] == 0x25))
                            {
                                std::int32_t disp = 0;
                                std::memcpy(
                                    &disp,
                                    bytes.data() + off + 2,
                                    sizeof(disp));

                                const auto slot =
                                    static_cast<std::uintptr_t>(
                                        static_cast<std::intptr_t>(
                                            here + 6) + disp);

                                std::uintptr_t target = 0;

                                if (SafeRead(
                                        slot,
                                        &target,
                                        sizeof(target)))
                                {
                                    codeEdges.push_back(
                                        {
                                            here,
                                            target,
                                            slot,
                                            bytes[off + 1] == 0x15
                                                ? EDGE_INDIRECT_CALL
                                                : EDGE_INDIRECT_JMP
                                        });
                                }
                            }

                            std::size_t op = off;
                            if ((bytes[op] & 0xF0) == 0x40)
                                ++op;

                            if (op + 6 <= want)
                            {
                                const auto opcode =
                                    bytes[op];
                                const auto modrm =
                                    bytes[op + 1];

                                if ((opcode == 0x8D ||
                                     opcode == 0x8B ||
                                     opcode == 0x89 ||
                                     opcode == 0xFF) &&
                                    (modrm & 0xC7) == 0x05)
                                {
                                    std::int32_t disp = 0;
                                    std::memcpy(
                                        &disp,
                                        bytes.data() + op + 2,
                                        sizeof(disp));

                                    const auto len =
                                        (op - off) + 6;

                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                here + len) + disp);

                                    if (IsGame(target))
                                    {
                                        codeEdges.push_back(
                                            {
                                                here,
                                                target,
                                                0,
                                                EDGE_RIP_REF
                                            });
                                    }
                                }
                            }
                        }
                    }

                    scannedExecBytes += want;
                    consumed += want;
                }
            }

            Console(
                "[SCAN] Phase 1 complete: %.2f MB, %llu code refs.\n",
                static_cast<double>(scannedExecBytes) /
                    (1024.0 * 1024.0),
                static_cast<unsigned long long>(
                    codeEdges.size()));

            Console(
                "[SCAN] Phase 2/4: one readable-data pointer index pass...\n");

            for (const auto& range : ranges)
            {
                if (!range.readable ||
                    range.executable)
                    continue;

                const auto total =
                    static_cast<std::size_t>(
                        range.end - range.start);

                Console(
                    "[SCAN]   data %-8s %.2f MB\n",
                    range.name,
                    static_cast<double>(total) /
                        (1024.0 * 1024.0));

                std::vector<unsigned char>
                    bytes(kChunk + 16);

                for (std::size_t consumed = 0;
                     consumed < total;)
                {
                    const auto want =
                        (std::min<std::size_t>)(
                            kChunk,
                            total - consumed);

                    const auto cursor =
                        range.start + consumed;

                    if (SafeRead(
                            cursor,
                            bytes.data(),
                            want))
                    {
                        for (std::size_t off = 0;
                             off + 8 <= want;
                             off += 8)
                        {
                            std::uintptr_t target = 0;
                            std::memcpy(
                                &target,
                                bytes.data() + off,
                                sizeof(target));

                            if (IsExec(target))
                            {
                                dataEdges.push_back(
                                    {
                                        cursor + off,
                                        target,
                                        0,
                                        EDGE_DATA_QWORD
                                    });
                            }
                        }

                        for (std::size_t off = 0;
                             off + 4 <= want;
                             off += 4)
                        {
                            std::uint32_t rva = 0;
                            std::memcpy(
                                &rva,
                                bytes.data() + off,
                                sizeof(rva));

                            const auto target =
                                base +
                                static_cast<std::uintptr_t>(
                                    rva);

                            if (rva &&
                                IsGame(target) &&
                                IsExec(target))
                            {
                                dataEdges.push_back(
                                    {
                                        cursor + off,
                                        target,
                                        0,
                                        EDGE_DATA_RVA32
                                    });
                            }
                        }
                    }

                    scannedDataBytes += want;
                    consumed += want;

                    if (dataEdges.size() >= 2500000)
                    {
                        Console(
                            "[SCAN]   pointer index cap reached (2,500,000).\n");
                        break;
                    }
                }

                if (dataEdges.size() >= 2500000)
                    break;
            }

            Console(
                "[SCAN] Phase 2 complete: %.2f MB, %llu pointer refs.\n",
                static_cast<double>(scannedDataBytes) /
                    (1024.0 * 1024.0),
                static_cast<unsigned long long>(
                    dataEdges.size()));

            Console(
                "[SCAN] Phase 3/4: building reverse lookup tables...\n");

            std::unordered_multimap<
                std::uintptr_t,
                std::size_t> codeByTarget;

            std::unordered_multimap<
                std::uintptr_t,
                std::size_t> codeByResolvedAddress;

            std::unordered_multimap<
                std::uintptr_t,
                std::size_t> dataByTarget;

            codeByTarget.reserve(codeEdges.size());
            codeByResolvedAddress.reserve(codeEdges.size());
            dataByTarget.reserve(dataEdges.size());

            for (std::size_t i = 0;
                 i < codeEdges.size();
                 ++i)
            {
                const auto& e = codeEdges[i];

                if ((e.kind == EDGE_DIRECT_CALL ||
                     e.kind == EDGE_DIRECT_JMP ||
                     e.kind == EDGE_INDIRECT_CALL ||
                     e.kind == EDGE_INDIRECT_JMP) &&
                    e.target)
                {
                    codeByTarget.emplace(
                        e.target,
                        i);
                }

                if (e.kind == EDGE_RIP_REF &&
                    e.target)
                {
                    codeByResolvedAddress.emplace(
                        e.target,
                        i);
                }

                if (e.slot)
                {
                    codeByResolvedAddress.emplace(
                        e.slot,
                        i);
                }
            }

            for (std::size_t i = 0;
                 i < dataEdges.size();
                 ++i)
            {
                dataByTarget.emplace(
                    dataEdges[i].target,
                    i);
            }

            Console("[SCAN] Phase 3 complete.\n");
            Console(
                "[SCAN] Phase 4/4: walking ONLY upstream callers/owners...\n");

            auto FindLikelyStart =
                [&](std::uintptr_t site)
                    -> std::uintptr_t
            {
                if (!IsExec(site))
                    return site;

                constexpr std::size_t kBack =
                    0x500;

                const auto begin =
                    site > base + kBack
                        ? site - kBack
                        : base;

                const auto size =
                    static_cast<std::size_t>(
                        site - begin);

                if (!size)
                    return site;

                std::vector<unsigned char> bytes(size);

                if (!SafeRead(
                        begin,
                        bytes.data(),
                        bytes.size()))
                {
                    return site;
                }

                for (std::size_t i = bytes.size();
                     i-- > 1;)
                {
                    if (bytes[i - 1] == 0xCC ||
                        bytes[i - 1] == 0xC3 ||
                        bytes[i - 1] == 0xC2)
                    {
                        return begin + i;
                    }
                }

                return site;
            };

            struct Node
            {
                std::uintptr_t queryAddress = 0;
                std::uintptr_t entry = 0;
                std::uintptr_t discoveredAt = 0;
                std::uintptr_t from = 0;
                unsigned int depth = 0;
                std::string reason;
            };

            struct GraphRef
            {
                std::uintptr_t from = 0;
                std::uintptr_t to = 0;
                std::string kind;
            };

            std::vector<Node> nodes;
            std::vector<GraphRef> graphRefs;
            std::vector<std::size_t> queue;
            std::unordered_set<std::uintptr_t> seenQueries;

            auto AddNode =
                [&](std::uintptr_t query,
                    std::uintptr_t discoveredAt,
                    unsigned int depth,
                    std::uintptr_t from,
                    const char* reason)
            {
                if (!IsExec(query) ||
                    depth > 8 ||
                    nodes.size() >= 512)
                    return;

                if (!seenQueries.insert(query).second)
                    return;

                Node n{};
                n.queryAddress = query;
                n.entry = FindLikelyStart(query);
                n.discoveredAt = discoveredAt;
                n.from = from;
                n.depth = depth;
                n.reason =
                    reason ? reason : "unknown";

                nodes.push_back(n);
                queue.push_back(nodes.size() - 1);

                Console(
                    "[SCAN]   upstream #%llu query=0x%llX entry~=0x%llX depth=%u reason=%s\n",
                    static_cast<unsigned long long>(
                        nodes.size() - 1),
                    static_cast<unsigned long long>(
                        query - base),
                    static_cast<unsigned long long>(
                        n.entry - base),
                    depth,
                    n.reason.c_str());
            };

            auto AddRef =
                [&](std::uintptr_t from,
                    std::uintptr_t to,
                    const char* kind)
            {
                GraphRef r{};
                r.from = from;
                r.to = to;
                r.kind =
                    kind ? kind : "unknown";
                graphRefs.push_back(r);
            };

            // Exact seeds plus the two most useful candidates from Build246.
            AddNode(
                base + 0xAF20CB0,
                base + 0xAF20CB0,
                0,
                0,
                "seed_setter_exact");

            AddNode(
                base + 0xAEA1256,
                base + 0xAEA1256,
                0,
                0,
                "seed_wrapper");

            AddNode(
                base + 0xAEA1264,
                base + 0xAEA1264,
                0,
                0,
                "seed_callsite");

            AddNode(
                base + 0x998AA2,
                base + 0x998AA2,
                0,
                0,
                "build246_candidate_998AA2");

            AddNode(
                base + 0x146A039,
                base + 0x146A039,
                0,
                0,
                "build246_candidate_146A039");

            std::size_t processed = 0;

            while (processed < queue.size() &&
                   nodes.size() < 512)
            {
                const auto nodeIndex =
                    queue[processed++];

                const auto node =
                    nodes[nodeIndex];

                const std::uintptr_t lookupTargets[] =
                {
                    node.queryAddress,
                    node.entry
                };

                for (const auto lookup :
                     lookupTargets)
                {
                    if (!lookup)
                        continue;

                    auto directRange =
                        codeByTarget.equal_range(
                            lookup);

                    for (auto it = directRange.first;
                         it != directRange.second;
                         ++it)
                    {
                        const auto& e =
                            codeEdges[it->second];

                        const char* kind =
                            e.kind == EDGE_DIRECT_CALL
                                ? "DIRECT_CALLER"
                                : e.kind == EDGE_DIRECT_JMP
                                    ? "DIRECT_JMP_CALLER"
                                    : e.kind == EDGE_INDIRECT_CALL
                                        ? "INDIRECT_SLOT_CALLER"
                                        : "INDIRECT_SLOT_JMP";

                        AddRef(
                            e.from,
                            lookup,
                            kind);

                        const auto callerEntry =
                            FindLikelyStart(
                                e.from);

                        AddNode(
                            callerEntry,
                            e.from,
                            node.depth + 1,
                            lookup,
                            kind);
                    }

                    // Code may take the function's address directly via LEA/MOV.
                    auto codeRefRange =
                        codeByResolvedAddress.equal_range(
                            lookup);

                    for (auto it =
                             codeRefRange.first;
                         it !=
                             codeRefRange.second;
                         ++it)
                    {
                        const auto& e =
                            codeEdges[it->second];

                        AddRef(
                            e.from,
                            lookup,
                            "CODE_ADDRESS_REF");

                        AddNode(
                            FindLikelyStart(e.from),
                            e.from,
                            node.depth + 1,
                            lookup,
                            "code_address_ref");
                    }

                    // Qword/RVA pointer owners, then code that uses the owner.
                    auto dataRange =
                        dataByTarget.equal_range(
                            lookup);

                    for (auto it = dataRange.first;
                         it != dataRange.second;
                         ++it)
                    {
                        const auto& d =
                            dataEdges[it->second];

                        AddRef(
                            d.from,
                            lookup,
                            d.kind == EDGE_DATA_QWORD
                                ? "QWORD_POINTER_OWNER"
                                : "RVA32_POINTER_OWNER");

                        auto ownerUsers =
                            codeByResolvedAddress.equal_range(
                                d.from);

                        for (auto user =
                                 ownerUsers.first;
                             user !=
                                 ownerUsers.second;
                             ++user)
                        {
                            const auto& u =
                                codeEdges[
                                    user->second];

                            AddRef(
                                u.from,
                                d.from,
                                "OWNER_TABLE_USER");

                            AddNode(
                                FindLikelyStart(
                                    u.from),
                                u.from,
                                node.depth + 1,
                                d.from,
                                "owner_table_user");
                        }
                    }
                }

                if ((processed % 8) == 0 ||
                    processed == queue.size())
                {
                    Console(
                        "[SCAN]   upstream progress %llu/%llu | functions=%llu refs=%llu\n",
                        static_cast<unsigned long long>(
                            processed),
                        static_cast<unsigned long long>(
                            queue.size()),
                        static_cast<unsigned long long>(
                            nodes.size()),
                        static_cast<unsigned long long>(
                            graphRefs.size()));
                }
            }

            WriteLine("[UPSTREAM FUNCTIONS]\r\n");

            for (std::size_t i = 0;
                 i < nodes.size();
                 ++i)
            {
                const auto& n = nodes[i];

                char line[768]{};
                sprintf_s(
                    line,
                    "id=%llu queryRva=0x%llX entryGuessRva=0x%llX discoveredAtRva=0x%llX depth=%u from=%s0x%llX reason=%s\r\n",
                    static_cast<unsigned long long>(i),
                    static_cast<unsigned long long>(
                        n.queryAddress - base),
                    static_cast<unsigned long long>(
                        n.entry - base),
                    static_cast<unsigned long long>(
                        IsGame(n.discoveredAt)
                            ? n.discoveredAt - base
                            : n.discoveredAt),
                    n.depth,
                    IsGame(n.from)
                        ? "rva="
                        : "abs=",
                    static_cast<unsigned long long>(
                        IsGame(n.from)
                            ? n.from - base
                            : n.from),
                    n.reason.c_str());

                WriteLine(line);

                const auto dumpStart =
                    n.discoveredAt &&
                    IsExec(n.discoveredAt) &&
                    n.discoveredAt > base + 0x80
                        ? n.discoveredAt - 0x80
                        : n.entry;

                unsigned char code[0x300]{};
                SIZE_T got = 0;

                if (ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(
                            dumpStart),
                        code,
                        sizeof(code),
                        &got) &&
                    got)
                {
                    char codeLine[8192]{};
                    int used =
                        sprintf_s(
                            codeLine,
                            "  codeStartRva=0x%llX bytes:",
                            static_cast<unsigned long long>(
                                dumpStart - base));

                    for (SIZE_T j = 0;
                         j < got &&
                         used <
                            static_cast<int>(
                                sizeof(codeLine) - 8);
                         ++j)
                    {
                        used +=
                            sprintf_s(
                                codeLine + used,
                                sizeof(codeLine) - used,
                                " %02X",
                                static_cast<unsigned int>(
                                    code[j]));
                    }

                    used +=
                        sprintf_s(
                            codeLine + used,
                            sizeof(codeLine) - used,
                            "\r\n");
                    WriteLine(codeLine);
                }
            }

            WriteLine("\r\n[UPSTREAM REFERENCES]\r\n");

            for (const auto& r : graphRefs)
            {
                char line[512]{};

                const bool fromGame =
                    IsGame(r.from);
                const bool toGame =
                    IsGame(r.to);

                sprintf_s(
                    line,
                    "kind=%s from=%s0x%llX to=%s0x%llX\r\n",
                    r.kind.c_str(),
                    fromGame ? "rva=" : "abs=",
                    static_cast<unsigned long long>(
                        fromGame
                            ? r.from - base
                            : r.from),
                    toGame ? "rva=" : "abs=",
                    static_cast<unsigned long long>(
                        toGame
                            ? r.to - base
                            : r.to));

                WriteLine(line);
            }

            char footer[512]{};
            sprintf_s(
                footer,
                "\r\ncodeRefs=%llu dataRefs=%llu upstreamFunctions=%llu upstreamRefs=%llu\r\n"
                "[END BUILD247 UPSTREAM GRAPH]\r\n",
                static_cast<unsigned long long>(
                    codeEdges.size()),
                static_cast<unsigned long long>(
                    dataEdges.size()),
                static_cast<unsigned long long>(
                    nodes.size()),
                static_cast<unsigned long long>(
                    graphRefs.size()));
            WriteLine(footer);

            CloseHandle(file);

            Console(
                "[SCAN] ----------------------------------------\n"
                "[SCAN] SCAN COMPLETE\n"
                "[SCAN] upstreamFunctions=%llu upstreamRefs=%llu\n"
                "[SCAN] codeRefs=%llu dataRefs=%llu\n"
                "[SCAN] output=%s\n"
                "[SCAN] ========================================\n\n",
                static_cast<unsigned long long>(
                    nodes.size()),
                static_cast<unsigned long long>(
                    graphRefs.size()),
                static_cast<unsigned long long>(
                    codeEdges.size()),
                static_cast<unsigned long long>(
                    dataEdges.size()),
                path);
        }

        DWORD WINAPI Worker(LPVOID)
        {
            log_paths::EnsureAll();

            std::uint32_t lastNetworkMode = 0;
            unsigned char lastInited = 0;
            std::uintptr_t lastAuth = 0;

            SafeRead(
                g_networkModeAddress,
                &lastNetworkMode,
                sizeof(lastNetworkMode));
            SafeRead(
                g_initedAddress,
                &lastInited,
                sizeof(lastInited));
            SafeRead(
                g_authManagerAddress,
                &lastAuth,
                sizeof(lastAuth));

            char start[512]{};
            sprintf_s(
                start,
                "[TRACE-START] mode=%s networkMode=0x%X inited=%u auth=0x%llX\r\n",
                g_modeLabel,
                lastNetworkMode,
                static_cast<unsigned int>(lastInited),
                static_cast<unsigned long long>(lastAuth));
            Append(start);

            // Build244: passive upstream analysis of the only known caller
            // into LobbyBase_SetNetworkMode. This does not patch or hook code.
            ScanRuntimeFunctionGraph();

            const auto module =
                GetModuleHandleW(nullptr);
            const auto moduleBase =
                reinterpret_cast<std::uintptr_t>(module);

            std::uintptr_t moduleEnd = 0;
            if (moduleBase)
            {
                IMAGE_DOS_HEADER dos{};
                IMAGE_NT_HEADERS64 nt{};

                if (SafeRead(
                        moduleBase,
                        &dos,
                        sizeof(dos)) &&
                    dos.e_magic ==
                        IMAGE_DOS_SIGNATURE &&
                    SafeRead(
                        moduleBase +
                            static_cast<std::uintptr_t>(
                                dos.e_lfanew),
                        &nt,
                        sizeof(nt)) &&
                    nt.Signature ==
                        IMAGE_NT_SIGNATURE)
                {
                    moduleEnd =
                        moduleBase +
                        static_cast<std::uintptr_t>(
                            nt.OptionalHeader.SizeOfImage);
                }
            }

            // Build243: service-object auto-resolution is disabled. Build242
            // did not resolve the object reliably; the direct setter hook is
            // the authoritative trace for this test.
            g_serviceObjectGlobal = 0;

            DiffField serviceFields[] =
            {
                { "ptr38", 0x38, 8, 0, false },
                { "ptrB0", 0xB0, 8, 0, false },
                { "dispatchD0", 0xD0, 8, 0, false },
                { "state704", 0x704, 4, 0, false },
                { "state738", 0x738, 8, 0, false },
                { "state740", 0x740, 8, 0, false },
                { "state748", 0x748, 8, 0, false },
                { "state750", 0x750, 8, 0, false },
                { "state754", 0x754, 4, 0, false },
                { "state758", 0x758, 8, 0, false },
                { "flag9E9", 0x9E9, 1, 0, false },
                { "stateA58", 0xA58, 8, 0, false }
            };

            std::uintptr_t lastServiceObject = 0;

            const ULONGLONG begin = GetTickCount64();

            while (g_running.load())
            {
                std::uint32_t networkMode = lastNetworkMode;
                unsigned char inited = lastInited;
                std::uintptr_t auth = lastAuth;

                SafeRead(
                    g_networkModeAddress,
                    &networkMode,
                    sizeof(networkMode));
                SafeRead(
                    g_initedAddress,
                    &inited,
                    sizeof(inited));
                SafeRead(
                    g_authManagerAddress,
                    &auth,
                    sizeof(auth));

                if (networkMode != lastNetworkMode ||
                    inited != lastInited ||
                    auth != lastAuth)
                {
                    SYSTEMTIME st{};
                    GetLocalTime(&st);

                    char line[768]{};
                    sprintf_s(
                        line,
                        "[%02u:%02u:%02u.%03u] mode=%s "
                        "networkMode=0x%X->0x%X "
                        "inited=%u->%u "
                        "auth=0x%llX->0x%llX\r\n",
                        st.wHour,
                        st.wMinute,
                        st.wSecond,
                        st.wMilliseconds,
                        g_modeLabel,
                        lastNetworkMode,
                        networkMode,
                        static_cast<unsigned int>(lastInited),
                        static_cast<unsigned int>(inited),
                        static_cast<unsigned long long>(lastAuth),
                        static_cast<unsigned long long>(auth));

                    Append(line);

                    lastNetworkMode = networkMode;
                    lastInited = inited;
                    lastAuth = auth;
                }

                // 1 ms during the early 90-second online bootstrap window,
                // then relax to 10 ms.
                const ULONGLONG elapsed =
                    GetTickCount64() - begin;
                Sleep(elapsed < 90000 ? 2 : 10);
            }

            return 0;
        }
    }

    void Start(
        std::uintptr_t networkModeAddress,
        std::uintptr_t initedAddress,
        std::uintptr_t authManagerAddress,
        const char* modeLabel)
    {
        if (!networkModeAddress ||
            !initedAddress ||
            !authManagerAddress)
            return;

        g_networkModeAddress = networkModeAddress;
        g_initedAddress = initedAddress;
        g_authManagerAddress = authManagerAddress;

        if (modeLabel && *modeLabel)
            strncpy_s(
                g_modeLabel,
                sizeof(g_modeLabel),
                modeLabel,
                _TRUNCATE);

        if (g_running.exchange(true))
            return;

        g_worker = CreateThread(
            nullptr,
            0,
            Worker,
            nullptr,
            0,
            nullptr);

        if (!g_worker)
            g_running.store(false);
    }

    bool IsRunning()
    {
        return g_running.load();
    }
}
