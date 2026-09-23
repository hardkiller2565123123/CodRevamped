#include "LanProfileResearch.h"

#include "../core/functions.hpp"
#include "../runtime/LogPaths.h"

#include <Windows.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <map>
#include <algorithm>
#include <set>

namespace
{
    bool SafeRead(std::uintptr_t address, void* out, std::size_t size)
    {
        if (!address || !out || !size)
            return false;

        SIZE_T got = 0;
        return ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<const void*>(address),
            out,
            size,
            &got) &&
            got == size;
    }


    bool IsReadable(std::uintptr_t address, std::size_t size)
    {
        if (!address || !size)
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
            return false;

        if (mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return false;

        const auto regionStart =
            reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto regionEnd = regionStart + mbi.RegionSize;

        return address >= regionStart &&
               address + size >= address &&
               address + size <= regionEnd;
    }

    bool LooksAscii(const unsigned char* data, std::size_t len)
    {
        if (!data || len < 3)
            return false;

        std::size_t printable = 0;

        for (std::size_t i = 0; i < len; ++i)
        {
            const unsigned char c = data[i];

            if (c == 0)
                break;

            if (c >= 0x20 && c <= 0x7E)
                ++printable;
            else
                return false;
        }

        return printable >= 3;
    }

    std::vector<std::uintptr_t> FindAsciiInModule(
        const char* needle,
        std::size_t maxHits = 64)
    {
        std::vector<std::uintptr_t> hits;

        if (!needle || !*needle)
            return hits;

        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
            return hits;

        const auto base =
            reinterpret_cast<std::uintptr_t>(module);

        IMAGE_DOS_HEADER dos{};
        if (!SafeRead(base, &dos, sizeof(dos)) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE)
            return hits;

        IMAGE_NT_HEADERS64 nt{};
        if (!SafeRead(
                base + static_cast<std::uintptr_t>(dos.e_lfanew),
                &nt,
                sizeof(nt)) ||
            nt.Signature != IMAGE_NT_SIGNATURE)
            return hits;

        const auto moduleEnd =
            base +
            static_cast<std::uintptr_t>(
                nt.OptionalHeader.SizeOfImage);

        const std::size_t needleLen =
            std::strlen(needle);

        std::uintptr_t cursor = base;

        while (cursor < moduleEnd &&
               hits.size() < maxHits)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (!VirtualQuery(
                    reinterpret_cast<const void*>(cursor),
                    &mbi,
                    sizeof(mbi)))
            {
                break;
            }

            const auto regionBase =
                reinterpret_cast<std::uintptr_t>(
                    mbi.BaseAddress);

            const auto regionEnd =
                regionBase +
                static_cast<std::uintptr_t>(
                    mbi.RegionSize);

            const auto clippedStart =
                std::max(regionBase, base);

            const auto clippedEnd =
                std::min(regionEnd, moduleEnd);

            const bool readable =
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                clippedEnd > clippedStart;

            if (readable)
            {
                const auto size =
                    static_cast<std::size_t>(
                        clippedEnd - clippedStart);

                std::vector<unsigned char> bytes(size);

                if (SafeRead(
                        clippedStart,
                        bytes.data(),
                        bytes.size()))
                {
                    for (std::size_t i = 0;
                         i + needleLen <= bytes.size() &&
                         hits.size() < maxHits;
                         ++i)
                    {
                        if (_strnicmp(
                                reinterpret_cast<const char*>(
                                    bytes.data() + i),
                                needle,
                                needleLen) == 0)
                        {
                            hits.push_back(
                                clippedStart + i);
                        }
                    }
                }
            }

            if (regionEnd <= cursor)
                break;

            cursor = regionEnd;
        }

        return hits;
    }

    const char* YesNo(bool value)
    {
        return value ? "yes" : "no";
    }
}

namespace lan_profile_research
{
    std::string LanStatus()
    {
        std::ostringstream out;
        out << "LAN research: "
            << "LobbyBase_SetNetworkMode=" << YesNo(g_Addrs.LobbyBase_SetNetworkMode != 0)
            << " Com_SessionMode_SetNetworkMode=" << YesNo(g_Addrs.Com_SessionMode_SetNetworkMode != 0)
            << " LiveUser=" << YesNo(g_Addrs.LiveUser_GetUserDataForController != 0)
            << " controllingLobby=" << YesNo(g_Addrs.LobbySession_GetControllingLobbySession != 0)
            << " config0=" << YesNo(g_Addrs.config[0] != 0)
            << " config1=" << YesNo(g_Addrs.config[1] != 0)
            << " nativeSessionCreate=scanning"
            << " nativePartyJoin=scanning";
        return out.str();
    }

    std::string ProfileStatus()
    {
        std::ostringstream out;
        out << "Profile research: LiveUser_GetUserDataForController="
            << YesNo(g_Addrs.LiveUser_GetUserDataForController != 0);

        if (g_Addrs.LiveUser_GetUserDataForController)
        {
            const auto user = LiveUser_GetUserDataForController(0);
            out << " userData=0x"
                << std::hex << std::uppercase
                << static_cast<unsigned long long>(user)
                << std::dec;
        }

        out << " usernameSetter="
            << YesNo(g_Addrs.set_username != 0);

        return out.str();
    }

    bool SetLanNetworkMode(bool lan, std::string& message)
    {
        if (!g_Addrs.LobbyBase_SetNetworkMode)
        {
            message = "LobbyBase_SetNetworkMode is unresolved.";
            return false;
        }

        LobbyBase_SetNetworkMode(
            lan
                ? LOBBY_NETWORKMODE_LAN
                : LOBBY_NETWORKMODE_LIVE);

        message = lan
            ? "Lobby network mode set to LAN (1)."
            : "Lobby network mode set to LIVE (2).";
        return true;
    }

    bool SetSessionMode(int mode, std::string& message)
    {
        if (!g_Addrs.Com_SessionMode_SetNetworkMode)
        {
            message = "Com_SessionMode_SetNetworkMode is unresolved.";
            return false;
        }

        if (mode < 0 || mode > 2)
        {
            message = "session mode must be 0, 1, or 2";
            return false;
        }

        Com_SessionMode_SetMode(mode);

        std::ostringstream out;
        out << "Com_SessionMode_SetNetworkMode(" << mode << ") called.";
        message = out.str();
        return true;
    }

    bool WriteLanResearchReport(std::string& message)
    {
        log_paths::EnsureAll();

        std::ofstream file(
            "logs\\lan\\lan_research_status.txt",
            std::ios::trunc);

        if (!file)
        {
            message = "could not create logs\\lan\\lan_research_status.txt";
            return false;
        }

        file << "[T9 LAN RESEARCH]\n";
        file << LanStatus() << "\n\n";

        file << "[KNOWN T9 SIGNATURE REFERENCES FROM USER-SUPPLIED SOURCE]\n";
        file << "LiveUser_GetUserDataForController: "
             << "E8 ? ? ? ? 48 8B E8 33 C0 48 89 85 ? ? ? ? 48 8D 4D 10 ...\n";
        file << "LobbyBase_SetNetworkMode: "
             << "40 53 48 83 EC 20 8B D9 89 0D ? ? ? ? E8 ? ? ? ? 8B CB E8 ? ? ? ?\n";
        file << "Com_SessionMode_SetNetworkMode: "
             << "8B 05 ? ? ? ? 8B D0 33 D1 83 E2 0F 33 C2 89 05 ? ? ? ? C3\n";
        file << "Native system-link LUI menu reference: menu_systemlink_join\n\n";

        if (!g_Addrs.config[1])
        {
            file << "[CONFIG[1] RETRY PATTERNS]\n";
            file << "primary: 80 3D ? ? ? ? ? 75 58 33 C9 48 89 5C 24 ?\n";
            file << "alternate/source: 80 3D ? ? ? ? ? 48 8D 15 ? ? ? ? 48 8B 3F 48 8B C8 48 0F 45 3D ? ? ? ? E8 ? ? ? ?\n\n";
        }

        file << "[NATIVE LAN / SYSTEMLINK STRINGS]\n";

        for (const char* term :
             {"menu_systemlink_join", "systemlink", "system_link", "lan"})
        {
            const auto hits = FindAsciiInModule(term, 24);

            file << term << ": " << hits.size() << " hit(s)\n";

            for (const auto hit : hits)
            {
                file << "  0x"
                     << std::hex
                     << std::uppercase
                     << hit
                     << std::dec
                     << "\n";
            }
        }

        file << "\n";

        file << "[CURRENT RESOLVED ADDRESSES]\n";
        file << std::hex << std::uppercase;
        file << "LiveUser_GetUserDataForController=0x" << g_Addrs.LiveUser_GetUserDataForController << "\n";
        file << "LobbyBase_SetNetworkMode=0x" << g_Addrs.LobbyBase_SetNetworkMode << "\n";
        file << "Com_SessionMode_SetNetworkMode=0x" << g_Addrs.Com_SessionMode_SetNetworkMode << "\n";
        file << "LobbySession_GetControllingLobbySession=0x" << g_Addrs.LobbySession_GetControllingLobbySession << "\n";
        file << "config0=0x" << g_Addrs.config[0] << "\n";
        file << "config1=0x" << g_Addrs.config[1] << "\n";
        file << std::dec;

        file << "\n[NEXT NATIVE LAN TARGETS]\n";
        file << "NET_CreateSession equivalent: unresolved; build207 ranked candidates are in lan_native_candidate_summary.txt\n";
        file << "Party_StartLANServerJoin equivalent: unresolved; build207 ranked candidates are in lan_native_candidate_summary.txt\n";
        file << "XSESSION_INFO layout: unresolved; do not assume MW19's 108-byte layout\n";
        file << "Live_IsInSystemlinkLobby equivalent: unresolved\n";

        message = "LAN research report written to logs\\lan\\lan_research_status.txt";
        return true;
    }



    bool ScanSystemlinkXrefs(std::string& message)
    {
        log_paths::EnsureAll();

        HMODULE module = GetModuleHandleW(nullptr);
        if (!module)
        {
            message = "main module unavailable";
            return false;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(module);
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        if (!SafeRead(base, &dos, sizeof(dos)) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE ||
            !SafeRead(base + static_cast<std::uintptr_t>(dos.e_lfanew),
                &nt, sizeof(nt)) ||
            nt.Signature != IMAGE_NT_SIGNATURE)
        {
            message = "could not read PE headers";
            return false;
        }

        const auto moduleEnd =
            base + static_cast<std::uintptr_t>(nt.OptionalHeader.SizeOfImage);
        const auto sectionHeaderBase =
            base + static_cast<std::uintptr_t>(dos.e_lfanew) +
            sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
            nt.FileHeader.SizeOfOptionalHeader;

        constexpr std::uintptr_t kSystemlinkSlotRva = 0xE79E450;
        constexpr std::uintptr_t kTableStartRva = 0xE79E400;
        constexpr std::size_t kTableBytes = 0x1000;

        const auto tableStart = base + kTableStartRva;
        const auto tableEnd = (std::min)(
            tableStart + kTableBytes, moduleEnd);

        std::ostringstream summaryPath;
        summaryPath << "logs\\lan\\systemlink_table_"
                    << GetCurrentProcessId() << ".txt";
        std::ofstream summary(summaryPath.str(), std::ios::trunc);
        if (!summary)
        {
            message = "could not create systemlink table report";
            return false;
        }

        summary << "[T9 SYSTEMLINK TABLE FOCUS BUILD213]\n";
        summary << "moduleBase=0x" << std::hex << std::uppercase << base << "\n";
        summary << "knownSystemlinkSlotRva=0x" << kSystemlinkSlotRva << "\n";
        summary << "tableWindowRva=0x" << kTableStartRva
                << "-0x" << (kTableStartRva + kTableBytes) << std::dec << "\n\n";

        // Dump qword-oriented table interpretation.
        summary << "[TABLE QWORDS / STRING POINTERS]\n";
        for (std::uintptr_t address = tableStart;
             address + sizeof(std::uint64_t) <= tableEnd;
             address += sizeof(std::uint64_t))
        {
            std::uint64_t value = 0;
            if (!SafeRead(address, &value, sizeof(value)))
                continue;

            summary << "slotRva=0x" << std::hex << std::uppercase
                    << (address - base)
                    << " value=0x" << value;

            if (value >= base && value < moduleEnd)
            {
                char text[128]{};
                if (SafeRead(static_cast<std::uintptr_t>(value),
                    text, sizeof(text) - 1))
                {
                    std::size_t len = 0;
                    while (len < sizeof(text) - 1 &&
                           text[len] >= 0x20 && text[len] <= 0x7E)
                        ++len;
                    if (len >= 2)
                        summary << " ascii=\""
                                << std::string(text, len) << "\"";
                }
                summary << " targetRva=0x"
                        << (static_cast<std::uintptr_t>(value) - base);
            }
            summary << std::dec << "\n";
        }

        // Find executable references to the specific table slot and nearby table
        // base. This is fast because we match only a handful of concrete targets.
        const std::uintptr_t targets[] =
        {
            base + kSystemlinkSlotRva,
            base + kTableStartRva,
            base + kTableStartRva + 0x38,
            base + kTableStartRva + 0x40,
            base + kTableStartRva + 0x48,
            base + kTableStartRva + 0x50,
            base + kTableStartRva + 0x58,
            base + kTableStartRva + 0x60
        };

        struct CodeRef
        {
            std::uintptr_t instruction = 0;
            std::uintptr_t target = 0;
            std::uintptr_t functionStart = 0;
            std::vector<std::uintptr_t> calls;
        };
        std::vector<CodeRef> refs;

        auto FindLikelyFunctionStart =
            [&](std::uintptr_t xref) -> std::uintptr_t
        {
            constexpr std::size_t kBack = 0x240;
            const auto begin =
                xref > base + kBack ? xref - kBack : base;
            const auto size =
                static_cast<std::size_t>(xref - begin);
            std::vector<unsigned char> bytes(size);
            if (bytes.empty() ||
                !SafeRead(begin, bytes.data(), bytes.size()))
                return 0;

            for (std::size_t i = bytes.size(); i-- > 1;)
            {
                if (bytes[i - 1] == 0xCC || bytes[i - 1] == 0xC3)
                    return begin + i;
            }
            return 0;
        };

        for (unsigned int si = 0;
             si < nt.FileHeader.NumberOfSections;
             ++si)
        {
            IMAGE_SECTION_HEADER sh{};
            if (!SafeRead(sectionHeaderBase +
                    static_cast<std::uintptr_t>(si) * sizeof(sh),
                    &sh, sizeof(sh)))
                continue;

            if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                continue;

            const auto sectionStart = base + sh.VirtualAddress;
            const auto sectionSize = static_cast<std::size_t>(
                std::max(sh.Misc.VirtualSize, sh.SizeOfRawData));
            if (sectionSize < 8 ||
                sectionSize > 512ull * 1024ull * 1024ull)
                continue;

            const auto sectionEnd = sectionStart + sectionSize;
            std::uintptr_t cursor = sectionStart;

            while (cursor < sectionEnd)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void*>(cursor),
                    &mbi, sizeof(mbi)))
                    break;

                const auto regionBase =
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto regionEnd =
                    regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
                const auto chunkStart = std::max(cursor, regionBase);
                const auto chunkEnd = std::min(sectionEnd, regionEnd);
                const bool readable =
                    mbi.State == MEM_COMMIT &&
                    !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                    chunkEnd > chunkStart;

                if (readable)
                {
                    const auto size =
                        static_cast<std::size_t>(chunkEnd - chunkStart);
                    std::vector<unsigned char> bytes(size);
                    if (SafeRead(chunkStart, bytes.data(), bytes.size()))
                    {
                        for (std::size_t off = 0;
                             off + 7 <= bytes.size();
                             ++off)
                        {
                            // REX? + opcode + ModRM RIP-relative disp32.
                            std::size_t op = off;
                            if ((bytes[op] & 0xF0) == 0x40)
                                ++op;
                            if (op + 6 > bytes.size())
                                continue;

                            const unsigned char opcode = bytes[op];
                            if (opcode != 0x8D && opcode != 0x8B &&
                                opcode != 0x89 && opcode != 0x3B &&
                                opcode != 0x39)
                                continue;

                            const unsigned char modrm = bytes[op + 1];
                            if ((modrm & 0xC7) != 0x05)
                                continue;

                            std::int32_t disp = 0;
                            std::memcpy(&disp,
                                bytes.data() + op + 2, sizeof(disp));

                            const std::size_t instrLen =
                                (op - off) + 6;
                            const auto target =
                                static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(
                                        chunkStart + off + instrLen) + disp);

                            bool wanted = false;
                            for (const auto candidate : targets)
                            {
                                if (target == candidate)
                                {
                                    wanted = true;
                                    break;
                                }
                            }
                            if (!wanted)
                                continue;

                            CodeRef ref{};
                            ref.instruction = chunkStart + off;
                            ref.target = target;
                            ref.functionStart =
                                FindLikelyFunctionStart(ref.instruction);

                            const auto begin =
                                off > 0xC0 ? off - 0xC0 : 0;
                            const auto finish =
                                std::min<std::size_t>(
                                    bytes.size(), off + 0xC1);

                            for (std::size_t ci = begin;
                                 ci + 5 <= finish; ++ci)
                            {
                                if (bytes[ci] != 0xE8) continue;
                                std::int32_t rel = 0;
                                std::memcpy(&rel,
                                    bytes.data() + ci + 1, sizeof(rel));
                                const auto callAddress = chunkStart + ci;
                                const auto callTarget =
                                    static_cast<std::uintptr_t>(
                                        static_cast<std::intptr_t>(
                                            callAddress + 5) + rel);
                                if (callTarget >= base &&
                                    callTarget < moduleEnd)
                                    ref.calls.push_back(callTarget);
                            }

                            refs.push_back(std::move(ref));
                        }
                    }
                }

                if (regionEnd <= cursor)
                    break;
                cursor = regionEnd;
            }
        }

        summary << "\n[EXECUTABLE REFERENCES TO SYSTEMLINK TABLE]\n";
        for (const auto& ref : refs)
        {
            summary << "xrefRva=0x" << std::hex << std::uppercase
                    << (ref.instruction - base)
                    << " targetRva=0x" << (ref.target - base);

            if (ref.functionStart)
                summary << " functionStartRva=0x"
                        << (ref.functionStart - base);

            summary << std::dec
                    << " nearbyCalls=" << ref.calls.size() << "\n";

            for (const auto call : ref.calls)
                summary << "  callTargetRva=0x"
                        << std::hex << std::uppercase
                        << (call - base) << std::dec << "\n";
        }

        // Build214: dissect the concrete system-link function found by
        // build213, plus its incoming callers and direct call targets.
        {
            constexpr std::uintptr_t kLanFunctionRva = 0xB40DA59;
            constexpr std::uintptr_t kLanFunctionScanBytes = 0x900;
            const auto functionAddress = base + kLanFunctionRva;

            std::ostringstream dissectPath;
            dissectPath << "logs\\lan\\lan_B40DA59_"
                        << GetCurrentProcessId() << ".txt";
            std::ofstream dissect(dissectPath.str(), std::ios::trunc);

            if (dissect)
            {
                dissect << "[T9 LAN FUNCTION B40DA59 DISSECTION BUILD214]\n";
                dissect << "functionRva=0x" << std::hex << std::uppercase
                        << kLanFunctionRva << std::dec << "\n\n";

                std::vector<unsigned char> functionBytes(kLanFunctionScanBytes);
                if (SafeRead(functionAddress,
                    functionBytes.data(), functionBytes.size()))
                {
                    dissect << "[RAW WINDOW]\n";
                    for (std::size_t off = 0;
                         off < functionBytes.size(); off += 16)
                    {
                        dissect << "rva=0x" << std::hex << std::uppercase
                                << (kLanFunctionRva + off) << ": ";
                        for (std::size_t j = 0;
                             j < 16 && off + j < functionBytes.size(); ++j)
                        {
                            dissect << std::setw(2)
                                    << std::setfill('0')
                                    << static_cast<unsigned int>(
                                        functionBytes[off + j]) << ' ';
                        }
                        dissect << std::dec << "\n";
                    }

                    dissect << "\n[DIRECT CALLS FROM WINDOW]\n";
                    for (std::size_t off = 0;
                         off + 5 <= functionBytes.size(); ++off)
                    {
                        if (functionBytes[off] != 0xE8)
                            continue;

                        std::int32_t rel = 0;
                        std::memcpy(&rel,
                            functionBytes.data() + off + 1,
                            sizeof(rel));
                        const auto callAddress =
                            functionAddress + off;
                        const auto target =
                            static_cast<std::uintptr_t>(
                                static_cast<std::intptr_t>(
                                    callAddress + 5) + rel);

                        if (target >= base && target < moduleEnd)
                        {
                            dissect << "callRva=0x"
                                    << std::hex << std::uppercase
                                    << (callAddress - base)
                                    << " targetRva=0x"
                                    << (target - base)
                                    << std::dec << "\n";
                        }
                    }

                    dissect << "\n[SYSTEMLINK TABLE REFERENCES IN WINDOW]\n";
                    const std::uintptr_t tableTargets[] =
                    {
                        base + 0xE79E438,
                        base + 0xE79E440,
                        base + 0xE79E448,
                        base + 0xE79E450,
                        base + 0xE79E458
                    };

                    for (std::size_t off = 0;
                         off + 7 <= functionBytes.size(); ++off)
                    {
                        std::size_t op = off;
                        if ((functionBytes[op] & 0xF0) == 0x40)
                            ++op;
                        if (op + 6 > functionBytes.size())
                            continue;

                        const unsigned char opcode = functionBytes[op];
                        if (opcode != 0x8D && opcode != 0x8B &&
                            opcode != 0x89 && opcode != 0x3B &&
                            opcode != 0x39)
                            continue;

                        const unsigned char modrm = functionBytes[op + 1];
                        if ((modrm & 0xC7) != 0x05)
                            continue;

                        std::int32_t disp = 0;
                        std::memcpy(&disp,
                            functionBytes.data() + op + 2, sizeof(disp));
                        const std::size_t instrLen = (op - off) + 6;
                        const auto target =
                            static_cast<std::uintptr_t>(
                                static_cast<std::intptr_t>(
                                    functionAddress + off + instrLen) + disp);

                        for (const auto tableTarget : tableTargets)
                        {
                            if (target == tableTarget)
                            {
                                dissect << "instructionRva=0x"
                                        << std::hex << std::uppercase
                                        << (functionAddress + off - base)
                                        << " tableSlotRva=0x"
                                        << (tableTarget - base)
                                        << std::dec << "\n";
                            }
                        }
                    }
                }

                dissect << "\n[INDIRECT DISPATCH IN B40DA59 WINDOW]\n";
                if (!functionBytes.empty())
                {
                    for (std::size_t off = 0;
                         off + 2 <= functionBytes.size(); ++off)
                    {
                        // FF /2 = indirect CALL, FF /4 = indirect JMP.
                        if (functionBytes[off] != 0xFF)
                            continue;

                        const unsigned char modrm = functionBytes[off + 1];
                        const unsigned int regField = (modrm >> 3) & 7;
                        if (regField != 2 && regField != 4)
                            continue;

                        dissect << (regField == 2 ? "indirect_call" : "indirect_jmp")
                                << " instructionRva=0x"
                                << std::hex << std::uppercase
                                << (functionAddress + off - base);

                        // RIP-relative memory operand: mod=00 r/m=101.
                        if ((modrm & 0xC7) == 0x05 &&
                            off + 6 <= functionBytes.size())
                        {
                            std::int32_t disp = 0;
                            std::memcpy(
                                &disp,
                                functionBytes.data() + off + 2,
                                sizeof(disp));

                            const auto slot =
                                static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(
                                        functionAddress + off + 6) + disp);

                            dissect << " slotRva=0x"
                                    << (slot - base);

                            std::uintptr_t pointerValue = 0;
                            if (SafeRead(slot, &pointerValue, sizeof(pointerValue)))
                            {
                                dissect << " slotValue=0x"
                                        << pointerValue;
                                if (pointerValue >= base &&
                                    pointerValue < moduleEnd)
                                {
                                    dissect << " targetRva=0x"
                                            << (pointerValue - base);
                                }
                            }
                        }
                        else
                        {
                            dissect << " register_or_complex_operand_modrm=0x"
                                    << static_cast<unsigned int>(modrm);
                        }

                        dissect << std::dec << "\n";
                    }
                }

                dissect << "\n[NEARBY POINTER TABLE CANDIDATES]\n";
                for (std::uintptr_t slot = base + 0xE79E400;
                     slot < base + 0xE79E500;
                     slot += sizeof(std::uintptr_t))
                {
                    std::uintptr_t value = 0;
                    if (!SafeRead(slot, &value, sizeof(value)))
                        continue;

                    dissect << "slotRva=0x"
                            << std::hex << std::uppercase
                            << (slot - base)
                            << " value=0x" << value;

                    if (value >= base && value < moduleEnd)
                    {
                        dissect << " targetRva=0x"
                                << (value - base);

                        char text[96]{};
                        if (SafeRead(value, text, sizeof(text) - 1))
                        {
                            std::size_t len = 0;
                            while (len < sizeof(text) - 1 &&
                                   text[len] >= 0x20 &&
                                   text[len] <= 0x7E)
                                ++len;
                            if (len >= 2)
                                dissect << " ascii=\""
                                        << std::string(text, len)
                                        << "\"";
                        }
                    }
                    dissect << std::dec << "\n";
                }

                dissect << "\n[INCOMING CALLERS TO B40DA59]\n";
                unsigned int callerCount = 0;

                for (unsigned int si = 0;
                     si < nt.FileHeader.NumberOfSections; ++si)
                {
                    IMAGE_SECTION_HEADER sh{};
                    if (!SafeRead(sectionHeaderBase +
                            static_cast<std::uintptr_t>(si) * sizeof(sh),
                            &sh, sizeof(sh)))
                        continue;

                    if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                        !(sh.Characteristics & IMAGE_SCN_MEM_READ))
                        continue;

                    const auto sectionStart = base + sh.VirtualAddress;
                    const auto sectionSize = static_cast<std::size_t>(
                        std::max(sh.Misc.VirtualSize, sh.SizeOfRawData));
                    if (sectionSize < 5 ||
                        sectionSize > 512ull * 1024ull * 1024ull)
                        continue;

                    const auto sectionEnd = sectionStart + sectionSize;
                    std::uintptr_t cursor = sectionStart;

                    while (cursor < sectionEnd)
                    {
                        MEMORY_BASIC_INFORMATION mbi{};
                        if (!VirtualQuery(
                                reinterpret_cast<const void*>(cursor),
                                &mbi, sizeof(mbi)))
                            break;

                        const auto regionBase =
                            reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                        const auto regionEnd =
                            regionBase +
                            static_cast<std::uintptr_t>(mbi.RegionSize);
                        const auto chunkStart = std::max(cursor, regionBase);
                        const auto chunkEnd = std::min(sectionEnd, regionEnd);
                        const bool readable =
                            mbi.State == MEM_COMMIT &&
                            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                            chunkEnd > chunkStart;

                        if (readable)
                        {
                            const auto size =
                                static_cast<std::size_t>(chunkEnd - chunkStart);
                            std::vector<unsigned char> bytes(size);

                            if (SafeRead(chunkStart,
                                bytes.data(), bytes.size()))
                            {
                                for (std::size_t off = 0;
                                     off + 5 <= bytes.size(); ++off)
                                {
                                    if (bytes[off] != 0xE8)
                                        continue;

                                    std::int32_t rel = 0;
                                    std::memcpy(&rel,
                                        bytes.data() + off + 1,
                                        sizeof(rel));
                                    const auto callAddress =
                                        chunkStart + off;
                                    const auto target =
                                        static_cast<std::uintptr_t>(
                                            static_cast<std::intptr_t>(
                                                callAddress + 5) + rel);

                                    if (target == functionAddress)
                                    {
                                        dissect << "callerCallRva=0x"
                                                << std::hex << std::uppercase
                                                << (callAddress - base)
                                                << std::dec << "\n";
                                        ++callerCount;
                                    }
                                }
                            }
                        }

                        if (regionEnd <= cursor)
                            break;
                        cursor = regionEnd;
                    }
                }

                dissect << "incomingCallerCount="
                        << callerCount << "\n";
            }
        }

        std::ostringstream out;
        out << "systemlink table focus complete: "
            << refs.size()
            << " executable reference(s) to known table neighborhood. PID="
            << GetCurrentProcessId();
        message = out.str();
        return true;
    }

    bool InspectLanFunctions(std::string& message)
    {
        log_paths::EnsureAll();

        std::ofstream file(
            "logs\\lan\\lan_function_windows.txt",
            std::ios::trunc);

        if (!file)
        {
            message =
                "could not create logs\\lan\\lan_function_windows.txt";
            return false;
        }

        struct Target
        {
            const char* name;
            std::uintptr_t address;
        };

        const Target targets[] =
        {
            {
                "LobbyBase_SetNetworkMode",
                g_Addrs.LobbyBase_SetNetworkMode
            },
            {
                "Com_SessionMode_SetNetworkMode",
                g_Addrs.Com_SessionMode_SetNetworkMode
            },
            {
                "LobbySession_GetControllingLobbySession",
                g_Addrs.LobbySession_GetControllingLobbySession
            },
            {
                "LiveUser_GetUserDataForController",
                g_Addrs.LiveUser_GetUserDataForController
            }
        };

        unsigned int dumped = 0;

        for (const auto& target : targets)
        {
            file << "[" << target.name << "]\n";
            file << "address=0x"
                 << std::hex
                 << std::uppercase
                 << target.address
                 << std::dec
                 << "\n";

            if (!target.address)
            {
                file << "unresolved\n\n";
                continue;
            }

            constexpr std::size_t kWindow = 0x180;
            std::vector<unsigned char> bytes(kWindow);

            if (!SafeRead(
                    target.address,
                    bytes.data(),
                    bytes.size()))
            {
                file << "unreadable\n\n";
                continue;
            }

            ++dumped;

            for (std::size_t i = 0;
                 i < bytes.size();
                 ++i)
            {
                if ((i % 16) == 0)
                {
                    file << "+0x"
                         << std::hex
                         << std::setw(4)
                         << std::setfill('0')
                         << i
                         << ": ";
                }

                file << std::setw(2)
                     << static_cast<unsigned int>(bytes[i])
                     << ' ';

                if ((i % 16) == 15)
                    file << "\n";
            }

            file << std::dec << "\n";
        }

        std::ostringstream out;
        out << "dumped "
            << dumped
            << " resolved LAN/profile function window(s) to logs\\lan\\lan_function_windows.txt";

        message = out.str();
        return dumped != 0;
    }

    bool DumpProfile(std::string& message)
    {
        log_paths::EnsureAll();

        if (!g_Addrs.LiveUser_GetUserDataForController)
        {
            message = "LiveUser_GetUserDataForController is unresolved.";
            return false;
        }

        const auto user =
            LiveUser_GetUserDataForController(0);

        if (!user)
        {
            message = "controller 0 user-data pointer is null.";
            return false;
        }

        constexpr std::size_t kDumpSize = 0x180;
        std::vector<unsigned char> bytes(kDumpSize);

        if (!SafeRead(user, bytes.data(), bytes.size()))
        {
            message = "could not safely read the controller 0 user-data block.";
            return false;
        }

        {
            std::ofstream bin(
                "logs\\profile\\userdata_controller0.bin",
                std::ios::binary | std::ios::trunc);

            if (!bin)
            {
                message = "could not create profile binary dump.";
                return false;
            }

            bin.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        }

        std::ofstream txt(
            "logs\\profile\\userdata_controller0.txt",
            std::ios::trunc);

        if (!txt)
        {
            message = "binary dump succeeded but text dump could not be created.";
            return false;
        }

        txt << "controller=0\n";
        txt << "address=0x"
            << std::hex << std::uppercase
            << static_cast<unsigned long long>(user)
            << std::dec << "\n";
        txt << "size=0x" << std::hex << kDumpSize << std::dec << "\n\n";

        for (std::size_t i = 0; i < bytes.size(); i += 16)
        {
            txt << "+0x"
                << std::hex << std::setw(4) << std::setfill('0')
                << i << ": ";

            for (std::size_t j = 0;
                 j < 16 && i + j < bytes.size();
                 ++j)
            {
                txt << std::setw(2)
                    << static_cast<unsigned int>(bytes[i + j])
                    << ' ';
            }

            txt << "\n";
        }

        message =
            "profile dump written to logs\\profile\\userdata_controller0.*";
        return true;
    }


    bool AnalyzeProfile(std::string& message)
    {
        log_paths::EnsureAll();

        if (!g_Addrs.LiveUser_GetUserDataForController)
        {
            message = "LiveUser_GetUserDataForController is unresolved.";
            return false;
        }

        const auto user = LiveUser_GetUserDataForController(0);

        if (!user)
        {
            message = "controller 0 user-data pointer is null.";
            return false;
        }

        constexpr std::size_t kRootBytes = 0x400;
        std::vector<unsigned char> root(kRootBytes);

        if (!SafeRead(user, root.data(), root.size()))
        {
            message = "could not safely read the controller 0 user-data block.";
            return false;
        }

        std::ofstream file(
            "logs\\profile\\userdata_analysis.txt",
            std::ios::trunc);

        if (!file)
        {
            message = "could not create logs\\profile\\userdata_analysis.txt";
            return false;
        }

        file << "[T9 PROFILE OBJECT ANALYSIS]\n";
        file << "root=0x"
             << std::hex << std::uppercase
             << static_cast<unsigned long long>(user)
             << std::dec << "\n";
        file << "rootBytes=0x400\n\n";

        file << "[INLINE ASCII STRINGS]\n";

        unsigned int inlineStrings = 0;

        for (std::size_t off = 0; off < root.size(); ++off)
        {
            const auto* p = root.data() + off;
            const auto remain = root.size() - off;

            if (remain < 4 ||
                !LooksAscii(p, std::min<std::size_t>(remain, 64)))
                continue;

            std::size_t len = 0;

            while (len < remain &&
                   len < 96 &&
                   p[len] >= 0x20 &&
                   p[len] <= 0x7E)
                ++len;

            file << "+0x"
                 << std::hex << off
                 << std::dec
                 << " \""
                 << std::string(
                        reinterpret_cast<const char*>(p),
                        len)
                 << "\"\n";

            ++inlineStrings;
            off += len;
        }

        file << "\n[READABLE POINTERS / FIRST CHILD DATA]\n";

        unsigned int readablePointers = 0;

        for (std::size_t off = 0;
             off + 8 <= root.size();
             off += 8)
        {
            std::uint64_t ptr = 0;
            std::memcpy(&ptr, root.data() + off, sizeof(ptr));

            if (!IsReadable(static_cast<std::uintptr_t>(ptr), 0x20))
                continue;

            unsigned char child[0x40]{};

            if (!SafeRead(
                    static_cast<std::uintptr_t>(ptr),
                    child,
                    sizeof(child)))
                continue;

            file << "+0x"
                 << std::hex << off
                 << " -> 0x" << ptr
                 << std::dec;

            if (LooksAscii(child, sizeof(child)))
            {
                std::size_t len = 0;

                while (len < sizeof(child) &&
                       child[len] >= 0x20 &&
                       child[len] <= 0x7E)
                    ++len;

                file << " ascii=\""
                     << std::string(
                            reinterpret_cast<const char*>(child),
                            len)
                     << "\"";
            }

            file << " bytes=";

            for (unsigned int i = 0; i < 16; ++i)
            {
                file << std::hex
                     << std::setw(2)
                     << std::setfill('0')
                     << static_cast<unsigned int>(child[i])
                     << ' ';
            }

            file << std::dec << "\n";
            ++readablePointers;
        }

        file << "\n[SUMMARY]\n";
        file << "inlineStrings=" << inlineStrings << "\n";
        file << "readablePointers=" << readablePointers << "\n";
        file << "MW/Vanguard CoDUserData layout is NOT assumed for T9.\n";
        file << "Use /profile name <name> then rerun /profile analyze to diff which field/object changes.\n";

        message =
            "profile analysis written to logs\\profile\\userdata_analysis.txt";
        return true;
    }

    bool HostResearch(std::string& message)
    {
        std::string report;
        WriteLanResearchReport(report);
        message =
            "LAN mode is prepared, but native host/session creation remains game-owned and unresolved. "
            "No speculative XSESSION_INFO/session object was fabricated. Keep the game in a private/offline lobby or match while the peer tests /connect. " +
            report;
        return true;
    }

    bool SessionResearch(std::string& message)
    {
        std::string report;
        WriteLanResearchReport(report);
        message =
            "native XSESSION_INFO capture is not resolved yet; diagnostic report refreshed.";
        return false;
    }

    bool JoinResearch(
        const std::string& sessionData,
        std::string& message)
    {
        (void)sessionData;
        std::string report;
        WriteLanResearchReport(report);
        message =
            "Party_StartLANServerJoin equivalent and T9 XSESSION_INFO layout are unresolved; no join call was made.";
        return false;
    }
}
