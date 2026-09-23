#include "MW2019LuaDump.hpp"
#include "MW2019MemoryScanner.hpp"
#include "MW2019Shared.hpp"

#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{
    template <typename T, size_t N> constexpr size_t CountOf(const T (&)[N]) noexcept { return N; }

    volatile LONG g_busy = 0;
    volatile LONG g_passCounter = 0;
    unsigned long long g_lastAutoDump = 0;
    unsigned g_autoDumpsStarted = 0;
    unsigned long long g_lastVmWaitLog = 0;
    bool g_vmReadyLogged = false;

    struct SeenCandidate
    {
        const void* address;
        std::uint64_t fingerprint;
    };
    SeenCandidate g_seen[128]{};
    unsigned g_seenCount = 0;

    bool IsReadable(DWORD protect)
    {
        if (protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        const DWORD p = protect & 0xFF;
        return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    bool ContainsI(const char* s, const char* needle)
    {
        if (!s || !needle) return false;
        const size_t n = strlen(needle);
        for (; *s; ++s)
            if (_strnicmp(s, needle, n) == 0) return true;
        return false;
    }

    bool Interesting(const char* s)
    {
        return ContainsI(s, ".lua") || ContainsI(s, "lua/") || ContainsI(s, "lui/") || ContainsI(s, "LUI.") ||
               ContainsI(s, "require(") || ContainsI(s, "Engine.") || ContainsI(s, "frontend") || ContainsI(s, "menu/") ||
               ContainsI(s, "function ") || ContainsI(s, "local ") || ContainsI(s, "RegisterType") || ContainsI(s, "CoD.");
    }

    void WriteLine(HANDLE file, const char* text)
    {
        if (file == INVALID_HANDLE_VALUE || !text) return;
        DWORD w{};
        WriteFile(file, text, static_cast<DWORD>(strlen(text)), &w, nullptr);
    }

    std::uint64_t Fingerprint(const unsigned char* p, std::size_t n)
    {
        std::uint64_t h = 1469598103934665603ull;
        const std::size_t amount = n > 4096 ? 4096 : n;
        __try
        {
            for (std::size_t i = 0; i < amount; ++i)
            {
                h ^= p[i];
                h *= 1099511628211ull;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        return h;
    }

    bool AlreadySeen(const void* address, std::uint64_t fp)
    {
        for (unsigned i = 0; i < g_seenCount; ++i)
            if (g_seen[i].address == address || (fp && g_seen[i].fingerprint == fp)) return true;
        if (g_seenCount < CountOf(g_seen)) g_seen[g_seenCount++] = { address, fp };
        return false;
    }

    struct Cursor
    {
        const unsigned char* p{};
        const unsigned char* end{};
        bool little{true};

        bool ReadU8(std::uint8_t& v)
        {
            if (!p || p + 1 > end) return false;
            v = *p++;
            return true;
        }

        bool ReadInt(std::uint64_t& v, unsigned size)
        {
            if (!p || size == 0 || size > 8 || p + size > end) return false;
            v = 0;
            if (little)
                for (unsigned i = 0; i < size; ++i) v |= static_cast<std::uint64_t>(p[i]) << (i * 8);
            else
                for (unsigned i = 0; i < size; ++i) v = (v << 8) | p[i];
            p += size;
            return true;
        }

        bool Skip(std::size_t n)
        {
            if (!p || p + n > end) return false;
            p += n;
            return true;
        }
    };

    bool ReadLuaString(Cursor& c, unsigned sizeT, char* out, std::size_t outCount)
    {
        if (out && outCount) out[0] = 0;
        std::uint64_t len = 0;
        if (!c.ReadInt(len, sizeT)) return false;
        if (!len) return true;
        if (len > static_cast<std::uint64_t>(c.end - c.p)) return false;
        const std::size_t copyLen = static_cast<std::size_t>(len > 0 ? len - 1 : 0);
        if (out && outCount)
        {
            const std::size_t n = copyLen < outCount - 1 ? copyLen : outCount - 1;
            memcpy(out, c.p, n);
            out[n] = 0;
        }
        return c.Skip(static_cast<std::size_t>(len));
    }

    const char* Lua51OpcodeName(unsigned op)
    {
        static const char* names[] = {
            "MOVE","LOADK","LOADBOOL","LOADNIL","GETUPVAL","GETGLOBAL","GETTABLE","SETGLOBAL","SETUPVAL","SETTABLE",
            "NEWTABLE","SELF","ADD","SUB","MUL","DIV","MOD","POW","UNM","NOT","LEN","CONCAT","JMP","EQ","LT","LE",
            "TEST","TESTSET","CALL","TAILCALL","RETURN","FORLOOP","FORPREP","TFORLOOP","SETLIST","CLOSE","CLOSURE","VARARG"
        };
        return op < CountOf(names) ? names[op] : "OP?";
    }

    bool DecodeLua51Proto(Cursor& c, HANDLE report, unsigned intSize, unsigned sizeT, unsigned instructionSize, unsigned numberSize, unsigned depth)
    {
        if (depth > 12) return false;
        char source[512]{};
        if (!ReadLuaString(c, sizeT, source, CountOf(source))) return false;

        std::uint64_t lineDefined{}, lastLine{};
        if (!c.ReadInt(lineDefined, intSize) || !c.ReadInt(lastLine, intSize)) return false;
        std::uint8_t nups{}, numparams{}, vararg{}, maxstack{};
        if (!c.ReadU8(nups) || !c.ReadU8(numparams) || !c.ReadU8(vararg) || !c.ReadU8(maxstack)) return false;

        char line[1024]{};
        _snprintf_s(line, sizeof(line), _TRUNCATE,
            "PROTO depth=%u source=%s lines=%llu..%llu nups=%u params=%u vararg=%u maxstack=%u\r\n",
            depth, source[0] ? source : "(inherited)",
            static_cast<unsigned long long>(lineDefined), static_cast<unsigned long long>(lastLine),
            nups, numparams, vararg, maxstack);
        WriteLine(report, line);

        std::uint64_t codeCount{};
        if (!c.ReadInt(codeCount, intSize) || codeCount > 1000000ull) return false;
        _snprintf_s(line, sizeof(line), _TRUNCATE, "  CODE count=%llu\r\n", static_cast<unsigned long long>(codeCount));
        WriteLine(report, line);

        for (std::uint64_t i = 0; i < codeCount; ++i)
        {
            std::uint64_t raw{};
            if (!c.ReadInt(raw, instructionSize)) return false;
            if (instructionSize == 4 && i < 100000)
            {
                const std::uint32_t ins = static_cast<std::uint32_t>(raw);
                const unsigned op = ins & 0x3F;
                const unsigned A = (ins >> 6) & 0xFF;
                const unsigned C = (ins >> 14) & 0x1FF;
                const unsigned B = (ins >> 23) & 0x1FF;
                const unsigned Bx = (ins >> 14) & 0x3FFFF;
                const int sBx = static_cast<int>(Bx) - 131071;
                _snprintf_s(line, sizeof(line), _TRUNCATE,
                    "    %06llu  %-10s raw=%08X A=%u B=%u C=%u Bx=%u sBx=%d\r\n",
                    static_cast<unsigned long long>(i), Lua51OpcodeName(op), ins, A, B, C, Bx, sBx);
                WriteLine(report, line);
            }
        }

        std::uint64_t constantCount{};
        if (!c.ReadInt(constantCount, intSize) || constantCount > 1000000ull) return false;
        _snprintf_s(line, sizeof(line), _TRUNCATE, "  CONSTANTS count=%llu\r\n", static_cast<unsigned long long>(constantCount));
        WriteLine(report, line);
        for (std::uint64_t i = 0; i < constantCount; ++i)
        {
            std::uint8_t type{};
            if (!c.ReadU8(type)) return false;
            if (type == 0)
                _snprintf_s(line, sizeof(line), _TRUNCATE, "    K[%llu] nil\r\n", static_cast<unsigned long long>(i));
            else if (type == 1)
            {
                std::uint8_t b{}; if (!c.ReadU8(b)) return false;
                _snprintf_s(line, sizeof(line), _TRUNCATE, "    K[%llu] bool=%u\r\n", static_cast<unsigned long long>(i), b);
            }
            else if (type == 3)
            {
                if (c.p + numberSize > c.end) return false;
                if (numberSize == 8)
                {
                    std::uint64_t bits{}; if (!c.ReadInt(bits, 8)) return false;
                    double d{}; memcpy(&d, &bits, sizeof(d));
                    _snprintf_s(line, sizeof(line), _TRUNCATE, "    K[%llu] number=%g\r\n", static_cast<unsigned long long>(i), d);
                }
                else
                {
                    std::uint64_t bits{}; if (!c.ReadInt(bits, numberSize)) return false;
                    _snprintf_s(line, sizeof(line), _TRUNCATE, "    K[%llu] numberBits=0x%llX\r\n", static_cast<unsigned long long>(i), static_cast<unsigned long long>(bits));
                }
            }
            else if (type == 4)
            {
                char str[1024]{};
                if (!ReadLuaString(c, sizeT, str, CountOf(str))) return false;
                _snprintf_s(line, sizeof(line), _TRUNCATE, "    K[%llu] string=%s\r\n", static_cast<unsigned long long>(i), str);
            }
            else
            {
                _snprintf_s(line, sizeof(line), _TRUNCATE, "    K[%llu] unsupportedType=%u (decode stopped)\r\n", static_cast<unsigned long long>(i), type);
                WriteLine(report, line);
                return false;
            }
            WriteLine(report, line);
        }

        std::uint64_t protoCount{};
        if (!c.ReadInt(protoCount, intSize) || protoCount > 100000ull) return false;
        for (std::uint64_t i = 0; i < protoCount; ++i)
            if (!DecodeLua51Proto(c, report, intSize, sizeT, instructionSize, numberSize, depth + 1)) return false;

        // Debug sections: lineinfo, locals, upvalue names.
        std::uint64_t n{};
        if (!c.ReadInt(n, intSize) || n > 10000000ull || !c.Skip(static_cast<std::size_t>(n) * intSize)) return false;
        if (!c.ReadInt(n, intSize) || n > 1000000ull) return false;
        for (std::uint64_t i = 0; i < n; ++i)
        {
            if (!ReadLuaString(c, sizeT, nullptr, 0)) return false;
            std::uint64_t a{}, b{};
            if (!c.ReadInt(a, intSize) || !c.ReadInt(b, intSize)) return false;
        }
        if (!c.ReadInt(n, intSize) || n > 1000000ull) return false;
        for (std::uint64_t i = 0; i < n; ++i)
            if (!ReadLuaString(c, sizeT, nullptr, 0)) return false;
        return true;
    }

    std::uint64_t ReadULEB(const unsigned char*& p, const unsigned char* end, bool& ok)
    {
        std::uint64_t v = 0;
        unsigned shift = 0;
        ok = false;
        while (p < end && shift < 64)
        {
            const unsigned char b = *p++;
            v |= static_cast<std::uint64_t>(b & 0x7F) << shift;
            if (!(b & 0x80)) { ok = true; return v; }
            shift += 7;
        }
        return 0;
    }


    bool ComputeLuaJitChunkSize(const unsigned char* p, std::size_t remain, std::size_t& outSize)
    {
        outSize = 0;
        if (!p || remain < 5 || p[0] != 0x1B || p[1] != 'L' || p[2] != 'J' || p[3] != 2)
            return false;

        const unsigned char* cur = p + 4;
        const unsigned char* end = p + remain;
        bool ok = false;
        const std::uint64_t flags = ReadULEB(cur, end, ok);
        if (!ok || flags > 0x7F)
            return false;

        // LuaJIT BCDUMP_F_STRIP = 0x02. Non-stripped chunks carry a chunk-name length.
        if ((flags & 0x02) == 0)
        {
            const std::uint64_t nameLen = ReadULEB(cur, end, ok);
            if (!ok || nameLen > static_cast<std::uint64_t>(end - cur) || nameLen > (1ull << 20))
                return false;
            cur += static_cast<std::size_t>(nameLen);
        }

        unsigned protos = 0;
        while (cur < end && protos < 4096)
        {
            const std::uint64_t protoSize = ReadULEB(cur, end, ok);
            if (!ok)
                return false;

            if (protoSize == 0)
            {
                outSize = static_cast<std::size_t>(cur - p);
                return protos != 0 && outSize >= 6;
            }

            if (protoSize > static_cast<std::uint64_t>(end - cur) || protoSize > (64ull << 20))
                return false;

            cur += static_cast<std::size_t>(protoSize);
            ++protos;
        }
        return false;
    }

    void DumpPrintableStrings(HANDLE report, const unsigned char* p, std::size_t size, const char* prefix)
    {
        unsigned emitted = 0;
        for (std::size_t i = 0; i < size && emitted < 2048; )
        {
            if (p[i] >= 0x20 && p[i] <= 0x7E)
            {
                char text[1024]{};
                std::size_t j = i, n = 0;
                while (j < size && n + 1 < CountOf(text) && p[j] >= 0x20 && p[j] <= 0x7E)
                    text[n++] = static_cast<char>(p[j++]);
                text[n] = 0;
                if (n >= 4)
                {
                    char line[1300]{};
                    _snprintf_s(line, sizeof(line), _TRUNCATE, "%s +0x%zX %s\r\n", prefix ? prefix : "STR", i, text);
                    WriteLine(report, line);
                    ++emitted;
                }
                i = j;
            }
            else ++i;
        }
    }

    void DecodeLuaJit(const unsigned char* p, std::size_t size, HANDLE report)
    {
        if (size < 5) return;
        char line[1024]{};
        const unsigned version = p[3];
        const unsigned char* cur = p + 4;
        const unsigned char* end = p + size;
        bool ok = false;
        const std::uint64_t flags = ReadULEB(cur, end, ok);
        _snprintf_s(line, sizeof(line), _TRUNCATE, "LuaJIT bytecode version=%u flags=0x%llX\r\n", version, static_cast<unsigned long long>(flags));
        WriteLine(report, line);
        if (!ok) return;

        // LuaJIT BCDUMP_F_STRIP = 0x02. If names are present, decode chunk name.
        if ((flags & 0x02) == 0)
        {
            const std::uint64_t nameLen = ReadULEB(cur, end, ok);
            if (!ok || nameLen > static_cast<std::uint64_t>(end - cur)) return;
            char name[1024]{};
            const std::size_t n = static_cast<std::size_t>(nameLen < CountOf(name) - 1 ? nameLen : CountOf(name) - 1);
            memcpy(name, cur, n); name[n] = 0; cur += static_cast<std::size_t>(nameLen);
            _snprintf_s(line, sizeof(line), _TRUNCATE, "chunkName=%s\r\n", name);
            WriteLine(report, line);
        }

        unsigned protoIndex = 0;
        while (cur < end && protoIndex < 4096)
        {
            const std::uint64_t protoSize = ReadULEB(cur, end, ok);
            if (!ok || protoSize == 0) break;
            if (protoSize > static_cast<std::uint64_t>(end - cur))
            {
                _snprintf_s(line, sizeof(line), _TRUNCATE, "PROTO[%u] declaredSize=%llu exceeds captured data; stopping\r\n",
                    protoIndex, static_cast<unsigned long long>(protoSize));
                WriteLine(report, line);
                break;
            }
            const unsigned char* proto = cur;
            const unsigned char* protoEnd = cur + static_cast<std::size_t>(protoSize);
            _snprintf_s(line, sizeof(line), _TRUNCATE, "PROTO[%u] size=%llu\r\n", protoIndex, static_cast<unsigned long long>(protoSize));
            WriteLine(report, line);

            if (proto + 4 <= protoEnd)
            {
                const unsigned flagsP = proto[0], params = proto[1], frame = proto[2], uv = proto[3];
                const unsigned char* q = proto + 4;
                const std::uint64_t kgc = ReadULEB(q, protoEnd, ok); if (!ok) { cur = protoEnd; ++protoIndex; continue; }
                const std::uint64_t kn = ReadULEB(q, protoEnd, ok); if (!ok) { cur = protoEnd; ++protoIndex; continue; }
                const std::uint64_t bc = ReadULEB(q, protoEnd, ok); if (!ok) { cur = protoEnd; ++protoIndex; continue; }
                const std::uint64_t dbg = ReadULEB(q, protoEnd, ok); if (!ok) { cur = protoEnd; ++protoIndex; continue; }
                _snprintf_s(line, sizeof(line), _TRUNCATE,
                    "  flags=0x%02X params=%u frame=%u uv=%u kgc=%llu kn=%llu bc=%llu debug=%llu\r\n",
                    flagsP, params, frame, uv,
                    static_cast<unsigned long long>(kgc), static_cast<unsigned long long>(kn),
                    static_cast<unsigned long long>(bc), static_cast<unsigned long long>(dbg));
                WriteLine(report, line);

                // If debug info exists, LuaJIT stores firstline and numline before bytecode.
                if (dbg)
                {
                    (void)ReadULEB(q, protoEnd, ok); if (!ok) { cur = protoEnd; ++protoIndex; continue; }
                    (void)ReadULEB(q, protoEnd, ok); if (!ok) { cur = protoEnd; ++protoIndex; continue; }
                }

                const std::uint64_t bcBytes = bc * 4ull;
                if (bc <= 1000000ull && bcBytes <= static_cast<std::uint64_t>(protoEnd - q))
                {
                    for (std::uint64_t i = 0; i < bc && i < 100000; ++i)
                    {
                        const unsigned char* ins = q + static_cast<std::size_t>(i * 4);
                        const std::uint32_t raw = static_cast<std::uint32_t>(ins[0]) |
                            (static_cast<std::uint32_t>(ins[1]) << 8) |
                            (static_cast<std::uint32_t>(ins[2]) << 16) |
                            (static_cast<std::uint32_t>(ins[3]) << 24);
                        const unsigned op = raw & 0xFF;
                        const unsigned A = (raw >> 8) & 0xFF;
                        const unsigned C = (raw >> 16) & 0xFF;
                        const unsigned B = (raw >> 24) & 0xFF;
                        const unsigned D = (raw >> 16) & 0xFFFF;
                        _snprintf_s(line, sizeof(line), _TRUNCATE,
                            "    BC %06llu op=%03u raw=%08X A=%u B=%u C=%u D=%u\r\n",
                            static_cast<unsigned long long>(i), op, raw, A, B, C, D);
                        WriteLine(report, line);
                    }
                }
            }
            DumpPrintableStrings(report, proto, static_cast<std::size_t>(protoSize), "  STR");
            cur = protoEnd;
            ++protoIndex;
        }
    }

    void DecodeCandidate(const unsigned char* p, std::size_t size, const wchar_t* rawPath, unsigned index)
    {
        wchar_t rel[256]{}, reportPath[32768]{};
        _snwprintf_s(rel, CountOf(rel), _TRUNCATE, L"Lua\\decoded_%lu_%u_%p.txt", GetCurrentProcessId(), index, p);
        if (!mw2019_diag::BuildOutputPath(rel, reportPath, CountOf(reportPath))) return;
        HANDLE report = CreateFileW(reportPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (report == INVALID_HANDLE_VALUE) return;

        char head[1024]{};
        _snprintf_s(head, sizeof(head), _TRUNCATE,
            "CodRevamped MW2019 automatic Lua bytecode decoder\r\naddress=%p\r\ncapturedBytes=%zu\r\nrawFile=%ls\r\n\r\n",
            p, size, rawPath ? rawPath : L"");
        WriteLine(report, head);

        if (size >= 4 && p[0] == 0x1B && p[1] == 'L' && p[2] == 'u' && p[3] == 'a')
        {
            if (size < 12)
            {
                WriteLine(report, "Lua chunk header truncated.\r\n");
            }
            else
            {
                const unsigned version = p[4], format = p[5], endian = p[6];
                const unsigned intSize = p[7], sizeT = p[8], insSize = p[9], numSize = p[10], integral = p[11];
                _snprintf_s(head, sizeof(head), _TRUNCATE,
                    "format=standard Lua chunk\r\nversion=0x%02X\r\nformatByte=%u\r\nendianness=%s\r\nsizeof(int)=%u\r\nsizeof(size_t)=%u\r\nsizeof(instruction)=%u\r\nsizeof(number)=%u\r\nintegralNumber=%u\r\n\r\n",
                    version, format, endian ? "little" : "big", intSize, sizeT, insSize, numSize, integral);
                WriteLine(report, head);
                if (version == 0x51 && intSize >= 1 && intSize <= 8 && sizeT >= 1 && sizeT <= 8 && insSize >= 1 && insSize <= 8 && numSize >= 1 && numSize <= 8)
                {
                    Cursor c{ p + 12, p + size, endian != 0 };
                    const bool ok = DecodeLua51Proto(c, report, intSize, sizeT, insSize, numSize, 0);
                    WriteLine(report, ok ? "\r\n[DECODE] Lua 5.1 chunk parsed successfully.\r\n" : "\r\n[DECODE] Lua 5.1 parse stopped on incomplete/unsupported data.\r\n");
                }
                else
                {
                    WriteLine(report, "[DECODE] Header recognized; full disassembly currently implemented for Lua 5.1 only.\r\n");
                    DumpPrintableStrings(report, p, size, "STR");
                }
            }
        }
        else if (size >= 4 && p[0] == 0x1B && p[1] == 'L' && p[2] == 'J')
        {
            WriteLine(report, "format=LuaJIT bytecode\r\n");
            DecodeLuaJit(p, size, report);
        }
        else
        {
            WriteLine(report, "format=unknown/nonstandard Lua container; printable strings follow\r\n");
            DumpPrintableStrings(report, p, size, "STR");
        }
        CloseHandle(report);
        mw2019_diag::Log("[LUA-DECODE] candidate=%p raw=%ls report=%ls\r\n", p, rawPath ? rawPath : L"", reportPath);
    }

    void DumpBytecode(const unsigned char* p, std::size_t remain, unsigned index)
    {
        if (!p || remain < 5) return;

        const bool luaJitMagic = p[0] == 0x1B && p[1] == 'L' && p[2] == 'J';
        const bool lua51Magic = remain >= 12 && p[0] == 0x1B && p[1] == 'L' && p[2] == 'u' && p[3] == 'a' && p[4] == 0x51;

        std::size_t capture = 0;
        bool luaJit = false;

        if (luaJitMagic)
        {
            // IW8 uses LuaJIT bytecode version 2. Reject the random-memory false
            // positives Build343 produced and compute the real stream boundary by
            // walking the LuaJIT prototype-length records until the zero terminator.
            if (!ComputeLuaJitChunkSize(p, remain, capture))
                return;
            luaJit = true;
        }
        else if (lua51Magic)
        {
            // Standard Lua chunks do not have a top-level byte-length field. Keep a
            // bounded capture for now; the decoder itself validates the structure.
            capture = remain > (4ull << 20) ? (4ull << 20) : remain;
        }
        else
        {
            return;
        }

        if (!capture || capture > remain)
            return;

        const std::uint64_t fp = Fingerprint(p, capture);
        if (AlreadySeen(p, fp)) return;

        wchar_t rel[256]{}, path[32768]{};
        _snwprintf_s(rel, CountOf(rel), _TRUNCATE, luaJit ? L"Lua\\bytecode_%lu_%u_%p.luajit" : L"Lua\\bytecode_%lu_%u_%p.luac",
            GetCurrentProcessId(), index, p);
        if (!mw2019_diag::BuildOutputPath(rel, path, CountOf(path))) return;
        HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
        DWORD w{};
        __try { WriteFile(h, p, static_cast<DWORD>(capture), &w, nullptr); }
        __except(EXCEPTION_EXECUTE_HANDLER) { w = 0; }
        CloseHandle(h);

        if (w)
        {
            mw2019_diag::Log("[LUA-BYTECODE] validated=%s address=%p exactBytes=%lu path=%ls\r\n",
                luaJit ? "LuaJIT-v2" : "Lua-5.1", p, w, path);
            DecodeCandidate(p, w, path, index);
        }
    }

    struct DumpStats
    {
        unsigned strings{};
        unsigned bytecodes{};
        unsigned long long scanned{};
    };

    void ScanMemoryRange(std::uintptr_t start, std::uintptr_t end, HANDLE file, DumpStats& stats, unsigned maxStrings)
    {
        std::uintptr_t cur = start;
        while (cur < end && stats.strings < maxStrings)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi))) break;
            const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto regionEnd0 = base + static_cast<std::uintptr_t>(mbi.RegionSize);
            const auto regionStart = cur > base ? cur : base;
            const auto regionEnd = regionEnd0 < end ? regionEnd0 : end;
            const auto size = regionEnd > regionStart ? static_cast<std::size_t>(regionEnd - regionStart) : 0;

            if (size && mbi.State == MEM_COMMIT && IsReadable(mbi.Protect) && size <= (256ull << 20))
            {
                stats.scanned += size;
                __try
                {
                    const unsigned char* p = reinterpret_cast<const unsigned char*>(regionStart);
                    for (std::size_t i = 0; i < size && stats.strings < maxStrings; )
                    {
                        if (stats.bytecodes < 128 && i + 12 < size && p[i] == 0x1B && p[i + 1] == 'L')
                        {
                            const bool lua51 = p[i + 2] == 'u' && p[i + 3] == 'a' && p[i + 4] == 0x51;
                            const bool luaJit2 = p[i + 2] == 'J' && p[i + 3] == 2;
                            if (lua51 || luaJit2)
                            {
                                const unsigned before = stats.bytecodes;
                                DumpBytecode(p + i, size - i, before);
                                // Only advance the candidate number after a validated
                                // magic/version hit. Duplicate suppression is handled inside.
                                ++stats.bytecodes;
                            }
                        }

                        if (p[i] >= 0x20 && p[i] <= 0x7E)
                        {
                            char text[1025]{};
                            std::size_t j = i, n = 0;
                            while (j < size && n + 1 < CountOf(text) && p[j] >= 0x20 && p[j] <= 0x7E)
                                text[n++] = static_cast<char>(p[j++]);
                            text[n] = 0;
                            if (n >= 8 && Interesting(text))
                            {
                                char line[1400]{};
                                _snprintf_s(line, sizeof(line), _TRUNCATE, "[%p] %s\r\n", p + i, text);
                                WriteLine(file, line);
                                ++stats.strings;
                            }
                            i = j;
                        }
                        else ++i;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
            if (regionEnd <= cur) break;
            cur = regionEnd;
        }
    }

    DWORD WINAPI DumpWorker(LPVOID) noexcept
    {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        const LONG pass = InterlockedIncrement(&g_passCounter);
        wchar_t rel[256]{}, path[32768]{};
        _snwprintf_s(rel, CountOf(rel), _TRUNCATE, L"Lua\\lua_dump_%lu_pass%ld.txt", GetCurrentProcessId(), pass);
        if (!mw2019_diag::BuildOutputPath(rel, path, CountOf(path))) { InterlockedExchange(&g_busy, 0); return 0; }
        HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) { InterlockedExchange(&g_busy, 0); return 0; }

        const auto exeBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        std::size_t exeSize = 0;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(exeBase);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(exeBase + dos->e_lfanew);
            exeSize = nt->OptionalHeader.SizeOfImage;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) { exeSize = 0; }

        char head[1400]{};
        auto luaVmGlobal = mw2019_scanner::GetAddress("LUI_luaVM");
        void* luaVm = nullptr;
        if (luaVmGlobal)
        {
            __try { luaVm = *reinterpret_cast<void**>(luaVmGlobal); }
            __except(EXCEPTION_EXECUTE_HANDLER) { luaVm = nullptr; }
        }
        _snprintf_s(head, sizeof(head), _TRUNCATE,
            "CodRevamped MW2019 automatic Lua discovery/decode pass\r\npass=%ld\r\nluaL_openlib=%p\r\nLUI_luaVM_global=%p\r\nLUI_luaVM_value=%p\r\nLuaShared_PCall=%p\r\nDB_FindXAssetHeader=%p\r\nmainImage=%p size=0x%zX\r\n\r\n",
            pass,
            reinterpret_cast<void*>(mw2019_scanner::GetAddress("luaL_openlib")),
            reinterpret_cast<void*>(luaVmGlobal), luaVm,
            reinterpret_cast<void*>(mw2019_scanner::GetAddress("LuaShared_PCall")),
            reinterpret_cast<void*>(mw2019_scanner::GetAddress("DB_FindXAssetHeader")),
            reinterpret_cast<void*>(exeBase), exeSize);
        WriteLine(file, head);

        DumpStats stats{};

        // First scan the actual unpacked ModernWarfare.exe image. Build342 accidentally
        // consumed its global scan budget before reliably reaching this high address.
        if (exeBase && exeSize)
            ScanMemoryRange(exeBase, exeBase + exeSize, file, stats, 20000);

        // Then scan private allocations. These are where Lua VM heaps/asset buffers are
        // most likely to live. This runs on its own thread so diagnostics keep ticking.
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        std::uintptr_t cur = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const std::uintptr_t max = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
        unsigned long long privateBudget = 0;
        while (cur < max && privateBudget < (1536ull << 20) && stats.strings < 30000)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi))) break;
            const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto next = base + static_cast<std::uintptr_t>(mbi.RegionSize);
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && IsReadable(mbi.Protect) && mbi.RegionSize <= (128ull << 20))
            {
                privateBudget += mbi.RegionSize;
                ScanMemoryRange(base, next, file, stats, 30000);
            }
            if (next <= cur) break;
            cur = next;
        }

        CloseHandle(file);
        mw2019_diag::Log("[LUA] AUTO pass=%ld complete strings=%u bytecodeCandidates=%u scannedMB=%llu output=%ls\r\n",
            pass, stats.strings, stats.bytecodes, stats.scanned >> 20, path);
        InterlockedExchange(&g_busy, 0);
        return 0;
    }

    void StartAutoDump(const char* reason)
    {
        if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;
        mw2019_diag::Log("[LUA] starting automatic discovery/decode reason=%s\r\n", reason ? reason : "auto");
        HANDLE thread = CreateThread(nullptr, 0, DumpWorker, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        else
        {
            mw2019_diag::Log("[LUA] CreateThread failed error=%lu\r\n", GetLastError());
            InterlockedExchange(&g_busy, 0);
        }
    }
}

namespace mw2019_lua
{
    void Initialize() noexcept
    {
        mw2019_diag::Log("[LUA] automatic Lua/LUI discovery + bytecode decode ready; no hotkey required\r\n");
        mw2019_diag::Log("[LUA] recognized formats: standard Lua 5.1 and validated LuaJIT v2; raw + decoded reports are written automatically\r\n");
        mw2019_diag::Log("[LUA] Build344 waits for a non-null LUI_luaVM before starting dumps and trims LuaJIT files to their real stream boundary\r\n");
    }

    void DumpNow(const char* reason) noexcept
    {
        StartAutoDump(reason ? reason : "internal");
    }

    void Tick(unsigned long long uptimeMs) noexcept
    {
        // Build344: do not dump until the *actual* LUI VM pointer is live. Build343
        // had the correct global address but its value was still null during pass 1,
        // which caused broad process-memory scanning and false-positive bytecode hits.
        if (uptimeMs < 12000 || g_autoDumpsStarted >= 4) return;

        const auto openlib = mw2019_scanner::GetAddress("luaL_openlib");
        const auto luaVmGlobal = mw2019_scanner::GetAddress("LUI_luaVM");
        const auto pcall = mw2019_scanner::GetAddress("LuaShared_PCall");
        if (!openlib || !luaVmGlobal || !pcall)
            return;

        void* luaVm = nullptr;
        __try { luaVm = *reinterpret_cast<void**>(luaVmGlobal); }
        __except(EXCEPTION_EXECUTE_HANDLER) { luaVm = nullptr; }

        if (!luaVm)
        {
            if (!g_lastVmWaitLog || uptimeMs - g_lastVmWaitLog >= 10000)
            {
                g_lastVmWaitLog = uptimeMs;
                mw2019_diag::Log("[LUA] waiting for live LUI_luaVM global=%p value=NULL\r\n",
                    reinterpret_cast<void*>(luaVmGlobal));
            }
            return;
        }

        if (!g_vmReadyLogged)
        {
            g_vmReadyLogged = true;
            mw2019_diag::Log("[LUA] LUI VM READY global=%p vm=%p; validated LuaJIT-v2 auto dumps enabled\r\n",
                reinterpret_cast<void*>(luaVmGlobal), luaVm);
        }

        const unsigned long long interval = g_autoDumpsStarted == 0 ? 0 : 20000;
        if (g_autoDumpsStarted == 0 || uptimeMs - g_lastAutoDump >= interval)
        {
            if (InterlockedCompareExchange(&g_busy, 0, 0) != 0) return;
            g_lastAutoDump = uptimeMs;
            ++g_autoDumpsStarted;
            char reason[64]{};
            _snprintf_s(reason, sizeof(reason), _TRUNCATE, "vm-ready-pass-%u", g_autoDumpsStarted);
            StartAutoDump(reason);
        }
    }
}
