// CodRevamped built-in Black Ops Cold War (T9) GSC structural decompiler.
//
// This implementation is intentionally self-contained. It does not spawn,
// load, or require ACTS/gsc-tool/IDA/Ghidra or any other external decompiler.
// It parses VM37/VM38 ScriptParseTree objects directly, recovers export
// boundaries, imports/call sites, string/dev-string references, globals and
// includes, and writes readable source-like .gsc output. T9's VM uses many
// encoded opcode aliases; import metadata gives us exact call-site semantics,
// so the decoder learns those opcode aliases from the current dump instead of
// hardcoding build-specific opcode numbers.
namespace builtin_t9_decompiler
{
    constexpr uint64_t kMagicVm37 = 0x37000A0D43534780ull;
    constexpr uint64_t kMagicVm38 = 0x38000A0D43534780ull;
    constexpr size_t kHeaderSize = 0x58;
    constexpr size_t kMaxTableItems = 1000000;
    constexpr size_t kMaxStringProbe = 8;

#pragma pack(push, 1)
    struct Header38
    {
        uint64_t magic;
        uint32_t crc;
        uint32_t pad0c;
        uint64_t name;
        uint16_t stringCount;
        uint16_t exportCount;
        uint16_t importCount;
        uint16_t unk1e;
        uint16_t globalCount;
        uint16_t unk22;
        uint16_t includeCount;
        uint16_t devStringCount;
        uint32_t devStringOffset;
        uint32_t csegOffset;
        uint32_t stringOffset;
        uint32_t includeOffset;
        uint32_t exportOffset;
        uint32_t importOffset;
        uint32_t unk40;
        uint32_t globalOffset;
        uint32_t fileSize;
        uint32_t unk4c;
        uint32_t csegSize;
        uint32_t unk54;
    };

    struct Header37
    {
        uint64_t magic;
        uint32_t crc;
        uint32_t pad0c;
        uint64_t name;
        uint32_t includeOffset;
        uint16_t stringCount;
        uint16_t exportCount;
        uint32_t csegOffset;
        uint32_t stringOffset;
        uint16_t importCount;
        uint16_t fixupCount;
        uint32_t devStringOffset;
        uint32_t exportOffset;
        uint32_t importOffset;
        uint16_t globalCount;
        uint16_t unk3a;
        uint32_t fixupOffset;
        uint32_t globalOffset;
        uint32_t fileSize;
        uint16_t unk48;
        uint16_t devStringCount;
        uint32_t csegSize;
        uint16_t includeCount;
        uint16_t unk52;
        uint32_t unk54;
    };

    struct ExportDisk
    {
        uint32_t checksum;
        uint32_t address;
        uint32_t name;
        uint32_t nameSpace;
        uint32_t callbackEvent;
        uint8_t paramCount;
        uint8_t flags;
        uint16_t padding;
    };

    struct ImportDisk
    {
        uint32_t name;
        uint32_t nameSpace;
        uint16_t addressCount;
        uint8_t paramCount;
        uint8_t flags;
    };

    struct StringDisk
    {
        uint32_t stringId;
        uint8_t addressCount;
        uint8_t type;
        uint16_t padding;
    };

    struct GlobalDisk
    {
        uint32_t name;
        uint32_t addressCount;
    };
#pragma pack(pop)

    static_assert(sizeof(Header38) == kHeaderSize, "T9 VM38 header must be 0x58 bytes");
    static_assert(sizeof(Header37) == kHeaderSize, "T9 VM37 header must be 0x58 bytes");
    static_assert(sizeof(ExportDisk) == 24, "T9 export record must be 24 bytes");
    static_assert(sizeof(ImportDisk) == 12, "T9 import header must be 12 bytes");
    static_assert(sizeof(StringDisk) == 8, "T9 string header must be 8 bytes");
    static_assert(sizeof(GlobalDisk) == 8, "T9 global header must be 8 bytes");

    struct HeaderView
    {
        int vm = 0;
        uint32_t crc = 0;
        uint64_t name = 0;
        uint16_t stringCount = 0;
        uint16_t exportCount = 0;
        uint16_t importCount = 0;
        uint16_t globalCount = 0;
        uint16_t includeCount = 0;
        uint16_t devStringCount = 0;
        uint32_t devStringOffset = 0;
        uint32_t csegOffset = 0;
        uint32_t stringOffset = 0;
        uint32_t includeOffset = 0;
        uint32_t exportOffset = 0;
        uint32_t importOffset = 0;
        uint32_t globalOffset = 0;
        uint32_t fileSize = 0;
        uint32_t csegSize = 0;
    };

    struct ExportRow
    {
        uint32_t checksum = 0;
        uint32_t address = 0;
        uint32_t name = 0;
        uint32_t nameSpace = 0;
        uint32_t callbackEvent = 0;
        uint8_t paramCount = 0;
        uint8_t flags = 0;
    };

    struct ImportRow
    {
        uint32_t name = 0;
        uint32_t nameSpace = 0;
        uint8_t paramCount = 0;
        uint8_t flags = 0;
        std::vector<uint32_t> references;
    };

    struct StringRow
    {
        uint32_t stringId = 0;
        uint8_t type = 0;
        bool dev = false;
        std::vector<uint32_t> references;
        std::string candidateText;
    };

    struct GlobalRow
    {
        uint32_t name = 0;
        std::vector<uint32_t> references;
    };

    struct ParsedScript
    {
        HeaderView header;
        std::vector<uint64_t> includes;
        std::vector<ExportRow> exports;
        std::vector<ImportRow> imports;
        std::vector<StringRow> strings;
        std::vector<StringRow> devStrings;
        std::vector<GlobalRow> globals;
    };

    struct OpcodeVotes
    {
        // VM -> opcode -> call-type(low nibble) -> hits.
        std::map<int, std::map<uint16_t, std::map<unsigned int, uint64_t>>> calls;
        uint64_t observations = 0;
    };

    struct RunStats
    {
        uint64_t parsed = 0;
        uint64_t decompiled = 0;
        uint64_t failed = 0;
        uint64_t vm37 = 0;
        uint64_t vm38 = 0;
        uint64_t exports = 0;
        uint64_t imports = 0;
        uint64_t importReferences = 0;
        uint64_t strings = 0;
        uint64_t globals = 0;
        uint64_t learnedCallOpcodes = 0;
    };

    template <typename T>
    static bool ReadAt(const std::vector<unsigned char>& data, size_t offset, T& value)
    {
        if (offset > data.size() || sizeof(T) > data.size() - offset)
            return false;
        std::memcpy(&value, data.data() + offset, sizeof(T));
        return true;
    }

    static bool ReadU16(const std::vector<unsigned char>& data, size_t offset, uint16_t& value)
    {
        return ReadAt(data, offset, value);
    }

    static bool RangeValid(size_t offset, size_t bytes, size_t limit)
    {
        return offset <= limit && bytes <= limit - offset;
    }

    static std::string Hex32(uint32_t value)
    {
        char text[16]{};
        sprintf_s(text, "0x%08X", value);
        return text;
    }

    static std::string Hex64(uint64_t value)
    {
        char text[24]{};
        sprintf_s(text, "0x%016llX", static_cast<unsigned long long>(value));
        return text;
    }

    static std::string Hash32Label(const char* prefix, uint32_t value)
    {
        char text[48]{};
        sprintf_s(text, "%s_%08X", prefix, value);
        return text;
    }

    static std::string Hash64Label(const char* prefix, uint64_t value)
    {
        char text[64]{};
        sprintf_s(text, "%s_%016llX", prefix, static_cast<unsigned long long>(value));
        return text;
    }

    static std::string EscapeCommentText(const std::string& value)
    {
        std::string out;
        out.reserve(value.size() + 16);
        for (unsigned char ch : value)
        {
            if (ch == '\\') out += "\\\\";
            else if (ch == '"') out += "\\\"";
            else if (ch == '\r') out += "\\r";
            else if (ch == '\n') out += "\\n";
            else if (ch == '\t') out += "\\t";
            else if (ch >= 32 && ch < 127) out.push_back(static_cast<char>(ch));
            else
            {
                char escaped[8]{};
                sprintf_s(escaped, "\\x%02X", static_cast<unsigned int>(ch));
                out += escaped;
            }
        }
        return out;
    }

    static bool ParseHeader(const std::vector<unsigned char>& data, HeaderView& out)
    {
        if (data.size() < kHeaderSize)
            return false;

        uint64_t magic = 0;
        if (!ReadAt(data, 0, magic))
            return false;

        if (magic == kMagicVm38)
        {
            Header38 h{};
            if (!ReadAt(data, 0, h)) return false;
            out.vm = 38;
            out.crc = h.crc;
            out.name = h.name;
            out.stringCount = h.stringCount;
            out.exportCount = h.exportCount;
            out.importCount = h.importCount;
            out.globalCount = h.globalCount;
            out.includeCount = h.includeCount;
            out.devStringCount = h.devStringCount;
            out.devStringOffset = h.devStringOffset;
            out.csegOffset = h.csegOffset;
            out.stringOffset = h.stringOffset;
            out.includeOffset = h.includeOffset;
            out.exportOffset = h.exportOffset;
            out.importOffset = h.importOffset;
            out.globalOffset = h.globalOffset;
            out.fileSize = h.fileSize;
            out.csegSize = h.csegSize;
        }
        else if (magic == kMagicVm37)
        {
            Header37 h{};
            if (!ReadAt(data, 0, h)) return false;
            out.vm = 37;
            out.crc = h.crc;
            out.name = h.name;
            out.stringCount = h.stringCount;
            out.exportCount = h.exportCount;
            out.importCount = h.importCount;
            out.globalCount = h.globalCount;
            out.includeCount = h.includeCount;
            out.devStringCount = h.devStringCount;
            out.devStringOffset = h.devStringOffset;
            out.csegOffset = h.csegOffset;
            out.stringOffset = h.stringOffset;
            out.includeOffset = h.includeOffset;
            out.exportOffset = h.exportOffset;
            out.importOffset = h.importOffset;
            out.globalOffset = h.globalOffset;
            out.fileSize = h.fileSize;
            out.csegSize = h.csegSize;
        }
        else
        {
            return false;
        }

        if (out.fileSize < kHeaderSize || out.fileSize > data.size())
            return false;
        if (out.csegOffset > out.fileSize || out.csegSize > out.fileSize - out.csegOffset)
            return false;
        if (out.exportCount > kMaxTableItems || out.importCount > kMaxTableItems ||
            out.stringCount > kMaxTableItems || out.globalCount > kMaxTableItems ||
            out.includeCount > kMaxTableItems || out.devStringCount > kMaxTableItems)
            return false;
        return true;
    }

    static std::string FindPrintableCandidate(const std::vector<unsigned char>& data,
        const HeaderView& h, uint32_t stringId)
    {
        // T9 PC strings are commonly encrypted. Do not sweep forward until an
        // unrelated plaintext literal happens to appear: only accept a real,
        // NUL-terminated printable string beginning at the id or within the
        // first few metadata bytes. Everything else stays hash/id-only.
        const size_t limit = (std::min)(static_cast<size_t>(h.fileSize), data.size());
        if (stringId >= limit)
            return {};

        std::string best;
        int bestScore = 0;
        const size_t startEnd = (std::min)(limit, static_cast<size_t>(stringId) + kMaxStringProbe + 1);
        for (size_t start = stringId; start < startEnd; ++start)
        {
            std::string value;
            value.reserve(96);
            bool terminated = false;
            const size_t textEnd = (std::min)(limit, start + static_cast<size_t>(256));
            for (size_t cursor = start; cursor < textEnd; ++cursor)
            {
                const unsigned char ch = data[cursor];
                if (ch == 0)
                {
                    terminated = true;
                    break;
                }
                if (ch == '\t' || ch == '\r' || ch == '\n' || (ch >= 32 && ch < 127))
                    value.push_back(static_cast<char>(ch));
                else
                {
                    value.clear();
                    break;
                }
            }
            if (!terminated || value.size() < 8)
                continue;

            // Some records have a few printable metadata bytes before the
            // literal. Prefer a nearby identifier-like start instead of
            // preserving obvious prefix noise such as "a+" or a control tag.
            if (!(std::isalnum(static_cast<unsigned char>(value[0])) || value[0] == '_'))
            {
                const size_t prefixLimit = (std::min)(static_cast<size_t>(8), value.size());
                for (size_t trim = 1; trim < prefixLimit; ++trim)
                {
                    const unsigned char ch = static_cast<unsigned char>(value[trim]);
                    if ((std::isalnum(ch) || ch == '_') && value.size() - trim >= 8)
                    {
                        value.erase(0, trim);
                        break;
                    }
                }
            }

            int useful = 0;
            int alpha = 0;
            for (unsigned char ch : value)
            {
                if (std::isalnum(ch)) ++alpha;
                if (std::isalnum(ch) || ch == '_' || ch == '-' || ch == '/' || ch == '\\' ||
                    ch == '.' || ch == ':' || ch == ' ' || ch == '[' || ch == ']' ||
                    ch == '(' || ch == ')' || ch == '$' || ch == '@' || ch == '#')
                    ++useful;
            }
            if (!alpha || useful * 100 < static_cast<int>(value.size()) * 70)
                continue;
            const int score = static_cast<int>(value.size()) + useful + alpha;
            if (score > bestScore)
            {
                bestScore = score;
                best = value;
            }
        }
        return best;
    }

    static bool ParseScript(const std::vector<unsigned char>& data, ParsedScript& out)
    {
        out = ParsedScript{};
        if (!ParseHeader(data, out.header))
            return false;
        const HeaderView& h = out.header;
        const size_t limit = (std::min)(static_cast<size_t>(h.fileSize), data.size());

        if (!RangeValid(h.includeOffset, static_cast<size_t>(h.includeCount) * sizeof(uint64_t), limit))
            return false;
        out.includes.reserve(h.includeCount);
        for (size_t i = 0; i < h.includeCount; ++i)
        {
            uint64_t includeHash = 0;
            if (!ReadAt(data, h.includeOffset + i * sizeof(uint64_t), includeHash)) return false;
            out.includes.push_back(includeHash);
        }

        if (!RangeValid(h.exportOffset, static_cast<size_t>(h.exportCount) * sizeof(ExportDisk), limit))
            return false;
        out.exports.reserve(h.exportCount);
        for (size_t i = 0; i < h.exportCount; ++i)
        {
            ExportDisk disk{};
            if (!ReadAt(data, h.exportOffset + i * sizeof(ExportDisk), disk)) return false;
            ExportRow row{};
            row.checksum = disk.checksum;
            row.address = disk.address;
            row.name = disk.name;
            row.nameSpace = disk.nameSpace;
            row.callbackEvent = disk.callbackEvent;
            row.paramCount = disk.paramCount;
            row.flags = disk.flags;
            out.exports.push_back(row);
        }

        size_t cursor = h.importOffset;
        out.imports.reserve(h.importCount);
        for (size_t i = 0; i < h.importCount; ++i)
        {
            ImportDisk disk{};
            if (!ReadAt(data, cursor, disk)) return false;
            cursor += sizeof(disk);
            const size_t refsBytes = static_cast<size_t>(disk.addressCount) * sizeof(uint32_t);
            if (!RangeValid(cursor, refsBytes, limit)) return false;
            ImportRow row{};
            row.name = disk.name;
            row.nameSpace = disk.nameSpace;
            row.paramCount = disk.paramCount;
            row.flags = disk.flags;
            row.references.reserve(disk.addressCount);
            for (size_t r = 0; r < disk.addressCount; ++r)
            {
                uint32_t reference = 0;
                if (!ReadAt(data, cursor + r * sizeof(uint32_t), reference)) return false;
                row.references.push_back(reference);
            }
            cursor += refsBytes;
            out.imports.push_back(std::move(row));
        }

        auto parseStringTable = [&](size_t start, size_t count, bool dev, std::vector<StringRow>& rows) -> bool
        {
            size_t stringCursor = start;
            rows.reserve(count);
            for (size_t i = 0; i < count; ++i)
            {
                StringDisk disk{};
                if (!ReadAt(data, stringCursor, disk)) return false;
                stringCursor += sizeof(disk);
                const size_t refsBytes = static_cast<size_t>(disk.addressCount) * sizeof(uint32_t);
                if (!RangeValid(stringCursor, refsBytes, limit)) return false;
                StringRow row{};
                row.stringId = disk.stringId;
                row.type = disk.type;
                row.dev = dev;
                row.references.reserve(disk.addressCount);
                for (size_t r = 0; r < disk.addressCount; ++r)
                {
                    uint32_t reference = 0;
                    if (!ReadAt(data, stringCursor + r * sizeof(uint32_t), reference)) return false;
                    row.references.push_back(reference);
                }
                row.candidateText = FindPrintableCandidate(data, h, row.stringId);
                stringCursor += refsBytes;
                rows.push_back(std::move(row));
            }
            return true;
        };

        if (!parseStringTable(h.stringOffset, h.stringCount, false, out.strings))
            return false;
        if (h.devStringCount && !parseStringTable(h.devStringOffset, h.devStringCount, true, out.devStrings))
            return false;

        cursor = h.globalOffset;
        out.globals.reserve(h.globalCount);
        for (size_t i = 0; i < h.globalCount; ++i)
        {
            GlobalDisk disk{};
            if (!ReadAt(data, cursor, disk)) return false;
            cursor += sizeof(disk);
            const size_t refsBytes = static_cast<size_t>(disk.addressCount) * sizeof(uint32_t);
            if (!RangeValid(cursor, refsBytes, limit)) return false;
            GlobalRow row{};
            row.name = disk.name;
            row.references.reserve(disk.addressCount);
            for (size_t r = 0; r < disk.addressCount; ++r)
            {
                uint32_t reference = 0;
                if (!ReadAt(data, cursor + r * sizeof(uint32_t), reference)) return false;
                row.references.push_back(reference);
            }
            cursor += refsBytes;
            out.globals.push_back(std::move(row));
        }

        return true;
    }

    static unsigned int ImportCallType(const HeaderView& h, uint8_t flags)
    {
        (void)h;
        return static_cast<unsigned int>(flags & 0x0Fu);
    }

    static const char* ImportCallTypeName(int vm, unsigned int callType)
    {
        if (vm == 38)
        {
            switch (callType)
            {
            case 1: return "method_childthread";
            case 2: return "method_thread";
            case 3: return "function_childthread";
            case 4: return "function";
            case 5: return "func_method";
            case 6: return "function_thread";
            case 7: return "method";
            default: return "call_unknown";
            }
        }

        // VM37 uses the older T8/T9 call-flag ordering.
        switch (callType)
        {
        case 1: return "func_method";
        case 2: return "function";
        case 3: return "function_thread";
        case 4: return "function_childthread";
        case 5: return "method";
        case 6: return "method_thread";
        case 7: return "method_childthread";
        default: return "call_unknown";
        }
    }

    static std::string ImportFlagSuffix(int vm, uint8_t flags)
    {
        std::string out;
        if (vm == 38)
        {
            if (flags & 0x10u) out += " get_call";
            if (flags & 0x20u) out += " dev_call";
        }
        else
        {
            if (flags & 0x10u) out += " dev_call";
            if (flags & 0x20u) out += " get_call";
            if (flags & 0x40u) out += " local_call";
        }
        return out;
    }

    static std::string ExportFlagsText(int vm, uint8_t flags)
    {
        // VM38 uses 0x15 as the dedicated class-vtable export form rather
        // than a normal OR-combination of the lower flag bits.
        if (vm == 38 && flags == 0x15u)
            return "class_vtable";
        std::vector<std::string> names;
        auto add = [&](uint8_t bit, const char* name)
        {
            if (flags & bit) names.emplace_back(name);
        };
        if (vm == 38)
        {
            add(0x01, "autoexec");
            add(0x02, "linked");
        }
        else
        {
            add(0x01, "linked");
            add(0x02, "autoexec");
        }
        add(0x04, "private");
        add(0x08, "class_member");
        add(0x10, "destructor");
        add(0x20, "event");
        add(0x40, "ve");
        add(0x80, "class_linked");
        std::string out;
        for (const auto& name : names)
        {
            if (!out.empty()) out += '|';
            out += name;
        }
        return out.empty() ? "none" : out;
    }

    static bool ReadWholeFile(const std::wstring& path, std::vector<unsigned char>& data)
    {
        data.clear();
        FILE* file = nullptr;
        if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || !file)
            return false;
        _fseeki64(file, 0, SEEK_END);
        const int64_t length = static_cast<int64_t>(_ftelli64(file));
        _fseeki64(file, 0, SEEK_SET);
        if (length <= 0 || static_cast<uint64_t>(length) > 128ull * 1024ull * 1024ull)
        {
            fclose(file);
            return false;
        }
        data.resize(static_cast<size_t>(length));
        const size_t got = fread(data.data(), 1, data.size(), file);
        fclose(file);
        if (got != data.size())
        {
            data.clear();
            return false;
        }
        return true;
    }

    static bool EnumerateRawScripts(const std::wstring& rawDir, std::vector<std::wstring>& files)
    {
        files.clear();
        const std::wstring wildcard = rawDir + L"\\*.gscc";
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW(wildcard.c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
            return false;
        do
        {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                files.push_back(rawDir + L"\\" + data.cFileName);
        } while (FindNextFileW(find, &data));
        FindClose(find);
        std::sort(files.begin(), files.end());
        return !files.empty();
    }

    static void LearnCallOpcodes(const std::vector<unsigned char>& data,
        const ParsedScript& script, OpcodeVotes& votes)
    {
        for (const auto& importRow : script.imports)
        {
            const unsigned int callType = ImportCallType(script.header, importRow.flags);
            if (callType < 1 || callType > 7)
                continue;
            for (uint32_t reference : importRow.references)
            {
                uint16_t opcode = 0;
                if (!ReadU16(data, reference, opcode))
                    continue;
                ++votes.calls[script.header.vm][opcode][callType];
                ++votes.observations;
            }
        }
    }

    static std::string LearnedOpcodeName(const OpcodeVotes& votes, int vm, uint16_t opcode)
    {
        const auto vmIt = votes.calls.find(vm);
        if (vmIt == votes.calls.end()) return {};
        const auto opIt = vmIt->second.find(opcode);
        if (opIt == vmIt->second.end() || opIt->second.empty()) return {};
        uint64_t total = 0;
        uint64_t bestHits = 0;
        unsigned int bestType = 0;
        for (const auto& pair : opIt->second)
        {
            total += pair.second;
            if (pair.second > bestHits)
            {
                bestHits = pair.second;
                bestType = pair.first;
            }
        }
        if (!total || bestHits * 100 < total * 90)
            return {};
        return ImportCallTypeName(vm, bestType);
    }

    static uint64_t CountLearnedOpcodes(const OpcodeVotes& votes)
    {
        uint64_t count = 0;
        for (const auto& vm : votes.calls)
        {
            for (const auto& op : vm.second)
            {
                uint64_t total = 0;
                uint64_t best = 0;
                for (const auto& type : op.second)
                {
                    total += type.second;
                    best = (std::max)(best, type.second);
                }
                if (total && best * 100 >= total * 90) ++count;
            }
        }
        return count;
    }

    struct SemanticRef
    {
        uint32_t address = 0;
        int priority = 0;
        std::string text;
    };

    static std::string FunctionArguments(uint8_t count)
    {
        std::string args;
        for (unsigned int i = 0; i < count; ++i)
        {
            if (!args.empty()) args += ", ";
            args += "arg" + std::to_string(i);
        }
        return args;
    }

    static std::string HexPreview(const std::vector<unsigned char>& data, size_t start, size_t end)
    {
        if (start >= end || start >= data.size()) return {};
        end = (std::min)(end, data.size());
        const size_t bytes = (std::min)(static_cast<size_t>(32), end - start);
        std::ostringstream out;
        out << std::uppercase << std::hex << std::setfill('0');
        for (size_t i = 0; i < bytes; ++i)
        {
            if (i) out << ' ';
            out << std::setw(2) << static_cast<unsigned int>(data[start + i]);
        }
        if (end - start > bytes) out << " ...";
        return out.str();
    }

    static bool WriteSource(const std::vector<unsigned char>& data, const ParsedScript& script,
        const OpcodeVotes& votes, const std::wstring& outputPath)
    {
        FILE* out = nullptr;
        if (_wfopen_s(&out, outputPath.c_str(), L"wb") != 0 || !out)
            return false;

        const HeaderView& h = script.header;
        fprintf(out, "/*\r\n");
        fprintf(out, " * CodRevamped built-in T9 GSC structural decompiler\r\n");
        fprintf(out, " * VM%d script=%s crc=%s file_size=0x%X\r\n",
            h.vm, Hex64(h.name).c_str(), Hex32(h.crc).c_str(), h.fileSize);
        fprintf(out, " * Self-contained: no external executable or decompiler backend is used.\r\n");
        fprintf(out, " * Hash labels are retained where the original symbol name is not present.\r\n");
        fprintf(out, " * Call sites are exact (from T9 import metadata). String text marked\r\n");
        fprintf(out, " * 'candidate' is a conservative printable-data recovery near the string id.\r\n");
        fprintf(out, " */\r\n\r\n");

        if (!script.includes.empty())
        {
            fprintf(out, "// Includes\r\n");
            for (uint64_t includeHash : script.includes)
                fprintf(out, "// #using %s;\r\n", Hash64Label("script", includeHash).c_str());
            fprintf(out, "\r\n");
        }

        std::vector<ExportRow> exports = script.exports;
        std::sort(exports.begin(), exports.end(), [](const ExportRow& a, const ExportRow& b)
        {
            if (a.address != b.address) return a.address < b.address;
            if (a.nameSpace != b.nameSpace) return a.nameSpace < b.nameSpace;
            return a.name < b.name;
        });

        const size_t csegEnd = (std::min)(static_cast<size_t>(h.fileSize),
            static_cast<size_t>(h.csegOffset) + static_cast<size_t>(h.csegSize));

        for (size_t index = 0; index < exports.size(); ++index)
        {
            const ExportRow& fn = exports[index];
            size_t start = fn.address;
            size_t end = csegEnd;
            for (size_t next = index + 1; next < exports.size(); ++next)
            {
                if (exports[next].address > fn.address)
                {
                    end = (std::min)(end, static_cast<size_t>(exports[next].address));
                    break;
                }
            }
            if (start < h.csegOffset) start = h.csegOffset;
            if (end < start) end = start;

            const std::string nsName = Hash32Label("ns", fn.nameSpace);
            const std::string fnName = Hash32Label("fn", fn.name);
            fprintf(out, "// export[%zu] addr=0x%08X end=0x%08zX bytes=%zu checksum=%s flags=%s callback=%s\r\n",
                index, fn.address, end, end > start ? end - start : 0,
                Hex32(fn.checksum).c_str(), ExportFlagsText(h.vm, fn.flags).c_str(),
                Hex32(fn.callbackEvent).c_str());
            fprintf(out, "function %s::%s(%s)\r\n{\r\n",
                nsName.c_str(), fnName.c_str(), FunctionArguments(fn.paramCount).c_str());

            std::vector<SemanticRef> refs;
            for (const auto& importRow : script.imports)
            {
                const unsigned int callType = ImportCallType(h, importRow.flags);
                const char* callName = ImportCallTypeName(h.vm, callType);
                const std::string suffix = ImportFlagSuffix(h.vm, importRow.flags);
                for (uint32_t reference : importRow.references)
                {
                    if (reference < start || reference >= end) continue;
                    uint16_t opcode = 0;
                    ReadU16(data, reference, opcode);
                    std::string learned = LearnedOpcodeName(votes, h.vm, opcode);
                    std::ostringstream line;
                    line << "call " << callName << ' '
                        << Hash32Label("ns", importRow.nameSpace) << "::"
                        << Hash32Label("fn", importRow.name)
                        << " params=" << static_cast<unsigned int>(importRow.paramCount)
                        << " flags=0x" << std::uppercase << std::hex
                        << static_cast<unsigned int>(importRow.flags)
                        << " opcode=0x" << std::setw(4) << std::setfill('0') << opcode;
                    if (!learned.empty()) line << " learned=" << learned;
                    if (!suffix.empty()) line << suffix;
                    refs.push_back({ reference, 0, line.str() });
                }
            }

            auto addStrings = [&](const std::vector<StringRow>& rows)
            {
                for (const auto& stringRow : rows)
                {
                    for (uint32_t reference : stringRow.references)
                    {
                        if (reference < start || reference >= end) continue;
                        std::ostringstream line;
                        line << (stringRow.dev ? "dev_string" : "string")
                            << " id=" << Hex32(stringRow.stringId)
                            << " type=" << static_cast<unsigned int>(stringRow.type);
                        if (!stringRow.candidateText.empty())
                            line << " candidate=\"" << EscapeCommentText(stringRow.candidateText) << "\"";
                        refs.push_back({ reference, 1, line.str() });
                    }
                }
            };
            addStrings(script.strings);
            addStrings(script.devStrings);

            for (const auto& globalRow : script.globals)
            {
                for (uint32_t reference : globalRow.references)
                {
                    if (reference < start || reference >= end) continue;
                    refs.push_back({ reference, 2, "global " + Hash32Label("global", globalRow.name) });
                }
            }

            std::sort(refs.begin(), refs.end(), [](const SemanticRef& a, const SemanticRef& b)
            {
                if (a.address != b.address) return a.address < b.address;
                if (a.priority != b.priority) return a.priority < b.priority;
                return a.text < b.text;
            });
            refs.erase(std::unique(refs.begin(), refs.end(), [](const SemanticRef& a, const SemanticRef& b)
            {
                return a.address == b.address && a.text == b.text;
            }), refs.end());

            if (refs.empty())
            {
                fprintf(out, "    // No import/string/global metadata references in this function.\r\n");
            }
            else
            {
                for (const auto& ref : refs)
                    fprintf(out, "    // @0x%08X %s\r\n", ref.address, ref.text.c_str());
            }
            const std::string preview = HexPreview(data, start, end);
            if (!preview.empty())
                fprintf(out, "    // bytecode_preview: %s\r\n", preview.c_str());
            fprintf(out, "}\r\n\r\n");
        }

        if (exports.empty())
        {
            fprintf(out, "// No exports were present in this ScriptParseTree object.\r\n");
        }

        fprintf(out, "// ---- Script metadata ----\r\n");
        fprintf(out, "// exports=%zu imports=%zu strings=%zu dev_strings=%zu globals=%zu includes=%zu\r\n",
            script.exports.size(), script.imports.size(), script.strings.size(), script.devStrings.size(),
            script.globals.size(), script.includes.size());
        fclose(out);
        return true;
    }

    static bool DecompileRun(const std::wstring& rawDir, const std::wstring& outputDir,
        const std::wstring& runRoot, RunStats& stats)
    {
        stats = RunStats{};
        std::vector<std::wstring> files;
        if (!EnumerateRawScripts(rawDir, files))
            return false;

        EnsureDirectory(outputDir);
        OpcodeVotes votes;

        // First pass: validate every object and learn the current build's
        // encoded call-opcode aliases from import metadata. This is what keeps
        // the decoder portable across T9 opcode-map changes.
        for (const auto& path : files)
        {
            std::vector<unsigned char> data;
            ParsedScript script;
            if (!ReadWholeFile(path, data) || !ParseScript(data, script))
            {
                ++stats.failed;
                continue;
            }
            ++stats.parsed;
            if (script.header.vm == 37) ++stats.vm37;
            else if (script.header.vm == 38) ++stats.vm38;
            LearnCallOpcodes(data, script, votes);
        }
        stats.learnedCallOpcodes = CountLearnedOpcodes(votes);

        const std::wstring manifestPath = runRoot + L"\\decompile_manifest.tsv";
        FILE* manifest = nullptr;
        _wfopen_s(&manifest, manifestPath.c_str(), L"wb");
        if (manifest)
            fprintf(manifest, "input\tvm\tscript_hash\texports\timports\timport_refs\tstrings\tglobals\tresult\toutput\r\n");

        FILE* exportIndex = nullptr;
        FILE* callIndex = nullptr;
        FILE* stringIndex = nullptr;
        _wfopen_s(&exportIndex, (runRoot + L"\\decompiled_exports.tsv").c_str(), L"wb");
        _wfopen_s(&callIndex, (runRoot + L"\\decompiled_calls.tsv").c_str(), L"wb");
        _wfopen_s(&stringIndex, (runRoot + L"\\decompiled_strings.tsv").c_str(), L"wb");
        if (exportIndex)
            fprintf(exportIndex, "script_hash\tvm\taddress\tnamespace\tfunction\tparams\tflags\tchecksum\tcallback_event\r\n");
        if (callIndex)
            fprintf(callIndex, "script_hash\tvm\taddress\tnamespace\tfunction\tcall_type\tparams\tflags\topcode\tlearned\r\n");
        if (stringIndex)
            fprintf(stringIndex, "script_hash\tvm\tkind\tstring_id\ttype\taddress\tcandidate_text\r\n");

        for (const auto& path : files)
        {
            std::vector<unsigned char> data;
            ParsedScript script;
            bool parsed = ReadWholeFile(path, data) && ParseScript(data, script);
            if (!parsed)
            {
                if (manifest)
                    fprintf(manifest, "%ls\t0\t0\t0\t0\t0\t0\t0\tparse_failed\t\r\n", path.c_str());
                continue;
            }

            uint64_t importRefs = 0;
            for (const auto& row : script.imports) importRefs += row.references.size();
            stats.exports += script.exports.size();
            stats.imports += script.imports.size();
            stats.importReferences += importRefs;
            stats.strings += script.strings.size() + script.devStrings.size();
            stats.globals += script.globals.size();

            if (exportIndex)
            {
                for (const auto& row : script.exports)
                {
                    fprintf(exportIndex, "0x%016llX\t%d\t0x%08X\t0x%08X\t0x%08X\t%u\t%s\t0x%08X\t0x%08X\r\n",
                        static_cast<unsigned long long>(script.header.name), script.header.vm, row.address,
                        row.nameSpace, row.name, static_cast<unsigned int>(row.paramCount),
                        ExportFlagsText(script.header.vm, row.flags).c_str(), row.checksum, row.callbackEvent);
                }
            }
            if (callIndex)
            {
                for (const auto& row : script.imports)
                {
                    const unsigned int type = ImportCallType(script.header, row.flags);
                    for (uint32_t reference : row.references)
                    {
                        uint16_t opcode = 0;
                        ReadU16(data, reference, opcode);
                        const std::string learned = LearnedOpcodeName(votes, script.header.vm, opcode);
                        fprintf(callIndex, "0x%016llX\t%d\t0x%08X\t0x%08X\t0x%08X\t%s\t%u\t0x%02X\t0x%04X\t%s\r\n",
                            static_cast<unsigned long long>(script.header.name), script.header.vm, reference,
                            row.nameSpace, row.name, ImportCallTypeName(script.header.vm, type),
                            static_cast<unsigned int>(row.paramCount), static_cast<unsigned int>(row.flags),
                            opcode, learned.c_str());
                    }
                }
            }
            auto writeStringIndex = [&](const std::vector<StringRow>& rows, const char* kind)
            {
                if (!stringIndex) return;
                for (const auto& row : rows)
                {
                    const std::string text = EscapeCommentText(row.candidateText);
                    if (row.references.empty())
                    {
                        fprintf(stringIndex, "0x%016llX\t%d\t%s\t0x%08X\t%u\t\t%s\r\n",
                            static_cast<unsigned long long>(script.header.name), script.header.vm, kind,
                            row.stringId, static_cast<unsigned int>(row.type), text.c_str());
                    }
                    else
                    {
                        for (uint32_t reference : row.references)
                            fprintf(stringIndex, "0x%016llX\t%d\t%s\t0x%08X\t%u\t0x%08X\t%s\r\n",
                                static_cast<unsigned long long>(script.header.name), script.header.vm, kind,
                                row.stringId, static_cast<unsigned int>(row.type), reference, text.c_str());
                    }
                }
            };
            writeStringIndex(script.strings, "string");
            writeStringIndex(script.devStrings, "dev_string");

            wchar_t baseName[96]{};
            swprintf_s(baseName, L"script_%016llX.gsc",
                static_cast<unsigned long long>(script.header.name));
            const std::wstring outputPath = outputDir + L"\\" + baseName;
            const bool ok = WriteSource(data, script, votes, outputPath);
            if (ok) ++stats.decompiled;
            else ++stats.failed;

            if (manifest)
            {
                fprintf(manifest, "%ls\t%d\t0x%016llX\t%zu\t%zu\t%llu\t%zu\t%zu\t%s\t%ls\r\n",
                    path.c_str(), script.header.vm,
                    static_cast<unsigned long long>(script.header.name),
                    script.exports.size(), script.imports.size(),
                    static_cast<unsigned long long>(importRefs),
                    script.strings.size() + script.devStrings.size(), script.globals.size(),
                    ok ? "ok" : "write_failed", ok ? outputPath.c_str() : L"");
            }
        }
        if (manifest) fclose(manifest);
        if (exportIndex) fclose(exportIndex);
        if (callIndex) fclose(callIndex);
        if (stringIndex) fclose(stringIndex);

        const std::wstring opcodePath = runRoot + L"\\learned_call_opcodes.tsv";
        FILE* opcodeFile = nullptr;
        _wfopen_s(&opcodeFile, opcodePath.c_str(), L"wb");
        if (opcodeFile)
        {
            fprintf(opcodeFile, "vm\topcode\tcall_type\thits\ttotal\tconfidence\r\n");
            for (const auto& vmPair : votes.calls)
            {
                for (const auto& opPair : vmPair.second)
                {
                    uint64_t total = 0;
                    uint64_t bestHits = 0;
                    unsigned int bestType = 0;
                    for (const auto& typePair : opPair.second)
                    {
                        total += typePair.second;
                        if (typePair.second > bestHits)
                        {
                            bestHits = typePair.second;
                            bestType = typePair.first;
                        }
                    }
                    const double confidence = total ? static_cast<double>(bestHits) / static_cast<double>(total) : 0.0;
                    fprintf(opcodeFile, "%d\t0x%04X\t%s\t%llu\t%llu\t%.4f\r\n",
                        vmPair.first, opPair.first, ImportCallTypeName(vmPair.first, bestType),
                        static_cast<unsigned long long>(bestHits),
                        static_cast<unsigned long long>(total), confidence);
                }
            }
            fclose(opcodeFile);
        }

        return stats.decompiled != 0;
    }
}
