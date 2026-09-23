#include "pattern_scan.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstdlib>
#include <vector>

namespace
{
    bool IsReadableProtection(DWORD protect)
    {
        if (protect & PAGE_GUARD || protect & PAGE_NOACCESS)
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

    std::vector<int> ParsePattern(const char* pattern)
    {
        std::vector<int> bytes;
        if (!pattern)
            return bytes;

        const char* cursor = pattern;
        while (*cursor)
        {
            while (*cursor == ' ')
                ++cursor;
            if (!*cursor)
                break;

            if (*cursor == '?')
            {
                ++cursor;
                if (*cursor == '?')
                    ++cursor;
                bytes.push_back(-1);
            }
            else
            {
                char* next = nullptr;
                const unsigned long value = std::strtoul(cursor, &next, 16);
                if (next == cursor || value > 0xFFu)
                    return {};
                bytes.push_back(static_cast<int>(value));
                cursor = next;
            }

            while (*cursor == ' ')
                ++cursor;
        }

        return bytes;
    }
}

namespace utils::pattern_scan
{
    std::uintptr_t find_first(HMODULE module, const char* pattern)
    {
        return find_first(module, 0, pattern);
    }

    std::uintptr_t find_first(HMODULE module, std::uintptr_t requestedStart, const char* pattern)
    {
        if (!module)
            module = GetModuleHandleW(nullptr);
        if (!module)
            return 0;

        const auto moduleBase = reinterpret_cast<std::uintptr_t>(module);

        IMAGE_DOS_HEADER dos{};
        SIZE_T read = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(moduleBase), &dos, sizeof(dos), &read) ||
            read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
        {
            return 0;
        }

        IMAGE_NT_HEADERS64 nt{};
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(moduleBase + dos.e_lfanew), &nt, sizeof(nt), &read) ||
            read != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE ||
            nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || !nt.OptionalHeader.SizeOfImage)
        {
            return 0;
        }

        const auto signature = ParsePattern(pattern);
        if (signature.empty())
            return 0;

        const auto moduleEnd = moduleBase + nt.OptionalHeader.SizeOfImage;
        std::uintptr_t cursor = requestedStart ? (std::max)(requestedStart, moduleBase) : moduleBase;
        if (cursor >= moduleEnd)
            return 0;

        while (cursor < moduleEnd)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) || !mbi.RegionSize)
                break;

            const auto rawRegionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            const auto regionBase = (std::max)(cursor, reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
            const auto regionEnd = (std::min)(rawRegionEnd, moduleEnd);

            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect) &&
                regionEnd > regionBase && static_cast<std::size_t>(regionEnd - regionBase) >= signature.size())
            {
                std::vector<unsigned char> buffer(static_cast<std::size_t>(regionEnd - regionBase));
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void*>(regionBase),
                        buffer.data(),
                        buffer.size(),
                        &bytesRead) &&
                    bytesRead >= signature.size())
                {
                    const std::size_t limit = bytesRead - signature.size();
                    for (std::size_t i = 0; i <= limit; ++i)
                    {
                        bool match = true;
                        for (std::size_t j = 0; j < signature.size(); ++j)
                        {
                            if (signature[j] >= 0 && buffer[i + j] != static_cast<unsigned char>(signature[j]))
                            {
                                match = false;
                                break;
                            }
                        }

                        if (match)
                            return regionBase + i;
                    }
                }
            }

            if (rawRegionEnd <= cursor)
                break;
            cursor = rawRegionEnd;
        }

        return 0;
    }
}
