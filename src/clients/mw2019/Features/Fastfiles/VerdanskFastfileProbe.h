#pragma once
// MW2019 Replay 1.20: diagnose a Verdansk collision fastfile that exists on
// disk but fails DB_FileSys open during level load. This is NOT a fastfile
// format bypass and does not pretend another file is the requested asset.
// It does not touch the game's collision mode or game-state memory.
// Included by MW2019RedirectProxy.cpp *inside its existing anonymous namespace*.
// The parent translation unit provides Windows.h and ConsolePrint.

namespace replay120_fastfiles
{
    struct FileProbe
    {
        bool exists = false;
        bool readable = false;
        bool regular = false;
        DWORD attributesError = 0;
        DWORD openError = 0;
        unsigned long long fileSize = 0;
        unsigned char header[8] = {};
        DWORD headerBytes = 0;
    };

    inline bool JoinPath(const wchar_t* base, const wchar_t* suffix,
                         wchar_t (&result)[MAX_PATH]) noexcept
    {
        if (!base || !suffix)
            return false;
        const size_t baseLen = std::wcslen(base);
        const size_t suffixLen = std::wcslen(suffix);
        if (!baseLen || baseLen + suffixLen + 1 >= MAX_PATH)
            return false;
        std::wmemcpy(result, base, baseLen);
        std::wmemcpy(result + baseLen, suffix, suffixLen + 1);
        return true;
    }

    inline FileProbe Inspect(const wchar_t* path) noexcept
    {
        FileProbe result{};
        if (!path || !*path)
            return result;
        const DWORD attrs = GetFileAttributesW(path);
        if (attrs == INVALID_FILE_ATTRIBUTES)
            result.attributesError = GetLastError();
        else
        {
            result.exists = true;
            result.regular = (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
        }
        const HANDLE handle = CreateFileW(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            result.openError = GetLastError();
            return result;
        }
        result.readable = true;
        LARGE_INTEGER size{};
        if (GetFileSizeEx(handle, &size))
            result.fileSize = static_cast<unsigned long long>(size.QuadPart);
        DWORD bytesRead = 0;
        if (ReadFile(handle, result.header, sizeof(result.header), &bytesRead, nullptr))
            result.headerBytes = bytesRead;
        CloseHandle(handle);
        return result;
    }

    inline void Report(const char* location, const FileProbe& result) noexcept
    {
        char magic[9] = {};
        for (DWORD i = 0; i < result.headerBytes && i < 8; ++i)
        {
            const unsigned char c = result.header[i];
            magic[i] = c >= 32 && c < 127 ? static_cast<char>(c) : '.';
        }
        ConsolePrint(
            "[FF120] location=%s exists=%u regular=%u canOpen=%u "
            "attributesError=%lu openError=%lu size=%llu header=%s\r\n",
            location, result.exists ? 1u : 0u, result.regular ? 1u : 0u,
            result.readable ? 1u : 0u,
            static_cast<unsigned long>(result.attributesError),
            static_cast<unsigned long>(result.openError), result.fileSize,
            magic);
    }

    // The 1.20 replay install can ship Verdansk collision in numbered tiles.
    // Validate a real five-digit tile name rather than treating any wildcard
    // result as proof that the collision-tile layout exists.
    inline bool HasNumberedTile(const wchar_t* pattern) noexcept
    {
        if (!pattern || !*pattern)
            return false;
        WIN32_FIND_DATAW entry{};
        const HANDLE find = FindFirstFileW(pattern, &entry);
        if (find == INVALID_HANDLE_VALUE)
            return false;
        bool found = false;
        unsigned scanned = 0;
        do
        {
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
                std::wcslen(entry.cFileName) == 25 &&
                std::wcsncmp(entry.cFileName, L"mp_donetsk_cg_", 14) == 0 &&
                std::wcscmp(entry.cFileName + 19, L"_tr.ff") == 0)
            {
                bool digits = true;
                for (unsigned i = 14; i != 19; ++i)
                    digits = digits && entry.cFileName[i] >= L'0' &&
                              entry.cFileName[i] <= L'9';
                if (digits)
                {
                    found = true;
                    break;
                }
            }
        } while (++scanned < 2048 && FindNextFileW(find, &entry));
        FindClose(find);
        return found;
    }

    inline void ProbeVerdanskCollisionFiles() noexcept
    {
        // File names and the numbered-tile alternative are taken from the
        // same-build DW_MapAvailability.cpp.  Stock 1.20 expects the combined
        // file in collision mode 2, even on installations that only have tiles.
        constexpr wchar_t kCombined[] = L"\\zone\\mp_donetsk_cg_ls_tr.ff";
        constexpr wchar_t kFirstTile[] = L"\\zone\\mp_donetsk_cg_00000_tr.ff";

        wchar_t gameExe[MAX_PATH] = {};
        wchar_t currentDir[MAX_PATH] = {};
        const DWORD exeChars = GetModuleFileNameW(nullptr, gameExe, MAX_PATH);
        const DWORD cwdChars = GetCurrentDirectoryW(MAX_PATH, currentDir);
        if (!exeChars || exeChars >= MAX_PATH || !cwdChars || cwdChars >= MAX_PATH)
        {
            ConsolePrint("[FF120] could not obtain executable and working directories; error=%lu\r\n",
                static_cast<unsigned long>(GetLastError()));
            return;
        }
        wchar_t* const slash = std::wcsrchr(gameExe, L'\\');
        if (!slash)
            return;
        *slash = 0;

        wchar_t exeCombined[MAX_PATH] = {};
        wchar_t cwdCombined[MAX_PATH] = {};
        wchar_t exeTile[MAX_PATH] = {};
        wchar_t exeTilesPattern[MAX_PATH] = {};
        wchar_t cwdTilesPattern[MAX_PATH] = {};
        constexpr wchar_t kPattern[] = L"\\zone\\mp_donetsk_cg_?????_tr.ff";
        if (!JoinPath(gameExe, kCombined, exeCombined) ||
            !JoinPath(currentDir, kCombined, cwdCombined) ||
            !JoinPath(gameExe, kFirstTile, exeTile) ||
            !JoinPath(gameExe, kPattern, exeTilesPattern) ||
            !JoinPath(currentDir, kPattern, cwdTilesPattern))
        {
            ConsolePrint("[FF120] paths too long for safe diagnostic\r\n");
            return;
        }
        ConsolePrint("[FF120] zoneRoots exe=%ls cwd=%ls\r\n", gameExe, currentDir);
        const FileProbe exeFile = Inspect(exeCombined);
        const FileProbe cwdFile = Inspect(cwdCombined);
        const FileProbe numberedTile = Inspect(exeTile);
        Report("exe-zone-combined", exeFile);
        Report("cwd-zone-combined", cwdFile);
        Report("exe-zone-tile00000", numberedTile);
        const bool exeHasTiles = HasNumberedTile(exeTilesPattern);
        const bool cwdHasTiles = HasNumberedTile(cwdTilesPattern);
        ConsolePrint("[FF120] numbered-collision-tiles exe=%u cwd=%u\r\n",
                     exeHasTiles ? 1u : 0u, cwdHasTiles ? 1u : 0u);

        // The DLL launcher sometimes changes the current working directory.
        // Correct that mismatch only if the exact requested combined fastfile
        // is readable from the EXE root and is not readable relative to cwd.
        // Never change cwd to mask a corrupt, locked, or absent zone file.
        if (_wcsicmp(gameExe, currentDir) != 0 &&
            ((exeFile.readable && !cwdFile.readable) ||
             (!exeFile.exists && exeHasTiles && !cwdHasTiles)))
        {
            const BOOL corrected = SetCurrentDirectoryW(gameExe);
            const DWORD error = corrected ? 0 : GetLastError();
            ConsolePrint("[FF120] working-directory-repair=%s win32=%lu\r\n",
                corrected ? "applied" : "failed", static_cast<unsigned long>(error));
        }
        else
        {
            ConsolePrint("[FF120] working-directory-repair=unnecessary\r\n");
        }

        if (exeFile.readable && exeFile.headerBytes == 8 &&
            std::memcmp(exeFile.header, "IWffc100", 8) != 0)
            ConsolePrint("[FF120] WARNING: unexpected combined-fastfile header; "
                         "being readable does not prove it is compatible with build 1.20\r\n");
        if (!exeFile.readable && exeHasTiles)
            ConsolePrint("[FF120] combined-zone-not-openable numbered-tile-present; "
                         "native collision mode may require tile-mode selection "
                         "(not automatically forced)\r\n");
    }
}
