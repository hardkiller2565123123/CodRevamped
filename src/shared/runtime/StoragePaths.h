#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winioctl.h>

#include <filesystem>
#include <string>
#include <system_error>
#include <vector>
#include <cstring>

namespace storage_paths
{
    inline std::filesystem::path Root()
    {
        wchar_t profile[32768]{};
        const DWORD length = GetEnvironmentVariableW(L"USERPROFILE", profile,
            static_cast<DWORD>(sizeof(profile) / sizeof(profile[0])));

        if (length > 0 && length < (sizeof(profile) / sizeof(profile[0])))
            return std::filesystem::path(profile) / L"Documents" / L"CodRevamped";

        // USERPROFILE exists on normal Windows user sessions. This fallback is
        // intentionally generic and never embeds a developer/user-specific path.
        return std::filesystem::path(L".") / L"CodRevamped";
    }

    inline std::filesystem::path Logs()
    {
        return Root() / L"logs";
    }

    inline std::filesystem::path CustomData()
    {
        return Root() / L"custom_data";
    }

    inline void EnsureDirectory(const std::filesystem::path& path)
    {
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
    }

    inline void EnsureBaseDirectories()
    {
        EnsureDirectory(Root());
        EnsureDirectory(Logs());
        EnsureDirectory(CustomData());
    }

    inline std::filesystem::path Path(const std::filesystem::path& relative)
    {
        EnsureBaseDirectories();
        return Root() / relative;
    }

    inline bool CreateDirectoryJunction(
        const std::filesystem::path& junction,
        const std::filesystem::path& target)
    {
        EnsureDirectory(target);

        if (!CreateDirectoryW(junction.c_str(), nullptr) &&
            GetLastError() != ERROR_ALREADY_EXISTS)
        {
            return false;
        }

        HANDLE handle = CreateFileW(
            junction.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
            return false;

        struct MountPointReparseData
        {
            DWORD ReparseTag;
            WORD ReparseDataLength;
            WORD Reserved;
            WORD SubstituteNameOffset;
            WORD SubstituteNameLength;
            WORD PrintNameOffset;
            WORD PrintNameLength;
            WCHAR PathBuffer[1];
        };

        std::error_code absoluteEc;
        const auto absoluteTarget = std::filesystem::absolute(target, absoluteEc);
        if (absoluteEc)
        {
            CloseHandle(handle);
            std::error_code removeEc;
            std::filesystem::remove(junction, removeEc);
            return false;
        }
        const std::wstring printName = absoluteTarget.wstring();
        const std::wstring substituteName = L"\\??\\" + printName;
        const std::size_t substituteBytes = substituteName.size() * sizeof(wchar_t);
        const std::size_t printBytes = printName.size() * sizeof(wchar_t);
        const std::size_t pathBytes = substituteBytes + sizeof(wchar_t) +
            printBytes + sizeof(wchar_t);
        const std::size_t reparseDataLength = 8u + pathBytes;
        const std::size_t totalBytes = 8u + reparseDataLength;

        if (totalBytes > MAXIMUM_REPARSE_DATA_BUFFER_SIZE ||
            substituteBytes > 0xFFFFu || printBytes > 0xFFFFu)
        {
            CloseHandle(handle);
            std::error_code removeEc;
            std::filesystem::remove(junction, removeEc);
            return false;
        }

        std::vector<unsigned char> buffer(totalBytes, 0);
        auto* data = reinterpret_cast<MountPointReparseData*>(buffer.data());
        data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
        data->ReparseDataLength = static_cast<WORD>(reparseDataLength);
        data->SubstituteNameOffset = 0;
        data->SubstituteNameLength = static_cast<WORD>(substituteBytes);
        data->PrintNameOffset = static_cast<WORD>(substituteBytes + sizeof(wchar_t));
        data->PrintNameLength = static_cast<WORD>(printBytes);

        unsigned char* pathBuffer = reinterpret_cast<unsigned char*>(data->PathBuffer);
        std::memcpy(pathBuffer, substituteName.data(), substituteBytes);
        pathBuffer += substituteBytes + sizeof(wchar_t);
        std::memcpy(pathBuffer, printName.data(), printBytes);

        DWORD returned = 0;
        const BOOL ok = DeviceIoControl(
            handle,
            FSCTL_SET_REPARSE_POINT,
            data,
            static_cast<DWORD>(totalBytes),
            nullptr,
            0,
            &returned,
            nullptr);
        CloseHandle(handle);

        if (!ok)
        {
            std::error_code removeEc;
            std::filesystem::remove(junction, removeEc);
            return false;
        }
        return true;
    }

    inline bool EnsureLegacyRelativeLogRedirect()
    {
        EnsureBaseDirectories();

        std::error_code ec;
        const auto cwd = std::filesystem::current_path(ec);
        if (ec || cwd.empty()) return false;

        const auto localLogs = cwd / L"logs";
        const auto targetLogs = Logs();

        const DWORD attrs = GetFileAttributesW(localLogs.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
            return true;

        std::filesystem::path backup;
        bool movedExisting = false;

        if (attrs != INVALID_FILE_ATTRIBUTES)
        {
            if (!(attrs & FILE_ATTRIBUTE_DIRECTORY))
                return false;

            // Preserve any pre-existing local logs instead of deleting them.
            // Once renamed, new relative logs\... writers can be transparently
            // redirected to Documents\CodRevamped\logs.
            backup = cwd / L"logs.pre_codrevamped_documents";
            if (std::filesystem::exists(backup, ec))
                return false;

            ec.clear();
            std::filesystem::rename(localLogs, backup, ec);
            if (ec)
                return false;
            movedExisting = true;
        }

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
        DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
        BOOL linked = CreateSymbolicLinkW(localLogs.c_str(), targetLogs.c_str(), flags);
        if (!linked)
        {
            // Elevated sessions on older systems may reject the unprivileged flag
            // but still allow a normal directory symbolic link.
            linked = CreateSymbolicLinkW(localLogs.c_str(), targetLogs.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY);
        }

        if (linked)
            return true;

        // Junctions do not require the symbolic-link privilege and keep all of
        // the older relative logs\... writers pointed at the Documents root.
        if (CreateDirectoryJunction(localLogs, targetLogs))
            return true;

        // If Windows refuses both redirect methods, restore the old directory
        // exactly as it was. Modules converted to storage_paths still write to
        // Documents; untouched legacy writers continue working locally.
        if (movedExisting)
        {
            ec.clear();
            std::filesystem::rename(backup, localLogs, ec);
        }
        return false;
    }

    inline std::filesystem::path GameIni(const wchar_t* fileName)
    {
        EnsureBaseDirectories();
        return Root() / fileName;
    }

    inline std::string Narrow(const std::filesystem::path& path)
    {
        const std::wstring wide = path.wstring();
        if (wide.empty()) return {};

        const int count = WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1,
            nullptr, 0, nullptr, nullptr);
        if (count <= 1) return {};

        std::string out(static_cast<std::size_t>(count), '\0');
        WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1,
            out.data(), count, nullptr, nullptr);
        if (!out.empty() && out.back() == '\0') out.pop_back();
        return out;
    }

    inline std::string PathA(const char* relative)
    {
        std::filesystem::path rel;
        if (relative && *relative)
            rel = std::filesystem::path(relative);
        return Narrow(Path(rel));
    }

    inline std::wstring PathW(const wchar_t* relative)
    {
        std::filesystem::path rel;
        if (relative && *relative)
            rel = std::filesystem::path(relative);
        return Path(rel).wstring();
    }

    inline std::string GameIniA(const char* fileName)
    {
        std::filesystem::path rel(fileName ? fileName : "");
        return Narrow(Path(rel));
    }
}
