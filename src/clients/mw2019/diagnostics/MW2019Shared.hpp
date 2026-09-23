#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace mw2019_diag
{
    void Log(const char* format, ...) noexcept;
    void RunServerEmuAuthScan(unsigned pass = 0) noexcept;
    void PrintServerEmuNetworkStatus() noexcept;
    void PrintSource3TestStatus() noexcept;
    bool SetSource3TestValue(unsigned value) noexcept;
    bool GetOutputRoot(wchar_t* out, std::size_t outCount) noexcept;
    bool BuildOutputPath(const wchar_t* relativePath, wchar_t* out, std::size_t outCount) noexcept;
    bool EnsureDirectoryTree(const wchar_t* path) noexcept;
}
