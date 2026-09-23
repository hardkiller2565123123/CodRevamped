#pragma once

#include "StoragePaths.h"

namespace log_paths
{
    inline void EnsureAll()
    {
        storage_paths::EnsureBaseDirectories();
        (void)storage_paths::EnsureLegacyRelativeLogRedirect();
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"camo");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"lan");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"online");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"profile");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"scanner");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"scanner" / L"analysis");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"research");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"runtime");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"ui");
        storage_paths::EnsureDirectory(storage_paths::Logs() / L"general");
    }
}
