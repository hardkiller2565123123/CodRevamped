#pragma once

#include <Windows.h>

#include <cstdint>

namespace utils::pattern_scan
{
    // Safe runtime pattern scan bounded to one PE image. Wildcards may be
    // written as either '?' or '??'. Only committed/readable memory regions
    // are copied, so protected/guard pages are skipped instead of dereferenced.
    std::uintptr_t find_first(HMODULE module, const char* pattern);
    std::uintptr_t find_first(HMODULE module, std::uintptr_t start, const char* pattern);
}
