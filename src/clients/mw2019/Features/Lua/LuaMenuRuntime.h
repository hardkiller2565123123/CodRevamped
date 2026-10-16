#pragma once
#include <cstdint>

namespace codrevamped::replay120::luamenus {
using LogFn = void (*)(const char* format, ...);
// Experimental: always off unless the user opts in locally. The caller
// already verifies the full Replay 1.20 image fingerprint.
bool Install(std::uintptr_t base, std::uint32_t imageSize, LogFn log) noexcept;
}
