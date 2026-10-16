#pragma once

#include <cstdint>

// CodRevamped-owned, exact-build Replay 1.20 custom map loader.
// Other builds remain untouched. Call only after MinHook initialization, on
// the normal client startup worker (never inside DllMain).
namespace codrevamped::replay120::custommaps {
    using LogFn = void (*)(const char*, ...);
    bool Install(std::uintptr_t imageBase, std::uint32_t imageSize, LogFn logger) noexcept;
    void Refresh() noexcept;
}
