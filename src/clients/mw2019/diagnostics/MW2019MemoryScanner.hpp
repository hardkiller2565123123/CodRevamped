#pragma once
#include <cstdint>

namespace mw2019_scanner
{
    void Initialize() noexcept;
    void Tick(unsigned long long uptimeMs) noexcept;
    void ScanNow(const char* reason) noexcept;
    void ScanAllNow(const char* reason) noexcept;

    // Shared MW2019 command registry / Engine.ExecNow console.
    void StartConsole() noexcept;
    void ScanCommands() noexcept;

    // Exact-build profiles can seed validated RVAs before the late/manual
    // signature pass. This keeps protected startup fast while still giving
    // offsetscan a common address catalog.
    void SeedAddress(const char* name, std::uintptr_t address) noexcept;
    std::uintptr_t GetAddress(const char* name) noexcept;
    void PrintAddresses() noexcept;

    // Post-registration dvar helpers. Never call these during early protected
    // startup; the 1.44 profile waits for its late frontend window first.
    bool SetBool(const char* keyOrName, const char* friendlyName, bool value) noexcept;
    unsigned ApplyFrontendBladeSelectors(bool verbose) noexcept;
}
