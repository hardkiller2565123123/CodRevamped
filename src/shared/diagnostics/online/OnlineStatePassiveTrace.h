#pragma once
#include <cstdint>

namespace online_state_passive_trace
{
    void Start(
        std::uintptr_t networkModeAddress,
        std::uintptr_t initedAddress,
        std::uintptr_t authManagerAddress,
        const char* modeLabel);
    bool IsRunning();
}
