#pragma once
#include "wire.h"
#include <filesystem>

namespace qos_provider
{
    struct Host
    {
        wire::Bytes address, securityId, securityKey;
    };

    void start(const std::filesystem::path &directory);
    void stop();
    bool enabled();
    Host host();
    uint64_t probes();
    uint64_t traversals();
} // namespace qos_provider
