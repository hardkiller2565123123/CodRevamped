#pragma once
#include "platform.h"
#include "wire.h"
#include <filesystem>

namespace relay_provider
{
    void start(const std::filesystem::path &directory);
    void stop();
    bool enabled();
    wire::Bytes serverToken(const platform::LobbyIdentity &id);
    std::string status();
} // namespace relay_provider
