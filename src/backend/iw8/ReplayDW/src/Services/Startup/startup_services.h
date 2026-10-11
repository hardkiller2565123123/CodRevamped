#pragma once
#include "services.h"

namespace services
{
    void initializeStartup(const std::filesystem::path &directory);
    std::optional<Reply> startup(const platform::LobbyIdentity &,
                                 uint8_t service,
                                 uint8_t task,
                                 wire::Reader &);
} // namespace services
