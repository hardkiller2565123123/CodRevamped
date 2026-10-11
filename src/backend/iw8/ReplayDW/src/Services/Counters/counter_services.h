#pragma once
#include "services.h"

namespace services
{
    std::optional<Reply> counterServices(const std::filesystem::path &directory,
                                         const platform::LobbyIdentity &identity,
                                         uint8_t service,
                                         uint8_t task,
                                         wire::Reader &params);
}
