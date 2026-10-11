#pragma once
#include "services.h"

namespace services
{
    std::optional<Reply> anticheatServices(const std::filesystem::path &root,
                                           const platform::LobbyIdentity &identity,
                                           uint8_t service,
                                           uint8_t task,
                                           wire::Reader &params);
}
