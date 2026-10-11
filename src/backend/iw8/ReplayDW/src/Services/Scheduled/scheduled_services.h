#pragma once
#include "services.h"

namespace services
{
    std::optional<Reply> scheduledServices(const std::filesystem::path &,
                                           const platform::LobbyIdentity &,
                                           uint8_t service,
                                           uint8_t task,
                                           wire::Reader &);
}
