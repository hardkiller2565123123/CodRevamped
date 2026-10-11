#pragma once
#include "services.h"

namespace services
{
    std::optional<Reply> qosServices(const std::filesystem::path &,
                                     const platform::LobbyIdentity &,
                                     uint8_t,
                                     uint8_t,
                                     wire::Reader &);
}
