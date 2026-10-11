#pragma once
#include "services.h"

namespace services
{
    std::optional<Reply> identity(const platform::LobbyIdentity &,
                                  uint8_t,
                                  uint8_t,
                                  wire::Reader &);
}
