#pragma once
#include "services.h"

namespace services
{
    bool clanDeliveryValid(const std::filesystem::path &, uint32_t title, const Delivery &);
    std::optional<Reply> clanServices(const std::filesystem::path &,
                                      const platform::LobbyIdentity &,
                                      uint8_t service,
                                      uint8_t task,
                                      wire::Reader &);
} // namespace services
