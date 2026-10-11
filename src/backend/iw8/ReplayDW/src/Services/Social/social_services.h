#pragma once
#include "rest_services.h"

namespace services
{
    std::optional<Reply> social(const std::filesystem::path &,
                                const platform::LobbyIdentity &,
                                const RESTRequest &);
    std::vector<Delivery> socialDisconnected(const std::filesystem::path &,
                                             uint32_t title,
                                             uint64_t user);
    bool socialDeliveryValid(uint32_t title, const Delivery &);
} // namespace services
