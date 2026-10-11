#pragma once
#include "services.h"

namespace services
{
    std::vector<Delivery> currentMailDeliveries(const std::filesystem::path &,
                                                uint32_t title,
                                                uint64_t user);
    bool mailDeliveryValid(const std::filesystem::path &, uint32_t title, const Delivery &);
    std::optional<Reply> mailServices(const std::filesystem::path &,
                                      const platform::LobbyIdentity &,
                                      uint8_t service,
                                      uint8_t task,
                                      wire::Reader &);
} // namespace services
