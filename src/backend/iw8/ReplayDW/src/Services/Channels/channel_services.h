#pragma once
#include "services.h"

namespace services
{
    void initializeChannels(const std::filesystem::path &);
    std::vector<Delivery> disconnectChannels(const std::filesystem::path &,
                                             uint32_t title,
                                             uint64_t user);
    bool channelDeliveryValid(const std::filesystem::path &, uint32_t title, const Delivery &);
    std::optional<Reply> channelServices(const std::filesystem::path &,
                                         const platform::LobbyIdentity &,
                                         uint8_t service,
                                         uint8_t task,
                                         wire::Reader &);
} // namespace services
