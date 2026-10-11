#pragma once
#include "services.h"

namespace services
{
    struct RESTRequest;

    Reply abTestingEnroll(const std::filesystem::path &,
                          const platform::LobbyIdentity &,
                          const std::string &,
                          std::optional<uint32_t> restVersion = std::nullopt);
    std::optional<Reply> abTestingRest(const std::filesystem::path &,
                                       const platform::LobbyIdentity &,
                                       const RESTRequest &);
} // namespace services
