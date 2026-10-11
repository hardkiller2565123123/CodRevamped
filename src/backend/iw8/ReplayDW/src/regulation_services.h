#pragma once
#include "rest_services.h"

namespace services
{
    std::optional<Reply> regulations(const std::filesystem::path &directory,
                                     const platform::LobbyIdentity &identity,
                                     const RESTRequest &request);
}
