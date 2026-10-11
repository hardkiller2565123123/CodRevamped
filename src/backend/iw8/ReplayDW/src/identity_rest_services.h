#pragma once
#include "rest_services.h"

namespace services
{
    std::optional<Reply> identityRest(const platform::LobbyIdentity &, const RESTRequest &);
} // namespace services
