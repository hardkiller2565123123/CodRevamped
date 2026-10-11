#pragma once
#include "services.h"
#include <map>

namespace services
{
    struct RESTRequest
    {
        uint32_t version = 0, method = 0, accept = 0, content = 0;
        std::string service, resource, operation, uri;
        // Retain only headers consumed by domain handlers. Never log credentials
        // or raw header/body contents in task diagnostics.
        std::map<std::string, std::string> headers;
        bool hasBody = false;
        wire::Bytes body;
    };

    Reply rest(const std::filesystem::path &directory,
               const platform::LobbyIdentity &,
               wire::Reader &);
    wire::Bytes restResult(uint64_t transaction, const RESTResult &);
} // namespace services
