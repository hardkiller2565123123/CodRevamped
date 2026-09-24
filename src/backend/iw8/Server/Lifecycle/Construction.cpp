#include "Construction.h"

namespace revamped::iw8
{
    Server::Server(ServerConfig config) : config_(std::move(config)) {}

    Server::~Server()
    {
        Stop();
    }
}
