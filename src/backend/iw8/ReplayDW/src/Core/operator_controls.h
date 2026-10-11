#pragma once
#include "services.h"

namespace services
{
    struct OperatorMatchStart
    {
        unsigned status = 409;
        std::string message;
        uint32_t title = 0;
        std::vector<Delivery> deliveries;
    };

    OperatorMatchStart operatorStartMatch(const std::string &credential,
                                          const std::string &matchToken,
                                          bool fillBots = false,
                                          unsigned botCount = 0);
} // namespace services
