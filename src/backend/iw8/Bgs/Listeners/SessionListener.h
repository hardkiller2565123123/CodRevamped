#pragma once

#include "../BgsDispatcher.h"

#include <vector>

namespace revamped::iw8::bgs
{
    void QueueSessionCreatedNotification(RequestContext& context,
        const std::vector<Byte>& identity,
        const std::vector<Byte>& sessionKey);
}
