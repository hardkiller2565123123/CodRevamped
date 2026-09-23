#include "PointerRegistry.h"
#include <mutex>

namespace pointer_registry
{
    namespace
    {
        Snapshot g_snapshot{};
        std::mutex g_mutex;
    }

    void Publish(const Snapshot& snapshot)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_snapshot = snapshot;
    }

    Snapshot Get()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_snapshot;
    }
}
