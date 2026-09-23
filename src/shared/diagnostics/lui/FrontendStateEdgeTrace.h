#pragma once
#include <string>

namespace frontend_state_edge_trace
{
    void StartAsync();
    bool IsRunning();
    void PrintStatus();
    bool SnapshotNow(
        const std::string& label,
        std::string& message);
}
