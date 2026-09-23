#pragma once

namespace native_lui_route_trace
{
    void StartAsync();
    bool IsRunning();
    void Mark(const char* text);
}
