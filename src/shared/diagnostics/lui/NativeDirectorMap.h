#pragma once
#include <string>

namespace native_director_map
{
    void StartAsync();
    bool IsRunning();
    bool HasCompleted();
    bool ScanNow(std::string& message);
}
