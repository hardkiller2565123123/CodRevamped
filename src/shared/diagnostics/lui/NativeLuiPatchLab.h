#pragma once
#include <string>

namespace native_lui_patch_lab
{
    void StartAsync();
    bool IsRunning();
    bool HasScanCompleted();

    bool ScanNow(std::string& message);
    bool ApplyOverrides(std::string& message);
    bool RestoreOverrides(std::string& message);
}
