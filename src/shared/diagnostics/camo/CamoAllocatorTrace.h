#pragma once
#include <string>

namespace camo_allocator_trace
{
    // Starts once, immediately after WaitForStableImage returns and before the
    // existing 15-second delayed initialization.
    void StartEarly();

    // Kept for compatibility with the image path. If early capture is already
    // running/started this is a no-op.
    void NotifyImageReady();

    bool Command(const std::string& action, std::string& message);
    bool WriterWatchStatus(std::string& message);
    bool DumpRegistrationFunctions(std::string& message);
    bool IsRunning();
}
