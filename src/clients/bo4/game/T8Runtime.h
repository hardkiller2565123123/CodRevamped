#pragma once
#include <string>

namespace t8_runtime
{
    bool VerifySupportedBuild(std::string& message);
    bool Initialize(std::string& message);
    bool QueueCommand(const std::string& command, std::string& message);
    bool ApplyIdentity(const std::string& name, std::string& message);
    void PrintStatus();
}
