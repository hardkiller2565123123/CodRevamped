#pragma once
#include <cstdint>
#include <string>

namespace runtime_focus_trace
{
    enum class Mode
    {
        Off,
        Lan,
        Online,
        Both
    };

    bool Start(Mode mode, std::string& message);
    void Stop(std::string& message);
    std::string Status();
    void Mark(const std::string& label);

    // Called from already-existing network detours. This performs no game-code
    // modification; it only inspects the current thread's stack when tracing.
    void ObserveCurrentNetworkStack(const char* api);
    void ObserveDnsRequest(
        const char* api,
        const char* host,
        std::uintptr_t callerAddress = 0);
    void UpdateCorrelationState(std::uintptr_t authManager, std::uint32_t networkMode, bool inited);
}
