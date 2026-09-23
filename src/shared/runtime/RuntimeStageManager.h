#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace runtime_stages
{
    enum class State : std::uint8_t
    {
        Pending,
        Running,
        Succeeded,
        Failed,
        Skipped
    };

    struct SnapshotEntry
    {
        std::string name;
        State state = State::Pending;
        std::string detail;
        std::uint64_t startedAtMs = 0;
        std::uint64_t finishedAtMs = 0;
    };

    void Reset();
    void Begin(const char* name, const char* detail = nullptr);
    void Succeed(const char* name, const char* detail = nullptr);
    void Fail(const char* name, const char* detail = nullptr);
    void Skip(const char* name, const char* detail = nullptr);
    State GetState(const char* name);
    std::vector<SnapshotEntry> Snapshot();
    const char* ToString(State state);
}
