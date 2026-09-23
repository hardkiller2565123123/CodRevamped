#pragma once
#include <Windows.h>
#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace runtime_scheduler
{
    using JobCallback = std::function<void()>;

    struct Job
    {
        std::string name;
        DWORD intervalMs = 1000;
        ULONGLONG nextRun = 0;
        JobCallback callback;
        bool enabled = true;
    };

    void Start();
    void Stop();
    bool IsRunning();
    void AddPeriodic(const char* name, DWORD intervalMs, JobCallback callback);
    void AddOneShot(const char* name, DWORD delayMs, JobCallback callback);
    void Clear();
}
