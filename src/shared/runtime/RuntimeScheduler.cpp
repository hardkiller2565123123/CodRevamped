#include "RuntimeScheduler.h"
#include <algorithm>

namespace runtime_scheduler
{
    namespace
    {
        std::mutex g_mutex;
        std::vector<Job> g_jobs;
        std::atomic_bool g_running{ false };
        HANDLE g_thread = nullptr;

        DWORD WINAPI ThreadMain(LPVOID)
        {
            while (g_running.load())
            {
                const ULONGLONG now = GetTickCount64();
                std::vector<JobCallback> due;
                {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    for (auto& job : g_jobs)
                    {
                        if (!job.enabled || !job.callback || now < job.nextRun)
                            continue;
                        due.push_back(job.callback);
                        if (job.intervalMs == 0)
                            job.enabled = false;
                        else
                            job.nextRun = now + job.intervalMs;
                    }
                    g_jobs.erase(std::remove_if(g_jobs.begin(), g_jobs.end(), [](const Job& job)
                    {
                        return !job.enabled && job.intervalMs == 0;
                    }), g_jobs.end());
                }

                for (auto& callback : due)
                {
                    try
                    {
                        callback();
                    }
                    catch (...)
                    {
                        // Keep the scheduler alive if a C++ callback reports failure.
                    }
                }
                Sleep(10);
            }
            return 0;
        }
    }

    void Start()
    {
        bool expected = false;
        if (!g_running.compare_exchange_strong(expected, true))
            return;
        g_thread = CreateThread(nullptr, 0, ThreadMain, nullptr, 0, nullptr);
        if (!g_thread)
            g_running.store(false);
    }

    void Stop()
    {
        g_running.store(false);
        if (g_thread)
        {
            WaitForSingleObject(g_thread, 1000);
            CloseHandle(g_thread);
            g_thread = nullptr;
        }
    }

    bool IsRunning()
    {
        return g_running.load();
    }

    void AddPeriodic(const char* name, DWORD intervalMs, JobCallback callback)
    {
        if (!callback || intervalMs == 0)
            return;
        std::lock_guard<std::mutex> lock(g_mutex);
        Job job{};
        job.name = name ? name : "periodic";
        job.intervalMs = intervalMs;
        job.nextRun = GetTickCount64() + intervalMs;
        job.callback = std::move(callback);
        g_jobs.push_back(std::move(job));
    }

    void AddOneShot(const char* name, DWORD delayMs, JobCallback callback)
    {
        if (!callback)
            return;
        std::lock_guard<std::mutex> lock(g_mutex);
        Job job{};
        job.name = name ? name : "one-shot";
        job.intervalMs = 0;
        job.nextRun = GetTickCount64() + delayMs;
        job.callback = std::move(callback);
        g_jobs.push_back(std::move(job));
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_jobs.clear();
    }
}
