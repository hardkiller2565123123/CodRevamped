#include "RuntimeStageManager.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace runtime_stages
{
    namespace
    {
        std::mutex g_mutex;
        std::vector<SnapshotEntry> g_entries;

        std::uint64_t NowMs()
        {
            return static_cast<std::uint64_t>(GetTickCount64());
        }

        SnapshotEntry& FindOrCreate(const char* name)
        {
            const std::string key = name ? name : "unnamed";
            const auto it = std::find_if(g_entries.begin(), g_entries.end(), [&](const SnapshotEntry& entry)
            {
                return entry.name == key;
            });
            if (it != g_entries.end())
                return *it;
            g_entries.push_back({});
            g_entries.back().name = key;
            return g_entries.back();
        }

        void WriteStageLog(const SnapshotEntry& entry)
        {
            char modulePath[MAX_PATH]{};
            GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
            char* slash = strrchr(modulePath, '\\');
            if (slash)
                *(slash + 1) = '\0';
            strcat_s(modulePath, "logs\\runtime\\runtime_stages.log");

            std::string directory(modulePath);
            const auto separator = directory.find_last_of("\\/");
            if (separator != std::string::npos)
            {
                directory.resize(separator);
                CreateDirectoryA(directory.c_str(), nullptr);
            }

            FILE* file = nullptr;
            if (fopen_s(&file, modulePath, "a") == 0 && file)
            {
                SYSTEMTIME time{};
                GetLocalTime(&time);
                std::fprintf(file, "[%02u:%02u:%02u.%03u] %-20s %-10s %s\n",
                    time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
                    entry.name.c_str(), ToString(entry.state), entry.detail.c_str());
                std::fclose(file);
            }
        }

        void Set(const char* name, State state, const char* detail)
        {
            std::scoped_lock lock(g_mutex);
            SnapshotEntry& entry = FindOrCreate(name);
            entry.state = state;
            if (detail)
                entry.detail = detail;
            if (state == State::Running)
            {
                entry.startedAtMs = NowMs();
                entry.finishedAtMs = 0;
            }
            else if (state == State::Succeeded || state == State::Failed || state == State::Skipped)
            {
                if (entry.startedAtMs == 0)
                    entry.startedAtMs = NowMs();
                entry.finishedAtMs = NowMs();
            }
            WriteStageLog(entry);
        }
    }

    void Reset()
    {
        std::scoped_lock lock(g_mutex);
        g_entries.clear();
    }

    void Begin(const char* name, const char* detail) { Set(name, State::Running, detail); }
    void Succeed(const char* name, const char* detail) { Set(name, State::Succeeded, detail); }
    void Fail(const char* name, const char* detail) { Set(name, State::Failed, detail); }
    void Skip(const char* name, const char* detail) { Set(name, State::Skipped, detail); }

    State GetState(const char* name)
    {
        std::scoped_lock lock(g_mutex);
        const std::string key = name ? name : "unnamed";
        const auto it = std::find_if(g_entries.begin(), g_entries.end(), [&](const SnapshotEntry& entry)
        {
            return entry.name == key;
        });
        return it == g_entries.end() ? State::Pending : it->state;
    }

    std::vector<SnapshotEntry> Snapshot()
    {
        std::scoped_lock lock(g_mutex);
        return g_entries;
    }

    const char* ToString(State state)
    {
        switch (state)
        {
        case State::Pending: return "pending";
        case State::Running: return "running";
        case State::Succeeded: return "succeeded";
        case State::Failed: return "failed";
        case State::Skipped: return "skipped";
        default: return "unknown";
        }
    }
}
