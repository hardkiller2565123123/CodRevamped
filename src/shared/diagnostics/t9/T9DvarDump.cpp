#include "T9DvarDump.h"
#include "../../../clients/coldwar/game/T9Dvar.h"
#include "../../runtime/LogPaths.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <atomic>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <string>

namespace t9_dvar_dump
{
    namespace
    {
        std::atomic_bool g_started{ false };
        std::string Csv(std::string s)
        {
            std::string out = "\"";
            for (char c : s) { if (c == '"') out += '"'; out += c; }
            out += '"';
            return out;
        }
        void Perform()
        {
            log_paths::EnsureAll();
            CreateDirectoryA("logs\\dvars", nullptr);
            t9_dvars::Refresh();
            t9_dvars::WriteReport();
            const auto entries = t9_dvars::Entries({}, false);
            std::ofstream out("logs\\dvars\\snapshot.csv", std::ios::trunc);
            if (out)
            {
                out << "name,type,value,hash,address,flags,verified,source\n";
                for (const auto& e : entries)
                    out << Csv(e.name) << ',' << Csv(e.type) << ',' << Csv(e.value) << ",0x" << std::hex << std::uppercase
                        << e.hash << ",0x" << e.address << std::dec << ',' << e.flags << ',' << (e.verified ? 1 : 0) << ','
                        << static_cast<int>(e.source) << "\n";
            }
            std::printf("[DVAR-DUMP] wrote %llu known/runtime dvars to logs\\dvars\\snapshot.csv.\n",
                static_cast<unsigned long long>(entries.size()));
        }
        DWORD WINAPI Worker(LPVOID)
        {
            Sleep(8000);
            for (unsigned int i = 0; i < 6; ++i)
            {
                __try { Perform(); }
                __except (EXCEPTION_EXECUTE_HANDLER) { std::printf("[DVAR-DUMP] guarded snapshot faulted; retrying.\n"); }
                Sleep(10000);
            }
            return 0;
        }
    }
    void StartAsync()
    {
        if (g_started.exchange(true)) return;
        HANDLE t = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    void DumpNow()
    {
        __try { Perform(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { std::printf("[DVAR-DUMP] guarded manual snapshot faulted.\n"); }
    }
}
