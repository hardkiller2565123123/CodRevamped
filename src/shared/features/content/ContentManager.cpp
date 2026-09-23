#include "ContentManager.h"
#include <TlHelp32.h>
#include <mutex>

namespace content_manager
{
    namespace
    {
        DWORD g_processId = 0;
        std::vector<ModuleSnapshot> g_modules;
        std::mutex g_mutex;
    }

    void Initialize(DWORD processId)
    {
        g_processId = processId;
        Refresh();
    }

    void Refresh()
    {
        if (!g_processId)
            return;
        std::vector<ModuleSnapshot> next;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_processId);
        if (snapshot == INVALID_HANDLE_VALUE)
            return;
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot, &entry))
        {
            do
            {
                ModuleSnapshot item{};
                item.name = entry.szModule;
                item.base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                item.size = entry.modBaseSize;
                next.push_back(std::move(item));
            } while (Module32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        std::lock_guard<std::mutex> lock(g_mutex);
        g_modules.swap(next);
    }

    std::vector<ModuleSnapshot> Modules()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_modules;
    }
}
