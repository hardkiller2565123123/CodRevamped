#include "FrontendCustomButtons.h"
#include "../../runtime/LogPaths.h"

#include <atomic>
#include <cstdio>
#include <fstream>
#include <string>

namespace frontend_custom_buttons
{
    namespace
    {
        std::atomic_bool g_enabled{ false };

        void Log(const char* text)
        {
            if (!text || !*text)
                return;

            log_paths::EnsureAll();
            CreateDirectoryA("logs\\lui", nullptr);

            std::ofstream out(
                "logs\\lui\\frontend_custom_buttons.log",
                std::ios::app);

            if (out)
                out << text;
        }
    }

    void StartAuto()
    {
        // Build267 crash fix:
        // R_AddCmdDrawStretchPic was already marked ABI-unverified elsewhere
        // in the project. Do not hook it. Custom frontend work continues
        // through the Lua/LUI MenuBuilder path.
        g_enabled.store(false);

        Log(
            "[CUSTOM-UI] Build267: unsafe renderer hook removed. "
            "Custom button path is Lua/LUI only.\\n");

        std::printf(
            "[CUSTOM-UI] Unsafe renderer hook removed; "
            "custom frontend button work is using the Lua/LUI path.\\n");
        std::fflush(stdout);
    }

    bool Enable(std::string& message)
    {
        g_enabled.store(false);
        message =
            "blocked intentionally: the old custom renderer hook used an unverified "
            "R_AddCmdDrawStretchPic ABI and caused the Build266 crash; use Lua/LUI path";
        return false;
    }

    bool Disable(std::string& message)
    {
        g_enabled.store(false);
        message =
            "custom renderer hook is disabled";
        return true;
    }

    bool IsInstalled()
    {
        return false;
    }

    bool IsEnabled()
    {
        return false;
    }

    void PrintStatus()
    {
        std::printf(
            "[CUSTOM-UI] installed=no enabled=no mode=Lua/LUI "
            "rendererHookRemoved=yes\\n");
        std::fflush(stdout);
    }
}
