#include "NativeDirectorStateRouter.h"
#include "../../core/Main.hpp"
#include "../../core/functions.hpp"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>

namespace native_director_state_router
{
    namespace
    {
        std::atomic_bool g_started{ false };
        std::atomic_bool g_enabled{ true };
        std::atomic_bool g_running{ false };

        std::atomic_uint g_mpHits{ 0 };
        std::atomic_uint g_zmHits{ 0 };
        std::atomic_uint g_lanMpHits{ 0 };
        std::atomic_uint g_lanZmHits{ 0 };

        constexpr unsigned int kModeMask = 0x0F;
        constexpr unsigned int kModeZombies = 0;
        constexpr unsigned int kModeMultiplayer = 1;
        constexpr unsigned int kModeCampaign = 2;
        constexpr unsigned int kModeFourth = 3;

        template <typename T>
        bool SafeRead(
            std::uintptr_t address,
            T& value)
        {
            SIZE_T got = 0;
            return address &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    &value,
                    sizeof(value),
                    &got) &&
                got == sizeof(value);
        }

        bool SafeWriteU32(
            std::uintptr_t address,
            std::uint32_t value)
        {
            if (!address)
                return false;

            DWORD oldProtect = 0;

            if (!VirtualProtect(
                    reinterpret_cast<void*>(address),
                    sizeof(value),
                    PAGE_READWRITE,
                    &oldProtect))
            {
                return false;
            }

            *reinterpret_cast<volatile std::uint32_t*>(
                address) = value;

            DWORD ignored = 0;
            VirtualProtect(
                reinterpret_cast<void*>(address),
                sizeof(value),
                oldProtect,
                &ignored);

            return true;
        }

        void Append(
            const char* text)
        {
            if (!text || !*text)
                return;

            log_paths::EnsureAll();
            CreateDirectoryA(
                "logs\\lui",
                nullptr);

            HANDLE file =
                CreateFileA(
                    "logs\\lui\\native_director_state_router.log",
                    FILE_APPEND_DATA,
                    FILE_SHARE_READ |
                        FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);

            if (file == INVALID_HANDLE_VALUE)
                return;

            DWORD written = 0;
            WriteFile(
                file,
                text,
                static_cast<DWORD>(strlen(text)),
                &written,
                nullptr);
            CloseHandle(file);
        }

        void LogRoute(
            const char* label,
            std::uint32_t before,
            std::uint32_t after,
            LobbyNetworkMode network)
        {
            SYSTEMTIME st{};
            GetLocalTime(&st);

            char line[768]{};
            sprintf_s(
                line,
                "[%02u:%02u:%02u.%03u] %s session=0x%08X->0x%08X network=%s\r\n",
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds,
                label,
                before,
                after,
                network == LOBBY_NETWORKMODE_LAN
                    ? "LAN"
                    : "LIVE");

            Append(line);
            printf("[NATIVE-STATE] %s\n", line);
            fflush(stdout);
        }

        DWORD WINAPI Worker(LPVOID)
        {
            g_running.store(true);

            Append(
                "[BUILD258 NATIVE DIRECTOR STATE ROUTER]\r\n"
                "NO CODE PATCHES / NO MINHOOK / NO CALLSITE PATCHES\r\n"
                "watches sSessionModeState only while screen 10 is active\r\n");

            std::uint32_t previousState = 0;
            bool havePrevious = false;

            for (;;)
            {
                if (!g_enabled.load())
                {
                    Sleep(25);
                    continue;
                }

                unsigned char inited = 0;
                std::uint32_t screen = 0;
                std::uint32_t state = 0;

                const bool ok =
                    SafeRead(g_Addrs.s_inited, inited) &&
                    SafeRead(g_Addrs.s_uiScreen, screen) &&
                    SafeRead(g_Addrs.sSessionModeState, state);

                if (!ok ||
                    inited == 0 ||
                    screen != 10)
                {
                    havePrevious = false;
                    Sleep(10);
                    continue;
                }

                if (!havePrevious)
                {
                    previousState = state;
                    havePrevious = true;

                    char line[256]{};
                    sprintf_s(
                        line,
                        "[ARMED] screen=10 session=0x%08X\r\n",
                        state);
                    Append(line);

                    Sleep(2);
                    continue;
                }

                if (state == previousState)
                {
                    Sleep(2);
                    continue;
                }

                const auto oldMode =
                    previousState & kModeMask;
                const auto newMode =
                    state & kModeMask;

                // Only react to an actual low-nibble session mode change.
                // Upper-bit frontend/state changes are left completely alone.
                if (oldMode != newMode)
                {
                    if (newMode == kModeMultiplayer)
                    {
                        ++g_mpHits;
                        LobbyBase_SetNetworkMode(
                            LOBBY_NETWORKMODE_LIVE);

                        LogRoute(
                            "native Multiplayer -> LIVE MP",
                            previousState,
                            state,
                            LOBBY_NETWORKMODE_LIVE);
                    }
                    else if (newMode == kModeZombies)
                    {
                        ++g_zmHits;
                        LobbyBase_SetNetworkMode(
                            LOBBY_NETWORKMODE_LIVE);

                        LogRoute(
                            "native Zombies -> LIVE ZM",
                            previousState,
                            state,
                            LOBBY_NETWORKMODE_LIVE);
                    }
                    else if (newMode == kModeCampaign)
                    {
                        ++g_lanMpHits;

                        const std::uint32_t rewritten =
                            (state & ~kModeMask) |
                            kModeMultiplayer;

                        LobbyBase_SetNetworkMode(
                            LOBBY_NETWORKMODE_LAN);

                        SafeWriteU32(
                            g_Addrs.sSessionModeState,
                            rewritten);

                        LogRoute(
                            "native Campaign slot -> LAN MP",
                            state,
                            rewritten,
                            LOBBY_NETWORKMODE_LAN);

                        if (g_Addrs.SetScreen)
                            SetScreen(11, 0);

                        state = rewritten;
                    }
                    else if (newMode == kModeFourth)
                    {
                        ++g_lanZmHits;

                        const std::uint32_t rewritten =
                            (state & ~kModeMask) |
                            kModeZombies;

                        LobbyBase_SetNetworkMode(
                            LOBBY_NETWORKMODE_LAN);

                        SafeWriteU32(
                            g_Addrs.sSessionModeState,
                            rewritten);

                        LogRoute(
                            "native fourth slot -> LAN ZM",
                            state,
                            rewritten,
                            LOBBY_NETWORKMODE_LAN);

                        if (g_Addrs.SetScreen)
                            SetScreen(11, 0);

                        state = rewritten;
                    }
                }

                previousState = state;
                Sleep(2);
            }
        }
    }

    void StartAuto()
    {
        if (g_started.exchange(true))
            return;

        HANDLE thread =
            CreateThread(
                nullptr,
                0,
                Worker,
                nullptr,
                0,
                nullptr);

        if (!thread)
        {
            g_started.store(false);
            Append("[ERROR] failed to create state router worker\r\n");
            return;
        }

        CloseHandle(thread);

        printf(
            "[NATIVE-STATE] Passive state router started; executable code remains untouched.\n");
        fflush(stdout);
    }

    bool Enable(std::string& message)
    {
        g_enabled.store(true);
        message =
            "enabled; state router watches native director selections without patching code";
        return true;
    }

    bool Disable(std::string& message)
    {
        g_enabled.store(false);
        message =
            "disabled; no native session/network state will be rewritten";
        return true;
    }

    bool IsRunning()
    {
        return g_running.load();
    }

    bool IsEnabled()
    {
        return g_enabled.load();
    }

    void PrintStatus()
    {
        printf(
            "[NATIVE-STATE] running=%s enabled=%s MP=%u ZM=%u LANMP=%u LANZM=%u\n",
            g_running.load() ? "yes" : "no",
            g_enabled.load() ? "yes" : "no",
            g_mpHits.load(),
            g_zmHits.load(),
            g_lanMpHits.load(),
            g_lanZmHits.load());
        fflush(stdout);
    }
}
