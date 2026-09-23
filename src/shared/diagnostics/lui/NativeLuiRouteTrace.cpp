#include "NativeLuiRouteTrace.h"
#include "../../core/Main.hpp"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace native_lui_route_trace
{
    namespace
    {
        std::atomic_bool g_running{ false };
        CRITICAL_SECTION g_logLock{};
        std::atomic_bool g_lockReady{ false };
        char g_path[MAX_PATH]{};

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

        void EnsureLock()
        {
            if (!g_lockReady.exchange(true))
                InitializeCriticalSection(&g_logLock);
        }

        void Append(const char* text)
        {
            if (!text || !*text)
                return;

            EnsureLock();
            EnterCriticalSection(&g_logLock);

            HANDLE file =
                CreateFileA(
                    g_path,
                    FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);

            if (file != INVALID_HANDLE_VALUE)
            {
                DWORD written = 0;
                WriteFile(
                    file,
                    text,
                    static_cast<DWORD>(strlen(text)),
                    &written,
                    nullptr);
                CloseHandle(file);
            }

            LeaveCriticalSection(&g_logLock);
        }

        void Timestamp(char* out, size_t size)
        {
            SYSTEMTIME st{};
            GetLocalTime(&st);
            sprintf_s(
                out,
                size,
                "%02u:%02u:%02u.%03u",
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds);
        }

        void DumpFunctionBytes(
            const char* name,
            std::uintptr_t address)
        {
            if (!address)
                return;

            unsigned char bytes[0x100]{};
            SIZE_T got = 0;

            if (!ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    bytes,
                    sizeof(bytes),
                    &got) ||
                !got)
            {
                return;
            }

            const auto base =
                reinterpret_cast<std::uintptr_t>(
                    GetModuleHandleW(nullptr));

            char line[4096]{};
            int used = sprintf_s(
                line,
                "[FUNC] %s address=0x%llX rva=%s0x%llX bytes=",
                name,
                static_cast<unsigned long long>(address),
                base && address >= base ? "" : "abs:",
                static_cast<unsigned long long>(
                    base && address >= base
                        ? address - base
                        : address));

            for (SIZE_T i = 0;
                 i < got &&
                 used < static_cast<int>(sizeof(line) - 8);
                 ++i)
            {
                used += sprintf_s(
                    line + used,
                    sizeof(line) - used,
                    "%02X ",
                    static_cast<unsigned int>(bytes[i]));
            }

            sprintf_s(
                line + used,
                sizeof(line) - used,
                "\r\n");

            Append(line);
        }

        void DumpRoutingFunctions()
        {
            Append("[ROUTING-FUNCTION-SNAPSHOT]\r\n");
            DumpFunctionBytes(
                "SetScreen",
                g_Addrs.SetScreen);
            DumpFunctionBytes(
                "LobbyBase_SetNetworkMode",
                g_Addrs.LobbyBase_SetNetworkMode);
            DumpFunctionBytes(
                "Com_SessionMode_SetMode",
                g_Addrs.Com_SessionMode_SetNetworkMode);
            DumpFunctionBytes(
                "CL_Disconnect",
                g_Addrs.CL_Disconnect);
            Append("[END-ROUTING-FUNCTION-SNAPSHOT]\r\n");
        }

        struct State
        {
            std::uint32_t screen = 0;
            std::uint32_t networkMode = 0;
            std::uint32_t sessionMode = 0;
            unsigned char inited = 0;
            std::uintptr_t auth = 0;
        };

        State ReadState()
        {
            State s{};
            SafeRead(g_Addrs.s_uiScreen, s.screen);
            SafeRead(g_Addrs.s_networkMode, s.networkMode);
            SafeRead(g_Addrs.sSessionModeState, s.sessionMode);
            SafeRead(g_Addrs.s_inited, s.inited);
            SafeRead(g_Addrs.g_auth_manager, s.auth);
            return s;
        }

        bool Different(
            const State& a,
            const State& b)
        {
            return
                a.screen != b.screen ||
                a.networkMode != b.networkMode ||
                a.sessionMode != b.sessionMode ||
                a.inited != b.inited ||
                a.auth != b.auth;
        }

        void LogState(
            const char* tag,
            const State& oldState,
            const State& newState)
        {
            char time[64]{};
            Timestamp(time, sizeof(time));

            char line[1024]{};
            sprintf_s(
                line,
                "[%s] %s "
                "screen=0x%X->0x%X "
                "network=0x%08X->0x%08X "
                "session=0x%X->0x%X "
                "inited=%u->%u "
                "auth=0x%llX->0x%llX\r\n",
                time,
                tag ? tag : "STATE",
                oldState.screen,
                newState.screen,
                oldState.networkMode,
                newState.networkMode,
                oldState.sessionMode,
                newState.sessionMode,
                static_cast<unsigned int>(oldState.inited),
                static_cast<unsigned int>(newState.inited),
                static_cast<unsigned long long>(oldState.auth),
                static_cast<unsigned long long>(newState.auth));

            Append(line);

            // Mirror important native UI transitions in the CMD window.
            printf(
                "[LUI-ROUTE] screen 0x%X->0x%X network %08X->%08X session %X->%X\n",
                oldState.screen,
                newState.screen,
                oldState.networkMode,
                newState.networkMode,
                oldState.sessionMode,
                newState.sessionMode);
            fflush(stdout);
        }

        DWORD WINAPI Worker(LPVOID)
        {
            log_paths::EnsureAll();

            sprintf_s(
                g_path,
                "logs\\online\\native_lui_route_%lu.log",
                static_cast<unsigned long>(
                    GetCurrentProcessId()));

            HANDLE reset =
                CreateFileA(
                    g_path,
                    GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);

            if (reset != INVALID_HANDLE_VALUE)
                CloseHandle(reset);

            Append(
                "[BUILD251 NATIVE LUI ROUTE TRACE]\r\n"
                "purpose=native director/lobby/tab transition tracing; no menu replacement\r\n");

            DumpRoutingFunctions();

            State previous = ReadState();

            {
                State zero{};
                LogState(
                    "TRACE-START",
                    zero,
                    previous);
            }

            std::uint32_t transitionCount = 0;

            while (g_running.load())
            {
                const State current =
                    ReadState();

                if (Different(previous, current))
                {
                    LogState(
                        "STATE-CHANGE",
                        previous,
                        current);

                    ++transitionCount;

                    // Screen transitions are the useful signal when a native
                    // tab/menu suddenly enters the Connecting flow. Snapshot
                    // the routing functions again so every test log is
                    // self-contained even if the executable changes.
                    if (previous.screen != current.screen)
                    {
                        char marker[256]{};
                        sprintf_s(
                            marker,
                            "[SCREEN-TRANSITION #%u] old=0x%X new=0x%X\r\n",
                            transitionCount,
                            previous.screen,
                            current.screen);
                        Append(marker);
                        DumpRoutingFunctions();
                    }

                    previous = current;
                }

                Sleep(10);
            }

            Append("[END BUILD251 NATIVE LUI ROUTE TRACE]\r\n");
            return 0;
        }
    }

    void StartAsync()
    {
        if (g_running.exchange(true))
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
            g_running.store(false);
            return;
        }

        CloseHandle(thread);

        printf(
            "[LUI-ROUTE] Native route tracer armed. "
            "Click native tabs/buttons normally; transitions will be logged.\n");
        fflush(stdout);
    }

    bool IsRunning()
    {
        return g_running.load();
    }

    void Mark(const char* text)
    {
        if (!g_running.load())
            return;

        char time[64]{};
        Timestamp(time, sizeof(time));

        char line[1024]{};
        sprintf_s(
            line,
            "[%s] USER-MARK %s\r\n",
            time,
            text && *text ? text : "(empty)");
        Append(line);

        printf(
            "[LUI-ROUTE] MARK: %s\n",
            text && *text ? text : "(empty)");
        fflush(stdout);
    }
}
