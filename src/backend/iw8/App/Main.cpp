#include "Server/Core/Server.h"
#include "Common/Logging/Log.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

namespace
{
    std::atomic_bool g_exitRequested{false};
    revamped::iw8::Server* g_server = nullptr;

    BOOL WINAPI ConsoleHandler(DWORD type)
    {
        if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT)
        {
            g_exitRequested = true;
            if (g_server) g_server->Stop();
            return TRUE;
        }
        return FALSE;
    }

    void SetLsgTestMode(bool enabled)
    {
        SetEnvironmentVariableA("CODREVAMPED_FORCE_LSG_TEST", enabled ? "1" : "0");
        _putenv_s("CODREVAMPED_FORCE_LSG_TEST", enabled ? "1" : "0");
        if (enabled)
        {
            revamped::iw8::log::Print("[LSG-TEST] ENABLED by /LSG. TEST-ONLY handoff assists are active: next BGS request may queue OnGameAccountSelected, and Auth3 advertises crossplay plus snake/camel LSG endpoint fields. No client memory/state patch is used.");
            revamped::iw8::log::Print("[LSG-TEST] Watch for [BGS-LSG-TEST], Umbrella traffic, DNS for mw-lobby-1.prod.demonware.net, and TCP localPort=3074.");
        }
        else
        {
            revamped::iw8::log::Print("[LSG-TEST] DISABLED. Normal semantic emulation behavior restored for subsequent requests.");
        }
    }

    DWORD WINAPI CommandWorker(LPVOID)
    {
        char line[256]{};
        while (!g_exitRequested && std::fgets(line, static_cast<int>(sizeof(line)), stdin))
        {
            std::size_t length = std::strlen(line);
            while (length && (line[length - 1] == '\r' || line[length - 1] == '\n' || line[length - 1] == ' ' || line[length - 1] == '\t'))
                line[--length] = '\0';
            char* command = line;
            while (*command == ' ' || *command == '\t')
                ++command;

            if (_stricmp(command, "/LSG") == 0 || _stricmp(command, "/LSG ON") == 0)
            {
                SetLsgTestMode(true);
                continue;
            }
            if (_stricmp(command, "/LSG OFF") == 0)
            {
                SetLsgTestMode(false);
                continue;
            }
            if (_stricmp(command, "/LSG STATUS") == 0)
            {
                char value[8]{};
                const DWORD count = GetEnvironmentVariableA("CODREVAMPED_FORCE_LSG_TEST", value, static_cast<DWORD>(sizeof(value)));
                revamped::iw8::log::Print("[LSG-TEST] status=%s", (count && value[0] == '1') ? "ENABLED" : "DISABLED");
                continue;
            }
            if (*command == '/')
                revamped::iw8::log::Print("[COMMAND] unknown command '%s'. Available: /LSG, /LSG OFF, /LSG STATUS", command);
        }
        return 0;
    }

    std::vector<std::uint16_t> ParsePorts(const char* text)
    {
        std::vector<std::uint16_t> ports;
        if (!text) return ports;
        std::string value(text);
        std::size_t start = 0;
        while (start < value.size())
        {
            const std::size_t comma = value.find(',', start);
            const std::string token = value.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            const int port = std::atoi(token.c_str());
            if (port > 0 && port <= 65535) ports.push_back(static_cast<std::uint16_t>(port));
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
        return ports;
    }
}

int main(int argc, char** argv)
{
    revamped::iw8::ServerConfig config{};
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--bind" && i + 1 < argc) config.bindAddress = argv[++i];
        else if (arg == "--tcp" && i + 1 < argc) config.tcpPorts = ParsePorts(argv[++i]);
        else if (arg == "--udp" && i + 1 < argc) config.udpPorts = ParsePorts(argv[++i]);
        else if (arg == "--no-payloads") config.dumpPayloads = false;
    }

    SetConsoleTitleW(L"Revamped IW8 Server - xpak_ignore.keylist Research");
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    revamped::iw8::Server server(config);
    g_server = &server;
    if (!server.Start())
    {
        std::fprintf(stderr, "Failed to start Revamped IW8 server.\n");
        return 1;
    }

    revamped::iw8::log::Print("Welcome to Revamped IW8 Server.");
    revamped::iw8::log::Print("[KEYLIST] RESEARCH RESULT: /pc/0/xpak_ignore.keylist uses HTTP 200 with a single LF byte as the accepted empty list.");
    revamped::iw8::log::Print("[KEYLIST] Auto-fuzz is disabled; response is now deterministic for 1.44/1.20 testing.");
    SetLsgTestMode(false);
    revamped::iw8::log::Print("[COMMAND] Type /LSG to enable the temporary LSG handoff test. Use /LSG OFF to disable it and /LSG STATUS to check it.");
    if (HANDLE commandThread = CreateThread(nullptr, 0, CommandWorker, nullptr, 0, nullptr))
        CloseHandle(commandThread);
    server.Run();
    g_server = nullptr;
    revamped::iw8::log::Print("Server stopped.");
    return 0;
}
