#include "Server/Core/Server.h"
#include "Common/Logging/Log.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <atomic>
#include <cstdio>
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

    SetConsoleTitleW(L"Revamped IW8 Server - Pure Emulation Login Research");
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    revamped::iw8::Server server(config);
    g_server = &server;
    if (!server.Start())
    {
        std::fprintf(stderr, "Failed to start Revamped IW8 server.\n");
        return 1;
    }

    revamped::iw8::log::Print("Welcome to Revamped IW8 Server.");
    server.Run();
    g_server = nullptr;
    revamped::iw8::log::Print("Server stopped.");
    return 0;
}
