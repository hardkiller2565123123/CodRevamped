#include "Start.h"

namespace revamped::iw8
{
    bool Server::Start()
    {
        if (running_.exchange(true)) return true;
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        {
            running_ = false;
            return false;
        }
        log::Initialize();
        if (!InitializeBundleSigner())
            log::Print("[TRUST-BOOT] WARNING: local BGS bundle signer setup failed. Start the server beside ModernWarfare.exe and inspect the error before launching the game.");
        if (!web::InitializeLocalAuthSigner())
            log::Print("[AUTH3-TRUST] WARNING: local Auth3 response signer setup failed. Stock Auth3 signature validation cannot complete until this is fixed.");
        if (!InitializeTlsCredential())
            log::Print("[TLS1119] WARNING: TLS credential setup failed. The server will still run, but :1119 cannot complete a TLS handshake until this is fixed.");
        unsigned opened = 0;
        for (const auto port : config_.tcpPorts) opened += CreateTcpListener(port) ? 1u : 0u;
        for (const auto port : config_.udpPorts) opened += CreateUdpListener(port) ? 1u : 0u;
        if (!opened)
        {
            log::Print("No listeners opened; stopping");
            Stop();
            return false;
        }
        log::Print("Revamped IW8 server phase 1 ready; listeners=%u", opened);
        return true;
    }
}
