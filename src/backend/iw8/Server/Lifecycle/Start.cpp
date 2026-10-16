#include "Start.h"
#include "../../LocalPublisherContent.h"

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
        // Initialize both Retail manifests BEFORE opening listeners. Otherwise
        // the local public key would only appear after the first client request,
        // potentially racing the client's native signature verification.
        std::string patchManifest, commsManifest;
        if (!localpublisher::LoadManifest("1_manifest_patch_pc_8.69.txt", patchManifest) ||
            !localpublisher::LoadManifest("1_manifest_comms_pc_8.69.txt", commsManifest))
            log::Print("[IW8-RETAIL-MANIFEST] WARNING: native 8.69 manifests unavailable");
        else
            log::Print("[IW8-RETAIL-MANIFEST] 8.69 patch and comms prepared patchBytes=%zu commsBytes=%zu",
                patchManifest.size(), commsManifest.size());
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
        log::Print("[LSG-NATIVE] Umbrella handoff target=127.0.0.1 transport=TCP port=3074; UDP 3074 remains a separate socket/probe path");
        return true;
    }
}
