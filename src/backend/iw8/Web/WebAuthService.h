#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace revamped::iw8::web
{
    // Initializes the persistent local RSA-PSS key used to sign Auth3 JSON
    // replies and exports its 294-byte DER public key beside the server.
    bool InitializeLocalAuthSigner();

    struct HttpResult
    {
        bool complete = false;
        bool handled = false;
        int statusCode = 0;
        std::string method;
        std::string host;
        std::string path;
        std::string formKeys;
        std::size_t requestBytes = 0;
        std::string label;
        std::string response;
    };

    // Consumes exactly one complete HTTP/1.x request from buffer. Values from
    // Authorization headers and form/query parameters are never copied into
    // HttpResult; only parameter names are surfaced for diagnostics.
    HttpResult TryHandleLocalWebRequest(std::vector<std::uint8_t>& buffer);

    // Read-only auth-pipeline diagnostics. These do not fabricate client auth
    // state; they only correlate the last accepted Auth3/Umbrella exchange with
    // any subsequent local Demonware lobby transport observed by the server.
    void NotePostLsgTransport(std::uint16_t port, const char* transport);
    void PollAuthPipelineDiagnostics();

    // Returns the 24-byte session key associated with the most recent local
    // Auth3 ticket pair.  The server uses it only to authenticate the stock
    // LSG binary handshake; no client-side state is modified.
    bool GetLatestAuth3SessionKey(std::uint8_t outKey[24], std::uint64_t* auth3Serial = nullptr);
}
