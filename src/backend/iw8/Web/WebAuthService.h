#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace revamped::iw8::web
{
    // Sets up the local Auth3 signer.
    bool InitializeLocalAuthSigner();

    // HTTP request result.
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

    // Handles one local web request.
    HttpResult TryHandleLocalWebRequest(std::vector<std::uint8_t>& buffer);

    // Tracks the LSG connection.
    void NotePostLsgTransport(std::uint16_t port, const char* transport);

    // Updates auth diagnostics.
    void PollAuthPipelineDiagnostics();

    // Gets available LSG session keys.
    std::size_t GetLsgSessionKeyCandidatesV72(
        std::uint8_t* outKeys,
        std::uint32_t* outKinds,
        std::size_t maxKeys,
        std::uint64_t* auth3Serial = nullptr);

    // Gets available Auth3 key data.
    std::size_t GetLsgKeyMaterialBlobsV73(
        std::uint8_t* outBlobs,
        std::uint32_t* outSizes,
        std::uint32_t* outKinds,
        std::size_t stride,
        std::size_t maxBlobs,
        std::uint64_t* auth3Serial = nullptr);

    // Gets the latest Auth3 session key.
    bool GetLatestAuth3SessionKey(
        std::uint8_t outKey[24],
        std::uint64_t* auth3Serial = nullptr);
}