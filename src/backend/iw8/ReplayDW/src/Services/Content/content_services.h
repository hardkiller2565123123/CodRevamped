#pragma once
#include "services.h"

namespace services
{
    void initializeContentStreaming(const std::filesystem::path &, unsigned short);
    std::optional<Reply> contentServices(const std::filesystem::path &,
                                         const platform::LobbyIdentity &,
                                         uint8_t,
                                         uint8_t,
                                         wire::Reader &);
    std::optional<wire::Bytes> streamingContent(const std::string &);
    unsigned streamingUpload(const std::string &, std::span<const uint8_t>);
    unsigned streamingCopy(const std::string &source, const std::string &destination);
    constexpr unsigned maximumStreamingBody = 16 * 1024 * 1024;
} // namespace services
