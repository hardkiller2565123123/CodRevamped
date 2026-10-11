#pragma once
#include <filesystem>
#include <string>
#include <optional>
#include <vector>
#include <cstdint>

namespace platform_resources
{
    void initialize(const std::filesystem::path &directory, unsigned short port);
    const std::vector<uint8_t> &handle();
    const std::vector<uint8_t> &content();
    std::optional<std::string> download(const std::string &path);
} // namespace platform_resources
