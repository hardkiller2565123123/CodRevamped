#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace revamped::iw8::log
{
    bool Initialize();
    void Print(const char* format, ...);
    void Connection(std::uint64_t id, const std::string& peer, std::uint16_t port, const char* event, const char* detail = nullptr);
    void Payload(std::uint64_t id, const char* direction, std::uint16_t port, const std::string& peer, const void* data, std::size_t size);
    void Udp(std::uint16_t port, const std::string& peer, const void* data, std::size_t size);
}
