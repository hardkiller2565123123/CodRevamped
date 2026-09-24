#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace revamped::iw8::protocol
{
    std::string HexPrefix(const void* data, std::size_t size, std::size_t limit = 96);
    std::string AsciiPrefix(const void* data, std::size_t size, std::size_t limit = 96);
    bool LooksLikeTlsClientHello(const void* data, std::size_t size);
    std::string TryExtractTlsSni(const void* data, std::size_t size);
    std::string Classify(const void* data, std::size_t size);
}
