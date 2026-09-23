#pragma once
#include <string>

namespace camo_texture_upload
{
    bool Apply(unsigned int camoIndex,
               const std::string& packageName,
               const std::string& colorPath,
               std::string& message);
    bool Restore(unsigned int camoIndex, std::string& message);
    bool PrecacheGif(const std::string& colorPath, std::string& message);
    void StartBackgroundPrecache();
    std::string PrecacheStatus();
    bool IsGifPrecached(const std::string& colorPath, unsigned int size);
}
