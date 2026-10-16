#pragma once
#include <cstdlib>
#include <string>

namespace revamped::iw8::web::localplayer
{
    inline std::string Name()
    {
        // The launcher sets this on the local server process only.  The
        // existing local account ID stays stable when the display name changes.
#if defined(_MSC_VER)
        char* configured = nullptr;
        std::size_t configuredLength = 0;
        if (_dupenv_s(&configured, &configuredLength, "CODREVAMPED_PLAYER_NAME") != 0 ||
            configured == nullptr)
            return "revamped";
        const std::string value(configured);
        std::free(configured);
#else
        const char* configured = std::getenv("CODREVAMPED_PLAYER_NAME");
        if (!configured)
            return "revamped";
        const std::string value(configured);
#endif
        if (value.empty() || value.size() > 24)
            return "revamped";
        for (const unsigned char c : value)
        {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
                return "revamped";
        }
        return value;
    }
}
