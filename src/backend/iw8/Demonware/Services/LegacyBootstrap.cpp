#include "LegacyBootstrap.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        void AppendLegacyDmlInfo(std::vector<std::uint8_t>& serviceReply)
        {
            // Deterministic local/offline DML view. This is protocol data only;
            // it is not inferred from the user's physical location.
            AppendTypedU32(serviceReply, 1u); // numResults
            AppendTypedU32(serviceReply, 1u); // totalNumResults
            AppendTypedString(serviceReply, "US");
            AppendTypedString(serviceReply, "United States");
            AppendTypedString(serviceReply, "");
            AppendTypedString(serviceReply, "");
            AppendTypedFloat(serviceReply, 0.0f);
            AppendTypedFloat(serviceReply, 0.0f);
            AppendTypedU32(serviceReply, 0u);
            AppendTypedString(serviceReply, "UTC");
        }

        void AppendLegacyServerTime(std::vector<std::uint8_t>& serviceReply)
        {
            const auto now = std::chrono::system_clock::now().time_since_epoch();
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now).count();
            const std::uint32_t unixTime = seconds <= 0 ? 0u :
                static_cast<std::uint32_t>((std::min)(static_cast<std::uint64_t>(seconds),
                    static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())));

            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, 1u);
            AppendTypedU32(serviceReply, unixTime);
        }
    }
}
