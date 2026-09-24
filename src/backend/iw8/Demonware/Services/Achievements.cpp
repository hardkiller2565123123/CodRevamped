#include "Achievements.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        bool ExtractAchievementsRequestedKeys(const std::uint8_t* requestPayload,
            std::size_t requestPayloadBytes, std::string& context, std::vector<std::string>& keys)
        {
            context.clear();
            keys.clear();

            const std::uint8_t* body = nullptr;
            std::size_t bodyBytes = 0;
            if (!ExtractTypedStructBody(requestPayload, requestPayloadBytes, body, bodyBytes))
                return false;

            const std::uint8_t* cursor = body;
            const std::uint8_t* end = body + bodyBytes;
            while (cursor < end)
            {
                PbField field{};
                if (!NextPbField(cursor, end, field))
                    return false;
                if (field.wireType != 2u)
                    continue;
                const std::string value(reinterpret_cast<const char*>(field.bytes), field.bytesSize);
                if (field.tag == 1u && context.empty())
                    context = value;
                else if (field.tag == 2u && !value.empty())
                    keys.push_back(value);
            }
            return !context.empty();
        }

        std::string FreshAchievementStateJsonValue(const std::string& key)
        {
            if (key == "br_tutorial_rewarded")
            {
                // Fresh-account tutorial rewards: no reward has been granted.
                return "{\"br_tutorial_reward_0\":false,\"br_tutorial_reward_1\":false,\"br_tutorial_reward_2\":false,\"br_tutorial_reward_3\":false}";
            }
            if (key == "games_of_summer_rewarded")
            {
                // Trial medals use integer enum values; 0 is the fresh/unearned state.
                return "{\"trial_0\":0,\"trial_1\":0,\"trial_2\":0,\"trial_3\":0,\"trial_4\":0,\"trial_5\":0}";
            }
            if (key.size() >= 6u && key.compare(key.size() - 6u, 6u, "_owned") == 0)
                return "false";

            // All expiry/count/rank/xp style fields consumed by the IW8
            // OnlineProgression bootstrap are numeric. Zero is a real fresh-account
            // value, not an empty/generic response.
            return "0";
        }

        bool AppendAchievementsUserStateStruct(std::vector<std::uint8_t>& serviceReply,
            const std::uint8_t* requestPayload, std::size_t requestPayloadBytes)
        {
            std::string context;
            std::vector<std::string> keys;
            if (!ExtractAchievementsRequestedKeys(requestPayload, requestPayloadBytes, context, keys))
                return false;

            std::string json = "{";
            for (std::size_t i = 0; i < keys.size(); ++i)
            {
                if (i)
                    json.push_back(',');
                json += "\"" + JsonEscape(keys[i]) + "\":" + FreshAchievementStateJsonValue(keys[i]);
            }
            json += "}";

            std::printf("[DW-ACHIEVEMENTS] getUserState context=%s requestedKeys=%zu response=fresh-account-state\n",
                context.c_str(), keys.size());

            std::vector<std::uint8_t> body;
            AppendPbString(body, 1u, json);
            AppendTypedStruct(serviceReply, body);
            return true;
        }
    }
}
