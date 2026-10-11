#include "../src/tournament_map_policy.h"
#include <iostream>

int main()
{
    try
    {
        const auto cases = nlohmann::json::parse(std::cin);
        auto result = nlohmann::json::array();
        for (const auto &entry : cases)
        {
            const nlohmann::json policy = {{"schema", 1},
                                           {"title", uint32_t{5800}},
                                           {"revision", uint32_t{1}},
                                           {"rounds", entry.at("pools")}};
            result.push_back(
                services::tournamentMapsForId(policy, entry.at("tournament").get<uint64_t>()));
        }
        std::cout << result.dump() << '\n';
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
