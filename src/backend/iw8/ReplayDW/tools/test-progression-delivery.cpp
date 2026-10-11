#include "../src/achievement_services.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

// Link this focused verifier against the compiled backend objects except
// server.cpp. It exercises the actual delivery validator, without sockets or
// a replacement implementation of the achievement store.
int main(int argc, char **argv)
{
    try
    {
        if (argc != 2)
            throw std::runtime_error("Provide an isolated fixture directory");
        const std::filesystem::path root(argv[1]);
        const auto folder = root / "achievements/5800/5800/42";
        std::filesystem::create_directories(folder);
        const auto path = folder / "events.json";
        const auto publish = [&](const char *document)
        {
            std::ofstream out(path);
            if (!(out << document).flush())
                throw std::runtime_error("Fixture write failed");
        };
        unsigned checks = 0;
        const auto require = [&](bool condition)
        {
            if (!condition)
                throw std::runtime_error("Progression delivery contract failed");
            ++checks;
        };
        services::Delivery delivery;
        delivery.user = 42;
        require(services::achievementDeliveryValid(root, 5800, delivery));
        delivery.progressionContext = "5800";
        delivery.progressionXp = 17;
        publish(R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp":17})");
        require(services::achievementDeliveryValid(root, 5800, delivery));
        delivery.progressionXp = 16;
        require(!services::achievementDeliveryValid(root, 5800, delivery));
        delivery.progressionXp = 18;
        require(!services::achievementDeliveryValid(root, 5800, delivery));
        delivery.progressionXp = 17;
        publish(R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp":10})");
        require(!services::achievementDeliveryValid(root, 5800, delivery));
        delivery.progressionXp = 10;
        require(services::achievementDeliveryValid(root, 5800, delivery));
        publish(R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp":0})");
        delivery.progressionXp = 0;
        require(services::achievementDeliveryValid(root, 5800, delivery));
        const auto rejects = [&](const auto &operation)
        {
            bool rejected = false;
            try
            {
                operation();
            }
            catch (const std::exception &)
            {
                rejected = true;
            }
            require(rejected);
        };
        publish(R"({"schema":1,"next":1,"events":{},"requests":[],"player_xp":0})");
        rejects([&] { services::achievementDeliveryValid(root, 5800, delivery); });
        publish(R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp":0})");
        delivery.progressionContext = "../escape";
        rejects([&] { services::achievementDeliveryValid(root, 5800, delivery); });
        delivery.progressionContext = "5800";
        rejects([&] { services::achievementDeliveryValid(root, 5311, delivery); });
        const auto intent = root / "achievements/5800/event-transaction.json";
        {
            std::ofstream out(intent);
            out << R"({"schema":1,"phase":"prepared"})";
        }
        rejects([&] { services::achievementDeliveryValid(root, 5800, delivery); });
        std::filesystem::remove(intent);
        publish(R"({"schema":1,"next":1,"events":[],"requests":[]})");
        {
            std::ofstream out(folder / "states.json");
            out << R"([{"id":1000000,"multiProgress":[{"name":"xp","current":31}]}])";
        }
        delivery.progressionXp = 31;
        require(services::achievementDeliveryValid(root, 5800, delivery));
        delivery.progressionXp = 0;
        require(!services::achievementDeliveryValid(root, 5800, delivery));
        for (const char *invalid : {
            R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp":0,"player_xp_pending":1})",
            R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp_pending":0})",
            R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp":0,"player_xp_pending":true})"})
        {
            publish(invalid);
            rejects([&] { services::achievementDeliveryValid(root, 5800, delivery); });
        }
        publish(R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp":100,"player_xp_pending":100})");
        services::restoreAchievementProgression(root, 5800, 42, 50, true, 0);
        delivery.progressionXp = 100;
        require(services::achievementDeliveryValid(root, 5800, delivery));
        services::restoreAchievementProgression(root, 5800, 42, 100, true, 0);
        nlohmann::json confirmed;
        {
            std::ifstream in(path);
            in >> confirmed;
        }
        require(!confirmed.contains("player_xp_pending"));
        publish(R"({"schema":1,"next":1,"events":[],"requests":[],"player_xp":100,"player_xp_pending":100})");
        services::restoreAchievementProgression(root, 5800, 42, 50, true, 2);
        delivery.progressionXp = 3000;
        require(services::achievementDeliveryValid(root, 5800, delivery));
        const auto owns = [&](uint32_t item)
        {
            nlohmann::json inventory;
            std::ifstream input(root / "marketplace/5800/42/inventory.json");
            input >> inventory;
            for (const auto &entry : inventory.at("items"))
                if (entry.at("1").get<uint32_t>() == item)
                    return entry.at("2").get<uint32_t>() > 0;
            return false;
        };
        require(!owns(350003)); // Replay create-a-class: native rank 3, UI level 4.
        services::restoreAchievementProgression(root, 5800, 42, 0, false, 3);
        require(!owns(350003));
        services::restoreAchievementProgression(root, 5800, 42, 0, false, 4);
        require(owns(350003));
        services::restoreAchievementProgression(root, 5800, 42, 0, false, 53);
        require(owns(350003) && owns(350004));
        std::cout << "PASS: " << checks << " compiled progression delivery checks\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
