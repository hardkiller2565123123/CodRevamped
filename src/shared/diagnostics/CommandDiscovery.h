#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace command_discovery
{
    struct DvarEntry
    {
        std::string name;
        std::string type;
        std::string value;
        std::uint64_t hash = 0;
        std::uintptr_t address = 0;
        unsigned int flags = 0;
        bool live = false;
    };

    void Refresh();
    std::vector<DvarEntry> Dvars(const std::string& filter = {});
    std::vector<std::string> Commands(const std::string& filter = {});
    std::vector<std::string> Suggestions(const std::string& input, std::size_t limit = 8);
    void WriteReports();
}
