#include "CommandDiscovery.h"
#include "../../clients/coldwar/game/T9Dvar.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>

namespace command_discovery
{
    namespace
    {
        const char* kCommands[] = {
            "/help", "/helpscan", "/stages", "/imgui status", "/scan dvar", "/scan command",
            "/scan camo", "/scan status", "/scan stop", "/offsets", "/map", "/missing",
            "/state", "/network", "/research", "/researchresolve", "/feature status", "/dvars",
            "/commands", "/discover", "/map_restart", "/disconnect", "/connect", "/god",
            "/noclip", "/ufo", "/notarget", "/kill", "/give", "/take", "/say", "/team",
            "/fast_restart", "/vid_restart", "/snd_restart"
        };

        std::string Lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });
            return value;
        }

        std::string Normalize(std::string value)
        {
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
                value.pop_back();
            return Lower(value);
        }
    }

    void Refresh()
    {
        t9_dvars::Refresh();
    }

    std::vector<DvarEntry> Dvars(const std::string& filter)
    {
        std::vector<DvarEntry> result;
        for (const auto& source : t9_dvars::Entries(filter))
        {
            DvarEntry entry;
            entry.name = source.name;
            entry.type = source.type;
            entry.value = source.value;
            entry.hash = source.hash;
            entry.address = source.address;
            entry.flags = source.flags;
            entry.live = source.verified;
            result.push_back(std::move(entry));
        }
        return result;
    }

    std::vector<std::string> Commands(const std::string& filter)
    {
        const std::string needle = Lower(filter);
        std::vector<std::string> result;
        std::set<std::string> seen;
        for (const char* command : kCommands)
        {
            const std::string value(command);
            if (!needle.empty() && Lower(value).find(needle) == std::string::npos)
                continue;
            if (seen.insert(Normalize(value)).second)
                result.push_back(value);
        }
        return result;
    }

    std::vector<std::string> Suggestions(const std::string& input, std::size_t limit)
    {
        struct Ranked
        {
            int rank;
            std::string text;
        };

        const std::string needle = Lower(input);
        std::vector<Ranked> ranked;
        std::set<std::string> seen;

        for (const std::string& command : Commands())
        {
            const std::string lowered = Lower(command);
            const std::size_t pos = lowered.find(needle);
            if (!needle.empty() && pos == std::string::npos)
                continue;
            if (!seen.insert(Normalize(command)).second)
                continue;
            ranked.push_back({ (pos == 0 ? 0 : 30) + static_cast<int>(lowered.size()), command });
        }

        for (const std::string& dvar : t9_dvars::Suggestions(input, limit * 2))
        {
            if (!seen.insert(Normalize(dvar)).second)
                continue;
            const std::string lowered = Lower(dvar);
            const std::size_t pos = lowered.find(needle);
            ranked.push_back({ (pos == 0 ? 5 : 35) + static_cast<int>(lowered.size()), dvar });
        }

        std::sort(ranked.begin(), ranked.end(), [](const Ranked& a, const Ranked& b)
        {
            if (a.rank != b.rank) return a.rank < b.rank;
            return Lower(a.text) < Lower(b.text);
        });

        std::vector<std::string> result;
        for (const Ranked& item : ranked)
        {
            result.push_back(item.text);
            if (result.size() >= limit)
                break;
        }
        return result;
    }

    void WriteReports()
    {
        t9_dvars::WriteReport();
        std::ofstream commands("logs\\research\\discovered_commands.txt", std::ios::trunc);
        for (const std::string& command : Commands())
            commands << command << '\n';
    }
}
