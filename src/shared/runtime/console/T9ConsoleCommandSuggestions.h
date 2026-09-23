#pragma once
#include <string>
#include <vector>
#include <algorithm>

namespace t9_console_suggestions
{
    inline const std::vector<std::string>& All()
    {
        static const std::vector<std::string> commands = {
            "/help",
            "/helpscan",
            "/scan dvar",
            "/scan float",
            "/scan int",
            "/scan variant",
            "/scan vector",
            "/scan lookup",
            "/scan command",
            "/scan camo",
            "/scan camo deep",
            "/scan status",
            "/scan stop",
            "/onlinehooks",
            "/online status",
            "/online scan",
            "/offsets",
            "/map",
            "/missing",
            "/state",
            "/network",
            "/tracefocus lan",
            "/tracefocus online",
            "/tracefocus both",
            "/tracefocus off",
            "/tracefocus status",
            "/lan status",
            "/lan scan",
            "/lan inspect",
            "/lan xrefs",
            "/lan mode lan",
            "/lan mode live",
            "/lan sessionmode 0",
            "/lan sessionmode 1",
            "/lan menu",
            "/lan host",
            "/lan session",
            "/lan join ",
            "/lan trace on",
            "/lan trace off",
            "/lan trace status",
            "/connect ",
            "/profile status",
            "/profile dump",
            "/profile analyze",
            "/profile name ",
            "/setname <name>",
            "/setmap <map>",
            "/setgametype <gametype>",
            "/setmode campaign|multiplayer|zombies",
            "/addbot [count]",
            "/disconnect",
            "/offline",
            "/nodw on|off",
            "/dvarptr bool <address> <0|1>",
            "/dvarptr float <address> <value>",
            "/dvarptr string <address> <value>",
            "/dvarlabel <id> <name>",
            "/cg_fov <value>",
            "/window 1|2|3",
            "/mute_sound 0|1",
            "/voice_chat_enabled 0|1",
            "/microphone_activation 0|1",
            "/subtitles 0|1",
            "/intro_movie 0|1",
            "/camo status",            "/camo dump",
            "/camo apply <name>",
            "/camo prototype status",
            "/camo prototype create",
            "/camo prototype reset",
            "/camo research status",
            "/camo research writers",
            "/camo research functions",
            "/camo research restart",
            "/camo research stop",
            "/camo inspect",
            "/camo replace <targetIndex> <sourceIndex>",
            "/camo restore <targetIndex>",
            "/apply camo <folder>",
            "/apply camo list",
            "/restore camo",
            "/camo custom list",
            "/camo custom inspect <name>",
            "/camo custom stage <name> <targetIndex>",
            "/camo custom apply <name> <targetIndex>",
            "/camo custom restore <targetIndex>",
            "/camo custom analyze <targetIndex>",
            "/camo custom test <targetIndex> <candidateIndex>",
            "/camo custom testrestore <targetIndex>",
            "/camo custom next <targetIndex>",
            "/camo custom prev <targetIndex>",
            "/camo custom status <targetIndex>",
            "/camo custom keep <targetIndex> [role]",
            "/game <command>",
            "/research [query]",
            "/researchresolve",
            "/discover",
            "/dvars [query]",
            "/commands [query]",
            "/researchui on|off",
            "/feature <name|status>",
            "/stages",
            "/imgui status|install|off",
            "/verbose on|off",
            "/clear",
            "/exit"
        };
        return commands;
    }

    inline std::vector<std::string> Match(const std::string& input)
    {
        std::string needle = input;
        std::transform(needle.begin(), needle.end(), needle.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        std::vector<std::string> result;
        for (const auto& command : All())
        {
            std::string lowered = command;
            std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (needle.empty() || lowered.rfind(needle, 0) == 0)
                result.push_back(command);
        }
        return result;
    }
}
