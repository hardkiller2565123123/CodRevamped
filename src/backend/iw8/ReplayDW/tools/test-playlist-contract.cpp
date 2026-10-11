// Execute the production selector against isolated catalog/package publications.
// This executable contains no game image, network listener or platform identity.
#include "../src/playlist_catalog.h"
#include <fstream>
#include <iostream>

int main(int argc, char **argv)
{
    using Json = nlohmann::json;
    if (argc != 2 && argc != 3)
        return 2;
    try
    {
        const std::filesystem::path directory(argv[1]);
        std::ifstream input(directory / "playlists/5800/catalog.json");
        const auto catalog = Json::parse(input);
        Json result = Json::array();
        Json queries = Json::array();
        if (argc == 3)
        {
            std::ifstream queryInput(argv[2]);
            queries.push_back(Json::parse(queryInput));
        }
        else
            for (const auto &playlist : catalog.at("playlists"))
                queries.push_back(
                    {{"ruleset_payload",
                      {{"filter",
                        {{"playlist_id", playlist.at("playlist")},
                         {"playlist_version", catalog.at("system").at("version")}}}}}});
        for (const auto &query : queries)
        {
            const auto id = query.at("ruleset_payload").at("filter").at("playlist_id");
            const auto selected = services::selectPlaylist(directory, 5800, query);
            if (selected)
                result.push_back({{"playlist", selected->metadata.at("playlist_id")},
                                  {"team_count", selected->teamCount},
                                  {"maximum_members", selected->maximumMembers},
                                  {"rules", selected->rules},
                                  {"metadata", selected->metadata}});
            else
                result.push_back({{"playlist", id}, {"unavailable", true}});
        }
        std::cout << result.dump() << '\n';
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "Playlist contract rejected: " << error.what() << '\n';
        return 1;
    }
}
