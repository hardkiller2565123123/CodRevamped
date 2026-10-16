#pragma once

// MW2019 1.20 (TU19) matchmaking playlist catalog.
//
// This is the bootstrap data written to ReplayDWData/playlists/5800/catalog.json
// when no operator-provided catalog exists. Keep playlist IDs, map names,
// game types, and dvars consistent with the published TU19 playlist.
//
// Each playlist is an independent raw string rather than a single large
// literal. This avoids MSVC C2026 and allows the data to be reviewed by mode.

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace revamped::iw8::matchmaking_catalog_120
{
    inline constexpr unsigned PublisherVersion = 1;
    inline constexpr unsigned PlaylistCount = 39;
    inline constexpr unsigned GametypeCount = 17;

    namespace detail
    {
        inline constexpr std::string_view CatalogPrefix = R"MM120({
  "system": { "version": 1 },
  "global_dvars": {},
  "gametypes": [
    {"gametype": "war", "name": "Team Deathmatch", "script": "war", "teamCount": 2, "teamSize": 6},
    {"gametype": "dm", "name": "Free-for-All", "script": "dm", "teamCount": 0, "teamSize": 0},
    {"gametype": "dom", "name": "Domination", "script": "dom", "teamCount": 2, "teamSize": 6},
    {"gametype": "koth", "name": "Hardpoint", "script": "koth", "teamCount": 2, "teamSize": 6},
    {"gametype": "conf", "name": "Kill Confirmed", "script": "conf", "teamCount": 2, "teamSize": 6},
    {"gametype": "sd", "name": "Search & Destroy", "script": "sd", "teamCount": 2, "teamSize": 6},
    {"gametype": "hq", "name": "Headquarters", "script": "hq", "teamCount": 2, "teamSize": 6},
    {"gametype": "cyber", "name": "Cyber Attack", "script": "cyber", "teamCount": 2, "teamSize": 6},
    {"gametype": "arena", "name": "Gunfight", "script": "arena", "teamCount": 2, "teamSize": 2},
    {"gametype": "gun", "name": "Gun Game", "script": "gun", "teamCount": 0, "teamSize": 0},
    {"gametype": "ctf", "name": "Capture the Flag", "script": "ctf", "teamCount": 2, "teamSize": 6},
    {"gametype": "dd", "name": "Demolition", "script": "dd", "teamCount": 2, "teamSize": 6},
    {"gametype": "infect", "name": "Infected", "script": "infect", "teamCount": 2, "teamSize": 6},
    {"gametype": "grind", "name": "Grind", "script": "grind", "teamCount": 2, "teamSize": 6},
    {"gametype": "cranked", "name": "Cranked", "script": "cranked", "teamCount": 2, "teamSize": 6},
    {"gametype": "grnd", "name": "Drop Zone", "script": "grnd", "teamCount": 2, "teamSize": 6},
    {"gametype": "br", "name": "Battle Royale", "script": "br", "teamCount": 0, "teamSize": 4, "dvars": {"MQSPQRQQRO": 1, "MOLPOSLOMO": "br", "NKTMKRMSKR": "br", "RKMMNSQKO": "mp/loot_item_defs.csv", "scr_br_gulag": 1, "OKTSLRSQMS": -1, "scriptable_force_large_mode": 1, "MQNOMMKSMM": 1, "LQLTOQSRNO": 0}}
  ],
  "playlists": [
)MM120";

        inline constexpr std::array<std::string_view, PlaylistCount> Playlists = {

            // Quick Play (1-16)

            //  1 - Team Deathmatch
            R"MM120(    {
      "playlist": 1,
      "name": "Team Deathmatch",
      "description": "Quick Play - Team Deathmatch",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "war", "weight": 100},
        {"map": "mp_cave", "gametype": "war", "weight": 100},
        {"map": "mp_cave_am", "gametype": "war", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "war", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "war", "weight": 100},
        {"map": "mp_raid", "gametype": "war", "weight": 100},
        {"map": "mp_runner", "gametype": "war", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "war", "weight": 100},
        {"map": "mp_quarry2", "gametype": "war", "weight": 100},
        {"map": "mp_deadzone", "gametype": "war", "weight": 100},
        {"map": "mp_euphrates", "gametype": "war", "weight": 100},
        {"map": "mp_spear", "gametype": "war", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "war", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "war", "weight": 100},
        {"map": "mp_petrograd", "gametype": "war", "weight": 100},
        {"map": "mp_crash2", "gametype": "war", "weight": 100},
        {"map": "mp_shipment", "gametype": "war", "weight": 100},
        {"map": "mp_vacant", "gametype": "war", "weight": 100},
        {"map": "mp_emporium", "gametype": "war", "weight": 100},
        {"map": "mp_rust", "gametype": "war", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "war", "weight": 100},
        {"map": "mp_layover", "gametype": "war", "weight": 100},
        {"map": "mp_hideout", "gametype": "war", "weight": 100},
        {"map": "mp_backlot2", "gametype": "war", "weight": 100},
        {"map": "mp_village2", "gametype": "war", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            //  2 - Free-for-All
            R"MM120(    {
      "playlist": 2,
      "name": "Free-for-All",
      "description": "Quick Play - Free-for-All",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "dm", "weight": 100},
        {"map": "mp_cave", "gametype": "dm", "weight": 100},
        {"map": "mp_cave_am", "gametype": "dm", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "dm", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "dm", "weight": 100},
        {"map": "mp_raid", "gametype": "dm", "weight": 100},
        {"map": "mp_runner", "gametype": "dm", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "dm", "weight": 100},
        {"map": "mp_quarry2", "gametype": "dm", "weight": 100},
        {"map": "mp_deadzone", "gametype": "dm", "weight": 100},
        {"map": "mp_euphrates", "gametype": "dm", "weight": 100},
        {"map": "mp_spear", "gametype": "dm", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "dm", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "dm", "weight": 100},
        {"map": "mp_petrograd", "gametype": "dm", "weight": 100},
        {"map": "mp_crash2", "gametype": "dm", "weight": 100},
        {"map": "mp_shipment", "gametype": "dm", "weight": 100},
        {"map": "mp_vacant", "gametype": "dm", "weight": 100},
        {"map": "mp_emporium", "gametype": "dm", "weight": 100},
        {"map": "mp_rust", "gametype": "dm", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "dm", "weight": 100},
        {"map": "mp_layover", "gametype": "dm", "weight": 100},
        {"map": "mp_hideout", "gametype": "dm", "weight": 100},
        {"map": "mp_backlot2", "gametype": "dm", "weight": 100},
        {"map": "mp_village2", "gametype": "dm", "weight": 100}
      ],
      "maxparty": 1,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            //  3 - Domination
            R"MM120(    {
      "playlist": 3,
      "name": "Domination",
      "description": "Quick Play - Domination",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "dom", "weight": 100},
        {"map": "mp_cave", "gametype": "dom", "weight": 100},
        {"map": "mp_cave_am", "gametype": "dom", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "dom", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "dom", "weight": 100},
        {"map": "mp_raid", "gametype": "dom", "weight": 100},
        {"map": "mp_runner", "gametype": "dom", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "dom", "weight": 100},
        {"map": "mp_quarry2", "gametype": "dom", "weight": 100},
        {"map": "mp_deadzone", "gametype": "dom", "weight": 100},
        {"map": "mp_euphrates", "gametype": "dom", "weight": 100},
        {"map": "mp_spear", "gametype": "dom", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "dom", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "dom", "weight": 100},
        {"map": "mp_petrograd", "gametype": "dom", "weight": 100},
        {"map": "mp_crash2", "gametype": "dom", "weight": 100},
        {"map": "mp_shipment", "gametype": "dom", "weight": 100},
        {"map": "mp_vacant", "gametype": "dom", "weight": 100},
        {"map": "mp_emporium", "gametype": "dom", "weight": 100},
        {"map": "mp_rust", "gametype": "dom", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "dom", "weight": 100},
        {"map": "mp_layover", "gametype": "dom", "weight": 100},
        {"map": "mp_hideout", "gametype": "dom", "weight": 100},
        {"map": "mp_backlot2", "gametype": "dom", "weight": 100},
        {"map": "mp_village2", "gametype": "dom", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            //  4 - Hardpoint
            R"MM120(    {
      "playlist": 4,
      "name": "Hardpoint",
      "description": "Quick Play - Hardpoint",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "koth", "weight": 100},
        {"map": "mp_cave", "gametype": "koth", "weight": 100},
        {"map": "mp_cave_am", "gametype": "koth", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "koth", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "koth", "weight": 100},
        {"map": "mp_raid", "gametype": "koth", "weight": 100},
        {"map": "mp_runner", "gametype": "koth", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "koth", "weight": 100},
        {"map": "mp_quarry2", "gametype": "koth", "weight": 100},
        {"map": "mp_deadzone", "gametype": "koth", "weight": 100},
        {"map": "mp_euphrates", "gametype": "koth", "weight": 100},
        {"map": "mp_spear", "gametype": "koth", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "koth", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "koth", "weight": 100},
        {"map": "mp_petrograd", "gametype": "koth", "weight": 100},
        {"map": "mp_crash2", "gametype": "koth", "weight": 100},
        {"map": "mp_shipment", "gametype": "koth", "weight": 100},
        {"map": "mp_vacant", "gametype": "koth", "weight": 100},
        {"map": "mp_emporium", "gametype": "koth", "weight": 100},
        {"map": "mp_rust", "gametype": "koth", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "koth", "weight": 100},
        {"map": "mp_layover", "gametype": "koth", "weight": 100},
        {"map": "mp_hideout", "gametype": "koth", "weight": 100},
        {"map": "mp_backlot2", "gametype": "koth", "weight": 100},
        {"map": "mp_village2", "gametype": "koth", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            //  5 - Kill Confirmed
            R"MM120(    {
      "playlist": 5,
      "name": "Kill Confirmed",
      "description": "Quick Play - Kill Confirmed",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "conf", "weight": 100},
        {"map": "mp_cave", "gametype": "conf", "weight": 100},
        {"map": "mp_cave_am", "gametype": "conf", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "conf", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "conf", "weight": 100},
        {"map": "mp_raid", "gametype": "conf", "weight": 100},
        {"map": "mp_runner", "gametype": "conf", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "conf", "weight": 100},
        {"map": "mp_quarry2", "gametype": "conf", "weight": 100},
        {"map": "mp_deadzone", "gametype": "conf", "weight": 100},
        {"map": "mp_euphrates", "gametype": "conf", "weight": 100},
        {"map": "mp_spear", "gametype": "conf", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "conf", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "conf", "weight": 100},
        {"map": "mp_petrograd", "gametype": "conf", "weight": 100},
        {"map": "mp_crash2", "gametype": "conf", "weight": 100},
        {"map": "mp_shipment", "gametype": "conf", "weight": 100},
        {"map": "mp_vacant", "gametype": "conf", "weight": 100},
        {"map": "mp_emporium", "gametype": "conf", "weight": 100},
        {"map": "mp_rust", "gametype": "conf", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "conf", "weight": 100},
        {"map": "mp_layover", "gametype": "conf", "weight": 100},
        {"map": "mp_hideout", "gametype": "conf", "weight": 100},
        {"map": "mp_backlot2", "gametype": "conf", "weight": 100},
        {"map": "mp_village2", "gametype": "conf", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            //  6 - Search & Destroy
            R"MM120(    {
      "playlist": 6,
      "name": "Search & Destroy",
      "description": "Quick Play - Search & Destroy",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "sd", "weight": 100},
        {"map": "mp_cave", "gametype": "sd", "weight": 100},
        {"map": "mp_cave_am", "gametype": "sd", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "sd", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "sd", "weight": 100},
        {"map": "mp_raid", "gametype": "sd", "weight": 100},
        {"map": "mp_runner", "gametype": "sd", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "sd", "weight": 100},
        {"map": "mp_quarry2", "gametype": "sd", "weight": 100},
        {"map": "mp_deadzone", "gametype": "sd", "weight": 100},
        {"map": "mp_euphrates", "gametype": "sd", "weight": 100},
        {"map": "mp_spear", "gametype": "sd", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "sd", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "sd", "weight": 100},
        {"map": "mp_petrograd", "gametype": "sd", "weight": 100},
        {"map": "mp_crash2", "gametype": "sd", "weight": 100},
        {"map": "mp_shipment", "gametype": "sd", "weight": 100},
        {"map": "mp_vacant", "gametype": "sd", "weight": 100},
        {"map": "mp_emporium", "gametype": "sd", "weight": 100},
        {"map": "mp_rust", "gametype": "sd", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "sd", "weight": 100},
        {"map": "mp_layover", "gametype": "sd", "weight": 100},
        {"map": "mp_hideout", "gametype": "sd", "weight": 100},
        {"map": "mp_backlot2", "gametype": "sd", "weight": 100},
        {"map": "mp_village2", "gametype": "sd", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            //  7 - Headquarters
            R"MM120(    {
      "playlist": 7,
      "name": "Headquarters",
      "description": "Quick Play - Headquarters",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "hq", "weight": 100},
        {"map": "mp_cave", "gametype": "hq", "weight": 100},
        {"map": "mp_cave_am", "gametype": "hq", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "hq", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "hq", "weight": 100},
        {"map": "mp_raid", "gametype": "hq", "weight": 100},
        {"map": "mp_runner", "gametype": "hq", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "hq", "weight": 100},
        {"map": "mp_quarry2", "gametype": "hq", "weight": 100},
        {"map": "mp_deadzone", "gametype": "hq", "weight": 100},
        {"map": "mp_euphrates", "gametype": "hq", "weight": 100},
        {"map": "mp_spear", "gametype": "hq", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "hq", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "hq", "weight": 100},
        {"map": "mp_petrograd", "gametype": "hq", "weight": 100},
        {"map": "mp_crash2", "gametype": "hq", "weight": 100},
        {"map": "mp_shipment", "gametype": "hq", "weight": 100},
        {"map": "mp_vacant", "gametype": "hq", "weight": 100},
        {"map": "mp_emporium", "gametype": "hq", "weight": 100},
        {"map": "mp_rust", "gametype": "hq", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "hq", "weight": 100},
        {"map": "mp_layover", "gametype": "hq", "weight": 100},
        {"map": "mp_hideout", "gametype": "hq", "weight": 100},
        {"map": "mp_backlot2", "gametype": "hq", "weight": 100},
        {"map": "mp_village2", "gametype": "hq", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            //  8 - Cyber Attack
            R"MM120(    {
      "playlist": 8,
      "name": "Cyber Attack",
      "description": "Quick Play - Cyber Attack",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "cyber", "weight": 100},
        {"map": "mp_cave", "gametype": "cyber", "weight": 100},
        {"map": "mp_cave_am", "gametype": "cyber", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "cyber", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "cyber", "weight": 100},
        {"map": "mp_raid", "gametype": "cyber", "weight": 100},
        {"map": "mp_runner", "gametype": "cyber", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "cyber", "weight": 100},
        {"map": "mp_quarry2", "gametype": "cyber", "weight": 100},
        {"map": "mp_deadzone", "gametype": "cyber", "weight": 100},
        {"map": "mp_euphrates", "gametype": "cyber", "weight": 100},
        {"map": "mp_spear", "gametype": "cyber", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "cyber", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "cyber", "weight": 100},
        {"map": "mp_petrograd", "gametype": "cyber", "weight": 100},
        {"map": "mp_crash2", "gametype": "cyber", "weight": 100},
        {"map": "mp_shipment", "gametype": "cyber", "weight": 100},
        {"map": "mp_vacant", "gametype": "cyber", "weight": 100},
        {"map": "mp_emporium", "gametype": "cyber", "weight": 100},
        {"map": "mp_rust", "gametype": "cyber", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "cyber", "weight": 100},
        {"map": "mp_layover", "gametype": "cyber", "weight": 100},
        {"map": "mp_hideout", "gametype": "cyber", "weight": 100},
        {"map": "mp_backlot2", "gametype": "cyber", "weight": 100},
        {"map": "mp_village2", "gametype": "cyber", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            //  9 - Gunfight
            R"MM120(    {
      "playlist": 9,
      "name": "Gunfight",
      "description": "Quick Play - Gunfight",
      "type": "mp",
      "maps": [
        {"map": "mp_m_king", "gametype": "arena", "weight": 100},
        {"map": "mp_m_overunder", "gametype": "arena", "weight": 100},
        {"map": "mp_m_pine", "gametype": "arena", "weight": 100},
        {"map": "mp_m_speedball", "gametype": "arena", "weight": 100},
        {"map": "mp_m_stack", "gametype": "arena", "weight": 100},
        {"map": "mp_m_hill", "gametype": "arena", "weight": 100},
        {"map": "mp_m_showers", "gametype": "arena", "weight": 100},
        {"map": "mp_m_cage", "gametype": "arena", "weight": 100},
        {"map": "mp_m_cargo", "gametype": "arena", "weight": 100},
        {"map": "mp_m_overwinter", "gametype": "arena", "weight": 100},
        {"map": "mp_m_fork", "gametype": "arena", "weight": 100}
      ],
      "maxparty": 2,
      "minparty": 1,
      "maxhumanplayers": 4,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 4
      }
    })MM120",

            // 10 - Gun Game
            R"MM120(    {
      "playlist": 10,
      "name": "Gun Game",
      "description": "Quick Play - Gun Game",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "gun", "weight": 100},
        {"map": "mp_cave", "gametype": "gun", "weight": 100},
        {"map": "mp_cave_am", "gametype": "gun", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "gun", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "gun", "weight": 100},
        {"map": "mp_raid", "gametype": "gun", "weight": 100},
        {"map": "mp_runner", "gametype": "gun", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "gun", "weight": 100},
        {"map": "mp_quarry2", "gametype": "gun", "weight": 100},
        {"map": "mp_deadzone", "gametype": "gun", "weight": 100},
        {"map": "mp_euphrates", "gametype": "gun", "weight": 100},
        {"map": "mp_spear", "gametype": "gun", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "gun", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "gun", "weight": 100},
        {"map": "mp_petrograd", "gametype": "gun", "weight": 100},
        {"map": "mp_crash2", "gametype": "gun", "weight": 100},
        {"map": "mp_shipment", "gametype": "gun", "weight": 100},
        {"map": "mp_vacant", "gametype": "gun", "weight": 100},
        {"map": "mp_emporium", "gametype": "gun", "weight": 100},
        {"map": "mp_rust", "gametype": "gun", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "gun", "weight": 100},
        {"map": "mp_layover", "gametype": "gun", "weight": 100},
        {"map": "mp_hideout", "gametype": "gun", "weight": 100},
        {"map": "mp_backlot2", "gametype": "gun", "weight": 100},
        {"map": "mp_village2", "gametype": "gun", "weight": 100}
      ],
      "maxparty": 1,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            // 11 - Capture the Flag
            R"MM120(    {
      "playlist": 11,
      "name": "Capture the Flag",
      "description": "Quick Play - Capture the Flag",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "ctf", "weight": 100},
        {"map": "mp_cave", "gametype": "ctf", "weight": 100},
        {"map": "mp_cave_am", "gametype": "ctf", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "ctf", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "ctf", "weight": 100},
        {"map": "mp_raid", "gametype": "ctf", "weight": 100},
        {"map": "mp_runner", "gametype": "ctf", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "ctf", "weight": 100},
        {"map": "mp_quarry2", "gametype": "ctf", "weight": 100},
        {"map": "mp_deadzone", "gametype": "ctf", "weight": 100},
        {"map": "mp_euphrates", "gametype": "ctf", "weight": 100},
        {"map": "mp_spear", "gametype": "ctf", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "ctf", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "ctf", "weight": 100},
        {"map": "mp_petrograd", "gametype": "ctf", "weight": 100},
        {"map": "mp_crash2", "gametype": "ctf", "weight": 100},
        {"map": "mp_shipment", "gametype": "ctf", "weight": 100},
        {"map": "mp_vacant", "gametype": "ctf", "weight": 100},
        {"map": "mp_emporium", "gametype": "ctf", "weight": 100},
        {"map": "mp_rust", "gametype": "ctf", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "ctf", "weight": 100},
        {"map": "mp_layover", "gametype": "ctf", "weight": 100},
        {"map": "mp_hideout", "gametype": "ctf", "weight": 100},
        {"map": "mp_backlot2", "gametype": "ctf", "weight": 100},
        {"map": "mp_village2", "gametype": "ctf", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            // 12 - Demolition
            R"MM120(    {
      "playlist": 12,
      "name": "Demolition",
      "description": "Quick Play - Demolition",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "dd", "weight": 100},
        {"map": "mp_cave", "gametype": "dd", "weight": 100},
        {"map": "mp_cave_am", "gametype": "dd", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "dd", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "dd", "weight": 100},
        {"map": "mp_raid", "gametype": "dd", "weight": 100},
        {"map": "mp_runner", "gametype": "dd", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "dd", "weight": 100},
        {"map": "mp_quarry2", "gametype": "dd", "weight": 100},
        {"map": "mp_deadzone", "gametype": "dd", "weight": 100},
        {"map": "mp_euphrates", "gametype": "dd", "weight": 100},
        {"map": "mp_spear", "gametype": "dd", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "dd", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "dd", "weight": 100},
        {"map": "mp_petrograd", "gametype": "dd", "weight": 100},
        {"map": "mp_crash2", "gametype": "dd", "weight": 100},
        {"map": "mp_shipment", "gametype": "dd", "weight": 100},
        {"map": "mp_vacant", "gametype": "dd", "weight": 100},
        {"map": "mp_emporium", "gametype": "dd", "weight": 100},
        {"map": "mp_rust", "gametype": "dd", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "dd", "weight": 100},
        {"map": "mp_layover", "gametype": "dd", "weight": 100},
        {"map": "mp_hideout", "gametype": "dd", "weight": 100},
        {"map": "mp_backlot2", "gametype": "dd", "weight": 100},
        {"map": "mp_village2", "gametype": "dd", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            // 13 - Infected
            R"MM120(    {
      "playlist": 13,
      "name": "Infected",
      "description": "Quick Play - Infected",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "infect", "weight": 100},
        {"map": "mp_cave", "gametype": "infect", "weight": 100},
        {"map": "mp_cave_am", "gametype": "infect", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "infect", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "infect", "weight": 100},
        {"map": "mp_raid", "gametype": "infect", "weight": 100},
        {"map": "mp_runner", "gametype": "infect", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "infect", "weight": 100},
        {"map": "mp_quarry2", "gametype": "infect", "weight": 100},
        {"map": "mp_deadzone", "gametype": "infect", "weight": 100},
        {"map": "mp_euphrates", "gametype": "infect", "weight": 100},
        {"map": "mp_spear", "gametype": "infect", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "infect", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "infect", "weight": 100},
        {"map": "mp_petrograd", "gametype": "infect", "weight": 100},
        {"map": "mp_crash2", "gametype": "infect", "weight": 100},
        {"map": "mp_shipment", "gametype": "infect", "weight": 100},
        {"map": "mp_vacant", "gametype": "infect", "weight": 100},
        {"map": "mp_emporium", "gametype": "infect", "weight": 100},
        {"map": "mp_rust", "gametype": "infect", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "infect", "weight": 100},
        {"map": "mp_layover", "gametype": "infect", "weight": 100},
        {"map": "mp_hideout", "gametype": "infect", "weight": 100},
        {"map": "mp_backlot2", "gametype": "infect", "weight": 100},
        {"map": "mp_village2", "gametype": "infect", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 18,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 18
      }
    })MM120",

            // 14 - Grind
            R"MM120(    {
      "playlist": 14,
      "name": "Grind",
      "description": "Quick Play - Grind",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "grind", "weight": 100},
        {"map": "mp_cave", "gametype": "grind", "weight": 100},
        {"map": "mp_cave_am", "gametype": "grind", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "grind", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "grind", "weight": 100},
        {"map": "mp_raid", "gametype": "grind", "weight": 100},
        {"map": "mp_runner", "gametype": "grind", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "grind", "weight": 100},
        {"map": "mp_quarry2", "gametype": "grind", "weight": 100},
        {"map": "mp_deadzone", "gametype": "grind", "weight": 100},
        {"map": "mp_euphrates", "gametype": "grind", "weight": 100},
        {"map": "mp_spear", "gametype": "grind", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "grind", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "grind", "weight": 100},
        {"map": "mp_petrograd", "gametype": "grind", "weight": 100},
        {"map": "mp_crash2", "gametype": "grind", "weight": 100},
        {"map": "mp_shipment", "gametype": "grind", "weight": 100},
        {"map": "mp_vacant", "gametype": "grind", "weight": 100},
        {"map": "mp_emporium", "gametype": "grind", "weight": 100},
        {"map": "mp_rust", "gametype": "grind", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "grind", "weight": 100},
        {"map": "mp_layover", "gametype": "grind", "weight": 100},
        {"map": "mp_hideout", "gametype": "grind", "weight": 100},
        {"map": "mp_backlot2", "gametype": "grind", "weight": 100},
        {"map": "mp_village2", "gametype": "grind", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            // 15 - Cranked
            R"MM120(    {
      "playlist": 15,
      "name": "Cranked",
      "description": "Quick Play - Cranked",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "cranked", "weight": 100},
        {"map": "mp_cave", "gametype": "cranked", "weight": 100},
        {"map": "mp_cave_am", "gametype": "cranked", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "cranked", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "cranked", "weight": 100},
        {"map": "mp_raid", "gametype": "cranked", "weight": 100},
        {"map": "mp_runner", "gametype": "cranked", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "cranked", "weight": 100},
        {"map": "mp_quarry2", "gametype": "cranked", "weight": 100},
        {"map": "mp_deadzone", "gametype": "cranked", "weight": 100},
        {"map": "mp_euphrates", "gametype": "cranked", "weight": 100},
        {"map": "mp_spear", "gametype": "cranked", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "cranked", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "cranked", "weight": 100},
        {"map": "mp_petrograd", "gametype": "cranked", "weight": 100},
        {"map": "mp_crash2", "gametype": "cranked", "weight": 100},
        {"map": "mp_shipment", "gametype": "cranked", "weight": 100},
        {"map": "mp_vacant", "gametype": "cranked", "weight": 100},
        {"map": "mp_emporium", "gametype": "cranked", "weight": 100},
        {"map": "mp_rust", "gametype": "cranked", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "cranked", "weight": 100},
        {"map": "mp_layover", "gametype": "cranked", "weight": 100},
        {"map": "mp_hideout", "gametype": "cranked", "weight": 100},
        {"map": "mp_backlot2", "gametype": "cranked", "weight": 100},
        {"map": "mp_village2", "gametype": "cranked", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            // 16 - Drop Zone
            R"MM120(    {
      "playlist": 16,
      "name": "Drop Zone",
      "description": "Quick Play - Drop Zone",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "grnd", "weight": 100},
        {"map": "mp_cave", "gametype": "grnd", "weight": 100},
        {"map": "mp_cave_am", "gametype": "grnd", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "grnd", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "grnd", "weight": 100},
        {"map": "mp_raid", "gametype": "grnd", "weight": 100},
        {"map": "mp_runner", "gametype": "grnd", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "grnd", "weight": 100},
        {"map": "mp_quarry2", "gametype": "grnd", "weight": 100},
        {"map": "mp_deadzone", "gametype": "grnd", "weight": 100},
        {"map": "mp_euphrates", "gametype": "grnd", "weight": 100},
        {"map": "mp_spear", "gametype": "grnd", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "grnd", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "grnd", "weight": 100},
        {"map": "mp_petrograd", "gametype": "grnd", "weight": 100},
        {"map": "mp_crash2", "gametype": "grnd", "weight": 100},
        {"map": "mp_shipment", "gametype": "grnd", "weight": 100},
        {"map": "mp_vacant", "gametype": "grnd", "weight": 100},
        {"map": "mp_emporium", "gametype": "grnd", "weight": 100},
        {"map": "mp_rust", "gametype": "grnd", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "grnd", "weight": 100},
        {"map": "mp_layover", "gametype": "grnd", "weight": 100},
        {"map": "mp_hideout", "gametype": "grnd", "weight": 100},
        {"map": "mp_backlot2", "gametype": "grnd", "weight": 100},
        {"map": "mp_village2", "gametype": "grnd", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",


            // Hardcore (40-55)

            // 40 - Team Deathmatch
            R"MM120(    {
      "playlist": 40,
      "name": "Team Deathmatch",
      "description": "Hardcore - Team Deathmatch",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "war", "weight": 100},
        {"map": "mp_cave", "gametype": "war", "weight": 100},
        {"map": "mp_cave_am", "gametype": "war", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "war", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "war", "weight": 100},
        {"map": "mp_raid", "gametype": "war", "weight": 100},
        {"map": "mp_runner", "gametype": "war", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "war", "weight": 100},
        {"map": "mp_quarry2", "gametype": "war", "weight": 100},
        {"map": "mp_deadzone", "gametype": "war", "weight": 100},
        {"map": "mp_euphrates", "gametype": "war", "weight": 100},
        {"map": "mp_spear", "gametype": "war", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "war", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "war", "weight": 100},
        {"map": "mp_petrograd", "gametype": "war", "weight": 100},
        {"map": "mp_crash2", "gametype": "war", "weight": 100},
        {"map": "mp_shipment", "gametype": "war", "weight": 100},
        {"map": "mp_vacant", "gametype": "war", "weight": 100},
        {"map": "mp_emporium", "gametype": "war", "weight": 100},
        {"map": "mp_rust", "gametype": "war", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "war", "weight": 100},
        {"map": "mp_layover", "gametype": "war", "weight": 100},
        {"map": "mp_hideout", "gametype": "war", "weight": 100},
        {"map": "mp_backlot2", "gametype": "war", "weight": 100},
        {"map": "mp_village2", "gametype": "war", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 41 - Free-for-All
            R"MM120(    {
      "playlist": 41,
      "name": "Free-for-All",
      "description": "Hardcore - Free-for-All",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "dm", "weight": 100},
        {"map": "mp_cave", "gametype": "dm", "weight": 100},
        {"map": "mp_cave_am", "gametype": "dm", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "dm", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "dm", "weight": 100},
        {"map": "mp_raid", "gametype": "dm", "weight": 100},
        {"map": "mp_runner", "gametype": "dm", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "dm", "weight": 100},
        {"map": "mp_quarry2", "gametype": "dm", "weight": 100},
        {"map": "mp_deadzone", "gametype": "dm", "weight": 100},
        {"map": "mp_euphrates", "gametype": "dm", "weight": 100},
        {"map": "mp_spear", "gametype": "dm", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "dm", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "dm", "weight": 100},
        {"map": "mp_petrograd", "gametype": "dm", "weight": 100},
        {"map": "mp_crash2", "gametype": "dm", "weight": 100},
        {"map": "mp_shipment", "gametype": "dm", "weight": 100},
        {"map": "mp_vacant", "gametype": "dm", "weight": 100},
        {"map": "mp_emporium", "gametype": "dm", "weight": 100},
        {"map": "mp_rust", "gametype": "dm", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "dm", "weight": 100},
        {"map": "mp_layover", "gametype": "dm", "weight": 100},
        {"map": "mp_hideout", "gametype": "dm", "weight": 100},
        {"map": "mp_backlot2", "gametype": "dm", "weight": 100},
        {"map": "mp_village2", "gametype": "dm", "weight": 100}
      ],
      "maxparty": 1,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 42 - Domination
            R"MM120(    {
      "playlist": 42,
      "name": "Domination",
      "description": "Hardcore - Domination",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "dom", "weight": 100},
        {"map": "mp_cave", "gametype": "dom", "weight": 100},
        {"map": "mp_cave_am", "gametype": "dom", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "dom", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "dom", "weight": 100},
        {"map": "mp_raid", "gametype": "dom", "weight": 100},
        {"map": "mp_runner", "gametype": "dom", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "dom", "weight": 100},
        {"map": "mp_quarry2", "gametype": "dom", "weight": 100},
        {"map": "mp_deadzone", "gametype": "dom", "weight": 100},
        {"map": "mp_euphrates", "gametype": "dom", "weight": 100},
        {"map": "mp_spear", "gametype": "dom", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "dom", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "dom", "weight": 100},
        {"map": "mp_petrograd", "gametype": "dom", "weight": 100},
        {"map": "mp_crash2", "gametype": "dom", "weight": 100},
        {"map": "mp_shipment", "gametype": "dom", "weight": 100},
        {"map": "mp_vacant", "gametype": "dom", "weight": 100},
        {"map": "mp_emporium", "gametype": "dom", "weight": 100},
        {"map": "mp_rust", "gametype": "dom", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "dom", "weight": 100},
        {"map": "mp_layover", "gametype": "dom", "weight": 100},
        {"map": "mp_hideout", "gametype": "dom", "weight": 100},
        {"map": "mp_backlot2", "gametype": "dom", "weight": 100},
        {"map": "mp_village2", "gametype": "dom", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 43 - Hardpoint
            R"MM120(    {
      "playlist": 43,
      "name": "Hardpoint",
      "description": "Hardcore - Hardpoint",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "koth", "weight": 100},
        {"map": "mp_cave", "gametype": "koth", "weight": 100},
        {"map": "mp_cave_am", "gametype": "koth", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "koth", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "koth", "weight": 100},
        {"map": "mp_raid", "gametype": "koth", "weight": 100},
        {"map": "mp_runner", "gametype": "koth", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "koth", "weight": 100},
        {"map": "mp_quarry2", "gametype": "koth", "weight": 100},
        {"map": "mp_deadzone", "gametype": "koth", "weight": 100},
        {"map": "mp_euphrates", "gametype": "koth", "weight": 100},
        {"map": "mp_spear", "gametype": "koth", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "koth", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "koth", "weight": 100},
        {"map": "mp_petrograd", "gametype": "koth", "weight": 100},
        {"map": "mp_crash2", "gametype": "koth", "weight": 100},
        {"map": "mp_shipment", "gametype": "koth", "weight": 100},
        {"map": "mp_vacant", "gametype": "koth", "weight": 100},
        {"map": "mp_emporium", "gametype": "koth", "weight": 100},
        {"map": "mp_rust", "gametype": "koth", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "koth", "weight": 100},
        {"map": "mp_layover", "gametype": "koth", "weight": 100},
        {"map": "mp_hideout", "gametype": "koth", "weight": 100},
        {"map": "mp_backlot2", "gametype": "koth", "weight": 100},
        {"map": "mp_village2", "gametype": "koth", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 44 - Kill Confirmed
            R"MM120(    {
      "playlist": 44,
      "name": "Kill Confirmed",
      "description": "Hardcore - Kill Confirmed",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "conf", "weight": 100},
        {"map": "mp_cave", "gametype": "conf", "weight": 100},
        {"map": "mp_cave_am", "gametype": "conf", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "conf", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "conf", "weight": 100},
        {"map": "mp_raid", "gametype": "conf", "weight": 100},
        {"map": "mp_runner", "gametype": "conf", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "conf", "weight": 100},
        {"map": "mp_quarry2", "gametype": "conf", "weight": 100},
        {"map": "mp_deadzone", "gametype": "conf", "weight": 100},
        {"map": "mp_euphrates", "gametype": "conf", "weight": 100},
        {"map": "mp_spear", "gametype": "conf", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "conf", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "conf", "weight": 100},
        {"map": "mp_petrograd", "gametype": "conf", "weight": 100},
        {"map": "mp_crash2", "gametype": "conf", "weight": 100},
        {"map": "mp_shipment", "gametype": "conf", "weight": 100},
        {"map": "mp_vacant", "gametype": "conf", "weight": 100},
        {"map": "mp_emporium", "gametype": "conf", "weight": 100},
        {"map": "mp_rust", "gametype": "conf", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "conf", "weight": 100},
        {"map": "mp_layover", "gametype": "conf", "weight": 100},
        {"map": "mp_hideout", "gametype": "conf", "weight": 100},
        {"map": "mp_backlot2", "gametype": "conf", "weight": 100},
        {"map": "mp_village2", "gametype": "conf", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 45 - Search & Destroy
            R"MM120(    {
      "playlist": 45,
      "name": "Search & Destroy",
      "description": "Hardcore - Search & Destroy",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "sd", "weight": 100},
        {"map": "mp_cave", "gametype": "sd", "weight": 100},
        {"map": "mp_cave_am", "gametype": "sd", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "sd", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "sd", "weight": 100},
        {"map": "mp_raid", "gametype": "sd", "weight": 100},
        {"map": "mp_runner", "gametype": "sd", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "sd", "weight": 100},
        {"map": "mp_quarry2", "gametype": "sd", "weight": 100},
        {"map": "mp_deadzone", "gametype": "sd", "weight": 100},
        {"map": "mp_euphrates", "gametype": "sd", "weight": 100},
        {"map": "mp_spear", "gametype": "sd", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "sd", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "sd", "weight": 100},
        {"map": "mp_petrograd", "gametype": "sd", "weight": 100},
        {"map": "mp_crash2", "gametype": "sd", "weight": 100},
        {"map": "mp_shipment", "gametype": "sd", "weight": 100},
        {"map": "mp_vacant", "gametype": "sd", "weight": 100},
        {"map": "mp_emporium", "gametype": "sd", "weight": 100},
        {"map": "mp_rust", "gametype": "sd", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "sd", "weight": 100},
        {"map": "mp_layover", "gametype": "sd", "weight": 100},
        {"map": "mp_hideout", "gametype": "sd", "weight": 100},
        {"map": "mp_backlot2", "gametype": "sd", "weight": 100},
        {"map": "mp_village2", "gametype": "sd", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 46 - Headquarters
            R"MM120(    {
      "playlist": 46,
      "name": "Headquarters",
      "description": "Hardcore - Headquarters",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "hq", "weight": 100},
        {"map": "mp_cave", "gametype": "hq", "weight": 100},
        {"map": "mp_cave_am", "gametype": "hq", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "hq", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "hq", "weight": 100},
        {"map": "mp_raid", "gametype": "hq", "weight": 100},
        {"map": "mp_runner", "gametype": "hq", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "hq", "weight": 100},
        {"map": "mp_quarry2", "gametype": "hq", "weight": 100},
        {"map": "mp_deadzone", "gametype": "hq", "weight": 100},
        {"map": "mp_euphrates", "gametype": "hq", "weight": 100},
        {"map": "mp_spear", "gametype": "hq", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "hq", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "hq", "weight": 100},
        {"map": "mp_petrograd", "gametype": "hq", "weight": 100},
        {"map": "mp_crash2", "gametype": "hq", "weight": 100},
        {"map": "mp_shipment", "gametype": "hq", "weight": 100},
        {"map": "mp_vacant", "gametype": "hq", "weight": 100},
        {"map": "mp_emporium", "gametype": "hq", "weight": 100},
        {"map": "mp_rust", "gametype": "hq", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "hq", "weight": 100},
        {"map": "mp_layover", "gametype": "hq", "weight": 100},
        {"map": "mp_hideout", "gametype": "hq", "weight": 100},
        {"map": "mp_backlot2", "gametype": "hq", "weight": 100},
        {"map": "mp_village2", "gametype": "hq", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 47 - Cyber Attack
            R"MM120(    {
      "playlist": 47,
      "name": "Cyber Attack",
      "description": "Hardcore - Cyber Attack",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "cyber", "weight": 100},
        {"map": "mp_cave", "gametype": "cyber", "weight": 100},
        {"map": "mp_cave_am", "gametype": "cyber", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "cyber", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "cyber", "weight": 100},
        {"map": "mp_raid", "gametype": "cyber", "weight": 100},
        {"map": "mp_runner", "gametype": "cyber", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "cyber", "weight": 100},
        {"map": "mp_quarry2", "gametype": "cyber", "weight": 100},
        {"map": "mp_deadzone", "gametype": "cyber", "weight": 100},
        {"map": "mp_euphrates", "gametype": "cyber", "weight": 100},
        {"map": "mp_spear", "gametype": "cyber", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "cyber", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "cyber", "weight": 100},
        {"map": "mp_petrograd", "gametype": "cyber", "weight": 100},
        {"map": "mp_crash2", "gametype": "cyber", "weight": 100},
        {"map": "mp_shipment", "gametype": "cyber", "weight": 100},
        {"map": "mp_vacant", "gametype": "cyber", "weight": 100},
        {"map": "mp_emporium", "gametype": "cyber", "weight": 100},
        {"map": "mp_rust", "gametype": "cyber", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "cyber", "weight": 100},
        {"map": "mp_layover", "gametype": "cyber", "weight": 100},
        {"map": "mp_hideout", "gametype": "cyber", "weight": 100},
        {"map": "mp_backlot2", "gametype": "cyber", "weight": 100},
        {"map": "mp_village2", "gametype": "cyber", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 48 - Gunfight
            R"MM120(    {
      "playlist": 48,
      "name": "Gunfight",
      "description": "Hardcore - Gunfight",
      "type": "mp",
      "maps": [
        {"map": "mp_m_king", "gametype": "arena", "weight": 100},
        {"map": "mp_m_overunder", "gametype": "arena", "weight": 100},
        {"map": "mp_m_pine", "gametype": "arena", "weight": 100},
        {"map": "mp_m_speedball", "gametype": "arena", "weight": 100},
        {"map": "mp_m_stack", "gametype": "arena", "weight": 100},
        {"map": "mp_m_hill", "gametype": "arena", "weight": 100},
        {"map": "mp_m_showers", "gametype": "arena", "weight": 100},
        {"map": "mp_m_cage", "gametype": "arena", "weight": 100},
        {"map": "mp_m_cargo", "gametype": "arena", "weight": 100},
        {"map": "mp_m_overwinter", "gametype": "arena", "weight": 100},
        {"map": "mp_m_fork", "gametype": "arena", "weight": 100}
      ],
      "maxparty": 2,
      "minparty": 1,
      "maxhumanplayers": 4,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 4
      }
    })MM120",

            // 49 - Gun Game
            R"MM120(    {
      "playlist": 49,
      "name": "Gun Game",
      "description": "Hardcore - Gun Game",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "gun", "weight": 100},
        {"map": "mp_cave", "gametype": "gun", "weight": 100},
        {"map": "mp_cave_am", "gametype": "gun", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "gun", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "gun", "weight": 100},
        {"map": "mp_raid", "gametype": "gun", "weight": 100},
        {"map": "mp_runner", "gametype": "gun", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "gun", "weight": 100},
        {"map": "mp_quarry2", "gametype": "gun", "weight": 100},
        {"map": "mp_deadzone", "gametype": "gun", "weight": 100},
        {"map": "mp_euphrates", "gametype": "gun", "weight": 100},
        {"map": "mp_spear", "gametype": "gun", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "gun", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "gun", "weight": 100},
        {"map": "mp_petrograd", "gametype": "gun", "weight": 100},
        {"map": "mp_crash2", "gametype": "gun", "weight": 100},
        {"map": "mp_shipment", "gametype": "gun", "weight": 100},
        {"map": "mp_vacant", "gametype": "gun", "weight": 100},
        {"map": "mp_emporium", "gametype": "gun", "weight": 100},
        {"map": "mp_rust", "gametype": "gun", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "gun", "weight": 100},
        {"map": "mp_layover", "gametype": "gun", "weight": 100},
        {"map": "mp_hideout", "gametype": "gun", "weight": 100},
        {"map": "mp_backlot2", "gametype": "gun", "weight": 100},
        {"map": "mp_village2", "gametype": "gun", "weight": 100}
      ],
      "maxparty": 1,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 50 - Capture the Flag
            R"MM120(    {
      "playlist": 50,
      "name": "Capture the Flag",
      "description": "Hardcore - Capture the Flag",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "ctf", "weight": 100},
        {"map": "mp_cave", "gametype": "ctf", "weight": 100},
        {"map": "mp_cave_am", "gametype": "ctf", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "ctf", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "ctf", "weight": 100},
        {"map": "mp_raid", "gametype": "ctf", "weight": 100},
        {"map": "mp_runner", "gametype": "ctf", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "ctf", "weight": 100},
        {"map": "mp_quarry2", "gametype": "ctf", "weight": 100},
        {"map": "mp_deadzone", "gametype": "ctf", "weight": 100},
        {"map": "mp_euphrates", "gametype": "ctf", "weight": 100},
        {"map": "mp_spear", "gametype": "ctf", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "ctf", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "ctf", "weight": 100},
        {"map": "mp_petrograd", "gametype": "ctf", "weight": 100},
        {"map": "mp_crash2", "gametype": "ctf", "weight": 100},
        {"map": "mp_shipment", "gametype": "ctf", "weight": 100},
        {"map": "mp_vacant", "gametype": "ctf", "weight": 100},
        {"map": "mp_emporium", "gametype": "ctf", "weight": 100},
        {"map": "mp_rust", "gametype": "ctf", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "ctf", "weight": 100},
        {"map": "mp_layover", "gametype": "ctf", "weight": 100},
        {"map": "mp_hideout", "gametype": "ctf", "weight": 100},
        {"map": "mp_backlot2", "gametype": "ctf", "weight": 100},
        {"map": "mp_village2", "gametype": "ctf", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 51 - Demolition
            R"MM120(    {
      "playlist": 51,
      "name": "Demolition",
      "description": "Hardcore - Demolition",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "dd", "weight": 100},
        {"map": "mp_cave", "gametype": "dd", "weight": 100},
        {"map": "mp_cave_am", "gametype": "dd", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "dd", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "dd", "weight": 100},
        {"map": "mp_raid", "gametype": "dd", "weight": 100},
        {"map": "mp_runner", "gametype": "dd", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "dd", "weight": 100},
        {"map": "mp_quarry2", "gametype": "dd", "weight": 100},
        {"map": "mp_deadzone", "gametype": "dd", "weight": 100},
        {"map": "mp_euphrates", "gametype": "dd", "weight": 100},
        {"map": "mp_spear", "gametype": "dd", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "dd", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "dd", "weight": 100},
        {"map": "mp_petrograd", "gametype": "dd", "weight": 100},
        {"map": "mp_crash2", "gametype": "dd", "weight": 100},
        {"map": "mp_shipment", "gametype": "dd", "weight": 100},
        {"map": "mp_vacant", "gametype": "dd", "weight": 100},
        {"map": "mp_emporium", "gametype": "dd", "weight": 100},
        {"map": "mp_rust", "gametype": "dd", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "dd", "weight": 100},
        {"map": "mp_layover", "gametype": "dd", "weight": 100},
        {"map": "mp_hideout", "gametype": "dd", "weight": 100},
        {"map": "mp_backlot2", "gametype": "dd", "weight": 100},
        {"map": "mp_village2", "gametype": "dd", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 52 - Infected
            R"MM120(    {
      "playlist": 52,
      "name": "Infected",
      "description": "Hardcore - Infected",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "infect", "weight": 100},
        {"map": "mp_cave", "gametype": "infect", "weight": 100},
        {"map": "mp_cave_am", "gametype": "infect", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "infect", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "infect", "weight": 100},
        {"map": "mp_raid", "gametype": "infect", "weight": 100},
        {"map": "mp_runner", "gametype": "infect", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "infect", "weight": 100},
        {"map": "mp_quarry2", "gametype": "infect", "weight": 100},
        {"map": "mp_deadzone", "gametype": "infect", "weight": 100},
        {"map": "mp_euphrates", "gametype": "infect", "weight": 100},
        {"map": "mp_spear", "gametype": "infect", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "infect", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "infect", "weight": 100},
        {"map": "mp_petrograd", "gametype": "infect", "weight": 100},
        {"map": "mp_crash2", "gametype": "infect", "weight": 100},
        {"map": "mp_shipment", "gametype": "infect", "weight": 100},
        {"map": "mp_vacant", "gametype": "infect", "weight": 100},
        {"map": "mp_emporium", "gametype": "infect", "weight": 100},
        {"map": "mp_rust", "gametype": "infect", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "infect", "weight": 100},
        {"map": "mp_layover", "gametype": "infect", "weight": 100},
        {"map": "mp_hideout", "gametype": "infect", "weight": 100},
        {"map": "mp_backlot2", "gametype": "infect", "weight": 100},
        {"map": "mp_village2", "gametype": "infect", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 18,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 18
      }
    })MM120",

            // 53 - Grind
            R"MM120(    {
      "playlist": 53,
      "name": "Grind",
      "description": "Hardcore - Grind",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "grind", "weight": 100},
        {"map": "mp_cave", "gametype": "grind", "weight": 100},
        {"map": "mp_cave_am", "gametype": "grind", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "grind", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "grind", "weight": 100},
        {"map": "mp_raid", "gametype": "grind", "weight": 100},
        {"map": "mp_runner", "gametype": "grind", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "grind", "weight": 100},
        {"map": "mp_quarry2", "gametype": "grind", "weight": 100},
        {"map": "mp_deadzone", "gametype": "grind", "weight": 100},
        {"map": "mp_euphrates", "gametype": "grind", "weight": 100},
        {"map": "mp_spear", "gametype": "grind", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "grind", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "grind", "weight": 100},
        {"map": "mp_petrograd", "gametype": "grind", "weight": 100},
        {"map": "mp_crash2", "gametype": "grind", "weight": 100},
        {"map": "mp_shipment", "gametype": "grind", "weight": 100},
        {"map": "mp_vacant", "gametype": "grind", "weight": 100},
        {"map": "mp_emporium", "gametype": "grind", "weight": 100},
        {"map": "mp_rust", "gametype": "grind", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "grind", "weight": 100},
        {"map": "mp_layover", "gametype": "grind", "weight": 100},
        {"map": "mp_hideout", "gametype": "grind", "weight": 100},
        {"map": "mp_backlot2", "gametype": "grind", "weight": 100},
        {"map": "mp_village2", "gametype": "grind", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 54 - Cranked
            R"MM120(    {
      "playlist": 54,
      "name": "Cranked",
      "description": "Hardcore - Cranked",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "cranked", "weight": 100},
        {"map": "mp_cave", "gametype": "cranked", "weight": 100},
        {"map": "mp_cave_am", "gametype": "cranked", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "cranked", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "cranked", "weight": 100},
        {"map": "mp_raid", "gametype": "cranked", "weight": 100},
        {"map": "mp_runner", "gametype": "cranked", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "cranked", "weight": 100},
        {"map": "mp_quarry2", "gametype": "cranked", "weight": 100},
        {"map": "mp_deadzone", "gametype": "cranked", "weight": 100},
        {"map": "mp_euphrates", "gametype": "cranked", "weight": 100},
        {"map": "mp_spear", "gametype": "cranked", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "cranked", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "cranked", "weight": 100},
        {"map": "mp_petrograd", "gametype": "cranked", "weight": 100},
        {"map": "mp_crash2", "gametype": "cranked", "weight": 100},
        {"map": "mp_shipment", "gametype": "cranked", "weight": 100},
        {"map": "mp_vacant", "gametype": "cranked", "weight": 100},
        {"map": "mp_emporium", "gametype": "cranked", "weight": 100},
        {"map": "mp_rust", "gametype": "cranked", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "cranked", "weight": 100},
        {"map": "mp_layover", "gametype": "cranked", "weight": 100},
        {"map": "mp_hideout", "gametype": "cranked", "weight": 100},
        {"map": "mp_backlot2", "gametype": "cranked", "weight": 100},
        {"map": "mp_village2", "gametype": "cranked", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",

            // 55 - Drop Zone
            R"MM120(    {
      "playlist": 55,
      "name": "Drop Zone",
      "description": "Hardcore - Drop Zone",
      "type": "mp",
      "maps": [
        {"map": "mp_aniyah", "gametype": "grnd", "weight": 100},
        {"map": "mp_cave", "gametype": "grnd", "weight": 100},
        {"map": "mp_cave_am", "gametype": "grnd", "weight": 100},
        {"map": "mp_hackney_am", "gametype": "grnd", "weight": 100},
        {"map": "mp_hackney_yard", "gametype": "grnd", "weight": 100},
        {"map": "mp_raid", "gametype": "grnd", "weight": 100},
        {"map": "mp_runner", "gametype": "grnd", "weight": 100},
        {"map": "mp_runner_pm", "gametype": "grnd", "weight": 100},
        {"map": "mp_quarry2", "gametype": "grnd", "weight": 100},
        {"map": "mp_deadzone", "gametype": "grnd", "weight": 100},
        {"map": "mp_euphrates", "gametype": "grnd", "weight": 100},
        {"map": "mp_spear", "gametype": "grnd", "weight": 100},
        {"map": "mp_spear_pm", "gametype": "grnd", "weight": 100},
        {"map": "mp_piccadilly", "gametype": "grnd", "weight": 100},
        {"map": "mp_petrograd", "gametype": "grnd", "weight": 100},
        {"map": "mp_crash2", "gametype": "grnd", "weight": 100},
        {"map": "mp_shipment", "gametype": "grnd", "weight": 100},
        {"map": "mp_vacant", "gametype": "grnd", "weight": 100},
        {"map": "mp_emporium", "gametype": "grnd", "weight": 100},
        {"map": "mp_rust", "gametype": "grnd", "weight": 100},
        {"map": "mp_aniyah_tac", "gametype": "grnd", "weight": 100},
        {"map": "mp_layover", "gametype": "grnd", "weight": 100},
        {"map": "mp_hideout", "gametype": "grnd", "weight": 100},
        {"map": "mp_backlot2", "gametype": "grnd", "weight": 100},
        {"map": "mp_village2", "gametype": "grnd", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 1,
        "party_maxplayers": 12
      }
    })MM120",


            // Warzone / Verdansk (70-73)

            // 70 - Battle Royale Solos
            R"MM120(    {
      "playlist": 70,
      "name": "Battle Royale Solos",
      "description": "Verdansk - Solos",
      "type": "mp",
      "maxparty": 1,
      "minparty": 1,
      "maxhumanplayers": 150,
      "dvars": {
        "scr_br_gametype": "br",
        "scr_br_teamsize": 1,
        "scr_br_plunder": 0,
        "scr_br_solo_test": 1,
        "scr_dmz_teamPlunder": 0,
        "scr_br_plunder_sites": 0,
        "scr_br_gulag": 1,
        "br_minplayers": 1,
        "live_lobby_minplayers_start": 1,
        "party_minplayers": 1,
        "party_maxplayers": 150,
        "party_maxSquadSize": 1,
        "scr_live_lobby": 1,
        "RKMMNSQKO": "mp/loot_item_defs.csv",
        "scriptable_force_large_mode": 1,
        "MQNOMMKSMM": 1,
        "LQLTOQSRNO": 0,
        "QTQRQPLNK": 1,
        "MOLPOSLOMO": "br",
        "NSQLTTMRMP": "mp_donetsk",
        "ORMSMKOKL": "br",
        "NKTMKRMSKR": "br",
        "MQSPQRQQRO": 1
      },
      "maps": [
        {"map": "mp_donetsk", "gametype": "br", "weight": 100}
      ],
      "image": "icon_mode_wz_br",
      "smallImage": "icon_mode_wz_br",
      "featuredImage": "button_offline"
    })MM120",

            // 71 - Battle Royale Duos
            R"MM120(    {
      "playlist": 71,
      "name": "Battle Royale Duos",
      "description": "Verdansk - Duos",
      "type": "mp",
      "maxparty": 2,
      "minparty": 1,
      "maxhumanplayers": 150,
      "dvars": {
        "scr_br_gametype": "br",
        "scr_br_teamsize": 2,
        "scr_br_plunder": 0,
        "scr_br_solo_test": 0,
        "scr_dmz_teamPlunder": 0,
        "scr_br_plunder_sites": 0,
        "scr_br_gulag": 1,
        "br_minplayers": 1,
        "live_lobby_minplayers_start": 1,
        "party_minplayers": 1,
        "party_maxplayers": 150,
        "party_maxSquadSize": 2,
        "scr_live_lobby": 1,
        "RKMMNSQKO": "mp/loot_item_defs.csv",
        "scriptable_force_large_mode": 1,
        "MQNOMMKSMM": 1,
        "LQLTOQSRNO": 0,
        "QTQRQPLNK": 1,
        "MOLPOSLOMO": "br",
        "NSQLTTMRMP": "mp_donetsk",
        "ORMSMKOKL": "br",
        "NKTMKRMSKR": "br",
        "MQSPQRQQRO": 1
      },
      "maps": [
        {"map": "mp_donetsk", "gametype": "br", "weight": 100}
      ],
      "image": "icon_mode_wz_br_duos",
      "smallImage": "icon_mode_wz_br_duos",
      "featuredImage": "button_offline"
    })MM120",

            // 72 - Battle Royale Trios
            R"MM120(    {
      "playlist": 72,
      "name": "Battle Royale Trios",
      "description": "Verdansk - Trios",
      "type": "mp",
      "maxparty": 3,
      "minparty": 1,
      "maxhumanplayers": 150,
      "dvars": {
        "scr_br_gametype": "br",
        "scr_br_teamsize": 3,
        "scr_br_plunder": 0,
        "scr_br_solo_test": 0,
        "scr_dmz_teamPlunder": 0,
        "scr_br_plunder_sites": 0,
        "scr_br_gulag": 1,
        "br_minplayers": 1,
        "live_lobby_minplayers_start": 1,
        "party_minplayers": 1,
        "party_maxplayers": 150,
        "party_maxSquadSize": 3,
        "scr_live_lobby": 1,
        "RKMMNSQKO": "mp/loot_item_defs.csv",
        "scriptable_force_large_mode": 1,
        "MQNOMMKSMM": 1,
        "LQLTOQSRNO": 0,
        "QTQRQPLNK": 1,
        "MOLPOSLOMO": "br",
        "NSQLTTMRMP": "mp_donetsk",
        "ORMSMKOKL": "br",
        "NKTMKRMSKR": "br",
        "MQSPQRQQRO": 1
      },
      "maps": [
        {"map": "mp_donetsk", "gametype": "br", "weight": 100}
      ],
      "image": "icon_mode_wz_br_trios",
      "smallImage": "icon_mode_wz_br_trios",
      "featuredImage": "button_offline"
    })MM120",

            // 73 - Battle Royale Quads
            R"MM120(    {
      "playlist": 73,
      "name": "Battle Royale Quads",
      "description": "Verdansk - Quads",
      "type": "mp",
      "maxparty": 4,
      "minparty": 1,
      "maxhumanplayers": 150,
      "dvars": {
        "scr_br_gametype": "br",
        "scr_br_teamsize": 4,
        "scr_br_plunder": 0,
        "scr_br_solo_test": 0,
        "scr_dmz_teamPlunder": 0,
        "scr_br_plunder_sites": 0,
        "scr_br_gulag": 1,
        "br_minplayers": 1,
        "live_lobby_minplayers_start": 1,
        "party_minplayers": 1,
        "party_maxplayers": 150,
        "party_maxSquadSize": 4,
        "scr_live_lobby": 1,
        "RKMMNSQKO": "mp/loot_item_defs.csv",
        "scriptable_force_large_mode": 1,
        "MQNOMMKSMM": 1,
        "LQLTOQSRNO": 0,
        "QTQRQPLNK": 1,
        "MOLPOSLOMO": "br",
        "NSQLTTMRMP": "mp_donetsk",
        "ORMSMKOKL": "br",
        "NKTMKRMSKR": "br",
        "MQSPQRQQRO": 1
      },
      "maps": [
        {"map": "mp_donetsk", "gametype": "br", "weight": 100}
      ],
      "image": "icon_mode_wz_br_quads",
      "smallImage": "icon_mode_wz_br_quads",
      "featuredImage": "button_offline"
    })MM120",


            // Featured Modes (90-92)

            // 90 - Shipment 24/7
            R"MM120(    {
      "playlist": 90,
      "name": "Shipment 24/7",
      "description": "Shipment 24/7 - TDM, Domination, Headquarters, Kill Confirmed and Hardpoint",
      "type": "mp",
      "maps": [
        {"map": "mp_shipment", "gametype": "war", "weight": 100},
        {"map": "mp_shipment", "gametype": "dom", "weight": 100},
        {"map": "mp_shipment", "gametype": "hq", "weight": 100},
        {"map": "mp_shipment", "gametype": "conf", "weight": 100},
        {"map": "mp_shipment", "gametype": "koth", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120",

            // 91 - Gunfight - Snipers Only
            R"MM120(    {
      "playlist": 91,
      "name": "Gunfight - Snipers Only",
      "description": "2v2 Gunfight with sniper rifles only.",
      "type": "mp",
      "maps": [
        {"map": "mp_m_king", "gametype": "arena", "weight": 100},
        {"map": "mp_m_overunder", "gametype": "arena", "weight": 100},
        {"map": "mp_m_pine", "gametype": "arena", "weight": 100},
        {"map": "mp_m_speedball", "gametype": "arena", "weight": 100},
        {"map": "mp_m_stack", "gametype": "arena", "weight": 100},
        {"map": "mp_m_hill", "gametype": "arena", "weight": 100},
        {"map": "mp_m_showers", "gametype": "arena", "weight": 100},
        {"map": "mp_m_cage", "gametype": "arena", "weight": 100},
        {"map": "mp_m_cargo", "gametype": "arena", "weight": 100},
        {"map": "mp_m_overwinter", "gametype": "arena", "weight": 100},
        {"map": "mp_m_fork", "gametype": "arena", "weight": 100}
      ],
      "maxparty": 2,
      "minparty": 1,
      "maxhumanplayers": 4,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "scr_arena_teamsize": 2,
        "scr_arena_startWeapon": "none",
        "scr_arena_weaponTier1": "rand_sniper",
        "scr_arena_weaponTier2": "rand_sniper",
        "scr_arena_weaponTier3": "rand_sniper",
        "scr_arena_weaponTier4": "rand_sniper",
        "scr_arena_weaponTier5": "rand_sniper",
        "scr_arena_weaponTier6": "rand_sniper",
        "scr_arena_weaponTier7": "rand_sniper",
        "scr_arena_weaponTier8": "rand_sniper",
        "OSMSLRTOP": 0,
        "party_maxplayers": 4
      }
    })MM120",

            // 92 - Shoot the Ship
            R"MM120(    {
      "playlist": 92,
      "name": "Shoot the Ship",
      "description": "Shoot House and Shipment mosh pit.",
      "type": "mp",
      "maps": [
        {"map": "mp_m_speed", "gametype": "war", "weight": 100},
        {"map": "mp_m_speed", "gametype": "dom", "weight": 100},
        {"map": "mp_m_speed", "gametype": "hq", "weight": 100},
        {"map": "mp_m_speed", "gametype": "conf", "weight": 100},
        {"map": "mp_m_speed", "gametype": "koth", "weight": 100},
        {"map": "mp_shipment", "gametype": "war", "weight": 100},
        {"map": "mp_shipment", "gametype": "dom", "weight": 100},
        {"map": "mp_shipment", "gametype": "hq", "weight": 100},
        {"map": "mp_shipment", "gametype": "conf", "weight": 100},
        {"map": "mp_shipment", "gametype": "koth", "weight": 100}
      ],
      "maxparty": 6,
      "minparty": 1,
      "maxhumanplayers": 12,
      "image": "filter_icon",
      "smallImage": "filter_icon",
      "dvars": {
        "OSMSLRTOP": 0,
        "party_maxplayers": 12
      }
    })MM120"

        };

        inline constexpr std::string_view CatalogSuffix = R"MM120(
  ]
}
)MM120";
    } // namespace detail

    inline std::string BuildCatalog()
    {
        std::string json;
        json.reserve(80000);
        json.append(detail::CatalogPrefix);

        for (std::size_t index = 0; index < detail::Playlists.size(); ++index)
        {
            if (index != 0)
                json.append(",\n");
            json.append(detail::Playlists[index]);
        }

        json.append(detail::CatalogSuffix);
        return json;
    }

    // Preserve the existing bridge-facing API.
    inline const std::string CatalogStorage = BuildCatalog();
    inline const std::string_view Catalog = CatalogStorage;
} // namespace revamped::iw8::matchmaking_catalog_120
