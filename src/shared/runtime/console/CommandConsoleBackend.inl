#include "../ClientIdentity.h"
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
#include "../../../clients/bo4/game/T8Runtime.h"
#include "../../../clients/bo4/game/T8Scanner.h"
#endif
#include "../scanner/UniversalScanner.h"
#include "../../../clients/coldwar/game/beta/BetaResearch.h"
#include "../../../clients/coldwar/game/beta/BetaSupport.h"
#include "../../features/camo/CamoManager.h"
#include "../../../clients/coldwar/game/T9Addresses.h"
#include "../../features/camo/CamoTextureUpload.h"
#include "../../features/LanProfileResearch.h"
#include "../../features/OnlineResearch.h"
#include "../../features/ColdWarFrontendDvars.h"
#include "../../features/CamoPrototype1.h"
#include "../../diagnostics/camo/CamoAllocatorTrace.h"
#include "../../diagnostics/RuntimeFocusTrace.h"
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
#include "../../../clients/mw2019/game/IW8ResearchScanner.h"
#include "../../../clients/mw2019/game/IW8144Compat.h"
#endif
#include "../network/UniversalLan.h"
namespace
{
    std::atomic_bool g_commandConsoleStarted{ false };
    std::atomic_bool g_commandConsoleRunning{ true };

    struct SlashCommandDescriptor
    {
        const wchar_t* name;
        const wchar_t* usage;
    };

    static const std::vector<SlashCommandDescriptor>& SlashCommandRegistry()
    {
        static const std::vector<SlashCommandDescriptor> commands = {
            { L"/help", L"/help" },
            { L"/helpscan", L"/helpscan" },
            { L"/scan", L"/scan dvar|float|int|variant|vector|lookup|command|camo" },
            { L"/scan", L"/scan beta|frontend|lua|state|auth|name|all" },
            { L"/scan", L"/scan status" },
            { L"/scan", L"/scan stop" },
            { L"/verbose", L"/verbose on|off" },
            { L"/clear", L"/clear" },
            { L"/exit", L"/exit" },

            { L"/onlinehooks", L"/onlinehooks" },
            { L"/online", L"/online status|scan" },
            { L"/tracefocus", L"/tracefocus lan|online|both|off|status|mark <label>" },
            { L"/offsets", L"/offsets" },
            { L"/map", L"/map" },
            { L"/missing", L"/missing" },
            { L"/state", L"/state" },
            { L"/network", L"/network" },
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
            { L"/iw8", L"/iw8 status|scan|frontend|lua|lan" },
            { L"/t8", L"/t8 status|scan|lua|frontend|assets|cmd <text>" },
#endif
            { L"/ulan", L"/ulan status" },
            { L"/lan", L"/lan status|menu|host|export|join <ip|CWJOIN1>|joinblob <token> [1|4]|pending|joinstate|sessionnative|maxclients <1-64>|watch|netmsg on|off|status|transcript|scan|trace|fake" },
            { L"/connect", L"/connect <LAN IPv4[:port]>" },
            { L"/profile", L"/profile status|dump|analyze|name <name>" },
            { L"/game", L"/game <command>" },
            { L"/research", L"/research [query]" },
            { L"/researchresolve", L"/researchresolve" },
            { L"/researchui", L"/researchui on|off" },
            { L"/feature", L"/feature <name|status>" },
            { L"/stages", L"/stages" },
            { L"/imgui", L"/imgui status|install|off" },
            { L"/dvars", L"/dvars [query]" },
            { L"/commands", L"/commands [query]" },
            { L"/discover", L"/discover" },

            { L"/setname", L"/setname <name>" },
            { L"/username", L"/username [name]" },
            { L"/beta", L"/beta status|scan|frontend|lua|state|auth|name|all" },
            { L"/beta", L"/beta enter mp|arena|zm|campaign|local|prelocal|servicefail|clean17" },
            { L"/beta", L"/beta read" },
            { L"/beta", L"/beta lobbyprobe [label]" },
            { L"/beta", L"/beta bigscan [label]" },
            { L"/beta", L"/beta transition <state> [arg]" },
            { L"/beta", L"/beta mode <0|1|2>" },
            { L"/beta", L"/beta session <value>" },
            { L"/beta", L"/beta setstate <A> <B> <C>" },
            { L"/beta", L"/beta cmd <native command>" },
            { L"/uscan", L"/uscan status|all|functions|lua|frontend" },
            { L"/setmap", L"/setmap <map>" },
            { L"/setgametype", L"/setgametype <gametype>" },
            { L"/setmode", L"/setmode campaign|multiplayer|mp|zombies|zm" },
            { L"/mp", L"/mp" },
            { L"/zm", L"/zm" },
            { L"/weapons", L"/weapons (show the v45 Weapons/dev-discovery workflow)" },
            { L"/menudump", L"/menudump (dump loaded Lua/LUI menu strings to logs\\menus)" },
            { L"/gsc", L"/gsc status|dump [hash-filter]|decompile [hash-filter] (built-in VM37/VM38 decompiler)" },
            { L"/unlockscan", L"/unlockscan status|run|deep (focused offline ownership/content research)" },
            { L"/devscan", L"/devscan status|commands [filter]|dvars [filter] (one-shot command/dvar/debug discovery)" },
            { L"/nativeconsole", L"/nativeconsole status|show|hide|toggle (native T9 renderer bar)" },
            { L"/menutrace", L"/menutrace on|off|status (automatic on Retail; manual override/status)" },
            { L"/openmenu", L"/openmenu <name> (direct validated LUI_OpenMenu call)" },
            { L"/menumark", L"/menumark <weapons|operators|barracks|battlepass|store|social|custom|label>" },
            { L"/hub", L"/hub mp|zm|lan mp|lan zm" },
            { L"/route", L"/route status|mark <label>" },
            { L"/lui", L"/lui status|scan|apply|restore" },
            { L"/director", L"/director status|scan" },
            { L"/nativehub", L"/nativehub status|enable|disable" },
            { L"/luibridge", L"/luibridge status|scan|load" },
            { L"/luapath", L"/luapath status|scan" },
            { L"/luactx", L"/luactx status|find|mark <label>" },
            { L"/stateedge", L"/stateedge status|mark <label>" },
            { L"/customui", L"/customui status|enable|disable" },
            { L"/luabutton", L"/luabutton status|apply|restore" },
            { L"/frontenddvars", L"/frontenddvars status|apply" },
            { L"/frontend", L"/frontend root|screen <0-64>" },
            { L"/lua", L"/lua status|dump|decompile [force]|dumpall" },
            { L"/luamenu", L"/luamenu status|setup|bridge|loadprobe" },
            { L"/lanmenu", L"/lanmenu status|setup|install|restore|open" },
            { L"/luapatch", L"/luapatch status|setup|analyze|bridge" },
            { L"/addbot", L"/addbot [count]" },
            { L"/disconnect", L"/disconnect" },
            { L"/offline", L"/offline" },
            { L"/nodw", L"/nodw on|off" },

            { L"/dvarptr", L"/dvarptr bool <address> <0|1>" },
            { L"/dvarptr", L"/dvarptr float <address> <value>" },
            { L"/dvarptr", L"/dvarptr string <address> <value>" },
            { L"/dvarlabel", L"/dvarlabel <id> <name>" },

            { L"/cg_fov", L"/cg_fov <value>" },
            { L"/window", L"/window 1|2|3" },
            { L"/mute_sound", L"/mute_sound 0|1" },
            { L"/voice_chat_enabled", L"/voice_chat_enabled 0|1" },
            { L"/microphone_activation", L"/microphone_activation 0|1" },
            { L"/subtitles", L"/subtitles 0|1" },
            { L"/intro_movie", L"/intro_movie 0|1" },

            { L"/camo", L"/camo status" },
            { L"/camo", L"/camo dump" },
            { L"/camo", L"/camo replace <targetIndex> <sourceIndex>" },
            { L"/camo", L"/camo restore <targetIndex>" },
            { L"/apply", L"/apply camo <folder>" },
            { L"/restore", L"/restore camo" },
        };
        return commands;
    }

    static bool IsRetailReleaseCommandName(const std::wstring& name)
    {
        static const wchar_t* const allowed[] = {
            L"/help", L"/network", L"/username", L"/setname",
            L"/setmode", L"/mp", L"/zm", L"/lan", L"/weapons", L"/menudump", L"/gsc", L"/unlockscan", L"/devscan", L"/nativeconsole", L"/menutrace", L"/openmenu", L"/menumark", L"/hybrid",
            L"/lua", L"/luamenu", L"/lanmenu", L"/luapatch", L"/luibridge", L"/luapath", L"/luactx", L"/stateedge", L"/customui", L"/luabutton", L"/lui",
            L"/setmap", L"/setgametype", L"/addbot",
            L"/disconnect", L"/offline", L"/apply", L"/restore",
            L"/camo", L"/clear", L"/exit"
        };
        for (const auto* item : allowed)
            if (name == item)
                return true;
        return false;
    }

    static bool IsBetaFocusedCommandName(const std::wstring& name)
    {
        // Open Beta v7 is a fully automatic, observation-only research target.
        // Keep the legacy /beta and broad scan handlers compiled but hide/block
        // them so this test cannot accidentally revive the old Beta runtime.
        static const wchar_t* const allowed[] = {
            L"/help", L"/network", L"/username", L"/setname",
            L"/clear", L"/exit"
        };
        for (const auto* item : allowed)
            if (name == item)
                return true;
        return false;
    }

    static std::vector<std::wstring> SlashCommandNames()
    {
        std::vector<std::wstring> commands;
        for (const auto& descriptor : SlashCommandRegistry())
        {
            const std::wstring name(descriptor.name);
            if (g_activeGameKind == games::GameKind::Retail &&
                !IsRetailReleaseCommandName(name))
                continue;
            if (g_activeGameKind == games::GameKind::Beta &&
                !IsBetaFocusedCommandName(name))
                continue;
            if (std::find(commands.begin(), commands.end(), name) == commands.end())
                commands.push_back(name);
        }
        return commands;
    }

    static void PrintSlashHelp()
    {
        StatusPrintf("\n[CMD] Available slash commands:\n");

        // Open Beta focused mode is fully automatic. Custom camos are Retail-only.
        // The old /beta frontend/Lua mutation commands stay compiled but dormant.
        if (g_activeGameKind == games::GameKind::Beta)
        {
            StatusPrintf("[CMD]   Service-fence memory scan is AUTOMATIC. Let the Connecting/error flow run and watch [FENCE-*].\n");
            StatusPrintf("[CMD]   FULL CMD MIRROR is ON: timeline/network/auth/candidate rows all print here for copy/paste.\n");
            StatusPrintf("[CMD]   Alpha/Season2 are semantic hints only; no foreign addresses are applied.\n");
            StatusPrintf("[CMD]   /help                    Show this list.\n");
            StatusPrintf("[CMD]   /network                 Show network-isolation status.\n");
            StatusPrintf("[CMD]   /username [name]          Show/set the player name.\n");
            StatusPrintf("[CMD]   /clear                    Clear this CMD window.\n");
            StatusPrintf("[CMD]   /exit                     Stop slash-command input; DLL stays active.\n\n");
            return;
        }

        // Retail release UI is intentionally compact. Research commands remain
        // compiled for development, but only the focused LAN scanner auto-starts.
        if (g_activeGameKind == games::GameKind::Retail)
        {
            StatusPrintf("[CMD]   /help                    Show this list.\n");
            StatusPrintf("[CMD]   /network                 Show Offline/LAN network filter status.\n");
            StatusPrintf("[CMD]   /username [name]          Show/set the player name.\n");
            StatusPrintf("[CMD]   /setmode campaign|multiplayer|mp|zombies|zm\n");
            StatusPrintf("[CMD]   /mp | /zm                Manual isolated LIVE frontend commands; never auto-run.\n[CMD]   /lan status|menu|host|export|join|joinblob|pending|joinstate|sessionnative|maxclients|watch|netmsg|transcript|scan|trace|fake  LAN tools; cw-mod-v2 descriptor join is integrated; fake browser test defaults OFF during frontend-fence isolation; use /lan fake on manually.\n[CMD]   /menudump                MANUAL: dump loaded Lua/LUI menu strings to logs\\menus.\n[CMD]   /lua status|dump|decompile [force]|dumpall  Built-in T9 LuaJIT full-pool dump + readable decompile/disassembly.\n[CMD]   /luamenu status|setup|bridge|loadprobe  Custom Lua/LUI workspace + validated bridge workflow.\n[CMD]   /lanmenu status|setup|install|restore|open  Stock root-card LAN MP/ZM patch; no Lua redump/bridge trace.\n[CMD]   /luapatch status|setup|analyze|bridge  Patch-aware Lua target mapping + local hotfix workspace.\n[CMD]   /luibridge status|scan|load | /luapath status|scan | /luactx status|find|mark <label>\n[CMD]   /customui status|enable|disable | /luabutton status|apply|restore | /lui status|scan|apply|restore\n[CMD]   /gsc status|dump [filter]|decompile [filter]  MANUAL built-in T9 VM37/VM38 dump/decompiler.\n[CMD]   /unlockscan status|run|deep  MANUAL offline ownership/content research.\n[CMD]   /devscan status|commands [filter]|dvars [filter]  MANUAL command/dvar/debug discovery.\n[CMD]   /nativeconsole status|show|hide|toggle  MANUAL native T9 renderer command bar.\n[CMD]   /menutrace on|off|status MANUAL LUI/menu tracing.\n[CMD]   /openmenu <name>         Directly open a menu after manual LUI resolver validation.\n[CMD]   /weapons                 Manual Weapons/dev-discovery workflow.\n[CMD]   /menumark <label>         Optional manual label for menu testing.\n[CMD]   /hybrid status|off        Inspect/release the local service-ready latch.\n");
            StatusPrintf("[CMD]   /setmap <map>             Set lobby map.\n");
            StatusPrintf("[CMD]   /setgametype <type>       Set lobby gametype.\n");
            StatusPrintf("[CMD]   /addbot [count]           Add bots to the current lobby.\n");
            StatusPrintf("[CMD]   /disconnect               Disconnect local client.\n");
            StatusPrintf("[CMD]   /offline                  Re-apply Offline/LAN state.\n");
            StatusPrintf("[CMD]   /apply camo <folder>      Apply a PNG/GIF camo folder.\n");
            StatusPrintf("[CMD]   /apply camo list          List available camo folders.\n");
            StatusPrintf("[CMD]   /restore camo             Restore the original camo.\n");
            StatusPrintf("[CMD]   /camo status              Show current camo backend state.\n");
            StatusPrintf("[CMD]   /camo precache [status|start]  Show/build fallback camo cache.\n");
            StatusPrintf("[CMD]   /clear                    Clear this CMD window.\n");
            StatusPrintf("[CMD]   /exit                     Stop slash-command input; DLL stays active.\n\n");
            return;
        }
        StatusPrintf("[CMD]   /help                 Show the compact client command list.\n");
        StatusPrintf("[CMD]   /helpscan             Show unified scan commands.\n");
        StatusPrintf("[CMD]   /scan <mode>          Start dvar/float/int/variant/vector/lookup/command/camo discovery.\n");
        StatusPrintf("[CMD]   /scan status|stop     Inspect or stop the active scanner.\n");
        StatusPrintf("[CMD]   /network               Show the shared public DNS/connect/sendto blocker status.\n");
        StatusPrintf("[CMD]   /username [name]       Show/set the persistent universal name (default: Revampedplayer).\n");
        StatusPrintf("[CMD]   /uscan status|all|functions|lua|frontend   Universal per-game scanner.\n");
        StatusPrintf("[CMD]   /ulan status           Show the shared Universal LAN/network-isolation layer.\n");

#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
        if (g_activeGameKind == games::GameKind::IW8)
        {
            StatusPrintf("[CMD]   /iw8 status            Show IW8 1.69 scanner status.\n");
            StatusPrintf("[CMD]   /iw8 scan              Run all IW8 frontend/Lua/LAN discovery.\n");
            StatusPrintf("[CMD]   /iw8 frontend          Scan frontend/menu strings + code xrefs.\n");
            StatusPrintf("[CMD]   /iw8 lua               Scan Lua/LUI strings + code xrefs.\n");
            StatusPrintf("[CMD]   /iw8 lan               Scan LAN/lobby/session/network strings + code xrefs.\n");
        }
#endif

        if (g_activeGameKind == games::GameKind::Retail)
        {
            StatusPrintf("[CMD]   /onlinehooks          Show analysis-only online hook candidates (runtime probes disabled).\n");
            StatusPrintf("[CMD]   /online status|scan    Read-only backend/auth/lobby/matchmaking research scanner.\n");
            StatusPrintf("[CMD]   /tracefocus lan|online|both|off|status|mark <label>   Passive runtime hit tracing for confirmed LAN/online candidates.\n");
            StatusPrintf("[CMD]   /offsets              Print the Retail live address table.\n");
            StatusPrintf("[CMD]   /map                  Print the game module memory map.\n");
            StatusPrintf("[CMD]   /missing              Retry unresolved Retail addresses.\n");
            StatusPrintf("[CMD]   /state                Print current Retail frontend/runtime/network/session state.\n");
            StatusPrintf("[CMD]   /network              Show the Retail network kill-switch status.\n");
            StatusPrintf("[CMD]   /lan status|menu|host|export|join|joinblob|pending|joinstate|sessionnative|maxclients|watch|netmsg|transcript|scan|trace|fake   LAN/System Link + cw-mod-v2 descriptor commands.\n");
            StatusPrintf("[CMD]   /connect <LAN IPv4[:port]>   Send the native connect command to a private/LAN host and enable passive LAN packet tracing.\n");
            StatusPrintf("[CMD]   /profile status|dump|analyze|name <name>   Profile research/test commands.\n");
            StatusPrintf("[CMD]   /setname <name>        Alias for /username; saved in the active game INI under Documents\\CodRevamped.\n");
            StatusPrintf("[CMD]   /setmap <map>          Set the controlling lobby map.\n");
            StatusPrintf("[CMD]   /setgametype <type>    Set lobby and gametype settings.\n");
            StatusPrintf("[CMD]   /setmode campaign|multiplayer|mp|zombies|zm   Retail MP/ZM holds isolated LIVE frontend semantics; public COD/Demonware traffic stays blocked.\n");
            StatusPrintf("[CMD]   /mp | /zm             Enter the isolated LIVE MP/ZM frontend; public COD/Demonware networking stays blocked.\n");
            StatusPrintf("[CMD]   /menumark <label>      Mark the next online-menu click for focused tracing (broad scanners stay paused).\n");
            StatusPrintf("[CMD]   /addbot [count]        Add 1-17 bots to the current lobby.\n");
            StatusPrintf("[CMD]   /disconnect            Disconnect the local client.\n");
            StatusPrintf("[CMD]   /offline               Re-apply LAN/offline state without disabling startup automation.\n");
            StatusPrintf("[CMD]   /nodw on|off           Toggle the verified dvar_noDW pointer.\n");
            StatusPrintf("[CMD]   /dvarptr bool <hexptr> <0|1>   Set a captured bool dvar pointer.\n");
            StatusPrintf("[CMD]   /dvarptr string <hexptr> <text> Set a captured string dvar pointer.\n");
            StatusPrintf("[CMD]   /dvarlabel <id> <label> Persist a human-readable label for a captured DVAR ID.\n");
            StatusPrintf("[CMD]   /cg_fov <value>        Set cg_fov to any finite float; expands a uniquely detected FOV domain.\n");
            StatusPrintf("[CMD]   /window 1|2|3         1=windowed, 2=fullscreen, 3=windowed fullscreen.\n");
            StatusPrintf("[CMD]   /mute_sound 0|1        Toggle mute sound.\n");
            StatusPrintf("[CMD]   /voice_chat_enabled 0|1 Toggle voice chat.\n");
            StatusPrintf("[CMD]   /microphone_activation 0|1 Toggle microphone activation.\n");
            StatusPrintf("[CMD]   /subtitles 0|1         Toggle subtitles.\n");
            StatusPrintf("[CMD]   /intro_movie 0|1       Toggle introduction movies.\n");
            StatusPrintf("[CMD]   /camo status            Show weapon-features/camo/binding/material/image pool state.\n");
            StatusPrintf("[CMD]   /camo prototype [status|create|reset] | /camo research [status|writers|functions|restart|stop]   10-minute capture auto-starts after stable executable detection; registration report is generated immediately.\n");
            StatusPrintf("[CMD]   /camo dump              Dump parsed weapon-camo pool fields.\n");
            StatusPrintf("[CMD]   /camo inspect           Follow binding +0x10 objects and indirect material pointers; watch menu->game transitions.\n");
            StatusPrintf("[CMD]   /camo replace <target> <source>  Replace a target camo slot with an existing source definition.\n");
            StatusPrintf("[CMD]   /camo restore <target>  Restore a camo slot changed during this run.\n");
            StatusPrintf("[CMD]   /apply camo <folder>    Apply GIF or PNG; PNG can animate from animation.json level0.scroll (GIF priority).\n");
            StatusPrintf("[CMD]   /apply camo list        List GIF/PNG camo folders (GIF priority; Info.txt disabled).\n");
            StatusPrintf("[CMD]   /restore camo           Stop custom animation and restore the original camo.\n");
            StatusPrintf("[CMD]   /camo precache [status|start]  Prebuild 2048/1024/512/256 BC7 caches.\n");
            StatusPrintf("[CMD]   /camo custom list       Read custom camo packages from the game Camos folder.\n");
            StatusPrintf("[CMD]   /camo custom inspect <name>  Show one custom camo package.\n");
            StatusPrintf("[CMD]   /camo custom stage <name> <target>  Validate/stage custom camo files for a slot.\n");
            StatusPrintf("[CMD]   /camo custom apply <name> <target>  HQ BC7 upload to GfxImage 23956; multi-frame GIFs animate live.\n");
            StatusPrintf("[CMD]   /camo custom restore <target>  Restore the original confirmed color texture or legacy proof pointers.\n");
            StatusPrintf("[CMD]   /camo custom analyze <target>  Dump exact GfxImage candidates/records for one camo.\n");
            StatusPrintf("[CMD]   /camo custom test <target> <candidate>  Patch ONE image reference to donor image #4.\n");
            StatusPrintf("[CMD]   /camo custom testrestore <target>  Restore active next/prev or raw test; kept role stays saved.\n");
            StatusPrintf("[CMD]   /camo custom next <target>     Test the next prioritized image group.\n");
            StatusPrintf("[CMD]   /camo custom prev <target>     Test the previous prioritized image group.\n");
            StatusPrintf("[CMD]   /camo custom status <target>   Show current image-test candidate.\n");
            StatusPrintf("[CMD]   /camo custom keep <target> [role]  Mark current candidate (default role=color).\n");
            StatusPrintf("[CMD]   /dvarptr float <hexptr> <value> Set a captured float dvar through the labeled T9 retail setter.\n");
            StatusPrintf("[CMD]   /game <command>        Send a command through the Retail command path.\n");
            StatusPrintf("[CMD]   /research [query]      Search the version-tagged research catalog.\n");
            StatusPrintf("[CMD]   /researchresolve       Re-run analysis-only signature validation.\n");
            StatusPrintf("[CMD]   /discover              Probe known command/dvar names against this build.\n");
            StatusPrintf("[CMD]   /dvars [query]         List discovered live dvars.\n");
            StatusPrintf("[CMD]   /commands [query]      List known command candidates.\n");
            StatusPrintf("[CMD]   /researchui on|off     Toggle the optional ImGui diagnostics panel.\n");
            StatusPrintf("[CMD]   /feature <name|status> Toggle offline local-match features (noclip/god/ufo/notarget).\n");
            StatusPrintf("[CMD]   /stages               Show isolated runtime-stage status.\n");
            StatusPrintf("[CMD]   /imgui status|install|off   Inspect or retry the optional overlay stage.\n");
        }
        else if (g_activeGameKind == games::GameKind::Alpha)
        {
            StatusPrintf("[CMD]   /alpha status|frontend|zombies|multiplayer|disconnect   Legacy Alpha controls.\n");
            StatusPrintf("[CMD]   /setmode mp|zm         Use scanner-validated MP/ZM frontend semantics while preserving Offline/LAN network state.\n");
        }
        else if (g_activeGameKind == games::GameKind::Beta)
        {
            StatusPrintf("[CMD]   /beta status|scan|frontend|lua|state|auth|name|all   Open Beta research scanner.\n");
            StatusPrintf("[CMD]   /beta read             Read recovered frontend A/B/C + ready state.\n");
            StatusPrintf("[CMD]   /beta lobbyprobe [label]  Fast read-only Lobby/LUI/session runtime probe.\n");
            StatusPrintf("[CMD]   /beta bigscan [label]  Start the slower exhaustive Beta memory census.\n");
            StatusPrintf("[CMD]   /beta enter mp|arena|zm|campaign   Attempt recovered LOCAL frontend mode entry.\n");
            StatusPrintf("[CMD]   /beta enter prelocal|servicefail|clean17   Reproduce/test recovered disconnect tuples.\n");
            StatusPrintf("[CMD]   /beta transition <state> [arg]     Call recovered SetScreen/transition directly (hex accepted).\n");
            StatusPrintf("[CMD]   /beta mode <0|1|2>     Call recovered Com_SessionMode_SetMode/initA: 0=ZM 1=MP 2=Campaign.\n");
            StatusPrintf("[CMD]   /beta session <value>  Call recovered LobbyBase_SetNetworkMode/initB: 1=LAN 2=LIVE.\n");
            StatusPrintf("[CMD]   /beta setstate <A> <B> <C>   Write recovered frontend globals for testing.\n");
            StatusPrintf("[CMD]   /beta cmd <text>       Send text through the recovered Beta Command/Cbuf path.\n");
            StatusPrintf("[CMD]   /setmode mp|zm         Hold LIVE frontend semantics under the public-network blocker using current-build resolved addresses only.\n");
        }
        StatusPrintf("[CMD]   /verbose on|off        Enable or hide verbose scanner output.\n");
        StatusPrintf("[CMD]   /clear                 Clear this CMD window.\n");
        StatusPrintf("[CMD]   /exit                  Stop slash-command input; DLL stays active.\n");
        StatusPrintf("[CMD] TAB completes/cycles command names. In-game T9 console handles its own suggestions.\n\n");
    }

    static void PrintScanHelp()
    {
        StatusPrintf("\n[SCAN] Unified discovery commands:\n");
        StatusPrintf("[SCAN]   /scan dvar       Broad dvar/name scan and live setter capture.\n");
        StatusPrintf("[SCAN]   /scan float      Observe float setter candidates.\n");
        StatusPrintf("[SCAN]   /scan int        Observe integer and enum setter candidates.\n");
        StatusPrintf("[SCAN]   /scan variant    Observe generic Dvar_SetVariant candidates.\n");
        StatusPrintf("[SCAN]   /scan vector     Observe vec2/vec3/vec4 setter candidates.\n");
        StatusPrintf("[SCAN]   /scan lookup     Observe Dvar_FindVar/hash lookup candidates.\n");
        StatusPrintf("[SCAN]   /scan command    Observe command registration/execution candidates. Manual only.\n");
        StatusPrintf("[SCAN]   /scan camo       Fast camo scan + targeted snapshots. Use /scan camo deep for full heap/index discovery.\n");
        StatusPrintf("[SCAN]   /scan beta|frontend|lua|state|auth|name|all   Exact Open Beta read-only research scanner.\n");
        StatusPrintf("[SCAN]   /scan status     Show the currently active dedicated probe and broad dvar capture.\n");
        StatusPrintf("[SCAN]   /scan stop       Stop the active dedicated probe and broad dvar scan/capture.\n");
        StatusPrintf("[SCAN] Only one dedicated probe runs at a time; confirmed always-on setter hooks remain independent.\n\n");
    }

    static void PrintCurrentState()
    {
        StatusPrintf("[STATE] -------- current retail state --------\n");
        auto read32 = [](uintptr_t address, unsigned int& value) -> bool
        {
            SIZE_T got = 0;
            return address && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                &value, sizeof(value), &got) && got == sizeof(value);
        };
        auto read8 = [](uintptr_t address, unsigned char& value) -> bool
        {
            SIZE_T got = 0;
            return address && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                &value, sizeof(value), &got) && got == sizeof(value);
        };

        unsigned int value32 = 0;
        unsigned char value8 = 0;
        if (read32(g_Addrs.s_uiScreen, value32)) StatusPrintf("[STATE] s_uiScreen        = 0x%X\n", value32);
        if (read32(g_Addrs.s_networkMode, value32)) StatusPrintf("[STATE] s_networkMode     = 0x%X\n", value32);
        if (read32(g_Addrs.sSessionModeState, value32)) StatusPrintf("[STATE] sessionModeState  = 0x%X\n", value32);
        if (read32(g_Addrs.config[0], value32)) StatusPrintf("[STATE] config[0]         = 0x%X\n", value32);
        if (read8(g_Addrs.s_inited, value8)) StatusPrintf("[STATE] s_inited          = 0x%X\n", value8);
        StatusPrintf("[STATE] offline addresses = %s\n", called_once ? "applied" : "not applied");
    }

    static void PrintLoadedModulesForScan()
    {
        StatusPrintf("[MEMSCAN] -------- loaded process modules --------\n");
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE) { StatusPrintf("[MEMSCAN] module snapshot failed (%lu).\n", GetLastError()); return; }
        MODULEENTRY32W module{}; module.dwSize = sizeof(module);
        unsigned int count = 0;
        if (Module32FirstW(snapshot, &module))
        {
            do
            {
                char name[MAX_PATH]{}; char path[MAX_PATH * 2]{};
                WideCharToMultiByte(CP_UTF8, 0, module.szModule, -1, name, sizeof(name), nullptr, nullptr);
                WideCharToMultiByte(CP_UTF8, 0, module.szExePath, -1, path, sizeof(path), nullptr, nullptr);
                StatusPrintf("[MEMSCAN] MODULE %03u base=%p size=0x%08lX name=%s path=%s\n", count++, module.modBaseAddr, module.modBaseSize, name, path);
            } while (Module32NextW(snapshot, &module));
        }
        CloseHandle(snapshot);
        StatusPrintf("[MEMSCAN] loaded modules complete: %u module(s).\n", count);
    }

    static void PrintProcessThreadsForScan()
    {
        StatusPrintf("[MEMSCAN] -------- process threads --------\n");
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) { StatusPrintf("[MEMSCAN] thread snapshot failed (%lu).\n", GetLastError()); return; }
        THREADENTRY32 thread{}; thread.dwSize = sizeof(thread);
        unsigned int count = 0;
        if (Thread32First(snapshot, &thread))
        {
            do
            {
                if (thread.th32OwnerProcessID == GetCurrentProcessId())
                    StatusPrintf("[MEMSCAN] THREAD %03u tid=%lu basePriority=%ld deltaPriority=%ld\n", count++, thread.th32ThreadID, thread.tpBasePri, thread.tpDeltaPri);
            } while (Thread32Next(snapshot, &thread));
        }
        CloseHandle(snapshot);
        StatusPrintf("[MEMSCAN] process threads complete: %u thread(s).\n", count);
    }

    static void SaveConsoleTranscript(COORD start, const char* fileName)
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO info{};
        if (output == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(output, &info)) return;
        FILE* file = nullptr;
        if (fopen_s(&file, fileName, "wb") != 0 || !file) return;
        const SHORT width = info.dwSize.X;
        std::vector<char> row(static_cast<size_t>(width) + 1);
        const SHORT endY = info.dwCursorPosition.Y;
        for (SHORT y = start.Y; y <= endY; ++y)
        {
            DWORD read = 0;
            COORD position{0, y};
            if (!ReadConsoleOutputCharacterA(output, row.data(), width, position, &read)) continue;
            while (read && row[read - 1] == ' ') --read;
            if (read) fwrite(row.data(), 1, read, file);
            fwrite("\r\n", 1, 2, file);
        }
        fclose(file);
    }


    static DWORD WINAPI ManualMemscanThread(LPVOID) { StatusPrintf("[MEMSCAN] In-process scanning is disabled. Use IWScanner.exe.\n"); return 0; }
    static DWORD WINAPI StringScanThread(LPVOID) { StatusPrintf("[SCAN] In-process scanning is disabled. Use IWScanner.exe.\n"); return 0; }

    static bool ParsePointerArgument(const std::string& text, uintptr_t& value)
    {
        if (text.empty())
            return false;
        char* end = nullptr;
        errno = 0;
        const unsigned long long parsed = _strtoui64(text.c_str(), &end, 0);
        if (errno != 0 || !end || *end != '\0' || parsed == 0)
            return false;
        value = static_cast<uintptr_t>(parsed);
        MEMORY_BASIC_INFORMATION mbi{};
        return VirtualQuery(reinterpret_cast<const void*>(value), &mbi, sizeof(mbi)) != 0 &&
            mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && mbi.Protect != PAGE_NOACCESS;
    }

    static std::string ReadRemainingArgument(std::istringstream& input)
    {
        std::string value;
        std::getline(input, value);
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
            value.erase(value.begin());
        return value;
    }

    static bool SetNoDemonwareValue(bool enabled)
    {
        if (!g_Addrs.dvar_noDW || !g_Addrs.Dvar_SetBoolFromSource)
            return false;
        uintptr_t dvar = 0;
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(g_Addrs.dvar_noDW),
            &dvar, sizeof(dvar), &got) || got != sizeof(dvar) || !dvar)
            return false;
        Dvar_SetBoolFromSource(dvar, enabled, 0);
        return true;
    }

    static void ExecuteSlashCommand(const std::wstring& line)
    {
        std::string utf8;
        if (!line.empty())
        {
            const int needed = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (needed > 1)
            {
                utf8.resize(static_cast<size_t>(needed));
                WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, utf8.data(), needed, nullptr, nullptr);
                if (!utf8.empty() && utf8.back() == '\0') utf8.pop_back();
            }
        }

        if (!utf8.empty())
            StatusPrintf("[CMD] > %s\n", utf8.c_str());

        std::istringstream input(utf8);
        std::string command;
        input >> command;
        std::transform(command.begin(), command.end(), command.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        // Retail release mode intentionally exposes only the Offline/LAN + camo
        // surface. Keep the development/research implementation compiled so it
        // can return later, but do not allow a release user to accidentally kick
        // off the broad Lua/GSC/xref/online scanners that caused startup races.
        if (g_activeGameKind == games::GameKind::Retail)
        {
            std::wstring commandWide(command.begin(), command.end());
            if (!IsRetailReleaseCommandName(commandWide))
            {
                StatusPrintf("[RELEASE] Command disabled. This build exposes only Offline/LAN and custom-camo controls.\n");
                return;
            }
        }
        else if (g_activeGameKind == games::GameKind::Beta)
        {
            std::wstring commandWide(command.begin(), command.end());
            if (!IsBetaFocusedCommandName(commandWide))
            {
                StatusPrintf("[BETA] Manual command disabled. Offline/LAN address + service-fence scanning runs automatically; custom camos are Retail-only.\n");
                return;
            }
        }

        if (command == "/help" || command == "/?")
            PrintSlashHelp();
        else if (command == "/helpscan")
            PrintScanHelp();
        else if (command == "/scan")
        {
            std::string mode;
            input >> mode;
            std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });

            std::string extra;
            std::getline(input, extra);
            while (!extra.empty() && std::isspace(static_cast<unsigned char>(extra.front())))
                extra.erase(extra.begin());

            if (mode.empty())
            {
                PrintScanHelp();
            }
            else if (!extra.empty())
            {
                StatusPrintf("[CMD] FAILED: /scan %s does not take extra options. Use /helpscan.\n", mode.c_str());
            }
            else if (mode == "status")
            {
                universal_scanner::PrintStatus();
                if (g_activeGameKind == games::GameKind::Beta)
                    beta_research::PrintStatus();
                if (g_activeGameKind == games::GameKind::Retail)
                {
                    PrintRuntimeDiscoveryStatus();
                    t9_dvars::PrintProbeStatus();
                    t9_dvars::PrintLiveCaptureStatus();
                }
            }
            else if (g_activeGameKind == games::GameKind::Beta &&
                     (mode == "beta" || mode == "all" || mode == "functions" ||
                      mode == "lua" || mode == "frontend" || mode == "state" ||
                      mode == "auth" || mode == "name"))
            {
                std::string message;
                const std::string betaMode = mode == "functions" ? "all" : mode;
                const bool ok = beta_research::RunManual(betaMode, message);
                StatusPrintf("[BETA-SCAN] %s: %s\n", ok ? "complete" : "failed", message.c_str());
            }
            else if (mode == "all" || mode == "functions" || mode == "lua" || mode == "frontend")
            {
                std::string message;
                bool ok = false;
                if (mode == "all") ok = universal_scanner::RunAll(message);
                else if (mode == "functions") ok = universal_scanner::RunFunctions(message);
                else if (mode == "lua") ok = universal_scanner::RunLua(message);
                else ok = universal_scanner::RunFrontend(message);
                StatusPrintf("[UNIVERSAL-SCAN] %s: %s\n", ok ? "complete" : "failed", message.c_str());
            }
            else if (mode == "stop")
            {
                StopRuntimeDiscovery();
                t9_dvars::StopProbe();
                t9_dvars::StopLiveCapture();
                StatusPrintf("[CMD] OK: Active scan, dedicated probe, and live dvar capture stop requested.\n");
            }
            else if (mode == "camo")
            {
                if (g_activeGameKind != games::GameKind::Retail)
                {
                    StatusPrintf(
                        "[CMD] FAILED: /scan camo currently requires the Retail T9 profile.\n");
                }
                else
                {
                    std::string slotMessage;

                    std::string camoMode;
                    input >> camoMode;
                    std::transform(camoMode.begin(), camoMode.end(), camoMode.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    const bool deep = camoMode == "deep";
                    if (!camoMode.empty() && !deep)
                    {
                        StatusPrintf("[CAMO-SCAN] FAILED: usage: /scan camo [deep]\n");
                        return;
                    }
                    const bool ok =
                        camo_manager::ScanCamo(
                            slotMessage,
                            deep);

                    StatusPrintf(
                        ok
                        ? "[CAMO-SCAN] OK: %s\n"
                        : "[CAMO-SCAN] FAILED: %s\n",
                        slotMessage.c_str());
                }
            }
            else if (mode == "dvar")
            {
                if (!t9_dvars::IsLiveCaptureRunning())
                    t9_dvars::StartLiveCapture();
                StartRuntimeDiscovery("dvar", "");
                StatusPrintf("[CMD] OK: Broad dvar discovery started.\n");
            }
            else if (mode == "float" || mode == "int" || mode == "variant" ||
                     mode == "vector" || mode == "lookup" || mode == "command")
            {
                if (t9_dvars::StartProbe(mode))
                    StatusPrintf("[CMD] OK: %s probe started. Use /scan status or /scan stop.\n", mode.c_str());
                else
                    StatusPrintf("[CMD] FAILED: %s probe could not start; another dedicated probe is already active or candidates are invalid.\n", mode.c_str());
            }
            else
            {
                StatusPrintf("[CMD] FAILED: Usage: /scan beta|all|functions|lua|frontend|state|auth|name|dvar|float|int|variant|vector|lookup|command|camo [deep]|status|stop\n");
            }
        }
        else if (command == "/tracefocus" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (sub == "lan" || sub == "online" || sub == "both")
            {
                runtime_focus_trace::Mode mode =
                    sub == "lan"
                        ? runtime_focus_trace::Mode::Lan
                        : sub == "online"
                            ? runtime_focus_trace::Mode::Online
                            : runtime_focus_trace::Mode::Both;

                std::string message;
                const bool ok =
                    runtime_focus_trace::Start(mode, message);
                StatusPrintf(ok
                    ? "[FOCUS] OK: %s\n"
                    : "[FOCUS] FAILED: %s\n",
                    message.c_str());
            }
            else if (sub == "off" || sub == "stop")
            {
                std::string message;
                runtime_focus_trace::Stop(message);
                StatusPrintf("[FOCUS] %s\n", message.c_str());
            }
            else if (sub == "status" || sub.empty())
            {
                StatusPrintf("[FOCUS] %s\n",
                    runtime_focus_trace::Status().c_str());
            }
            else if (sub == "mark")
            {
                std::string label;
                std::getline(input >> std::ws, label);
                if (label.empty())
                    label = "manual";
                runtime_focus_trace::Mark(label);
                StatusPrintf("[FOCUS] mark added: %s\n",
                    label.c_str());
            }
            else
            {
                StatusPrintf("[FOCUS] Usage: /tracefocus lan|online|both|off|status|mark <label>\n");
            }
        }
        else if (command == "/online" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (sub.empty() || sub == "status")
            {
                StatusPrintf("[ONLINE] %s\n", online_research::Status().c_str());
            }
            else if (sub == "scan")
            {
                std::string message;
                const bool ok = online_research::Scan(message);
                StatusPrintf(ok
                    ? "[ONLINE-SCAN] OK: %s\n"
                    : "[ONLINE-SCAN] FAILED: %s\n",
                    message.c_str());
            }
            else
            {
                StatusPrintf("[ONLINE] Usage: /online status|scan\n");
            }
        }
        else if (command == "/onlinehooks" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string mode; input >> mode;
            std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (mode == "off") RemoveOnlineTraceHooks();
            else
            {
                PrintOnlineTraceHookStatus();
                StatusPrintf("[ONLINE-HOOK] Runtime arming is disabled because the previous INT3 probes crashed retail.\n");
            }
        }
        else if (command == "/alpha" && g_activeGameKind == games::GameKind::Alpha)
        {
            std::string mode; input >> mode;
            std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (mode.empty() || mode == "status")
            {
                StatusPrintf("[ALPHA] Legacy Open Beta support: %s.\n",
                    alpha_support::IsSupported() ? "available" : "not available for this executable");
            }
            else if (mode == "frontend")
            {
                StatusPrintf("[ALPHA] Frontend transition %s.\n",
                    alpha_support::EnterFrontend() ? "applied" : "failed validation or execution");
            }
            else if (mode == "zombies" || mode == "zm")
            {
                StatusPrintf("[ALPHA] Zombies mode transition %s.\n",
                    alpha_support::SwitchZombies() ? "applied" : "failed validation or execution");
            }
            else if (mode == "multiplayer")
            {
                StatusPrintf("[ALPHA] Multiplayer state restore %s.\n",
                    alpha_support::RestoreMultiplayer() ? "applied" : "failed (original state was not captured)");
            }
            else if (mode == "disconnect")
            {
                StatusPrintf("[ALPHA] Disconnect command %s.\n",
                    alpha_support::Disconnect() ? "sent" : "failed validation or execution");
            }
            else
                StatusPrintf("[CMD] Usage: /alpha status|frontend|zombies|mp|disconnect\n");
        }
        else if (command == "/beta" && g_activeGameKind == games::GameKind::Beta)
        {
            std::string mode; input >> mode;
            std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (mode.empty() || mode == "status")
            {
                beta_research::PrintStatus();
                std::string frontendMessage;
                if (beta_support::ExecuteFrontendControl("read", "", frontendMessage))
                    StatusPrintf("[BETA-FRONTEND] %s\n", frontendMessage.c_str());
            }
            else if (mode == "scan" || mode == "beta" || mode == "all" ||
                     mode == "frontend" || mode == "lua" || mode == "state" ||
                     mode == "auth" || mode == "name")
            {
                std::string message;
                const std::string betaMode = (mode == "scan" || mode == "beta") ? "all" : mode;
                const bool ok = beta_research::RunManual(betaMode, message);
                StatusPrintf("[BETA-SCAN] %s: %s\n", ok ? "complete" : "failed", message.c_str());
            }
            else if (mode == "read" || mode == "lobbyprobe" || mode == "lobbyscan" || mode == "initprobe" ||
                     mode == "bigscan" || mode == "memscan" || mode == "fullscan" ||
                     mode == "enter" || mode == "transition" ||
                     mode == "mode" || mode == "gamemode" || mode == "session" ||
                     mode == "setstate" || mode == "cmd" || mode == "gamecmd" ||
                     mode == "mp" || mode == "mpoffline" || mode == "arena" ||
                     mode == "mparena" || mode == "mparenaoffline" || mode == "zm" ||
                     mode == "zombies" || mode == "zmoffline" || mode == "campaign" ||
                     mode == "local" || mode == "prelocal" || mode == "servicefail" ||
                     mode == "failure17" || mode == "clean17" || mode == "disconnect17" ||
                     mode == "cleandisconnect")
            {
                std::string args;
                std::getline(input, args);
                while (!args.empty() && std::isspace(static_cast<unsigned char>(args.front())))
                    args.erase(args.begin());

                std::string message;
                const bool ok = beta_support::ExecuteFrontendControl(mode, args, message);
                StatusPrintf("[BETA-FRONTEND] %s: %s\n", ok ? "OK" : "FAILED", message.c_str());
            }
            else
            {
                StatusPrintf("[CMD] /beta scanner: status|scan|frontend|lua|state|auth|name|all\n");
                StatusPrintf("[CMD] /beta frontend: read | lobbyprobe [label] | bigscan [label] | enter mp|arena|zm|campaign|local\n");
                StatusPrintf("[CMD]                 prelocal|servicefail|clean17 (legacy error-path tests; do not use for normal MP)\n");
                StatusPrintf("[CMD]                 transition <state> [arg] | mode <0|1|2> | session <value>\n");
                StatusPrintf("[CMD]                 setstate <A> <B> <C> | cmd <native command>\n");
            }
        }
        else if (command == "/setname" || command == "/username")
        {
            const std::string name = ReadRemainingArgument(input);
            if (name.empty())
            {
                client_identity::PrintStatus(g_activeGameKind);
            }
            else
            {
                std::string message;
                client_identity::SetAndApply(g_activeGameKind, name, message);
                StatusPrintf("[IDENTITY] %s\n", message.c_str());
            }
        }
        else if (command == "/uscan")
        {
            std::string sub; input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (g_activeGameKind == games::GameKind::Beta)
            {
                if (sub.empty() || sub == "status") beta_research::PrintStatus();
                else
                {
                    std::string message;
                    const std::string betaMode = sub == "functions" ? "all" : sub;
                    const bool ok = beta_research::RunManual(betaMode, message);
                    StatusPrintf("[BETA-SCAN] %s: %s\n", ok ? "complete" : "failed", message.c_str());
                }
            }
            else if (sub.empty() || sub == "status") universal_scanner::PrintStatus();
            else
            {
                std::string message;
                bool ok = false;
                if (sub == "all") ok = universal_scanner::RunAll(message);
                else if (sub == "functions") ok = universal_scanner::RunFunctions(message);
                else if (sub == "lua") ok = universal_scanner::RunLua(message);
                else if (sub == "frontend") ok = universal_scanner::RunFrontend(message);
                else { StatusPrintf("[CMD] Usage: /uscan status|all|functions|lua|frontend\n"); return; }
                StatusPrintf("[UNIVERSAL-SCAN] %s: %s\n", ok ? "complete" : "failed", message.c_str());
            }
        }
        else if (command == "/setmap" && g_activeGameKind == games::GameKind::Retail)
        {
            const std::string map = ReadRemainingArgument(input);
            if (map.empty()) StatusPrintf("[CMD] FAILED: Usage: /setmap <map>\n");
            else if (!g_Addrs.LobbySession_GetControllingLobbySession || !g_Addrs.LobbyData_SetMap)
                StatusPrintf("[CMD] FAILED: Map functions are unresolved.\n");
            else
            {
                const int lobby = LobbySession_GetControllingLobbySession(0);
                if (!lobby)
                    StatusPrintf("[CMD] FAILED: No controlling lobby session is available.\n");
                else
                {
                    LobbyData_SetMap(lobby, map.c_str());
                    StatusPrintf("[CMD] OK: Lobby map set to %s (lobby=%d).\n", map.c_str(), lobby);
                }
            }
        }
        else if (command == "/setgametype" && g_activeGameKind == games::GameKind::Retail)
        {
            const std::string gametype = ReadRemainingArgument(input);
            if (gametype.empty()) StatusPrintf("[CMD] FAILED: Usage: /setgametype <gametype>\n");
            else if (!g_Addrs.Com_GametypeSettings_SetGametype)
                StatusPrintf("[CMD] FAILED: Gametype function is unresolved.\n");
            else
            {
                if (g_Addrs.LobbySession_GetControllingLobbySession && g_Addrs.LobbyData_SetGameType)
                    LobbyData_SetGameType(LobbySession_GetControllingLobbySession(0), gametype.c_str());
                Com_GametypeSettings_SetGametype(gametype.c_str(), true);
                StatusPrintf("[CMD] OK: Gametype set to %s.\n", gametype.c_str());
            }
        }
        else if ((command == "/mp" || command == "/zm") &&
                 (g_activeGameKind == games::GameKind::Retail ||
                  g_activeGameKind == games::GameKind::Alpha ||
                  g_activeGameKind == games::GameKind::S2 ||
                  g_activeGameKind == games::GameKind::Beta))
        {
            const bool multiplayer = command == "/mp";
            const char* label = multiplayer ? "multiplayer" : "zombies";
            const int sessionMode = multiplayer ? 1 : 0;
            if (ApplyHybridOnlineFrontendMode(sessionMode, label))
            {
                StatusPrintf(
                    "[CMD] OK: /%s -> %s isolated LIVE frontend active; public COD/Demonware networking remains blocked.\n",
                    multiplayer ? "mp" : "zm",
                    label);
                if (g_activeGameKind == games::GameKind::Retail)
                {
                    std::string luaWorkspace;
                    if (EnsureRetailStockLanCardWorkspace(luaWorkspace))
                        StatusPrintf("[LAN-MENU] %s. Use /lanmenu install for the stock-card override; no DirectorHub/Lua redump is used.\n", luaWorkspace.c_str());
                    std::string luaPatchWorkspace;
                    if (EnsureRetailLuaPatchWorkspace(luaPatchWorkspace))
                        StatusPrintf("[LUA-PATCH] %s. The patch-aware decompiler will map the exact failing source line before any new model key is forced.\n", luaPatchWorkspace.c_str());

                    // v47.30: reuse any already-decompiled Lua workspace first.
                    // Do not dump/decompile thousands of scripts again just because
                    // /mp was entered. A fresh full pass is only scheduled when no
                    // usable decompiled output exists at all.
                    unsigned int existingDecompiledFiles = 0;
                    if (RetailLuaExistingDecompileAvailable(existingDecompiledFiles))
                    {
                        StatusPrintf(
                            "[LUA-DECOMP] existing readable decompile detected (%u files); reusing it. No automatic Lua dump/re-decompile started.\n",
                            existingDecompiledFiles);
                    }
                    else if (StartRetailLuaDecompileAllAsync(true, false))
                    {
                        StatusPrintf("[LUA-DECOMP] no existing readable decompile found; automatic Retail Lua dump/decompile scheduled once. Use /lua status for progress.\n");
                    }
                }
            }
            else
            {
                StatusPrintf(
                    "[CMD] FAILED: /%s transition was not applied; watch [HYBRID-ONLINE] for the unresolved target.\n",
                    multiplayer ? "mp" : "zm");
            }
        }
        else if (command == "/menudump" && g_activeGameKind == games::GameKind::Retail)
        {
            if (StartRetailMenuDump())
            {
                StatusPrintf("[CMD] OK: focused menu dump requested. Watch [MENU-DUMP]; broad graph/online scanners remain paused.\n");
            }
            else
            {
                StatusPrintf("[CMD] FAILED: menu dump worker did not start.\n");
            }
        }
        else if (command == "/gsc" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string action;
            input >> action;
            std::transform(action.begin(), action.end(), action.begin(),
                [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (action.empty() || action == "status")
            {
                t9_manual_gsc::PrintStatus();
            }
            else if (action == "dump" || action == "decompile")
            {
                std::string filter;
                input >> filter;
                const bool decompile = action == "decompile";
                if (t9_manual_gsc::Start(decompile, filter))
                {
                    StatusPrintf("[CMD] OK: manual read-only T9 GSC %s started%s%s. Broad scanners remain paused; decompile backend=builtin-t9.\n",
                        decompile ? "dump+self-contained-decompile" : "dump",
                        filter.empty() ? "" : " filter=",
                        filter.empty() ? "" : filter.c_str());
                }
                else
                {
                    StatusPrintf("[CMD] FAILED: GSC job did not start; use /gsc status.\n");
                }
            }
            else
            {
                StatusPrintf("[CMD] Usage: /gsc status|dump [hash-filter]|decompile [hash-filter]\n");
            }
        }
        else if (command == "/unlockscan" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string action;
            input >> action;
            std::transform(action.begin(), action.end(), action.begin(),
                [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (action.empty() || action == "status")
            {
                PrintAutomaticLocalContentStatus();
            }
            else if (action == "run" || action == "start" || action == "scan" || action == "deep")
            {
                if (g_localContentAutoStarted.load())
                {
                    StatusPrintf("[CMD] Focused unlock/content scan is already running. Use /unlockscan status.\n");
                }
                else
                {
                    const bool deepScan = action == "deep";
                    StatusPrintf("[CMD] OK: MANUAL unlock/content research requested mode=%s. Automatic LAN discovery stays independent; public networking remains blocked.\n", deepScan ? "deep" : "quick");
                    StartAutomaticLocalContentMode(deepScan);
                }
            }
            else
            {
                StatusPrintf("[CMD] Usage: /unlockscan status|run|deep\n");
            }
        }
        else if (command == "/devscan" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string action;
            input >> action;
            std::transform(action.begin(), action.end(), action.begin(),
                [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (action.empty() || action == "start" || action == "run")
            {
                if (StartRetailDevDiscovery())
                    StatusPrintf("[CMD] OK: MANUAL command/dvar/debug/native-console discovery is running. Automatic LAN discovery is separate; wait for [DEVSCAN] COMPLETE.\n");
                else
                    StatusPrintf("[CMD] FAILED: dev discovery worker did not start.\n");
            }
            else if (action == "status")
            {
                PrintRetailDevDiscoveryStatus();
            }
            else if (action == "commands")
            {
                std::string filter;
                input >> filter;
                if (!g_retailDevScanCompleted.load())
                    StatusPrintf("[CMD] Wait for [DEVSCAN] COMPLETE before listing recovered engine commands.\n");
                else
                    PrintRetailRecoveredCommands(filter);
            }
            else if (action == "dvars")
            {
                std::string filter;
                input >> filter;
                if (!g_retailDevScanCompleted.load())
                    StatusPrintf("[CMD] Wait for [DEVSCAN] COMPLETE before listing recovered dvars.\n");
                else
                    PrintRetailRecoveredDvars(filter);
            }
            else
            {
                StatusPrintf("[CMD] Usage: /devscan status|commands [filter]|dvars [filter]\n");
            }
        }
        else if (command == "/nativeconsole" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string action;
            input >> action;
            std::transform(action.begin(), action.end(), action.begin(),
                [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (action.empty() || action == "status")
            {
                native_t9_command_bar::PrintStatus();
            }
            else if (action == "toggle")
            {
                native_t9_command_bar::Toggle();
            }
            else if (action == "show" || action == "on" || action == "open")
            {
                native_t9_command_bar::SetOpen(true);
            }
            else if (action == "hide" || action == "off" || action == "close")
            {
                native_t9_command_bar::SetOpen(false);
            }
            else
            {
                StatusPrintf("[CMD] Usage: /nativeconsole status|show|hide|toggle\n");
            }
        }
        else if (command == "/menutrace" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string action;
            input >> action;
            std::transform(action.begin(), action.end(), action.begin(),
                [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

            if (action.empty() || action == "status")
            {
                const uintptr_t target = g_retailLuiOpenMenuAddress.load();
                StatusPrintf(
                    "[MENU-TRACE] status enabled=%d created=%d target=0x%llX rva=0x%llX dumpRunning=%d.\n",
                    g_retailMenuTraceEnabled.load() ? 1 : 0,
                    g_retailMenuTraceCreated.load() ? 1 : 0,
                    static_cast<unsigned long long>(target),
                    static_cast<unsigned long long>(
                        target && g_Addrs.ModuleBase && target >= g_Addrs.ModuleBase
                            ? target - g_Addrs.ModuleBase
                            : 0),
                    g_retailMenuDumpRunning.load() ? 1 : 0);
            }
            else if (action == "on")
            {
                if (SetRetailMenuTraceEnabled(true))
                    StatusPrintf("[CMD] OK: MANUAL menu trace enabled. Click the target blade once; automatic LAN discovery is unaffected.\n");
                else
                    StatusPrintf("[CMD] FAILED: menu trace could not validate/install; send [MENU-RESOLVE] lines.\n");
            }
            else if (action == "off")
            {
                (void)SetRetailMenuTraceEnabled(false);
            }
            else
            {
                StatusPrintf("[CMD] Usage: /menutrace on|off|status\n");
            }
        }
        else if (command == "/openmenu" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string menuName;
            std::getline(input, menuName);
            while (!menuName.empty() && std::isspace(static_cast<unsigned char>(menuName.front())))
                menuName.erase(menuName.begin());
            while (!menuName.empty() && std::isspace(static_cast<unsigned char>(menuName.back())))
                menuName.pop_back();

            if (menuName.empty())
            {
                StatusPrintf("[CMD] Usage: /openmenu <name>\n");
            }
            else if (!g_hybridLocalReadyLatch.load() ||
                     g_hybridActiveSessionMode.load() != 1)
            {
                StatusPrintf("[CMD] FAILED: enter /mp first, then use /openmenu <name>. LAN/offline state was not changed.\n");
            }
            else if (OpenRetailMenuDirect(menuName))
            {
                StatusPrintf("[CMD] OK: direct LUI menu call issued for %s.\n", menuName.c_str());
            }
            else
            {
                StatusPrintf("[CMD] FAILED: direct LUI menu call did not validate for %s.\n", menuName.c_str());
            }
        }
        else if (command == "/weapons" && g_activeGameKind == games::GameKind::Retail)
        {
            StatusPrintf(
                "[CMD] v44 Weapons discovery: guessed lui_open routes remain retired; v41.3 proved executable string-anchor tracing is stripped on this build.\n");
            StatusPrintf(
                "[CMD] /menudump provides the Lua menu inventory; /gsc manually dumps loaded T9 ScriptParseTree objects. v44 /devscan adds keybind-derived command-registrar truth validation and focused debug anchors.\n");
        }
        else if (command == "/setmode" &&
                 (g_activeGameKind == games::GameKind::Retail ||
                  g_activeGameKind == games::GameKind::Alpha ||
                  g_activeGameKind == games::GameKind::S2 ||
                  g_activeGameKind == games::GameKind::Beta))
        {
            std::string mode; input >> mode;
            std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (mode == "campaign" || mode == "cp")
            {
                if (g_activeGameKind != games::GameKind::Retail)
                {
                    StatusPrintf("[CMD] FAILED: campaign switching remains disabled outside Retail; use /setmode mp or /setmode zm.\n");
                }
                else
                {
                    SetHybridLocalReadyLatch(false);
                    SetMode(0, 10);
                    StatusPrintf("[CMD] OK: Offline campaign frontend applied; hybrid readiness latch released.\n");
                }
            }
            else if (mode == "multiplayer" || mode == "mp")
            {
                if (ApplyHybridOnlineFrontendMode(1, "multiplayer"))
                    StatusPrintf("[CMD] OK: Multiplayer isolated LIVE frontend active; public COD/Demonware networking remains blocked.\n");
                else
                    StatusPrintf("[CMD] FAILED: Multiplayer LIVE frontend transition was not applied.\n");
            }
            else if (mode == "zombies" || mode == "zm")
            {
                if (ApplyHybridOnlineFrontendMode(0, "zombies"))
                    StatusPrintf("[CMD] OK: Zombies isolated LIVE frontend active; public COD/Demonware networking remains blocked.\n");
                else
                    StatusPrintf("[CMD] FAILED: Zombies LIVE frontend transition was not applied.\n");
            }
            else
            {
                StatusPrintf("[CMD] FAILED: Usage: /setmode campaign|multiplayer|mp|zombies|zm\n");
            }
        }
        else if (command == "/menumark" &&
                 (g_activeGameKind == games::GameKind::Retail ||
                  g_activeGameKind == games::GameKind::Alpha ||
                  g_activeGameKind == games::GameKind::S2 ||
                  g_activeGameKind == games::GameKind::Beta))
        {
            std::string label;
            std::getline(input >> std::ws, label);
            if (label.empty())
            {
                StatusPrintf("[CMD] Usage: /menumark <weapons|operators|barracks|battlepass|store|social|custom|label>\n");
            }
            else if (!g_hybridLocalReadyLatch.load())
            {
                StatusPrintf("[CMD] FAILED: enter /mp or /zm first, then use /menumark <label> immediately before clicking.\n");
            }
            else
            {
                ArmMenuResearchMark(label);
                StatusPrintf("[CMD] OK: next menu action marked '%s'. Broad scanners remain paused.\n", label.c_str());
            }
        }
        else if (command == "/hybrid" &&
                 (g_activeGameKind == games::GameKind::Retail ||
                  g_activeGameKind == games::GameKind::Alpha ||
                  g_activeGameKind == games::GameKind::S2 ||
                  g_activeGameKind == games::GameKind::Beta))
        {
            std::string sub; input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (sub.empty() || sub == "status")
            {
                const HybridOnlineState state = ReadHybridOnlineState();
                StatusPrintf(
                    "[HYBRID-READY] status=%s holdLive=%d repairs=%u ui=0x%llX network=0x%llX session=0x%llX config0=0x%llX config1=0x%llX.\n",
                    g_hybridLocalReadyLatch.load() ? "ON" : "OFF",
                    g_hybridHoldLiveFrontend.load() ? 1 : 0,
                    g_hybridReadyRepairCount.load(),
                    state.ui,
                    state.network,
                    state.session,
                    state.config0,
                    state.config1);
            }
            else if (sub == "off")
            {
                const int activeMode = g_hybridActiveSessionMode.load();
                SetHybridLocalReadyLatch(false);
                DWORD restore = 0;
                if (activeMode >= 0)
                    restore = RestoreLanNetworkModeForGameplayGuarded(activeMode);
                StatusPrintf(restore == 0
                    ? "[CMD] OK: Hybrid LIVE frontend released and networkMode restored to LAN; network blocker policy unchanged.\n"
                    : "[CMD] WARNING: Hybrid latch released but LAN restore faulted code=0x%08lX; network blocker policy unchanged.\n",
                    static_cast<unsigned long>(restore));
            }
            else
            {
                StatusPrintf("[CMD] Usage: /hybrid status|off\n");
            }
        }
        else if (command == "/window" && g_activeGameKind == games::GameKind::Retail)
        {
            int mode = 0; input >> mode;
            constexpr std::uintptr_t kWindowFullscreenDvarRva = 0x0EBBEA80;
            if (mode < 1 || mode > 3)
            {
                StatusPrintf("[CMD] FAILED: Usage: /window 1|2|3 (1=windowed, 2=fullscreen, 3=windowed fullscreen)\n");
            }
            else if (!g_Addrs.ModuleBase)
            {
                StatusPrintf("[CMD] FAILED: Game module base is unavailable.\n");
            }
            else if (mode == 3)
            {
                StatusPrintf("[CMD] FAILED: Windowed-fullscreen needs the separate borderless/display-mode dvar, which is not resolved yet. Use /window 1 or /window 2 for now.\n");
            }
            else
            {
                const std::uintptr_t dvar = g_Addrs.ModuleBase + kWindowFullscreenDvarRva;
                const bool fullscreen = mode == 2;
                Dvar_SetBoolFromSource(dvar, fullscreen, 0);
                StatusPrintf("[CMD] OK: Window mode set to %d (%s) using dvar=%p rva=0x%llX.\n",
                    mode, fullscreen ? "fullscreen" : "windowed", reinterpret_cast<void*>(dvar),
                    static_cast<unsigned long long>(kWindowFullscreenDvarRva));
            }
        }
        else if (command == "/addbot" && g_activeGameKind == games::GameKind::Retail)
        {
            int count = 1; input >> count; count = (std::max)(1, (std::min)(17, count));
            if (!g_Addrs.LobbyHostBots_AddBotsToLobby) StatusPrintf("[CMD] FAILED: Bot function is unresolved.\n");
            else { LobbyHostBots_AddBotsToLobby(0, count, false, 0, 0); StatusPrintf("[CMD] OK: Requested %d bot(s).\n", count); }
        }
        else if (command == "/disconnect" && g_activeGameKind == games::GameKind::Retail)
        {
            if (!g_Addrs.CL_Disconnect) StatusPrintf("[CMD] FAILED: Disconnect function is unresolved.\n");
            else { CL_Disconnect(0, false, ""); StatusPrintf("[CMD] OK: Local client disconnected.\n"); }
        }
        else if (command == "/offline" && g_activeGameKind == games::GameKind::Retail)
        {
            SetHybridLocalReadyLatch(false);
            SetMode(0, 10);
            const bool noDw = SetNoDemonwareValue(true);

            // Returning to the stock offline screen must not throw away the
            // online-era content/frontend exposure preset. Re-apply it after
            // the offline transition so Operators/Weapons/Blueprints/etc. stay
            // visible wherever the running build exposes them locally.
            std::string contentMessage;
            const bool contentApplied =
                coldwar_frontend_dvars::Apply(contentMessage);

            StatusPrintf(
                "[CMD] %s: Offline/LAN state re-applied; dvar_noDW=%s; offline-online content=%s. %s\n",
                noDw ? "OK" : "PARTIAL",
                noDw ? "on" : "unresolved",
                contentApplied ? "re-applied" : "pending",
                contentMessage.c_str());
        }
        else if (command == "/nodw" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string value; input >> value;
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (value != "on" && value != "off" && value != "1" && value != "0") StatusPrintf("[CMD] FAILED: Usage: /nodw on|off\n");
            else
            {
                const bool enabled = value == "on" || value == "1";
                { const bool changed = SetNoDemonwareValue(enabled); StatusPrintf("[CMD] %s: dvar_noDW %s.\n", changed ? "OK" : "FAILED", changed ? (enabled ? "enabled" : "disabled") : "could not be changed"); }
            }
        }
        else if (command == "/dvarptr" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string type, pointerText; input >> type >> pointerText;
            std::transform(type.begin(), type.end(), type.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            uintptr_t pointer = 0;
            if ((type != "bool" && type != "string" && type != "float") || !ParsePointerArgument(pointerText, pointer))
            {
                StatusPrintf("[CMD] Usage: /dvarptr bool <hexptr> <0|1> OR /dvarptr float <hexptr> <value> OR /dvarptr string <hexptr> <text>\n");
            }
            else if (type == "bool")
            {
                std::string value; input >> value;
                if (value != "0" && value != "1" && value != "on" && value != "off") StatusPrintf("[CMD] Bool value must be 0, 1, on, or off.\n");
                else { const bool enabled = value == "1" || value == "on"; Dvar_SetBoolFromSource(pointer, enabled, 0); StatusPrintf("[CMD] OK: Bool dvar pointer %p set to %d.\n", reinterpret_cast<void*>(pointer), enabled ? 1 : 0); }
            }
            else if (type == "float")
            {
                std::string valueText; input >> valueText;
                char* end = nullptr; errno = 0;
                const float value = std::strtof(valueText.c_str(), &end);
                const uintptr_t setter = t9_addresses::Resolve(g_Addrs.ModuleBase, t9_addresses::Retail.Dvar_SetFloatFromSource);
                if (valueText.empty() || errno != 0 || !end || *end != '\0' || !std::isfinite(value))
                    StatusPrintf("[CMD] Float value is invalid.\n");
                else if (!g_Addrs.ModuleBase)
                    StatusPrintf("[CMD] FAILED: Module base is unavailable.\n");
                else
                {
                    using FloatSetter = void(*)(uintptr_t, float, int);
                    reinterpret_cast<FloatSetter>(setter)(pointer, value, 0);
                    StatusPrintf("[CMD] OK: Float dvar pointer %p set to %g through T9Addresses::Retail.Dvar_SetFloatFromSource.\n", reinterpret_cast<void*>(pointer), value);
                }
            }
            else
            {
                const std::string value = ReadRemainingArgument(input);
                if (value.empty()) StatusPrintf("[CMD] String value cannot be empty.\n");
                else { Dvar_SetStringFromSource(pointer, value.c_str(), 0); StatusPrintf("[CMD] OK: String dvar pointer %p set to: %s\n", reinterpret_cast<void*>(pointer), value.c_str()); }
            }
        }
        else if (command == "/dvarlabel" && g_activeGameKind == games::GameKind::Retail)
        {
            std::uint32_t stableId = 0;
            input >> stableId;
            const std::string label = ReadRemainingArgument(input);
            std::string message;
            if (t9_dvars::SetCapturedLabel(stableId, label, message))
                StatusPrintf("[CMD] OK: %s\n", message.c_str());
            else
                StatusPrintf("[CMD] FAILED: %s\n", message.c_str());
        }
        else if (command == "/apply" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string type;
            input >> type;

            std::transform(
                type.begin(),
                type.end(),
                type.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(std::tolower(c));
                });

            if (type != "camo")
            {
                StatusPrintf(
                    "[CMD] FAILED: usage: /apply camo <folder>\\n");
            }
            else
            {
                std::string folder;
                std::getline(input >> std::ws, folder);

                std::string message;
                bool ok = false;

                if (folder.empty())
                {
                    message = "usage: /apply camo <folder>";
                }
                else
                {
                    std::string lower = folder;
                    std::transform(
                        lower.begin(),
                        lower.end(),
                        lower.begin(),
                        [](unsigned char c)
                        {
                            return static_cast<char>(std::tolower(c));
                        });

                    if (lower == "list")
                        ok = camo_manager::CustomList(message);
                    else
                        ok = camo_manager::CustomApplyConfigured(folder, message);
                }

                StatusPrintf(
                    ok
                    ? "[CAMO] OK: %s\\n"
                    : "[CAMO] FAILED: %s\\n",
                    message.c_str());
            }
        }
        else if (command == "/restore" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string type;
            input >> type;

            std::transform(
                type.begin(),
                type.end(),
                type.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(std::tolower(c));
                });

            if (type == "camo")
            {
                std::string message;
                const bool ok =
                    camo_manager::CustomRestore(1, message);

                StatusPrintf(
                    ok
                    ? "[CAMO] OK: %s\\n"
                    : "[CAMO] FAILED: %s\\n",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] FAILED: usage: /restore camo\\n");
            }
        }
        else if (command == "/camo" && g_activeGameKind == games::GameKind::Retail)
        {



            std::string action;
            input >> action;
            std::transform(action.begin(), action.end(), action.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            std::string message;
            bool ok = false;

            // Release surface: the ONLY research command kept live is the
            // direct-bind WeaponCamo/WeaponCamoBinding trace.  All legacy camo
            // mutation/analyze/test commands stay blocked.  /apply camo remains
            // the proven fallback until the scanner resolves a safe gun-binding
            // setter.
            if (!action.empty() && action != "status" && action != "precache" &&
                action != "research")
            {
                StatusPrintf("[RELEASE] Camo debug/mutation command disabled; use /apply camo <folder>, /restore camo, /camo status, /camo precache, or /camo research.\n");
                return;
            }

            if (action == "precache")
            {
                std::string sub;
                input >> sub;

                std::transform(
                    sub.begin(),
                    sub.end(),
                    sub.begin(),
                    [](unsigned char c)
                    {
                        return static_cast<char>(
                            std::tolower(c));
                    });

                if (sub.empty() ||
                    sub == "status")
                {
                    message =
                        camo_texture_upload::PrecacheStatus();
                    ok = true;
                }
                else if (sub == "start")
                {
                    camo_texture_upload::StartBackgroundPrecache();
                    message =
                        camo_texture_upload::PrecacheStatus();
                    ok = true;
                }
                else
                {
                    message =
                        "usage: /camo precache [status|start]";
                }
            }

            else if (action == "apply")
            {
                std::string name;
                std::getline(input, name);
                while (!name.empty() && std::isspace(static_cast<unsigned char>(name.front())))
                    name.erase(name.begin());
                ok = camo_prototype1::NativeApply(name, message);
            }

            else if (action == "prototype")
            {
                std::string sub;
                input >> sub;

                std::transform(
                    sub.begin(),
                    sub.end(),
                    sub.begin(),
                    [](unsigned char c)
                    {
                        return static_cast<char>(
                            std::tolower(c));
                    });

                if (sub.empty() ||
                    sub == "status")
                {
                    ok =
                        camo_prototype1::Status(
                            message);
                }
                else if (sub == "create")
                {
                    ok =
                        camo_prototype1::Create(
                            message);
                }
                else if (sub == "reset")
                {
                    ok =
                        camo_prototype1::ResetAttempt(
                            message);
                }
                else
                {
                    message =
                        "usage: /camo prototype [status|create|reset]";
                }
            }
            else if (action == "research")
            {
                std::string researchAction;
                input >> researchAction;
                std::transform(researchAction.begin(), researchAction.end(), researchAction.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                if (researchAction == "writers")
                {
                    ok =
                        camo_allocator_trace::WriterWatchStatus(
                            message);
                }
                else if (researchAction == "functions")
                {
                    ok =
                        camo_allocator_trace::DumpRegistrationFunctions(
                            message);
                }
                else if (researchAction.empty() || researchAction == "status" ||
                         researchAction == "restart" || researchAction == "start" ||
                         researchAction == "stop" || researchAction == "off")
                {
                    ok =
                        camo_allocator_trace::Command(
                            researchAction,
                            message);
                }
                else
                {
                    message = "usage: /camo research [status|writers|functions|restart|stop]";
                }
            }
            else if (action == "status" || action.empty())
                ok = camo_manager::Status(message);
            else if (action == "dump")
                ok = camo_manager::Dump(message);
            else if (action == "inspect")
                ok = camo_manager::InspectAll(message);
            else if (action == "replace")
            {
                unsigned int target = 0, source = 0;
                if (!(input >> target >> source))
                    message = "usage: /camo replace <targetIndex> <sourceIndex>";
                else
                    ok = camo_manager::Replace(target, source, message);
            }
            else if (action == "restore")
            {
                unsigned int target = 0;
                if (!(input >> target))
                    message = "usage: /camo restore <targetIndex>";
                else
                    ok = camo_manager::Restore(target, message);
            }
            else if (action == "custom")
            {
                std::string sub;
                input >> sub;
                std::transform(sub.begin(), sub.end(), sub.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                if (sub == "list")
                    ok = camo_manager::CustomList(message);
                else if (sub == "analyze")
                {
                    unsigned int target = 0;
                    if (!(input >> target))
                        message = "usage: /camo custom analyze <targetIndex>";
                    else
                        ok = camo_manager::CustomAnalyzeImages(target, message);
                }
                else if (sub == "test")
                {
                    unsigned int target = 0, candidate = 0;
                    if (!(input >> target >> candidate))
                        message = "usage: /camo custom test <targetIndex> <candidateIndex>";
                    else
                        ok = camo_manager::CustomTestImage(target, candidate, message);
                }
                else if (sub == "testrestore")
                {
                    unsigned int target = 0;
                    if (!(input >> target))
                        message = "usage: /camo custom testrestore <targetIndex>";
                    else
                        ok = camo_manager::CustomTestRestore(target, message);
                }
                else if (sub == "next")
                {
                    unsigned int target = 0;
                    if (!(input >> target))
                        message = "usage: /camo custom next <targetIndex>";
                    else
                        ok = camo_manager::CustomNextImage(target, message);
                }
                else if (sub == "prev")
                {
                    unsigned int target = 0;
                    if (!(input >> target))
                        message = "usage: /camo custom prev <targetIndex>";
                    else
                        ok = camo_manager::CustomPrevImage(target, message);
                }
                else if (sub == "status")
                {
                    unsigned int target = 0;
                    if (!(input >> target))
                        message = "usage: /camo custom status <targetIndex>";
                    else
                        ok = camo_manager::CustomTestStatus(target, message);
                }
                else if (sub == "keep")
                {
                    unsigned int target = 0;
                    std::string role;
                    if (!(input >> target))
                        message = "usage: /camo custom keep <targetIndex> [role]";
                    else
                    {
                        input >> role;
                        ok = camo_manager::CustomKeepImage(target, role, message);
                    }
                }
                else if (sub == "restore")
                {
                    unsigned int target = 0;
                    if (!(input >> target))
                        message = "usage: /camo custom restore <targetIndex>";
                    else
                        ok = camo_manager::CustomRestore(target, message);
                }
                else if (sub == "inspect")
                {
                    std::string name;
                    std::getline(input >> std::ws, name);
                    if (name.empty())
                        message = "usage: /camo custom inspect <name>";
                    else
                        ok = camo_manager::CustomInspect(name, message);
                }
                else if (sub == "stage" || sub == "apply")
                {
                    std::string rest;
                    std::getline(input >> std::ws, rest);
                    const auto split = rest.find_last_of(' ');
                    if (split == std::string::npos)
                    {
                        message = sub == "stage"
                            ? "usage: /camo custom stage <name> <targetIndex>"
                            : "usage: /camo custom apply <name> <targetIndex>";
                    }
                    else
                    {
                        const std::string name = rest.substr(0, split);
                        const std::string targetText = rest.substr(split + 1);
                        char* end = nullptr;
                        const unsigned long target = std::strtoul(targetText.c_str(), &end, 10);
                        if (!end || *end != 0)
                            message = "targetIndex must be a number";
                        else if (sub == "stage")
                            ok = camo_manager::CustomStage(name, static_cast<unsigned int>(target), message);
                        else
                            ok = camo_manager::CustomApply(name, static_cast<unsigned int>(target), message);
                    }
                }
                else
                    message = "usage: /camo custom list|inspect|stage|analyze|next|prev|status|keep|test|testrestore|apply|restore";
            }
            else
                message = "usage: /camo precache [status|start]|status|dump|inspect|replace <target> <source>|restore <target>|custom ...";

            StatusPrintf(ok ? "[CAMO] OK: %s\n" : "[CAMO] FAILED: %s\n", message.c_str());
        }
        else if (command == "/research" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string query;
            std::getline(input, query);
            while (!query.empty() && std::isspace(static_cast<unsigned char>(query.front()))) query.erase(query.begin());
            const auto results = research_catalog::Search(query, 100);
            StatusPrintf("[RESEARCH] query=\"%s\" results=%zu catalog=%zu signatures=%zu\n",
                query.c_str(), results.size(), research_catalog::EntryCount(), research_catalog::ResolvedCount());
            for (const auto& item : results)
                StatusPrintf("[RESEARCH] %-48s RVA=0x%llX subsystem=%s source=%s\n",
                    item.name, static_cast<unsigned long long>(item.referenceRva), item.subsystem, item.source);
        }
        else if (command == "/discover" && g_activeGameKind == games::GameKind::Retail)
        {
            command_discovery::Refresh(); command_discovery::WriteReports();
            size_t live=0; for (const auto& e:command_discovery::Dvars()) if(e.live) ++live;
            StatusPrintf("[DISCOVERY] Found %zu live dvars from %zu candidates. Reports written under logs\\research and logs\\scanner.\n", live, command_discovery::Dvars().size());
        }
        else if (command == "/dvars" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string q; std::getline(input,q); while(!q.empty()&&std::isspace((unsigned char)q.front()))q.erase(q.begin());
            for(const auto&e:command_discovery::Dvars(q)) if(e.live) StatusPrintf("[DVAR] %-32s type=%s value=%s flags=0x%X address=%p\n",e.name.c_str(),e.type.c_str(),e.value.c_str(),e.flags,(void*)e.address);
        }
        else if (command == "/commands" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string q; std::getline(input,q); while(!q.empty()&&std::isspace((unsigned char)q.front()))q.erase(q.begin());
            for(const auto&c:command_discovery::Commands(q)) StatusPrintf("[COMMAND] %s\n",c.c_str());
        }
        else if (command == "/researchresolve" && g_activeGameKind == games::GameKind::Retail)
        {
            research_catalog::ResolveAll();
            StatusPrintf("[RESEARCH] analysis-only resolver complete: %zu validated signature(s).\n",
                research_catalog::ResolvedCount());
        }
        else if (command == "/stages" && g_activeGameKind == games::GameKind::Retail)
        {
            const auto stages = runtime_stages::Snapshot();
            StatusPrintf("[STAGE] -------- runtime stages --------\n");
            for (const auto& stage : stages)
            {
                const unsigned long long elapsed = stage.finishedAtMs >= stage.startedAtMs
                    ? static_cast<unsigned long long>(stage.finishedAtMs - stage.startedAtMs) : 0ULL;
                StatusPrintf("[STAGE] %-20s %-10s elapsed=%llums detail=%s\n",
                    stage.name.c_str(), runtime_stages::ToString(stage.state), elapsed, stage.detail.c_str());
            }
        }
        else if (command == "/imgui" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string mode;
            input >> mode;
            std::transform(mode.begin(), mode.end(), mode.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (mode.empty() || mode == "status")
            {
                StatusPrintf("[IMGUI] stage=%s hooks=%s backend=%s visible=%s\n",
                    runtime_stages::ToString(runtime_stages::GetState("overlay")),
                    imgui_backend_bridge::HooksInstalled() ? "yes" : "no",
                    imgui_backend_bridge::IsReady() ? "ready" : "not-ready",
                    research_imgui::IsVisible() ? "yes" : "no");
            }
            else if (mode == "install" || mode == "retry")
            {
                if (imgui_backend_bridge::HooksInstalled())
                    StatusPrintf("[IMGUI] Hooks are already installed. Press INSERT to toggle the dashboard.\n");
                else
                {
                    HANDLE thread = CreateThread(nullptr, 0, core_runtime::DeferredOverlayStageThread, nullptr, 0, nullptr);
                    if (thread)
                    {
                        CloseHandle(thread);
                        StatusPrintf("[IMGUI] Guarded overlay stage queued. Use /stages to inspect the result.\n");
                    }
                    else
                        StatusPrintf("[IMGUI] Could not create overlay stage thread (error %lu).\n", GetLastError());
                }
            }
            else if (mode == "off")
            {
                research_imgui::SetVisible(false);
                StatusPrintf("[IMGUI] Dashboard hidden. Installed hooks remain dormant.\n");
            }
            else
                StatusPrintf("[CMD] Usage: /imgui status|install|off\n");
        }
        else if (command == "/researchui" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string mode; input >> mode;
            std::transform(mode.begin(), mode.end(), mode.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (!research_imgui::BackendAvailable())
            {
                StatusPrintf("[IMGUI] Dear ImGui core is included, but the DX12/Win32 backend has not been attached to a validated swap-chain yet.\n");
            }
            else
            {
                const bool visible = mode != "off" && (mode == "on" || !research_imgui::IsVisible());
                research_imgui::SetVisible(visible);
                StatusPrintf("[IMGUI] Research diagnostics panel %s.\n", visible ? "enabled" : "disabled");
            }
        }
        else if (command == "/feature" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string featureName;
            input >> featureName;
            std::transform(featureName.begin(), featureName.end(), featureName.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (featureName.empty() || featureName == "status")
            {
                for (const auto& state : offline_features::Snapshot())
                    StatusPrintf("[FEATURE] %-18s available=%s enabled=%s reason=%s\n",
                        state.name, state.available ? "yes" : "no", state.enabled ? "yes" : "no", state.reason.c_str());
            }
            else
            {
                offline_features::FeatureId id{};
                if (!offline_features::Parse(featureName, id))
                    StatusPrintf("[CMD] Usage: /feature noclip|god|ufo|notarget|status\n");
                else if (offline_features::Toggle(id))
                    StatusPrintf("[FEATURE] %s toggled through the native command path.\n", offline_features::Name(id));
    
            else
                    StatusPrintf("[FEATURE] %s unavailable. Enter a local offline match and verify the command path.\n", offline_features::Name(id));
            }
        }
        else if (command == "/offsets" && g_activeGameKind == games::GameKind::Retail)
            PrintAllLiveOffsets();
        else if (command == "/map" && g_activeGameKind == games::GameKind::Retail)
            PrintModuleMemoryMap();
        else if (command == "/missing" && g_activeGameKind == games::GameKind::Retail)
        {
            StatusPrintf("[MEMSCAN] Retrying optional address discovery...\n");
            RefreshMissingLiveOffsets();
            ResolveRetailConsoleTargets(true);
            PrintLiveAddress("config[1]", g_Addrs.config[1]);
            PrintLiveAddress("watermark_font", g_Addrs.watermark_font);
            PrintLiveAddress("ScrPlace_GetViewUIContext", g_Addrs.ScrPlace_GetViewUIContext);
            PrintLiveAddress("UI_GetFontHandle", g_Addrs.UI_GetFontHandle);
            PrintLiveAddress("Cbuf_AddText", g_Addrs.Cbuf_AddText);
        }
        else if (command == "/state" && g_activeGameKind == games::GameKind::Retail)
            PrintCurrentState();
        else if (command == "/network" &&
                 (g_activeGameKind == games::GameKind::Retail ||
                  g_activeGameKind == games::GameKind::IW8))
        {
            StatusPrintf("[NETWORK] Offline filter active: socket creation and local/LAN traffic allowed; public DNS/connect/sendto blocked.\n");
            StatusPrintf("[NETWORK] Hooked APIs: socket/WSASocket pass through; localhost DNS passes; public DNS/connect/sendto are rejected.\n");
        }
        else if (command == "/connect" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string target;
            std::getline(input >> std::ws, target);
            if (target.empty() || target.find_first_of(" \t\r\n") != std::string::npos)
            {
                StatusPrintf("[LAN] Usage: /connect <LAN IPv4[:port]>\n");
            }
            else
            {
                std::string host = target;
                const size_t colon = host.find(':');
                if (colon != std::string::npos)
                    host.resize(colon);

                sockaddr_in endpoint{};
                endpoint.sin_family = AF_INET;
                const bool numeric = InetPtonA(AF_INET, host.c_str(), &endpoint.sin_addr) == 1;
                const bool local = numeric && IsAllowedOfflineAddress(
                    reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint));

                if (!local)
                {
                    StatusPrintf("[LAN] REFUSED: /connect is limited to private/loopback IPv4 addresses. Got '%s'.\n", target.c_str());
                }
                else
                {
                    std::string modeMessage;
                    const bool modeOk = lan_profile_research::SetLanNetworkMode(true, modeMessage);
                    SetLanNetworkTraceEnabled(true);
                    const std::string native = "connect " + target;
                    const bool queued = ExecuteDeveloperCommand(native.c_str());
                    StatusPrintf("[LAN] %s\n", modeMessage.c_str());
                    StatusPrintf(queued
                        ? "[LAN] Native command queued: %s. Passive local socket trace ENABLED.\n"
                        : "[LAN] Native connect command could not be queued: %s\n", native.c_str());
                }
            }
        }
        else if (command == "/ulan")
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                universal_lan::PrintStatus();
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /ulan status\n");
            }
        }
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
        else if (command == "/t8" && g_activeGameKind == games::GameKind::T8)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                t8_runtime::PrintStatus();
                t8_scanner::PrintStatus();
            }
            else if (sub == "scan")
            {
                std::string message;
                const bool ok =
                    t8_scanner::Run(
                        t8_scanner::Mode::All,
                        message);

                StatusPrintf(
                    "[T8] scan %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else if (sub == "lua")
            {
                std::string message;
                const bool ok =
                    t8_scanner::Run(
                        t8_scanner::Mode::Lua,
                        message);

                StatusPrintf(
                    "[T8] lua scan %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else if (sub == "frontend")
            {
                std::string message;
                const bool ok =
                    t8_scanner::Run(
                        t8_scanner::Mode::Frontend,
                        message);

                StatusPrintf(
                    "[T8] frontend scan %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else if (sub == "assets")
            {
                std::string message;
                const bool ok =
                    t8_scanner::Run(
                        t8_scanner::Mode::Assets,
                        message);

                StatusPrintf(
                    "[T8] asset scan %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else if (sub == "cmd")
            {
                std::string text;
                std::getline(input, text);

                while (!text.empty() &&
                       (text.front() == ' ' ||
                        text.front() == '\t'))
                {
                    text.erase(text.begin());
                }

                if (text.empty())
                {
                    StatusPrintf(
                        "[CMD] Usage: /t8 cmd <game command>\n");
                }
                else
                {
                    std::string message;
                    const bool ok =
                        t8_runtime::QueueCommand(
                            text,
                            message);

                    StatusPrintf(
                        "[T8] command %s: %s\n",
                        ok ? "queued" : "failed",
                        message.c_str());
                }
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /t8 status|scan|lua|frontend|assets|cmd <text>\n");
            }
        }
        else if (command == "/iw8" && g_activeGameKind == games::GameKind::IW8)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                iw8_research::PrintStatus();
                iw8_144::PrintStatus();
            }
            else
            {
                iw8_research::ScanMode mode =
                    iw8_research::ScanMode::All;

                if (sub == "frontend")
                    mode = iw8_research::ScanMode::Frontend;
                else if (sub == "lua" ||
                         sub == "lui")
                    mode = iw8_research::ScanMode::LuaLui;
                else if (sub == "lan" ||
                         sub == "network")
                    mode = iw8_research::ScanMode::LanNetwork;
                else if (sub != "scan" &&
                         sub != "all")
                {
                    StatusPrintf(
                        "[CMD] Usage: /iw8 status|scan|frontend|lua|lan\n");
                    return;
                }

                std::string message;
                const bool ok =
                    iw8_research::Run(
                        mode,
                        message);

                StatusPrintf(
                    "[IW8-SCAN] %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
        }
#endif
        else if (command == "/lan" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (sub.empty() || sub == "status")
            {
                StatusPrintf("[LAN] %s\n", lan_profile_research::LanStatus().c_str());
                StatusPrintf("[LAN-AUTO] native discovery running=%d complete=%d; passive socket trace=%s. Non-LAN scanners are command-only.\n",
                    g_retailLanOnlyScanRunning.load() ? 1 : 0,
                    g_retailLanOnlyScanCompleted.load() ? 1 : 0,
                    IsLanNetworkTraceEnabled() ? "ON" : "OFF");
                StatusPrintf("[LAN-AUTO] v47.29 join focus: PartyAtomic_StartJoin, PartyAtomic_AcceptPrivateMP, g_PartyData/PartyData and dyn.sessionInfo/sessionInfo -> logs\\debug\\lan_party_join_focus.tsv.\n");
                StatusPrintf("[CWMOD-LAN] %s\n", universal_lan::ColdWarRetailBridgeStatus().c_str());
                PrintRetailLanFakeBrowserStatus();
            }
            else if (sub == "scan")
            {
                std::string reportMessage;
                const bool reportOk =
                    lan_profile_research::WriteLanResearchReport(reportMessage);
                StatusPrintf(reportOk
                    ? "[LAN] OK: %s\n"
                    : "[LAN] FAILED: %s\n",
                    reportMessage.c_str());

                std::string resolverMessage;
                const bool resolverOk =
                    lan_profile_research::ScanSystemlinkXrefs(resolverMessage);
                StatusPrintf(resolverOk
                    ? "[LAN-SCAN] OK: %s\n"
                    : "[LAN-SCAN] FAILED: %s\n",
                    resolverMessage.c_str());
            }
            else if (sub == "inspect")
            {
                std::string message;
                const bool ok =
                    lan_profile_research::InspectLanFunctions(message);

                StatusPrintf(ok ? "[LAN] OK: %s\n" : "[LAN] FAILED: %s\n", message.c_str());
            }
            else if (sub == "xrefs")
            {
                std::string message;
                const bool ok =
                    lan_profile_research::ScanSystemlinkXrefs(message);

                StatusPrintf(ok ? "[LAN] OK: %s\n" : "[LAN] FAILED: %s\n", message.c_str());
            }
            else if (sub == "mode")
            {
                std::string value;
                input >> value;
                std::transform(value.begin(), value.end(), value.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                std::string message;
                bool ok = false;

                if (value == "lan" || value == "local")
                    ok = lan_profile_research::SetLanNetworkMode(true, message);
                else if (value == "live")
                    ok = lan_profile_research::SetLanNetworkMode(false, message);
                else
                    message = "usage: /lan mode lan|live";

                StatusPrintf(ok ? "[LAN] OK: %s\n" : "[LAN] FAILED: %s\n", message.c_str());
            }
            else if (sub == "sessionmode")
            {
                int mode = -1;
                input >> mode;

                std::string message;
                const bool ok =
                    lan_profile_research::SetSessionMode(mode, message);

                StatusPrintf(ok ? "[LAN] OK: %s\n" : "[LAN] FAILED: %s\n", message.c_str());
            }
            else if (sub == "menu" || sub == "browser")
            {
                ExecuteDeveloperCommand("lui_open menu_systemlink_join");
                if (g_retailLanFakeBrowserEnabled.load())
                    RequestRetailLanFakeBrowserRefresh(false);
                StatusPrintf("[LAN] Requested native System Link/server-browser menu_systemlink_join through the validated developer-command path.\n");
            }
            else if (sub == "host")
            {
                std::string modeMessage;
                const bool modeOk = lan_profile_research::SetLanNetworkMode(true, modeMessage);
                SetLanNetworkTraceEnabled(true);
                std::string message;
                lan_profile_research::HostResearch(message);
                std::string cwmodMessage;
                const bool cwmodReady = universal_lan::InitializeColdWarRetailBridge(cwmodMessage);
                StatusPrintf(modeOk ? "[LAN] OK: %s\n" : "[LAN] WARN: %s\n", modeMessage.c_str());
                StatusPrintf("[LAN] HOST PREP: %s\n", message.c_str());
                StatusPrintf(cwmodReady ? "[CWMOD-LAN] READY: %s\n" : "[CWMOD-LAN] WARN: %s\n", cwmodMessage.c_str());
                StatusPrintf("[LAN] Passive local socket trace ENABLED. Host through the stock System Link/Create Match path, then run /lan export to print the live CWJOIN1 descriptor for PC2.\n");
            }
            else if (sub == "export" || sub == "descriptor")
            {
                std::string message;
                const bool ok = universal_lan::QueueColdWarHostDescriptor(message);
                StatusPrintf(ok ? "[CWMOD-LAN] OK: %s\n" : "[CWMOD-LAN] FAILED: %s\n", message.c_str());
                if (ok)
                    StatusPrintf("[CWMOD-LAN] The full CWJOIN1 token will print from the T9 game thread. Copy that single line to PC2.\n");
            }
            else if (sub == "pending")
            {
                std::string message;
                const bool ok = universal_lan::QueueColdWarPendingTargetDump(message);
                StatusPrintf(ok ? "[CWMOD-LAN] OK: %s\n" : "[CWMOD-LAN] FAILED: %s\n", message.c_str());
            }
            else if (sub == "joinstate")
            {
                std::string message;
                const bool ok = universal_lan::QueueColdWarJoinStateDump(message);
                StatusPrintf(ok ? "[CWMOD-LAN] OK: %s\n" : "[CWMOD-LAN] FAILED: %s\n", message.c_str());
            }
            else if (sub == "sessionnative" || sub == "cwstate")
            {
                std::string message;
                const bool ok = universal_lan::QueueColdWarSessionStateDump(message);
                StatusPrintf(ok ? "[CWMOD-LAN] OK: %s\n" : "[CWMOD-LAN] FAILED: %s\n", message.c_str());
            }
            else if (sub == "watch")
            {
                universal_lan::StartColdWarJoinWatch();
                StatusPrintf("[CWMOD-LAN] Join FSM watcher requested; transitions log to logs\\network\\cwmod_lan_join.log.\n");
            }
            else if (sub == "maxclients")
            {
                int count = 0;
                input >> count;
                if (count < 1 || count > 64)
                {
                    StatusPrintf("[CWMOD-LAN] Usage: /lan maxclients <1-64>\n");
                }
                else
                {
                    const std::string native = "com_maxclients " + std::to_string(count);
                    const bool queued = ExecuteDeveloperCommand(native.c_str());
                    StatusPrintf(queued
                        ? "[CWMOD-LAN] queued %s through T9's command buffer; set this before loading the map.\n"
                        : "[CWMOD-LAN] failed to queue %s.\n", native.c_str());
                }
            }
            else if (sub == "transcript" || sub == "joinlog")
            {
                StatusPrintf("[CWMOD-LAN] JOIN TRANSCRIPT:\n%s\n", universal_lan::ColdWarJoinTranscript().c_str());
            }
            else if (sub == "netmsg")
            {
                std::string value;
                input >> value;
                std::transform(value.begin(), value.end(), value.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (value.empty() || value == "status")
                {
                    StatusPrintf("[CWMOD-LAN] post-decryption netmsg transcript is %s.\n",
                        universal_lan::ColdWarNetMsgTranscriptInstalled() ? "ON" : "off");
                }
                else
                {
                    std::string message;
                    bool ok = false;
                    if (value == "on" || value == "install")
                        ok = universal_lan::InstallColdWarNetMsgTranscript(message);
                    else if (value == "off" || value == "remove")
                        ok = universal_lan::RemoveColdWarNetMsgTranscript(message);
                    else
                        message = "usage: /lan netmsg on|off|status";
                    StatusPrintf(ok ? "[CWMOD-LAN] OK: %s\n" : "[CWMOD-LAN] FAILED: %s\n", message.c_str());
                }
            }
            else if (sub == "joinblob")
            {
                std::string rest;
                std::getline(input >> std::ws, rest);
                std::istringstream blobInput(rest);
                std::string blob;
                int joinType = 4;
                blobInput >> blob;
                int requestedType = 0;
                if (blobInput >> requestedType) joinType = requestedType;
                if (blob.empty())
                {
                    StatusPrintf("[CWMOD-LAN] Usage: /lan joinblob <CWJOIN1 token> [1|4]\n");
                }
                else
                {
                    SetLanNetworkTraceEnabled(true);
                    std::string message;
                    const bool ok = universal_lan::QueueColdWarDescriptorJoin(blob, joinType, message);
                    StatusPrintf(ok ? "[CWMOD-LAN] OK: %s\n" : "[CWMOD-LAN] FAILED: %s\n", message.c_str());
                    if (ok)
                        StatusPrintf("[CWMOD-LAN] Native descriptor join queued with jointype=%d; public COD/Demonware remains blocked.\n", joinType);
                }
            }
            else if (sub == "session")
            {
                std::string message;
                const bool ok = lan_profile_research::SessionResearch(message);
                StatusPrintf(ok ? "[LAN] OK: %s\n" : "[LAN] RESEARCH: %s\n", message.c_str());
            }
            else if (sub == "join")
            {
                std::string data;
                std::getline(input >> std::ws, data);
                if (data.empty())
                {
                    StatusPrintf("[LAN] Usage: /lan join <LAN IPv4[:port] | CWJOIN1 token>\n");
                }
                else if (data.find("CWJOIN1.") != std::string::npos)
                {
                    SetLanNetworkTraceEnabled(true);
                    std::string message;
                    const bool ok = universal_lan::QueueColdWarDescriptorJoin(data, 4, message);
                    StatusPrintf(ok ? "[CWMOD-LAN] OK: %s\n" : "[CWMOD-LAN] FAILED: %s\n", message.c_str());
                    if (ok)
                        StatusPrintf("[CWMOD-LAN] Detected CWJOIN1 token; using donor native descriptor path with preferred jointype=4.\n");
                }
                else
                {
                    std::string host = data;
                    const size_t colon = host.find(':');
                    if (colon != std::string::npos) host.resize(colon);
                    sockaddr_in endpoint{};
                    endpoint.sin_family = AF_INET;
                    const bool numeric = InetPtonA(AF_INET, host.c_str(), &endpoint.sin_addr) == 1;
                    const bool local = numeric && IsAllowedOfflineAddress(
                        reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint));
                    if (!local)
                    {
                        StatusPrintf("[LAN] REFUSED: join target must be a private/loopback IPv4 address or a CWJOIN1 descriptor.\n");
                    }
                    else
                    {
                        std::string modeMessage;
                        lan_profile_research::SetLanNetworkMode(true, modeMessage);
                        SetLanNetworkTraceEnabled(true);
                        const std::string native = "connect " + data;
                        const bool queued = ExecuteDeveloperCommand(native.c_str());
                        StatusPrintf(queued
                            ? "[LAN] Legacy native connect queued: %s. For two-PC Cold War LAN prefer /lan export + /lan join <CWJOIN1...>.\n"
                            : "[LAN] Native join/connect could not be queued: %s\n", native.c_str());
                    }
                }
            }
            else if (sub == "fake")
            {
                std::string value;
                input >> value;
                std::transform(value.begin(), value.end(), value.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                if (value.empty() || value == "status")
                {
                    PrintRetailLanFakeBrowserStatus();
                }
                else if (value == "on")
                {
                    SetRetailLanFakeBrowserEnabled(true, true);
                }
                else if (value == "off")
                {
                    SetRetailLanFakeBrowserEnabled(false, false);
                }
                else if (value == "refresh" || value == "test")
                {
                    RequestRetailLanFakeBrowserRefresh(true);
                    StatusPrintf("[LAN-FAKE] refresh requested; native System Link browser will be opened automatically.\n");
                }
                else
                {
                    StatusPrintf("[LAN] Usage: /lan fake on|off|status|refresh\n");
                }
            }
            else if (sub == "trace")
            {
                std::string value;
                input >> value;
                std::transform(value.begin(), value.end(), value.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (value == "on") SetLanNetworkTraceEnabled(true);
                else if (value == "off") SetLanNetworkTraceEnabled(false);
                else if (!value.empty() && value != "status")
                {
                    StatusPrintf("[LAN] Usage: /lan trace on|off|status\n");
                    value.clear();
                }
                if (value.empty() || value == "status" || value == "on" || value == "off")
                    StatusPrintf("[LAN] Passive local socket trace is %s.\n", IsLanNetworkTraceEnabled() ? "ON" : "OFF");
            }
            else
            {
                StatusPrintf("[CMD] Usage: /lan status|menu|host|export|join <ip|CWJOIN1>|joinblob <token> [1|4]|pending|joinstate|sessionnative|maxclients <1-64>|watch|netmsg on|off|status|transcript|scan|inspect|xrefs|mode|sessionmode|trace|fake\n");
            }
        }
        else if (command == "/frontenddvars" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                coldwar_frontend_dvars::PrintStatus();
            }
            else if (sub == "apply")
            {
                std::string message;
                const bool ok =
                    coldwar_frontend_dvars::Apply(
                        message);

                StatusPrintf(
                    "[CW-DVARS] apply %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /frontenddvars status|apply\n");
            }
        }
        else if (command == "/luabutton" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() || sub == "status")
            {
                lua_native_button_patch::PrintStatus();
            }
            else if (sub == "apply")
            {
                std::string message;
                const bool ok = lua_native_button_patch::Apply(message);
                StatusPrintf(
                    "[LUA-BUTTON] apply %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else if (sub == "restore")
            {
                std::string message;
                const bool ok = lua_native_button_patch::Restore(message);
                StatusPrintf(
                    "[LUA-BUTTON] restore %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /luabutton status|apply|restore\n");
            }
        }
        else if (command == "/customui" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                frontend_custom_buttons::PrintStatus();
            }
            else if (sub == "enable")
            {
                std::string message;
                const bool ok =
                    frontend_custom_buttons::Enable(
                        message);

                StatusPrintf(
                    "[CUSTOM-UI] enable %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else if (sub == "disable")
            {
                std::string message;
                frontend_custom_buttons::Disable(
                    message);

                StatusPrintf(
                    "[CUSTOM-UI] %s\n",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /customui status|enable|disable\n");
            }
        }
        else if (command == "/stateedge" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                frontend_state_edge_trace::PrintStatus();
            }
            else if (sub == "mark")
            {
                std::string label;
                std::getline(input, label);

                while (!label.empty() &&
                       (label.front() == ' ' ||
                        label.front() == '\t'))
                {
                    label.erase(label.begin());
                }

                if (label.empty())
                    label = "manual";

                std::string message;
                const bool ok =
                    frontend_state_edge_trace::SnapshotNow(
                        label,
                        message);

                StatusPrintf(
                    "[STATE-EDGE] mark %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /stateedge status|mark <label>\n");
            }
        }
        else if (command == "/luactx" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                lua_owner_state_trace::PrintStatus();
            }
            else if (sub == "find")
            {
                std::string message;
                const bool ok =
                    lua_owner_state_trace::FindOwnerNow(
                        message);

                StatusPrintf(
                    "[LUA-CTX] find %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else if (sub == "mark")
            {
                std::string label;
                std::getline(input, label);

                while (!label.empty() &&
                       (label.front() == ' ' ||
                        label.front() == '\t'))
                {
                    label.erase(label.begin());
                }

                if (label.empty())
                    label = "manual";

                std::string message;
                const bool ok =
                    lua_owner_state_trace::Mark(
                        label,
                        message);

                StatusPrintf(
                    "[LUA-CTX] mark %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /luactx status|find|mark <label>\n");
            }
        }
        else if (command == "/luapath" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                lua_runtime_path_trace::PrintStatus();
            }
            else if (sub == "scan")
            {
                std::string message;
                const bool ok =
                    lua_runtime_path_trace::ScanNow(
                        message);

                StatusPrintf(
                    "[LUA-PATH] scan %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /luapath status|scan\n");
            }
        }
        else if (command == "/luibridge" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                lua_bridge_discovery::PrintStatus();
            }
            else if (sub == "scan")
            {
                std::string message;
                const bool ok =
                    lua_bridge_discovery::ScanNow(
                        message);

                StatusPrintf(
                    "[LUA-BRIDGE] scan %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else if (sub == "load")
            {
                std::string message;
                const bool ok =
                    lua_bridge_discovery::LoadDirectorHub(
                        message);

                StatusPrintf(
                    "[LUA-BRIDGE] load %s: %s\n",
                    ok ? "complete" : "blocked",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /luibridge status|scan|load\n");
            }
        }
        else if (command == "/nativehub" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                native_director_state_router::PrintStatus();
            }
            else if (sub == "enable")
            {
                std::string message;
                native_director_state_router::Enable(message);
                StatusPrintf("[NATIVE-STATE] %s\n", message.c_str());
            }
            else if (sub == "disable")
            {
                std::string message;
                native_director_state_router::Disable(message);
                StatusPrintf("[NATIVE-STATE] %s\n", message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /nativehub status|enable|disable\n");
            }
        }
        else if (command == "/director" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                StatusPrintf(
                    "[DIRECTOR-MAP] running=%s complete=%s\n",
                    native_director_map::IsRunning()
                        ? "yes"
                        : "no",
                    native_director_map::HasCompleted()
                        ? "yes"
                        : "no");
            }
            else if (sub == "scan" ||
                     sub == "map")
            {
                std::string message;
                const bool ok =
                    native_director_map::ScanNow(
                        message);

                StatusPrintf(
                    "[DIRECTOR-MAP] %s: %s\n",
                    ok ? "complete" : "failed",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /director status|scan\n");
            }
        }
        else if (command == "/lui" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                StatusPrintf(
                    "[LUI-PATCH] running=%s scanComplete=%s\n",
                    native_lui_patch_lab::IsRunning()
                        ? "yes"
                        : "no",
                    native_lui_patch_lab::HasScanCompleted()
                        ? "yes"
                        : "no");
            }
            else if (sub == "scan")
            {
                std::string message;
                const bool ok =
                    native_lui_patch_lab::ScanNow(
                        message);

                StatusPrintf(
                    "[LUI-PATCH] scan %s: %s\n",
                    ok ? "completed" : "failed",
                    message.c_str());
            }
            else if (sub == "apply")
            {
                std::string message;
                const bool ok =
                    native_lui_patch_lab::ApplyOverrides(
                        message);

                StatusPrintf(
                    "[LUI-PATCH] apply %s: %s\n",
                    ok ? "completed" : "not applied",
                    message.c_str());
            }
            else if (sub == "restore")
            {
                std::string message;
                const bool ok =
                    native_lui_patch_lab::RestoreOverrides(
                        message);

                StatusPrintf(
                    "[LUI-PATCH] restore %s: %s\n",
                    ok ? "completed" : "not needed",
                    message.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /lui status|scan|apply|restore\n");
            }
        }
        else if (command == "/route" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;

            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "status")
            {
                StatusPrintf(
                    "[LUI-ROUTE] tracer=%s\n",
                    native_lui_route_trace::IsRunning()
                        ? "running"
                        : "stopped");
            }
            else if (sub == "mark")
            {
                std::string label;
                std::getline(input, label);

                while (!label.empty() &&
                       (label.front() == ' ' ||
                        label.front() == '\t'))
                {
                    label.erase(label.begin());
                }

                native_lui_route_trace::Mark(
                    label.empty()
                        ? "manual"
                        : label.c_str());
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /route status|mark <label>\n");
            }
        }
        else if (command == "/hub" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            std::string sub2;
            input >> sub;
            input >> sub2;

            const auto lower =
                [](std::string& value)
                {
                    std::transform(
                        value.begin(),
                        value.end(),
                        value.begin(),
                        [](unsigned char c)
                        {
                            return static_cast<char>(
                                std::tolower(c));
                        });
                };

            lower(sub);
            lower(sub2);

            const bool lanMp =
                sub == "lanmp" ||
                sub == "lan-multiplayer" ||
                (sub == "lan" &&
                 (sub2 == "mp" ||
                  sub2 == "multiplayer"));

            const bool lanZm =
                sub == "lanzm" ||
                sub == "lan-zombies" ||
                (sub == "lan" &&
                 (sub2 == "zm" ||
                  sub2 == "zombies"));

            if (sub == "mp" ||
                sub == "multiplayer")
            {
                SetModeNetwork(
                    1,
                    11,
                    LOBBY_NETWORKMODE_LIVE);

                StatusPrintf(
                    "[HUB] LIVE Multiplayer requested.\n");
            }
            else if (sub == "zm" ||
                     sub == "zombies")
            {
                SetModeNetwork(
                    0,
                    11,
                    LOBBY_NETWORKMODE_LIVE);

                StatusPrintf(
                    "[HUB] LIVE Zombies requested.\n");
            }
            else if (lanMp)
            {
                SetModeNetwork(
                    1,
                    11,
                    LOBBY_NETWORKMODE_LAN);

                StatusPrintf(
                    "[HUB] LAN Multiplayer requested.\n");
            }
            else if (lanZm)
            {
                SetModeNetwork(
                    0,
                    11,
                    LOBBY_NETWORKMODE_LAN);

                StatusPrintf(
                    "[HUB] LAN Zombies requested.\n");
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /hub mp|zm|lan mp|lan zm|lanmp|lanzm\n");
            }
        }

        else if (command == "/frontend" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() ||
                sub == "root" ||
                sub == "director" ||
                sub == "main")
            {
                const bool ok =
                    OpenFrontendDirectorRoot();

                StatusPrintf(
                    ok
                        ? "[FRONTEND] Requested top-level director/root screen 10; network mode untouched.\\n"
                        : "[FRONTEND] FAILED: SetScreen/LobbyBase_SetNetworkMode unavailable.\\n");
            }
            else if (sub == "screen")
            {
                int screen = -1;
                input >> screen;

                if (screen < 0 ||
                    screen > 64 ||
                    !g_Addrs.SetScreen)
                {
                    StatusPrintf(
                        "[FRONTEND] Usage: /frontend screen <0-64>\\n");
                }
                else
                {
                    SetScreen(screen, 0);
                    StatusPrintf(
                        "[FRONTEND] Requested raw SetScreen(%d, 0).\\n",
                        screen);
                }
            }
            else
            {
                StatusPrintf(
                    "[CMD] Usage: /frontend root|screen <0-64>\\n");
            }
        }
        else if (command == "/lanmenu" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (sub.empty() || sub == "status")
            {
                const DWORD specAttrs = GetFileAttributesA("CodRevamped\\lua\\stock_menu\\stock_cards.patch.txt");
                const DWORD luaAttrs = GetFileAttributesA("CodRevamped\\lua\\stock_menu\\stock_lan_cards.lua");
                StatusPrintf(
                    "[LAN-MENU] mode=STOCK_CARDS workspace=%s descriptor=%s primary=2CBD14A5E53ED76B fallback=5BCA1EA30C053DDD cards=LAN_MP,LAN_ZM preserve=CAMPAIGN,MP,ZM publicNetwork=BLOCKED directorHub=RETIRED.\n",
                    specAttrs != INVALID_FILE_ATTRIBUTES ? "ready" : "missing",
                    luaAttrs != INVALID_FILE_ATTRIBUTES ? "ready" : "missing");
                lua_native_button_patch::PrintStatus();
            }
            else if (sub == "setup")
            {
                std::string message;
                const bool ok = EnsureRetailStockLanCardWorkspace(message);
                StatusPrintf("[LAN-MENU] stock setup %s: %s\n", ok ? "complete" : "failed", message.c_str());
                if (ok)
                {
                    StatusPrintf(
                        "[LAN-MENU] Static target is locked to the existing cache: lua_01610_2CBD14A5E53ED76B + fallback lua_01641_5BCA1EA30C053DDD. No Lua dump/decompile or bridge scan was started.\n");
                    StatusPrintf("[LAN-MENU] Next: /lanmenu install\n");
                }
            }
            else if (sub == "install")
            {
                std::string workspace;
                if (!EnsureRetailStockLanCardWorkspace(workspace))
                {
                    StatusPrintf("[LAN-MENU] install blocked: %s\n", workspace.c_str());
                }
                else
                {
                    StatusPrintf("[LAN-MENU] install: %s\n", workspace.c_str());
                    StatusPrintf("[LAN-MENU] DirectorHub/load-ABI path is retired; invoking the existing native Lua/LUI override layer only.\n");

                    std::string patchMessage;
                    const bool patchOk = lua_native_button_patch::Apply(patchMessage);
                    StatusPrintf(
                        "[LAN-MENU] native override %s: %s\n",
                        patchOk ? "applied" : "failed",
                        patchMessage.c_str());
                    lua_native_button_patch::PrintStatus();

                    if (patchOk)
                    {
                        StatusPrintf(
                            "[LAN-MENU] Refreshing the stock frontend root. Expected root keeps CAMPAIGN / MULTIPLAYER / ZOMBIES and adds LAN MULTIPLAYER / LAN ZOMBIES.\n");
                        OpenFrontendDirectorRoot();
                    }
                    else
                    {
                        StatusPrintf(
                            "[LAN-MENU] No unknown Lua VM call was attempted. The stock-card workspace remains staged and public networking remains blocked.\n");
                    }
                }
            }
            else if (sub == "restore")
            {
                std::string message;
                const bool ok = lua_native_button_patch::Restore(message);
                StatusPrintf("[LAN-MENU] restore %s: %s\n", ok ? "complete" : "failed", message.c_str());
                lua_native_button_patch::PrintStatus();
                if (ok)
                    OpenFrontendDirectorRoot();
            }
            else if (sub == "open")
            {
                StatusPrintf("[LAN-MENU] refreshing stock frontend root; no custom LUI_OpenMenu resolver is used.\n");
                OpenFrontendDirectorRoot();
                lua_native_button_patch::PrintStatus();
            }
            else if (sub == "bridge" || sub == "load" || sub == "trace" || sub == "traceoff")
            {
                StatusPrintf(
                    "[LAN-MENU] '%s' retired in V5. Stock-card mode does not use DirectorHub, unknown Lua load ABI calls, or live bridge traces. Use /lanmenu setup then /lanmenu install.\n",
                    sub.c_str());
            }
            else
            {
                StatusPrintf("[CMD] Usage: /lanmenu status|setup|install|restore|open\n");
            }
        }
        else if (command == "/luamenu" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (sub.empty() || sub == "status")
            {
                const DWORD attrs = GetFileAttributesA("CodRevamped\\lua\\menus\\codrevamped_menu.lua");
                StatusPrintf(
                    "[LUA-MENU] workspace=%s path=CodRevamped\\lua\\menus\\codrevamped_menu.lua. Stock readable Lua is under logs\\lua\\decompiled.\n",
                    attrs != INVALID_FILE_ATTRIBUTES ? "ready" : "missing");
                PrintRetailLuaDecompileStatus();
                lua_bridge_discovery::PrintStatus();
            }
            else if (sub == "setup")
            {
                std::string message;
                const bool ok = EnsureRetailLuaMenuWorkspace(message);
                StatusPrintf("[LUA-MENU] setup %s: %s\n", ok ? "complete" : "failed", message.c_str());
            }
            else if (sub == "bridge")
            {
                std::string workspace;
                (void)EnsureRetailLuaMenuWorkspace(workspace);
                std::string message;
                const bool ok = lua_bridge_discovery::ScanNow(message);
                StatusPrintf(
                    "[LUA-MENU] bridge scan %s: %s. This validates the current-build Lua load route without blindly executing the workspace script.\n",
                    ok ? "complete" : "failed", message.c_str());
            }
            else if (sub == "loadprobe")
            {
                std::string message;
                const bool ok = lua_bridge_discovery::LoadDirectorHub(message);
                StatusPrintf(
                    "[LUA-MENU] built-in load probe %s: %s. This exercises the existing DirectorHub bridge only; CodRevamped\\lua\\menus\\codrevamped_menu.lua is not auto-executed until its file-load ABI is validated.\n",
                    ok ? "complete" : "blocked", message.c_str());
            }
            else
            {
                StatusPrintf("[CMD] Usage: /luamenu status|setup|bridge|loadprobe\n");
            }
        }
        else if (command == "/luapatch" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (sub.empty() || sub == "status")
            {
                const DWORD probe = GetFileAttributesA("CodRevamped\\lua\\patches\\weapons_nil_probe.lua");
                const DWORD hotfix = GetFileAttributesA("CodRevamped\\lua\\patches\\weapons_offline_hotfix.lua");
                const DWORD targets = GetFileAttributesA("logs\\lua\\decompiled\\patch_targets.tsv");
                StatusPrintf(
                    "[LUA-PATCH] workspace=%s probe=%s hotfix=%s targets=%s targetRows=%u publicNetwork=BLOCKED\n",
                    (probe != INVALID_FILE_ATTRIBUTES && hotfix != INVALID_FILE_ATTRIBUTES) ? "ready" : "missing",
                    probe != INVALID_FILE_ATTRIBUTES ? "ready" : "missing",
                    hotfix != INVALID_FILE_ATTRIBUTES ? "ready" : "missing",
                    targets != INVALID_FILE_ATTRIBUTES ? "ready" : "missing",
                    g_retailLuaPatchTargetsFound.load());
                PrintRetailLuaDecompileStatus();
                lua_bridge_discovery::PrintStatus();
            }
            else if (sub == "setup")
            {
                std::string message;
                const bool ok = EnsureRetailLuaPatchWorkspace(message);
                StatusPrintf("[LUA-PATCH] setup %s: %s\n", ok ? "complete" : "failed", message.c_str());
            }
            else if (sub == "analyze")
            {
                std::string workspace;
                (void)EnsureRetailLuaPatchWorkspace(workspace);
                std::string analysis;
                if (RetailLuaReuseExistingPatchTargets(analysis) ||
                    RetailLuaScanExistingDecompileForPatchTargets(analysis))
                {
                    StatusPrintf(
                        "[LUA-PATCH] analyze complete from existing cache: %s. No dump/re-decompile was started.\n",
                        analysis.c_str());
                }
                else
                {
                    // /luapatch analyze is intentionally cache-only. Never
                    // trigger another raw Lua dump/decompile from this command.
                    // Rebuilding is slow and can mix stale/current raw snapshots
                    // into duplicate ordinals. Capture the Weapons nil once and
                    // then rescan the existing readable cache.
                    StatusPrintf(
                        "[LUA-PATCH] analyze blocked: %s. Existing decompile left untouched; NO Lua dump/re-decompile was started. Click Weapons once under /mp, then run /luapatch analyze again.\n",
                        analysis.c_str());
                }
            }
            else if (sub == "bridge")
            {
                std::string workspace;
                (void)EnsureRetailLuaPatchWorkspace(workspace);
                std::string message;
                const bool ok = lua_bridge_discovery::ScanNow(message);
                StatusPrintf(
                    "[LUA-PATCH] bridge scan %s: %s. No arbitrary patch file is executed unless the current-build load ABI is validated.\n",
                    ok ? "complete" : "failed", message.c_str());
            }
            else
            {
                StatusPrintf("[CMD] Usage: /luapatch status|setup|analyze|bridge\n");
            }
        }
        else if (command == "/lua" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(
                sub.begin(),
                sub.end(),
                sub.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(
                        std::tolower(c));
                });

            if (sub.empty() || sub == "status")
            {
                StatusPrintf(
                    "[LUA-DUMP] running=%s completed=%s raw=logs\\lua\\dumped\\raw\n",
                    t9_lua_dump::IsRunning() ? "yes" : "no",
                    t9_lua_dump::HasCompleted() ? "yes" : "no");
                PrintRetailLuaDecompileStatus();
            }
            else if (sub == "dump")
            {
                StatusPrintf("[LUA-DUMP] Manual raw Lua pool dump requested.\n");
                t9_lua_dump::StartAsync();
            }
            else if (sub == "decompile")
            {
                std::string option;
                input >> option;
                std::transform(option.begin(), option.end(), option.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                const bool force = option == "force";
                if (StartRetailLuaDecompileAllAsync(false, force))
                {
                    StatusPrintf(
                        "[LUA-DECOMP] requested existing-pool decompile%s. Output -> logs\\lua\\decompiled.\n",
                        force ? " (forced rebuild)" : "");
                }
            }
            else if (sub == "dumpall" || sub == "all")
            {
                if (StartRetailLuaDecompileAllAsync(true, true))
                    StatusPrintf("[LUA-DECOMP] dumpall requested: current-process raw pool -> full readable decompile/disassembly.\n");
            }
            else
            {
                StatusPrintf("[CMD] Usage: /lua status|dump|decompile [force]|dumpall\n");
            }
        }
        else if (command == "/profile" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string sub;
            input >> sub;
            std::transform(sub.begin(), sub.end(), sub.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (sub.empty() || sub == "status")
            {
                StatusPrintf("[PROFILE] %s\n", lan_profile_research::ProfileStatus().c_str());
            }
            else if (sub == "dump")
            {
                std::string message;
                const bool ok =
                    lan_profile_research::DumpProfile(message);

                StatusPrintf(ok ? "[PROFILE] OK: %s\n" : "[PROFILE] FAILED: %s\n", message.c_str());
            }
            else if (sub == "analyze")
            {
                std::string message;
                const bool ok =
                    lan_profile_research::AnalyzeProfile(message);

                StatusPrintf(ok ? "[PROFILE] OK: %s\n" : "[PROFILE] FAILED: %s\n", message.c_str());
            }
            else if (sub == "name")
            {
                const std::string name = ReadRemainingArgument(input);
                if (name.empty())
                {
                    client_identity::PrintStatus(g_activeGameKind);
                }
                else
                {
                    std::string message;
                    client_identity::SetAndApply(g_activeGameKind, name, message);
                    StatusPrintf("[PROFILE] %s\n", message.c_str());
                }
            }
            else
            {
                StatusPrintf("[CMD] Usage: /profile status|dump|analyze|name <name>\n");
            }
        }
        else if (command == "/verbose")
        {
            std::string value;
            input >> value;
            std::transform(value.begin(), value.end(), value.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (value == "on") g_showVerboseConsole.store(true);
            else if (value == "off") g_showVerboseConsole.store(false);
            else { StatusPrintf("[CMD] Usage: /verbose on|off\n"); return; }
            StatusPrintf("[CMD] Verbose scanner output %s.\n", g_showVerboseConsole.load() ? "enabled" : "disabled");
        }
        else if (command == "/clear")
            system("cls");
        else if (command == "/game" && g_activeGameKind == games::GameKind::Retail)
        {
            std::string gameCommand;
            std::getline(input, gameCommand);
            while (!gameCommand.empty() && std::isspace(static_cast<unsigned char>(gameCommand.front())))
                gameCommand.erase(gameCommand.begin());
            if (gameCommand.empty()) StatusPrintf("[CMD] Usage: /game <command>\n");
            else ExecuteDeveloperCommand(gameCommand.c_str());
        }
        else if (command == "/exit")
        {
            g_commandConsoleRunning.store(false);
            StatusPrintf("[CMD] Slash-command input stopped. Network blocking and offline state remain active.\n");
        }
        else if (g_activeGameKind == games::GameKind::Retail && command.size() > 1)
        {
            const std::string dvarName = command.substr(1);
            const std::string dvarValue = ReadRemainingArgument(input);
            std::string message;
            const auto result = t9_dvars::ExecuteBuiltinSlashDvar(dvarName, dvarValue, message);
            if (result == t9_dvars::ExecuteResult::Set || result == t9_dvars::ExecuteResult::Read)
                StatusPrintf("[CMD] OK: %s\n", message.c_str());
            else if (result == t9_dvars::ExecuteResult::Rejected || result == t9_dvars::ExecuteResult::Fault)
                StatusPrintf("[CMD] FAILED: %s\n", message.c_str());
            else
                StatusPrintf("[CMD] Unknown command: %s. Use /help or /helpscan.\n", command.c_str());
        }
        else
            StatusPrintf("[CMD] Unknown command: %s. Use /help or /helpscan.\n", command.c_str());
    }

    static void RedrawSlashPrompt(HANDLE output, const std::wstring& buffer)
    {
        CONSOLE_SCREEN_BUFFER_INFO info{};
        if (!GetConsoleScreenBufferInfo(output, &info))
            return;

        COORD start{ 0, info.dwCursorPosition.Y };
        DWORD written = 0;
        FillConsoleOutputCharacterW(output, L' ', static_cast<DWORD>(info.dwSize.X), start, &written);
        FillConsoleOutputAttribute(output, info.wAttributes, static_cast<DWORD>(info.dwSize.X), start, &written);
        SetConsoleCursorPosition(output, start);

        const std::wstring prompt = L"T9> " + buffer;
        WriteConsoleW(output, prompt.c_str(), static_cast<DWORD>(prompt.size()), &written, nullptr);

        COORD editCursor{
            static_cast<SHORT>(std::min<int>(
                info.dwSize.X - 1, static_cast<int>(4 + buffer.size()))),
            start.Y
        };
        SetConsoleCursorPosition(output, editCursor);
    }

    static DWORD WINAPI SlashCommandThread(LPVOID)
    {
        // Open the console device directly. Some T9 beta startup paths replace or
        // inherit unusable STD_INPUT/STD_OUTPUT handles even though the CMD window
        // is visible. CONIN$/CONOUT$ bind us to the actual allocated console.
        HANDLE directInput = CreateFileW(
            L"CONIN$",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
        HANDLE directOutput = CreateFileW(
            L"CONOUT$",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);

        const bool directInputOk = directInput != INVALID_HANDLE_VALUE && directInput != nullptr;
        const bool directOutputOk = directOutput != INVALID_HANDLE_VALUE && directOutput != nullptr;

        HANDLE input = directInputOk ? directInput : GetStdHandle(STD_INPUT_HANDLE);
        HANDLE output = directOutputOk ? directOutput : GetStdHandle(STD_OUTPUT_HANDLE);

        if (input == INVALID_HANDLE_VALUE || input == nullptr ||
            output == INVALID_HANDLE_VALUE || output == nullptr)
        {
            StatusPrintf("[CMD] Console handles are unavailable (input=%p output=%p error=%lu).\n",
                input, output, GetLastError());
            if (directInputOk) CloseHandle(directInput);
            if (directOutputOk) CloseHandle(directOutput);
            return 1;
        }

        DWORD originalMode = 0;
        if (!GetConsoleMode(input, &originalMode))
        {
            StatusPrintf("[CMD] GetConsoleMode failed (input=%p error=%lu).\n", input, GetLastError());
            if (directInputOk) CloseHandle(directInput);
            if (directOutputOk) CloseHandle(directOutput);
            return 1;
        }

        DWORD commandMode = originalMode |
            ENABLE_EXTENDED_FLAGS |
            ENABLE_PROCESSED_INPUT |
            ENABLE_LINE_INPUT |
            ENABLE_ECHO_INPUT;
        commandMode &= ~(ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT | ENABLE_QUICK_EDIT_MODE);

        if (!SetConsoleMode(input, commandMode))
        {
            StatusPrintf("[CMD] SetConsoleMode failed (error %lu); continuing with the existing mode.\n",
                GetLastError());
        }

        FlushConsoleInputBuffer(input);

        PrintSlashHelp();
        StatusPrintf(
            "[CMD] Console input ready: backend=%s output=%s thread=%lu mode=0x%08lX.\n",
            directInputOk ? "CONIN$" : "STD_INPUT_HANDLE",
            directOutputOk ? "CONOUT$" : "STD_OUTPUT_HANDLE",
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long>(commandMode));
        if (g_activeGameKind == games::GameKind::Retail)
            StatusPrintf("[CMD] Ready. Example: /apply camo list\n");
        else if (g_activeGameKind == games::GameKind::Beta)
            StatusPrintf("[CMD] Ready. Open Beta service-fence scan is automatic; let Connecting/error run, then copy this CMD output back here. No camo code runs on Beta.\n");

        constexpr DWORD kLineCapacity = 2048;
        wchar_t line[kLineCapacity]{};

        while (g_commandConsoleRunning.load())
        {
            DWORD written = 0;
            WriteConsoleW(output, L"T9> ", 4, &written, nullptr);

            DWORD charsRead = 0;
            ZeroMemory(line, sizeof(line));
            if (!ReadConsoleW(input, line, kLineCapacity - 1, &charsRead, nullptr))
            {
                const DWORD error = GetLastError();
                StatusPrintf("\n[CMD] ReadConsoleW failed (backend=%s error=%lu).\n",
                    directInputOk ? "CONIN$" : "STD_INPUT_HANDLE", error);
                Sleep(100);
                continue;
            }

            std::wstring commandLine(line, line + charsRead);
            while (!commandLine.empty() &&
                (commandLine.back() == L'\r' || commandLine.back() == L'\n' ||
                 commandLine.back() == L'\0'))
            {
                commandLine.pop_back();
            }

            if (!commandLine.empty())
                ExecuteSlashCommand(commandLine);
        }

        SetConsoleMode(input, originalMode);
        if (directInputOk) CloseHandle(directInput);
        if (directOutputOk) CloseHandle(directOutput);
        return 0;
    }

    static void StartSlashCommandConsole()
    {
        if (g_commandConsoleStarted.exchange(true)) return;
        HANDLE thread = CreateThread(nullptr, 0, SlashCommandThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        else StatusPrintf("[CMD] Failed to start slash-command console (error %lu).\n", GetLastError());
    }
}
