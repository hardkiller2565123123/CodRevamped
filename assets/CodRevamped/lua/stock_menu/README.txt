CodRevamped Cold War - stock LAN card workspace (V5)

Primary stock datasource candidate: lua_01610_2CBD14A5E53ED76B.luac
Fallback/root candidate: lua_01641_5BCA1EA30C053DDD.luac
Both were selected from the existing readable cache; no new dump/decompile is required.

Desired stock root order:
  CAMPAIGN
  MULTIPLAYER
  ZOMBIES
  LAN MULTIPLAYER
  LAN ZOMBIES

LAN cards route through LuaUtils.GetLanSelectMenu after setting lobbyRoot.mainMode.
Normal Multiplayer/Zombies cards are preserved.
Public COD/Demonware filtering remains blocked by the DLL.
The old DirectorHub arbitrary-file loader is not used by /lanmenu anymore.

/lanmenu commands:
  /lanmenu status
  /lanmenu setup
  /lanmenu install
  /lanmenu restore
  /lanmenu open
