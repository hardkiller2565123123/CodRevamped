"""Checks against accidentally regressing later bot and matchmaking overlays."""
from pathlib import Path
r=Path(__file__).resolve().parents[4]
files={
 'src/clients/mw2019/Features/Bots/BotSystem.h':['HostLaunchTrace','s_hostLaunchTrace.RecordReady','s_hostLaunchTrace.RecordStart','BOT120-LAUNCH'],
 'src/clients/mw2019/Features/Bots/BotProfiles.cpp':['BotProfiles'],
 'src/clients/mw2019/Features/Loading/HostLaunchTrace.h':['HostLaunchTrace'],
 'src/clients/mw2019/Features/CustomMaps/CustomMapProbe.h':['codrevamped-map-package'],
 'src/clients/mw2019/Features/Fastfiles/VerdanskCollisionMode.h':['Collision'],
 'src/backend/iw8/ReplayDW/src/Services/Matchmaking/matchmaking_services.cpp':['matchmaking'],
}
for rel,need in files.items():
 p=r/rel;assert p.is_file(),p
 s=p.read_text(encoding='utf-8',errors='replace')
 for term in need:assert term.lower() in s.lower(),(rel,term)
print('Bot population/start handoff, matchmaking, collision and map probe included: PASS')
