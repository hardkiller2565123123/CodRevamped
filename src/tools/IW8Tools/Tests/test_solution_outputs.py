"""Validate a single VS IW8Tools entry, x64-only targets, and artifacts outputs.
Portable structural checks; not a substitute for an MSVC/VS build.
"""
from pathlib import Path
import re
import xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[4]
sln=(root/'CodRevamped.sln').read_text(encoding='utf-8-sig')
projects=re.findall(r'^Project\("\{[^\n]+?"\) = "([^"]+)", "([^"]+\.(?:vcxproj|csproj))", "(\{[A-F0-9-]+\})"',sln,re.M)
assert len(projects)==17,(len(projects),projects)
assert len({g for _,_,g in projects})==17
assert [n for n,_,_ in projects if n in {'IW8Tools','IW8FastfileLab','IW8MapPack','IW8ReverseLab','MWAssetLab'}]==['IW8Tools']
assert 'Debug|Win32' not in sln and 'Release|Win32' not in sln
assert 'Debug|Any CPU = ' not in sln and 'Release|Any CPU = ' not in sln
for n,rel,guid in projects:
    p=root/rel.replace('\\','/')
    assert p.is_file(),p
    ET.parse(p)
    if p.suffix=='.vcxproj':
        xml=p.read_text(encoding='utf-8-sig')
        assert '<CodRevampedRoot>$(MSBuildThisFileDirectory)' in xml, p
        assert 'DLLs\\' not in xml and '<OutDir>$(CodRevampedRoot)Servers\\' not in xml
        assert 'artifacts\\' in xml
for game in ('bo4','coldwar','mw2019','bo6','mw3'):
    p=root/f'build/clients/{game}/{game}.vcxproj'
    assert f'artifacts\\dll\\{game.upper() if game != "coldwar" else "ColdWar"}\\' in p.read_text().replace('BO4\\','BO4\\') if game!='mw2019' else 'artifacts\\dll\\MW2019\\' in p.read_text()
    assert '<TargetName>version</TargetName>' in p.read_text()
assert 'artifacts\\dll\\BO4\\' in (root/'build/clients/bo4/internal/Bootstrap.vcxproj').read_text()
assert 'artifacts\\server\\$(Configuration)' in (root/'build/backend/IW8Server.vcxproj').read_text()
ui=root/'src/tools/IW8Tools/Editor'
cs=(ui/'IW8Tools.Editor.csproj').read_text()
assert 'artifacts\\tools\\$(Configuration)\\IW8Tools' in cs
assert 'IW8ToolsNative.vcxproj' in cs and 'Platform=x64' in cs
native=root/'build/tools/IW8ToolsNative/IW8ToolsNative.vcxproj'
nt=native.read_text()
assert 'artifacts\\tools\\$(Configuration)\\IW8Tools' in nt
for tool in ('IW8MapPack','IW8FastfileLab','IW8ReverseLab','MWAssetLab'):
    assert (f'{tool}.cpp' in nt) and ('_Entry' in nt)
    assert not (root/f'build/tools/{tool}/{tool}.vcxproj').exists()
assert 'Path.Combine(gameRoot, "maps", id)' in (ui/'Replay120MapLoader.cs').read_text()
assert 'return root/"maps"/id' in (root/'src/tools/IW8MapPack/IW8MapPack.cpp').read_text()
assert (root/'src/clients/mw2019/Features/Bots/BotSystem.h').stat().st_size>65000
assert (root/'src/backend/iw8/ReplayDW/src/Services/Matchmaking/matchmaking_services.cpp').exists()
print('17 solution entries; 1 IW8Tools project; x64-only; artifacts output; native bundling: PASS')
