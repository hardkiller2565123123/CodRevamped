"""Offline source contract check. Windows WPF + actual game runtime MUST be tested separately."""
from pathlib import Path
from xml.etree import ElementTree as ET
import json

root = Path(__file__).resolve().parents[4]
editor = root / 'src/tools/IW8Tools/Editor'
xaml = ET.parse(editor / 'MainWindow.xaml').getroot()
source = (editor / 'MainWindow.xaml.cs').read_text()
bridge = (editor / 'Replay120MapLoader.cs').read_text()
probe = (root / 'src/clients/mw2019/Features/CustomMaps/CustomMapProbe.h').read_text()
handlers = [x.attrib['Click'] for x in xaml.iter() if 'Click' in x.attrib]
assert all(name + '(' in source for name in handlers)
assert len(handlers) >= 35
assert 'mp_tdm_spawn_allies_start' in source and 'mp_tdm_spawn_axis_start' in source
assert 'materialDefinition=$"{id}.d3dbsp.material.json"' in source
assert 'Path.Combine(gameRoot, "maps", id)' in bridge
assert 'CODREVAMPED_NATIVE_MAPS_V1' in bridge
assert 'mods", "mw120r", "maps"' not in bridge
assert '1C238FE327F2ECC3B0DB924C5B425439' in bridge
assert 'SHA256.HashData' in bridge and 'ExpectedReplayMd5' in bridge
assert 'SafeChildren(gameRoot' in bridge
assert 'codrevamped-map-package' in probe
project = root / 'examples/mp_crtest'
scene = json.loads((project / 'source/scene.json').read_text())
assert len(scene) >= 7 and any(x['Name'] == 'ArenaFloor' for x in scene)
assert any(x.get('Shape') == 'ramp' for x in scene)
assert any(x.get('Shape') == 'cylinder' for x in scene)
# Source distribution does not include generated .txt entities;
# the editor regenerates them from source/spawns.json during export.
spawns = json.loads((project / 'source/spawns.json').read_text())
assert {'info_player_start', 'mp_tdm_spawn', 'mp_tdm_spawn_allies_start',
        'mp_tdm_spawn_axis_start'} <= {spawn['Type'] for spawn in spawns}
assert 'WriteTdmSpawns(root,id)' in source and '_iw8_ents.txt' in source
assert 'XInput9_1_0.dll' not in bridge
assert 'Native runtime requires an upstream' not in (editor/'MainWindow.xaml').read_text()
print('IW8Tools XAML, integrated version.dll deployment, TDM source, and sample project contracts: PASS')
