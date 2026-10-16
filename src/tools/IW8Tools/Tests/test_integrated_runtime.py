"""Static integration and record-layout regression checks (not a Windows/game test)."""
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[4]
client=ROOT/'src/clients/mw2019'
runtime=(client/'Features/CustomMaps/CustomMapRuntime.cpp').read_text()
proxy=(client/'MW2019RedirectProxy.cpp').read_text()
editor=(ROOT/'src/tools/IW8Tools/Editor/Replay120MapLoader.cs').read_text()
xaml=(ROOT/'src/tools/IW8Tools/Editor/MainWindow.xaml').read_text()
project=ET.parse(ROOT/'build/clients/mw2019/mw2019.vcxproj').getroot()
ns={'b':'http://schemas.microsoft.com/developer/msbuild/2003'}
units=[e.attrib['Include'] for e in project.findall('.//b:ClCompile',ns) if 'Include' in e.attrib]
assert sum('CustomMapRuntime.cpp' in u for u in units)==1
assert 'codrevamped::replay120::custommaps::Install(' in proxy
assert 'MW120' in proxy and 'Replay120CompatEnabled()' in proxy
assert 'CODREVAMPED_NATIVE_MAPS_V1' in runtime and 'CODREVAMPED_NATIVE_MAPS_V1' in editor
assert 'ClientName = "version.dll"' in editor
assert 'XInput9_1_0' not in editor and 'XInput9_1_0' not in xaml
assert '"maps"' in runtime and 'g_root=fs::path(exe).parent_path()/"maps";' in runtime
assert 'MemoryReadable' in runtime and 'MemoryWritable' in runtime
assert 'kDiskOpen,kDiskBytes' in runtime and 'kResetReader,kResetBytes' in runtime
assert 'kLoadMapInfo,kListBytes' in runtime and 'kOverlay,kOverlayBytes' in runtime
assert 'RefreshSelection();' in runtime and 'OnMainThreadOverlay' in runtime
assert 'MH_RemoveHook' in runtime and 'g_originalReset(reader)' in runtime
# DW_MapAvailability.cpp documents the native gameInfo structure independently:
# header+32 game modes then mapCount and 128 map rows of 1240 bytes.
mode_row=172
map_row=1240
native_gameinfo_rva=0x0C4FC330
assert native_gameinfo_rva+4+32*mode_row==0x0C4FD8B4
assert native_gameinfo_rva+4+32*mode_row+4==0x0C4FD8B8
assert map_row==0x4D8
assert 0x0C4FD8B8+128*map_row<0x1324B000
assert 'kMapCount = 0x0C4FD8B4' in runtime
assert 'kMapRows = 0x0C4FD8B8' in runtime
assert 'kRowStride = 0x4D8' in runtime
print('Integrated version.dll hooks, package root, editor and map-info ABI checks: PASS')
