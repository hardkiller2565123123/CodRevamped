"""Portable source/project contract + optional genuine Lua VM smoke test.
The smoke test uses system Lua 5.4, not the game's LuaJIT VM; it verifies Lua
syntax/control construction only and is never evidence of Replay execution.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
import ctypes
import ctypes.util
import json
import re

root=Path(__file__).resolve().parents[4]
ui=root/'src/tools/IW8Tools/Editor'
preview=ET.parse(ui/'LuaMenuWorkbench.xaml').getroot()
window=(ui/'LuaMenuWorkbench.xaml.cs').read_text(encoding='utf-8')
model=(ui/'LuaMenuProject.cs').read_text(encoding='utf-8')
main=(ui/'MainWindow.xaml').read_text(encoding='utf-8')
cpp=(root/'src/clients/mw2019/Features/Lua/LuaMenuRuntime.cpp').read_text(encoding='utf-8')
client=(root/'src/clients/mw2019/MW2019RedirectProxy.cpp').read_text(encoding='utf-8')
vcxproj=(root/'build/clients/mw2019/mw2019.vcxproj').read_text(encoding='utf-8')
for node in preview.iter():
    for key in ['Click','MouseMove','MouseLeftButtonUp','MouseLeftButtonDown','SelectionChanged','LostFocus']:
        if key in node.attrib:
            assert node.attrib[key]+'(' in window, (node.tag,node.attrib)
assert 'OpenLuaWorkbench_Click' in main
assert 'LuaMenuWorkbench' in (ui/'MainWindow.xaml.cs').read_text()
for template in ['Gunsmith','Loadouts','Multiplayer','Warzone']:
    assert template in (ui/'LuaMenuWorkbench.xaml').read_text()
assert 'LUI.createMenu' in model and 'LUI.MenuBuilder.registerType' in model
assert 'Validate(project)' in model
assert 'experimental_load' in cpp and '0x3E' in cpp
assert '0x11868880' in cpp and '0x01B9BDB0' in cpp
assert 'LuaMenuRuntime.cpp' in vcxproj and 'luamenus::Install' in client
assert 'LuaMenuCompiler.VerifyReplay120Executable' in window
assert 'luaL_loadfile_FastFile' not in cpp # don't graft in upstream implementation
example=root/'examples/lua/CRGunsmithPanel'
doc=json.loads((example/'menu.project.json').read_text())
manifest=json.loads((example/'menu.build.json').read_text())
assert doc['MenuId']==manifest['id'] and manifest['runtime']=='requires-verified-lui-loader'
assert len(doc['Widgets'])==manifest['widgets']==2
assert not (root/'src/tools/IW8Tools/Editor').joinpath('LuaMenuRuntime.dll').exists()

source=(example/'CRGunsmithPanel.lua').read_bytes()
libname=ctypes.util.find_library('lua5.4')
if libname:
    lua=ctypes.CDLL(libname)
    lua.luaL_newstate.argtypes=[]; lua.luaL_newstate.restype=ctypes.c_void_p
    lua.luaL_openlibs.argtypes=[ctypes.c_void_p]
    lua.luaL_loadbufferx.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_size_t,ctypes.c_char_p,ctypes.c_char_p]
    lua.luaL_loadbufferx.restype=ctypes.c_int
    lua.lua_pcallk.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_longlong,ctypes.c_void_p]
    lua.lua_pcallk.restype=ctypes.c_int
    lua.lua_close.argtypes=[ctypes.c_void_p]
    state=lua.luaL_newstate()
    assert state
    try:
        lua.luaL_openlibs(state)
        harness='''
        LUI = {UIElement={},UIText={},MenuBuilder={}}
        local function element()
            local o={children={}}
            function o:registerAnimationState(name,value) assert(type(value)=="table") end
            function o:animateToState(name,duration) end
            function o:setText(text) assert(type(text)=="string") end
            function o:addElement(child) table.insert(self.children,child) end
            return o
        end
        LUI.UIElement.new=element
        LUI.UIText.new=element
        function LUI.MenuBuilder.registerType(key,fn) LUI.MenuBuilder[key]=fn end
        '''.encode()
        def run(code,name):
            assert lua.luaL_loadbufferx(state,code,len(code),name,b't')==0, 'Lua parse error'
            assert lua.lua_pcallk(state,0,0,0,0,None)==0, 'Lua runtime error'
        run(harness,b'bootstrap')
        run(source,b'CRGunsmithPanel.lua')
        run(b'local result = LUI.MenuBuilder["CRGunsmithPanel"](0); assert(#result.children == 2)',b'smoke')
        print('Lua 5.4 syntax + LUI widget construction: PASS (not the game VM)')
    finally:
        lua.lua_close(state)
else:
    print('No system Lua library; source contract checks only')
print('Lua editor, client integration, project paths, and export contracts: PASS')
