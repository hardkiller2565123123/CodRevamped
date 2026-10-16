// CodRevamped original implementation. No third-party loader code is included.
// Experimental Replay 1.20 LUI LuaFile asset bridge.
// The engine's LuaCoD_VmLoader performs DB_FindXAssetHeader(type=LUAFILE, name),
// and LuaCoD_SetLuaLoader installs the require() package loader. This module
// supplies *only* explicitly staged ui/codrevamped/<id>.lua LuaFile assets.
// A first LUI_OpenMenu UI-thread callback invokes require() to register them.
// This code is opt-in until live 1.20 VM/API validation is complete.
#include "LuaMenuRuntime.h"
#include <windows.h>
#include <MinHook.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace codrevamped::replay120::luamenus {
namespace {
namespace fs = std::filesystem;
constexpr std::uintptr_t kFindAsset = 0x011AA890;  // Replay 1.20 DB_FindXAssetHeader
constexpr std::uintptr_t kOpenMenu = 0x01B9BDB0;   // Replay 1.20 LUI_OpenMenu
constexpr std::uintptr_t kVmGlobal = 0x11868880; // LUI_luaVM
constexpr std::uintptr_t kLuaGetTop = 0x020838B0;
constexpr std::uintptr_t kLuaGetField = 0x020836E0;
constexpr std::uintptr_t kLuaPushString = 0x02084120;
constexpr std::uintptr_t kLuaSetTop = 0x02084790;
constexpr std::uintptr_t kLuaToString = 0x02084950;
constexpr std::uintptr_t kLuaPCall = 0x019B7570;
constexpr int kLuaFileType = 0x3E;
struct LuaFile { const char* name{}; std::int32_t length{}; std::uint8_t stripping{}; std::uint8_t pad[3]{}; const char* buffer{}; };
static_assert(sizeof(LuaFile)==24);
struct Entry {
    std::string name; std::string body; std::string module; LuaFile asset{};
};
using FindAssetFn = void*(__fastcall*)(int, const char*, int);
using OpenMenuFn = void(__fastcall*)(int, const char*, int, int, int);
using LuaGetTopFn = int(__fastcall*)(void*);
using LuaGetFieldFn = void(__fastcall*)(void*, int, const char*);
using LuaPushStringFn = void(__fastcall*)(void*, const char*);
using LuaSetTopFn = void(__fastcall*)(void*, int);
using LuaToStringFn = const char*(__fastcall*)(void*,int,std::size_t*);
using LuaPCallFn = int(__fastcall*)(void*, int, int);
std::vector<std::unique_ptr<Entry>> entries;
FindAssetFn originalFind = nullptr;
OpenMenuFn originalOpen = nullptr;
LogFn logger = nullptr;
std::uintptr_t imageBase = 0;
std::atomic<bool> busy{false};
std::atomic<bool> ready{false};
std::atomic<unsigned> tries{0};
fs::path requestFile;
std::atomic<unsigned> menuTrace{0};

bool Id(const std::string& value) {
    if (value.size()<2 || value.size()>64 || !(std::isalpha((unsigned char)value[0]) || value[0]=='_')) return false;
    return std::all_of(value.begin()+1,value.end(),[](unsigned char ch){return std::isalnum(ch)||ch=='_';});
}
bool SectionExecutable(std::uintptr_t rva, std::uint32_t imageSize) {
    if (rva>=imageSize || !imageBase) return false;
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(imageBase+rva),&info,sizeof(info)) != sizeof(info)) return false;
    const auto protection=info.Protect & 0xFFu;
    return info.State==MEM_COMMIT && (protection==PAGE_EXECUTE || protection==PAGE_EXECUTE_READ ||
        protection==PAGE_EXECUTE_READWRITE || protection==PAGE_EXECUTE_WRITECOPY);
}
bool Match(std::uintptr_t rva,const std::uint8_t* expected,const char* mask,std::size_t size,std::uint32_t imageSize) {
    if (!SectionExecutable(rva,imageSize) || rva+size>imageSize) return false;
    const auto* actual=reinterpret_cast<const std::uint8_t*>(imageBase+rva);
    for(std::size_t i=0;i<size;++i) if(mask[i]=='x' && actual[i]!=expected[i]) return false;
    return true;
}
// Replays documented prologues and 1.20 OpenMenu signature; all other Lua
// functions are checked for executable pages, then protected by opt-in.
bool Verify(std::uint32_t imageSize) {
    constexpr std::uint8_t find[] = {0x48,0x89,0x5C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7C,0x24,0x20};
    constexpr std::uint8_t open[] = {0x48,0x89,0x5C,0x24,0,0x48,0x89,0x74,0x24,0,0x57,0x48,0x83,0xEC,0,0x41,0x8B,0xF1,0x41,0x8B,0xD8};
    if (!Match(kFindAsset,find,"xxxxxxxxxxxxxxx",sizeof(find),imageSize) ||
        !Match(kOpenMenu,open,"xxxx?xxxx?xxxx?xxxxxx",sizeof(open),imageSize)) return false;
    for(const auto rva:{kLuaGetTop,kLuaGetField,kLuaPushString,kLuaSetTop,kLuaToString,kLuaPCall})
        if(!SectionExecutable(rva,imageSize))return false;
    return kVmGlobal+sizeof(void*)<=imageSize;
}
bool Read(const fs::path& path,std::string& out) {
    std::error_code ec;
    if (!fs::is_regular_file(path,ec)||fs::is_symlink(path,ec) || fs::file_size(path,ec)>256*1024 || ec) return false;
    std::ifstream file(path,std::ios::binary);
    if(!file) return false;
    out.assign(std::istreambuf_iterator<char>(file),{});
    return !out.empty() && out.size()<=256*1024 && out.find('\0')==std::string::npos;
}
void Scan(const fs::path& gameRoot) {
    entries.clear();
    const auto root=gameRoot/"lua";
    std::error_code ec;
    if(!fs::is_directory(root,ec)||fs::is_symlink(root,ec)) return;
    for(fs::directory_iterator it(root,ec),end;!ec && it!=end && entries.size()<32;it.increment(ec)) {
        if(!it->is_directory(ec)||it->is_symlink(ec))continue;
        const auto id=it->path().filename().string();
        if(!Id(id))continue;
        // Explicit manifest requirement prevents arbitrary *.lua auto-execution.
        std::string manifest,source;
        if(!Read(it->path()/"menu.build.json",manifest) ||
           manifest.find("\"runtime\": \"requires-verified-lui-loader\"")==std::string::npos ||
           manifest.find("\"id\": \""+id+"\"")==std::string::npos ||
           !Read(it->path()/(id+".lua"),source)) continue;
        auto entry=std::make_unique<Entry>();
        entry->name="ui/codrevamped/"+id+".lua";
        entry->module="ui.codrevamped."+id;
        entry->body=std::move(source);
        entry->asset.name=entry->name.c_str();
        entry->asset.length=static_cast<std::int32_t>(entry->body.size());
        entry->asset.buffer=entry->body.data();
        entries.push_back(std::move(entry));
    }
}
void* __fastcall FindLuaFile(int type,const char* name,int allowDefault) {
    if(type==kLuaFileType && name) {
        // The Lua source arrays remain immutable for the lifetime of the hook.
        for(const auto& entry:entries)
            if(entry->name==name) return &entry->asset;
    }
    return originalFind ? originalFind(type,name,allowDefault):nullptr;
}
bool TryRequire() {
    if(entries.empty())return true;
    auto* vm=*reinterpret_cast<void**>(imageBase+kVmGlobal);
    if(!vm)return false;
    const auto getTop=reinterpret_cast<LuaGetTopFn>(imageBase+kLuaGetTop);
    const auto getField=reinterpret_cast<LuaGetFieldFn>(imageBase+kLuaGetField);
    const auto push=reinterpret_cast<LuaPushStringFn>(imageBase+kLuaPushString);
    const auto setTop=reinterpret_cast<LuaSetTopFn>(imageBase+kLuaSetTop);
    const auto toString=reinterpret_cast<LuaToStringFn>(imageBase+kLuaToString);
    const auto pcall=reinterpret_cast<LuaPCallFn>(imageBase+kLuaPCall);
    // Invoked on the native LUI menu callback thread (no worker VM calls).
    const int baseTop=getTop(vm);
    if(baseTop<0||baseTop>1024)return false;
    bool ok=true;
    for(const auto& entry:entries) {
        getField(vm,-10002,"require");
        push(vm,entry->module.c_str());
        const int result=pcall(vm,1,0);
        if(result!=0) {
            ok=false;
            if(logger) {
                const char* message=toString(vm,-1,nullptr);
                logger("[LUA120] require %s error=%.*s\r\n",entry->module.c_str(),256,message?message:"unknown Lua error");
            }
        } else if(logger) logger("[LUA120] require %s ok\r\n",entry->module.c_str());
        setTop(vm,baseTop);
    }
    return ok;
}
void CheckOpenRequest(int client) {
    if(!ready.load(std::memory_order_acquire) || requestFile.empty() || !originalOpen) return;
    std::error_code ec;
    if(!fs::is_regular_file(requestFile,ec) || fs::is_symlink(requestFile,ec) || fs::file_size(requestFile,ec)>128 || ec)return;
    std::ifstream request(requestFile,std::ios::binary);
    if(!request)return;
    std::string id;
    std::getline(request,id);
    request.close();
    if(!Id(id))return;
    for(const auto& entry:entries) {
        if(entry->name!="ui/codrevamped/"+id+".lua")continue;
        // Explicit, one-time local test request. No arbitrary commands accepted.
        fs::remove(requestFile,ec);
        if(ec) { if(logger)logger("[LUA120] could not consume test request (%d)\r\n",ec.value());return; }
        if(logger)logger("[LUA120] opening custom test menu=%s\r\n",id.c_str());
        originalOpen(client,id.c_str(),1,0,0);
        return;
    }
}
void __fastcall OpenMenu(int client,const char* menu,int popup,int modal,int exclusive) {
    // One-shot module registration *before* native opening of a menu. This
    // source still requires a live 1.20 test to confirm VM lock ownership.
    if(!ready.load(std::memory_order_acquire) && !busy.exchange(true)) {
        const unsigned attempt=tries.fetch_add(1)+1;
        if(attempt<=3 && TryRequire())ready.store(true,std::memory_order_release);
        busy.store(false);
    }
    if(logger && menu && menuTrace.fetch_add(1)<24)
        logger("[LUA120] LUI_OpenMenu observed name=%s\r\n",menu);
    if(originalOpen)originalOpen(client,menu,popup,modal,exclusive);
    CheckOpenRequest(client);
}
bool Hook(std::uintptr_t rva,void* detour,void** original) {
    auto* address=reinterpret_cast<void*>(imageBase+rva);
    const auto create=MH_CreateHook(address,detour,original);
    if(create!=MH_OK)return false;
    if(MH_EnableHook(address)!=MH_OK) { MH_RemoveHook(address);return false; }
    return true;
}
} // namespace
bool Install(std::uintptr_t base,std::uint32_t imageSize,LogFn log) noexcept {
    try {
        logger=log; imageBase=base;
        wchar_t exe[32768]{};
        if(!GetModuleFileNameW(nullptr,exe,static_cast<DWORD>(std::size(exe))))return false;
        const fs::path gameRoot=fs::path(exe).parent_path();
        const auto config=gameRoot/"codrevamped_lua.ini";
        requestFile=gameRoot/"lua"/"open_request.ini";
        if(!GetPrivateProfileIntW(L"lua",L"experimental_load",0,config.c_str())) {
            if(log)log("[LUA120] source loader disabled (codrevamped_lua.ini experimental_load=0)\r\n");
            return false;
        }
        if(!Verify(imageSize)) {if(log)log("[LUA120] unverified VM/map bindings; no hooks installed\r\n");return false;}
        Scan(gameRoot);
        if(entries.empty()) {if(log)log("[LUA120] no built menus staged in game/lua; no hooks installed\r\n");return false;}
        if(!Hook(kFindAsset,reinterpret_cast<void*>(&FindLuaFile),reinterpret_cast<void**>(&originalFind)))return false;
        if(!Hook(kOpenMenu,reinterpret_cast<void*>(&OpenMenu),reinterpret_cast<void**>(&originalOpen))) {
            MH_DisableHook(reinterpret_cast<void*>(imageBase+kFindAsset));
            MH_RemoveHook(reinterpret_cast<void*>(imageBase+kFindAsset));
            originalFind=nullptr;return false;
        }
        if(log)log("[LUA120] EXPERIMENTAL LuaFile provider installed entries=%zu (in-game behavior unverified)\r\n",entries.size());
        return true;
    } catch(...) {if(log)log("[LUA120] exception during experimental setup; loader unavailable\r\n");return false;}
}
} // namespace codrevamped::replay120::luamenus
