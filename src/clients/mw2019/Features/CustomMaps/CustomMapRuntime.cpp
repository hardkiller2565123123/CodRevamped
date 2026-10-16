#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include "CustomMapRuntime.h"
#include "../../../../shared/common/utils/MinHook.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

// Only the five known 1.20 zones are routed. Never redirect a stock-map path,
// arbitrary loose file, other game's fastfile, or an unvalidated map package.
// The engine's original handle, reader and zone ownership remains unchanged.
namespace codrevamped::replay120::custommaps {
namespace {
namespace fs = std::filesystem;
constexpr std::uintptr_t kDiskOpen = 0x013F4D50;
constexpr std::uintptr_t kResetReader = 0x00D871E0;
constexpr std::uintptr_t kInitInflater = 0x00D88120;
constexpr std::uintptr_t kLoadMapInfo = 0x010C7E70;
constexpr std::uintptr_t kGetDvarString = 0x013E69B0;
constexpr std::uintptr_t kOverlay = 0x015E1340;
constexpr std::uintptr_t kMapCount = 0x0C4FD8B4;
constexpr std::uintptr_t kMapRows = 0x0C4FD8B8;
constexpr std::size_t kRowStride = 0x4D8, kMaxRows = 128;
constexpr std::array<unsigned char, 15> kDiskBytes = {0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x40,0x8B,0xDA,0x48,0x8B,0xF9};
constexpr std::array<unsigned char, 16> kResetBytes = {0x40,0x53,0x48,0x83,0xEC,0x20,0x4C,0x8B,0x81,0xB0,0x00,0x00,0x00,0x48,0x8B,0xD9};
constexpr std::array<unsigned char, 15> kInflaterBytes = {0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18};
constexpr std::array<unsigned char, 16> kListBytes = {0x41,0x55,0x48,0x83,0xEC,0x50,0x45,0x33,0xED,0x44,0x89,0x2D,0x34,0x5A,0x43,0x0B};
constexpr std::array<unsigned char, 16> kGetStringBytes = {0x48,0x83,0xEC,0x28,0xE8,0x07,0xFD,0xFF,0xFF,0x8B,0xC8,0xE8,0x00,0xF9,0xFF,0xFF};
constexpr std::array<unsigned char, 7> kOverlayBytes = {0x8B,0xCA,0xE9,0x79,0x39,0x01,0x00};

using DiskFn = HANDLE (__fastcall*)(const char*, unsigned);
using ResetFn = std::uintptr_t (__fastcall*)(std::uintptr_t);
using InflaterFn = std::uintptr_t (__fastcall*)(std::uintptr_t,unsigned,std::uintptr_t,std::uintptr_t);
using ListFn = void (__fastcall*)();
using StringFn = const char* (__fastcall*)(const char*);
using OverlayFn = std::uintptr_t (__fastcall*)(std::uintptr_t,int);
DiskFn g_originalDisk = nullptr;
ResetFn g_originalReset = nullptr;
ListFn g_originalList = nullptr;
InflaterFn g_inflater = nullptr;
StringFn g_getString = nullptr;
OverlayFn g_originalOverlay = nullptr;
LogFn g_log = nullptr;
std::uintptr_t g_base = 0;
std::uint32_t g_size = 0;
fs::path g_root;
std::atomic<bool> g_enabled{false};
std::mutex g_lock;

struct Package {
    std::string id;
    std::string title;
    fs::path path;
};
std::vector<Package> g_packages;
std::string g_active;

bool MemoryAccessible(const void* address, std::size_t length, bool requireWritable) noexcept {
    if (!address || !length) return false;
    const auto begin=reinterpret_cast<std::uintptr_t>(address);
    if (length>UINTPTR_MAX-begin) return false;
    const auto finish=begin+length;
    auto position=begin;
    while (position<finish) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(position),&mbi,sizeof(mbi)) ||
            mbi.State!=MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            return false;
        const DWORD p=mbi.Protect & 0xFFu;
        const bool readable=p==PAGE_READONLY || p==PAGE_READWRITE ||
            p==PAGE_WRITECOPY || p==PAGE_EXECUTE_READ ||
            p==PAGE_EXECUTE_READWRITE || p==PAGE_EXECUTE_WRITECOPY;
        const bool writable=p==PAGE_READWRITE || p==PAGE_WRITECOPY ||
            p==PAGE_EXECUTE_READWRITE || p==PAGE_EXECUTE_WRITECOPY;
        if (!readable || (requireWritable && !writable)) return false;
        const auto regionStart=reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        if (position<regionStart || mbi.RegionSize>UINTPTR_MAX-regionStart) return false;
        const auto regionEnd=regionStart+mbi.RegionSize;
        if (regionEnd<=position) return false;
        position=std::min(finish,regionEnd);
    }
    return true;
}
bool MemoryReadable(const void* value, std::size_t length) noexcept {
    return MemoryAccessible(value,length,false);
}
bool MemoryWritable(const void* value, std::size_t length) noexcept {
    return MemoryAccessible(value,length,true);
}

template<std::size_t N>
bool Signature(std::uintptr_t rva, const std::array<unsigned char,N>& expected) noexcept {
    if (!g_base || rva >= g_size || N > g_size - rva) return false;
    auto* where = reinterpret_cast<const void*>(g_base + rva);
    return MemoryReadable(where, N) && std::memcmp(where, expected.data(), N) == 0;
}

bool IsId(const std::string& id) noexcept {
    if (id.size() < 4 || id.size() > 15 || id.rfind("mp_",0) != 0) return false;
    for (unsigned char c : id) if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_') return false;
    return true;
}
std::array<std::string,5> ZoneNames(const std::string& id) {
    return {id, "srv_"+id, "eng_"+id, "ww_"+id, "techsets_"+id};
}
std::string ReadString(const char* value, std::size_t limit) {
    if (!MemoryReadable(value, 1)) return {};
    std::string result;
    for (std::size_t i=0; i<limit; ++i) {
        if (!MemoryReadable(value+i,1)) return {};
        const char c=value[i];
        if (!c) return result;
        if (static_cast<unsigned char>(c)<32 || static_cast<unsigned char>(c)>126) return {};
        result.push_back(c);
    }
    return {};
}
bool FileHeader(const fs::path& file) {
    std::error_code error;
    const auto size = fs::file_size(file,error);
    if (error || size < 0x8c || size > 0xffffffffULL) return false;
    std::ifstream in(file,std::ios::binary);
    std::array<unsigned char,0xA0> h{};
    in.read(reinterpret_cast<char*>(h.data()),static_cast<std::streamsize>(std::min<std::uintmax_t>(h.size(),size)));
    if (static_cast<std::uintmax_t>(in.gcount())!=std::min<std::uintmax_t>(h.size(),size)) return false;
    const auto u32=[&](unsigned off)->std::uint32_t {
        std::uint32_t result=0; std::memcpy(&result,h.data()+off,4);return result;
    };
    const auto u64=[&](unsigned off)->std::uint64_t {
        std::uint64_t result=0; std::memcpy(&result,h.data()+off,8);return result;
    };
    const bool stored=std::memcmp(h.data(),"IWffc100",8)==0;
    if (!stored && std::memcmp(h.data(),"IWffa100",8)!=0) return false;
    if (u32(8)!=11 || u32(12)!=0x0FF7 || h[17]!=0 || u32(0x14)!=size-0x88 || !u64(0x20)) return false;
    std::uint64_t sum=0;
    // IW8 has eleven *64-bit* stream descriptors, not 32-bit sizes.
    for (unsigned i=0;i<11;++i) {
        const auto block=u64(0x30+i*8);
        if (block>UINT64_MAX-sum) return false;
        sum+=block;
    }
    if (sum<u64(0x20)) return false;
    return stored ? h[16]==0 && std::memcmp(h.data()+0x88,"\x01IWC",4)==0 && u32(0x14)==u64(0x20)+4
        : size>=0xA0 && h[16]==1 && std::memcmp(h.data()+0x88,"IWffs100",8)==0;
}
bool VerifyFolder(const fs::path& path, const std::string& id) {
    std::error_code ec;
    if (!fs::is_directory(path,ec) || fs::is_symlink(path,ec)) return false;
    std::vector<std::string> expected;
    for (auto& name:ZoneNames(id)) expected.push_back(name+".ff");
    expected.push_back("map.json");
    std::vector<std::string> found;
    for (fs::directory_iterator iter(path,ec),end;!ec && iter!=end;iter.increment(ec)) {
        if (!iter->is_regular_file(ec) || iter->is_symlink(ec)) return false;
        found.push_back(iter->path().filename().string());
    }
    if (ec) return false;
    std::sort(expected.begin(),expected.end());
    std::sort(found.begin(),found.end());
    if (found!=expected) return false;
    for (auto& name:ZoneNames(id)) if (!FileHeader(path/(name+".ff"))) return false;
    // The C# editor performs full JSON parsing on deploy. This runtime limits
    // itself to a small bounded file and confirms the package id token.
    std::ifstream meta(path/"map.json",std::ios::binary);
    if (!meta) return false;
    std::string data((std::istreambuf_iterator<char>(meta)),std::istreambuf_iterator<char>());
    if (data.size()>65536 || data.find('"'+id+'"')==std::string::npos) return false;
    return true;
}
void RefreshLocked() {
    g_packages.clear();
    std::error_code ec;
    if (!fs::is_directory(g_root,ec) || fs::is_symlink(g_root,ec)) return;
    for (fs::directory_iterator it(g_root,ec),end; !ec && it!=end && g_packages.size()<96;it.increment(ec)) {
        if (!it->is_directory(ec) || it->is_symlink(ec)) continue;
        const std::string id=it->path().filename().string();
        if (!IsId(id) || !VerifyFolder(it->path(),id)) continue;
        Package package{id,id,it->path()};
        std::ifstream input(it->path()/"map.json");
        std::string line;
        while (std::getline(input,line)) {
            if (line.find("\"title\"")==std::string::npos) continue;
            const auto colon=line.find(':'),first=line.find('"',colon+1);
            const auto last=first==std::string::npos?std::string::npos:line.find('"',first+1);
            if (last!=std::string::npos && last>first+1) {
                std::string name=line.substr(first+1,std::min<std::size_t>(last-first-1,30));
                if (!name.empty() && name.find('\\')==std::string::npos) package.title=std::move(name);
            }
            break;
        }
        g_packages.push_back(std::move(package));
    }
    std::sort(g_packages.begin(),g_packages.end(),[](const Package& a,const Package& b){return a.id<b.id;});
    if (std::none_of(g_packages.begin(),g_packages.end(),[](const Package& p){return p.id==g_active;})) g_active.clear();
}

// Called at game file-open time. We read the native selected-map dvar, not an
// overlay hotkey or network message, to cover the standard Local Play selector.
void RefreshSelection() {
    if (!g_getString) return;
    const std::string id=ReadString(g_getString("NSQLTTMRMP"),16);
    std::lock_guard lock(g_lock);
    const auto found=std::find_if(g_packages.begin(),g_packages.end(),[&](const Package& p){return p.id==id;});
    if (found==g_packages.end()) g_active.clear();
    else g_active=found->id;
}
std::uintptr_t __fastcall OnMainThreadOverlay(std::uintptr_t arg,int flags) {
    const auto result = g_originalOverlay ? g_originalOverlay(arg,flags) : 0;
    // No native dvar functions are invoked from the loader's worker/IO thread.
    const DWORD saved=GetLastError();
    if (g_enabled.load(std::memory_order_relaxed)) RefreshSelection();
    SetLastError(saved);
    return result;
}
bool PathForRequest(const std::string& request, fs::path& out) {
    if (request.find("..")!=std::string::npos) return false;
    // Only explicitly known zone search paths are accepted; never replace
    // arbitrary system paths, extension aliases, or user-supplied locations.
    std::string normalized=request;
    std::replace(normalized.begin(),normalized.end(),'\\','/');
    constexpr std::array<const char*,4> prefixes={"","zone/","zone/english/","zone/worldwide/"};
    for (const auto* prefix:prefixes) {
        std::string_view candidate=normalized;
        if (candidate.substr(0,std::strlen(prefix))!=prefix) continue;
        candidate.remove_prefix(std::strlen(prefix));
        if (candidate.empty() || candidate.find('/')!=std::string_view::npos || !candidate.ends_with(".ff")) continue;
        const std::string zone(candidate.substr(0,candidate.size()-3));
        std::lock_guard lock(g_lock);
        const auto found=std::find_if(g_packages.begin(),g_packages.end(),[](const Package& p){return p.id==g_active;});
        if (found==g_packages.end()) return false;
        for (const auto& name:ZoneNames(found->id)) if (name==zone) {
            const fs::path source=found->path/(zone+".ff");
            std::error_code ec;
            if (!fs::is_regular_file(source,ec) || fs::is_symlink(source,ec)) return false;
            out=source;
            return true;
        }
    }
    return false;
}
HANDLE __fastcall OpenMapZone(const char* file, unsigned flags) {
    if (!g_originalDisk) return INVALID_HANDLE_VALUE;
    const DWORD last=GetLastError();
    const std::string request=ReadString(file,1024);
    fs::path source;
    bool use=false;
    if (!request.empty()) {
        use=PathForRequest(request,source);
    }
    if (!use) { SetLastError(last);return g_originalDisk(file,flags); }
    const auto replacement=source.string();
    SetLastError(last);
    const HANDLE handle=g_originalDisk(replacement.c_str(),flags);
    const DWORD after=GetLastError();
    if (g_log) g_log("[MAP120] disk %s => %s (%s)\r\n",request.c_str(),replacement.c_str(),
                     handle!=INVALID_HANDLE_VALUE?"opened":"failed");
    SetLastError(after);
    return handle;
}
std::uintptr_t __fastcall ResetSelectedReader(std::uintptr_t reader) {
    if (!g_originalReset) return 0;
    if (!MemoryReadable(reinterpret_cast<void*>(reader),0xB8)) return g_originalReset(reader);
    std::uintptr_t state=0,descriptor=0;
    std::memcpy(&state,reinterpret_cast<void*>(reader),sizeof(state));
    std::memcpy(&descriptor,reinterpret_cast<void*>(reader+0xB0),sizeof(descriptor));
    if (!state || !MemoryReadable(reinterpret_cast<void*>(descriptor),0x114)) return g_originalReset(reader);
    std::uint8_t signedFile=1;
    std::memcpy(&signedFile,reinterpret_cast<void*>(descriptor+0x50),1);
    if (signedFile) return g_originalReset(reader);
    const auto name=ReadString(reinterpret_cast<const char*>(descriptor),64);
    if (!name.ends_with(".ff")) return g_originalReset(reader);
    const auto zone=name.substr(0,name.size()-3);
    bool selected=false;
    {
        std::lock_guard lock(g_lock);
        for (const auto& p:g_packages) if (p.id==g_active)
            for (const auto& n:ZoneNames(p.id)) selected |= n==zone;
    }
    const auto* header=reinterpret_cast<const unsigned char*>(descriptor+0x88);
    if (!selected || std::memcmp(header,"IWffc100",8)!=0 ||
        header[8]!=11 || header[9]!=0 || header[10]!=0 || header[11]!=0 ||
        header[12]!=0xF7 || header[13]!=0x0F || header[14]!=0 || header[15]!=0 ||
        header[16]!=0 || header[17]!=0 || !g_inflater) return g_originalReset(reader);
    std::uint32_t comp=0;
    std::memcpy(&comp,reinterpret_cast<void*>(descriptor+0x54),sizeof(comp));
    const DWORD saved=GetLastError();
    if (g_log) g_log("[MAP120] native unsigned stored decoder: %s\r\n",name.c_str());
    SetLastError(saved);
    return g_inflater(state,0,descriptor,comp?descriptor+0x54:0);
}
void WriteField(unsigned char* row,std::size_t off,std::size_t capacity,const std::string& text) {
    std::memset(row+off,0,capacity);
    std::memcpy(row+off,text.data(),std::min(text.size(),capacity-1));
}
void __fastcall LoadMapList() {
    if (!g_originalList) return;
    g_originalList();
    const DWORD saved=GetLastError();
    Refresh();  // see new user-created maps when the stock map menu is refreshed
    auto* count=reinterpret_cast<int*>(g_base+kMapCount);
    auto* rows=reinterpret_cast<unsigned char*>(g_base+kMapRows);
    if (!MemoryReadable(count,sizeof(int)) || !MemoryWritable(rows,kRowStride*kMaxRows)) return;
    int current=*count;
    if (current<=0 || current>static_cast<int>(kMaxRows)) return;
    std::array<unsigned char,kRowStride> templateRow{};
    bool hasTemplate=false;
    for (int i=0;i<current;++i) if (std::memcmp(rows+i*kRowStride+0x20,"mp_shipment\0",12)==0) {
        std::memcpy(templateRow.data(),rows+i*kRowStride,kRowStride);
        hasTemplate=true;break;
    }
    if (!hasTemplate || !MemoryWritable(count,sizeof(int))) return;
    std::lock_guard lock(g_lock);
    unsigned added=0;
    for (const auto& package:g_packages) {
        if (current>=static_cast<int>(kMaxRows)) break;
        bool exists=false;
        for (int i=0;i<current;++i) {
            if (std::strncmp(reinterpret_cast<char*>(rows+i*kRowStride+0x20),package.id.c_str(),16)==0)
                {exists=true;break;}
        }
        if (exists) continue;
        auto row=templateRow;
        WriteField(row.data(),0,32,std::string(1,'\x1f')+package.title);
        WriteField(row.data(),0x20,16,package.id);
        WriteField(row.data(),0x30,32,std::string(1,'\x1f')+"CodRevamped map");
        WriteField(row.data(),0x50,32,"maps/"+package.id);
        WriteField(row.data(),0x70,32,"maps/"+package.id);
        WriteField(row.data(),0xB0,32,"war");
        WriteField(row.data(),0xD0,1024,"war");
        std::memset(row.data()+0x4D0,0,4);
        std::memcpy(rows+current*kRowStride,row.data(),row.size());
        ++current;++added;
    }
    *count=current;
    if (g_log) g_log("[MAP120] map list injected=%u total=%d\r\n",added,current);
    SetLastError(saved);
}

bool Hook(std::uintptr_t rva,LPVOID detour,LPVOID* trampoline,const char* name) {
    const auto address=reinterpret_cast<LPVOID>(g_base+rva);
    const MH_STATUS create=MH_CreateHook(address,detour,trampoline);
    if (create!=MH_OK) { if(g_log)g_log("[MAP120] create hook failed %s: %d\r\n",name,static_cast<int>(create));return false; }
    const MH_STATUS enabled=MH_EnableHook(address);
    if (enabled==MH_OK) return true;
    MH_RemoveHook(address);
    if(g_log)g_log("[MAP120] enable hook failed %s: %d\r\n",name,static_cast<int>(enabled));
    return false;
}
} // namespace

void Refresh() noexcept {
    try { std::lock_guard lock(g_lock);RefreshLocked(); }
    catch (...) { if(g_log)g_log("[MAP120] rescan failed\r\n"); }
}

bool Install(std::uintptr_t imageBase,std::uint32_t imageSize,LogFn log) noexcept {
    g_log=log;
    g_base=imageBase;
    g_size=imageSize;
    if (g_enabled.load(std::memory_order_acquire)) return true;

    // Defense in depth: bypass all std::filesystem work when no map loading
    // has been requested. Keep this even if some future caller bypasses the
    // early guard in MW2019RedirectProxy.cpp.
    wchar_t optIn[8]{};
    const DWORD optInLength = GetEnvironmentVariableW(
        L"CODREVAMPED_120_CUSTOM_MAPS", optIn,
        static_cast<DWORD>(std::size(optIn)));
    if (optInLength != 1 || optIn[0] != L'1') {
        if (g_log) g_log("[MAP120] native runtime skipped before filesystem work: opt-in=off\r\n");
        return false;
    }

    // The stock 1.20 startup must NEVER depend on custom-map hooks.  The
    // previous implementation hooked the file reader even with no maps folder,
    // creating a startup regression when the user's game had no custom maps.
    // Resolve and validate the packages BEFORE inspecting any game addresses
    // or creating MinHook trampolines.
    try {
        wchar_t exe[MAX_PATH]{};
        const DWORD length=GetModuleFileNameW(nullptr,exe,MAX_PATH);
        if (!length || length>=MAX_PATH) {
            if (g_log) g_log("[MAP120] skipped: cannot locate game executable; stock loader unchanged\r\n");
            return false;
        }
        g_root=fs::path(exe).parent_path()/"maps";
        // Cheap Win32 existence gate before directory traversal and native
        // package checks. A normal installation often has no custom maps.
        const DWORD rootAttributes = GetFileAttributesW(g_root.wstring().c_str());
        if (rootAttributes == INVALID_FILE_ATTRIBUTES ||
            (rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            if (g_log) g_log("[MAP120] custom maps directory absent or unsafe; stock loader unchanged\r\n");
            return false;
        }
        Refresh();
        std::size_t available=0;
        {
            std::lock_guard lock(g_lock);
            available=g_packages.size();
        }
        if (!available) {
            if (g_log) g_log("[MAP120] no verified maps in maps/<id>; no native hooks installed; stock loader unchanged\r\n");
            return false;
        }
        // Experimental hooks are opt-in.  Merely having files in maps/ must
        // not make the base game crash or hang during startup.
        wchar_t enable[8]{};
        const DWORD chars=GetEnvironmentVariableW(
            L"CODREVAMPED_120_CUSTOM_MAPS",enable,
            static_cast<DWORD>(std::size(enable)));
        if (chars!=1 || enable[0]!=L'1') {
            if (g_log) g_log("[MAP120] validated maps=%zu; native loader OPT-IN disabled; set CODREVAMPED_120_CUSTOM_MAPS=1 to test\r\n",available);
            return false;
        }
        if (g_log) g_log("[MAP120] experimental loading requested for %zu maps; checking native bindings\r\n",available);
    } catch (...) {
        if (g_log) g_log("[MAP120] package discovery exception; stock loader unchanged\r\n");
        return false;
    }

    if (!Signature(kDiskOpen,kDiskBytes) || !Signature(kResetReader,kResetBytes) ||
        !Signature(kInitInflater,kInflaterBytes) || !Signature(kLoadMapInfo,kListBytes) ||
        !Signature(kGetDvarString,kGetStringBytes) || !Signature(kOverlay,kOverlayBytes)) {
        if (g_log) g_log("[MAP120] native signatures differ from expected 1.20 build; custom loading disabled\r\n");
        return false;
    }

    // Being inside the image is not the same as being a writable map-list
    // allocation.  The old diagnostic incorrectly said the RVA exceeded the
    // image when the actual failure was the protection/layout validation.
    const bool countInImage = kMapCount <= g_size && sizeof(int)<=g_size-kMapCount;
    const bool rowsInImage = kMapRows <= g_size &&
        kRowStride*kMaxRows <= g_size-kMapRows;
    const bool countWritable = countInImage &&
        MemoryWritable(reinterpret_cast<void*>(g_base+kMapCount),sizeof(int));
    const bool rowsWritable = rowsInImage &&
        MemoryWritable(reinterpret_cast<void*>(g_base+kMapRows),kRowStride*kMaxRows);
    if (!countWritable || !rowsWritable) {
        if (g_log) g_log(
            "[MAP120] map-list binding not writable: countInImage=%s rowsInImage=%s "
            "countWritable=%s rowsWritable=%s; all native custom-map hooks skipped\r\n",
            countInImage?"yes":"no",rowsInImage?"yes":"no",
            countWritable?"yes":"no",rowsWritable?"yes":"no");
        return false; // No half-installed map loader without working menu registration.
    }

    g_inflater=reinterpret_cast<InflaterFn>(g_base+kInitInflater);
    g_getString=reinterpret_cast<StringFn>(g_base+kGetDvarString);
    // Keep stock startup unmodified if any hook fails; log exactly which
    // native transition could not be installed.
    std::array<std::uintptr_t,4> installed{};
    std::size_t installedCount=0;
    const auto install=[&](std::uintptr_t rva,LPVOID detour,LPVOID* trampoline,const char* name) {
        if (!Hook(rva,detour,trampoline,name)) return false;
        installed[installedCount++]=rva;
        return true;
    };
    if (!install(kDiskOpen,reinterpret_cast<LPVOID>(&OpenMapZone),
                 reinterpret_cast<LPVOID*>(&g_originalDisk),"Sys_OpenFileReliable") ||
        !install(kResetReader,reinterpret_cast<LPVOID>(&ResetSelectedReader),
                 reinterpret_cast<LPVOID*>(&g_originalReset),"DB_ResetFileReader") ||
        !install(kLoadMapInfo,reinterpret_cast<LPVOID>(&LoadMapList),
                 reinterpret_cast<LPVOID*>(&g_originalList),"LoadMapInfoList") ||
        !install(kOverlay,reinterpret_cast<LPVOID>(&OnMainThreadOverlay),
                 reinterpret_cast<LPVOID*>(&g_originalOverlay),"CL_ScreenMP_DrawOverlay")) {
        for (std::size_t i=installedCount;i>0;--i) {
            auto* target=reinterpret_cast<LPVOID>(g_base+installed[i-1]);
            MH_DisableHook(target);
            MH_RemoveHook(target);
        }
        g_originalDisk=nullptr;
        g_originalReset=nullptr;
        g_originalList=nullptr;
        g_originalOverlay=nullptr;
        if (g_log) g_log("[MAP120] custom-map hook rollback complete; stock loader restored\r\n");
        return false;
    }
    g_enabled.store(true,std::memory_order_release);
    if (g_log) g_log("[MAP120] native map loader active only for validated maps; root=maps\r\n");
    return true;
}

} // namespace codrevamped::replay120::custommaps

// Explicit compatibility identifier for the map deployer's version.dll test.
extern "C" __declspec(dllexport) const char CODREVAMPED_NATIVE_MAPS_V1[] = "CODREVAMPED_NATIVE_MAPS_V1";
