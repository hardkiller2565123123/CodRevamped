#pragma once
// Replay 1.20 passive custom-map inventory for CodRevamped. This code never
// modifies loader bytes or installs native engine hooks. The first-party CustomMapRuntime.cpp owns the optional engine hooks.
#include "../../../../shared/iw8/AssetFormat.h"
#include <initializer_list>
#include <cwchar>
namespace replay120_custom_maps {
inline bool CandidateMapFile(const wchar_t* base,const wchar_t* relativeRoot,
                             const wchar_t* id,const wchar_t* prefix) noexcept {
    wchar_t path[MAX_PATH]{};
    if(swprintf_s(path,L"%ls\\%ls\\%ls\\%ls%ls.ff",base,relativeRoot,id,prefix,id)<0)return false;
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
       nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return false;
    unsigned char data[16]{};DWORD read=0;
    BOOL ok=ReadFile(file,data,sizeof(data),&read,nullptr);CloseHandle(file);
    if(!ok||read<16)return false;
    auto h=codrevamped::iw8::assets::Inspect(data,read);
    return h.compatibility==codrevamped::iw8::assets::Compatibility::Candidate120;
}
inline void ProbeFolder(const wchar_t* base,const wchar_t* relativeRoot,const char* kind) noexcept {
    wchar_t pattern[MAX_PATH]{};
    if(swprintf_s(pattern,L"%ls\\%ls\\*",base,relativeRoot)<0)return;
    WIN32_FIND_DATAW fd{};
    HANDLE it=FindFirstFileW(pattern,&fd);
    if(it==INVALID_HANDLE_VALUE) {
        ConsolePrint("[MAP120] source=%s staged-dir=absent\r\n",kind);
        return;
    }
    unsigned checked=0,eligible=0;
    do {
        if(!(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) ||
           (fd.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) ||
           fd.cFileName[0]==L'.')continue;
        unsigned count=0;
        for(const wchar_t* prefix:{L"",L"srv_",L"eng_",L"ww_",L"techsets_"})
            count+=CandidateMapFile(base,relativeRoot,fd.cFileName,prefix)?1u:0u;
        if(count==5)++eligible;
        ConsolePrint("[MAP120] source=%s id=%ls candidateCompanionHeaders=%u/5\r\n",
                     kind,fd.cFileName,count);
        ++checked;
    } while(checked<48 && FindNextFileW(it,&fd));
    FindClose(it);
    ConsolePrint("[MAP120] source=%s scanned=%u headerCandidates=%u\r\n",kind,checked,eligible);
}
inline void Run() noexcept {
    wchar_t base[MAX_PATH]{};
    const DWORD got=GetModuleFileNameW(nullptr,base,MAX_PATH);
    if(!got||got>=MAX_PATH)return;
    wchar_t* slash=std::wcsrchr(base,L'\\');if(!slash)return;
    *slash=0;
    ProbeFolder(base,L"maps","codrevamped-map-package");
    ConsolePrint("[MAP120] passive inventory complete; native hooks are installed separately if signature checks pass\r\n");
}
}
