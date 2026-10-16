#pragma once
// Passive, bounded startup asset inventory, scoped to exact Replay 1.20.
// Included inside MW2019RedirectProxy.cpp's existing Win32/logger namespace.
// Never redirects a path, patches a header, or loads a foreign fastfile.
#include "../../../../shared/iw8/AssetFormat.h"
namespace replay120_asset_inventory {
inline void Run() noexcept {
    wchar_t gamePath[MAX_PATH]{};
    const auto got = GetModuleFileNameW(nullptr,gamePath,MAX_PATH);
    if(!got || got>=MAX_PATH) return;
    wchar_t* slash=std::wcsrchr(gamePath,L'\\');
    if(!slash) return;
    *slash=0;
    wchar_t pattern[MAX_PATH]{};
    if (swprintf_s(pattern, L"%ls\\zone\\*.ff",gamePath)<0) return;
    WIN32_FIND_DATAW fd{};
    HANDLE find=FindFirstFileW(pattern,&fd);
    if(find==INVALID_HANDLE_VALUE) {
        ConsolePrint("[ASSET120] zone inventory unavailable winerr=%lu\r\n",GetLastError());
        return;
    }
    unsigned scanned=0,candidate=0,collision=0,other=0,unreadable=0;
    do {
        if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        wchar_t path[MAX_PATH]{};
        if(swprintf_s(path,L"%ls\\zone\\%ls",gamePath,fd.cFileName)<0)continue;
        HANDLE file=CreateFileW(path,GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
            OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file==INVALID_HANDLE_VALUE){++unreadable;continue;}
        unsigned char head[32]{};DWORD read=0;
        const BOOL ok=ReadFile(file,head,sizeof(head),&read,nullptr);
        CloseHandle(file);
        if(!ok){++unreadable;continue;}
        const auto result=codrevamped::iw8::assets::Inspect(head,read);
        switch(result.compatibility){
        case codrevamped::iw8::assets::Compatibility::Candidate120:++candidate;break;
        case codrevamped::iw8::assets::Compatibility::CollisionCandidate120:++collision;break;
        default:
            ++other;
            if(other<=6) ConsolePrint("[ASSET120] unknown-or-other zone=%ls magic=%s xfile=%lu status=%s\r\n",
                  fd.cFileName,codrevamped::iw8::assets::Label(result.container),
                  static_cast<unsigned long>(result.xfileVersion),
                  codrevamped::iw8::assets::Label(result.compatibility));
        }
    } while(++scanned<1024 && FindNextFileW(find,&fd));
    FindClose(find);
    ConsolePrint("[ASSET120] inventory scanned=%u headerCandidate=%u collisionCandidate=%u other=%u unreadable=%u safeReadOnly=yes\r\n",
        scanned,candidate,collision,other,unreadable);
}
}
