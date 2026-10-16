#include <cwchar>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
using DWORD=unsigned long;
using BOOL=int;
using HANDLE=void*;
constexpr HANDLE INVALID_HANDLE_VALUE=nullptr;
constexpr DWORD MAX_PATH=260;
constexpr DWORD FILE_ATTRIBUTE_DIRECTORY=16;
constexpr DWORD FILE_ATTRIBUTE_REPARSE_POINT=1024;
constexpr DWORD FILE_ATTRIBUTE_NORMAL=128;
constexpr DWORD GENERIC_READ=0x80000000;
constexpr DWORD FILE_SHARE_READ=1,FILE_SHARE_WRITE=2,FILE_SHARE_DELETE=4;
constexpr DWORD OPEN_EXISTING=3;
struct WIN32_FIND_DATAW {DWORD dwFileAttributes=0;wchar_t cFileName[MAX_PATH]{};};
DWORD GetModuleFileNameW(void*,wchar_t*,DWORD);
HANDLE CreateFileW(const wchar_t*,DWORD,DWORD,void*,DWORD,DWORD,void*);
BOOL ReadFile(HANDLE,void*,DWORD,DWORD*,void*);
BOOL CloseHandle(HANDLE);
HANDLE FindFirstFileW(const wchar_t*,WIN32_FIND_DATAW*);
BOOL FindNextFileW(HANDLE,WIN32_FIND_DATAW*);
BOOL FindClose(HANDLE);
void ConsolePrint(const char*,...);
template<std::size_t N,typename ...Args>
int swprintf_s(wchar_t (&dest)[N],const wchar_t* fmt,Args...args){return std::swprintf(dest,N,fmt,args...);}
#include "../../../clients/mw2019/Features/CustomMaps/CustomMapProbe.h"
int main(){return 0;}
