// CodRevamped IW8MapPack: native Replay 1.20 package validator and safe staged deploy.
// Builds without third-party dependencies. This validates structure, NOT GfxWorld/engine acceptance.
#include "../../shared/iw8/AssetFormat.h"
#include <array>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>
#include <system_error>
#include <cstdint>
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace fs=std::filesystem;
using codrevamped::iw8::assets::Inspect;
using codrevamped::iw8::assets::Compatibility;
namespace {
void need(bool b,const std::string& reason){if(!b)throw std::runtime_error(reason);}
std::string u8(const fs::path& p){auto v=p.generic_u8string();return {reinterpret_cast<const char*>(v.data()),v.size()};}
std::string normalized(const fs::path& p){return u8(p.lexically_normal());}
std::string mapid(std::string id){
 need(id.size()>=4&&id.size()<=15&&id.starts_with("mp_"),"Map ID must be mp_... and <=15 characters");
 for(unsigned char c:id)need(std::islower(c)||std::isdigit(c)||c=='_',"Map ID must be lowercase ASCII");
 return id;
}
std::array<std::string,6> names(const std::string& id){return {id+".ff","srv_"+id+".ff","eng_"+id+".ff","ww_"+id+".ff","techsets_"+id+".ff","map.json"};}
std::uint32_t le32(const unsigned char* b){return std::uint32_t(b[0])|(std::uint32_t(b[1])<<8)|(std::uint32_t(b[2])<<16)|(std::uint32_t(b[3])<<24);}
std::uint16_t le16(const unsigned char* b){return std::uint16_t(b[0])|(std::uint16_t(b[1])<<8);}
void regular(const fs::path& p){
 need(fs::is_regular_file(fs::symlink_status(p)),"Missing or non-regular file: "+u8(p));
 need(!fs::is_symlink(fs::symlink_status(p)),"Symlink not allowed: "+u8(p));
}
std::uint64_t checksum(const fs::path& p){
 std::ifstream in(p,std::ios::binary);need(bool(in),"Cannot open: "+u8(p));
 std::array<char,1024*256> buf{};std::uint64_t h=14695981039346656037ULL;
 while(in){in.read(buf.data(),std::streamsize(buf.size()));auto n=in.gcount();
  for(std::streamsize i=0;i<n;++i){h^=static_cast<unsigned char>(buf[std::size_t(i)]);h*=1099511628211ULL;}}
 need(in.eof(),"Read failed: "+u8(p));return h;
}
std::string smallText(const fs::path& p){
 need(fs::file_size(p)<128*1024,"Manifest too large: "+u8(p));
 std::ifstream s(p,std::ios::binary);need(bool(s),"Manifest unreadable");
 return {std::istreambuf_iterator<char>(s),{}};
}
void validate(const fs::path& folder,const std::string& id){
 need(fs::is_directory(folder),"Package folder does not exist: "+u8(folder));
 need(!fs::is_symlink(fs::symlink_status(folder)),"Package directory must not be symlink");
 const auto all=names(id);std::size_t count=0;
 for(auto& entry:fs::directory_iterator(folder)){
  regular(entry.path());++count;
  need(std::find(all.begin(),all.end(),u8(entry.path().filename()))!=all.end(),"Unexpected package file: "+u8(entry.path()));
 }
 need(count==all.size(),"Package must have exactly five .ff zones and map.json");
 for(std::size_t i=0;i<5;++i){
  const auto p=folder/all[i];regular(p);
  const auto size=fs::file_size(p);need(size>=0xA0,"Truncated fastfile header: "+all[i]);
  std::array<unsigned char,0xA0> bytes{};std::ifstream in(p,std::ios::binary);
  in.read(reinterpret_cast<char*>(bytes.data()),bytes.size());
  need(in.gcount()==std::streamsize(bytes.size()),"Truncated fastfile: "+all[i]);
  const auto result=Inspect(bytes.data(),bytes.size());
  need(result.compatibility==Compatibility::Candidate120,"Not a Replay 1.20 XFile candidate: "+all[i]);
  need(bytes[0x10]==0 && bytes[0x11]==0 && std::memcmp(bytes.data()+0x88,"\x01IWC",4)==0,
       "Replay 1.20 custom map requires an unsigned stored zone body: "+all[i]);
  const auto read64=[](const unsigned char* x)->std::uint64_t {
    return std::uint64_t(le32(x))|(std::uint64_t(le32(x+4))<<32);
  };
  const auto rawSize=read64(bytes.data()+0x20);
  const auto resident=le32(bytes.data()+0x14);
  need(rawSize>0 && rawSize<=UINT32_MAX-4 && resident==rawSize+4 && size==0x8C+rawSize,
       "Fastfile stored-frame length mismatches header: "+all[i]);
  std::uint64_t streamTotal=0;
  for(int stream=0;stream<11;++stream){
    const auto block=read64(bytes.data()+0x30+stream*8);
    need(block<=UINT64_MAX-streamTotal,"Fastfile stream-size overflow: "+all[i]);
    streamTotal+=block;
  }
  need(streamTotal>=rawSize,"Native stream allocations cannot fit XFile body: "+all[i]);
  std::cout<<"STORED-HEADER-OK "<<all[i]<<" bytes="<<size<<" raw="<<rawSize
           <<" xfile="<<result.xfileVersion<<" (asset semantics still unverified)\n";
 }
 const auto manifest=smallText(folder/"map.json");
 const auto pattern=std::regex(R"_json_("id"\s*:\s*"([^"]+)")_json_");std::smatch m;
 need(std::regex_search(manifest,m,pattern),"map.json has no id field");
 need(m[1].str()==id,"map.json id does not match requested map");
 std::cout<<"PACKAGE-OK "<<id<<" (stored framing verified; XAsset semantics/game acceptance not tested)\n";
}
void exactExe(const fs::path& root){
 const auto p=root/"game_dx12_ship_replay.exe";regular(p);
 std::ifstream f(p,std::ios::binary);std::array<unsigned char,512> d{};
 f.read(reinterpret_cast<char*>(d.data()),d.size());need(f.gcount()==512,"Bad PE header");
 need(le16(d.data())==0x5A4D,"Not a Windows EXE");
 const auto pe=le32(d.data()+0x3c);need(pe>=64&&pe<=8192,"Invalid PE offset");
 f.clear();f.seekg(pe);std::array<unsigned char,100> nt{};
 f.read(reinterpret_cast<char*>(nt.data()),nt.size());need(f.gcount()==100,"Truncated PE header");
 need(fs::file_size(p)==98035200ULL, "Executable size does not match verified 1.20 build");
 need(le32(nt.data())==0x4550&&le16(nt.data()+4)==0x8664&&
      le32(nt.data()+8)==0x5E9BAF80&&le32(nt.data()+0x28)==0x021CDC10&&
      le32(nt.data()+0x50)==0x1324B000,"Game is not supported Replay 1.20 fingerprint");
}
void gameClosed(){
#ifdef _WIN32
 HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
 need(h!=INVALID_HANDLE_VALUE,"Cannot verify running game processes");
 PROCESSENTRY32W e{};e.dwSize=sizeof(e);
 bool running=false;
 if(Process32FirstW(h,&e)){
  do{if(!_wcsicmp(e.szExeFile,L"game_dx12_ship_replay.exe")){running=true;break;}}
  while(Process32NextW(h,&e));
 }
 CloseHandle(h);
 need(!running,"Close game_dx12_ship_replay.exe before staging or rollback");
#endif
}
void safeRoot(const fs::path& root){
 need(fs::is_directory(root),"Game root missing");
 need(!fs::is_symlink(fs::symlink_status(root)),"Game root cannot be a symlink");
 exactExe(root);gameClosed();
}
fs::path mapdir(const fs::path& root,const std::string& id){return root/"maps"/id;}
fs::path backdir(const fs::path& root,const std::string& id){return root/".codrevamped"/"map-backups"/id;}
std::string stamp(){using namespace std::chrono;return std::to_string(duration_cast<microseconds>(system_clock::now().time_since_epoch()).count());}
void copyChecked(const fs::path& src,const fs::path& dest){
 regular(src);fs::copy_file(src,dest,fs::copy_options::none);
 need(fs::file_size(src)==fs::file_size(dest)&&checksum(src)==checksum(dest),"Copy checksum mismatch: "+u8(dest));
}
void stage(const fs::path& folder,const fs::path& root,const std::string& id){
 validate(folder,id);safeRoot(root);
 const auto target=mapdir(root,id), backup=backdir(root,id)/stamp();
 const auto parent=target.parent_path();fs::create_directories(parent);
 need(!fs::exists(target)||fs::is_directory(target),"Map target is not a directory");
 const auto temp=parent/(id+".incoming."+stamp());
 fs::create_directory(temp);
 try{
  for(const auto& name:names(id))copyChecked(folder/name,temp/name);
  validate(temp,id);
  if(fs::exists(target)){
   need(!fs::is_symlink(fs::symlink_status(target)),"Existing map folder is symlink");
   fs::create_directories(backup.parent_path());fs::rename(target,backup);
   std::cout<<"BACKUP "<<normalized(backup)<<"\n";
  }
  try{fs::rename(temp,target);}catch(...){
   if(fs::exists(backup)&&!fs::exists(target)) fs::rename(backup,target);
   throw;
  }
  std::cout<<"STAGED "<<normalized(target)<<"\n";
 }catch(...){std::error_code ec;fs::remove_all(temp,ec);throw;}
}
void verifyStaged(const fs::path& source,const fs::path& root,const std::string& id){
 validate(source,id);
 exactExe(root);
 const auto staged=mapdir(root,id);
 validate(staged,id);
 for(const auto& file:names(id)){
  const auto a=source/file,b=staged/file;
  need(fs::file_size(a)==fs::file_size(b),"Installed file size differs: "+file);
  need(checksum(a)==checksum(b),"Installed file hash differs: "+file);
 }
 std::cout<<"VERIFY-OK "<<id<<" all six staged files match source bytes; engine acceptance not tested\n";
}
void restore(const fs::path& root,const std::string& id){
 safeRoot(root);const auto base=backdir(root,id);need(fs::is_directory(base),"No backups for "+id);
 fs::path latest;for(auto& e:fs::directory_iterator(base)){
  if(!e.is_directory()||e.is_symlink())continue;
  if(latest.empty()||e.path().filename().native()>latest.filename().native())latest=e.path();
 }
 need(!latest.empty(),"No restorable backup found");validate(latest,id);
 const auto target=mapdir(root,id), quarantined=target.parent_path()/(id+".replaced."+stamp());
 if(fs::exists(target))fs::rename(target,quarantined);
 try{fs::rename(latest,target);}catch(...){if(fs::exists(quarantined))fs::rename(quarantined,target);throw;}
 std::cout<<"RESTORED "<<normalized(target)<<"\n";
 if(fs::exists(quarantined))std::cout<<"PREVIOUS "<<normalized(quarantined)<<"\n";
}
} // namespace
int main(int argc,char** argv){
 try{
  if(argc>=4&&std::string(argv[1])=="validate"){
   need(argc==4,"Usage: IW8MapPack validate <package-folder> <mp_id>");validate(fs::u8path(argv[2]),mapid(argv[3]));return 0;}
  if(argc>=5&&std::string(argv[1])=="stage"){
   need(argc==5,"Usage: IW8MapPack stage <package-folder> <Replay-game-root> <mp_id>");
   stage(fs::u8path(argv[2]),fs::u8path(argv[3]),mapid(argv[4]));return 0;}
  if(argc>=5&&std::string(argv[1])=="verify"){
   need(argc==5,"Usage: IW8MapPack verify <package-folder> <Replay-game-root> <mp_id>");
   verifyStaged(fs::u8path(argv[2]),fs::u8path(argv[3]),mapid(argv[4]));return 0;}
  if(argc>=4&&std::string(argv[1])=="restore"){
   need(argc==4,"Usage: IW8MapPack restore <Replay-game-root> <mp_id>");
   restore(fs::u8path(argv[2]),mapid(argv[3]));return 0;}
  std::cerr<<"IW8MapPack v1 - Replay 1.20 package header check + safe staging\n"
           <<"  IW8MapPack validate <folder> <mp_id>\n"
           <<"  IW8MapPack stage <folder> <game-root> <mp_id>\n"
           <<"  IW8MapPack verify <package-folder> <game-root> <mp_id>\n"
           <<"  IW8MapPack restore <game-root> <mp_id>\n"
           <<"NOTE: Game must be closed. Validating fastfile headers is NOT native map loading.\n";
  return 2;
 }catch(const std::exception& e){std::cerr<<"ERROR: "<<e.what()<<"\n";return 1;}
}
