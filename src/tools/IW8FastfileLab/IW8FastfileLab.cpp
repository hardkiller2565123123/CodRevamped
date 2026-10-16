// CodRevamped IW8FastfileLab: portable, bounded, read-only IW8 fastfile research.
// Rebuilding is limited to an already-valid Replay 1.20 uncompressed zone with
// an equal-size raw body; this is NOT XAsset deserialization or cross-version conversion.
// Based on independently described IW8 header offsets, not vendored upstream code.
#include "../../shared/iw8/AssetFormat.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs=std::filesystem;
namespace {
using codrevamped::iw8::assets::ReadLE32;
void require(bool condition,const std::string& why){if(!condition)throw std::runtime_error(why);}
std::string u8(const fs::path& p){auto s=p.generic_u8string();return {reinterpret_cast<const char*>(s.data()),s.size()};}
fs::path cliPath(const char* arg){return fs::path(std::u8string(reinterpret_cast<const char8_t*>(arg)));}
std::string quote(const std::string& s){std::string out="\"";for(unsigned char c:s){switch(c){case '\\':out+="\\\\";break;case '"':out+="\\\"";break;case '\n':out+="\\n";break;case '\r':out+="\\r";break;default:if(c<0x20){char t[7];std::snprintf(t,sizeof(t),"\\u%04x",c);out+=t;}else out+=char(c);}}return out+'"';}
std::uint64_t le64(const unsigned char* p){return std::uint64_t(ReadLE32(p))|(std::uint64_t(ReadLE32(p+4))<<32);}
constexpr std::uint64_t MaxFile=8ull*1024*1024*1024; // never allocate whole .ff
constexpr std::uint64_t MaxRaw=2ull*1024*1024*1024;
constexpr std::size_t HeadLen=0xA0, StoredPrefix=0x8C;
struct Header{
 fs::path file;std::uint64_t bytes{};
 std::array<unsigned char,HeadLen> prefix{};
 std::string magic,framing,issue;
 std::uint32_t version{},xfile{},resident{},residentHash{},alwaysLoaded{};
 std::uint8_t compression{},encryption{},transient{};
 std::uint64_t uncompressed{},preload{},blockSum{};
 std::array<std::uint64_t,11> blocks{};
 bool storedValid=false,compressedCandidate=false;
 bool hasAssetListHeader=false;
 std::uint32_t assetCount{},scriptStringCount{},assetReadPos{};
};
Header inspect(const fs::path& path){
 Header h;h.file=path;
 require(fs::is_regular_file(fs::symlink_status(path)) && !fs::is_symlink(fs::symlink_status(path)),"Expected a regular fastfile, not a link");
 h.bytes=fs::file_size(path);require(h.bytes>=HeadLen && h.bytes<=MaxFile,"Fastfile too small, too large, or truncated");
 std::ifstream f(path,std::ios::binary);require(bool(f),"Cannot open fastfile");
 f.read(reinterpret_cast<char*>(h.prefix.data()),HeadLen);require(f.gcount()==HeadLen,"Cannot read fastfile header");
 const auto* b=h.prefix.data();h.magic.assign(reinterpret_cast<const char*>(b),8);
 require(h.magic=="IWffc100"||h.magic=="IWffa100","Unsupported IW8 magic (patch files require their base zone)");
 h.version=ReadLE32(b+8);h.xfile=ReadLE32(b+12);h.compression=b[16];h.encryption=b[17];h.transient=b[18];
 h.resident=ReadLE32(b+0x14);h.residentHash=ReadLE32(b+0x18);h.alwaysLoaded=ReadLE32(b+0x1C);
 h.uncompressed=le64(b+0x20);h.preload=le64(b+0x28);
 for(int i=0;i<11;i++){
  h.blocks[std::size_t(i)]=le64(b+0x30+i*8);
  require(h.blockSum<=std::numeric_limits<std::uint64_t>::max()-h.blocks[std::size_t(i)],"Stream-size overflow");
  h.blockSum+=h.blocks[std::size_t(i)];
 }
 if(std::memcmp(b+0x88,"\x01IWC",4)==0)h.framing="resident-IWC-stored";
 else if(std::memcmp(b+0x88,"IWffs100",8)==0)h.framing="signed-IWffs100";
 else h.framing="unknown";
 if(h.version!=11)h.issue="Unknown fastfile header layout; offset assumptions not verified";
 else if(h.encryption!=0)h.issue="Encrypted payload; needs version-specific decoder";
 else if(h.uncompressed==0 || h.uncompressed>MaxRaw)h.issue="Invalid or oversized declared uncompressed size";
 else if(h.blockSum<h.uncompressed)h.issue="Uncompressed size exceeds stream allocation total";
 else if(std::uint64_t(h.resident)+0x88 != h.bytes)h.issue="Resident size does not match the full file";
 else if(h.magic=="IWffc100" && h.compression==0 && h.framing=="resident-IWC-stored" &&
         std::uint64_t(h.resident)==h.uncompressed+4){
  h.storedValid=true;
  if(h.xfile!=4087)h.issue="Stored payload readable; serialized assets are NOT Replay 1.20-compatible";
  else if(h.uncompressed>=32){
   // Initial IW8_XAssetList is 32 bytes: script-string list + count + read-pos + pointer.
   // Deliberately DO NOT resolve tagged pointers or walk arbitrary asset records here.
   std::array<unsigned char,32> root{};
   f.seekg(StoredPrefix);f.read(reinterpret_cast<char*>(root.data()),root.size());
   if(f.gcount()==std::streamsize(root.size())){
    auto strings=ReadLE32(root.data());auto assets=ReadLE32(root.data()+16);
    auto readPos=ReadLE32(root.data()+20);
    if(strings<=1000000 && assets<=1000000 && readPos<=assets){
     h.hasAssetListHeader=true;
     h.scriptStringCount=strings;h.assetCount=assets;h.assetReadPos=readPos;
    }
   }
  }
 }else if(h.magic=="IWffa100" && h.compression==1 && h.framing=="signed-IWffs100"){
  h.compressedCandidate=true;
  h.issue="Oodle-compressed signed zone: matching framing, Oodle decoder, and asset schema required";
 }else h.issue="Unsupported magic/compression/framing combination; no safe decode rule";
 return h;
}
std::string json(const Header& h){
 std::ostringstream o;
 o<<"{\n  \"input\": "<<quote(u8(h.file))<<",\n  \"fileBytes\": "<<h.bytes
  <<",\n  \"magic\": "<<quote(h.magic)<<",\n  \"headerVersion\": "<<h.version
  <<",\n  \"xfileVersion\": "<<h.xfile<<",\n  \"compressionByte\": "<<unsigned(h.compression)
  <<",\n  \"encryptionByte\": "<<unsigned(h.encryption)
  <<",\n  \"transientType\": "<<unsigned(h.transient)
  <<",\n  \"residentPartSize\": "<<h.resident
  <<",\n  \"residentHash\": "<<h.residentHash
  <<",\n  \"alwaysLoadedPartSize\": "<<h.alwaysLoaded
  <<",\n  \"uncompressedXFileBytes\": "<<h.uncompressed
  <<",\n  \"preloadWalkBytes\": "<<h.preload
  <<",\n  \"streamBytesTotal\": "<<h.blockSum<<",\n  \"streams\": [";
 for(int i=0;i<11;i++)o<<(i?", ":"")<<h.blocks[std::size_t(i)];
 o<<"],\n  \"framing\": "<<quote(h.framing)
  <<",\n  \"canExtractStoredBody\": "<<(h.storedValid?"true":"false")
  <<",\n  \"replay120XFile\": "<<(h.xfile==4087 && h.version==11?"true":"false")
  <<",\n  \"requiresExternalOodleDecode\": "<<(h.compressedCandidate?"true":"false")
  <<",\n  \"hasPlausibleXAssetListRoot\": "<<(h.hasAssetListHeader?"true":"false")
  <<",\n  \"assetCountCandidate\": "<<h.assetCount
  <<",\n  \"scriptStringCountCandidate\": "<<h.scriptStringCount
  <<",\n  \"assetSchemaDecoded\": false,\n  \"note\": "<<quote(h.issue.empty()?"Stored native zone body available; XAsset deserialization still required":h.issue)<<"\n}\n";
 return o.str();
}
void writeNew(const fs::path& path,const std::string& content){require(!fs::exists(path),"Destination already exists: "+u8(path));std::ofstream f(path,std::ios::binary|std::ios::trunc);require(bool(f),"Cannot create destination");f.write(content.data(),std::streamsize(content.size()));require(bool(f),"Write error");}
void copyRange(std::istream& in,std::ostream& out,std::uint64_t bytes){
 std::array<char,1<<17> buf{};while(bytes){auto n=std::min<std::uint64_t>(bytes,buf.size());in.read(buf.data(),std::streamsize(n));require(in.gcount()==std::streamsize(n),"Source truncation");out.write(buf.data(),std::streamsize(n));require(bool(out),"Write failed");bytes-=n;}
}
void dump(const Header& h,const fs::path& folder){
 require(h.storedValid,"Extraction supports verified IWffc100 stored-body fastfiles only; inspect the report");
 require(!fs::exists(folder),"Output folder already exists: "+u8(folder));
 fs::create_directories(folder);
 try{
  std::ifstream src(h.file,std::ios::binary);require(bool(src),"Input reopened unsuccessfully");
  std::ofstream meta(folder/"header_prefix.bin",std::ios::binary);require(bool(meta),"Header output failed");
  meta.write(reinterpret_cast<const char*>(h.prefix.data()),StoredPrefix);require(bool(meta),"Header write failed");meta.close();
  src.seekg(StoredPrefix);std::ofstream raw(folder/"zone.raw",std::ios::binary);require(bool(raw),"Raw output failed");
  copyRange(src,raw,h.uncompressed);raw.close();
  writeNew(folder/"inspection.json",json(h));
  std::cout<<"EXTRACTED stored zone body: "<<u8(folder/"zone.raw")<<" ("<<h.uncompressed<<" bytes)\n";
  std::cout<<"NOTE: This is raw serialized XFile data, NOT extracted map/model/weapon assets.\n";
 }catch(...){std::error_code ec;fs::remove_all(folder,ec);throw;}
}
void rebuild(const fs::path& folder,const fs::path& output){
 const fs::path meta=folder/"header_prefix.bin",raw=folder/"zone.raw";
 require(fs::is_regular_file(meta)&&!fs::is_symlink(fs::symlink_status(meta)),"Missing header_prefix.bin");
 require(fs::is_regular_file(raw)&&!fs::is_symlink(fs::symlink_status(raw)),"Missing zone.raw");
 require(fs::file_size(meta)==StoredPrefix,"Header prefix size must be exactly 0x8C");
 require(!fs::exists(output),"Refusing to overwrite existing destination");
 std::array<unsigned char,StoredPrefix> head{};std::ifstream hf(meta,std::ios::binary);
 hf.read(reinterpret_cast<char*>(head.data()),head.size());require(hf.gcount()==std::streamsize(head.size()),"Header read failed");
 require(std::memcmp(head.data(),"IWffc100",8)==0 && ReadLE32(head.data()+8)==11 &&
     ReadLE32(head.data()+12)==4087 && head[16]==0 && head[17]==0 &&
     std::memcmp(head.data()+0x88,"\x01IWC",4)==0,"Repack accepts only Replay 1.20 unsigned stored headers");
 const auto size=le64(head.data()+0x20);
 require(size>0 && size<=MaxRaw && fs::file_size(raw)==size,"Raw zone size changed; unsupported without rebuilding stream allocations");
 require(ReadLE32(head.data()+0x14)==size+4,"Header resident size mismatch");
 require(ReadLE32(head.data()+0x18)==0,"Nonzero resident hash: cannot safely rebuild edited payload without rehashing");
 std::uint64_t total=0;
 for(int i=0;i<11;i++){auto block=le64(head.data()+0x30+i*8);require(block<=std::numeric_limits<std::uint64_t>::max()-total,"Stream sum overflow");total+=block;}
 require(total>=size,"Header stream allocation smaller than body");
 std::ofstream out(output,std::ios::binary);require(bool(out),"Cannot create output");
 try{
  out.write(reinterpret_cast<const char*>(head.data()),head.size());require(bool(out),"Header write failed");
  std::ifstream src(raw,std::ios::binary);require(bool(src),"Raw input failed");copyRange(src,out,size);out.close();require(bool(out),"Output close failed");
  std::cout<<"REBUILT unsigned stored 1.20 zone: "<<u8(output)<<"\n";
  std::cout<<"WARNING: Repacking raw bytes does not repair any edited XAsset references or native engine dependencies.\n";
 }catch(...){out.close();std::error_code ec;fs::remove(output,ec);throw;}
}
void compare(const Header& a,const Header& b){
 std::cout<<"{\n  \"left\": "<<json(a).substr(0,json(a).size()-1)<<",\n  \"right\": "<<json(b).substr(0,json(b).size()-1)
 <<",\n  \"sameCompressionByte\": "<<(a.compression==b.compression?"true":"false")
 <<",\n  \"sameHeaderVersion\": "<<(a.version==b.version?"true":"false")
 <<",\n  \"sameXFileVersion\": "<<(a.xfile==b.xfile?"true":"false")
 <<",\n  \"compatibleByHeaderAlone\": false\n}\n";
}
void usage(){std::cerr<<"IW8FastfileLab (CodRevamped) - native header research and verified stored-payload extraction\n"
 <<"  IW8FastfileLab inspect <input.ff> [report.json]\n"
 <<"  IW8FastfileLab compare <1.20.ff> <newer.ff>\n"
 <<"  IW8FastfileLab extract-stored <input.ff> <NEW-output-folder>\n"
 <<"  IW8FastfileLab rebuild-stored <extracted-folder> <NEW-output.ff>\n"
 <<"No Oodle decoder, asset-schema converter, signature bypass, or cross-build backport is implied.\n";}
}
int main(int argc,char** argv){
 try{
  require(argc>=2,"Missing action");const std::string action=argv[1];
  if(action=="inspect" && (argc==3||argc==4)){auto h=inspect(cliPath(argv[2]));if(argc==4)writeNew(cliPath(argv[3]),json(h));else std::cout<<json(h);return 0;}
  if(action=="compare" && argc==4){compare(inspect(cliPath(argv[2])),inspect(cliPath(argv[3])));return 0;}
  if(action=="extract-stored" && argc==4){dump(inspect(cliPath(argv[2])),cliPath(argv[3]));return 0;}
  if(action=="rebuild-stored" && argc==4){rebuild(cliPath(argv[2]),cliPath(argv[3]));return 0;}
  usage();return 2;
 }catch(const std::exception& e){std::cerr<<"ERROR: "<<e.what()<<"\n";return 1;}
}
