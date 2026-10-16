// Read-only research inspector for the IW8 fastfile / patch / archive / soundbank families.
// No game code, key extraction, decompression, or unsafe header rewriting.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs=std::filesystem;
namespace {
std::uint32_t u32(const unsigned char* p){return std::uint32_t(p[0])|(std::uint32_t(p[1])<<8)|(std::uint32_t(p[2])<<16)|(std::uint32_t(p[3])<<24);}
std::uint64_t u64(const unsigned char* p){return std::uint64_t(u32(p))|(std::uint64_t(u32(p+4))<<32);}
std::string utf8(const fs::path& p){auto s=p.generic_u8string();return {reinterpret_cast<const char*>(s.data()),s.size()};}
fs::path pathFromCli(const char* s){return fs::path(std::u8string(reinterpret_cast<const char8_t*>(s)));}
std::string quote(const std::string& s){std::ostringstream o;o<<'"';for(unsigned char c:s){switch(c){case '"':o<<"\\\"";break;case '\\':o<<"\\\\";break;case '\n':o<<"\\n";break;case '\r':o<<"\\r";break;case '\t':o<<"\\t";break;default:if(c<32){o<<"\\u"<<std::hex<<std::setfill('0')<<std::setw(4)<<unsigned(c)<<std::dec;}else o<<char(c);}}o<<'"';return o.str();}
struct Sample{
 fs::path name;std::uint64_t length=0;
 std::array<unsigned char,256> header{};std::size_t headerBytes=0;
 std::string kind="unknown", magic, issue;
 std::uint32_t version=0, xfile=0, patchKind=0, sizeField=0;
 std::uint8_t compressed=0, encrypted=0, transient=0;
 std::uint64_t uncompressed=0, streamTotal=0, hash=14695981039346656037ull;
 int duplicateOf=-1, embeddedMatches=-1;
};
Sample inspect(const fs::path& p){
 Sample s;s.name=p;
 const auto st=fs::symlink_status(p);
 if(!fs::is_regular_file(st)||fs::is_symlink(st))throw std::runtime_error("Expected a regular file, not a directory or symlink: "+utf8(p));
 s.length=fs::file_size(p);
 if(s.length>16ull*1024*1024*1024)throw std::runtime_error("File exceeds 16 GiB inspection limit");
 std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("Cannot open "+utf8(p));
 f.read(reinterpret_cast<char*>(s.header.data()),s.header.size());s.headerBytes=std::size_t(f.gcount());
 std::array<char,65536> chunk{};f.clear();f.seekg(0);
 while(f){f.read(chunk.data(),chunk.size());const auto n=f.gcount();for(std::streamsize i=0;i<n;++i){s.hash^=static_cast<unsigned char>(chunk[std::size_t(i)]);s.hash*=1099511628211ull;}}
 if(f.bad())throw std::runtime_error("Read failed: "+utf8(p));
 const auto* b=s.header.data();
 if(s.headerBytes>=8 && (!std::memcmp(b,"IWffa100",8)||!std::memcmp(b,"IWffc100",8))){
  s.kind="fastfile";s.magic.assign(reinterpret_cast<const char*>(b),8);
  if(s.headerBytes<0xA0){s.issue="Truncated fastfile header";return s;}
  s.version=u32(b+8);s.xfile=u32(b+12);s.compressed=b[16];s.encrypted=b[17];s.transient=b[18];s.sizeField=u32(b+0x14);
  s.uncompressed=u64(b+0x20);for(int i=0;i<11;++i){auto n=u64(b+0x30+8*i);if(n>UINT64_MAX-s.streamTotal){s.issue="Stream sizes overflow";break;}s.streamTotal+=n;}
  if(s.length<0x88 || s.length-0x88!=s.sizeField)s.issue="Resident part size differs from file length";
  else if(s.version!=11)s.issue="Unknown header version: do not apply Replay 1.20 offsets";
  else if(s.xfile!=4087)s.issue="Not Replay 1.20 XFile 4087; native asset conversion required";
  else if(s.magic=="IWffa100"&&s.compressed==1)s.issue="Signed compressed fastfile; Oodle framing and native XAsset deserialization needed";
  else s.issue="Header inspected; not proof of a loadable zone";
 }else if(s.headerBytes>=8&&!std::memcmp(b,"IWffd100",8)){
  s.kind="fastfile-patch";s.magic="IWffd100";
  if(s.headerBytes>=0x40){s.version=u32(b+8);s.patchKind=u32(b+12);}
  s.issue="Patch data requires a matching base fastfile and version-specific patch decoder";
 }else if(s.headerBytes>=4&&!std::memcmp(b,"KAPI",4)){
  s.kind="xpak";s.magic="KAPI";
  if(s.headerBytes>=24){s.version=u32(b+4);s.sizeField=u32(b+0x10);}
  s.issue=(s.sizeField==s.length ? "KAPI archive length field matches file size; content not decoded" : "KAPI archive length field differs from file size; verify completeness");
 }else if(s.headerBytes>=4&&!std::memcmp(b,"2UX#",4)){
  s.kind="sabs";s.magic="2UX#";
  if(s.headerBytes>=48){s.version=u32(b+4);s.sizeField=u32(b+0x20);}
  s.issue=(s.sizeField==s.length ? "Sound bank length field matches file size; audio codecs/entry table not decoded" : "Sound bank length field differs from file size; verify completeness");
 }else s.issue="Unknown magic; file extension alone is not a format signature";
 return s;
}
bool exactEqual(const fs::path& a,const fs::path& b){
 std::ifstream x(a,std::ios::binary),y(b,std::ios::binary);if(!x||!y)return false;
 std::array<char,65536> p{},q{};
 while(x&&y){x.read(p.data(),p.size());y.read(q.data(),q.size());if(x.gcount()!=y.gcount())return false;if(!std::equal(p.begin(),p.begin()+x.gcount(),q.begin()))return false;}
 return !x.bad()&&!y.bad();
}
std::string json(const Sample& s){
 std::ostringstream o;o<<"{\"file\":"<<quote(utf8(s.name))<<",\"kind\":"<<quote(s.kind)<<",\"bytes\":"<<s.length
  <<",\"magic\":"<<quote(s.magic)<<",\"headerVersionOrRawField\":"<<s.version<<",\"xfileVersion\":"<<s.xfile
  <<",\"compressionByte\":"<<unsigned(s.compressed)<<",\"encryptionByte\":"<<unsigned(s.encrypted)
  <<",\"transientType\":"<<unsigned(s.transient)<<",\"patchKind\":"<<s.patchKind
  <<",\"residentOrSizeField\":"<<s.sizeField<<",\"decompressedXFileBytes\":"<<s.uncompressed
  <<",\"streamBytesTotal\":"<<s.streamTotal;
 o<<",\"fnv64\":\""<<std::hex<<std::setw(16)<<std::setfill('0')<<s.hash<<std::dec<<"\"";
 if(s.duplicateOf>=0)o<<",\"identicalToIndex\":"<<s.duplicateOf;
 if(s.embeddedMatches>=0)o<<",\"patchBaseMatchesIndex\":"<<s.embeddedMatches;
 o<<",\"note\":"<<quote(s.issue)<<"}";return o.str();
}
} // namespace
int IW8PackageInspect_Entry(int argc,char** argv){
 try{
  if(argc<2){std::cerr<<"IW8Tools.Native packages <file> [other files...]\n";return 2;}
  std::vector<Sample> records;
  for(int i=1;i<argc;++i)records.push_back(inspect(pathFromCli(argv[i])));
  for(std::size_t i=0;i<records.size();++i){
   for(std::size_t j=0;j<i;++j){
    if(records[i].length==records[j].length && records[i].hash==records[j].hash &&
       exactEqual(records[i].name,records[j].name)){records[i].duplicateOf=int(j);break;}
   }
   if(records[i].kind=="fastfile-patch"&&records[i].headerBytes>=0x38+0x8C){
    for(std::size_t j=0;j<records.size();++j){
     const auto& b=records[j];
     if(b.kind=="fastfile"&&b.headerBytes>=0x8C&&
      !std::memcmp(records[i].header.data()+0x38,b.header.data(),0x8C)){
       records[i].embeddedMatches=int(j);break;
     }
    }
   }
  }
  std::cout<<"{\"readOnly\":true,\"sampleCount\":"<<records.size()<<",\"files\":[\n";
  for(std::size_t i=0;i<records.size();++i)std::cout<<(i?",\n":"")<<json(records[i]);
  std::cout<<"\n]}\n";return 0;
 }catch(const std::exception& e){std::cerr<<"Package inspector: "<<e.what()<<'\n';return 1;}
}
