// CodRevamped IW8ReverseLab: read-only PE inventory for matching MW2019 build research.
// File offsets and mapped RVAs are explicitly separate; no function signatures
// or callable engine addresses are inferred from matching strings.
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <limits>
#include <map>
#include <unordered_map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace {
using Bytes = std::vector<std::uint8_t>;
struct Section { std::string name; uint32_t va, virtualSize, raw, rawSize, flags; };
struct Symbol { std::string name, section; uint32_t raw = 0; std::optional<uint32_t> rva; };
struct CrossReference {
    uint32_t instructionRva=0, targetRva=0, fileOffset=0;
    std::string anchor;
};
struct PE {
    std::string path, format; uint32_t timestamp=0, entry=0, imageSize=0, headersSize=0;
    uint64_t imageBase=0; uint16_t machine=0;
    std::vector<Section> sections;
    std::map<std::string,std::vector<std::string>> imports;
    std::vector<Symbol> exports, anchors;
    std::vector<CrossReference> candidateRipReferences;
    uint64_t bytes=0;
};
uint16_t u16(const Bytes& d, size_t p) {
    if(p>d.size() || d.size()-p<2) throw std::runtime_error("truncated PE (u16)");
    return uint16_t(d[p]) | (uint16_t(d[p+1])<<8);
}
uint32_t u32(const Bytes& d, size_t p) {
    if(p>d.size() || d.size()-p<4) throw std::runtime_error("truncated PE (u32)");
    return uint32_t(d[p]) | (uint32_t(d[p+1])<<8) | (uint32_t(d[p+2])<<16) | (uint32_t(d[p+3])<<24);
}
uint64_t u64(const Bytes& d, size_t p) { return uint64_t(u32(d,p)) | (uint64_t(u32(d,p+4))<<32); }
std::string str(const Bytes& d, size_t at, size_t maxLength = 256) {
    if(at>=d.size()) throw std::runtime_error("invalid string address");
    std::string v;
    for(size_t i=at;i<d.size() && v.size()<maxLength;++i) {
        if(!d[i]) return v;
        if(d[i]<32 || d[i]>126) throw std::runtime_error("invalid PE string");
        v.push_back(char(d[i]));
    }
    throw std::runtime_error("unterminated PE string");
}
std::string quote(const std::string& s) {
    std::string o="\"";
    for(unsigned char c:s) {
        if(c=='\\')o+="\\\\";
        else if(c=='\"')o+="\\\"";
        else if(c=='\n')o+="\\n";
        else if(c=='\r')o+="\\r";
        else if(c=='\t')o+="\\t";
        else if(c<32) {char buf[7];std::snprintf(buf,sizeof(buf),"\\u%04x",c);o+=buf;}
        else o+=char(c);
    }
    return o+'"';
}
Bytes load(const fs::path& p) {
    std::error_code ec;
    const auto size=fs::file_size(p,ec);
    if(ec || size<64 || size>1024ull*1024*1024) throw std::runtime_error("missing, truncated or over 1 GiB: "+p.string());
    Bytes data(static_cast<size_t>(size));
    std::ifstream f(p,std::ios::binary);
    if(!f.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(data.size())))
        throw std::runtime_error("failed to read "+p.string());
    return data;
}
std::optional<size_t> rawFromRva(const PE& p, const Bytes& d, uint32_t rva, size_t length=1) {
    if(rva<p.headersSize && uint64_t(rva)+length<=std::min(uint64_t(p.headersSize),uint64_t(d.size()))) return size_t(rva);
    for(const auto& s:p.sections) {
        if(rva<s.va)continue;
        const auto delta=uint64_t(rva)-s.va;
        if(delta<s.rawSize && delta+length<=s.rawSize && uint64_t(s.raw)+delta+length<=d.size())
            return static_cast<size_t>(s.raw+delta);
    }
    return std::nullopt;
}
std::optional<uint32_t> rvaFromRaw(const PE& p, size_t off, std::string* sec=nullptr) {
    for(const auto& s:p.sections)
        if(off>=s.raw && uint64_t(off)-s.raw<s.rawSize && uint64_t(s.va)+off-s.raw<=UINT32_MAX) {
            if(sec)*sec=s.name;
            return uint32_t(s.va+off-s.raw);
        }
    if(sec)*sec="header/unmapped";
    return std::nullopt;
}
std::vector<std::string> needles(){return {
 "DB_LoadXAssets","DB_FindXAssetHeader","DB_GetXAssetName","DB_Zones_PerformZoneLoad",
 "DB_ResetFileReader","GfxWorld","GfxImage","XModel","XAnim","WeaponDef","weaponDef",
 "techsets_","mapents","clipMap","havok","XPAK","IWffc100","IWffa100",
 "IWffd100","Unable to open","zone/","frontend","weapon", "material",
 "R_EndFrame","CL_ScreenMP_DrawOverlay","Live_IsUserSignedInToDemonware",
 "DW-1.20","lobby","demonware"};}
PE inspect(const fs::path& input) {
    const auto d=load(input);
    PE p;p.path=input.string();p.bytes=d.size();
    if(u16(d,0)!=0x5A4D)throw std::runtime_error("not an MZ file");
    const auto pe=uint64_t(u32(d,0x3c));
    if(pe>d.size()||d.size()-pe<24||u32(d,size_t(pe))!=0x4550)throw std::runtime_error("invalid PE signature");
    const auto coff=size_t(pe)+4;
    p.machine=u16(d,coff);const auto nsec=u16(d,coff+2);p.timestamp=u32(d,coff+4);
    const auto opts=u16(d,coff+16);const auto opt=coff+20;
    if(nsec>96 || opt>d.size() || d.size()-opt<opts || opts<96)throw std::runtime_error("invalid COFF/optional header bounds");
    const auto magic=u16(d,opt);const bool pe64=magic==0x20B;
    if(!pe64 && magic!=0x10B)throw std::runtime_error("unsupported PE optional header");
    if(opts<(pe64?112:96)) throw std::runtime_error("truncated PE optional header");
    p.format=pe64?"PE32+":"PE32";
    p.entry=u32(d,opt+16);p.imageBase=pe64?u64(d,opt+24):u32(d,opt+28);
    p.imageSize=u32(d,opt+56);p.headersSize=u32(d,opt+60);
    const auto sectionTable=opt+opts;
    if(sectionTable>d.size() || uint64_t(nsec)*40>d.size()-sectionTable)throw std::runtime_error("section table truncated");
    for(unsigned i=0;i<nsec;++i){
        const auto at=sectionTable+size_t(i)*40;
        std::string name;
        for(size_t j=0;j<8&&d[at+j];++j) name+=char(d[at+j]);
        Section s{name,u32(d,at+12),u32(d,at+8),u32(d,at+20),u32(d,at+16),u32(d,at+36)};
        p.sections.push_back(s);
    }
    const auto numDirOff=opt+(pe64?108:92), dirOff=opt+(pe64?112:96);
    uint32_t dirs=0;
    if(numDirOff+4<=opt+opts)dirs=std::min(uint32_t(16),u32(d,numDirOff));
    auto dir=[&](uint32_t index)->std::pair<uint32_t,uint32_t> {
        if(index>=dirs||dirOff+(index+1)*8>opt+opts)return {0,0};
        return {u32(d,dirOff+index*8),u32(d,dirOff+index*8+4)};
    };
    // Export directory: names point into the image, not directly to raw offsets.
    const auto [exportRva,exportSize]=dir(0);
    if(exportRva && exportSize>=40)if(auto ed=rawFromRva(p,d,exportRva,40)){
        const auto count=u32(d,*ed+24), namesRva=u32(d,*ed+32), ordRva=u32(d,*ed+36), funcsRva=u32(d,*ed+28);
        if(count<100000)for(uint32_t i=0;i<count;++i){
            if(uint64_t(namesRva)+uint64_t(i)*4>UINT32_MAX ||
               uint64_t(ordRva)+uint64_t(i)*2>UINT32_MAX) break;
            auto np=rawFromRva(p,d,uint32_t(uint64_t(namesRva)+uint64_t(i)*4),4);
            auto op=rawFromRva(p,d,uint32_t(uint64_t(ordRva)+uint64_t(i)*2),2);
            if(!np||!op)break;
            auto nameOffset=rawFromRva(p,d,u32(d,*np));
            if(!nameOffset)continue;
            try{
                auto name=str(d,*nameOffset);
                uint32_t ordinal=u16(d,*op);
                if(uint64_t(funcsRva)+uint64_t(ordinal)*4>UINT32_MAX)continue;
                auto fp=rawFromRva(p,d,uint32_t(uint64_t(funcsRva)+uint64_t(ordinal)*4),4);
                if(!fp)continue;
                auto rva=u32(d,*fp);Symbol s{name,"unmapped",0,rva};
                if(auto raw=rawFromRva(p,d,rva)){
                    s.raw=uint32_t(*raw);std::string sec;rvaFromRaw(p,*raw,&sec);s.section=sec;
                }
                p.exports.push_back(std::move(s));
            }catch(const std::runtime_error&){}
        }
    }
    // Import descriptors and name thunks; ordinal imports retained explicitly.
    const auto [importRva,importSize]=dir(1);
    if(importRva&&importSize)for(uint32_t i=0;i<4096;++i){
        if(uint64_t(importRva)+uint64_t(i)*20>UINT32_MAX)break;
        auto desc=rawFromRva(p,d,uint32_t(uint64_t(importRva)+uint64_t(i)*20),20);
        if(!desc||uint64_t(i)*20>=importSize)break;
        auto orig=u32(d,*desc),nameRva=u32(d,*desc+12),first=u32(d,*desc+16);
        if(!orig&&!nameRva&&!first)break;
        auto nm=rawFromRva(p,d,nameRva);
        if(!nm)continue;
        std::string dll;
        try{dll=str(d,*nm);}catch(const std::runtime_error&){continue;}
        auto& imports=p.imports[dll];
        const uint32_t thunk=orig?orig:first;
        const uint32_t stride=pe64?8:4;
        for(uint32_t j=0;j<20000;++j){
            uint64_t off=uint64_t(thunk)+uint64_t(j)*stride;
            if(off>UINT32_MAX)break;
            auto tp=rawFromRva(p,d,uint32_t(off),stride);
            if(!tp)break;
            auto value=pe64?u64(d,*tp):u32(d,*tp);
            if(value==0)break;
            if(value & (pe64?0x8000000000000000ull:0x80000000ull)){
                imports.push_back("ordinal:"+std::to_string(value&0xffff));continue;
            }
            if(value>UINT32_MAX)continue;
            auto byName=rawFromRva(p,d,uint32_t(value),3);
            if(!byName)continue;
            try{imports.push_back(str(d,*byName+2));}catch(const std::runtime_error&){}
        }
    }
    // Bound scan: only exact string hits in file data; raw->RVA mapping is mechanical.
    const auto keys=needles();
    std::map<unsigned char,std::vector<const std::string*>> firstByte;
    std::map<std::string,size_t> observed;
    for(const auto& key:keys)if(!key.empty())firstByte[static_cast<unsigned char>(key[0])].push_back(&key);
    for(const auto& sec:p.sections){
        if(!(sec.flags&0x40000000u) || sec.raw>=d.size())continue; // initialized-readable
        const auto end=std::min(uint64_t(d.size()),uint64_t(sec.raw)+sec.rawSize);
        for(uint64_t off=sec.raw;off<end;++off){
            auto bucket=firstByte.find(d[size_t(off)]);
            if(bucket==firstByte.end())continue;
            for(const auto* key:bucket->second){
                if(key->size()>end-off || std::memcmp(d.data()+off,key->data(),key->size())!=0)continue;
                if(p.anchors.size()>=5000)break;
                if(observed[*key]++>=64)continue; // distributed across distinct anchors
                p.anchors.push_back({*key,sec.name,uint32_t(off),rvaFromRaw(p,size_t(off))});
            }
            if(p.anchors.size()>=5000)break;
        }
        if(p.anchors.size()>=5000)break;
    }
    // Limited instruction-template search. This is NOT a disassembler: disassemble
    // matching sites and check control flow in IDA/Ghidra before using any RVA.
    if(pe64) {
        std::unordered_map<uint32_t,std::string> anchorTargets;
        for(const auto& a:p.anchors)if(a.rva)anchorTargets.emplace(*a.rva,a.name);
        for(const auto& sec:p.sections) {
            if(!(sec.flags&0x20000000u)||sec.raw>=d.size())continue;
            const auto end=std::min(uint64_t(d.size()),uint64_t(sec.raw)+sec.rawSize);
            for(uint64_t off=sec.raw;off+7<=end;++off) {
                // REX.W LEA/MOV reg, [RIP+disp32]. The byte templates could
                // also occur inside data/instruction immediates: heuristic only.
                const auto rex=d[size_t(off)],opcode=d[size_t(off+1)],modrm=d[size_t(off+2)];
                if((rex!=0x48&&rex!=0x4C)||(opcode!=0x8D&&opcode!=0x8B) || (modrm&0xC7)!=0x05)
                    continue;
                auto sourceRva=rvaFromRaw(p,size_t(off));
                if(!sourceRva)continue;
                const auto displacement=static_cast<int32_t>(u32(d,size_t(off+3)));
                const auto target=int64_t(*sourceRva)+7+displacement;
                if(target<0 || target>UINT32_MAX)continue;
                auto found=anchorTargets.find(uint32_t(target));
                if(found==anchorTargets.end())continue;
                p.candidateRipReferences.push_back({*sourceRva,uint32_t(target),uint32_t(off),found->second});
                if(p.candidateRipReferences.size()>=10000)break;
            }
            if(p.candidateRipReferences.size()>=10000)break;
        }
    }
    return p;
}
void symbol(std::ostream& o,const Symbol& s) {
    o<<"{\"name\":"<<quote(s.name)<<",\"section\":"<<quote(s.section)<<",\"fileOffset\":"<<s.raw<<",\"rva\":";
    if(s.rva)o<<*s.rva;else o<<"null";o<<"}";
}
void output(std::ostream& o,const PE& p){
    o<<"{\"path\":"<<quote(p.path)<<",\"format\":"<<quote(p.format)
     <<",\"bytes\":"<<p.bytes<<",\"machine\":"<<p.machine<<",\"timestamp\":"<<p.timestamp
     <<",\"entryRva\":"<<p.entry<<",\"imageBase\":"<<p.imageBase
     <<",\"sizeOfImage\":"<<p.imageSize<<",\"sections\":[";
    for(size_t i=0;i<p.sections.size();++i){if(i)o<<",";const auto& s=p.sections[i];
        o<<"{\"name\":"<<quote(s.name)<<",\"rva\":"<<s.va<<",\"virtualSize\":"<<s.virtualSize
          <<",\"rawOffset\":"<<s.raw<<",\"rawSize\":"<<s.rawSize<<",\"characteristics\":"<<s.flags<<"}";
    }
    o<<"],\"imports\":{";size_t n=0;
    for(const auto& [dll,imports]:p.imports){if(n++)o<<",";o<<quote(dll)<<":[";
        for(size_t i=0;i<imports.size();++i){if(i)o<<",";o<<quote(imports[i]);}o<<"]";
    }
    o<<"},\"exports\":[";
    for(size_t i=0;i<p.exports.size();++i){if(i)o<<",";symbol(o,p.exports[i]);}
    o<<"],\"stringAnchors\":[";
    for(size_t i=0;i<p.anchors.size();++i){if(i)o<<",";symbol(o,p.anchors[i]);}
    o<<"],\"candidateRipReferences\":[";
    for(size_t i=0;i<p.candidateRipReferences.size();++i) {
        if(i)o<<",";
        const auto& x=p.candidateRipReferences[i];
        o<<"{\"instructionRva\":"<<x.instructionRva<<",\"fileOffset\":"<<x.fileOffset
         <<",\"targetRva\":"<<x.targetRva<<",\"anchor\":"<<quote(x.anchor)<<"}";
    }
    o<<"],\"note\":\"Read-only evidence. PE anchors and candidate RIP references are heuristics, not decompiled functions or verified callable signatures.\"}";
}
void compare(std::ostream& o,const PE& a,const PE& b){
    o<<"{\"tool\":\"IW8ReverseLab\",\"mode\":\"compare\",\"old\":";output(o,a);
    o<<",\"new\":";output(o,b);
    auto flatten=[](const PE& p){std::set<std::string> s;
        for(const auto& [dll,imports]:p.imports)for(const auto& name:imports)s.insert(dll+"!"+name);
        return s;};
    auto x=flatten(a),y=flatten(b);
    o<<",\"importChanges\":{\"onlyOld\":[";size_t i=0;
    for(const auto& s:x) {if(!y.contains(s)){if(i++)o<<",";o<<quote(s);}}
    o<<"],\"onlyNew\":[";i=0;
    for(const auto& s:y) {if(!x.contains(s)){if(i++)o<<",";o<<quote(s);}}
    o<<"]},\"anchorCountChanges\":[";
    std::map<std::string,std::pair<size_t,size_t>> counts;
    for(const auto& s:a.anchors)counts[s.name].first++;
    for(const auto& s:b.anchors)counts[s.name].second++;
    i=0;for(const auto& [key,values]:counts){if(i++)o<<",";
        o<<"{\"string\":"<<quote(key)<<",\"oldCount\":"<<values.first<<",\"newCount\":"<<values.second<<"}";}
    o<<"],\"warning\":\"Matching strings/imports never prove matching function layouts or engine ABI.\"}";
}
} // namespace
int main(int argc,char** argv){
    try{
        if(argc<4 || (std::string(argv[1])!="scan" && std::string(argv[1])!="compare")){
            std::cerr<<"Usage: IW8ReverseLab scan <file.exe|dll> <report.json>\n"
                     <<"       IW8ReverseLab compare <old.exe|dll> <new.exe|dll> <report.json>\n";return 2;
        }
        const bool diff=std::string(argv[1])=="compare";
        if(argc!=(diff?5:4))throw std::runtime_error("incorrect argument count");
        const auto first=inspect(argv[2]);
        std::optional<PE> second;
        if(diff)second=inspect(argv[3]);
        const fs::path report=argv[diff?4:3];
        if((fs::exists(report) && fs::equivalent(fs::path(argv[2]),report)) ||
           (diff && fs::exists(report) && fs::equivalent(fs::path(argv[3]),report)))
            throw std::runtime_error("report path must not overwrite an inspected binary");
        std::ofstream out(report,std::ios::binary|std::ios::trunc);
        if(!out)throw std::runtime_error("could not create report");
        if(diff)compare(out,first,*second);
        else{out<<"{\"tool\":\"IW8ReverseLab\",\"mode\":\"scan\",\"image\":";output(out,first);out<<"}";}
        out<<"\n";
        if(!out)throw std::runtime_error("failed to write report");
        std::cout<<"Wrote read-only report: "<<report.string()<<"\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<"IW8ReverseLab: "<<e.what()<<"\n";return 1;}
}
