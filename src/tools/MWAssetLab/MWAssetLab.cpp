// CodRevamped MWAssetLab. Portable C++20, no game executable/DLL load needed.
// Drag a file/folder onto the Windows EXE or pass paths on a command line.
// Read-only by default. Produces a compatibility inventory and porting plan;
// it DOES NOT rename versions, decrypt, decompress, or backport native assets.
#include "../../shared/iw8/AssetFormat.h"
#include "LoadingReport.h"
#include "../../shared/iw8/GfxInspect.h"
#include "../../shared/iw8/ObjInspect.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <map>
#include <limits>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace codrevamped::iw8::assets;

namespace {
struct SHA256 {
    std::array<std::uint32_t,8> h{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                  0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::array<unsigned char,64> buf{};
    std::size_t used=0;
    std::uint64_t total=0;
    static std::uint32_t rot(std::uint32_t a,unsigned n) {return (a>>n)|(a<<(32-n));}
    void block(const unsigned char* b) {
        static constexpr std::uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        std::uint32_t w[64]{};
        for(int i=0;i<16;++i)w[i]=(std::uint32_t(b[i*4])<<24)|(std::uint32_t(b[i*4+1])<<16)|
                                      (std::uint32_t(b[i*4+2])<<8)|b[i*4+3];
        for(int i=16;i<64;++i) {
            auto s0=rot(w[i-15],7)^rot(w[i-15],18)^(w[i-15]>>3);
            auto s1=rot(w[i-2],17)^rot(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        auto a=h[0],b0=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;++i){
            const auto s1=rot(e,6)^rot(e,11)^rot(e,25);
            const auto ch=(e&f)^((~e)&g);
            const auto t1=hh+s1+ch+k[i]+w[i];
            const auto s0=rot(a,2)^rot(a,13)^rot(a,22);
            const auto maj=(a&b0)^(a&c)^(b0&c);
            const auto t2=s0+maj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=b0;b0=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b0;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    void update(const unsigned char* p,std::size_t n){
        total+=n;
        while(n){auto step=std::min(n,std::size_t(64-used));
            std::copy(p,p+step,buf.begin()+static_cast<std::ptrdiff_t>(used));
            p+=step;n-=step;used+=step;
            if(used==64){block(buf.data());used=0;}
        }
    }
    std::string finish(){
        const std::uint64_t bits=total*8;
        const unsigned char one=0x80;update(&one,1);
        const unsigned char zero=0;
        while(used!=56) update(&zero,1);
        unsigned char bytes[8]{};
        for(int i=0;i<8;++i)bytes[i]=static_cast<unsigned char>(bits>>(56-8*i));
        update(bytes,8);
        std::ostringstream o;o<<std::hex<<std::setfill('0');
        for(auto v:h)o<<std::setw(8)<<v;
        return o.str();
    }
};
std::string json(const std::string& s){
    std::string o="\"";
    for(unsigned char c:s){
        switch(c){
        case '\\':o+="\\\\";break;case '"':o+="\\\"";break;
        case '\n':o+="\\n";break;case '\r':o+="\\r";break;
        case '\t':o+="\\t";break;
        default:if(c<32){char b[7];std::snprintf(b,sizeof(b),"\\u%04x",c);o+=b;}else o+=char(c);
        }
    }
    return o+'"';
}
std::string utf8(const fs::path& path){
    auto u=path.generic_u8string();return {reinterpret_cast<const char*>(u.c_str()),u.size()};
}
std::string hexPrefix(const unsigned char* bytes,std::size_t n){
    std::ostringstream o;o<<std::hex<<std::setfill('0');
    for(std::size_t i=0;i<n;++i)o<<std::setw(2)<<unsigned(bytes[i]);
    return o.str();
}
std::string lower(std::string s){
    std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;
}
std::string nameType(const fs::path& p) {
    std::string s=lower(utf8(p.filename()));
    if(s.find("mp_")==0 || s.find("_cg_")!=std::string::npos || s.find("_map")!=std::string::npos)
        return "map-or-collision";
    if(s.find("weapon")!=std::string::npos||s.find("wpn_")!=std::string::npos||s.find("gun")!=std::string::npos)
        return "weapon-candidate";
    if(s.find("techset")!=std::string::npos||s.find("material")!=std::string::npos)
        return "material-or-shader-candidate";
    return "asset-type-not-decoded";
}
struct Entry {
    fs::path path;std::uintmax_t size=0;
    Header h{};std::string sha256,kind,notes;
    std::array<unsigned char,256> prefix{};std::size_t prefixBytes=0;
    std::uint32_t peStamp=0,peImage=0,peEntry=0;
    codrevamped::iw8::gfx::ImageInfo gfx{};
    codrevamped::iw8::obj::Result geometry{};
    bool isObj=false;
    bool error=false;
};
Entry inspect(const fs::path& path) {
    Entry e;e.path=path;e.kind=nameType(path);
    std::ifstream file(path,std::ios::binary);
    if(!file){e.error=true;e.notes="read-failed";return e;}
    std::error_code ec;e.size=fs::file_size(path,ec);
    if(ec){e.error=true;e.notes="size-failed";return e;}
    file.read(reinterpret_cast<char*>(e.prefix.data()),e.prefix.size());
    e.prefixBytes=static_cast<std::size_t>(file.gcount());
    e.h=Inspect(e.prefix.data(),e.prefixBytes);
    const auto extension=lower(utf8(path.extension()));
    e.gfx=codrevamped::iw8::gfx::Inspect(e.prefix.data(),e.prefixBytes);
    if(extension==".obj") {
        // OBJ is a text source format; process it separately and bound the line count.
        std::ifstream model(path);
        if(model){e.geometry=codrevamped::iw8::obj::Inspect(model);e.isObj=true;}
        e.kind="geometry-source-obj";
    } else if(e.gfx.type!=codrevamped::iw8::gfx::Type::Unknown) {
        e.kind="gfx-source-image";
    }
    if(e.h.container==Container::Unknown) {
        if(extension==".xpak")e.h.container=Container::Xpak;
        else if(extension==".ipak")e.h.container=Container::Ipak;
        else if(extension==".json"||extension==".csv"||extension==".gsc"||extension==".lua"||extension==".txt")
            e.h.container=Container::TextAsset;
    }
    if(e.h.container==Container::WindowsExecutable && e.size>=512) {
        const auto peoff=ReadLE32(e.prefix.data()+0x3c);
        if(peoff+0x60<e.size && peoff<64*1024*1024) {
            file.clear();file.seekg(peoff);
            unsigned char pe[128]{};file.read(reinterpret_cast<char*>(pe),sizeof(pe));
            if(file.gcount()>=0x60 && !std::memcmp(pe,"PE\0\0",4)){
                e.peStamp=ReadLE32(pe+8);
                e.peEntry=ReadLE32(pe+0x28);
                e.peImage=ReadLE32(pe+0x50);
                if(e.peStamp==0x5E9BAF80 && e.peImage==0x1324B000 && e.peEntry==0x021CDC10)
                    e.notes="verified-Replay-1.20-executable-fingerprint";
            }
        }
    }
    // Hash whole file in bounded streaming chunks, never load huge XPAKs into RAM.
    file.clear();file.seekg(0);SHA256 sha;
    std::array<char,1024*1024> chunk{};
    while(file){file.read(chunk.data(),chunk.size());const auto n=file.gcount();
        if(n>0)sha.update(reinterpret_cast<const unsigned char*>(chunk.data()),static_cast<std::size_t>(n));
    }
    if(file.bad()){e.error=true;e.notes="read-incomplete";return e;}
    e.sha256=sha.finish();
    if(e.h.compatibility==Compatibility::OtherVersion)
        e.notes="backport-blocked:asset-enums-compression-pointers-dependencies-and-content-must-be-converted";
    else if(e.h.compatibility==Compatibility::Candidate120)
        e.notes="candidate-header:codec-flags-framing-and-serialized-XAsset-schema-not-validated";
    else if(e.h.compatibility==Compatibility::CollisionCandidate120)
        e.notes="special-case-only:verify-transient-type-3-and-zone-name-in-native-loader";
    else if(e.h.container==Container::IW8Patch)
        e.notes="patch-pair-and-header-equality-require-native-validation";
    else if(e.h.container==Container::Xpak||e.h.container==Container::Ipak)
        e.notes="asset-archive-structure-not-yet-decoded";
    return e;
}
struct MapBundle {
    std::string id,root;
    std::vector<std::string> missing;
    unsigned detected=0;
};
std::vector<MapBundle> locateMapBundles(const std::vector<Entry>& entries) {
    std::set<fs::path> all;
    for(const auto& e:entries)all.insert(e.path.lexically_normal());
    std::vector<MapBundle> bundles;
    for(const auto& e:entries) {
        if(lower(utf8(e.path.filename()))!="map.json")continue;
        const auto root=e.path.parent_path();
        // An external map manifest alone is insufficient: collect all main
        // native zones and identify explicitly missing companions.
        for(const auto& zone:entries) {
            if(zone.path.parent_path()!=root || lower(utf8(zone.path.extension()))!=".ff")continue;
            const auto name=lower(utf8(zone.path.stem()));
            if(!name.starts_with("mp_")||name.find("_cg_")!=std::string::npos||name.size()>15)continue;
            MapBundle bundle;bundle.id=name;bundle.root=utf8(root);
            for(const auto& required:{name+".ff", "srv_"+name+".ff", "eng_"+name+".ff",
                                      "ww_"+name+".ff", "techsets_"+name+".ff"}){
                if(all.contains((root/required).lexically_normal())) ++bundle.detected;
                else bundle.missing.push_back(required);
            }
            bundles.push_back(std::move(bundle));
        }
    }
    return bundles;
}
struct CollisionFamily {
    std::string name, directory;
    std::size_t tileCount=0;
    unsigned minIndex=std::numeric_limits<unsigned>::max(), maxIndex=0;
    bool combined=false;
};
std::vector<CollisionFamily> collisionFamilies(const std::vector<Entry>& entries) {
    std::map<std::string, CollisionFamily> families;
    for (const auto& e : entries) {
        const auto fname=lower(utf8(e.path.filename()));
        if (!fname.starts_with("mp_")) continue;
        const auto mark=fname.find("_cg_");
        if (mark==std::string::npos || !fname.ends_with("_tr.ff")) continue;
        const auto stem=fname.substr(0,mark);
        const auto fragment=fname.substr(mark+4,fname.size()-(mark+4)-6);
        if (fragment!="ls" && (fragment.size()!=5 ||
            !std::all_of(fragment.begin(),fragment.end(),[](unsigned char c){return c>='0'&&c<='9';})))
            continue;
        const auto dir=utf8(e.path.parent_path());
        const std::string key=dir+"/"+stem;
        auto& f=families[key]; f.name=stem;f.directory=dir;
        if (fragment=="ls") f.combined=true;
        else {
            unsigned number=0;
            for (char c:fragment) number=number*10+unsigned(c-'0');
            ++f.tileCount;f.minIndex=std::min(f.minIndex,number);
            f.maxIndex=std::max(f.maxIndex,number);
        }
    }
    std::vector<CollisionFamily> found;
    for (auto& [key,f] : families) found.push_back(std::move(f));
    return found;
}
std::vector<codrevamped::mwassetlab::loading::Timeline> readTimelines(
    const std::vector<Entry>& entries, const std::vector<fs::path>& extraTraces) {
    std::set<fs::path> logPaths(extraTraces.begin(),extraTraces.end());
    for(const auto& e:entries)
        if (lower(utf8(e.path.extension()))==".log") logPaths.insert(e.path);
    std::vector<codrevamped::mwassetlab::loading::Timeline> reports;
    for(const auto& p:logPaths) {
        if(reports.size()>=20)break;
        std::error_code ec;
        if (!fs::is_regular_file(p,ec) || fs::file_size(p,ec)>32ull*1024*1024) continue;
        std::ifstream file(p);
        if(!file)continue;
        auto report=codrevamped::mwassetlab::loading::Parse(file,utf8(p));
        if(!report.events.empty())reports.push_back(std::move(report));
    }
    return reports;
}
struct BaselineComparison {
    std::string source,reference,status;
    std::uint32_t sourceVersion=0, referenceVersion=0;
};
std::vector<BaselineComparison> compareBaseline(const std::vector<Entry>& entries,
                                                const fs::path& baseline,
                                                std::vector<std::string>& errors) {
    std::vector<BaselineComparison> result;
    if(baseline.empty())return result;
    std::error_code ec;
    if(!fs::is_directory(baseline,ec)){
        errors.push_back("baseline-must-be-a-readable-directory: "+utf8(baseline));
        return result;
    }
    std::map<std::string,fs::path> lookup;
    std::set<std::string> ambiguous;
    std::size_t seen=0;
    fs::recursive_directory_iterator it(baseline,fs::directory_options::skip_permission_denied,ec),end;
    while(!ec && it!=end && seen<30000) {
        std::error_code sub;
        if(it->is_regular_file(sub)&&!it->is_symlink(sub)) {
            ++seen;
            auto key=lower(utf8(it->path().filename()));
            if(!lookup.emplace(key,it->path()).second)ambiguous.insert(key);
        }
        it.increment(ec);
    }
    if(ec)errors.push_back("baseline-enumeration-error: "+ec.message());
    if(seen>=30000)errors.push_back("baseline-file-cap-reached-30000");
    for(const auto& e:entries) {
        const auto key=lower(utf8(e.path.filename()));
        if(e.h.container!=Container::IW8Fastfile &&
           e.h.container!=Container::IW8AlternateFastfile &&
           e.h.container!=Container::IW8Patch)continue;
        BaselineComparison c; c.source=utf8(e.path);c.sourceVersion=e.h.xfileVersion;
        if(ambiguous.contains(key))c.status="ambiguous-baseline-filename-multiple-candidates";
        else if(auto match=lookup.find(key);match==lookup.end())c.status="no-matching-baseline-filename";
        else {
            const auto ref=inspect(match->second);
            c.reference=utf8(ref.path);c.referenceVersion=ref.h.xfileVersion;
            if(ref.error)c.status="cannot-read-baseline-file";
            else if(e.h.container!=ref.h.container)c.status="different-container-format";
            else if(e.h.headerVersion!=ref.h.headerVersion || e.h.xfileVersion!=ref.h.xfileVersion)
                c.status="different-header-version-requires-asset-schema-translation";
            else if(e.sha256==ref.sha256)c.status="identical-file";
            else c.status="same-header-different-content-requires-dependency-review";
        }
        result.push_back(std::move(c));
    }
    return result;
}
void writeJson(std::ostream& out,const std::vector<Entry>& entries,
    const std::vector<std::string>& errors,
    const std::vector<codrevamped::mwassetlab::loading::Timeline>& timelines,
    const std::vector<BaselineComparison>& comparisons) {
    out<<"{\n  \"tool\": \"CodRevamped MWAssetLab 0.2\",\n"
          "  \"target\": \"MW2019 Replay 1.20\",\n"
          "  \"targetXFileVersion\": 4087,\n"
          "  \"conversionStatus\": \"analysis-only-no-foreign-fastfiles-converted\",\n"
          "  \"files\": [\n";
    for(std::size_t i=0;i<entries.size();++i){const auto& e=entries[i];
        out<<"    {\"path\":"<<json(utf8(e.path))
           <<",\"bytes\":"<<e.size<<",\"sha256\":"<<json(e.sha256)
           <<",\"magic\":"<<json(Label(e.h.container))
           <<",\"headerPrefixHex\":"<<json(hexPrefix(e.prefix.data(),std::min(e.prefixBytes,std::size_t(64))))
           <<",\"headerVersion\":"<<e.h.headerVersion
           <<",\"xfileVersion\":"<<e.h.xfileVersion
           <<",\"patchType\":"<<e.h.patchType
           <<",\"codecFlagsAvailable\":"<<(e.h.hasCodecFlags?"true":"false")
           <<",\"compressionByte\":"<<unsigned(e.h.compression)
           <<",\"encryptionByte\":"<<unsigned(e.h.encryption)
           <<",\"transientType\":"<<unsigned(e.h.transientFileType)
           <<",\"residentPartSize\":"<<e.h.residentPartSize
           <<",\"compatibility\":"<<json(Label(e.h.compatibility))
           <<",\"assetHint\":"<<json(e.kind)
           <<",\"notes\":"<<json(e.notes)
           <<",\"peTimestamp\":"<<e.peStamp
           <<",\"peImageSize\":"<<e.peImage
           <<",\"peEntryRva\":"<<e.peEntry
           <<",\"gfxType\":"<<json(codrevamped::iw8::gfx::Label(e.gfx.type))
           <<",\"gfxWidth\":"<<e.gfx.width
           <<",\"gfxHeight\":"<<e.gfx.height
           <<",\"gfxVersion\":"<<e.gfx.version
           <<",\"gfxFormat\":"<<json(e.gfx.format)
           <<",\"objVertexCount\":"<<e.geometry.vertices
           <<",\"objTriangleCount\":"<<e.geometry.triangles
           <<",\"objInvalidFaces\":"<<e.geometry.invalidFaces
           <<",\"readError\":"<<(e.error?"true":"false")<<"}";
        if(i+1!=entries.size())out<<",";
        out<<"\n";
    }
    out<<"  ],\n  \"mapBundles\": [\n";
    const auto bundles=locateMapBundles(entries);
    for(std::size_t i=0;i<bundles.size();++i){
        const auto& b=bundles[i];
        out<<"    {\"id\":"<<json(b.id)<<",\"directory\":"<<json(b.root)
           <<",\"detectedNativeZones\":"<<b.detected
           <<",\"nativeZonesExpected\":5,\"missing\":[";
        for(std::size_t j=0;j<b.missing.size();++j){if(j)out<<',';out<<json(b.missing[j]);}
        out<<"],\"status\":\"package-layout-only-not-native-load-validated\"}";
        if(i+1!=bundles.size())out<<',';
        out<<"\n";
    }
    out<<"  ],\n  \"collisionFamilies\": [\n";
    const auto families=collisionFamilies(entries);
    for(std::size_t i=0;i<families.size();++i) {
        const auto& f=families[i];
        out<<"    {\"map\":"<<json(f.name)<<",\"directory\":"<<json(f.directory)
           <<",\"combinedFilePresent\":"<<(f.combined?"true":"false")
           <<",\"numberedTileCount\":"<<f.tileCount
           <<",\"minimumTileIndex\":"<<(f.tileCount?f.minIndex:0)
           <<",\"maximumTileIndex\":"<<f.maxIndex
           <<",\"suggestedCollisionMode\":"<<json(!f.combined&&f.tileCount?"mode-1-candidate":"native-mode-validation-required")
           <<",\"note\":\"filename-inventory-only-tile-payload-not-validated\"}";
        if(i+1!=families.size())out<<",";
        out<<"\n";
    }
    out<<"  ],\n  \"loadingTimelines\": [\n";
    for(std::size_t i=0;i<timelines.size();++i) {
        const auto& t=timelines[i];
        out<<"    {\"source\":"<<json(t.source)<<",\"linesRead\":"<<t.lines
           <<",\"truncated\":"<<(t.truncated?"true":"false")<<",\"events\":[";
        for(std::size_t j=0;j<t.events.size();++j){
            const auto& e=t.events[j];
            if(j)out<<",";
            out<<"{\"line\":"<<e.line<<",\"type\":"<<json(e.type)
               <<",\"detail\":"<<json(e.detail)<<"}";
        }
        out<<"]}";
        if(i+1!=timelines.size())out<<",";
        out<<"\n";
    }
    out<<"  ],\n  \"baselineComparisons\": [\n";
    for(std::size_t i=0;i<comparisons.size();++i){
        const auto& c=comparisons[i];
        out<<"    {\"source\":"<<json(c.source)<<",\"reference\":"<<json(c.reference)
           <<",\"sourceXFileVersion\":"<<c.sourceVersion
           <<",\"referenceXFileVersion\":"<<c.referenceVersion
           <<",\"status\":"<<json(c.status)<<"}";
        if(i+1!=comparisons.size())out<<',';
        out<<"\n";
    }
    out<<"  ],\n  \"errors\": [";
    for(std::size_t i=0;i<errors.size();++i){if(i)out<<',';out<<json(errors[i]);}
    out<<"]\n}\n";
}
int run(const std::vector<fs::path>& paths,fs::path output,
        const std::vector<fs::path>& traceFiles={},
        const fs::path& baseline={}) {
    std::vector<fs::path> candidates;std::vector<std::string> errors;
    std::set<fs::path> seen;
    constexpr std::size_t kMaxFiles=30000;
    for(const auto& input:paths) {
        std::error_code ec;
        if(fs::is_regular_file(input,ec)){if(seen.insert(input).second)candidates.push_back(input);continue;}
        if(!fs::is_directory(input,ec)){errors.push_back("missing-or-unreadable: "+utf8(input));continue;}
        fs::recursive_directory_iterator it(input,fs::directory_options::skip_permission_denied,ec),end;
        while(!ec && it!=end && candidates.size()<kMaxFiles) {
            std::error_code sub;
            if(it->is_regular_file(sub) && !it->is_symlink(sub)){
                auto p=it->path();if(seen.insert(p).second)candidates.push_back(std::move(p));
            }
            it.increment(ec);
        }
        if(ec)errors.push_back("directory-enumeration-error: "+utf8(input)+": "+ec.message());
    }
    if(candidates.size()>=kMaxFiles)errors.push_back("file-count-cap-reached-30000");
    std::sort(candidates.begin(),candidates.end());
    std::vector<Entry> entries;entries.reserve(candidates.size());
    for(const auto& p:candidates){
        auto e=inspect(p);
        std::cout<<"["<<entries.size()+1<<"/"<<candidates.size()<<"] "<<utf8(p)<<"  "
                 <<Label(e.h.container)<<"  version="<<e.h.xfileVersion
                 <<"  "<<Label(e.h.compatibility)<<"\n";
        entries.push_back(std::move(e));
    }
    if(output.empty())output="MWAssetLab_Report.json";
    std::ofstream report(output,std::ios::binary|std::ios::trunc);
    if(!report){std::cerr<<"Cannot create report: "<<utf8(output)<<"\n";return 2;}
    const auto timelines=readTimelines(entries,traceFiles);
    const auto comparisons=compareBaseline(entries,baseline,errors);
    writeJson(report,entries,errors,timelines,comparisons);
    if(!report){std::cerr<<"Error writing report\n";return 2;}
    for(const auto& timeline:timelines) {
        std::cout<<"[LOAD-TRACE] "<<timeline.source<<" events="<<timeline.events.size()<<"\n";
        for(const auto& event:timeline.events) {
            if(event.type=="native-launch-observation"||event.type=="server-lobby-disband")
                std::cout<<"  line "<<event.line<<" "<<event.type<<"\n";
        }
    }
    for(const auto& fam:collisionFamilies(entries))
        std::cout<<"[COLLISION] "<<fam.name<<" tiles="<<fam.tileCount
                 <<" combined="<<fam.combined<<"\n";
    if (!baseline.empty())
        std::cout<<"[BASELINE] candidates compared="<<comparisons.size()<<" no conversion performed\n";
    std::cout<<"\nReport: "<<utf8(fs::absolute(output))<<"\n";
    std::cout<<"No game files have been modified. Native asset backporting is NOT performed.\n";
    return errors.empty()?0:1;
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
#else
int main(int argc,char** argv) {
#endif
    std::vector<fs::path> paths;fs::path report;std::vector<fs::path> traceFiles;fs::path baseline;
    for(int i=1;i<argc;++i){
#ifdef _WIN32
        const fs::path a(argv[i]);
#else
        const fs::path a(argv[i]);
#endif
        if(a=="--output" && i+1<argc)report=fs::path(argv[++i]);
        else if(a=="--trace" && i+1<argc)traceFiles.emplace_back(argv[++i]);
        else if(a=="--baseline" && i+1<argc)baseline=fs::path(argv[++i]);
        else if(a=="--help"||a=="-h"){
            std::cout<<"MWAssetLab: drag files/folders onto MWAssetLab.exe\n"
            "Or: MWAssetLab.exe <file or folder> ... [--trace client.log] [--baseline 1.20-zone-dir] [--output report.json]\n";
            return 0;
        } else paths.push_back(a);
    }
    if(paths.empty() && traceFiles.empty()){
        std::cout<<"CodRevamped MWAssetLab 0.3 - read-only asset compatibility\n"
                   "Drag any .ff/.fp/.xpak/.exe onto MWAssetLab.exe or enter a path: ";
        std::string path;std::getline(std::cin,path);
        if(path.empty())return 0;
        if(path.size()>1 && path.front()=='"'&&path.back()=='"')path=path.substr(1,path.size()-2);
        paths.emplace_back(path);
    }
    return run(paths,report,traceFiles,baseline);
}
