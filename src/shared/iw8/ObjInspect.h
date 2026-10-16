#pragma once
// OBJ geometry validator. This is a source-model inspector, not an IW8 XModel
// serializer. It rejects malformed vertex references and non-finite values.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <istream>
#include <sstream>
#include <string>
#include <vector>
namespace codrevamped::iw8::obj {
struct Result {
 std::size_t vertices=0, texcoords=0, normals=0, faces=0, triangles=0;
 std::size_t materialReferences=0, invalidFaces=0, invalidNumbers=0;
 float min[3]{},max[3]{};
 bool hasGeometry=false;
};
inline bool indexOk(const std::string& value,std::size_t count) {
 if(value.empty())return true;
 try {std::size_t end=0;const int idx=std::stoi(value,&end);
     if(end!=value.size() || idx==0)return false;
     return idx>0?static_cast<std::size_t>(idx)<=count:static_cast<std::size_t>(-std::int64_t(idx))<=count;
 } catch(...) {return false;}
}
inline Result Inspect(std::istream& input,std::size_t maxLines=2000000) {
 Result r{};std::string line;std::size_t count=0;
 while(count++<maxLines && std::getline(input,line)) {
   if(line.empty()||line[0]=='#')continue;
   std::istringstream s(line);std::string cmd;s>>cmd;
   if(cmd=="v"){
     float a[3]{};if(!(s>>a[0]>>a[1]>>a[2]) || !std::isfinite(a[0])||!std::isfinite(a[1])||!std::isfinite(a[2])) {++r.invalidNumbers;continue;}
     for(int i=0;i<3;++i){if(!r.hasGeometry){r.min[i]=r.max[i]=a[i];}else {r.min[i]=std::min(r.min[i],a[i]);r.max[i]=std::max(r.max[i],a[i]);}}
     r.hasGeometry=true;++r.vertices;
   } else if(cmd=="vt") {++r.texcoords;}
   else if(cmd=="vn") {++r.normals;}
   else if(cmd=="usemtl" || cmd=="mtllib") {++r.materialReferences;}
   else if(cmd=="f") {
     std::size_t n=0;bool valid=true;std::string token;
     while(s>>token){
       if(token[0]=='#')break;
       std::string a[3];std::size_t off=0;
       for(int j=0;j<3;++j){auto next=token.find('/',off);
         a[j]=token.substr(off,next==std::string::npos?std::string::npos:next-off);
         if(next==std::string::npos){break;} off=next+1;
       }
       if(!indexOk(a[0],r.vertices)||a[0].empty()||!indexOk(a[1],r.texcoords)||!indexOk(a[2],r.normals))valid=false;
       ++n;
     }
     ++r.faces;if(n<3||!valid)++r.invalidFaces;
     else r.triangles+=n-2;
   }
 }
 return r;
}
}
