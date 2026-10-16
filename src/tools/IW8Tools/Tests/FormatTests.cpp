#include "../../../shared/iw8/GfxInspect.h"
#include "../../../shared/iw8/ObjInspect.h"
#include <cassert>
#include <sstream>
int main(){
 unsigned char png[32]={137,'P','N','G',13,10,26,10,0,0,0,13,'I','H','D','R',0,0,1,0,0,0,0,128};
 auto p=codrevamped::iw8::gfx::Inspect(png,sizeof png); assert(p.validDimensions&&p.width==256&&p.height==128);
 unsigned char dds[128]={};dds[0]='D';dds[1]='D';dds[2]='S';dds[3]=' ';dds[4]=124;dds[76]=32;dds[12]=64;dds[16]=32;
 auto d=codrevamped::iw8::gfx::Inspect(dds,sizeof dds);assert(d.validDimensions&&d.width==32&&d.height==64);
 unsigned char iwi[]={'I','W','i',6};assert(codrevamped::iw8::gfx::Inspect(iwi,4).version==6);
 std::istringstream good("v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n");
 auto a=codrevamped::iw8::obj::Inspect(good);assert(a.faces==1&&a.triangles==1&&!a.invalidFaces);
 std::istringstream bad("v 0 0 0\nf 1 2 3\n"); assert(codrevamped::iw8::obj::Inspect(bad).invalidFaces==1);
}
