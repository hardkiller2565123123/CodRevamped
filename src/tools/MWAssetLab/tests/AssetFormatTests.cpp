#include "../../../shared/iw8/AssetFormat.h"
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>

using namespace codrevamped::iw8::assets;
static std::array<unsigned char,16> header(const char* magic,std::uint32_t hv,std::uint32_t xv) {
    std::array<unsigned char,16> h{};
    std::memcpy(h.data(),magic,8);
    for(int i=0;i<4;++i){h[8+i]=static_cast<unsigned char>(hv>>(8*i));h[12+i]=static_cast<unsigned char>(xv>>(8*i));}
    return h;
}
int main(){
    auto a=header("IWffc100",11,4087);
    auto r=Inspect(a.data(),a.size());
    assert(r.recognized&&r.container==Container::IW8Fastfile&&r.compatibility==Compatibility::Candidate120);
    a=header("IWffa100",11,4087);
    assert(Inspect(a.data(),a.size()).container==Container::IW8AlternateFastfile);
    a=header("IWffc100",11,4083);
    assert(Inspect(a.data(),a.size()).compatibility==Compatibility::CollisionCandidate120);
    a=header("IWffc100",11,4200);
    assert(Inspect(a.data(),a.size()).compatibility==Compatibility::OtherVersion);
    a=header("IWffc100",22,4087);
    assert(Inspect(a.data(),a.size()).compatibility==Compatibility::NeedsNativeValidation);
    a=header("IWffd100",6,4);
    assert(Inspect(a.data(),a.size()).compatibility==Compatibility::RequiresPatchPair);
    a=header("MZabcdef",0,0);
    assert(Inspect(a.data(),a.size()).container==Container::WindowsExecutable);
    assert(Inspect(a.data(),3).container==Container::Unknown);
}
