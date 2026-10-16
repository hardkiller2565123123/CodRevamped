#pragma once
// Bounded, read-only conventional image header recognition. GfxImage creation
// and native IW8 texture streaming are NOT implied by any successful probe.
#include <cstddef>
#include <cstdint>
#include <cstring>
namespace codrevamped::iw8::gfx {
enum class Type { Unknown, PNG, DDS, TGA, IWI };
struct ImageInfo {
  Type type = Type::Unknown;
  std::uint32_t width = 0, height = 0;
  std::uint32_t mipCount = 0;
  std::uint32_t version = 0;
  char format[9]{};
  bool validDimensions = false;
};
inline std::uint32_t le32(const unsigned char* p) {
  return std::uint32_t(p[0])|std::uint32_t(p[1])<<8|std::uint32_t(p[2])<<16|std::uint32_t(p[3])<<24;
}
inline std::uint32_t be32(const unsigned char* p) {
  return std::uint32_t(p[3])|std::uint32_t(p[2])<<8|std::uint32_t(p[1])<<16|std::uint32_t(p[0])<<24;
}
inline std::uint32_t le16(const unsigned char* p) {return std::uint32_t(p[0])|std::uint32_t(p[1])<<8;}
inline ImageInfo Inspect(const unsigned char* p, std::size_t n) {
  ImageInfo i{};
  if (!p) return i;
  if (n>=24 && !std::memcmp(p,"\x89PNG\r\n\x1a\n",8) && !std::memcmp(p+12,"IHDR",4)) {
    i.type=Type::PNG;i.width=be32(p+16);i.height=be32(p+20);
    std::memcpy(i.format,"PNG",4);i.mipCount=1;
  } else if (n>=128 && !std::memcmp(p,"DDS ",4) && le32(p+4)==124 && le32(p+76)==32) {
    i.type=Type::DDS;i.height=le32(p+12);i.width=le32(p+16);
    i.mipCount=le32(p+28);if (!i.mipCount)i.mipCount=1;
    std::memcpy(i.format,p+84,4); // fourCC e.g. DXT1/DXT5/DX10
    if (!i.format[0])std::memcpy(i.format,"RGBA",5);
  } else if (n>=4 && p[0]=='I'&&p[1]=='W'&&p[2]=='i') {
    i.type=Type::IWI;i.version=p[3];std::memcpy(i.format,"IWI",4);
    // Version-specific IWI dimensions are intentionally not guessed.
  } else if (n>=18 && p[1]==0 && (p[2]==2 || p[2]==3) && (p[16]==8||p[16]==24||p[16]==32)) {
    i.type=Type::TGA;i.width=le16(p+12);i.height=le16(p+14);
    std::memcpy(i.format,p[2]==3?"GRAY":"BGR",5);i.mipCount=1;
  }
  i.validDimensions = i.width>0 && i.height>0 && i.width<=32768 && i.height<=32768;
  return i;
}
inline const char* Label(Type t){switch(t){
case Type::PNG:return "png";case Type::DDS:return "dds";
case Type::TGA:return "tga";case Type::IWI:return "iwi";
default:return "unknown";}}
}
