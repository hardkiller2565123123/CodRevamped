#pragma once
// Read-only IW8/Replay 1.20 header classifier.  This is *not* a fastfile
// decompressor and must never be used to relabel an incompatible XFile version.
// Sources: exact-build DB_ResetFileReader.cpp, replay120 loader validation,
// and native IWff header fixtures. Unrecognized fields stay untrusted.
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace codrevamped::iw8::assets {
constexpr std::uint32_t kReplay120XFile = 4087;
constexpr std::uint32_t kReplay120CollisionXFile = 4083;
constexpr std::uint32_t kReplay120HeaderVersion = 11;

inline std::uint32_t ReadLE32(const unsigned char* p) noexcept {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
           (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}

enum class Container : std::uint8_t {
    Unknown, IW8Fastfile, IW8AlternateFastfile, IW8Patch, WindowsExecutable,
    Xpak, Ipak, TextAsset
};
enum class Compatibility : std::uint8_t {
    Unknown, Candidate120, CollisionCandidate120, OtherVersion,
    RequiresPatchPair, NeedsNativeValidation, NotAFastfile
};
struct Header {
    Container container = Container::Unknown;
    Compatibility compatibility = Compatibility::Unknown;
    std::uint32_t headerVersion = 0;
    std::uint32_t xfileVersion = 0;
    std::uint32_t patchType = 0;
    std::uint8_t compression = 0;
    std::uint8_t encryption = 0;
    std::uint8_t transientFileType = 0;
    std::uint32_t residentPartSize = 0;
    bool hasCodecFlags = false;
    bool recognized = false;
};

inline Header Inspect(const unsigned char* input, std::size_t n) noexcept {
    Header h{};
    if (!input || n < 8) return h;
    if (input[0]=='M' && input[1]=='Z') {
        h.container=Container::WindowsExecutable;
        h.compatibility=Compatibility::NotAFastfile;h.recognized=true;return h;
    }
    if (!std::memcmp(input,"IWffc100",8) || !std::memcmp(input,"IWffa100",8)) {
        h.container = input[4]=='c' ? Container::IW8Fastfile : Container::IW8AlternateFastfile;
        h.recognized=true;
        if(n<16) return h;
        h.headerVersion=ReadLE32(input+8);
        h.xfileVersion=ReadLE32(input+12);
        if(n>=0x18) {
            h.compression=input[0x10];
            h.encryption=input[0x11];
            h.transientFileType=input[0x12];
            h.residentPartSize=ReadLE32(input+0x14);
            h.hasCodecFlags=true;
        }
        if(h.headerVersion != kReplay120HeaderVersion) {
            h.compatibility=Compatibility::NeedsNativeValidation;
        } else if(h.xfileVersion==kReplay120XFile) {
            // Only a header candidate. Compression, encryption, pointers,
            // dependencies and asset enums require native validation.
            h.compatibility=Compatibility::Candidate120;
        } else if(h.xfileVersion==kReplay120CollisionXFile) {
            // Collision exception applies to *_cg_ls_tr.ff AND transient type 3,
            // which must be verified by the native loader; filename alone is
            // not sufficient. Therefore never blindly accept it as a zone.
            h.compatibility=Compatibility::CollisionCandidate120;
        } else {
            h.compatibility=Compatibility::OtherVersion;
        }
        return h;
    }
    if (!std::memcmp(input,"IWffd100",8)) {
        h.container=Container::IW8Patch;h.recognized=true;
        h.compatibility=Compatibility::RequiresPatchPair;
        if(n>=16){ h.headerVersion=ReadLE32(input+8);h.patchType=ReadLE32(input+12); }
        return h;
    }
    return h;
}
inline const char* Label(Container c) noexcept {
    switch(c) {
    case Container::IW8Fastfile:return "IWffc100";
    case Container::IW8AlternateFastfile:return "IWffa100";
    case Container::IW8Patch:return "IWffd100";
    case Container::WindowsExecutable:return "Windows-PE";
    case Container::Xpak:return "XPAK";
    case Container::Ipak:return "IPAK";
    case Container::TextAsset:return "TextAsset";
    default:return "Unknown";
    }
}
inline const char* Label(Compatibility s) noexcept {
    switch(s) {
    case Compatibility::Candidate120:return "candidate-1.20-header-only";
    case Compatibility::CollisionCandidate120:return "collision-4083-needs-native-transient-check";
    case Compatibility::OtherVersion:return "other-XFile-version-recompilation-required";
    case Compatibility::RequiresPatchPair:return "patch-needs-matched-ff-fp-native-validation";
    case Compatibility::NeedsNativeValidation:return "header-layout-unknown";
    case Compatibility::NotAFastfile:return "not-a-fastfile";
    default:return "unknown-format";
    }
}
}
