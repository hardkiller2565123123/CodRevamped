#include <stddef.h>
#include <stdint.h>

#include "db/DB_ResetFileReader.h"
#ifdef REPLAY_COMPILER_FRONTEND_CONSOLIDATED_C3S5
#include "db/DB_FrontendProfiles.h"
#endif

extern "C" void replay_rva_00d86f00(void*, uint32_t, uint32_t); // DB_DiscError
extern "C" uintptr_t replay_rva_00d88120(void*, uint32_t, void*, const uint32_t*);

#ifdef REPLAY_COMPILER_FRONTEND_PROBE
extern "C" uint32_t s_dbFrontendUnsignedReaders = 0;
#endif

namespace {
constexpr uint32_t kReplayXFileVersion = 0x0ff7;
#ifdef REPLAY_COMPILER_FRONTEND_PROBE
constexpr uint32_t kReplayFrontend6XFileVersion = 4118;
constexpr uint32_t kReplayFrontend7bXFileVersion = 4136;
#endif
constexpr uint32_t kReplayIwcHeaderVersion = 11;
constexpr uint32_t kReplayPatchHeaderVersion = 6;
constexpr uint32_t kReplayHeaderOnlyPatchType = 4;

size_t DB_StringLength(const char* value)
{
    size_t length = 0;
    while (value[length]) ++length;
    return length;
}

bool DB_BytesEqual(const void* left, const void* right, size_t length)
{
    const auto* leftBytes = static_cast<const volatile uint8_t*>(left);
    const auto* rightBytes = static_cast<const volatile uint8_t*>(right);
    for (size_t index = 0; index < length; ++index) {
        if (leftBytes[index] != rightBytes[index]) return false;
    }
    return true;
}

bool DB_HasZoneFileSuffix(const DBReplayFastfileDescriptor& descriptor,
                          const char* suffix)
{
    size_t length = 0;
    while (length < sizeof(descriptor.zoneName) && descriptor.zoneName[length]) ++length;
    const size_t suffixLength = DB_StringLength(suffix);
    return length > suffixLength && length < sizeof(descriptor.zoneName) &&
        DB_BytesEqual(descriptor.zoneName + length - suffixLength, suffix, suffixLength);
}

#ifdef REPLAY_COMPILER_FRONTEND_PROBE
bool DB_HasExactZoneFileName(const DBReplayFastfileDescriptor& descriptor,
                             const char* fileName)
{
    size_t length = 0;
    while (length < sizeof(descriptor.zoneName) && descriptor.zoneName[length]) ++length;
    const size_t fileNameLength = DB_StringLength(fileName);
    if (length < fileNameLength || length >= sizeof(descriptor.zoneName) ||
        !DB_BytesEqual(descriptor.zoneName + length - fileNameLength, fileName, fileNameLength))
        return false;
    if (length == fileNameLength) return true;
    const char separator = descriptor.zoneName[length - fileNameLength - 1];
    return separator == '/' || separator == '\\';
}
#endif

bool DB_IsReplayIwcHeader(const DBReplayFastfileHeader& header, uint32_t xfileVersion,
                          uint8_t transientTypeLimit = 1)
{
    if (!DB_BytesEqual(header.magic, "IWffc100", 8) ||
        header.headerVersion != kReplayIwcHeaderVersion ||
        header.xfileVersion != xfileVersion ||
        header.compression != 0 || header.encryption != 0 || header.zeroPad13 != 0 ||
        header.transientFileType > transientTypeLimit || header.zeroPad18 != 0 ||
        !header.decodedSize || header.alwaysLoadedSize != header.decodedSize)
        return false;
    return true;
}

#ifdef REPLAY_COMPILER_FRONTEND_PROBE
bool DB_IsRetainedFrontendPackage(const DBReplayFastfileDescriptor& descriptor)
{
    const auto& header = descriptor.payload.iwc;
    if (!DB_HasZoneFileSuffix(descriptor, ".ff")) return false;
    if (DB_HasExactZoneFileName(descriptor, "techsets_mp_frontend6.ff"))
        return DB_IsReplayIwcHeader(header, kReplayFrontend6XFileVersion);
    if (DB_HasExactZoneFileName(descriptor, "techsets_mp_frontend7b.ff"))
        return DB_IsReplayIwcHeader(header, kReplayFrontend7bXFileVersion);
    return false;
}
#endif

#ifdef REPLAY_COMPILER_FRONTEND_CONSOLIDATED_C3S5
const DBFrontendProfile* DB_ConsolidatedFrontendProfile(
    const DBReplayFastfileDescriptor& descriptor)
{
    const bool isFastfile = DB_HasZoneFileSuffix(descriptor, ".ff");
    const bool isPatchFile = DB_HasZoneFileSuffix(descriptor, ".fp");
    if (!isFastfile && !isPatchFile) return nullptr;

    const auto* profile = DB_FindFrontendProfile(descriptor.zoneName);
    if (!profile || profile->contract != DB_FRONTEND_TRANSLATED_PLACEHOLDERS ||
        !DB_FrontendZoneNameMatches(descriptor.zoneName, "", profile->scene) ||
        !DB_FrontendZoneNameMatches(REPLAY_COMPILER_FRONTEND_PROBE, "", profile->scene))
        return nullptr;
    return profile;
}

bool DB_IsConsolidatedFrontendPackage(const DBReplayFastfileDescriptor& descriptor,
                                      const DBFrontendProfile& profile)
{
    const bool isFastfile = DB_HasZoneFileSuffix(descriptor, ".ff");

    if (isFastfile)
        return DB_IsReplayIwcHeader(descriptor.payload.iwc, profile.finalVersion);

    const auto& patch = descriptor.payload.patch;
    return DB_BytesEqual(patch.prefix.magic, "IWffd100", 8) &&
        patch.prefix.patchVersion == kReplayPatchHeaderVersion &&
        patch.prefix.patchType == kReplayHeaderOnlyPatchType &&
        DB_IsReplayIwcHeader(patch.previous, profile.finalVersion) &&
        DB_IsReplayIwcHeader(patch.target, profile.finalVersion) &&
        DB_BytesEqual(&patch.previous, &patch.target, sizeof(DBReplayFastfileHeader));
}
#endif

bool DB_IsNativeUnsignedReplayPackage(const DBReplayFastfileDescriptor& descriptor)
{
    if (descriptor.signedFile != 0 ||
        (!DB_HasZoneFileSuffix(descriptor, ".ff") &&
         !DB_HasZoneFileSuffix(descriptor, ".fp")))
        return false;

#ifdef REPLAY_COMPILER_FRONTEND_CONSOLIDATED_C3S5
    if (const auto* profile = DB_ConsolidatedFrontendProfile(descriptor))
        return DB_FrontendProfileEnabled(*profile) &&
            DB_IsConsolidatedFrontendPackage(descriptor, *profile);
#endif

    const auto& package = descriptor.payload.patch;
    if (DB_BytesEqual(descriptor.payload.iwc.magic, "IWffc100", 8)) {
        if (DB_IsReplayIwcHeader(descriptor.payload.iwc, kReplayXFileVersion))
            return true;
        // Shipped Replay collision zones use 4083/type 3. Retain their native
        // contract when the zonetool merges the tile grid into a full zone.
        if (descriptor.payload.iwc.transientFileType == 3 &&
            DB_HasZoneFileSuffix(descriptor, "_cg_ls_tr.ff") &&
            DB_IsReplayIwcHeader(descriptor.payload.iwc, 4083, 3))
            return true;
#ifdef REPLAY_COMPILER_FRONTEND_PROBE
        return DB_IsRetainedFrontendPackage(descriptor);
#else
        return false;
#endif
    }

    // Our no-op header patch is the stock ReloadReader patch representation:
    // a version-6/type-4 patch with equal, complete native Replay headers on
    // both sides. This admits the associated .fp while rejecting arbitrary or
    // version-changing patch descriptors.
    if (!DB_BytesEqual(package.prefix.magic, "IWffd100", 8) ||
        package.prefix.patchVersion != kReplayPatchHeaderVersion ||
        package.prefix.patchType != kReplayHeaderOnlyPatchType ||
        !DB_IsReplayIwcHeader(package.previous, kReplayXFileVersion) ||
        !DB_IsReplayIwcHeader(package.target, kReplayXFileVersion))
        return false;
    return DB_BytesEqual(&package.previous, &package.target,
                         sizeof(DBReplayFastfileHeader));
}
}

// Native 0xd871e0..0xd87229. Keep descriptor ownership, compression metadata,
// error handling and the original signed-reader path in the engine.
extern "C" uintptr_t DB_ResetFileReader(void* reader)
{
    auto* nativeReader = static_cast<DBReplayFileReaderPrefix*>(reader);
    auto* descriptor = nativeReader->descriptor;
    if (!descriptor->signedFile) {
        if (DB_IsNativeUnsignedReplayPackage(*descriptor)) {
#ifdef REPLAY_COMPILER_FRONTEND_PROBE
            ++s_dbFrontendUnsignedReaders;
#endif
            const auto* compression = descriptor->compressionInfo
                ? &descriptor->compressionInfo : nullptr;
            return replay_rva_00d88120(reinterpret_cast<void*>(nativeReader->inflatorState),
                0, descriptor, compression);
        }
        replay_rva_00d86f00(reader, 1, 0);
        descriptor = nativeReader->descriptor;
    }
    const auto* compression = descriptor->compressionInfo
        ? &descriptor->compressionInfo : nullptr;
    return replay_rva_00d88120(reinterpret_cast<void*>(nativeReader->inflatorState),
        descriptor->signedFile, descriptor, compression);
}
