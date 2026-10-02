#pragma once
#include <string>
#include <cstdlib>
#include "LocalManifestData.h"

namespace revamped::iw8::localpublisher
{
    // IW8 1.20 requests TU19. Keep TU24 accepted as well so the same local
    // publisher helper remains usable by later IW8 builds that use that name.
    inline constexpr const char* PlaylistNameTu19 = "unified_large_playlist_tu19.aggr";
    inline constexpr const char* PlaylistNameTu24 = "unified_large_playlist_tu24.aggr";

    inline bool IsManifest(const std::string& name)
    {
        return name == "1_manifest_patch_pc_8.19.txt" ||
            name == "1_manifest_comms_pc_8.19.txt";
    }

    inline bool IsPlaylist(const std::string& name)
    {
        return name == PlaylistNameTu19 || name == PlaylistNameTu24;
    }
    inline bool LocalManifestEnabled()
    {
        // MW2019 1.20's 8.19 patch/comms manifests are required for the stock
        // update fence. Enable the local signed manifests by default so the
        // client and backend cannot silently fall out of sync because the
        // server process was launched without an environment variable.
        //
        // Set CODREVAMPED_MW120_LOCAL_MANIFESTS=0 only when explicitly testing
        // the stock missing-manifest path.
        char* value = nullptr;
        std::size_t length = 0;
        if (_dupenv_s(&value, &length, "CODREVAMPED_MW120_LOCAL_MANIFESTS") != 0)
            return true;

        if (!value)
            return true;

        const std::string setting(value);
        std::free(value);
        return setting != "0";
    }

    // Locally signed empty inventory; requires the opt-in manifest trust key.
    inline const std::string& ManifestBody()
    {
        static const std::string body = localmanifestdata::Body;
        return body;
    }
    // CCS copies this into char[29] and base64-decodes a 20-byte SHA-1.
    inline constexpr const char* ManifestChecksum = localmanifestdata::Checksum;
    inline constexpr const char* PathPrefix = "/__revamped/objectstore/publisher/infinityward/";

    // Stock IW8 expects playlistAggrFilename to be a zlib-compressed aggregate
    // and calls DecompressIntoBuffer before parsing it as JSON. An entirely
    // empty playlist document parses but is rejected because the root category
    // has no entries. Keep one harmless local MP playlist so the parser reaches
    // a clean zero-error state without impersonating the retail playlist set.
    // Uncompressed JSON:
    // {"system":{"version":1},"gametypes":[{"gametype":"dm","script":"dm"}],"playlists":[{"playlist":1,"type":"mp","maps":[{"map":"mp_m_cave","gametype":"dm","weight":100}]}],"categories":[]}
    inline const std::string& PlaylistBody()
    {
        static constexpr unsigned char kCompressed[] = {
            0x78, 0xDA, 0x65, 0x8E, 0x4D, 0x0A, 0xC3, 0x20,
            0x10, 0x85, 0xEF, 0xF2, 0xD6, 0x2E, 0x92, 0xAD,
            0x57, 0x29, 0x12, 0xC4, 0x0E, 0x56, 0xC8, 0x24,
            0xE2, 0x48, 0x8A, 0x88, 0x77, 0xAF, 0x89, 0x69,
            0x37, 0xDD, 0xCD, 0x37, 0xBC, 0xBF, 0x0A, 0x29,
            0x92, 0x89, 0xA1, 0x2B, 0x0E, 0x4A, 0x12, 0xF6,
            0x0D, 0x7A, 0x6E, 0x0A, 0xDE, 0x32, 0xE5, 0x12,
            0x49, 0xA0, 0x1F, 0xF5, 0x47, 0xD0, 0x78, 0x32,
            0x14, 0xC4, 0xA5, 0x10, 0xF3, 0xA0, 0x66, 0x14,
            0xE2, 0x6A, 0xCB, 0x1A, 0x24, 0x0F, 0xF5, 0x97,
            0x7A, 0x92, 0xC2, 0x6D, 0xE3, 0xD8, 0x6D, 0x6C,
            0xE3, 0x50, 0xF4, 0xE3, 0xFA, 0x2D, 0xBC, 0x38,
            0x7B, 0x10, 0xD4, 0x5F, 0xC3, 0x9B, 0x82, 0x7F,
            0x9D, 0x09, 0xD3, 0xD4, 0xCC, 0x59, 0xE1, 0x6C,
            0x26, 0xBF, 0xA7, 0x70, 0x2D, 0x32, 0xED, 0x03,
            0xE1, 0x25, 0x3E, 0x3A
        };
        static const std::string body(
            reinterpret_cast<const char*>(kCompressed), sizeof(kCompressed));
        return body;
    }
}
