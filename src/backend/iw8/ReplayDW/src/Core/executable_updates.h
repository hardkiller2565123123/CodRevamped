#pragma once
#include "shared_protocol/dw_update_protocol.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace executable_updates
{
    inline bool digestName(const std::string &text)
    {
        return text.size() == 64 && std::all_of(text.begin(),
                                                text.end(),
                                                [](char c)
                                                {
                                                    return (c >= '0' && c <= '9') ||
                                                           (c >= 'a' && c <= 'f');
                                                });
    }

    inline std::string hex(const uint8_t *bytes)
    {
        std::string result;
        for (unsigned i = 0; i < 32; ++i)
        {
            result += "0123456789abcdef"[bytes[i] >> 4];
            result += "0123456789abcdef"[bytes[i] & 15];
        }
        return result;
    }

    inline void decode(const std::string &value, uint8_t *out)
    {
        if (!digestName(value))
            throw std::runtime_error("Invalid executable update digest");
        auto digit = [](char c)
        {
            return c <= '9' ? c - '0' : c - 'a' + 10;
        };
        for (unsigned i = 0; i < 32; ++i)
            out[i] = static_cast<uint8_t>((digit(value[i * 2]) << 4) | digit(value[i * 2 + 1]));
    }

    inline DWUpdatePlan plan(const std::filesystem::path &root,
                             const DWUpdateRequest &request,
                             uint64_t now)
    {
        if (request.magic != DW_UPDATE_MAGIC ||
            (request.version != 1 && request.version != 2) || request.reserved ||
            std::all_of(std::begin(request.nonce),
                        std::end(request.nonce),
                        [](uint8_t c)
                        {
                            return c == 0;
                        }))
            throw std::runtime_error("Invalid executable update request");
        DWUpdatePlan result{};
        result.magic = DW_UPDATE_MAGIC;
        result.version = request.version;
        result.status = 2;
        result.issued = now;
        result.expires = now + 86400;
        std::memcpy(result.nonce, request.nonce, 32);
        std::memcpy(result.baseHash, request.baseHash, 32);
        if (request.version == 2)
        {
            const auto index = root / "updates" / "full-image-catalog.json";
            if (!std::filesystem::exists(index))
                return result;
            if (std::filesystem::file_size(index) > 4096)
                throw std::runtime_error("Full executable catalog exceeds bounds");
            std::ifstream file(index);
            const auto catalog = nlohmann::json::parse(file);
            if (catalog.at("schema") != 1 || catalog.at("format") != "full-executable-v1")
                throw std::runtime_error("Unsupported full executable catalog");
            const auto latest = catalog.at("latest").get<std::string>();
            decode(latest, result.targetHash);
            result.targetSize = catalog.at("target_size").get<uint64_t>();
            result.release = catalog.at("release").get<uint64_t>();
            if (!result.targetSize || result.targetSize > DW_UPDATE_MAX_IMAGE ||
                !result.release ||
                std::filesystem::file_size(root / "updates" / "images" / (latest + ".exe")) !=
                    result.targetSize)
                throw std::runtime_error("Full executable is not completely published");
            if (hex(request.baseHash) == latest)
                result.status = 0;
            else
            {
                // A complete image needs no prior-build inventory. The signed
                // base hash still binds replacement to the player's unchanged EXE.
                result.status = 1;
                std::memcpy(result.patchHash, result.targetHash, 32);
                result.patchSize = result.targetSize;
            }
            return result;
        }
        const auto index = root / "updates" / "catalog.json";
        if (!std::filesystem::exists(index))
            return result;
        if (std::filesystem::file_size(index) > 4 * 1024 * 1024)
            throw std::runtime_error("Executable catalog exceeds bounds");
        std::ifstream file(index);
        const auto catalog = nlohmann::json::parse(file);
        if (catalog.at("schema") != 1 || catalog.at("format") != "msdelta-raw-v1")
            throw std::runtime_error("Unsupported executable catalog");
        const auto latest = catalog.at("latest").get<std::string>();
        decode(latest, result.targetHash);
        result.targetSize = catalog.at("target_size").get<uint64_t>();
        result.release = catalog.at("release").get<uint64_t>();
        if (!result.targetSize || result.targetSize > DW_UPDATE_MAX_IMAGE || !result.release)
            throw std::runtime_error("Invalid target executable bounds");
        const auto base = hex(request.baseHash);
        if (base == latest)
        {
            result.status = 0;
            result.baseSize = result.targetSize;
            return result;
        }
        const auto &patches = catalog.at("patches");
        if (!patches.contains(base))
            return result;
        const auto &entry = patches.at(base);
        result.baseSize = entry.at("base_size").get<uint64_t>();
        result.patchSize = entry.at("size").get<uint64_t>();
        const auto patch = entry.at("sha256").get<std::string>();
        decode(patch, result.patchHash);
        if (!result.baseSize || result.baseSize > DW_UPDATE_MAX_IMAGE || !result.patchSize ||
            result.patchSize > DW_UPDATE_MAX_IMAGE ||
            std::filesystem::file_size(root / "updates" / "patches" / (patch + ".delta")) !=
                result.patchSize)
            throw std::runtime_error("Executable patch is not completely published");
        result.status = 1;
        return result;
    }
} // namespace executable_updates
