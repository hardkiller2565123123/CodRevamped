#include "platform_resources.h"
#include "crypto.h"
#include "network.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <stdexcept>
#include <set>

namespace platform_resources
{
    namespace
    {
        std::vector<uint8_t> resourceHandle, loopbackHandle, resourceContent;
        std::string contentPath;

        void varint(std::vector<uint8_t> &out, size_t value)
        {
            do
            {
                out.push_back(static_cast<uint8_t>((value & 127) | (value > 127 ? 128 : 0)));
                value >>= 7;
            } while (value);
        }

        void blob(std::vector<uint8_t> &out, unsigned field, const std::vector<uint8_t> &bytes)
        {
            varint(out, static_cast<size_t>(field) * 8 + 2);
            varint(out, bytes.size());
            out.insert(out.end(), bytes.begin(), bytes.end());
        }

        void text(std::vector<uint8_t> &out, unsigned field, const std::string &value)
        {
            blob(out, field, {value.begin(), value.end()});
        }

        void little(std::vector<uint8_t> &out, uint32_t value)
        {
            for (unsigned i = 0; i < 4; ++i)
                out.push_back(static_cast<uint8_t>(value >> (i * 8)));
        }

        bool ascii(const std::string &value, size_t limit)
        {
            if (value.empty() || value.size() > limit)
                return false;
            for (auto c : value)
                if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126)
                    return false;
            return true;
        }
    } // namespace

    void initialize(const std::filesystem::path &directory, unsigned short port)
    {
        const auto path = directory / "platform-word-filters.json";
        // Explicit local policy, not a claim to reproduce Blizzard's production
        // dictionary. An empty policy is valid; native parsing/compilation still run.
        if (!std::filesystem::exists(path))
        {
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!(file << "{\"schema\":1,\"policy\":\"local\",\"filters\":[]}\n") || !file.flush())
                throw std::runtime_error("Cannot create local word-filter policy");
        }
        if (std::filesystem::file_size(path) > 65536)
            throw std::runtime_error("Word-filter policy exceeds limit");
        nlohmann::json policy;
        {
            std::ifstream file(path);
            file >> policy;
        }
        if (!policy.is_object() || policy.value("schema", 0) != 1 ||
            policy.value("policy", "") != "local" || !policy.contains("filters") ||
            !policy["filters"].is_array() || policy["filters"].size() > 128)
            throw std::runtime_error("Invalid local word-filter policy");
        std::vector<uint8_t> protobuf;
        std::set<std::pair<std::string, std::string>> unique;
        for (const auto &filter : policy["filters"])
        {
            const auto word = filter.at("word").get<std::string>(),
                       pattern = filter.at("pattern").get<std::string>();
            if (!ascii(word, 64) || !ascii(pattern, 512) || !unique.emplace(word, pattern).second)
                throw std::runtime_error("Invalid or duplicate word-filter entry");
            std::vector<uint8_t> entry;
            text(entry, 1, word);
            text(entry, 2, pattern);
            blob(protobuf, 1, entry);
            if (protobuf.size() > 4069)
                throw std::runtime_error("Compressed resource exceeds provider limit");
        }
        if (protobuf.empty())
        {
            // Replay's native ZpmC loader cannot decode into a zero-byte output
            // buffer. Represent an explicitly empty local policy with one regex
            // that can never match. The upstream BN/apft example uses this same
            // WordFilters entry shape and negative-lookahead expression.
            std::vector<uint8_t> entry;
            text(entry, 1, "__dw_local_empty_policy__");
            text(entry, 2, "(?!)");
            blob(protobuf, 1, entry);
        }
        // Native codec: 16-byte ZpmC header with 64-bit little-endian decoded size,
        // then an RFC1950 stream containing a single final RFC1951 stored block.
        // No library- or platform-dependent compression output is required.
        resourceContent.clear();
        resourceContent.insert(resourceContent.end(), {'Z', 'p', 'm', 'C'});
        little(resourceContent, 0);
        little(resourceContent, static_cast<uint32_t>(protobuf.size()));
        little(resourceContent, 0);
        resourceContent.insert(resourceContent.end(), {0x78, 0x01, 0x01});
        const auto length = static_cast<uint16_t>(protobuf.size());
        resourceContent.push_back(static_cast<uint8_t>(length));
        resourceContent.push_back(static_cast<uint8_t>(length >> 8));
        resourceContent.push_back(static_cast<uint8_t>(~length));
        resourceContent.push_back(static_cast<uint8_t>((~length) >> 8));
        resourceContent.insert(resourceContent.end(), protobuf.begin(), protobuf.end());
        uint32_t a = 1, b = 0;
        for (auto c : protobuf)
        {
            a = (a + c) % 65521;
            b = (b + a) % 65521;
        }
        const uint32_t adler = (b << 16) | a;
        for (unsigned i = 4; i; --i)
            resourceContent.push_back(static_cast<uint8_t>(adler >> ((i - 1) * 8)));
        const auto digest = crypto::sha256(resourceContent);
        constexpr char hex[] = "0123456789abcdef";
        std::string hash;
        for (auto c : digest)
        {
            hash += hex[c >> 4];
            hash += hex[c & 15];
        }
        contentPath = "/platform/resources/" + hash + ".apft";
        resourceHandle.clear();
        // Exact original ResourceHandle response: region fixed32 field1, usage
        // fixed32 field2, SHA256 bytes field3, content URL string field4.
        resourceHandle.push_back(0x0d);
        little(resourceHandle, 1);
        resourceHandle.push_back(0x15);
        little(resourceHandle, 0x61706674);
        blob(resourceHandle, 3, digest);
        loopbackHandle = resourceHandle;
        text(resourceHandle, 4, network::httpOrigin(port) + contentPath);
        text(loopbackHandle, 4, "http://127.0.0.1:" + std::to_string(port) + contentPath);
        if (resourceContent.size() > 4096 || resourceHandle.size() > 256 ||
            loopbackHandle.size() > 256)
            throw std::runtime_error("Resource publication exceeds ABI bounds");
    }

    const std::vector<uint8_t> &handle()
    {
        return network::isLoopbackPeer() ? loopbackHandle : resourceHandle;
    }

    const std::vector<uint8_t> &content()
    {
        return resourceContent;
    }

    std::optional<std::string> download(const std::string &path)
    {
        if (path != contentPath || resourceContent.empty())
            return std::nullopt;
        return std::string(reinterpret_cast<const char *>(resourceContent.data()),
                           resourceContent.size());
    }
} // namespace platform_resources
