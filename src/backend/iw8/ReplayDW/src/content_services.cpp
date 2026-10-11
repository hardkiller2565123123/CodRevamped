#include "host_os.h"
#include "content_services.h"
#include "crypto.h"
#include "network.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <chrono>
#include <charconv>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <string_view>
#include <memory>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t maxStore = 16 * 1024 * 1024, maxFiles = 4096;
        constexpr size_t maxMultipartParts = 1024, maxMultipartSessions = 128;
        constexpr size_t maxCopySessions = 128, maxCopyReceipts = 32768;
        constexpr size_t maxUserUploads = 128, maxUserUploadReceipts = 4096;
        constexpr uint32_t copyLifetimeSeconds = 600;
        std::filesystem::path dataRoot;
        unsigned short contentPort = 0;

        std::string origin()
        {
            return network::httpOrigin(contentPort);
        }

        std::mutex contentMutex;

        uint32_t now()
        {
            return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        bool hashText(const std::string &text, size_t size = 64)
        {
            return text.size() == size && std::all_of(text.begin(),
                                                      text.end(),
                                                      [](char c)
                                                      {
                                                          return (c >= '0' && c <= '9') ||
                                                                 (c >= 'a' && c <= 'f');
                                                      });
        }

        std::string hex(std::span<const uint8_t> bytes)
        {
            constexpr char digits[] = "0123456789abcdef";
            std::string out;
            for (auto byte : bytes)
            {
                out.push_back(digits[byte >> 4]);
                out.push_back(digits[byte & 15]);
            }
            return out;
        }

        std::filesystem::path storePath(uint32_t title)
        {
            return dataRoot / "content-streaming" / std::to_string(title) / "files.json";
        }

        std::filesystem::path blobPath(uint32_t title, const std::string &hash)
        {
            return dataRoot / "content-streaming" / std::to_string(title) / "blobs" /
                   (hash + ".bin");
        }

        std::filesystem::path multipartPath(uint32_t title)
        {
            return dataRoot / "content-streaming" / std::to_string(title) / "multipart.json";
        }

        void atomic(const std::filesystem::path &path, std::span<const uint8_t> bytes)
        {
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            const auto file = CreateFileW(pending.c_str(),
                                          GENERIC_WRITE,
                                          0,
                                          nullptr,
                                          CREATE_ALWAYS,
                                          FILE_ATTRIBUTE_NORMAL,
                                          nullptr);
            if (file == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Streaming store write failed");
            std::unique_ptr<void, decltype(&CloseHandle)> handle(file, &CloseHandle);
            size_t offset = 0;
            while (offset < bytes.size())
            {
                DWORD written = 0;
                if (!WriteFile(file,
                               bytes.data() + offset,
                               static_cast<DWORD>(bytes.size() - offset),
                               &written,
                               nullptr) ||
                    !written)
                    throw std::runtime_error("Streaming store write failed");
                offset += written;
            }
            if (!FlushFileBuffers(file))
                throw std::runtime_error("Streaming store flush failed");
            // Windows replacement requires closing the non-delete-sharing writer.
            CloseHandle(handle.release());
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Streaming store publication failed");
        }

        void save(uint32_t title, const Json &value)
        {
            const auto encoded = value.dump();
            wire::require(encoded.size() <= maxStore);
            atomic(storePath(title),
                   std::span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size()));
        }

        uint64_t number(const Json &value, uint64_t maximum = UINT64_MAX)
        {
            wire::require(value.is_number_unsigned());
            const auto out = value.get<uint64_t>();
            wire::require(out <= maximum);
            return out;
        }

        std::string text(const Json &value, size_t limit)
        {
            const auto out = value.get<std::string>();
            wire::require(out.size() < limit && out.find('\0') == std::string::npos);
            return out;
        }

        void validateTags(const Json &tags)
        {
            wire::require(tags.is_array() && tags.size() <= 256);
            for (const auto &pair : tags)
            {
                wire::require(pair.is_array() && pair.size() == 2);
                for (const auto &part : pair)
                    (void)number(part, UINT64_MAX - 1);
            }
        }

        void validateFile(const Json &row)
        {
            wire::require(number(row.at("id"), UINT64_MAX - 1) != 0);
            wire::require(row.at("kind") == "user" || row.at("kind") == "publisher" ||
                          row.at("kind") == "pooled");
            const auto owner = number(row.at("owner"), UINT64_MAX - 1);
            wire::require(owner || row.at("kind") == "publisher");
            wire::require(!text(row.at("name"), 128).empty());
            (void)text(row.at("owner_name"), 64);
            for (const auto *key : {"created", "modified", "copies"})
                (void)number(row.at(key), UINT32_MAX);
            for (const auto *key : {"slot", "category"})
                (void)number(row.at(key), UINT16_MAX);
            (void)number(row.at("origin"), UINT64_MAX - 1);
            (void)number(row.at("size"), maximumStreamingBody);
            (void)number(row.at("summary_size"), maximumStreamingBody);
            wire::require(hashText(text(row.at("content"), 65)));
            const auto summary = text(row.at("summary"), 65);
            wire::require(summary.empty() ? row.at("summary_size") == 0 : hashText(summary));
            (void)wire::base64(row.at("metadata").get<std::string>(), 2048);
            validateTags(row.at("tags"));
            if (row.contains("copy_receipt"))
            {
                const auto &receipt = row.at("copy_receipt");
                wire::require(row.at("kind") == "user" &&
                              hashText(text(receipt.at("token"), 33), 32) &&
                              hashText(text(receipt.at("request_sha256"), 65)));
            }
            if (row.contains("upload_receipt"))
                wire::require(row.at("kind") == "user" &&
                              hashText(text(row.at("upload_receipt"), 33), 32));
            if (row.contains("parts"))
            {
                const auto &parts = row.at("parts");
                wire::require(row.at("kind") == "pooled" && parts.is_array() &&
                              parts.size() <= maxMultipartParts);
                uint64_t total = 0;
                for (const auto &part : parts)
                {
                    wire::require(hashText(text(part.at("content"), 65)));
                    total += number(part.at("size"), maximumStreamingBody);
                    wire::require(total <= maximumStreamingBody);
                }
                wire::require(total == row.at("size"));
            }
        }

        Json load(uint32_t title)
        {
            const auto path = storePath(title);
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"files", Json::array()}};
            if (std::filesystem::file_size(path) > maxStore)
                throw std::runtime_error("Streaming store size invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Streaming store read failed");
            const auto data = Json::parse(in);
            try
            {
                wire::require(data.at("schema") == 1 && data.at("files").is_array() &&
                              data.at("files").size() <= maxFiles);
                std::set<uint64_t> ids;
                for (const auto &row : data.at("files"))
                {
                    const auto file = number(row.at("id"), UINT64_MAX - 1);
                    wire::require(file && ids.insert(file).second);
                    validateFile(row);
                }
                if (data.contains("copy_receipts"))
                {
                    const auto &receipts = data.at("copy_receipts");
                    wire::require(receipts.is_object() && receipts.size() <= maxCopyReceipts);
                    for (const auto &entry : receipts.items())
                    {
                        const auto &receipt = entry.value();
                        wire::require(hashText(entry.key(), 32) && receipt.is_object() &&
                                      number(receipt.at("owner"), UINT64_MAX - 1) &&
                                      number(receipt.at("file"), UINT64_MAX - 1) &&
                                      hashText(text(receipt.at("request_sha256"), 65)));
                    }
                }
                if (data.contains("upload_receipts"))
                {
                    const auto &receipts = data.at("upload_receipts");
                    wire::require(receipts.is_object() && receipts.size() <= maxUserUploadReceipts);
                    std::set<uint64_t> receiptFiles;
                    for (const auto &entry : receipts.items())
                    {
                        const auto &receipt = entry.value();
                        wire::require(hashText(entry.key(), 32) && receipt.is_object() &&
                                      hashText(text(receipt.at("request_sha256"), 65)));
                        const auto &row = receipt.at("row");
                        validateFile(row);
                        wire::require(row.at("kind") == "user" &&
                                      row.at("upload_receipt") == entry.key() &&
                                      receiptFiles.insert(number(row.at("id"))).second);
                    }
                }
                for (const auto &row : data.at("files"))
                    if (row.contains("upload_receipt"))
                    {
                        const auto &receipt = data.at("upload_receipts")
                                                  .at(row.at("upload_receipt").get<std::string>());
                        const auto &original = receipt.at("row");
                        for (const auto *key : {"id", "owner", "slot", "content", "size"})
                            wire::require(original.at(key) == row.at(key));
                    }
                for (const auto &row : data.at("files"))
                    if (row.contains("copy_receipt"))
                    {
                        const auto &marker = row.at("copy_receipt");
                        const auto &receipt =
                            data.at("copy_receipts").at(marker.at("token").get<std::string>());
                        wire::require(receipt.at("owner") == row.at("owner") &&
                                      receipt.at("file") == row.at("id") &&
                                      receipt.at("request_sha256") == marker.at("request_sha256"));
                    }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Streaming store schema invalid");
            }
            return data;
        }

        Json loadMultipart(uint32_t title)
        {
            const auto path = multipartPath(title);
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"title", title}, {"sessions", Json::array()}};
            if (std::filesystem::file_size(path) > maxStore)
                throw std::runtime_error("Multipart store size invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Multipart store read failed");
            auto data = Json::parse(in);
            try
            {
                wire::require(data.at("schema") == 1 &&
                              number(data.at("title"), UINT32_MAX) == title);
                const auto &sessions = data.at("sessions");
                wire::require(sessions.is_array() && sessions.size() <= maxMultipartSessions);
                std::set<uint64_t> files;
                std::set<std::string> tokens;
                for (const auto &session : sessions)
                {
                    const auto file = number(session.at("id"), UINT64_MAX - 1);
                    wire::require(file && files.insert(file).second);
                    wire::require(number(session.at("owner"), UINT64_MAX - 1) > 0);
                    wire::require(!text(session.at("name"), 128).empty());
                    (void)text(session.at("owner_name"), 64);
                    (void)number(session.at("category"), UINT16_MAX);
                    validateTags(session.at("tags"));
                    const auto created = number(session.at("created"), UINT32_MAX),
                               expires = number(session.at("expires"), UINT32_MAX);
                    wire::require(expires > created);
                    const auto &parts = session.at("parts");
                    wire::require(parts.is_array() && parts.size() <= maxMultipartParts);
                    uint64_t total = 0;
                    for (const auto &part : parts)
                    {
                        const auto token = text(part.at("token"), 33);
                        wire::require(hashText(token, 32) && tokens.insert(token).second);
                        const auto hash = text(part.at("content"), 65);
                        const auto size = number(part.at("size"), maximumStreamingBody);
                        wire::require(hash.empty() ? size == 0 : hashText(hash));
                        total += size;
                        wire::require(total <= maximumStreamingBody);
                    }
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Multipart store schema invalid");
            }
            return data;
        }

        void saveMultipart(uint32_t title, const Json &data)
        {
            const auto encoded = data.dump();
            if (encoded.size() > maxStore)
                throw std::runtime_error("Multipart store capacity exceeded");
            atomic(multipartPath(title),
                   std::span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size()));
        }

        void expireMultipart(Json &data)
        {
            const auto stamp = now();
            auto &sessions = data["sessions"];
            sessions.erase(std::remove_if(sessions.begin(),
                                          sessions.end(),
                                          [stamp](const auto &row)
                                          {
                                              return row.at("expires").template get<uint32_t>() <=
                                                     stamp;
                                          }),
                           sessions.end());
        }

        std::filesystem::path copyPath(uint32_t title)
        {
            return dataRoot / "content-streaming" / std::to_string(title) / "copies.json";
        }

        Json loadCopies(uint32_t title)
        {
            const auto path = copyPath(title);
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"sessions", Json::array()}};
            if (std::filesystem::file_size(path) > maxStore)
                throw std::runtime_error("Streaming copy store size invalid");
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Streaming copy store read failed");
            auto result = Json::parse(stream);
            try
            {
                wire::require(result.at("schema") == 1 && result.at("sessions").is_array() &&
                              result["sessions"].size() <= maxCopySessions);
                std::set<std::string> tokens;
                std::set<uint64_t> files;
                for (const auto &session : result["sessions"])
                {
                    const auto token = text(session.at("token"), 33);
                    wire::require(hashText(token, 32) && tokens.insert(token).second &&
                                  number(session.at("owner"), UINT64_MAX - 1) &&
                                  number(session.at("file"), UINT64_MAX - 1) &&
                                  files.insert(session["file"].get<uint64_t>()).second &&
                                  session.at("pooled").is_boolean());
                    (void)text(session.at("owner_name"), 64);
                    (void)number(session.at("slot"), UINT16_MAX);
                    (void)number(session.at("expires"), UINT32_MAX);
                    validateFile(session.at("source"));
                    wire::require(session["pooled"] == (session["source"]["kind"] == "pooled") &&
                                  (session["source"]["kind"] == "pooled" ||
                                   session["source"]["kind"] == "user"));
                    const auto &copied = session.at("copied");
                    wire::require(copied.is_array() &&
                                  copied.size() == (session["source"]["summary"] == "" ? 1 : 2));
                    for (const auto &part : copied)
                        wire::require(part.is_boolean());
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Streaming copy store schema invalid");
            }
            auto &sessions = result["sessions"];
            sessions.erase(std::remove_if(sessions.begin(),
                                          sessions.end(),
                                          [](const auto &session)
                                          {
                                              return session["expires"].template get<uint32_t>() <=
                                                     now();
                                          }),
                           sessions.end());
            return result;
        }

        void saveCopies(uint32_t title, const Json &value)
        {
            const auto bytes = value.dump();
            if (bytes.size() > maxStore)
                throw std::runtime_error("Streaming copy store capacity exceeded");
            atomic(copyPath(title),
                   std::span(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()));
        }

        wire::Bytes readBlob(uint32_t title, const std::string &hash, uint64_t expected)
        {
            const auto path = blobPath(title, hash);
            if (!std::filesystem::exists(path) || std::filesystem::file_size(path) != expected ||
                expected > maximumStreamingBody)
                throw std::runtime_error("Streaming blob size invalid");
            wire::Bytes bytes(static_cast<size_t>(expected));
            std::ifstream in(path, std::ios::binary);
            if (!in.read(reinterpret_cast<char *>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size())))
                throw std::runtime_error("Streaming blob read failed");
            if (hex(crypto::sha256(bytes)) != hash)
                throw std::runtime_error("Streaming blob hash invalid");
            return bytes;
        }

        std::filesystem::path userUploadPath(uint32_t title)
        {
            return dataRoot / "content-streaming" / std::to_string(title) / "user-uploads.json";
        }

        Json loadUserUploads(uint32_t title)
        {
            const auto path = userUploadPath(title);
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"title", title}, {"sessions", Json::array()}};
            if (std::filesystem::file_size(path) > maxStore)
                throw std::runtime_error("User upload store size invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("User upload store read failed");
            auto data = Json::parse(in);
            try
            {
                wire::require(data.at("schema") == 1 &&
                              number(data.at("title"), UINT32_MAX) == title);
                const auto &sessions = data.at("sessions");
                wire::require(sessions.is_array() && sessions.size() <= maxUserUploads);
                std::set<std::string> tokens;
                std::set<uint64_t> files;
                for (const auto &row : sessions)
                {
                    const auto token = text(row.at("token"), 33);
                    wire::require(hashText(token, 32) && tokens.insert(token).second &&
                                  number(row.at("file"), UINT64_MAX - 1) &&
                                  files.insert(number(row.at("file"))).second &&
                                  number(row.at("owner"), UINT64_MAX - 1));
                    wire::require(!text(row.at("name"), 128).empty());
                    (void)text(row.at("owner_name"), 64);
                    (void)number(row.at("slot"), UINT16_MAX);
                    (void)number(row.at("category"), UINT16_MAX);
                    (void)number(row.at("size"), maximumStreamingBody);
                    const auto created = number(row.at("created"), UINT32_MAX);
                    wire::require(number(row.at("expires"), UINT32_MAX) > created);
                    const auto hash = text(row.at("content"), 65);
                    wire::require(hash.empty() || hashText(hash));
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("User upload store schema invalid");
            }
            auto &sessions = data["sessions"];
            sessions.erase(std::remove_if(sessions.begin(),
                                          sessions.end(),
                                          [](const auto &row)
                                          {
                                              return row.at("expires").template get<uint32_t>() <=
                                                     now();
                                          }),
                           sessions.end());
            return data;
        }

        void saveUserUploads(uint32_t title, const Json &data)
        {
            const auto encoded = data.dump();
            if (encoded.size() > maxStore)
                throw std::runtime_error("User upload store capacity exceeded");
            atomic(userUploadPath(title),
                   std::span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size()));
        }

        std::filesystem::path pooledUploadPath(uint32_t title)
        {
            return dataRoot / "content-streaming" / std::to_string(title) / "pooled-uploads.json";
        }

        Json loadPooledUploads(uint32_t title)
        {
            const auto path = pooledUploadPath(title);
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"title", title}, {"sessions", Json::array()}};
            try
            {
                wire::require(std::filesystem::file_size(path) <= maxStore);
                std::ifstream input(path);
                wire::require(static_cast<bool>(input));
                bool unique = true;
                std::vector<std::set<std::string>> keys;
                auto data = Json::parse(
                    input,
                    [&](int, Json::parse_event_t event, Json &value)
                    {
                        if (event == Json::parse_event_t::object_start)
                            keys.emplace_back();
                        else if (event == Json::parse_event_t::key)
                            unique = keys.back().insert(value.get<std::string>()).second && unique;
                        else if (event == Json::parse_event_t::object_end)
                            keys.pop_back();
                        return true;
                    });
                wire::require(unique && data.is_object() && data.size() == 3 &&
                              data.at("schema") == 1 &&
                              number(data.at("title"), UINT32_MAX) == title);
                auto &sessions = data.at("sessions");
                wire::require(sessions.is_array() && sessions.size() <= 128);
                std::set<std::string> tokens;
                std::set<uint64_t> files;
                for (const auto &row : sessions)
                {
                    wire::require(row.is_object() && row.size() == 11);
                    const auto token = text(row.at("token"), 33);
                    wire::require(hashText(token, 32) && tokens.insert(token).second &&
                                  number(row.at("file"), UINT64_MAX - 1) &&
                                  files.insert(number(row.at("file"))).second &&
                                  number(row.at("owner"), UINT64_MAX - 1) &&
                                  !text(row.at("name"), 128).empty());
                    (void)text(row.at("owner_name"), 64);
                    (void)number(row.at("category"), UINT16_MAX);
                    validateTags(row.at("tags"));
                    wire::require(number(row.at("expires"), UINT32_MAX) >
                                  number(row.at("created"), UINT32_MAX));
                    const auto hash = text(row.at("content"), 65);
                    const auto size = number(row.at("size"), maximumStreamingBody);
                    wire::require(hash.empty() ? size == 0 : hashText(hash));
                }
                sessions.erase(
                    std::remove_if(sessions.begin(),
                                   sessions.end(),
                                   [](const auto &row)
                                   {
                                       return row.at("expires").template get<uint32_t>() <= now();
                                   }),
                    sessions.end());
                return data;
            }
            catch (const std::exception &)
            {
                throw std::runtime_error("Pooled upload store schema invalid");
            }
        }

        void savePooledUploads(uint32_t title, const Json &data)
        {
            const auto encoded = data.dump();
            if (encoded.size() > maxStore)
                throw std::runtime_error("Pooled upload store capacity exceeded");
            atomic(pooledUploadPath(title),
                   std::span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size()));
        }

        uint64_t allocateFile(uint32_t title, const Json &files, const Json &sessions)
        {
            const auto copies = loadCopies(title);
            const auto userUploads = loadUserUploads(title);
            const auto pooledUploads = loadPooledUploads(title);
            const auto catalog = load(title);
            const auto receipts = catalog.value("copy_receipts", Json::object());
            const auto uploadReceipts = catalog.value("upload_receipts", Json::object());
            uint64_t file = 0;
            do
            {
                file = wire::at<uint64_t>(crypto::random(8), 0);
            } while (!file || file == UINT64_MAX ||
                     std::any_of(receipts.begin(),
                                 receipts.end(),
                                 [file](const auto &receipt)
                                 {
                                     return receipt.at("file") == file;
                                 }) ||
                     std::any_of(uploadReceipts.begin(),
                                 uploadReceipts.end(),
                                 [file](const auto &receipt)
                                 {
                                     return receipt.at("row").at("id") == file;
                                 }) ||
                     std::any_of(userUploads["sessions"].begin(),
                                 userUploads["sessions"].end(),
                                 [file](const auto &row)
                                 {
                                     return row.at("file") == file;
                                 }) ||
                     std::any_of(copies["sessions"].begin(),
                                 copies["sessions"].end(),
                                 [file](const auto &row)
                                 {
                                     return row.at("file") == file;
                                 }) ||
                     std::any_of(files.begin(),
                                 files.end(),
                                 [file](const auto &row)
                                 {
                                     return row.at("id") == file;
                                 }) ||
                     std::any_of(sessions.begin(),
                                 sessions.end(),
                                 [file](const auto &row)
                                 {
                                     return row.at("id") == file;
                                 }) ||
                     std::any_of(pooledUploads["sessions"].begin(),
                                 pooledUploads["sessions"].end(),
                                 [file](const auto &row)
                                 {
                                     return row.at("file") == file;
                                 }));
            return file;
        }

        Json tags(wire::Reader &p)
        {
            // Replay writeArrayStart(type=10,width=8), two raw UInt64s per tag.
            wire::require(p.offset + 10 <= p.data.size() && p.data[p.offset++] == 110 &&
                          p.data[p.offset++] == 8);
            const auto size = wire::at<uint32_t>(p.data, p.offset);
            p.offset += 4;
            const auto count = wire::at<uint32_t>(p.data, p.offset);
            p.offset += 4;
            wire::require(count <= 512 && !(count & 1) && size == count * 8 &&
                          size <= p.data.size() - p.offset);
            auto out = Json::array();
            for (uint32_t i = 0; i < count; i += 2)
            {
                const auto first = wire::at<uint64_t>(p.data, p.offset),
                           second = wire::at<uint64_t>(p.data, p.offset + 8);
                p.offset += 16;
                wire::require(first != UINT64_MAX && second != UINT64_MAX);
                out.push_back(Json::array({first, second}));
            }
            return out;
        }

        void writeTags(wire::Writer &out, const Json &tags)
        {
            out.data.push_back(110);
            out.data.push_back(8);
            wire::raw(out.data, static_cast<uint32_t>(tags.size() * 16));
            wire::raw(out.data, static_cast<uint32_t>(tags.size() * 2));
            for (const auto &pair : tags)
                for (const auto &value : pair)
                    wire::raw(out.data, value.get<uint64_t>());
        }

        wire::Bytes multipartURLs(uint32_t title, const Json &session, size_t start, size_t count)
        {
            // Same-Replay 142164040: UInt64 file ID, packed string array, max ten
            // 1025-byte URL slots. Array elements suppress their individual type tag.
            wire::Writer out;
            out.u64(session.at("id").get<uint64_t>());
            wire::Bytes strings;
            for (size_t i = start; i < start + count; ++i)
            {
                const auto value = origin() + "/content-streaming/upload/multipart/" +
                                   std::to_string(title) + "/" +
                                   std::to_string(session.at("id").get<uint64_t>()) + "/" +
                                   std::to_string(i) + "/" +
                                   session.at("parts").at(i).at("token").get<std::string>();
                wire::require(value.size() < 1025);
                strings.insert(strings.end(), value.begin(), value.end());
                strings.push_back(0);
            }
            out.data.push_back(116);
            out.data.push_back(8);
            wire::raw(out.data, static_cast<uint32_t>(strings.size()));
            wire::raw(out.data, static_cast<uint32_t>(count));
            out.data.insert(out.data.end(), strings.begin(), strings.end());
            return std::move(out.data);
        }

        Reply preUploadMultipart(const platform::LobbyIdentity &id, wire::Reader &p)
        {
            // 14213D580 (58/20): name/category/packed tag pairs/signed offset and
            // page capacity/existing file ID. (-1,-1) reserves an ID without URLs.
            const auto name = p.text(129);
            const auto category = p.u16();
            const auto suppliedTags = tags(p);
            const auto offset = p.value<int16_t>(5), maximum = p.value<int16_t>(5);
            const auto file = p.u64();
            p.end();
            const bool reserve = offset == -1 && maximum == -1;
            wire::require(
                !name.empty() && name.size() < 128 && file != UINT64_MAX &&
                (reserve || (offset >= 0 && maximum > 0 && maximum <= 10 &&
                             static_cast<size_t>(offset + maximum) <= maxMultipartParts)));
            wire::require(file || reserve || offset == 0);
            auto pending = loadMultipart(id.titleId);
            expireMultipart(pending);
            auto &sessions = pending["sessions"];
            auto found = std::find_if(sessions.begin(),
                                      sessions.end(),
                                      [file](const auto &row)
                                      {
                                          return row.at("id") == file;
                                      });
            if (file && found == sessions.end())
                return {108, {}, "streaming-multipart-upload-not-found"};
            if (found != sessions.end())
            {
                if (found->at("owner") != id.userId)
                    return {101, {}, "streaming-multipart-owner-denied"};
                wire::require(found->at("name") == name && found->at("category") == category &&
                              found->at("tags") == suppliedTags);
            }
            else
            {
                if (sessions.size() >= maxMultipartSessions)
                    return {102, {}, "streaming-multipart-session-capacity-exceeded"};
                const auto catalog = load(id.titleId);
                if (catalog.at("files").size() >= maxFiles)
                    return {102, {}, "streaming-file-capacity-exceeded"};
                const auto stamp = now();
                sessions.push_back(
                    Json{{"id", allocateFile(id.titleId, catalog.at("files"), sessions)},
                         {"owner", id.userId},
                         {"owner_name", id.name},
                         {"name", name},
                         {"category", category},
                         {"tags", suppliedTags},
                         {"created", stamp},
                         {"expires", stamp + 600},
                         {"parts", Json::array()}});
                found = std::prev(sessions.end());
            }
            const auto start = reserve ? size_t{0} : static_cast<size_t>(offset),
                       count = reserve ? size_t{0} : static_cast<size_t>(maximum);
            auto &parts = (*found)["parts"];
            std::set<std::string> tokens;
            for (const auto &session : sessions)
                for (const auto &part : session.at("parts"))
                    tokens.insert(part.at("token").get<std::string>());
            while (parts.size() < start + count)
            {
                std::string token;
                do
                {
                    token = hex(crypto::random(16));
                } while (!tokens.insert(token).second);
                parts.push_back(Json{{"token", token}, {"content", ""}, {"size", 0u}});
            }
            (*found)["expires"] = now() + 600;
            auto result = multipartURLs(id.titleId, *found, start, count);
            saveMultipart(id.titleId, pending);
            return {0, {std::move(result)}, "streaming-multipart-upload-prepared"};
        }

        Reply postUploadMultipart(const platform::LobbyIdentity &id, wire::Reader &p)
        {
            // 14213D030 (58/21): file ID/UInt16 part count/UInt32 byte total/Int32
            // HTTP error. Same result pointer as 58/6, native bdFileID UInt64 reader.
            const auto file = p.u64();
            const auto count = p.u16();
            const auto size = p.u32();
            const auto error = p.value<int32_t>(7);
            p.end();
            wire::require(file && file != UINT64_MAX && count <= maxMultipartParts &&
                          size <= maximumStreamingBody);
            if (error)
                return {108, {}, "streaming-multipart-client-transfer-failed"};
            auto catalog = load(id.titleId);
            auto &files = catalog["files"];
            const auto committed = std::find_if(files.begin(),
                                                files.end(),
                                                [file](const auto &row)
                                                {
                                                    return row.at("id") == file;
                                                });
            if (committed != files.end())
            {
                if (committed->at("owner") != id.userId)
                    return {101, {}, "streaming-multipart-owner-denied"};
                wire::require(committed->contains("parts") &&
                              committed->at("parts").size() == count &&
                              committed->at("size") == size);
                (void)readBlob(id.titleId, committed->at("content").get<std::string>(), size);
                for (const auto &part : committed->at("parts"))
                    (void)readBlob(id.titleId,
                                   part.at("content").get<std::string>(),
                                   part.at("size").get<uint32_t>());
                auto pending = loadMultipart(id.titleId);
                auto &sessions = pending["sessions"];
                const auto staged = std::find_if(sessions.begin(),
                                                 sessions.end(),
                                                 [file](const auto &row)
                                                 {
                                                     return row.at("id") == file;
                                                 });
                if (staged != sessions.end())
                {
                    if (staged->at("owner") != id.userId)
                        throw std::runtime_error(
                            "Multipart staging owner conflicts with committed file");
                    sessions.erase(staged);
                    saveMultipart(id.titleId, pending);
                }
                wire::Writer out;
                out.u64(file);
                return {0, {std::move(out.data)}, "streaming-multipart-commit-retried"};
            }
            auto pending = loadMultipart(id.titleId);
            expireMultipart(pending);
            auto &sessions = pending["sessions"];
            const auto found = std::find_if(sessions.begin(),
                                            sessions.end(),
                                            [file](const auto &row)
                                            {
                                                return row.at("id") == file;
                                            });
            if (found == sessions.end())
                return {108, {}, "streaming-multipart-upload-not-found"};
            if (found->at("owner") != id.userId)
                return {101, {}, "streaming-multipart-owner-denied"};
            const auto &parts = found->at("parts");
            wire::require(count <= parts.size());
            auto manifest = Json::array();
            uint64_t total = 0;
            for (size_t i = 0; i < parts.size(); ++i)
            {
                const auto &part = parts.at(i);
                const auto hash = part.at("content").get<std::string>();
                wire::require(i < count ? !hash.empty() : hash.empty());
                if (i < count)
                {
                    total += part.at("size").get<uint32_t>();
                    wire::require(total <= maximumStreamingBody);
                    manifest.push_back(Json{{"content", hash}, {"size", part.at("size")}});
                }
            }
            wire::require(total == size);
            if (files.size() >= maxFiles)
                return {102, {}, "streaming-file-capacity-exceeded"};
            wire::Bytes combined;
            combined.reserve(size);
            for (const auto &part : manifest)
            {
                const auto bytes = readBlob(id.titleId,
                                            part.at("content").get<std::string>(),
                                            part.at("size").get<uint32_t>());
                combined.insert(combined.end(), bytes.begin(), bytes.end());
            }
            const auto hash = hex(crypto::sha256(combined));
            atomic(blobPath(id.titleId, hash), combined);
            files.push_back(Json{{"id", file},
                                 {"kind", "pooled"},
                                 {"owner", id.userId},
                                 {"owner_name", found->at("owner_name")},
                                 {"name", found->at("name")},
                                 {"category", found->at("category")},
                                 {"slot", 0u},
                                 {"created", found->at("created")},
                                 {"modified", now()},
                                 {"size", size},
                                 {"content", hash},
                                 {"summary", ""},
                                 {"summary_size", 0u},
                                 {"metadata", ""},
                                 {"tags", found->at("tags")},
                                 {"copies", 0u},
                                 {"origin", 0u},
                                 {"parts", manifest}});
            // Immutable parts and assembled bytes precede the atomic catalog commit.
            // Removing staging follows it; a crash between these writes retries the
            // already committed file ID instead of adding a second catalog entry.
            save(id.titleId, catalog);
            sessions.erase(found);
            saveMultipart(id.titleId, pending);
            wire::Writer out;
            out.u64(file);
            return {0, {std::move(out.data)}, "streaming-multipart-upload-committed"};
        }

        unsigned putMultipart(const std::string &request, std::span<const uint8_t> bytes)
        {
            constexpr std::string_view prefix = "/content-streaming/upload/multipart/";
            const auto suffix = request.substr(prefix.size());
            std::vector<std::string> fields;
            size_t start = 0;
            for (size_t i = 0; i <= suffix.size(); ++i)
                if (i == suffix.size() || suffix[i] == '/')
                {
                    fields.push_back(suffix.substr(start, i - start));
                    start = i + 1;
                }
            if (fields.size() != 4 || !hashText(fields[3], 32))
                return 404;
            uint64_t numbers[3]{};
            for (size_t i = 0; i < 3; ++i)
            {
                const auto &field = fields[i];
                if (field.empty() || (field.size() > 1 && field[0] == '0'))
                    return 404;
                const auto parsed =
                    std::from_chars(field.data(), field.data() + field.size(), numbers[i]);
                if (parsed.ec != std::errc{} || parsed.ptr != field.data() + field.size())
                    return 404;
            }
            if (numbers[0] > UINT32_MAX || !numbers[1] || numbers[1] == UINT64_MAX ||
                numbers[2] >= maxMultipartParts)
                return 404;
            if (bytes.size() > maximumStreamingBody)
                return 400;
            const auto title = static_cast<uint32_t>(numbers[0]);
            auto pending = loadMultipart(title);
            expireMultipart(pending);
            auto &sessions = pending["sessions"];
            const auto found = std::find_if(sessions.begin(),
                                            sessions.end(),
                                            [&](const auto &row)
                                            {
                                                return row.at("id") == numbers[1];
                                            });
            if (found == sessions.end() || numbers[2] >= found->at("parts").size())
                return 404;
            auto &part = (*found)["parts"].at(static_cast<size_t>(numbers[2]));
            if (part.at("token") != fields[3])
                return 404;
            if (!part.at("content").get<std::string>().empty())
            {
                const auto previous = readBlob(
                    title, part.at("content").get<std::string>(), part.at("size").get<uint32_t>());
                return crypto::equal(previous, bytes) ? 200 : 409;
            }
            uint64_t total = 0, held = 0;
            for (const auto &entry : found->at("parts"))
                total += entry.at("size").get<uint32_t>();
            if (total + bytes.size() > maximumStreamingBody)
                return 400;
            for (const auto &session : sessions)
                for (const auto &entry : session.at("parts"))
                    held += entry.at("size").get<uint32_t>();
            const auto pooledUploads = loadPooledUploads(title);
            for (const auto &entry : pooledUploads.at("sessions"))
                held += entry.at("size").template get<uint32_t>();
            if (held + bytes.size() > 64 * 1024 * 1024)
                return 503;
            const auto hash = hex(crypto::sha256(bytes));
            if (std::filesystem::exists(blobPath(title, hash)))
                (void)readBlob(title, hash, bytes.size());
            else
                atomic(blobPath(title, hash), bytes);
            part["content"] = hash;
            part["size"] = static_cast<uint32_t>(bytes.size());
            (*found)["expires"] = now() + 600;
            saveMultipart(title, pending);
            return 200;
        }

        std::string url(uint32_t title, const std::string &hash)
        {
            return origin() + "/content-streaming/download/" + std::to_string(title) + "/" + hash;
        }

        wire::Bytes metadata(uint32_t title, const Json &row)
        {
            // Complete same-Replay bdFileMetaData reader 0x14213DBE0, including
            // packed tag pairs, summary size, copies and origin. No fields omitted.
            wire::Writer out;
            out.u64(row.at("id").get<uint64_t>());
            out.u32(row.at("created").get<uint32_t>());
            out.u32(row.at("modified").get<uint32_t>());
            out.u32(row.at("size").get<uint32_t>());
            out.u64(row.at("owner").get<uint64_t>());
            out.text(row.at("owner_name").get<std::string>());
            out.u16(row.at("slot").get<uint16_t>());
            out.text(row.at("name").get<std::string>());
            out.text(url(title, row.at("content").get<std::string>()));
            out.u16(row.at("category").get<uint16_t>());
            out.blob(wire::base64(row.at("metadata").get<std::string>(), 2048));
            out.u32(row.at("summary_size").get<uint32_t>());
            writeTags(out, row.at("tags"));
            out.u32(row.at("copies").get<uint32_t>());
            out.u64(row.at("origin").get<uint64_t>());
            return std::move(out.data);
        }

        std::string copyURL(uint32_t title, const std::string &token, size_t part, bool source)
        {
            return origin() + "/content-streaming/copy/" + std::to_string(title) + "/" + token +
                   (source ? "/source/" : "/destination/") + std::to_string(part);
        }

        Reply preCopy(const platform::LobbyIdentity &id, bool pooled, wire::Reader &params)
        {
            // The preparation IDs 50/15 (pooled) and 50/20 (user) are supported
            // source-oracle contracts; their writers are not exported in Replay.
            // Replay's actual result reader 142163DD0 consumes bdURL, destination
            // string and UInt32 size. Do not label these IDs as target CFG proofs.
            const auto source = params.u64();
            const auto slot = params.u16();
            params.end();
            wire::require(source && source != UINT64_MAX);
            const auto catalog = load(id.titleId);
            const auto &files = catalog["files"];
            const auto found = std::find_if(files.begin(),
                                            files.end(),
                                            [source](const auto &row)
                                            {
                                                return row["id"] == source;
                                            });
            if (found == files.end() || (*found)["kind"] != (pooled ? "pooled" : "user"))
                return {108, {}, "streaming-copy-source-not-found"};
            auto pending = loadCopies(id.titleId);
            if (pending["sessions"].size() >= maxCopySessions)
                return {108, {}, "streaming-copy-capacity"};
            auto multipart = loadMultipart(id.titleId);
            expireMultipart(multipart);
            const auto file = allocateFile(id.titleId, files, multipart["sessions"]);
            auto token = hex(crypto::random(16));
            const auto receipts = catalog.value("copy_receipts", Json::object());
            if (receipts.size() >= maxCopyReceipts)
                return {108, {}, "streaming-copy-receipt-capacity"};
            while (receipts.contains(token) || std::any_of(pending["sessions"].begin(),
                                                           pending["sessions"].end(),
                                                           [&](const auto &session)
                                                           {
                                                               return session["token"] == token;
                                                           }))
                token = hex(crypto::random(16));
            const auto parts = (*found)["summary"] == "" ? 1u : 2u;
            Json session = {{"token", token},
                            {"owner", id.userId},
                            {"owner_name", id.name},
                            {"file", file},
                            {"slot", slot},
                            {"pooled", pooled},
                            {"expires", now() + copyLifetimeSeconds},
                            {"source", *found},
                            {"copied", Json::array()}};
            Reply result{0, {}, "streaming-copy-prepared"};
            for (unsigned part = 0; part < parts; ++part)
            {
                const auto hash = (*found)[part ? "summary" : "content"].get<std::string>();
                const auto size = (*found)[part ? "summary_size" : "size"].get<uint32_t>();
                (void)readBlob(id.titleId, hash, size);
                session["copied"].push_back(false);
                wire::Writer writer;
                writer.text(copyURL(id.titleId, token, part, true));
                writer.u16(0);
                writer.text(token);
                writer.u64(file);
                writer.text(copyURL(id.titleId, token, part, false));
                writer.u32(size);
                result.results.push_back(std::move(writer.data));
            }
            pending["sessions"].push_back(std::move(session));
            saveCopies(id.titleId, pending);
            return result;
        }

        Reply postCopy(const platform::LobbyIdentity &id, wire::Reader &params)
        {
            // Full original Replay writer 142133750. In particular, summary size
            // precedes the metadata blob, and the pooled flag is a typed Boolean.
            const auto name = params.text(129);
            const auto slot = params.u16(), location = params.u16();
            const auto token = params.text(128);
            const auto size = params.u32();
            const auto category = params.u16();
            const auto summarySize = params.u32();
            const auto metadataBytes = params.blob(2048);
            const auto suppliedTags = tags(params);
            const auto pooled = params.boolean();
            const auto source = params.u64();
            params.end();
            wire::require(!name.empty() && name.size() < 128 && !location && hashText(token, 32) &&
                          size <= maximumStreamingBody && summarySize <= maximumStreamingBody &&
                          source && source != UINT64_MAX);
            const Json request = {{"owner", id.userId},
                                  {"name", name},
                                  {"slot", slot},
                                  {"size", size},
                                  {"category", category},
                                  {"summary_size", summarySize},
                                  {"metadata", wire::base64Encode(metadataBytes)},
                                  {"tags", suppliedTags},
                                  {"pooled", pooled},
                                  {"source", source}};
            const auto encoded = request.dump();
            const auto requestHash = hex(crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(encoded.data()), encoded.size())));
            auto catalog = load(id.titleId);
            auto &files = catalog["files"];
            auto &receipts = catalog["copy_receipts"];
            if (receipts.is_null())
                receipts = Json::object();
            if (receipts.contains(token))
            {
                const auto &receipt = receipts[token];
                if (receipt["owner"] != id.userId)
                    return {101, {}, "streaming-copy-owner-denied"};
                if (receipt["request_sha256"] != requestHash)
                    return {106, {}, "streaming-copy-retry-conflict"};
                // A later slot replacement must not allow this retry to roll
                // back the new file or increment the old source counter again.
                wire::Writer result;
                result.u64(receipt["file"].get<uint64_t>());
                return {0, {std::move(result.data)}, "streaming-copy-already-committed"};
            }
            if (receipts.size() >= maxCopyReceipts)
                return {108, {}, "streaming-copy-receipt-capacity"};
            const auto pending = loadCopies(id.titleId);
            const auto &sessions = pending["sessions"];
            const auto found = std::find_if(sessions.begin(),
                                            sessions.end(),
                                            [&](const auto &session)
                                            {
                                                return session["token"] == token;
                                            });
            if (found == sessions.end())
                return {108, {}, "streaming-copy-session-unavailable"};
            if ((*found)["owner"] != id.userId)
                return {101, {}, "streaming-copy-owner-denied"};
            const auto &snapshot = (*found)["source"];
            if ((*found)["slot"] != slot || (*found)["pooled"] != pooled ||
                snapshot["id"] != source || snapshot["size"] != size ||
                snapshot["summary_size"] != summarySize)
                return {106, {}, "streaming-copy-description-mismatch"};
            if (std::any_of((*found)["copied"].begin(),
                            (*found)["copied"].end(),
                            [](const auto &part)
                            {
                                return part == false;
                            }))
                return {108, {}, "streaming-copy-http-incomplete"};
            (void)readBlob(id.titleId, snapshot["content"].get<std::string>(), size);
            if (snapshot["summary"] != "")
                (void)readBlob(id.titleId, snapshot["summary"].get<std::string>(), summarySize);
            const auto file = (*found)["file"].get<uint64_t>();
            if (std::any_of(files.begin(),
                            files.end(),
                            [file](const auto &row)
                            {
                                return row["id"] == file;
                            }))
                throw std::runtime_error("Streaming copy reserved ID collision");
            for (auto &row : files)
                if (row["id"] == source)
                {
                    const auto copies = row["copies"].get<uint32_t>();
                    if (copies == UINT32_MAX)
                        throw std::runtime_error("Streaming copy counter exhausted");
                    row["copies"] = copies + 1;
                }
            Json destination = snapshot;
            destination.erase("parts");
            // Transfer receipts identify the operation that created this file.
            // A copy must not inherit its source's upload-commit identity.
            destination.erase("upload_receipt");
            destination["id"] = file;
            destination["kind"] = "user";
            destination["owner"] = id.userId;
            destination["owner_name"] = (*found)["owner_name"];
            destination["name"] = name;
            destination["slot"] = slot;
            destination["category"] = category;
            destination["metadata"] = request["metadata"];
            destination["tags"] = suppliedTags;
            destination["created"] = now();
            destination["modified"] = now();
            destination["copies"] = 0u;
            destination["origin"] = source;
            destination["copy_receipt"] = {{"token", token}, {"request_sha256", requestHash}};
            validateFile(destination);
            files.erase(std::remove_if(files.begin(),
                                       files.end(),
                                       [&](const auto &row)
                                       {
                                           return row["kind"] == "user" &&
                                                  row["owner"] == id.userId && row["slot"] == slot;
                                       }),
                        files.end());
            if (files.size() >= maxFiles)
                return {102, {}, "streaming-file-capacity-exceeded"};
            files.push_back(std::move(destination));
            receipts[token] = {
                {"owner", id.userId}, {"file", file}, {"request_sha256", requestHash}};
            // Source counter, slot replacement, clone and retry receipt have
            // one commit point. Pending HTTP sessions are only durable staging.
            save(id.titleId, catalog);
            wire::Writer result;
            result.u64(file);
            return {0, {std::move(result.data)}, "streaming-copy-committed"};
        }

        Reply preUserUpload(const platform::LobbyIdentity &id, wire::Reader &params)
        {
            // OpenIW8's _preUpload supplies the 50/5 contract. Its constructor is
            // not exported in the Replay database; do not claim a target binding.
            const auto name = params.text(129);
            const auto slot = params.u16();
            const auto size = params.u32();
            const auto category = params.u16();
            const auto checksum = params.blob(32);
            wire::require(params.text(1).empty());
            params.end();
            wire::require(!name.empty() && name.size() < 128 && size <= maximumStreamingBody &&
                          (checksum.empty() || checksum.size() == 32));
            // The SDK sends an optional opaque X-Checksum. Its algorithm is not
            // established for Replay. Reject this variant rather than ignore it.
            if (!checksum.empty())
                return {108, {}, "streaming-user-upload-checksum-unclassified"};
            auto pending = loadUserUploads(id.titleId);
            auto catalog = load(id.titleId);
            const auto receipts = catalog.value("upload_receipts", Json::object());
            if (pending["sessions"].size() >= maxUserUploads ||
                receipts.size() >= maxUserUploadReceipts)
                return {102, {}, "streaming-user-upload-capacity-exceeded"};
            const auto &files = catalog.at("files");
            const bool replacing = std::any_of(files.begin(),
                                               files.end(),
                                               [&](const auto &row)
                                               {
                                                   return row.at("kind") == "user" &&
                                                          row.at("owner") == id.userId &&
                                                          row.at("slot") == slot;
                                               });
            if (files.size() >= maxFiles && !replacing)
                return {102, {}, "streaming-file-capacity-exceeded"};
            auto multipart = loadMultipart(id.titleId);
            expireMultipart(multipart);
            const auto file = allocateFile(id.titleId, files, multipart.at("sessions"));
            std::string token;
            do
            {
                token = hex(crypto::random(16));
            } while (receipts.contains(token) || std::any_of(pending["sessions"].begin(),
                                                             pending["sessions"].end(),
                                                             [&](const auto &row)
                                                             {
                                                                 return row.at("token") == token;
                                                             }));
            const auto created = now();
            pending["sessions"].push_back(Json{{"token", token},
                                               {"file", file},
                                               {"owner", id.userId},
                                               {"owner_name", id.name},
                                               {"name", name},
                                               {"slot", slot},
                                               {"category", category},
                                               {"size", size},
                                               {"created", created},
                                               {"expires", created + 600},
                                               {"content", ""}});
            saveUserUploads(id.titleId, pending);
            // Complete Replay bdURL reader 142163B40, maximum ten URL results.
            wire::Writer out;
            out.text(origin() + "/content-streaming/upload/user/" + std::to_string(id.titleId) +
                     "/" + token);
            out.u16(0);
            out.text(token);
            out.u64(file);
            return {0, {std::move(out.data)}, "streaming-user-upload-prepared"};
        }

        unsigned putUserUpload(const std::string &request, std::span<const uint8_t> bytes)
        {
            constexpr std::string_view prefix = "/content-streaming/upload/user/";
            const auto suffix = request.substr(prefix.size());
            const auto split = suffix.find('/');
            if (split == std::string::npos || split == 0)
                return 404;
            uint32_t title = 0;
            const auto parsed = std::from_chars(suffix.data(), suffix.data() + split, title);
            const auto token = suffix.substr(split + 1);
            if (parsed.ec != std::errc{} || parsed.ptr != suffix.data() + split || !title ||
                suffix.substr(0, split) != std::to_string(title) || !hashText(token, 32))
                return 404;
            auto pending = loadUserUploads(title);
            auto &sessions = pending["sessions"];
            auto found = std::find_if(sessions.begin(),
                                      sessions.end(),
                                      [&](const auto &row)
                                      {
                                          return row.at("token") == token;
                                      });
            if (found == sessions.end())
                return 404;
            if (bytes.size() != found->at("size") || bytes.size() > maximumStreamingBody)
                return 400;
            const auto hash = hex(crypto::sha256(bytes));
            if (found->at("content") != "")
            {
                (void)readBlob(title, found->at("content").get<std::string>(), bytes.size());
                return found->at("content") == hash ? 200 : 409;
            }
            if (std::filesystem::exists(blobPath(title, hash)))
                (void)readBlob(title, hash, bytes.size());
            else
                atomic(blobPath(title, hash), bytes);
            (*found)["content"] = hash;
            saveUserUploads(title, pending);
            return 200;
        }

        Reply postUserUpload(const platform::LobbyIdentity &id, wire::Reader &params)
        {
            // Complete same-Replay _postUploadFile writer 1421339F0. Its result is
            // bdFileMetaData when +42080 is set, otherwise bdFileID at +42072.
            const auto requestBytes = params.data.subspan(params.offset);
            const auto name = params.text(129);
            const auto slot = params.u16(), location = params.u16();
            const auto token = params.text(129);
            const auto size = params.u32();
            const auto category = params.u16();
            const auto extra = params.blob(2048);
            const auto pairTags = tags(params);
            wire::require(params.text(1).empty());
            params.end();
            wire::require(!name.empty() && name.size() < 128 && !location && hashText(token, 32) &&
                          size <= maximumStreamingBody);
            const auto fingerprint = hex(crypto::sha256(requestBytes));
            auto catalog = load(id.titleId);
            auto receipts = catalog.value("upload_receipts", Json::object());
            if (receipts.contains(token))
            {
                const auto &receipt = receipts.at(token);
                const auto &row = receipt.at("row");
                if (row.at("owner") != id.userId)
                    return {101, {}, "streaming-user-upload-owner-denied"};
                wire::require(receipt.at("request_sha256") == fingerprint);
                (void)readBlob(id.titleId, row.at("content").get<std::string>(), size);
                return {0, {metadata(id.titleId, row)}, "streaming-user-upload-commit-retried"};
            }
            const auto pending = loadUserUploads(id.titleId);
            const auto &sessions = pending.at("sessions");
            const auto found = std::find_if(sessions.begin(),
                                            sessions.end(),
                                            [&](const auto &row)
                                            {
                                                return row.at("token") == token;
                                            });
            if (found == sessions.end())
                return {108, {}, "streaming-user-upload-not-found"};
            if (found->at("owner") != id.userId)
                return {101, {}, "streaming-user-upload-owner-denied"};
            wire::require(found->at("name") == name && found->at("slot") == slot &&
                          found->at("size") == size && found->at("category") == category &&
                          found->at("content") != "");
            (void)readBlob(id.titleId, found->at("content").get<std::string>(), size);
            if (receipts.size() >= maxUserUploadReceipts)
                return {102, {}, "streaming-user-upload-receipt-capacity-exceeded"};
            Json row{{"id", found->at("file")},
                     {"kind", "user"},
                     {"owner", id.userId},
                     {"owner_name", found->at("owner_name")},
                     {"name", name},
                     {"category", category},
                     {"slot", slot},
                     {"created", found->at("created")},
                     {"modified", now()},
                     {"size", size},
                     {"content", found->at("content")},
                     {"summary", ""},
                     {"summary_size", 0u},
                     {"metadata", wire::base64Encode(extra)},
                     {"tags", pairTags},
                     {"copies", 0u},
                     {"origin", 0u},
                     {"upload_receipt", token}};
            auto &files = catalog["files"];
            files.erase(std::remove_if(files.begin(),
                                       files.end(),
                                       [&](const auto &current)
                                       {
                                           return current.at("kind") == "user" &&
                                                  current.at("owner") == id.userId &&
                                                  current.at("slot") == slot;
                                       }),
                        files.end());
            if (files.size() >= maxFiles)
                return {102, {}, "streaming-file-capacity-exceeded"};
            files.push_back(row);
            receipts[token] = Json{{"request_sha256", fingerprint}, {"row", row}};
            catalog["upload_receipts"] = std::move(receipts);
            // Snapshot and slot replacement share one atomic catalog publication.
            // A retry after another upload/copy replaced this slot returns the old
            // snapshot, without republishing it. Both native result variants work:
            // bdFileID reads the first UInt64; 1420FE060 permits unread trailing data.
            auto result = metadata(id.titleId, row);
            save(id.titleId, catalog);
            return {0, {std::move(result)}, "streaming-user-upload-committed"};
        }

        Reply preUpload(const platform::LobbyIdentity &id, wire::Reader &p)
        {
            const auto name = p.text(129);
            wire::require(!name.empty() && name.size() < 128);
            const auto category = p.u16();
            const auto suppliedTags = tags(p);
            wire::require(p.text(1).empty());
            p.end();
            auto pending = loadPooledUploads(id.titleId);
            auto &sessions = pending["sessions"];
            if (sessions.size() >= 128)
                return {102, {}, "streaming-upload-capacity-exceeded"};
            const auto catalog = load(id.titleId);
            if (catalog.at("files").size() >= maxFiles)
                return {102, {}, "streaming-file-capacity-exceeded"};
            const auto multipart = loadMultipart(id.titleId);
            const auto file =
                allocateFile(id.titleId, catalog.at("files"), multipart.at("sessions"));
            std::string token;
            do
                token = hex(crypto::random(16));
            while (std::any_of(sessions.begin(),
                               sessions.end(),
                               [&token](const auto &row)
                               {
                                   return row.at("token") == token;
                               }));
            const auto created = now();
            sessions.push_back(Json{{"file", file},
                                    {"owner", id.userId},
                                    {"owner_name", id.name},
                                    {"name", name},
                                    {"category", category},
                                    {"tags", suppliedTags},
                                    {"token", token},
                                    {"created", created},
                                    {"expires", created + 600},
                                    {"content", ""},
                                    {"size", 0u}});
            savePooledUploads(id.titleId, pending);
            // Native bdURL format is unchanged. Its opaque URL now includes the
            // realm so a fresh process can resolve the durable session directly.
            wire::Writer out;
            out.text(origin() + "/content-streaming/upload/pooled/" + std::to_string(id.titleId) +
                     "/" + token);
            out.u16(0);
            out.text(std::to_string(file));
            out.u64(file);
            return {0, {std::move(out.data)}, "streaming-upload-prepared"};
        }

        Reply postUpload(const platform::LobbyIdentity &id, wire::Reader &p)
        {
            const auto file = p.u64();
            const auto location = p.u16();
            const auto serverName = p.text(129);
            const auto size = p.u32();
            p.end();
            wire::require(file && file != UINT64_MAX && !location && size <= maximumStreamingBody &&
                          serverName == std::to_string(file));
            auto pending = loadPooledUploads(id.titleId);
            auto &sessions = pending["sessions"];
            const auto found = std::find_if(sessions.begin(),
                                            sessions.end(),
                                            [file](const auto &row)
                                            {
                                                return row.at("file") == file;
                                            });
            auto catalog = load(id.titleId);
            const auto committed = std::find_if(catalog["files"].begin(),
                                                catalog["files"].end(),
                                                [file](const auto &row)
                                                {
                                                    return row.at("id") == file &&
                                                           row.at("kind") == "pooled" &&
                                                           !row.contains("parts");
                                                });
            if (committed != catalog["files"].end())
            {
                if (committed->at("owner") != id.userId)
                    return {101, {}, "streaming-upload-owner-denied"};
                wire::require(committed->at("size") == size);
                (void)readBlob(
                    id.titleId, committed->at("content").template get<std::string>(), size);
                if (found != sessions.end())
                {
                    for (const auto *key : {"owner", "name", "category", "tags", "content", "size"})
                        if (found->at(key) != committed->at(key))
                            throw std::runtime_error("Pooled upload recovery snapshot mismatch");
                    sessions.erase(found);
                    savePooledUploads(id.titleId, pending);
                }
                wire::Writer out;
                out.u64(file);
                return {0, {std::move(out.data)}, "streaming-upload-commit-retried"};
            }
            if (found == sessions.end())
                return {108, {}, "streaming-upload-not-found"};
            if (found->at("owner") != id.userId)
                return {101, {}, "streaming-upload-owner-denied"};
            if (found->at("content").get<std::string>().empty())
                return {108, {}, "streaming-upload-http-incomplete"};
            wire::require(found->at("size") == size);
            const auto hash = found->at("content").get<std::string>();
            (void)readBlob(id.titleId, hash, size);
            if (catalog.at("files").size() >= maxFiles)
                return {102, {}, "streaming-file-capacity-exceeded"};
            catalog["files"].push_back(Json{{"id", file},
                                            {"kind", "pooled"},
                                            {"owner", id.userId},
                                            {"owner_name", found->at("owner_name")},
                                            {"name", found->at("name")},
                                            {"category", found->at("category")},
                                            {"slot", 0u},
                                            {"created", now()},
                                            {"modified", now()},
                                            {"size", size},
                                            {"content", hash},
                                            {"summary", ""},
                                            {"summary_size", 0u},
                                            {"metadata", ""},
                                            {"tags", found->at("tags")},
                                            {"copies", 0u},
                                            {"origin", 0u}});
            // Publish the complete catalog before removing staging. A restart or
            // failed cleanup retries the same row rather than creating another ID.
            save(id.titleId, catalog);
            sessions.erase(found);
            savePooledUploads(id.titleId, pending);
            wire::Writer out;
            out.u64(file);
            return {0, {std::move(out.data)}, "streaming-upload-committed"};
        }

        unsigned putPooledUpload(const std::string &request, std::span<const uint8_t> bytes)
        {
            constexpr std::string_view prefix = "/content-streaming/upload/pooled/";
            const auto suffix = request.substr(prefix.size());
            const auto slash = suffix.find('/');
            if (slash == std::string::npos || !hashText(suffix.substr(slash + 1), 32))
                return 404;
            const auto realm = suffix.substr(0, slash);
            uint32_t title = 0;
            const auto parsed = std::from_chars(realm.data(), realm.data() + realm.size(), title);
            if (realm.empty() || (realm.size() > 1 && realm[0] == '0') ||
                parsed.ec != std::errc{} || parsed.ptr != realm.data() + realm.size())
                return 404;
            if (bytes.size() > maximumStreamingBody)
                return 400;
            auto pending = loadPooledUploads(title);
            auto &sessions = pending["sessions"];
            const auto token = suffix.substr(slash + 1);
            const auto found = std::find_if(sessions.begin(),
                                            sessions.end(),
                                            [&token](const auto &row)
                                            {
                                                return row.at("token") == token;
                                            });
            if (found == sessions.end())
                return 404;
            const auto hash = found->at("content").get<std::string>();
            if (!hash.empty())
                return crypto::equal(readBlob(title, hash, found->at("size").get<uint32_t>()),
                                     bytes)
                           ? 200
                           : 409;
            uint64_t held = 0;
            for (const auto &row : sessions)
                held += row.at("size").get<uint32_t>();
            auto multipart = loadMultipart(title);
            expireMultipart(multipart);
            for (const auto &session : multipart.at("sessions"))
                for (const auto &part : session.at("parts"))
                    held += part.at("size").template get<uint32_t>();
            if (held + bytes.size() > 64 * 1024 * 1024)
                return 503;
            const auto checksum = hex(crypto::sha256(bytes));
            if (std::filesystem::exists(blobPath(title, checksum)))
                (void)readBlob(title, checksum, bytes.size());
            else
                atomic(blobPath(title, checksum), bytes);
            (*found)["content"] = checksum;
            (*found)["size"] = static_cast<uint32_t>(bytes.size());
            (*found)["expires"] = now() + 600;
            savePooledUploads(title, pending);
            return 200;
        }
    } // namespace

    void initializeContentStreaming(const std::filesystem::path &directory, unsigned short port)
    {
        std::lock_guard lock(contentMutex);
        dataRoot = std::filesystem::absolute(directory);
        contentPort = port;
    }

    std::optional<Reply> contentServices(const std::filesystem::path &,
                                         const platform::LobbyIdentity &id,
                                         uint8_t service,
                                         uint8_t task,
                                         wire::Reader &p)
    {
        if (service != 50 && service != 58)
            return std::nullopt;
        std::lock_guard lock(contentMutex);
        if (service == 50 && task == 5)
            return preUserUpload(id, p);
        if (service == 50 && task == 6)
            return postUserUpload(id, p);
        if (service == 58 && task == 5)
            return preUpload(id, p);
        if (service == 58 && task == 6)
            return postUpload(id, p);
        if (service == 58 && task == 20)
            return preUploadMultipart(id, p);
        if (service == 58 && task == 21)
            return postUploadMultipart(id, p);
        if (service == 50 && (task == 15 || task == 20))
            return preCopy(id, task == 15, p);
        if (service == 50 && task == 16)
            return postCopy(id, p);
        if (service == 50 && (task == 2 || task == 3))
        {
            const auto owner = task == 2 ? p.u64() : 0;
            const auto since = p.u32();
            const auto maximum = p.u16(), start = p.u16(), category = p.u16();
            const auto name = p.more() ? p.text(129) : "";
            p.end();
            wire::require(maximum <= 1024 && name.size() < 128);
            const auto data = load(id.titleId);
            std::vector<Json> selected;
            for (const auto &row : data.at("files"))
                if ((task == 3 ? row.at("kind") == "publisher"
                               : row.at("kind") != "publisher" && row.at("owner") == owner) &&
                    row.at("modified").get<uint32_t>() >= since && row.at("category") == category &&
                    (name.empty() || row.at("name") == name))
                    selected.push_back(row);
            std::sort(selected.begin(),
                      selected.end(),
                      [](const auto &a, const auto &b)
                      {
                          return a.at("id") < b.at("id");
                      });
            Reply reply{
                0, {}, task == 2 ? "streaming-owner-files-read" : "streaming-publisher-files-read"};
            const auto end = std::min(selected.size(), static_cast<size_t>(start) + maximum);
            for (size_t i = start; i < end; ++i)
                reply.results.push_back(metadata(id.titleId, selected[i]));
            return reply;
        }
        if ((service == 50 && (task == 9 || task == 10 || task == 19)) || task == 18)
        {
            const auto file = p.u64();
            if (task != 19)
                (void)p.u32();
            p.end();
            wire::require(file && file != UINT64_MAX);
            const auto data = load(id.titleId);
            const auto &rows = data.at("files");
            const auto found = std::find_if(rows.begin(),
                                            rows.end(),
                                            [&](const auto &row)
                                            {
                                                return row.at("id") == file;
                                            });
            if (found == rows.end() || (task == 10 && found->at("kind") != "publisher") ||
                (task == 9 && found->at("kind") == "publisher"))
                return Reply{108, {}, "streaming-file-not-found"};
            if (task == 18 || task == 19)
            {
                const auto summary = found->at("summary").get<std::string>();
                if (summary.empty())
                    return Reply{108, {}, "streaming-summary-not-found"};
                // Replay 142163950 bdSummaryMetaHandler reader: URL/UInt32 size.
                wire::Writer out;
                out.text(url(id.titleId, summary));
                out.u32(found->at("summary_size").get<uint32_t>());
                return Reply{0, {std::move(out.data)}, "streaming-summary-read"};
            }
            return Reply{0, {metadata(id.titleId, *found)}, "streaming-download-prepared"};
        }
        return std::nullopt;
    }

    unsigned streamingCopy(const std::string &source, const std::string &destination)
    {
        std::lock_guard lock(contentMutex);
        constexpr std::string_view prefix = "/content-streaming/copy/";
        if (!source.starts_with(prefix))
            return 400;
        const auto rest = source.substr(prefix.size());
        const auto slash = rest.find('/');
        if (slash == std::string::npos || !slash || slash > 10 || (slash > 1 && rest[0] == '0'))
            return 400;
        uint32_t title = 0;
        const auto parsed = std::from_chars(rest.data(), rest.data() + slash, title);
        if (parsed.ec != std::errc{} || parsed.ptr != rest.data() + slash)
            return 400;
        const auto suffix = rest.substr(slash + 1);
        if (suffix.size() != 41 || !hashText(suffix.substr(0, 32), 32) ||
            suffix.substr(32, 8) != "/source/" || (suffix[40] != '0' && suffix[40] != '1'))
            return 400;
        const auto token = suffix.substr(0, 32);
        const size_t part = static_cast<size_t>(suffix[40] - '0');
        if (destination != copyURL(title, token, part, false))
            return 400;
        auto pending = loadCopies(title);
        auto &sessions = pending["sessions"];
        const auto found = std::find_if(sessions.begin(),
                                        sessions.end(),
                                        [&](const auto &session)
                                        {
                                            return session["token"] == token;
                                        });
        if (found == sessions.end())
            return 404;
        if (part >= (*found)["copied"].size())
            return 400;
        const auto &snapshot = (*found)["source"];
        (void)readBlob(title,
                       snapshot[part ? "summary" : "content"].get<std::string>(),
                       snapshot[part ? "summary_size" : "size"].get<uint32_t>());
        if ((*found)["copied"][part] == true)
            return 200;
        // The immutable verified blob is shared physically, while the final
        // destination is a distinct owned file. No untrusted URL is fetched.
        (*found)["copied"][part] = true;
        saveCopies(title, pending);
        return 201;
    }

    std::optional<wire::Bytes> streamingContent(const std::string &request)
    {
        std::lock_guard lock(contentMutex);
        constexpr std::string_view prefix = "/content-streaming/download/";
        if (!request.starts_with(prefix))
            return std::nullopt;
        const auto rest = request.substr(prefix.size());
        const auto slash = rest.find('/');
        if (slash == std::string::npos)
            return std::nullopt;
        const auto titleText = rest.substr(0, slash), hash = rest.substr(slash + 1);
        if (!hashText(hash) || titleText.empty() || titleText.size() > 10 ||
            (titleText.size() > 1 && titleText[0] == '0'))
            return std::nullopt;
        uint64_t title = 0;
        for (char c : titleText)
        {
            if (c < '0' || c > '9')
                return std::nullopt;
            title = title * 10 + static_cast<unsigned>(c - '0');
        }
        if (title > UINT32_MAX)
            return std::nullopt;
        const auto data = load(static_cast<uint32_t>(title));
        const auto &rows = data.at("files");
        if (std::none_of(rows.begin(),
                         rows.end(),
                         [&](const auto &row)
                         {
                             return row.at("content") == hash || row.at("summary") == hash;
                         }))
            return std::nullopt;
        const auto path = blobPath(static_cast<uint32_t>(title), hash);
        if (!std::filesystem::exists(path))
            return std::nullopt;
        const auto size = std::filesystem::file_size(path);
        if (size > maximumStreamingBody)
            throw std::runtime_error("Streaming blob size invalid");
        for (const auto &row : rows)
            if ((row.at("content") == hash && row.at("size") != size) ||
                (row.at("summary") == hash && row.at("summary_size") != size))
                throw std::runtime_error("Streaming metadata size disagrees with blob");
        wire::Bytes bytes(static_cast<size_t>(size));
        std::ifstream in(path, std::ios::binary);
        if (!in.read(reinterpret_cast<char *>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size())))
            throw std::runtime_error("Streaming blob read failed");
        if (hex(crypto::sha256(bytes)) != hash)
            throw std::runtime_error("Streaming blob hash invalid");
        return bytes;
    }

    unsigned streamingUpload(const std::string &request, std::span<const uint8_t> bytes)
    {
        std::lock_guard lock(contentMutex);
        if (request.starts_with("/content-streaming/upload/user/"))
            return putUserUpload(request, bytes);
        if (request.starts_with("/content-streaming/upload/multipart/"))
            return putMultipart(request, bytes);
        if (request.starts_with("/content-streaming/upload/pooled/"))
            return putPooledUpload(request, bytes);
        return 404;
    }
} // namespace services
