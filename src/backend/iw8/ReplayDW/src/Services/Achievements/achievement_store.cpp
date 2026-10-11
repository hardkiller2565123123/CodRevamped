#include "host_os.h"
#include "achievement_store.h"
#include "crypto.h"
#include "wire.h"
#include <fstream>
#include <iterator>
#include <set>

namespace achievement_store
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t maximumDocument = 4 * 1024 * 1024;
        constexpr size_t maximumIntent = 64 * 1024 * 1024;
        constexpr size_t maximumWrites = 4096;

        std::string digest(const Json &value)
        {
            const auto text = value.dump();
            const auto hash = crypto::sha256({reinterpret_cast<const uint8_t *>(text.data()),
                                             text.size()});
            std::string out;
            for (const auto byte : hash)
            {
                out += "0123456789abcdef"[byte >> 4];
                out += "0123456789abcdef"[byte & 15];
            }
            return out;
        }

        bool hash(const std::string &value)
        {
            return value.size() == 64 &&
                   value.find_first_not_of("0123456789abcdef") == std::string::npos;
        }

        std::filesystem::path intentPath(const std::filesystem::path &root, uint32_t title)
        {
            wire::require(title == 5800);
            return root / "achievements" / std::to_string(title) / "event-transaction.json";
        }

        Json read(const std::filesystem::path &path, size_t maximum)
        {
            if (!std::filesystem::exists(path))
                return Json();
            wire::require(std::filesystem::is_regular_file(path) &&
                          std::filesystem::file_size(path) <= maximum);
            std::ifstream input(path, std::ios::binary);
            if (!input)
                throw std::runtime_error("Achievement transaction read failed");
            const std::string bytes((std::istreambuf_iterator<char>(input)), {});
            wire::require(bytes.size() <= maximum);
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            const auto callback = [&](int depth, Json::parse_event_t event, Json &value)
            {
                wire::require(depth <= 32);
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    unique = keys.back().insert(value.get<std::string>()).second && unique;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            auto value = Json::parse(bytes, callback);
            wire::require(unique && (value.is_object() || value.is_array()));
            return value;
        }

        void publish(const std::filesystem::path &path, const Json &value, size_t maximum)
        {
            const auto bytes = value.dump();
            wire::require(bytes.size() <= maximum);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            const auto file = CreateFileW(pending.c_str(), GENERIC_WRITE, 0, nullptr,
                                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Achievement transaction write failed");
            DWORD written = 0;
            const bool passed = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()),
                                          &written, nullptr) && written == bytes.size() &&
                                FlushFileBuffers(file);
            CloseHandle(file);
            if (!passed || !MoveFileExW(pending.c_str(), path.c_str(),
                                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Achievement transaction publication failed");
        }

        Write decode(const Json &row)
        {
            wire::require(row.is_object() && (row.size() == 7 || row.size() == 8) &&
                          row.at("owner").is_number_unsigned() &&
                          row.at("platform_account").is_number_unsigned());
            const auto platform = row.at("platform_account").get<uint64_t>();
            wire::require(platform <= UINT32_MAX);
            auto kind = Destination::event;
            if (row.contains("kind"))
            {
                wire::require(row.at("kind") == "inventory" || row.at("kind") == "states");
                kind = row.at("kind") == "inventory" ? Destination::inventory : Destination::states;
            }
            wire::require(kind == Destination::states ? row.at("after").is_array()
                                                     : row.at("after").is_object());
            return {row.at("owner").get<uint64_t>(), static_cast<uint32_t>(platform),
                    row.at("context").get<std::string>(), row.at("receipt_key").get<std::string>(),
                    row.at("after"), kind};
        }
    } // namespace

    std::filesystem::path destination(const std::filesystem::path &root,
                                      uint32_t title,
                                      const Write &write)
    {
        wire::require(title == 5800 && write.owner && write.owner != UINT64_MAX &&
                      (write.context == "5800" || write.context == "iw8") &&
                      (write.receiptKey.empty() || hash(write.receiptKey)));
        if (write.kind == Destination::inventory)
        {
            wire::require(write.context == "5800" && write.receiptKey.empty());
            return root / "marketplace" / std::to_string(title) /
                   std::to_string(write.owner) / "inventory.json";
        }
        if (write.kind == Destination::states)
        {
            wire::require(write.receiptKey.empty());
            return root / "achievements" / std::to_string(title) / write.context /
                   std::to_string(write.owner) / "states.json";
        }
        wire::require(write.kind == Destination::event);
        const auto folder = root / "achievements" / std::to_string(title) /
                            write.context / std::to_string(write.owner);
        return write.receiptKey.empty() ? folder / "events.json"
                                        : folder / "receipts" / (write.receiptKey + ".json");
    }

    void recover(const std::filesystem::path &root, uint32_t title, const Validator &validate)
    {
        const auto path = intentPath(root, title);
        if (!std::filesystem::exists(path))
            return;
        const auto intent = read(path, maximumIntent);
        wire::require(intent.is_object() && intent.size() == 5 && intent.at("schema") == 1 &&
                      intent.at("title") == title && intent.at("phase") == "prepared" &&
                      intent.at("writes").is_array() && !intent.at("writes").empty() &&
                      intent.at("writes").size() <= maximumWrites &&
                      intent.at("checksum") == digest(intent.at("writes")));
        std::set<std::filesystem::path> destinations;
        std::vector<Write> pending;
        // Validate the entire persisted window before resuming even its first
        // write. A later malformed/conflicting owner cannot partially recover it.
        for (const auto &row : intent.at("writes"))
        {
            auto write = decode(row);
            const auto target = destination(root, title, write);
            wire::require(destinations.insert(target).second &&
                          write.document.dump().size() <= maximumDocument &&
                          row.at("after_digest") == digest(write.document));
            validate(write);
            const auto current = read(target, maximumDocument);
            const auto before = row.at("before_digest");
            wire::require(before.is_null() || (before.is_string() && hash(before.get<std::string>())));
            const auto currentHash = current.is_null() ? Json() : Json(digest(current));
            wire::require(currentHash == before || currentHash == row.at("after_digest"));
            if (currentHash != row.at("after_digest"))
                pending.push_back(std::move(write));
        }
        for (const auto &write : pending)
            publish(destination(root, title, write), write.document, maximumDocument);
        if (!DeleteFileW(path.c_str()))
            throw std::runtime_error("Achievement transaction retirement failed");
    }

    void commit(const std::filesystem::path &root,
                uint32_t title,
                std::span<const Write> writes,
                const Validator &validate)
    {
        recover(root, title, validate);
        if (writes.empty())
            return;
        wire::require(writes.size() <= maximumWrites);
        Json entries = Json::array();
        std::set<std::filesystem::path> destinations;
        for (const auto &write : writes)
        {
            const auto path = destination(root, title, write);
            wire::require(destinations.insert(path).second &&
                          write.document.dump().size() <= maximumDocument);
            validate(write);
            const auto current = read(path, maximumDocument);
            entries.push_back({{"owner", write.owner}, {"platform_account", write.platformAccount},
                               {"context", write.context}, {"receipt_key", write.receiptKey},
                               {"after", write.document}, {"after_digest", digest(write.document)},
                               {"before_digest", current.is_null() ? Json() : Json(digest(current))}});
            if (write.kind == Destination::inventory)
                entries.back()["kind"] = "inventory";
            else if (write.kind == Destination::states)
                entries.back()["kind"] = "states";
        }
        // The complete intent reaches stable storage before any account journal
        // or archived retry receipt is changed. Keep it on every failure.
        const Json intent = {{"schema", 1}, {"title", title}, {"phase", "prepared"},
                             {"writes", entries}, {"checksum", digest(entries)}};
        publish(intentPath(root, title), intent, maximumIntent);
        recover(root, title, validate);
    }
} // namespace achievement_store
