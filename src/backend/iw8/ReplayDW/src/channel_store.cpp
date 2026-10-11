#include "host_os.h"
#include "channel_store.h"
#include <charconv>
#include <memory>
#include <set>
#include <stdexcept>

namespace channel_store
{
    namespace
    {
        constexpr size_t documentLimit = 4 * 1024 * 1024;

        void require(bool valid)
        {
            if (!valid)
                throw std::runtime_error("Invalid persisted channel layout");
        }

        uint64_t identifier(const std::string &text)
        {
            uint64_t id = 0;
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), id);
            require(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && id &&
                    id != UINT64_MAX && std::to_string(id) == text);
            return id;
        }

        bool text(const Json &value, size_t capacity)
        {
            return value.is_string() && !value.get_ref<const std::string &>().empty() &&
                   value.get_ref<const std::string &>().size() < capacity &&
                   value.get_ref<const std::string &>().find('\0') == std::string::npos;
        }

        Json normalize(Json state, uint32_t title)
        {
            require(state.is_object() && state.size() == 3 &&
                    state.at("schema").is_number_integer() && state.at("schema") == 1 &&
                    state.at("title").is_number_unsigned() && state.at("title") == title &&
                    state.at("channels").is_object() && state["channels"].size() <= 4096);
            for (auto &row : state["channels"].items())
            {
                auto &channel = row.value();
                require(
                    channel.is_object() &&
                    channel.size() == (channel.contains("revision") ? 6 : 5) &&
                    text(channel.at("category"), 16) && channel.at("id").is_number_unsigned() &&
                    channel["id"].get<uint64_t>() && channel["id"].get<uint64_t>() != UINT64_MAX &&
                    channel.at("owner").is_number_unsigned() && channel["owner"].get<uint64_t>() &&
                    channel["owner"].get<uint64_t>() != UINT64_MAX &&
                    channel.at("created").is_number_unsigned() &&
                    channel["created"].get<uint64_t>() &&
                    channel["created"].get<uint64_t>() <= UINT32_MAX &&
                    channel.at("members").is_object() && channel["members"].size() <= memberLimit);
                const auto &category = channel["category"].get_ref<const std::string &>();
                for (const auto c : category)
                    require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '_');
                require(row.key() ==
                        category + ":" + std::to_string(channel["id"].get<uint64_t>()));
                // Older servers emitted creation time as native dataVersion. Keep
                // that version while upgrading, then advance on membership changes.
                if (!channel.contains("revision"))
                    channel["revision"] = channel["created"];
                require(channel["revision"].is_number_unsigned() &&
                        channel["revision"].get<uint64_t>() <= UINT32_MAX);
                for (auto &member : channel["members"].items())
                {
                    (void)identifier(member.key());
                    auto &record = member.value();
                    require(record.is_object() &&
                            record.size() == (record.contains("generation") ? 3 : 2) &&
                            text(record.at("name"), 64) &&
                            record.at("expires").is_number_unsigned() &&
                            record["expires"].get<uint64_t>());
                    if (!record.contains("generation"))
                        record["generation"] = channel["revision"];
                    require(record["generation"].is_number_unsigned() &&
                            record["generation"].get<uint64_t>() <=
                                channel["revision"].get<uint64_t>());
                }
            }
            require(state.dump().size() <= documentLimit);
            return state;
        }

        Json parse(const std::string &bytes)
        {
            std::vector<std::set<std::string>> keys;
            bool unique = true;
            auto callback = [&](int, Json::parse_event_t event, Json &value)
            {
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    unique = keys.back().insert(value.get<std::string>()).second && unique;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            auto state = Json::parse(bytes, callback, false);
            require(unique && state.is_object());
            return state;
        }
    } // namespace

    Json load(const std::filesystem::path &path, uint32_t title)
    {
        require(title && path.filename() == std::to_string(title) + ".json");
        if (!std::filesystem::exists(path))
            return {{"schema", 1}, {"title", title}, {"channels", Json::object()}};
        const auto handle = CreateFileW(path.c_str(),
                                        GENERIC_READ,
                                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                                        nullptr,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        nullptr);
        if (handle == INVALID_HANDLE_VALUE)
            throw std::runtime_error("Channel snapshot read failed");
        const std::unique_ptr<void, decltype(&CloseHandle)> snapshot(handle, &CloseHandle);
        LARGE_INTEGER size{};
        require(GetFileSizeEx(handle, &size) && size.QuadPart >= 0 &&
                static_cast<uint64_t>(size.QuadPart) <= documentLimit);
        std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
        DWORD received = 0;
        if (!bytes.empty() &&
            (!ReadFile(
                 handle, bytes.data(), static_cast<DWORD>(bytes.size()), &received, nullptr) ||
             received != bytes.size()))
            throw std::runtime_error("Channel snapshot truncated");
        return normalize(parse(bytes), title);
    }

    void save(const std::filesystem::path &path, uint32_t title, const Json &state)
    {
        require(title && path.filename() == std::to_string(title) + ".json");
        const auto bytes = normalize(state, title).dump();
        std::filesystem::create_directories(path.parent_path());
        auto pending = path;
        pending += ".pending";
        {
            const auto handle = CreateFileW(pending.c_str(),
                                            GENERIC_WRITE,
                                            0,
                                            nullptr,
                                            CREATE_ALWAYS,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Channel persistence open failed");
            const std::unique_ptr<void, decltype(&CloseHandle)> output(handle, &CloseHandle);
            DWORD written = 0;
            if (!WriteFile(
                    handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) ||
                written != bytes.size() || !FlushFileBuffers(handle))
                throw std::runtime_error("Channel persistence flush failed");
        }
        if (!MoveFileExW(
                pending.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("Channel publication failed");
    }

    uint32_t advance(Json &channel)
    {
        const auto current = channel.at("revision").get<uint64_t>();
        require(current < UINT32_MAX);
        channel["revision"] = current + 1;
        return static_cast<uint32_t>(current + 1);
    }
} // namespace channel_store
