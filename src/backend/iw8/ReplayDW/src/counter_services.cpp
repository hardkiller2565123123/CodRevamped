#include "host_os.h"
#include "counter_services.h"
#include "../third_party/nlohmann/json.hpp"
#include <charconv>
#include <fstream>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t maxCounters = 4096;

        void validStore(bool value)
        {
            if (!value)
                throw std::runtime_error("Counter store schema invalid");
        }

        int64_t signedValue(const Json &value)
        {
            validStore(value.is_number_integer());
            if (value.is_number_unsigned())
                validStore(value.get<uint64_t>() < static_cast<uint64_t>(INT64_MAX));
            const auto result = value.get<int64_t>();
            validStore(result != INT64_MAX);
            return result;
        }

        Json load(const std::filesystem::path &path, uint32_t title)
        {
            if (!std::filesystem::exists(path))
                return Json{{"schema", 1}, {"title", title}, {"totals", Json::object()}};
            validStore(std::filesystem::file_size(path) <= 512 * 1024);
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Counter store read failed");
            auto state = Json::parse(in);
            validStore(state.at("schema") == 1 && state.at("title") == title);
            const auto &totals = state.at("totals");
            validStore(totals.is_object() && totals.size() <= maxCounters);
            for (auto entry = totals.begin(); entry != totals.end(); ++entry)
            {
                uint32_t id = 0;
                const auto &key = entry.key();
                const auto parsed = std::from_chars(key.data(), key.data() + key.size(), id);
                validStore(parsed.ec == std::errc{} && parsed.ptr == key.data() + key.size() &&
                           id != UINT32_MAX && key == std::to_string(id));
                (void)signedValue(entry.value());
            }
            return state;
        }

        void save(const std::filesystem::path &path, const Json &state)
        {
            const auto bytes = state.dump();
            validStore(bytes.size() <= 512 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream out(pending, std::ios::binary | std::ios::trunc);
                if (!out.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !out.flush())
                    throw std::runtime_error("Counter store write failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Counter store publication failed");
        }
    } // namespace

    std::optional<Reply> counterServices(const std::filesystem::path &root,
                                         const platform::LobbyIdentity &id,
                                         uint8_t service,
                                         uint8_t task,
                                         wire::Reader &params)
    {
        if (service != 23 || (task != 1 && task != 2))
            return std::nullopt;
        // Same-Replay requests 0x14212E170 / 0x14212E050 have no entry count.
        // Actual counter vtables 0x1426A40E8 / 0x1426A40F8 bind the UInt32/Int64
        // reader 0x142149910 and serializer 0x142149990 (64-byte native object).
        std::vector<std::pair<uint32_t, int64_t>> entries;
        while (params.more())
        {
            wire::require(entries.size() < maxCounters);
            const auto counter = params.u32();
            wire::require(counter != UINT32_MAX);
            const auto increment = task == 1 ? params.value<int64_t>(9) : int64_t{0};
            // INT64_MAX is the SDK's NAN sentinel (0x1420F02F0), not a count.
            wire::require(increment != INT64_MAX);
            entries.emplace_back(counter, increment);
        }
        params.end();
        const auto path = root / "counters" / (std::to_string(id.titleId) + ".json");
        auto state = load(path, id.titleId);
        auto &totals = state["totals"];
        if (task == 2)
        {
            Reply reply{0, {}, "global-counter-totals-read"};
            for (const auto &entry : entries)
            {
                const auto key = std::to_string(entry.first);
                wire::Writer out;
                out.u32(entry.first);
                out.data.push_back(9);
                wire::raw(out.data,
                          totals.contains(key) ? signedValue(totals.at(key)) : int64_t{0});
                reply.results.push_back(std::move(out.data));
            }
            return reply;
        }
        // The service is a per-title aggregate, not per-user profile data. The
        // dispatch store lock and single atomic publication protect the whole batch.
        // Duplicate IDs represent separate increments in request order.
        for (const auto &[counter, increment] : entries)
        {
            const auto key = std::to_string(counter);
            const auto value = totals.contains(key) ? signedValue(totals.at(key)) : int64_t{0};
            if ((increment > 0 && value > INT64_MAX - 1 - increment) ||
                (increment < 0 && value < INT64_MIN - increment))
                return Reply{106, {}, "counter-increment-overflow"};
            if (!totals.contains(key) && totals.size() >= maxCounters)
                return Reply{102, {}, "counter-store-capacity-exceeded"};
            totals[key] = value + increment;
        }
        if (!entries.empty())
            save(path, state);
        return Reply{0, {}, "global-counter-increments-persisted"};
    }
} // namespace services
