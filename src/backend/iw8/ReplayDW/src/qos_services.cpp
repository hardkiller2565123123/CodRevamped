#include "host_os.h"
#include "qos_services.h"
#include "qos_provider.h"
#include "relay_provider.h"
#include "../third_party/nlohmann/json.hpp"
#include <chrono>
#include <fstream>
#include <cmath>
#include <set>
#include <algorithm>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        uint64_t now()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        }

        Json readDocument(const std::filesystem::path &path, const Json &fallback)
        {
            if (!std::filesystem::exists(path))
                return fallback;
            wire::require(std::filesystem::file_size(path) <= 256 * 1024);
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("QoS document read failed");
            return Json::parse(stream);
        }

        void publish(const std::filesystem::path &path, const Json &document)
        {
            const auto bytes = document.dump();
            wire::require(bytes.size() <= 256 * 1024);
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            {
                std::ofstream stream(pending, std::ios::binary | std::ios::trunc);
                if (!stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !stream.flush())
                    throw std::runtime_error("QoS transaction persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("QoS transaction publication failed");
        }

        std::string string(const Json &document, const char *key, size_t capacity)
        {
            wire::require(document.at(key).is_string());
            const auto value = document.at(key).get<std::string>();
            wire::require(!value.empty() && value.size() < capacity &&
                          value.find('\0') == std::string::npos);
            return value;
        }

        wire::Bytes decode(const std::string &value, size_t capacity)
        {
            return wire::base64(value, capacity);
        }

        Json configuration(const std::filesystem::path &directory, uint32_t title)
        {
            // An empty local datacenter fleet is a real empty collection. It does not
            // invent probe successes, external relay credentials, or dedicated hosts.
            auto out = readDocument(
                directory / "qos" / std::to_string(title) / "configuration.json",
                Json{{"num_probes", 3}, {"hosts", Json::array()}, {"datacenters", Json::array()}});
            wire::require(out.is_object() && out.at("num_probes").is_number_integer());
            wire::require(out.at("num_probes").get<unsigned>() > 0 &&
                          out.at("num_probes").get<unsigned>() <= 16);
            wire::require(out.at("hosts").is_array() && out.at("hosts").size() <= 64);
            wire::require(out.at("datacenters").is_array() && out.at("datacenters").size() <= 64);
            std::set<wire::Bytes> addresses;
            for (const auto &host : out.at("hosts"))
            {
                wire::require(decode(string(host, "security_id", 113), 8).size() == 8);
                wire::require(decode(string(host, "security_key", 113), 16).size() == 16);
                const auto address = decode(string(host, "address", 113), 84);
                wire::require(address.size() == 84 && addresses.insert(address).second);
                wire::require(!decode(string(host, "datacenter", 89), 64).empty());
            }
            std::set<std::string> names;
            for (const auto &value : out.at("datacenters"))
            {
                const auto name = string(Json{{"name", value}}, "name", 64);
                wire::require(names.insert(name).second);
            }
            return out;
        }

        std::filesystem::path transactions(const std::filesystem::path &directory,
                                           const platform::LobbyIdentity &id)
        {
            return directory / "qos" / std::to_string(id.titleId) / "transactions" /
                   (std::to_string(id.userId) + ".json");
        }

        Reply initiate(const std::filesystem::path &directory,
                       const platform::LobbyIdentity &id,
                       wire::Reader &p)
        {
            // Same-Replay 0x142135A70: typed JSON string -> one bdStringResult.
            const auto query = Json::parse(p.text(4097), nullptr, false);
            p.end();
            wire::require(query.is_object());
            for (const auto *field : {"qos_build_name_context", "qos_build_name"})
                if (query.contains(field))
                    (void)string(query, field, 128);
            auto config = configuration(directory, id.titleId);
            if (qos_provider::enabled() && config.at("hosts").empty())
            {
                const auto host = qos_provider::host();
                config["hosts"].push_back(
                    {{"security_id", wire::base64Encode(host.securityId)},
                     {"security_key", wire::base64Encode(host.securityKey)},
                     {"address", wire::base64Encode(host.address)},
                     {"datacenter", wire::base64Encode(wire::Bytes{'l', 'o', 'c', 'a', 'l', 0})}});
                config["datacenters"] = Json::array({"local"});
            }
            auto state = readDocument(transactions(directory, id), Json::array());
            wire::require(state.is_array());
            Json retained = Json::array();
            for (const auto &row : state)
                if (row.at("expires").get<uint64_t>() > now())
                    retained.push_back(row);
            if (retained.size() >= 16)
                retained.erase(retained.begin(), retained.end() - 15);
            uint64_t transaction = 0;
            do
            {
                const auto random = crypto::random(8);
                transaction = wire::at<uint64_t>(random, 0);
            } while (!transaction || std::any_of(retained.begin(),
                                                 retained.end(),
                                                 [&](const auto &row)
                                                 {
                                                     return row.at("id") == transaction;
                                                 }));
            retained.push_back({{"id", transaction},
                                {"expires", now() + 300},
                                {"hosts", config.at("hosts")},
                                {"datacenters", config.at("datacenters")},
                                {"num_probes", config.at("num_probes")},
                                {"replied", false}});
            publish(transactions(directory, id), retained);
            wire::Writer result;
            result.text(Json{{"transaction_id", transaction},
                             {"num_probes", config.at("num_probes")},
                             {"hosts", config.at("hosts")}}
                            .dump());
            return {0, {std::move(result.data)}, "dcqos-initiated"};
        }

        std::vector<float> latencyArray(wire::Reader &p, unsigned maximum)
        {
            // 0x1420EFE40 / 0x1420EF220: packed arrays suppress per-element tags.
            wire::require(p.offset + 10 <= p.data.size() && p.data[p.offset++] == 113 &&
                          p.data[p.offset++] == 8);
            const auto size = wire::at<uint32_t>(p.data, p.offset);
            p.offset += 4;
            const auto count = wire::at<uint32_t>(p.data, p.offset);
            p.offset += 4;
            wire::require(count <= maximum && size == count * 4 &&
                          size <= p.data.size() - p.offset);
            std::vector<float> out;
            for (uint32_t index = 0; index < count; ++index)
            {
                const auto value = wire::at<float>(p.data, p.offset);
                p.offset += 4;
                wire::require(std::isfinite(value) && value >= 0);
                out.push_back(value);
            }
            return out;
        }

        Reply report(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     wire::Reader &p)
        {
            // Same-Replay 0x142135CE0: transaction, host count, complete probe record.
            const char *stage = "transaction";
            uint64_t count = 0;
            size_t addressBytes = 0, socketBytes = 0, sampleCount = 0;
            uint32_t bandwidthDown = 0, bandwidthUp = 0;
            try
            {
                const auto transaction = p.u64();
                count = p.u64();
                wire::require(count <= 64);
                auto state = readDocument(transactions(directory, id), Json::array());
                wire::require(state.is_array());
                auto row = std::find_if(state.begin(),
                                        state.end(),
                                        [&](const auto &entry)
                                        {
                                            return entry.at("id") == transaction;
                                        });
                if (row == state.end() || row->at("expires").get<uint64_t>() <= now())
                    return {101, {}, "dcqos-transaction-denied"};
                stage = "host-count";
                wire::require(count == row->at("hosts").size());
                Json reports = Json::array();
                std::set<wire::Bytes> seen;
                for (uint64_t index = 0; index < count; ++index)
                {
                    stage = "addresses";
                    const auto address = p.blob(84), socketAddress = p.blob(84);
                    addressBytes = address.size();
                    socketBytes = socketAddress.size();
                    wire::require(address.size() == 84 &&
                                  (socketAddress.size() == 6 || socketAddress.size() == 18) &&
                                  seen.insert(address).second);
                    const auto &hosts = row->at("hosts");
                    stage = "issued-host";
                    wire::require(std::any_of(
                        hosts.begin(),
                        hosts.end(),
                        [&](const auto &host)
                        {
                            return decode(host.at("address").template get<std::string>(), 84) ==
                                   address;
                        }));
                    stage = "latency-array";
                    const auto samples =
                        latencyArray(p, std::min(16U, 2 * row->at("num_probes").get<unsigned>()));
                    sampleCount = samples.size();
                    stage = "probe-result";
                    const auto payload = p.blob(1024);
                    const bool disabled = p.boolean();
                    // +184/+188 are bandwidthDown/bandwidthUp, not packet counters.
                    // +192 is minLatency, not average latency. Same-Replay 0x142135CE0
                    // verifies the offsets; bdAsyncMatchMaking's source identifies fields.
                    // Zero and UINT32_MAX are legitimate unavailable-bandwidth values.
                    bandwidthDown = p.u32();
                    bandwidthUp = p.u32();
                    const auto minimum = p.value<float>(13);
                    wire::require(std::isfinite(minimum) && minimum >= 0);
                    reports.push_back({{"samples", samples},
                                       {"bandwidth_down", bandwidthDown},
                                       {"bandwidth_up", bandwidthUp},
                                       {"minimum_latency", minimum},
                                       {"disabled", disabled},
                                       {"payload_bytes", payload.size()}});
                }
                stage = "end";
                p.end();
                if (row->at("replied").get<bool>() && row->at("reports") != reports)
                    return {106, {}, "dcqos-report-conflict"};
                (*row)["replied"] = true;
                (*row)["reports"] = reports;
                publish(transactions(directory, id), state);
                return {0, {}, "dcqos-results-recorded"};
            }
            catch (const std::runtime_error &e)
            {
                if (std::string(e.what()) != "Malformed native task parameters")
                    throw;
                Reply invalid{106, {}, "dcqos-report-invalid"};
                invalid.detail = " validation_stage=" + std::string(stage) +
                                 " hosts=" + std::to_string(count) +
                                 " address_bytes=" + std::to_string(addressBytes) +
                                 " socket_bytes=" + std::to_string(socketBytes) +
                                 " samples=" + std::to_string(sampleCount) +
                                 " bandwidth_down=" + std::to_string(bandwidthDown) +
                                 " bandwidth_up=" + std::to_string(bandwidthUp) +
                                 " parameter_offset=" + std::to_string(p.offset) +
                                 " parameter_bytes=" + std::to_string(p.data.size());
                return invalid;
            }
        }

        Reply datacenter(const platform::LobbyIdentity &id, wire::Reader &p)
        {
            // Task 145/24: two native build-name strings at 0x1421357F0.
            // 0x140F4FA80 explicitly accepts a direct datacenter independently of
            // server_info is a nested JSON STRING, not an object (140F4FA80).
            (void)p.text(64);
            (void)p.text(64);
            p.end();
            if (!qos_provider::enabled())
                return {108, {}, "dcqos-local-provider-unavailable"};
            Json document = {{"datacenter", "local"}};
            if (relay_provider::enabled())
                document["server_info"] =
                    Json{{"relay_auth_token", wire::base64Encode(relay_provider::serverToken(id))}}
                        .dump();
            wire::Writer result;
            result.text(document.dump());
            return {0,
                    {std::move(result.data)},
                    relay_provider::enabled() ? "dcqos-local-relay-read"
                                              : "dcqos-direct-datacenter-read"};
        }

        Reply preferences(const std::filesystem::path &directory,
                          const platform::LobbyIdentity &id,
                          wire::Reader &p)
        {
            // 0x1421354B0 -> bdDataCenterPreferences::deserialize at 0x14210BE60.
            const auto count = p.u64();
            wire::require(count > 0 && count <= 64);
            for (uint64_t i = 0; i < count; ++i)
                if (p.u64() != id.userId)
                    return {101, {}, "dcqos-preference-owner-denied"};
            p.end();
            const auto config = configuration(directory, id.titleId);
            wire::Writer result;
            result.data.push_back(116);
            result.data.push_back(8);
            const auto names = qos_provider::enabled() && config.at("datacenters").empty()
                                   ? Json::array({"local"})
                                   : config.at("datacenters");
            wire::raw(result.data, static_cast<uint32_t>(names.size() * 64));
            wire::raw(result.data, static_cast<uint32_t>(names.size()));
            for (const auto &item : names)
            {
                const auto name = item.get<std::string>();
                result.data.insert(result.data.end(), name.begin(), name.end());
                result.data.push_back(0);
            }
            return {0, {std::move(result.data)}, "dcqos-preferences-read"};
        }
    } // namespace

    std::optional<Reply> qosServices(const std::filesystem::path &directory,
                                     const platform::LobbyIdentity &id,
                                     uint8_t service,
                                     uint8_t task,
                                     wire::Reader &p)
    {
        if (service != 145)
            return std::nullopt;
        if (task == 25)
            return initiate(directory, id, p);
        if (task == 4)
            return report(directory, id, p);
        if (task == 16)
            return preferences(directory, id, p);
        if (task == 24)
            return datacenter(id, p);
        return std::nullopt;
    }
} // namespace services
