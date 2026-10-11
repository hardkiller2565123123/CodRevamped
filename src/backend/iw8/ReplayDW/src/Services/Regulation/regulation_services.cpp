#include "host_os.h"
#include "regulation_services.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <ctime>
#include <memory>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        constexpr size_t documentLimit = 64 * 1024, recordLimit = 15;

        void persisted(bool valid)
        {
            if (!valid)
                throw std::runtime_error("Invalid persisted regulation layout");
        }

        Json parse(const std::string &bytes, bool caller = false)
        {
            std::vector<std::set<std::string>> keys;
            bool valid = bytes.size() <= documentLimit;
            auto callback = [&](int depth, Json::parse_event_t event, Json &value)
            {
                if (depth > 16)
                {
                    if (caller)
                        wire::require(false);
                    persisted(false);
                }
                if (event == Json::parse_event_t::object_start)
                    keys.emplace_back();
                else if (event == Json::parse_event_t::key)
                    valid = keys.back().insert(value.get<std::string>()).second && valid;
                else if (event == Json::parse_event_t::object_end)
                    keys.pop_back();
                return true;
            };
            const auto result = Json::parse(bytes, callback, false);
            valid = valid && result.is_object();
            if (caller)
                wire::require(valid);
            else
                persisted(valid);
            return result;
        }

        Json read(const std::filesystem::path &path)
        {
            const auto handle = CreateFileW(path.c_str(),
                                            GENERIC_READ,
                                            FILE_SHARE_READ | FILE_SHARE_DELETE,
                                            nullptr,
                                            OPEN_EXISTING,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Regulation snapshot open failed");
            const std::unique_ptr<void, decltype(&CloseHandle)> snapshot(handle, &CloseHandle);
            LARGE_INTEGER size{};
            persisted(GetFileSizeEx(handle, &size) && size.QuadPart >= 0 &&
                      static_cast<uint64_t>(size.QuadPart) <= documentLimit);
            std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
            DWORD received = 0;
            persisted(
                bytes.empty() ||
                (ReadFile(
                     handle, bytes.data(), static_cast<DWORD>(bytes.size()), &received, nullptr) &&
                 received == bytes.size()));
            return parse(bytes);
        }

        bool regulation(const Json &row)
        {
            if (!row.is_object() || row.size() != 2 || !row.contains("name") ||
                !row["name"].is_string() || !row.contains("version") ||
                !row["version"].is_number_unsigned())
                return false;
            const auto &name = row["name"].get_ref<const std::string &>();
            return !name.empty() && name.size() < 10 &&
                   std::all_of(
                       name.begin(),
                       name.end(),
                       [](char c)
                       {
                           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                  (c >= '0' && c <= '9') || c == '_' || c == '-';
                       });
        }

        std::string timestamp(uint64_t value)
        {
            persisted(value <= static_cast<uint64_t>(INT64_MAX));
            const auto seconds = static_cast<__time64_t>(value);
            tm utc{};
            char text[21]{};
            persisted(_gmtime64_s(&utc, &seconds) == 0 &&
                      std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &utc) == 20);
            return text;
        }

        void validate(const Json &state, uint32_t title, uint64_t owner = 0)
        {
            persisted(state.is_object() && state.size() == (owner ? 4 : 3) &&
                      state.at("schema").is_number_integer() && state["schema"] == 1 &&
                      state.at("title").is_number_unsigned() && state["title"] == title);
            if (owner)
                persisted(state.at("owner").is_number_unsigned() && state["owner"] == owner);
            const auto &rows = state.at(owner ? "optouts" : "regulations");
            persisted(rows.is_array() && rows.size() <= recordLimit);
            std::set<std::string> names;
            for (const auto &row : rows)
            {
                const auto &entry = owner ? row.at("regulation") : row;
                persisted(regulation(entry) &&
                          names.insert(entry.at("name").get<std::string>()).second);
                if (owner)
                    persisted(row.is_object() && row.size() == 5 &&
                              row.at("clientMessageVersion").is_number_unsigned() &&
                              row.at("value").is_boolean() && row.at("updated").is_string() &&
                              row.at("updatedTimestamp").is_number_unsigned() &&
                              row["updated"] == timestamp(row["updatedTimestamp"].get<uint64_t>()));
            }
            persisted(state.dump().size() <= documentLimit);
        }

        void save(const std::filesystem::path &path,
                  const Json &state,
                  uint32_t title,
                  uint64_t owner)
        {
            validate(state, title, owner);
            const auto bytes = state.dump();
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
                    throw std::runtime_error("Regulation persistence open failed");
                const std::unique_ptr<void, decltype(&CloseHandle)> output(handle, &CloseHandle);
                DWORD written = 0;
                if (!WriteFile(handle,
                               bytes.data(),
                               static_cast<DWORD>(bytes.size()),
                               &written,
                               nullptr) ||
                    written != bytes.size() || !FlushFileBuffers(handle))
                    throw std::runtime_error("Regulation persistence flush failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Regulation publication failed");
        }

        Reply response(const RESTRequest &request,
                       std::string operation,
                       uint32_t status,
                       const Json &body)
        {
            Reply reply{0, {}, std::move(operation)};
            RESTResult result;
            result.version = request.version;
            result.status = status;
            result.body = body.dump();
            reply.rest = std::move(result);
            return reply;
        }

        Reply error(const RESTRequest &request, uint32_t status, const char *name)
        {
            return response(
                request,
                "regulation-request-denied",
                status,
                {{"error", {{"name", name}, {"msg", "Regulation request unavailable"}}}});
        }

        std::string path(const std::string &uri)
        {
            // Each recovered request adds one client query. It is routing metadata,
            // never an account selector, filesystem path, log field or credential.
            const auto query = uri.find('?');
            wire::require(
                query != std::string::npos && uri.substr(query + 1).starts_with("client=") &&
                uri.size() - query - 8 > 0 && uri.size() - query - 8 <= 384 &&
                uri.find('&', query) == std::string::npos && uri.find('#') == std::string::npos);
            const auto value = uri.substr(query + 8);
            size_t decoded = 0;
            for (size_t i = 0; i < value.size(); ++i)
            {
                unsigned char c = static_cast<unsigned char>(value[i]);
                if (c == '%')
                {
                    wire::require(i + 2 < value.size());
                    unsigned byte = 0;
                    const auto parsed =
                        std::from_chars(value.data() + i + 1, value.data() + i + 3, byte, 16);
                    wire::require(parsed.ec == std::errc{} && parsed.ptr == value.data() + i + 3);
                    c = static_cast<unsigned char>(byte);
                    i += 2;
                }
                wire::require(c >= 32 && c < 127 && ++decoded <= 128);
            }
            return uri.substr(0, query);
        }
    } // namespace

    std::optional<Reply> regulations(const std::filesystem::path &directory,
                                     const platform::LobbyIdentity &id,
                                     const RESTRequest &request)
    {
        if (request.service != "umbrella" || request.resource != "Regulations")
            return std::nullopt;
        const bool fetch = request.operation == "fetchRegulations";
        const bool get = request.operation == "getUserPreference";
        const bool set = request.operation == "setUserPreference";
        if (!fetch && !get && !set)
            return error(request, 404, "UnknownRegulationOperation");
        wire::require(request.method == (set ? 0x505554U : 0x474554U) && request.hasBody == set &&
                      (set || request.body.empty()));
        const auto route = path(request.uri);
        const auto root = directory / "regulations" / std::to_string(id.titleId);
        const auto publicationPath = root / "publication.json";
        if (fetch)
        {
            wire::require(route == "/v1.0/regulations/");
            // Absence is explicit unavailability, never an invented empty policy.
            if (!std::filesystem::exists(publicationPath))
                return error(request, 503, "RegulationsNotPublished");
            const auto publication = read(publicationPath);
            validate(publication, id.titleId);
            return response(request,
                            "regulation-enforcement-read",
                            200,
                            {{"regulations", publication["regulations"]}});
        }
        constexpr std::string_view prefix = "/v1.0/accounts/", suffix = "/optouts/";
        wire::require(route.starts_with(prefix) && route.ends_with(suffix) &&
                      route.size() > prefix.size() + suffix.size());
        const auto account =
            route.substr(prefix.size(), route.size() - prefix.size() - suffix.size());
        const auto split = account.find('/');
        wire::require(split != std::string::npos);
        const auto type = account.substr(0, split), ownerText = account.substr(split + 1);
        uint64_t owner = 0;
        const auto parsed =
            std::from_chars(ownerText.data(), ownerText.data() + ownerText.size(), owner);
        wire::require((type == "uno" || type == "bnet") && owner && owner != UINT64_MAX &&
                      parsed.ec == std::errc{} &&
                      parsed.ptr == ownerText.data() + ownerText.size() &&
                      std::to_string(owner) == ownerText);
        if (owner != id.userId)
            return error(request, 403, "RegulationOwnerDenied");
        const auto preferencesPath = root / "preferences" / (std::to_string(owner) + ".json");
        auto state = std::filesystem::exists(preferencesPath) ? read(preferencesPath)
                                                              : Json{{"schema", 1},
                                                                     {"title", id.titleId},
                                                                     {"owner", owner},
                                                                     {"optouts", Json::array()}};
        validate(state, id.titleId, owner);
        if (get)
            return response(
                request, "regulation-preferences-read", 200, {{"optouts", state["optouts"]}});
        wire::require(request.content == 1 && !request.body.empty() &&
                      request.body.size() <= documentLimit);
        const auto input = parse(std::string(request.body.begin(), request.body.end()), true);
        wire::require(input.size() == 3 && input.contains("regulation") &&
                      regulation(input["regulation"]) && input.contains("clientMessageVersion") &&
                      input["clientMessageVersion"].is_number_unsigned() &&
                      input.contains("value") && input["value"].is_boolean());
        if (!std::filesystem::exists(publicationPath))
            return error(request, 503, "RegulationsNotPublished");
        const auto publication = read(publicationPath);
        validate(publication, id.titleId);
        const auto name = input["regulation"]["name"].get<std::string>();
        const auto &published = publication["regulations"];
        const auto active = std::find_if(published.begin(),
                                         published.end(),
                                         [&](const Json &entry)
                                         {
                                             return entry["name"] == name;
                                         });
        if (active == published.end())
            return error(request, 404, "RegulationNotPublished");
        // The exact Replay writer always sends regulation version zero. Resolve
        // that current-version selector using explicit local publication only.
        if (input["regulation"]["version"] != 0 &&
            input["regulation"]["version"] != (*active)["version"])
            return error(request, 409, "RegulationVersionConflict");
        auto &rows = state["optouts"];
        const auto previous = std::find_if(rows.begin(),
                                           rows.end(),
                                           [&](const Json &entry)
                                           {
                                               return entry["regulation"]["name"] == name;
                                           });
        if (previous == rows.end() && rows.size() == recordLimit)
            return error(request, 409, "RegulationPreferenceCapacity");
        if (previous == rows.end() || (*previous)["regulation"] != *active ||
            (*previous)["clientMessageVersion"] != input["clientMessageVersion"] ||
            (*previous)["value"] != input["value"])
        {
            const auto seconds =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
            const Json record = {{"regulation", *active},
                                 {"clientMessageVersion", input["clientMessageVersion"]},
                                 {"value", input["value"]},
                                 {"updated", timestamp(seconds)},
                                 {"updatedTimestamp", seconds}};
            if (previous == rows.end())
                rows.push_back(record);
            else
                *previous = record;
            save(preferencesPath, state, id.titleId, owner);
        }
        // Actual response vtable 0x1426A2758 +8 -> 0x142142C00 reads this boolean.
        return response(request, "regulation-preference-updated", 200, {{"success", true}});
    }
} // namespace services
