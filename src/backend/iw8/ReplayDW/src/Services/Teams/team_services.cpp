#include "team_services.h"
#include "nlohmann/json.hpp"
#include <algorithm>
#include <fstream>
#include <set>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        std::string scope(const std::string &value)
        {
            wire::require(value.size() < 16 && value != "." && value != "..");
            for (char c : value)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            return value.empty() ? "_default" : value;
        }

        uint64_t number(const Json &row, const char *name)
        {
            wire::require(row.at(name).is_number_unsigned());
            const auto value = row.at(name).get<uint64_t>();
            wire::require(value && value != UINT64_MAX);
            return value;
        }

        Json teams(const std::filesystem::path &path)
        {
            if (!std::filesystem::exists(path))
                return Json::array();
            if (std::filesystem::file_size(path) > 1024 * 1024)
                throw std::runtime_error("Team publication size invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Team publication read failed");
            const auto data = Json::parse(in);
            try
            {
                wire::require(data.at("schema") == 1 && data.at("teams").is_array() &&
                              data.at("teams").size() <= 1024);
                std::set<uint64_t> ids;
                for (const auto &row : data.at("teams"))
                {
                    wire::require(ids.insert(number(row, "id")).second);
                    const auto owner = number(row, "owner");
                    wire::require(row.at("account") == "uno" || row.at("account") == "bnet");
                    const auto name = row.at("name").get<std::string>();
                    wire::require(!name.empty() && name.size() < 64 &&
                                  name.find('\0') == std::string::npos);
                    wire::require(row.at("members").is_array() && !row.at("members").empty() &&
                                  row.at("members").size() <= 1024);
                    std::set<uint64_t> members;
                    for (const auto &member : row.at("members"))
                    {
                        wire::require(members.insert(number(member, "user")).second);
                        wire::require(member.at("status").is_number_unsigned() &&
                                      member.at("status").get<uint64_t>() <= UINT8_MAX);
                    }
                    wire::require(members.contains(owner));
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Team publication schema invalid");
            }
            return data.at("teams");
        }
    } // namespace

    std::optional<Reply> teamServices(const std::filesystem::path &root,
                                      const platform::LobbyIdentity &id,
                                      uint8_t service,
                                      uint8_t task,
                                      wire::Reader &p)
    {
        if (service != 3 || task != 46)
            return std::nullopt;
        // Exact Replay constructor 0x142128970: context, ContextUser,
        // maximum, start. This legacy family is separate from MW4 clans.
        const auto context = scope(p.text(16));
        auto user = p.u64();
        const auto account = p.text(10);
        wire::require(account.empty() || account == "uno" || account == "bnet");
        if (!user || user == UINT64_MAX)
            user = id.userId;
        const auto maximum = p.u32(), start = p.u32();
        p.end();
        wire::require(maximum > 0 && maximum <= 1024 && start <= 1000000);
        const auto rows =
            teams(root / "teams" / std::to_string(id.titleId) / context / "teams.json");
        std::vector<wire::Bytes> selected;
        for (const auto &row : rows)
            for (const auto &member : row.at("members"))
                if (member.at("user") == user)
                {
                    // Complete bdTeamInfo reader 0x142113D50. The misleadingly named
                    // q_bdByteBuffer::readUInt64 at 1420EFB80 actually reads tag 3/u8.
                    wire::Writer out;
                    out.u64(row.at("id").get<uint64_t>());
                    out.text(row.at("name").get<std::string>());
                    out.u64(row.at("owner").get<uint64_t>());
                    out.text(row.at("account").get<std::string>());
                    out.u8(member.at("status").get<uint8_t>());
                    selected.push_back(std::move(out.data));
                    break;
                }
        Reply reply{0, {}, "team-memberships-read"};
        const auto end = std::min(selected.size(), static_cast<size_t>(start) + maximum);
        for (size_t i = start; i < end; ++i)
            reply.results.push_back(std::move(selected[i]));
        return reply;
    }
} // namespace services
