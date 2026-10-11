#include "identity_services.h"
#include "protobuf.h"

namespace services
{
    std::optional<Reply> identity(const platform::LobbyIdentity &id,
                                  uint8_t service,
                                  uint8_t task,
                                  wire::Reader &p)
    {
        if (service != 197 || (task != 10 && task != 11))
            return std::nullopt;
        proto::Reader request{p.structure(32 * 1024)};
        proto::Field f;
        Reply reply{0, {}, "cross-platform-identity-resolved", true, {}};
        unsigned count = 0;
        // Exact Replay request 0x1420FB850/0x1420FBF00 and response
        // 0x1420FBAD0/0x1420FC0C0: one field-1 account per requested slot.
        // MappedUser::deserialize (0x1420F6700) reads UInt64 1 and string 2;
        // isValid (0x1420FB610) tests the resulting ID against zero.
        while (request.next(f))
        {
            if (f.tag != 1)
                continue;
            wire::require(f.type == 2 && ++count <= 200);
            proto::Reader account{f.bytes};
            proto::Field field;
            bool hasUser = false, hasType = false;
            uint64_t user = 0;
            std::string type;
            while (account.next(field))
            {
                if (field.tag == 1)
                {
                    wire::require(!hasUser && field.type == 0);
                    hasUser = true;
                    user = field.value;
                }
                else if (field.tag == 2)
                {
                    wire::require(!hasType && field.type == 2 && field.bytes.size() < 10);
                    hasType = true;
                    type.assign(reinterpret_cast<const char *>(field.bytes.data()),
                                field.bytes.size());
                    wire::require(type.find('\0') == std::string::npos);
                }
            }
            wire::require(hasUser && hasType && user != UINT64_MAX);
            // The signed local provider's native ticket and UNO storage bind this
            // XUID to both account representations. Do not infer mappings for
            // unknown IDs, other platforms or the separate legacy numeric ID.
            const bool known = (user == id.userId || platform::accountName(user).has_value()) &&
                               (type.empty() || type == "uno" || type == "bnet");
            wire::Bytes mapped;
            proto::integer(mapped, 1, known ? user : 0);
            proto::text(mapped, 2, known ? (task == 10 ? "uno" : "bnet") : "");
            proto::bytes(reply.structure, 1, mapped);
        }
        return reply;
    }
} // namespace services
