#include "Serialization.h"

namespace revamped::iw8::demonware
{
    namespace
    {
        constexpr std::uint8_t kTaskRequestType = 0x86;
        constexpr std::uint8_t kTaskReplyType = 0x01;

        // bdByteBuffer legacy type tags used by the stock IW8 Demonware client.
        constexpr std::uint8_t kBbBool = 0x01;
        constexpr std::uint8_t kBbUnsignedChar8 = 0x03;
        constexpr std::uint8_t kBbUnsignedInteger16 = 0x06;
        constexpr std::uint8_t kBbUnsignedInteger32 = 0x08;
        constexpr std::uint8_t kBbUnsignedInteger64 = 0x0A;
        constexpr std::uint8_t kBbFloat32 = 0x0D;
        constexpr std::uint8_t kBbString = 0x10;
        constexpr std::uint8_t kBbBlob = 0x13;
        constexpr std::uint8_t kBbStruct = 0x17;
        constexpr std::uint8_t kBbStructEnd = 0x00;

        constexpr std::uint32_t kRestVersion = 1u;
        constexpr std::uint32_t kHttpOk = 200u;
        constexpr std::uint32_t kRestMimeJson = 1u;

        // V88: the byte after serviceId is a typed-U8 marker (0x03), not the
        // task number. The actual task number follows it. These task IDs now
        // line up with stock OpenIW8 call sites and the captured 1.44 payloads.
        constexpr TaskRoute kRoutes[] = {
            {38u, 6u, "bdAntiCheat", "reportExtendedAuthInfo", ReplyPolicy::NoResultSuccess},
            {38u, 7u, "bdAntiCheat", "reportBNetSessionToken", ReplyPolicy::NoResultSuccess},

            {27u, 2u, "bdDML", "getUserData", ReplyPolicy::LegacyDmlInfo},
            {67u, 6u, "bdEventLog", "initializeFiltering", ReplyPolicy::NoResultSuccess},
            {12u, 1u, "bdTitleUtilities", "verifyString", ReplyPolicy::LegacyVerifyStringClean},
            {12u, 6u, "bdTitleUtilities", "getServerTime", ReplyPolicy::LegacyServerTime},

            // IW8 1.20 startup inbox poll. bdMail::getMailInfo binds an array
            // result and asks for a small page; a new local account has no mail.
            {29u, 10u, "bdMail", "getMailInfo", ReplyPolicy::LegacyMailInfoEmpty},

            // IW8 1.20 profile bootstrap. Stock code treats a missing public
            // profile as a normal first-run condition and creates its default
            // 256-byte DDL locally. Upload then succeeds with no bound result.
            {8u, 1u, "bdProfiles", "getPublicInfos", ReplyPolicy::LegacyProfileNotFound},
            {8u, 3u, "bdProfiles", "setPublicInfo", ReplyPolicy::NoResultSuccess},

            // IW8 1.20 marketplace fence calls. 0xF5 has a known empty struct
            // shape for an account with no balances. 0xF3 and task 58 are
            // deliberately registered as known-but-unimplemented until their
            // exact native result structures are proven; never guess bytes.
            {80u, 0xF3u, "bdMarketplace", "reconcileLicenses", ReplyPolicy::None},
            {80u, 0xF5u, "bdMarketplace", "getBalancesV3", ReplyPolicy::StructMarketplaceBalancesEmpty},
            {80u, 58u, "bdMarketplace", "validateInventoryItemsToken", ReplyPolicy::None},

            // Observed IW8 1.20 calls whose exact reply contracts are not yet
            // proven. Keeping them in the registry gives precise diagnostics
            // while preserving the DO_NOT_GUESS_RESPONSE_BYTES policy.
            {4u, 1u, "bdStorage", "observedTask1", ReplyPolicy::None},
            {4u, 11u, "bdStorage", "observedTask11", ReplyPolicy::None},
            {4u, 14u, "bdStorage", "serverValidatedStatsWrite", ReplyPolicy::None},
            {3u, 46u, "bdService3", "observedTask46", ReplyPolicy::None},
            {67u, 5u, "bdEventLog", "observedTask5", ReplyPolicy::None},
            {80u, 125u, "bdMarketplace", "observedTask125", ReplyPolicy::None},
            {145u, 15u, "bdService145", "observedTask15", ReplyPolicy::None},
            {145u, 23u, "bdService145", "observedTask23", ReplyPolicy::None},
            {152u, 1u, "bdService152", "observedTask1", ReplyPolicy::None},

            // IW8 1.20 uses legacy task 1. Its request carries an empty/context
            // string followed by one namespace (max 31 chars). The result object
            // reads UInt16 MajorVersion, UInt16 MinorVersion, namespace String,
            // and JSON String. Later builds use task 3 with StructBuffer.
            {95u, 1u, "bdPublisherVariables", "retrievePublisherVariablesLegacy", ReplyPolicy::LegacyPublisherVariables120},
            {95u, 3u, "bdPublisherVariables", "retrievePublisherVariables", ReplyPolicy::StructPublisherVariables},
            {104u, 6u, "bdMarketingComms", "getMessages", ReplyPolicy::StructMarketingMessagesEmpty},

            // IW8 ObjectStore startup stats path. Native 1.44 builds submit service
            // 0xC1/task 6 as ObjectsVectorizedResourceUsers/get_objects against
            // /v2/core/users/objects/. A fresh account receives per-object
            // Error:ClientError:NotFound entries; stock LiveStorage converts that
            // into RESET_STATS_REASON_NOT_FOUND and creates the six DDL stats blobs
            // locally before firing playerdata_available. Task 7 is the matching
            // vectorized upload path used once local objects are available.
            {193u, 6u, "bdObjectStore", "getUserObjectsVectorized", ReplyPolicy::StructObjectStoreVectorized},
            {193u, 7u, "bdObjectStore", "uploadUserObjectsVectorized", ReplyPolicy::StructObjectStoreUploadVectorized},
            // Stock OpenIW8 maps service 0xC1/task 0x10 to the vectorized
            // publisher-object metadata path.  The response parser explicitly
            // supports per-object errors.  A local preservation server with no
            // publisher cache therefore returns canonical ObjectStore NotFound
            // entries instead of leaving the remote task pending.
            {193u, 16u, "bdObjectStore", "getPublisherObjects", ReplyPolicy::StructObjectStorePublisherVectorizedNotFound},

            // Stock OpenIW8 maps task 8 to the single publisher-object metadata
            // + streaming path. Keep it named and diagnostic-only for now. The
            // request URL identifies the exact publisher/object needed if 0x10
            // still falls through to the single-object path.
            {193u, 8u, "bdObjectStore", "getPublisherObject", ReplyPolicy::None},

            // 1.20 sends AB testing enrollment as service 0xC2/task 1 using
            // bdHTTPProxyRequest. Stock bdABTestingEnrollResponse requires a
            // 200 status plus expiresIn, ABToken, and enrollments JSON fields.
            {194u, 1u, "bdABTesting", "enroll", ReplyPolicy::StructABTestingEnrollEmpty},

            {197u, 0x15u, "bdMW4Service", "getGroupInfos", ReplyPolicy::StructClanGroupInfosEmpty},
            {197u, 0x1Cu, "bdMW4Service", "getMembershipProposalsByUser", ReplyPolicy::StructClanProposalsEmpty},
            {197u, 0x1Eu, "bdMW4Service", "getMembershipsByUsers", ReplyPolicy::StructClanMembershipsEmpty},

            // Achievement Engine progression bootstrap. Stock OpenIW8 maps
            // service 0x7D/task 3 to getAchievementStates, task 5 to
            // activateAchievement, and task 9 to getUserState. Fresh local
            // accounts have no achievement-state rows, but task 3 still
            // requires an empty terminal page token. activateAchievement binds
            // no result object, so a normal no-result task success is its
            // native reply contract.
            {125u, 3u, "bdAchievementsEngineService", "getAchievementStates", ReplyPolicy::StructAchievementStatesEmpty},
            {125u, 5u, "bdAchievementsEngineService", "activateAchievement", ReplyPolicy::NoResultSuccess},
            {125u, 9u, "bdAchievementsEngineService", "getUserState", ReplyPolicy::StructAchievementsUserState},

            {198u, 0x0Cu, "bdMessaging", "channelUnsubscribeFromCategory", ReplyPolicy::StructMessagingUnsubscribeAck},

            // Stock bdRESTTaskManager uses service 0xFF / task 0x0A.
            // Only the reconstructed startup social reads below get replies.
            {255u, 0x0Au, "bdRESTLegacy", "request", ReplyPolicy::RestJsonSuccess},
        };

        std::uint32_t ReadLe32(const std::uint8_t* p)
        {
            return static_cast<std::uint32_t>(p[0]) |
                (static_cast<std::uint32_t>(p[1]) << 8) |
                (static_cast<std::uint32_t>(p[2]) << 16) |
                (static_cast<std::uint32_t>(p[3]) << 24);
        }

        void AppendLe16(std::vector<std::uint8_t>& out, std::uint16_t value)
        {
            out.push_back(static_cast<std::uint8_t>(value));
            out.push_back(static_cast<std::uint8_t>(value >> 8));
        }

        void AppendLe32(std::vector<std::uint8_t>& out, std::uint32_t value)
        {
            out.push_back(static_cast<std::uint8_t>(value));
            out.push_back(static_cast<std::uint8_t>(value >> 8));
            out.push_back(static_cast<std::uint8_t>(value >> 16));
            out.push_back(static_cast<std::uint8_t>(value >> 24));
        }

        void AppendLe64(std::vector<std::uint8_t>& out, std::uint64_t value)
        {
            AppendLe32(out, static_cast<std::uint32_t>(value));
            AppendLe32(out, static_cast<std::uint32_t>(value >> 32));
        }

        void AppendTypedBool(std::vector<std::uint8_t>& out, bool value)
        {
            out.push_back(kBbBool);
            out.push_back(value ? 1u : 0u);
        }

        void AppendTypedU8(std::vector<std::uint8_t>& out, std::uint8_t value)
        {
            out.push_back(kBbUnsignedChar8);
            out.push_back(value);
        }

        void AppendTypedU16(std::vector<std::uint8_t>& out, std::uint16_t value)
        {
            out.push_back(kBbUnsignedInteger16);
            AppendLe16(out, value);
        }

        void AppendTypedU32(std::vector<std::uint8_t>& out, std::uint32_t value)
        {
            out.push_back(kBbUnsignedInteger32);
            AppendLe32(out, value);
        }

        void AppendTypedU64(std::vector<std::uint8_t>& out, std::uint64_t value)
        {
            out.push_back(kBbUnsignedInteger64);
            AppendLe64(out, value);
        }

        void AppendTypedFloat(std::vector<std::uint8_t>& out, float value)
        {
            std::uint32_t bits = 0;
            static_assert(sizeof(bits) == sizeof(value), "float32 size mismatch");
            std::memcpy(&bits, &value, sizeof(bits));
            out.push_back(kBbFloat32);
            AppendLe32(out, bits);
        }

        void AppendTypedString(std::vector<std::uint8_t>& out, const std::string& value)
        {
            out.push_back(kBbString);
            out.insert(out.end(), value.begin(), value.end());
            out.push_back(0u);
        }

        void AppendTypedBlob(std::vector<std::uint8_t>& out, const void* data, std::size_t size)
        {
            if (size > (std::numeric_limits<std::uint32_t>::max)())
                return;

            out.push_back(kBbBlob);
            AppendTypedU32(out, static_cast<std::uint32_t>(size));
            if (size && data)
            {
                const auto* bytes = static_cast<const std::uint8_t*>(data);
                out.insert(out.end(), bytes, bytes + size);
            }
        }

        void AppendTypedStruct(std::vector<std::uint8_t>& out, const std::vector<std::uint8_t>& body)
        {
            out.push_back(kBbStruct);
            AppendTypedU32(out, static_cast<std::uint32_t>(body.size()));
            out.insert(out.end(), body.begin(), body.end());
            out.push_back(kBbStructEnd);
        }

        void AppendPbVarint(std::vector<std::uint8_t>& out, std::uint64_t value)
        {
            do
            {
                std::uint8_t byte = static_cast<std::uint8_t>(value & 0x7Fu);
                value >>= 7u;
                if (value)
                    byte |= 0x80u;
                out.push_back(byte);
            } while (value);
        }

        bool ReadPbVarint(const std::uint8_t*& cursor, const std::uint8_t* end, std::uint64_t& value)
        {
            value = 0;
            unsigned shift = 0;
            while (cursor < end && shift < 64u)
            {
                const std::uint8_t byte = *cursor++;
                value |= static_cast<std::uint64_t>(byte & 0x7Fu) << shift;
                if ((byte & 0x80u) == 0)
                    return true;
                shift += 7u;
            }
            return false;
        }

        void AppendPbTag(std::vector<std::uint8_t>& out, std::uint32_t tag, std::uint8_t wireType)
        {
            AppendPbVarint(out, (static_cast<std::uint64_t>(tag) << 3u) | wireType);
        }

        void AppendPbU32(std::vector<std::uint8_t>& out, std::uint32_t tag, std::uint32_t value)
        {
            AppendPbTag(out, tag, 0u);
            AppendPbVarint(out, value);
        }

        void AppendPbU64(std::vector<std::uint8_t>& out, std::uint32_t tag, std::uint64_t value)
        {
            AppendPbTag(out, tag, 0u);
            AppendPbVarint(out, value);
        }

        void AppendPbBool(std::vector<std::uint8_t>& out, std::uint32_t tag, bool value)
        {
            AppendPbTag(out, tag, 0u);
            AppendPbVarint(out, value ? 1u : 0u);
        }

        void AppendPbBytes(std::vector<std::uint8_t>& out, std::uint32_t tag,
            const void* data, std::size_t size)
        {
            AppendPbTag(out, tag, 2u);
            AppendPbVarint(out, static_cast<std::uint64_t>(size));
            if (size && data)
            {
                const auto* bytes = static_cast<const std::uint8_t*>(data);
                out.insert(out.end(), bytes, bytes + size);
            }
        }

        void AppendPbString(std::vector<std::uint8_t>& out, std::uint32_t tag, const std::string& value)
        {
            AppendPbBytes(out, tag, value.data(), value.size());
        }

        void AppendPbObject(std::vector<std::uint8_t>& out, std::uint32_t tag,
            const std::vector<std::uint8_t>& object)
        {
            AppendPbBytes(out, tag, object.data(), object.size());
        }

        struct PbField
        {
            std::uint32_t tag = 0;
            std::uint8_t wireType = 0;
            std::uint64_t varint = 0;
            const std::uint8_t* bytes = nullptr;
            std::size_t bytesSize = 0;
        };

        bool NextPbField(const std::uint8_t*& cursor, const std::uint8_t* end, PbField& field)
        {
            if (!cursor || cursor >= end)
                return false;

            std::uint64_t key = 0;
            if (!ReadPbVarint(cursor, end, key))
                return false;

            field = {};
            field.tag = static_cast<std::uint32_t>(key >> 3u);
            field.wireType = static_cast<std::uint8_t>(key & 7u);
            if (!field.tag)
                return false;

            switch (field.wireType)
            {
            case 0u:
                return ReadPbVarint(cursor, end, field.varint);

            case 1u:
                if (static_cast<std::size_t>(end - cursor) < 8u)
                    return false;
                field.bytes = cursor;
                field.bytesSize = 8u;
                cursor += 8u;
                return true;

            case 2u:
            {
                std::uint64_t len = 0;
                if (!ReadPbVarint(cursor, end, len) || len > static_cast<std::uint64_t>(end - cursor))
                    return false;
                field.bytes = cursor;
                field.bytesSize = static_cast<std::size_t>(len);
                cursor += field.bytesSize;
                return true;
            }

            case 5u:
                if (static_cast<std::size_t>(end - cursor) < 4u)
                    return false;
                field.bytes = cursor;
                field.bytesSize = 4u;
                cursor += 4u;
                return true;

            default:
                return false;
            }
        }

        bool ExtractTypedStructBody(const std::uint8_t* payload, std::size_t payloadBytes,
            const std::uint8_t*& body, std::size_t& bodyBytes)
        {
            body = nullptr;
            bodyBytes = 0;
            if (!payload || payloadBytes < 7u || payload[0] != kBbStruct || payload[1] != kBbUnsignedInteger32)
                return false;

            const std::uint32_t declared = ReadLe32(payload + 2u);
            const std::size_t bodyOffset = 6u;
            if (declared > payloadBytes - bodyOffset)
                return false;

            body = payload + bodyOffset;
            bodyBytes = declared;

            // Stock writeStructEnd emits one trailing 0 marker. Permit an exact
            // envelope or extra task-buffer padding after the struct.
            if (payloadBytes > bodyOffset + bodyBytes && payload[bodyOffset + bodyBytes] != kBbStructEnd)
                return false;
            return true;
        }
    }
}
