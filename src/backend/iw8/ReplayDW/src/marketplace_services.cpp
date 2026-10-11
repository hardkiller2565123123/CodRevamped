#include "host_os.h"
#include "marketplace_services.h"
#include "achievement_services.h"
#include "protobuf.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>
#include <chrono>
#include <algorithm>
#include <charconv>
#include <set>
#include <map>
#include <memory>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;
        wire::Bytes inventoryItem(const Json &);
        void validatePurchaseReceipts(const Json &, uint32_t title, uint64_t user);

        void validateBalances(const Json &balances)
        {
            wire::require(balances.is_array() && balances.size() <= 16);
            std::set<uint8_t> currencies;
            for (const auto &row : balances)
            {
                wire::require(row.at("currency").is_number_unsigned() &&
                              row.at("currency").get<uint64_t>() <= 255);
                wire::require(currencies.insert(row.at("currency").get<uint8_t>()).second);
                const auto &amount = row.at("amount");
                wire::require(amount.is_number_integer() &&
                              (!amount.is_number_unsigned() ||
                               amount.get<uint64_t>() <= uint64_t(INT64_MAX)) &&
                              amount.get<int64_t>() >= 0);
                if (row.contains("source"))
                    wire::require(row.at("source").is_number_unsigned() &&
                                  row.at("source").get<uint64_t>() <= UINT16_MAX);
            }
        }

        void validateInventory(const Json &out)
        {
            wire::require(out.is_object() && out.at("items").is_array() &&
                          out.at("items").size() <= 15000);
            std::set<uint32_t> ids;
            for (const auto &item : out.at("items"))
            {
                (void)inventoryItem(item);
                wire::require(ids.insert(item.at("1").get<uint32_t>()).second);
            }
            validateBalances(out.at("balances"));
        }

        Json read(const std::filesystem::path &path)
        {
            if (!std::filesystem::exists(path))
                return Json{{"items", Json::array()}, {"balances", Json::array()}};
            if (std::filesystem::file_size(path) > 4 * 1024 * 1024)
                throw std::runtime_error("Marketplace store size invalid");
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Marketplace store read failed");
            auto out = Json::parse(stream);
            try
            {
                validateInventory(out);
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Marketplace store schema invalid");
            }
            return out;
        }

        std::filesystem::path store(const std::filesystem::path &directory,
                                    const platform::LobbyIdentity &id)
        {
            return directory / "marketplace" / std::to_string(id.titleId) /
                   std::to_string(id.userId) / "inventory.json";
        }

        std::string fingerprint(const std::string &bytes)
        {
            const auto hash = crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()));
            std::string out;
            for (unsigned i = 0; i < 8; ++i)
            {
                out += "0123456789abcdef"[hash[i] >> 4];
                out += "0123456789abcdef"[hash[i] & 15];
            }
            return out;
        }

        std::string digest(const std::string &value)
        {
            const auto hash = crypto::sha256(
                std::span(reinterpret_cast<const uint8_t *>(value.data()), value.size()));
            std::string out;
            for (auto byte : hash)
            {
                out += "0123456789abcdef"[byte >> 4];
                out += "0123456789abcdef"[byte & 15];
            }
            return out;
        }

        bool hashText(const std::string &value)
        {
            return value.size() == 64 && std::all_of(value.begin(),
                                                     value.end(),
                                                     [](char c)
                                                     {
                                                         return (c >= '0' && c <= '9') ||
                                                                (c >= 'a' && c <= 'f');
                                                     });
        }

        void saveInventory(const std::filesystem::path &path,
                           const Json &data,
                           size_t limit = 4 * 1024 * 1024)
        {
            const auto bytes = data.dump();
            if (bytes.size() > limit)
                throw std::runtime_error("Marketplace store capacity exceeded");
            std::filesystem::create_directories(path.parent_path());
            auto pending = path;
            pending += ".pending";
            // A journal must reach disk before any account checkpoint. Flushing
            // the C++ stream alone only drains its userspace buffer.
            const auto handle = CreateFileW(pending.c_str(),
                                            GENERIC_WRITE,
                                            0,
                                            nullptr,
                                            CREATE_ALWAYS,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
            if (handle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Marketplace store write open failed");
            {
                const std::unique_ptr<void, decltype(&CloseHandle)> file(handle, &CloseHandle);
                DWORD written = 0;
                if (!WriteFile(handle,
                               bytes.data(),
                               static_cast<DWORD>(bytes.size()),
                               &written,
                               nullptr) ||
                    written != bytes.size() || !FlushFileBuffers(handle))
                    throw std::runtime_error("Marketplace store write/flush failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Marketplace publication failed");
        }

        std::filesystem::path purchaseJournal(const std::filesystem::path &directory,
                                              uint32_t title)
        {
            return directory / "marketplace" / std::to_string(title) / "pending-purchase.json";
        }

        void recoverPurchase(const std::filesystem::path &directory,
                             const platform::LobbyIdentity &id)
        {
            const auto path = purchaseJournal(directory, id.titleId);
            if (!std::filesystem::exists(path))
                return;
            if (std::filesystem::file_size(path) > 64 * 1024 * 1024)
                throw std::runtime_error("Marketplace purchase journal size invalid");
            std::ifstream stream(path);
            if (!stream)
                throw std::runtime_error("Marketplace purchase journal read failed");
            auto journal = Json::parse(stream);
            stream.close();
            std::vector<std::pair<std::filesystem::path, Json>> checkpoints;
            try
            {
                const auto checksum = journal.at("checksum").get<std::string>();
                journal.erase("checksum");
                wire::require(hashText(checksum) && checksum == digest(journal.dump()) &&
                              journal.size() == 7 && journal.at("schema") == 1 &&
                              journal.at("title").is_number_unsigned() &&
                              journal.at("title") == id.titleId &&
                              journal.at("buyer").is_number_unsigned());
                const auto &owners = journal.at("owners");
                wire::require(owners.is_array());
                const auto buyer = journal.at("buyer").get<uint64_t>();
                const auto transaction = journal.at("transaction").get<std::string>();
                wire::require(buyer && buyer != UINT64_MAX && !transaction.empty() &&
                              transaction.size() < 25 &&
                              transaction.find('\0') == std::string::npos &&
                              hashText(journal.at("request").get<std::string>()));
                const auto &phase = journal.at("phase");
                wire::require((phase == "applied" && owners.empty()) ||
                              (phase == "prepared" && owners.size() > 1 && owners.size() <= 256));
                if (phase == "applied")
                    return;
                std::set<uint64_t> users;
                bool haveBuyer = false;
                for (const auto &entry : owners)
                {
                    wire::require(entry.is_object() && entry.size() == 4 &&
                                  entry.at("owner").is_number_unsigned());
                    const auto user = entry.at("owner").get<uint64_t>();
                    wire::require(user && user != UINT64_MAX && users.insert(user).second);
                    const auto &after = entry.at("after");
                    validateInventory(after);
                    validatePurchaseReceipts(after, id.titleId, user);
                    wire::require(after.dump().size() <= 4 * 1024 * 1024 &&
                                  hashText(entry.at("after_checksum").get<std::string>()) &&
                                  digest(after.dump()) ==
                                      entry.at("after_checksum").get<std::string>());
                    auto owner = id;
                    owner.userId = user;
                    const auto accountPath = store(directory, owner);
                    const auto current = std::filesystem::exists(accountPath)
                                             ? Json(digest(read(accountPath).dump()))
                                             : Json(nullptr);
                    const auto &before = entry.at("before_checksum");
                    wire::require(before.is_null() ||
                                  (before.is_string() && hashText(before.get<std::string>())));
                    // Recovery accepts either the old image or a completed
                    // checkpoint. A conflicting external edit is never overwritten.
                    wire::require(current == before || current == entry.at("after_checksum"));
                    if (user == buyer)
                    {
                        const auto &receipt =
                            after.at("purchases")
                                .at(digest(std::to_string(id.titleId) + "\n" + transaction));
                        wire::require(receipt.at("owner") == buyer &&
                                      receipt.at("title") == id.titleId &&
                                      receipt.at("transaction") == transaction &&
                                      receipt.at("request") == journal.at("request"));
                        auto receiptBody = receipt;
                        receiptBody.erase("checksum");
                        wire::require(receipt.at("checksum") == digest(receiptBody.dump()));
                        haveBuyer = true;
                    }
                    if (current != entry.at("after_checksum"))
                        checkpoints.emplace_back(accountPath, after);
                }
                wire::require(haveBuyer);
            }
            catch (const std::exception &)
            {
                throw std::runtime_error(
                    "Marketplace purchase journal schema or checkpoint invalid");
            }
            // services::storeMutex excludes other marketplace readers/writers.
            // Validate every checkpoint before touching the first account.
            for (const auto &[accountPath, after] : checkpoints)
                saveInventory(accountPath, after);
            journal["phase"] = "applied";
            journal["owners"] = Json::array();
            journal["checksum"] = digest(journal.dump());
            saveInventory(path, journal);
        }

        void account(wire::Bytes &out, uint64_t user)
        {
            proto::integer(out, 1, user);
            proto::text(out, 2, "bnet");
        }

        std::string text(const proto::Field &field, size_t capacity)
        {
            wire::require(field.type == 2 && field.bytes.size() < capacity);
            std::string out(reinterpret_cast<const char *>(field.bytes.data()), field.bytes.size());
            wire::require(out.find('\0') == std::string::npos);
            return out;
        }

        wire::Bytes inventoryItem(const Json &item)
        {
            // Full native bdMarketplaceInventoryItemInfoV2, 0x142166800. Keep optional
            // metadata on every object rather than publishing only ID/quantity fields.
            wire::require(item.is_object());
            wire::Bytes out;
            std::set<unsigned> fields;
            for (auto entry = item.begin(); entry != item.end(); ++entry)
            {
                unsigned tag = 0;
                const auto key = entry.key();
                const auto parsed = std::from_chars(key.data(), key.data() + key.size(), tag);
                wire::require(parsed.ec == std::errc{} && parsed.ptr == key.data() + key.size() &&
                              fields.insert(tag).second);
            }
            wire::require(item.contains("1") && item.contains("2"));
            for (unsigned tag = 1; tag <= 22; ++tag)
            {
                if (tag == 12)
                {
                    wire::require(!fields.contains(tag));
                    continue;
                }
                const auto key = std::to_string(tag);
                if (tag == 4)
                {
                    const auto bytes = item.value(key, Json::array());
                    wire::require(bytes.is_array() && bytes.size() <= 64);
                    wire::Bytes data;
                    for (const auto &value : bytes)
                    {
                        wire::require(value.is_number_unsigned() && value.get<uint64_t>() <= 255);
                        data.push_back(value.get<uint8_t>());
                    }
                    proto::bytes(out, tag, data);
                }
                else if (tag == 5 || tag == 16 || tag == 17)
                {
                    const auto value = item.value(key, Json(false));
                    wire::require(value.is_boolean());
                    proto::integer(out, tag, value.get<bool>());
                }
                else if (tag == 13 || tag == 14 || tag == 15 || tag == 20)
                {
                    const auto value = item.value(key, Json(""));
                    wire::require(value.is_string());
                    const auto data = value.get<std::string>();
                    wire::require(data.size() < (tag == 13 ? 770u : 11u) &&
                                  data.find('\0') == std::string::npos);
                    proto::text(out, tag, data);
                }
                else if (tag == 10)
                {
                    const auto value = item.value(key, Json(int64_t{0}));
                    wire::require(value.is_number_integer() &&
                                  (!value.is_number_unsigned() ||
                                   value.get<uint64_t>() <= uint64_t(INT64_MAX)));
                    proto::signedInteger(out, tag, value.get<int64_t>());
                }
                else
                {
                    const auto value = item.value(key, Json(uint64_t{0}));
                    wire::require(value.is_number_unsigned());
                    const auto number = value.get<uint64_t>();
                    wire::require(number <= (tag == 9 ? UINT16_MAX : UINT32_MAX));
                    proto::integer(out, tag, number);
                }
            }
            for (auto tag : fields)
                wire::require(tag >= 1 && tag <= 22 && tag != 12);
            wire::require(item.at("1").get<uint32_t>() > 0);
            return out;
        }

        Reply inventory(const std::filesystem::path &directory,
                        const platform::LobbyIdentity &id,
                        wire::Reader &p)
        {
            // 80/69, request 0x14214D8F0, response 0x14214D750. The response account is
            // a structured object, not the ordinary bdUserAccountID byte-buffer layout.
            proto::Reader reader{p.structure(16 * 1024)};
            proto::Field f;
            std::string context, page;
            uint64_t maximum = 0;
            unsigned seen = 0;
            std::set<uint32_t> filters;
            while (reader.next(f))
            {
                wire::require(f.tag >= 1 && f.tag <= 4);
                if (f.tag != 4)
                {
                    wire::require(!(seen & (1U << f.tag)));
                    seen |= 1U << f.tag;
                }
                if (f.tag == 1)
                    context = text(f, 17);
                else if (f.tag == 2)
                    page = text(f, 65);
                else
                {
                    wire::require(f.type == 0 && f.value <= UINT32_MAX);
                    if (f.tag == 3)
                        maximum = f.value;
                    else
                        wire::require(filters.size() < 1000 &&
                                      filters.insert(static_cast<uint32_t>(f.value)).second);
                }
            }
            wire::require(seen == 14 && context == std::to_string(id.titleId) && maximum > 0 &&
                          maximum <= 1000);
            const auto data = read(store(directory, id));
            std::vector<Json> items;
            std::set<uint32_t> ids;
            for (const auto &item : data.at("items"))
            {
                (void)inventoryItem(item);
                const auto itemId = item.at("1").get<uint32_t>();
                wire::require(ids.insert(itemId).second);
                if (filters.empty() || filters.contains(itemId))
                    items.push_back(item);
            }
            std::sort(items.begin(),
                      items.end(),
                      [](const auto &a, const auto &b)
                      {
                          return a.at("1").template get<uint32_t>() <
                                 b.at("1").template get<uint32_t>();
                      });
            const auto digest = fingerprint(Json(items).dump());
            size_t start = 0;
            if (!page.empty())
            {
                wire::require(page.starts_with(digest + ":"));
                const auto value = page.substr(17);
                const auto parsed =
                    std::from_chars(value.data(), value.data() + value.size(), start);
                wire::require(parsed.ec == std::errc{} &&
                              parsed.ptr == value.data() + value.size() && start < items.size());
            }
            const auto end = std::min(items.size(), start + static_cast<size_t>(maximum));
            Reply reply{0, {}, "inventory-read", true, {}};
            wire::Bytes owner;
            account(owner, id.userId);
            proto::bytes(reply.structure, 1, owner);
            proto::text(reply.structure, 2, context);
            proto::text(
                reply.structure, 3, end < items.size() ? digest + ":" + std::to_string(end) : "");
            for (size_t i = start; i < end; ++i)
                proto::bytes(reply.structure, 4, inventoryItem(items[i]));
            wire::require(reply.structure.size() <= 256 * 1024);
            return reply;
        }

        Reply balances(const std::filesystem::path &directory,
                       const platform::LobbyIdentity &id,
                       wire::Reader &p)
        {
            // 80/245, full sixteen-element bdGetPlayerBalancesResponse. Currency entry
            // is UByte8 currency, ZigZag Int64 amount, UInt16 collision/source field.
            proto::Reader reader{p.structure(1024)};
            proto::Field f;
            std::string context;
            uint64_t maximum = 0;
            unsigned seen = 0;
            while (reader.next(f))
            {
                wire::require(f.tag >= 1 && f.tag <= 2 && !(seen & (1U << f.tag)));
                seen |= 1U << f.tag;
                if (f.tag == 1)
                    context = text(f, 17);
                else
                {
                    wire::require(f.type == 0);
                    maximum = f.value;
                }
            }
            wire::require(seen == 6 && context == std::to_string(id.titleId) && maximum > 0 &&
                          maximum <= 16);
            Reply reply{0, {}, "balances-read", true, {}};
            const auto data = read(store(directory, id));
            std::set<uint8_t> currencies;
            for (const auto &balance : data.at("balances"))
            {
                wire::require(balance.at("currency").is_number_unsigned() &&
                              balance.at("currency").get<uint64_t>() <= 255);
                const auto currency = balance.at("currency").get<uint8_t>();
                wire::require(currencies.insert(currency).second);
                wire::require(balance.at("amount").is_number_integer());
                const auto amount = balance.at("amount").get<int64_t>();
                wire::require(amount >= 0);
                const auto source = balance.value("source", uint64_t{0});
                wire::require(source <= UINT16_MAX);
                if (currencies.size() > maximum)
                    continue;
                wire::Bytes row;
                proto::integer(row, 1, currency);
                proto::signedInteger(row, 2, amount);
                proto::integer(row, 3, source);
                proto::bytes(reply.structure, 1, row);
            }
            return reply;
        }

        Reply legacyBalances(const std::filesystem::path &directory,
                             const platform::LobbyIdentity &id,
                             wire::Reader &p)
        {
            // Replay constructor 1421292E0: context/UInt32 capacity. Target reader
            // 14215E8C0 consumes UByte8/UInt32, unlike the newer Int64 struct DTO.
            const auto context = p.text(16);
            const auto maximum = p.u32();
            p.end();
            wire::require(context == std::to_string(id.titleId) && maximum > 0 && maximum <= 16);
            const auto data = read(store(directory, id));
            Reply reply{0, {}, "legacy-balances-read"};
            for (const auto &row : data.at("balances"))
            {
                const auto amount = row.at("amount").get<uint64_t>();
                if (amount > UINT32_MAX)
                    return {102, {}, "legacy-balance-out-of-range"};
                if (reply.results.size() >= maximum)
                    continue;
                wire::Writer out;
                out.u8(row.at("currency").get<uint8_t>());
                out.u32(static_cast<uint32_t>(amount));
                reply.results.push_back(std::move(out.data));
            }
            return reply;
        }

        uint64_t catalogNumber(const Json &row, const char *key, uint64_t maximum)
        {
            const auto &value = row.at(key);
            wire::require(value.is_number_unsigned() && value.get<uint64_t>() <= maximum);
            return value.get<uint64_t>();
        }

        wire::Bytes sku(const Json &row)
        {
            // Complete bdMarketplaceSku::deserialize in this Replay, 142339400.
            // All fields remain present; a price count is UInt32, each price is u8/u32.
            wire::Writer out;
            const auto skuId = catalogNumber(row, "id", UINT32_MAX);
            wire::require(skuId > 0);
            out.u32(static_cast<uint32_t>(skuId));
            out.u32(static_cast<uint32_t>(catalogNumber(row, "product", UINT32_MAX)));
            out.u8(static_cast<uint8_t>(catalogNumber(row, "type", UINT8_MAX)));
            out.blob(wire::base64(row.at("data").get<std::string>(), 64));
            out.u8(static_cast<uint8_t>(catalogNumber(row, "ignore_entitlements", UINT8_MAX)));
            for (const auto *key : {"sale_start", "sale_end", "rental_duration"})
                out.u32(static_cast<uint32_t>(catalogNumber(row, key, UINT32_MAX)));
            out.blob(wire::base64(row.at("promotional").get<std::string>(), 1536));
            out.u32(static_cast<uint32_t>(catalogNumber(row, "original", UINT32_MAX)));
            out.u16(static_cast<uint16_t>(catalogNumber(row, "collision", UINT16_MAX)));
            out.u32(static_cast<uint32_t>(catalogNumber(row, "modified", UINT32_MAX)));
            out.u8(static_cast<uint8_t>(catalogNumber(row, "coupon_enabled", UINT8_MAX)));
            const auto &prices = row.at("prices");
            wire::require(prices.is_array() && prices.size() <= 10);
            out.u32(static_cast<uint32_t>(prices.size()));
            std::set<uint8_t> seen;
            for (const auto &price : prices)
            {
                const auto currency =
                    static_cast<uint8_t>(catalogNumber(price, "currency", UINT8_MAX));
                wire::require(seen.insert(currency).second);
                out.u8(currency);
                out.u32(static_cast<uint32_t>(catalogNumber(price, "amount", UINT32_MAX)));
            }
            return std::move(out.data);
        }

        Json publishedCatalog(const std::filesystem::path &directory,
                              const platform::LobbyIdentity &id)
        {
            const auto path =
                directory / "marketplace" / std::to_string(id.titleId) / "catalog.json";
            if (!std::filesystem::exists(path))
                return nullptr;
            if (std::filesystem::file_size(path) > 4 * 1024 * 1024)
                throw std::runtime_error("Marketplace catalog size invalid");
            std::ifstream in(path);
            if (!in)
                throw std::runtime_error("Marketplace catalog read failed");
            auto data = Json::parse(in);
            std::set<uint32_t> ids;
            try
            {
                wire::require(data.at("schema") == 1 && data.at("skus").is_array() &&
                              data.at("skus").size() <= 1024);
                for (const auto &row : data.at("skus"))
                {
                    (void)sku(row);
                    wire::require(ids.insert(row.at("id").get<uint32_t>()).second &&
                                  row.at("enabled").is_boolean());
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Marketplace catalog schema invalid");
            }
            return data;
        }

        Reply catalog(const std::filesystem::path &directory,
                      const platform::LobbyIdentity &id,
                      wire::Reader &p)
        {
            // 1421293F0 is 80/134 getSkus, despite some database inventory labels.
            const auto context = p.text(16);
            const auto maximum = p.u16();
            const bool showAll = p.boolean();
            std::set<uint32_t> filters;
            while (p.more())
            {
                wire::require(filters.size() < 255);
                const auto item = p.u32();
                wire::require(item > 0 && item != UINT32_MAX && filters.insert(item).second);
            }
            p.end();
            wire::require(context == std::to_string(id.titleId) && maximum > 0 && maximum <= 1000);
            const auto data = publishedCatalog(directory, id);
            if (data.is_null())
                return {0, {}, "marketplace-catalog-empty"};
            auto rows = data.at("skus");
            std::sort(rows.begin(),
                      rows.end(),
                      [](const auto &a, const auto &b)
                      {
                          return a.at("id") < b.at("id");
                      });
            Reply reply{0, {}, "marketplace-catalog-read"};
            size_t size = 0;
            for (const auto &row : rows)
            {
                if ((!showAll && !row.at("enabled").get<bool>()) ||
                    (!filters.empty() && !filters.contains(row.at("id").get<uint32_t>())))
                    continue;
                if (reply.results.size() < maximum)
                {
                    auto result = sku(row);
                    size += result.size();
                    if (size > 256 * 1024)
                        return {102, {}, "marketplace-catalog-response-too-large"};
                    reply.results.push_back(std::move(result));
                }
            }
            return reply;
        }

        std::string purchaseChecksum(Json receipt)
        {
            receipt.erase("checksum");
            return digest(receipt.dump());
        }

        struct PurchaseRequest
        {
            std::string context, transaction;
            Json orders = Json::array(), metadata = Json::array();
            uint32_t maximum = 0, source = 0;
            bool ignoreEntitlements = false, assetsV3 = false;
        };
        wire::Bytes couponV4(const Json &coupon)
        try
        {
            // Replay 14215DE20: the byte after rental duration is its UNIT. The
            // signed field is penalty percentage; neither field is a SKU type.
            wire::Writer out;
            const auto key = coupon.at("id").get<std::string>();
            wire::require(!key.empty() && key.size() < 25);
            out.text(key);
            out.u64(catalogNumber(coupon, "owner", UINT64_MAX - 1));
            out.text("uno");
            wire::require(coupon.at("claimed").is_boolean());
            out.boolean(coupon.at("claimed").get<bool>());
            out.u32(static_cast<uint32_t>(catalogNumber(coupon, "product", UINT32_MAX)));
            out.u64(catalogNumber(coupon, "buyer", UINT64_MAX - 1));
            out.text("uno");
            out.u32(static_cast<uint32_t>(catalogNumber(coupon, "sku", UINT32_MAX)));
            out.u32(static_cast<uint32_t>(catalogNumber(coupon, "rental_duration", UINT32_MAX)));
            out.u8(static_cast<uint8_t>(catalogNumber(coupon, "rental_duration_unit", UINT8_MAX)));
            out.u32(static_cast<uint32_t>(catalogNumber(coupon, "expires", UINT32_MAX)));
            const auto &penalty = coupon.at("penalty_percentage");
            wire::require(penalty.is_number_integer());
            wire::require((!penalty.is_number_unsigned() || penalty.get<uint64_t>() <= INT32_MAX) &&
                          penalty.get<int64_t>() >= INT32_MIN &&
                          penalty.get<int64_t>() <= INT32_MAX);
            out.data.push_back(7);
            wire::raw(out.data, penalty.get<int32_t>());
            out.u32(static_cast<uint32_t>(catalogNumber(coupon, "product_expires", UINT32_MAX)));
            out.blob(wire::base64(coupon.at("metadata").get<std::string>(), 64));
            out.u32(static_cast<uint32_t>(catalogNumber(coupon, "source", UINT32_MAX)));
            out.u32(static_cast<uint32_t>(catalogNumber(coupon, "started", UINT32_MAX)));
            return std::move(out.data);
        }
        catch (const std::runtime_error &)
        {
            throw std::runtime_error("Marketplace coupon V4 publication invalid");
        }
        void playerAssetsV3(wire::Writer &out, const Json &inventory, uint64_t user)
        try
        {
            // Replay 142165A10 -> 142178CC0, 142179500, 142179110 and 14215DE20.
            // One enclosing account is read first. Currency/inventory/entitlement
            // elements inherit that account and MUST NOT repeat an account on wire.
            const auto &balances = inventory.at("balances");
            const auto &items = inventory.at("items");
            const auto entitlements = inventory.value("entitlements", Json::array());
            const auto coupons = inventory.value("coupons", Json::array());
            wire::require(balances.size() <= 10 && items.size() <= 2048 &&
                          entitlements.is_array() && entitlements.size() <= 1000 &&
                          coupons.is_array() && coupons.size() <= 2048);
            out.u64(user);
            out.text("uno");
            out.u32(static_cast<uint32_t>(balances.size()));
            for (const auto &balance : balances)
            {
                out.u8(balance.at("currency").get<uint8_t>());
                out.u32(static_cast<uint32_t>(catalogNumber(balance, "amount", UINT32_MAX)));
            }
            out.u32(static_cast<uint32_t>(items.size()));
            for (const auto &item : items)
            {
                (void)inventoryItem(item);
                for (const auto tag : {1, 2, 3})
                    out.u32(item.value(std::to_string(tag), uint32_t{0}));
                wire::Bytes data;
                for (const auto &byte : item.value("4", Json::array()))
                    data.push_back(byte.get<uint8_t>());
                out.blob(data);
                out.u32(item.value("6", uint32_t{0}));
                out.data.push_back(9);
                wire::raw(out.data, item.value("10", int64_t{0}));
                out.u16(item.value("9", uint16_t{0}));
                out.u32(item.value("8", uint32_t{0}));
                out.u32(item.value("11", uint32_t{0}));
            }
            out.u32(static_cast<uint32_t>(entitlements.size()));
            std::set<uint32_t> ids;
            for (const auto &entitlement : entitlements)
            {
                const auto key =
                    static_cast<uint32_t>(catalogNumber(entitlement, "id", UINT32_MAX));
                wire::require(ids.insert(key).second);
                out.u32(key);
                out.u32(static_cast<uint32_t>(catalogNumber(entitlement, "level", UINT32_MAX)));
            }
            out.u32(static_cast<uint32_t>(coupons.size()));
            std::set<std::string> couponIds;
            for (const auto &coupon : coupons)
            {
                wire::require(coupon.at("owner") == user &&
                              couponIds.insert(coupon.at("id").get<std::string>()).second);
                const auto bytes = couponV4(coupon);
                out.data.insert(out.data.end(), bytes.begin(), bytes.end());
            }
        }
        catch (const std::runtime_error &)
        {
            throw std::runtime_error("Marketplace PlayerAssetsV3 snapshot exceeds native layout or "
                                     "has invalid publication");
        }

        std::string purchaseRequestDigest(const PurchaseRequest &request)
        {
            Json body{{"orders", request.orders},
                      {"maximum", request.maximum},
                      {"source", request.source},
                      {"ignore_entitlements", request.ignoreEntitlements}};
            if (request.assetsV3)
            {
                body["format"] = 125;
                body["metadata"] = request.metadata;
            }
            return digest(body.dump());
        }

        void validatePurchaseReceipts(const Json &inventory, uint32_t title, uint64_t user)
        {
            const auto context = std::to_string(title);
            const auto receipts = inventory.value("purchases", Json::object());
            try
            {
                wire::require(receipts.is_object() && receipts.size() <= 4096);
                for (auto entry = receipts.begin(); entry != receipts.end(); ++entry)
                {
                    const auto &receipt = entry.value();
                    const auto saved = receipt.at("transaction").get<std::string>();
                    wire::require(!saved.empty() && saved.size() < 25 &&
                                  saved.find('\0') == std::string::npos &&
                                  receipt.at("schema") == 1);
                    const auto format = receipt.value("format", 106u);
                    wire::require(format == 106 || format == 125);
                    wire::require(receipt.at("title") == title && receipt.at("owner") == user &&
                                  receipt.at("context") == context);
                    wire::require(entry.key() == digest(context + "\n" + saved) &&
                                  hashText(receipt.at("request").get<std::string>()));
                    wire::require(receipt.at("recorded").is_number_unsigned() &&
                                  receipt.at("recorded").get<uint64_t>() <= UINT32_MAX);
                    if (receipt.contains("refresh_items"))
                    {
                        const auto &refresh = receipt.at("refresh_items");
                        wire::require(format == 106 && refresh.is_array() && !refresh.empty() &&
                                      refresh.size() <= 32 * 255);
                        uint32_t previous = 0;
                        for (const auto &item : refresh)
                        {
                            wire::require(item.is_number_unsigned() &&
                                          item.get<uint64_t>() > previous &&
                                          item.get<uint64_t>() <= INT32_MAX);
                            previous = item.get<uint32_t>();
                        }
                    }
                    wire::require(receipt.at("orders").is_array() &&
                                  !receipt.at("orders").empty() &&
                                  receipt.at("orders").size() <= 255);
                    for (const auto &order : receipt.at("orders"))
                    {
                        wire::require(catalogNumber(order, "sku", UINT32_MAX - 1) > 0 &&
                                      catalogNumber(order, "quantity", UINT32_MAX - 1) > 0);
                        (void)catalogNumber(order, "discount", UINT32_MAX - 1);
                        wire::require(catalogNumber(order, "recipient", UINT64_MAX - 1) > 0 &&
                                      (format == 106 || order.at("recipient") == user));
                        (void)wire::base64(order.at("metadata").get<std::string>(), 64);
                    }
                    (void)catalogNumber(receipt, "maximum", 255);
                    (void)catalogNumber(receipt, "source", format == 106 ? 255 : UINT32_MAX);
                    wire::require(receipt.at("ignore_entitlements").is_boolean());
                    const PurchaseRequest previous{context,
                                                   saved,
                                                   receipt.at("orders"),
                                                   receipt.value("metadata", Json::array()),
                                                   receipt.at("maximum").get<uint32_t>(),
                                                   receipt.at("source").get<uint32_t>(),
                                                   receipt.at("ignore_entitlements").get<bool>(),
                                                   format == 125};
                    wire::require(receipt.at("request") == purchaseRequestDigest(previous));
                    wire::require(hashText(receipt.at("checksum").get<std::string>()) &&
                                  receipt.at("checksum") == purchaseChecksum(receipt));
                    const auto response =
                        wire::base64(receipt.at("response").get<std::string>(), 128 * 1024);
                    wire::Reader decoded{response};
                    wire::require(decoded.text(25) == saved);
                    if (format == 106)
                        wire::require(decoded.u32() <= 255);
                    else
                        wire::require(decoded.u64() == user && decoded.text(10) == "uno");
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Marketplace purchase receipt schema invalid");
            }
        }

        Reply commitPurchase(const std::filesystem::path &directory,
                             const platform::LobbyIdentity &id,
                             const PurchaseRequest &input);

        std::vector<wire::Bytes> inventoryUpdates(const platform::LobbyIdentity &id,
                                                  const std::set<uint32_t> &selected,
                                                  const Json &inventory)
        {
            if (selected.empty())
                return {};
            // Same-Replay event 67 must first pass AchievementEvent (140F33650).
            // A kind-18 completion (140F34CA0) reaches the GRANT_PRODUCT reader
            // (141B3B6D0) without processing player/weapon progression. Use its
            // absolute quantities, not increments. Sale/smart SKU IDs do not
            // occur in bundle_ids.csv, so their purchase callback cannot expand
            // the base bundle locally. Notify its actual durable item records.
            std::map<uint32_t, uint32_t> quantities;
            for (const auto &item : inventory.at("items"))
                if (selected.contains(item.at("1").get<uint32_t>()))
                {
                    const auto quantity = item.at("2").get<uint32_t>();
                    wire::require(quantity > 0 && quantity <= INT32_MAX);
                    quantities.emplace(item.at("1").get<uint32_t>(), quantity);
                }
            wire::require(quantities.size() == selected.size());
            std::vector<wire::Bytes> messages;
            auto grant = quantities.begin();
            while (grant != quantities.end())
            {
                auto rows = Json::array();
                for (unsigned count = 0; count < 128 && grant != quantities.end(); ++count, ++grant)
                    rows.push_back({{"id", grant->first}, {"quantity", grant->second}});
                const auto body = Json{{"type", "ACHIEVEMENT"},
                                       {"name", "marketplace_inventory"},
                                       {"reason", "completed"},
                                       {"kind", 18},
                                       {"triggers",
                                        Json::array({{{"type", "GRANT_PRODUCT"},
                                                      {"inventory", {{"granted_items", rows}}}}})}}
                                      .dump();
                wire::require(body.size() < 16 * 1024);
                wire::Writer push;
                push.u32(67);
                push.u8(1);
                push.u64(id.userId);
                push.text("uno");
                push.text(std::to_string(id.titleId));
                push.data.push_back(7);
                wire::raw(push.data, int32_t{1});
                push.u32(1);
                push.data.push_back(7);
                wire::raw(push.data, int32_t{1});
                push.text(body);
                messages.push_back(std::move(push.data));
            }
            return messages;
        }

        Reply purchase(const std::filesystem::path &directory,
                       const platform::LobbyIdentity &id,
                       wire::Reader &p)
        {
            // Replay 1421295B0, service 80/task 106. Every optional array is either
            // absent (count zero) or has exactly the SKU count. Last fields are source
            // UByte8 then ignore-entitlements Bool, proven by 1420F0680/1420EFFA0.
            const auto context = p.text(16), transaction = p.text(25);
            const auto count = p.u32();
            wire::require(context == std::to_string(id.titleId) && count > 0 && count <= 255);
            auto orders = Json::array();
            for (uint32_t i = 0; i < count; ++i)
            {
                const auto skuId = p.u32();
                wire::require(skuId && skuId != UINT32_MAX);
                orders.push_back(Json{
                    {"sku", skuId}, {"discount", 0u}, {"recipient", id.userId}, {"metadata", ""}});
            }
            wire::require(p.u32() == count);
            for (auto &order : orders)
            {
                const auto quantity = p.u32();
                wire::require(quantity > 0 && quantity != UINT32_MAX);
                order["quantity"] = quantity;
            }
            const auto maximum = p.u32();
            wire::require(maximum <= 255);
            const auto discountCount = p.u32();
            wire::require(!discountCount || discountCount == count);
            for (uint32_t i = 0; i < discountCount; ++i)
            {
                const auto discount = p.u32();
                wire::require(discount != UINT32_MAX);
                orders.at(i)["discount"] = discount;
            }
            const auto recipientCount = p.u32();
            wire::require(!recipientCount || recipientCount == count);
            for (uint32_t i = 0; i < recipientCount; ++i)
            {
                auto recipient = p.u64();
                const auto accountType = p.text(10);
                wire::require(accountType.empty() || accountType == "uno" || accountType == "bnet");
                if (!recipient || recipient == UINT64_MAX)
                    recipient = id.userId;
                orders.at(i)["recipient"] = recipient;
            }
            const auto metadataCount = p.u32();
            wire::require(!metadataCount || metadataCount == count);
            for (uint32_t i = 0; i < metadataCount; ++i)
                orders.at(i)["metadata"] = wire::base64Encode(p.blob(64));
            const auto source = p.u8();
            const auto ignoreEntitlements = p.boolean();
            p.end();
            return commitPurchase(directory,
                                  id,
                                  {context,
                                   transaction,
                                   orders,
                                   Json::array(),
                                   maximum,
                                   source,
                                   ignoreEntitlements,
                                   false});
        }

        Reply purchaseV4(const std::filesystem::path &directory,
                         const platform::LobbyIdentity &id,
                         wire::Reader &p)
        {
            // Constructor 142129000 and builder 142128AC0. The last UInt32 is
            // customSourceType, NOT a maximum result count or the 106 source byte.
            PurchaseRequest input;
            input.assetsV3 = true;
            input.context = p.text(16);
            input.transaction = p.text(25);
            auto buyer = p.u64();
            const auto accountType = p.text(10);
            wire::require(input.context == std::to_string(id.titleId) &&
                          (accountType.empty() || accountType == "uno" || accountType == "bnet"));
            if (!buyer || buyer == UINT64_MAX)
                buyer = id.userId;
            if (buyer != id.userId)
                return {101, {}, "marketplace-buyer-denied"};
            const auto count = p.u32();
            wire::require(count <= 255);
            for (uint32_t i = 0; i < count; ++i)
            {
                const auto skuId = p.u32(), quantity = p.u32(), discount = p.u32();
                wire::require(skuId && skuId != UINT32_MAX && quantity && quantity != UINT32_MAX &&
                              discount != UINT32_MAX);
                Json order{{"sku", skuId},
                           {"quantity", quantity},
                           {"discount", discount},
                           {"recipient", id.userId},
                           {"metadata", ""},
                           {"expected_prices", Json::array()}};
                const auto prices = p.u32();
                wire::require(prices <= 10);
                std::set<uint8_t> currencies;
                for (uint32_t j = 0; j < prices; ++j)
                {
                    const auto currency = p.u8();
                    const auto amount = p.u32();
                    wire::require(amount != UINT32_MAX && currencies.insert(currency).second);
                    order["expected_prices"].push_back(
                        Json{{"currency", currency}, {"amount", amount}});
                }
                input.orders.push_back(std::move(order));
            }
            const auto couponOrders = p.u32();
            wire::require(couponOrders <= 255);
            // No native CouponOrderV2 serializer was recovered in this Replay image.
            // Never charge/claim an opaque coupon request as if it were an SKU order.
            if (couponOrders)
                return {108, {}, "marketplace-coupon-order-unavailable"};
            wire::require(count > 0);
            const auto entries = p.u32();
            wire::require(entries <= 255);
            std::set<std::string> keys;
            for (uint32_t i = 0; i < entries; ++i)
            {
                const auto key = p.text(16), value = p.text(256);
                wire::require(!key.empty() && keys.insert(key).second);
                input.metadata.push_back(Json{{"key", key}, {"value", value}});
            }
            input.source = p.u32();
            wire::require(input.source != UINT32_MAX);
            input.ignoreEntitlements = p.boolean();
            p.end();
            return commitPurchase(directory, id, input);
        }

        Reply commitPurchase(const std::filesystem::path &directory,
                             const platform::LobbyIdentity &id,
                             const PurchaseRequest &input)
        {
            const auto &context = input.context;
            const auto &transaction = input.transaction;
            const auto &orders = input.orders;
            const auto maximum = input.maximum, source = input.source;
            const auto ignoreEntitlements = input.ignoreEntitlements;
            const auto request = purchaseRequestDigest(input);
            const auto path = store(directory, id);
            auto inventory = read(path);
            auto receipts = inventory.value("purchases", Json::object());
            validatePurchaseReceipts(inventory, id.titleId, id.userId);
            if (!transaction.empty())
            {
                const auto key = digest(context + "\n" + transaction);
                if (receipts.contains(key))
                {
                    const auto &receipt = receipts.at(key);
                    wire::require(receipt.value("format", 106u) == (input.assetsV3 ? 125u : 106u) &&
                                  receipt.at("request") == request);
                    Reply reply{
                        0,
                        {wire::base64(receipt.at("response").get<std::string>(), 128 * 1024)},
                        "marketplace-purchase-retried"};
                    if (receipt.contains("refresh_items"))
                    {
                        const auto items = receipt.at("refresh_items").get<std::vector<uint32_t>>();
                        reply.pushes =
                            inventoryUpdates(id, {items.begin(), items.end()}, inventory);
                    }
                    return reply;
                }
            }
            const auto catalog = publishedCatalog(directory, id);
            const auto rulesPath =
                directory / "marketplace" / std::to_string(id.titleId) / "purchase-rules.json";
            if (catalog.is_null() || !std::filesystem::exists(rulesPath))
                return {108, {}, "marketplace-purchase-not-published"};
            if (std::filesystem::file_size(rulesPath) > 4 * 1024 * 1024)
                throw std::runtime_error("Marketplace purchase rules size invalid");
            std::ifstream in(rulesPath);
            if (!in)
                throw std::runtime_error("Marketplace purchase rules read failed");
            const auto rules = Json::parse(in);
            std::map<uint32_t, Json> definitions;
            std::map<uint32_t, Json> skus;
            for (const auto &row : catalog.at("skus"))
                skus.emplace(row.at("id").get<uint32_t>(), row);
            try
            {
                wire::require(rules.at("schema") == 1 && rules.at("rules").is_array() &&
                              rules.at("rules").size() <= 1024);
                for (const auto &rule : rules.at("rules"))
                {
                    const auto skuId =
                        static_cast<uint32_t>(catalogNumber(rule, "sku", UINT32_MAX));
                    wire::require(skus.contains(skuId) && definitions.emplace(skuId, rule).second);
                    wire::require(rule.at("enabled").is_boolean() &&
                                  rule.at("allow_ignore_entitlements").is_boolean());
                    if (rule.contains("allow_gifting"))
                        wire::require(rule.at("allow_gifting").is_boolean());
                    if (rule.contains("required_owned_items"))
                    {
                        const auto &required = rule.at("required_owned_items");
                        wire::require(required.is_array() && !required.empty() &&
                                      required.size() <= 32);
                        std::set<uint32_t> prerequisites;
                        for (const auto &value : required)
                            wire::require(value.is_number_unsigned() && value.get<uint64_t>() > 0 &&
                                          value.get<uint64_t>() < UINT32_MAX &&
                                          prerequisites.insert(value.get<uint32_t>()).second);
                    }
                    wire::require(catalogNumber(rule, "maximum_quantity", UINT32_MAX) > 0);
                    const auto &sources = rule.at("sources");
                    wire::require(sources.is_array() && !sources.empty() && sources.size() <= 256);
                    std::set<uint32_t> unique;
                    for (const auto &value : sources)
                    {
                        wire::require(value.is_number_unsigned() &&
                                      value.get<uint64_t>() < UINT32_MAX &&
                                      unique.insert(value.get<uint32_t>()).second);
                    }
                    const auto &items = rule.at("items");
                    wire::require(items.is_array() && items.size() <= 32);
                    std::set<uint32_t> itemIds;
                    for (const auto &item : items)
                    {
                        (void)inventoryItem(item);
                        wire::require(item.at("2").get<uint32_t>() > 0 &&
                                      itemIds.insert(item.at("1").get<uint32_t>()).second);
                    }
                    validateBalances(rule.at("currencies"));
                    for (const auto &currency : rule.at("currencies"))
                        wire::require(currency.at("amount").get<uint64_t>() > 0 &&
                                      currency.at("amount").get<uint64_t>() <= UINT32_MAX);
                    wire::require(!items.empty() || !rule.at("currencies").empty());
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Marketplace purchase rules schema invalid");
            }
            const auto stamp =
                static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
            std::map<uint8_t, uint64_t> costs;
            std::map<uint32_t, uint64_t> quantities;
            std::map<std::pair<uint64_t, uint32_t>, uint64_t> grants;
            std::set<uint32_t> refreshItems;
            std::map<uint64_t, Json> recipients;
            std::map<uint64_t, Json> beforeChecksums;
            size_t snapshotBytes = inventory.dump().size();
            beforeChecksums[id.userId] =
                std::filesystem::exists(path) ? Json(digest(inventory.dump())) : Json(nullptr);
            uint64_t couponCount = 0;
            for (const auto &order : orders)
            {
                const auto skuId = order.at("sku").get<uint32_t>(),
                           quantity = order.at("quantity").get<uint32_t>();
                if (!definitions.contains(skuId) || !skus.at(skuId).at("enabled").get<bool>() ||
                    !definitions.at(skuId).at("enabled").get<bool>())
                    return {108, {}, "marketplace-purchase-not-published"};
                const auto &definition = definitions.at(skuId);
                const auto &offer = skus.at(skuId);
                const auto original = offer.at("original").get<uint32_t>();
                if (!input.assetsV3 && order.at("recipient") == id.userId && original >= 400000 &&
                    original < 410000 && offer.at("product") == original &&
                    (skuId == original + 20000 || skuId == original + 60000))
                    for (const auto &item : definition.at("items"))
                    {
                        const auto itemId = item.at("1").get<uint32_t>();
                        wire::require(itemId > 0 && itemId <= INT32_MAX);
                        refreshItems.insert(itemId);
                    }
                // Replay selects its smart SKU only when the local buyer owns
                // smartID. Enforce the same entitlement against durable inventory
                // before prices, debits or grants; the request cannot supply it.
                if (definition.contains("required_owned_items"))
                    for (const auto &required : definition.at("required_owned_items"))
                        if (std::none_of(inventory.at("items").begin(),
                                         inventory.at("items").end(),
                                         [&](const auto &item)
                                         {
                                             return item.at("1") == required &&
                                                    item.at("2").template get<uint64_t>() > 0;
                                         }))
                            return {101, {}, "marketplace-smart-prerequisite-not-owned"};
                const auto recipient = order.at("recipient").get<uint64_t>();
                if (recipient != id.userId)
                {
                    if (!definition.value("allow_gifting", false))
                        return {108, {}, "marketplace-gift-not-published"};
                    if (!platform::accountName(recipient))
                        return {108, {}, "marketplace-gift-recipient-not-found"};
                    if (!recipients.contains(recipient))
                    {
                        auto owner = id;
                        owner.userId = recipient;
                        const auto recipientPath = store(directory, owner);
                        auto recipientInventory = read(recipientPath);
                        const auto snapshot = recipientInventory.dump();
                        if (snapshot.size() > 64 * 1024 * 1024 - snapshotBytes)
                            return {102, {}, "marketplace-gift-window-capacity-exceeded"};
                        snapshotBytes += snapshot.size();
                        beforeChecksums[recipient] = std::filesystem::exists(recipientPath)
                                                         ? Json(digest(snapshot))
                                                         : Json(nullptr);
                        recipients.emplace(recipient, std::move(recipientInventory));
                    }
                }
                if (order.at("discount") != 0)
                    return {108, {}, "marketplace-discount-not-published"};
                if (input.assetsV3 && !order.at("expected_prices").empty())
                {
                    std::map<uint8_t, uint32_t> expected, actual;
                    for (const auto &price : order.at("expected_prices"))
                        expected.emplace(price.at("currency").get<uint8_t>(),
                                         price.at("amount").get<uint32_t>());
                    for (const auto &price : offer.at("prices"))
                        actual.emplace(price.at("currency").get<uint8_t>(),
                                       price.at("amount").get<uint32_t>());
                    if (expected != actual)
                        return {101, {}, "marketplace-expected-price-mismatch"};
                }
                if (std::none_of(definition.at("sources").begin(),
                                 definition.at("sources").end(),
                                 [source](const auto &value)
                                 {
                                     return value == source;
                                 }))
                    return {108, {}, "marketplace-source-not-published"};
                if (ignoreEntitlements && !definition.at("allow_ignore_entitlements").get<bool>())
                    return {101, {}, "marketplace-entitlement-bypass-denied"};
                if ((offer.at("sale_start").get<uint32_t>() &&
                     offer.at("sale_start").get<uint32_t>() > stamp) ||
                    (offer.at("sale_end").get<uint32_t>() &&
                     offer.at("sale_end").get<uint32_t>() <= stamp))
                    return {108, {}, "marketplace-offer-not-active"};
                quantities[skuId] += quantity;
                grants[{recipient, skuId}] += quantity;
                if (quantities[skuId] > definition.at("maximum_quantity").get<uint32_t>())
                    return {102, {}, "marketplace-purchase-quantity-limit"};
                for (const auto &price : offer.at("prices"))
                {
                    const auto currency = price.at("currency").get<uint8_t>();
                    const auto unit = price.at("amount").get<uint32_t>();
                    const auto delta = uint64_t(unit) * quantity;
                    if (delta > uint64_t(INT64_MAX) - costs[currency])
                        return {102, {}, "marketplace-price-overflow"};
                    costs[currency] += delta;
                }
                if (offer.at("coupon_enabled").get<uint8_t>())
                    couponCount += quantity;
            }
            if (couponCount > 4096 || receipts.size() >= 4096)
                return {102, {}, "marketplace-purchase-receipt-capacity-exceeded"};
            // All order validation precedes durable mutations. A gift's complete
            // before/after images and exact response are journaled together.
            for (const auto &[currency, cost] : costs)
            {
                auto &balances = inventory["balances"];
                const auto found = std::find_if(balances.begin(),
                                                balances.end(),
                                                [currency](const auto &row)
                                                {
                                                    return row.at("currency") == currency;
                                                });
                const auto before =
                    found == balances.end() ? uint64_t{0} : found->at("amount").get<uint64_t>();
                if (before < cost)
                    return {101, {}, "marketplace-insufficient-balance"};
                if (found != balances.end())
                    (*found)["amount"] = before - cost;
            }
            for (const auto &[destination, quantity] : grants)
            {
                const auto [recipient, skuId] = destination;
                auto &target = recipient == id.userId ? inventory : recipients.at(recipient);
                const auto &definition = definitions.at(skuId);
                for (const auto &grant : definition.at("items"))
                {
                    auto &items = target["items"];
                    auto found = std::find_if(items.begin(),
                                              items.end(),
                                              [&](const auto &row)
                                              {
                                                  return row.at("1") == grant.at("1");
                                              });
                    const auto delta = quantity * grant.at("2").get<uint32_t>(),
                               before = found == items.end() ? uint64_t{0}
                                                             : found->at("2").get<uint32_t>();
                    if (delta > UINT32_MAX || before > UINT32_MAX - delta)
                        return {102, {}, "marketplace-inventory-overflow"};
                    const auto publishedLimit = grant.value("18", uint64_t{0});
                    const auto storedLimit =
                        found == items.end() ? uint64_t{0} : found->value("18", uint64_t{0});
                    // Existing inventory can predate this offer and omit a limit.
                    // It cannot relax the current publication's ownership policy.
                    const auto limit = publishedLimit && storedLimit
                                           ? std::min(publishedLimit, storedLimit)
                                           : std::max(publishedLimit, storedLimit);
                    if (limit && before + delta > limit)
                        return {102, {}, "marketplace-inventory-limit"};
                    if (found == items.end())
                    {
                        if (items.size() >= 15000)
                            return {102, {}, "marketplace-inventory-capacity-exceeded"};
                        auto item = grant;
                        item["2"] = delta;
                        items.push_back(item);
                    }
                    else
                        (*found)["2"] = before + delta;
                }
                for (const auto &grant : definition.at("currencies"))
                {
                    auto &balances = target["balances"];
                    auto found = std::find_if(balances.begin(),
                                              balances.end(),
                                              [&](const auto &row)
                                              {
                                                  return row.at("currency") == grant.at("currency");
                                              });
                    const auto delta = quantity * grant.at("amount").get<uint32_t>(),
                               before = found == balances.end()
                                            ? uint64_t{0}
                                            : found->at("amount").get<uint64_t>();
                    if (delta > uint64_t(INT64_MAX) || before > uint64_t(INT64_MAX) - delta)
                        return {102, {}, "marketplace-balance-overflow"};
                    if (found == balances.end())
                    {
                        if (balances.size() >= 16)
                            return {102, {}, "marketplace-balance-capacity-exceeded"};
                        auto balance = grant;
                        balance["amount"] = delta;
                        balances.push_back(balance);
                    }
                    else
                        (*found)["amount"] = before + delta;
                }
            }
            auto transactionId = transaction;
            if (transactionId.empty())
            {
                do
                {
                    const auto bytes = crypto::random(12);
                    transactionId.clear();
                    for (auto byte : bytes)
                    {
                        transactionId += "0123456789abcdef"[byte >> 4];
                        transactionId += "0123456789abcdef"[byte & 15];
                    }
                } while (receipts.contains(digest(context + "\n" + transactionId)));
            }
            wire::Writer response;
            response.text(transactionId);
            const auto couponMaximum =
                input.assetsV3 ? couponCount : std::min<uint64_t>(maximum, couponCount);
            if (input.assetsV3)
            {
                playerAssetsV3(response, inventory, id.userId);
                wire::require(couponCount <= 2048);
            }
            response.u32(static_cast<uint32_t>(couponMaximum));
            uint32_t emitted = 0;
            for (const auto &order : orders)
            {
                const auto skuId = order.at("sku").get<uint32_t>();
                const auto &offer = skus.at(skuId);
                if (!offer.at("coupon_enabled").get<uint8_t>())
                    continue;
                const auto rental = offer.at("rental_duration").get<uint32_t>();
                if (rental > UINT32_MAX - stamp)
                    return {102, {}, "marketplace-coupon-expiry-overflow"};
                for (uint32_t i = 0;
                     i < order.at("quantity").get<uint32_t>() && emitted < couponMaximum;
                     ++i, ++emitted)
                {
                    if (input.assetsV3)
                    {
                        Json coupon{
                            {"id",
                             digest(transactionId + "\n" + std::to_string(emitted)).substr(0, 24)},
                            {"owner", id.userId},
                            {"buyer", id.userId},
                            {"claimed", true},
                            {"product", offer.at("product")},
                            {"sku", skuId},
                            {"rental_duration", rental},
                            {"rental_duration_unit",
                             offer.value("rental_duration_unit", Json(uint32_t{0}))},
                            {"expires", rental ? stamp + rental : 0u},
                            {"penalty_percentage",
                             offer.value("penalty_percentage", Json(int32_t{0}))},
                            {"product_expires", offer.value("product_expires", Json(uint32_t{0}))},
                            {"metadata", offer.value("coupon_metadata", Json(""))},
                            {"source", source},
                            {"started", stamp}};
                        const auto bytes = couponV4(coupon);
                        response.data.insert(response.data.end(), bytes.begin(), bytes.end());
                        continue;
                    }
                    // Full bound 14215CF20 coupon DTO: ID/owner/claimed/product/buyer/
                    // SKU/rental/expiry/Int32 type. Grants are already applied locally.
                    response.text(
                        digest(transactionId + "\n" + std::to_string(emitted)).substr(0, 24));
                    response.u64(order.at("recipient").get<uint64_t>());
                    response.text("uno");
                    response.boolean(true);
                    response.u32(offer.at("product").get<uint32_t>());
                    response.u64(id.userId);
                    response.text("uno");
                    response.u32(skuId);
                    response.u32(rental);
                    response.u32(rental ? stamp + rental : 0);
                    response.data.push_back(7);
                    wire::raw(response.data, int32_t{offer.at("type").get<uint8_t>()});
                }
            }
            if (response.data.size() > 128 * 1024)
                return {102, {}, "marketplace-purchase-response-capacity-exceeded"};
            // Construct every notification before committing, so an invalid
            // native quantity cannot turn an acknowledged purchase into an error.
            auto notifications = inventoryUpdates(id, refreshItems, inventory);
            Json receipt{{"schema", 1},
                         {"title", id.titleId},
                         {"owner", id.userId},
                         {"context", context},
                         {"transaction", transactionId},
                         {"orders", orders},
                         {"maximum", maximum},
                         {"source", source},
                         {"ignore_entitlements", ignoreEntitlements},
                         {"request", request},
                         {"recorded", stamp},
                         {"response", wire::base64Encode(response.data)}};
            if (!refreshItems.empty())
                receipt["refresh_items"] =
                    std::vector<uint32_t>(refreshItems.begin(), refreshItems.end());
            receipt["checksum"] = purchaseChecksum(receipt);
            if (input.assetsV3)
            {
                receipt["format"] = 125;
                receipt["metadata"] = input.metadata;
                receipt["checksum"] = purchaseChecksum(receipt);
            }
            receipts[digest(context + "\n" + transactionId)] = receipt;
            inventory["purchases"] = receipts;
            if (recipients.empty())
                saveInventory(path, inventory);
            else
            {
                recipients.emplace(id.userId, std::move(inventory));
                Json journal{{"schema", 1},
                             {"title", id.titleId},
                             {"buyer", id.userId},
                             {"transaction", transactionId},
                             {"request", request},
                             {"phase", "prepared"},
                             {"owners", Json::array()}};
                wire::require(recipients.size() <= 256);
                for (const auto &[owner, after] : recipients)
                {
                    validateInventory(after);
                    if (after.dump().size() > 4 * 1024 * 1024)
                        return {102, {}, "marketplace-gift-store-capacity-exceeded"};
                    journal["owners"].push_back(Json{{"owner", owner},
                                                     {"before_checksum", beforeChecksums.at(owner)},
                                                     {"after", after},
                                                     {"after_checksum", digest(after.dump())}});
                }
                journal["checksum"] = digest(journal.dump());
                // Publication is the commit decision. If a checkpoint fails, all
                // marketplace access first rolls it forward, including after restart.
                saveInventory(purchaseJournal(directory, id.titleId), journal, 64 * 1024 * 1024);
                recoverPurchase(directory, id);
            }
            Reply reply{0, {std::move(response.data)}, "marketplace-purchase-committed"};
            reply.pushes = std::move(notifications);
            return reply;
        }

        wire::Bytes grantedItem(const Json &item)
        {
            // Replay result vtable 1426A4A50 -> 14214DC60 reads field-1 granted
            // items (142166BA0) and field-2 currency grants (142166E70).
            (void)inventoryItem(item);
            wire::Bytes out;
            proto::integer(out, 1, item.at("1").get<uint32_t>());
            for (const auto [target, source] :
                 {std::pair{2, 13}, std::pair{3, 14}, std::pair{4, 15}})
            {
                const auto value = item.value(std::to_string(source), std::string());
                wire::require(value.size() < (target == 2 ? 769u : 10u));
                proto::text(out, target, value);
            }
            wire::Bytes data;
            for (const auto &value : item.value("4", Json::array()))
                data.push_back(value.get<uint8_t>());
            proto::bytes(out, 5, data);
            for (const auto [target, source] : {std::pair{6, 2},
                                                std::pair{7, 3},
                                                std::pair{8, 9},
                                                std::pair{9, 6},
                                                std::pair{11, 8},
                                                std::pair{12, 7},
                                                std::pair{15, 18},
                                                std::pair{16, 19}})
                proto::integer(out, target, item.value(std::to_string(source), uint64_t{0}));
            proto::signedInteger(out, 10, item.value("10", int64_t{0}));
            proto::integer(out, 13, 1);
            proto::integer(out, 14, item.value("16", false));
            return out;
        }

        Reply redeem(const std::filesystem::path &directory,
                     const platform::LobbyIdentity &id,
                     uint8_t task,
                     wire::Reader &p)
        {
            // Exact request constructors 142136990/142136AA0 and serializers
            // 142165210/142164F00: context, transaction, code or payload/signature.
            proto::Reader reader{p.structure(4096)};
            proto::Field field;
            unsigned seen = 0;
            std::string context, transaction, value, signature;
            while (reader.next(field))
            {
                wire::require(field.tag >= 1 && field.tag <= (task == 1 ? 3u : 4u) &&
                              !(seen & (1U << field.tag)));
                seen |= 1U << field.tag;
                const auto decoded = text(field,
                                          field.tag == 1   ? 17u
                                          : field.tag == 2 ? 26u
                                          : field.tag == 3 ? (task == 1 ? 26u : 1025u)
                                                           : 65u);
                if (field.tag == 1)
                    context = decoded;
                else if (field.tag == 2)
                    transaction = decoded;
                else if (field.tag == 3)
                    value = decoded;
                else
                    signature = decoded;
            }
            wire::require(seen == (task == 1 ? 14u : 30u) && !context.empty() &&
                          !transaction.empty() && !value.empty() &&
                          (task == 1 || !signature.empty()));
            wire::require(context != "." && context != "..");
            for (char c : context)
                wire::require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
            const auto transactionKey = digest(context + "\n" + transaction);
            const auto requestKey = digest(Json::array({task, context, value, signature}).dump());
            const auto grantKey = digest(Json::array({task, context, digest(value)}).dump());
            const auto path = store(directory, id);
            auto inventory = read(path);
            auto receipts = inventory.value("redemptions", Json::object());
            auto used = inventory.value("redeemed_keys", Json::object());
            try
            {
                wire::require(receipts.is_object() && used.is_object() && receipts.size() <= 4096 &&
                              used.size() <= 4096);
                for (auto entry = receipts.begin(); entry != receipts.end(); ++entry)
                {
                    wire::require(hashText(entry.key()) &&
                                  hashText(entry->at("request").get<std::string>()) &&
                                  hashText(entry->at("grant").get<std::string>()) &&
                                  entry->at("recorded").is_number_unsigned());
                    (void)wire::base64(entry->at("response").get<std::string>(), 128 * 1024);
                    wire::require(used.contains(entry->at("grant").get<std::string>()) &&
                                  used.at(entry->at("grant").get<std::string>()) == entry.key());
                }
                wire::require(used.size() == receipts.size());
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Redemption receipt schema invalid");
            }
            if (receipts.contains(transactionKey))
            {
                const auto &previous = receipts.at(transactionKey);
                wire::require(previous.at("request") == requestKey);
                return {0,
                        {},
                        "code-redemption-retried",
                        true,
                        wire::base64(previous.at("response").get<std::string>(), 128 * 1024)};
            }
            if (used.contains(grantKey))
                return {108, {}, "code-already-redeemed"};
            const auto catalogPath =
                directory / "redemptions" / std::to_string(id.titleId) / context / "codes.json";
            if (!std::filesystem::exists(catalogPath))
                return {108, {}, "code-not-published"};
            if (std::filesystem::file_size(catalogPath) > 4 * 1024 * 1024)
                throw std::runtime_error("Redemption catalog size invalid");
            std::ifstream in(catalogPath);
            if (!in)
                throw std::runtime_error("Redemption catalog read failed");
            const auto catalog = Json::parse(in);
            const auto valueHash = digest(value);
            const Json *definition = nullptr;
            std::set<std::pair<std::string, std::string>> keys;
            try
            {
                wire::require(catalog.at("schema") == 1 && catalog.at("codes").is_array() &&
                              catalog.at("codes").size() <= 4096);
                for (const auto &row : catalog.at("codes"))
                {
                    const auto kind = row.at("kind").get<std::string>(),
                               key = row.at("hash").get<std::string>();
                    wire::require((kind == "code" || kind == "payload") && hashText(key) &&
                                  keys.insert({kind, key}).second &&
                                  row.at("enabled").is_boolean());
                    (void)catalogNumber(row, "expires", UINT32_MAX);
                    const auto &owners = row.at("users");
                    wire::require(owners.is_array() && owners.size() <= 200);
                    std::set<uint64_t> users;
                    for (const auto &owner : owners)
                    {
                        wire::require(owner.is_number_unsigned());
                        const auto user = owner.get<uint64_t>();
                        wire::require(user && user != UINT64_MAX && users.insert(user).second);
                    }
                    if (kind == "payload")
                        wire::require(hashText(row.at("signature_hash").get<std::string>()));
                    wire::require(row.at("items").is_array() && row.at("items").size() <= 32);
                    std::set<uint32_t> items;
                    for (const auto &item : row.at("items"))
                    {
                        wire::require(items.insert(item.at("1").get<uint32_t>()).second);
                        (void)grantedItem(item);
                        wire::require(item.at("2").get<uint32_t>() > 0);
                    }
                    validateBalances(row.at("currencies"));
                    for (const auto &currency : row.at("currencies"))
                        wire::require(currency.at("amount").get<uint64_t>() > 0 &&
                                      currency.at("amount").get<uint64_t>() <= UINT32_MAX);
                    if (key == valueHash && kind == (task == 1 ? "code" : "payload"))
                        definition = &row;
                }
            }
            catch (const std::runtime_error &)
            {
                throw std::runtime_error("Redemption catalog schema invalid");
            }
            if (!definition || !definition->at("enabled").get<bool>())
                return {108, {}, "code-not-published"};
            const auto stamp =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
            if (definition->at("expires").get<uint64_t>() &&
                definition->at("expires").get<uint64_t>() <= stamp)
                return {108, {}, "code-expired"};
            const auto &owners = definition->at("users");
            if (!owners.empty() && std::none_of(owners.begin(),
                                                owners.end(),
                                                [&](const auto &owner)
                                                {
                                                    return owner == id.userId;
                                                }))
                return {101, {}, "code-owner-denied"};
            if (task == 2 && definition->at("signature_hash") != digest(signature))
                return {101, {}, "code-signature-denied"};
            if (receipts.size() >= 4096)
                return {102, {}, "code-receipt-capacity-exceeded"};
            Reply reply{0, {}, "code-redeemed", true, {}};
            // Grants and their exact response are committed in ONE inventory file.
            // No acknowledgement precedes commit, and retries replay the prior delta.
            for (const auto &grant : definition->at("items"))
            {
                auto &items = inventory["items"];
                auto found = std::find_if(items.begin(),
                                          items.end(),
                                          [&](const auto &row)
                                          {
                                              return row.at("1") == grant.at("1");
                                          });
                const auto delta = grant.at("2").get<uint64_t>();
                const auto quantity = found == items.end() ? 0 : found->at("2").get<uint64_t>();
                if (quantity > UINT32_MAX - delta)
                    return {102, {}, "inventory-quantity-overflow"};
                const auto maximum = found == items.end() ? grant.value("18", uint64_t{0})
                                                          : found->value("18", uint64_t{0});
                if (maximum && quantity + delta > maximum)
                    return {102, {}, "inventory-quantity-limit"};
                if (found == items.end())
                {
                    if (items.size() >= 15000)
                        return {102, {}, "inventory-capacity-exceeded"};
                    items.push_back(grant);
                }
                else
                    (*found)["2"] = quantity + delta;
                proto::bytes(reply.structure, 1, grantedItem(grant));
            }
            for (const auto &grant : definition->at("currencies"))
            {
                auto &balances = inventory["balances"];
                auto found = std::find_if(balances.begin(),
                                          balances.end(),
                                          [&](const auto &row)
                                          {
                                              return row.at("currency") == grant.at("currency");
                                          });
                const auto before =
                               found == balances.end() ? 0 : found->at("amount").get<uint64_t>(),
                           delta = grant.at("amount").get<uint64_t>();
                if (before > UINT32_MAX - delta)
                    return {102, {}, "redemption-balance-overflow"};
                if (found == balances.end())
                {
                    if (balances.size() >= 16)
                        return {102, {}, "balance-capacity-exceeded"};
                    auto row = grant;
                    row["amount"] = delta;
                    balances.push_back(row);
                }
                else
                    (*found)["amount"] = before + delta;
                wire::Bytes row;
                proto::integer(row, 1, grant.at("currency").get<uint8_t>());
                proto::integer(row, 2, before);
                proto::integer(row, 3, delta);
                proto::bytes(reply.structure, 2, row);
            }
            receipts[transactionKey] = Json{{"request", requestKey},
                                            {"grant", grantKey},
                                            {"recorded", stamp},
                                            {"response", wire::base64Encode(reply.structure)}};
            used[grantKey] = transactionKey;
            inventory["redemptions"] = receipts;
            inventory["redeemed_keys"] = used;
            saveInventory(path, inventory);
            return reply;
        }

        Reply reconcile(const std::filesystem::path &directory,
                        const platform::LobbyIdentity &id,
                        wire::Reader &p)
        {
            // Same-Replay 0x142128DB0: marketplace 80/243. Full request serializer at
            // 0x142141B10 and response deserializer at 0x1421419E0. Both SKU arrays have
            // capacity 25; field 3 is the continuation bool, not a fabricated success.
            proto::Reader reader{p.structure(20 * 1024)};
            proto::Field field;
            std::string context, credential, country, sso;
            uint64_t maximum = 0;
            unsigned seen = 0;
            while (reader.next(field))
            {
                wire::require(field.tag >= 1 && field.tag <= 5 && !(seen & (1U << field.tag)));
                seen |= 1U << field.tag;
                if (field.tag == 1)
                    context = text(field, 17);
                else if (field.tag == 2)
                    credential = text(field, 113);
                else if (field.tag == 3)
                    country = text(field, 4);
                else if (field.tag == 4)
                {
                    wire::require(field.type == 0);
                    maximum = field.value;
                }
                else
                    sso = text(field, 16385);
            }
            // 0x140F70A00 supplies the native title as the Marketplace context.
            // Constructor 0x1421417C0 copies its web token to +33 (field 2).
            // Field 5 points to Replay's existing platform SSO string. The local realm
            // authenticates its issued web credential rather than an external SSO
            // value; never persist that opaque string or treat it as an identity.
            wire::require(seen == 62 && context == std::to_string(id.titleId) && country == "US" &&
                          maximum > 0 && maximum <= 25);
            if (!platform::sessionTokenMatches(id, credential))
                return {101, {}, "reconciliation-credential-denied"};
            (void)sso;
            // Local base-game ownership is already supplied by the signed platform
            // provider. No store SKU was bought or refunded in this realm, so there are
            // no grants/revocations. Persist the actual reconciliation receipt without
            // storing the credential. Future local catalog transactions use this store.
            const auto folder =
                directory / "marketplace" / std::to_string(id.titleId) / std::to_string(id.userId);
            std::filesystem::create_directories(folder);
            const auto target = folder / "reconciliation.json";
            auto pending = target;
            pending += ".pending";
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            const auto bytes = Json{
                {"schema", 1},
                {"context", context},
                {"country", country},
                {"completed", now},
                {"granted", Json::array()},
                {"revoked", Json::array()},
                {"more", false}}.dump();
            {
                std::ofstream stream(pending, std::ios::binary | std::ios::trunc);
                if (!stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size())) ||
                    !stream.flush())
                    throw std::runtime_error("Reconciliation receipt persistence failed");
            }
            if (!MoveFileExW(pending.c_str(),
                             target.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("Reconciliation receipt publication failed");
            Reply reply{0, {}, "licenses-reconciled", true, {}};
            proto::integer(reply.structure, 3, 0);
            return reply;
        }
    } // namespace

    void validateRankInventory(const nlohmann::json &document)
    {
        validateInventory(document);
    }

    RankInventory prepareRankInventory(const std::filesystem::path &directory,
                                       const platform::LobbyIdentity &id,
                                       std::span<const uint32_t> selected,
                                       bool award)
    {
        wire::require(id.titleId == 5800 && id.userId && id.userId != UINT64_MAX &&
                      selected.size() <= 15000);
        recoverPurchase(directory, id);
        RankInventory result;
        result.document = read(store(directory, id));
        auto &items = result.document["items"];
        std::map<uint32_t, size_t> positions;
        for (size_t index = 0; index < items.size(); ++index)
            positions.emplace(items[index].at("1").get<uint32_t>(), index);
        std::set<uint32_t> ids;
        for (const auto item : selected)
        {
            wire::require(item && item <= INT32_MAX && ids.insert(item).second);
            auto found = positions.find(item);
            auto quantity = found == positions.end() ? uint32_t{0}
                                                     : items[found->second].at("2").get<uint32_t>();
            // GRANT_PRODUCT's native reader uses getInt32 and stores a full,
            // absolute positive cache quantity. Never truncate an owned stack.
            wire::require(quantity <= INT32_MAX);
            if (award && !quantity)
            {
                quantity = 1;
                if (found == positions.end())
                {
                    wire::require(items.size() < 15000);
                    positions[item] = items.size();
                    items.push_back({{"1", item}, {"2", quantity}});
                }
                else
                    items[found->second]["2"] = quantity;
                result.changed = true;
                result.newlyOwned.push_back(item);
            }
            result.quantities.emplace_back(item, quantity);
        }
        std::sort(result.quantities.begin(), result.quantities.end());
        std::sort(result.newlyOwned.begin(), result.newlyOwned.end());
        validateInventory(result.document);
        return result;
    }

    std::optional<Reply> marketplaceServices(const std::filesystem::path &directory,
                                             const platform::LobbyIdentity &id,
                                             uint8_t service,
                                             uint8_t task,
                                             wire::Reader &p)
    {
        if (service == 80 || service == 123)
        {
            recoverAchievementWrites(directory, id.titleId);
            recoverPurchase(directory, id);
        }
        if (service == 80 && task == 243)
            return reconcile(directory, id, p);
        if (service == 80 && task == 69)
            return inventory(directory, id, p);
        if (service == 80 && task == 245)
            return balances(directory, id, p);
        if (service == 80 && task == 132)
            return legacyBalances(directory, id, p);
        if (service == 80 && task == 134)
            return catalog(directory, id, p);
        if (service == 80 && task == 106)
            return purchase(directory, id, p);
        if (service == 80 && task == 125)
            return purchaseV4(directory, id, p);
        if (service == 123 && (task == 1 || task == 2))
            return redeem(directory, id, task, p);
        return std::nullopt;
    }
} // namespace services
