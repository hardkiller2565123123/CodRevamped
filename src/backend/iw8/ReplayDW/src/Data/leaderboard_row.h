#pragma once
#include "wire.h"
#include "nlohmann/json.hpp"
#include <cstdint>

namespace services::leaderboard_row
{
    inline constexpr size_t maximumStoredColumns = 240;
    inline constexpr size_t maximumResponseColumns = 10;

    // The persistent layout is shared by ordinary/validated writes and projected
    // reads. Native write packets still carry at most ten columns; a partial
    // write must preserve the complete valid stored row, including its tail.
    inline void validate(const nlohmann::json &row)
    {
        wire::require(row.is_object() && row.contains("rating") &&
                      row.contains("columns") && row["columns"].is_array() &&
                      row["columns"].size() <= maximumStoredColumns);
        const auto &rating = row["rating"];
        wire::require(rating.is_null() ||
                      (rating.is_number_integer() &&
                       (!rating.is_number_unsigned() ||
                        rating.get<uint64_t>() <= uint64_t{INT64_MAX})));
        for (const auto &column : row["columns"])
        {
            if (column.is_null())
                continue;
            wire::require(column.is_number_integer() &&
                          (!column.is_number_unsigned() ||
                           column.get<uint64_t>() <= uint64_t{INT32_MAX}) &&
                          column.get<int64_t>() >= INT32_MIN &&
                          column.get<int64_t>() <= INT32_MAX);
        }
        if (row.contains("name"))
        {
            wire::require(row["name"].is_string());
            const auto &name = row["name"].get_ref<const std::string &>();
            wire::require(name.size() < 64 && name.find('\0') == std::string::npos);
        }
        if (row.contains("updated"))
            wire::require(row["updated"].is_number_unsigned() ||
                          (row["updated"].is_number_integer() &&
                           row["updated"].get<int64_t>() >= 0));
    }
} // namespace services::leaderboard_row
