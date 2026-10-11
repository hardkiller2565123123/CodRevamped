#pragma once
#include "achievement_store.h"
#include "services.h"

namespace services
{
    void projectBattlepassUserState(const std::filesystem::path &root,
                                    const platform::LobbyIdentity &identity,
                                    const std::string &context,
                                    nlohmann::json &state);

    std::optional<Reply> battlepassActivation(const std::filesystem::path &root,
                                              const platform::LobbyIdentity &identity,
                                              const std::string &context,
                                              const std::string &name,
                                              uint64_t selected,
                                              uint64_t timestamp,
                                              const achievement_store::Validator &validate);

    // Append to the existing event transaction. Its durable request receipt,
    // inventory debit, tier rewards and state changes recover as one operation.
    void battlepassEvents(const std::filesystem::path &root,
                          const platform::LobbyIdentity &identity,
                          const std::string &context,
                          const nlohmann::json &events,
                          std::vector<achievement_store::Write> &writes,
                          std::vector<Delivery> &deliveries,
                          bool refresh = false);
} // namespace services
