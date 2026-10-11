#pragma once
#include "platform.h"
#include "wire.h"
#include "nlohmann/json.hpp"
#include <filesystem>
#include <optional>
#include <functional>

namespace services
{
    struct RESTResult
    {
        uint32_t version = 0, status = 503;
        std::string body;
    };

    struct Delivery
    {
        uint64_t user = 0;
        wire::Bytes payload;
        uint32_t delayMs = 0;
        uint64_t lobbyId = 0, searchId = 0;
        uint64_t presenceUser = 0, presenceRevision = 0;
        std::string presenceContext;
        uint64_t clanGroup = 0, clanUser = 0;
        uint32_t clanEvent = 0, clanRole = 0;
        uint64_t tournamentId = 0;
        std::string tournamentStateHash;
        bool tournamentUnavailable = false;
        bool tournamentRefresh = false;
        bool tournamentJoin = false;
        bool tournamentFormationDisband = false;
        bool tournamentRoundLobby = false;
        std::string mailContext;
        uint64_t mailId = 0;
        std::string channelCategory;
        uint64_t channelId = 0, channelMember = 0;
        uint32_t channelEvent = 0, channelMemberGeneration = 0, channelRecipientGeneration = 0;
        wire::Bytes channelJoinPayload;
        std::string progressionContext;
        uint64_t progressionXp = 0;
        bool progressionRefresh = false;
        uint64_t progressionId = 1000000;
        std::string progressionRewardsHash;
        std::string questContext, questStateHash;
        uint32_t questId = 0;
    };

    struct Reply
    {
        uint32_t error = 0;
        std::vector<wire::Bytes> results;
        std::string operation;
        bool structured = false;
        wire::Bytes structure;
        std::vector<wire::Bytes> pushes;
        std::optional<RESTResult> rest;
        std::string detail;
        std::vector<Delivery> deliveries;
    };

    void initialize(const std::filesystem::path &directory);
    nlohmann::json publicActivity();
    void restoreLocalProgression(
        uint32_t title, uint64_t user, uint64_t xp, bool restore, unsigned startingRank,
        uint32_t platformAccount = 0);
    void maintainTournamentPublications(const std::function<void(const std::string &)> &log);
    std::vector<Delivery> disconnected(uint32_t title, uint64_t user);
    bool deliveryValid(uint32_t title, const Delivery &delivery);
    std::optional<Delivery> tournamentUpdate(uint32_t title, uint64_t user);
    std::optional<Delivery> tournamentLobbyUpdate(uint32_t title, uint64_t user);
    std::vector<Delivery> mailUpdates(uint32_t title, uint64_t user);
    std::vector<Delivery> progressionUpdates(uint32_t title, uint64_t user);
    Reply dispatch(const platform::LobbyIdentity &identity,
                   uint8_t service,
                   uint8_t task,
                   wire::Reader &params,
                   bool hostAuthenticated = false);
    wire::Bytes taskReply(uint64_t transaction, uint8_t task, const Reply &reply);
} // namespace services
