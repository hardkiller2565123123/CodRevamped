#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace offline_features
{
    enum class FeatureId
    {
        Noclip,
        God,
        Ufo,
        Notarget
    };

    struct FeatureState
    {
        FeatureId id{};
        const char* name{};
        const char* command{};
        bool available{};
        bool enabled{};
        std::string reason;
    };

    using CommandExecutor = bool(*)(const char* command);
    using OfflinePredicate = bool(*)();
    using InGamePredicate = bool(*)();

    void Configure(CommandExecutor executor, OfflinePredicate offlinePredicate, InGamePredicate inGamePredicate);
    bool Toggle(FeatureId id);
    bool Set(FeatureId id, bool enabled);
    std::vector<FeatureState> Snapshot();
    const char* Name(FeatureId id);
    bool Parse(const std::string& text, FeatureId& out);
}
