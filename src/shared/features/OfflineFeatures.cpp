#include "OfflineFeatures.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <mutex>

namespace offline_features
{
    namespace
    {
        struct Definition
        {
            FeatureId id;
            const char* name;
            const char* command;
            bool enabled;
        };

        std::array<Definition, 4> g_features{{
            {FeatureId::Noclip, "Noclip", "noclip", false},
            {FeatureId::God, "God mode", "god", false},
            {FeatureId::Ufo, "UFO movement", "ufo", false},
            {FeatureId::Notarget, "AI notarget", "notarget", false}
        }};

        CommandExecutor g_executor = nullptr;
        OfflinePredicate g_offlinePredicate = nullptr;
        InGamePredicate g_inGamePredicate = nullptr;
        std::mutex g_mutex;

        Definition* Find(FeatureId id)
        {
            for (auto& feature : g_features)
                if (feature.id == id)
                    return &feature;
            return nullptr;
        }

        std::string Lower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        }
    }

    void Configure(CommandExecutor executor, OfflinePredicate offlinePredicate, InGamePredicate inGamePredicate)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_executor = executor;
        g_offlinePredicate = offlinePredicate;
        g_inGamePredicate = inGamePredicate;
    }

    bool Set(FeatureId id, bool enabled)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto* feature = Find(id);
        if (!feature || !g_executor || !g_offlinePredicate || !g_inGamePredicate)
            return false;
        if (!g_offlinePredicate() || !g_inGamePredicate())
            return false;
        if (feature->enabled == enabled)
            return true;

        // These use the game's own developer-command path. No gameplay memory is patched.
        if (!g_executor(feature->command))
            return false;
        feature->enabled = enabled;
        return true;
    }

    bool Toggle(FeatureId id)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto* feature = Find(id);
        if (!feature || !g_executor || !g_offlinePredicate || !g_inGamePredicate)
            return false;
        if (!g_offlinePredicate() || !g_inGamePredicate())
            return false;
        if (!g_executor(feature->command))
            return false;
        feature->enabled = !feature->enabled;
        return true;
    }

    std::vector<FeatureState> Snapshot()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const bool commandReady = g_executor != nullptr;
        const bool offline = g_offlinePredicate && g_offlinePredicate();
        const bool inGame = g_inGamePredicate && g_inGamePredicate();
        std::vector<FeatureState> out;
        out.reserve(g_features.size());
        for (const auto& feature : g_features)
        {
            FeatureState state{};
            state.id = feature.id;
            state.name = feature.name;
            state.command = feature.command;
            state.enabled = feature.enabled;
            state.available = commandReady && offline && inGame;
            if (!commandReady) state.reason = "native command path unresolved";
            else if (!offline) state.reason = "offline filter/state is not active";
            else if (!inGame) state.reason = "enter a local match first";
            else state.reason = "ready (native command; no memory patch)";
            out.push_back(std::move(state));
        }
        return out;
    }

    const char* Name(FeatureId id)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (const auto* feature = Find(id))
            return feature->name;
        return "Unknown";
    }

    bool Parse(const std::string& text, FeatureId& out)
    {
        const std::string value = Lower(text);
        if (value == "noclip") out = FeatureId::Noclip;
        else if (value == "god" || value == "godmode") out = FeatureId::God;
        else if (value == "ufo") out = FeatureId::Ufo;
        else if (value == "notarget") out = FeatureId::Notarget;
        else return false;
        return true;
    }
}
