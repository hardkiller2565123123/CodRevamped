#include "ClientIdentity.h"
#include "../core/functions.hpp"
#include "StoragePaths.h"
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
#include "../../clients/bo4/game/T8FullBridge.h"
#include "../../clients/mw2019/game/IW8LegacyBridge.h"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <mutex>
#include <string>

namespace client_identity
{
    namespace
    {
        constexpr const char* kDefault = "Revampedplayer";
        constexpr const char* kIniSection = "Identity";
        constexpr const char* kIniKey = "Username";

        std::mutex g_mutex;
        std::string g_name = kDefault;
        games::GameKind g_loadedFor = games::GameKind::Unknown;
        bool g_loaded = false;

        const char* IniFileName(games::GameKind game)
        {
            switch (game)
            {
            case games::GameKind::Retail:
            case games::GameKind::Beta:
            case games::GameKind::Alpha:
                return "t9.ini";
            case games::GameKind::IW8:
                return "iw8.ini";
            case games::GameKind::T8:
                return "t8.ini";
            default:
                return nullptr;
            }
        }

        std::string ConfigPath(games::GameKind game)
        {
            if (const char* ini = IniFileName(game))
                return storage_paths::GameIniA(ini);

            return storage_paths::PathA("custom_data\\identity.ini");
        }

        std::string Clean(std::string value)
        {
            value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) {
                return c < 0x20 || c == '\x7F';
            }), value.end());
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(value.begin());
            if (value.size() > 31) value.resize(31);
            return value;
        }

        bool ApplyT9(const std::string& name, std::string& message)
        {
            if (!g_Addrs.LiveUser_GetUserDataForController || !g_Addrs.set_username)
            {
                message = "T9 username functions are not resolved yet; name remains saved";
                return false;
            }
            const auto user = LiveUser_GetUserDataForController(0);
            if (!user)
            {
                message = "T9 controller-0 user data is not ready yet; name remains saved";
                return false;
            }
            set_username(user, name.c_str());
            message = "applied to T9 local profile";
            return true;
        }
    }

    const char* DefaultName() { return kDefault; }

    std::string CurrentName()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_name;
    }

    bool LoadForGame(games::GameKind game, std::string& message)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_loaded && g_loadedFor == game)
        {
            message = "identity already loaded: " + g_name;
            return true;
        }

        storage_paths::EnsureBaseDirectories();
        const std::string path = ConfigPath(game);

        char buffer[256]{};
        GetPrivateProfileStringA(kIniSection, kIniKey, kDefault,
            buffer, static_cast<DWORD>(sizeof(buffer)), path.c_str());

        const auto cleaned = Clean(buffer);
        g_name = cleaned.empty() ? kDefault : cleaned;
        g_loadedFor = game;
        g_loaded = true;

        message = "username=" + g_name + "; config=" + path;
        return true;
    }

    bool Load(std::string& message)
    {
        return LoadForGame(games::GameKind::Unknown, message);
    }

    bool SaveNameForGame(games::GameKind game, const std::string& name, std::string& message)
    {
        const auto cleaned = Clean(name);
        if (cleaned.empty())
        {
            message = "username cannot be empty";
            return false;
        }

        storage_paths::EnsureBaseDirectories();
        const std::string path = ConfigPath(game);
        if (!WritePrivateProfileStringA(kIniSection, kIniKey, cleaned.c_str(), path.c_str()))
        {
            message = "could not write identity config: " + path;
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_name = cleaned;
            g_loadedFor = game;
            g_loaded = true;
        }

        message = "saved username=" + cleaned + "; config=" + path;
        return true;
    }

    bool SaveName(const std::string& name, std::string& message)
    {
        return SaveNameForGame(games::GameKind::Unknown, name, message);
    }

    bool ApplyForGame(games::GameKind game, std::string& message)
    {
        std::string load;
        LoadForGame(game, load);
        const auto name = CurrentName();
        switch (game)
        {
        case games::GameKind::Retail:
        case games::GameKind::Beta:
        case games::GameKind::Alpha:
            return ApplyT9(name, message);
#ifndef CODREVAMPED_COLDWAR_RUNTIME_ONLY
        case games::GameKind::IW8:
            CodRevamped_IW8Legacy_SetUsername(name.c_str());
            message = "applied to full IW8 legacy client identity";
            return true;
        case games::GameKind::T8:
            CodRevamped_T8Shield_SetUsername(name.c_str());
            message = "applied to full Shield T8 platform identity";
            return true;
#endif
        default:
            message = "identity saved; this game profile has no username adapter";
            return false;
        }
    }

    bool SetAndApply(games::GameKind game, const std::string& name, std::string& message)
    {
        std::string saved;
        if (!SaveNameForGame(game, name, saved))
        {
            message = saved;
            return false;
        }
        std::string applied;
        const bool ok = ApplyForGame(game, applied);
        message = saved + "; " + applied;
        return ok;
    }

    void PrintStatus(games::GameKind game)
    {
        std::string ignored;
        LoadForGame(game, ignored);
        const std::string path = ConfigPath(game);
        std::printf("[IDENTITY] default=%s current=%s game=%d config=%s\n",
            kDefault, CurrentName().c_str(), static_cast<int>(game), path.c_str());
        std::fflush(stdout);
    }
}
