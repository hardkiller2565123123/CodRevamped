#include "T8Runtime.h"
#include "T8Addresses.h"
#include "T8BuildProfile.h"
#include "../../../shared/common/utils/MinHook.hpp"
#include "../../../shared/runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>

namespace t8_runtime
{
    namespace
    {
        using BNetGetUsernameFn = const char*(*)();
        BNetGetUsernameFn g_originalGetUsername = nullptr;

        std::mutex g_mutex;
        std::string g_identity = "Revampedplayer";
        std::atomic_bool g_verified{ false };
        std::atomic_bool g_initialized{ false };
        std::atomic_bool g_identityHooked{ false };

        std::uintptr_t Base()
        {
            return reinterpret_cast<std::uintptr_t>(
                GetModuleHandleW(nullptr));
        }

        template <typename T>
        bool SafeRead(std::uintptr_t address, T& value)
        {
            SIZE_T got = 0;
            return address &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    &value,
                    sizeof(value),
                    &got) &&
                got == sizeof(value);
        }

        bool IsExecutable(std::uintptr_t address)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!address ||
                !VirtualQuery(
                    reinterpret_cast<const void*>(address),
                    &mbi,
                    sizeof(mbi)))
                return false;

            if (mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                return false;

            const DWORD p = mbi.Protect & 0xFF;
            return p == PAGE_EXECUTE ||
                   p == PAGE_EXECUTE_READ ||
                   p == PAGE_EXECUTE_READWRITE ||
                   p == PAGE_EXECUTE_WRITECOPY;
        }

        const char* UsernameDetour()
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            return g_identity.c_str();
        }

        bool SafeCallCbuf(
            std::uintptr_t target,
            const char* text)
        {
            using Fn = void(*)(int, const char*);

            __try
            {
                reinterpret_cast<Fn>(target)(
                    0,
                    text);
                return true;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        void Log(const std::string& line)
        {
            log_paths::EnsureAll();
            const std::string folder = t8_build::LogFolder(t8_build::Active());
            CreateDirectoryA(folder.c_str(), nullptr);
            std::ofstream out(folder + "\\runtime.log", std::ios::app);
            if (out)
                out << line << "\n";
        }

        bool InstallIdentityHook(std::string& message)
        {
            if (g_identityHooked.load())
            {
                message = "T8 Battle.net username hook already active";
                return true;
            }

            if (!g_verified.load())
            {
                message = "T8 source build is not verified; username hook stays disabled";
                return false;
            }

            const auto rva = t8_build::ActiveCore().BNet_GetUsername;
            if (!rva)
            {
                message = std::string("T8 BNet_GetUsername is not mapped for profile ") + t8_build::Key(t8_build::Active());
                return false;
            }

            const auto target = t8_addresses::Resolve(Base(), rva);

            if (!IsExecutable(target))
            {
                message = "T8 BNet_GetUsername address is not executable";
                return false;
            }

            const auto init = MH_Initialize();
            if (init != MH_OK &&
                init != MH_ERROR_ALREADY_INITIALIZED)
            {
                message = "MinHook initialization failed";
                return false;
            }

            const auto create =
                MH_CreateHook(
                    reinterpret_cast<void*>(target),
                    reinterpret_cast<void*>(&UsernameDetour),
                    reinterpret_cast<void**>(&g_originalGetUsername));

            if (create != MH_OK &&
                create != MH_ERROR_ALREADY_CREATED)
            {
                message = "T8 username hook creation failed";
                return false;
            }

            const auto enable =
                MH_EnableHook(
                    reinterpret_cast<void*>(target));

            if (enable != MH_OK &&
                enable != MH_ERROR_ENABLED)
            {
                message = "T8 username hook enable failed";
                return false;
            }

            g_identityHooked.store(true);
            message = "T8 Battle.net username hook active";
            return true;
        }
    }

    bool VerifySupportedBuild(std::string& message)
    {
        const bool ok = t8_build::VerifyActive(message);
        g_verified.store(ok);
        Log(message);
        return ok;
    }

    bool Initialize(std::string& message)
    {
        std::string verify;
        const bool supported = VerifySupportedBuild(verify);

        if (!supported)
        {
            message = "T8 profile verification failed; " + verify;
            g_initialized.store(false);
            return false;
        }

        g_initialized.store(true);

        const auto& core = t8_build::ActiveCore();
        const bool commandMapped = core.Cbuf_AddText != 0;
        const bool identityMapped = core.BNet_GetUsername != 0;

        std::ostringstream out;
        out << "T8 shared retail framework active for profile=" << t8_build::Key(t8_build::Active())
            << "; command=" << (commandMapped ? "mapped" : "pending-rva")
            << "; identity=" << (identityMapped ? "mapped" : "pending-rva")
            << "; fullClient=" << (t8_build::FullClientAddressMapComplete() ? "ready" : "gated-until-address-map")
            << "; " << verify;
        message = out.str();
        Log(message);
        return true;
    }

    bool QueueCommand(
        const std::string& command,
        std::string& message)
    {
        if (!g_verified.load())
        {
            message = "T8 source build not verified; command queue blocked";
            return false;
        }

        const auto rva = t8_build::ActiveCore().Cbuf_AddText;
        if (!rva)
        {
            message = std::string("T8 Cbuf_AddText is not mapped for profile ") + t8_build::Key(t8_build::Active());
            return false;
        }

        const auto target = t8_addresses::Resolve(Base(), rva);

        if (!IsExecutable(target))
        {
            message = "T8 Cbuf_AddText is unavailable";
            return false;
        }

        if (!SafeCallCbuf(
                target,
                command.c_str()))
        {
            message =
                "T8 Cbuf_AddText raised an exception";
            return false;
        }

        message =
            "queued T8 command: " +
            command;
        return true;
    }

    bool ApplyIdentity(
        const std::string& name,
        std::string& message)
    {
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_identity = name.empty()
                ? "Revampedplayer"
                : name;
        }

        std::string hook;
        const bool ok =
            InstallIdentityHook(hook);

        message =
            "T8 identity=" +
            g_identity +
            "; " +
            hook;

        Log(message);
        return ok;
    }

    void PrintStatus()
    {
        std::lock_guard<std::mutex> lock(g_mutex);

        const auto& set = t8_build::ActiveAddressSet();
        std::printf(
            "[T8] profile=%s verified=%s initialized=%s identityHook=%s username=%s addressEntries=%llu retailMapEntries=%llu fullClientMap=%s\n",
            t8_build::Key(set.build),
            g_verified.load() ? "yes" : "no",
            g_initialized.load() ? "yes" : "no",
            g_identityHooked.load() ? "yes" : "no",
            g_identity.c_str(),
            static_cast<unsigned long long>(set.namedCount),
            static_cast<unsigned long long>(set.retailMapCount),
            set.fullClientAddressMapComplete ? "complete" : "partial");
        std::fflush(stdout);
    }
}
