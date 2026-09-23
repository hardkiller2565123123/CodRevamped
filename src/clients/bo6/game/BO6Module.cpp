#include "BO6Module.h"
#include "../../../shared/core/CoreRuntime.h"
#include "../../../shared/runtime/LogPaths.h"

#include <Windows.h>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <mutex>
#include <string>

namespace
{
    std::mutex g_logMutex;
    std::wstring g_logPath;
    PVOID g_veh = nullptr;
    std::atomic<unsigned> g_exceptionCount{0};

    bool IsCodExe(const wchar_t* name)
    {
        return name && _wcsicmp(name, L"cod.exe") == 0;
    }

    bool IsKnownBetaFingerprint(const games::ExecutableInfo& image)
    {
        return image.timestamp == 0x66B3F4B4u &&
               image.imageSize == 0x2384F800u;
    }

    std::filesystem::path ExeDirectory()
    {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        return std::filesystem::path(path).parent_path();
    }

    bool ExistsNearExe(const wchar_t* relative)
    {
        std::error_code ec;
        return std::filesystem::exists(ExeDirectory() / relative, ec);
    }

    void AppendLog(const char* fmt, ...)
    {
        if (g_logPath.empty())
            return;

        std::lock_guard<std::mutex> lock(g_logMutex);
        FILE* file = nullptr;
        _wfopen_s(&file, g_logPath.c_str(), L"a");
        if (!file)
            return;

        SYSTEMTIME st{};
        GetLocalTime(&st);
        std::fprintf(file, "[%02u:%02u:%02u.%03u] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        va_list args;
        va_start(args, fmt);
        std::vfprintf(file, fmt, args);
        va_end(args);
        std::fprintf(file, "\n");
        std::fflush(file);
        std::fclose(file);
    }

    LONG CALLBACK CrashTrace(EXCEPTION_POINTERS* info)
    {
        if (!info || !info->ExceptionRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        const DWORD code = info->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP)
            return EXCEPTION_CONTINUE_SEARCH;

        const unsigned index = g_exceptionCount.fetch_add(1);
        if (index >= 32)
            return EXCEPTION_CONTINUE_SEARCH;

        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        const auto address = reinterpret_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionAddress);
        const auto rva = (base && address >= base) ? address - base : 0;

#ifdef _M_X64
        const CONTEXT* c = info->ContextRecord;
        AppendLog(
            "[EXCEPTION] #%u code=0x%08lX addr=%p mainRVA=0x%llX RIP=%p RSP=%p RAX=%p RBX=%p RCX=%p RDX=%p",
            index + 1,
            code,
            info->ExceptionRecord->ExceptionAddress,
            static_cast<unsigned long long>(rva),
            c ? reinterpret_cast<void*>(c->Rip) : nullptr,
            c ? reinterpret_cast<void*>(c->Rsp) : nullptr,
            c ? reinterpret_cast<void*>(c->Rax) : nullptr,
            c ? reinterpret_cast<void*>(c->Rbx) : nullptr,
            c ? reinterpret_cast<void*>(c->Rcx) : nullptr,
            c ? reinterpret_cast<void*>(c->Rdx) : nullptr);
#else
        AppendLog("[EXCEPTION] #%u code=0x%08lX addr=%p mainRVA=0x%llX",
            index + 1, code, info->ExceptionRecord->ExceptionAddress,
            static_cast<unsigned long long>(rva));
#endif
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void PrepareLog()
    {
        const auto dir = ExeDirectory() / L"logs" / L"bo6";
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);

        SYSTEMTIME st{};
        GetLocalTime(&st);
        wchar_t name[96]{};
        swprintf_s(name, L"bo6_startup_%04u%02u%02u-%02u%02u%02u.log",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
        g_logPath = (dir / name).wstring();
    }
}

namespace games
{
    BO6Variant BO6Module::DetectVariant(const ExecutableInfo& image) noexcept
    {
        if (IsKnownBetaFingerprint(image))
            return BO6Variant::Beta;

        if (!IsCodExe(image.executableName))
            return BO6Variant::Unknown;

        // The 2024 BO6 beta is hosted by the root CoD HQ cod.exe and its
        // multiplayer beta payload is present under mp24.
        if (ExistsNearExe(L"mp24"))
            return BO6Variant::Beta;

        // Retail support is intentionally conservative until an exact retail
        // fingerprint is recorded. These folders are enough to keep cod.exe out
        // of T9/IW8 initialization and in the passive BO6 profile.
        if (ExistsNearExe(L"sp24") || ExistsNearExe(L"zm24"))
            return BO6Variant::Retail;

        return BO6Variant::Unknown;
    }

    const char* BO6Module::VariantName(BO6Variant variant) noexcept
    {
        switch (variant)
        {
        case BO6Variant::Beta:   return "BO6 Beta / mp24";
        case BO6Variant::Retail: return "BO6 Retail";
        default:                 return "Unknown BO6";
        }
    }

    GameKind BO6Module::Kind() const noexcept
    {
        return GameKind::BO6;
    }

    const char* BO6Module::Name() const noexcept
    {
        return "Black Ops 6";
    }

    bool BO6Module::Matches(const ExecutableInfo& image) const noexcept
    {
        // CoD HQ-era titles use the shared root cod.exe. Claim that host before
        // any legacy T9/default startup path is considered. Folder/layout
        // probing is only used to identify the BO6 variant; failure to see
        // mp24 during the early child-process startup must not send cod.exe
        // through the Cold War Offline/LAN selector.
        return IsKnownBetaFingerprint(image) || IsCodExe(image.executableName);
    }

    DWORD BO6Module::Initialize(const ExecutableInfo& image) noexcept
    {
        PrepareLog();
        const auto variant = DetectVariant(image);
        const auto base = reinterpret_cast<unsigned long long>(image.module);

        AppendLog("[INIT] CodRevamped BO6 profile starting");
        AppendLog("[BUILD] variant=%s exe=%ls base=0x%llX timestamp=0x%08lX imageSize=0x%08lX entryRVA=0x%08lX",
            VariantName(variant), image.executableName, base,
            image.timestamp, image.imageSize, image.entryPointRva);
        AppendLog("[LAYOUT] mp24=%d sp24=%d zm24=%d",
            ExistsNearExe(L"mp24") ? 1 : 0,
            ExistsNearExe(L"sp24") ? 1 : 0,
            ExistsNearExe(L"zm24") ? 1 : 0);

        if (!g_veh)
            g_veh = AddVectoredExceptionHandler(1, CrashTrace);

        std::printf("\n=========================================\n");
        std::printf("Black Ops 6 / CodRevamped\n");
        std::printf("=========================================\n");
        std::printf("[BO6] Variant      : %s\n", VariantName(variant));
        std::printf("[BO6] Timestamp    : 0x%08lX\n", image.timestamp);
        std::printf("[BO6] Image size   : 0x%08lX\n", image.imageSize);
        std::printf("[BO6] Entry RVA    : 0x%08lX\n", image.entryPointRva);
        std::printf("[BO6] Runtime base : 0x%llX\n", base);
        std::printf("[BO6] Passive startup diagnostics only; no T9/IW8 hooks or game-state patches installed.\n");
        std::printf("[BO6] Log: logs\\bo6\\bo6_startup_*.log\n");

        AppendLog("[READY] passive BO6 startup diagnostics active; no game patches installed");
        return 0;
    }
}
