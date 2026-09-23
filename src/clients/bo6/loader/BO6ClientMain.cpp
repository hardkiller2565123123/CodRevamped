#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <cstring>

#include "../../../shared/compat/games/common/GameTypes.h"
#include "../game/BO6Module.h"

namespace
{
    bool ReadImage(games::ExecutableInfo& out) noexcept
    {
        out = {};
        out.module = GetModuleHandleW(nullptr);
        if (!out.module)
            return false;
        __try
        {
            const auto base = reinterpret_cast<const unsigned char*>(out.module);
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            out.timestamp = nt->FileHeader.TimeDateStamp;
            out.imageSize = nt->OptionalHeader.SizeOfImage;
            out.entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
            GetModuleFileNameW(nullptr, out.executableName, MAX_PATH);
            const wchar_t* slash = wcsrchr(out.executableName, L'\\');
            if (slash)
                memmove(out.executableName, slash + 1, (wcslen(slash + 1) + 1) * sizeof(wchar_t));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    DWORD WINAPI Bootstrap(LPVOID) noexcept
    {
        games::ExecutableInfo image{};
        if (!ReadImage(image))
            return 1;
        games::BO6Module module{};
        return module.Initialize(image);
    }
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, Bootstrap, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
    }
    return TRUE;
}
