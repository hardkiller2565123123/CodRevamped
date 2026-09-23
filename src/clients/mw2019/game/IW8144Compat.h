#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include "IW8Addresses.h"

namespace iw8_144
{
    using Detection = iw8_addresses::Resolved144;

    bool IsExactBuild(HMODULE module) noexcept;
    bool IsPureServerEmulationMode() noexcept;
    bool Detect(HMODULE module, Detection& result);
    bool Initialize(HMODULE module, std::string& message);
    void Tick(unsigned long long uptimeMs) noexcept;
    void PrintStatus() noexcept;
    void PrintOffsets() noexcept;
    void RequestFrontendSelectorPass() noexcept;
    bool QueueFrontendMenu(const char* menuName) noexcept;
    void EnableSignInHooks() noexcept;
    void EnableContentHook() noexcept;
    void EnableLuiHooks() noexcept;
    void EnablePatchHooks() noexcept;
    void EnableLateOfflineHooks() noexcept;
}
