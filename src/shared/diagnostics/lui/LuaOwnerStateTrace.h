#pragma once
#include <string>
#include <cstdint>

namespace lua_owner_state_trace
{
    void StartAsync();
    bool IsRunning();
    bool HasOwner();
    bool FindOwnerNow(std::string& message);
    bool Mark(const std::string& label, std::string& message);
    void PrintStatus();
    bool GetOwnerAddress(std::uintptr_t& owner);
    bool GetLiveAssetPointers(
        std::uintptr_t items[4],
        std::uintptr_t data[4],
        std::uint64_t hashes[4]);
}
