#pragma once
#include <Windows.h>
#include <cstdint>

namespace runtime_ipc {
struct RuntimeData {
    uint32_t gameKind{};
    uint32_t runtimeStage{};
    const char* buildName{};
    uint64_t uiScreen{};
    uint64_t networkMode{};
    uint64_t sessionMode{};
    uint64_t config0{};
    uint64_t config1{};
    uint64_t initialized{};
    uint64_t authManager{};
    uint64_t noDemonware{};
    bool frontendReady{};
    bool rendererReady{};
    bool scriptReady{};
    bool offlineFilterEnabled{};
    bool hooksInstalled{};
    uint32_t resolvedAddressCount{};
    uint32_t validAddressCount{};
    uint32_t missingAddressCount{};
    uint32_t lastExceptionCode{};
};

bool Initialize(uintptr_t moduleBase, size_t imageSize) noexcept;
void Shutdown() noexcept;
void PublishLog(const char* text) noexcept;
void PublishAddress(const char* name, uintptr_t address, uintptr_t moduleBase, bool valid,
                    uint32_t flags = 0, uint32_t confidence = 100) noexcept;
void ResetAddresses() noexcept;
void PublishRuntime(const RuntimeData& data) noexcept;
void Heartbeat() noexcept;
void ProcessCommands() noexcept;
}
