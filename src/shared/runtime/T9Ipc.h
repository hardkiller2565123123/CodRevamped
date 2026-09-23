#pragma once
#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace t9ipc
{
    inline constexpr std::uint32_t kMagic = 0x50493954u; // "T9IP"
    inline constexpr std::uint32_t kVersion = 1u;
    inline constexpr std::size_t kLogCapacity = 256;
    inline constexpr std::size_t kAddressCapacity = 512;
    inline constexpr std::size_t kNameText = 96;
    inline constexpr std::size_t kBuildText = 96;

    struct SectionState
    {
        volatile LONG64 sequence{};
        std::uint64_t updatedMs{};
        std::uint32_t count{};
        std::uint32_t capacity{};
    };

    struct LogEntry
    {
        volatile LONG64 sequence{};
        SYSTEMTIME time{};
        std::uint32_t level{};
        std::uint32_t category{};
        char text[512]{};
    };

    struct AddressEntry
    {
        volatile LONG64 sequence{};
        char name[kNameText]{};
        std::uint64_t address{};
        std::uint64_t rva{};
        std::uint32_t flags{};
        std::uint32_t confidence{};
    };

    struct RuntimeState
    {
        volatile LONG64 sequence{};
        std::uint64_t timestampMs{};
        std::uint64_t heartbeatMs{};
        std::uint32_t gameKind{};
        std::uint32_t runtimeStage{};
        char buildName[kBuildText]{};
        std::uint64_t uiScreen{};
        std::uint64_t networkMode{};
        std::uint64_t sessionMode{};
        std::uint64_t config0{};
        std::uint64_t config1{};
        std::uint64_t initialized{};
        std::uint64_t authManager{};
        std::uint64_t noDemonware{};
        std::uint32_t frontendReady{};
        std::uint32_t rendererReady{};
        std::uint32_t scriptReady{};
        std::uint32_t offlineFilterEnabled{};
        std::uint32_t hooksInstalled{};
        std::uint32_t resolvedAddressCount{};
        std::uint32_t validAddressCount{};
        std::uint32_t missingAddressCount{};
        std::uint32_t lastExceptionCode{};
        std::uint32_t scannerInDllDisabled{};
        std::uint32_t commandBackendReady{};
        std::uint32_t activeGameModule{};
    };

    using RuntimeSnapshot = RuntimeState;

    struct CommandRequest
    {
        volatile LONG64 sequence{};
        std::uint64_t address{};
        std::uint64_t result{};
        std::uint32_t flags{};
        volatile LONG state{};
        volatile LONG workerActive{};
        std::uint64_t submittedMs{};
        std::uint64_t startedMs{};
        std::uint64_t finishedMs{};
        std::uint32_t exceptionCode{};
        std::uint32_t reserved{};
        char label[kNameText]{};
    };

    struct SharedState
    {
        std::uint32_t magic{};
        std::uint32_t version{};
        std::uint32_t structureSize{};
        std::uint32_t processId{};
        std::uint64_t moduleBase{};
        std::uint64_t imageSize{};
        volatile LONG64 heartbeat{};
        volatile LONG64 logWriteSequence{};
        volatile LONG64 addressWriteSequence{};
        SectionState logSection{};
        SectionState addressSection{};
        SectionState runtimeSection{};
        SectionState commandSection{};
        LogEntry logs[kLogCapacity]{};
        AddressEntry addresses[kAddressCapacity]{};
        RuntimeState runtime{};
        CommandRequest command{};
    };

    inline void MappingName(DWORD processId, wchar_t (&buffer)[64]) noexcept
    {
        _snwprintf_s(buffer, (sizeof(buffer) / sizeof(buffer[0])), _TRUNCATE,
            L"Local\\CodRevamped.T9IPC.%lu", processId);
    }
}
