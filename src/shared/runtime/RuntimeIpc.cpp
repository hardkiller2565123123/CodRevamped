#include "RuntimeIpc.h"
#include "T9Ipc.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace {
HANDLE g_map = nullptr;
t9ipc::SharedState* g_state = nullptr;

void CommitSection(t9ipc::SectionState& section, uint32_t count) noexcept {
    section.updatedMs = GetTickCount64();
    section.count = count;
    MemoryBarrier();
    InterlockedIncrement64(&section.sequence);
}
}

namespace runtime_ipc {
bool Initialize(uintptr_t base, size_t size) noexcept {
    if (g_state) return true;
    wchar_t name[64]{};
    t9ipc::MappingName(GetCurrentProcessId(), name);
    g_map = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                               static_cast<DWORD>(sizeof(t9ipc::SharedState)), name);
    if (!g_map) return false;
    g_state = static_cast<t9ipc::SharedState*>(MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0,
                                                             sizeof(t9ipc::SharedState)));
    if (!g_state) { CloseHandle(g_map); g_map = nullptr; return false; }
    ZeroMemory(g_state, sizeof(*g_state));
    g_state->magic = t9ipc::kMagic;
    g_state->version = t9ipc::kVersion;
    g_state->structureSize = static_cast<uint32_t>(sizeof(t9ipc::SharedState));
    g_state->processId = GetCurrentProcessId();
    g_state->moduleBase = base;
    g_state->imageSize = size;
    g_state->logSection.capacity = static_cast<uint32_t>(t9ipc::kLogCapacity);
    g_state->addressSection.capacity = static_cast<uint32_t>(t9ipc::kAddressCapacity);
    g_state->runtimeSection.capacity = 1;
    g_state->commandSection.capacity = 1;
    Heartbeat();
    return true;
}

void Shutdown() noexcept {
    if (g_state) { UnmapViewOfFile(g_state); g_state = nullptr; }
    if (g_map) { CloseHandle(g_map); g_map = nullptr; }
}

void Heartbeat() noexcept {
    if (g_state) InterlockedIncrement64(&g_state->heartbeat);
}

void PublishLog(const char* text) noexcept {
    if (!g_state || !text) return;
    const auto seq = InterlockedIncrement64(&g_state->logWriteSequence);
    auto& e = g_state->logs[seq % t9ipc::kLogCapacity];
    InterlockedExchange64(&e.sequence, 0);
    GetLocalTime(&e.time);
    e.level = 0;
    e.category = 0;
    strncpy_s(e.text, text, _TRUNCATE);
    MemoryBarrier();
    InterlockedExchange64(&e.sequence, seq);
    CommitSection(g_state->logSection,
        static_cast<uint32_t>((std::min)(static_cast<LONG64>(t9ipc::kLogCapacity), seq)));
}

void ResetAddresses() noexcept {
    if (!g_state) return;
    InterlockedExchange64(&g_state->addressWriteSequence, 0);
    ZeroMemory(g_state->addresses, sizeof(g_state->addresses));
    CommitSection(g_state->addressSection, 0);
}

void PublishAddress(const char* name, uintptr_t address, uintptr_t base, bool valid,
                    uint32_t flags, uint32_t confidence) noexcept {
    if (!g_state || !name) return;
    const auto seq = InterlockedIncrement64(&g_state->addressWriteSequence);
    auto& e = g_state->addresses[seq % t9ipc::kAddressCapacity];
    InterlockedExchange64(&e.sequence, 0);
    strncpy_s(e.name, name, _TRUNCATE);
    e.address = address;
    e.rva = address && base ? address - base : 0;
    e.flags = flags | (valid ? 1u : 0u);
    e.confidence = confidence > 100 ? 100 : confidence;
    MemoryBarrier();
    InterlockedExchange64(&e.sequence, seq);
    CommitSection(g_state->addressSection,
        static_cast<uint32_t>((std::min)(static_cast<LONG64>(t9ipc::kAddressCapacity), seq)));
}

namespace {
DWORD WINAPI ExecuteCommandWorker(LPVOID parameter) noexcept {
    auto* command = static_cast<t9ipc::CommandRequest*>(parameter);
    if (!command) return 0;

    const LONG64 requestSequence = command->sequence;
    const uintptr_t address = static_cast<uintptr_t>(command->address);
    DWORD exceptionCode = 0;
    uint64_t result = 0;

    __try {
        using NoArgFunction = uintptr_t(*)();
        result = reinterpret_cast<NoArgFunction>(address)();
    }
    __except (exceptionCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
    }

    // Do not overwrite a newer request if the UI was restarted or the mapping changed.
    if (g_state && command->sequence == requestSequence) {
        command->result = result;
        command->exceptionCode = exceptionCode;
        command->finishedMs = GetTickCount64();
        if (exceptionCode) {
            InterlockedExchange(&command->state, 4);
            PublishLog("[IPC-CALL] Function call faulted; exception captured.");
        } else {
            InterlockedExchange(&command->state, 3);
            PublishLog("[IPC-CALL] Function call completed.");
        }
        InterlockedExchange(&command->workerActive, 0);
        CommitSection(g_state->commandSection, 1);
    }
    return 0;
}
}

void ProcessCommands() noexcept {
    if (!g_state) return;
    auto& command = g_state->command;

    // Keep the IPC publisher responsive even if an arbitrary target never returns.
    if (InterlockedCompareExchange(&command.workerActive, 0, 0) != 0) {
        if (command.state == 2 && command.startedMs &&
            GetTickCount64() - command.startedMs >= 5000) {
            InterlockedExchange(&command.state, 6);
            command.exceptionCode = WAIT_TIMEOUT;
            CommitSection(g_state->commandSection, 1);
            PublishLog("[IPC-CALL] Function has not returned after 5 seconds; worker left isolated and runtime IPC remains responsive.");
        }
        return;
    }

    if (InterlockedCompareExchange(&command.state, 2, 1) != 1) return;
    command.startedMs = GetTickCount64();
    command.finishedMs = 0;
    command.exceptionCode = 0;
    InterlockedExchange(&command.workerActive, 1);
    CommitSection(g_state->commandSection, 1);

    const uintptr_t address = static_cast<uintptr_t>(command.address);
    MEMORY_BASIC_INFORMATION mbi{};
    const bool queried = VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi);
    const DWORD protection = queried ? (mbi.Protect & 0xFFu) : 0;
    const bool executable = queried && mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
        (protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
         protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY);
    if (!executable || !(command.flags & 1u)) {
        command.exceptionCode = ERROR_INVALID_ADDRESS;
        command.finishedMs = GetTickCount64();
        InterlockedExchange(&command.workerActive, 0);
        InterlockedExchange(&command.state, 5);
        CommitSection(g_state->commandSection, 1);
        PublishLog("[IPC-CALL] Rejected non-executable or unsupported address request.");
        return;
    }

    HANDLE worker = CreateThread(nullptr, 0, ExecuteCommandWorker, &command, 0, nullptr);
    if (worker) {
        CloseHandle(worker);
        PublishLog("[IPC-CALL] Function call dispatched to isolated worker thread.");
    } else {
        command.exceptionCode = GetLastError();
        command.finishedMs = GetTickCount64();
        InterlockedExchange(&command.workerActive, 0);
        InterlockedExchange(&command.state, 4);
        CommitSection(g_state->commandSection, 1);
        PublishLog("[IPC-CALL] Could not create the isolated call worker thread.");
    }
}

void PublishRuntime(const RuntimeData& data) noexcept {
    if (!g_state) return;
    auto& r = g_state->runtime;
    LONG64 next = r.sequence + 1;
    if (next <= 0) next = 1;
    InterlockedExchange64(&r.sequence, 0);
    r.timestampMs = GetTickCount64();
    r.heartbeatMs = r.timestampMs;
    r.gameKind = data.gameKind;
    r.runtimeStage = data.runtimeStage;
    strncpy_s(r.buildName, data.buildName ? data.buildName : "unknown", _TRUNCATE);
    r.uiScreen = data.uiScreen;
    r.networkMode = data.networkMode;
    r.sessionMode = data.sessionMode;
    r.config0 = data.config0;
    r.config1 = data.config1;
    r.initialized = data.initialized;
    r.authManager = data.authManager;
    r.noDemonware = data.noDemonware;
    r.frontendReady = data.frontendReady ? 1u : 0u;
    r.rendererReady = data.rendererReady ? 1u : 0u;
    r.scriptReady = data.scriptReady ? 1u : 0u;
    r.offlineFilterEnabled = data.offlineFilterEnabled ? 1u : 0u;
    r.hooksInstalled = data.hooksInstalled ? 1u : 0u;
    r.resolvedAddressCount = data.resolvedAddressCount;
    r.validAddressCount = data.validAddressCount;
    r.missingAddressCount = data.missingAddressCount;
    r.lastExceptionCode = data.lastExceptionCode;
    r.scannerInDllDisabled = 1;
    r.commandBackendReady = 1;
    r.activeGameModule = data.gameKind;
    MemoryBarrier();
    InterlockedExchange64(&r.sequence, next);
    CommitSection(g_state->runtimeSection, 1);
    Heartbeat();
}
}
