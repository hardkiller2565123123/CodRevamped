#pragma once

#include <cstdint>
#include <string>

namespace camo_prototype1
{
    // Called only by the research breakpoint at the real native parent
    // CALL site. Copies the 16-byte WeaponCamo loader record read-only.
    void CaptureNativeTemplate(
        const void* recordAddress,
        std::uintptr_t callerRip);

    bool HasTemplate();
    void ArmAutomaticStartupAttempt();

    // Status is read-only.
    bool Status(std::string& message);

    bool NativeApply(const std::string& name, std::string& message);

    // Prototype 1:
    // Replays a CLONED native 16-byte WeaponCamo loader record through the
    // already-mapped native bridge. It never points the bridge at a stock
    // loader record and never writes a stock WeaponCamo slot directly.
    //
    // This is intentionally a one-shot experimental registration probe.
    bool Create(std::string& message);

    // Prototype 1 is queued by the console and executed only when the real
    // WeaponCamo loader thread reaches a native type-0x2E record.
    bool IsPending();

    // Called from the proven WeaponCamo stage breakpoints on the real loader thread.
    void CapturePreparedSource(
        const void* preparedSource,
        std::uintptr_t callerRip);

    bool ExecuteAfterStockRegistration(
        std::uintptr_t stockResult,
        std::uintptr_t callerRip);

    void PumpDeferredAttempt();

    // Allows another attempt only if Create() did not validate a new entry.
    // Does not unregister anything from the game.
    bool ResetAttempt(std::string& message);
}
