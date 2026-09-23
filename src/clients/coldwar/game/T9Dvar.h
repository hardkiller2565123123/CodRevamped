#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace t9_dvars
{
    enum class Source
    {
        Seed,
        RuntimeDump,
        Verified
    };

    struct Entry
    {
        std::string name;
        std::string type;
        std::string value;
        std::uint64_t hash = 0;
        std::uintptr_t address = 0;
        unsigned int flags = 0;
        Source source = Source::Seed;
        bool verified = false;
    };

    enum class ExecuteResult
    {
        NotFound,
        Read,
        Set,
        Rejected,
        Fault
    };

    // Rebuilds the one authoritative dvar database and verifies every candidate
    // against the running game's Dvar_FindVar implementation.
    void Refresh();

    std::vector<Entry> Entries(const std::string& filter = {}, bool verifiedOnly = false);
    std::vector<std::string> Suggestions(const std::string& input, std::size_t limit = 8);

    // Accepts a name without the leading slash and an optional value.
    // Empty value reads the dvar; non-empty value sets it through the native
    // dvar setter selected for its runtime type.
    ExecuteResult Execute(const std::string& name, const std::string& value, std::string& message);

    bool IsKnownName(const std::string& name);
    bool IsVerified(const std::string& name);

    // Validates one runtime-discovered candidate through the authoritative
    // Dvar_FindVar path. A true return means the name is a registered dvar in
    // the current game state/build. The returned Entry contains live metadata.
    bool VerifyCandidate(const std::string& name, Entry& result);

    // Uses the exact same name resolution and Dvar_FindVar path as the dev-console
    // dispatcher. This is the authoritative probe used by /scan dvar.
    bool ProbeConsoleDvar(const std::string& name, Entry& result, std::string* message = nullptr);

    // Merges newly scanned names into the authoritative database. Verified
    // entries replace candidate-only records; names are deduplicated without
    // regard to case.
    void MergeCandidates(const std::vector<std::string>& names, Source source = Source::RuntimeDump);

    void WriteReport();

    // Continuous live capture used by /scan dvar. It polls every known
    // candidate through Dvar_FindVar, prints newly registered dvars and every
    // value/type/flag change, and appends the same events to CSV until stopped.
    bool StartLiveCapture();
    void StopLiveCapture();
    bool IsLiveCaptureRunning();
    bool SetCapturedLabel(std::uint32_t stableId, const std::string& label, std::string& message);
    void PrintLiveCaptureStatus();

    // Signature-independent numeric setter probes for build-specific dvar discovery.
    bool StartProbe(const std::string& mode);
    void StopProbe();
    void PrintProbeStatus();
    bool StartFloatProbe();
    void StopFloatProbe();
    void PrintFloatProbeStatus();

    // Executes verified, build-specific slash dvars through their native setters.
    // name is supplied without the leading slash.
    ExecuteResult ExecuteBuiltinSlashDvar(const std::string& name, const std::string& value, std::string& message);
}
