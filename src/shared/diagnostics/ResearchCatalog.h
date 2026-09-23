#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace research_catalog
{
    enum class EntryKind { Function, Reference };
    enum class ResolveKind { CALL, MOV, LEA, OFFSET };

    struct Entry
    {
        const char* name;
        std::uint64_t referenceRva;
        EntryKind kind;
        const char* subsystem;
        const char* source;
        bool runtimeValidated;
        std::uintptr_t runtimeAddress = 0;
        bool currentBuildCandidate = false;
    };

    struct Pattern
    {
        const char* name;
        const char* bytes;
        ResolveKind resolve;
        std::uint32_t operandOffset;
        std::uintptr_t resolvedAddress;
        bool unique;
        bool scalarValue = false;
        std::string status;
    };

    void Initialize(std::uintptr_t moduleBase);
    void ResolveAll();
    void Revalidate();
    std::vector<Entry> Search(const std::string& query, std::size_t limit = 64);
    std::vector<Pattern> PatternSnapshot();
    bool TryGetResolved(const std::string& name, std::uintptr_t& value, bool& scalar);
    std::string BuildFingerprint();
    std::size_t EntryCount();
    std::size_t ResolvedCount();
    void WriteReports();
}
