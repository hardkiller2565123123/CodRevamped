#pragma once

namespace scanner
{
    // Builds a richer read-only function database from PE unwind metadata,
    // direct calls, RIP-relative references, and printable strings.
    bool RunAdvancedAnalysisPass();
}
