#pragma once
// Passive native launch stage counter for Replay 1.20. No native hooks, game
// memory writes, session spoofing or automatic retries are performed here.
// This class only records outcomes observed by the EXISTING native detours.
#include <atomic>
#include <cstdint>

namespace codrevamped::mw120::loading {
struct Snapshot {
    std::uint64_t requestTick = 0;
    std::uint64_t readyTick = 0;
    std::uint64_t internalTick = 0;
    std::uint32_t readyChecks = 0;
    std::uint32_t readyAccepted = 0;
    std::uint32_t internalCalls = 0;
    std::uint32_t policyBlockedReady = 0;
    std::uint32_t policyBlockedStart = 0;
    std::uint64_t lastInternalResult = 0;
};
class HostLaunchTrace {
    std::atomic<std::uint64_t> request_{0};
    std::atomic<std::uint64_t> ready_{0};
    std::atomic<std::uint64_t> internal_{0};
    std::atomic<std::uint64_t> result_{0};
    std::atomic<std::uint32_t> checks_{0};
    std::atomic<std::uint32_t> accepted_{0};
    std::atomic<std::uint32_t> starts_{0};
    std::atomic<std::uint32_t> blockedReady_{0}, blockedStart_{0};
public:
    void Reset() noexcept {
        request_.store(0); ready_.store(0); internal_.store(0);
        result_.store(0); checks_.store(0); accepted_.store(0); starts_.store(0);
        blockedReady_.store(0); blockedStart_.store(0);
    }
    void RecordRequest(std::uint64_t tick) noexcept { request_.store(tick); }
    void RecordPolicyBlocked(bool startPath) noexcept {
        if(startPath) blockedStart_.fetch_add(1); else blockedReady_.fetch_add(1);
    }
    void RecordReady(std::uint64_t tick, bool ok) noexcept {
        checks_.fetch_add(1);
        if (ok) accepted_.fetch_add(1);
        ready_.store(tick);
    }
    void RecordStart(std::uint64_t tick, std::uint64_t result) noexcept {
        starts_.fetch_add(1); result_.store(result); internal_.store(tick);
    }
    Snapshot Read() const noexcept {
        Snapshot v;
        v.requestTick=request_.load();v.readyTick=ready_.load();
        v.internalTick=internal_.load();v.lastInternalResult=result_.load();
        v.readyChecks=checks_.load();v.readyAccepted=accepted_.load();
        v.internalCalls=starts_.load();v.policyBlockedReady=blockedReady_.load();
        v.policyBlockedStart=blockedStart_.load();return v;
    }
};
// These are OBSERVED STATES, NOT REASONS for game teardown.
inline const char* LastObservedPhase(const Snapshot& s) noexcept {
    if (!s.requestTick) return "no-native-request-observed";
    if (!s.readyChecks && !s.internalCalls && (s.policyBlockedReady || s.policyBlockedStart))
        return "native-launch-attempt-blocked-by-local-policy";
    if (!s.readyChecks && !s.internalCalls) return "request-only-no-native-ready-or-start-observed";
    if (!s.internalCalls && !s.readyAccepted) return "native-ready-observed-not-accepted";
    if (!s.internalCalls) return "native-ready-accepted-no-start-internal-observed";
    if (!s.lastInternalResult) return "start-internal-returned-zero-uninterpreted";
    return "start-internal-called-result-uninterpreted";
}
}
