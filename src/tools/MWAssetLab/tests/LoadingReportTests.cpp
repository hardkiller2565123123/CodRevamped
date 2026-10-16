#include "../LoadingReport.h"
#include "../../../clients/mw2019/Features/Loading/HostLaunchTrace.h"
#include <cassert>
#include <sstream>
#include <string>

int main() {
    using codrevamped::mw120::loading::HostLaunchTrace;
    using codrevamped::mw120::loading::LastObservedPhase;
    HostLaunchTrace trace;
    assert(std::string(LastObservedPhase(trace.Read())) == "no-native-request-observed");
    trace.RecordRequest(100);
    assert(std::string(LastObservedPhase(trace.Read())) == "request-only-no-native-ready-or-start-observed");
    trace.RecordPolicyBlocked(false);
    assert(std::string(LastObservedPhase(trace.Read())) == "native-launch-attempt-blocked-by-local-policy");
    trace.RecordReady(110, false);
    assert(std::string(LastObservedPhase(trace.Read())) == "native-ready-observed-not-accepted");
    trace.RecordReady(120, true);
    assert(std::string(LastObservedPhase(trace.Read())) == "native-ready-accepted-no-start-internal-observed");
    trace.RecordStart(130, 0);
    assert(std::string(LastObservedPhase(trace.Read())) == "start-internal-returned-zero-uninterpreted");
    trace.RecordStart(140, 12);
    assert(trace.Read().internalCalls == 2);
    trace.Reset();assert(trace.Read().internalCalls == 0);
    std::istringstream text("[BOT120-LAUNCH] requested\n[FF120-MODE] selected=1\n[LOAD120] phase=x\n"
                             "[LSG-ROUTE] operation=matchmaker-lobby-disbanded\n");
    auto report=codrevamped::mwassetlab::loading::Parse(text,"fixture");
    assert(report.events.size()==4);
    assert(report.events[0].type=="native-start-request");
    assert(report.events[3].type=="server-lobby-disband");
}
