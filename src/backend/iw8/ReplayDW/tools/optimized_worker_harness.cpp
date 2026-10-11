#include "replay_workercmd.h"

extern "C" {
extern uint32_t s_comOptimizedMode;
WorkerCmdData gl_14D53F300[WORKER_CMD_COUNT_REPLAY]{};
volatile int32_t gl_1445ADBB8[3] = {-1,-1,-1};
volatile int32_t gl_14D57EE44 = WORKER_CMD_NONE_REPLAY;
volatile int32_t gl_14D57EE48 = 0;
volatile uint32_t gl_14D57EE4C = 2;
volatile uint8_t gl_14D57EE42 = 0;
uint32_t TlsIndex = 0;
}

static int waitType = -1, goalJobs, raceType = -1;
static bool renderThread, serverThread, done, injectEarlier, failedDependency;
static unsigned checks, tlsReads, resets, waits, sleeps, attempts, completed, claims;
static unsigned renderQueries, serverQueries;
static bool changeWorkers, changeParticipation;
static bool benchmarking, enqueueOnReset;
static int processed[8];
static bool invariants;

extern "C" {
void Sys_WorkerTest_RunWakeCycle();
int Sys_WorkerTest_WaitType() { if (!benchmarking) ++tlsReads; return waitType; }
bool Sys_IsRenderThread() { ++renderQueries; return renderThread; }
bool Sys_IsServerThread() { ++serverQueries; return serverThread; }
void Sys_WorkerTest_CompareExchange() { if (!benchmarking) ++attempts; }
void Sys_WorkerTest_BeforeClear(int type) {
    if (benchmarking) return;
    if (raceType == type) {
        // An earlier queue update between the optimistic read and CAS
        // must not be erased by a stale expected value.
        gl_14D57EE44 = 1;
        gl_14D53F300[1].outSize = 1;
        raceType = -1;
    }
}
void Sys_WorkerTest_SleepZero() { ++sleeps; done = true; }
void func_1412CF460() {
    if (benchmarking) return;
    ++resets;
    if (enqueueOnReset) {
        enqueueOnReset = false;
        gl_14D53F300[6].outSize = 1;
        gl_14D57EE44 = 6;
    }
}
void Sys_WaitForWorkerCmdWithTimeout() {
    ++waits;
    invariants &= gl_14D57EE48 == 1;
    done = true;
}
bool func_1412CDA80(int type) {
    ++claims;
    invariants &= type >= 0 && type < WORKER_CMD_COUNT_REPLAY;
    if (failedDependency || gl_14D53F300[type].outSize <= 0) return false;
    gl_14D53F300[type].outSize = gl_14D53F300[type].outSize - 1;
    processed[completed++] = type;
    if (injectEarlier) {
        injectEarlier = false;
        gl_14D53F300[2].outSize = 1;
        gl_14D57EE44 = 2;
    }
    return true;
}
}

static bool Timeout(void* user) {
    invariants &= user == &goalJobs;
    ++checks;
    if (checks == 2 && changeWorkers) gl_14D57EE4C = 0;
    if (checks == 2 && changeParticipation) gl_14D57EE42 = 1;
    // The ceiling makes a scheduler regression report a failing invariant.
    if (checks > 2000) { invariants = false; return true; }
    return done || (goalJobs && completed >= unsigned(goalJobs));
}

static void Reset(unsigned optimized) {
    for (auto& queue : gl_14D53F300) queue = {};
    for (auto& type : gl_1445ADBB8) type = -1;
    gl_14D57EE44 = WORKER_CMD_NONE_REPLAY;
    gl_14D57EE48 = 0;
    gl_14D57EE4C = 2;
    gl_14D57EE42 = 0;
    s_comOptimizedMode = optimized;
    waitType = raceType = -1;
    goalJobs = 0;
    renderThread = serverThread = done = injectEarlier = failedDependency = false;
    checks = tlsReads = resets = waits = sleeps = attempts = completed = claims = 0;
    renderQueries = serverQueries = 0;
    changeWorkers = changeParticipation = false;
    benchmarking = enqueueOnReset = false;
    invariants = true;
}

#define CHECK(x) do { if (!(x)) return __LINE__; } while (false)
extern "C" __declspec(dllexport) int Test_Worker_Run() {
    for (unsigned optimized = 0; optimized <= 2; ++optimized) {
        Reset(optimized); done = true;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(checks == 1 && !tlsReads && !attempts && !waits);

        Reset(optimized);
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && resets == 1 && waits == 1 && !sleeps && !claims);
        CHECK(gl_14D57EE48 == 0 && checks == 4);
        CHECK(attempts == (optimized ? 0 : 294));

        Reset(optimized); goalJobs = 2;
        gl_14D57EE44 = 13; gl_14D53F300[13].outSize = 2;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && completed == 2 && processed[0] == 13 && processed[1] == 13);
        CHECK(!waits && !resets && !sleeps);

        Reset(optimized); goalJobs = 2; injectEarlier = true;
        gl_14D57EE44 = 13; gl_14D53F300[13].outSize = 1;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && completed == 2 && processed[0] == 13 && processed[1] == 2);

        Reset(optimized); goalJobs = 1; waitType = 7;
        gl_14D53F300[7].outSize = 1; gl_14D53F300[2].outSize = 1;
        gl_14D57EE44 = 2;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,true));
        CHECK(invariants && processed[0] == 7 && gl_14D53F300[2].outSize == 1);

        Reset(optimized); goalJobs = 1; gl_1445ADBB8[1] = 9;
        gl_14D53F300[9].outSize = 1;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && processed[0] == 9);

        Reset(optimized); waitType = 7;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,true));
        CHECK(invariants && sleeps == 1 && !claims && !waits);

        Reset(optimized); waitType = 7; failedDependency = true;
        gl_14D53F300[7].outSize = 1;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,true));
        // Native flow tries the preferred queue again after yielding, before
        // observing the timeout callback's newly ready result.
        CHECK(invariants && sleeps == 1 && claims == 2 && !completed);

        // Every native exclusion bit retains the corresponding off path.
        constexpr unsigned exclusionFlags[] = {4,8,16};
        for (unsigned flag : exclusionFlags) {
            Reset(optimized); waitType = 7;
            renderThread = serverThread = true;
            gl_14D53F300[7].flags = flag; gl_14D53F300[7].outSize = 1;
            CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,true));
            CHECK(invariants && sleeps == 1 && !claims && !completed);
        }
        // Native full-worker server participation overrides its exclusion.
        Reset(optimized); goalJobs = 1; waitType = 7; serverThread = true;
        gl_14D57EE42 = 1; gl_14D53F300[7].flags = 16; gl_14D53F300[7].outSize = 1;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,true));
        CHECK(invariants && processed[0] == 7);

        // With no worker threads, the caller handles the queue itself.
        Reset(optimized); goalJobs = 1; waitType = 7; gl_14D57EE4C = 0;
        renderThread = true; gl_14D53F300[7].flags = 8; gl_14D53F300[7].outSize = 1;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,true));
        CHECK(invariants && processed[0] == 7 && !sleeps);

        // An eligible queue after a forbidden queue is still dispatched.
        Reset(optimized); goalJobs = 1; renderThread = true;
        gl_14D57EE44 = 3; gl_14D53F300[3].flags = 8; gl_14D53F300[3].outSize = 1;
        gl_14D53F300[146].outSize = 1;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && processed[0] == 146 && gl_14D53F300[3].outSize == 1);

        // Matching minimum values still require the original atomic update.
        Reset(optimized); gl_14D57EE44 = 0;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && gl_14D57EE44 == WORKER_CMD_NONE_REPLAY);
        CHECK(attempts == (optimized ? 1 : 294));

        // A concurrent lower queued type wins over the attempted clear.
        Reset(optimized); goalJobs = 1; raceType = 8; gl_14D57EE44 = 8;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && completed == 1 && processed[0] == 1 && !waits);

        // Identity is reused across both scans, including false predicates.
        // Failed dependencies are still tried; only repeated role queries go.
        Reset(optimized); failedDependency = true;
        for (auto& queue : gl_14D53F300) { queue.flags = 8 | 16; queue.outSize = 1; }
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && claims == 294 && resets == 1 && waits == 1);
        CHECK(renderQueries == (optimized ? 1 : 294));
        CHECK(serverQueries == (optimized ? 1 : 294));

        // Participation may change during a wait even though thread identity
        // cannot. Neither control may accidentally become part of the cache.
        Reset(optimized); goalJobs = 1; renderThread = changeWorkers = true;
        gl_14D53F300[7].flags = 8; gl_14D53F300[7].outSize = 1;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && completed == 1 && processed[0] == 7 && !waits);
        CHECK(renderQueries == (optimized ? 1 : 2));

        Reset(optimized); goalJobs = 1; serverThread = changeParticipation = true;
        gl_14D53F300[7].flags = 16; gl_14D53F300[7].outSize = 1;
        CHECK(Sys_ProcessWorkerCmdsWithTimeoutAndFilter(Timeout,&goalJobs,false));
        CHECK(invariants && completed == 1 && processed[0] == 7 && !waits);
        CHECK(serverQueries == (optimized ? 1 : 2));

        // The actual dedicated-worker cycle always scans, resets its native
        // event, and rescans before the surrounding entry may block again.
        Reset(optimized);
        Sys_WorkerTest_RunWakeCycle();
        CHECK(invariants && resets == 1 && !claims && !waits && !sleeps);
        CHECK(attempts == (optimized ? 0 : 294));

        Reset(optimized); gl_14D57EE44 = 13; gl_14D53F300[13].outSize = 2;
        Sys_WorkerTest_RunWakeCycle();
        CHECK(invariants && completed == 2 && processed[0] == 13 && processed[1] == 13);
        CHECK(resets == 1 && !waits && gl_14D57EE44 == WORKER_CMD_NONE_REPLAY);

        // Global preference overrides TLS here (the timeout helper differs).
        Reset(optimized); waitType = 7; gl_1445ADBB8[1] = 9;
        gl_14D53F300[7].outSize = 1; gl_14D53F300[9].outSize = 1;
        gl_14D53F300[9].flags = 4 | 8 | 16;
        Sys_WorkerTest_RunWakeCycle();
        CHECK(invariants && completed == 2 && processed[0] == 9 && processed[1] == 7);

        Reset(optimized); injectEarlier = true; gl_14D57EE44 = 13;
        gl_14D53F300[13].outSize = 1;
        Sys_WorkerTest_RunWakeCycle();
        CHECK(invariants && completed == 2 && processed[0] == 13 && processed[1] == 2);

        Reset(optimized); failedDependency = true; gl_14D53F300[8].outSize = 1;
        Sys_WorkerTest_RunWakeCycle();
        CHECK(invariants && claims == 2 && !completed && resets == 1);
        CHECK(gl_14D53F300[8].outSize == 1);

        // A producer racing event reset remains visible to the second scan.
        Reset(optimized); enqueueOnReset = true;
        Sys_WorkerTest_RunWakeCycle();
        CHECK(invariants && completed == 1 && processed[0] == 6 && resets == 1);

        Reset(optimized); raceType = 8; gl_14D57EE44 = 8;
        Sys_WorkerTest_RunWakeCycle();
        CHECK(invariants && completed == 1 && processed[0] == 1 && resets == 1);
    }
    s_comOptimizedMode = 0;
    return 0;
}

extern "C" __declspec(dllexport) void Test_Worker_BenchmarkSetup(unsigned mode) {
    Reset(mode);
    benchmarking = true;
}
extern "C" __declspec(dllexport) void Test_Worker_Benchmark(unsigned cycles) {
    for (unsigned i = 0; i < cycles; ++i) Sys_WorkerTest_RunWakeCycle();
}
