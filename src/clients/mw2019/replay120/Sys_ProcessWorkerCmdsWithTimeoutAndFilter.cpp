#include "com_optimized.h"
#ifdef REPLAY_COMPILER_OPTIMIZED
#include "replay_workercmd.h"
#ifndef REPLAY_COMPILER_OPTIMIZED_TEST
#include <intrin.h>
#endif

extern "C" {
extern WorkerCmdData gl_14D53F300[WORKER_CMD_COUNT_REPLAY];
extern volatile int32_t gl_1445ADBB8[3]; // global wait-type preferences
extern volatile int32_t gl_14D57EE44;    // minimum queued type
extern volatile int32_t gl_14D57EE48;    // native event-waiter count
extern volatile uint32_t gl_14D57EE4C;   // worker-thread count
extern volatile uint8_t gl_14D57EE42;    // server participates as full worker
extern uint32_t TlsIndex;
bool Sys_IsRenderThread();
bool Sys_IsMainThread();
bool Sys_IsServerThread();
bool func_1412CDA80(int);                // native claim, dependency, callback, release
void func_1412CF460();                   // native reset worker event
void Sys_WaitForWorkerCmdWithTimeout();
void* func_1412CEF90(int);               // engine-owned per-thread jump buffer
int func_14108F230(int);                // current engine thread context
void func_141090870(int);               // native per-thread initialization
void func_1412AAC10();                  // fatal error after worker longjmp
void func_1412D04E0();                  // native infinite worker-event wait
#ifndef REPLAY_COMPILER_OPTIMIZED_TEST
__attribute__((returns_twice)) int __intrinsic_setjmp(void*, void*);
#endif
#ifdef REPLAY_COMPILER_OPTIMIZED_TEST
int Sys_WorkerTest_WaitType();
void Sys_WorkerTest_SleepZero();
void Sys_WorkerTest_BeforeClear(int);
void Sys_WorkerTest_CompareExchange();
#else
__declspec(dllimport) void __stdcall Sleep(unsigned long);
#endif
}

namespace {
void Yield() {
#ifdef REPLAY_COMPILER_OPTIMIZED_TEST
    Sys_WorkerTest_SleepZero();
#else
    Sleep(0);
#endif
}

int WaitType() {
#ifdef REPLAY_COMPILER_OPTIMIZED_TEST
    return Sys_WorkerTest_WaitType();
#else
    // The compiler retains the native TLS block and relocates TlsIndex.
    const auto slots = reinterpret_cast<const uintptr_t*>(__readgsqword(0x58));
    const auto* waitType = reinterpret_cast<const int32_t*>(slots[TlsIndex] + 336);
    return __atomic_load_n(waitType, __ATOMIC_RELAXED);
#endif
}

bool Blocked(const WorkerCmdData& queue, bool optimized, unsigned& threadRoles) {
    // A wait call cannot change its calling thread. Cache only these identity
    // predicates, lazily and per invocation; worker counts/participation and
    // queue flags still have their original live reads and short-circuit order.
    const auto isThread = [&](unsigned bit, bool (*query)()) {
        if (!optimized) return query();
        if (!(threadRoles & (bit << 8))) {
            if (query()) threadRoles |= bit;
            threadRoles |= bit << 8;
        }
        return (threadRoles & bit) != 0;
    };
    return ((queue.flags & 8) && isThread(8, Sys_IsRenderThread) && gl_14D57EE4C) ||
           ((queue.flags & 4) && isThread(4, Sys_IsMainThread) && gl_14D57EE4C) ||
           ((queue.flags & 16) && isThread(16, Sys_IsServerThread) && !gl_14D57EE42 && gl_14D57EE4C);
}

void ClearMinimum(int type, bool optimized) {
    // A failed CAS only observes this atomic; it cannot clear a different type.
    // Read first to avoid taking exclusive ownership of the shared cache line
    // for every empty/ineligible queue. A matching read still uses native CAS.
    // The seq_cst read is the observation point when the CAS can be skipped.
    if (optimized && __atomic_load_n(&gl_14D57EE44, __ATOMIC_SEQ_CST) != type) return;
#ifdef REPLAY_COMPILER_OPTIMIZED_TEST
    Sys_WorkerTest_BeforeClear(type);
    Sys_WorkerTest_CompareExchange();
#endif
    int32_t expected = type;
    __atomic_compare_exchange_n(&gl_14D57EE44, &expected, WORKER_CMD_NONE_REPLAY,
                                false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

// One native worker wake/drain/reset/rescan cycle. Unlike the timeout/filter
// helper, global wait preferences override this thread's TLS preference and
// dedicated workers do not apply render/main/server queue exclusion flags.
void ProcessWorkerWakeCycle() {
    const bool optimized = Com_Optimized_IsEnabled();
    bool resetEvent = true;
    for (;;) {
restart:
        int preferred = WaitType();
        for (unsigned i = 0; i < 3; ++i) {
            if (gl_1445ADBB8[i] != -1) {
                preferred = gl_1445ADBB8[i];
                break;
            }
        }
        if (preferred != -1 && gl_14D53F300[preferred].outSize > 0 &&
            func_1412CDA80(preferred)) {
            while (func_1412CDA80(preferred)) {}
            ClearMinimum(preferred, optimized);
            continue;
        }

        int start = __atomic_load_n(&gl_14D57EE44, __ATOMIC_RELAXED);
        if (start == WORKER_CMD_NONE_REPLAY) start = 0;
        for (int type = start; type < WORKER_CMD_COUNT_REPLAY; ++type) {
            if (gl_14D53F300[type].outSize > 0 && func_1412CDA80(type)) {
                // Original loop checks newly queued earlier types before each
                // additional claim. Claim/copy/dependency/callback/release and
                // producer wakeups stay entirely in the native routine.
                while (__atomic_load_n(&gl_14D57EE44, __ATOMIC_RELAXED) >= type) {
                    if (!func_1412CDA80(type)) {
                        ClearMinimum(type, optimized);
                        goto restart;
                    }
                }
                goto restart;
            }
            // This is the sampled hot path in Replay's dedicated worker loop.
            // Reuse the existing observation-before-CAS policy; a mismatch
            // needs no locked cache-line ownership. A match still uses CAS.
            ClearMinimum(type, optimized);
        }
        if (start) continue;
        if (!resetEvent) return;
        func_1412CF460();
        resetEvent = false;
    }
}
}

#ifdef REPLAY_COMPILER_OPTIMIZED_TEST
extern "C" void Sys_WorkerTest_RunWakeCycle() { ProcessWorkerWakeCycle(); }
#else
// Exact Replay worker entry identity. Keep native startup, jump-buffer ownership
// and error recovery around the optimized drain loop. The frame passed to the
// native setjmp is the current establisher RSP, as in the original instructions.
extern "C" void func_1412CE8A0(int threadContext) {
    void* jumpBuffer = func_1412CEF90(2);
    void* frame;
    __asm__ volatile("movq %%rsp, %0" : "=r"(frame));
    if (__intrinsic_setjmp(jumpBuffer, frame)) func_1412AAC10();
    func_141090870(func_14108F230(threadContext));
    for (;;) {
        __atomic_add_fetch(&gl_14D57EE48, 1, __ATOMIC_SEQ_CST);
        func_1412D04E0();
        __atomic_sub_fetch(&gl_14D57EE48, 1, __ATOMIC_SEQ_CST);
        ProcessWorkerWakeCycle();
    }
}
#endif

extern "C" bool Sys_ProcessWorkerCmdsWithTimeoutAndFilter(
        bool (*timeout)(void*), void* userData, bool onlyOfType) {
    // Snapshot only this optimization policy; all scheduler state stays live.
    const bool optimized = Com_Optimized_IsEnabled();
    unsigned threadRoles = 0;
    for (;;) {
        if (timeout(userData)) return true;
        bool resetEvent = true;
        for (;;) {
restart:
            int preferred = WaitType();
            if (preferred == -1) {
                for (unsigned i = 0; i < 3; ++i) {
                    preferred = gl_1445ADBB8[i];
                    if (preferred != -1) break;
                }
            }
            const bool stall = onlyOfType && gl_14D57EE4C;
            if (preferred != -1) {
                const auto& queue = gl_14D53F300[preferred];
                if (queue.outSize <= 0 || Blocked(queue, optimized, threadRoles)) {
                    if (stall) {
                        while (!timeout(userData)) Yield();
                        return true;
                    }
                } else if (func_1412CDA80(preferred)) {
                    do {
                        if (timeout(userData)) return true;
                    } while (func_1412CDA80(preferred));
                    ClearMinimum(preferred, optimized);
                    continue;
                } else if (stall) {
                    if (timeout(userData)) return true;
                    Yield();
                    continue;
                }
            }

            int start = __atomic_load_n(&gl_14D57EE44, __ATOMIC_RELAXED);
            if (start == WORKER_CMD_NONE_REPLAY) start = 0;
            for (int type = start; type < WORKER_CMD_COUNT_REPLAY; ++type) {
                const auto& queue = gl_14D53F300[type];
                if (queue.outSize > 0 && !Blocked(queue, optimized, threadRoles) && func_1412CDA80(type)) {
                    do {
                        if (timeout(userData)) return true;
                        if (__atomic_load_n(&gl_14D57EE44, __ATOMIC_RELAXED) < type) goto restart;
                    } while (func_1412CDA80(type));
                    ClearMinimum(type, optimized);
                    goto restart;
                }
                ClearMinimum(type, optimized);
            }
            if (timeout(userData)) return true;
            if (!start) {
                if (resetEvent) {
                    func_1412CF460();
                    resetEvent = false;
                } else {
                    __atomic_add_fetch(&gl_14D57EE48, 1, __ATOMIC_SEQ_CST);
                    Sys_WaitForWorkerCmdWithTimeout();
                    __atomic_sub_fetch(&gl_14D57EE48, 1, __ATOMIC_SEQ_CST);
                    break;
                }
            }
        }
    }
}
#endif
