// Included inside the server bridge namespace; uses its bounded safe-read/log helpers.
//
// V111: crash-resistant SessionService completion execution watch.
//
// V110.1 deliberately disabled generic function-entry detours because the three
// interesting routines are obfuscated and their real ABI/prologue requirements
// are not proven. V111 does not detour or rewrite any stock IW8 instruction.
// Instead it uses x64 hardware EXECUTE breakpoints (DR0-DR2) on the exact,
// already-verified instruction boundaries:
//   DR0 -> 0x4642C90  auth-result bit-7 gate
//   DR1 -> 0x4642CE8  CALL 0x4641A60 (installer callsite)
//   DR2 -> 0x46417FF  MOV [RCX],2 (confirmed state-2 writer)
//
// The breakpoints are armed on existing game threads and newly discovered game
// threads for a bounded window. On a hit the VEH only snapshots registers/state,
// disables that one debug slot for the current thread, and resumes the untouched
// stock instruction. No code byte, vtable, auth state, Source3 value, fence, or
// menu/LUI state is modified.

struct V111ExecutionCapture144
{
    DWORD tid{};
    ULONGLONG tickMs{};
    std::uintptr_t rip{};
    std::uintptr_t rcx{};
    std::uintptr_t rdx{};
    std::uintptr_t rsi{};
    std::uintptr_t rdi{};
    std::uintptr_t rsp{};
    std::uint32_t firstState{};

    // Gate-specific snapshot.
    std::uint32_t flags10{};
    std::uint32_t requiredField28{};
    std::uint32_t errorCode38{};
    std::uintptr_t ptr60{};
    std::uintptr_t ptr68{};
    bool gateObjectReadable{};

    // Installer-call-specific snapshot.
    std::uintptr_t payloadQword0{};
    std::uintptr_t payloadQword8{};
    bool payloadReadable{};

    // Success-writer-specific snapshot.
    std::uint32_t successOldState{};
    std::uint32_t successOldError{};
    bool successStateReadable{};
    bool successErrorReadable{};
};

struct V111ThreadDebugState144
{
    DWORD tid{};
    DWORD64 dr0{};
    DWORD64 dr1{};
    DWORD64 dr2{};
    DWORD64 dr6{};
    DWORD64 dr7{};
};

static PVOID g_v111Veh144 = nullptr;
static HANDLE g_v111Worker144 = nullptr;
static std::atomic_bool g_v111Started144{false};
static std::atomic_bool g_v111Stop144{false};
static std::atomic_bool g_v111Finished144{false};
static std::atomic_uint g_v111ThreadsArmed144{0};
static volatile LONG g_v111GateCaptureState144 = 0;     // 0=none,1=writing,2=ready
static volatile LONG g_v111CallCaptureState144 = 0;     // 0=none,1=writing,2=ready
static volatile LONG g_v111SuccessCaptureState144 = 0;  // 0=none,1=writing,2=ready
static V111ExecutionCapture144 g_v111GateCapture144{};
static V111ExecutionCapture144 g_v111CallCapture144{};
static V111ExecutionCapture144 g_v111SuccessCapture144{};
static std::atomic_bool g_v111StaticLogged144{false};

static constexpr std::uintptr_t kV111GateRva144 = 0x4642C90u;
static constexpr std::uintptr_t kV111InstallerCallRva144 = 0x4642CE8u;
static constexpr std::uintptr_t kV111SuccessWriterRva144 = 0x46417FFu;
static constexpr ULONGLONG kV111SignatureWaitTimeoutMs144 = 120000ull;
static constexpr ULONGLONG kV111NoGateTimeoutMs144 = 180000ull;
static constexpr ULONGLONG kV111AfterGateNoCallTimeoutMs144 = 5000ull;
static constexpr ULONGLONG kV111AfterCallNoSuccessTimeoutMs144 = 15000ull;

static bool V111CaptureReady144(volatile LONG* state) noexcept
{
    return state && InterlockedCompareExchange(state, 0, 0) == 2;
}

static void V111DisableDebugSlotInContext144(CONTEXT* c, unsigned slot) noexcept
{
    if (!c || slot > 3u)
        return;

    const DWORD64 enableMask = static_cast<DWORD64>(0x3ull) << (slot * 2u);
    const DWORD64 controlMask = static_cast<DWORD64>(0xFull) << (16u + slot * 4u);
    c->Dr7 &= ~enableMask;   // clear local/global enable for this slot
    c->Dr7 &= ~controlMask;  // force execute/len1 semantics off with the slot
    c->Dr6 = 0;
}

static void V111CaptureCommon144(V111ExecutionCapture144& out, const CONTEXT* c) noexcept
{
    if (!c)
        return;

    out.tid = GetCurrentThreadId();
    out.tickMs = GetTickCount64();
    out.rip = static_cast<std::uintptr_t>(c->Rip);
    out.rcx = static_cast<std::uintptr_t>(c->Rcx);
    out.rdx = static_cast<std::uintptr_t>(c->Rdx);
    out.rsi = static_cast<std::uintptr_t>(c->Rsi);
    out.rdi = static_cast<std::uintptr_t>(c->Rdi);
    out.rsp = static_cast<std::uintptr_t>(c->Rsp);

    const auto base = MainImageBase();
    if (base)
        ServerEmuSafeReadU32(reinterpret_cast<const void*>(base + iw8_addresses::MW2019_1_44_Discovery.BNetFirstStateValue), out.firstState);
}

static LONG CALLBACK V111HardwareExecutionVeh144(PEXCEPTION_POINTERS ep) noexcept
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord ||
        ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto base = MainImageBase();
    if (!base)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT* c = ep->ContextRecord;
    const std::uintptr_t rip = static_cast<std::uintptr_t>(c->Rip);
    const std::uintptr_t gateVa = base + kV111GateRva144;
    const std::uintptr_t callVa = base + kV111InstallerCallRva144;
    const std::uintptr_t successVa = base + kV111SuccessWriterRva144;

    if (rip == gateVa)
    {
        // One-shot for this thread: execute the untouched MOV after we return.
        V111DisableDebugSlotInContext144(c, 0u);

        if (InterlockedCompareExchange(&g_v111GateCaptureState144, 1, 0) == 0)
        {
            auto& out = g_v111GateCapture144;
            V111CaptureCommon144(out, c);
            out.gateObjectReadable =
                ServerEmuSafeReadU32(reinterpret_cast<const void*>(out.rsi + 0x10u), out.flags10) &&
                ServerEmuSafeReadU32(reinterpret_cast<const void*>(out.rsi + 0x28u), out.requiredField28) &&
                ServerEmuSafeReadU32(reinterpret_cast<const void*>(out.rsi + 0x38u), out.errorCode38);
            ServerEmuSafeReadPointer(reinterpret_cast<const void*>(out.rsi + 0x60u), out.ptr60);
            ServerEmuSafeReadPointer(reinterpret_cast<const void*>(out.rsi + 0x68u), out.ptr68);
            InterlockedExchange(&g_v111GateCaptureState144, 2);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (rip == callVa)
    {
        // One-shot for this thread: execute the untouched CALL after we return.
        V111DisableDebugSlotInContext144(c, 1u);

        if (InterlockedCompareExchange(&g_v111CallCaptureState144, 1, 0) == 0)
        {
            auto& out = g_v111CallCapture144;
            V111CaptureCommon144(out, c);
            const bool q0 = ServerEmuSafeReadPointer(reinterpret_cast<const void*>(out.rdx), out.payloadQword0);
            const bool q8 = ServerEmuSafeReadPointer(reinterpret_cast<const void*>(out.rdx + sizeof(std::uintptr_t)), out.payloadQword8);
            out.payloadReadable = q0 && q8;
            InterlockedExchange(&g_v111CallCaptureState144, 2);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (rip == successVa)
    {
        // One-shot for this thread: execute the untouched MOV [RCX],2 after return.
        V111DisableDebugSlotInContext144(c, 2u);

        if (InterlockedCompareExchange(&g_v111SuccessCaptureState144, 1, 0) == 0)
        {
            auto& out = g_v111SuccessCapture144;
            V111CaptureCommon144(out, c);
            out.successStateReadable =
                ServerEmuSafeReadU32(reinterpret_cast<const void*>(out.rcx), out.successOldState);
            out.successErrorReadable =
                ServerEmuSafeReadU32(reinterpret_cast<const void*>(out.rcx + 0x1C8u), out.successOldError);
            InterlockedExchange(&g_v111SuccessCaptureState144, 2);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static bool V111VerifySignatures144(bool emitLog) noexcept
{
    const auto base = MainImageBase();
    const auto size = MainImageSize();
    if (!base || size <= kV111InstallerCallRva144 + 5u || size <= kV111SuccessWriterRva144 + 6u)
    {
        if (emitLog)
        {
            ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
                "[V111-SIGNATURE] ready=no reason=IMAGE_RANGE_NOT_READY base=%p size=0x%llX "
                "codeWrites=off stateWrites=off\r\n",
                reinterpret_cast<void*>(base), static_cast<unsigned long long>(size));
        }
        return false;
    }

    unsigned char gate[3]{};
    unsigned char call[5]{};
    unsigned char success[6]{};
    const bool gateReadable =
        ServerEmuSafeReadBytes(reinterpret_cast<const void*>(base + kV111GateRva144), gate, sizeof(gate));
    const bool callReadable =
        ServerEmuSafeReadBytes(reinterpret_cast<const void*>(base + kV111InstallerCallRva144), call, sizeof(call));
    const bool successReadable =
        ServerEmuSafeReadBytes(reinterpret_cast<const void*>(base + kV111SuccessWriterRva144), success, sizeof(success));

    const bool gateOk = gateReadable && gate[0] == 0x8B && gate[1] == 0x46 && gate[2] == 0x10;
    const bool callOk = callReadable && call[0] == 0xE8 && call[1] == 0x73 && call[2] == 0xED && call[3] == 0xFF && call[4] == 0xFF;
    const bool successOk = successReadable && success[0] == 0xC7 && success[1] == 0x01 && success[2] == 0x02 &&
        success[3] == 0x00 && success[4] == 0x00 && success[5] == 0x00;

    if (emitLog || (gateOk && callOk && successOk))
    {
        ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
            "[V111-SIGNATURE] gate={rva:0x4642C90 readable:%s match:%s bytes:%02X-%02X-%02X} "
            "installerCall={rva:0x4642CE8 readable:%s match:%s bytes:%02X-%02X-%02X-%02X-%02X} "
            "successWriter={rva:0x46417FF readable:%s match:%s bytes:%02X-%02X-%02X-%02X-%02X-%02X} "
            "ready=%s codeWrites=off stateWrites=off\r\n",
            gateReadable ? "yes" : "no", gateOk ? "YES" : "no", gate[0], gate[1], gate[2],
            callReadable ? "yes" : "no", callOk ? "YES" : "no", call[0], call[1], call[2], call[3], call[4],
            successReadable ? "yes" : "no", successOk ? "YES" : "no", success[0], success[1], success[2], success[3], success[4], success[5],
            gateOk && callOk && successOk ? "YES" : "no");
    }

    return gateOk && callOk && successOk;
}

static bool V111ArmThread144(DWORD tid, V111ThreadDebugState144& saved) noexcept
{
    if (!tid || tid == GetCurrentThreadId())
        return false;

    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE, tid);
    if (!thread)
        return false;

    bool armed = false;
    const DWORD suspend = SuspendThread(thread);
    if (suspend != static_cast<DWORD>(-1))
    {
        CONTEXT c{};
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &c))
        {
            // Do not steal hardware-breakpoint slots from an attached debugger or
            // another diagnostic component. DR0-DR2 local/global enable bits occupy
            // bits 0..5 in DR7.
            if ((c.Dr7 & 0x3Full) == 0)
            {
                saved.tid = tid;
                saved.dr0 = c.Dr0;
                saved.dr1 = c.Dr1;
                saved.dr2 = c.Dr2;
                saved.dr6 = c.Dr6;
                saved.dr7 = c.Dr7;

                const auto base = MainImageBase();
                c.Dr0 = static_cast<DWORD64>(base + kV111GateRva144);
                c.Dr1 = static_cast<DWORD64>(base + kV111InstallerCallRva144);
                c.Dr2 = static_cast<DWORD64>(base + kV111SuccessWriterRva144);

                // Clear RW/LEN control fields for DR0-DR2 (execute, length 1), then
                // enable local breakpoints L0/L1/L2. Preserve unrelated DR7 bits.
                c.Dr7 &= ~((0xFull << 16u) | (0xFull << 20u) | (0xFull << 24u));
                c.Dr7 |= (1ull << 0u) | (1ull << 2u) | (1ull << 4u);
                c.Dr6 = 0;
                armed = SetThreadContext(thread, &c) != FALSE;
            }
        }
        ResumeThread(thread);
    }

    CloseHandle(thread);
    return armed;
}

static void V111RestoreThread144(const V111ThreadDebugState144& saved) noexcept
{
    if (!saved.tid)
        return;

    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE, saved.tid);
    if (!thread)
        return;

    const DWORD suspend = SuspendThread(thread);
    if (suspend != static_cast<DWORD>(-1))
    {
        CONTEXT c{};
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &c))
        {
            c.Dr0 = saved.dr0;
            c.Dr1 = saved.dr1;
            c.Dr2 = saved.dr2;
            c.Dr6 = saved.dr6;
            c.Dr7 = saved.dr7;
            SetThreadContext(thread, &c);
        }
        ResumeThread(thread);
    }
    CloseHandle(thread);
}

static bool V111ThreadAlreadyTracked144(const std::vector<V111ThreadDebugState144>& states, DWORD tid) noexcept
{
    for (const auto& state : states)
        if (state.tid == tid)
            return true;
    return false;
}

static unsigned V111ArmNewThreads144(std::vector<V111ThreadDebugState144>& states) noexcept
{
    unsigned added = 0;
    const DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID != pid || V111ThreadAlreadyTracked144(states, entry.th32ThreadID))
                continue;

            V111ThreadDebugState144 saved{};
            if (V111ArmThread144(entry.th32ThreadID, saved))
            {
                states.push_back(saved);
                ++added;
            }
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    if (added)
        g_v111ThreadsArmed144.fetch_add(added, std::memory_order_acq_rel);
    return added;
}

static void V111LogCaptures144(bool& gateLogged, bool& callLogged, bool& successLogged) noexcept
{
    if (!gateLogged && V111CaptureReady144(&g_v111GateCaptureState144))
    {
        gateLogged = true;
        const auto& c = g_v111GateCapture144;
        const bool bit7 = (c.flags10 & 0x80u) != 0u;
        ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
            "[V111-GATE-HIT] tid=%lu tickMs=%llu rip=0x%llX firstState=%u rsi=%p rdi=%p "
            "flags10=0x%08X bit7=%u expectedInstallerPath=%s requiredField28=0x%08X errorCode38=0x%08X "
            "ptr60=%p ptr68=%p objectReadable=%s codeWrites=off stateWrites=off\r\n",
            c.tid, static_cast<unsigned long long>(c.tickMs),
            static_cast<unsigned long long>(c.rip - MainImageBase()), static_cast<unsigned>(c.firstState),
            reinterpret_cast<void*>(c.rsi), reinterpret_cast<void*>(c.rdi),
            static_cast<unsigned>(c.flags10), bit7 ? 1u : 0u,
            bit7 ? "no_BIT7_SET_FALLTHROUGH" : "YES_BIT7_CLEAR_BRANCH",
            static_cast<unsigned>(c.requiredField28), static_cast<unsigned>(c.errorCode38),
            reinterpret_cast<void*>(c.ptr60), reinterpret_cast<void*>(c.ptr68),
            c.gateObjectReadable ? "yes" : "no");
    }

    if (!callLogged && V111CaptureReady144(&g_v111CallCaptureState144))
    {
        callLogged = true;
        const auto& c = g_v111CallCapture144;
        ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
            "[V111-INSTALLER-CALL-HIT] tid=%lu tickMs=%llu rip=0x%llX firstState=%u "
            "rcx=%p rdx=%p rsi=%p rdi=%p payloadQ0=%p payloadQ8=%p payloadReadable=%s "
            "proof=0x4642CE8_TO_0x4641A60_EXECUTED codeWrites=off stateWrites=off\r\n",
            c.tid, static_cast<unsigned long long>(c.tickMs),
            static_cast<unsigned long long>(c.rip - MainImageBase()), static_cast<unsigned>(c.firstState),
            reinterpret_cast<void*>(c.rcx), reinterpret_cast<void*>(c.rdx),
            reinterpret_cast<void*>(c.rsi), reinterpret_cast<void*>(c.rdi),
            reinterpret_cast<void*>(c.payloadQword0), reinterpret_cast<void*>(c.payloadQword8),
            c.payloadReadable ? "yes" : "no");
    }

    if (!successLogged && V111CaptureReady144(&g_v111SuccessCaptureState144))
    {
        successLogged = true;
        const auto& c = g_v111SuccessCapture144;
        ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
            "[V111-SUCCESS-WRITER-HIT] tid=%lu tickMs=%llu rip=0x%llX firstState=%u rcx=%p "
            "oldState=%u oldError=0x%08X stateReadable=%s errorReadable=%s "
            "proof=0x46417FF_STATE2_WRITER_EXECUTED instructionStillStock=yes codeWrites=off stateWrites=off\r\n",
            c.tid, static_cast<unsigned long long>(c.tickMs),
            static_cast<unsigned long long>(c.rip - MainImageBase()), static_cast<unsigned>(c.firstState),
            reinterpret_cast<void*>(c.rcx), static_cast<unsigned>(c.successOldState),
            static_cast<unsigned>(c.successOldError), c.successStateReadable ? "yes" : "no",
            c.successErrorReadable ? "yes" : "no");
    }
}

static void V111StaticBranchSummary144() noexcept;

static DWORD WINAPI V111HardwareWatchWorker144(LPVOID) noexcept
{
    std::vector<V111ThreadDebugState144> states;
    states.reserve(64u);

    const ULONGLONG workerStarted = GetTickCount64();
    ULONGLONG nextSignatureLog = 0;

    // The bridge can reach this worker before the protected/late-mapped BNet code
    // pages contain their final stock bytes. Keep polling instead of consuming the
    // one-shot V111 start state on the first all-zero read.
    for (;;)
    {
        if (g_v111Stop144.load(std::memory_order_acquire))
            return 0;

        const ULONGLONG now = GetTickCount64();
        const bool emitLog = !nextSignatureLog || now >= nextSignatureLog;
        if (emitLog)
            nextSignatureLog = now + 1000ull;

        if (V111VerifySignatures144(emitLog))
            break;

        if (now >= workerStarted + kV111SignatureWaitTimeoutMs144)
        {
            ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
                "[V111-COMPLETE] gate=no installerCall=no successWriter=no "
                "classification=SIGNATURES_NOT_READY_WITHIN_120S threadsArmed=0 "
                "debugRegistersRestored=yes instructionBytesModified=NO vtableWrites=off stateWrites=off\r\n");
            g_v111Finished144.store(true, std::memory_order_release);
            return 0;
        }

        Sleep(10u);
    }

    // Only decode/log branch targets after the real stock bytes are readable.
    V111StaticBranchSummary144();

    g_v111Veh144 = AddVectoredExceptionHandler(1, V111HardwareExecutionVeh144);
    if (!g_v111Veh144)
    {
        ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
            "[V111-COMPLETE] gate=no installerCall=no successWriter=no "
            "classification=VEH_INSTALL_FAILED error=%lu threadsArmed=0 "
            "instructionBytesModified=NO stateWrites=off\r\n",
            GetLastError());
        g_v111Finished144.store(true, std::memory_order_release);
        return 0;
    }

    // Arm every thread immediately after the signatures become valid. Then keep
    // discovering new game threads quickly through the login/session window.
    V111ArmNewThreads144(states);
    const ULONGLONG watchStarted = GetTickCount64();
    ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
        "[V111-ARM] ready=YES targets=3/3 mechanism=DR0_DR1_DR2_EXECUTE_BREAKPOINTS "
        "threadsArmed=%u signatureWaitMs=%llu functionDetours=OFF int3=OFF "
        "originalInstructions=UNCHANGED stateWrites=off\r\n",
        g_v111ThreadsArmed144.load(std::memory_order_acquire),
        static_cast<unsigned long long>(watchStarted - workerStarted));

    ULONGLONG nextEnumerate = watchStarted;
    ULONGLONG nextHeartbeat = watchStarted;
    bool gateLogged = false;
    bool callLogged = false;
    bool successLogged = false;
    const char* classification = nullptr;

    while (!g_v111Stop144.load(std::memory_order_acquire))
    {
        const ULONGLONG now = GetTickCount64();
        if (now >= nextEnumerate)
        {
            // New BNet/DW worker threads can appear during login. Poll fast for
            // the first 20 seconds, then reduce enumeration overhead.
            const ULONGLONG age = now - watchStarted;
            nextEnumerate = now + (age < 20000ull ? 50ull : 250ull);
            V111ArmNewThreads144(states);
        }

        V111LogCaptures144(gateLogged, callLogged, successLogged);

        const bool gate = V111CaptureReady144(&g_v111GateCaptureState144);
        const bool call = V111CaptureReady144(&g_v111CallCaptureState144);
        const bool success = V111CaptureReady144(&g_v111SuccessCaptureState144);

        if (call && success)
        {
            classification = "INSTALLER_AND_SUCCESS_EXECUTED";
            break;
        }
        if (gate && !call && now >= g_v111GateCapture144.tickMs + kV111AfterGateNoCallTimeoutMs144)
        {
            classification = "MISSING_ROUTE_IS_BEFORE_METHOD1_INSTALLER";
            break;
        }
        if (call && !success && now >= g_v111CallCapture144.tickMs + kV111AfterCallNoSuccessTimeoutMs144)
        {
            classification = "INSTALLER_EXECUTED_SUCCESS_STILL_MISSING";
            break;
        }
        if (!gate && now >= watchStarted + kV111NoGateTimeoutMs144)
        {
            classification = "GATE_NOT_OBSERVED_WITHIN_180S";
            break;
        }

        if (now >= nextHeartbeat)
        {
            nextHeartbeat = now + 15000ull;
            ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
                "[V111-WATCH] elapsedMs=%llu threadsArmed=%u gate=%s installerCall=%s successWriter=%s "
                "codeWrites=off stateWrites=off\r\n",
                static_cast<unsigned long long>(now - watchStarted),
                g_v111ThreadsArmed144.load(std::memory_order_acquire),
                gate ? "HIT" : "waiting", call ? "HIT" : "waiting", success ? "HIT" : "waiting");
        }

        Sleep(10u);
    }

    V111LogCaptures144(gateLogged, callLogged, successLogged);

    for (const auto& state : states)
        V111RestoreThread144(state);

    if (g_v111Veh144)
    {
        RemoveVectoredExceptionHandler(g_v111Veh144);
        g_v111Veh144 = nullptr;
    }

    const bool gate = V111CaptureReady144(&g_v111GateCaptureState144);
    const bool call = V111CaptureReady144(&g_v111CallCaptureState144);
    const bool success = V111CaptureReady144(&g_v111SuccessCaptureState144);
    if (!classification)
        classification = "STOPPED_WITHOUT_CLASSIFICATION";

    ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
        "[V111-COMPLETE] gate=%s installerCall=%s successWriter=%s classification=%s threadsArmed=%u "
        "debugRegistersRestored=yes instructionBytesModified=NO vtableWrites=off stateWrites=off\r\n",
        gate ? "yes" : "no", call ? "yes" : "no", success ? "yes" : "no", classification,
        g_v111ThreadsArmed144.load(std::memory_order_acquire));
    g_v111Finished144.store(true, std::memory_order_release);

    return 0;
}

static void V111StaticBranchSummary144() noexcept
{
    const auto base = MainImageBase();
    const auto size = MainImageSize();
    constexpr std::uintptr_t start = 0x4642C70u, end = 0x4642D10u;
    if (!base || size < end || g_v111StaticLogged144.load(std::memory_order_acquire))
        return;

    unsigned char code[end - start]{};
    if (!ServerEmuSafeReadBytes(reinterpret_cast<const void*>(base + start), code, sizeof(code)))
        return;

    const auto* gate = code + (0x4642C90u - start);
    const auto* call = code + (0x4642CE8u - start);
    const auto* setup = code + (0x4642CE1u - start);
    const bool gateDecoded = gate[0] == 0x8B && gate[1] == 0x46 && gate[2] == 0x10 &&
        gate[3] == 0xC1 && gate[4] == 0xE8 && gate[5] == 7 && gate[6] == 0xA8 && gate[7] == 1 && gate[8] == 0x74;
    const bool setupDecoded = setup[0] == 0x48 && setup[1] == 0x8B && setup[2] == 0x56 &&
        setup[3] == 0x68 && setup[4] == 0x48 && setup[5] == 0x8B && setup[6] == 0xCF;
    if (!gateDecoded || !setupDecoded || call[0] != 0xE8)
        return;

    std::int32_t relativeCall = 0;
    memcpy(&relativeCall, call + 1, sizeof(relativeCall));
    const auto target = static_cast<std::intptr_t>(0x4642CEDu) + relativeCall;
    const auto taken = static_cast<std::intptr_t>(0x4642C9Au) + static_cast<std::int8_t>(gate[9]);
    if (target != 0x4641A60 || taken != 0x4642CE1)
        return;

    bool expected = false;
    if (!g_v111StaticLogged144.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
        "[V111-BRANCH] decoded=yes gateRva=0x4642C90 instruction={mov_eax,[rsi+0x10];shr_eax,7;test_al,1;jz_rel8} "
        "fieldOffset=0x10 bitIndex=7 mask=0x80 takenTarget=0x4642CE1 fallthroughTarget=0x4642C9A "
        "installerPath=BIT_CLEAR_TO_0x4642CE1 installerArgs={rcx:RDI,rdx:[RSI+0x68]} "
        "callRva=0x4642CE8 callTarget=0x4641A60 successWriterRva=0x46417FF codeWrites=off stateWrites=off\r\n");
}

static void ObserveSessionCompletion144() noexcept
{
    // V111.1 starts exactly once, but signature readiness is NOT consumed here.
    // The worker waits for the late-mapped/protected BNet pages to contain their
    // final stock bytes, then installs the hardware execute watch immediately.
    if (!MainImageBase())
        return;

    bool expected = false;
    if (!g_v111Started144.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
        "[V111.1-AUTO] mode=DEFERRED_HARDWARE_EXECUTION_WATCH "
        "targets={DR0:0x4642C90,DR1:0x4642CE8,DR2:0x46417FF} "
        "signaturePolicy=RETRY_UNTIL_STOCK_BYTES_READY functionDetours=OFF int3=OFF "
        "codeWrites=OFF stateWrites=off\r\n");

    DWORD workerId = 0;
    g_v111Worker144 = CreateThread(nullptr, 0, V111HardwareWatchWorker144, nullptr, 0, &workerId);
    if (!g_v111Worker144)
    {
        const DWORD error = GetLastError();
        g_v111Started144.store(false, std::memory_order_release);
        ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
            "[V111-ARM] ready=NO reason=WORKER_CREATE_FAILED error=%lu hwBreakpoints=0 "
            "instructionBytesModified=NO stateWrites=off\r\n",
            error);
        return;
    }

    CloseHandle(g_v111Worker144);
    g_v111Worker144 = nullptr;
    ServerEmuTargetedAppend(L"v111_session_completion_hwtrace.log",
        "[V111-ARM] ready=PENDING workerTid=%lu reason=WAITING_FOR_STOCK_SIGNATURES "
        "retryIntervalMs=10 signatureTimeoutMs=120000 instructionBytesModified=NO stateWrites=off\r\n",
        workerId);
}
