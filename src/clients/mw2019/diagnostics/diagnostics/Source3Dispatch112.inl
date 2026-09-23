// Included inside the server bridge namespace.
//
// V112.1 purpose:
//   V112's hardware breakpoint on A_RESULT_FETCH (0x3D5E090) proved too hot:
//   it generated tens of thousands of EXCEPTION_SINGLE_STEP events before the
//   Demonware connected transition and could hold the game on a black screen.
//
//   V112.1 removes ALL V112 hardware breakpoints and performs passive
//   correlation only. It reuses the already-safe observers that are installed
//   elsewhere in this bridge and that always call the stock functions unchanged:
//
//     V98 -> A_RESULT_FETCH         0x3D5E090 (g_v98FetchCalls)
//     V103 -> CONNECTED_STATUS_OP   0x4531C20 (g_v104ConnectedCommitSeen)
//     V103 -> ALT_RESULT_ROUTE      0x3D5B570 (g_v103AltRouteCalls)
//     V97 -> PRIMARY_SOURCE3_ROUTE  0x3D1E300 (g_v97PrimaryCallbackCalls)
//     V97 -> SOURCE3_SETTER         0x3D05920 (g_v97SetterCalls)
//
// No V112.1 detours are added. No debug registers, INT3/code patching, vtable
// writes, auth/fence/menu state writes, task flag writes, or Source3 writes occur.

static HANDLE g_v112Worker144 = nullptr;
static std::atomic_bool g_v112Started144{false};
static std::atomic_bool g_v112Stop144{false};

static constexpr ULONGLONG kV112WaitForV111TimeoutMs144 = 120000ull;
static constexpr ULONGLONG kV112WaitForConnectedTimeoutMs144 = 180000ull;
static constexpr ULONGLONG kV112PostCommitClassificationMs144 = 5000ull;

static bool V112FlagsDiffer144(const DwV58TaskFlags& a, const DwV58TaskFlags& b) noexcept
{
    if (!a.readable || !b.readable)
        return false;
    for (unsigned i = 0; i < 4u; ++i)
        if (a.d[i] != b.d[i] || a.e[i] != b.e[i])
            return true;
    return false;
}

static void V112Snapshot144(
    std::uint32_t& source3,
    DwV58TaskFlags& flags,
    std::uintptr_t& task,
    int& dwStatus) noexcept
{
    source3 = 0xFFFFFFFFu;
    task = V97ReadSlot7Task144();
    flags = SnapshotDwV58TaskFlags(task);
    V97ReadSource3Value144(source3);
    dwStatus = DwV58DerivedStatus();
}

static DWORD WINAPI V112PassiveCorrelationWorker144(LPVOID) noexcept
{
    const ULONGLONG workerStarted = GetTickCount64();
    ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
        "[V112.1-WAIT] phase=WAIT_FOR_V111_RESTORE mode=PASSIVE_CORRELATION_ONLY "
        "reason=avoid_debug_register_collision timeoutMs=120000 hardwareBreakpoints=0 "
        "functionDetoursAddedByV112=0 stateWrites=off\r\n");

    // Keep the V111 proof step, but do not take ownership of any debug register
    // afterward. V111 restores its own DR0-DR2 state before this continues.
    while (!g_v112Stop144.load(std::memory_order_acquire))
    {
        const bool v111Finished = g_v111Finished144.load(std::memory_order_acquire);
        const bool v111Success = V111CaptureReady144(&g_v111CallCaptureState144) &&
            V111CaptureReady144(&g_v111SuccessCaptureState144);
        if (v111Finished && v111Success)
            break;
        if (v111Finished && !v111Success)
        {
            ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
                "[V112.1-COMPLETE] classification=V111_FINISHED_WITHOUT_PROVEN_SESSION_SUCCESS "
                "hardwareBreakpoints=0 functionDetoursAddedByV112=0 stateWrites=off\r\n");
            return 0;
        }
        if (GetTickCount64() >= workerStarted + kV112WaitForV111TimeoutMs144)
        {
            ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
                "[V112.1-COMPLETE] classification=V111_DID_NOT_FINISH_WITHIN_120S "
                "hardwareBreakpoints=0 functionDetoursAddedByV112=0 stateWrites=off\r\n");
            return 0;
        }
        Sleep(10u);
    }

    // V112.1 deliberately does not arm any hardware breakpoint here. The old
    // result-fetch watch was the source of the exception storm. Instead wait for
    // V103's existing stock-forwarding observer to prove the real 1 -> 2 commit.
    const unsigned fetchBeforeConnect = g_v98FetchCalls.load(std::memory_order_acquire);
    const unsigned altBeforeConnect = g_v103AltRouteCalls.load(std::memory_order_acquire);
    const unsigned primaryBeforeConnect = g_v97PrimaryCallbackCalls.load(std::memory_order_acquire);
    const unsigned setterBeforeConnect = g_v97SetterCalls.load(std::memory_order_acquire);

    ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
        "[V112.1-ARM] ready=YES mode=PASSIVE_CORRELATION_ONLY hardwareBreakpoints=0 "
        "observers={resultFetch:V98,statusCommit:V103,altRoute:V103,primary:V97,setter:V97} "
        "baselines={fetch:%u,alt:%u,primary:%u,setter:%u} functionDetoursAddedByV112=0 "
        "int3=OFF traceCodeWrites=off vtableWrites=off stateWrites=off\r\n",
        fetchBeforeConnect, altBeforeConnect, primaryBeforeConnect, setterBeforeConnect);

    const ULONGLONG waitStarted = GetTickCount64();
    ULONGLONG nextHeartbeat = waitStarted;
    while (!g_v112Stop144.load(std::memory_order_acquire))
    {
        const ULONGLONG now = GetTickCount64();
        const bool connected = g_v104ConnectedCommitSeen.load(std::memory_order_acquire) || DwV58DerivedStatus() == 2;
        if (connected)
            break;

        if (now >= nextHeartbeat)
        {
            nextHeartbeat = now + 5000ull;
            std::uint32_t source3 = 0xFFFFFFFFu;
            DwV58TaskFlags flags{};
            std::uintptr_t task = 0;
            int dwStatus = -999;
            V112Snapshot144(source3, flags, task, dwStatus);
            ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
                "[V112.1-WATCH] phase=WAIT_CONNECTED elapsedMs=%llu dwStatus=%d source3=0x%08X task=%p "
                "observerCalls={fetch:%u,alt:%u,primary:%u,setter:%u} "
                "D={%02X/%02X/%02X/%02X} E={%02X/%02X/%02X/%02X} "
                "hardwareBreakpoints=0 stateWrites=off\r\n",
                static_cast<unsigned long long>(now - waitStarted), dwStatus, source3,
                reinterpret_cast<void*>(task),
                g_v98FetchCalls.load(std::memory_order_acquire),
                g_v103AltRouteCalls.load(std::memory_order_acquire),
                g_v97PrimaryCallbackCalls.load(std::memory_order_acquire),
                g_v97SetterCalls.load(std::memory_order_acquire),
                flags.d[0], flags.d[1], flags.d[2], flags.d[3],
                flags.e[0], flags.e[1], flags.e[2], flags.e[3]);
        }

        if (now >= waitStarted + kV112WaitForConnectedTimeoutMs144)
        {
            ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
                "[V112.1-COMPLETE] classification=CONNECTED_COMMIT_NOT_OBSERVED_WITHIN_180S "
                "observerDeltas={fetch:%u,alt:%u,primary:%u,setter:%u} hardwareBreakpoints=0 "
                "functionDetoursAddedByV112=0 stateWrites=off\r\n",
                g_v98FetchCalls.load(std::memory_order_acquire) - fetchBeforeConnect,
                g_v103AltRouteCalls.load(std::memory_order_acquire) - altBeforeConnect,
                g_v97PrimaryCallbackCalls.load(std::memory_order_acquire) - primaryBeforeConnect,
                g_v97SetterCalls.load(std::memory_order_acquire) - setterBeforeConnect);
            return 0;
        }
        Sleep(10u);
    }

    if (g_v112Stop144.load(std::memory_order_acquire))
        return 0;

    // Capture exact counters and Source3/task state at the first observed connected
    // commit. From here, only deltas from existing safe observers are compared.
    const ULONGLONG commitTick = GetTickCount64();
    const unsigned fetchBaseline = g_v98FetchCalls.load(std::memory_order_acquire);
    const unsigned altBaseline = g_v103AltRouteCalls.load(std::memory_order_acquire);
    const unsigned primaryBaseline = g_v97PrimaryCallbackCalls.load(std::memory_order_acquire);
    const unsigned setterBaseline = g_v97SetterCalls.load(std::memory_order_acquire);

    std::uint32_t baselineSource3 = 0xFFFFFFFFu;
    DwV58TaskFlags baselineFlags{};
    std::uintptr_t baselineTask = 0;
    int baselineDwStatus = -999;
    V112Snapshot144(baselineSource3, baselineFlags, baselineTask, baselineDwStatus);

    ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
        "[V112.1-COMMIT] tickMs=%llu callerRva=0x%llX dwStatus=%d source3=0x%08X task=%p "
        "D={%02X/%02X/%02X/%02X} E={%02X/%02X/%02X/%02X} "
        "baselines={fetch:%u,alt:%u,primary:%u,setter:%u} hardwareBreakpoints=0 stateWrites=off\r\n",
        static_cast<unsigned long long>(commitTick),
        static_cast<unsigned long long>(g_v104ConnectedCommitCallerRva.load(std::memory_order_acquire)),
        baselineDwStatus, baselineSource3, reinterpret_cast<void*>(baselineTask),
        baselineFlags.d[0], baselineFlags.d[1], baselineFlags.d[2], baselineFlags.d[3],
        baselineFlags.e[0], baselineFlags.e[1], baselineFlags.e[2], baselineFlags.e[3],
        fetchBaseline, altBaseline, primaryBaseline, setterBaseline);

    const char* classification = nullptr;
    ULONGLONG nextPostCommitHeartbeat = commitTick;
    while (!g_v112Stop144.load(std::memory_order_acquire))
    {
        const ULONGLONG now = GetTickCount64();
        std::uint32_t source3 = 0xFFFFFFFFu;
        DwV58TaskFlags flags{};
        std::uintptr_t task = 0;
        int dwStatus = -999;
        V112Snapshot144(source3, flags, task, dwStatus);

        const unsigned fetchDelta = g_v98FetchCalls.load(std::memory_order_acquire) - fetchBaseline;
        const unsigned altDelta = g_v103AltRouteCalls.load(std::memory_order_acquire) - altBaseline;
        const unsigned primaryDelta = g_v97PrimaryCallbackCalls.load(std::memory_order_acquire) - primaryBaseline;
        const unsigned setterDelta = g_v97SetterCalls.load(std::memory_order_acquire) - setterBaseline;
        const bool flagsChanged = V112FlagsDiffer144(baselineFlags, flags);
        const bool sourceMaterialized = source3 != 0u && source3 != 0xFFFFFFFFu;

        if (sourceMaterialized || flagsChanged)
        {
            classification = "SOURCE3_COMPLETION_MATERIALIZED";
            ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
                "[V112.1-MATERIALIZED] ageMs=%llu dwStatus=%d source3=0x%08X flagsChanged=%s "
                "observerDeltas={fetch:%u,alt:%u,primary:%u,setter:%u} "
                "D={%02X/%02X/%02X/%02X} E={%02X/%02X/%02X/%02X} "
                "hardwareBreakpoints=0 stateWrites=off\r\n",
                static_cast<unsigned long long>(now - commitTick), dwStatus, source3,
                flagsChanged ? "yes" : "no", fetchDelta, altDelta, primaryDelta, setterDelta,
                flags.d[0], flags.d[1], flags.d[2], flags.d[3],
                flags.e[0], flags.e[1], flags.e[2], flags.e[3]);
            break;
        }

        if (now >= nextPostCommitHeartbeat)
        {
            nextPostCommitHeartbeat = now + 1000ull;
            ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
                "[V112.1-POSTCOMMIT] ageMs=%llu dwStatus=%d source3=0x%08X task=%p "
                "observerDeltas={fetch:%u,alt:%u,primary:%u,setter:%u} "
                "D={%02X/%02X/%02X/%02X} E={%02X/%02X/%02X/%02X} "
                "hardwareBreakpoints=0 stateWrites=off\r\n",
                static_cast<unsigned long long>(now - commitTick), dwStatus, source3,
                reinterpret_cast<void*>(task), fetchDelta, altDelta, primaryDelta, setterDelta,
                flags.d[0], flags.d[1], flags.d[2], flags.d[3],
                flags.e[0], flags.e[1], flags.e[2], flags.e[3]);
        }

        if (now >= commitTick + kV112PostCommitClassificationMs144)
        {
            if (primaryDelta > 0u && setterDelta == 0u)
                classification = "PRIMARY_CALLBACK_EXECUTED_SETTER_MISSING";
            else if (setterDelta > 0u)
                classification = "SETTER_EXECUTED_RESULT_NOT_MATERIALIZED";
            else if (altDelta > 0u)
                classification = "ALT_ROUTE_EXECUTED_NO_SOURCE3_COMPLETION";
            else if (fetchDelta > 0u)
                classification = "RESULT_FETCH_ONLY_NO_COMPLETION_DISPATCH";
            else
                classification = "CONNECTED_COMMIT_NO_POSTCOMMIT_SOURCE3_DISPATCH";
            break;
        }

        Sleep(10u);
    }

    if (!classification)
        classification = "STOPPED_WITHOUT_CLASSIFICATION";

    std::uint32_t finalSource3 = 0xFFFFFFFFu;
    DwV58TaskFlags finalFlags{};
    std::uintptr_t finalTask = 0;
    int finalDwStatus = -999;
    V112Snapshot144(finalSource3, finalFlags, finalTask, finalDwStatus);

    const unsigned finalFetchDelta = g_v98FetchCalls.load(std::memory_order_acquire) - fetchBaseline;
    const unsigned finalAltDelta = g_v103AltRouteCalls.load(std::memory_order_acquire) - altBaseline;
    const unsigned finalPrimaryDelta = g_v97PrimaryCallbackCalls.load(std::memory_order_acquire) - primaryBaseline;
    const unsigned finalSetterDelta = g_v97SetterCalls.load(std::memory_order_acquire) - setterBaseline;

    ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
        "[V112.1-COMPLETE] classification=%s dwStatus=%d observerDeltas={fetch:%u,alt:%u,primary:%u,setter:%u} "
        "source3=0x%08X task=%p D={%02X/%02X/%02X/%02X} E={%02X/%02X/%02X/%02X} "
        "hardwareBreakpoints=0 debugRegistersTouched=NO functionDetoursAddedByV112=0 int3=OFF "
        "traceCodeWrites=off vtableWrites=off stateWrites=off\r\n",
        classification, finalDwStatus, finalFetchDelta, finalAltDelta, finalPrimaryDelta, finalSetterDelta,
        finalSource3, reinterpret_cast<void*>(finalTask),
        finalFlags.d[0], finalFlags.d[1], finalFlags.d[2], finalFlags.d[3],
        finalFlags.e[0], finalFlags.e[1], finalFlags.e[2], finalFlags.e[3]);
    return 0;
}

static void ObserveSource3Dispatch112144() noexcept
{
    if (!MainImageBase())
        return;

    bool expected = false;
    if (!g_v112Started144.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
        "[V112.1-AUTO] mode=PASSIVE_POST_CONNECTED_SOURCE3_CORRELATION hardwareBreakpoints=0 "
        "observers={resultFetch:V98_0x3D5E090,statusCommit:V103_0x4531C20,altRoute:V103_0x3D5B570,"
        "primary:V97_0x3D1E300,setter:V97_0x3D05920} waitForV111Restore=yes "
        "functionDetoursAddedByV112=0 int3=OFF traceCodeWrites=off vtableWrites=off stateWrites=off\r\n");

    DWORD workerId = 0;
    g_v112Worker144 = CreateThread(nullptr, 0, V112PassiveCorrelationWorker144, nullptr, 0, &workerId);
    if (!g_v112Worker144)
    {
        const DWORD error = GetLastError();
        g_v112Started144.store(false, std::memory_order_release);
        ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
            "[V112.1-ARM] ready=NO reason=WORKER_CREATE_FAILED error=%lu hardwareBreakpoints=0 "
            "stateWrites=off\r\n", error);
        return;
    }

    CloseHandle(g_v112Worker144);
    g_v112Worker144 = nullptr;
    ServerEmuTargetedAppend(L"v112_source3_dispatch_hwtrace.log",
        "[V112.1-ARM] ready=PENDING workerTid=%lu phase=WAIT_FOR_V111_THEN_CONNECTED "
        "hardwareBreakpoints=0 traceCodeWrites=off stateWrites=off\r\n", workerId);
}
