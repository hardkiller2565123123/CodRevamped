// Included inside the server bridge namespace.
//
// V113 purpose:
//   V112.1 proved that the stock Demonware CONNECTED commit completes (status 1 -> 2)
//   but none of the known Source3 completion observers run afterward:
//     resultFetch=0, altRoute=0, primary=0, setter=0, Source3=0, task D/E=0.
//
//   V113 traces the *owner continuation* that resumes immediately after the
//   CONNECTED status operation.  It deliberately avoids the hot 0x3D5E090 result
//   fetch target that caused V112's exception storm.
//
//   Before CONNECTED, V113 arms exactly one EXECUTE hardware breakpoint:
//     DR0 -> 0x4531538, the proven return site after CONNECTED_STATUS_OP.
//
//   When DR0 fires after V103 has proven the natural CONNECTED commit, the VEH
//   captures the live register context and, in that same exception context,
//   converts the remaining debug slots into bounded post-commit one-shots:
//     DR1 -> 0x2B59C00, the exact live TASK_TABLE_50 slot7 target
//     DR2 -> first local Jcc after 0x4531538 in the bounded owner (if found)
//     DR3 -> first local CALL after 0x4531538 in the bounded owner (if found)
//
//   The worker also promotes DR1 to other game threads after the commit so an
//   asynchronous slot50 dispatch can reveal its real caller through [RSP].
//
// No stock instruction, vtable, task flag, Source3 value, auth/fence/menu state,
// or backend response is changed by V113.

struct V113Capture144
{
    DWORD tid{};
    ULONGLONG tickMs{};
    std::uintptr_t rip{};
    std::uintptr_t rax{};
    std::uintptr_t rbx{};
    std::uintptr_t rcx{};
    std::uintptr_t rdx{};
    std::uintptr_t r8{};
    std::uintptr_t r9{};
    std::uintptr_t rsi{};
    std::uintptr_t rdi{};
    std::uintptr_t rsp{};
    std::uintptr_t stackReturn{};
    DWORD64 eflags{};

    std::uintptr_t task{};
    std::uintptr_t object50{};
    std::uintptr_t vtable50{};
    std::uintptr_t slot50Target{};
    std::uint32_t source3{0xFFFFFFFFu};
    int dwStatus{-999};
    DwV58TaskFlags flags{};
};

struct V113ThreadDebugState144
{
    DWORD tid{};
    DWORD64 dr0{};
    DWORD64 dr1{};
    DWORD64 dr2{};
    DWORD64 dr3{};
    DWORD64 dr6{};
    DWORD64 dr7{};
};

struct V113OwnerCandidate144
{
    std::uintptr_t rva{};
    std::uintptr_t targetRva{};
    unsigned opcode{};
    unsigned condition{};
    bool valid{};
    bool direct{};
    bool isCall{};
};

static PVOID g_v113Veh144 = nullptr;
static HANDLE g_v113Worker144 = nullptr;
static std::atomic_bool g_v113Started144{false};
static std::atomic_bool g_v113Stop144{false};
static std::atomic_bool g_v113Finished144{false};
static std::atomic_uint g_v113ThreadsArmed144{0};
static std::atomic_uint g_v113PreCommitReturnHits144{0};
static std::atomic_uint g_v113PreCommitOtherHits144{0};
static std::atomic_bool g_v113PostCommitPromoted144{false};

static volatile LONG g_v113ReturnCaptureState144 = 0;
static volatile LONG g_v113Slot50CaptureState144 = 0;
static volatile LONG g_v113BranchCaptureState144 = 0;
static volatile LONG g_v113CallCaptureState144 = 0;
static V113Capture144 g_v113ReturnCapture144{};
static V113Capture144 g_v113Slot50Capture144{};
static V113Capture144 g_v113BranchCapture144{};
static V113Capture144 g_v113CallCapture144{};

static V113OwnerCandidate144 g_v113BranchCandidate144{};
static V113OwnerCandidate144 g_v113CallCandidate144{};
static std::uintptr_t g_v113OwnerBegin144 = 0;
static std::uintptr_t g_v113OwnerEnd144 = 0;

static constexpr std::uintptr_t kV113ConnectedReturnRva144 = 0x4531538u;
static constexpr std::uintptr_t kV113Slot50TargetRva144 = 0x2B59C00u;
static constexpr std::uintptr_t kV113Vtable50Rva144 = 0x6F1A230u;
static constexpr ULONGLONG kV113WaitForV111TimeoutMs144 = 120000ull;
static constexpr ULONGLONG kV113WaitForV103TimeoutMs144 = 180000ull;
static constexpr ULONGLONG kV113WaitForCommitTimeoutMs144 = 180000ull;
static constexpr ULONGLONG kV113PostCommitWatchMs144 = 5000ull;
static constexpr unsigned kV113PreCommitExceptionSafetyLimit144 = 256u;

static bool V113CaptureReady144(volatile LONG* state) noexcept
{
    return state && InterlockedCompareExchange(state, 0, 0) == 2;
}

static void V113DisableDebugSlot144(CONTEXT* c, unsigned slot) noexcept
{
    if (!c || slot > 3u)
        return;
    const DWORD64 enableMask = static_cast<DWORD64>(0x3ull) << (slot * 2u);
    const DWORD64 controlMask = static_cast<DWORD64>(0xFull) << (16u + slot * 4u);
    c->Dr7 &= ~enableMask;
    c->Dr7 &= ~controlMask;
    c->Dr6 = 0;
}

static void V113EnableExecuteSlot144(CONTEXT* c, unsigned slot, std::uintptr_t address) noexcept
{
    if (!c || slot > 3u || !address)
        return;

    switch (slot)
    {
    case 0u: c->Dr0 = static_cast<DWORD64>(address); break;
    case 1u: c->Dr1 = static_cast<DWORD64>(address); break;
    case 2u: c->Dr2 = static_cast<DWORD64>(address); break;
    case 3u: c->Dr3 = static_cast<DWORD64>(address); break;
    default: return;
    }

    const DWORD64 enableMask = static_cast<DWORD64>(0x3ull) << (slot * 2u);
    const DWORD64 controlMask = static_cast<DWORD64>(0xFull) << (16u + slot * 4u);
    c->Dr7 &= ~enableMask;
    c->Dr7 &= ~controlMask; // RW=00 LEN=00 => execute, length 1
    c->Dr7 |= static_cast<DWORD64>(1ull) << (slot * 2u); // local enable
    c->Dr6 = 0;
}

static void V113CaptureContext144(V113Capture144& out, const CONTEXT* c) noexcept
{
    if (!c)
        return;

    out.tid = GetCurrentThreadId();
    out.tickMs = GetTickCount64();
    out.rip = static_cast<std::uintptr_t>(c->Rip);
    out.rax = static_cast<std::uintptr_t>(c->Rax);
    out.rbx = static_cast<std::uintptr_t>(c->Rbx);
    out.rcx = static_cast<std::uintptr_t>(c->Rcx);
    out.rdx = static_cast<std::uintptr_t>(c->Rdx);
    out.r8 = static_cast<std::uintptr_t>(c->R8);
    out.r9 = static_cast<std::uintptr_t>(c->R9);
    out.rsi = static_cast<std::uintptr_t>(c->Rsi);
    out.rdi = static_cast<std::uintptr_t>(c->Rdi);
    out.rsp = static_cast<std::uintptr_t>(c->Rsp);
    out.eflags = static_cast<DWORD64>(c->EFlags);
    ServerEmuSafeReadPointer(reinterpret_cast<const void*>(out.rsp), out.stackReturn);

    out.task = V97ReadSlot7Task144();
    out.object50 = out.task ? out.task + 0x50u : 0u;
    if (out.object50)
        ServerEmuSafeReadPointer(reinterpret_cast<const void*>(out.object50), out.vtable50);
    if (out.vtable50)
        ServerEmuSafeReadPointer(reinterpret_cast<const void*>(out.vtable50 + 7ull * sizeof(std::uintptr_t)), out.slot50Target);
    V97ReadSource3Value144(out.source3);
    out.dwStatus = DwV58DerivedStatus();
    out.flags = SnapshotDwV58TaskFlags(out.task);
}

static unsigned V113RegisterRelation144(std::uintptr_t value, const V113Capture144& c) noexcept
{
    unsigned mask = 0;
    if (!value)
        return mask;
    if (value == c.task) mask |= 0x01u;
    if (value == c.object50) mask |= 0x02u;
    if (value == c.vtable50) mask |= 0x04u;
    if (value == c.slot50Target) mask |= 0x08u;

    std::uintptr_t q0 = 0;
    if (ServerEmuSafeReadPointer(reinterpret_cast<const void*>(value), q0) && q0 == c.vtable50)
        mask |= 0x10u;
    if (value <= ~static_cast<std::uintptr_t>(0) - 0x50u)
    {
        std::uintptr_t q50 = 0;
        if (ServerEmuSafeReadPointer(reinterpret_cast<const void*>(value + 0x50u), q50) && q50 == c.vtable50)
            mask |= 0x20u;
    }
    return mask;
}

static bool V113EvaluateJcc144(unsigned condition, DWORD64 eflags) noexcept
{
    const bool cf = (eflags & (1ull << 0u)) != 0;
    const bool pf = (eflags & (1ull << 2u)) != 0;
    const bool zf = (eflags & (1ull << 6u)) != 0;
    const bool sf = (eflags & (1ull << 7u)) != 0;
    const bool of = (eflags & (1ull << 11u)) != 0;
    switch (condition & 0xFu)
    {
    case 0x0: return of;
    case 0x1: return !of;
    case 0x2: return cf;
    case 0x3: return !cf;
    case 0x4: return zf;
    case 0x5: return !zf;
    case 0x6: return cf || zf;
    case 0x7: return !cf && !zf;
    case 0x8: return sf;
    case 0x9: return !sf;
    case 0xA: return pf;
    case 0xB: return !pf;
    case 0xC: return sf != of;
    case 0xD: return sf == of;
    case 0xE: return zf || (sf != of);
    case 0xF: return !zf && (sf == of);
    default: return false;
    }
}

static bool V113DiscoverOwnerPath144() noexcept
{
    const auto base = MainImageBase();
    const auto size = MainImageSize();
    if (!base || !size || kV113ConnectedReturnRva144 >= size)
        return false;

    const std::uintptr_t returnVa = base + kV113ConnectedReturnRva144;
    std::uintptr_t ownerBegin = 0, ownerEnd = 0;
    if (!RuntimeFunctionBounds144(returnVa, ownerBegin, ownerEnd) || ownerEnd <= ownerBegin)
    {
        ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
            "[V113-OWNER] ready=NO returnRva=0x4531538 reason=UNBOUNDED_OWNER stateWrites=off\r\n");
        return false;
    }

    g_v113OwnerBegin144 = ownerBegin;
    g_v113OwnerEnd144 = ownerEnd;
    const std::uintptr_t scanEnd = (std::min)(ownerEnd, returnVa + 0x240u);
    const std::size_t n = static_cast<std::size_t>(scanEnd - returnVa);
    std::vector<unsigned char> code(n);
    if (!n || !ServerEmuSafeReadBytes(reinterpret_cast<const void*>(returnVa), code.data(), code.size()))
        return false;

    V113OwnerCandidate144 branch{};
    V113OwnerCandidate144 call{};
    for (std::size_t i = 0; i < code.size(); ++i)
    {
        const std::uintptr_t siteVa = returnVa + i;
        const unsigned char b = code[i];
        if (!branch.valid && b >= 0x70u && b <= 0x7Fu && i + 1u < code.size())
        {
            const auto rel = static_cast<std::int8_t>(code[i + 1u]);
            branch.valid = true;
            branch.rva = siteVa - base;
            branch.targetRva = static_cast<std::uintptr_t>(siteVa + 2u + static_cast<std::intptr_t>(rel) - base);
            branch.opcode = b;
            branch.condition = b & 0x0Fu;
            branch.direct = true;
            branch.isCall = false;
        }
        else if (!branch.valid && b == 0x0Fu && i + 5u < code.size() && code[i + 1u] >= 0x80u && code[i + 1u] <= 0x8Fu)
        {
            std::int32_t rel = 0;
            memcpy(&rel, code.data() + i + 2u, sizeof(rel));
            branch.valid = true;
            branch.rva = siteVa - base;
            branch.targetRva = static_cast<std::uintptr_t>(siteVa + 6u + static_cast<std::intptr_t>(rel) - base);
            branch.opcode = 0x0F00u | code[i + 1u];
            branch.condition = code[i + 1u] & 0x0Fu;
            branch.direct = true;
            branch.isCall = false;
        }

        if (!call.valid && b == 0xE8u && i + 4u < code.size())
        {
            std::int32_t rel = 0;
            memcpy(&rel, code.data() + i + 1u, sizeof(rel));
            call.valid = true;
            call.rva = siteVa - base;
            call.targetRva = static_cast<std::uintptr_t>(siteVa + 5u + static_cast<std::intptr_t>(rel) - base);
            call.opcode = 0xE8u;
            call.direct = true;
            call.isCall = true;
        }
        else if (!call.valid && b == 0xFFu)
        {
            std::size_t ilen = 0;
            std::uint32_t disp = 0;
            unsigned modrm = 0;
            if (V106DecodeIndirectCallDisp144(code.data() + i, code.size() - i, ilen, disp, modrm))
            {
                call.valid = true;
                call.rva = siteVa - base;
                call.targetRva = 0;
                call.opcode = 0xFF00u | modrm;
                call.direct = false;
                call.isCall = true;
            }
        }

        if (branch.valid && call.valid)
            break;
    }

    g_v113BranchCandidate144 = branch;
    g_v113CallCandidate144 = call;
    ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
        "[V113-OWNER] ready=YES returnRva=0x4531538 owner=0x%llX..0x%llX ownerBytes=%llu "
        "branch={ready:%s,rva:%s0x%llX,target:%s0x%llX,opcode:0x%X,cc:0x%X} "
        "call={ready:%s,rva:%s0x%llX,target:%s0x%llX,opcode:0x%X,direct:%s} "
        "slot50TargetRva=0x2B59C00 vtable50Rva=0x6F1A230 mode=READ_ONLY stateWrites=off\r\n",
        static_cast<unsigned long long>(ownerBegin - base), static_cast<unsigned long long>(ownerEnd - base),
        static_cast<unsigned long long>(ownerEnd - ownerBegin),
        branch.valid ? "YES" : "no", branch.valid ? "" : "n/a-", static_cast<unsigned long long>(branch.rva),
        branch.valid ? "" : "n/a-", static_cast<unsigned long long>(branch.targetRva), branch.opcode, branch.condition,
        call.valid ? "YES" : "no", call.valid ? "" : "n/a-", static_cast<unsigned long long>(call.rva),
        call.valid && call.direct ? "" : "n/a-", static_cast<unsigned long long>(call.targetRva), call.opcode,
        call.direct ? "yes" : "no");
    AppendCodeBytes144(L"v113_source3_dispatch_owner_trace.log", "[V113-OWNER-CODE]", returnVa, 0x40u,
        static_cast<std::size_t>((std::min<std::uintptr_t>)(0x200u, ownerEnd - returnVa)));
    return true;
}

static LONG CALLBACK V113HardwareVeh144(PEXCEPTION_POINTERS ep) noexcept
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord ||
        ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    const auto base = MainImageBase();
    if (!base)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT* c = ep->ContextRecord;
    const std::uintptr_t rip = static_cast<std::uintptr_t>(c->Rip);
    const std::uintptr_t returnVa = base + kV113ConnectedReturnRva144;
    const std::uintptr_t slot50Va = base + kV113Slot50TargetRva144;
    const std::uintptr_t branchVa = g_v113BranchCandidate144.valid ? base + g_v113BranchCandidate144.rva : 0u;
    const std::uintptr_t callVa = g_v113CallCandidate144.valid ? base + g_v113CallCandidate144.rva : 0u;
    const bool committed = g_v104ConnectedCommitSeen.load(std::memory_order_acquire);

    if (rip == returnVa)
    {
        if (!committed)
        {
            g_v113PreCommitReturnHits144.fetch_add(1u, std::memory_order_acq_rel);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        V113DisableDebugSlot144(c, 0u);
        if (InterlockedCompareExchange(&g_v113ReturnCaptureState144, 1, 0) == 0)
        {
            V113CaptureContext144(g_v113ReturnCapture144, c);
            InterlockedExchange(&g_v113ReturnCaptureState144, 2);
        }

        // The exception context is the safest place to arm the immediate
        // post-return path: there is no worker-thread race between CONNECTED and
        // the caller's next instruction.
        V113EnableExecuteSlot144(c, 1u, slot50Va);
        if (branchVa && branchVa != returnVa)
            V113EnableExecuteSlot144(c, 2u, branchVa);
        if (callVa && callVa != returnVa && callVa != branchVa)
            V113EnableExecuteSlot144(c, 3u, callVa);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (rip == slot50Va)
    {
        if (!committed)
        {
            g_v113PreCommitOtherHits144.fetch_add(1u, std::memory_order_acq_rel);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        V113DisableDebugSlot144(c, 1u);
        if (InterlockedCompareExchange(&g_v113Slot50CaptureState144, 1, 0) == 0)
        {
            V113CaptureContext144(g_v113Slot50Capture144, c);
            InterlockedExchange(&g_v113Slot50CaptureState144, 2);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (branchVa && rip == branchVa)
    {
        if (!committed)
        {
            g_v113PreCommitOtherHits144.fetch_add(1u, std::memory_order_acq_rel);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        V113DisableDebugSlot144(c, 2u);
        if (InterlockedCompareExchange(&g_v113BranchCaptureState144, 1, 0) == 0)
        {
            V113CaptureContext144(g_v113BranchCapture144, c);
            InterlockedExchange(&g_v113BranchCaptureState144, 2);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (callVa && rip == callVa)
    {
        if (!committed)
        {
            g_v113PreCommitOtherHits144.fetch_add(1u, std::memory_order_acq_rel);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        V113DisableDebugSlot144(c, 3u);
        if (InterlockedCompareExchange(&g_v113CallCaptureState144, 1, 0) == 0)
        {
            V113CaptureContext144(g_v113CallCapture144, c);
            InterlockedExchange(&g_v113CallCaptureState144, 2);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static bool V113ThreadAlreadyTracked144(const std::vector<V113ThreadDebugState144>& states, DWORD tid) noexcept
{
    for (const auto& state : states)
        if (state.tid == tid)
            return true;
    return false;
}

static bool V113ArmThread144(DWORD tid, V113ThreadDebugState144& saved, bool postCommit) noexcept
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
        if (GetThreadContext(thread, &c) && (c.Dr7 & 0xFFull) == 0)
        {
            saved.tid = tid;
            saved.dr0 = c.Dr0;
            saved.dr1 = c.Dr1;
            saved.dr2 = c.Dr2;
            saved.dr3 = c.Dr3;
            saved.dr6 = c.Dr6;
            saved.dr7 = c.Dr7;

            if (postCommit)
                V113EnableExecuteSlot144(&c, 1u, MainImageBase() + kV113Slot50TargetRva144);
            else
                V113EnableExecuteSlot144(&c, 0u, MainImageBase() + kV113ConnectedReturnRva144);
            armed = SetThreadContext(thread, &c) != FALSE;
        }
        ResumeThread(thread);
    }
    CloseHandle(thread);
    return armed;
}

static unsigned V113ArmNewThreads144(std::vector<V113ThreadDebugState144>& states, bool postCommit) noexcept
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
            if (entry.th32OwnerProcessID != pid || V113ThreadAlreadyTracked144(states, entry.th32ThreadID))
                continue;
            V113ThreadDebugState144 saved{};
            if (V113ArmThread144(entry.th32ThreadID, saved, postCommit))
            {
                states.push_back(saved);
                ++added;
            }
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (added)
        g_v113ThreadsArmed144.fetch_add(added, std::memory_order_acq_rel);
    return added;
}

static void V113PromoteThreadToPostCommit144(DWORD tid) noexcept
{
    if (!tid || tid == GetCurrentThreadId())
        return;
    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE, tid);
    if (!thread)
        return;
    const DWORD suspend = SuspendThread(thread);
    if (suspend != static_cast<DWORD>(-1))
    {
        CONTEXT c{};
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &c))
        {
            V113DisableDebugSlot144(&c, 0u);
            V113EnableExecuteSlot144(&c, 1u, MainImageBase() + kV113Slot50TargetRva144);
            SetThreadContext(thread, &c);
        }
        ResumeThread(thread);
    }
    CloseHandle(thread);
}

static void V113RestoreThread144(const V113ThreadDebugState144& saved) noexcept
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
            c.Dr3 = saved.dr3;
            c.Dr6 = saved.dr6;
            c.Dr7 = saved.dr7;
            SetThreadContext(thread, &c);
        }
        ResumeThread(thread);
    }
    CloseHandle(thread);
}

static void V113LogCapture144(const char* label, const V113Capture144& c, const V113OwnerCandidate144* candidate = nullptr) noexcept
{
    const auto base = MainImageBase();
    const auto size = MainImageSize();
    const auto rrva = [base, size](std::uintptr_t v) -> std::uintptr_t {
        return base && size && v >= base && v < base + size ? v - base : 0u;
    };

    const unsigned relRax = V113RegisterRelation144(c.rax, c);
    const unsigned relRbx = V113RegisterRelation144(c.rbx, c);
    const unsigned relRcx = V113RegisterRelation144(c.rcx, c);
    const unsigned relRdx = V113RegisterRelation144(c.rdx, c);
    const unsigned relR8 = V113RegisterRelation144(c.r8, c);
    const unsigned relR9 = V113RegisterRelation144(c.r9, c);
    const unsigned relRsi = V113RegisterRelation144(c.rsi, c);
    const unsigned relRdi = V113RegisterRelation144(c.rdi, c);
    const bool branchTaken = candidate && candidate->valid && !candidate->isCall ?
        V113EvaluateJcc144(candidate->condition, c.eflags) : false;

    ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
        "[V113-%s-HIT] tid=%lu tickMs=%llu ripRva=0x%llX stackReturn=%s0x%llX dwStatus=%d source3=0x%08X "
        "task=%p object50=%p vtable50=%s0x%llX slot50Target=%s0x%llX "
        "D={%02X/%02X/%02X/%02X} E={%02X/%02X/%02X/%02X} "
        "regs={rax:%p,rbx:%p,rcx:%p,rdx:%p,r8:%p,r9:%p,rsi:%p,rdi:%p} "
        "relationMask={rax:0x%X,rbx:0x%X,rcx:0x%X,rdx:0x%X,r8:0x%X,r9:0x%X,rsi:0x%X,rdi:0x%X} "
        "eflags=0x%llX branchWouldTake=%s hardwareOnly=yes stockUnchanged=yes stateWrites=off\r\n",
        label ? label : "?", c.tid, static_cast<unsigned long long>(c.tickMs),
        static_cast<unsigned long long>(rrva(c.rip)),
        rrva(c.stackReturn) ? "" : "n/a-", static_cast<unsigned long long>(rrva(c.stackReturn)),
        c.dwStatus, c.source3, reinterpret_cast<void*>(c.task), reinterpret_cast<void*>(c.object50),
        rrva(c.vtable50) ? "" : "n/a-", static_cast<unsigned long long>(rrva(c.vtable50)),
        rrva(c.slot50Target) ? "" : "n/a-", static_cast<unsigned long long>(rrva(c.slot50Target)),
        c.flags.d[0], c.flags.d[1], c.flags.d[2], c.flags.d[3],
        c.flags.e[0], c.flags.e[1], c.flags.e[2], c.flags.e[3],
        reinterpret_cast<void*>(c.rax), reinterpret_cast<void*>(c.rbx), reinterpret_cast<void*>(c.rcx),
        reinterpret_cast<void*>(c.rdx), reinterpret_cast<void*>(c.r8), reinterpret_cast<void*>(c.r9),
        reinterpret_cast<void*>(c.rsi), reinterpret_cast<void*>(c.rdi),
        relRax, relRbx, relRcx, relRdx, relR8, relR9, relRsi, relRdi,
        static_cast<unsigned long long>(c.eflags),
        candidate && candidate->valid && !candidate->isCall ? (branchTaken ? "YES" : "no") : "n/a");
}

static DWORD WINAPI V113OwnerTraceWorker144(LPVOID) noexcept
{
    std::vector<V113ThreadDebugState144> states;
    states.reserve(96u);
    const ULONGLONG started = GetTickCount64();

    ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
        "[V113-WAIT] phase=WAIT_FOR_V111_RESTORE reason=avoid_debug_register_collision timeoutMs=120000 "
        "preCommitBreakpoints=1 hotResultFetchWatch=OFF stateWrites=off\r\n");

    while (!g_v113Stop144.load(std::memory_order_acquire))
    {
        if (g_v111Finished144.load(std::memory_order_acquire))
            break;
        if (GetTickCount64() >= started + kV113WaitForV111TimeoutMs144)
        {
            ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
                "[V113-COMPLETE] classification=V111_DID_NOT_FINISH_WITHIN_120S stateWrites=off\r\n");
            g_v113Finished144.store(true, std::memory_order_release);
            return 0;
        }
        Sleep(10u);
    }

    if (!V111CaptureReady144(&g_v111CallCaptureState144) || !V111CaptureReady144(&g_v111SuccessCaptureState144))
    {
        ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
            "[V113-COMPLETE] classification=SESSION_SUCCESS_NOT_PROVEN_BY_V111 stateWrites=off\r\n");
        g_v113Finished144.store(true, std::memory_order_release);
        return 0;
    }

    if (!V113DiscoverOwnerPath144())
    {
        ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
            "[V113-COMPLETE] classification=CONNECTED_OWNER_PATH_DISCOVERY_FAILED stateWrites=off\r\n");
        g_v113Finished144.store(true, std::memory_order_release);
        return 0;
    }

    const ULONGLONG v103WaitStart = GetTickCount64();
    while (!g_v113Stop144.load(std::memory_order_acquire) &&
           !g_v103ConnectedDispatchHooksReady.load(std::memory_order_acquire))
    {
        if (GetTickCount64() >= v103WaitStart + kV113WaitForV103TimeoutMs144)
        {
            ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
                "[V113-COMPLETE] classification=V103_CONNECTED_OBSERVER_NOT_READY_WITHIN_180S stateWrites=off\r\n");
            g_v113Finished144.store(true, std::memory_order_release);
            return 0;
        }
        Sleep(10u);
    }

    g_v113Veh144 = AddVectoredExceptionHandler(1, V113HardwareVeh144);
    if (!g_v113Veh144)
    {
        ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
            "[V113-COMPLETE] classification=VEH_INSTALL_FAILED error=%lu stateWrites=off\r\n", GetLastError());
        g_v113Finished144.store(true, std::memory_order_release);
        return 0;
    }

    V113ArmNewThreads144(states, false);
    ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
        "[V113-ARM] ready=YES mechanism=DR0_CONNECTED_RETURN_ONLY preCommitTargets={DR0:0x4531538} "
        "postCommitTargets={DR1:0x2B59C00,DR2:%s0x%llX,DR3:%s0x%llX} threadsArmed=%u "
        "resultFetchBreakpoint=OFF instructionBytesModified=NO vtableWrites=off stateWrites=off\r\n",
        g_v113BranchCandidate144.valid ? "" : "disabled/", static_cast<unsigned long long>(g_v113BranchCandidate144.rva),
        g_v113CallCandidate144.valid ? "" : "disabled/", static_cast<unsigned long long>(g_v113CallCandidate144.rva),
        g_v113ThreadsArmed144.load(std::memory_order_acquire));

    const ULONGLONG armTick = GetTickCount64();
    ULONGLONG nextEnumerate = armTick;
    ULONGLONG nextHeartbeat = armTick;
    ULONGLONG commitTick = 0;
    bool returnLogged = false, slotLogged = false, branchLogged = false, callLogged = false;
    const char* classification = nullptr;

    while (!g_v113Stop144.load(std::memory_order_acquire))
    {
        const ULONGLONG now = GetTickCount64();
        const bool commitSeen = g_v104ConnectedCommitSeen.load(std::memory_order_acquire);
        const bool returnHit = V113CaptureReady144(&g_v113ReturnCaptureState144);

        if (now >= nextEnumerate)
        {
            nextEnumerate = now + (commitSeen ? 100u : 50u);
            V113ArmNewThreads144(states, commitSeen);
        }

        if (returnHit && !g_v113PostCommitPromoted144.exchange(true, std::memory_order_acq_rel))
        {
            commitTick = g_v113ReturnCapture144.tickMs;
            for (const auto& state : states)
                if (state.tid != g_v113ReturnCapture144.tid)
                    V113PromoteThreadToPostCommit144(state.tid);
            ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
                "[V113-PROMOTE] commitTid=%lu action=ARM_SLOT50_ON_OTHER_TRACKED_THREADS tracked=%zu "
                "DR2_DR3=commit_thread_only stateWrites=off\r\n",
                g_v113ReturnCapture144.tid, states.size());
        }

        if (returnHit && !returnLogged)
        {
            returnLogged = true;
            V113LogCapture144("CONNECTED-RETURN", g_v113ReturnCapture144, nullptr);
        }
        if (V113CaptureReady144(&g_v113BranchCaptureState144) && !branchLogged)
        {
            branchLogged = true;
            V113LogCapture144("POST-BRANCH", g_v113BranchCapture144, &g_v113BranchCandidate144);
        }
        if (V113CaptureReady144(&g_v113CallCaptureState144) && !callLogged)
        {
            callLogged = true;
            V113LogCapture144("POST-CALLSITE", g_v113CallCapture144, &g_v113CallCandidate144);
        }
        if (V113CaptureReady144(&g_v113Slot50CaptureState144) && !slotLogged)
        {
            slotLogged = true;
            V113LogCapture144("SLOT50-TARGET", g_v113Slot50Capture144, nullptr);
            classification = "SLOT50_TARGET_EXECUTED_CALLER_CAPTURED";
            break;
        }

        std::uint32_t source3 = 0xFFFFFFFFu;
        V97ReadSource3Value144(source3);
        if (source3 != 0u && source3 != 0xFFFFFFFFu)
        {
            classification = "SOURCE3_COMPLETION_MATERIALIZED_DURING_V113";
            break;
        }

        const unsigned safetyHits = g_v113PreCommitReturnHits144.load(std::memory_order_acquire) +
            g_v113PreCommitOtherHits144.load(std::memory_order_acquire);
        if (!commitSeen && safetyHits > kV113PreCommitExceptionSafetyLimit144)
        {
            classification = "PRECOMMIT_BREAKPOINT_RATE_SAFETY_ABORT";
            break;
        }

        if (!commitSeen && now >= armTick + kV113WaitForCommitTimeoutMs144)
        {
            classification = "CONNECTED_COMMIT_NOT_OBSERVED_WITHIN_180S";
            break;
        }

        if (returnHit && commitTick && now >= commitTick + kV113PostCommitWatchMs144)
        {
            if (branchLogged || callLogged)
                classification = "CONNECTED_OWNER_CONTINUED_WITHOUT_SLOT50_TARGET";
            else
                classification = "CONNECTED_RETURN_CAPTURED_NO_SELECTED_POSTSITE";
            break;
        }

        if (commitSeen && !returnHit)
        {
            const ULONGLONG naturalCommitTick = static_cast<ULONGLONG>(g_v104ConnectedCommitUptimeMs.load(std::memory_order_acquire));
            if (naturalCommitTick && now >= naturalCommitTick + 2000ull)
            {
                classification = "CONNECTED_COMMIT_OBSERVED_BUT_RETURN_WATCH_MISSED";
                break;
            }
        }

        if (now >= nextHeartbeat)
        {
            nextHeartbeat = now + 1000ull;
            ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
                "[V113-WATCH] elapsedMs=%llu commitSeen=%s captures={return:%s,branch:%s,call:%s,slot50:%s} "
                "preCommitHits={return:%u,other:%u} threadsArmed=%u source3=0x%08X stateWrites=off\r\n",
                static_cast<unsigned long long>(now - armTick), commitSeen ? "yes" : "no",
                returnHit ? "HIT" : "waiting", branchLogged ? "HIT" : "waiting", callLogged ? "HIT" : "waiting",
                slotLogged ? "HIT" : "waiting",
                g_v113PreCommitReturnHits144.load(std::memory_order_acquire),
                g_v113PreCommitOtherHits144.load(std::memory_order_acquire),
                g_v113ThreadsArmed144.load(std::memory_order_acquire), source3);
        }

        Sleep(10u);
    }

    for (const auto& state : states)
        V113RestoreThread144(state);
    if (g_v113Veh144)
    {
        RemoveVectoredExceptionHandler(g_v113Veh144);
        g_v113Veh144 = nullptr;
    }

    if (!classification)
        classification = "STOPPED_WITHOUT_CLASSIFICATION";

    const auto task = V97ReadSlot7Task144();
    const auto flags = SnapshotDwV58TaskFlags(task);
    std::uint32_t source3 = 0xFFFFFFFFu;
    V97ReadSource3Value144(source3);
    ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
        "[V113-COMPLETE] classification=%s dwStatus=%d source3=0x%08X task=%p "
        "captures={return:%s,branch:%s,call:%s,slot50:%s} "
        "D={%02X/%02X/%02X/%02X} E={%02X/%02X/%02X/%02X} "
        "threadsArmed=%u debugRegistersRestored=yes resultFetchBreakpoint=OFF instructionBytesModified=NO "
        "vtableWrites=off stateWrites=off\r\n",
        classification, DwV58DerivedStatus(), source3, reinterpret_cast<void*>(task),
        V113CaptureReady144(&g_v113ReturnCaptureState144) ? "yes" : "no",
        V113CaptureReady144(&g_v113BranchCaptureState144) ? "yes" : "no",
        V113CaptureReady144(&g_v113CallCaptureState144) ? "yes" : "no",
        V113CaptureReady144(&g_v113Slot50CaptureState144) ? "yes" : "no",
        flags.d[0], flags.d[1], flags.d[2], flags.d[3],
        flags.e[0], flags.e[1], flags.e[2], flags.e[3],
        g_v113ThreadsArmed144.load(std::memory_order_acquire));
    g_v113Finished144.store(true, std::memory_order_release);
    return 0;
}

static void ObserveSource3Dispatch113144() noexcept
{
    if (!MainImageBase())
        return;

    bool expected = false;
    if (!g_v113Started144.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
        "[V113-AUTO] mode=CONNECTED_OWNER_CONTINUATION_TRACE "
        "preCommitWatch={DR0:0x4531538} postCommitWatch={DR1:0x2B59C00,DR2:firstLocalJcc,DR3:firstLocalCall} "
        "waitForV111Restore=yes requiresV103ConnectedObserver=yes hotResultFetchBreakpoint=OFF "
        "functionDetoursAddedByV113=0 int3=OFF codeWrites=OFF vtableWrites=OFF stateWrites=off\r\n");

    DWORD workerId = 0;
    g_v113Worker144 = CreateThread(nullptr, 0, V113OwnerTraceWorker144, nullptr, 0, &workerId);
    if (!g_v113Worker144)
    {
        const DWORD error = GetLastError();
        g_v113Started144.store(false, std::memory_order_release);
        ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
            "[V113-ARM] ready=NO reason=WORKER_CREATE_FAILED error=%lu stateWrites=off\r\n", error);
        return;
    }
    CloseHandle(g_v113Worker144);
    g_v113Worker144 = nullptr;
    ServerEmuTargetedAppend(L"v113_source3_dispatch_owner_trace.log",
        "[V113-ARM] ready=PENDING workerTid=%lu phase=WAIT_FOR_V111_THEN_V103 "
        "hotResultFetchBreakpoint=OFF stateWrites=off\r\n", workerId);
}
