#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cwchar>

#include "../game/IW8Addresses.h"

// MW2019 1.44 focused SessionService completion monitor.
//
// V8-V16 mapped the stock first-state machinery and eliminated several false
// State-2 producer candidates without forcing auth state. V17 then captured the
// live virtual slot selected after a successfully parsed SessionService method-1
// response: outer callback vtable 0x7109520 slot 1 -> 0x6C0B20.
//
// V18 proved 0x6C0B20 is not the completion body. Its exact code advances RCX
// to object+0x8, resolves an embedded/tagged interface, loads that interface's
// vtable, and tail-jumps through slot 1. The outer object and RPC argument
// buffers were unchanged across that dispatch. V18 also found the outer object
// links directly to the first-state storage at object+0x20 and observed the
// embedded interface vtable at RVA 0x6F662C8.
//
// V19 resolved that second-level slot to 0x4641710 and exposed the actual
// delegate layout. 0x4641710 is itself a tiny dispatcher: it loads the callback
// context from embedded+0x18 and tail-jumps through the function pointer at
// embedded+0x08. On the live path those fields are exactly 0x9BF08B0 (the
// first-state object) and 0x4641CF0. V20 proved 0x4641CF0 is the obfuscated
// preserve-and-return default stub and found exactly one focused address-taken
// xref: 0x4641BF6 inside bounded function 0x4641A60..0x4641CE2.
//
// V21 found that 0x4641A60 has exactly one focused direct caller:
// 0x4642CE8 inside the already-known AuthenticationListener result handler.
// The address catalog had already identified that call as the flag-7-absent
// helper path (the handler loads [RSI+0x10], shifts by 7, tests bit 0, and
// branches to 0x4642CE1 when that bit is clear). V21's runtime installer
// breakpoint did not fire, and its Method-1 observer armed too late because the
// 236/64-byte BGS replies arrived while the worker was dumping/scanning code.
//
// V22 corrects that timing and the interpretation. It arms the Method-1 virtual
// call observer before waiting for State 1 and adds exact one-shot observers at
// the auth-result flag-7 gate (0x4642C90) and the flag-7-absent helper call
// (0x4642CE8). The live response flags/required field/error/pointers are
// captured without modification. If the absent-helper path executes, V22 also
// traps immediately after the helper returns to prove whether it changes the
// first-state object before the stock jump to the handler epilogue. Heavy static
// scans are deferred until after the live trace. Every patched byte is restored
// before stock execution continues; no auth/game state value is written. The
// final emulator goal remains server/protocol driven.

namespace
{
    constexpr const auto& k144 = iw8_addresses::MW2019_1_44_Discovery;

    template <typename T, size_t N>
    constexpr size_t ArrayCount(const T (&)[N]) noexcept
    {
        return N;
    }

    constexpr std::uintptr_t kFirstStateRva = k144.BNetFirstStateValue;
    constexpr std::uintptr_t kPrereqRva = k144.BNetPrereqBoolValue;
    constexpr std::uintptr_t kPrereqInitRva = k144.BNetPrereqInitFlag;

    constexpr std::uintptr_t kResult1B8 = k144.BNetAuthResultField1B8Offset;
    constexpr std::uintptr_t kResult1BC = k144.BNetAuthResultField1BCOffset;
    constexpr std::uintptr_t kResult1C0 = k144.BNetAuthResultField1C0Offset;
    constexpr std::uintptr_t kResult1C8 = k144.BNetAuthResultField1C8Offset;
    constexpr std::uintptr_t kSnapshotObjectOffset = k144.BNetFirstStateSnapshotObjectOffset;
    constexpr std::uintptr_t kSnapshotValueOffset = k144.BNetFirstStateSnapshotValueOffset;
    constexpr std::uintptr_t kSnapshotInitOffset = k144.BNetFirstStateSnapshotInitOffset;
    constexpr size_t kWatchBytes = 0x340;

    constexpr ULONGLONG kWaitForState1Ms = 180000ull;
    constexpr ULONGLONG kTraceAfterState1Ms = 60000ull;
    constexpr ULONGLONG kWaitHeartbeatMs = 15000ull;
    constexpr ULONGLONG kTraceHeartbeatMs = 2000ull;
    constexpr unsigned kMaxDiffLines = 512u;
    constexpr ULONGLONG kAuthCommitReadyHeartbeatMs = 1000ull;

    // Corrected V3 interpretation: the JNE at 0x4641D5B is taken whenever
    // firstState is already nonzero, and its target 0x4641E4D is the pump's
    // common early-return/epilogue, not a state-1 processing routine.
    constexpr std::uintptr_t kFirstStatePumpRva = k144.BNetFirstStatePumpCandidate;
    constexpr std::uintptr_t kFirstStatePumpNonzeroBranchRva = k144.BNetFirstStatePumpNonzeroBranch;
    constexpr std::uintptr_t kFirstStatePumpEarlyReturnEpilogueRva = k144.BNetFirstStatePumpEarlyReturnEpilogue;
    constexpr std::uintptr_t kFirstStateGetterRva = k144.BNetSignInFirstStateGetter;

    // V4 correction targets. Candidate #1 is a state-2 consumer: it calls the
    // getter at 0x2AD94EA, compares [RAX] with 2 at 0x2AD94F8, and leaves the
    // function unless state 2 has ALREADY been reached. Candidate #2's reported
    // store at 0x3DAA9C8 is inside the rel32 displacement of the CALL at
    // 0x3DAA9C5, so it is not an instruction at all. These are retained only as
    // evidence/corrections and are never patched.
    constexpr std::uintptr_t kState2ConsumerGetterCall1Rva = k144.BNetFirstState2ConsumerGetterCall;
    constexpr std::uintptr_t kState2ConsumerCompareRva = k144.BNetFirstState2ConsumerCompare;
    constexpr std::uintptr_t kState2ConsumerRejectJneRva = k144.BNetFirstState2ConsumerRejectJne;
    constexpr std::uintptr_t kState2ConsumerRejectTargetRva = k144.BNetFirstState2ConsumerRejectTarget;
    constexpr std::uintptr_t kState2ConsumerSnapshotGetterCallRva = k144.BNetFirstState2ConsumerSnapshotGetterCall;
    constexpr std::uintptr_t kState2ConsumerSnapshotCompareRva = k144.BNetFirstState2ConsumerSnapshotCompare;
    constexpr std::uintptr_t kState2ConsumerSnapshotRejectJeRva = k144.BNetFirstState2ConsumerSnapshotRejectJe;
    constexpr std::uintptr_t kState2ConsumerObjectGetterCallRva = k144.BNetFirstState2ConsumerObjectGetterCall;
    constexpr std::uintptr_t kState2ConsumerObjectLeaRva = k144.BNetFirstState2ConsumerObjectLea;
    constexpr std::uintptr_t kFalseWriter2GetterCallRva = k144.BNetFirstStateAsyncWriterCandidate2Call;
    constexpr std::uintptr_t kFalseWriter2PostCallJmpRva = k144.BNetFirstStateFalseWriter2PostCallJmp;
    constexpr std::uintptr_t kFalseWriter2SecondGetterCallRva = k144.BNetFirstStateFalseWriter2SecondGetterCall;
    constexpr std::uintptr_t kFalseWriter2BogusStoreByteRva = k144.BNetFirstStateFalseWriter2BogusStoreByte;

    // Confirmed auth-result handler. This is the routine/page where the older
    // failing server response executed the exact [RDI]=3 writer at 0x4642A2A.
    // V7 passively dumps this extended window only after its protected code has
    // materialized. V6 showed the success-side structural continuation extends
    // beyond 0x4642B20, so this wider range follows that same callback farther.
    constexpr std::uintptr_t kAuthCommitWindowStartRva = k144.BNetAuthCommitSearchWindowStart;
    constexpr std::uintptr_t kAuthCommitWindowEndRva = k144.BNetAuthCommitSearchWindowEnd;
    constexpr std::uintptr_t kAuthResultInit1B8Rva = k144.BNetAuthResultInitByteWriter;
    constexpr std::uintptr_t kAuthResultInit1BCRva = k144.BNetAuthResultInitDwordWriter;
    constexpr std::uintptr_t kAuthResultInit1C0Rva = k144.BNetAuthResultInitQwordWriter;
    constexpr std::uintptr_t kAuthFailureState3WriterRva = k144.BNetAuthFailureState3Writer;
    constexpr std::uintptr_t kAuthFailureErrorWriterRva = k144.BNetAuthFailureErrorWriter;

    // V6 materialized-code confirmations inside the same callback. A zero
    // response error at [RSI+0x38] branches from 0x46429F7 to 0x4642A65,
    // where the success-side structural validation begins. The two entitlement
    // flag failures write 0x7FFFFF03/04 before converging on state 3.
    constexpr std::uintptr_t kAuthResponseErrorLoadRva = k144.BNetAuthResponseErrorCodeLoad;
    constexpr std::uintptr_t kAuthResponseErrorTestRva = k144.BNetAuthResponseErrorCodeTest;
    constexpr std::uintptr_t kAuthNoErrorBranchRva = k144.BNetAuthResponseNoErrorBranch;
    constexpr std::uintptr_t kAuthNoErrorTargetRva = k144.BNetAuthResponseNoErrorTarget;
    constexpr std::uintptr_t kAuthValidation1CallRva = k144.BNetAuthSuccessValidation1Call;
    constexpr std::uintptr_t kAuthValidation1RejectJccRva = k144.BNetAuthSuccessValidation1RejectJcc;
    constexpr std::uintptr_t kAuthRequiredField28CompareRva = k144.BNetAuthRequiredField28Compare;
    constexpr std::uintptr_t kAuthRequiredField28RejectJccRva = k144.BNetAuthRequiredField28RejectJcc;
    constexpr std::uintptr_t kAuthValidation2CallRva = k144.BNetAuthSuccessValidation2Call;
    constexpr std::uintptr_t kAuthValidation2RejectJccRva = k144.BNetAuthSuccessValidation2RejectJcc;
    constexpr std::uintptr_t kAuthFlag6TestRva = k144.BNetAuthFlag6Test;
    constexpr std::uintptr_t kAuthFlag10TestRva = k144.BNetAuthFlag10Test;
    constexpr std::uintptr_t kAuthFailureError4WriterRva = k144.BNetAuthFailureError4Writer;
    constexpr std::uintptr_t kAuthSuccessContinuationRva = k144.BNetAuthSuccessContinuation;

    // V7 confirmations. The structural validation reject target is a second
    // state-3 commit with error 0x7FFFFF02. The normal handler itself returns
    // without any literal [RDI]=2 store, so V8 searches the neighboring BNet
    // cluster for the caller/result consumers that perform the later readiness
    // transition. All scans are read-only.
    constexpr std::uintptr_t kAuthResultHandlerEntryRva = k144.BNetAuthResultHandlerEntry;
    constexpr std::uintptr_t kAuthStructuralFailureState3WriterRva = k144.BNetAuthStructuralFailureState3Writer;
    constexpr std::uintptr_t kAuthStructuralFailureError2WriterRva = k144.BNetAuthStructuralFailureError2Writer;
    constexpr std::uintptr_t kAuthFlag7LoadRva = k144.BNetAuthFlag7Load;
    constexpr std::uintptr_t kAuthFlag7TestRva = k144.BNetAuthFlag7Test;
    constexpr std::uintptr_t kAuthFlag7AbsentBranchRva = k144.BNetAuthFlag7AbsentBranch;
    constexpr std::uintptr_t kAuthFlag7AbsentTargetRva = k144.BNetAuthFlag7AbsentTarget;
    constexpr std::uintptr_t kAuthFlag7AbsentHelperCallRva = k144.BNetAuthFlag7AbsentHelperCall;
    constexpr std::uintptr_t kAuthFlag7AbsentHelperTargetRva = k144.BNetAuthFlag7AbsentHelperTarget;
    constexpr std::uintptr_t kAuthResultHandlerEpilogueRva = k144.BNetAuthResultHandlerEpilogue;
    constexpr std::uintptr_t kAuthResultHandlerReturnRva = k144.BNetAuthResultHandlerReturn;

    constexpr std::uintptr_t kBNetConsumerScanStartRva = k144.BNetAuthClusterScanStart;
    constexpr std::uintptr_t kBNetConsumerScanEndRva = k144.BNetAuthClusterScanEnd;

    // V8's +0x1C8 field scan exposed the real stock state-2 commit. The field
    // scanner reported the displacement at 0x4641807 / instruction hint
    // 0x4641806, but decoding the captured bytes places the actual MOV [RCX],2
    // at 0x46417FF and the following error/status write at 0x4641805.
    constexpr std::uintptr_t kState2SuccessEntryRva = k144.BNetAuthSuccessState2Entry;
    constexpr std::uintptr_t kState2SuccessWriterRva = k144.BNetAuthSuccessState2Writer;
    constexpr std::uintptr_t kState2SuccessErrorWriterRva = k144.BNetAuthSuccessErrorWriter;
    constexpr std::uintptr_t kState2SuccessErrorDispRva = k144.BNetAuthSuccessErrorDisp;
    constexpr std::uintptr_t kState2SuccessWindowStartRva = k144.BNetAuthSuccessCommitWindowStart;
    constexpr std::uintptr_t kState2SuccessWindowEndRva = k144.BNetAuthSuccessCommitWindowEnd;
    constexpr std::uintptr_t kState2SuccessLocalFlowStartRva = k144.BNetAuthSuccessLocalFlowStart;
    constexpr std::uintptr_t kState2SuccessLocalFlowEndRva = k144.BNetAuthSuccessLocalFlowEnd;

    // V10: the only direct rel32 CALL found to the exact 0x46417C0 entry is
    // 0x464314C, but 0x4643147 is an unconditional EB 08 -> 0x4643151 that
    // skips the call. Treat that xref as dead unless a separate edge lands in
    // the skipped bytes. Search for the real indirect/function-pointer route.
    constexpr std::uintptr_t kState2DeadDirectCallRva = k144.BNetAuthSuccessDeadDirectCall;
    constexpr std::uintptr_t kState2DeadSkipJmpRva = k144.BNetAuthSuccessDeadSkipJmp;
    constexpr std::uintptr_t kState2DeadSkipTargetRva = k144.BNetAuthSuccessDeadSkipTarget;
    constexpr std::uintptr_t kState2Thunk16E0Rva = k144.BNetAuthFieldA8AddressAccessor;
    constexpr std::uintptr_t kState2Thunk16F0Rva = k144.BNetAuthFieldF0LoadAccessor;
    constexpr std::uintptr_t kState2Thunk17B0Rva = k144.BNetAuthField118AddressAccessor;

    // V11/V12 runtime correlation limits. V11 proved the live object contains
    // several image/private references and, critically, an image-resident table
    // at authOffset +0xA8 whose entries resolve to executable functions. V12
    // treats those as function pointers instead of recursively scanning code as
    // if it were another pointer table. It also classifies direct executable
    // callback fields (notably the observed +0x318 -> 0x464A840 path), scans
    // bounded function bodies for rel32 edges into the confirmed state-2 window,
    // and finds RIP-relative code references to the owner slot/table.
    constexpr size_t kState2RuntimeGlobalRadius = 0x00800000u; // +/- 8 MiB
    constexpr size_t kState2RuntimeRefWindow = 0x00010000u;    // +/- 64 KiB
    constexpr size_t kState2RuntimeVtableWindow = 0x00000800u; // 2 KiB
    constexpr unsigned kState2RuntimeMaxHits = 256u;
    constexpr unsigned kState2RuntimeMaxRegions = 96u;
    constexpr unsigned kState2OwnerMaxTableEntries = 96u;
    constexpr size_t kState2OwnerFunctionScanBytes = 0x00000600u;
    constexpr unsigned kState2OwnerMaxEdgeLogs = 256u;
    constexpr unsigned kState2OwnerMaxXrefLogs = 256u;

    // V14: 0x4653A20 is a tail JMP alias to the &auth+0xA8 accessor at
    // 0x46416E0. Follow callers of all confirmed accessors and inspect a short
    // read-only window after each CALL for stores through the returned pointer.
    constexpr std::uintptr_t kState2Thunk16E0AliasRva = k144.BNetAuthFieldA8AddressAccessorAlias;
    constexpr size_t kState2AccessorPostCallScanBytes = 0x00000080u;
    constexpr unsigned kState2AccessorMaxCallerLogs = 256u;
    constexpr unsigned kState2AccessorMaxUseLogs = 256u;

    // V16: V15 proved the caller itself never writes through the returned
    // accessor pointer after instruction-boundary/call-clobber cleanup.
    // Follow the pointer one level into the helper receiving it.
    constexpr unsigned kState2HelperMaxCandidates = 64u;
    constexpr size_t kState2HelperFunctionScanBytes = 0x00000500u;
    constexpr unsigned kState2HelperMaxFlowLogs = 256u;

    // Confirmed SessionService locations retained for correlation only. No
    // breakpoint or patch is placed at any of these addresses.
    constexpr std::uintptr_t kSessionRpcRva = k144.BgsSessionServiceSharedRpcCall;
    constexpr std::uintptr_t kSessionParserRva = k144.BgsSessionServiceMethod1Parser;
    constexpr std::uintptr_t kRpcDecisionRva = k144.BgsSessionServiceRpcResultDecision;
    constexpr std::uintptr_t kOptionalField20Rva = k144.BgsSessionServiceOptionalField20Decision;
    constexpr std::uintptr_t kNormalPathRva = k144.BgsSessionServiceNormalNoField20Path;
    constexpr std::uintptr_t kPreVirtualCallbackRva = k144.BgsSessionServiceNormalVirtualCallback;
    constexpr std::uintptr_t kPostVirtualCallbackRva = k144.BgsSessionServiceNormalVirtualCallbackReturn;
    constexpr std::uintptr_t kNormalHandlerReturnRva = k144.BgsSessionServiceNormalHandlerReturn;

    // V19: V18 proved the live slot-1 target at 0x6C0B20 is a forwarding
    // thunk, not the auth-completion body. It adjusts RCX to object+0x8,
    // resolves an embedded/tagged interface, loads that interface vtable, and
    // tail-jumps through slot 1. Resolve that second-level target at runtime.
    constexpr std::uintptr_t kSessionMethod1CallbackRva = k144.BgsSessionServiceMethod1CallbackSlot1;
    constexpr std::uintptr_t kSessionMethod1CallbackVtableRva = k144.BgsSessionServiceMethod1CallbackVtable;
    constexpr std::uintptr_t kSessionMethod1EmbeddedInterfaceOffset = k144.BgsSessionServiceMethod1EmbeddedInterfaceOffset;
    constexpr std::uintptr_t kSessionMethod1ObservedEmbeddedVtableRva = k144.BgsSessionServiceMethod1ObservedEmbeddedVtable;
    constexpr std::uintptr_t kSessionMethod1EmbeddedSlot1DispatchRva = k144.BgsSessionServiceMethod1EmbeddedSlot1Dispatch;
    constexpr std::uintptr_t kSessionMethod1EmbeddedInvokeTargetOffset = k144.BgsSessionServiceMethod1EmbeddedInvokeTargetOffset;
    constexpr std::uintptr_t kSessionMethod1EmbeddedInvokeContextOffset = k144.BgsSessionServiceMethod1EmbeddedInvokeContextOffset;
    constexpr std::uintptr_t kSessionMethod1CompanionCodeOffset = k144.BgsSessionServiceMethod1CompanionCodeOffset;
    constexpr std::uintptr_t kSessionMethod1ObservedInvokeTargetRva = k144.BgsSessionServiceMethod1ObservedCompanionCode;
    constexpr std::uintptr_t kSessionMethod1StateObjectOffset = k144.BgsSessionServiceMethod1StateObjectOffset;
    constexpr size_t kSessionMethod1ObjectSnapshotBytes = 0x100u;
    constexpr size_t kSessionMethod1ArgSnapshotBytes = 0x80u;
    constexpr size_t kSessionMethod1ForwardSnapshotBytes = 0x100u;
    constexpr size_t kSessionMethod1LinkedStateSnapshotBytes = 0x80u;
    constexpr std::uintptr_t kSessionMethod1BgsXrefScanStartRva = 0x00600000u;
    constexpr std::uintptr_t kSessionMethod1BgsXrefScanEndRva = 0x00900000u;
    constexpr std::uintptr_t kSessionMethod1BnetXrefScanStartRva = 0x0463F000u;
    constexpr std::uintptr_t kSessionMethod1BnetXrefScanEndRva = 0x04660000u;
    constexpr unsigned kSessionMethod1InvokeMaxXrefs = 96u;

    // V21: V20 found the only focused address-taken xref to the default
    // preserve/return invoke stub. The bounded owner function constructs the
    // delegate locally and is now the exact registration target.
    constexpr std::uintptr_t kSessionMethod1DelegateInstallerFunctionRva =
        k144.BgsSessionServiceMethod1DelegateInstallerFunction;
    constexpr std::uintptr_t kSessionMethod1DelegateInstallerFunctionEndRva =
        k144.BgsSessionServiceMethod1DelegateInstallerFunctionEnd;
    constexpr std::uintptr_t kSessionMethod1DefaultInvokeAddressLoadRva =
        k144.BgsSessionServiceMethod1DefaultInvokeAddressLoad;
    constexpr std::uintptr_t kSessionMethod1DelegateVtableAddressLoadRva =
        k144.BgsSessionServiceMethod1DelegateVtableAddressLoad;
    constexpr std::uintptr_t kSessionMethod1DelegateSubmitCallRva =
        k144.BgsSessionServiceMethod1DelegateSubmitCall;
    constexpr std::uintptr_t kSessionMethod1DelegateSubmitTargetRva =
        k144.BgsSessionServiceMethod1DelegateSubmitTarget;
    constexpr std::uintptr_t kSessionMethod1DelegatePreInstallCallRva =
        k144.BgsSessionServiceMethod1DelegatePreInstallCall;
    constexpr std::uintptr_t kSessionMethod1DelegatePreInstallTargetRva =
        k144.BgsSessionServiceMethod1DelegatePreInstallTarget;
    constexpr unsigned kSessionMethod1InstallerStackQwords = 32u;
    constexpr size_t kSessionMethod1InstallerFrameBytes = 0x100u;
    constexpr unsigned kSessionMethod1InstallerMaxCallerXrefs = 64u;

    // V22 live auth-result gate observer. 0x4642C90 is the confirmed
    // MOV EAX,[RSI+0x10] that feeds SHR EAX,7 / TEST AL,1. If bit 7 is
    // clear, 0x4642C98 branches to 0x4642CE1 and reaches CALL 0x4641A60
    // at 0x4642CE8. The byte after that CALL is the stock EB 40 jump to
    // the auth-result handler epilogue.
    constexpr std::uintptr_t kAuthFlag7GateRva = kAuthFlag7LoadRva;
    constexpr std::uintptr_t kAuthFlag7AbsentCallRva = kAuthFlag7AbsentHelperCallRva;
    constexpr std::uintptr_t kAuthFlag7AbsentReturnRva = kAuthFlag7AbsentHelperCallRva + 5u;
    constexpr size_t kAuthFlag7ResponseSnapshotBytes = 0x80u;
    constexpr unsigned kAuthFlag7StackQwords = 24u;

    // Retained only so the V18 owner-scan helper remains compilable for
    // reference; V19 no longer calls that broad scan.
    constexpr std::uintptr_t kSessionBgsOwnerScanStartRva = 0x00600000u;
    constexpr std::uintptr_t kSessionBgsOwnerScanEndRva = 0x00900000u;
    constexpr unsigned kSessionOwnerMaxXrefs = 64u;
    constexpr std::uintptr_t kSessionCallbackObjectOffsetFromR14 = k144.BgsSessionServiceNormalCallbackObjectOffsetFromR14;
    constexpr std::uintptr_t kSessionCallbackVtableSlotOffset = k144.BgsSessionServiceNormalCallbackVtableSlotOffset;

    volatile LONG g_logLock = 0;
    volatile LONG g_workerStarted = 0;
    HANDLE g_logFile = INVALID_HANDLE_VALUE;
    std::uintptr_t g_imageBase = 0;
    std::uintptr_t g_imageEnd = 0;

    template <typename T>
    bool SafeRead(std::uintptr_t address, T* out) noexcept
    {
        if (!address || !out)
            return false;
        __try
        {
            *out = *reinterpret_cast<const T*>(address);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::memset(out, 0, sizeof(T));
            return false;
        }
    }

    bool SafeReadBytes(std::uintptr_t address, void* out, size_t bytes) noexcept
    {
        if (!address || !out || !bytes)
            return false;
        __try
        {
            std::memcpy(out, reinterpret_cast<const void*>(address), bytes);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::memset(out, 0, bytes);
            return false;
        }
    }

    void LockLog() noexcept
    {
        while (InterlockedCompareExchange(&g_logLock, 1, 0) != 0)
            YieldProcessor();
    }

    void UnlockLog() noexcept
    {
        InterlockedExchange(&g_logLock, 0);
    }

    void WriteRaw(const char* text) noexcept
    {
        if (!text || !*text)
            return;

        LockLog();
        const DWORD length = static_cast<DWORD>(std::strlen(text));
        DWORD written = 0;
        if (g_logFile != INVALID_HANDLE_VALUE)
        {
            WriteFile(g_logFile, text, length, &written, nullptr);
            FlushFileBuffers(g_logFile);
        }

        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        if (out && out != INVALID_HANDLE_VALUE)
        {
            DWORD consoleWritten = 0;
            WriteFile(out, text, length, &consoleWritten, nullptr);
        }
        OutputDebugStringA(text);
        UnlockLog();
    }

    void Log(const char* fmt, ...) noexcept
    {
        char buffer[4096]{};
        va_list args;
        va_start(args, fmt);
        _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args);
        va_end(args);
        WriteRaw(buffer);
    }

    void OpenTraceLog() noexcept
    {
        wchar_t exePath[32768]{};
        const DWORD n = GetModuleFileNameW(nullptr, exePath, static_cast<DWORD>(ArrayCount(exePath)));
        if (!n || n >= ArrayCount(exePath))
            return;

        wchar_t* slash = wcsrchr(exePath, L'\\');
        if (!slash)
            return;
        *slash = L'\0';

        wchar_t codDir[32768]{};
        wchar_t mwDir[32768]{};
        wchar_t emuDir[32768]{};
        wchar_t logPath[32768]{};
        _snwprintf_s(codDir, ArrayCount(codDir), _TRUNCATE, L"%s\\CodRevamped", exePath);
        _snwprintf_s(mwDir, ArrayCount(mwDir), _TRUNCATE, L"%s\\MW2019", codDir);
        _snwprintf_s(emuDir, ArrayCount(emuDir), _TRUNCATE, L"%s\\server_emu", mwDir);
        _snwprintf_s(logPath, ArrayCount(logPath), _TRUNCATE, L"%s\\session_completion_trace.log", emuDir);

        CreateDirectoryW(codDir, nullptr);
        CreateDirectoryW(mwDir, nullptr);
        CreateDirectoryW(emuDir, nullptr);
        g_logFile = CreateFileW(
            logPath,
            FILE_APPEND_DATA | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    }

    bool ReadImageBounds(std::uintptr_t base, std::uintptr_t* endOut) noexcept
    {
        if (!base || !endOut)
            return false;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return false;
            if (nt->FileHeader.TimeDateStamp != iw8_addresses::MW2019_1_44.timestamp ||
                nt->OptionalHeader.SizeOfImage != iw8_addresses::MW2019_1_44.imageSize)
            {
                return false;
            }
            *endOut = base + nt->OptionalHeader.SizeOfImage;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    std::uint32_t ReadU32FromBlock(const BYTE* block, size_t offset) noexcept
    {
        std::uint32_t value = 0;
        if (block && offset + sizeof(value) <= kWatchBytes)
            std::memcpy(&value, block + offset, sizeof(value));
        return value;
    }

    std::uint64_t ReadU64FromBlock(const BYTE* block, size_t offset) noexcept
    {
        std::uint64_t value = 0;
        if (block && offset + sizeof(value) <= kWatchBytes)
            std::memcpy(&value, block + offset, sizeof(value));
        return value;
    }

    struct AuthSnapshot
    {
        bool readable{};
        BYTE object[kWatchBytes]{};
        std::uint32_t state{};
        BYTE field1B8{};
        std::uint32_t field1BC{};
        std::uint64_t field1C0{};
        std::uint32_t field1C8{};
        std::uint32_t snapshotValue{};
        BYTE snapshotInit{};
        BYTE prereq{};
        BYTE prereqInit{};
    };

    AuthSnapshot ReadSnapshot() noexcept
    {
        AuthSnapshot s{};
        const std::uintptr_t a = g_imageBase + kFirstStateRva;
        s.readable = SafeReadBytes(a, s.object, sizeof(s.object));
        if (s.readable)
        {
            s.state = ReadU32FromBlock(s.object, 0x0);
            s.field1B8 = s.object[kResult1B8];
            s.field1BC = ReadU32FromBlock(s.object, kResult1BC);
            s.field1C0 = ReadU64FromBlock(s.object, kResult1C0);
            s.field1C8 = ReadU32FromBlock(s.object, kResult1C8);
            s.snapshotValue = ReadU32FromBlock(s.object, kSnapshotValueOffset);
            s.snapshotInit = s.object[kSnapshotInitOffset];
        }
        SafeRead(g_imageBase + kPrereqRva, &s.prereq);
        SafeRead(g_imageBase + kPrereqInitRva, &s.prereqInit);
        return s;
    }

    bool ScalarDifferent(const AuthSnapshot& a, const AuthSnapshot& b) noexcept
    {
        return a.readable != b.readable ||
            a.state != b.state ||
            a.field1B8 != b.field1B8 ||
            a.field1BC != b.field1BC ||
            a.field1C0 != b.field1C0 ||
            a.field1C8 != b.field1C8 ||
            a.snapshotValue != b.snapshotValue ||
            a.snapshotInit != b.snapshotInit ||
            a.prereq != b.prereq ||
            a.prereqInit != b.prereqInit;
    }

    bool ObjectDifferent(const AuthSnapshot& a, const AuthSnapshot& b) noexcept
    {
        if (a.readable != b.readable)
            return true;
        if (!a.readable)
            return false;
        return std::memcmp(a.object, b.object, sizeof(a.object)) != 0;
    }

    void LogSnapshot(const char* reason, ULONGLONG elapsed, const AuthSnapshot& s) noexcept
    {
        Log(
            "[BGS-SESSION-COMP144] SAMPLE reason=%s elapsedMs=%llu readable=%s firstState=%u fields={+1B8:0x%02X +1BC:0x%08X +1C0:0x%016llX +1C8:0x%08X} snapshot={object:+0x%03llX value:0x%08X init:0x%02X} prereq={value:%u init:%u} mode=READ_ONLY_OBJECT_DIFF\r\n",
            reason ? reason : "sample",
            static_cast<unsigned long long>(elapsed),
            s.readable ? "yes" : "no",
            static_cast<unsigned>(s.state),
            static_cast<unsigned>(s.field1B8),
            static_cast<unsigned>(s.field1BC),
            static_cast<unsigned long long>(s.field1C0),
            static_cast<unsigned>(s.field1C8),
            static_cast<unsigned long long>(kSnapshotObjectOffset),
            static_cast<unsigned>(s.snapshotValue),
            static_cast<unsigned>(s.snapshotInit),
            static_cast<unsigned>(s.prereq),
            static_cast<unsigned>(s.prereqInit));
    }

    void BytesToHex(const BYTE* data, size_t count, char* out, size_t outCount) noexcept
    {
        if (!out || !outCount)
            return;
        out[0] = '\0';
        if (!data)
            return;

        size_t pos = 0;
        for (size_t i = 0; i < count && pos + 4 < outCount; ++i)
        {
            const int n = _snprintf_s(
                out + pos,
                outCount - pos,
                _TRUNCATE,
                "%s%02X",
                i ? " " : "",
                static_cast<unsigned>(data[i]));
            if (n <= 0)
                break;
            pos += static_cast<size_t>(n);
        }
    }

    unsigned LogObjectDiffs(
        ULONGLONG elapsed,
        const AuthSnapshot& before,
        const AuthSnapshot& after,
        unsigned emittedSoFar) noexcept
    {
        if (!before.readable || !after.readable || emittedSoFar >= kMaxDiffLines)
            return emittedSoFar;

        size_t i = 0;
        while (i < kWatchBytes && emittedSoFar < kMaxDiffLines)
        {
            if (before.object[i] == after.object[i])
            {
                ++i;
                continue;
            }

            const size_t runStart = i;
            while (i < kWatchBytes && before.object[i] != after.object[i])
                ++i;
            const size_t runEnd = i;

            size_t chunk = runStart;
            while (chunk < runEnd && emittedSoFar < kMaxDiffLines)
            {
                size_t count = runEnd - chunk;
                if (count > 16)
                    count = 16;

                char oldHex[64]{};
                char newHex[64]{};
                BytesToHex(before.object + chunk, count, oldHex, ArrayCount(oldHex));
                BytesToHex(after.object + chunk, count, newHex, ArrayCount(newHex));
                Log(
                    "[BGS-SESSION-COMP144] OBJECT_DIFF elapsedMs=%llu offset=+0x%03llX len=%llu old={%s} new={%s}\r\n",
                    static_cast<unsigned long long>(elapsed),
                    static_cast<unsigned long long>(chunk),
                    static_cast<unsigned long long>(count),
                    oldHex,
                    newHex);
                ++emittedSoFar;
                chunk += count;
            }
        }
        return emittedSoFar;
    }

    void LogFocusedWindow(const char* reason, ULONGLONG elapsed, const AuthSnapshot& s, size_t start, size_t bytes) noexcept
    {
        if (!s.readable || start >= kWatchBytes)
            return;
        if (start + bytes > kWatchBytes)
            bytes = kWatchBytes - start;

        size_t pos = 0;
        while (pos < bytes)
        {
            size_t count = bytes - pos;
            if (count > 16)
                count = 16;
            char hex[64]{};
            BytesToHex(s.object + start + pos, count, hex, ArrayCount(hex));
            Log(
                "[BGS-SESSION-COMP144] WINDOW reason=%s elapsedMs=%llu offset=+0x%03llX bytes={%s}\r\n",
                reason ? reason : "window",
                static_cast<unsigned long long>(elapsed),
                static_cast<unsigned long long>(start + pos),
                hex);
            pos += count;
        }
    }


    const char* DwordRegisterName(unsigned reg) noexcept
    {
        static const char* const names[] = {
            "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI",
            "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D"
        };
        return reg < ArrayCount(names) ? names[reg] : "UNKNOWN";
    }

    const char* BaseRegisterName(unsigned reg) noexcept
    {
        static const char* const names[] = {
            "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
            "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"
        };
        return reg < ArrayCount(names) ? names[reg] : "UNKNOWN";
    }

    bool ReadRel32Target(std::uintptr_t instructionRva, BYTE expectedOpcode, std::uintptr_t* targetOut) noexcept
    {
        if (!targetOut || !g_imageBase || g_imageBase + instructionRva + 5 > g_imageEnd)
            return false;
        BYTE b[5]{};
        if (!SafeReadBytes(g_imageBase + instructionRva, b, sizeof(b)) || b[0] != expectedOpcode)
            return false;
        std::int32_t rel = 0;
        std::memcpy(&rel, b + 1, sizeof(rel));
        *targetOut = static_cast<std::uintptr_t>(
            static_cast<std::intptr_t>(instructionRva + 5) + static_cast<std::intptr_t>(rel));
        return true;
    }

    void LogV4CandidateCorrections() noexcept
    {
        BYTE stateCmp[3]{};
        BYTE snapshotCmp[7]{};
        BYTE objectLea[7]{};
        BYTE bogusCall[5]{};
        std::uintptr_t reject1 = 0;
        std::uintptr_t reject2 = 0;
        std::uintptr_t postCallJmpTarget = 0;

        SafeReadBytes(g_imageBase + kState2ConsumerCompareRva, stateCmp, sizeof(stateCmp));
        SafeReadBytes(g_imageBase + kState2ConsumerSnapshotCompareRva, snapshotCmp, sizeof(snapshotCmp));
        SafeReadBytes(g_imageBase + kState2ConsumerObjectLeaRva, objectLea, sizeof(objectLea));
        SafeReadBytes(g_imageBase + kFalseWriter2SecondGetterCallRva, bogusCall, sizeof(bogusCall));

        // Jcc rel32 is six bytes: 0F 8x rel32.
        BYTE jcc[6]{};
        if (SafeReadBytes(g_imageBase + kState2ConsumerRejectJneRva, jcc, sizeof(jcc)) && jcc[0] == 0x0F && jcc[1] == 0x85)
        {
            std::int32_t rel = 0;
            std::memcpy(&rel, jcc + 2, sizeof(rel));
            reject1 = static_cast<std::uintptr_t>(static_cast<std::intptr_t>(kState2ConsumerRejectJneRva + 6) + rel);
        }
        if (SafeReadBytes(g_imageBase + kState2ConsumerSnapshotRejectJeRva, jcc, sizeof(jcc)) && jcc[0] == 0x0F && jcc[1] == 0x84)
        {
            std::int32_t rel = 0;
            std::memcpy(&rel, jcc + 2, sizeof(rel));
            reject2 = static_cast<std::uintptr_t>(static_cast<std::intptr_t>(kState2ConsumerSnapshotRejectJeRva + 6) + rel);
        }
        ReadRel32Target(kFalseWriter2PostCallJmpRva, 0xE9, &postCallJmpTarget);

        Log("[BGS-SESSION-COMP144] V4_CORRECTION candidate=async_writer_1 classification=STATE2_CONSUMER getterCall=0x%llX stateCmpRva=0x%llX stateCmpBytes={%02X %02X %02X} requiredState=2 rejectJne=0x%llX rejectTarget=0x%llX snapshotGetterCall=0x%llX snapshotCmpRva=0x%llX snapshotOffset=0x2D0 snapshotRejectJe=0x%llX snapshotRejectTarget=0x%llX objectGetterCall=0x%llX objectLeaRva=0x%llX objectOffset=0x2D4 writer=no\r\n",
            static_cast<unsigned long long>(kState2ConsumerGetterCall1Rva),
            static_cast<unsigned long long>(kState2ConsumerCompareRva),
            static_cast<unsigned>(stateCmp[0]), static_cast<unsigned>(stateCmp[1]), static_cast<unsigned>(stateCmp[2]),
            static_cast<unsigned long long>(kState2ConsumerRejectJneRva), static_cast<unsigned long long>(reject1),
            static_cast<unsigned long long>(kState2ConsumerSnapshotGetterCallRva),
            static_cast<unsigned long long>(kState2ConsumerSnapshotCompareRva),
            static_cast<unsigned long long>(kState2ConsumerSnapshotRejectJeRva), static_cast<unsigned long long>(reject2),
            static_cast<unsigned long long>(kState2ConsumerObjectGetterCallRva),
            static_cast<unsigned long long>(kState2ConsumerObjectLeaRva));

        const bool bogusBytesInsideCall = bogusCall[0] == 0xE8 &&
            kFalseWriter2BogusStoreByteRva > kFalseWriter2SecondGetterCallRva &&
            kFalseWriter2BogusStoreByteRva < kFalseWriter2SecondGetterCallRva + 5;
        Log("[BGS-SESSION-COMP144] V4_CORRECTION candidate=async_writer_2 classification=FALSE_POSITIVE getterCall=0x%llX postCallJmp=0x%llX postCallJmpTarget=0x%llX secondGetterCall=0x%llX callBytes={%02X %02X %02X %02X %02X} bogusStoreRva=0x%llX liesInsideCallRel32=%s writer=no\r\n",
            static_cast<unsigned long long>(kFalseWriter2GetterCallRva),
            static_cast<unsigned long long>(kFalseWriter2PostCallJmpRva),
            static_cast<unsigned long long>(postCallJmpTarget),
            static_cast<unsigned long long>(kFalseWriter2SecondGetterCallRva),
            static_cast<unsigned>(bogusCall[0]), static_cast<unsigned>(bogusCall[1]), static_cast<unsigned>(bogusCall[2]),
            static_cast<unsigned>(bogusCall[3]), static_cast<unsigned>(bogusCall[4]),
            static_cast<unsigned long long>(kFalseWriter2BogusStoreByteRva),
            bogusBytesInsideCall ? "yes" : "no");
    }

    struct AuthCommitSignature
    {
        BYTE init1B8 = 0;
        BYTE init1BC = 0;
        BYTE init1C0 = 0;
        BYTE failureState3 = 0;
        BYTE failureError = 0;
        unsigned readable = 0;
        unsigned expectedMatches = 0;
        unsigned nonZero = 0;
    };

    AuthCommitSignature ReadAuthCommitSignature() noexcept
    {
        AuthCommitSignature sig{};
        struct ProbeByte { std::uintptr_t rva; BYTE expected; BYTE* out; };
        ProbeByte probes[] =
        {
            { kAuthResultInit1B8Rva, 0xC6, &sig.init1B8 },
            { kAuthResultInit1BCRva, 0x89, &sig.init1BC },
            { kAuthResultInit1C0Rva, 0x48, &sig.init1C0 },
            { kAuthFailureState3WriterRva, 0xC7, &sig.failureState3 },
            { kAuthFailureErrorWriterRva, 0xC7, &sig.failureError },
        };
        for (auto& probe : probes)
        {
            BYTE value = 0;
            if (!SafeRead(g_imageBase + probe.rva, &value))
                continue;
            *probe.out = value;
            ++sig.readable;
            if (value != 0)
                ++sig.nonZero;
            if (value == probe.expected)
                ++sig.expectedMatches;
        }
        return sig;
    }

    bool AuthCommitWindowMaterialized(const AuthCommitSignature& sig) noexcept
    {
        // Exact 1.44 should converge to all five known opcode bytes. Allow one
        // mismatch so an already-live page is not missed because of a benign
        // neighboring runtime transform; the all-zero startup image cannot pass.
        return sig.readable == 5u && sig.nonZero >= 4u && sig.expectedMatches >= 4u;
    }

    void LogAuthCommitSignature(const char* reason, ULONGLONG elapsedMs, const AuthCommitSignature& sig) noexcept
    {
        Log("[BGS-SESSION-COMP144] AUTH_COMMIT_READY reason=%s elapsedMs=%llu readable=%u/5 nonZero=%u/5 expectedMatches=%u/5 opcodes={1B8:%02X 1BC:%02X 1C0:%02X state3:%02X error:%02X} materialized=%s read_only=yes\r\n",
            reason ? reason : "unknown", static_cast<unsigned long long>(elapsedMs),
            sig.readable, sig.nonZero, sig.expectedMatches,
            static_cast<unsigned>(sig.init1B8), static_cast<unsigned>(sig.init1BC),
            static_cast<unsigned>(sig.init1C0), static_cast<unsigned>(sig.failureState3),
            static_cast<unsigned>(sig.failureError), AuthCommitWindowMaterialized(sig) ? "yes" : "no");
    }

    void LogAuthCommitWindow(const char* reason, ULONGLONG elapsedMs) noexcept
    {
        if (!g_imageBase || kAuthCommitWindowStartRva >= kAuthCommitWindowEndRva ||
            g_imageBase + kAuthCommitWindowEndRva > g_imageEnd)
        {
            Log("[BGS-SESSION-COMP144] AUTH_COMMIT_WINDOW unavailable=yes reason=%s elapsedMs=%llu\r\n", reason ? reason : "unknown", static_cast<unsigned long long>(elapsedMs));
            return;
        }

        constexpr size_t kBytes = static_cast<size_t>(kAuthCommitWindowEndRva - kAuthCommitWindowStartRva);
        BYTE block[kBytes]{};
        if (!SafeReadBytes(g_imageBase + kAuthCommitWindowStartRva, block, sizeof(block)))
        {
            Log("[BGS-SESSION-COMP144] AUTH_COMMIT_WINDOW unreadable=yes reason=%s elapsedMs=%llu startRva=0x%llX endRva=0x%llX\r\n",
                reason ? reason : "unknown", static_cast<unsigned long long>(elapsedMs),
                static_cast<unsigned long long>(kAuthCommitWindowStartRva),
                static_cast<unsigned long long>(kAuthCommitWindowEndRva));
            return;
        }

        Log("[BGS-SESSION-COMP144] AUTH_COMMIT_WINDOW begin reason=%s elapsedMs=%llu startRva=0x%llX endRva=0x%llX knownInit={0x%llX,0x%llX,0x%llX} knownFailureState3=0x%llX knownFailureError=0x%llX mode=READ_ONLY_MATERIALIZED_CODE\r\n",
            reason ? reason : "unknown", static_cast<unsigned long long>(elapsedMs),
            static_cast<unsigned long long>(kAuthCommitWindowStartRva),
            static_cast<unsigned long long>(kAuthCommitWindowEndRva),
            static_cast<unsigned long long>(kAuthResultInit1B8Rva),
            static_cast<unsigned long long>(kAuthResultInit1BCRva),
            static_cast<unsigned long long>(kAuthResultInit1C0Rva),
            static_cast<unsigned long long>(kAuthFailureState3WriterRva),
            static_cast<unsigned long long>(kAuthFailureErrorWriterRva));

        Log("[BGS-SESSION-COMP144] AUTH_SUCCESS_PATH confirmed noErrorLoad=0x%llX noErrorTest=0x%llX noErrorJe=0x%llX target=0x%llX validation1Call=0x%llX validation1Reject=0x%llX requiredField28Cmp=0x%llX requiredField28Reject=0x%llX validation2Call=0x%llX validation2Reject=0x%llX flag6Test=0x%llX error03=0x%llX flag10Test=0x%llX error04=0x%llX continuation=0x%llX interpretation=success_side_continuation_after_error03_error04_gates read_only=yes\r\n",
            static_cast<unsigned long long>(kAuthResponseErrorLoadRva),
            static_cast<unsigned long long>(kAuthResponseErrorTestRva),
            static_cast<unsigned long long>(kAuthNoErrorBranchRva),
            static_cast<unsigned long long>(kAuthNoErrorTargetRva),
            static_cast<unsigned long long>(kAuthValidation1CallRva),
            static_cast<unsigned long long>(kAuthValidation1RejectJccRva),
            static_cast<unsigned long long>(kAuthRequiredField28CompareRva),
            static_cast<unsigned long long>(kAuthRequiredField28RejectJccRva),
            static_cast<unsigned long long>(kAuthValidation2CallRva),
            static_cast<unsigned long long>(kAuthValidation2RejectJccRva),
            static_cast<unsigned long long>(kAuthFlag6TestRva),
            static_cast<unsigned long long>(kAuthFailureErrorWriterRva),
            static_cast<unsigned long long>(kAuthFlag10TestRva),
            static_cast<unsigned long long>(kAuthFailureError4WriterRva),
            static_cast<unsigned long long>(kAuthSuccessContinuationRva));

        for (size_t pos = 0; pos < sizeof(block); pos += 16)
        {
            const size_t count = ((sizeof(block) - pos) > 16) ? 16 : (sizeof(block) - pos);
            char hex[64]{};
            BytesToHex(block + pos, count, hex, ArrayCount(hex));
            Log("[BGS-SESSION-COMP144] AUTH_COMMIT_CODE rva=0x%llX bytes={%s}\r\n",
                static_cast<unsigned long long>(kAuthCommitWindowStartRva + pos), hex);
        }

        unsigned exactState2Hits = 0;
        for (size_t i = 0; i + 6 <= sizeof(block); ++i)
        {
            // Exact sibling of the confirmed [RDI]=3 writer.
            if (block[i] == 0xC7 && block[i + 1] == 0x07 &&
                block[i + 2] == 0x02 && block[i + 3] == 0x00 &&
                block[i + 4] == 0x00 && block[i + 5] == 0x00)
            {
                ++exactState2Hits;
                Log("[BGS-SESSION-COMP144] AUTH_SUCCESS_STATE2_EXACT hit=%u rva=0x%llX bytes={C7 07 02 00 00 00} candidate=YES boundary_unverified=yes siblingOfKnownState3Writer=yes read_only=yes\r\n",
                    exactState2Hits,
                    static_cast<unsigned long long>(kAuthCommitWindowStartRva + i));
            }
        }

        unsigned literalHits = 0;
        for (size_t i = 0; i + 6 <= sizeof(block); ++i)
        {
            // C7 /0, mod=00, no SIB/displacement: MOV DWORD PTR [base], imm32.
            // This narrow pattern catches the confirmed C7 07 03 00 00 00 at
            // 0x4642A2A and any symmetric immediate state-2 commit using the
            // same simple base-register form. Raw hits remain boundary-unverified.
            if (block[i] != 0xC7)
                continue;
            const BYTE modrm = block[i + 1];
            const unsigned mod = (modrm >> 6) & 3u;
            const unsigned ext = (modrm >> 3) & 7u;
            const unsigned rm = modrm & 7u;
            if (mod != 0u || ext != 0u || rm == 4u || rm == 5u)
                continue;
            std::uint32_t value = 0;
            std::memcpy(&value, block + i + 2, sizeof(value));
            if (value > 3u)
                continue;
            const std::uintptr_t rva = kAuthCommitWindowStartRva + i;
            ++literalHits;
            Log("[BGS-SESSION-COMP144] AUTH_COMMIT_LITERAL_STORE hit=%u rva=0x%llX baseReg=%s value=%u bytes={C7 %02X %02X %02X %02X %02X} boundary_unverified=yes knownFailureState3=%s state2Candidate=%s\r\n",
                literalHits, static_cast<unsigned long long>(rva), BaseRegisterName(rm), value,
                static_cast<unsigned>(modrm), static_cast<unsigned>(block[i + 2]), static_cast<unsigned>(block[i + 3]),
                static_cast<unsigned>(block[i + 4]), static_cast<unsigned>(block[i + 5]),
                rva == kAuthFailureState3WriterRva ? "yes" : "no",
                value == 2u ? "YES" : "no");
        }

        Log("[BGS-SESSION-COMP144] AUTH_COMMIT_WINDOW complete reason=%s elapsedMs=%llu literalStateLikeStores=%u exactState2Hits=%u next=decode_final_success_commit_or_helper no_code_modified=yes\r\n",
            reason ? reason : "unknown", static_cast<unsigned long long>(elapsedMs), literalHits, exactState2Hits);
    }

    void LogCodeContext(const char* tag, std::uintptr_t rva, size_t before, size_t after) noexcept
    {
        if (!g_imageBase || rva < before)
            return;
        const std::uintptr_t startRva = rva - before;
        const size_t bytes = before + after;
        if (g_imageBase + startRva + bytes > g_imageEnd || bytes > 96)
            return;
        BYTE block[96]{};
        if (!SafeReadBytes(g_imageBase + startRva, block, bytes))
            return;
        char hex[384]{};
        BytesToHex(block, bytes, hex, ArrayCount(hex));
        Log("[BGS-SESSION-COMP144] %s rva=0x%llX contextStartRva=0x%llX bytes={%s}\r\n",
            tag ? tag : "CODE_CONTEXT",
            static_cast<unsigned long long>(rva),
            static_cast<unsigned long long>(startRva),
            hex);
    }

    void ScanAuthResultConsumers() noexcept
    {
        if (!g_imageBase || kBNetConsumerScanStartRva >= kBNetConsumerScanEndRva ||
            g_imageBase + kBNetConsumerScanEndRva > g_imageEnd)
        {
            Log("[BGS-SESSION-COMP144] AUTH_RESULT_CONSUMER_SCAN unavailable=yes\r\n");
            return;
        }

        constexpr size_t kBytes = static_cast<size_t>(kBNetConsumerScanEndRva - kBNetConsumerScanStartRva);
        BYTE block[kBytes]{};
        if (!SafeReadBytes(g_imageBase + kBNetConsumerScanStartRva, block, sizeof(block)))
        {
            Log("[BGS-SESSION-COMP144] AUTH_RESULT_CONSUMER_SCAN unreadable=yes startRva=0x%llX endRva=0x%llX\r\n",
                static_cast<unsigned long long>(kBNetConsumerScanStartRva),
                static_cast<unsigned long long>(kBNetConsumerScanEndRva));
            return;
        }

        Log("[BGS-SESSION-COMP144] AUTH_RESULT_CONSUMER_SCAN begin startRva=0x%llX endRva=0x%llX handlerEntry=0x%llX fields={0x%llX,0x%llX,0x%llX,0x%llX} mode=READ_ONLY_CLUSTER_SCAN\r\n",
            static_cast<unsigned long long>(kBNetConsumerScanStartRva),
            static_cast<unsigned long long>(kBNetConsumerScanEndRva),
            static_cast<unsigned long long>(kAuthResultHandlerEntryRva),
            static_cast<unsigned long long>(kResult1B8),
            static_cast<unsigned long long>(kResult1BC),
            static_cast<unsigned long long>(kResult1C0),
            static_cast<unsigned long long>(kResult1C8));

        unsigned handlerXrefs = 0;
        for (size_t i = 0; i + 5 <= sizeof(block); ++i)
        {
            if (block[i] != 0xE8 && block[i] != 0xE9)
                continue;
            std::int32_t rel = 0;
            std::memcpy(&rel, block + i + 1, sizeof(rel));
            const std::uintptr_t sourceRva = kBNetConsumerScanStartRva + i;
            const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                static_cast<std::intptr_t>(sourceRva + 5) + static_cast<std::intptr_t>(rel));
            if (targetRva != kAuthResultHandlerEntryRva)
                continue;
            ++handlerXrefs;
            Log("[BGS-SESSION-COMP144] AUTH_HANDLER_XREF hit=%u sourceRva=0x%llX opcode=%s targetRva=0x%llX boundary_unverified=yes\r\n",
                handlerXrefs, static_cast<unsigned long long>(sourceRva),
                block[i] == 0xE8 ? "CALL" : "JMP",
                static_cast<unsigned long long>(targetRva));
            LogCodeContext("AUTH_HANDLER_XREF_CONTEXT", sourceRva, 24, 48);
        }

        const std::uint32_t fields[] = {
            static_cast<std::uint32_t>(kResult1B8),
            static_cast<std::uint32_t>(kResult1BC),
            static_cast<std::uint32_t>(kResult1C0),
            static_cast<std::uint32_t>(kResult1C8),
        };
        const char* fieldNames[] = { "+1B8", "+1BC", "+1C0", "+1C8" };
        unsigned fieldHits[4]{};
        unsigned totalFieldHits = 0;

        for (size_t f = 0; f < ArrayCount(fields); ++f)
        {
            BYTE disp[4]{};
            std::memcpy(disp, &fields[f], sizeof(disp));
            for (size_t i = 0; i + sizeof(disp) <= sizeof(block); ++i)
            {
                if (std::memcmp(block + i, disp, sizeof(disp)) != 0)
                    continue;

                // A real [base+disp32] operand normally has a ModRM byte with
                // mod=10 immediately before the displacement, optionally after
                // a SIB byte. Requiring this removes most literal-data matches
                // while remaining decoder-free and read-only.
                bool plausibleOperand = false;
                std::uintptr_t instructionHintRva = kBNetConsumerScanStartRva + i;
                if (i >= 1)
                {
                    const BYTE modrm = block[i - 1];
                    plausibleOperand = ((modrm >> 6) & 3u) == 2u;
                    if (plausibleOperand)
                        instructionHintRva = kBNetConsumerScanStartRva + i - 1;
                }
                if (!plausibleOperand && i >= 2)
                {
                    const BYTE modrm = block[i - 2];
                    const BYTE sib = block[i - 1];
                    if (((modrm >> 6) & 3u) == 2u && (modrm & 7u) == 4u)
                    {
                        (void)sib;
                        plausibleOperand = true;
                        instructionHintRva = kBNetConsumerScanStartRva + i - 2;
                    }
                }
                if (!plausibleOperand)
                    continue;

                ++fieldHits[f];
                ++totalFieldHits;
                const std::uintptr_t dispRva = kBNetConsumerScanStartRva + i;
                const bool insideHandler = dispRva >= kAuthResultHandlerEntryRva && dispRva <= kAuthResultHandlerReturnRva;
                Log("[BGS-SESSION-COMP144] AUTH_RESULT_FIELD_XREF field=%s hit=%u dispRva=0x%llX instructionHintRva=0x%llX insideAuthHandler=%s boundary_unverified=yes\r\n",
                    fieldNames[f], fieldHits[f],
                    static_cast<unsigned long long>(dispRva),
                    static_cast<unsigned long long>(instructionHintRva),
                    insideHandler ? "yes" : "no");
                LogCodeContext("AUTH_RESULT_FIELD_XREF_CONTEXT", instructionHintRva, 16, 40);
            }
        }

        Log("[BGS-SESSION-COMP144] AUTH_RESULT_CONSUMER_SCAN complete handlerXrefs=%u fieldHits={+1B8:%u +1BC:%u +1C0:%u +1C8:%u} totalFieldHits=%u next=inspect_post_handler_consumer_for_state2 no_code_modified=yes\r\n",
            handlerXrefs, fieldHits[0], fieldHits[1], fieldHits[2], fieldHits[3], totalFieldHits);
    }

    void ScanState2SuccessCommitPath() noexcept
    {
        if (!g_imageBase || kState2SuccessWindowStartRva >= kState2SuccessWindowEndRva ||
            g_imageBase + kState2SuccessWindowEndRva > g_imageEnd)
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_PATH unavailable=yes\r\n");
            return;
        }

        constexpr size_t kWindowBytes = static_cast<size_t>(kState2SuccessWindowEndRva - kState2SuccessWindowStartRva);
        BYTE window[kWindowBytes]{};
        if (!SafeReadBytes(g_imageBase + kState2SuccessWindowStartRva, window, sizeof(window)))
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_PATH unreadable=yes startRva=0x%llX endRva=0x%llX\r\n",
                static_cast<unsigned long long>(kState2SuccessWindowStartRva),
                static_cast<unsigned long long>(kState2SuccessWindowEndRva));
            return;
        }

        BYTE writer[6]{};
        BYTE errorWriter[6]{};
        const bool writerReadable = SafeReadBytes(g_imageBase + kState2SuccessWriterRva, writer, sizeof(writer));
        const bool errorReadable = SafeReadBytes(g_imageBase + kState2SuccessErrorWriterRva, errorWriter, sizeof(errorWriter));
        const BYTE expectedWriter[6] = { 0xC7, 0x01, 0x02, 0x00, 0x00, 0x00 };
        const BYTE expectedErrorWriter[6] = { 0x89, 0x99, 0xC8, 0x01, 0x00, 0x00 };
        const bool writerMatch = writerReadable && std::memcmp(writer, expectedWriter, sizeof(writer)) == 0;
        const bool errorMatch = errorReadable && std::memcmp(errorWriter, expectedErrorWriter, sizeof(errorWriter)) == 0;

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_COMMIT_CONFIRMED writerRva=0x%llX writerMatch=%s bytes={%02X %02X %02X %02X %02X %02X} errorWriterRva=0x%llX errorMatch=%s errorDispRva=0x%llX semantics={firstState=2,errorOrStatus=EBX} read_only=yes\r\n",
            static_cast<unsigned long long>(kState2SuccessWriterRva), writerMatch ? "yes" : "no",
            static_cast<unsigned>(writer[0]), static_cast<unsigned>(writer[1]), static_cast<unsigned>(writer[2]),
            static_cast<unsigned>(writer[3]), static_cast<unsigned>(writer[4]), static_cast<unsigned>(writer[5]),
            static_cast<unsigned long long>(kState2SuccessErrorWriterRva), errorMatch ? "yes" : "no",
            static_cast<unsigned long long>(kState2SuccessErrorDispRva));

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_WINDOW begin startRva=0x%llX endRva=0x%llX writerRva=0x%llX mode=READ_ONLY_SUCCESS_COMMIT_CODE\r\n",
            static_cast<unsigned long long>(kState2SuccessWindowStartRva),
            static_cast<unsigned long long>(kState2SuccessWindowEndRva),
            static_cast<unsigned long long>(kState2SuccessWriterRva));
        for (size_t off = 0; off < sizeof(window); off += 16)
        {
            const size_t lineBytes = (sizeof(window) - off) < 16 ? (sizeof(window) - off) : 16;
            char hex[96]{};
            BytesToHex(window + off, lineBytes, hex, ArrayCount(hex));
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_CODE rva=0x%llX bytes={%s}\r\n",
                static_cast<unsigned long long>(kState2SuccessWindowStartRva + off), hex);
        }

        // Decode only simple direct control-flow encodings in a tight local
        // range around the success commit. Results are tagged boundary-unverified
        // because this intentionally stays dependency-free and read-only.
        unsigned localBranches = 0;
        unsigned localCalls = 0;
        const size_t localStart = static_cast<size_t>(kState2SuccessLocalFlowStartRva - kState2SuccessWindowStartRva);
        const size_t localEnd = static_cast<size_t>(kState2SuccessLocalFlowEndRva - kState2SuccessWindowStartRva);
        for (size_t i = localStart; i < localEnd && i < sizeof(window); ++i)
        {
            const std::uintptr_t sourceRva = kState2SuccessWindowStartRva + i;
            if (window[i] == 0xE8 && i + 5 <= sizeof(window))
            {
                std::int32_t rel = 0;
                std::memcpy(&rel, window + i + 1, sizeof(rel));
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(sourceRva + 5) + static_cast<std::intptr_t>(rel));
                ++localCalls;
                Log("[BGS-SESSION-COMP144] AUTH_STATE2_LOCAL_CALL hit=%u sourceRva=0x%llX targetRva=0x%llX beforeCommit=%s boundary_unverified=yes\r\n",
                    localCalls, static_cast<unsigned long long>(sourceRva), static_cast<unsigned long long>(targetRva),
                    sourceRva < kState2SuccessWriterRva ? "yes" : "no");
                continue;
            }
            if (window[i] == 0xE9 && i + 5 <= sizeof(window))
            {
                std::int32_t rel = 0;
                std::memcpy(&rel, window + i + 1, sizeof(rel));
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(sourceRva + 5) + static_cast<std::intptr_t>(rel));
                if (targetRva >= kState2SuccessWindowStartRva && targetRva < kState2SuccessWindowEndRva)
                {
                    ++localBranches;
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_LOCAL_BRANCH hit=%u kind=JMP_REL32 sourceRva=0x%llX targetRva=0x%llX landsBeforeOrAtCommit=%s boundary_unverified=yes\r\n",
                        localBranches, static_cast<unsigned long long>(sourceRva), static_cast<unsigned long long>(targetRva),
                        targetRva <= kState2SuccessWriterRva ? "yes" : "no");
                }
                continue;
            }
            if (window[i] >= 0x70 && window[i] <= 0x7F && i + 2 <= sizeof(window))
            {
                const std::int8_t rel = static_cast<std::int8_t>(window[i + 1]);
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(sourceRva + 2) + static_cast<std::intptr_t>(rel));
                if (targetRva >= kState2SuccessWindowStartRva && targetRva < kState2SuccessWindowEndRva)
                {
                    ++localBranches;
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_LOCAL_BRANCH hit=%u kind=JCC_REL8 cc=0x%X sourceRva=0x%llX targetRva=0x%llX nearCommit=%s boundary_unverified=yes\r\n",
                        localBranches, static_cast<unsigned>(window[i] & 0x0F),
                        static_cast<unsigned long long>(sourceRva), static_cast<unsigned long long>(targetRva),
                        (targetRva + 0x40 >= kState2SuccessWriterRva && targetRva <= kState2SuccessWriterRva + 0x40) ? "YES" : "no");
                }
                continue;
            }
            if (window[i] == 0x0F && i + 6 <= sizeof(window) && window[i + 1] >= 0x80 && window[i + 1] <= 0x8F)
            {
                std::int32_t rel = 0;
                std::memcpy(&rel, window + i + 2, sizeof(rel));
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(sourceRva + 6) + static_cast<std::intptr_t>(rel));
                if (targetRva >= kState2SuccessWindowStartRva && targetRva < kState2SuccessWindowEndRva)
                {
                    ++localBranches;
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_LOCAL_BRANCH hit=%u kind=JCC_REL32 cc=0x%X sourceRva=0x%llX targetRva=0x%llX nearCommit=%s boundary_unverified=yes\r\n",
                        localBranches, static_cast<unsigned>(window[i + 1] & 0x0F),
                        static_cast<unsigned long long>(sourceRva), static_cast<unsigned long long>(targetRva),
                        (targetRva + 0x40 >= kState2SuccessWriterRva && targetRva <= kState2SuccessWriterRva + 0x40) ? "YES" : "no");
                }
            }
        }

        constexpr size_t kClusterBytes = static_cast<size_t>(kBNetConsumerScanEndRva - kBNetConsumerScanStartRva);
        BYTE cluster[kClusterBytes]{};
        unsigned incomingHits = 0;
        if (SafeReadBytes(g_imageBase + kBNetConsumerScanStartRva, cluster, sizeof(cluster)))
        {
            for (size_t i = 0; i + 5 <= sizeof(cluster); ++i)
            {
                if (cluster[i] != 0xE8 && cluster[i] != 0xE9)
                    continue;
                const std::uintptr_t sourceRva = kBNetConsumerScanStartRva + i;
                if (sourceRva >= kState2SuccessWindowStartRva && sourceRva < kState2SuccessWindowEndRva)
                    continue;
                std::int32_t rel = 0;
                std::memcpy(&rel, cluster + i + 1, sizeof(rel));
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(sourceRva + 5) + static_cast<std::intptr_t>(rel));
                if (targetRva < kState2SuccessWindowStartRva || targetRva >= kState2SuccessWindowEndRva)
                    continue;
                ++incomingHits;
                Log("[BGS-SESSION-COMP144] AUTH_STATE2_INCOMING_XREF hit=%u sourceRva=0x%llX opcode=%s targetRva=0x%llX targetBeforeCommit=%s distanceToCommit=%lld boundary_unverified=yes\r\n",
                    incomingHits, static_cast<unsigned long long>(sourceRva), cluster[i] == 0xE8 ? "CALL" : "JMP",
                    static_cast<unsigned long long>(targetRva), targetRva <= kState2SuccessWriterRva ? "yes" : "no",
                    static_cast<long long>(static_cast<std::intptr_t>(kState2SuccessWriterRva) - static_cast<std::intptr_t>(targetRva)));
                LogCodeContext("AUTH_STATE2_INCOMING_CONTEXT", sourceRva, 24, 48);
                if (incomingHits >= 128u)
                {
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_INCOMING_XREF limit=128 reached=yes\r\n");
                    break;
                }
            }
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_PATH complete writerMatch=%s errorWriterMatch=%s localCalls=%u localBranches=%u incomingXrefs=%u next=indirect_entry_topology no_code_modified=yes\r\n",
            writerMatch ? "yes" : "no", errorMatch ? "yes" : "no", localCalls, localBranches, incomingHits);
    }

    const char* State2PointerTargetLabel(std::uintptr_t rva) noexcept
    {
        if (rva == kState2SuccessEntryRva) return "ENTRY_17C0";
        if (rva == kState2Thunk17B0Rva) return "THUNK_17B0";
        if (rva == kState2Thunk16F0Rva) return "THUNK_16F0";
        if (rva == kState2Thunk16E0Rva) return "THUNK_16E0";
        if (rva == kState2SuccessWriterRva) return "WRITER_17FF";
        return nullptr;
    }

    struct State2PointerSlot
    {
        std::uintptr_t slotRva{};
        std::uintptr_t targetRva{};
        char section[9]{};
    };

    bool MatchState2Slot(const State2PointerSlot* slots, unsigned count, std::uintptr_t slotRva, unsigned* indexOut) noexcept
    {
        for (unsigned i = 0; i < count; ++i)
        {
            if (slots[i].slotRva == slotRva)
            {
                if (indexOut) *indexOut = i;
                return true;
            }
        }
        return false;
    }

    bool IsReadableMemoryProtection(DWORD protect) noexcept
    {
        if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0)
            return false;
        const DWORD base = protect & 0xFFu;
        return base == PAGE_READONLY || base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
            base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
    }

    const char* MemoryTypeLabel(DWORD type) noexcept
    {
        if (type == MEM_IMAGE) return "IMAGE";
        if (type == MEM_MAPPED) return "MAPPED";
        if (type == MEM_PRIVATE) return "PRIVATE";
        return "OTHER";
    }

    bool RuntimeRegionAlreadySeen(const std::uintptr_t* regions, unsigned count, std::uintptr_t base) noexcept
    {
        for (unsigned i = 0; i < count; ++i)
        {
            if (regions[i] == base)
                return true;
        }
        return false;
    }

    void ScanRuntimePointerWindow(
        const char* source,
        std::uintptr_t requestedStart,
        size_t requestedBytes,
        std::uintptr_t ownerVa,
        size_t ownerOffset,
        unsigned depth,
        unsigned* hitCount) noexcept
    {
        if (!source || !requestedStart || !requestedBytes || !hitCount || *hitCount >= kState2RuntimeMaxHits)
            return;

        std::uintptr_t cursor = requestedStart;
        const std::uintptr_t requestedEnd = requestedStart + requestedBytes;
        while (cursor < requestedEnd && *hitCount < kState2RuntimeMaxHits)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
            std::uintptr_t scanStart = cursor > regionBase ? cursor : regionBase;
            std::uintptr_t scanEnd = requestedEnd < regionEnd ? requestedEnd : regionEnd;

            if (mbi.State == MEM_COMMIT && IsReadableMemoryProtection(mbi.Protect) && scanEnd > scanStart)
            {
                scanStart = (scanStart + 7u) & ~static_cast<std::uintptr_t>(7u);
                __try
                {
                    for (std::uintptr_t slot = scanStart; slot + sizeof(std::uintptr_t) <= scanEnd; slot += sizeof(std::uintptr_t))
                    {
                        std::uintptr_t value = *reinterpret_cast<const std::uintptr_t*>(slot);
                        if (value < g_imageBase || value >= g_imageEnd)
                            continue;
                        const std::uintptr_t targetRva = value - g_imageBase;
                        const char* target = State2PointerTargetLabel(targetRva);
                        if (!target)
                            continue;

                        ++(*hitCount);
                        const bool slotInImage = slot >= g_imageBase && slot < g_imageEnd;
                        Log("[BGS-SESSION-COMP144] AUTH_STATE2_RUNTIME_PTR hit=%u source=%s depth=%u ownerVa=%p ownerOffset=0x%llX slotVa=%p slotRva=%s0x%llX targetRva=0x%llX target=%s regionBase=%p regionSize=0x%llX type=%s protect=0x%08X read_only=yes\r\n",
                            *hitCount, source, depth,
                            reinterpret_cast<void*>(ownerVa), static_cast<unsigned long long>(ownerOffset),
                            reinterpret_cast<void*>(slot), slotInImage ? "" : "n/a/",
                            static_cast<unsigned long long>(slotInImage ? slot - g_imageBase : 0ull),
                            static_cast<unsigned long long>(targetRva), target,
                            mbi.BaseAddress, static_cast<unsigned long long>(mbi.RegionSize),
                            MemoryTypeLabel(mbi.Type), static_cast<unsigned>(mbi.Protect));
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_RUNTIME_PTR window_exception source=%s start=%p bytes=0x%llX partialHits=%u read_only=yes\r\n",
                        source, reinterpret_cast<void*>(requestedStart),
                        static_cast<unsigned long long>(requestedBytes), *hitCount);
                }
            }

            if (regionEnd <= cursor)
                break;
            cursor = regionEnd;
        }
    }

    void ScanState2RuntimeDispatchGraph() noexcept
    {
        unsigned hits = 0;
        std::uintptr_t seenRegions[kState2RuntimeMaxRegions]{};
        unsigned seenRegionCount = 0;
        unsigned authRefs = 0;
        unsigned followedRefs = 0;
        unsigned followedSecondLevel = 0;

        const std::uintptr_t authBase = g_imageBase + kFirstStateRva;
        BYTE authObject[kWatchBytes]{};
        const bool authReadable = SafeReadBytes(authBase, authObject, sizeof(authObject));

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_RUNTIME_GRAPH begin authBase=%p authReadable=%s globalRadius=0x%llX refWindow=0x%llX vtableWindow=0x%llX mode=READ_ONLY_BOUNDED_RUNTIME_POINTER_CORRELATION\r\n",
            reinterpret_cast<void*>(authBase), authReadable ? "yes" : "no",
            static_cast<unsigned long long>(kState2RuntimeGlobalRadius),
            static_cast<unsigned long long>(kState2RuntimeRefWindow),
            static_cast<unsigned long long>(kState2RuntimeVtableWindow));

        // First, cover the relevant slice of the huge image data section V10
        // skipped. This includes the known first-state/post-fence BNet globals.
        const std::uintptr_t imageSpan = g_imageEnd - g_imageBase;
        std::uintptr_t globalStartRva = kFirstStateRva > kState2RuntimeGlobalRadius
            ? kFirstStateRva - kState2RuntimeGlobalRadius : 0u;
        std::uintptr_t globalEndRva = kFirstStateRva + kState2RuntimeGlobalRadius;
        if (globalEndRva > imageSpan)
            globalEndRva = imageSpan;
        if (globalEndRva > globalStartRva)
        {
            ScanRuntimePointerWindow("BNET_GLOBAL_WINDOW", g_imageBase + globalStartRva,
                static_cast<size_t>(globalEndRva - globalStartRva), authBase, 0, 0, &hits);
        }

        if (authReadable)
        {
            // Scan the auth object itself, then follow only pointer-sized fields
            // that resolve to committed readable memory. This keeps V11 bounded
            // while exposing heap objects and runtime-built callback/vtable data.
            ScanRuntimePointerWindow("AUTH_OBJECT", authBase, sizeof(authObject), authBase, 0, 0, &hits);

            for (size_t off = 0; off + sizeof(std::uintptr_t) <= sizeof(authObject) && followedRefs < kState2RuntimeMaxRegions; off += sizeof(std::uintptr_t))
            {
                std::uintptr_t candidate = 0;
                std::memcpy(&candidate, authObject + off, sizeof(candidate));
                if (candidate < 0x10000u)
                    continue;

                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(reinterpret_cast<const void*>(candidate), &mbi, sizeof(mbi)) != sizeof(mbi) ||
                    mbi.State != MEM_COMMIT || !IsReadableMemoryProtection(mbi.Protect))
                {
                    continue;
                }

                ++authRefs;
                const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                if (RuntimeRegionAlreadySeen(seenRegions, seenRegionCount, regionBase))
                    continue;
                if (seenRegionCount < kState2RuntimeMaxRegions)
                    seenRegions[seenRegionCount++] = regionBase;

                const std::uintptr_t regionEnd = regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
                std::uintptr_t windowStart = candidate > kState2RuntimeRefWindow ? candidate - kState2RuntimeRefWindow : regionBase;
                if (windowStart < regionBase) windowStart = regionBase;
                std::uintptr_t windowEnd = candidate + kState2RuntimeRefWindow;
                if (windowEnd > regionEnd) windowEnd = regionEnd;
                if (windowEnd <= windowStart)
                    continue;

                ++followedRefs;
                Log("[BGS-SESSION-COMP144] AUTH_STATE2_RUNTIME_REF ref=%u authOffset=0x%llX value=%p regionBase=%p regionSize=0x%llX type=%s protect=0x%08X scanStart=%p scanBytes=0x%llX read_only=yes\r\n",
                    followedRefs, static_cast<unsigned long long>(off), reinterpret_cast<void*>(candidate),
                    mbi.BaseAddress, static_cast<unsigned long long>(mbi.RegionSize), MemoryTypeLabel(mbi.Type),
                    static_cast<unsigned>(mbi.Protect), reinterpret_cast<void*>(windowStart),
                    static_cast<unsigned long long>(windowEnd - windowStart));
                ScanRuntimePointerWindow("AUTH_REF_REGION", windowStart, static_cast<size_t>(windowEnd - windowStart), authBase, off, 1, &hits);

                // Inspect the referenced object itself for pointers to image data
                // (typically vtables/callback tables), then inspect those tables.
                const size_t objectProbeBytes = static_cast<size_t>((regionEnd - candidate) < 0x400u ? (regionEnd - candidate) : 0x400u);
                if (!objectProbeBytes)
                    continue;
                BYTE objectProbe[0x400]{};
                if (!SafeReadBytes(candidate, objectProbe, objectProbeBytes))
                    continue;

                for (size_t inner = 0; inner + sizeof(std::uintptr_t) <= objectProbeBytes && followedSecondLevel < 64u; inner += sizeof(std::uintptr_t))
                {
                    std::uintptr_t second = 0;
                    std::memcpy(&second, objectProbe + inner, sizeof(second));
                    if (second < g_imageBase || second >= g_imageEnd)
                        continue;
                    MEMORY_BASIC_INFORMATION secondMbi{};
                    if (VirtualQuery(reinterpret_cast<const void*>(second), &secondMbi, sizeof(secondMbi)) != sizeof(secondMbi) ||
                        secondMbi.State != MEM_COMMIT || !IsReadableMemoryProtection(secondMbi.Protect))
                    {
                        continue;
                    }
                    ++followedSecondLevel;
                    const std::uintptr_t secondRegionBase = reinterpret_cast<std::uintptr_t>(secondMbi.BaseAddress);
                    const std::uintptr_t secondRegionEnd = secondRegionBase + static_cast<std::uintptr_t>(secondMbi.RegionSize);
                    std::uintptr_t secondStart = second;
                    std::uintptr_t secondEnd = second + kState2RuntimeVtableWindow;
                    if (secondEnd > secondRegionEnd) secondEnd = secondRegionEnd;
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_RUNTIME_SECOND_LEVEL hit=%u authOffset=0x%llX objectOffset=0x%llX tableVa=%p tableRva=0x%llX scanBytes=0x%llX protect=0x%08X read_only=yes\r\n",
                        followedSecondLevel, static_cast<unsigned long long>(off), static_cast<unsigned long long>(inner),
                        reinterpret_cast<void*>(second), static_cast<unsigned long long>(second - g_imageBase),
                        static_cast<unsigned long long>(secondEnd > secondStart ? secondEnd - secondStart : 0u),
                        static_cast<unsigned>(secondMbi.Protect));
                    if (secondEnd > secondStart)
                    {
                        ScanRuntimePointerWindow("AUTH_SECOND_LEVEL_IMAGE_TABLE", secondStart,
                            static_cast<size_t>(secondEnd - secondStart), candidate, inner, 2, &hits);
                    }
                }
            }
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_RUNTIME_GRAPH complete authRefs=%u followedRegions=%u secondLevelTables=%u exactTargetHits=%u next=runtime_owner_dispatch no_code_modified=yes\r\n",
            authRefs, followedRefs, followedSecondLevel, hits);
    }

    struct ImageSectionView
    {
        std::uintptr_t startRva{};
        std::uintptr_t endRva{};
        DWORD characteristics{};
        char name[9]{};
    };

    bool QueryImageSection(std::uintptr_t rva, ImageSectionView* out) noexcept
    {
        if (!out || !g_imageBase || !g_imageEnd)
            return false;
        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_imageBase);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                g_imageBase + static_cast<std::uintptr_t>(dos->e_lfanew));
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            const IMAGE_SECTION_HEADER* first = IMAGE_FIRST_SECTION(nt);
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            {
                const IMAGE_SECTION_HEADER& sec = first[i];
                const std::uintptr_t start = sec.VirtualAddress;
                const std::uintptr_t size = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
                if (!size || rva < start || rva >= start + size)
                    continue;
                std::memset(out, 0, sizeof(*out));
                out->startRva = start;
                out->endRva = start + size;
                out->characteristics = sec.Characteristics;
                std::memcpy(out->name, sec.Name, 8);
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return false;
    }

    bool IsExecutableImageRva(std::uintptr_t rva) noexcept
    {
        ImageSectionView sec{};
        return QueryImageSection(rva, &sec) && (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    const char* OwnerEdgeTargetLabel(std::uintptr_t rva) noexcept
    {
        if (const char* state2 = State2PointerTargetLabel(rva))
            return state2;
        if (rva == kFirstStateGetterRva) return "FIRST_STATE_GETTER";
        if (rva == kFirstStatePumpRva) return "FIRST_STATE_PUMP";
        if (rva == kAuthResultHandlerEntryRva) return "AUTH_RESULT_HANDLER";
        if (rva == kAuthSuccessContinuationRva) return "AUTH_RESULT_SUCCESS_CONT";
        return nullptr;
    }

    bool IsState2WindowRva(std::uintptr_t rva) noexcept
    {
        return rva >= kState2SuccessWindowStartRva && rva < kState2SuccessWindowEndRva;
    }

    struct OwnerFunctionSummary
    {
        unsigned directEdges{};
        unsigned state2Edges{};
        unsigned getterCalls{};
        unsigned state2Compares{};
        unsigned bnetClusterEdges{};
    };

    OwnerFunctionSummary ScanOwnerFunctionEdges(
        const char* source,
        std::uintptr_t functionRva,
        std::uintptr_t ownerSlotRva,
        std::uintptr_t tableRva,
        unsigned tableIndex,
        unsigned depth,
        unsigned* globalEdgeLogs) noexcept
    {
        OwnerFunctionSummary summary{};
        if (!source || !IsExecutableImageRva(functionRva))
            return summary;

        ImageSectionView sec{};
        if (!QueryImageSection(functionRva, &sec))
            return summary;
        const std::uintptr_t remaining = sec.endRva > functionRva ? sec.endRva - functionRva : 0u;
        const size_t bytesToRead = static_cast<size_t>(remaining < kState2OwnerFunctionScanBytes ? remaining : kState2OwnerFunctionScanBytes);
        if (bytesToRead < 8u)
            return summary;

        BYTE code[kState2OwnerFunctionScanBytes]{};
        if (!SafeReadBytes(g_imageBase + functionRva, code, bytesToRead))
            return summary;

        size_t mostRecentGetterEnd = static_cast<size_t>(-1);
        for (size_t i = 0; i + 5 <= bytesToRead; ++i)
        {
            if (code[i] == 0xE8 || code[i] == 0xE9)
            {
                std::int32_t rel = 0;
                std::memcpy(&rel, code + i + 1, sizeof(rel));
                const std::uintptr_t sourceRva = functionRva + i;
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(sourceRva + 5) + static_cast<std::intptr_t>(rel));
                if (targetRva >= static_cast<std::uintptr_t>(g_imageEnd - g_imageBase))
                    continue;

                ++summary.directEdges;
                if (targetRva == kFirstStateGetterRva)
                {
                    ++summary.getterCalls;
                    mostRecentGetterEnd = i + 5;
                }
                if (targetRva >= kBNetConsumerScanStartRva && targetRva < kBNetConsumerScanEndRva)
                    ++summary.bnetClusterEdges;

                const char* targetLabel = OwnerEdgeTargetLabel(targetRva);
                const bool state2Target = IsState2WindowRva(targetRva);
                if (state2Target)
                    ++summary.state2Edges;

                if ((state2Target || targetLabel) && globalEdgeLogs && *globalEdgeLogs < kState2OwnerMaxEdgeLogs)
                {
                    ++(*globalEdgeLogs);
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_EDGE hit=%u source=%s depth=%u ownerSlotRva=0x%llX tableRva=0x%llX tableIndex=%u functionRva=0x%llX edgeRva=0x%llX opcode=%s targetRva=0x%llX target=%s state2Window=%s boundary_unverified=yes read_only=yes\r\n",
                        *globalEdgeLogs, source, depth,
                        static_cast<unsigned long long>(ownerSlotRva),
                        static_cast<unsigned long long>(tableRva), tableIndex,
                        static_cast<unsigned long long>(functionRva),
                        static_cast<unsigned long long>(sourceRva), code[i] == 0xE8 ? "CALL" : "JMP",
                        static_cast<unsigned long long>(targetRva),
                        targetLabel ? targetLabel : "STATE2_WINDOW", state2Target ? "yes" : "no");
                    LogCodeContext("AUTH_STATE2_OWNER_EDGE_CONTEXT", sourceRva, 24, 48);
                }
            }

            // A very common downstream consumer sequence in this build is
            // CALL first-state getter; CMP DWORD PTR [RAX],2. Recognize it so
            // V12 can distinguish a callback that waits for state 2 from the
            // missing callback that actually produces state 2.
            if (mostRecentGetterEnd != static_cast<size_t>(-1) &&
                i >= mostRecentGetterEnd && i <= mostRecentGetterEnd + 16u &&
                i + 3 <= bytesToRead && code[i] == 0x83 && code[i + 1] == 0x38 && code[i + 2] == 0x02)
            {
                ++summary.state2Compares;
                mostRecentGetterEnd = static_cast<size_t>(-1);
            }
        }
        return summary;
    }

    unsigned CountExecutableTableEntries(std::uintptr_t tableRva, unsigned maxEntries) noexcept
    {
        if (!tableRva || tableRva >= static_cast<std::uintptr_t>(g_imageEnd - g_imageBase))
            return 0;
        unsigned count = 0;
        for (unsigned i = 0; i < maxEntries; ++i)
        {
            std::uintptr_t value = 0;
            if (!SafeRead(g_imageBase + tableRva + static_cast<std::uintptr_t>(i) * sizeof(std::uintptr_t), &value))
                break;
            if (value < g_imageBase || value >= g_imageEnd)
                continue;
            if (IsExecutableImageRva(value - g_imageBase))
                ++count;
        }
        return count;
    }

    void ScanRipRefsToOwnerTarget(
        const char* label,
        std::uintptr_t targetRva,
        std::uintptr_t authOffset,
        unsigned* globalXrefLogs) noexcept
    {
        if (!label || !targetRva || !globalXrefLogs || *globalXrefLogs >= kState2OwnerMaxXrefLogs)
            return;

        unsigned readableRegions = 0;
        unsigned skippedRegions = 0;
        unsigned localHits = 0;

        IMAGE_DOS_HEADER dosCopy{};
        if (!SafeRead(g_imageBase, &dosCopy) || dosCopy.e_magic != IMAGE_DOS_SIGNATURE)
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_XREF_SCAN complete label=%s targetRva=0x%llX readableRegions=0 skippedRegions=0 localHits=0 reason=bad_dos read_only=yes\r\n",
                label, static_cast<unsigned long long>(targetRva));
            return;
        }

        IMAGE_NT_HEADERS64 ntCopy{};
        const std::uintptr_t ntVa = g_imageBase + static_cast<std::uintptr_t>(dosCopy.e_lfanew);
        if (!SafeRead(ntVa, &ntCopy) || ntCopy.Signature != IMAGE_NT_SIGNATURE)
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_XREF_SCAN complete label=%s targetRva=0x%llX readableRegions=0 skippedRegions=0 localHits=0 reason=bad_nt read_only=yes\r\n",
                label, static_cast<unsigned long long>(targetRva));
            return;
        }

        const std::uintptr_t firstSectionVa =
            ntVa + static_cast<std::uintptr_t>(offsetof(IMAGE_NT_HEADERS64, OptionalHeader)) +
            static_cast<std::uintptr_t>(ntCopy.FileHeader.SizeOfOptionalHeader);

        for (unsigned si = 0; si < ntCopy.FileHeader.NumberOfSections &&
            *globalXrefLogs < kState2OwnerMaxXrefLogs; ++si)
        {
            IMAGE_SECTION_HEADER sec{};
            if (!SafeRead(firstSectionVa + static_cast<std::uintptr_t>(si) * sizeof(sec), &sec))
                continue;
            if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                continue;

            const std::uintptr_t secRva = sec.VirtualAddress;
            const size_t secSize = static_cast<size_t>(
                sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData);
            if (!secSize || secRva >= static_cast<std::uintptr_t>(g_imageEnd - g_imageBase))
                continue;

            const std::uintptr_t rawSecStartRva = secRva;
            const std::uintptr_t rawSecEndRva = secRva + secSize;
            const std::uintptr_t boundedStartRva =
                rawSecStartRva > kBNetConsumerScanStartRva ? rawSecStartRva : kBNetConsumerScanStartRva;
            const std::uintptr_t boundedEndRva =
                rawSecEndRva < kBNetConsumerScanEndRva ? rawSecEndRva : kBNetConsumerScanEndRva;
            if (boundedEndRva <= boundedStartRva)
                continue;

            const std::uintptr_t secStartVa = g_imageBase + boundedStartRva;
            const std::uintptr_t secEndVa = g_imageBase + boundedEndRva;

            std::uintptr_t cursor = secStartVa;
            while (cursor < secEndVa && *globalXrefLogs < kState2OwnerMaxXrefLogs)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi))
                {
                    ++skippedRegions;
                    cursor += 0x1000u;
                    continue;
                }

                const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::uintptr_t regionEnd = regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
                const std::uintptr_t scanStart = cursor > regionBase ? cursor : regionBase;
                const std::uintptr_t scanEnd = secEndVa < regionEnd ? secEndVa : regionEnd;

                if (mbi.State != MEM_COMMIT || !IsReadableMemoryProtection(mbi.Protect) || scanEnd <= scanStart)
                {
                    ++skippedRegions;
                    cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
                    continue;
                }

                ++readableRegions;
                __try
                {
                    const BYTE* code = reinterpret_cast<const BYTE*>(scanStart);
                    const size_t scanBytes = static_cast<size_t>(scanEnd - scanStart);
                    for (size_t i = 0; i + 10 <= scanBytes &&
                        *globalXrefLogs < kState2OwnerMaxXrefLogs; ++i)
                    {
                        size_t prefix = (code[i] >= 0x40 && code[i] <= 0x4F) ? 1u : 0u;
                        const size_t op = i + prefix;
                        const char* kind = nullptr;
                        size_t length = 0;
                        size_t dispOff = 0;

                        if (op + 6 <= scanBytes && (code[op] == 0x8B || code[op] == 0x8D || code[op] == 0x89))
                        {
                            const BYTE modrm = code[op + 1];
                            if (((modrm >> 6) & 3u) == 0u && (modrm & 7u) == 5u)
                            {
                                kind = code[op] == 0x8B ? "MOV_RIP_READ" :
                                    (code[op] == 0x8D ? "LEA_RIP" : "MOV_RIP_WRITE");
                                dispOff = op + 2;
                                length = prefix + 6;
                            }
                        }
                        else if (prefix == 0 && op + 6 <= scanBytes && code[op] == 0xFF &&
                            (code[op + 1] == 0x15 || code[op + 1] == 0x25))
                        {
                            kind = code[op + 1] == 0x15 ? "CALL_PTR_RIP" : "JMP_PTR_RIP";
                            dispOff = op + 2;
                            length = 6;
                        }
                        else if (op + 10 <= scanBytes && code[op] == 0xC7 && code[op + 1] == 0x05)
                        {
                            kind = "MOV_RIP_IMM32";
                            dispOff = op + 2;
                            length = prefix + 10;
                        }

                        if (!kind)
                            continue;

                        std::int32_t disp = 0;
                        std::memcpy(&disp, code + dispOff, sizeof(disp));
                        const std::uintptr_t instructionVa = scanStart + i;
                        const std::uintptr_t instructionRva = instructionVa - g_imageBase;
                        const std::uintptr_t resolvedRva = static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(instructionRva + length) +
                            static_cast<std::intptr_t>(disp));
                        if (resolvedRva != targetRva)
                            continue;

                        ++(*globalXrefLogs);
                        ++localHits;
                        Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_XREF hit=%u label=%s authOffset=0x%llX kind=%s instructionRva=0x%llX targetRva=0x%llX pageProtect=0x%08X boundary_unverified=yes read_only=yes\r\n",
                            *globalXrefLogs, label, static_cast<unsigned long long>(authOffset), kind,
                            static_cast<unsigned long long>(instructionRva),
                            static_cast<unsigned long long>(targetRva),
                            static_cast<unsigned>(mbi.Protect));
                        LogCodeContext("AUTH_STATE2_OWNER_XREF_CONTEXT", instructionRva, 24, 48);
                        // Do not reinterpret the interior bytes of the same
                        // instruction (e.g. the 0x48 REX-prefixed LEA at
                        // 0x46416E0) as a second overlapping xref.
                        if (length > 1u)
                            i += length - 1u;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    ++skippedRegions;
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_XREF_REGION_FAULT label=%s regionBase=%p regionSize=0x%llX protect=0x%08X continuing=yes read_only=yes\r\n",
                        label, mbi.BaseAddress, static_cast<unsigned long long>(mbi.RegionSize),
                        static_cast<unsigned>(mbi.Protect));
                }

                cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
            }
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_XREF_SCAN complete label=%s authOffset=0x%llX targetRva=0x%llX readableRegions=%u skippedRegions=%u localHits=%u totalXrefLogs=%u read_only=yes\r\n",
            label, static_cast<unsigned long long>(authOffset),
            static_cast<unsigned long long>(targetRva), readableRegions, skippedRegions,
            localHits, *globalXrefLogs);
    }


    const char* State2AccessorLabel(std::uintptr_t rva) noexcept
    {
        if (rva == kState2Thunk16E0Rva) return "ADDR_AUTH_PLUS_A8";
        if (rva == kState2Thunk16F0Rva) return "LOAD_AUTH_PLUS_F0";
        if (rva == kState2Thunk17B0Rva) return "ADDR_AUTH_PLUS_118";
        if (rva == kState2Thunk16E0AliasRva) return "ALIAS_TO_ADDR_AUTH_PLUS_A8";
        return nullptr;
    }

    std::uintptr_t State2AccessorAuthOffset(std::uintptr_t rva) noexcept
    {
        if (rva == kState2Thunk16E0Rva || rva == kState2Thunk16E0AliasRva) return 0xA8u;
        if (rva == kState2Thunk16F0Rva) return 0xF0u;
        if (rva == kState2Thunk17B0Rva) return 0x118u;
        return 0;
    }

    bool IsState2AccessorAddressGetter(std::uintptr_t rva) noexcept
    {
        return rva == kState2Thunk16E0Rva || rva == kState2Thunk16E0AliasRva ||
            rva == kState2Thunk17B0Rva;
    }

    struct RuntimeFunctionBounds
    {
        std::uintptr_t beginRva = 0;
        std::uintptr_t endRva = 0;
        bool fromUnwind = false;
    };

    bool QueryRuntimeFunctionBounds(std::uintptr_t instructionRva, RuntimeFunctionBounds* out) noexcept
    {
        if (!out || !g_imageBase)
            return false;

        using RtlLookupFunctionEntryFn = PRUNTIME_FUNCTION (WINAPI*)(DWORD64, PDWORD64, PVOID);
        static RtlLookupFunctionEntryFn lookup = []() noexcept -> RtlLookupFunctionEntryFn
        {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll)
                return nullptr;
            return reinterpret_cast<RtlLookupFunctionEntryFn>(
                GetProcAddress(ntdll, "RtlLookupFunctionEntry"));
        }();

        if (!lookup)
            return false;

        DWORD64 functionImageBase = 0;
        PRUNTIME_FUNCTION runtimeFunction = lookup(
            static_cast<DWORD64>(g_imageBase + instructionRva),
            &functionImageBase,
            nullptr);
        if (!runtimeFunction || !functionImageBase)
            return false;

        const std::uintptr_t beginVa = static_cast<std::uintptr_t>(functionImageBase) + runtimeFunction->BeginAddress;
        const std::uintptr_t endVa = static_cast<std::uintptr_t>(functionImageBase) + runtimeFunction->EndAddress;
        const std::uintptr_t instructionVa = g_imageBase + instructionRva;
        if (beginVa > instructionVa || endVa <= instructionVa || beginVa < g_imageBase || endVa <= g_imageBase)
            return false;

        out->beginRva = beginVa - g_imageBase;
        out->endRva = endVa - g_imageBase;
        out->fromUnwind = true;
        return out->endRva > out->beginRva;
    }

    // ---------------------------------------------------------------------
    // V17: exact SessionService method-1 virtual callback capture.
    // ---------------------------------------------------------------------
    // The accepted method-1 response reaches 0x6BF4AE and then executes:
    //   MOV RAX,[RDI]
    //   ...
    //   MOV RCX,RDI
    //   CALL QWORD PTR [RAX+8]     ; 0x6BF4E3
    //   NOP                        ; 0x6BF4E6
    //
    // A one-shot INT3 at the verified CALL byte is the smallest reliable way
    // to recover the live vtable slot target. The stock byte is restored before
    // the original instruction is re-executed. A second one-shot breakpoint at
    // the post-call NOP records the return value and state after the callback.
    constexpr BYTE kSessionVCallExpected[3] = { 0xFF, 0x50, 0x08 };
    constexpr BYTE kSessionPostExpected = 0x90;
    constexpr unsigned kSessionCaptureStackQwords = 24u;
    constexpr unsigned kSessionCaptureVtableSlots = 12u;

    struct SessionMethod1VCallCapture
    {
        std::uintptr_t preRip{};
        std::uintptr_t object{};
        std::uintptr_t vtable{};
        std::uintptr_t callbackVa{};
        std::uintptr_t callbackRva{};
        std::uintptr_t r14{};
        std::uintptr_t rdx{};
        std::uintptr_t r8{};
        std::uintptr_t r9{};
        std::uintptr_t rsp{};
        std::uintptr_t preStack[kSessionCaptureStackQwords]{};
        BYTE preObject[kSessionMethod1ObjectSnapshotBytes]{};
        BYTE preRdxArg[kSessionMethod1ArgSnapshotBytes]{};
        BYTE preR8Arg[kSessionMethod1ArgSnapshotBytes]{};
        bool preObjectReadable{};
        bool preRdxReadable{};
        bool preR8Readable{};

        // V19 second-level dispatch resolved from the 0x6C0B20 forwarding
        // thunk. If the low tag bit is clear, object+0x8 is the embedded
        // interface object itself. If set, the qword at object+0x8 is an
        // external interface pointer tagged in bit 0.
        std::uintptr_t forwardStorage{};
        std::uintptr_t forwardRaw{};
        bool forwardTagged{};
        std::uintptr_t forwardObject{};
        std::uintptr_t forwardVtable{};
        std::uintptr_t forwardVtableRva{};
        std::uintptr_t forwardTargetVa{};
        std::uintptr_t forwardTargetRva{};
        // V20: 0x4641710 dispatches through these fields of the embedded
        // interface: function pointer at +0x08 and context at +0x18.
        std::uintptr_t invokeTargetVa{};
        std::uintptr_t invokeTargetRva{};
        std::uintptr_t invokeContextVa{};
        std::uintptr_t companionCodeVa{};
        std::uintptr_t companionCodeRva{};
        std::uintptr_t linkedStateVa{};
        BYTE preForwardObject[kSessionMethod1ForwardSnapshotBytes]{};
        BYTE preLinkedState[kSessionMethod1LinkedStateSnapshotBytes]{};
        bool preForwardReadable{};
        bool preLinkedStateReadable{};

        std::uintptr_t postRip{};
        std::uintptr_t postRax{};
        std::uintptr_t postRcx{};
        std::uintptr_t postRdx{};
        std::uintptr_t postR8{};
        std::uintptr_t postR9{};
        std::uintptr_t postRsp{};
        std::uintptr_t postStack[kSessionCaptureStackQwords]{};
        BYTE postObject[kSessionMethod1ObjectSnapshotBytes]{};
        BYTE postRdxArg[kSessionMethod1ArgSnapshotBytes]{};
        BYTE postR8Arg[kSessionMethod1ArgSnapshotBytes]{};
        BYTE postForwardObject[kSessionMethod1ForwardSnapshotBytes]{};
        BYTE postLinkedState[kSessionMethod1LinkedStateSnapshotBytes]{};
        bool postObjectReadable{};
        bool postRdxReadable{};
        bool postR8Readable{};
        bool postForwardReadable{};
        bool postLinkedStateReadable{};

        std::uint32_t stateAtPre{};
        std::uint32_t stateAtPost{};
    };

    SessionMethod1VCallCapture g_sessionVCallCapture{};
    PVOID g_sessionVCallVeh = nullptr;
    volatile LONG g_sessionPreArmed = 0;
    volatile LONG g_sessionPostArmed = 0;
    volatile LONG g_sessionPreCaptured = 0;
    volatile LONG g_sessionPostCaptured = 0;
    volatile LONG g_sessionPreLogged = 0;
    volatile LONG g_sessionPostLogged = 0;
    BYTE g_sessionPreOriginal = 0;
    BYTE g_sessionPostOriginal = 0;

    bool RawPatchByte(std::uintptr_t va, BYTE replacement, BYTE* oldByteOut = nullptr) noexcept
    {
        if (!va)
            return false;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(va), 1, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        bool ok = false;
        __try
        {
            BYTE* p = reinterpret_cast<BYTE*>(va);
            if (oldByteOut)
                *oldByteOut = *p;
            *p = replacement;
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(va), 1);
            ok = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ok = false;
        }

        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(va), 1, oldProtect, &ignored);
        return ok;
    }

    bool RestoreSessionBreakpoint(std::uintptr_t rva, BYTE original, volatile LONG* armed) noexcept
    {
        if (!armed)
            return false;
        if (InterlockedCompareExchange(armed, 0, 1) != 1)
            return true;
        return RawPatchByte(g_imageBase + rva, original, nullptr);
    }

    void CaptureStackQwords(std::uintptr_t rsp, std::uintptr_t* out, unsigned count) noexcept
    {
        if (!rsp || !out || !count)
            return;
        for (unsigned i = 0; i < count; ++i)
            SafeRead(rsp + static_cast<std::uintptr_t>(i) * sizeof(std::uintptr_t), &out[i]);
    }

    void LogCapturedStack(const char* label, const std::uintptr_t* stack, unsigned count) noexcept;

    // V22: capture the live auth-result bit-7 gate and, if the absent path
    // executes, the helper call immediately before/after 0x4641A60.
    constexpr BYTE kAuthFlag7GateExpected[3] = { 0x8B, 0x46, 0x10 };
    constexpr BYTE kAuthFlag7AbsentCallExpected[5] = { 0xE8, 0x73, 0xED, 0xFF, 0xFF };
    constexpr BYTE kAuthFlag7AbsentReturnExpected = 0xEB;

    struct AuthFlag7FlowCapture
    {
        std::uintptr_t response{};
        std::uintptr_t stateObject{};
        std::uintptr_t gateRsp{};
        std::uintptr_t gateStack[kAuthFlag7StackQwords]{};
        std::uint32_t stateAtGate{};
        std::uint32_t flags10{};
        std::uint32_t requiredField28{};
        std::uint32_t errorCode38{};
        std::uintptr_t ptr60{};
        std::uintptr_t ptr68{};
        BYTE responseBytes[kAuthFlag7ResponseSnapshotBytes]{};
        bool responseReadable{};

        std::uintptr_t helperPreRcx{};
        std::uintptr_t helperPreRdx{};
        std::uintptr_t helperPreRsi{};
        std::uintptr_t helperPreRdi{};
        std::uintptr_t helperPreRsp{};
        std::uintptr_t helperPreStack[kAuthFlag7StackQwords]{};
        std::uint32_t stateAtHelperPre{};
        std::uintptr_t helperPayloadQword0{};
        std::uintptr_t helperPayloadQword8{};

        std::uintptr_t helperPostRax{};
        std::uintptr_t helperPostRcx{};
        std::uintptr_t helperPostRdx{};
        std::uintptr_t helperPostRsi{};
        std::uintptr_t helperPostRdi{};
        std::uintptr_t helperPostRsp{};
        std::uint32_t stateAtHelperPost{};
    };

    AuthFlag7FlowCapture g_authFlag7Capture{};
    PVOID g_authFlag7Veh = nullptr;
    volatile LONG g_authFlag7GateArmed = 0;
    volatile LONG g_authFlag7CallArmed = 0;
    volatile LONG g_authFlag7ReturnArmed = 0;
    volatile LONG g_authFlag7GateCaptured = 0;
    volatile LONG g_authFlag7CallCaptured = 0;
    volatile LONG g_authFlag7ReturnCaptured = 0;
    volatile LONG g_authFlag7GateLogged = 0;
    volatile LONG g_authFlag7CallLogged = 0;
    volatile LONG g_authFlag7ReturnLogged = 0;
    BYTE g_authFlag7GateOriginal = 0;
    BYTE g_authFlag7CallOriginal = 0;
    BYTE g_authFlag7ReturnOriginal = 0;

    LONG CALLBACK AuthFlag7FlowVeh(PEXCEPTION_POINTERS ep) noexcept
    {
        if (!ep || !ep->ExceptionRecord || !ep->ContextRecord ||
            ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT || !g_imageBase)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        const std::uintptr_t exceptionVa =
            reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
        CONTEXT* c = ep->ContextRecord;
        const std::uintptr_t gateVa = g_imageBase + kAuthFlag7GateRva;
        const std::uintptr_t callVa = g_imageBase + kAuthFlag7AbsentCallRva;
        const std::uintptr_t returnVa = g_imageBase + kAuthFlag7AbsentReturnRva;

        if (exceptionVa == gateVa &&
            InterlockedCompareExchange(&g_authFlag7GateArmed, 0, 1) == 1)
        {
            RawPatchByte(gateVa, g_authFlag7GateOriginal, nullptr);

            g_authFlag7Capture.response = static_cast<std::uintptr_t>(c->Rsi);
            g_authFlag7Capture.stateObject = static_cast<std::uintptr_t>(c->Rdi);
            g_authFlag7Capture.gateRsp = static_cast<std::uintptr_t>(c->Rsp);
            SafeRead(g_imageBase + kFirstStateRva, &g_authFlag7Capture.stateAtGate);
            SafeRead(g_authFlag7Capture.response + 0x10u, &g_authFlag7Capture.flags10);
            SafeRead(g_authFlag7Capture.response + 0x28u, &g_authFlag7Capture.requiredField28);
            SafeRead(g_authFlag7Capture.response + 0x38u, &g_authFlag7Capture.errorCode38);
            SafeRead(g_authFlag7Capture.response + 0x60u, &g_authFlag7Capture.ptr60);
            SafeRead(g_authFlag7Capture.response + 0x68u, &g_authFlag7Capture.ptr68);
            g_authFlag7Capture.responseReadable = SafeReadBytes(
                g_authFlag7Capture.response,
                g_authFlag7Capture.responseBytes,
                sizeof(g_authFlag7Capture.responseBytes));
            CaptureStackQwords(g_authFlag7Capture.gateRsp,
                g_authFlag7Capture.gateStack, kAuthFlag7StackQwords);
            InterlockedExchange(&g_authFlag7GateCaptured, 1);

            c->Rip = static_cast<DWORD64>(gateVa);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (exceptionVa == callVa &&
            InterlockedCompareExchange(&g_authFlag7CallArmed, 0, 1) == 1)
        {
            RawPatchByte(callVa, g_authFlag7CallOriginal, nullptr);

            g_authFlag7Capture.helperPreRcx = static_cast<std::uintptr_t>(c->Rcx);
            g_authFlag7Capture.helperPreRdx = static_cast<std::uintptr_t>(c->Rdx);
            g_authFlag7Capture.helperPreRsi = static_cast<std::uintptr_t>(c->Rsi);
            g_authFlag7Capture.helperPreRdi = static_cast<std::uintptr_t>(c->Rdi);
            g_authFlag7Capture.helperPreRsp = static_cast<std::uintptr_t>(c->Rsp);
            SafeRead(g_imageBase + kFirstStateRva, &g_authFlag7Capture.stateAtHelperPre);
            SafeRead(g_authFlag7Capture.helperPreRdx, &g_authFlag7Capture.helperPayloadQword0);
            SafeRead(g_authFlag7Capture.helperPreRdx + sizeof(std::uintptr_t),
                &g_authFlag7Capture.helperPayloadQword8);
            CaptureStackQwords(g_authFlag7Capture.helperPreRsp,
                g_authFlag7Capture.helperPreStack, kAuthFlag7StackQwords);

            BYTE postByte = 0;
            if (SafeRead(returnVa, &postByte) && postByte == kAuthFlag7AbsentReturnExpected)
            {
                g_authFlag7ReturnOriginal = postByte;
                InterlockedExchange(&g_authFlag7ReturnArmed, 1);
                if (!RawPatchByte(returnVa, 0xCC, nullptr))
                    InterlockedExchange(&g_authFlag7ReturnArmed, 0);
            }

            InterlockedExchange(&g_authFlag7CallCaptured, 1);
            c->Rip = static_cast<DWORD64>(callVa);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (exceptionVa == returnVa &&
            InterlockedCompareExchange(&g_authFlag7ReturnArmed, 0, 1) == 1)
        {
            RawPatchByte(returnVa, g_authFlag7ReturnOriginal, nullptr);

            g_authFlag7Capture.helperPostRax = static_cast<std::uintptr_t>(c->Rax);
            g_authFlag7Capture.helperPostRcx = static_cast<std::uintptr_t>(c->Rcx);
            g_authFlag7Capture.helperPostRdx = static_cast<std::uintptr_t>(c->Rdx);
            g_authFlag7Capture.helperPostRsi = static_cast<std::uintptr_t>(c->Rsi);
            g_authFlag7Capture.helperPostRdi = static_cast<std::uintptr_t>(c->Rdi);
            g_authFlag7Capture.helperPostRsp = static_cast<std::uintptr_t>(c->Rsp);
            SafeRead(g_imageBase + kFirstStateRva, &g_authFlag7Capture.stateAtHelperPost);
            InterlockedExchange(&g_authFlag7ReturnCaptured, 1);

            c->Rip = static_cast<DWORD64>(returnVa);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool ArmAuthFlag7FlowCapture() noexcept
    {
        // Scanner/redirect-only mode: never place INT3 breakpoints in stock IW8
        // code. The former one-shot observer could resume on a rewritten/protected
        // instruction boundary and produce 0xC000001D (illegal instruction).
        Log("[BGS-SESSION-COMP144] AUTH_FLAG7_FLOW DISABLED reason=scanner_redirect_only int3=off veh=off executableWrites=off stateWrites=off\r\n");
        return false;
    }

    void DisarmAuthFlag7FlowCapture() noexcept
    {
        RestoreSessionBreakpoint(kAuthFlag7GateRva,
            g_authFlag7GateOriginal, &g_authFlag7GateArmed);
        RestoreSessionBreakpoint(kAuthFlag7AbsentCallRva,
            g_authFlag7CallOriginal, &g_authFlag7CallArmed);
        RestoreSessionBreakpoint(kAuthFlag7AbsentReturnRva,
            g_authFlag7ReturnOriginal, &g_authFlag7ReturnArmed);
        if (g_authFlag7Veh)
        {
            RemoveVectoredExceptionHandler(g_authFlag7Veh);
            g_authFlag7Veh = nullptr;
        }
    }

    void LogAuthFlag7FlowCaptureIfReady() noexcept
    {
        const std::uintptr_t expectedState = g_imageBase + kFirstStateRva;

        if (InterlockedCompareExchange(&g_authFlag7GateCaptured, 0, 0) &&
            InterlockedCompareExchange(&g_authFlag7GateLogged, 1, 0) == 0)
        {
            const bool bit7 = (g_authFlag7Capture.flags10 & 0x80u) != 0u;
            Log("[BGS-SESSION-COMP144] AUTH_FLAG7_GATE HIT gateRva=0x%llX stateAtHit=%u response=%p stateObject=%p expectedState=%p stateObjectMatch=%s flags10=0x%08X bit7=%u expectedPath=%s requiredField28=0x%08X errorCode38=0x%08X ptr60=%p ptr68=%p responseReadable=%s stockByteRestored=yes\r\n",
                static_cast<unsigned long long>(kAuthFlag7GateRva),
                static_cast<unsigned>(g_authFlag7Capture.stateAtGate),
                reinterpret_cast<void*>(g_authFlag7Capture.response),
                reinterpret_cast<void*>(g_authFlag7Capture.stateObject),
                reinterpret_cast<void*>(expectedState),
                g_authFlag7Capture.stateObject == expectedState ? "YES" : "no",
                static_cast<unsigned>(g_authFlag7Capture.flags10),
                bit7 ? 1u : 0u,
                bit7 ? "BIT7_PRESENT_FALLTHROUGH" : "BIT7_ABSENT_HELPER",
                static_cast<unsigned>(g_authFlag7Capture.requiredField28),
                static_cast<unsigned>(g_authFlag7Capture.errorCode38),
                reinterpret_cast<void*>(g_authFlag7Capture.ptr60),
                reinterpret_cast<void*>(g_authFlag7Capture.ptr68),
                g_authFlag7Capture.responseReadable ? "yes" : "no");

            LogCapturedStack("AUTH_FLAG7_GATE_STACK",
                g_authFlag7Capture.gateStack, kAuthFlag7StackQwords);

            if (g_authFlag7Capture.responseReadable)
            {
                for (size_t off = 0; off < sizeof(g_authFlag7Capture.responseBytes); off += 32u)
                {
                    char hex[160]{};
                    BytesToHex(g_authFlag7Capture.responseBytes + off, 32u,
                        hex, ArrayCount(hex));
                    Log("[BGS-SESSION-COMP144] AUTH_FLAG7_RESPONSE offset=+0x%02llX bytes={%s}\r\n",
                        static_cast<unsigned long long>(off), hex);
                }
            }
        }

        if (InterlockedCompareExchange(&g_authFlag7CallCaptured, 0, 0) &&
            InterlockedCompareExchange(&g_authFlag7CallLogged, 1, 0) == 0)
        {
            Log("[BGS-SESSION-COMP144] AUTH_FLAG7_ABSENT_HELPER PRE callRva=0x%llX stateBefore=%u rcx=%p rdx=%p rsi=%p rdi=%p rcxMatchesState=%s rdiMatchesState=%s rdxMatchesResponsePlus68=%s payloadQword0=%p payloadQword8=%p\r\n",
                static_cast<unsigned long long>(kAuthFlag7AbsentCallRva),
                static_cast<unsigned>(g_authFlag7Capture.stateAtHelperPre),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPreRcx),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPreRdx),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPreRsi),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPreRdi),
                g_authFlag7Capture.helperPreRcx == expectedState ? "YES" : "no",
                g_authFlag7Capture.helperPreRdi == expectedState ? "YES" : "no",
                g_authFlag7Capture.helperPreRdx == g_authFlag7Capture.ptr68 ? "YES" : "no",
                reinterpret_cast<void*>(g_authFlag7Capture.helperPayloadQword0),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPayloadQword8));
            LogCapturedStack("AUTH_FLAG7_ABSENT_HELPER_STACK",
                g_authFlag7Capture.helperPreStack, kAuthFlag7StackQwords);
        }

        if (InterlockedCompareExchange(&g_authFlag7ReturnCaptured, 0, 0) &&
            InterlockedCompareExchange(&g_authFlag7ReturnLogged, 1, 0) == 0)
        {
            Log("[BGS-SESSION-COMP144] AUTH_FLAG7_ABSENT_HELPER POST returnRva=0x%llX stateBefore=%u stateAfter=%u changed=%s rax=%p rcx=%p rdx=%p rsi=%p rdi=%p stockJumpRestored=yes\r\n",
                static_cast<unsigned long long>(kAuthFlag7AbsentReturnRva),
                static_cast<unsigned>(g_authFlag7Capture.stateAtHelperPre),
                static_cast<unsigned>(g_authFlag7Capture.stateAtHelperPost),
                g_authFlag7Capture.stateAtHelperPre != g_authFlag7Capture.stateAtHelperPost ? "YES" : "no",
                reinterpret_cast<void*>(g_authFlag7Capture.helperPostRax),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPostRcx),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPostRdx),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPostRsi),
                reinterpret_cast<void*>(g_authFlag7Capture.helperPostRdi));
        }
    }

    // V21: capture the exact moment the registration owner takes the address
    // of the default invoke stub. This breakpoint is armed before waiting for
    // firstState=1 because delegate construction can happen during startup.
    constexpr BYTE kSessionInstallerExpected[7] =
        { 0x48, 0x8D, 0x05, 0xF3, 0x00, 0x00, 0x00 };

    struct SessionMethod1InstallerCapture
    {
        std::uintptr_t rip{};
        std::uintptr_t rax{};
        std::uintptr_t rbx{};
        std::uintptr_t rcx{};
        std::uintptr_t rdx{};
        std::uintptr_t rsi{};
        std::uintptr_t rdi{};
        std::uintptr_t rbp{};
        std::uintptr_t rsp{};
        std::uintptr_t r8{};
        std::uintptr_t r9{};
        std::uintptr_t stack[kSessionMethod1InstallerStackQwords]{};
        std::uintptr_t frameStart{};
        BYTE frame[kSessionMethod1InstallerFrameBytes]{};
        bool frameReadable{};
        std::uintptr_t rdi0{};
        std::uintptr_t rdi8{};
        std::uintptr_t rsi0{};
        std::uint32_t stateAtHit{};
    };

    SessionMethod1InstallerCapture g_sessionInstallerCapture{};
    PVOID g_sessionInstallerVeh = nullptr;
    volatile LONG g_sessionInstallerArmed = 0;
    volatile LONG g_sessionInstallerCaptured = 0;
    volatile LONG g_sessionInstallerLogged = 0;
    BYTE g_sessionInstallerOriginal = 0;

    LONG CALLBACK SessionMethod1InstallerVeh(PEXCEPTION_POINTERS ep) noexcept
    {
        if (!ep || !ep->ExceptionRecord || !ep->ContextRecord ||
            ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT || !g_imageBase)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        const std::uintptr_t exceptionVa =
            reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
        const std::uintptr_t installVa =
            g_imageBase + kSessionMethod1DefaultInvokeAddressLoadRva;
        if (exceptionVa != installVa ||
            InterlockedCompareExchange(&g_sessionInstallerArmed, 0, 1) != 1)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        RawPatchByte(installVa, g_sessionInstallerOriginal, nullptr);

        CONTEXT* c = ep->ContextRecord;
        g_sessionInstallerCapture.rip = installVa;
        g_sessionInstallerCapture.rax = static_cast<std::uintptr_t>(c->Rax);
        g_sessionInstallerCapture.rbx = static_cast<std::uintptr_t>(c->Rbx);
        g_sessionInstallerCapture.rcx = static_cast<std::uintptr_t>(c->Rcx);
        g_sessionInstallerCapture.rdx = static_cast<std::uintptr_t>(c->Rdx);
        g_sessionInstallerCapture.rsi = static_cast<std::uintptr_t>(c->Rsi);
        g_sessionInstallerCapture.rdi = static_cast<std::uintptr_t>(c->Rdi);
        g_sessionInstallerCapture.rbp = static_cast<std::uintptr_t>(c->Rbp);
        g_sessionInstallerCapture.rsp = static_cast<std::uintptr_t>(c->Rsp);
        g_sessionInstallerCapture.r8 = static_cast<std::uintptr_t>(c->R8);
        g_sessionInstallerCapture.r9 = static_cast<std::uintptr_t>(c->R9);
        SafeRead(g_imageBase + kFirstStateRva, &g_sessionInstallerCapture.stateAtHit);
        CaptureStackQwords(g_sessionInstallerCapture.rsp,
            g_sessionInstallerCapture.stack, kSessionMethod1InstallerStackQwords);

        if (g_sessionInstallerCapture.rbp >= 0x80u)
        {
            g_sessionInstallerCapture.frameStart = g_sessionInstallerCapture.rbp - 0x80u;
            g_sessionInstallerCapture.frameReadable = SafeReadBytes(
                g_sessionInstallerCapture.frameStart,
                g_sessionInstallerCapture.frame,
                sizeof(g_sessionInstallerCapture.frame));
        }

        SafeRead(g_sessionInstallerCapture.rdi, &g_sessionInstallerCapture.rdi0);
        SafeRead(g_sessionInstallerCapture.rdi + sizeof(std::uintptr_t),
            &g_sessionInstallerCapture.rdi8);
        SafeRead(g_sessionInstallerCapture.rsi, &g_sessionInstallerCapture.rsi0);

        InterlockedExchange(&g_sessionInstallerCaptured, 1);

        // Re-execute the original seven-byte LEA after restoring byte 0.
        c->Rip = static_cast<DWORD64>(installVa);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    bool ArmSessionMethod1InstallerCapture() noexcept
    {
        BYTE code[sizeof(kSessionInstallerExpected)]{};
        if (!SafeReadBytes(g_imageBase + kSessionMethod1DefaultInvokeAddressLoadRva,
                code, sizeof(code)) ||
            std::memcmp(code, kSessionInstallerExpected, sizeof(code)) != 0)
        {
            char hex[64]{};
            BytesToHex(code, sizeof(code), hex, ArrayCount(hex));
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER ARM_FAILED rva=0x%llX bytes={%s} expected={48 8D 05 F3 00 00 00} no_state_modified=yes\r\n",
                static_cast<unsigned long long>(kSessionMethod1DefaultInvokeAddressLoadRva),
                hex);
            return false;
        }

        if (!g_sessionInstallerVeh)
            g_sessionInstallerVeh = AddVectoredExceptionHandler(1, SessionMethod1InstallerVeh);
        if (!g_sessionInstallerVeh)
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER ARM_FAILED veh=no no_state_modified=yes\r\n");
            return false;
        }

        g_sessionInstallerOriginal = code[0];
        InterlockedExchange(&g_sessionInstallerArmed, 1);
        if (!RawPatchByte(g_imageBase + kSessionMethod1DefaultInvokeAddressLoadRva, 0xCC, nullptr))
        {
            InterlockedExchange(&g_sessionInstallerArmed, 0);
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER ARM_FAILED patch=no no_state_modified=yes\r\n");
            return false;
        }

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER ARMED functionRva=0x%llX loadRva=0x%llX verified={48 8D 05 F3 00 00 00} mode=ONE_SHOT_PRE_STATE1 stateWrites=off\r\n",
            static_cast<unsigned long long>(kSessionMethod1DelegateInstallerFunctionRva),
            static_cast<unsigned long long>(kSessionMethod1DefaultInvokeAddressLoadRva));
        return true;
    }

    void DisarmSessionMethod1InstallerCapture() noexcept
    {
        RestoreSessionBreakpoint(kSessionMethod1DefaultInvokeAddressLoadRva,
            g_sessionInstallerOriginal, &g_sessionInstallerArmed);
        if (g_sessionInstallerVeh)
        {
            RemoveVectoredExceptionHandler(g_sessionInstallerVeh);
            g_sessionInstallerVeh = nullptr;
        }
    }

    void ResolveSessionMethod1ForwardDispatch() noexcept
    {
        g_sessionVCallCapture.forwardStorage =
            g_sessionVCallCapture.object + kSessionMethod1EmbeddedInterfaceOffset;

        std::uintptr_t raw = 0;
        if (!SafeRead(g_sessionVCallCapture.forwardStorage, &raw))
            return;

        g_sessionVCallCapture.forwardRaw = raw;
        g_sessionVCallCapture.forwardTagged = (raw & 1u) != 0u;
        g_sessionVCallCapture.forwardObject =
            g_sessionVCallCapture.forwardTagged
                ? (raw & ~static_cast<std::uintptr_t>(1u))
                : g_sessionVCallCapture.forwardStorage;

        std::uintptr_t vtable = 0;
        if (SafeRead(g_sessionVCallCapture.forwardObject, &vtable))
        {
            g_sessionVCallCapture.forwardVtable = vtable;
            if (vtable >= g_imageBase && vtable < g_imageEnd)
                g_sessionVCallCapture.forwardVtableRva = vtable - g_imageBase;

            std::uintptr_t target = 0;
            if (SafeRead(vtable + kSessionCallbackVtableSlotOffset, &target))
            {
                g_sessionVCallCapture.forwardTargetVa = target;
                if (target >= g_imageBase && target < g_imageEnd)
                    g_sessionVCallCapture.forwardTargetRva = target - g_imageBase;
            }
        }

        if (g_sessionVCallCapture.forwardObject)
        {
            std::uintptr_t invokeTarget = 0;
            if (SafeRead(g_sessionVCallCapture.forwardObject +
                kSessionMethod1EmbeddedInvokeTargetOffset, &invokeTarget))
            {
                g_sessionVCallCapture.invokeTargetVa = invokeTarget;
                if (invokeTarget >= g_imageBase && invokeTarget < g_imageEnd)
                    g_sessionVCallCapture.invokeTargetRva = invokeTarget - g_imageBase;
            }

            SafeRead(g_sessionVCallCapture.forwardObject +
                kSessionMethod1EmbeddedInvokeContextOffset,
                &g_sessionVCallCapture.invokeContextVa);
        }

        std::uintptr_t companion = 0;
        if (SafeRead(g_sessionVCallCapture.object + kSessionMethod1CompanionCodeOffset, &companion))
        {
            g_sessionVCallCapture.companionCodeVa = companion;
            if (companion >= g_imageBase && companion < g_imageEnd)
                g_sessionVCallCapture.companionCodeRva = companion - g_imageBase;
        }

        SafeRead(g_sessionVCallCapture.object + kSessionMethod1StateObjectOffset,
            &g_sessionVCallCapture.linkedStateVa);

        g_sessionVCallCapture.preForwardReadable =
            g_sessionVCallCapture.forwardObject != 0 &&
            SafeReadBytes(g_sessionVCallCapture.forwardObject,
                g_sessionVCallCapture.preForwardObject,
                sizeof(g_sessionVCallCapture.preForwardObject));
        g_sessionVCallCapture.preLinkedStateReadable =
            g_sessionVCallCapture.linkedStateVa != 0 &&
            SafeReadBytes(g_sessionVCallCapture.linkedStateVa,
                g_sessionVCallCapture.preLinkedState,
                sizeof(g_sessionVCallCapture.preLinkedState));
    }

    LONG CALLBACK SessionMethod1VCallVeh(PEXCEPTION_POINTERS ep) noexcept
    {
        if (!ep || !ep->ExceptionRecord || !ep->ContextRecord ||
            ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT || !g_imageBase)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        const std::uintptr_t exceptionVa =
            reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
        CONTEXT* c = ep->ContextRecord;
        const std::uintptr_t preVa = g_imageBase + kPreVirtualCallbackRva;
        const std::uintptr_t postVa = g_imageBase + kPostVirtualCallbackRva;

        if (exceptionVa == preVa && InterlockedCompareExchange(&g_sessionPreArmed, 0, 1) == 1)
        {
            // Restore the exact stock CALL byte before re-executing it.
            RawPatchByte(preVa, g_sessionPreOriginal, nullptr);

            g_sessionVCallCapture.preRip = preVa;
            g_sessionVCallCapture.object = static_cast<std::uintptr_t>(c->Rcx);
            g_sessionVCallCapture.vtable = static_cast<std::uintptr_t>(c->Rax);
            g_sessionVCallCapture.r14 = static_cast<std::uintptr_t>(c->R14);
            g_sessionVCallCapture.rdx = static_cast<std::uintptr_t>(c->Rdx);
            g_sessionVCallCapture.r8 = static_cast<std::uintptr_t>(c->R8);
            g_sessionVCallCapture.r9 = static_cast<std::uintptr_t>(c->R9);
            g_sessionVCallCapture.rsp = static_cast<std::uintptr_t>(c->Rsp);

            std::uintptr_t callback = 0;
            SafeRead(g_sessionVCallCapture.vtable + kSessionCallbackVtableSlotOffset, &callback);
            g_sessionVCallCapture.callbackVa = callback;
            if (callback >= g_imageBase && callback < g_imageEnd)
                g_sessionVCallCapture.callbackRva = callback - g_imageBase;

            SafeRead(g_imageBase + kFirstStateRva, &g_sessionVCallCapture.stateAtPre);
            ResolveSessionMethod1ForwardDispatch();
            CaptureStackQwords(g_sessionVCallCapture.rsp,
                g_sessionVCallCapture.preStack, kSessionCaptureStackQwords);
            g_sessionVCallCapture.preObjectReadable = SafeReadBytes(
                g_sessionVCallCapture.object, g_sessionVCallCapture.preObject,
                sizeof(g_sessionVCallCapture.preObject));
            g_sessionVCallCapture.preRdxReadable = SafeReadBytes(
                g_sessionVCallCapture.rdx, g_sessionVCallCapture.preRdxArg,
                sizeof(g_sessionVCallCapture.preRdxArg));
            g_sessionVCallCapture.preR8Readable = SafeReadBytes(
                g_sessionVCallCapture.r8, g_sessionVCallCapture.preR8Arg,
                sizeof(g_sessionVCallCapture.preR8Arg));

            // Arm the exact post-call NOP only after this live method-1 call site
            // has been reached, minimizing unrelated execution interception.
            BYTE postByte = 0;
            if (SafeRead(postVa, &postByte) && postByte == kSessionPostExpected)
            {
                g_sessionPostOriginal = postByte;
                InterlockedExchange(&g_sessionPostArmed, 1);
                if (!RawPatchByte(postVa, 0xCC, nullptr))
                    InterlockedExchange(&g_sessionPostArmed, 0);
            }

            InterlockedExchange(&g_sessionPreCaptured, 1);

            // Windows advances RIP past INT3. Rewind so the restored stock
            // FF 50 08 CALL executes normally.
            c->Rip = static_cast<DWORD64>(preVa);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (exceptionVa == postVa && InterlockedCompareExchange(&g_sessionPostArmed, 0, 1) == 1)
        {
            RawPatchByte(postVa, g_sessionPostOriginal, nullptr);

            g_sessionVCallCapture.postRip = postVa;
            g_sessionVCallCapture.postRax = static_cast<std::uintptr_t>(c->Rax);
            g_sessionVCallCapture.postRcx = static_cast<std::uintptr_t>(c->Rcx);
            g_sessionVCallCapture.postRdx = static_cast<std::uintptr_t>(c->Rdx);
            g_sessionVCallCapture.postR8 = static_cast<std::uintptr_t>(c->R8);
            g_sessionVCallCapture.postR9 = static_cast<std::uintptr_t>(c->R9);
            g_sessionVCallCapture.postRsp = static_cast<std::uintptr_t>(c->Rsp);
            SafeRead(g_imageBase + kFirstStateRva, &g_sessionVCallCapture.stateAtPost);
            CaptureStackQwords(g_sessionVCallCapture.postRsp,
                g_sessionVCallCapture.postStack, kSessionCaptureStackQwords);
            g_sessionVCallCapture.postObjectReadable = SafeReadBytes(
                g_sessionVCallCapture.object, g_sessionVCallCapture.postObject,
                sizeof(g_sessionVCallCapture.postObject));
            g_sessionVCallCapture.postRdxReadable = SafeReadBytes(
                g_sessionVCallCapture.rdx, g_sessionVCallCapture.postRdxArg,
                sizeof(g_sessionVCallCapture.postRdxArg));
            g_sessionVCallCapture.postR8Readable = SafeReadBytes(
                g_sessionVCallCapture.r8, g_sessionVCallCapture.postR8Arg,
                sizeof(g_sessionVCallCapture.postR8Arg));
            g_sessionVCallCapture.postForwardReadable =
                g_sessionVCallCapture.forwardObject != 0 &&
                SafeReadBytes(g_sessionVCallCapture.forwardObject,
                    g_sessionVCallCapture.postForwardObject,
                    sizeof(g_sessionVCallCapture.postForwardObject));
            g_sessionVCallCapture.postLinkedStateReadable =
                g_sessionVCallCapture.linkedStateVa != 0 &&
                SafeReadBytes(g_sessionVCallCapture.linkedStateVa,
                    g_sessionVCallCapture.postLinkedState,
                    sizeof(g_sessionVCallCapture.postLinkedState));

            InterlockedExchange(&g_sessionPostCaptured, 1);

            // Re-execute the original NOP.
            c->Rip = static_cast<DWORD64>(postVa);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool ArmSessionMethod1VCallCapture() noexcept
    {
        // Scanner/redirect-only mode: do not patch the verified CALL/NOP with INT3.
        // Keep all SessionService research passive/static to avoid 0xC000001D.
        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_VCALL DISABLED reason=scanner_redirect_only int3=off veh=off executableWrites=off stateWrites=off\r\n");
        return false;
    }

    void DisarmSessionMethod1VCallCapture() noexcept
    {
        RestoreSessionBreakpoint(kPreVirtualCallbackRva, g_sessionPreOriginal, &g_sessionPreArmed);
        RestoreSessionBreakpoint(kPostVirtualCallbackRva, g_sessionPostOriginal, &g_sessionPostArmed);
        if (g_sessionVCallVeh)
        {
            RemoveVectoredExceptionHandler(g_sessionVCallVeh);
            g_sessionVCallVeh = nullptr;
        }
    }

    void LogCapturedStack(const char* label, const std::uintptr_t* stack, unsigned count) noexcept
    {
        if (!label || !stack)
            return;

        char line[4096]{};
        size_t used = static_cast<size_t>(_snprintf_s(
            line, sizeof(line), _TRUNCATE,
            "[BGS-SESSION-COMP144] %s gameReturnCandidates={", label));

        unsigned emitted = 0;
        for (unsigned i = 0; i < count && used + 64 < sizeof(line); ++i)
        {
            const std::uintptr_t va = stack[i];
            if (va < g_imageBase || va >= g_imageEnd)
                continue;
            const std::uintptr_t rva = va - g_imageBase;
            if (!IsExecutableImageRva(rva))
                continue;

            const int wrote = _snprintf_s(
                line + used, sizeof(line) - used, _TRUNCATE,
                "%s#%u:0x%llX", emitted ? "," : "", i,
                static_cast<unsigned long long>(rva));
            if (wrote <= 0)
                break;
            used += static_cast<size_t>(wrote);
            ++emitted;
        }

        _snprintf_s(line + used, sizeof(line) - used, _TRUNCATE,
            "} count=%u\r\n", emitted);
        WriteRaw(line);
    }

    void LogSessionMethod1InstallerCaptureIfReady() noexcept
    {
        if (!InterlockedCompareExchange(&g_sessionInstallerCaptured, 0, 0) ||
            InterlockedCompareExchange(&g_sessionInstallerLogged, 1, 0) != 0)
        {
            return;
        }

        const std::uintptr_t expectedState = g_imageBase + kFirstStateRva;
        const bool rsiMatchesState = g_sessionInstallerCapture.rsi == expectedState;
        const bool rdiInImage =
            g_sessionInstallerCapture.rdi >= g_imageBase &&
            g_sessionInstallerCapture.rdi < g_imageEnd;
        const bool rsiInImage =
            g_sessionInstallerCapture.rsi >= g_imageBase &&
            g_sessionInstallerCapture.rsi < g_imageEnd;

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER HIT loadRva=0x%llX stateAtHit=%u regs={rax:%p rbx:%p rcx:%p rdx:%p rsi:%p rdi:%p rbp:%p rsp:%p r8:%p r9:%p} expectedState=%p rsiMatchesState=%s rdiImage=%s rsiImage=%s stockByteRestored=yes\r\n",
            static_cast<unsigned long long>(kSessionMethod1DefaultInvokeAddressLoadRva),
            static_cast<unsigned>(g_sessionInstallerCapture.stateAtHit),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rax),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rbx),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rcx),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rdx),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rsi),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rdi),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rbp),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rsp),
            reinterpret_cast<void*>(g_sessionInstallerCapture.r8),
            reinterpret_cast<void*>(g_sessionInstallerCapture.r9),
            reinterpret_cast<void*>(expectedState),
            rsiMatchesState ? "YES" : "no",
            rdiInImage ? "yes" : "no",
            rsiInImage ? "yes" : "no");

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER POINTERS rdi0=%p rdi8=%p rsi0=%p frameStart=%p frameReadable=%s interpretation=RSI_is_value_later_saved_as_delegate_context_candidate\r\n",
            reinterpret_cast<void*>(g_sessionInstallerCapture.rdi0),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rdi8),
            reinterpret_cast<void*>(g_sessionInstallerCapture.rsi0),
            reinterpret_cast<void*>(g_sessionInstallerCapture.frameStart),
            g_sessionInstallerCapture.frameReadable ? "yes" : "no");

        LogCapturedStack("SESSION_METHOD1_INSTALLER_STACK",
            g_sessionInstallerCapture.stack, kSessionMethod1InstallerStackQwords);

        if (g_sessionInstallerCapture.frameReadable)
        {
            for (size_t off = 0; off < sizeof(g_sessionInstallerCapture.frame); off += 32u)
            {
                char hex[160]{};
                BytesToHex(g_sessionInstallerCapture.frame + off, 32u,
                    hex, ArrayCount(hex));
                Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_FRAME offset=+0x%02llX bytes={%s}\r\n",
                    static_cast<unsigned long long>(off), hex);
            }
        }
    }

    void LogSessionBufferDiff(const char* label, const BYTE* before, const BYTE* after,
        size_t bytes, bool beforeReadable, bool afterReadable) noexcept
    {
        if (!label || !before || !after)
            return;
        if (!beforeReadable || !afterReadable)
        {
            Log("[BGS-SESSION-COMP144] %s readableBefore=%s readableAfter=%s diff=unavailable\r\n",
                label, beforeReadable ? "yes" : "no", afterReadable ? "yes" : "no");
            return;
        }

        unsigned runs = 0;
        size_t i = 0;
        while (i < bytes && runs < 24u)
        {
            if (before[i] == after[i])
            {
                ++i;
                continue;
            }
            const size_t start = i;
            while (i < bytes && before[i] != after[i] && i - start < 24u)
                ++i;
            const size_t len = i - start;

            char oldHex[128]{};
            char newHex[128]{};
            BytesToHex(before + start, len, oldHex, ArrayCount(oldHex));
            BytesToHex(after + start, len, newHex, ArrayCount(newHex));
            ++runs;
            Log("[BGS-SESSION-COMP144] %s run=%u offset=+0x%llX len=%llu old={%s} new={%s}\r\n",
                label, runs, static_cast<unsigned long long>(start),
                static_cast<unsigned long long>(len), oldHex, newHex);
        }

        Log("[BGS-SESSION-COMP144] %s complete bytes=0x%llX diffRuns=%u changed=%s\r\n",
            label, static_cast<unsigned long long>(bytes), runs, runs ? "yes" : "NO");
    }

    void LogSessionObjectPointers() noexcept
    {
        if (!g_sessionVCallCapture.preObjectReadable)
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_OBJECT_POINTERS unavailable=pre_object_unreadable\r\n");
            return;
        }

        unsigned emitted = 0;
        for (size_t off = 0; off + sizeof(std::uintptr_t) <=
            sizeof(g_sessionVCallCapture.preObject) && emitted < 32u;
            off += sizeof(std::uintptr_t))
        {
            std::uintptr_t value = 0;
            std::memcpy(&value, g_sessionVCallCapture.preObject + off, sizeof(value));
            if (value < 0x10000u)
                continue;

            const bool image = value >= g_imageBase && value < g_imageEnd;
            MEMORY_BASIC_INFORMATION mbi{};
            const bool queried = VirtualQuery(reinterpret_cast<const void*>(value), &mbi, sizeof(mbi)) == sizeof(mbi);
            if (!image && (!queried || mbi.State != MEM_COMMIT))
                continue;

            ++emitted;
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_OBJECT_POINTER slot=0x%llX value=%p image=%s rva=0x%llX committed=%s type=%s protect=0x%08X\r\n",
                static_cast<unsigned long long>(off), reinterpret_cast<void*>(value),
                image ? "yes" : "no",
                static_cast<unsigned long long>(image ? value - g_imageBase : 0ull),
                queried && mbi.State == MEM_COMMIT ? "yes" : "no",
                queried ? MemoryTypeLabel(mbi.Type) : "UNKNOWN",
                queried ? static_cast<unsigned>(mbi.Protect) : 0u);
        }

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_OBJECT_POINTERS complete emitted=%u object=%p bytes=0x%llX\r\n",
            emitted, reinterpret_cast<void*>(g_sessionVCallCapture.object),
            static_cast<unsigned long long>(sizeof(g_sessionVCallCapture.preObject)));
    }

    void ScanSessionMethod1CallbackVtableOwners() noexcept
    {
        if (!g_imageBase || kSessionMethod1CallbackVtableRva == 0u)
            return;

        unsigned hits = 0;
        const std::uintptr_t scanStartVa = g_imageBase + kSessionBgsOwnerScanStartRva;
        const std::uintptr_t scanEndVa = g_imageBase + kSessionBgsOwnerScanEndRva;
        std::uintptr_t cursor = scanStartVa;

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_OWNER_SCAN begin targetVtableRva=0x%llX callbackRva=0x%llX scan=0x%llX..0x%llX mode=PAGE_SAFE_RIP_XREF_READ_ONLY\r\n",
            static_cast<unsigned long long>(kSessionMethod1CallbackVtableRva),
            static_cast<unsigned long long>(kSessionMethod1CallbackRva),
            static_cast<unsigned long long>(kSessionBgsOwnerScanStartRva),
            static_cast<unsigned long long>(kSessionBgsOwnerScanEndRva));

        while (cursor < scanEndVa && hits < kSessionOwnerMaxXrefs)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi))
            {
                cursor += 0x1000u;
                continue;
            }

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
            const std::uintptr_t begin = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t end = scanEndVa < regionEnd ? scanEndVa : regionEnd;

            if (mbi.State != MEM_COMMIT || !IsReadableMemoryProtection(mbi.Protect) || end <= begin)
            {
                cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
                continue;
            }

            __try
            {
                const BYTE* code = reinterpret_cast<const BYTE*>(begin);
                const size_t bytes = static_cast<size_t>(end - begin);
                for (size_t i = 0; i + 10u <= bytes && hits < kSessionOwnerMaxXrefs; ++i)
                {
                    const size_t prefix = (code[i] >= 0x40 && code[i] <= 0x4F) ? 1u : 0u;
                    const size_t op = i + prefix;
                    const char* kind = nullptr;
                    size_t dispOff = 0;
                    size_t instructionLen = 0;

                    if (op + 6u <= bytes &&
                        (code[op] == 0x8D || code[op] == 0x8B || code[op] == 0x89))
                    {
                        const BYTE modrm = code[op + 1];
                        if (((modrm >> 6) & 3u) == 0u && (modrm & 7u) == 5u)
                        {
                            kind = code[op] == 0x8D ? "LEA_RIP" :
                                (code[op] == 0x8B ? "MOV_RIP_READ" : "MOV_RIP_WRITE");
                            dispOff = op + 2u;
                            instructionLen = prefix + 6u;
                        }
                    }

                    if (!kind)
                        continue;

                    std::int32_t disp = 0;
                    std::memcpy(&disp, code + dispOff, sizeof(disp));
                    const std::uintptr_t instructionRva = begin - g_imageBase + i;
                    const std::uintptr_t resolvedRva = static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(instructionRva + instructionLen) +
                        static_cast<std::intptr_t>(disp));
                    if (resolvedRva != kSessionMethod1CallbackVtableRva)
                        continue;

                    ++hits;
                    RuntimeFunctionBounds bounds{};
                    const bool bounded = QueryRuntimeFunctionBounds(instructionRva, &bounds);
                    Log("[BGS-SESSION-COMP144] SESSION_METHOD1_OWNER_XREF hit=%u kind=%s instructionRva=0x%llX targetVtableRva=0x%llX functionBeginRva=0x%llX functionEndRva=0x%llX unwind=%s read_only=yes\r\n",
                        hits, kind,
                        static_cast<unsigned long long>(instructionRva),
                        static_cast<unsigned long long>(resolvedRva),
                        static_cast<unsigned long long>(bounded ? bounds.beginRva : instructionRva),
                        static_cast<unsigned long long>(bounded ? bounds.endRva : 0ull),
                        bounded ? "yes" : "no");
                    LogCodeContext("SESSION_METHOD1_OWNER_XREF_CONTEXT", instructionRva, 24, 48);

                    unsigned edgeLogs = 0;
                    const OwnerFunctionSummary owner = ScanOwnerFunctionEdges(
                        "SESSION_METHOD1_VTABLE_OWNER",
                        bounded ? bounds.beginRva : instructionRva,
                        0, kSessionMethod1CallbackVtableRva, 0, 1, &edgeLogs);
                    Log("[BGS-SESSION-COMP144] SESSION_METHOD1_OWNER_FUNCTION xref=%u startRva=0x%llX directEdges=%u state2Edges=%u firstStateGetterCalls=%u state2Compares=%u bnetClusterEdges=%u\r\n",
                        hits,
                        static_cast<unsigned long long>(bounded ? bounds.beginRva : instructionRva),
                        owner.directEdges, owner.state2Edges, owner.getterCalls,
                        owner.state2Compares, owner.bnetClusterEdges);

                    if (instructionLen > 1u)
                        i += instructionLen - 1u;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Log("[BGS-SESSION-COMP144] SESSION_METHOD1_OWNER_SCAN regionFault=yes regionBase=%p regionSize=0x%llX continuing=yes\r\n",
                    mbi.BaseAddress, static_cast<unsigned long long>(mbi.RegionSize));
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_OWNER_SCAN complete targetVtableRva=0x%llX hits=%u next=identify_callback_class_and_required_session_fields\r\n",
            static_cast<unsigned long long>(kSessionMethod1CallbackVtableRva), hits);
    }

    bool IsSessionMethod1SecondLevelDispatchThunk(std::uintptr_t rva) noexcept
    {
        static constexpr BYTE kExpected[] =
        {
            0x48, 0x8B, 0xC1,             // MOV RAX,RCX
            0x48, 0x8B, 0x49, 0x18,       // MOV RCX,[RCX+0x18]
            0x48, 0xFF, 0x60, 0x08        // JMP QWORD PTR [RAX+0x08]
        };
        BYTE code[sizeof(kExpected)]{};
        return SafeReadBytes(g_imageBase + rva, code, sizeof(code)) &&
            std::memcmp(code, kExpected, sizeof(code)) == 0;
    }

    bool IsSessionMethod1PreserveReturnStub(std::uintptr_t rva) noexcept
    {
        // Exact live V19 bytes. The CALL at +0x0C targets +0x07, whose EB 1E
        // jumps to +0x27. That path pops the synthetic return address, restores
        // flags and the original RCX, then RETs without touching auth state.
        BYTE code[49]{};
        if (!SafeReadBytes(g_imageBase + rva, code, sizeof(code)))
            return false;
        if (code[0] != 0x51 || code[1] != 0x9C || code[2] != 0x48 || code[3] != 0xB9 ||
            code[7] != 0xEB || code[8] != 0x1E || code[12] != 0xE8 ||
            code[39] != 0x59 || code[40] != 0x81 || code[41] != 0xE9 ||
            code[46] != 0x9D || code[47] != 0x59 || code[48] != 0xC3)
        {
            return false;
        }
        std::int32_t callRel = 0;
        std::memcpy(&callRel, code + 13, sizeof(callRel));
        return callRel == -10;
    }

    struct SessionInvokeXrefHints
    {
        bool firstStateDataRef{};
        bool callsWriterA{};
        bool callsWriterB{};
        bool callsSessionRpc{};
    };

    SessionInvokeXrefHints AnalyzeSessionInvokeXrefFunction(
        const RuntimeFunctionBounds& bounds) noexcept
    {
        SessionInvokeXrefHints hints{};
        if (!bounds.beginRva || bounds.endRva <= bounds.beginRva)
            return hints;

        constexpr size_t kMaxBytes = 0x800u;
        size_t bytes = static_cast<size_t>(bounds.endRva - bounds.beginRva);
        if (bytes > kMaxBytes)
            bytes = kMaxBytes;
        if (!bytes)
            return hints;

        BYTE code[kMaxBytes]{};
        if (!SafeReadBytes(g_imageBase + bounds.beginRva, code, bytes))
            return hints;

        for (size_t i = 0; i < bytes; ++i)
        {
            if (i + 5u <= bytes && (code[i] == 0xE8 || code[i] == 0xE9))
            {
                std::int32_t rel = 0;
                std::memcpy(&rel, code + i + 1u, sizeof(rel));
                const std::uintptr_t sourceRva = bounds.beginRva + i;
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(sourceRva + 5u) +
                    static_cast<std::intptr_t>(rel));
                if (targetRva == k144.BgsSessionServiceMethod1CallbackVtableWriterA)
                    hints.callsWriterA = true;
                if (targetRva == k144.BgsSessionServiceMethod1CallbackVtableWriterB)
                    hints.callsWriterB = true;
                if (targetRva == kSessionRpcRva)
                    hints.callsSessionRpc = true;
                i += 4u;
                continue;
            }

            const size_t prefix = (code[i] >= 0x40 && code[i] <= 0x4F) ? 1u : 0u;
            const size_t op = i + prefix;
            if (op + 6u > bytes ||
                (code[op] != 0x8D && code[op] != 0x8B && code[op] != 0x89))
            {
                continue;
            }

            const BYTE modrm = code[op + 1u];
            if (((modrm >> 6u) & 3u) != 0u || (modrm & 7u) != 5u)
                continue;

            std::int32_t disp = 0;
            std::memcpy(&disp, code + op + 2u, sizeof(disp));
            const size_t instructionLen = prefix + 6u;
            const std::uintptr_t sourceRva = bounds.beginRva + i;
            const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                static_cast<std::intptr_t>(sourceRva + instructionLen) +
                static_cast<std::intptr_t>(disp));
            if (targetRva == kFirstStateRva)
                hints.firstStateDataRef = true;
            if (instructionLen > 1u)
                i += instructionLen - 1u;
        }
        return hints;
    }

    void ScanSessionMethod1InvokeXrefRange(const char* rangeLabel,
        std::uintptr_t scanStartRva, std::uintptr_t scanEndRva,
        unsigned* totalHits) noexcept
    {
        if (!rangeLabel || !totalHits || !g_imageBase || scanStartRva >= scanEndRva)
            return;

        const std::uintptr_t targetRva = kSessionMethod1ObservedInvokeTargetRva;
        const std::uintptr_t targetVa = g_imageBase + targetRva;
        std::uintptr_t cursor = g_imageBase + scanStartRva;
        const std::uintptr_t scanEndVa = g_imageBase + scanEndRva;
        unsigned localHits = 0;

        while (cursor < scanEndVa && *totalHits < kSessionMethod1InvokeMaxXrefs)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
            const std::uintptr_t begin = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t end = scanEndVa < regionEnd ? scanEndVa : regionEnd;
            if (mbi.State != MEM_COMMIT || !IsReadableMemoryProtection(mbi.Protect) || end <= begin)
            {
                cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
                continue;
            }

            __try
            {
                const BYTE* code = reinterpret_cast<const BYTE*>(begin);
                const size_t bytes = static_cast<size_t>(end - begin);
                for (size_t i = 0; i < bytes && *totalHits < kSessionMethod1InvokeMaxXrefs; ++i)
                {
                    const char* kind = nullptr;
                    size_t instructionLen = 0;
                    std::uintptr_t resolvedRva = 0;

                    if (i + 5u <= bytes && (code[i] == 0xE8 || code[i] == 0xE9))
                    {
                        std::int32_t rel = 0;
                        std::memcpy(&rel, code + i + 1u, sizeof(rel));
                        const std::uintptr_t sourceRva = begin - g_imageBase + i;
                        resolvedRva = static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(sourceRva + 5u) +
                            static_cast<std::intptr_t>(rel));
                        kind = code[i] == 0xE8 ? "DIRECT_CALL" : "DIRECT_JMP";
                        instructionLen = 5u;
                    }
                    else
                    {
                        const size_t prefix = (code[i] >= 0x40 && code[i] <= 0x4F) ? 1u : 0u;
                        const size_t op = i + prefix;
                        if (op + 6u <= bytes &&
                            (code[op] == 0x8D || code[op] == 0x8B || code[op] == 0x89))
                        {
                            const BYTE modrm = code[op + 1u];
                            if (((modrm >> 6u) & 3u) == 0u && (modrm & 7u) == 5u)
                            {
                                std::int32_t disp = 0;
                                std::memcpy(&disp, code + op + 2u, sizeof(disp));
                                instructionLen = prefix + 6u;
                                const std::uintptr_t sourceRva = begin - g_imageBase + i;
                                resolvedRva = static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(sourceRva + instructionLen) +
                                    static_cast<std::intptr_t>(disp));
                                kind = code[op] == 0x8D ? "LEA_RIP_ADDRESS" :
                                    (code[op] == 0x8B ? "MOV_RIP_READ" : "MOV_RIP_WRITE");
                            }
                        }

                        if (!kind && i + 10u <= bytes && code[i] >= 0x48 && code[i] <= 0x4F &&
                            code[i + 1u] >= 0xB8 && code[i + 1u] <= 0xBF)
                        {
                            std::uintptr_t imm = 0;
                            std::memcpy(&imm, code + i + 2u, sizeof(imm));
                            if (imm == targetVa)
                            {
                                kind = "MOVABS_ADDRESS";
                                instructionLen = 10u;
                                resolvedRva = targetRva;
                            }
                        }
                    }

                    if (!kind || resolvedRva != targetRva)
                        continue;

                    ++localHits;
                    ++(*totalHits);
                    const std::uintptr_t instructionRva = begin - g_imageBase + i;
                    RuntimeFunctionBounds bounds{};
                    const bool bounded = QueryRuntimeFunctionBounds(instructionRva, &bounds);
                    const SessionInvokeXrefHints hints = bounded
                        ? AnalyzeSessionInvokeXrefFunction(bounds)
                        : SessionInvokeXrefHints{};

                    Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INVOKE_XREF hit=%u range=%s kind=%s instructionRva=0x%llX targetRva=0x%llX functionBeginRva=0x%llX functionEndRva=0x%llX unwind=%s firstStateDataRef=%s callsCallbackWriterA=%s callsCallbackWriterB=%s callsSessionRpc=%s read_only=yes\r\n",
                        *totalHits, rangeLabel, kind,
                        static_cast<unsigned long long>(instructionRva),
                        static_cast<unsigned long long>(resolvedRva),
                        static_cast<unsigned long long>(bounded ? bounds.beginRva : instructionRva),
                        static_cast<unsigned long long>(bounded ? bounds.endRva : 0ull),
                        bounded && bounds.fromUnwind ? "yes" : "no",
                        hints.firstStateDataRef ? "yes" : "no",
                        hints.callsWriterA ? "yes" : "no",
                        hints.callsWriterB ? "yes" : "no",
                        hints.callsSessionRpc ? "yes" : "no");
                    LogCodeContext("SESSION_METHOD1_INVOKE_XREF_CONTEXT", instructionRva, 24, 48);

                    if (instructionLen > 1u)
                        i += instructionLen - 1u;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INVOKE_XREF regionFault=yes range=%s regionBase=%p regionSize=0x%llX continuing=yes\r\n",
                    rangeLabel, mbi.BaseAddress,
                    static_cast<unsigned long long>(mbi.RegionSize));
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INVOKE_XREF_RANGE complete range=%s scan=0x%llX..0x%llX localHits=%u totalHits=%u read_only=yes\r\n",
            rangeLabel,
            static_cast<unsigned long long>(scanStartRva),
            static_cast<unsigned long long>(scanEndRva),
            localHits, *totalHits);
    }

    void ScanSessionMethod1InvokeTargetXrefs() noexcept
    {
        unsigned hits = 0;
        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INVOKE_XREF begin targetRva=0x%llX ranges={BGS:0x%llX..0x%llX,BNET:0x%llX..0x%llX} mode=PAGE_SAFE_ADDRESS_TAKEN_AND_DIRECT_XREF read_only=yes\r\n",
            static_cast<unsigned long long>(kSessionMethod1ObservedInvokeTargetRva),
            static_cast<unsigned long long>(kSessionMethod1BgsXrefScanStartRva),
            static_cast<unsigned long long>(kSessionMethod1BgsXrefScanEndRva),
            static_cast<unsigned long long>(kSessionMethod1BnetXrefScanStartRva),
            static_cast<unsigned long long>(kSessionMethod1BnetXrefScanEndRva));
        ScanSessionMethod1InvokeXrefRange("BGS", kSessionMethod1BgsXrefScanStartRva,
            kSessionMethod1BgsXrefScanEndRva, &hits);
        ScanSessionMethod1InvokeXrefRange("BNET", kSessionMethod1BnetXrefScanStartRva,
            kSessionMethod1BnetXrefScanEndRva, &hits);
        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INVOKE_XREF complete targetRva=0x%llX totalHits=%u next=identify_delegate_registration_owner read_only=yes\r\n",
            static_cast<unsigned long long>(kSessionMethod1ObservedInvokeTargetRva), hits);
    }

    unsigned ScanState2SuccessEntryXrefs() noexcept
    {
        if (!g_imageBase || kState2SuccessEntryRva == 0u)
            return 0u;

        constexpr unsigned kMaxHits = 64u;
        const std::uintptr_t targetRva = kState2SuccessEntryRva;
        const std::uintptr_t targetVa = g_imageBase + targetRva;
        const std::uintptr_t scanStartRva = kSessionMethod1BnetXrefScanStartRva;
        const std::uintptr_t scanEndRva = kSessionMethod1BnetXrefScanEndRva;
        std::uintptr_t cursor = g_imageBase + scanStartRva;
        const std::uintptr_t scanEndVa = g_imageBase + scanEndRva;
        unsigned hits = 0;

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_SUCCESS_XREF_SCAN begin targetEntryRva=0x%llX writerRva=0x%llX scan=0x%llX..0x%llX mode=PAGE_SAFE_ADDRESS_TAKEN_AND_DIRECT_XREF read_only=yes\r\n",
            static_cast<unsigned long long>(targetRva),
            static_cast<unsigned long long>(kState2SuccessWriterRva),
            static_cast<unsigned long long>(scanStartRva),
            static_cast<unsigned long long>(scanEndRva));

        while (cursor < scanEndVa && hits < kMaxHits)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
            const std::uintptr_t begin = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t end = scanEndVa < regionEnd ? scanEndVa : regionEnd;
            if (mbi.State != MEM_COMMIT || !IsReadableMemoryProtection(mbi.Protect) || end <= begin)
            {
                cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
                continue;
            }

            __try
            {
                const BYTE* code = reinterpret_cast<const BYTE*>(begin);
                const size_t bytes = static_cast<size_t>(end - begin);
                for (size_t i = 0; i < bytes && hits < kMaxHits; ++i)
                {
                    const char* kind = nullptr;
                    size_t instructionLen = 0u;
                    std::uintptr_t resolvedRva = 0u;

                    if (i + 5u <= bytes && (code[i] == 0xE8 || code[i] == 0xE9))
                    {
                        std::int32_t rel = 0;
                        std::memcpy(&rel, code + i + 1u, sizeof(rel));
                        const std::uintptr_t sourceRva = begin - g_imageBase + i;
                        resolvedRva = static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(sourceRva + 5u) +
                            static_cast<std::intptr_t>(rel));
                        kind = code[i] == 0xE8 ? "DIRECT_CALL" : "DIRECT_JMP";
                        instructionLen = 5u;
                    }
                    else
                    {
                        const size_t prefix = (code[i] >= 0x40 && code[i] <= 0x4F) ? 1u : 0u;
                        const size_t op = i + prefix;
                        if (op + 6u <= bytes &&
                            (code[op] == 0x8D || code[op] == 0x8B || code[op] == 0x89))
                        {
                            const BYTE modrm = code[op + 1u];
                            if (((modrm >> 6u) & 3u) == 0u && (modrm & 7u) == 5u)
                            {
                                std::int32_t disp = 0;
                                std::memcpy(&disp, code + op + 2u, sizeof(disp));
                                instructionLen = prefix + 6u;
                                const std::uintptr_t sourceRva = begin - g_imageBase + i;
                                resolvedRva = static_cast<std::uintptr_t>(
                                    static_cast<std::intptr_t>(sourceRva + instructionLen) +
                                    static_cast<std::intptr_t>(disp));
                                kind = code[op] == 0x8D ? "LEA_RIP_ADDRESS" :
                                    (code[op] == 0x8B ? "MOV_RIP_READ" : "MOV_RIP_WRITE");
                            }
                        }

                        if (!kind && i + 10u <= bytes && code[i] >= 0x48 && code[i] <= 0x4F &&
                            code[i + 1u] >= 0xB8 && code[i + 1u] <= 0xBF)
                        {
                            std::uintptr_t imm = 0;
                            std::memcpy(&imm, code + i + 2u, sizeof(imm));
                            if (imm == targetVa)
                            {
                                kind = "MOVABS_ADDRESS";
                                instructionLen = 10u;
                                resolvedRva = targetRva;
                            }
                        }
                    }

                    if (!kind || resolvedRva != targetRva)
                        continue;

                    ++hits;
                    const std::uintptr_t instructionRva = begin - g_imageBase + i;
                    RuntimeFunctionBounds bounds{};
                    const bool bounded = QueryRuntimeFunctionBounds(instructionRva, &bounds);
                    const bool knownDeadDirect =
                        instructionRva == kState2DeadDirectCallRva &&
                        std::strcmp(kind, "DIRECT_CALL") == 0;

                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_SUCCESS_XREF hit=%u kind=%s instructionRva=0x%llX functionBeginRva=0x%llX functionEndRva=0x%llX unwind=%s knownDeadDirect=%s read_only=yes\r\n",
                        hits, kind,
                        static_cast<unsigned long long>(instructionRva),
                        static_cast<unsigned long long>(bounded ? bounds.beginRva : instructionRva),
                        static_cast<unsigned long long>(bounded ? bounds.endRva : 0ull),
                        bounded && bounds.fromUnwind ? "yes" : "no",
                        knownDeadDirect ? "YES" : "no");
                    LogCodeContext("AUTH_STATE2_SUCCESS_XREF_CONTEXT", instructionRva, 24, 48);

                    if (instructionLen > 1u)
                        i += instructionLen - 1u;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Log("[BGS-SESSION-COMP144] AUTH_STATE2_SUCCESS_XREF regionFault=yes regionBase=%p regionSize=0x%llX continuing=yes\r\n",
                    mbi.BaseAddress,
                    static_cast<unsigned long long>(mbi.RegionSize));
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_SUCCESS_XREF_SCAN complete targetEntryRva=0x%llX totalHits=%u knownDeadDirectCallRva=0x%llX next=classify_address_taken_success_callback_registration read_only=yes\r\n",
            static_cast<unsigned long long>(targetRva), hits,
            static_cast<unsigned long long>(kState2DeadDirectCallRva));
        return hits;
    }

    std::uintptr_t ResolveRel32Target(std::uintptr_t instructionRva, size_t instructionLen) noexcept
    {
        if (!g_imageBase || instructionLen < 5u)
            return 0;
        std::int32_t rel = 0;
        if (!SafeRead(g_imageBase + instructionRva + instructionLen - 4u, &rel))
            return 0;
        return static_cast<std::uintptr_t>(
            static_cast<std::intptr_t>(instructionRva + instructionLen) +
            static_cast<std::intptr_t>(rel));
    }

    void DumpSessionMethod1DelegateInstaller() noexcept
    {
        RuntimeFunctionBounds bounds{};
        const bool bounded = QueryRuntimeFunctionBounds(
            kSessionMethod1DefaultInvokeAddressLoadRva, &bounds);
        const std::uintptr_t beginRva = bounded
            ? bounds.beginRva : kSessionMethod1DelegateInstallerFunctionRva;
        const std::uintptr_t endRva = bounded
            ? bounds.endRva : kSessionMethod1DelegateInstallerFunctionEndRva;

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_FUNCTION beginRva=0x%llX endRva=0x%llX expectedBegin=0x%llX expectedEnd=0x%llX unwind=%s boundsMatch=%s read_only=yes\r\n",
            static_cast<unsigned long long>(beginRva),
            static_cast<unsigned long long>(endRva),
            static_cast<unsigned long long>(kSessionMethod1DelegateInstallerFunctionRva),
            static_cast<unsigned long long>(kSessionMethod1DelegateInstallerFunctionEndRva),
            bounded && bounds.fromUnwind ? "yes" : "no",
            beginRva == kSessionMethod1DelegateInstallerFunctionRva &&
                endRva == kSessionMethod1DelegateInstallerFunctionEndRva ? "YES" : "no");

        if (!beginRva || endRva <= beginRva || g_imageBase + endRva > g_imageEnd)
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_FUNCTION unavailable=yes\r\n");
            return;
        }

        constexpr size_t kChunk = 64u;
        for (std::uintptr_t rva = beginRva; rva < endRva; rva += kChunk)
        {
            const size_t remaining = static_cast<size_t>(endRva - rva);
            const size_t bytes = remaining < kChunk ? remaining : kChunk;
            BYTE code[kChunk]{};
            if (!SafeReadBytes(g_imageBase + rva, code, bytes))
            {
                Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_CODE rva=0x%llX readable=no\r\n",
                    static_cast<unsigned long long>(rva));
                continue;
            }
            char hex[256]{};
            BytesToHex(code, bytes, hex, ArrayCount(hex));
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_CODE rva=0x%llX bytes={%s}\r\n",
                static_cast<unsigned long long>(rva), hex);
        }

        BYTE invokeLoad[7]{};
        BYTE vtableLoad[7]{};
        BYTE submitCall[5]{};
        BYTE preCall[5]{};
        const bool invokeLoadOk =
            SafeReadBytes(g_imageBase + kSessionMethod1DefaultInvokeAddressLoadRva,
                invokeLoad, sizeof(invokeLoad)) &&
            std::memcmp(invokeLoad, kSessionInstallerExpected, sizeof(invokeLoad)) == 0;
        const BYTE expectedVtableLoad[7] = { 0x48, 0x8D, 0x05, 0xB6, 0x46, 0x92, 0x02 };
        const bool vtableLoadOk =
            SafeReadBytes(g_imageBase + kSessionMethod1DelegateVtableAddressLoadRva,
                vtableLoad, sizeof(vtableLoad)) &&
            std::memcmp(vtableLoad, expectedVtableLoad, sizeof(vtableLoad)) == 0;
        const bool submitCallOk =
            SafeReadBytes(g_imageBase + kSessionMethod1DelegateSubmitCallRva,
                submitCall, sizeof(submitCall)) && submitCall[0] == 0xE8;
        const bool preCallOk =
            SafeReadBytes(g_imageBase + kSessionMethod1DelegatePreInstallCallRva,
                preCall, sizeof(preCall)) && preCall[0] == 0xE8;

        const std::uintptr_t submitTarget = submitCallOk
            ? ResolveRel32Target(kSessionMethod1DelegateSubmitCallRva, 5u) : 0;
        const std::uintptr_t preTarget = preCallOk
            ? ResolveRel32Target(kSessionMethod1DelegatePreInstallCallRva, 5u) : 0;

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_LAYOUT defaultInvokeLoadRva=0x%llX exact=%s vtableLoadRva=0x%llX exact=%s submitCallRva=0x%llX submitTargetRva=0x%llX expectedSubmit=0x%llX submitMatch=%s preCallRva=0x%llX preTargetRva=0x%llX expectedPre=0x%llX preMatch=%s semantics={invoke:0x%llX,vtable:0x%llX,context_candidate:RSI_saved_to_stack_plus_0x30} read_only=yes\r\n",
            static_cast<unsigned long long>(kSessionMethod1DefaultInvokeAddressLoadRva),
            invokeLoadOk ? "YES" : "no",
            static_cast<unsigned long long>(kSessionMethod1DelegateVtableAddressLoadRva),
            vtableLoadOk ? "YES" : "no",
            static_cast<unsigned long long>(kSessionMethod1DelegateSubmitCallRva),
            static_cast<unsigned long long>(submitTarget),
            static_cast<unsigned long long>(kSessionMethod1DelegateSubmitTargetRva),
            submitTarget == kSessionMethod1DelegateSubmitTargetRva ? "YES" : "no",
            static_cast<unsigned long long>(kSessionMethod1DelegatePreInstallCallRva),
            static_cast<unsigned long long>(preTarget),
            static_cast<unsigned long long>(kSessionMethod1DelegatePreInstallTargetRva),
            preTarget == kSessionMethod1DelegatePreInstallTargetRva ? "YES" : "no",
            static_cast<unsigned long long>(kSessionMethod1ObservedInvokeTargetRva),
            static_cast<unsigned long long>(kSessionMethod1ObservedEmbeddedVtableRva));
    }

    void ScanSessionMethod1InstallerCallerRange(const char* rangeLabel,
        std::uintptr_t scanStartRva, std::uintptr_t scanEndRva,
        unsigned* totalHits) noexcept
    {
        if (!rangeLabel || !totalHits || !g_imageBase || scanStartRva >= scanEndRva)
            return;

        std::uintptr_t cursor = g_imageBase + scanStartRva;
        const std::uintptr_t scanEndVa = g_imageBase + scanEndRva;
        unsigned localHits = 0;

        while (cursor < scanEndVa &&
            *totalHits < kSessionMethod1InstallerMaxCallerXrefs)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const std::uintptr_t regionBase =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd =
                regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
            const std::uintptr_t begin = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t end = scanEndVa < regionEnd ? scanEndVa : regionEnd;
            if (mbi.State != MEM_COMMIT || !IsReadableMemoryProtection(mbi.Protect) ||
                end <= begin)
            {
                cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
                continue;
            }

            __try
            {
                const BYTE* code = reinterpret_cast<const BYTE*>(begin);
                const size_t bytes = static_cast<size_t>(end - begin);
                for (size_t i = 0; i + 5u <= bytes &&
                    *totalHits < kSessionMethod1InstallerMaxCallerXrefs; ++i)
                {
                    if (code[i] != 0xE8 && code[i] != 0xE9)
                        continue;

                    std::int32_t rel = 0;
                    std::memcpy(&rel, code + i + 1u, sizeof(rel));
                    const std::uintptr_t sourceRva = begin - g_imageBase + i;
                    const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(sourceRva + 5u) +
                        static_cast<std::intptr_t>(rel));
                    if (targetRva != kSessionMethod1DelegateInstallerFunctionRva)
                        continue;

                    ++localHits;
                    ++(*totalHits);
                    RuntimeFunctionBounds caller{};
                    const bool callerBounded =
                        QueryRuntimeFunctionBounds(sourceRva, &caller);
                    const SessionInvokeXrefHints hints = callerBounded
                        ? AnalyzeSessionInvokeXrefFunction(caller)
                        : SessionInvokeXrefHints{};

                    Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_CALLER hit=%u range=%s kind=%s instructionRva=0x%llX targetRva=0x%llX functionBeginRva=0x%llX functionEndRva=0x%llX unwind=%s firstStateDataRef=%s callsSessionRpc=%s read_only=yes\r\n",
                        *totalHits, rangeLabel,
                        code[i] == 0xE8 ? "CALL" : "JMP",
                        static_cast<unsigned long long>(sourceRva),
                        static_cast<unsigned long long>(targetRva),
                        static_cast<unsigned long long>(
                            callerBounded ? caller.beginRva : sourceRva),
                        static_cast<unsigned long long>(
                            callerBounded ? caller.endRva : 0ull),
                        callerBounded && caller.fromUnwind ? "yes" : "no",
                        hints.firstStateDataRef ? "yes" : "no",
                        hints.callsSessionRpc ? "yes" : "no");
                    LogCodeContext("SESSION_METHOD1_INSTALLER_CALLER_CONTEXT",
                        sourceRva, 32, 56);
                    i += 4u;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_CALLER regionFault=yes range=%s regionBase=%p regionSize=0x%llX continuing=yes\r\n",
                    rangeLabel, mbi.BaseAddress,
                    static_cast<unsigned long long>(mbi.RegionSize));
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_CALLER_RANGE complete range=%s scan=0x%llX..0x%llX localHits=%u totalHits=%u read_only=yes\r\n",
            rangeLabel,
            static_cast<unsigned long long>(scanStartRva),
            static_cast<unsigned long long>(scanEndRva),
            localHits, *totalHits);
    }

    void ScanSessionMethod1InstallerCallers() noexcept
    {
        unsigned hits = 0;
        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_CALLER_SCAN begin targetRva=0x%llX ranges={BGS:0x%llX..0x%llX,BNET:0x%llX..0x%llX} mode=PAGE_SAFE_DIRECT_REL32 read_only=yes\r\n",
            static_cast<unsigned long long>(
                kSessionMethod1DelegateInstallerFunctionRva),
            static_cast<unsigned long long>(kSessionMethod1BgsXrefScanStartRva),
            static_cast<unsigned long long>(kSessionMethod1BgsXrefScanEndRva),
            static_cast<unsigned long long>(kSessionMethod1BnetXrefScanStartRva),
            static_cast<unsigned long long>(kSessionMethod1BnetXrefScanEndRva));

        ScanSessionMethod1InstallerCallerRange("BGS",
            kSessionMethod1BgsXrefScanStartRva,
            kSessionMethod1BgsXrefScanEndRva, &hits);
        ScanSessionMethod1InstallerCallerRange("BNET",
            kSessionMethod1BnetXrefScanStartRva,
            kSessionMethod1BnetXrefScanEndRva, &hits);

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INSTALLER_CALLER_SCAN complete targetRva=0x%llX totalHits=%u next=correlate_live_installer_context_with_registration_caller read_only=yes\r\n",
            static_cast<unsigned long long>(
                kSessionMethod1DelegateInstallerFunctionRva),
            hits);
    }

    void AnalyzeSessionMethod1ForwardTarget() noexcept
    {
        const std::uintptr_t targetRva = g_sessionVCallCapture.forwardTargetRva;
        const bool vtableMatchesObserved =
            g_sessionVCallCapture.forwardVtableRva == kSessionMethod1ObservedEmbeddedVtableRva;
        const bool stateObjectMatches =
            g_sessionVCallCapture.linkedStateVa == g_imageBase + kFirstStateRva;
        const bool invokeContextMatches =
            g_sessionVCallCapture.invokeContextVa == g_imageBase + kFirstStateRva;
        const bool invokeTargetMatches =
            g_sessionVCallCapture.invokeTargetRva == kSessionMethod1ObservedInvokeTargetRva;
        const bool aliasFieldsMatch =
            g_sessionVCallCapture.invokeTargetVa == g_sessionVCallCapture.companionCodeVa &&
            g_sessionVCallCapture.invokeContextVa == g_sessionVCallCapture.linkedStateVa;

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_FORWARD_RESOLVE storage=%p raw=0x%llX tagged=%s interface=%p vtable=%p vtableRva=0x%llX observedVtableRva=0x%llX observedMatch=%s slot1Target=%p targetRva=0x%llX invokeTarget=%p invokeTargetRva=0x%llX invokeContext=%p expectedState=%p invokeContextMatch=%s outerAliasFieldsMatch=%s\r\n",
            reinterpret_cast<void*>(g_sessionVCallCapture.forwardStorage),
            static_cast<unsigned long long>(g_sessionVCallCapture.forwardRaw),
            g_sessionVCallCapture.forwardTagged ? "yes" : "no",
            reinterpret_cast<void*>(g_sessionVCallCapture.forwardObject),
            reinterpret_cast<void*>(g_sessionVCallCapture.forwardVtable),
            static_cast<unsigned long long>(g_sessionVCallCapture.forwardVtableRva),
            static_cast<unsigned long long>(kSessionMethod1ObservedEmbeddedVtableRva),
            vtableMatchesObserved ? "YES" : "no",
            reinterpret_cast<void*>(g_sessionVCallCapture.forwardTargetVa),
            static_cast<unsigned long long>(targetRva),
            reinterpret_cast<void*>(g_sessionVCallCapture.invokeTargetVa),
            static_cast<unsigned long long>(g_sessionVCallCapture.invokeTargetRva),
            reinterpret_cast<void*>(g_sessionVCallCapture.invokeContextVa),
            reinterpret_cast<void*>(g_imageBase + kFirstStateRva),
            invokeContextMatches ? "YES" : "no",
            aliasFieldsMatch ? "YES" : "no");

        if (g_sessionVCallCapture.forwardVtable)
        {
            for (unsigned slot = 0; slot < kSessionCaptureVtableSlots; ++slot)
            {
                std::uintptr_t fn = 0;
                if (!SafeRead(g_sessionVCallCapture.forwardVtable +
                    static_cast<std::uintptr_t>(slot) * sizeof(std::uintptr_t), &fn))
                    break;
                const bool image = fn >= g_imageBase && fn < g_imageEnd;
                Log("[BGS-SESSION-COMP144] SESSION_METHOD1_FORWARD_VTABLE slot=%u fn=%p rva=0x%llX executable=%s selected=%s\r\n",
                    slot, reinterpret_cast<void*>(fn),
                    static_cast<unsigned long long>(image ? fn - g_imageBase : 0u),
                    image && IsExecutableImageRva(fn - g_imageBase) ? "yes" : "no",
                    slot == 1 ? "YES" : "no");
            }
        }

        const bool exactSecondLevelThunk =
            targetRva == kSessionMethod1EmbeddedSlot1DispatchRva &&
            IsSessionMethod1SecondLevelDispatchThunk(targetRva);

        if (!targetRva || !IsExecutableImageRva(targetRva))
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_FORWARD_TARGET executable=no targetRva=0x%llX next=validate_embedded_interface\r\n",
                static_cast<unsigned long long>(targetRva));
            return;
        }

        LogCodeContext("SESSION_METHOD1_FORWARD_TARGET_CODE", targetRva, 0, 48);
        if (exactSecondLevelThunk)
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_FORWARD_TARGET_CLASSIFY targetRva=0x%llX classification=SECOND_LEVEL_DELEGATE_DISPATCH semantics={context:[RCX+0x%llX],invoke:[RCX+0x%llX]} invokeTargetRva=0x%llX invokeContextMatch=%s V19BoundarySpillState2Edge=FALSE_POSITIVE no_direct_state2_edge=yes\r\n",
                static_cast<unsigned long long>(targetRva),
                static_cast<unsigned long long>(kSessionMethod1EmbeddedInvokeContextOffset),
                static_cast<unsigned long long>(kSessionMethod1EmbeddedInvokeTargetOffset),
                static_cast<unsigned long long>(g_sessionVCallCapture.invokeTargetRva),
                invokeContextMatches ? "YES" : "no");
        }
        else
        {
            RuntimeFunctionBounds bounds{};
            const bool bounded = QueryRuntimeFunctionBounds(targetRva, &bounds);
            unsigned edgeLogs = 0;
            const OwnerFunctionSummary summary = ScanOwnerFunctionEdges(
                "SESSION_METHOD1_FORWARD_TARGET_FALLBACK",
                bounded ? bounds.beginRva : targetRva,
                0, g_sessionVCallCapture.forwardVtableRva, 1, 2, &edgeLogs);
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_FORWARD_TARGET_FALLBACK targetRva=0x%llX functionBeginRva=0x%llX functionEndRva=0x%llX directEdges=%u state2Edges=%u firstStateGetterCalls=%u bnetClusterEdges=%u\r\n",
                static_cast<unsigned long long>(targetRva),
                static_cast<unsigned long long>(bounded ? bounds.beginRva : targetRva),
                static_cast<unsigned long long>(bounded ? bounds.endRva : 0ull),
                summary.directEdges, summary.state2Edges, summary.getterCalls,
                summary.bnetClusterEdges);
        }

        if (g_sessionVCallCapture.invokeTargetRva &&
            IsExecutableImageRva(g_sessionVCallCapture.invokeTargetRva))
        {
            LogCodeContext("SESSION_METHOD1_INVOKE_TARGET_CODE",
                g_sessionVCallCapture.invokeTargetRva, 0, 64);
            const bool preserveReturnStub = IsSessionMethod1PreserveReturnStub(
                g_sessionVCallCapture.invokeTargetRva);
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_DELEGATE_RESOLVE dispatchRva=0x%llX functionFieldOffset=0x%llX functionVa=%p functionRva=0x%llX expectedFunctionRva=0x%llX functionMatch=%s contextFieldOffset=0x%llX context=%p expectedState=%p contextMatch=%s outerStateLinkMatch=%s aliasFieldsMatch=%s\r\n",
                static_cast<unsigned long long>(targetRva),
                static_cast<unsigned long long>(kSessionMethod1EmbeddedInvokeTargetOffset),
                reinterpret_cast<void*>(g_sessionVCallCapture.invokeTargetVa),
                static_cast<unsigned long long>(g_sessionVCallCapture.invokeTargetRva),
                static_cast<unsigned long long>(kSessionMethod1ObservedInvokeTargetRva),
                invokeTargetMatches ? "YES" : "no",
                static_cast<unsigned long long>(kSessionMethod1EmbeddedInvokeContextOffset),
                reinterpret_cast<void*>(g_sessionVCallCapture.invokeContextVa),
                reinterpret_cast<void*>(g_imageBase + kFirstStateRva),
                invokeContextMatches ? "YES" : "no",
                stateObjectMatches ? "YES" : "no",
                aliasFieldsMatch ? "YES" : "no");
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_INVOKE_TARGET_CLASSIFY rva=0x%llX classification=%s exactBytes=%s stateWriteInstructionsOnLivePath=%s next=%s\r\n",
                static_cast<unsigned long long>(g_sessionVCallCapture.invokeTargetRva),
                preserveReturnStub ? "OBFUSCATED_PRESERVE_AND_RETURN_DEFAULT_STUB" : "UNKNOWN",
                preserveReturnStub ? "YES" : "no",
                preserveReturnStub ? "none" : "unknown",
                preserveReturnStub ? "find_who_installs_default_stub" : "trace_invoke_target_execution");
        }
        else
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_DELEGATE_RESOLVE invokeTargetRva=0x%llX executable=no next=validate_delegate_object\r\n",
                static_cast<unsigned long long>(g_sessionVCallCapture.invokeTargetRva));
        }

        if (invokeTargetMatches)
            ScanSessionMethod1InvokeTargetXrefs();

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_FORWARD_TARGET_SUMMARY targetRva=0x%llX classification=%s state2Edges=0 stateLinkMatch=%s invokeTargetRva=0x%llX invokeContextMatch=%s next=identify_delegate_registration_owner\r\n",
            static_cast<unsigned long long>(targetRva),
            exactSecondLevelThunk ? "SECOND_LEVEL_DELEGATE_DISPATCH" : "UNKNOWN",
            stateObjectMatches ? "YES" : "no",
            static_cast<unsigned long long>(g_sessionVCallCapture.invokeTargetRva),
            invokeContextMatches ? "YES" : "no");
    }

    void AnalyzeSessionMethod1CallbackTarget() noexcept
    {
        const std::uintptr_t callbackRva = g_sessionVCallCapture.callbackRva;
        if (!callbackRva || !IsExecutableImageRva(callbackRva))
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_CALLBACK_TARGET imageResident=no callbackVa=%p callbackRva=0x%llX\r\n",
                reinterpret_cast<void*>(g_sessionVCallCapture.callbackVa),
                static_cast<unsigned long long>(callbackRva));
            return;
        }

        RuntimeFunctionBounds bounds{};
        const bool bounded = QueryRuntimeFunctionBounds(callbackRva, &bounds);
        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_CALLBACK_TARGET imageResident=yes callbackRva=0x%llX functionBeginRva=0x%llX functionEndRva=0x%llX fromUnwind=%s\r\n",
            static_cast<unsigned long long>(callbackRva),
            static_cast<unsigned long long>(bounded ? bounds.beginRva : callbackRva),
            static_cast<unsigned long long>(bounded ? bounds.endRva : 0u),
            bounded && bounds.fromUnwind ? "yes" : "no");

        // V17 requested 192 through a helper capped at 96, so no line printed.
        LogCodeContext("SESSION_METHOD1_CALLBACK_CODE", callbackRva, 0, 96);

        unsigned edgeLogs = 0;
        const OwnerFunctionSummary summary = ScanOwnerFunctionEdges(
            "SESSION_METHOD1_VCALL",
            bounded ? bounds.beginRva : callbackRva,
            0, g_sessionVCallCapture.vtable >= g_imageBase &&
                g_sessionVCallCapture.vtable < g_imageEnd
                ? g_sessionVCallCapture.vtable - g_imageBase : 0,
            1, 0, &edgeLogs);

        Log("[BGS-SESSION-COMP144] SESSION_METHOD1_CALLBACK_SUMMARY callbackRva=0x%llX directEdges=%u state2Edges=%u firstStateGetterCalls=%u state2Compares=%u bnetClusterEdges=%u next=map_callback_owner_to_auth_completion\r\n",
            static_cast<unsigned long long>(callbackRva),
            summary.directEdges, summary.state2Edges, summary.getterCalls,
            summary.state2Compares, summary.bnetClusterEdges);

        LogSessionObjectPointers();
        AnalyzeSessionMethod1ForwardTarget();
        Log("[BGS-SESSION-COMP144] V21_CORRECTION outerCallbackRva=0x%llX classification=FORWARDING_THUNK secondLevelRva=0x%llX secondLevelClassification=DELEGATE_DISPATCH invokeTargetRva=0x%llX invokeContext=%p V19BoundarySpillState2Edge=FALSE_POSITIVE ownerScanFromV18={writerA:0x%llX,writerB:0x%llX} no_state_modified=yes\r\n",
            static_cast<unsigned long long>(callbackRva),
            static_cast<unsigned long long>(g_sessionVCallCapture.forwardTargetRva),
            static_cast<unsigned long long>(g_sessionVCallCapture.invokeTargetRva),
            reinterpret_cast<void*>(g_sessionVCallCapture.invokeContextVa),
            static_cast<unsigned long long>(k144.BgsSessionServiceMethod1CallbackVtableWriterA),
            static_cast<unsigned long long>(k144.BgsSessionServiceMethod1CallbackVtableWriterB));
    }

    void LogSessionMethod1VCallCaptureIfReady() noexcept
    {
        if (InterlockedCompareExchange(&g_sessionPreCaptured, 0, 0) == 1 &&
            InterlockedCompareExchange(&g_sessionPreLogged, 1, 0) == 0)
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_VCALL PRE_HIT callRva=0x%llX firstState=%u object=%p r14=%p vtable=%p callbackVa=%p callbackRva=0x%llX args={rdx:%p r8:%p r9:%p} rsp=%p stockCallRestored=yes\r\n",
                static_cast<unsigned long long>(kPreVirtualCallbackRva),
                static_cast<unsigned>(g_sessionVCallCapture.stateAtPre),
                reinterpret_cast<void*>(g_sessionVCallCapture.object),
                reinterpret_cast<void*>(g_sessionVCallCapture.r14),
                reinterpret_cast<void*>(g_sessionVCallCapture.vtable),
                reinterpret_cast<void*>(g_sessionVCallCapture.callbackVa),
                static_cast<unsigned long long>(g_sessionVCallCapture.callbackRva),
                reinterpret_cast<void*>(g_sessionVCallCapture.rdx),
                reinterpret_cast<void*>(g_sessionVCallCapture.r8),
                reinterpret_cast<void*>(g_sessionVCallCapture.r9),
                reinterpret_cast<void*>(g_sessionVCallCapture.rsp));

            for (unsigned slot = 0; slot < kSessionCaptureVtableSlots; ++slot)
            {
                std::uintptr_t fn = 0;
                if (!SafeRead(g_sessionVCallCapture.vtable +
                    static_cast<std::uintptr_t>(slot) * sizeof(std::uintptr_t), &fn))
                    break;
                const bool image = fn >= g_imageBase && fn < g_imageEnd;
                Log("[BGS-SESSION-COMP144] SESSION_METHOD1_VTABLE slot=%u fn=%p rva=0x%llX executable=%s selected=%s\r\n",
                    slot, reinterpret_cast<void*>(fn),
                    static_cast<unsigned long long>(image ? fn - g_imageBase : 0u),
                    image && IsExecutableImageRva(fn - g_imageBase) ? "yes" : "no",
                    slot == 1 ? "YES" : "no");
            }

            LogCapturedStack("SESSION_METHOD1_PRE_STACK",
                g_sessionVCallCapture.preStack, kSessionCaptureStackQwords);
            AnalyzeSessionMethod1CallbackTarget();
        }

        if (InterlockedCompareExchange(&g_sessionPostCaptured, 0, 0) == 1 &&
            InterlockedCompareExchange(&g_sessionPostLogged, 1, 0) == 0)
        {
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_VCALL POST_HIT returnRva=0x%llX firstState=%u callbackRva=0x%llX returnRax=%p regs={rcx:%p rdx:%p r8:%p r9:%p} rsp=%p stockNopRestored=yes\r\n",
                static_cast<unsigned long long>(kPostVirtualCallbackRva),
                static_cast<unsigned>(g_sessionVCallCapture.stateAtPost),
                static_cast<unsigned long long>(g_sessionVCallCapture.callbackRva),
                reinterpret_cast<void*>(g_sessionVCallCapture.postRax),
                reinterpret_cast<void*>(g_sessionVCallCapture.postRcx),
                reinterpret_cast<void*>(g_sessionVCallCapture.postRdx),
                reinterpret_cast<void*>(g_sessionVCallCapture.postR8),
                reinterpret_cast<void*>(g_sessionVCallCapture.postR9),
                reinterpret_cast<void*>(g_sessionVCallCapture.postRsp));
            LogCapturedStack("SESSION_METHOD1_POST_STACK",
                g_sessionVCallCapture.postStack, kSessionCaptureStackQwords);
            LogSessionBufferDiff("SESSION_METHOD1_OBJECT_DIFF",
                g_sessionVCallCapture.preObject, g_sessionVCallCapture.postObject,
                sizeof(g_sessionVCallCapture.preObject),
                g_sessionVCallCapture.preObjectReadable,
                g_sessionVCallCapture.postObjectReadable);
            LogSessionBufferDiff("SESSION_METHOD1_RDX_DIFF",
                g_sessionVCallCapture.preRdxArg, g_sessionVCallCapture.postRdxArg,
                sizeof(g_sessionVCallCapture.preRdxArg),
                g_sessionVCallCapture.preRdxReadable,
                g_sessionVCallCapture.postRdxReadable);
            LogSessionBufferDiff("SESSION_METHOD1_R8_DIFF",
                g_sessionVCallCapture.preR8Arg, g_sessionVCallCapture.postR8Arg,
                sizeof(g_sessionVCallCapture.preR8Arg),
                g_sessionVCallCapture.preR8Readable,
                g_sessionVCallCapture.postR8Readable);
            LogSessionBufferDiff("SESSION_METHOD1_FORWARD_OBJECT_DIFF",
                g_sessionVCallCapture.preForwardObject,
                g_sessionVCallCapture.postForwardObject,
                sizeof(g_sessionVCallCapture.preForwardObject),
                g_sessionVCallCapture.preForwardReadable,
                g_sessionVCallCapture.postForwardReadable);
            LogSessionBufferDiff("SESSION_METHOD1_LINKED_STATE_DIFF",
                g_sessionVCallCapture.preLinkedState,
                g_sessionVCallCapture.postLinkedState,
                sizeof(g_sessionVCallCapture.preLinkedState),
                g_sessionVCallCapture.preLinkedStateReadable,
                g_sessionVCallCapture.postLinkedStateReadable);

            const std::intptr_t returnDelta =
                static_cast<std::intptr_t>(g_sessionVCallCapture.postRax) -
                static_cast<std::intptr_t>(g_sessionVCallCapture.object);
            Log("[BGS-SESSION-COMP144] SESSION_METHOD1_CALLBACK_CLASSIFY callbackRva=0x%llX observedVtableRva=0x%llX expectedVtableRva=0x%llX returnRax=%p object=%p returnDelta=%lld outerRole=FORWARDING_THUNK forwardTargetRva=0x%llX linkedStateMatch=%s stateAfter=%u\r\n",
                static_cast<unsigned long long>(g_sessionVCallCapture.callbackRva),
                static_cast<unsigned long long>(
                    g_sessionVCallCapture.vtable >= g_imageBase &&
                    g_sessionVCallCapture.vtable < g_imageEnd
                        ? g_sessionVCallCapture.vtable - g_imageBase : 0ull),
                static_cast<unsigned long long>(kSessionMethod1CallbackVtableRva),
                reinterpret_cast<void*>(g_sessionVCallCapture.postRax),
                reinterpret_cast<void*>(g_sessionVCallCapture.object),
                static_cast<long long>(returnDelta),
                static_cast<unsigned long long>(g_sessionVCallCapture.forwardTargetRva),
                g_sessionVCallCapture.linkedStateVa == g_imageBase + kFirstStateRva ? "YES" : "no",
                static_cast<unsigned>(g_sessionVCallCapture.stateAtPost));
        }
    }

    size_t ModRmEncodedLength(const BYTE* code, size_t bytes, size_t modrmIndex) noexcept
    {
        if (!code || modrmIndex >= bytes)
            return 0;

        const BYTE modrm = code[modrmIndex];
        const unsigned mod = (modrm >> 6) & 3u;
        const unsigned rmLow = modrm & 7u;
        size_t len = 1u; // ModRM
        unsigned sibBase = 0u;
        bool hasSib = false;

        if (mod != 3u && rmLow == 4u)
        {
            if (modrmIndex + len >= bytes)
                return 0;
            const BYTE sib = code[modrmIndex + len];
            sibBase = sib & 7u;
            hasSib = true;
            ++len;
        }

        if (mod == 0u)
        {
            if ((!hasSib && rmLow == 5u) || (hasSib && sibBase == 5u))
                len += 4u;
        }
        else if (mod == 1u)
        {
            len += 1u;
        }
        else if (mod == 2u)
        {
            len += 4u;
        }

        return modrmIndex + len <= bytes ? len : 0u;
    }


    struct State2HelperCandidate
    {
        std::uintptr_t targetRva = 0;
        unsigned argMask = 0;
        unsigned callCount = 0;
        unsigned depth = 0;
        std::uintptr_t firstCallRva = 0;
        std::uintptr_t accessorRva = 0;
        std::uintptr_t authOffset = 0;
    };

    State2HelperCandidate g_state2HelperCandidates[kState2HelperMaxCandidates]{};
    unsigned g_state2HelperCandidateCount = 0;

    void RecordState2HelperCandidate(
        std::uintptr_t targetRva,
        unsigned argMask,
        std::uintptr_t callRva,
        std::uintptr_t accessorRva,
        std::uintptr_t authOffset,
        unsigned depth) noexcept
    {
        if (!targetRva || !argMask || !IsExecutableImageRva(targetRva) || depth > 2u)
            return;

        for (unsigned i = 0; i < g_state2HelperCandidateCount; ++i)
        {
            State2HelperCandidate& c = g_state2HelperCandidates[i];
            if (c.targetRva == targetRva && c.depth == depth)
            {
                c.argMask |= argMask;
                ++c.callCount;
                return;
            }
        }

        if (g_state2HelperCandidateCount >= kState2HelperMaxCandidates)
            return;

        State2HelperCandidate& c = g_state2HelperCandidates[g_state2HelperCandidateCount++];
        c.targetRva = targetRva;
        c.argMask = argMask;
        c.callCount = 1;
        c.depth = depth;
        c.firstCallRva = callRva;
        c.accessorRva = accessorRva;
        c.authOffset = authOffset;
        Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_CANDIDATE hit=%u depth=%u targetRva=0x%llX argMask=0x%X firstCallRva=0x%llX accessorRva=0x%llX authOffset=0x%llX read_only=yes\r\n",
            g_state2HelperCandidateCount,
            depth,
            static_cast<unsigned long long>(targetRva),
            argMask,
            static_cast<unsigned long long>(callRva),
            static_cast<unsigned long long>(accessorRva),
            static_cast<unsigned long long>(authOffset));
    }

    void ScanState2HelperArgumentFlow(
        const State2HelperCandidate& candidate,
        unsigned* flowLogs,
        unsigned* writeHits,
        unsigned* forwardHits,
        unsigned* state2Edges) noexcept
    {
        if (!flowLogs || !writeHits || !forwardHits || !state2Edges ||
            *flowLogs >= kState2HelperMaxFlowLogs)
            return;

        RuntimeFunctionBounds bounds{};
        const bool bounded = QueryRuntimeFunctionBounds(candidate.targetRva, &bounds);
        std::uintptr_t beginRva = bounded ? bounds.beginRva : candidate.targetRva;
        std::uintptr_t endRva = bounded ? bounds.endRva : candidate.targetRva + kState2HelperFunctionScanBytes;
        if (candidate.targetRva < beginRva || candidate.targetRva >= endRva)
            beginRva = candidate.targetRva;

        size_t scanBytes = static_cast<size_t>(endRva - candidate.targetRva);
        if (scanBytes > kState2HelperFunctionScanBytes)
            scanBytes = kState2HelperFunctionScanBytes;
        if (!scanBytes || g_imageBase + candidate.targetRva + scanBytes > g_imageEnd)
            return;

        BYTE code[kState2HelperFunctionScanBytes]{};
        if (!SafeReadBytes(g_imageBase + candidate.targetRva, code, scanBytes))
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_FUNCTION targetRva=0x%llX depth=%u readable=no read_only=yes\r\n",
                static_cast<unsigned long long>(candidate.targetRva), candidate.depth);
            return;
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_FUNCTION targetRva=0x%llX depth=%u callCount=%u initialArgMask=0x%X functionBeginRva=0x%llX functionEndRva=0x%llX fromUnwind=%s scanBytes=0x%llX read_only=yes\r\n",
            static_cast<unsigned long long>(candidate.targetRva),
            candidate.depth, candidate.callCount, candidate.argMask,
            static_cast<unsigned long long>(bounded ? bounds.beginRva : candidate.targetRva),
            static_cast<unsigned long long>(bounded ? bounds.endRva : candidate.targetRva + scanBytes),
            bounded ? "yes" : "no",
            static_cast<unsigned long long>(scanBytes));
        LogCodeContext("AUTH_STATE2_HELPER_ENTRY_CONTEXT", candidate.targetRva, 0, scanBytes < 96u ? scanBytes : 96u);

        unsigned aliasMask = candidate.argMask;
        constexpr unsigned kArgMask = (1u << 1) | (1u << 2) | (1u << 8) | (1u << 9);
        constexpr unsigned kCallerSavedAliasMask =
            (1u << 0) | (1u << 1) | (1u << 2) | (1u << 8) |
            (1u << 9) | (1u << 10) | (1u << 11);
        unsigned localWrites = 0;
        unsigned localForwards = 0;
        unsigned localAliases = 0;
        unsigned localState2Edges = 0;

        for (size_t i = 0; i < scanBytes && *flowLogs < kState2HelperMaxFlowLogs; ++i)
        {
            size_t prefixLen = 0;
            BYTE rex = 0;
            while (i + prefixLen < scanBytes &&
                (code[i + prefixLen] == 0x66 || code[i + prefixLen] == 0xF2 || code[i + prefixLen] == 0xF3))
                ++prefixLen;
            if (i + prefixLen < scanBytes && code[i + prefixLen] >= 0x40 && code[i + prefixLen] <= 0x4F)
                rex = code[i + prefixLen++];
            if (i + prefixLen >= scanBytes)
                break;

            const size_t p = i + prefixLen;
            const BYTE op = code[p];
            const std::uintptr_t instructionRva = candidate.targetRva + i;

            if ((op == 0xE8 || op == 0xE9) && p + 5u <= scanBytes)
            {
                std::int32_t rel = 0;
                std::memcpy(&rel, code + p + 1u, sizeof(rel));
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(candidate.targetRva + p + 5u) + static_cast<std::intptr_t>(rel));
                const unsigned aliasArgs = aliasMask & kArgMask;
                const bool state2Edge = IsState2WindowRva(targetRva);

                if (aliasArgs && op == 0xE8 && IsExecutableImageRva(targetRva))
                {
                    ++localForwards;
                    ++(*forwardHits);
                    ++(*flowLogs);
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_ARG_FORWARD hit=%u depth=%u functionRva=0x%llX instructionRva=0x%llX targetRva=0x%llX argMask=0x%X authOffset=0x%llX read_only=yes\r\n",
                        *flowLogs, candidate.depth,
                        static_cast<unsigned long long>(candidate.targetRva),
                        static_cast<unsigned long long>(instructionRva),
                        static_cast<unsigned long long>(targetRva), aliasArgs,
                        static_cast<unsigned long long>(candidate.authOffset));
                    LogCodeContext("AUTH_STATE2_HELPER_FORWARD_CONTEXT", instructionRva, 24, 48);
                    if (candidate.depth < 2u)
                        RecordState2HelperCandidate(targetRva, aliasArgs, instructionRva,
                            candidate.accessorRva, candidate.authOffset, candidate.depth + 1u);
                }

                if (state2Edge)
                {
                    ++localState2Edges;
                    ++(*state2Edges);
                    ++(*flowLogs);
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_STATE2_EDGE hit=%u depth=%u functionRva=0x%llX instructionRva=0x%llX opcode=%s targetRva=0x%llX read_only=yes\r\n",
                        *flowLogs, candidate.depth,
                        static_cast<unsigned long long>(candidate.targetRva),
                        static_cast<unsigned long long>(instructionRva),
                        op == 0xE8 ? "CALL" : "JMP",
                        static_cast<unsigned long long>(targetRva));
                }

                if (op == 0xE8)
                {
                    aliasMask &= ~kCallerSavedAliasMask;
                    i += prefixLen + 5u - 1u;
                    continue;
                }
                break; // unconditional near JMP ends this linear path
            }

            if (op == 0xEB && p + 2u <= scanBytes)
                break;
            if (op == 0xC3 || op == 0xCB || op == 0xC2 || op == 0xCA)
                break;

            if (p + 2u > scanBytes)
                continue;
            const BYTE modrm = code[p + 1u];
            const unsigned mod = (modrm >> 6) & 3u;
            const unsigned reg = ((modrm >> 3) & 7u) | ((rex & 0x04u) ? 8u : 0u);
            const unsigned rm = (modrm & 7u) | ((rex & 0x01u) ? 8u : 0u);

            if (op == 0x8B || op == 0x89)
            {
                const size_t tail = ModRmEncodedLength(code, scanBytes, p + 1u);
                if (!tail)
                    continue;

                if (mod == 3u)
                {
                    if (op == 0x8B)
                    {
                        if (rm < 16u && reg < 16u && (aliasMask & (1u << rm)))
                        {
                            aliasMask |= 1u << reg;
                            ++localAliases;
                        }
                        else if (reg < 16u)
                            aliasMask &= ~(1u << reg);
                    }
                    else
                    {
                        if (reg < 16u && rm < 16u && (aliasMask & (1u << reg)))
                        {
                            aliasMask |= 1u << rm;
                            ++localAliases;
                        }
                        else if (rm < 16u)
                            aliasMask &= ~(1u << rm);
                    }
                    i += prefixLen + 1u + tail - 1u;
                    continue;
                }

                const bool sib = (modrm & 7u) == 4u;
                const bool rip = mod == 0u && (modrm & 7u) == 5u;
                if (op == 0x89 && !sib && !rip && rm < 16u && (aliasMask & (1u << rm)))
                {
                    ++localWrites;
                    ++(*writeHits);
                    ++(*flowLogs);
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_ARG_WRITE hit=%u depth=%u functionRva=0x%llX instructionRva=0x%llX kind=MOV_STORE argBaseReg=%u srcReg=%u authOffset=0x%llX read_only=yes\r\n",
                        *flowLogs, candidate.depth,
                        static_cast<unsigned long long>(candidate.targetRva),
                        static_cast<unsigned long long>(instructionRva), rm, reg,
                        static_cast<unsigned long long>(candidate.authOffset));
                    LogCodeContext("AUTH_STATE2_HELPER_WRITE_CONTEXT", instructionRva, 24, 48);
                }
                i += prefixLen + 1u + tail - 1u;
                continue;
            }

            if (op == 0x8D)
            {
                const size_t tail = ModRmEncodedLength(code, scanBytes, p + 1u);
                const bool sib = (modrm & 7u) == 4u;
                const bool rip = mod == 0u && (modrm & 7u) == 5u;
                if (tail && mod != 3u && !sib && !rip && rm < 16u && reg < 16u && (aliasMask & (1u << rm)))
                {
                    aliasMask |= 1u << reg;
                    ++localAliases;
                }
                else if (reg < 16u)
                    aliasMask &= ~(1u << reg);
                if (tail)
                    i += prefixLen + 1u + tail - 1u;
                continue;
            }

            if ((op == 0xC7 || op == 0xC6) && mod != 3u)
            {
                const size_t tail = ModRmEncodedLength(code, scanBytes, p + 1u);
                const size_t immLen = op == 0xC7 ? 4u : 1u;
                const bool sib = (modrm & 7u) == 4u;
                const bool rip = mod == 0u && (modrm & 7u) == 5u;
                if (tail && p + 1u + tail + immLen <= scanBytes &&
                    !sib && !rip && rm < 16u && (aliasMask & (1u << rm)))
                {
                    ++localWrites;
                    ++(*writeHits);
                    ++(*flowLogs);
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_ARG_WRITE hit=%u depth=%u functionRva=0x%llX instructionRva=0x%llX kind=%s argBaseReg=%u authOffset=0x%llX read_only=yes\r\n",
                        *flowLogs, candidate.depth,
                        static_cast<unsigned long long>(candidate.targetRva),
                        static_cast<unsigned long long>(instructionRva),
                        op == 0xC7 ? "IMM32_STORE" : "IMM8_STORE", rm,
                        static_cast<unsigned long long>(candidate.authOffset));
                    LogCodeContext("AUTH_STATE2_HELPER_WRITE_CONTEXT", instructionRva, 24, 48);
                }
                if (tail && p + 1u + tail + immLen <= scanBytes)
                    i += prefixLen + 1u + tail + immLen - 1u;
                continue;
            }

            // Common XMM stores such as MOVUPS/MOVDQU [arg+disp],xmmN.
            if (op == 0x0F && p + 3u <= scanBytes && (code[p + 1u] == 0x11 || code[p + 1u] == 0x7F))
            {
                const size_t tail = ModRmEncodedLength(code, scanBytes, p + 2u);
                const BYTE xmmModrm = code[p + 2u];
                const unsigned xmmMod = (xmmModrm >> 6) & 3u;
                const unsigned xmmRm = (xmmModrm & 7u) | ((rex & 0x01u) ? 8u : 0u);
                const bool sib = (xmmModrm & 7u) == 4u;
                const bool rip = xmmMod == 0u && (xmmModrm & 7u) == 5u;
                if (tail && xmmMod != 3u && !sib && !rip && xmmRm < 16u && (aliasMask & (1u << xmmRm)))
                {
                    ++localWrites;
                    ++(*writeHits);
                    ++(*flowLogs);
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_ARG_WRITE hit=%u depth=%u functionRva=0x%llX instructionRva=0x%llX kind=XMM_STORE argBaseReg=%u authOffset=0x%llX read_only=yes\r\n",
                        *flowLogs, candidate.depth,
                        static_cast<unsigned long long>(candidate.targetRva),
                        static_cast<unsigned long long>(instructionRva), xmmRm,
                        static_cast<unsigned long long>(candidate.authOffset));
                    LogCodeContext("AUTH_STATE2_HELPER_WRITE_CONTEXT", instructionRva, 24, 48);
                }
                if (tail)
                    i += prefixLen + 2u + tail - 1u;
                continue;
            }

            if (op == 0xFF)
            {
                const size_t tail = ModRmEncodedLength(code, scanBytes, p + 1u);
                const unsigned group = (modrm >> 3) & 7u;
                if (group == 2u)
                {
                    const unsigned aliasArgs = aliasMask & kArgMask;
                    if (aliasArgs)
                    {
                        ++localForwards;
                        ++(*forwardHits);
                        ++(*flowLogs);
                        Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_ARG_FORWARD hit=%u depth=%u functionRva=0x%llX instructionRva=0x%llX targetRva=INDIRECT argMask=0x%X authOffset=0x%llX read_only=yes\r\n",
                            *flowLogs, candidate.depth,
                            static_cast<unsigned long long>(candidate.targetRva),
                            static_cast<unsigned long long>(instructionRva), aliasArgs,
                            static_cast<unsigned long long>(candidate.authOffset));
                        LogCodeContext("AUTH_STATE2_HELPER_FORWARD_CONTEXT", instructionRva, 24, 48);
                    }
                    aliasMask &= ~kCallerSavedAliasMask;
                }
                if (tail)
                    i += prefixLen + 1u + tail - 1u;
                continue;
            }

            if (op == 0x83 || op == 0x81 || op == 0x80 || op == 0x85 || op == 0x39 || op == 0x3B)
            {
                const size_t tail = ModRmEncodedLength(code, scanBytes, p + 1u);
                size_t immLen = 0u;
                if (op == 0x83 || op == 0x80) immLen = 1u;
                if (op == 0x81) immLen = 4u;
                if (tail && p + 1u + tail + immLen <= scanBytes)
                    i += prefixLen + 1u + tail + immLen - 1u;
                continue;
            }
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_FUNCTION complete targetRva=0x%llX depth=%u aliases=%u writes=%u forwards=%u state2Edges=%u read_only=yes\r\n",
            static_cast<unsigned long long>(candidate.targetRva), candidate.depth,
            localAliases, localWrites, localForwards, localState2Edges);
    }

    void ScanState2HelperCandidates() noexcept
    {
        unsigned flowLogs = 0;
        unsigned writeHits = 0;
        unsigned forwardHits = 0;
        unsigned state2Edges = 0;
        Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_SCAN begin candidates=%u maxDepth=2 functionScanBytes=0x%llX mode=READ_ONLY_HELPER_ARGUMENT_FLOW\r\n",
            g_state2HelperCandidateCount,
            static_cast<unsigned long long>(kState2HelperFunctionScanBytes));

        // g_state2HelperCandidateCount can grow while scanning because a helper
        // may forward the tracked pointer to another helper. The hard candidate
        // cap + depth cap keeps this deterministic and bounded.
        for (unsigned i = 0; i < g_state2HelperCandidateCount && i < kState2HelperMaxCandidates; ++i)
            ScanState2HelperArgumentFlow(g_state2HelperCandidates[i], &flowLogs, &writeHits, &forwardHits, &state2Edges);

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_HELPER_SCAN complete candidates=%u flowLogs=%u writeHits=%u forwardHits=%u state2Edges=%u next=map_real_helper_writer_or_nested_completion_to_bgs_service no_code_modified=yes\r\n",
            g_state2HelperCandidateCount, flowLogs, writeHits, forwardHits, state2Edges);
    }

    void ScanState2AccessorPostCallUse(
        std::uintptr_t callRva,
        std::uintptr_t accessorRva,
        unsigned* useLogs,
        unsigned* writeHits,
        unsigned* aliasHits) noexcept
    {
        if (!useLogs || !writeHits || !aliasHits || *useLogs >= kState2AccessorMaxUseLogs)
            return;

        BYTE code[kState2AccessorPostCallScanBytes]{};
        const std::uintptr_t postRva = callRva + 5u;
        const std::uintptr_t postVa = g_imageBase + postRva;
        MEMORY_BASIC_INFORMATION postMbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(postVa), &postMbi, sizeof(postMbi)) != sizeof(postMbi) ||
            postMbi.State != MEM_COMMIT || !IsReadableMemoryProtection(postMbi.Protect))
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_POSTCALL unreadable=yes callRva=0x%llX accessorRva=0x%llX reason=page_not_readable read_only=yes\r\n",
                static_cast<unsigned long long>(callRva),
                static_cast<unsigned long long>(accessorRva));
            return;
        }

        RuntimeFunctionBounds bounds{};
        const bool functionBounded = QueryRuntimeFunctionBounds(callRva, &bounds);
        const std::uintptr_t postRegionEnd =
            reinterpret_cast<std::uintptr_t>(postMbi.BaseAddress) + static_cast<std::uintptr_t>(postMbi.RegionSize);
        size_t available = postRegionEnd > postVa ? static_cast<size_t>(postRegionEnd - postVa) : 0u;
        if (functionBounded && bounds.endRva > postRva)
        {
            const size_t functionAvailable = static_cast<size_t>(bounds.endRva - postRva);
            if (functionAvailable < available)
                available = functionAvailable;
        }

        const size_t bytesToRead = available < sizeof(code) ? available : sizeof(code);
        if (!bytesToRead || !SafeReadBytes(postVa, code, bytesToRead))
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_POSTCALL unreadable=yes callRva=0x%llX accessorRva=0x%llX reason=bounded_read_failed read_only=yes\r\n",
                static_cast<unsigned long long>(callRva),
                static_cast<unsigned long long>(accessorRva));
            return;
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_FUNCTION_BOUND callRva=0x%llX functionBeginRva=0x%llX functionEndRva=0x%llX fromUnwind=%s postScanBytes=0x%llX read_only=yes\r\n",
            static_cast<unsigned long long>(callRva),
            static_cast<unsigned long long>(functionBounded ? bounds.beginRva : 0u),
            static_cast<unsigned long long>(functionBounded ? bounds.endRva : 0u),
            functionBounded ? "yes" : "no",
            static_cast<unsigned long long>(bytesToRead));

        // Bit N means GPR N currently carries the accessor return value/address.
        // V15 fixes the main V14 false-positive source: caller-saved aliases are
        // dropped after every real CALL, and the scan is clipped to the x64
        // unwind function boundary when available.
        unsigned aliasMask = 1u << 0; // RAX is the accessor return.
        unsigned localUses = 0;
        unsigned localWrites = 0;
        unsigned localAliases = 0;
        unsigned callClobberResets = 0;
        constexpr unsigned kCallerSavedAliasMask =
            (1u << 0) | (1u << 1) | (1u << 2) | (1u << 8) |
            (1u << 9) | (1u << 10) | (1u << 11);

        for (size_t i = 0; i < bytesToRead && *useLogs < kState2AccessorMaxUseLogs; ++i)
        {
            // Direct near CALL. Validate that the destination is executable image
            // code before treating this byte as an instruction boundary. This
            // rejects many V14 rel32/immediate false alignments.
            if (code[i] == 0xE8 && i + 5u <= bytesToRead)
            {
                std::int32_t rel = 0;
                std::memcpy(&rel, code + i + 1u, sizeof(rel));
                const std::uintptr_t sourceRva = postRva + i;
                const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                    static_cast<std::intptr_t>(sourceRva + 5u) + static_cast<std::intptr_t>(rel));
                if (IsExecutableImageRva(targetRva))
                {
                    const unsigned aliasArgMask =
                        aliasMask & ((1u << 1) | (1u << 2) | (1u << 8) | (1u << 9));
                    const bool aliasInArg = aliasArgMask != 0;
                    if (aliasInArg)
                    {
                        ++localUses;
                        ++(*useLogs);
                        Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_USE hit=%u kind=CALL_WITH_RETURN_ALIAS_IN_ARG callRva=0x%llX accessorRva=0x%llX accessor=%s authOffset=0x%llX instructionRva=0x%llX targetRva=0x%llX functionBounded=%s read_only=yes\r\n",
                            *useLogs,
                            static_cast<unsigned long long>(callRva),
                            static_cast<unsigned long long>(accessorRva),
                            State2AccessorLabel(accessorRva),
                            static_cast<unsigned long long>(State2AccessorAuthOffset(accessorRva)),
                            static_cast<unsigned long long>(sourceRva),
                            static_cast<unsigned long long>(targetRva),
                            functionBounded ? "yes" : "no");
                        LogCodeContext("AUTH_STATE2_ACCESSOR_CALL_CONTEXT", sourceRva, 24, 48);
                        RecordState2HelperCandidate(
                            targetRva, aliasArgMask, sourceRva, accessorRva,
                            State2AccessorAuthOffset(accessorRva), 0u);
                    }

                    aliasMask &= ~kCallerSavedAliasMask;
                    ++callClobberResets;
                    if (State2AccessorLabel(targetRva) && IsState2AccessorAddressGetter(targetRva))
                        aliasMask |= 1u << 0;

                    i += 4u;
                    continue;
                }
            }

            // Unconditional control-flow exits end this linear path. Following
            // their targets would require a real CFG walker; stopping is safer
            // than attributing writes in unreachable bytes to the accessor.
            if (code[i] == 0xE9 && i + 5u <= bytesToRead)
                break;
            if (code[i] == 0xEB && i + 2u <= bytesToRead)
                break;

            // Short conditional branches preserve the fall-through path. Skip
            // the full instruction so its displacement cannot be decoded as an
            // opcode on the next iteration.
            if (code[i] >= 0x70 && code[i] <= 0x7F && i + 2u <= bytesToRead)
            {
                i += 1u;
                continue;
            }

            size_t p = i;
            BYTE rex = 0;
            if (code[p] >= 0x40 && code[p] <= 0x4F)
            {
                rex = code[p];
                ++p;
            }
            if (p >= bytesToRead)
                break;

            const BYTE op = code[p];
            if (p + 1u >= bytesToRead)
                continue;
            const BYTE modrm = code[p + 1u];
            const unsigned mod = (modrm >> 6) & 3u;
            const unsigned reg = ((modrm >> 3) & 7u) | ((rex & 0x04u) ? 8u : 0u);
            const unsigned rm = (modrm & 7u) | ((rex & 0x01u) ? 8u : 0u);
            const size_t prefixLen = p - i;

            // MOV r,r/m. 64-bit register-to-register moves can propagate an
            // address alias; narrower writes instead clear the destination alias.
            if (op == 0x8B)
            {
                const bool wide = (rex & 0x08u) != 0;
                if (mod == 3u)
                {
                    if (wide && rm < 16u && reg < 16u && (aliasMask & (1u << rm)) != 0)
                    {
                        if ((aliasMask & (1u << reg)) == 0)
                        {
                            aliasMask |= 1u << reg;
                            ++localAliases;
                            ++(*aliasHits);
                            ++localUses;
                            ++(*useLogs);
                            Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_USE hit=%u kind=REGISTER_ALIAS callRva=0x%llX accessorRva=0x%llX accessor=%s authOffset=0x%llX instructionRva=0x%llX srcReg=%u dstReg=%u functionBounded=%s read_only=yes\r\n",
                                *useLogs,
                                static_cast<unsigned long long>(callRva),
                                static_cast<unsigned long long>(accessorRva),
                                State2AccessorLabel(accessorRva),
                                static_cast<unsigned long long>(State2AccessorAuthOffset(accessorRva)),
                                static_cast<unsigned long long>(postRva + i),
                                rm, reg,
                                functionBounded ? "yes" : "no");
                        }
                    }
                    else if (reg < 16u)
                    {
                        aliasMask &= ~(1u << reg);
                    }
                    i += prefixLen + 2u - 1u;
                    continue;
                }

                if (reg < 16u)
                    aliasMask &= ~(1u << reg);
                const size_t tail = ModRmEncodedLength(code, bytesToRead, p + 1u);
                if (tail)
                    i += prefixLen + 1u + tail - 1u;
                continue;
            }

            // MOV r/m,r. A memory destination based on a tracked alias is a
            // same-function store candidate. Register destinations are handled
            // as alias propagation/overwrite so we do not fall into bytewise
            // scanning in the middle of the ModRM instruction.
            if (op == 0x89)
            {
                const bool wide = (rex & 0x08u) != 0;
                if (mod == 3u)
                {
                    if (wide && reg < 16u && rm < 16u && (aliasMask & (1u << reg)) != 0)
                    {
                        if ((aliasMask & (1u << rm)) == 0)
                        {
                            aliasMask |= 1u << rm;
                            ++localAliases;
                            ++(*aliasHits);
                        }
                    }
                    else if (rm < 16u)
                    {
                        aliasMask &= ~(1u << rm);
                    }
                    i += prefixLen + 2u - 1u;
                    continue;
                }

                const unsigned base = rm;
                const bool sib = (modrm & 7u) == 4u;
                const bool rip = mod == 0u && (modrm & 7u) == 5u;
                if (!sib && !rip && base < 16u && (aliasMask & (1u << base)) != 0)
                {
                    ++localWrites;
                    ++(*writeHits);
                    ++localUses;
                    ++(*useLogs);
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_USE hit=%u kind=MOV_STORE_THROUGH_RETURN callRva=0x%llX accessorRva=0x%llX accessor=%s authOffset=0x%llX instructionRva=0x%llX baseReg=%u srcReg=%u width=%s functionBounded=%s instructionBoundary=bounded_decoder read_only=yes\r\n",
                        *useLogs,
                        static_cast<unsigned long long>(callRva),
                        static_cast<unsigned long long>(accessorRva),
                        State2AccessorLabel(accessorRva),
                        static_cast<unsigned long long>(State2AccessorAuthOffset(accessorRva)),
                        static_cast<unsigned long long>(postRva + i),
                        base, reg, wide ? "64" : "32",
                        functionBounded ? "yes" : "no");
                    LogCodeContext("AUTH_STATE2_ACCESSOR_WRITE_CONTEXT", postRva + i, 24, 48);
                }
                const size_t tail = ModRmEncodedLength(code, bytesToRead, p + 1u);
                if (tail)
                    i += prefixLen + 1u + tail - 1u;
                continue;
            }

            // MOV r/m,imm through an alias base. ModRM-aware stepping avoids the
            // V14 FF C7 / 83 C6 false alignments that looked like C7/C6 stores.
            if ((op == 0xC7 || op == 0xC6) && mod != 3u)
            {
                const size_t tail = ModRmEncodedLength(code, bytesToRead, p + 1u);
                const size_t immLen = op == 0xC7 ? 4u : 1u;
                const unsigned base = rm;
                const bool sib = (modrm & 7u) == 4u;
                const bool rip = mod == 0u && (modrm & 7u) == 5u;
                if (tail && p + 1u + tail + immLen <= bytesToRead &&
                    !sib && !rip && base < 16u && (aliasMask & (1u << base)) != 0)
                {
                    ++localWrites;
                    ++(*writeHits);
                    ++localUses;
                    ++(*useLogs);
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_USE hit=%u kind=%s callRva=0x%llX accessorRva=0x%llX accessor=%s authOffset=0x%llX instructionRva=0x%llX baseReg=%u functionBounded=%s instructionBoundary=heuristic read_only=yes\r\n",
                        *useLogs, op == 0xC7 ? "IMM32_STORE_THROUGH_RETURN" : "IMM8_STORE_THROUGH_RETURN",
                        static_cast<unsigned long long>(callRva),
                        static_cast<unsigned long long>(accessorRva),
                        State2AccessorLabel(accessorRva),
                        static_cast<unsigned long long>(State2AccessorAuthOffset(accessorRva)),
                        static_cast<unsigned long long>(postRva + i),
                        base,
                        functionBounded ? "yes" : "no");
                    LogCodeContext("AUTH_STATE2_ACCESSOR_WRITE_CONTEXT", postRva + i, 24, 48);
                }
                if (tail && p + 1u + tail + immLen <= bytesToRead)
                    i += prefixLen + 1u + tail + immLen - 1u;
                continue;
            }

            // Common ModRM instructions that caused V14 byte-alignment noise.
            // We do not assign semantics here; we only skip their encoded bytes.
            if (op == 0xFF || op == 0x83 || op == 0x81 || op == 0x80 ||
                op == 0x85 || op == 0x39 || op == 0x3B || op == 0x8D)
            {
                const size_t tail = ModRmEncodedLength(code, bytesToRead, p + 1u);
                size_t immLen = 0u;
                if (op == 0x83 || op == 0x80) immLen = 1u;
                if (op == 0x81) immLen = 4u;

                // FF /2 is an indirect CALL: preserve only nonvolatile aliases.
                if (op == 0xFF && ((modrm >> 3) & 7u) == 2u)
                {
                    aliasMask &= ~kCallerSavedAliasMask;
                    ++callClobberResets;
                }

                if (tail && p + 1u + tail + immLen <= bytesToRead)
                    i += prefixLen + 1u + tail + immLen - 1u;
                continue;
            }

            // RET terminates the current control-flow path. Because V15 is now
            // function-bounded, this is a conservative early stop, not a scan
            // into the next function as happened in V14.
            if (op == 0xC3 || op == 0xCB)
                break;
            if ((op == 0xC2 || op == 0xCA) && p + 3u <= bytesToRead)
                break;
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_POSTCALL complete callRva=0x%llX accessorRva=0x%llX accessor=%s authOffset=0x%llX addressGetter=%s localUses=%u localWrites=%u localAliases=%u callClobberResets=%u functionBounded=%s functionBeginRva=0x%llX functionEndRva=0x%llX scanBytes=0x%llX read_only=yes\r\n",
            static_cast<unsigned long long>(callRva),
            static_cast<unsigned long long>(accessorRva),
            State2AccessorLabel(accessorRva),
            static_cast<unsigned long long>(State2AccessorAuthOffset(accessorRva)),
            IsState2AccessorAddressGetter(accessorRva) ? "yes" : "no",
            localUses, localWrites, localAliases, callClobberResets,
            functionBounded ? "yes" : "no",
            static_cast<unsigned long long>(functionBounded ? bounds.beginRva : 0u),
            static_cast<unsigned long long>(functionBounded ? bounds.endRva : 0u),
            static_cast<unsigned long long>(bytesToRead));
    }

    void ScanState2AccessorCallers() noexcept
    {
        unsigned callerLogs = 0;
        unsigned useLogs = 0;
        unsigned writeHits = 0;
        unsigned aliasHits = 0;
        unsigned readableRegions = 0;
        unsigned skippedRegions = 0;
        unsigned directCalls = 0;
        unsigned tailJumps = 0;

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_SCAN begin accessors={0x%llX:+A8_addr 0x%llX:+F0_load 0x%llX:+118_addr alias0x%llX:+A8_addr} postCallBytes=0x%llX mode=READ_ONLY_ACCESSOR_FUNCTION_BOUNDED_FLOW\r\n",
            static_cast<unsigned long long>(kState2Thunk16E0Rva),
            static_cast<unsigned long long>(kState2Thunk16F0Rva),
            static_cast<unsigned long long>(kState2Thunk17B0Rva),
            static_cast<unsigned long long>(kState2Thunk16E0AliasRva),
            static_cast<unsigned long long>(kState2AccessorPostCallScanBytes));

        const std::uintptr_t scanStartVa = g_imageBase + kBNetConsumerScanStartRva;
        const std::uintptr_t scanEndVa = g_imageBase + kBNetConsumerScanEndRva;
        std::uintptr_t cursor = scanStartVa;

        while (cursor < scanEndVa && callerLogs < kState2AccessorMaxCallerLogs)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi))
            {
                ++skippedRegions;
                cursor += 0x1000u;
                continue;
            }

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + static_cast<std::uintptr_t>(mbi.RegionSize);
            const std::uintptr_t boundedStart = cursor > regionBase ? cursor : regionBase;
            const std::uintptr_t boundedEnd = scanEndVa < regionEnd ? scanEndVa : regionEnd;
            if (mbi.State != MEM_COMMIT || !IsReadableMemoryProtection(mbi.Protect) || boundedEnd <= boundedStart)
            {
                ++skippedRegions;
                cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
                continue;
            }

            ++readableRegions;
            __try
            {
                const BYTE* code = reinterpret_cast<const BYTE*>(boundedStart);
                const size_t bytes = static_cast<size_t>(boundedEnd - boundedStart);
                for (size_t i = 0; i + 5 <= bytes && callerLogs < kState2AccessorMaxCallerLogs; ++i)
                {
                    if (code[i] != 0xE8 && code[i] != 0xE9)
                        continue;

                    std::int32_t rel = 0;
                    std::memcpy(&rel, code + i + 1, sizeof(rel));
                    const std::uintptr_t sourceVa = boundedStart + i;
                    const std::uintptr_t sourceRva = sourceVa - g_imageBase;
                    const std::uintptr_t targetRva = static_cast<std::uintptr_t>(
                        static_cast<std::intptr_t>(sourceRva + 5) + static_cast<std::intptr_t>(rel));
                    const char* label = State2AccessorLabel(targetRva);
                    if (!label)
                        continue;

                    ++callerLogs;
                    if (code[i] == 0xE8) ++directCalls; else ++tailJumps;
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_CALLER hit=%u sourceRva=0x%llX opcode=%s targetRva=0x%llX accessor=%s authOffset=0x%llX addressGetter=%s pageProtect=0x%08X boundary_unverified=yes read_only=yes\r\n",
                        callerLogs,
                        static_cast<unsigned long long>(sourceRva),
                        code[i] == 0xE8 ? "CALL" : "JMP",
                        static_cast<unsigned long long>(targetRva),
                        label,
                        static_cast<unsigned long long>(State2AccessorAuthOffset(targetRva)),
                        IsState2AccessorAddressGetter(targetRva) ? "yes" : "no",
                        static_cast<unsigned>(mbi.Protect));
                    LogCodeContext("AUTH_STATE2_ACCESSOR_CALLER_CONTEXT", sourceRva, 24, 48);

                    if (code[i] == 0xE8)
                        ScanState2AccessorPostCallUse(sourceRva, targetRva, &useLogs, &writeHits, &aliasHits);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ++skippedRegions;
                Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_SCAN_REGION_FAULT regionBase=%p regionSize=0x%llX protect=0x%08X continuing=yes read_only=yes\r\n",
                    mbi.BaseAddress, static_cast<unsigned long long>(mbi.RegionSize),
                    static_cast<unsigned>(mbi.Protect));
            }

            cursor = regionEnd > cursor ? regionEnd : cursor + 0x1000u;
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_ACCESSOR_SCAN complete callerLogs=%u directCalls=%u tailJumps=%u useLogs=%u writeHits=%u aliasHits=%u helperCandidates=%u readableRegions=%u skippedRegions=%u next=follow_pointer_into_helpers no_code_modified=yes\r\n",
            callerLogs, directCalls, tailJumps, useLogs, writeHits, aliasHits,
            g_state2HelperCandidateCount, readableRegions, skippedRegions);
        ScanState2HelperCandidates();
    }

    void ScanState2RuntimeOwnerDispatch() noexcept
    {
        BYTE authObject[kWatchBytes]{};
        const std::uintptr_t authBase = g_imageBase + kFirstStateRva;
        const bool authReadable = SafeReadBytes(authBase, authObject, sizeof(authObject));
        unsigned ownerTables = 0;
        unsigned directCallbacks = 0;
        unsigned tableEntries = 0;
        unsigned edgeLogs = 0;
        unsigned xrefLogs = 0;
        unsigned downstreamConsumers = 0;

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_DISPATCH begin authBase=%p authReadable=%s tableEntriesMax=%u functionScanBytes=0x%llX mode=READ_ONLY_RUNTIME_OWNER_CLASSIFICATION\r\n",
            reinterpret_cast<void*>(authBase), authReadable ? "yes" : "no", kState2OwnerMaxTableEntries,
            static_cast<unsigned long long>(kState2OwnerFunctionScanBytes));
        if (!authReadable)
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_DISPATCH complete ownerTables=0 directCallbacks=0 tableEntries=0 edgeLogs=0 xrefLogs=0 downstreamConsumers=0 next=retry_after_materialization no_code_modified=yes\r\n");
            return;
        }

        for (size_t off = 0; off + sizeof(std::uintptr_t) <= sizeof(authObject); off += sizeof(std::uintptr_t))
        {
            std::uintptr_t candidateVa = 0;
            std::memcpy(&candidateVa, authObject + off, sizeof(candidateVa));
            if (candidateVa < g_imageBase || candidateVa >= g_imageEnd)
                continue;
            const std::uintptr_t candidateRva = candidateVa - g_imageBase;
            ImageSectionView candidateSec{};
            if (!QueryImageSection(candidateRva, &candidateSec))
                continue;

            const std::uintptr_t ownerSlotRva = kFirstStateRva + off;
            if ((candidateSec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            {
                ++directCallbacks;
                const OwnerFunctionSummary summary = ScanOwnerFunctionEdges(
                    "AUTH_DIRECT_CALLBACK_FIELD", candidateRva, ownerSlotRva, 0, 0, 0, &edgeLogs);
                const bool downstream = summary.getterCalls != 0 && summary.state2Compares != 0;
                if (downstream) ++downstreamConsumers;
                Log("[BGS-SESSION-COMP144] AUTH_STATE2_DIRECT_CALLBACK_FIELD hit=%u authOffset=0x%llX ownerSlotRva=0x%llX functionRva=0x%llX section=%s directEdges=%u state2Edges=%u getterCalls=%u state2Compares=%u classification=%s read_only=yes\r\n",
                    directCallbacks, static_cast<unsigned long long>(off),
                    static_cast<unsigned long long>(ownerSlotRva), static_cast<unsigned long long>(candidateRva),
                    candidateSec.name, summary.directEdges, summary.state2Edges, summary.getterCalls, summary.state2Compares,
                    downstream ? "STATE2_CONSUMER_NOT_WRITER" : (summary.state2Edges ? "STATE2_PATH_CANDIDATE" : "UNCLASSIFIED_CALLBACK"));
                if (off == 0x318u || directCallbacks == 1u)
                    ScanRipRefsToOwnerTarget("AUTH_CALLBACK_SLOT", ownerSlotRva, off, &xrefLogs);
                continue;
            }

            const unsigned execEntries = CountExecutableTableEntries(candidateRva, 16u);
            if (execEntries < 4u)
                continue;

            ++ownerTables;
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_VTABLE_OWNER hit=%u authOffset=0x%llX ownerSlotRva=0x%llX tableRva=0x%llX section=%s execPointersFirst16=%u classification=IMAGE_FUNCTION_TABLE read_only=yes\r\n",
                ownerTables, static_cast<unsigned long long>(off),
                static_cast<unsigned long long>(ownerSlotRva), static_cast<unsigned long long>(candidateRva),
                candidateSec.name, execEntries);
            if (off == 0xA8u || ownerTables == 1u)
            {
                ScanRipRefsToOwnerTarget("AUTH_VTABLE_OWNER_SLOT", ownerSlotRva, off, &xrefLogs);
                ScanRipRefsToOwnerTarget("AUTH_VTABLE_ADDRESS", candidateRva, off, &xrefLogs);
            }

            for (unsigned index = 0; index < kState2OwnerMaxTableEntries; ++index)
            {
                std::uintptr_t functionVa = 0;
                if (!SafeRead(g_imageBase + candidateRva + static_cast<std::uintptr_t>(index) * sizeof(std::uintptr_t), &functionVa))
                    break;
                if (functionVa < g_imageBase || functionVa >= g_imageEnd)
                    continue;
                const std::uintptr_t functionRva = functionVa - g_imageBase;
                if (!IsExecutableImageRva(functionRva))
                    continue;
                ++tableEntries;
                const OwnerFunctionSummary summary = ScanOwnerFunctionEdges(
                    "AUTH_VTABLE_ENTRY", functionRva, ownerSlotRva, candidateRva, index, 0, &edgeLogs);
                const bool downstream = summary.getterCalls != 0 && summary.state2Compares != 0;
                if (downstream) ++downstreamConsumers;
                if (summary.state2Edges || downstream || summary.bnetClusterEdges)
                {
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_VTABLE_ENTRY tableRva=0x%llX index=%u functionRva=0x%llX directEdges=%u state2Edges=%u bnetClusterEdges=%u getterCalls=%u state2Compares=%u classification=%s read_only=yes\r\n",
                        static_cast<unsigned long long>(candidateRva), index,
                        static_cast<unsigned long long>(functionRva), summary.directEdges, summary.state2Edges,
                        summary.bnetClusterEdges, summary.getterCalls, summary.state2Compares,
                        downstream ? "STATE2_CONSUMER_NOT_WRITER" : (summary.state2Edges ? "STATE2_PATH_CANDIDATE" : "BNET_OWNER_METHOD"));
                }
            }
        }

        // The V11 run exposed +0xA8 as the strongest image function table and
        // +0x318 as a direct 0x464A840 callback. Emit an explicit observation
        // even if a future object layout changes so the log is self-checking.
        std::uintptr_t observedA8 = 0, observed318 = 0;
        std::memcpy(&observedA8, authObject + 0xA8, sizeof(observedA8));
        std::memcpy(&observed318, authObject + 0x318, sizeof(observed318));
        Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_OBSERVED authA8=%p authA8Rva=%s0x%llX auth318=%p auth318Rva=%s0x%llX expected318Consumer=0x464A840 read_only=yes\r\n",
            reinterpret_cast<void*>(observedA8),
            (observedA8 >= g_imageBase && observedA8 < g_imageEnd) ? "" : "n/a/",
            static_cast<unsigned long long>((observedA8 >= g_imageBase && observedA8 < g_imageEnd) ? observedA8 - g_imageBase : 0u),
            reinterpret_cast<void*>(observed318),
            (observed318 >= g_imageBase && observed318 < g_imageEnd) ? "" : "n/a/",
            static_cast<unsigned long long>((observed318 >= g_imageBase && observed318 < g_imageEnd) ? observed318 - g_imageBase : 0u));

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_OWNER_DISPATCH complete ownerTables=%u directCallbacks=%u tableEntries=%u edgeLogs=%u xrefLogs=%u downstreamConsumers=%u next=resolve_owner_initializers_then_map_server_side_completion no_code_modified=yes\r\n",
            ownerTables, directCallbacks, tableEntries, edgeLogs, xrefLogs, downstreamConsumers);
    }

    void ScanState2IndirectEntryTopology() noexcept
    {
        BYTE skip[2]{};
        BYTE directCall[5]{};
        const bool skipReadable = SafeReadBytes(g_imageBase + kState2DeadSkipJmpRva, skip, sizeof(skip));
        const bool callReadable = SafeReadBytes(g_imageBase + kState2DeadDirectCallRva, directCall, sizeof(directCall));
        std::uintptr_t skipTarget = 0;
        std::uintptr_t callTarget = 0;
        if (skipReadable && skip[0] == 0xEB)
        {
            const std::int8_t rel = static_cast<std::int8_t>(skip[1]);
            skipTarget = static_cast<std::uintptr_t>(
                static_cast<std::intptr_t>(kState2DeadSkipJmpRva + 2) + static_cast<std::intptr_t>(rel));
        }
        if (callReadable && directCall[0] == 0xE8)
        {
            std::int32_t rel = 0;
            std::memcpy(&rel, directCall + 1, sizeof(rel));
            callTarget = static_cast<std::uintptr_t>(
                static_cast<std::intptr_t>(kState2DeadDirectCallRva + 5) + static_cast<std::intptr_t>(rel));
        }
        const bool callSkipped = skipTarget > kState2DeadDirectCallRva && skipTarget >= kState2DeadDirectCallRva + 5;
        Log("[BGS-SESSION-COMP144] AUTH_STATE2_DIRECT_XREF_REACHABILITY skipJmpRva=0x%llX bytes={%02X %02X} skipTargetRva=0x%llX directCallRva=0x%llX callTargetRva=0x%llX expectedEntryRva=0x%llX callSkipped=%s conclusion=%s read_only=yes\r\n",
            static_cast<unsigned long long>(kState2DeadSkipJmpRva),
            static_cast<unsigned>(skip[0]), static_cast<unsigned>(skip[1]),
            static_cast<unsigned long long>(skipTarget),
            static_cast<unsigned long long>(kState2DeadDirectCallRva),
            static_cast<unsigned long long>(callTarget),
            static_cast<unsigned long long>(kState2SuccessEntryRva),
            callSkipped ? "YES" : "no",
            (callTarget == kState2SuccessEntryRva && callSkipped) ? "DIRECT_XREF_IS_SKIPPED_FALLTHROUGH" : "UNRESOLVED");

        BYTE precommit[10]{};
        const std::uintptr_t precommitRva = kState2SuccessWriterRva - 4;
        const bool precommitReadable = SafeReadBytes(g_imageBase + precommitRva, precommit, sizeof(precommit));
        Log("[BGS-SESSION-COMP144] AUTH_STATE2_PRECOMMIT bytesRva=0x%llX readable=%s bytes={%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X} expectedTail={9D 59 33 DB C7 01 02 00 00 00} ebxZeroBeforeCommit=%s immediateConditionalGate=none_in_final_4_bytes read_only=yes\r\n",
            static_cast<unsigned long long>(precommitRva), precommitReadable ? "yes" : "no",
            static_cast<unsigned>(precommit[0]), static_cast<unsigned>(precommit[1]),
            static_cast<unsigned>(precommit[2]), static_cast<unsigned>(precommit[3]),
            static_cast<unsigned>(precommit[4]), static_cast<unsigned>(precommit[5]),
            static_cast<unsigned>(precommit[6]), static_cast<unsigned>(precommit[7]),
            static_cast<unsigned>(precommit[8]), static_cast<unsigned>(precommit[9]),
            precommitReadable && precommit[0] == 0x9D && precommit[1] == 0x59 && precommit[2] == 0x33 && precommit[3] == 0xDB ? "YES" : "unknown");

        State2PointerSlot slots[128]{};
        unsigned slotCount = 0;
        unsigned scannedDataSections = 0;

        __try
        {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_imageBase);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_imageBase + static_cast<std::uintptr_t>(dos->e_lfanew));
            const IMAGE_SECTION_HEADER* first = IMAGE_FIRST_SECTION(nt);
            for (unsigned si = 0; si < nt->FileHeader.NumberOfSections; ++si)
            {
                const IMAGE_SECTION_HEADER& sec = first[si];
                if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                    continue;
                if ((sec.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == 0)
                    continue;

                const std::uintptr_t secRva = sec.VirtualAddress;
                size_t secSize = static_cast<size_t>(sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData);
                if (!secSize || secRva + secSize > static_cast<std::uintptr_t>(g_imageEnd - g_imageBase))
                    continue;
                if (secSize > 64u * 1024u * 1024u)
                {
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_PTR_SECTION skipRva=0x%llX size=0x%llX reason=too_large\r\n",
                        static_cast<unsigned long long>(secRva), static_cast<unsigned long long>(secSize));
                    continue;
                }

                char name[9]{};
                std::memcpy(name, sec.Name, 8);
                ++scannedDataSections;
                const BYTE* bytes = reinterpret_cast<const BYTE*>(g_imageBase + secRva);
                for (size_t off = 0; off + sizeof(std::uintptr_t) <= secSize; off += sizeof(std::uintptr_t))
                {
                    std::uintptr_t va = 0;
                    std::memcpy(&va, bytes + off, sizeof(va));
                    if (va < g_imageBase || va >= g_imageEnd)
                        continue;
                    const std::uintptr_t targetRva = va - g_imageBase;
                    const char* label = State2PointerTargetLabel(targetRva);
                    if (!label)
                        continue;
                    if (slotCount >= ArrayCount(slots))
                    {
                        Log("[BGS-SESSION-COMP144] AUTH_STATE2_PTR_SLOT limit=%u reached=yes\r\n", static_cast<unsigned>(ArrayCount(slots)));
                        break;
                    }
                    State2PointerSlot& out = slots[slotCount++];
                    out.slotRva = secRva + off;
                    out.targetRva = targetRva;
                    std::memcpy(out.section, name, sizeof(out.section));
                    Log("[BGS-SESSION-COMP144] AUTH_STATE2_PTR_SLOT hit=%u section=%s slotRva=0x%llX targetRva=0x%llX target=%s alignment=%llu read_only=yes\r\n",
                        slotCount, out.section,
                        static_cast<unsigned long long>(out.slotRva),
                        static_cast<unsigned long long>(out.targetRva), label,
                        static_cast<unsigned long long>(out.slotRva & 7ull));
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Log("[BGS-SESSION-COMP144] AUTH_STATE2_PTR_SCAN exception=yes partialSlots=%u\r\n", slotCount);
        }

        unsigned ripRefs = 0;
        if (slotCount)
        {
            __try
            {
                const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_imageBase);
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_imageBase + static_cast<std::uintptr_t>(dos->e_lfanew));
                const IMAGE_SECTION_HEADER* first = IMAGE_FIRST_SECTION(nt);
                for (unsigned si = 0; si < nt->FileHeader.NumberOfSections; ++si)
                {
                    const IMAGE_SECTION_HEADER& sec = first[si];
                    if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                        continue;
                    const std::uintptr_t secRva = sec.VirtualAddress;
                    const size_t secSize = static_cast<size_t>(sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData);
                    if (!secSize || secRva + secSize > static_cast<std::uintptr_t>(g_imageEnd - g_imageBase))
                        continue;
                    const BYTE* code = reinterpret_cast<const BYTE*>(g_imageBase + secRva);
                    for (size_t i = 0; i + 7 <= secSize; ++i)
                    {
                        size_t prefix = 0;
                        if (code[i] >= 0x40 && code[i] <= 0x4F)
                            prefix = 1;

                        const size_t op = i + prefix;
                        bool recognized = false;
                        const char* kind = nullptr;
                        size_t length = 0;
                        size_t dispOff = 0;

                        if (op + 6 <= secSize && (code[op] == 0x8B || code[op] == 0x8D))
                        {
                            const BYTE modrm = code[op + 1];
                            if (((modrm >> 6) & 3u) == 0u && (modrm & 7u) == 5u)
                            {
                                recognized = true;
                                kind = code[op] == 0x8B ? "MOV_RIP" : "LEA_RIP";
                                dispOff = op + 2;
                                length = prefix + 6;
                            }
                        }
                        else if (prefix == 0 && op + 6 <= secSize && code[op] == 0xFF && (code[op + 1] == 0x15 || code[op + 1] == 0x25))
                        {
                            recognized = true;
                            kind = code[op + 1] == 0x15 ? "CALL_PTR_RIP" : "JMP_PTR_RIP";
                            dispOff = op + 2;
                            length = 6;
                        }

                        if (!recognized)
                            continue;

                        std::int32_t disp = 0;
                        std::memcpy(&disp, code + dispOff, sizeof(disp));
                        const std::uintptr_t sourceRva = secRva + i;
                        const std::uintptr_t targetSlotRva = static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(sourceRva + length) + static_cast<std::intptr_t>(disp));
                        unsigned slotIndex = 0;
                        if (!MatchState2Slot(slots, slotCount, targetSlotRva, &slotIndex))
                            continue;
                        ++ripRefs;
                        const State2PointerSlot& slot = slots[slotIndex];
                        Log("[BGS-SESSION-COMP144] AUTH_STATE2_PTR_XREF hit=%u kind=%s instructionRva=0x%llX slotRva=0x%llX targetRva=0x%llX target=%s boundary_unverified=yes read_only=yes\r\n",
                            ripRefs, kind,
                            static_cast<unsigned long long>(sourceRva),
                            static_cast<unsigned long long>(slot.slotRva),
                            static_cast<unsigned long long>(slot.targetRva),
                            State2PointerTargetLabel(slot.targetRva));
                        LogCodeContext("AUTH_STATE2_PTR_XREF_CONTEXT", sourceRva, 24, 48);
                        if (ripRefs >= 256u)
                        {
                            Log("[BGS-SESSION-COMP144] AUTH_STATE2_PTR_XREF limit=256 reached=yes\r\n");
                            break;
                        }
                    }
                    if (ripRefs >= 256u)
                        break;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Log("[BGS-SESSION-COMP144] AUTH_STATE2_PTR_XREF_SCAN exception=yes partialHits=%u\r\n", ripRefs);
            }
        }

        Log("[BGS-SESSION-COMP144] AUTH_STATE2_INDIRECT_TOPOLOGY complete dataSections=%u pointerSlots=%u ripRelativeRefs=%u directEntryCallSkipped=%s next=runtime_dispatch_graph no_code_modified=yes\r\n",
            scannedDataSections, slotCount, ripRefs, callSkipped ? "YES" : "no");
        ScanState2RuntimeDispatchGraph();
        ScanState2RuntimeOwnerDispatch();
        ScanState2AccessorCallers();
    }

    bool AuthFlag7FlowSignatureReady() noexcept
    {
        BYTE gate[sizeof(kAuthFlag7GateExpected)]{};
        BYTE call[sizeof(kAuthFlag7AbsentCallExpected)]{};
        BYTE ret = 0;
        return SafeReadBytes(g_imageBase + kAuthFlag7GateRva, gate, sizeof(gate)) &&
            std::memcmp(gate, kAuthFlag7GateExpected, sizeof(gate)) == 0 &&
            SafeReadBytes(g_imageBase + kAuthFlag7AbsentCallRva, call, sizeof(call)) &&
            std::memcmp(call, kAuthFlag7AbsentCallExpected, sizeof(call)) == 0 &&
            SafeRead(g_imageBase + kAuthFlag7AbsentReturnRva, &ret) &&
            ret == kAuthFlag7AbsentReturnExpected;
    }

    bool SessionMethod1VCallSignatureReady() noexcept
    {
        BYTE pre[sizeof(kSessionVCallExpected)]{};
        BYTE post = 0;
        return SafeReadBytes(g_imageBase + kPreVirtualCallbackRva, pre, sizeof(pre)) &&
            std::memcmp(pre, kSessionVCallExpected, sizeof(pre)) == 0 &&
            SafeRead(g_imageBase + kPostVirtualCallbackRva, &post) &&
            post == kSessionPostExpected;
    }

    void RetryLiveObserversIfReady(bool& authFlag7ObserverArmed,
        bool& sessionVCallArmed, const char* phase, ULONGLONG elapsed) noexcept
    {
        (void)phase;
        (void)elapsed;
        authFlag7ObserverArmed = false;
        sessionVCallArmed = false;
        // Intentionally passive: no VEH installation and no executable-byte writes.
    }

    DWORD WINAPI ProbeWorker(LPVOID) noexcept
    {
        OpenTraceLog();
        g_imageBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        if (!ReadImageBounds(g_imageBase, &g_imageEnd))
        {
            Log("[BGS-SESSION-COMP144] SKIP exact MW2019 1.44 fingerprint not present\r\n");
            return 0;
        }

        Log(
            "[BGS-SESSION-COMP144] FOCUSED_MODE_V22 exact144=yes stateRva=0x%llX watchBytes=0x%llX waitForState1Ms=%llu traceAfterState1Ms=%llu pumpNonzeroJneRva=0x%llX pumpEarlyReturnRva=0x%llX authCommitWindow=0x%llX..0x%llX state2WriterRva=0x%llX state2Window=0x%llX..0x%llX instrumentation=PASSIVE_STATIC_ONLY int3=off veh=off debugRegisters=off executableWrites=off stateWrites=off\r\n",
            static_cast<unsigned long long>(kFirstStateRva),
            static_cast<unsigned long long>(kWatchBytes),
            static_cast<unsigned long long>(kWaitForState1Ms),
            static_cast<unsigned long long>(kTraceAfterState1Ms),
            static_cast<unsigned long long>(kFirstStatePumpNonzeroBranchRva),
            static_cast<unsigned long long>(kFirstStatePumpEarlyReturnEpilogueRva),
            static_cast<unsigned long long>(kAuthCommitWindowStartRva),
            static_cast<unsigned long long>(kAuthCommitWindowEndRva),
            static_cast<unsigned long long>(kState2SuccessWriterRva),
            static_cast<unsigned long long>(kState2SuccessWindowStartRva),
            static_cast<unsigned long long>(kState2SuccessWindowEndRva));

        Log("[BGS-SESSION-COMP144] PUMP_CORRECTION pumpRva=0x%llX nonzeroJneRva=0x%llX targetRva=0x%llX interpretation=COMMON_EARLY_RETURN_EPILOGUE not_state1_processor=yes read_only=yes\r\n",
            static_cast<unsigned long long>(kFirstStatePumpRva),
            static_cast<unsigned long long>(kFirstStatePumpNonzeroBranchRva),
            static_cast<unsigned long long>(kFirstStatePumpEarlyReturnEpilogueRva));
        LogV4CandidateCorrections();
        const AuthCommitSignature startupCommitSig = ReadAuthCommitSignature();
        LogAuthCommitSignature("startup_expected_protected_zero", 0, startupCommitSig);

        // V22 arms the two live paths BEFORE waiting for State 1. V21 armed
        // Method 1 only after expensive static scans, and the BGS replies raced
        // past the observer. The old installer-LEA observer is intentionally
        // disabled: V21's unique caller result reclassified 0x4641A60 as the
        // auth handler's bit-7-absent helper path, so the gate/call site is the
        // more meaningful runtime boundary.
        bool authFlag7ObserverArmed = false;
        bool sessionVCallArmed = false;
        RetryLiveObserversIfReady(authFlag7ObserverArmed, sessionVCallArmed, "startup", 0);
        if (!authFlag7ObserverArmed || !sessionVCallArmed)
            Log("[BGS-SESSION-COMP144] LIVE_OBSERVER_ARM disabled authFlag7=%s method1=%s reason=PASSIVE_STATIC_ONLY executionCoverage=NONE stateWrites=off\r\n",
                authFlag7ObserverArmed ? "ready" : "disabled", sessionVCallArmed ? "ready" : "disabled");

        const ULONGLONG waitStart = GetTickCount64();
        ULONGLONG nextWaitHeartbeat = kWaitHeartbeatMs;
        ULONGLONG nextObserverRetry = 100ull;
        bool sawState1 = false;
        AuthSnapshot state1Snapshot{};

        while (GetTickCount64() - waitStart < kWaitForState1Ms)
        {
            const ULONGLONG elapsed = GetTickCount64() - waitStart;
            if (elapsed >= nextObserverRetry && (!authFlag7ObserverArmed || !sessionVCallArmed))
            {
                RetryLiveObserversIfReady(authFlag7ObserverArmed, sessionVCallArmed, "waiting_state1", elapsed);
                nextObserverRetry = elapsed + 100ull;
            }
            LogAuthFlag7FlowCaptureIfReady();
            LogSessionMethod1VCallCaptureIfReady();
            const AuthSnapshot s = ReadSnapshot();
            if (s.readable && s.state == 1u)
            {
                state1Snapshot = s;
                sawState1 = true;
                break;
            }

            if (elapsed >= nextWaitHeartbeat)
            {
                LogSnapshot("waiting_for_state_1", elapsed, s);
                nextWaitHeartbeat += kWaitHeartbeatMs;
            }
            Sleep(2);
        }

        if (!sawState1)
        {
            const AuthSnapshot finalWait = ReadSnapshot();
            LogSnapshot("WAIT_TIMEOUT", GetTickCount64() - waitStart, finalWait);
            Log("[BGS-SESSION-COMP144] TIMEOUT waiting for natural firstState=1 after %llu ms; no auth/game state was modified\r\n",
                static_cast<unsigned long long>(kWaitForState1Ms));
            LogAuthFlag7FlowCaptureIfReady();
            LogSessionMethod1VCallCaptureIfReady();
            DisarmAuthFlag7FlowCapture();
            DisarmSessionMethod1VCallCapture();
            return 0;
        }

        const ULONGLONG traceStart = GetTickCount64();
        AuthSnapshot last = state1Snapshot;
        unsigned diffLines = 0;
        ULONGLONG nextHeartbeat = kTraceHeartbeatMs;
        ULONGLONG nextCommitReadyHeartbeat = 0;
        ULONGLONG nextTraceObserverRetry = 0;
        bool authCommitDumped = false;

        LogSnapshot("natural_state_1", 0, last);
        LogFocusedWindow("baseline_auth_result", 0, last, 0x180, 0x60);
        LogFocusedWindow("baseline_snapshot", 0, last, 0x2C0, 0x30);

        LogAuthFlag7FlowCaptureIfReady();
        LogSessionMethod1VCallCaptureIfReady();
        Log("[BGS-SESSION-COMP144] V22_PIVOT service=bnet.protocol.session.SessionService hash=0x%08X method=1 authResultHandler=0x%llX flag7Gate=0x%llX flag7AbsentBranch=0x%llX flag7AbsentHelperCall=0x%llX helperTarget=0x%llX method1Vcall=0x%llX knownResult=V21_unique_direct_caller_to_0x4641A60_is_flag7_absent_path heavyScansDeferred=yes authFlag7ObserverArmed=%s method1ObserverArmed=%s\r\n",
            static_cast<unsigned>(k144.BgsSessionServiceHash),
            static_cast<unsigned long long>(kAuthResultHandlerEntryRva),
            static_cast<unsigned long long>(kAuthFlag7GateRva),
            static_cast<unsigned long long>(kAuthFlag7AbsentBranchRva),
            static_cast<unsigned long long>(kAuthFlag7AbsentCallRva),
            static_cast<unsigned long long>(kAuthFlag7AbsentHelperTargetRva),
            static_cast<unsigned long long>(kPreVirtualCallbackRva),
            authFlag7ObserverArmed ? "yes" : "NO",
            sessionVCallArmed ? "yes" : "NO");

        while (GetTickCount64() - traceStart < kTraceAfterState1Ms)
        {
            const ULONGLONG elapsed = GetTickCount64() - traceStart;
            if (elapsed >= nextTraceObserverRetry && (!authFlag7ObserverArmed || !sessionVCallArmed))
            {
                RetryLiveObserversIfReady(authFlag7ObserverArmed, sessionVCallArmed, "after_state1", elapsed);
                nextTraceObserverRetry = elapsed + 100ull;
            }
            const AuthSnapshot now = ReadSnapshot();

            if (!authCommitDumped)
            {
                const AuthCommitSignature sig = ReadAuthCommitSignature();
                if (AuthCommitWindowMaterialized(sig))
                {
                    LogAuthCommitSignature("materialized_after_state1", elapsed, sig);
                    Log("[BGS-SESSION-COMP144] V22_FOCUSED_SKIP deep_state2_topology=yes reason=live_auth_result_flag7_and_method1_observers_active target=determine_missing_auth_response_flag_or_success_callback_route no_state_modified=yes\r\n");
                    authCommitDumped = true;
                }
                else if (elapsed >= nextCommitReadyHeartbeat)
                {
                    LogAuthCommitSignature("waiting_after_state1", elapsed, sig);
                    nextCommitReadyHeartbeat = elapsed + kAuthCommitReadyHeartbeatMs;
                }
            }

            LogAuthFlag7FlowCaptureIfReady();
            LogSessionMethod1VCallCaptureIfReady();

            const bool objectChanged = ObjectDifferent(last, now);
            const bool scalarChanged = ScalarDifferent(last, now);

            if (objectChanged)
            {
                diffLines = LogObjectDiffs(elapsed, last, now, diffLines);
                LogSnapshot("object_change", elapsed, now);
                last = now;
            }
            else if (scalarChanged)
            {
                LogSnapshot("scalar_change", elapsed, now);
                last = now;
            }
            else if (elapsed >= nextHeartbeat)
            {
                LogSnapshot("heartbeat", elapsed, now);
                nextHeartbeat += kTraceHeartbeatMs;
            }

            if (diffLines == kMaxDiffLines)
            {
                Log("[BGS-SESSION-COMP144] OBJECT_DIFF_LIMIT reached=%u; continuing scalar/state sampling without further byte-diff lines\r\n",
                    kMaxDiffLines);
                ++diffLines; // make the limit message one-shot
            }

            if (now.readable && (now.state == 2u || now.state == 3u))
            {
                LogSnapshot(now.state == 2u ? "TARGET_STATE_2" : "TARGET_STATE_3", elapsed, now);
                LogFocusedWindow("terminal_auth_result", elapsed, now, 0x180, 0x60);
                LogFocusedWindow("terminal_snapshot", elapsed, now, 0x2C0, 0x30);
                break;
            }

            Sleep(2);
        }

        const ULONGLONG finalElapsed = GetTickCount64() - traceStart;
        if (!authCommitDumped)
        {
            const AuthCommitSignature finalCommitSig = ReadAuthCommitSignature();
            LogAuthCommitSignature("trace_end_not_materialized", finalElapsed, finalCommitSig);
            Log("[BGS-SESSION-COMP144] AUTH_COMMIT_WINDOW TIMEOUT afterState1Ms=%llu dumpPerformed=no reason=protected_code_never_materialized_during_trace read_only=yes\r\n",
                static_cast<unsigned long long>(finalElapsed));
        }

        LogAuthFlag7FlowCaptureIfReady();
        LogSessionMethod1VCallCaptureIfReady();
        DisarmAuthFlag7FlowCapture();
        DisarmSessionMethod1VCallCapture();

        // Defer static work until all live network/callback timing has finished.
        // This avoids the V21 race where recv(236)/recv(64) completed while the
        // worker was dumping and scanning code before the Method-1 observer
        // had even been armed.
        DumpSessionMethod1DelegateInstaller();
        ScanSessionMethod1InstallerCallers();
        const unsigned state2SuccessXrefs = ScanState2SuccessEntryXrefs();

        const AuthSnapshot finalSnapshot = ReadSnapshot();
        LogSnapshot("final", finalElapsed, finalSnapshot);
        const bool flag7GateCaptured =
            InterlockedCompareExchange(&g_authFlag7GateCaptured, 0, 0) != 0;
        const bool flag7AbsentHelperCaptured =
            InterlockedCompareExchange(&g_authFlag7CallCaptured, 0, 0) != 0;
        const bool flag7AbsentHelperReturned =
            InterlockedCompareExchange(&g_authFlag7ReturnCaptured, 0, 0) != 0;
        const bool liveBit7 = (g_authFlag7Capture.flags10 & 0x80u) != 0u;

        Log(
            "[BGS-SESSION-COMP144] COMPLETE finalFirstState=%u diffLines=%u authCommitDumped=%s authFlag7ObserverArmed=%s authFlag7GateCaptured=%s flagsValid=%s flags10=0x%08X bit7=%u flag7AbsentHelperPre=%s flag7AbsentHelperPost=%s helperStateBefore=%u helperStateAfter=%u sessionVCallPre=%s sessionVCallPost=%s outerCallbackRva=0x%llX forwardTargetRva=0x%llX invokeTargetRva=0x%llX invokeTargetIsDefaultStub=%s invokeContextMatch=%s state2SuccessXrefs=%u mode=PASSIVE_STATIC_ONLY executionCoverage=NONE classification=INSUFFICIENT_EVIDENCE executableWrites=off stateWrites=off\r\n",
            static_cast<unsigned>(finalSnapshot.state),
            diffLines > kMaxDiffLines ? kMaxDiffLines : diffLines,
            authCommitDumped ? "yes" : "no",
            authFlag7ObserverArmed ? "yes" : "NO",
            flag7GateCaptured ? "yes" : "no",
            flag7GateCaptured ? "yes" : "no_UNKNOWN_NOT_ZERO",
            static_cast<unsigned>(g_authFlag7Capture.flags10),
            liveBit7 ? 1u : 0u,
            flag7AbsentHelperCaptured ? "yes" : "no",
            flag7AbsentHelperReturned ? "yes" : "no",
            static_cast<unsigned>(g_authFlag7Capture.stateAtHelperPre),
            static_cast<unsigned>(g_authFlag7Capture.stateAtHelperPost),
            InterlockedCompareExchange(&g_sessionPreCaptured, 0, 0) ? "yes" : "no",
            InterlockedCompareExchange(&g_sessionPostCaptured, 0, 0) ? "yes" : "no",
            static_cast<unsigned long long>(g_sessionVCallCapture.callbackRva),
            static_cast<unsigned long long>(g_sessionVCallCapture.forwardTargetRva),
            static_cast<unsigned long long>(g_sessionVCallCapture.invokeTargetRva),
            (g_sessionVCallCapture.invokeTargetRva && IsSessionMethod1PreserveReturnStub(g_sessionVCallCapture.invokeTargetRva)) ? "YES" : "no",
            g_sessionVCallCapture.invokeContextVa == g_imageBase + kFirstStateRva ? "YES" : "no",
            state2SuccessXrefs);
        return 0;
    }

    struct AutoStartProbe
    {
        AutoStartProbe() noexcept
        {
            if (InterlockedCompareExchange(&g_workerStarted, 1, 0) != 0)
                return;
            HANDLE thread = CreateThread(nullptr, 0, ProbeWorker, nullptr, 0, nullptr);
            if (thread)
                CloseHandle(thread);
        }
    };

    AutoStartProbe g_autoStartProbe;
}
