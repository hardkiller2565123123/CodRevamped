#include "dw_client_identity.h"
#include "com_debugstates.h"
#include "dw_platform_abi.h"
#include "dw_platform_protocol.h"
#include "replay_dvar.h"
#include "DW_LocalConfig.h"

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    uint64_t DW_LocalPlatform_Time();
    bool DW_LocalPlatform_MakeNonce(uint8_t *);
    bool DW_LocalPlatform_VerifyReply(const DWLocalPlatformReply *, const uint8_t *, uint64_t);
    bool DW_LocalResource_Fetch();
    void DW_LocalResource_Reset();
    bool Com_FrontEnd_IsInFrontEnd();
    void func_141526B50(unsigned); // Live_DemonwareDisconnectCleanup
    void func_1414F2FB0(unsigned); // DW_ResetLogon (retry state only)
    void func_141051630(void *,
                        unsigned char); // OnlineMgr::OnDisconnect (no NET_OfflineTransition)
    void func_141051740(void *, unsigned, unsigned); // OnlineMgr::OnSignedOut
    void func_1417ECE20(void *);                     // dwLogonHSM_xb3::OnUserSignout
    void func_141614830(void *);                     // dwLogOnHSM_base::HSM_Update (event queue)
    void func_1417EC990(unsigned);                   // native retry/backoff-aware logon request
    int func_1417EC930(unsigned);                    // dwGetLogOnStatus
    void func_1412BD8F0();                           // NET_OnlineTransition
    bool func_1412BD840();                           // NET_IsOffline
    bool func_1412BD890();                           // NET_IsStartFailed
    bool func_1412BD8A0();                           // NET_IsStarted
    void func_1412C0140(void *);                     // same-Replay NetRelay::Reset (one argument)
    void func_1412BF930(unsigned, bool);             // native NetRelay fence-dependency callback
    bool func_1414EFBA0();                           // dwNetIsRelayStarted
    bool func_1414EFBB0();                           // dwNetIsRelayStarting
    void func_1412BD540();                           // NET critical section enter
    void func_1412BD550();                           // NET critical section leave
    void *func_1414EEBA0();                          // native bdNetImpl singleton
    void *func_14217A520(void *);                    // native bdNetImpl socket-router getter
    void **func_142196200(void *);                   // native bound-relay reference getter
    bool func_14219F1C0(void *);                     // SDK relay disconnect (owns mutex/packet)
    extern void *s_instance_1;                       // native NetRelay singleton
    extern unsigned char gl_14C3851A0[], g_dwLogonHSMs[];
    extern dvar_t *DVARBOOL_online_signout_on_dw_disconnect_cleanup;
    DWPlatformAuth *func_141660280();
    DWPlatformAccount *func_1416702C0();
    void func_14165E580(); // native age/country fastfile policy, retained
    DWPlatformConnection *func_141662FC0();
    uint64_t func_1403E50B0(void *);
    void func_14165FA60(DWPlatformAuth *);
    uint8_t func_1413FDE80(unsigned, const char **);
    void func_1413E44F0(const uint32_t *, unsigned);  // native license/entitlement notification
    void func_1412976C0(unsigned, int, const char *); // same-Replay native command dispatch
    int Com_Keys_StringToKeynum(const char *);
    void CL_Keys_Event(int, int, bool, unsigned, unsigned, unsigned);
    unsigned Sys_Milliseconds();
    void func_1410C88F0(unsigned char, bool); // native Com_GameMode_SetDesiredGameMode
    void func_140D66AC0(int, int); // native CL_Mgr_ActivateClient, including notifications
    void *func_141B371E0();        // Online_Friends::GetInstance
    uint8_t func_140F54AE0(void *, unsigned, const char *, uint8_t);
    DWPlatformString *func_14038BAD0(DWPlatformString *, const char *, uint64_t);
    void func_1420F9380(void *, const char *);
    void func_1420F9330(void *, const char *);
    double func_1420F1050(uint64_t *);
    void func_1420F1090(uint64_t *);
    extern DWPlatformUser gl_14E5C0730[8];
    void *func_141670560(); // native Battle.net presence service
    uint8_t func_14166D610(void *, uint64_t, const uint32_t *, uint8_t *);
    uint8_t func_14166D6C0(void *, uint64_t, const uint32_t *, uint8_t *);
    void func_14166F3D0(void *, const uint32_t *, uint8_t);
    void func_141B95F20(int, unsigned); // native Social online-status change/delay
    uint8_t LUI_BeginEvent(unsigned, const char *, void *);
    uint64_t func_1419CE4F0(const char *, uint64_t, void *); // LuaShared_SetTableInt
    uint64_t func_1419BDA00(void *);                         // native LUI_EndEvent
    extern void *gl_151868880;
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) int __stdcall FreeLibrary(void *);
    __declspec(dllimport) void *__stdcall CreateThread(
        void *, size_t, unsigned long(__stdcall *)(void *), void *, unsigned long, unsigned long *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) unsigned long __stdcall WaitForSingleObject(void *, unsigned long);
    __declspec(dllimport) void *__stdcall CreateFileA(
        const char *, unsigned long, unsigned long, void *, unsigned long, unsigned long, void *);
    __declspec(dllimport) int __stdcall WriteFile(
        void *, const void *, unsigned long, unsigned long *, void *);
    __declspec(dllimport) int __stdcall ReadFile(
        void *, void *, unsigned long, unsigned long *, void *);
    __declspec(dllimport) uint64_t __stdcall GetTickCount64();
}

namespace
{
    unsigned s_state =
        0; // 0 idle, 1 pending, 2 signed provider response verified, 3 failed/expired
    DWLocalPlatformReply s_reply{};
    bool s_registered = false;
    unsigned s_onlineStatus = 2;    // Same-Replay: 1 Away, 2 Online, 3 Busy, 4 Offline.
    bool s_identityApplied = false; // engine thread only; native auth state alone is insufficient
    bool s_refreshIdentityHeld = false; // DW refresh must not sign out the local platform user
    cmd_function_s s_statusCommand{};
    cmd_function_s s_restartCommand{};
    enum class RestartPhase
    {
        Idle,
        Drain,
        Authenticate,
        Reconnect
    };
    RestartPhase s_restartPhase = RestartPhase::Idle; // main thread only
    uint64_t s_restartStarted = 0;
    bool s_restartDisconnectIssued = false;
    bool s_restartRelayStopIssued = false;
    void *s_loginThread = nullptr; // joined non-blockingly before credentials are reset
    void *s_renewThread = nullptr;
    unsigned s_renewState = 0; // 0 idle, 1 working, 2 verified, 3 failed
    uint64_t s_renewAttempt = 0;
    char s_renewToken[64]{};
    DWLocalPlatformReply s_renewReply{};
    cmd_function_s s_testKeyCommand{}, s_testMenuCommand{}, s_testFriendCommand{}, s_testRenewCommand{};
    void RenewFrame(bool force = false);
    unsigned s_testMode = 0;
    uint64_t s_testPoll = 0;
    uint32_t s_testRequest = 0;
    int s_testHeldKey = -1;
    uint64_t s_testReleaseAt = 0;
    DWPlatformWebRequest s_webRequests[4]{};
    unsigned s_webRequestCount = 0;

    unsigned State()
    {
        return __atomic_load_n(&s_state, __ATOMIC_ACQUIRE);
    }

    // Original bdSocketRouter::bindToRelay forwards its embedded routing layer
    // at +184. The native getter returns its owning bdReference, not a newly
    // acquired reference. Hold the game's NET lock while borrowing that owner;
    // the SDK disconnect also takes the association's own mutex. No credential,
    // SDK object state or DW network status is written here.
    constexpr size_t NativeSocketRouterRoutingLayerOffset = 184;

    bool DrainOldRelay()
    {
        if (!func_1414EFBA0() && !func_1414EFBB0())
            return true;
        if (!s_restartRelayStopIssued)
        {
            func_1412BD540();
            auto *router = static_cast<unsigned char *>(func_14217A520(func_1414EEBA0()));
            if (router)
            {
                auto **bound = func_142196200(router + NativeSocketRouterRoutingLayerOffset);
                if (bound && *bound)
                    func_14219F1C0(*bound);
            }
            func_1412BD550();
            s_restartRelayStopIssued = true;
        }
        // The normal network pump receives the authenticated disconnect reply
        // (or the SDK's bounded timeout) and calls dwRelayDisconnected. Yield
        // normal engine frames until that callback retires the old DW state.
        return false;
    }

    void Log(const char *message)
    {
        auto file = CreateFileA("replay-dw-client.log", 4, 3, nullptr, 4, 0x80, nullptr);
        if (file == reinterpret_cast<void *>(~uintptr_t{0}))
            return;
        unsigned long written = 0;
        char line[384]{}, digits[24]{};
        unsigned length = 0, count = 0;
        auto ticks = GetTickCount64();
        do
        {
            digits[count++] = static_cast<char>('0' + ticks % 10);
            ticks /= 10;
        } while (ticks);
        line[length++] = '[';
        while (count)
            line[length++] = digits[--count];
        for (const char *c = "ms] "; *c; ++c)
            line[length++] = *c;
        while (*message && length + 2 < sizeof(line))
            line[length++] = *message++;
        line[length++] = '\r';
        line[length++] = '\n';
        WriteFile(file, line, length, &written, nullptr);
        CloseHandle(file);
    }
} // namespace

extern "C" bool DW_LocalPlatform_CompleteWebCredential(const DWPlatformWebRequest *request,
                                                       const DWLocalPlatformPayload *payload,
                                                       bool valid)
{
    if (!request || !request->callback)
        return false;
    const bool accepted = valid && payload && request->audience == 1329875278U;
    DWPlatformString token{};
    if (accepted)
    {
        token.data = const_cast<char *>(payload->sessionToken);
        token.length = 64;
    }
    request->callback(accepted ? 0 : 1, &token, request->context);
    return accepted;
}

namespace
{
    void Copy(char *target, unsigned capacity, const char *value)
    {
        unsigned i = 0;
        while (i + 1 < capacity && value[i])
        {
            target[i] = value[i];
            ++i;
        }
        while (i < capacity)
            target[i++] = 0;
    }

    void TestKey_f()
    {
        if (s_testMode != 2 || Cmd_Argc() != 2 || s_testHeldKey >= 0)
            return;
        const int key = Com_Keys_StringToKeynum(Cmd_Argv(1));
        if (key <= 0 || key >= 222)
            return;
        s_testHeldKey = key;
        s_testReleaseAt = GetTickCount64() + 100;
        Log("DW_LOCAL_TEST_KEY native key-down queued; key-up follows on the engine thread");
        CL_Keys_Event(0, key, true, Sys_Milliseconds(), 0, 0);
    }

    void TestMenuMP_f()
    {
        if (s_testMode != 2 || Cmd_Argc() != 1)
            return;
        const auto mode = Com_GameMode_GetActiveGameMode();
        if (mode != 0 && mode != 2)
            return;
        // Developer selection through the same native mode/client transitions the
        // menu uses. No fence, permission, connection, or remote-task writes.
        if (mode == 0)
            func_1410C88F0(2, false);
        func_140D66AC0(0, 0);
        Log("DW_LOCAL_TEST_MENU_MP native mode/client selection dispatched");
    }

    void TestAddFriend_f()
    {
        if (s_testMode != 2 || Cmd_Argc() != 2 || State() != 2)
            return;
        // Same native entry point as Social.AddFriendCrossplay(controller, name,
        // platform). Platform zero selects UNO; native search and callback own
        // the invitation, asynchronous completion and LUI toast notification.
        const bool queued = func_140F54AE0(func_141B371E0(), 0, Cmd_Argv(1), 0) != 0;
        Log(queued ? "DW_LOCAL_TEST_FRIEND native name search queued"
                   : "DW_LOCAL_TEST_FRIEND native name search rejected");
    }

    void TestRenew_f()
    {
        if (s_testMode == 2 && Cmd_Argc() == 1 && Sys_IsMainThread())
            RenewFrame(true);
    }

    void TestFrame()
    {
        if (!Sys_IsMainThread())
            return;
        // Explicit opt-in for local development. Ordinary launches do no polling.
        // Execute through the native command parser on its owning thread; this
        // harness never modifies connection/fence/task state or writes game memory.
        if (!s_testMode)
        {
            auto file =
                CreateFileA(DW_LocalConfig_TestEnabled(), 0x80000000, 3, nullptr, 3, 0x80, nullptr);
            s_testMode = file == reinterpret_cast<void *>(~uintptr_t{0}) ? 1U : 2U;
            if (s_testMode == 2)
                CloseHandle(file);
        }
        if (s_testMode != 2)
            return;
        const auto ticks = GetTickCount64();
        if (s_testHeldKey >= 0 && ticks >= s_testReleaseAt)
        {
            const int key = s_testHeldKey;
            s_testHeldKey = -1;
            CL_Keys_Event(0, key, false, Sys_Milliseconds(), 0, 0);
        }
        if (ticks - s_testPoll < 500)
            return;
        s_testPoll = ticks;
        auto file =
            CreateFileA(DW_LocalConfig_TestCommand(), 0x80000000, 3, nullptr, 3, 0x80, nullptr);
        if (file == reinterpret_cast<void *>(~uintptr_t{0}))
            return;
        char request[512]{};
        unsigned long count = 0;
        const bool ok = ReadFile(file, request, sizeof(request) - 1, &count, nullptr) != 0;
        CloseHandle(file);
        if (!ok || count < 3 || count >= sizeof(request) - 1)
            return;
        uint32_t digest = 2166136261U;
        for (unsigned i = 0; i < count; ++i)
            digest = (digest ^ static_cast<unsigned char>(request[i])) * 16777619U;
        if (digest == s_testRequest)
            return;
        unsigned start = 0;
        while (request[start] >= '0' && request[start] <= '9')
            ++start;
        if (!start || request[start++] != ' ' || start >= count)
            return;
        for (unsigned i = start; i < count; ++i)
            if (request[i] < 32 || request[i] > 126 || request[i] == ';')
                return;
        s_testRequest = digest;
        Log("DW_LOCAL_TEST_COMMAND native main-thread command dispatched");
        // Separate clients share the diagnostic log, but acknowledge only their
        // own command channel. The request nonce is deliberately not a credential.
        char acknowledgement[160]{};
        const char *parts[] = {"DW_LOCAL_TEST_CHANNEL ", DW_LocalConfig_TestCommand()};
        unsigned used = 0;
        for (const auto *part : parts)
            for (; *part && used + 1 < sizeof(acknowledgement); ++part)
                acknowledgement[used++] = *part;
        Log(acknowledgement);
        func_1412976C0(0, 0, request + start);
    }
} // namespace

// Both provider exchanges use bounded, proxy-free localhost HTTP on the worker
// thread. Read exactly the expected size and reject a trailing response byte.
extern "C" bool DW_LocalPlatform_Post(
    const wchar_t *path, void *body, unsigned bodySize, void *output, unsigned outputSize)
{
    using Handle = void *;
    using Open = Handle(__stdcall *)(
        const wchar_t *, unsigned long, const wchar_t *, const wchar_t *, unsigned long);
    using Connect = Handle(__stdcall *)(Handle, const wchar_t *, unsigned short, unsigned long);
    using Request = Handle(__stdcall *)(Handle,
                                        const wchar_t *,
                                        const wchar_t *,
                                        const wchar_t *,
                                        const wchar_t *,
                                        const wchar_t **,
                                        unsigned long);
    using Timeouts = int(__stdcall *)(Handle, int, int, int, int);
    using Send = int(__stdcall *)(
        Handle, const wchar_t *, unsigned long, void *, unsigned long, unsigned long, uintptr_t);
    using Receive = int(__stdcall *)(Handle, void *);
    using Headers = int(__stdcall *)(
        Handle, unsigned long, const wchar_t *, void *, unsigned long *, unsigned long *);
    using Read = int(__stdcall *)(Handle, void *, unsigned long, unsigned long *);
    using Close = int(__stdcall *)(Handle);
    bool ok = false;
    auto library = LoadLibraryA("winhttp.dll");
    if (library && path && body && bodySize && output && outputSize)
    {
        auto open = reinterpret_cast<Open>(GetProcAddress(library, "WinHttpOpen"));
        auto connect = reinterpret_cast<Connect>(GetProcAddress(library, "WinHttpConnect"));
        auto request = reinterpret_cast<Request>(GetProcAddress(library, "WinHttpOpenRequest"));
        auto timeouts = reinterpret_cast<Timeouts>(GetProcAddress(library, "WinHttpSetTimeouts"));
        auto send = reinterpret_cast<Send>(GetProcAddress(library, "WinHttpSendRequest"));
        auto receive = reinterpret_cast<Receive>(GetProcAddress(library, "WinHttpReceiveResponse"));
        auto headers = reinterpret_cast<Headers>(GetProcAddress(library, "WinHttpQueryHeaders"));
        auto read = reinterpret_cast<Read>(GetProcAddress(library, "WinHttpReadData"));
        auto close = reinterpret_cast<Close>(GetProcAddress(library, "WinHttpCloseHandle"));
        if (open && connect && request && timeouts && send && receive && headers && read && close)
        {
            Handle session = open(L"IW8-Replay-LocalPlatform/1", 1, nullptr, nullptr, 0);
            Handle connection = nullptr, message = nullptr;
            if (session && timeouts(session, 10000, 10000, 10000, 10000))
                connection = connect(session, DW_LocalConfig_WideHost(), 8085, 0);
            if (connection)
                message = request(connection, L"POST", path, nullptr, nullptr, nullptr, 0);
            if (message &&
                send(message, DW_LocalConfig_Headers(), ~0UL, body, bodySize, bodySize, 0) &&
                receive(message, nullptr))
            {
                unsigned long status = 0, size = sizeof(status);
                if (headers(message, 0x20000013, nullptr, &status, &size, nullptr) && status == 200)
                {
                    unsigned used = 0;
                    bool complete = true;
                    while (used < outputSize)
                    {
                        unsigned long received = 0;
                        if (!read(message,
                                  reinterpret_cast<uint8_t *>(output) + used,
                                  outputSize - used,
                                  &received) ||
                            !received)
                        {
                            complete = false;
                            break;
                        }
                        used += received;
                    }
                    uint8_t extra = 0;
                    unsigned long received = 0;
                    ok = complete && used == outputSize && read(message, &extra, 1, &received) &&
                         !received;
                }
            }
            if (message)
                close(message);
            if (connection)
                close(connection);
            if (session)
                close(session);
        }
    }
    if (library)
        FreeLibrary(library);
    return ok;
}

namespace
{
    unsigned long __stdcall RenewThread(void *)
    {
        uint8_t nonce[32]{};
        DWLocalPlatformReply reply{};
        const bool ok = DW_LocalPlatform_MakeNonce(nonce) &&
                        DW_LocalIdentity_Renew(nonce, s_renewToken, &reply, DW_LocalPlatform_Post) &&
                        DW_LocalPlatform_VerifyReply(&reply, nonce, DW_LocalPlatform_Time());
        if (ok)
            s_renewReply = reply;
        // A renewal failure leaves the current signed session valid until its
        // own deadline. No sign-in callback, task or connection is reset here.
        __atomic_store_n(&s_renewState, ok ? 2U : 3U, __ATOMIC_RELEASE);
        return 0;
    }

    bool RenewalMatches()
    {
        const auto &candidate = s_renewReply.payload;
        if (candidate.expires <= s_reply.payload.expires ||
            candidate.expires <= DW_LocalPlatform_Time())
            return false;
        const auto *before = reinterpret_cast<const uint8_t *>(&s_reply.payload);
        const auto *after = reinterpret_cast<const uint8_t *>(&candidate);
        for (unsigned index = 0; index < sizeof(candidate); ++index)
        {
            // Only the challenge nonce and signed lifetime may change. The
            // complete remaining layout, including padding, stays identical.
            if (index >= offsetof(DWLocalPlatformPayload, nonce) &&
                index < offsetof(DWLocalPlatformPayload, userId))
                continue;
            if (before[index] != after[index])
                return false;
        }
        return true;
    }

    void RenewFrame(bool force)
    {
        if (!Sys_IsMainThread() || s_restartPhase != RestartPhase::Idle)
            return;
        const auto renewal = __atomic_load_n(&s_renewState, __ATOMIC_ACQUIRE);
        if (s_renewThread && renewal != 1)
        {
            const auto wait = WaitForSingleObject(s_renewThread, 0);
            if (wait != 0)
                return;
            CloseHandle(s_renewThread);
            s_renewThread = nullptr;
            if (renewal == 2 && State() == 2 && RenewalMatches())
            {
                // All account/token bytes are identical; publish the verified
                // nonce, signature and extended lifetime on the engine thread.
                s_reply = s_renewReply;
                Log("DW_LOCAL_PLATFORM_RENEWED signed session extended; native lobby and party retained");
            }
            else
                Log("DW_LOCAL_PLATFORM_RENEW_FAILED current signed session retained until expiry");
            __atomic_store_n(&s_renewState, 0U, __ATOMIC_RELEASE);
            return;
        }
        if (s_renewThread || State() != 2)
            return;
        const auto time = DW_LocalPlatform_Time();
        const auto ticks = GetTickCount64();
        if (time >= s_reply.payload.expires ||
            (!force && (s_reply.payload.expires - time > 300 ||
                        (s_renewAttempt && ticks - s_renewAttempt < 30000))))
            return;
        s_renewAttempt = ticks;
        for (unsigned i = 0; i < sizeof(s_renewToken); ++i)
            s_renewToken[i] = s_reply.payload.sessionToken[i];
        __atomic_store_n(&s_renewState, 1U, __ATOMIC_RELEASE);
        s_renewThread = CreateThread(nullptr, 0, RenewThread, nullptr, 0, nullptr);
        if (!s_renewThread)
        {
            __atomic_store_n(&s_renewState, 0U, __ATOMIC_RELEASE);
            Log("DW_LOCAL_PLATFORM_RENEW_FAILED worker creation failed; current session retained");
        }
        else
            Log("DW_LOCAL_PLATFORM_RENEW_BEGIN proving machine ownership of the current session");
    }

    unsigned long __stdcall LoginThread(void *)
    {
        uint8_t nonce[32]{};
        DWLocalPlatformReply reply{};
        bool ok = DW_LocalPlatform_MakeNonce(nonce);
        const char *failure = "windows-platform-nonce";
        if (ok)
        {
            ok = DW_LocalIdentity_Login(
                DW_LocalConfig_PlayerName(), nonce, &reply, DW_LocalPlatform_Post);
            failure = DW_LocalIdentity_Error();
        }
        if (ok)
        {
            ok = DW_LocalPlatform_VerifyReply(&reply, nonce, DW_LocalPlatform_Time());
            failure = "server-platform-reply-signature-or-expiry";
        }
        if (ok)
        {
            ok = DW_LocalResource_Fetch();
            failure = "server-platform-resource";
        }
        if (ok)
            s_reply = reply;
        else
            Log(failure);
        // The worker publishes data only. Native game objects are touched on the
        // engine thread after this release/acquire boundary.
        __atomic_store_n(&s_state, ok ? 2U : 3U, __ATOMIC_RELEASE);
        Log(ok ? "DW_LOCAL_PLATFORM_VERIFIED signed identity/session accepted; native DW login "
                 "remains authoritative"
               : "DW_LOCAL_PLATFORM_FAILED response unavailable, invalid, expired or signed by an "
                 "untrusted key");
        return 0;
    }

    void Start()
    {
        if (s_restartPhase == RestartPhase::Drain)
            return;
        unsigned idle = 0;
        if (!__atomic_compare_exchange_n(
                &s_state, &idle, 1U, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return;
        // Replay already writes config.cfg and settings.<platformId>.iw8 under
        // the player's Windows Documents directory. Its native cloud-sync opt-out
        // keeps that local GamerProfile authoritative, including on sign-in.
        // Set it before the profile callbacks; this affects only this process.
        using SetEnvironment = int(__stdcall *)(const char *, const char *);
        auto library = LoadLibraryA("kernel32.dll");
        auto setEnvironment = library ? reinterpret_cast<SetEnvironment>(
                                            GetProcAddress(library, "SetEnvironmentVariableA"))
                                      : nullptr;
        const bool localProfile = setEnvironment && setEnvironment("CODPC_NOCLOUD_SYNC", "1");
        if (library)
            FreeLibrary(library);
        if (!localProfile)
        {
            __atomic_store_n(&s_state, 3U, __ATOMIC_RELEASE);
            Log("DW_LOCAL_PROFILE_FAILED unable to select native local profile storage");
            return;
        }
        Log("DW_LOCAL_PROFILE native local settings/profile persistence selected");
        Log("DW_LOCAL_PLATFORM_BEGIN requesting nonce-bound local platform session");
        s_loginThread = CreateThread(nullptr, 0, LoginThread, nullptr, 0, nullptr);
        if (!s_loginThread)
        {
            __atomic_store_n(&s_state, 3U, __ATOMIC_RELEASE);
            Log("DW_LOCAL_PLATFORM_FAILED worker creation failed");
        }
    }

    bool Valid()
    {
        if (s_restartPhase == RestartPhase::Drain)
            return false;
        if (State() != 2)
            return false;
        if (DW_LocalPlatform_Time() < s_reply.payload.expires)
            return true;
        __atomic_store_n(&s_state, 3U, __ATOMIC_RELEASE);
        Log("DW_LOCAL_PLATFORM_EXPIRED run dw_restart to establish a new session");
        return false;
    }

    void WebCredentialFrame()
    {
        if (!s_webRequestCount || !Sys_IsMainThread())
            return;
        // Copy before invoking callbacks: a completion may enqueue another request.
        DWPlatformWebRequest completed[4]{};
        const auto count = s_webRequestCount;
        for (unsigned i = 0; i < count; ++i)
            completed[i] = s_webRequests[i];
        s_webRequestCount = 0;
        const bool valid = DW_LocalBackend_IsEnabled() && Valid();
        for (unsigned i = 0; i < count; ++i)
        {
            const auto &request = completed[i];
            if (!request.callback)
                continue;
            const bool accepted =
                DW_LocalPlatform_CompleteWebCredential(&request, &s_reply.payload, valid);
            Log(accepted ? "DW_LOCAL_WEB_CREDENTIAL native reconciliation callback completed with "
                           "issued credential"
                         : "DW_LOCAL_WEB_CREDENTIAL_FAILED unsupported audience or expired local "
                           "session");
        }
    }

    void Owned(DWPlatformProtectedFlag *flag)
    {
        if (flag->shift >= 32)
            return;
        uint32_t value = 1U << flag->shift;
        uint8_t *output = reinterpret_cast<uint8_t *>(&flag->encoded);
        for (unsigned i = 0; i < 4; ++i)
        {
            uint32_t salt =
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(output + i)) ^ flag->key;
            uint32_t product = salt * (salt + 2U);
            output[i] = static_cast<uint8_t>((value >> (i * 8)) ^ product ^ (product >> 8));
        }
    }

    void ApplyIdentityClaims(DWPlatformAuth *auth, const DWLocalPlatformPayload &p)
    {
        // The native platform getter returns ACCOUNT ID +24, not GAME ACCOUNT +24.
        // Keep both SDK objects' constructors/vtables and other entity fields.
        *reinterpret_cast<uint32_t *>(auth->accountId + 24) = p.gameAccountId;
        *reinterpret_cast<uint32_t *>(auth->gameAccountId + 24) = p.gameAccountId;
        auth->licenses[0] = (p.licenses & 1U) ? 51636U : 0U;
        auth->licenseCount = (p.licenses & 1U) ? 1U : 0U;
        Owned(&auth->ownership[2]);
        auth->tokenProcessed = 1;
        auto *user = &gl_14E5C0730[0];
        user->xuid = p.userId;
        Com_sprintf(user->xuidText, sizeof(user->xuidText), "%llu", p.userId);
        user->platformId = p.gameAccountId;
        Com_sprintf(user->platformIdText, sizeof(user->platformIdText), "%u", p.gameAccountId);
    }

    bool IdentityClaimsMatch(const DWPlatformAuth *auth, const DWLocalPlatformPayload &p)
    {
        return *reinterpret_cast<const uint32_t *>(auth->accountId + 24) == p.gameAccountId &&
               *reinterpret_cast<const uint32_t *>(auth->gameAccountId + 24) == p.gameAccountId &&
               auth->licenseCount == 1 && auth->licenses[0] == 51636 && auth->tokenProcessed &&
               gl_14E5C0730[0].platformId == p.gameAccountId;
    }
} // namespace

extern "C" void DW_LocalPlatform_RecordStage(const char *message)
{
    Log(message);
}

// The command queues work; native cleanup must never run reentrantly from a
// command callback or while the HTTP worker is publishing its reply.
extern "C" void DW_LocalPlatform_Restart_f()
{
    if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread())
        return;
    if (Cmd_Argc() != 1)
    {
        Com_Printf(25, "Usage: dw_restart\n");
        return;
    }
    if (s_restartPhase != RestartPhase::Idle)
    {
        Com_Printf(25, "[DW RESTART] Already running; dw_localPlatformStatus shows progress.\n");
        return;
    }
    s_restartStarted = GetTickCount64();
    s_refreshIdentityHeld =
        s_identityApplied && func_141660280()->state == 2 && gl_14E5C0730[0].signInState == 2;
    s_restartDisconnectIssued = false;
    s_restartRelayStopIssued = false;
    s_restartPhase = RestartPhase::Drain;
    Log("DW_RESTART_QUEUED waiting for frontend and existing provider worker");
    Com_Printf(
        25,
        "[DW RESTART] Queued. Any active match will disconnect; the game process stays open.\n");
}

extern "C" bool DW_LocalPlatform_RestartFrame()
{
    if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread() || s_restartPhase == RestartPhase::Idle)
        return false;
    const auto elapsed = GetTickCount64() - s_restartStarted;
    if (elapsed > (s_restartPhase == RestartPhase::Drain ? 30000U : 90000U))
    {
        Log("DW_RESTART_TIMEOUT restart monitor stopped; native connection state remains "
            "authoritative");
        Com_Printf(25,
                   "[DW RESTART] Timed out. Check the backend and dw_localPlatformStatus, then "
                   "retry dw_restart.\n");
        s_restartPhase = RestartPhase::Idle;
        return false;
    }
    if (s_restartPhase == RestartPhase::Drain)
    {
        if (!Com_FrontEnd_IsInFrontEnd())
        {
            if (!s_restartDisconnectIssued)
            {
                s_restartDisconnectIssued = true;
                func_1412976C0(0, 0, "disconnect");
            }
            return true;
        }
        if (s_renewThread)
        {
            const auto wait = WaitForSingleObject(s_renewThread, 0);
            if (wait == 258)
                return true;
            if (wait != 0)
            {
                Log("DW_RESTART_FAILED unable to join renewal worker; credentials retained");
                s_restartPhase = RestartPhase::Idle;
                return false;
            }
            CloseHandle(s_renewThread);
            s_renewThread = nullptr;
            s_renewAttempt = 0;
            __atomic_store_n(&s_renewState, 0U, __ATOMIC_RELEASE);
        }
        if (s_loginThread)
        {
            const auto wait = WaitForSingleObject(s_loginThread, 0);
            if (wait == 258)
                return true; // WAIT_TIMEOUT: do not block the engine
            if (wait != 0)
            {
                Log("DW_RESTART_FAILED unable to join provider worker; credentials retained");
                Com_Printf(25,
                           "[DW RESTART] Could not join the provider worker; restart cancelled.\n");
                s_restartPhase = RestartPhase::Idle;
                return false;
            }
            CloseHandle(s_loginThread);
            s_loginThread = nullptr;
        }
        if (!DVARBOOL_online_signout_on_dw_disconnect_cleanup)
        {
            Log("DW_RESTART_FAILED native online initialization has not registered its dvars yet");
            Com_Printf(25,
                       "[DW RESTART] Online initialization is not ready; retry from the menus.\n");
            s_restartPhase = RestartPhase::Idle;
            return false;
        }
        // Replay's original dwRelayStop is an XOR/RET stub. Clearing NetRelay
        // first leaves the old bound association alive and DW_NET_RELAY_STARTED
        // latched, so the native dependency callback refuses the new request.
        // Retire the old association through its native authenticated lifecycle
        // before cancelling tasks or resetting the credential owner.
        if (!DrainOldRelay())
            return false;
        if (s_restartRelayStopIssued)
            Log("DW_RESTART_RELAY_DRAINED old native relay association disconnected");
        // Complete outstanding SDK credential callbacks before native owners
        // are destroyed. Drain blocks new/reentrant requests and old tokens.
        WebCredentialFrame();
        const bool notified = DVARBOOL_online_signout_on_dw_disconnect_cleanup->current.enabled;
        if (!notified)
            func_141051740(gl_14C3851A0, 0, 1);
        func_141526B50(0);
        // Cleanup queues event 0 (auth error). Native sign-out queues event 1
        // (offline); drain both before another frame can submit a login task.
        func_1417ECE20(g_dwLogonHSMs);
        func_141614830(g_dwLogonHSMs);
        // A server-side disconnect can already have queued NET_OfflineTransition.
        // Restore networking through its native lifecycle after fresh credentials
        // are ready; retaining the platform identity does not retain NET mode.
        func_1414F2FB0(0);
        func_141051630(gl_14C3851A0, 0);
        // Relay credentials belong to the old DW session, even while native NET
        // remains online. Same-Replay Reset clears the SDK result through its
        // virtual assignment, auth state/expiry and retry timer. Native sign-out
        // above has cancelled the old tasks before this main-thread reset.
        if (s_instance_1)
        {
            func_1412C0140(s_instance_1);
            Log("DW_RESTART_RELAY_RESET native cached relay credential and retry state reset");
        }
        DW_LocalResource_Reset();
        s_reply = {};
        auto *auth = func_141660280();
        if (!s_refreshIdentityHeld)
        {
            s_identityApplied = false;
            auth->state = 1;
        }
        auth->failure = 0;
        auth->disconnected = 0;
        auth->queued = 0;
        auth->queuePosition = 0;
        auth->queueWait = 0;
        auto *account = func_1416702C0();
        if (!s_refreshIdentityHeld)
        {
            account->service.state = 0;
            account->gameTimeReady = 0;
        }
        auto *connection = func_141662FC0();
        if (!s_refreshIdentityHeld)
            connection->state = 1;
        connection->disconnectReason = 0;
        connection->retryCount = 0;
        connection->lastAttempt = 0;
        __atomic_store_n(&s_state, 0U, __ATOMIC_RELEASE);
        s_restartPhase = RestartPhase::Authenticate;
        s_restartStarted = GetTickCount64();
        Log("DW_RESTART_CLEANUP native tasks, login, lobby and online subsystems reset; requesting "
            "fresh credentials");
        Com_Printf(25,
                   "[DW RESTART] Native cleanup complete; requesting a fresh platform session.\n");
        Start();
    }
    else if (State() == 3)
    {
        Log("DW_RESTART_FAILED provider unavailable or rejected; dw_restart may be retried");
        Com_Printf(25,
                   "[DW RESTART] Platform login failed. Start/fix the backend, then run dw_restart "
                   "again.\n");
        s_restartPhase = RestartPhase::Idle;
    }
    else if (s_restartPhase == RestartPhase::Authenticate && Valid() && s_identityApplied)
    {
        s_restartPhase = RestartPhase::Reconnect;
        // Same operation as Live_OnlineServicesFence_Activate. The native routine
        // is a no-op when already online, otherwise it owns socket reset/start,
        // local-address initialization, relay/QoS and fence reevaluation.
        func_1412BD8F0();
        if (func_1417EC930(0) == 0)
            func_1417EC990(0);
        Log("DW_RESTART_RECONNECT fresh identity applied; waiting for native DW lobby "
            "authentication");
    }
    else if (s_restartPhase == RestartPhase::Reconnect && func_1412BD890())
    {
        Log("DW_RESTART_FAILED native network startup failed; native failure state retained");
        Com_Printf(25,
                   "[DW RESTART] Network startup failed. Check network/backend availability, "
                   "then retry dw_restart.\n");
        s_restartPhase = RestartPhase::Idle;
    }
    else if (s_restartPhase == RestartPhase::Reconnect && func_1417EC930(0) == 2 &&
             func_1412BD8A0() && !func_1412BD840())
    {
        // A fast same-server reconnect can retain the dependencies-met value
        // across Reset, so FenceManager has no false-to-true edge to dispatch.
        // Resume only the idle native relay through its own callback, with the
        // actual dependency value. That callback keeps relay enablement,
        // controller ownership and DW network-state gates authoritative.
        struct NativeFenceHeader
        {
            const void *vtable;
            unsigned controller;
            bool dependenciesMet;
            bool passing;
            bool failed;
            unsigned char reserved;
        };

        struct NativeRelayHeader
        {
            const void *vtable;
            void *netInit;
            bool callbackRegistered;
            unsigned char reserved[3];
            unsigned state;
        };

        static_assert(sizeof(NativeFenceHeader) == 16);
        static_assert(offsetof(NativeFenceHeader, dependenciesMet) == 12);
        static_assert(sizeof(NativeRelayHeader) == 24);
        static_assert(offsetof(NativeRelayHeader, state) == 20);
        const auto *fence = static_cast<const NativeFenceHeader *>(s_fenceObjects[5]);
        const auto *relay = static_cast<const NativeRelayHeader *>(s_instance_1);
        // Login can complete before QoS/publisher dependencies. Keep this phase
        // alive across normal engine frames instead of losing a one-shot check.
        // Returning false allows the native online domains to keep initializing.
        if (fence && relay && fence->controller == 0 && relay->state == 0 &&
            !fence->dependenciesMet)
            return false;
        if (fence && relay && fence->controller == 0 && fence->dependenciesMet && relay->state == 0)
        {
            func_1412BF930(0, fence->dependenciesMet);
            Log("DW_RESTART_RELAY_RESUME idle native relay dependency callback resumed");
        }
        s_refreshIdentityHeld = false;
        s_restartPhase = RestartPhase::Idle;
        Log("DW_RESTART_CONNECTED native DW login/lobby and online networking reconnected; online "
            "domains continue their "
            "native initialization");
        Com_Printf(25,
                   "[DW RESTART] Native DW lobby and networking reconnected. Online services are "
                   "reinitializing "
                   "normally.\n");
    }
    return false;
}

extern "C" void DW_LocalPlatform_Status_f()
{
    char status[256]{};
    Com_sprintf(status,
                sizeof(status),
                "DW_LOCAL_STATUS native=%d platform=%u auth=%u connection=%u user=%d mode=%d "
                "client=%u restart=%u",
                func_1417EC930(0),
                (s_refreshIdentityHeld || Valid()) && func_141660280()->state == 2,
                func_141660280()->state,
                func_141662FC0()->state,
                gl_14E5C0730[0].signInState,
                Com_GameMode_GetActiveGameMode(),
                CL_Mgr_IsClientActive(0),
                static_cast<unsigned>(s_restartPhase));
    Log(status);
    Com_Printf(25,
               "[DW RESTART] phase=%u (0 idle, 1 draining, 2 provider login, 3 DW reconnect); "
               "native DW status=%d\n",
               static_cast<unsigned>(s_restartPhase),
               func_1417EC930(0));
    const unsigned state = State();
    Com_Printf(25,
               "[DW LOCAL PLATFORM] provider=%s; native DW authentication/lobby services are "
               "independent\n",
               state == 2   ? "verified"
               : state == 1 ? "pending"
               : state == 3 ? "failed/expired"
                            : "idle");
    if (Valid())
        Com_Printf(25,
                   "[DW LOCAL PLATFORM] player=%s; account=%u; tokens expire=%llu\n",
                   s_reply.payload.name,
                   s_reply.payload.gameAccountId,
                   s_reply.payload.expires);
}

// Native ACCOUNT service (group 1) otherwise waits forever for SDK account
// notifications. Consume the same signed provider profile as authentication.
// Do not modify the Demonware fence, HSM, or other platform service groups.
extern "C" bool DW_LocalPlatform_ApplyAccountProfile(DWPlatformAccount *account,
                                                     const DWLocalPlatformPayload *payload)
{
    if (!account || !payload || payload->capabilities != 1 || payload->region != 1 ||
        payload->age < 18 || payload->age > 120 || payload->accountPolicy)
        return false;
    account->country = 0x5553; // native country-string packing: "US"
    account->age = payload->age;
    account->gameTimeReady = 1; // unrestricted local account has no timed-play quota
    account->service.state = 1;
    return true;
}

namespace
{
    uint64_t AccountFrame(DWPlatformAccount *account)
    {
        if (!account || !DW_LocalBackend_IsEnabled())
            return 0;
        if (s_refreshIdentityHeld && !Valid())
            return account->service.state;
        if (!Valid())
        {
            account->service.state = State() == 3 ? 2 : 0;
            return account->service.state;
        }
        const bool first = account->service.state != 1;
        if (!DW_LocalPlatform_ApplyAccountProfile(account, &s_reply.payload))
        {
            account->service.state = 2;
            return 2;
        }
        if (first)
            Log("DW_LOCAL_ACCOUNT_PROFILE signed country/age/play policy received; native account "
                "service completed");
        return 1;
    }
} // namespace

extern "C" uint64_t DW_LocalPlatform_UserId()
{
    return DW_LocalBackend_IsEnabled() && Valid() ? s_reply.payload.userId : 0;
}

// ACCOUNT initialize/sign-in/frame: these are the actual SDK request boundaries.
namespace
{
    bool CanCommunicate(const DWPlatformAccount *account)
    {
        // These three native getters otherwise read an absent launcher account
        // protobuf. The local provider's authenticated adult profile explicitly
        // grants unrestricted communication. Pending/expired profiles fail closed.
        return account && DW_LocalBackend_IsEnabled() && Valid() &&
               account == func_1416702C0() && account->service.state == 1 &&
               s_reply.payload.capabilities == 1 && s_reply.payload.accountPolicy == 0 &&
               s_reply.payload.age >= 18;
    }
}

extern "C" uint64_t func_14165D550(const DWPlatformAccount *account)
{
    return CanCommunicate(account);
}

extern "C" uint64_t func_14165D5E0(const DWPlatformAccount *account)
{
    return CanCommunicate(account);
}

extern "C" uint64_t func_14165DDB0(const DWPlatformAccount *account)
{
    return !CanCommunicate(account);
}

extern "C" uint64_t func_14165DD20(DWPlatformAccount *account)
{
    return AccountFrame(account);
}

extern "C" uint64_t func_14165DF30(DWPlatformAccount *account)
{
    return AccountFrame(account);
}

extern "C" uint64_t func_14165E230(DWPlatformAccount *account)
{
    return AccountFrame(account);
}

// The original asynchronous SDK request cannot finish without a launcher.
// Keep asynchronous completion on the engine thread and the original request
// counter. The native reconciliation callback still constructs the real 80/243
// task, and its real server response controls the reconciliation fence.
extern "C" uint64_t func_140C859F0(DWPlatformWebCredentials *manager,
                                   uint32_t audience,
                                   void (*callback)(int, const DWPlatformString *, void *),
                                   void *context)
{
    if (!manager || !callback)
        return ~uint64_t{0};
    const uint32_t id = manager->nextRequest++;
    if (!DW_LocalBackend_IsEnabled() || s_restartPhase == RestartPhase::Drain ||
        s_webRequestCount >= 4)
    {
        DWPlatformString empty{};
        callback(1, &empty, context);
        return id;
    }
    s_webRequests[s_webRequestCount++] = {id, audience, callback, context};
    return id;
}

// BattleNetConnection::Update. The DW image uses an actual local service
// connection instead of depending on launcher IPC or the Battle.net SDK pump.
extern "C" uint8_t func_141662F00(DWPlatformConnection *connection)
{
    if (!connection || !DW_LocalBackend_IsEnabled())
        return 0;
    Start();
    if (s_refreshIdentityHeld && !Valid())
        return static_cast<uint8_t>(connection->state);
    const unsigned state = State();
    connection->state = Valid() ? 2 : state == 3 ? 3 : 1;
    return static_cast<uint8_t>(connection->state);
}

// BattleNetConnection::Disconnect. DW_Frame passes 0x7ffffe00 when its lobby
// changes from connected to disconnected. That is a DW transport failure, not
// revocation of the independently verified local first-party session. The
// original SDK disconnect dereferences nativeClient; this provider has no SDK
// client. Keep DW's real disconnected HSM/task state and retry/error flow.
extern "C" uint64_t func_141662EE0(DWPlatformConnection *connection, uint32_t reason)
{
    if (!connection)
        return 0;
    if (!DW_LocalBackend_IsEnabled())
    {
        const uint32_t status = func_141662FC0()->state - 1U;
        if (status > 1U)
            return status;
        connection->disconnectReason = reason;
        return func_1403E50B0(connection->nativeClient);
    }
    if (connection->state != 1 && connection->state != 2)
        return connection->state - 1U;
    connection->disconnectReason = reason;
    if (reason == 0x7ffffe00U)
    {
        Log("DW_LOCAL_LOBBY_DISCONNECTED native DW retry/error flow retained; first-party provider "
            "session unchanged");
        connection->disconnectReason = 0;
    }
    else
    {
        s_refreshIdentityHeld = false; // A real platform disconnect still revokes identity.
        connection->state = 3;
        __atomic_store_n(&s_state, 3U, __ATOMIC_RELEASE);
        Log("DW_LOCAL_PLATFORM_DISCONNECTED local first-party connection failed");
        if (connection->callbackCount == 1 && connection->disconnectedCallback)
            connection->disconnectedCallback(reason);
        else if (connection->callbackCount)
            Log("DW_LOCAL_PLATFORM_FAILED unexpected native disconnect callback layout");
        connection->disconnectReason = 0;
    }
    return 0;
}

// Called only with a payload already authenticated by the provider. Isolating
// this complete native transition also permits compiled-code layout checks.
extern "C" bool DW_LocalPlatform_InitializeNativeIdentity(DWPlatformAuth *auth,
                                                          const DWLocalPlatformPayload *payload)
{
    if (!auth || !payload)
        return false;
    const auto &p = *payload;
    if (auth->callbackCount > 1 || (auth->callbackCount && !auth->signedInCallback))
    {
        auth->state = 3;
        auth->failure = 0x7fffff00U;
        Log("DW_LOCAL_PLATFORM_FAILED unexpected native auth callback layout");
        return false;
    }
    ApplyIdentityClaims(auth, p);
    unsigned nameLength = 0;
    while (p.name[nameLength])
        ++nameLength;
    func_14038BAD0(&auth->battleTag, p.name, nameLength);
    func_14038BAD0(&auth->clientId, "replaylocal", 11);
    func_14038BAD0(&auth->email, "local@localhost", 15);
    func_14038BAD0(&auth->geoIp, "US", 2);
    auth->queued = 0;
    auth->queuePosition = 0;
    auth->queueWait = 0;
    auth->disconnected = 0;
    auto *user = &gl_14E5C0730[0];
    Copy(user->name, sizeof(user->name), p.name);
    Copy(user->platformName, sizeof(user->platformName), p.name);
    // Set the latch before native callbacks, which may re-enter the provider.
    s_identityApplied = true;
    Log("DW_LOCAL_IDENTITY_CLAIMS account/platform ID and signed license applied; entering native "
        "callbacks");
    func_14165FA60(auth);
    Log("DW_LOCAL_SIGNIN_CALLBACK_RETURN native platform notification returned");
    // A locally logged-in profile may already be state 1. The registered
    // CheckSignIn callback handles state 0; use the real transition for state 1.
    if (user->signInState != 2)
    {
        const char *error = nullptr;
        func_1413FDE80(0, &error);
        Log("DW_LOCAL_PROFILE_TRANSITION_RETURN native online profile transition returned");
    }
    ApplyIdentityClaims(auth, p);
    func_1413E44F0(auth->licenses, auth->licenseCount);
    Log("DW_LOCAL_PLATFORM_SIGNED_IN native profile transition completed; requesting native DW "
        "login");
    return true;
}

// BattleNetAuth::BeginAuth. Uses native strings and native sign-in notification;
// no DW-ready bits, lobby objects or online-task results are manufactured here.
extern "C" void func_14165FFA0(DWPlatformAuth *auth)
{
    if (!auth || !DW_LocalBackend_IsEnabled())
        return;
    if (s_refreshIdentityHeld && !Valid())
        return;
    if (!Valid())
    {
        auth->state = State() == 3 ? 3 : 1;
        auth->failure = State() == 3 ? 0x7fffff00U : 0;
        return;
    }
    if (s_identityApplied)
    {
        // SDK token decoding can rewrite license state after local sign-in.
        // The verified local response owns these claims for its signed lifetime.
        // Repair claims only; never repeat sign-in callbacks or change DW fences.
        if (!IdentityClaimsMatch(auth, s_reply.payload))
        {
            ApplyIdentityClaims(auth, s_reply.payload);
            func_1413E44F0(auth->licenses, auth->licenseCount);
            Log("DW_LOCAL_IDENTITY_CLAIMS_RESTORED native ID/license cache refreshed from verified "
                "provider");
        }
        return;
    }
    DW_LocalPlatform_InitializeNativeIdentity(auth, &s_reply.payload);
}

// Platform frame. Local provider owns first-party authentication; SDK portal,
// launcher account-info and presence pumps cannot service a local session.
extern "C" DWPlatformAuth *func_141665AC0()
{
    auto *auth = func_141660280();
    if (!DW_LocalBackend_IsEnabled())
        return auth;
    TestFrame();
    if (!s_registered)
    {
        Cmd_AddCommandInternal(
            "dw_localPlatformStatus", DW_LocalPlatform_Status_f, &s_statusCommand);
        Cmd_AddCommandInternal("dw_restart", DW_LocalPlatform_Restart_f, &s_restartCommand);
        if (s_testMode == 2)
        {
            Cmd_AddCommandInternal("dw_localTestKey", TestKey_f, &s_testKeyCommand);
            Cmd_AddCommandInternal("dw_localTestMenuMP", TestMenuMP_f, &s_testMenuCommand);
            Cmd_AddCommandInternal("dw_localTestAddFriend", TestAddFriend_f, &s_testFriendCommand);
            Cmd_AddCommandInternal("dw_localTestRenew", TestRenew_f, &s_testRenewCommand);
        }
        s_registered = true;
    }
    if (DW_LocalPlatform_RestartFrame())
        return auth;
    RenewFrame();
    func_141662F00(func_141662FC0());
    func_14165FFA0(auth);
    func_14165E230(func_1416702C0());
    func_14165E580();
    WebCredentialFrame();
    return auth;
}

// First-party availability, not Demonware availability. Local license and
// account policy were supplied by the signed provider response.
extern "C" uint8_t func_1416659B0(int controller, int *reason)
{
    const bool ok = DW_LocalBackend_IsEnabled() && controller == 0 &&
                    (s_refreshIdentityHeld || Valid()) && func_141660280()->state == 2;
    if (reason)
        *reason = ok ? 0 : State() == 3 ? 12 : 1;
    return ok ? 1 : 0;
}

namespace
{
    unsigned PlatformOnlineStatus(uint64_t user, bool universalId)
    {
        const auto &local = gl_14E5C0730[0];
        const uint64_t ownId = universalId ? local.xuid : local.platformId;
        if (DW_LocalBackend_IsEnabled() && user && user == ownId)
            return func_1416659B0(0, nullptr) ? s_onlineStatus : 4;

        // Foreign accounts and native builds still use the original SDK cache.
        // Field 15 is connected, 8 invisible, 5 away and 7 busy. The two native
        // readers differ only in whether they first resolve a universal ID.
        auto read = universalId ? func_14166D610 : func_14166D6C0;
        auto *service = func_141670560();
        uint8_t values[4]{};
        const uint32_t fields[]{15, 8, 5, 7};
        for (unsigned index = 0; index < 4; ++index)
            read(service, user, &fields[index], &values[index]);
        if (!values[0] || values[1] || (values[2] && values[3]))
            return 4;
        return values[2] ? 1 : values[3] ? 3 : 2;
    }
} // namespace

// Keep the native UI and rich-presence callers; replace their first-party
// boundary because the launcher cache is not populated by the local provider.
extern "C" uint64_t func_140C88A30(uint64_t user)
{
    return PlatformOnlineStatus(user, true);
}

extern "C" uint64_t func_140C88B20(uint64_t user)
{
    return PlatformOnlineStatus(user, false);
}

extern "C" uint8_t func_140C88C10(unsigned status)
{
    if (status < 1 || status > 4)
        return 0;
    if (DW_LocalBackend_IsEnabled())
    {
        s_onlineStatus = status;
        Log("DW_LOCAL_PRESENCE native online-status selection retained by local provider");
    }
    else
    {
        const uint32_t fields[]{5, 7, 8};
        for (unsigned index = 0; index < 3; ++index)
            func_14166F3D0(func_141670560(),
                           &fields[index],
                           status == (index == 0   ? 1U
                                      : index == 1 ? 3U
                                                   : 4U));
    }
    // Preserve both native effects of the setter: schedule Social's normal
    // update and notify the menu. Its next presence update reads the same state.
    func_141B95F20(0, status);
    if (!LUI_BeginEvent(0, "bnet_online_status_set", gl_151868880))
        return 0;
    func_1419CE4F0("onlineStatus", status, gl_151868880);
    return static_cast<uint8_t>(func_1419BDA00(gl_151868880));
}

// bdLoginTaskFetchFirstPartyToken::pump. Preserve the real native task,
// vtable, result setters, stopwatch and normal success/failure state semantics.
extern "C" void func_14216AEB0(DWPlatformTokenTask *task)
{
    if (!task || task->state != 1)
        return;
    if (task->stage == 0)
    {
        func_1420F1090(&task->stopwatch);
        task->stage = 2;
        Copy(task->message, sizeof(task->message), "Waiting for local platform session");
        Start();
    }
    if (!DW_LocalBackend_IsEnabled() || State() == 3 || !task->result)
    {
        task->stage = 4;
        task->state = 2;
        Copy(task->message, sizeof(task->message), "Local platform token request failed");
        func_1420F1050(&task->stopwatch);
        Log("DW_LOCAL_PLATFORM_TOKENS_FAILED native first-party task failed");
        return;
    }
    if (!Valid())
        return;
    // Replay can fetch first-party tokens before running its platform frame.
    // Complete identity/license initialization before releasing those tokens
    // to DW's real login task, on the engine thread that owns these objects.
    if (!Sys_IsMainThread())
        return;
    func_141662F00(func_141662FC0());
    func_14165FFA0(func_141660280());
    func_14165E230(func_1416702C0());
    func_14165E580();
    if (!s_identityApplied || func_141660280()->state != 2)
    {
        task->stage = 4;
        task->state = 2;
        Copy(task->message, sizeof(task->message), "Local platform identity initialization failed");
        Log("DW_LOCAL_PLATFORM_TOKENS_FAILED native profile/license initialization failed");
        return;
    }
    func_1420F9380(task->result, s_reply.payload.sessionToken);
    func_1420F9330(task->result, s_reply.payload.accountToken);
    Copy(task->message, sizeof(task->message), "Fetched server-issued local platform tokens");
    task->stage = 5;
    task->state = 3;
    func_1420F1050(&task->stopwatch);
    Log("DW_LOCAL_PLATFORM_TOKENS native first-party task completed with issued session/account "
        "tokens");
}
