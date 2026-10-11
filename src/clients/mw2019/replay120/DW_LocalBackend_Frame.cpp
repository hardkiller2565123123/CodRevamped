// Authored source is imported through the Replay workstation revision API.
// Only the *_dw.exe build selects local endpoints. Other builds retain native values.
#include "com_debugstates.h"
#include "replay_dvar.h"
#include "DW_LocalConfig.h"
#include "DW_LocalProgression.h"

extern "C"
{
    void DW_ExecutableUpdate_Frame();
    void DW_LobbyControls_Frame();
    __declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void *, char *, unsigned long);
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) int __stdcall FreeLibrary(void *);
    __declspec(dllimport) void *__stdcall CreateThread(
        void *, size_t, unsigned long(__stdcall *)(void *), void *, unsigned long, unsigned long *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) void *__stdcall CreateFileA(
        const char *, unsigned long, unsigned long, void *, unsigned long, unsigned long, void *);
    __declspec(dllimport) int __stdcall WriteFile(
        void *, const void *, unsigned long, unsigned long *, void *);
}

// The native Replay getter instructions and buildAuthReq access establish this
// configuration prefix. Port getters originally read +0x424 / +0x826; the
// corresponding native address arrays occupy the preceding 1024 bytes.
#pragma pack(push, 1)

struct DWReplayLoginConfigPrefix
{
    unsigned char platformAndTitle[36];
    char authAddress[1024];
    uint16_t authPort;
    char lobbyAddress[1024];
    uint16_t lobbyPort;
};

#pragma pack(pop)
static_assert(offsetof(DWReplayLoginConfigPrefix, authAddress) == 36);
static_assert(offsetof(DWReplayLoginConfigPrefix, authPort) == 1060);
static_assert(offsetof(DWReplayLoginConfigPrefix, lobbyAddress) == 1062);
static_assert(offsetof(DWReplayLoginConfigPrefix, lobbyPort) == 2086);

namespace
{
    unsigned s_mode = 0;  // 0 unchecked, 1 native, 2 local DW build
    unsigned s_probe = 0; // 0 idle, 1 running, 2 transport ready, 3 unavailable
    unsigned s_reported = 0;
    bool s_registered = false;
    cmd_function_s s_statusCommand{}, s_probeCommand{};
    char s_response[2048]{};

    bool Contains(const char *text, const char *needle)
    {
        for (; *text; ++text)
        {
            unsigned i = 0;
            while (needle[i] && text[i] && text[i] == needle[i])
                ++i;
            if (!needle[i])
                return true;
        }
        return false;
    }

    void WriteLog(const char *message)
    {
        void *file = CreateFileA("replay-dw-client.log", 4, 3, nullptr, 4, 0x80, nullptr);
        if (file == reinterpret_cast<void *>(~uintptr_t{0}))
            return;
        unsigned long written = 0;
        unsigned length = 0;
        while (message[length])
            ++length;
        WriteFile(file, message, length, &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
        CloseHandle(file);
    }

    void WriteEndpointLog(const char *prefix, const char *suffix)
    {
        char message[256]{};
        const auto *host = DW_LocalConfig_Host();
        const char *parts[] = {prefix, *host ? host : "<invalid-config>", suffix};
        unsigned used = 0;
        for (const auto *part : parts)
            for (; *part && used + 1 < sizeof(message); ++part)
                message[used++] = *part;
        WriteLog(message);
    }

    unsigned long __stdcall ProbeThread(void *)
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
        using Send = int(__stdcall *)(Handle,
                                      const wchar_t *,
                                      unsigned long,
                                      void *,
                                      unsigned long,
                                      unsigned long,
                                      uintptr_t);
        using Receive = int(__stdcall *)(Handle, void *);
        using Headers = int(__stdcall *)(
            Handle, unsigned long, const wchar_t *, void *, unsigned long *, unsigned long *);
        using Read = int(__stdcall *)(Handle, void *, unsigned long, unsigned long *);
        using Close = int(__stdcall *)(Handle);
        void *library = LoadLibraryA("winhttp.dll");
        bool ok = false;
        s_response[0] = 0;
        if (library)
        {
            auto open = reinterpret_cast<Open>(GetProcAddress(library, "WinHttpOpen"));
            auto connect = reinterpret_cast<Connect>(GetProcAddress(library, "WinHttpConnect"));
            auto request = reinterpret_cast<Request>(GetProcAddress(library, "WinHttpOpenRequest"));
            auto timeouts =
                reinterpret_cast<Timeouts>(GetProcAddress(library, "WinHttpSetTimeouts"));
            auto send = reinterpret_cast<Send>(GetProcAddress(library, "WinHttpSendRequest"));
            auto receive =
                reinterpret_cast<Receive>(GetProcAddress(library, "WinHttpReceiveResponse"));
            auto headers =
                reinterpret_cast<Headers>(GetProcAddress(library, "WinHttpQueryHeaders"));
            auto read = reinterpret_cast<Read>(GetProcAddress(library, "WinHttpReadData"));
            auto close = reinterpret_cast<Close>(GetProcAddress(library, "WinHttpCloseHandle"));
            if (open && connect && request && timeouts && send && receive && headers && read &&
                close)
            {
                Handle session = open(L"IW8-Replay-LocalDW/1", 1, nullptr, nullptr, 0);
                Handle connection = nullptr, message = nullptr;
                if (session && timeouts(session, 1000, 1000, 1000, 1000))
                    connection = connect(session, DW_LocalConfig_WideHost(), 8085, 0);
                if (connection)
                    message = request(connection, L"GET", L"/health", nullptr, nullptr, nullptr, 0);
                if (message && send(message, nullptr, 0, nullptr, 0, 0, 0) &&
                    receive(message, nullptr))
                {
                    unsigned long status = 0, statusSize = sizeof(status);
                    if (headers(message, 0x20000013, nullptr, &status, &statusSize, nullptr) &&
                        status == 200)
                    {
                        unsigned used = 0;
                        bool complete = false;
                        while (used < sizeof(s_response) - 1)
                        {
                            unsigned long received = 0;
                            if (!read(message,
                                      s_response + used,
                                      static_cast<unsigned long>(sizeof(s_response) - 1 - used),
                                      &received))
                                break;
                            if (!received)
                            {
                                complete = true;
                                break;
                            }
                            used += received;
                        }
                        s_response[used] = 0;
                        ok = complete && Contains(s_response, "\"server\":\"iw8-dw\"") &&
                             Contains(s_response, "\"build\":\"replay120\"") &&
                             Contains(s_response, "\"stage\":\"transport-ready\"");
                    }
                }
                if (message)
                    close(message);
                if (connection)
                    close(connection);
                if (session)
                    close(session);
            }
            FreeLibrary(library);
        }
        WriteEndpointLog(ok ? "DW_LOCAL_PROBE_OK host=" : "DW_LOCAL_PROBE_FAILED host=",
                         ok ? ":8085 backend health reached; native authentication/tasks pending"
                            : ":8085 backend health unavailable; check this endpoint's server "
                              "and network access");
        __atomic_store_n(&s_probe, ok ? 2U : 3U, __ATOMIC_RELEASE);
        return 0;
    }
} // namespace

extern "C" bool DW_LocalBackend_IsEnabled()
{
    unsigned mode = __atomic_load_n(&s_mode, __ATOMIC_ACQUIRE);
    if (!mode)
    {
        char path[1024]{};
        const unsigned long length = GetModuleFileNameA(nullptr, path, sizeof(path));
        bool enabled = length >= 7 && length < sizeof(path);
        constexpr char suffix[] = "_dw.exe";
        for (unsigned i = 0; enabled && i < 7; ++i)
        {
            char c = path[length - 7 + i];
            if (c >= 'A' && c <= 'Z')
                c += 'a' - 'A';
            enabled = c == suffix[i];
        }
        mode = enabled ? 2U : 1U;
        __atomic_store_n(&s_mode, mode, __ATOMIC_RELEASE);
    }
    return mode == 2;
}

extern "C" uint16_t DW_LocalBackend_GetAuthPort(void *nativeConfig)
{
    auto *config = static_cast<DWReplayLoginConfigPrefix *>(nativeConfig);
    if (!DW_LocalBackend_IsEnabled())
        return config->authPort;
    // buildAuthReq calls this before formatting its HTTPS URL from authAddress.
    const auto *localAddress = DW_LocalConfig_Host();
    unsigned length = 0;
    while (localAddress[length])
        ++length;
    for (unsigned i = 0; i <= length; ++i)
        config->authAddress[i] = localAddress[i];
    return 8443;
}

extern "C" const char *DW_LocalBackend_GetLSGAddress(const void *nativeConfig)
{
    return DW_LocalBackend_IsEnabled()
               ? DW_LocalConfig_Host()
               : static_cast<const DWReplayLoginConfigPrefix *>(nativeConfig)->lobbyAddress;
}

extern "C" uint16_t DW_LocalBackend_GetLSGPort(const void *nativeConfig)
{
    return DW_LocalBackend_IsEnabled()
               ? 3075
               : static_cast<const DWReplayLoginConfigPrefix *>(nativeConfig)->lobbyPort;
}

extern "C" void DW_LocalBackend_Status_f()
{
    const unsigned state = __atomic_load_n(&s_probe, __ATOMIC_ACQUIRE);
    Com_Printf(
        25,
        "[DW LOCAL] external transport=%s; auth/tickets/tasks/profiles/matchmaking pending\n",
        state == 2   ? "ready"
        : state == 1 ? "probing"
                     : "unavailable");
    if (state == 2)
        Com_Printf(25, "[DW LOCAL] %s\n", s_response);
}

extern "C" void DW_LocalBackend_Probe_f()
{
    if (!DW_LocalBackend_IsEnabled())
        return;
    unsigned state = __atomic_load_n(&s_probe, __ATOMIC_ACQUIRE);
    if (state == 1 || !__atomic_compare_exchange_n(
                          &s_probe, &state, 1U, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    void *thread = CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr);
    if (thread)
        CloseHandle(thread);
    else
    {
        WriteLog("DW_LOCAL_PROBE_FAILED could not create probe thread");
        __atomic_store_n(&s_probe, 3U, __ATOMIC_RELEASE);
    }
}

extern "C" void DW_LocalBackend_Frame()
{
    if (!DW_LocalBackend_IsEnabled() || !Sys_IsMainThread())
        return;
    // Executable-enforced for every DW client, including after namespace or
    // game-mode resets. Resolve the registered native dvar rather than caching
    // a pointer across any deregistration/re-registration boundary.
    if (auto* tutorial = Dvar_FindVarByName("LSPSKLPNQT")) {
        if (tutorial->type == 0 && !tutorial->current.enabled) {
            DvarValue value{};
            value.enabled = true;
            Dvar_SetVariant(tutorial, &value, 0);
        }
    }
    DW_LocalProgression_Frame();
    DW_ExecutableUpdate_Frame();
    DW_LobbyControls_Frame();
    if (!s_registered)
    {
        // DW runs before Com_DebugStates_Frame. Initialize its default once;
        // subsequent com_debugStates commands can still enable the overlay.
        s_comDebugStates.enabled = 0;
        Cmd_AddCommandInternal("dw_localBackendStatus", DW_LocalBackend_Status_f, &s_statusCommand);
        Cmd_AddCommandInternal("dw_localBackendProbe", DW_LocalBackend_Probe_f, &s_probeCommand);
        WriteEndpointLog("DW_LOCAL_BUILD_INIT host=",
                         "; platform/auth HTTP=8085 native-auth=8443 lobby=3075; "
                         "workstation-compiled source active");
        s_registered = true;
        DW_LocalBackend_Probe_f();
    }
    const unsigned state = __atomic_load_n(&s_probe, __ATOMIC_ACQUIRE);
    if (state != 1 && state != s_reported)
    {
        s_reported = state;
        DW_LocalBackend_Status_f();
    }
}
