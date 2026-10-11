#include "DW_LocalConfig.h"
#include "com_debugstates.h"

extern "C"
{
    __declspec(dllimport) void *__stdcall CreateFileA(
        const char *, unsigned long, unsigned long, void *, unsigned long, unsigned long, void *);
    __declspec(dllimport) int __stdcall ReadFile(
        void *, void *, unsigned long, unsigned long *, void *);
    __declspec(dllimport) int __stdcall CloseHandle(void *);
    __declspec(dllimport) void __stdcall Sleep(unsigned long);
    __declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void *, char *, unsigned long);
}

namespace
{
    unsigned s_state = 0;
    char s_playerName[36]{};
    char s_host[64] = "127.0.0.1";
    wchar_t s_wideHost[64]{};
    wchar_t s_loginPath[96]{};
    wchar_t s_headers[256]{};
    char s_authUrl[128]{}, s_nativeAuthUrl[128]{}, s_legacyUrl[160]{};
    char s_public[64]{}, s_local[64]{};
    uint16_t s_gamePort = 3074;
    char s_testCommand[112] = "replay-dw-test.command";
    char s_testEnabled[112] = "replay-dw-test.enabled";
    bool s_fieldOverflow = false;
    bool s_unlockAll = false;
    unsigned s_rank = 0;

    bool IPv4(const char *value)
    {
        for (unsigned part = 0; part < 4; ++part)
        {
            unsigned n = 0, digits = 0;
            while (*value >= '0' && *value <= '9')
            {
                n = n * 10 + unsigned(*value++ - '0');
                if (++digits > 3 || n > 255)
                    return false;
            }
            if (!digits || (part < 3 ? *value++ != '.' : *value != 0))
                return false;
        }
        return true;
    }

    void Wide(wchar_t *out, const char *text)
    {
        do
        {
            *out++ = static_cast<unsigned char>(*text);
        } while (*text++);
    }

    void Join(char *out, const char *first, const char *second, const char *third)
    {
        const char *values[] = {first, second, third};
        for (const auto *text : values)
            while (*text)
                *out++ = *text++;
        *out = 0;
    }

    bool Field(const char *line, const char *key, char *out, unsigned capacity)
    {
        unsigned i = 0;
        while (key[i] && key[i] == line[i])
            ++i;
        if (key[i] || line[i++] != '=')
            return false;
        unsigned n = 0;
        while (line[i] && line[i] != '\r' && line[i] != '\n')
        {
            if (n + 1 >= capacity)
            {
                out[0] = 0;
                s_fieldOverflow = true;
                return true;
            }
            out[n++] = line[i++];
        }
        out[n] = 0;
        return true;
    }

    bool TestFilename(const char *value, const char *extension)
    {
        // Opt-in controls are simple leaves in the game working directory.
        // No absolute paths, parent traversal, streams or device filenames.
        constexpr char prefix[] = "replay-dw-test-";
        unsigned i = 0;
        for (; prefix[i]; ++i)
            if (value[i] != prefix[i])
                return false;
        const unsigned first = i;
        for (; value[i]; ++i)
        {
            if (!((value[i] >= 'a' && value[i] <= 'z') || (value[i] >= '0' && value[i] <= '9') ||
                  value[i] == '-' || value[i] == '.'))
                return false;
            if (value[i] == '.' && value[i + 1] == '.')
                return false;
        }
        unsigned length = 0;
        while (extension[length])
            ++length;
        if (i <= first + length)
            return false;
        for (unsigned at = 0; at < length; ++at)
            if (value[i - length + at] != extension[at])
                return false;
        return true;
    }

    void Load()
    {
        unsigned expected = 0;
        if (__atomic_compare_exchange_n(
                &s_state, &expected, 1U, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        {
            char port[8]{};
            bool customCommand = false, customEnabled = false;
            // An executable-specific file allows independent native test instances.
            // Normal guest installations use replay-dw.ini in the game folder.
            char executableIni[264]{};
            const auto length = GetModuleFileNameA(nullptr, executableIni, 260);
            void *file = reinterpret_cast<void *>(~uintptr_t{0});
            if (length > 4 && length < 260 && executableIni[length - 4] == '.')
            {
                executableIni[length - 3] = 'i';
                executableIni[length - 2] = 'n';
                executableIni[length - 1] = 'i';
                file = CreateFileA(executableIni, 0x80000000, 3, nullptr, 3, 0x80, nullptr);
            }
            if (file == reinterpret_cast<void *>(~uintptr_t{0}))
                file = CreateFileA("replay-dw.ini", 0x80000000, 3, nullptr, 3, 0x80, nullptr);
            if (file != reinterpret_cast<void *>(~uintptr_t{0}))
            {
                char text[2049]{};
                unsigned long count = 0;
                const bool read = ReadFile(file, text, sizeof(text) - 1, &count, nullptr) != 0;
                CloseHandle(file);
                if (!read || count >= sizeof(text) - 1)
                    s_host[0] = 0;
                else
                    // Editors commonly save UTF-8 with a BOM. It precedes the
                    // first key and must not turn a remote host into loopback.
                    for (unsigned at = count >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
                                               static_cast<unsigned char>(text[1]) == 0xBB &&
                                               static_cast<unsigned char>(text[2]) == 0xBF
                                           ? 3U
                                           : 0U;
                         at < count;)
                    {
                        Field(text + at, "host", s_host, sizeof(s_host));
                        Field(text + at, "public_address", s_public, sizeof(s_public));
                        Field(text + at, "local_address", s_local, sizeof(s_local));
                        Field(text + at, "game_port", port, sizeof(port));
                        Field(text + at, "player_name", s_playerName, sizeof(s_playerName));
                        char unlock[8]{}, rank[8]{};
                        if (Field(text + at, "unlock_all", unlock, sizeof(unlock)))
                        {
                            if ((unlock[0] != '0' && unlock[0] != '1') || unlock[1])
                                s_fieldOverflow = true;
                            else
                                s_unlockAll = unlock[0] == '1';
                        }
                        if (Field(text + at, "rank", rank, sizeof(rank)))
                        {
                            unsigned value = 0;
                            for (unsigned i = 0; rank[i]; ++i)
                                if (rank[i] < '0' || rank[i] > '9')
                                    s_fieldOverflow = true;
                                else
                                    value = value * 10 + unsigned(rank[i] - '0');
                            if (value > 55)
                                s_fieldOverflow = true;
                            else
                                s_rank = value;
                        }
                        customCommand |= Field(
                            text + at, "test_command_file", s_testCommand, sizeof(s_testCommand));
                        customEnabled |= Field(
                            text + at, "test_enabled_file", s_testEnabled, sizeof(s_testEnabled));
                        while (at < count && text[at] != '\n')
                            ++at;
                        if (at < count)
                            ++at;
                    }
            }
            bool valid = !s_fieldOverflow && IPv4(s_host);
            // Never fall back to another client's controls after invalid input.
            if ((customCommand && !TestFilename(s_testCommand, ".command")) ||
                (customEnabled && !TestFilename(s_testEnabled, ".enabled")))
            {
                s_testCommand[0] = s_testEnabled[0] = 0;
                valid = false;
            }
            if (s_public[0] || s_local[0])
                valid = valid && IPv4(s_public) && IPv4(s_local);
            if (port[0])
            {
                unsigned value = 0;
                for (unsigned i = 0; port[i]; ++i)
                {
                    if (port[i] < '0' || port[i] > '9')
                    {
                        valid = false;
                        break;
                    }
                    value = value * 10 + unsigned(port[i] - '0');
                }
                if (value < 1024 || value > 65535)
                    valid = false;
                else
                    s_gamePort = static_cast<uint16_t>(value);
            }
            unsigned nameLength = 0;
            for (; s_playerName[nameLength]; ++nameLength)
                valid = valid && s_playerName[nameLength] >= 32 && s_playerName[nameLength] < 127 &&
                        s_playerName[nameLength] != '#' && s_playerName[nameLength] != '%';
            if (nameLength)
                valid = valid && s_playerName[0] != ' ' && s_playerName[nameLength - 1] != ' ';
            if (!valid)
                s_host[0] = s_public[0] = s_local[0] = 0;
            Wide(s_wideHost, s_host);
            Wide(s_loginPath, "/platform/client/login");
            Wide(s_headers, "Content-Type: application/octet-stream\r\n");
            Join(s_authUrl, "http://", s_host, ":8085/auth/");
            Join(s_nativeAuthUrl, "https://", s_host, ":8443/auth/");
            Join(s_legacyUrl, "http://", s_host, ":8085/v1.0/tokens/lsg/?client=replaylocal");
            __atomic_store_n(&s_state, 2U, __ATOMIC_RELEASE);
        }
        else
        {
            while (__atomic_load_n(&s_state, __ATOMIC_ACQUIRE) != 2)
                Sleep(1);
        }
    }
} // namespace

extern "C" const char *DW_LocalConfig_Host()
{
    Load();
    return s_host;
}

extern "C" const wchar_t *DW_LocalConfig_WideHost()
{
    Load();
    return s_wideHost;
}

extern "C" const wchar_t *DW_LocalConfig_LoginPath()
{
    Load();
    return s_loginPath;
}

extern "C" const wchar_t *DW_LocalConfig_Headers()
{
    Load();
    return s_headers;
}

extern "C" const char *DW_LocalConfig_AuthUrl()
{
    Load();
    return s_authUrl;
}

extern "C" const char *DW_LocalConfig_NativeAuthUrl()
{
    Load();
    return s_nativeAuthUrl;
}

extern "C" const char *DW_LocalConfig_LegacyUrl()
{
    Load();
    return s_legacyUrl;
}

extern "C" const char *DW_LocalConfig_TestCommand()
{
    Load();
    return s_testCommand;
}

extern "C" const char *DW_LocalConfig_TestEnabled()
{
    Load();
    return s_testEnabled;
}

// Full native address prefix established by Replay's constructors, serializers
// and NetInit::InitLocalAddr. Preserve native relay construction and hashing.
struct DWNativeAddr
{
    uint8_t socketAddress[128];
    uint8_t relayRoute[24];
};

struct DWNativeAddressArray
{
    DWNativeAddr *data;
    uint32_t capacity, size;
};

struct DWNativeCommonAddrPrefix
{
    const void *vtable;
    uint32_t references, padding;
    DWNativeAddr local[5];
    uint32_t localCount, padding780;
    DWNativeAddr publicAddress;
    uint32_t natType, hash;
    uint8_t isSelf, padding945[3];
    uint32_t platform;
};

static_assert(sizeof(DWNativeAddr) == 152);
static_assert(sizeof(DWNativeCommonAddrPrefix) == 952);
static_assert(offsetof(DWNativeCommonAddrPrefix, publicAddress) == 784);
extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    extern uint8_t gl_14269C858[];
    void *func_1420EC270(void *, const DWNativeAddressArray *);
    void *func_1420EBBD0(void *, const DWNativeAddr *);
    void *func_1420EC5C0(void *);
    void *func_142192610(void *); // verified Replay bdRelayJoinData constructor
}

namespace
{
    void IpBytes(const char *text, uint8_t *out)
    {
        for (unsigned part = 0; part < 4; ++part)
        {
            unsigned value = 0;
            while (*text >= '0' && *text <= '9')
                value = value * 10 + unsigned(*text++ - '0');
            out[part] = static_cast<uint8_t>(value);
            if (*text == '.')
                ++text;
        }
    }
} // namespace

extern "C" void *func_1420EC390(DWNativeCommonAddrPrefix *self,
                                const DWNativeAddressArray *local,
                                const DWNativeAddr *publicAddress,
                                uint32_t natType,
                                uint32_t platform)
{
    self->references = 0;
    self->vtable = gl_14269C858;
    func_1420EC270(self->local, local);
    func_1420EBBD0(&self->publicAddress, publicAddress);
    self->natType = natType;
    self->isSelf = 1;
    self->platform = platform;
    func_142192610(reinterpret_cast<uint8_t *>(self) + 952);
    Load();
    if (DW_LocalBackend_IsEnabled() && s_public[0] && platform == 101)
    {
        uint8_t lan[4]{}, external[4]{};
        IpBytes(s_local, lan);
        IpBytes(s_public, external);
        for (unsigned i = 0; i < self->localCount && i < 5; ++i)
        {
            const auto *address = self->local[i].socketAddress;
            bool matches = address[0] == 2 && address[1] == 0 &&
                           ((unsigned(address[2]) << 8) | address[3]) == s_gamePort;
            for (unsigned j = 0; j < 4; ++j)
                matches = matches && address[4 + j] == lan[j];
            if (!matches)
                continue;
            auto *published = self->publicAddress.socketAddress;
            published[0] = 2;
            published[1] = 0;
            published[2] = static_cast<uint8_t>(s_gamePort >> 8);
            published[3] = static_cast<uint8_t>(s_gamePort);
            for (unsigned j = 0; j < 4; ++j)
                published[4 + j] = external[j];
            self->natType = 1;
            break;
        }
    }
    func_1420EC5C0(self);
    return self;
}

extern "C" const char *DW_LocalConfig_PlayerName()
{
    Load();
    return s_playerName;
}

extern "C" bool DW_LocalConfig_UnlockAll()
{
    Load();
    return s_unlockAll;
}

extern "C" unsigned DW_LocalConfig_Rank()
{
    Load();
    return s_rank;
}
