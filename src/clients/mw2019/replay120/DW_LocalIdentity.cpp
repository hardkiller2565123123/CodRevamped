#include "dw_client_identity.h"
#include "DW_LocalConfig.h"
#include "DW_LocalProgression.h"

extern "C"
{
    __declspec(dllimport) void *__stdcall LoadLibraryA(const char *);
    __declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
    __declspec(dllimport) int __stdcall FreeLibrary(void *);
}

namespace
{
    const char *s_error = "not-initialized"; // Only the login worker calls this module.
    char s_errorDetail[96]{};
    constexpr uintptr_t invalidFile = ~uintptr_t{0};

    bool Failure(const char *stage, uint32_t code = 0)
    {
        // Error text contains only a fixed stage and Windows status. No path or key.
        unsigned length = 0;
        while (stage[length] && length < 80)
        {
            s_errorDetail[length] = stage[length];
            ++length;
        }
        if (code)
        {
            const char digits[] = "0123456789ABCDEF";
            s_errorDetail[length++] = ':';
            s_errorDetail[length++] = '0';
            s_errorDetail[length++] = 'x';
            for (unsigned shift = 32; shift; shift -= 4)
                s_errorDetail[length++] = digits[(code >> (shift - 4)) & 15];
        }
        s_errorDetail[length] = 0;
        s_error = s_errorDetail;
        return false;
    }

    struct Blob
    {
        unsigned long length;
        uint8_t *data;
    };

    static_assert(sizeof(Blob) == 16);

    struct API
    {
        void *kernel = nullptr, *bcrypt = nullptr, *crypt = nullptr;
        unsigned long(__stdcall *GetEnvironmentVariableW)(const wchar_t *,
                                                          wchar_t *,
                                                          unsigned long);
        unsigned long(__stdcall *GetLastError)();
        int(__stdcall *CreateDirectoryW)(const wchar_t *, void *);
        void *(__stdcall *CreateFileW)(const wchar_t *,
                                       unsigned long,
                                       unsigned long,
                                       void *,
                                       unsigned long,
                                       unsigned long,
                                       void *);
        int(__stdcall *GetFileSizeEx)(void *, int64_t *);
        int(__stdcall *ReadFile)(void *, void *, unsigned long, unsigned long *, void *);
        int(__stdcall *WriteFile)(void *, const void *, unsigned long, unsigned long *, void *);
        int(__stdcall *FlushFileBuffers)(void *);
        int(__stdcall *CloseHandle)(void *);
        int(__stdcall *MoveFileExW)(const wchar_t *, const wchar_t *, unsigned long);
        void(__stdcall *Sleep)(unsigned long);
        void *(__stdcall *LocalFree)(void *);
        int(__stdcall *CryptProtectData)(
            Blob *, const wchar_t *, Blob *, void *, void *, unsigned long, Blob *);
        int(__stdcall *CryptUnprotectData)(
            Blob *, wchar_t **, Blob *, void *, void *, unsigned long, Blob *);
        long(__stdcall *BCryptOpenAlgorithmProvider)(void **,
                                                     const wchar_t *,
                                                     const wchar_t *,
                                                     unsigned long);
        long(__stdcall *BCryptCloseAlgorithmProvider)(void *, unsigned long);
        long(__stdcall *BCryptGenerateKeyPair)(void *, void **, unsigned long, unsigned long);
        long(__stdcall *BCryptFinalizeKeyPair)(void *, unsigned long);
        long(__stdcall *BCryptImportKeyPair)(
            void *, void *, const wchar_t *, void **, uint8_t *, unsigned long, unsigned long);
        long(__stdcall *BCryptExportKey)(void *,
                                         void *,
                                         const wchar_t *,
                                         uint8_t *,
                                         unsigned long,
                                         unsigned long *,
                                         unsigned long);
        long(__stdcall *BCryptDestroyKey)(void *);
        long(__stdcall *BCryptCreateHash)(
            void *, void **, uint8_t *, unsigned long, uint8_t *, unsigned long, unsigned long);
        long(__stdcall *BCryptHashData)(void *, uint8_t *, unsigned long, unsigned long);
        long(__stdcall *BCryptFinishHash)(void *, uint8_t *, unsigned long, unsigned long);
        long(__stdcall *BCryptDestroyHash)(void *);
        long(__stdcall *BCryptSignHash)(void *,
                                        void *,
                                        uint8_t *,
                                        unsigned long,
                                        uint8_t *,
                                        unsigned long,
                                        unsigned long *,
                                        unsigned long);

        bool Load()
        {
            kernel = LoadLibraryA("kernel32.dll");
            bcrypt = LoadLibraryA("bcrypt.dll");
            crypt = LoadLibraryA("crypt32.dll");
            if (!kernel || !bcrypt || !crypt)
                return Failure("windows-identity-library");
#define DW_LOAD(library, name)                                                                     \
    name = reinterpret_cast<decltype(name)>(GetProcAddress(library, #name));                       \
    if (!name)                                                                                     \
    return Failure("windows-identity-api-" #name)
            DW_LOAD(kernel, GetEnvironmentVariableW);
            DW_LOAD(kernel, GetLastError);
            DW_LOAD(kernel, CreateDirectoryW);
            DW_LOAD(kernel, CreateFileW);
            DW_LOAD(kernel, GetFileSizeEx);
            DW_LOAD(kernel, ReadFile);
            DW_LOAD(kernel, WriteFile);
            DW_LOAD(kernel, FlushFileBuffers);
            DW_LOAD(kernel, CloseHandle);
            DW_LOAD(kernel, MoveFileExW);
            DW_LOAD(kernel, Sleep);
            DW_LOAD(kernel, LocalFree);
            DW_LOAD(crypt, CryptProtectData);
            DW_LOAD(crypt, CryptUnprotectData);
            DW_LOAD(bcrypt, BCryptOpenAlgorithmProvider);
            DW_LOAD(bcrypt, BCryptCloseAlgorithmProvider);
            DW_LOAD(bcrypt, BCryptGenerateKeyPair);
            DW_LOAD(bcrypt, BCryptFinalizeKeyPair);
            DW_LOAD(bcrypt, BCryptImportKeyPair);
            DW_LOAD(bcrypt, BCryptExportKey);
            DW_LOAD(bcrypt, BCryptDestroyKey);
            DW_LOAD(bcrypt, BCryptCreateHash);
            DW_LOAD(bcrypt, BCryptHashData);
            DW_LOAD(bcrypt, BCryptFinishHash);
            DW_LOAD(bcrypt, BCryptDestroyHash);
            DW_LOAD(bcrypt, BCryptSignHash);
#undef DW_LOAD
            return true;
        }

        ~API()
        {
            if (crypt)
                FreeLibrary(crypt);
            if (bcrypt)
                FreeLibrary(bcrypt);
            if (kernel)
                FreeLibrary(kernel);
        }
    };

    void Wipe(uint8_t *bytes, unsigned count)
    {
        auto *target = static_cast<volatile uint8_t *>(bytes);
        while (count--)
            *target++ = 0;
    }

    bool Append(wchar_t *out, const wchar_t *suffix)
    {
        unsigned length = 0;
        while (out[length])
            ++length;
        while (*suffix)
        {
            if (length + 1 >= 1024)
                return false;
            out[length++] = *suffix++;
        }
        out[length] = 0;
        return true;
    }

    struct File
    {
        API &api;
        void *handle = reinterpret_cast<void *>(invalidFile);

        bool Valid() const
        {
            return handle != reinterpret_cast<void *>(invalidFile);
        }

        ~File()
        {
            if (Valid())
                api.CloseHandle(handle);
        }
    };

    struct Key
    {
        API &api;
        void *algorithm = nullptr, *key = nullptr;

        ~Key()
        {
            if (key)
                api.BCryptDestroyKey(key);
            if (algorithm)
                api.BCryptCloseAlgorithmProvider(algorithm, 0);
        }

        bool Load()
        {
            wchar_t directory[1024]{}, path[1024]{}, lockPath[1024]{}, pending[1024]{};
            const auto length = api.GetEnvironmentVariableW(L"LOCALAPPDATA", directory, 1024);
            if (!length)
                return Failure("local-identity-directory-path", api.GetLastError());
            if (length > 900 || !Append(directory, L"\\ReplayDW"))
                return Failure("local-identity-directory-length");
            if (!api.CreateDirectoryW(directory, nullptr) && api.GetLastError() != 183)
                return Failure("local-identity-directory-create", api.GetLastError());
            for (unsigned i = 0; directory[i]; ++i)
                path[i] = lockPath[i] = pending[i] = directory[i];
            if (!Append(path, L"\\player-identity.bin") ||
                !Append(lockPath, L"\\player-identity.lock") ||
                !Append(pending, L"\\player-identity.creating"))
                return Failure("local-identity-file-path");

            File lock{api};
            for (unsigned attempt = 0; attempt < 30; ++attempt)
            {
                lock.handle = api.CreateFileW(lockPath, 0x40000000, 0, nullptr, 4, 0x80, nullptr);
                if (lock.Valid())
                    break;
                api.Sleep(100);
            }
            if (!lock.Valid())
                return Failure("local-identity-lock", api.GetLastError());
            auto status = api.BCryptOpenAlgorithmProvider(&algorithm, L"ECDSA_P256", nullptr, 0);
            if (status < 0)
                return Failure("local-identity-key-provider", static_cast<uint32_t>(status));

            struct ProtectedIdentity
            {
                uint32_t magic, version, length;
                uint8_t bytes[4096];
            } record{};

            File existing{api};
            existing.handle = api.CreateFileW(path, 0x80000000, 1, nullptr, 3, 0x80, nullptr);
            bool recover = false;
            if (!existing.Valid())
            {
                if (api.GetLastError() != 2)
                    return Failure("local-identity-file-open", api.GetLastError());
                // Recover a completed first-launch write after a process/power failure.
                // An invalid pending identity is preserved and never replaced.
                existing.handle =
                    api.CreateFileW(pending, 0x80000000, 1, nullptr, 3, 0x80, nullptr);
                recover = existing.Valid();
            }
            if (existing.Valid())
            {
                int64_t size = 0;
                unsigned long received = 0;
                if (!api.GetFileSizeEx(existing.handle, &size))
                    return Failure("local-identity-file-size", api.GetLastError());
                if (size < 13 || size > static_cast<int64_t>(sizeof(record)))
                    return Failure("local-identity-record-size");
                if (!api.ReadFile(existing.handle,
                                  &record,
                                  static_cast<unsigned long>(size),
                                  &received,
                                  nullptr))
                    return Failure("local-identity-file-read", api.GetLastError());
                if (static_cast<int64_t>(received) != size ||
                    record.magic != DW_LOCAL_CLIENT_MAGIC ||
                    record.version != DW_LOCAL_CLIENT_VERSION || record.length != received - 12)
                    return Failure("local-identity-record-format");
                Blob encrypted{record.length, record.bytes}, plaintext{};
                if (!api.CryptUnprotectData(
                        &encrypted, nullptr, nullptr, nullptr, nullptr, 1, &plaintext))
                    return Failure("local-identity-dpapi-decrypt", api.GetLastError());
                const bool keySize = plaintext.length == 104;
                status = keySize ? api.BCryptImportKeyPair(algorithm,
                                                           nullptr,
                                                           L"ECCPRIVATEBLOB",
                                                           &key,
                                                           plaintext.data,
                                                           plaintext.length,
                                                           0)
                                 : 0;
                Wipe(plaintext.data, plaintext.length);
                api.LocalFree(plaintext.data);
                if (!keySize)
                    return Failure("local-identity-key-size");
                if (status < 0)
                    return Failure("local-identity-key-import", static_cast<uint32_t>(status));
                api.CloseHandle(existing.handle);
                existing.handle = reinterpret_cast<void *>(invalidFile);
                if (recover && !api.MoveFileExW(pending, path, 8))
                    return Failure("local-identity-recovery-publish", api.GetLastError());
                return true;
            }
            // An unreadable/corrupt profile must never silently become a new player.
            if (api.GetLastError() != 2)
                return Failure("local-identity-pending-open", api.GetLastError());
            status = api.BCryptGenerateKeyPair(algorithm, &key, 256, 0);
            if (status < 0)
                return Failure("local-identity-key-generate", static_cast<uint32_t>(status));
            status = api.BCryptFinalizeKeyPair(key, 0);
            if (status < 0)
                return Failure("local-identity-key-finalize", static_cast<uint32_t>(status));
            uint8_t privateKey[104]{};
            unsigned long written = 0;
            status = api.BCryptExportKey(
                key, nullptr, L"ECCPRIVATEBLOB", privateKey, sizeof(privateKey), &written, 0);
            if (status < 0 || written != sizeof(privateKey))
            {
                Wipe(privateKey, sizeof(privateKey));
                return Failure("local-identity-key-export", static_cast<uint32_t>(status));
            }
            Blob plaintext{written, privateKey}, encrypted{};
            const bool protectedKey = api.CryptProtectData(&plaintext,
                                                           L"Replay DW player identity",
                                                           nullptr,
                                                           nullptr,
                                                           nullptr,
                                                           1,
                                                           &encrypted) != 0;
            const auto protectError = api.GetLastError();
            Wipe(privateKey, sizeof(privateKey));
            if (!protectedKey)
                return Failure("local-identity-dpapi-protect", protectError);
            const bool bounded = encrypted.length > 0 && encrypted.length <= sizeof(record.bytes);
            if (bounded)
                for (unsigned i = 0; i < encrypted.length; ++i)
                    record.bytes[i] = encrypted.data[i];
            record.magic = DW_LOCAL_CLIENT_MAGIC;
            record.version = DW_LOCAL_CLIENT_VERSION;
            record.length = encrypted.length;
            api.LocalFree(encrypted.data);
            if (!bounded)
                return Failure("local-identity-protected-size");
            File output{api};
            output.handle = api.CreateFileW(pending, 0x40000000, 0, nullptr, 1, 0x80, nullptr);
            if (!output.Valid())
                return Failure("local-identity-pending-create", api.GetLastError());
            if (!api.WriteFile(output.handle, &record, 12 + record.length, &written, nullptr))
                return Failure("local-identity-pending-write", api.GetLastError());
            if (written != 12 + record.length)
                return Failure("local-identity-pending-short-write");
            if (!api.FlushFileBuffers(output.handle))
                return Failure("local-identity-pending-flush", api.GetLastError());
            api.CloseHandle(output.handle);
            output.handle = reinterpret_cast<void *>(invalidFile);
            if (!api.MoveFileExW(pending, path, 8))
                return Failure("local-identity-file-publish", api.GetLastError());
            return true;
        }

        bool Public(uint8_t *out)
        {
            unsigned long written = 0;
            const auto status =
                api.BCryptExportKey(key, nullptr, L"ECCPUBLICBLOB", out, 72, &written, 0);
            if (status < 0 || written != 72)
                return Failure("local-identity-public-export", static_cast<uint32_t>(status));
            return true;
        }

        template <typename Request>
        bool Sign(Request &request)
        {
            void *hashAlgorithm = nullptr, *hash = nullptr;
            uint8_t digest[32]{};
            unsigned long written = 0;
            const bool ok =
                api.BCryptOpenAlgorithmProvider(&hashAlgorithm, L"SHA256", nullptr, 0) >= 0 &&
                api.BCryptCreateHash(hashAlgorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0 &&
                api.BCryptHashData(hash,
                                   reinterpret_cast<uint8_t *>(&request),
                                   offsetof(Request, signature),
                                   0) >= 0 &&
                api.BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0 &&
                api.BCryptSignHash(key,
                                   nullptr,
                                   digest,
                                   sizeof(digest),
                                   request.signature,
                                   sizeof(request.signature),
                                   &written,
                                   0) >= 0 &&
                written == sizeof(request.signature);
            if (hash)
                api.BCryptDestroyHash(hash);
            if (hashAlgorithm)
                api.BCryptCloseAlgorithmProvider(hashAlgorithm, 0);
            Wipe(digest, sizeof(digest));
            return ok;
        }
    };
} // namespace

extern "C" bool DW_LocalIdentity_PublicKey(uint8_t *out)
{
    API api{};
    s_error = "windows-identity-api";
    if (!out || !api.Load())
        return false;
    Key key{api};
    if (!key.Load() || !key.Public(out))
        return false;
    s_error = "none";
    return true;
}

extern "C" const char *DW_LocalIdentity_Error()
{
    return s_error;
}

extern "C" bool DW_LocalIdentity_Login(const char *name,
                                       const uint8_t *nonce,
                                       DWLocalPlatformReply *reply,
                                       DWLocalIdentityPost post)
{
    API api{};
    s_error = "windows-identity-api";
    if (!name || !nonce || !reply || !post || !api.Load())
        return false;
    Key key{api};
    if (!key.Load())
        return false;
    DWLocalClientChallengeRequest challenge{};
    DWLocalClientLoginRequestV2 request{};
    request.magic = DW_LOCAL_CLIENT_MAGIC;
    request.version = DW_LOCAL_CLIENT_LOGIN_VERSION;
    unsigned appliedRank = 0;
    request.options = DW_LocalProgression_LoginFields(
        &request.localUserId, &request.playerXp, &appliedRank) ? 1U : 0U;
    const auto configuredRank = DW_LocalConfig_Rank();
    request.startingRank = configuredRank && appliedRank != configuredRank ? configuredRank : 0;
    if (!key.Public(request.publicKey))
        return false;
    unsigned length = 0;
    for (; name[length]; ++length)
    {
        if (length >= 35 || name[length] < 32 || name[length] >= 127 || name[length] == '#' ||
            name[length] == '%')
            return Failure("local-identity-player-name");
        request.name[length] = name[length];
    }
    if (length && (name[0] == ' ' || name[length - 1] == ' '))
        return Failure("local-identity-player-name");
    for (unsigned i = 0; i < 72; ++i)
        challenge.publicKey[i] = request.publicKey[i];
    for (unsigned i = 0; i < 32; ++i)
        challenge.nonce[i] = request.nonce[i] = nonce[i];
    s_error = "server-identity-challenge";
    if (!post(L"/platform/client/challenge", &challenge, sizeof(challenge), request.challenge, 32))
        return false;
    s_error = "local-identity-signature";
    if (!key.Sign(request))
        return false;
    s_error = "server-identity-login";
    if (!post(L"/platform/client/login", &request, sizeof(request), reply, sizeof(*reply)))
        return false;
    s_error = "none";
    return true;
}

extern "C" bool DW_LocalIdentity_Renew(const uint8_t *nonce,
                                       const char *sessionToken,
                                       DWLocalPlatformReply *reply,
                                       DWLocalIdentityPost post)
{
    API api{};
    s_error = "windows-identity-api";
    if (!nonce || !sessionToken || !reply || !post || !api.Load())
        return false;
    Key key{api};
    if (!key.Load())
        return false;
    DWLocalClientChallengeRequest challenge{};
    DWLocalClientRenewRequest request{};
    request.magic = DW_LOCAL_CLIENT_MAGIC;
    request.version = DW_LOCAL_CLIENT_RENEW_VERSION;
    if (!key.Public(request.publicKey))
        return false;
    for (unsigned i = 0; i < 72; ++i)
        challenge.publicKey[i] = request.publicKey[i];
    for (unsigned i = 0; i < 32; ++i)
        challenge.nonce[i] = request.nonce[i] = nonce[i];
    for (unsigned i = 0; i < 64; ++i)
        request.sessionToken[i] = sessionToken[i];
    s_error = "server-identity-renew-challenge";
    if (!post(L"/platform/client/challenge", &challenge, sizeof(challenge), request.challenge, 32))
        return false;
    s_error = "local-identity-renew-signature";
    if (!key.Sign(request))
        return false;
    s_error = "server-identity-renew";
    if (!post(L"/platform/client/renew", &request, sizeof(request), reply, sizeof(*reply)))
        return false;
    s_error = "none";
    return true;
}
