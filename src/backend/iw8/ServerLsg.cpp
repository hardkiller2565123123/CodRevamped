#include "Server.h"
#include "Log.h"
#include "Web/WebAuthService.h"
#include "Demonware/DemonwareTaskRouter.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <atomic>
#include <array>
#include <cstring>
#include <vector>
#include <mutex>
#include <limits>
#include <cstdarg>
#include <cstdio>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

// The Auth3 client-ticket session key is exposed by the existing V72 evidence API.
// V76 uses only its exact kind=2 source; speculative key-window/KDF searching is gone.
namespace revamped::iw8::web
{
    std::size_t GetLsgSessionKeyCandidatesV72(std::uint8_t* outKeys, std::uint32_t* outKinds,
        std::size_t maxKeys, std::uint64_t* auth3Serial);
}

namespace revamped::iw8
{
    namespace
    {
        // V63 keeps the LSG server on a stable stock-range baseline while the
        // redirect/scanner DLL passively records the untouched IW8 0x81 parser
        // ancestry. No client login, task, fence, Source3, or frontend state is written.
        struct PostLoginTaskCensusEntry
        {
            std::uint64_t clientId = 0;
            std::uint64_t firstSeenMs = 0;
            std::uint64_t lastSeenMs = 0;
            std::uint32_t firstCounter = 0;
            std::uint32_t lastCounter = 0;
            std::uint32_t observations = 0;
            std::uint32_t minPayloadBytes = (std::numeric_limits<std::uint32_t>::max)();
            std::uint32_t maxPayloadBytes = 0;
            std::uint64_t firstPayloadFingerprint = 0;
            std::uint64_t lastPayloadFingerprint = 0;
        };

        std::array<PostLoginTaskCensusEntry, 256u * 256u> g_postLoginTaskCensus{};
        std::mutex g_postLoginTaskCensusMutex;
        std::uint64_t g_postLoginCensusStartMs = 0;
        std::uint32_t g_postLoginCensusSequence = 0;
        std::uint32_t g_postLoginCensusUniqueRoutes = 0;

        std::uint64_t Fnv1a64(const std::uint8_t* data, std::size_t size)
        {
            std::uint64_t hash = 14695981039346656037ull;
            for (std::size_t i = 0; i < size; ++i)
            {
                hash ^= static_cast<std::uint64_t>(data[i]);
                hash *= 1099511628211ull;
            }
            return hash;
        }

        std::string HexPreview(const std::uint8_t* data, std::size_t size, std::size_t maxBytes = 64u)
        {
            if (!data || !size)
                return "<empty>";
            const std::size_t take = (std::min)(size, maxBytes);
            std::string out;
            out.reserve(take * 3u + 16u);
            char byteText[4]{};
            for (std::size_t i = 0; i < take; ++i)
            {
                if (i) out.push_back(' ');
                _snprintf_s(byteText, sizeof(byteText), _TRUNCATE, "%02X", static_cast<unsigned>(data[i]));
                out += byteText;
            }
            if (take != size)
                out += " ...";
            return out;
        }

        std::string PrintableRuns(const std::uint8_t* data, std::size_t size,
            std::size_t minimumRun = 4u, std::size_t maxOutput = 1800u)
        {
            if (!data || !size)
                return "<none>";

            std::string out;
            out.reserve((std::min)(size, maxOutput));
            std::size_t i = 0;
            bool first = true;
            while (i < size && out.size() < maxOutput)
            {
                std::size_t start = i;
                while (start < size && (data[start] < 0x20u || data[start] > 0x7Eu))
                    ++start;
                if (start >= size)
                    break;

                std::size_t end = start;
                while (end < size && data[end] >= 0x20u && data[end] <= 0x7Eu)
                    ++end;

                if (end - start >= minimumRun)
                {
                    if (!first)
                        out += " | ";
                    first = false;

                    char prefix[40]{};
                    _snprintf_s(prefix, sizeof(prefix), _TRUNCATE, "@0x%llX=\"",
                        static_cast<unsigned long long>(start));
                    out += prefix;

                    for (std::size_t j = start; j < end && out.size() + 4u < maxOutput; ++j)
                    {
                        const char c = static_cast<char>(data[j]);
                        if (c == '\\' || c == '"')
                            out.push_back('\\');
                        out.push_back(c);
                    }
                    out.push_back('"');
                }

                i = end + 1u;
            }

            return out.empty() ? "<none>" : out;
        }

        void AppendRest255Line(const char* format, ...)
        {
            if (!format)
                return;

            char message[8192]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
            va_end(args);

            // V88: diagnostics are live CMD output only. No per-feature .log files
            // are created or mirrored into server_emu anymore.
            log::Print("[DW-REST] %s", message);
        }

        void RecordRest255Candidate(std::uint64_t clientId, std::uint32_t counter,
            const std::uint8_t* payload, std::size_t payloadBytes, std::uint64_t fingerprint)
        {
            // V88 performs this observation entirely on the server after
            // decryption. The V86 client-side native task-manager detours were
            // removed after they triggered STATUS_ILLEGAL_INSTRUCTION in stock
            // IW8 1.44. No client executable code is patched by this logger.
            const std::string hex = HexPreview(payload, payloadBytes, payloadBytes);
            const std::string strings = PrintableRuns(payload, payloadBytes);

            AppendRest255Line(
                "REST_REQUEST clientId=%llu counter=%u service=255 task=10 payloadBytes=%llu fingerprint=%016llX mode=SERVER_DECRYPTED_READ_ONLY fullHex={%s}",
                static_cast<unsigned long long>(clientId), counter,
                static_cast<unsigned long long>(payloadBytes),
                static_cast<unsigned long long>(fingerprint), hex.c_str());
            AppendRest255Line(
                "REST_STRINGS clientId=%llu counter=%u printableRuns={%s}",
                static_cast<unsigned long long>(clientId), counter, strings.c_str());
        }

        void AppendPostLoginCensusLine(const char* format, ...)
        {
            if (!format)
                return;

            char message[4096]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
            va_end(args);

            log::Print("[DW-CENSUS] %s", message);
        }

        void RecordPostLoginTaskCensus(std::uint64_t clientId, std::uint32_t counter,
            const std::vector<std::uint8_t>& plain, const demonware::TaskRequest& request,
            const demonware::TaskRoute* route)
        {
            if (!request.valid || request.payloadOffset > plain.size() ||
                request.payloadBytes > plain.size() - request.payloadOffset)
                return;

            const std::uint8_t* payload = request.payloadBytes ? plain.data() + request.payloadOffset : nullptr;
            const std::uint64_t fingerprint = Fnv1a64(payload, request.payloadBytes);
            const std::string preview = HexPreview(payload, request.payloadBytes);

            if (request.serviceId == 255u && request.taskId == 0x0Au)
                RecordRest255Candidate(clientId, counter, payload, request.payloadBytes, fingerprint);

            const std::uint64_t now = GetTickCount64();
            const std::size_t key = (static_cast<std::size_t>(request.serviceId) << 8u) | request.taskId;

            std::lock_guard<std::mutex> lock(g_postLoginTaskCensusMutex);
            if (!g_postLoginCensusStartMs)
            {
                g_postLoginCensusStartMs = now;
                AppendPostLoginCensusLine("CENSUS_BEGIN mode=PASSIVE_SEMANTIC packetMatching=off guessedReplies=off clientId=%llu",
                    static_cast<unsigned long long>(clientId));
                AppendPostLoginCensusLine("COLUMNS seq elapsedMs clientId counter service task serviceName taskName known replyPolicy observation uniqueRoute payloadBytes minPayload maxPayload fingerprint changed preview");
            }

            auto& entry = g_postLoginTaskCensus[key];
            const bool newRoute = entry.observations == 0;

            if (newRoute)
            {
                entry.clientId = clientId;
                entry.firstSeenMs = now;
                entry.firstCounter = counter;
                entry.minPayloadBytes = static_cast<std::uint32_t>(request.payloadBytes);
                entry.firstPayloadFingerprint = fingerprint;
                ++g_postLoginCensusUniqueRoutes;
            }

            ++entry.observations;
            entry.lastSeenMs = now;
            entry.lastCounter = counter;
            entry.minPayloadBytes = (std::min)(entry.minPayloadBytes, static_cast<std::uint32_t>(request.payloadBytes));
            entry.maxPayloadBytes = (std::max)(entry.maxPayloadBytes, static_cast<std::uint32_t>(request.payloadBytes));
            const bool payloadChanged = entry.observations > 1u && entry.lastPayloadFingerprint != 0u && entry.lastPayloadFingerprint != fingerprint;
            entry.lastPayloadFingerprint = fingerprint;

            const char* policy = "UNMAPPED";
            if (route)
                policy = route->replyPolicy == demonware::ReplyPolicy::None ? "KNOWN_UNIMPLEMENTED" : "SEMANTIC_REPLY";

            const std::uint32_t seq = ++g_postLoginCensusSequence;
            AppendPostLoginCensusLine(
                "TASK seq=%u elapsedMs=%llu clientId=%llu counter=%u service=%u task=%u serviceName=%s taskName=%s known=%s replyPolicy=%s observation=%u uniqueRoute=%s payloadBytes=%llu minPayload=%u maxPayload=%u fingerprint=%016llX changed=%s preview={%s}",
                seq,
                static_cast<unsigned long long>(now - g_postLoginCensusStartMs),
                static_cast<unsigned long long>(clientId), counter,
                static_cast<unsigned>(request.serviceId), static_cast<unsigned>(request.taskId),
                route && route->serviceName ? route->serviceName : "unknown",
                route && route->taskName ? route->taskName : "unknown",
                route ? "yes" : "no", policy, entry.observations,
                newRoute ? "YES" : "no",
                static_cast<unsigned long long>(request.payloadBytes),
                entry.minPayloadBytes, entry.maxPayloadBytes,
                static_cast<unsigned long long>(fingerprint), payloadChanged ? "YES" : "no", preview.c_str());

            if (newRoute || entry.observations == 2u || (entry.observations % 5u) == 0u)
            {
                AppendPostLoginCensusLine(
                    "SUMMARY uniqueRoutes=%u totalObservations=%u last={service:%u task:%u counter:%u observations:%u firstCounter:%u lastCounter:%u firstMs:%llu lastMs:%llu} correlationKey=counter+service+task",
                    g_postLoginCensusUniqueRoutes, g_postLoginCensusSequence,
                    static_cast<unsigned>(request.serviceId), static_cast<unsigned>(request.taskId), counter,
                    entry.observations, entry.firstCounter, entry.lastCounter,
                    static_cast<unsigned long long>(entry.firstSeenMs - g_postLoginCensusStartMs),
                    static_cast<unsigned long long>(entry.lastSeenMs - g_postLoginCensusStartMs));
            }
        }

        void AppendLsgPipelineV63(const char* format, ...)
        {
            if (!format)
                return;

            char message[2048]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
            va_end(args);

            // V88 CMD-only research output. No lsg_pipeline_v63.log mirror.
            log::Print("[LSG-V63] %s", message);
        }

        bool SendAllNonBlocking(SOCKET socket, const void* data, std::size_t size)
        {
            const auto* bytes = static_cast<const unsigned char*>(data);
            std::size_t sentTotal = 0;
            while (sentTotal < size)
            {
                const int chunk = static_cast<int>((std::min)(size - sentTotal, static_cast<std::size_t>(0x7FFFFFFF)));
                const int sent = send(socket, reinterpret_cast<const char*>(bytes + sentTotal), chunk, 0);
                if (sent > 0)
                {
                    sentTotal += static_cast<std::size_t>(sent);
                    continue;
                }
                if (sent == 0)
                    return false;

                const int error = WSAGetLastError();
                if (error != WSAEWOULDBLOCK)
                    return false;

                fd_set writeSet{};
                FD_ZERO(&writeSet);
                FD_SET(socket, &writeSet);
                timeval timeout{};
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                const int ready = select(0, nullptr, &writeSet, nullptr, &timeout);
                if (ready <= 0)
                    return false;
            }
            return true;
        }

        std::uint32_t ReadLe32(const std::uint8_t* p)
        {
            return static_cast<std::uint32_t>(p[0]) |
                (static_cast<std::uint32_t>(p[1]) << 8) |
                (static_cast<std::uint32_t>(p[2]) << 16) |
                (static_cast<std::uint32_t>(p[3]) << 24);
        }

        void AppendLe32(std::vector<std::uint8_t>& out, std::uint32_t value)
        {
            out.push_back(static_cast<std::uint8_t>(value));
            out.push_back(static_cast<std::uint8_t>(value >> 8));
            out.push_back(static_cast<std::uint8_t>(value >> 16));
            out.push_back(static_cast<std::uint8_t>(value >> 24));
        }

        void AppendLe64(std::vector<std::uint8_t>& out, std::uint64_t value)
        {
            AppendLe32(out, static_cast<std::uint32_t>(value));
            AppendLe32(out, static_cast<std::uint32_t>(value >> 32));
        }

        bool BCryptAesCbcCrypt(bool encrypt, const std::uint8_t key[16], const std::uint8_t iv[16],
            const std::uint8_t* input, std::size_t inputSize, std::vector<std::uint8_t>& output)
        {
            output.clear();
            if (!key || !iv || !input || !inputSize || (inputSize & 15u) != 0u || inputSize > 0xFFFFFFFFu)
                return false;

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_KEY_HANDLE keyHandle = nullptr;
            DWORD objectBytes = 0;
            DWORD returned = 0;
            bool ok = false;

            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
                goto done;
            if (BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                    reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                    static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_CBC)), 0) != 0)
                goto done;
            if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &returned, 0) != 0 || !objectBytes)
                goto done;

            {
                std::vector<std::uint8_t> keyObject(objectBytes);
                if (BCryptGenerateSymmetricKey(algorithm, &keyHandle, keyObject.data(), objectBytes,
                        const_cast<PUCHAR>(key), 16, 0) != 0)
                    goto done;

                std::array<std::uint8_t, 16> ivCopy{};
                std::memcpy(ivCopy.data(), iv, ivCopy.size());
                output.resize(inputSize);
                ULONG outputBytes = 0;
                const NTSTATUS status = encrypt
                    ? BCryptEncrypt(keyHandle, const_cast<PUCHAR>(input), static_cast<ULONG>(inputSize), nullptr,
                        ivCopy.data(), static_cast<ULONG>(ivCopy.size()), output.data(), static_cast<ULONG>(output.size()),
                        &outputBytes, 0)
                    : BCryptDecrypt(keyHandle, const_cast<PUCHAR>(input), static_cast<ULONG>(inputSize), nullptr,
                        ivCopy.data(), static_cast<ULONG>(ivCopy.size()), output.data(), static_cast<ULONG>(output.size()),
                        &outputBytes, 0);
                if (status != 0 || outputBytes != inputSize)
                    goto done;
                output.resize(outputBytes);
                ok = true;
            }

        done:
            if (keyHandle) BCryptDestroyKey(keyHandle);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            if (!ok) output.clear();
            return ok;
        }

        bool BCryptSha1(const std::uint8_t* data, std::size_t size, std::uint8_t out[20])
        {
            if (!out || (size && !data) || size > 0xFFFFFFFFu)
                return false;

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            DWORD objectBytes = 0;
            DWORD returned = 0;
            bool ok = false;

            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
                goto done;
            if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &returned, 0) != 0 || !objectBytes)
                goto done;

            {
                std::vector<std::uint8_t> object(objectBytes);
                if (BCryptCreateHash(algorithm, &hash, object.data(), objectBytes, nullptr, 0, 0) != 0)
                    goto done;
                if (size && BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) != 0)
                    goto done;
                if (BCryptFinishHash(hash, out, 20, 0) != 0)
                    goto done;
                ok = true;
            }

        done:
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            return ok;
        }

        bool BCryptHmacSha1(const std::uint8_t* key, std::size_t keySize,
            const std::uint8_t* data, std::size_t dataSize, std::uint8_t out[20])
        {
            if (!out || (keySize && !key) || (dataSize && !data) ||
                keySize > 0xFFFFFFFFu || dataSize > 0xFFFFFFFFu)
                return false;

            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            DWORD objectBytes = 0;
            DWORD returned = 0;
            bool ok = false;

            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr,
                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
                goto done;
            if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &returned, 0) != 0 || !objectBytes)
                goto done;

            {
                std::vector<std::uint8_t> object(objectBytes);
                if (BCryptCreateHash(algorithm, &hash, object.data(), objectBytes,
                        const_cast<PUCHAR>(key), static_cast<ULONG>(keySize), 0) != 0)
                    goto done;
                if (dataSize && BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(dataSize), 0) != 0)
                    goto done;
                if (BCryptFinishHash(hash, out, 20, 0) != 0)
                    goto done;
                ok = true;
            }

        done:
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
            return ok;
        }

        bool HkdfExpandSha1Key(const std::uint8_t* prk, std::size_t prkSize,
            const std::uint8_t* info, std::size_t infoSize, std::uint8_t* out, std::size_t outSize)
        {
            if (!prk || !prkSize || !out || (infoSize && !info) || outSize > 20u * 255u)
                return false;

            std::array<std::uint8_t, 20> previous{};
            std::size_t previousSize = 0;
            std::size_t written = 0;
            std::uint8_t counter = 1;
            while (written < outSize)
            {
                std::vector<std::uint8_t> message;
                message.reserve(previousSize + infoSize + 1u);
                if (previousSize)
                    message.insert(message.end(), previous.begin(), previous.begin() + static_cast<std::ptrdiff_t>(previousSize));
                if (infoSize)
                    message.insert(message.end(), info, info + infoSize);
                message.push_back(counter++);

                if (!BCryptHmacSha1(prk, prkSize, message.data(), message.size(), previous.data()))
                    return false;
                previousSize = previous.size();
                const std::size_t chunk = (std::min)(previousSize, outSize - written);
                std::memcpy(out + written, previous.data(), chunk);
                written += chunk;
            }
            return true;
        }

        bool HkdfExpandSha1(const std::uint8_t prk[20], const std::uint8_t* info,
            std::size_t infoSize, std::uint8_t* out, std::size_t outSize)
        {
            return HkdfExpandSha1Key(prk, 20u, info, infoSize, out, outSize);
        }

        struct AuthTrafficSigningKeyCandidateV78
        {
            std::uint64_t fileOffset = 0;
            std::array<std::uint8_t, 294> der{};
        };

        std::uint64_t ReadLe64(const std::uint8_t* p)
        {
            std::uint64_t value = 0;
            for (unsigned shift = 0; shift < 64u; shift += 8u)
                value |= static_cast<std::uint64_t>(*p++) << shift;
            return value;
        }

        bool LooksLikeRsaSpki294V78(const std::uint8_t* p, std::size_t available)
        {
            if (!p || available < 294u)
                return false;
            static const std::uint8_t prefix[] =
            {
                0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,
                0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,
                0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,
                0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01
            };
            if (std::memcmp(p, prefix, sizeof(prefix)) != 0)
                return false;
            return p[32] == 0x00u &&
                p[289] == 0x02u && p[290] == 0x03u &&
                p[291] == 0x01u && p[292] == 0x00u && p[293] == 0x01u;
        }

        bool LoadTrafficSigningKeyCandidatePackV78(const wchar_t* path,
            std::vector<AuthTrafficSigningKeyCandidateV78>& out)
        {
            if (!path || !*path)
                return false;

            HANDLE file = CreateFileW(path, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;

            LARGE_INTEGER size{};
            if (!GetFileSizeEx(file, &size) || size.QuadPart < 16 || size.QuadPart > 1024 * 1024)
            {
                CloseHandle(file);
                return false;
            }

            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
            DWORD read = 0;
            const bool readOk = ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) &&
                read == static_cast<DWORD>(bytes.size());
            CloseHandle(file);
            if (!readOk)
                return false;

            static const std::uint8_t magic[8] = {'I','W','8','K','3','V','7','8'};
            if (std::memcmp(bytes.data(), magic, sizeof(magic)) != 0)
                return false;
            const std::uint32_t version = ReadLe32(bytes.data() + 8u);
            const std::uint32_t count = ReadLe32(bytes.data() + 12u);
            if (version != 1u || count > 128u)
                return false;

            constexpr std::size_t recordBytes = 8u + 294u;
            const std::size_t expected = 16u + static_cast<std::size_t>(count) * recordBytes;
            if (bytes.size() != expected)
                return false;

            out.clear();
            out.reserve(count);
            std::size_t offset = 16u;
            for (std::uint32_t i = 0; i < count; ++i)
            {
                AuthTrafficSigningKeyCandidateV78 candidate{};
                candidate.fileOffset = ReadLe64(bytes.data() + offset);
                offset += 8u;
                std::memcpy(candidate.der.data(), bytes.data() + offset, candidate.der.size());
                offset += candidate.der.size();
                if (!LooksLikeRsaSpki294V78(candidate.der.data(), candidate.der.size()))
                    return false;
                out.push_back(candidate);
            }
            return true;
        }

        bool LoadAuthTrafficSigningKeyCandidatesV78(
            std::vector<AuthTrafficSigningKeyCandidateV78>& out, std::wstring* loadedPath)
        {
            const wchar_t fileName[] = L"iw8-auth-traffic-signing-key3-candidates.bin";
            std::vector<std::wstring> paths;

            wchar_t modulePath[32768]{};
            const DWORD chars = GetModuleFileNameW(nullptr, modulePath,
                static_cast<DWORD>(sizeof(modulePath) / sizeof(modulePath[0])));
            if (chars > 0 && chars < (sizeof(modulePath) / sizeof(modulePath[0])))
            {
                std::wstring sibling(modulePath, chars);
                const std::wstring::size_type slash = sibling.find_last_of(L"\\/");
                if (slash != std::wstring::npos)
                    sibling.resize(slash + 1u);
                else
                    sibling.clear();
                paths.push_back(sibling + fileName);
            }
            paths.push_back(fileName);
            paths.push_back(std::wstring(L"server_emu\\") + fileName);

            for (const auto& path : paths)
            {
                std::vector<AuthTrafficSigningKeyCandidateV78> candidates;
                if (!LoadTrafficSigningKeyCandidatePackV78(path.c_str(), candidates))
                    continue;
                out.swap(candidates);
                if (loadedPath)
                    *loadedPath = path;
                return true;
            }
            return false;
        }

        bool EqualBytes(const std::uint8_t* left, const std::uint8_t* right, std::size_t size)
        {
            if (!left || !right) return false;
            std::uint8_t diff = 0;
            for (std::size_t i = 0; i < size; ++i)
                diff |= static_cast<std::uint8_t>(left[i] ^ right[i]);
            return diff == 0;
        }
    }

    bool Server::HandleLsgTcp(Client& client, const std::uint8_t* data, std::size_t size)
    {
        if (!data || !size)
            return true;

        AppendLsgPipelineV63("RX id=%llu port=%u stage=%u bytes=%llu bufferedBefore=%llu",
            static_cast<unsigned long long>(client.id), static_cast<unsigned>(client.localPort),
            static_cast<unsigned>(client.lsgStage), static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(client.lsgInput.size()));
        client.lsgInput.insert(client.lsgInput.end(), data, data + size);
        if (client.lsgInput.size() > 1024u * 1024u)
        {
            log::Print("[LSG] id=%llu port=%u input buffer exceeded 1 MiB; abandoning protocol attribution without touching client state",
                static_cast<unsigned long long>(client.id), static_cast<unsigned>(client.localPort));
            client.lsgInput.clear();
            client.lsgStage = 99;
            return true;
        }

        for (;;)
        {
            if (client.lsgStage == 99)
                return true;

            if (client.lsgStage == 0)
            {
                if (client.lsgInput.size() < 28u)
                    return true;

                const std::uint8_t* hello = client.lsgInput.data();
                const std::uint32_t protocolMinMarker = ReadLe32(hello + 0);
                const std::uint32_t protocolMaxMarker = ReadLe32(hello + 4);
                const std::uint32_t supportedMin = ReadLe32(hello + 8);
                const std::uint32_t supportedMax = ReadLe32(hello + 12);
                const std::uint32_t maxPacket = ReadLe32(hello + 16);
                if (protocolMinMarker != 200u || protocolMaxMarker != 200u ||
                    supportedMin > supportedMax || supportedMin > 220u || supportedMax < 210u ||
                    maxPacket == 0u || maxPacket > 16u * 1024u * 1024u)
                {
                    log::Print("[LSG] id=%llu port=%u first 28 bytes are not the stock bdLobbyConnection hello markers={%u,%u,%u,%u} maxPacket=%u attribution=NO",
                        static_cast<unsigned long long>(client.id), static_cast<unsigned>(client.localPort),
                        protocolMinMarker, protocolMaxMarker, supportedMin, supportedMax, maxPacket);
                    AppendLsgPipelineV63("HELLO_REJECT id=%llu markers={%u,%u,%u,%u} maxPacket=%u",
                        static_cast<unsigned long long>(client.id), protocolMinMarker, protocolMaxMarker, supportedMin, supportedMax, maxPacket);
                    client.lsgStage = 99;
                    return true;
                }

                std::uint64_t auth3Serial = 0;
                std::uint8_t sessionKey[24]{};
                if (!web::GetLatestAuth3SessionKey(sessionKey, &auth3Serial))
                {
                    log::Print("[LSG] id=%llu stock lobby hello arrived before a correlated local Auth3 ticket pair was available; keeping socket open",
                        static_cast<unsigned long long>(client.id));
                    AppendLsgPipelineV63("HELLO_WAIT_AUTH3 id=%llu", static_cast<unsigned long long>(client.id));
                    return true;
                }

                // V69: use the known IW8 Demonware header-ack layout.  The stock
                // hello advertises 210..220, while the reference IW8 handshake
                // selects protocol 210 and sends BOTH 64-bit fields after it:
                //   AB 81 | selectedProto[DWORD] | cypher210ConnID[QWORD] | serverNonce[QWORD]
                // V61-V68 accidentally omitted cypher210ConnID, producing a 14-byte
                // body / 18-byte frame.  The native parser expects a 22-byte body /
                // 26-byte frame, which explains the immediate close before 0x82.
                constexpr std::uint32_t kIw8ReferenceProtocol = 210u;
                constexpr std::uint64_t kIw8ReferenceConnectionId = 0x3713371337133713ull;
                constexpr std::uint64_t kIw8ReferenceServerNonce = 0x3713371337133713ull;

                client.lsgSelectedVersion =
                    (supportedMin <= kIw8ReferenceProtocol && supportedMax >= kIw8ReferenceProtocol)
                    ? kIw8ReferenceProtocol
                    : supportedMin;
                client.lsgMaxPacket = maxPacket;
                std::memcpy(client.lsgClientNonce, hello + 20, 8);
                for (unsigned i = 0; i < 8; ++i)
                    client.lsgServerNonce[i] = static_cast<std::uint8_t>(kIw8ReferenceServerNonce >> (i * 8));

                log::Print("[LSG-V69] HEADER_ACK_LAYOUT id=%llu advertised=%u..%u selected=%u bodyBytes=22 frameBytes=26 connectionId=0x%016llX serverNonce=0x%016llX source=IW8_REFERENCE_LAYOUT stateWrites=off",
                    static_cast<unsigned long long>(client.id), supportedMin, supportedMax,
                    client.lsgSelectedVersion,
                    static_cast<unsigned long long>(kIw8ReferenceConnectionId),
                    static_cast<unsigned long long>(kIw8ReferenceServerNonce));
                AppendLsgPipelineV63(
                    "V69_HEADER_ACK id=%llu advertised=%u..%u selected=%u bodyBytes=22 frameBytes=26 connectionId=0x%016llX next=EXPECT_NATIVE_0x82 clientStateWrites=off",
                    static_cast<unsigned long long>(client.id), supportedMin, supportedMax,
                    client.lsgSelectedVersion,
                    static_cast<unsigned long long>(kIw8ReferenceConnectionId));

                std::vector<std::uint8_t> response;
                response.reserve(26);
                AppendLe32(response, 22u); // AB/81 + DWORD + QWORD connection id + QWORD nonce
                response.push_back(0xAB);
                response.push_back(0x81);
                AppendLe32(response, client.lsgSelectedVersion);
                AppendLe64(response, kIw8ReferenceConnectionId);
                response.insert(response.end(), client.lsgServerNonce, client.lsgServerNonce + 8);

                if (!SendAllNonBlocking(client.socket, response.data(), response.size()))
                    return false;

                if (config_.dumpPayloads)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, response.data(), response.size());

                client.lsgInput.erase(client.lsgInput.begin(), client.lsgInput.begin() + 28);
                client.lsgStage = 1;
                web::NotePostLsgTransport(client.localPort, "TCP_LSG_STOCK_HELLO");
                log::Print("[LSG] id=%llu auth3Serial=%llu HELLO OK clientRange=%u..%u selected=%u maxPacket=%u; sent V69 framed 0x81 header ACK bytes=%llu",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    supportedMin, supportedMax, client.lsgSelectedVersion, client.lsgMaxPacket,
                    static_cast<unsigned long long>(response.size()));
                AppendLsgPipelineV63("HELLO_OK id=%llu auth3Serial=%llu clientRange=%u..%u selected=%u maxPacket=%u responseBytes=%llu layout=DWORD+QWORD+QWORD next=EXPECT_0x82_CLIENTCHAL",
                    static_cast<unsigned long long>(client.id), static_cast<unsigned long long>(auth3Serial),
                    supportedMin, supportedMax, client.lsgSelectedVersion, client.lsgMaxPacket,
                    static_cast<unsigned long long>(response.size()));
                continue;
            }

            if (client.lsgStage == 1)
            {
                if (client.lsgInput.size() < 4u)
                    return true;

                const std::uint32_t bodyBytes = ReadLe32(client.lsgInput.data());
                if (bodyBytes < 10u || bodyBytes > 256u * 1024u)
                {
                    log::Print("[LSG] id=%llu invalid 0x82 outer length=%u; leaving socket passive", static_cast<unsigned long long>(client.id), bodyBytes);
                    client.lsgStage = 99;
                    return true;
                }
                const std::size_t frameBytes = 4u + static_cast<std::size_t>(bodyBytes);
                if (client.lsgInput.size() < frameBytes)
                    return true;

                const std::uint8_t* frame = client.lsgInput.data();
                if (frameBytes < 14u || frame[4] != 0xAB || frame[5] != 0x82)
                {
                    log::Print("[LSG] id=%llu expected framed AB/82 response but got marker=%02X opcode=%02X length=%u; leaving socket passive",
                        static_cast<unsigned long long>(client.id), frameBytes > 4 ? frame[4] : 0u,
                        frameBytes > 5 ? frame[5] : 0u, bodyBytes);
                    client.lsgStage = 99;
                    return true;
                }

                AppendLsgPipelineV63(
                    "NEGOTIATION_ACCEPTED id=%llu selected=%u client82Bytes=%llu milestone=CLIENT_SENT_0x82 clientStateWrites=off",
                    static_cast<unsigned long long>(client.id), client.lsgSelectedVersion,
                    static_cast<unsigned long long>(frameBytes));

                // Stock sub_14232D1B0 hashes the exact connection transcript:
                // 210, 220, maxPacket, client nonce, complete server 0x81 frame,
                // then the client 0x82 frame excluding its final 8-byte proof.
                std::vector<std::uint8_t> transcript;
                transcript.reserve(64u + frameBytes);
                AppendLe32(transcript, 210u);
                AppendLe32(transcript, 220u);
                AppendLe32(transcript, client.lsgMaxPacket);
                transcript.insert(transcript.end(), client.lsgClientNonce, client.lsgClientNonce + 8);
                // Hash the complete V69 server header ACK exactly as it was sent.
                // This mirrors the IW8 reference transcript: 20-byte hello remainder,
                // complete 26-byte server 0x81 frame, then client 0x82 without its
                // trailing 8-byte proof.
                constexpr std::uint64_t kIw8ReferenceConnectionId = 0x3713371337133713ull;
                AppendLe32(transcript, 22u);
                transcript.push_back(0xAB);
                transcript.push_back(0x81);
                AppendLe32(transcript, client.lsgSelectedVersion);
                AppendLe64(transcript, kIw8ReferenceConnectionId);
                transcript.insert(transcript.end(), client.lsgServerNonce, client.lsgServerNonce + 8);
                transcript.insert(transcript.end(), frame, frame + frameBytes - 8u);

                std::uint8_t transcriptHash[20]{};
                if (!BCryptSha1(transcript.data(), transcript.size(), transcriptHash))
                {
                    log::Print("[LSG] id=%llu could not materialize transcript SHA1; no guessed reply sent",
                        static_cast<unsigned long long>(client.id));
                    client.lsgStage = 99;
                    return true;
                }

                // V78: preserve IW8's exact AuthSessionKeyKDF path but remove the
                // V77 runtime KEY_3 extractor. The client bridge scans the game EXE
                // file on disk for all structurally valid 294-byte RSA SPKI values.
                // We try those public DER candidates only against the native 0x82
                // proof. Nothing is accepted unless IW8's first 8 CLIENTCHAL bytes
                // are reproduced exactly.
                constexpr std::size_t kMaxKeySources = 12u;
                std::array<std::uint8_t, kMaxKeySources * 24u> sessionKeys{};
                std::array<std::uint32_t, kMaxKeySources> keyKinds{};
                std::uint64_t auth3Serial = 0;
                const std::size_t keySourceCount = web::GetLsgSessionKeyCandidatesV72(
                    sessionKeys.data(), keyKinds.data(), keyKinds.size(), &auth3Serial);

                const std::uint8_t* auth3ClientTicketSessionKey = nullptr;
                for (std::size_t keyIndex = 0; keyIndex < keySourceCount; ++keyIndex)
                {
                    if (keyKinds[keyIndex] == 2u) // AUTH3_CLIENT_TICKET_SESSIONKEY
                    {
                        auth3ClientTicketSessionKey = sessionKeys.data() + keyIndex * 24u;
                        break;
                    }
                }
                if (!auth3ClientTicketSessionKey)
                {
                    log::Print("[LSG-V78] IW8_KDF_INPUT_MISSING id=%llu auth3Serial=%llu source=AUTH3_CLIENT_TICKET_SESSIONKEY action=NO_0x83",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial));
                    AppendLsgPipelineV63("V78_IW8_KDF_INPUT_MISSING id=%llu auth3Serial=%llu action=NO_0x83",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial));
                    client.lsgStage = 99;
                    return true;
                }

                std::vector<AuthTrafficSigningKeyCandidateV78> key3Candidates;
                std::wstring key3PackPath;
                if (!LoadAuthTrafficSigningKeyCandidatesV78(key3Candidates, &key3PackPath) || key3Candidates.empty())
                {
                    log::Print("[LSG-V78] IW8_KDF_KEY3_CANDIDATES_MISSING id=%llu auth3Serial=%llu expectedFile=iw8-auth-traffic-signing-key3-candidates.bin action=NO_0x83",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial));
                    AppendLsgPipelineV63("V78_IW8_KDF_KEY3_CANDIDATES_MISSING id=%llu auth3Serial=%llu action=NO_0x83",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial));
                    client.lsgStage = 99;
                    return true;
                }

                const char clientChalLabel[] = "CLIENTCHAL";
                const char bdDataLabel[] = "BDDATA";
                const std::uint8_t* clientProof = frame + frameBytes - 8u;
                std::uint8_t chosenPrk[20]{};
                std::uint8_t chosenChallenge[16]{};
                std::size_t matchedCandidate = static_cast<std::size_t>(-1);

                log::Print("[LSG-V78] KEY3_ORACLE_BEGIN id=%llu auth3Serial=%llu candidates=%llu source=ON_DISK_EXE_DER transcriptBytes=%llu clientProof=%02X%02X%02X%02X%02X%02X%02X%02X",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(key3Candidates.size()),
                    static_cast<unsigned long long>(transcript.size()),
                    clientProof[0], clientProof[1], clientProof[2], clientProof[3],
                    clientProof[4], clientProof[5], clientProof[6], clientProof[7]);

                for (std::size_t candidateIndex = 0; candidateIndex < key3Candidates.size(); ++candidateIndex)
                {
                    const auto& candidate = key3Candidates[candidateIndex];
                    std::array<std::uint8_t, 24> trafficSessionKey{};
                    std::uint8_t candidatePrk[20]{};
                    std::uint8_t candidateChallenge[16]{};

                    const bool expanded = HkdfExpandSha1Key(auth3ClientTicketSessionKey, 24u,
                        candidate.der.data(), candidate.der.size(),
                        trafficSessionKey.data(), trafficSessionKey.size());
                    const bool extracted = expanded && BCryptHmacSha1(transcriptHash, sizeof(transcriptHash),
                        trafficSessionKey.data(), trafficSessionKey.size(), candidatePrk);
                    const bool challenged = extracted && HkdfExpandSha1(candidatePrk,
                        reinterpret_cast<const std::uint8_t*>(clientChalLabel), 10u,
                        candidateChallenge, sizeof(candidateChallenge));
                    const bool match = challenged && EqualBytes(candidateChallenge, clientProof, 8u);

                    log::Print("[LSG-V78] KEY3_CANDIDATE id=%llu index=%llu fileOffset=0x%llX derivedProof=%02X%02X%02X%02X%02X%02X%02X%02X valid=%s match=%s",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(candidateIndex),
                        static_cast<unsigned long long>(candidate.fileOffset),
                        candidateChallenge[0], candidateChallenge[1], candidateChallenge[2], candidateChallenge[3],
                        candidateChallenge[4], candidateChallenge[5], candidateChallenge[6], candidateChallenge[7],
                        challenged ? "yes" : "no", match ? "YES" : "no");

                    if (!match)
                        continue;

                    std::memcpy(chosenPrk, candidatePrk, sizeof(chosenPrk));
                    std::memcpy(chosenChallenge, candidateChallenge, sizeof(chosenChallenge));
                    matchedCandidate = candidateIndex;
                    break;
                }

                if (matchedCandidate == static_cast<std::size_t>(-1))
                {
                    log::Print("[LSG-V78] KEY3_ORACLE_NO_MATCH id=%llu auth3Serial=%llu candidates=%llu clientProof=%02X%02X%02X%02X%02X%02X%02X%02X action=NO_0x83 next=VERIFY_OTHER_KDF_INPUTS",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial),
                        static_cast<unsigned long long>(key3Candidates.size()),
                        clientProof[0], clientProof[1], clientProof[2], clientProof[3],
                        clientProof[4], clientProof[5], clientProof[6], clientProof[7]);
                    AppendLsgPipelineV63("V78_KEY3_ORACLE_NO_MATCH id=%llu auth3Serial=%llu candidates=%llu action=NO_0x83 next=VERIFY_OTHER_KDF_INPUTS",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial),
                        static_cast<unsigned long long>(key3Candidates.size()));
                    client.lsgStage = 99;
                    return true;
                }

                std::uint8_t chosenBdData[72]{};
                if (!HkdfExpandSha1(chosenPrk,
                        reinterpret_cast<const std::uint8_t*>(bdDataLabel), 6u,
                        chosenBdData, sizeof(chosenBdData)))
                {
                    log::Print("[LSG-V78] IW8_KDF_BDDATA_FAILED id=%llu action=NO_0x83",
                        static_cast<unsigned long long>(client.id));
                    client.lsgStage = 99;
                    return true;
                }

                client.lsgCryptoVariant = "IW8_AUTHSESSIONKEYKDF_SHA1_V78";
                std::memcpy(client.lsgPrk, chosenPrk, sizeof(client.lsgPrk));
                std::memcpy(client.lsgBdData, chosenBdData, sizeof(client.lsgBdData));

                const auto& matchedKey = key3Candidates[matchedCandidate];
                log::Print("[LSG-V78] IW8_KDF_PROOF_MATCH id=%llu auth3Serial=%llu source=AUTH3_CLIENT_TICKET_SESSIONKEY key3Source=ON_DISK_EXE_DER candidate=%llu fileOffset=0x%llX transcriptBytes=%llu responseId=%02X%02X%02X%02X%02X%02X%02X%02X action=SEND_NATIVE_0x83",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(matchedCandidate),
                    static_cast<unsigned long long>(matchedKey.fileOffset),
                    static_cast<unsigned long long>(transcript.size()),
                    chosenChallenge[8], chosenChallenge[9], chosenChallenge[10], chosenChallenge[11],
                    chosenChallenge[12], chosenChallenge[13], chosenChallenge[14], chosenChallenge[15]);
                AppendLsgPipelineV63("V78_IW8_KDF_PROOF_MATCH id=%llu auth3Serial=%llu candidate=%llu fileOffset=0x%llX next=SEND_0x83_THEN_EXPECT_0x85",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(matchedCandidate),
                    static_cast<unsigned long long>(matchedKey.fileOffset));

                std::vector<std::uint8_t> response;
                response.reserve(14);
                AppendLe32(response, 10u);
                response.push_back(0xAB);
                response.push_back(0x83);
                response.insert(response.end(), chosenChallenge + 8, chosenChallenge + 16);
                if (!SendAllNonBlocking(client.socket, response.data(), response.size()))
                    return false;
                if (config_.dumpPayloads)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, response.data(), response.size());

                client.lsgInput.erase(client.lsgInput.begin(), client.lsgInput.begin() + static_cast<std::ptrdiff_t>(frameBytes));
                client.lsgStage = 2;
                log::Print("[LSG-V78] SERVER_AUTH_DONE id=%llu auth3Serial=%llu sentBytes=%llu opcode=0x83 proofSource=IW8_AUTHSESSIONKEYKDF next=EXPECT_SECURE_0x85",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(response.size()));
                AppendLsgPipelineV63("V78_SERVER_AUTH_DONE id=%llu auth3Serial=%llu sentBytes=%llu next=EXPECT_SECURE_0x85",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(response.size()));
                continue;
            }

            if (client.lsgStage == 2)
            {
                if (client.lsgInput.size() < 4u)
                    return true;
                const std::uint32_t bodyBytes = ReadLe32(client.lsgInput.data());
                // V96: IW8 can emit a four-byte zero-length outer record while an
                // authenticated 2.x lobby connection is idle.  It carries no task
                // payload and must not poison the secure-stream parser.  Consume
                // only the empty record and keep stage 2 so a coalesced/following
                // 0x85 frame is decoded normally.
                if (bodyBytes == 0u)
                {
                    log::Print("[LSG-V96] id=%llu zero-length secure outer frame accepted as no-op/keepalive; stage=2 preserved bufferedBefore=%llu bufferedAfter=%llu",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(client.lsgInput.size()),
                        static_cast<unsigned long long>(client.lsgInput.size() - 4u));
                    AppendLsgPipelineV63(
                        "V96_ZERO_LENGTH_NOOP id=%llu stage=2 bytes=4 bufferedBefore=%llu bufferedAfter=%llu next=EXPECT_SECURE_0x85 stateWrites=off",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(client.lsgInput.size()),
                        static_cast<unsigned long long>(client.lsgInput.size() - 4u));
                    client.lsgInput.erase(client.lsgInput.begin(), client.lsgInput.begin() + 4);
                    continue;
                }
                if (bodyBytes < 2u || bodyBytes > 1024u * 1024u)
                {
                    log::Print("[LSG] id=%llu secure-stage invalid outer length=%u; retaining connection for diagnostics",
                        static_cast<unsigned long long>(client.id), bodyBytes);
                    client.lsgStage = 99;
                    return true;
                }
                const std::size_t frameBytes = 4u + static_cast<std::size_t>(bodyBytes);
                if (client.lsgInput.size() < frameBytes)
                    return true;

                const std::uint8_t marker = frameBytes > 4u ? client.lsgInput[4] : 0u;
                const std::uint8_t opcode = frameBytes > 5u ? client.lsgInput[5] : 0u;
                if (marker == 0xAB && opcode == 0x85 && frameBytes >= 34u)
                {
                    const std::uint32_t counter = ReadLe32(client.lsgInput.data() + 6);
                    const std::uint8_t* seed = client.lsgInput.data() + 10;
                    const std::size_t encryptedBytes = frameBytes - 34u;
                    const std::uint8_t* encrypted = client.lsgInput.data() + 26;
                    const std::uint8_t* receivedHash = client.lsgInput.data() + frameBytes - 8u;

                    std::uint8_t computedHash[20]{};
                    const bool hashOk = BCryptHmacSha1(client.lsgBdData, 20,
                        client.lsgInput.data(), frameBytes - 8u, computedHash) &&
                        EqualBytes(computedHash, receivedHash, 8u);

                    std::vector<std::uint8_t> plain;
                    const bool decryptOk = hashOk && encryptedBytes && (encryptedBytes & 15u) == 0u &&
                        BCryptAesCbcCrypt(false, client.lsgBdData + 40, seed, encrypted, encryptedBytes, plain);

                    if (!hashOk)
                    {
                        log::Print("[LSG] id=%llu secure 0x85 counter=%u HMAC mismatch; no fake success reply sent",
                            static_cast<unsigned long long>(client.id), counter);
                    }
                    else if (!decryptOk || plain.size() < 8u)
                    {
                        log::Print("[LSG] id=%llu secure 0x85 counter=%u decrypt/shape failed encryptedBytes=%llu; no fake success reply sent",
                            static_cast<unsigned long long>(client.id), counter,
                            static_cast<unsigned long long>(encryptedBytes));
                    }
                    else
                    {
                        const auto taskRequest = demonware::DecodeTaskRequest(plain);
                        const std::string taskDescription = demonware::DescribeTaskRequest(taskRequest);
                        log::Print("[LSG-DECODE] id=%llu secure 0x85 counter=%u %s encryptedBytes=%llu packetMatching=off",
                            static_cast<unsigned long long>(client.id), counter, taskDescription.c_str(),
                            static_cast<unsigned long long>(encryptedBytes));
                        AppendLsgPipelineV63("SECURE_0x85_DECODE id=%llu counter=%u %s encryptedBytes=%llu routing=SEMANTIC",
                            static_cast<unsigned long long>(client.id), counter, taskDescription.c_str(),
                            static_cast<unsigned long long>(encryptedBytes));

                        const demonware::TaskRoute* censusRoute = taskRequest.valid
                            ? demonware::FindTaskRoute(taskRequest.serviceId, taskRequest.taskId) : nullptr;
                        RecordPostLoginTaskCensus(client.id, counter, plain, taskRequest, censusRoute);

                        if (!taskRequest.valid)
                        {
                            log::Print("[LSG-COMPAT] id=%llu secure task decode rejected reason=%s policy=DO_NOT_GUESS_RESPONSE_BYTES",
                                static_cast<unsigned long long>(client.id),
                                taskRequest.error.empty() ? "unknown" : taskRequest.error.c_str());
                        }
                        else if (const demonware::TaskRoute* route = demonware::FindTaskRoute(taskRequest.serviceId, taskRequest.taskId))
                        {
                            if (route->replyPolicy == demonware::ReplyPolicy::None)
                            {
                                log::Print("[LSG-KNOWN-UNIMPLEMENTED] id=%llu service=%u(%s) task=%u(%s) payloadBytes=%llu policy=DO_NOT_GUESS_RESPONSE_BYTES",
                                    static_cast<unsigned long long>(client.id),
                                    static_cast<unsigned>(taskRequest.serviceId), route->serviceName ? route->serviceName : "?",
                                    static_cast<unsigned>(taskRequest.taskId), route->taskName ? route->taskName : "?",
                                    static_cast<unsigned long long>(taskRequest.payloadBytes));
                            }
                            else
                            {
                                const std::uint64_t transactionId = client.lsgTransactionId + 1u;
                                std::vector<std::uint8_t> replyPlain;
                                const std::uint8_t* requestPayload = taskRequest.payloadBytes
                                    ? plain.data() + taskRequest.payloadOffset : nullptr;
                                if (!demonware::BuildTaskReply(*route, taskRequest, requestPayload, taskRequest.payloadBytes,
                                    transactionId, replyPlain))
                                {
                                    if (taskRequest.serviceId == 255u && taskRequest.taskId == 0x0Au)
                                    {
                                        log::Print("[LSG-REST] id=%llu counter=%u REST service/operation not reconstructed; no reply sent",
                                            static_cast<unsigned long long>(client.id), counter);
                                    }
                                    log::Print("[LSG] id=%llu service=%u task=%u route=%s/%s could not serialize semantic reply",
                                        static_cast<unsigned long long>(client.id),
                                        static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId),
                                        route->serviceName ? route->serviceName : "?", route->taskName ? route->taskName : "?");
                                }
                                else
                                {
                                    client.lsgTransactionId = transactionId;
                                    const std::array<std::uint8_t, 16> replySeed{
                                    0x5E,0xED,0x5E,0xED,0x5E,0xED,0x5E,0xED,
                                    0x5E,0xED,0x5E,0xED,0x5E,0xED,0x5E,0xED
                                };
                                std::vector<std::uint8_t> replyEncrypted;
                                if (BCryptAesCbcCrypt(true, client.lsgBdData + 56, replySeed.data(),
                                        replyPlain.data(), replyPlain.size(), replyEncrypted))
                                {
                                    std::vector<std::uint8_t> response;
                                    AppendLe32(response, 30u + static_cast<std::uint32_t>(replyEncrypted.size()));
                                    response.push_back(0xAB);
                                    response.push_back(0x85);
                                    AppendLe32(response, ++client.lsgSendCounter);
                                    response.insert(response.end(), replySeed.begin(), replySeed.end());
                                    response.insert(response.end(), replyEncrypted.begin(), replyEncrypted.end());

                                    std::uint8_t responseHash[20]{};
                                    if (BCryptHmacSha1(client.lsgBdData + 20, 20, response.data(), response.size(), responseHash))
                                    {
                                        response.insert(response.end(), responseHash, responseHash + 8);
                                        if (!SendAllNonBlocking(client.socket, response.data(), response.size()))
                                            return false;
                                        if (config_.dumpPayloads)
                                            log::Payload(client.id, "OUT", client.localPort, client.peer, response.data(), response.size());
                                        log::Print("[LSG-ROUTE] id=%llu service=%u(%s) task=%u(%s) semantic reply sent counter=%u bytes=%llu transaction=%llu",
                                            static_cast<unsigned long long>(client.id),
                                            static_cast<unsigned>(taskRequest.serviceId), route->serviceName ? route->serviceName : "?",
                                            static_cast<unsigned>(taskRequest.taskId), route->taskName ? route->taskName : "?",
                                            client.lsgSendCounter, static_cast<unsigned long long>(response.size()),
                                            static_cast<unsigned long long>(transactionId));
                                        AppendLsgPipelineV63("SEMANTIC_TASK_REPLY_OK id=%llu service=%u task=%u counter=%u bytes=%llu transaction=%llu next=EXPECT_LOGIN_COMPLETE_OR_READY",
                                            static_cast<unsigned long long>(client.id),
                                            static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId),
                                            client.lsgSendCounter, static_cast<unsigned long long>(response.size()),
                                            static_cast<unsigned long long>(transactionId));
                                    }
                                    else
                                    {
                                        log::Print("[LSG] id=%llu semantic task reply HMAC generation failed service=%u task=%u",
                                            static_cast<unsigned long long>(client.id),
                                            static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId));
                                    }
                                }
                                else
                                {
                                    log::Print("[LSG] id=%llu semantic task reply AES encryption failed service=%u task=%u",
                                        static_cast<unsigned long long>(client.id),
                                        static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId));
                                }
                                }
                            }
                        }
                        else
                        {
                            log::Print("[LSG-UNSUPPORTED] id=%llu service=%u task=%u payloadBytes=%llu policy=DO_NOT_GUESS_RESPONSE_BYTES",
                                static_cast<unsigned long long>(client.id),
                                static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId),
                                static_cast<unsigned long long>(taskRequest.payloadBytes));
                        }
                    }
                }
                else
                {
                    log::Print("[LSG] id=%llu post-handshake frame marker=%02X opcode=%02X bytes=%llu",
                        static_cast<unsigned long long>(client.id), marker, opcode,
                        static_cast<unsigned long long>(frameBytes));
                }
                client.lsgInput.erase(client.lsgInput.begin(), client.lsgInput.begin() + static_cast<std::ptrdiff_t>(frameBytes));
                continue;
            }
        }
    }

}
