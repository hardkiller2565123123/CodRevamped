#include "Server.h"
#include "Log.h"
#include "Protocol.h"
#include "Bgs/BgsDispatcher.h"
#include "Web/WebAuthService.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32
#include <Windows.h>
#include <TlHelp32.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <utility>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace revamped::iw8
{
    namespace
    {
        std::string EndpointToString(const sockaddr* address, int length)
        {
            if (!address || length < static_cast<int>(sizeof(sockaddr))) return "<unknown>";
            char buffer[128]{};
            if (address->sa_family == AF_INET && length >= static_cast<int>(sizeof(sockaddr_in)))
            {
                const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
                const auto* bytes = reinterpret_cast<const unsigned char*>(&v4->sin_addr.s_addr);
                _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "%u.%u.%u.%u:%u",
                    bytes[0], bytes[1], bytes[2], bytes[3], ntohs(v4->sin_port));
                return buffer;
            }
            if (address->sa_family == AF_INET6 && length >= static_cast<int>(sizeof(sockaddr_in6)))
            {
                const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
                _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "[ipv6]:%u", ntohs(v6->sin6_port));
                return buffer;
            }
            _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "family=%d", address->sa_family);
            return buffer;
        }

        void MakeNonBlocking(SOCKET socket)
        {
            u_long value = 1;
            ioctlsocket(socket, FIONBIO, &value);
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

        std::wstring DirectoryOfPath(std::wstring path)
        {
            const std::size_t slash = path.find_last_of(L"\\/");
            if (slash == std::wstring::npos)
                return {};
            path.resize(slash);
            return path;
        }

        void AddUniqueBundleCandidate(std::vector<std::wstring>& candidates, const std::wstring& path)
        {
            if (path.empty())
                return;
            for (const auto& existing : candidates)
            {
                if (_wcsicmp(existing.c_str(), path.c_str()) == 0)
                    return;
            }
            candidates.push_back(path);
        }

        bool WriteSmallUtf8File(const std::wstring& path, const std::string& text)
        {
            if (path.empty() || text.empty())
                return false;
            HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;
            DWORD written = 0;
            const BOOL ok = WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
            FlushFileBuffers(file);
            CloseHandle(file);
            return ok && written == text.size();
        }

        std::wstring RunningModernWarfareDirectory()
        {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return {};

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            std::wstring result;
            if (Process32FirstW(snapshot, &entry))
            {
                do
                {
                    if (_wcsicmp(entry.szExeFile, L"ModernWarfare.exe") != 0)
                        continue;

                    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                    if (!process)
                        continue;

                    wchar_t imagePath[32768]{};
                    DWORD imageLength = static_cast<DWORD>(sizeof(imagePath) / sizeof(imagePath[0]));
                    if (QueryFullProcessImageNameW(process, 0, imagePath, &imageLength) && imageLength)
                        result = DirectoryOfPath(std::wstring(imagePath, imageLength));
                    CloseHandle(process);
                    if (!result.empty())
                        break;
                } while (Process32NextW(snapshot, &entry));
            }

            CloseHandle(snapshot);
            return result;
        }

        bool TryLoadStockBgsCertificateBundle(const std::wstring& path, std::vector<unsigned char>& bytes)
        {
            bytes.clear();
            FILE* file = nullptr;
            if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || !file)
                return false;

            if (fseek(file, 0, SEEK_END) != 0)
            {
                fclose(file);
                return false;
            }
            const long sizeLong = ftell(file);
            if (sizeLong <= 260 || sizeLong > 1024 * 1024)
            {
                fclose(file);
                return false;
            }
            rewind(file);

            bytes.resize(static_cast<std::size_t>(sizeLong));
            const std::size_t read = fread(bytes.data(), 1, bytes.size(), file);
            fclose(file);
            if (read != bytes.size() || bytes.empty() || bytes[0] != '{')
            {
                bytes.clear();
                return false;
            }

            const std::string json(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            if (json.find("\"Certificates\"") == std::string::npos ||
                json.find("\"PublicKeys\"") == std::string::npos ||
                json.find("\"SigningCertificates\"") == std::string::npos)
            {
                bytes.clear();
                return false;
            }

            std::size_t end = bytes.size();
            while (end && (bytes[end - 1] == '\r' || bytes[end - 1] == '\n' || bytes[end - 1] == ' ' || bytes[end - 1] == '\t'))
                --end;
            if (!end || bytes[end - 1] != '}')
            {
                bytes.clear();
                return false;
            }
            bytes.resize(end);
            return true;
        }

        std::vector<unsigned char> LoadStockBgsCertificateBundle()
        {
            std::vector<std::wstring> candidates;

            wchar_t envPath[32768]{};
            const DWORD envLength = GetEnvironmentVariableW(
                L"REVAMPED_IW8_BGS_BUNDLE",
                envPath,
                static_cast<DWORD>(sizeof(envPath) / sizeof(envPath[0])));
            if (envLength && envLength < (sizeof(envPath) / sizeof(envPath[0])))
                AddUniqueBundleCandidate(candidates, envPath);

            wchar_t serverPath[32768]{};
            const DWORD serverLength = GetModuleFileNameW(
                nullptr,
                serverPath,
                static_cast<DWORD>(sizeof(serverPath) / sizeof(serverPath[0])));
            const std::wstring serverDir =
                (serverLength && serverLength < (sizeof(serverPath) / sizeof(serverPath[0])))
                ? DirectoryOfPath(std::wstring(serverPath, serverLength))
                : std::wstring{};

            if (!serverDir.empty())
            {
                AddUniqueBundleCandidate(candidates, serverDir + L"\\bgs-key-fingerprint.stock");
                AddUniqueBundleCandidate(candidates, serverDir + L"\\CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock");
            }

            wchar_t currentDirectory[32768]{};
            const DWORD currentLength = GetCurrentDirectoryW(
                static_cast<DWORD>(sizeof(currentDirectory) / sizeof(currentDirectory[0])),
                currentDirectory);
            if (currentLength && currentLength < (sizeof(currentDirectory) / sizeof(currentDirectory[0])))
            {
                const std::wstring cwd(currentDirectory, currentLength);
                AddUniqueBundleCandidate(candidates, cwd + L"\\bgs-key-fingerprint.stock");
                AddUniqueBundleCandidate(candidates, cwd + L"\\CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock");
            }

            const std::wstring gameDir = RunningModernWarfareDirectory();
            if (!gameDir.empty())
            {
                AddUniqueBundleCandidate(candidates, gameDir + L"\\bgs-key-fingerprint.stock");
                AddUniqueBundleCandidate(candidates, gameDir + L"\\CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock");
            }

            std::vector<unsigned char> bytes;
            for (const auto& path : candidates)
            {
                if (!TryLoadStockBgsCertificateBundle(path, bytes))
                    continue;

                char utf8[32768]{};
                WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, utf8, static_cast<int>(sizeof(utf8)), nullptr, nullptr);
                log::Print("[BGS-BUNDLE] resolved stock bundle path=%s bytes=%llu",
                    utf8[0] ? utf8 : "<wide-path>",
                    static_cast<unsigned long long>(bytes.size()));
                return bytes;
            }

            log::Print("[BGS-BUNDLE] stock bundle lookup failed candidates=%llu serverDir=%ls gameDir=%ls",
                static_cast<unsigned long long>(candidates.size()),
                serverDir.empty() ? L"<unknown>" : serverDir.c_str(),
                gameDir.empty() ? L"<not-found>" : gameDir.c_str());
            return {};
        }

        std::uint16_t ReadBe16(const unsigned char* p)
        {
            return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
        }

        std::uint32_t ReadBe24(const unsigned char* p)
        {
            return (static_cast<std::uint32_t>(p[0]) << 16) |
                   (static_cast<std::uint32_t>(p[1]) << 8) |
                   static_cast<std::uint32_t>(p[2]);
        }

        const char* TlsVersionName(std::uint16_t version)
        {
            switch (version)
            {
            case 0x0301: return "TLS1.0";
            case 0x0302: return "TLS1.1";
            case 0x0303: return "TLS1.2";
            case 0x0304: return "TLS1.3";
            default: return "unknown";
            }
        }

        std::string Hex16(std::uint16_t value)
        {
            char out[16]{};
            _snprintf_s(out, sizeof(out), _TRUNCATE, "0x%04X", static_cast<unsigned>(value));
            return out;
        }

        bool LogTlsClientHello(std::uint64_t id, std::uint16_t localPort, const unsigned char* data, std::size_t size, std::string* sniOut = nullptr)
        {
            if (!data || size < 9 || data[0] != 0x16 || data[5] != 0x01) return false;
            const std::size_t recordLength = ReadBe16(data + 3);
            if (recordLength + 5 > size) return false;
            const std::size_t helloLength = ReadBe24(data + 6);
            if (helloLength + 9 > size) return false;

            const std::uint16_t recordVersion = ReadBe16(data + 1);
            std::size_t off = 9;
            if (off + 34 > size) return false;
            const std::uint16_t legacyVersion = ReadBe16(data + off);
            off += 34; // version + random

            if (off + 1 > size) return false;
            const std::size_t sessionLength = data[off++];
            if (off + sessionLength > size) return false;
            off += sessionLength;

            if (off + 2 > size) return false;
            const std::size_t cipherLength = ReadBe16(data + off);
            off += 2;
            if (off + cipherLength > size || (cipherLength & 1u)) return false;
            std::ostringstream ciphers;
            for (std::size_t i = 0; i < cipherLength; i += 2)
            {
                if (i) ciphers << ',';
                ciphers << Hex16(ReadBe16(data + off + i));
            }
            off += cipherLength;

            if (off + 1 > size) return false;
            const std::size_t compressionLength = data[off++];
            if (off + compressionLength > size) return false;
            off += compressionLength;

            std::string sni;
            std::string alpn;
            std::ostringstream extensions;
            std::ostringstream supportedVersions;
            if (off + 2 <= size)
            {
                const std::size_t extensionsLength = ReadBe16(data + off);
                off += 2;
                const std::size_t extensionsEnd = (std::min)(size, off + extensionsLength);
                bool firstExtension = true;
                while (off + 4 <= extensionsEnd)
                {
                    const std::uint16_t type = ReadBe16(data + off);
                    const std::size_t length = ReadBe16(data + off + 2);
                    off += 4;
                    if (off + length > extensionsEnd) break;
                    if (!firstExtension) extensions << ',';
                    firstExtension = false;
                    extensions << Hex16(type);

                    if (type == 0x0000 && length >= 5)
                    {
                        std::size_t pos = off;
                        const std::size_t listLength = ReadBe16(data + pos);
                        pos += 2;
                        const std::size_t listEnd = (std::min)(off + length, pos + listLength);
                        while (pos + 3 <= listEnd)
                        {
                            const unsigned char nameType = data[pos++];
                            const std::size_t nameLength = ReadBe16(data + pos);
                            pos += 2;
                            if (pos + nameLength > listEnd) break;
                            if (nameType == 0)
                            {
                                sni.assign(reinterpret_cast<const char*>(data + pos), nameLength);
                                break;
                            }
                            pos += nameLength;
                        }
                    }
                    else if (type == 0x0010 && length >= 2)
                    {
                        std::size_t pos = off;
                        const std::size_t listLength = ReadBe16(data + pos);
                        pos += 2;
                        const std::size_t listEnd = (std::min)(off + length, pos + listLength);
                        bool first = true;
                        while (pos < listEnd)
                        {
                            const std::size_t itemLength = data[pos++];
                            if (pos + itemLength > listEnd) break;
                            if (!first) alpn += ',';
                            first = false;
                            alpn.append(reinterpret_cast<const char*>(data + pos), itemLength);
                            pos += itemLength;
                        }
                    }
                    else if (type == 0x002B && length >= 3)
                    {
                        std::size_t pos = off;
                        const std::size_t listLength = data[pos++];
                        const std::size_t listEnd = (std::min)(off + length, pos + listLength);
                        bool first = true;
                        while (pos + 2 <= listEnd)
                        {
                            const std::uint16_t version = ReadBe16(data + pos);
                            pos += 2;
                            if (!first) supportedVersions << ',';
                            first = false;
                            supportedVersions << TlsVersionName(version) << '(' << Hex16(version) << ')';
                        }
                    }
                    off += length;
                }
            }

            log::Print("[TLS%u] id=%llu ClientHello record=%s(%s) legacy=%s(%s) recordBytes=%llu helloBytes=%llu",
                static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), TlsVersionName(recordVersion), Hex16(recordVersion).c_str(),
                TlsVersionName(legacyVersion), Hex16(legacyVersion).c_str(),
                static_cast<unsigned long long>(recordLength + 5), static_cast<unsigned long long>(helloLength));
            log::Print("[TLS%u] id=%llu sni=%s alpn=%s supportedVersions=%s",
                static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), sni.empty() ? "<none>" : sni.c_str(),
                alpn.empty() ? "<none>" : alpn.c_str(), supportedVersions.str().empty() ? "<legacy-only>" : supportedVersions.str().c_str());
            log::Print("[TLS%u] id=%llu cipherSuites=%s", static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), ciphers.str().c_str());
            log::Print("[TLS%u] id=%llu extensions=%s", static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), extensions.str().c_str());
            if (sniOut)
                *sniOut = sni;
            return true;
        }

        struct TlsSession
        {
            std::uint16_t localPort = 1119;
            CtxtHandle context{};
            bool contextValid = false;
            bool established = false;
            bool helloLogged = false;
            bool credentialLogged = false;
            std::string sni;
            bool bgsApplicationSeen = false;
            bool serverFirstLogged = false;
            bool challengeProbeSent = false;
            bool webAuthChallengeSent = false;
            bool webAuthChallengeUnsupported = false;
            std::uint32_t webAuthChallengeToken = 0;
            bool webAuthHttpServed = false;
            bgs::SessionState bgs;
            bool websocketUpgradeSeen = false;
            bool websocketUpgraded = false;
            ULONGLONG establishedAtMs = 0;
            std::uint64_t decryptedApplicationCount = 0;
            std::uint64_t websocketFrameCount = 0;
            std::vector<unsigned char> input;
            std::vector<unsigned char> websocketInput;
            std::vector<unsigned char> httpInput;
            SecPkgContext_StreamSizes streamSizes{};
        };

        CredHandle g_tlsCredential{};
        CredHandle g_tls443BattleNetCredential{};
        CredHandle g_tls443DemonwareCredential{};
        bool g_tlsCredentialValid = false;
        bool g_tls443BattleNetCredentialValid = false;
        bool g_tls443DemonwareCredentialValid = false;
        bool g_tlsCredentialAttempted = false;
        // TLS trust is intentionally split into a root CA and a server leaf.
        // The BGS bundle trusts the CA; SChannel presents only the leaf, signed
        // by that CA.  The bundle-signing RSA key below remains a third,
        // independent keypair.
        PCCERT_CONTEXT g_tlsCertificate = nullptr;      // BGS leaf: us.actual.battle.net
        PCCERT_CONTEXT g_tls443BattleNetCertificate = nullptr; // web leaf: us.battle.net
        PCCERT_CONTEXT g_tls443DemonwareCertificate = nullptr; // web leaf: iw8-bnet-auth3.prod.demonware.net
        PCCERT_CONTEXT g_tlsCaCertificate = nullptr;    // local BGS root CA
        HCRYPTPROV g_tlsProvider = 0;                   // leaf private-key provider
        HCRYPTPROV g_tlsCaProvider = 0;                 // CA private-key provider
        std::string g_tlsSpkiSha256;                    // CA SPKI SHA-256
        std::string g_tlsLeafSpkiSha256;                // BGS leaf SPKI SHA-256
        std::string g_tls443BattleNetSpkiSha256;        // exact :443 Battle.net leaf SPKI
        std::string g_tls443DemonwareSpkiSha256;        // exact :443 Demonware leaf SPKI
        // Schannel/libcurl performs certificate revocation checking by default.
        // Our local leaves therefore advertise a loopback CRL distribution point,
        // and the server publishes a signed empty CRL from the local CA on :80.
        std::vector<unsigned char> g_tlsCrlDer;
        std::vector<unsigned char> g_tlsCrlDistributionPointBytes;
        constexpr wchar_t kLocalCrlUrl[] = L"http://127.0.0.1/__revamped/iw8.crl";
        HCRYPTKEY g_tlsKey = 0;
        HCRYPTKEY g_tlsCaKey = 0;

        // Option 2 trust bootstrap: this key signs only the local BGS certificate
        // bundle. It is deliberately separate from the TLS server key. The DLL
        // trusts the public modulus only; no login/fence/LUI state is changed.
        HCRYPTPROV g_bundleSignerProvider = 0;
        HCRYPTKEY g_bundleSignerKey = 0;
        bool g_bundleSignerReady = false;
        std::vector<unsigned char> g_bundleSignerModulusLe;

        std::string HexBytes(const BYTE* data, DWORD size)
        {
            if (!data || !size) return {};
            std::ostringstream out;
            out << std::hex << std::uppercase << std::setfill('0');
            for (DWORD i = 0; i < size; ++i)
            {
                if (i) out << ':';
                out << std::setw(2) << static_cast<unsigned>(data[i]);
            }
            return out.str();
        }

        std::string HexBytesCompact(const BYTE* data, DWORD size)
        {
            if (!data || !size) return {};
            std::ostringstream out;
            out << std::hex << std::uppercase << std::setfill('0');
            for (DWORD i = 0; i < size; ++i)
                out << std::setw(2) << static_cast<unsigned>(data[i]);
            return out.str();
        }

        void ExportLocalTrustSpkiManifest()
        {
            if (g_tlsSpkiSha256.size() != 64 ||
                g_tlsLeafSpkiSha256.size() != 64 ||
                g_tls443BattleNetSpkiSha256.size() != 64 ||
                g_tls443DemonwareSpkiSha256.size() != 64)
            {
                log::Print("[TRUST-443] manifest not written; SPKI material is incomplete ca=%llu leaf=%llu battleNet=%llu demonware=%llu",
                    static_cast<unsigned long long>(g_tlsSpkiSha256.size()),
                    static_cast<unsigned long long>(g_tlsLeafSpkiSha256.size()),
                    static_cast<unsigned long long>(g_tls443BattleNetSpkiSha256.size()),
                    static_cast<unsigned long long>(g_tls443DemonwareSpkiSha256.size()));
                return;
            }

            std::ostringstream text;
            text << "REVAMPED_IW8_TRUST_V1\n"
                 << "ca=" << g_tlsSpkiSha256 << "\n"
                 << "leaf=" << g_tlsLeafSpkiSha256 << "\n"
                 << "battleNet=" << g_tls443BattleNetSpkiSha256 << "\n"
                 << "demonware=" << g_tls443DemonwareSpkiSha256 << "\n";
            const std::string body = text.str();

            std::vector<std::wstring> outputs;
            wchar_t serverPath[32768]{};
            const DWORD serverLength = GetModuleFileNameW(nullptr, serverPath,
                static_cast<DWORD>(sizeof(serverPath) / sizeof(serverPath[0])));
            if (serverLength && serverLength < (sizeof(serverPath) / sizeof(serverPath[0])))
            {
                const std::wstring dir = DirectoryOfPath(std::wstring(serverPath, serverLength));
                if (!dir.empty())
                    AddUniqueBundleCandidate(outputs, dir + L"\\revamped-iw8-trust-spki.txt");
            }

            wchar_t cwd[32768]{};
            const DWORD cwdLength = GetCurrentDirectoryW(
                static_cast<DWORD>(sizeof(cwd) / sizeof(cwd[0])), cwd);
            if (cwdLength && cwdLength < (sizeof(cwd) / sizeof(cwd[0])))
                AddUniqueBundleCandidate(outputs, std::wstring(cwd, cwdLength) + L"\\revamped-iw8-trust-spki.txt");

            const std::wstring gameDir = RunningModernWarfareDirectory();
            if (!gameDir.empty())
                AddUniqueBundleCandidate(outputs, gameDir + L"\\revamped-iw8-trust-spki.txt");

            std::size_t writtenCount = 0;
            for (const auto& path : outputs)
            {
                if (!WriteSmallUtf8File(path, body))
                    continue;
                ++writtenCount;
                char utf8[32768]{};
                WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, utf8,
                    static_cast<int>(sizeof(utf8)), nullptr, nullptr);
                log::Print("[TRUST-443] exported local trust manifest path=%s", utf8[0] ? utf8 : "<wide-path>");
            }
            log::Print("[TRUST-443] local trust manifest ready outputs=%llu ca=%s battleNet=%s demonware=%s",
                static_cast<unsigned long long>(writtenCount),
                g_tlsSpkiSha256.c_str(),
                g_tls443BattleNetSpkiSha256.c_str(),
                g_tls443DemonwareSpkiSha256.c_str());
        }

        bool ComputeCertificateSpkiSha256(PCCERT_CONTEXT certificate, std::string& hashHex)
        {
            hashHex.clear();
            if (!certificate || !certificate->pCertInfo)
                return false;

            DWORD encodedSize = 0;
            if (!CryptEncodeObjectEx(
                    X509_ASN_ENCODING,
                    X509_PUBLIC_KEY_INFO,
                    &certificate->pCertInfo->SubjectPublicKeyInfo,
                    0,
                    nullptr,
                    nullptr,
                    &encodedSize) || !encodedSize)
                return false;

            std::vector<BYTE> encoded(encodedSize);
            if (!CryptEncodeObjectEx(
                    X509_ASN_ENCODING,
                    X509_PUBLIC_KEY_INFO,
                    &certificate->pCertInfo->SubjectPublicKeyInfo,
                    0,
                    nullptr,
                    encoded.data(),
                    &encodedSize))
                return false;

            BYTE hash[32]{};
            DWORD hashSize = sizeof(hash);
            if (!CryptHashCertificate2(
                    L"SHA256",
                    0,
                    nullptr,
                    encoded.data(),
                    encodedSize,
                    hash,
                    &hashSize) || hashSize != sizeof(hash))
                return false;

            hashHex = HexBytesCompact(hash, hashSize);
            return hashHex.size() == 64;
        }

        bool ComputeProviderSpkiSha256(HCRYPTPROV provider, DWORD keySpec, std::string& hashHex)
        {
            hashHex.clear();
            if (!provider)
                return false;

            DWORD infoSize = 0;
            if (!CryptExportPublicKeyInfo(provider, keySpec, X509_ASN_ENCODING, nullptr, &infoSize) || !infoSize)
                return false;

            std::vector<BYTE> infoBytes(infoSize);
            auto* info = reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(infoBytes.data());
            if (!CryptExportPublicKeyInfo(provider, keySpec, X509_ASN_ENCODING, info, &infoSize))
                return false;

            DWORD encodedSize = 0;
            if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, info, 0, nullptr, nullptr, &encodedSize) || !encodedSize)
                return false;

            std::vector<BYTE> encoded(encodedSize);
            if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, info, 0, nullptr, encoded.data(), &encodedSize))
                return false;

            BYTE hash[32]{};
            DWORD hashSize = sizeof(hash);
            if (!CryptHashCertificate2(L"SHA256", 0, nullptr, encoded.data(), encodedSize, hash, &hashSize) || hashSize != sizeof(hash))
                return false;

            hashHex = HexBytesCompact(hash, hashSize);
            return hashHex.size() == 64;
        }

        bool WriteBinaryFileExact(const std::wstring& path, const void* data, std::size_t size)
        {
            if (path.empty() || !data || !size || size > 0xFFFFFFFFu)
                return false;
            HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;
            DWORD written = 0;
            const BOOL ok = WriteFile(file, data, static_cast<DWORD>(size), &written, nullptr);
            FlushFileBuffers(file);
            CloseHandle(file);
            return ok && written == size;
        }

        std::wstring ServerExecutableDirectory()
        {
            wchar_t path[32768]{};
            const DWORD length = GetModuleFileNameW(nullptr, path,
                static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
            if (!length || length >= (sizeof(path) / sizeof(path[0])))
                return {};
            return DirectoryOfPath(std::wstring(path, length));
        }

        std::wstring LocalBgsRootCertificatePath()
        {
            const std::wstring serverDir = ServerExecutableDirectory();
            if (serverDir.empty())
                return {};
            return serverDir + L"\\revamped-bgs-root-ca.cer";
        }

        PCCERT_CONTEXT LoadDerCertificateFile(const std::wstring& path)
        {
            if (path.empty())
                return nullptr;

            FILE* file = nullptr;
            if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || !file)
                return nullptr;
            if (fseek(file, 0, SEEK_END) != 0)
            {
                fclose(file);
                return nullptr;
            }
            const long sizeLong = ftell(file);
            if (sizeLong <= 0 || sizeLong > 1024 * 1024)
            {
                fclose(file);
                return nullptr;
            }
            rewind(file);
            std::vector<BYTE> bytes(static_cast<std::size_t>(sizeLong));
            const std::size_t read = fread(bytes.data(), 1, bytes.size(), file);
            fclose(file);
            if (read != bytes.size())
                return nullptr;

            return CertCreateCertificateContext(X509_ASN_ENCODING, bytes.data(), static_cast<DWORD>(bytes.size()));
        }

        bool CurrentUserRootContainsExactCertificate(PCCERT_CONTEXT certificate)
        {
            if (!certificate || !certificate->pbCertEncoded || !certificate->cbCertEncoded)
                return false;

            HCERTSTORE root = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG, L"ROOT");
            if (!root)
                return false;

            bool found = false;
            PCCERT_CONTEXT current = nullptr;
            while ((current = CertEnumCertificatesInStore(root, current)) != nullptr)
            {
                if (current->cbCertEncoded == certificate->cbCertEncoded &&
                    memcmp(current->pbCertEncoded, certificate->pbCertEncoded, certificate->cbCertEncoded) == 0)
                {
                    found = true;
                    CertFreeCertificateContext(current);
                    current = nullptr;
                    break;
                }
            }
            CertCloseStore(root, 0);
            return found;
        }

        bool ExportAndReportLocalBgsRootCertificate(PCCERT_CONTEXT certificate)
        {
            if (!certificate || !certificate->pbCertEncoded || !certificate->cbCertEncoded)
                return false;

            const std::wstring path = LocalBgsRootCertificatePath();
            if (path.empty())
            {
                log::Print("[TRUST-BOOT] unable to resolve local BGS root CA export path");
                return false;
            }

            const bool wrote = WriteBinaryFileExact(path, certificate->pbCertEncoded, certificate->cbCertEncoded);
            const bool trusted = CurrentUserRootContainsExactCertificate(certificate);

            BYTE sha1[20]{};
            DWORD sha1Size = sizeof(sha1);
            const bool haveSha1 = CertGetCertificateContextProperty(certificate, CERT_SHA1_HASH_PROP_ID, sha1, &sha1Size) == TRUE;
            const std::string thumbprint = haveSha1 ? HexBytesCompact(sha1, sha1Size) : std::string{};

            char utf8[32768]{};
            WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, utf8, static_cast<int>(sizeof(utf8)), nullptr, nullptr);
            log::Print("[TRUST-BOOT] Windows current-user TLS root trust=%s caFile=%s sha1=%s",
                trusted ? "present" : "MISSING",
                utf8[0] ? utf8 : "<wide-path>",
                thumbprint.empty() ? "<unknown>" : thumbprint.c_str());

            if (!trusted)
            {
                log::Print("[TRUST-BOOT] ACTION REQUIRED before launching MW2019: keep this server running and import the local CA for the current user:");
                log::Print("[TRUST-BOOT]   certutil -user -addstore Root \"%s\"", utf8[0] ? utf8 : "revamped-bgs-root-ca.cer");
                if (!thumbprint.empty())
                    log::Print("[TRUST-BOOT] remove later with: certutil -user -delstore Root %s", thumbprint.c_str());
            }
            return wrote;
        }

        bool ExportBundleSignerModulus()
        {
            if (!g_bundleSignerKey)
                return false;

            DWORD blobSize = 0;
            if (!CryptExportKey(g_bundleSignerKey, 0, PUBLICKEYBLOB, 0, nullptr, &blobSize) ||
                blobSize < sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + 256u)
            {
                log::Print("[TRUST-BOOT] CryptExportKey(size) failed error=%lu", GetLastError());
                return false;
            }

            std::vector<BYTE> blob(blobSize);
            if (!CryptExportKey(g_bundleSignerKey, 0, PUBLICKEYBLOB, 0, blob.data(), &blobSize))
            {
                log::Print("[TRUST-BOOT] CryptExportKey failed error=%lu", GetLastError());
                return false;
            }

            const auto* header = reinterpret_cast<const PUBLICKEYSTRUC*>(blob.data());
            const auto* rsa = reinterpret_cast<const RSAPUBKEY*>(blob.data() + sizeof(PUBLICKEYSTRUC));
            if (header->bType != PUBLICKEYBLOB || rsa->magic != 0x31415352u || rsa->bitlen != 2048u)
            {
                log::Print("[TRUST-BOOT] unexpected bundle signer public blob type=%u magic=0x%08lX bitlen=%lu",
                    static_cast<unsigned>(header->bType), static_cast<unsigned long>(rsa->magic),
                    static_cast<unsigned long>(rsa->bitlen));
                return false;
            }

            const std::size_t modulusOffset = sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);
            if (modulusOffset + 256u > blobSize)
                return false;
            g_bundleSignerModulusLe.assign(blob.begin() + static_cast<std::ptrdiff_t>(modulusOffset),
                blob.begin() + static_cast<std::ptrdiff_t>(modulusOffset + 256u));

            std::vector<std::wstring> outputs;
            const std::wstring serverDir = ServerExecutableDirectory();
            if (!serverDir.empty())
                outputs.push_back(serverDir + L"\\bgs-bundle-signing-modulus.bin");

            wchar_t cwdBuffer[32768]{};
            const DWORD cwdLength = GetCurrentDirectoryW(
                static_cast<DWORD>(sizeof(cwdBuffer) / sizeof(cwdBuffer[0])), cwdBuffer);
            if (cwdLength && cwdLength < (sizeof(cwdBuffer) / sizeof(cwdBuffer[0])))
            {
                const std::wstring cwd(cwdBuffer, cwdLength);
                const std::wstring cwdPath = cwd + L"\\bgs-bundle-signing-modulus.bin";
                if (std::find(outputs.begin(), outputs.end(), cwdPath) == outputs.end())
                    outputs.push_back(cwdPath);
            }

            bool wroteAny = false;
            std::wstring primary;
            for (const auto& path : outputs)
            {
                if (!WriteBinaryFileExact(path, g_bundleSignerModulusLe.data(), g_bundleSignerModulusLe.size()))
                    continue;
                if (primary.empty()) primary = path;
                wroteAny = true;
            }

            char utf8[32768]{};
            if (!primary.empty())
                WideCharToMultiByte(CP_UTF8, 0, primary.c_str(), -1, utf8, static_cast<int>(sizeof(utf8)), nullptr, nullptr);
            log::Print("[TRUST-BOOT] bundle signer public modulus ready bytes=%llu endian=LE exponent=%lu file=%s",
                static_cast<unsigned long long>(g_bundleSignerModulusLe.size()),
                static_cast<unsigned long>(rsa->pubexp),
                utf8[0] ? utf8 : (wroteAny ? "<written>" : "<write-failed>"));
            return wroteAny && g_bundleSignerModulusLe.size() == 256u;
        }

        bool InitializeBundleSigner()
        {
            if (g_bundleSignerReady)
                return true;

            static wchar_t containerName[] = L"CodRevamped_IW8_BGS_BundleSigner";
            if (!CryptAcquireContextW(&g_bundleSignerProvider, containerName,
                    MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT))
            {
                const DWORD error = GetLastError();
                if (error != NTE_EXISTS || !CryptAcquireContextW(&g_bundleSignerProvider, containerName,
                        MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_SILENT))
                {
                    log::Print("[TRUST-BOOT] CryptAcquireContext(bundle signer) failed error=%lu", GetLastError());
                    return false;
                }
            }

            if (!CryptGetUserKey(g_bundleSignerProvider, AT_SIGNATURE, &g_bundleSignerKey))
            {
                if (!CryptGenKey(g_bundleSignerProvider, AT_SIGNATURE,
                        (2048u << 16) | CRYPT_EXPORTABLE, &g_bundleSignerKey))
                {
                    log::Print("[TRUST-BOOT] CryptGenKey(bundle signer) failed error=%lu", GetLastError());
                    return false;
                }
            }

            if (!ExportBundleSignerModulus())
                return false;

            g_bundleSignerReady = true;
            log::Print("[TRUST-BOOT] OPTION2 ready: local bundle signer initialized; this establishes only server trust, not login/auth success");
            return true;
        }

        void ShutdownBundleSigner()
        {
            if (g_bundleSignerKey)
            {
                CryptDestroyKey(g_bundleSignerKey);
                g_bundleSignerKey = 0;
            }
            if (g_bundleSignerProvider)
            {
                CryptReleaseContext(g_bundleSignerProvider, 0);
                g_bundleSignerProvider = 0;
            }
            g_bundleSignerModulusLe.clear();
            g_bundleSignerReady = false;
        }

        bool HashBundleSigningInput(HCRYPTPROV provider, const std::string& json, HCRYPTHASH& hash)
        {
            hash = 0;
            if (!provider || !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash))
                return false;
            static const char context[] = "Blizzard Certificate Bundle";
            if (!CryptHashData(hash, reinterpret_cast<const BYTE*>(json.data()), static_cast<DWORD>(json.size()), 0) ||
                !CryptHashData(hash, reinterpret_cast<const BYTE*>(context), static_cast<DWORD>(sizeof(context) - 1u), 0))
            {
                CryptDestroyHash(hash);
                hash = 0;
                return false;
            }
            return true;
        }

        std::vector<unsigned char> SignLocalBgsBundle(const std::string& json, bool& signatureVerified)
        {
            signatureVerified = false;
            if (!InitializeBundleSigner() || !g_bundleSignerProvider || !g_bundleSignerKey || json.empty())
                return {};

            HCRYPTHASH hash = 0;
            if (!HashBundleSigningInput(g_bundleSignerProvider, json, hash))
            {
                log::Print("[TRUST-BOOT] failed creating SHA256 bundle hash error=%lu", GetLastError());
                return {};
            }

            DWORD signatureSize = 0;
            if (!CryptSignHashA(hash, AT_SIGNATURE, nullptr, 0, nullptr, &signatureSize) || !signatureSize)
            {
                log::Print("[TRUST-BOOT] CryptSignHash(size) failed error=%lu", GetLastError());
                CryptDestroyHash(hash);
                return {};
            }
            std::vector<BYTE> signature(signatureSize);
            if (!CryptSignHashA(hash, AT_SIGNATURE, nullptr, 0, signature.data(), &signatureSize))
            {
                log::Print("[TRUST-BOOT] CryptSignHash failed error=%lu", GetLastError());
                CryptDestroyHash(hash);
                return {};
            }
            CryptDestroyHash(hash);
            signature.resize(signatureSize);

            if (signature.size() != 256u)
            {
                log::Print("[TRUST-BOOT] unexpected RSA signature size=%llu expected=256",
                    static_cast<unsigned long long>(signature.size()));
                return {};
            }

            HCRYPTHASH verifyHash = 0;
            if (HashBundleSigningInput(g_bundleSignerProvider, json, verifyHash))
            {
                signatureVerified = CryptVerifySignatureA(verifyHash, signature.data(),
                    static_cast<DWORD>(signature.size()), g_bundleSignerKey, nullptr, 0) == TRUE;
                CryptDestroyHash(verifyHash);
            }
            if (!signatureVerified)
            {
                log::Print("[TRUST-BOOT] local bundle signature round-trip verification FAILED error=%lu", GetLastError());
                return {};
            }

            std::vector<unsigned char> wire;
            wire.reserve(json.size() + 4u + signature.size());
            wire.insert(wire.end(), json.begin(), json.end());
            static const unsigned char magic[4]{'N','G','I','S'};
            wire.insert(wire.end(), magic, magic + 4u);
            // Legacy CryptoAPI RSA signatures are emitted little-endian, which is
            // the byte order expected by the BGS NGIS bundle trailer.
            wire.insert(wire.end(), signature.begin(), signature.end());
            return wire;
        }

        std::string CertificateToCompactPem(PCCERT_CONTEXT certificate)
        {
            if (!certificate || !certificate->pbCertEncoded || !certificate->cbCertEncoded)
                return {};

            DWORD base64Size = 0;
            if (!CryptBinaryToStringA(certificate->pbCertEncoded, certificate->cbCertEncoded,
                    CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Size) || !base64Size)
            {
                log::Print("[TRUST-BOOT] CryptBinaryToStringA(size) failed error=%lu", GetLastError());
                return {};
            }

            std::string base64(base64Size, '\0');
            if (!CryptBinaryToStringA(certificate->pbCertEncoded, certificate->cbCertEncoded,
                    CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64.data(), &base64Size))
            {
                log::Print("[TRUST-BOOT] CryptBinaryToStringA failed error=%lu", GetLastError());
                return {};
            }
            if (!base64.empty() && base64.back() == '\0')
                base64.pop_back();

            return std::string("-----BEGIN CERTIFICATE-----") + base64 + "-----END CERTIFICATE-----";
        }

        bool ReplaceJsonArray(std::string& json, const char* key, const std::string& replacementArray)
        {
            if (json.empty() || !key || !*key || replacementArray.empty())
                return false;

            const std::string prefix = std::string("\"") + key + "\":";
            const std::size_t keyPos = json.find(prefix);
            if (keyPos == std::string::npos)
                return false;

            std::size_t begin = keyPos + prefix.size();
            while (begin < json.size() && (json[begin] == ' ' || json[begin] == '\t' || json[begin] == '\r' || json[begin] == '\n'))
                ++begin;
            if (begin >= json.size() || json[begin] != '[')
                return false;

            bool inString = false;
            bool escaped = false;
            int depth = 0;
            for (std::size_t i = begin; i < json.size(); ++i)
            {
                const char c = json[i];
                if (inString)
                {
                    if (escaped)
                    {
                        escaped = false;
                        continue;
                    }
                    if (c == '\\')
                    {
                        escaped = true;
                        continue;
                    }
                    if (c == '\"')
                        inString = false;
                    continue;
                }

                if (c == '\"')
                {
                    inString = true;
                    continue;
                }
                if (c == '[')
                    ++depth;
                else if (c == ']')
                {
                    --depth;
                    if (depth == 0)
                    {
                        json.replace(begin, i - begin + 1u, replacementArray);
                        return true;
                    }
                }
            }
            return false;
        }

        bool AppendJsonTrustPins(std::string& json, const char* key,
            const std::vector<std::string>& hosts, const std::string& spki, std::size_t& added)
        {
            added = 0;
            if (json.empty() || !key || !*key || hosts.empty() || spki.size() != 64)
                return false;

            const std::string prefix = std::string("\"") + key + "\":";
            const std::size_t keyPos = json.find(prefix);
            if (keyPos == std::string::npos)
                return false;

            std::size_t begin = keyPos + prefix.size();
            while (begin < json.size() && (json[begin] == ' ' || json[begin] == '\t' || json[begin] == '\r' || json[begin] == '\n'))
                ++begin;
            if (begin >= json.size() || json[begin] != '[')
                return false;

            bool inString = false;
            bool escaped = false;
            int depth = 0;
            std::size_t end = std::string::npos;
            for (std::size_t i = begin; i < json.size(); ++i)
            {
                const char c = json[i];
                if (inString)
                {
                    if (escaped)
                    {
                        escaped = false;
                        continue;
                    }
                    if (c == '\\')
                    {
                        escaped = true;
                        continue;
                    }
                    if (c == '"')
                        inString = false;
                    continue;
                }
                if (c == '"')
                {
                    inString = true;
                    continue;
                }
                if (c == '[')
                    ++depth;
                else if (c == ']')
                {
                    --depth;
                    if (depth == 0)
                    {
                        end = i;
                        break;
                    }
                }
            }
            if (end == std::string::npos)
                return false;

            std::string insertion;
            const std::string arrayContents = json.substr(begin + 1, end - begin - 1);
            for (const auto& host : hosts)
            {
                const std::string needle = std::string("\"Uri\":\"") + host +
                    "\",\"ShaHashPublicKeyInfo\":\"" + spki + "\"";
                if (arrayContents.find(needle) != std::string::npos)
                    continue;
                if (!insertion.empty())
                    insertion += ',';
                insertion += std::string("{\"Uri\":\"") + host + "\",\"ShaHashPublicKeyInfo\":\"" + spki + "\"}";
                ++added;
            }
            if (insertion.empty())
                return true;

            bool hasExisting = false;
            for (std::size_t i = begin + 1; i < end; ++i)
            {
                if (json[i] != ' ' && json[i] != '\t' && json[i] != '\r' && json[i] != '\n')
                {
                    hasExisting = true;
                    break;
                }
            }
            if (hasExisting)
                insertion.insert(insertion.begin(), ',');
            json.insert(end, insertion);
            return true;
        }

        std::vector<unsigned char> BuildLocalBgsTrustBundle(
            const std::vector<unsigned char>& stockBundle,
            std::size_t& pinReplacements,
            bool& signatureVerified)
        {
            pinReplacements = 0;
            signatureVerified = false;
            if (stockBundle.empty() || g_tlsSpkiSha256.size() != 64 || !g_tlsCertificate || !g_tlsCaCertificate || !InitializeBundleSigner())
                return {};

            // BGS has two independent trust layers:
            //   1) the RSA bundle-signing modulus patched by OPTION2 verifies this JSON;
            //   2) the TLS trust object uses the same CA SPKI in Certificates,
            //      PublicKeys and RootCAPublicKeys, with the CA certificate itself in
            //      SigningCertificates.  This mirrors the public BGS bundle-generator
            //      layout instead of changing only the hostname pins.
            const std::string localTrustCertificatePem = CertificateToCompactPem(g_tlsCaCertificate);
            if (localTrustCertificatePem.empty())
            {
                log::Print("[TRUST-BOOT] failed exporting local TLS CA certificate for BGS bundle");
                return {};
            }

            std::string json(reinterpret_cast<const char*>(stockBundle.data()), stockBundle.size());
            const std::string signingArray =
                std::string("[{\"RawData\":\"") + localTrustCertificatePem + "\"}]";
            const std::string rootArray = std::string("[\"") + g_tlsSpkiSha256 + "\"]";
            const bool signingCertificatesReplaced =
                ReplaceJsonArray(json, "SigningCertificates", signingArray);
            const bool rootCaPublicKeysReplaced =
                ReplaceJsonArray(json, "RootCAPublicKeys", rootArray);
            if (!signingCertificatesReplaced || !rootCaPublicKeysReplaced)
            {
                log::Print("[TRUST-BOOT] BGS trust arrays missing signingCertificates=%s rootCAPublicKeys=%s; refusing partial trust adaptation",
                    signingCertificatesReplaced ? "yes" : "no",
                    rootCaPublicKeysReplaced ? "yes" : "no");
                return {};
            }

            static const std::string prefix =
                "\"Uri\":\"us.actual.battle.net\",\"ShaHashPublicKeyInfo\":\"";

            std::size_t pos = 0;
            while ((pos = json.find(prefix, pos)) != std::string::npos)
            {
                const std::size_t hashStart = pos + prefix.size();
                const std::size_t hashEnd = hashStart + 64;
                if (hashEnd > json.size() || json[hashEnd] != '"')
                {
                    pos = hashStart;
                    continue;
                }
                bool hex64 = true;
                for (std::size_t i = hashStart; i < hashEnd; ++i)
                {
                    const char c = json[i];
                    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
                    {
                        hex64 = false;
                        break;
                    }
                }
                if (!hex64)
                {
                    pos = hashEnd;
                    continue;
                }
                json.replace(hashStart, 64, g_tlsSpkiSha256);
                ++pinReplacements;
                pos = hashEnd;
            }

            if (!pinReplacements)
            {
                log::Print("[TRUST-BOOT] no us.actual.battle.net SPKI entries were found in the stock JSON; refusing partial trust adaptation");
                return {};
            }

            const std::vector<std::string> battleNetWebTrustHosts = {
                "us.battle.net",
                "oauth-us.web.blizzard.net",
                "us.api.blizzard.com",
                "us-gateway.integration.blizzard.com"
            };
            const std::vector<std::string> demonwareWebTrustHosts = {
                "iw8-bnet-auth3.prod.demonware.net",
                "auth3.prod.demonware.net",
                "auth3-login.prod.demonware.net",
                "loginqueue.prod.demonware.net",
                "prod.umbrella.demonware.net",
                "*.umbrella.demonware.net",
                "*.prod.demonware.net"
            };
            std::vector<std::string> allWebTrustHosts = battleNetWebTrustHosts;
            allWebTrustHosts.insert(allWebTrustHosts.end(), demonwareWebTrustHosts.begin(), demonwareWebTrustHosts.end());

            const std::string& battleNetLeafSpki = g_tls443BattleNetSpkiSha256.size() == 64 ?
                g_tls443BattleNetSpkiSha256 : g_tlsLeafSpkiSha256;
            const std::string& demonwareLeafSpki = g_tls443DemonwareSpkiSha256.size() == 64 ?
                g_tls443DemonwareSpkiSha256 : g_tlsLeafSpkiSha256;

            std::size_t certificateCaPinsAdded = 0;
            std::size_t publicKeyCaPinsAdded = 0;
            std::size_t certificateBattleNetPinsAdded = 0;
            std::size_t publicKeyBattleNetPinsAdded = 0;
            std::size_t certificateDemonwarePinsAdded = 0;
            std::size_t publicKeyDemonwarePinsAdded = 0;
            const bool certificatesCaExpanded = AppendJsonTrustPins(json, "Certificates", allWebTrustHosts,
                g_tlsSpkiSha256, certificateCaPinsAdded);
            const bool publicKeysCaExpanded = AppendJsonTrustPins(json, "PublicKeys", allWebTrustHosts,
                g_tlsSpkiSha256, publicKeyCaPinsAdded);
            const bool certificatesBattleNetExpanded = battleNetLeafSpki.size() == 64 &&
                AppendJsonTrustPins(json, "Certificates", battleNetWebTrustHosts,
                    battleNetLeafSpki, certificateBattleNetPinsAdded);
            const bool publicKeysBattleNetExpanded = battleNetLeafSpki.size() == 64 &&
                AppendJsonTrustPins(json, "PublicKeys", battleNetWebTrustHosts,
                    battleNetLeafSpki, publicKeyBattleNetPinsAdded);
            const bool certificatesDemonwareExpanded = demonwareLeafSpki.size() == 64 &&
                AppendJsonTrustPins(json, "Certificates", demonwareWebTrustHosts,
                    demonwareLeafSpki, certificateDemonwarePinsAdded);
            const bool publicKeysDemonwareExpanded = demonwareLeafSpki.size() == 64 &&
                AppendJsonTrustPins(json, "PublicKeys", demonwareWebTrustHosts,
                    demonwareLeafSpki, publicKeyDemonwarePinsAdded);
            if (!certificatesCaExpanded || !publicKeysCaExpanded ||
                !certificatesBattleNetExpanded || !publicKeysBattleNetExpanded ||
                !certificatesDemonwareExpanded || !publicKeysDemonwareExpanded)
            {
                log::Print("[TRUST-BOOT] web trust-pin expansion failed certCA=%s pubCA=%s certBattleNet=%s pubBattleNet=%s certDemonware=%s pubDemonware=%s",
                    certificatesCaExpanded ? "yes" : "no", publicKeysCaExpanded ? "yes" : "no",
                    certificatesBattleNetExpanded ? "yes" : "no", publicKeysBattleNetExpanded ? "yes" : "no",
                    certificatesDemonwareExpanded ? "yes" : "no", publicKeysDemonwareExpanded ? "yes" : "no");
                return {};
            }
            log::Print("[TRUST-BOOT] web trust-pin expansion hosts=%llu certCA=%llu pubCA=%llu battleNetLeafPins={cert:%llu pub:%llu spki:%s} demonwareLeafPins={cert:%llu pub:%llu spki:%s}",
                static_cast<unsigned long long>(allWebTrustHosts.size()),
                static_cast<unsigned long long>(certificateCaPinsAdded),
                static_cast<unsigned long long>(publicKeyCaPinsAdded),
                static_cast<unsigned long long>(certificateBattleNetPinsAdded),
                static_cast<unsigned long long>(publicKeyBattleNetPinsAdded),
                battleNetLeafSpki.c_str(),
                static_cast<unsigned long long>(certificateDemonwarePinsAdded),
                static_cast<unsigned long long>(publicKeyDemonwarePinsAdded),
                demonwareLeafSpki.c_str());

            // This endpoint is downloaded over HTTP, so its JSON is not required
            // to remain byte-for-byte the same size as the embedded fallback.
            // Replacing RawData with our local trust certificate legitimately
            // changes the JSON length; the new length is covered by the fresh
            // OPTION2 RSA signature.
            log::Print("[TRUST-BOOT] BGS TLS trust object rebuilt signingCertificates=local-only rootCAPublicKeys=local-only caSpki=%s stockJsonBytes=%llu localJsonBytes=%llu pinReplacements=%llu",
                g_tlsSpkiSha256.c_str(),
                static_cast<unsigned long long>(stockBundle.size()),
                static_cast<unsigned long long>(json.size()),
                static_cast<unsigned long long>(pinReplacements));

            return SignLocalBgsBundle(json, signatureVerified);
        }

        std::string HexPrefix(const void* data, std::size_t size, std::size_t limit)
        {
            if (!data || !size) return "<empty>";
            const auto* bytes = static_cast<const BYTE*>(data);
            const std::size_t shown = (std::min)(size, limit);
            std::ostringstream out;
            out << std::hex << std::uppercase << std::setfill('0');
            for (std::size_t i = 0; i < shown; ++i)
            {
                if (i) out << ' ';
                out << std::setw(2) << static_cast<unsigned>(bytes[i]);
            }
            if (shown < size) out << " ...";
            return out.str();
        }

        std::uint32_t ReadLe32(const BYTE* p)
        {
            return static_cast<std::uint32_t>(p[0]) |
                (static_cast<std::uint32_t>(p[1]) << 8) |
                (static_cast<std::uint32_t>(p[2]) << 16) |
                (static_cast<std::uint32_t>(p[3]) << 24);
        }

        std::uint32_t ReadBe32(const BYTE* p)
        {
            return (static_cast<std::uint32_t>(p[0]) << 24) |
                (static_cast<std::uint32_t>(p[1]) << 16) |
                (static_cast<std::uint32_t>(p[2]) << 8) |
                static_cast<std::uint32_t>(p[3]);
        }

        bool ReadProtoVarint(const BYTE* data, std::size_t size, std::size_t& offset, std::uint64_t& value)
        {
            value = 0;
            unsigned shift = 0;
            for (unsigned i = 0; i < 10 && offset < size; ++i)
            {
                const BYTE b = data[offset++];
                value |= (static_cast<std::uint64_t>(b & 0x7Fu) << shift);
                if ((b & 0x80u) == 0) return true;
                shift += 7;
            }
            return false;
        }

        struct ProtoCandidate
        {
            std::size_t start = 0;
            std::size_t consumed = 0;
            unsigned fields = 0;
            std::string description;
        };

        ProtoCandidate ParseProtoCandidate(const BYTE* data, std::size_t size, std::size_t start)
        {
            ProtoCandidate result{};
            result.start = start;
            if (!data || start >= size) return result;

            std::size_t offset = start;
            std::ostringstream desc;
            for (unsigned item = 0; item < 12 && offset < size; ++item)
            {
                const std::size_t fieldStart = offset;
                std::uint64_t key = 0;
                if (!ReadProtoVarint(data, size, offset, key)) break;
                const std::uint64_t field = key >> 3;
                const unsigned wire = static_cast<unsigned>(key & 7u);
                if (field == 0 || field > 4096 || wire == 3 || wire == 4 || wire > 5)
                {
                    offset = fieldStart;
                    break;
                }

                if (result.fields) desc << ", ";
                desc << 'f' << field << "/w" << wire;

                if (wire == 0)
                {
                    std::uint64_t value = 0;
                    if (!ReadProtoVarint(data, size, offset, value)) { offset = fieldStart; break; }
                    desc << "=" << value;
                }
                else if (wire == 1)
                {
                    if (offset + 8 > size) { offset = fieldStart; break; }
                    desc << "[8]";
                    offset += 8;
                }
                else if (wire == 2)
                {
                    std::uint64_t length = 0;
                    if (!ReadProtoVarint(data, size, offset, length) || length > size - offset)
                    {
                        offset = fieldStart;
                        break;
                    }
                    desc << "[len=" << length << ']';
                    offset += static_cast<std::size_t>(length);
                }
                else if (wire == 5)
                {
                    if (offset + 4 > size) { offset = fieldStart; break; }
                    desc << "[4]";
                    offset += 4;
                }
                ++result.fields;
            }

            result.consumed = offset >= start ? offset - start : 0;
            result.description = desc.str();
            return result;
        }

        std::string DescribeBestProtoCandidate(const void* payload, std::size_t size)
        {
            if (!payload || !size) return "<none>";
            const auto* data = static_cast<const BYTE*>(payload);
            ProtoCandidate best{};
            const std::size_t maxStart = (std::min)(size, static_cast<std::size_t>(12));
            for (std::size_t start = 0; start < maxStart; ++start)
            {
                const ProtoCandidate candidate = ParseProtoCandidate(data, size, start);
                if (candidate.fields > best.fields ||
                    (candidate.fields == best.fields && candidate.consumed > best.consumed))
                    best = candidate;
            }
            if (!best.fields) return "<none>";

            std::ostringstream out;
            out << "offset=" << best.start << " fields=" << best.fields
                << " consumed=" << best.consumed << " {" << best.description << '}';
            return out.str();
        }

        void LogBgsApplicationPlaintext(TlsSession& session, std::uint64_t id, const std::string& peer, const void* payload, std::size_t size)
        {
            if (!payload || !size) return;
            const auto* bytes = static_cast<const BYTE*>(payload);
            session.bgsApplicationSeen = true;
            ++session.decryptedApplicationCount;

            log::Payload(id, "TLS-PLAIN-IN", 1119, peer, payload, size);
            log::Print("[BGS1119] id=%llu app#%llu decrypted application bytes=%llu",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                static_cast<unsigned long long>(size));
            log::Print("[BGS1119] id=%llu app#%llu header[0..31]=%s",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                HexPrefix(payload, size, 32).c_str());

            if (size >= 4)
            {
                log::Print("[BGS1119] id=%llu app#%llu frameHints u16be=%u u16le=%u u32be=%lu u32le=%lu firstByte=0x%02X",
                    static_cast<unsigned long long>(id),
                    static_cast<unsigned long long>(session.decryptedApplicationCount),
                    static_cast<unsigned>(ReadBe16(bytes)),
                    static_cast<unsigned>(static_cast<std::uint16_t>(bytes[0] | (static_cast<std::uint16_t>(bytes[1]) << 8))),
                    static_cast<unsigned long>(ReadBe32(bytes)),
                    static_cast<unsigned long>(ReadLe32(bytes)),
                    static_cast<unsigned>(bytes[0]));
            }
            else
            {
                log::Print("[BGS1119] id=%llu app#%llu frameHints short-payload firstByte=0x%02X",
                    static_cast<unsigned long long>(id),
                    static_cast<unsigned long long>(session.decryptedApplicationCount),
                    static_cast<unsigned>(bytes[0]));
            }

            log::Print("[BGS1119] id=%llu app#%llu hexPrefix=%s",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                HexPrefix(payload, size, 512).c_str());
            log::Print("[BGS1119] id=%llu app#%llu asciiPrefix=%s",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                protocol::AsciiPrefix(payload, size, 512).c_str());
            log::Print("[BGS1119] id=%llu app#%llu protobufCandidate=%s",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(session.decryptedApplicationCount),
                DescribeBestProtoCandidate(payload, size).c_str());
        }

        bool BuildLocalTlsRevocationArtifacts()
        {
            if (!g_tlsCaCertificate || !g_tlsCaCertificate->pCertInfo || !g_tlsCaProvider)
                return false;

            // Encode a CRL Distribution Points extension that points Schannel's
            // revocation fetcher at this local server. This remains transport
            // trust only; it does not alter any game login/fence state.
            CERT_ALT_NAME_ENTRY urlEntry{};
            urlEntry.dwAltNameChoice = CERT_ALT_NAME_URL;
            urlEntry.pwszURL = const_cast<LPWSTR>(kLocalCrlUrl);

            CRL_DIST_POINT distPoint{};
            distPoint.DistPointName.dwDistPointNameChoice = CRL_DIST_POINT_FULL_NAME;
            distPoint.DistPointName.FullName.cAltEntry = 1;
            distPoint.DistPointName.FullName.rgAltEntry = &urlEntry;

            CRL_DIST_POINTS_INFO distPoints{};
            distPoints.cDistPoint = 1;
            distPoints.rgDistPoint = &distPoint;

            DWORD distPointSize = 0;
            if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CRL_DIST_POINTS,
                    &distPoints, 0, nullptr, nullptr, &distPointSize) || !distPointSize)
            {
                log::Print("[TRUST-CRL] CRL distribution-point encode(size) failed error=%lu", GetLastError());
                return false;
            }

            g_tlsCrlDistributionPointBytes.resize(distPointSize);
            if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CRL_DIST_POINTS,
                    &distPoints, 0, nullptr, g_tlsCrlDistributionPointBytes.data(), &distPointSize))
            {
                log::Print("[TRUST-CRL] CRL distribution-point encode failed error=%lu", GetLastError());
                g_tlsCrlDistributionPointBytes.clear();
                return false;
            }
            g_tlsCrlDistributionPointBytes.resize(distPointSize);

            // Publish an empty, CA-signed CRL. "Empty" means none of the local
            // diagnostic leaves are revoked. This gives Schannel a real
            // revocation answer instead of CRYPT_E_NO_REVOCATION_CHECK.
            FILETIME now{};
            GetSystemTimeAsFileTime(&now);
            ULARGE_INTEGER nowValue{};
            nowValue.LowPart = now.dwLowDateTime;
            nowValue.HighPart = now.dwHighDateTime;

            constexpr ULONGLONG kTicksPerSecond = 10000000ULL;
            constexpr ULONGLONG kFiveMinutes = 5ULL * 60ULL * kTicksPerSecond;
            constexpr ULONGLONG kThirtyDays = 30ULL * 24ULL * 60ULL * 60ULL * kTicksPerSecond;

            ULARGE_INTEGER thisUpdateValue = nowValue;
            if (thisUpdateValue.QuadPart > kFiveMinutes)
                thisUpdateValue.QuadPart -= kFiveMinutes;
            ULARGE_INTEGER nextUpdateValue = nowValue;
            nextUpdateValue.QuadPart += kThirtyDays;

            FILETIME thisUpdate{};
            thisUpdate.dwLowDateTime = thisUpdateValue.LowPart;
            thisUpdate.dwHighDateTime = thisUpdateValue.HighPart;
            FILETIME nextUpdate{};
            nextUpdate.dwLowDateTime = nextUpdateValue.LowPart;
            nextUpdate.dwHighDateTime = nextUpdateValue.HighPart;

            CRYPT_ALGORITHM_IDENTIFIER signature{};
            signature.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);

            CRL_INFO crlInfo{};
            crlInfo.dwVersion = CRL_V1;
            crlInfo.SignatureAlgorithm = signature;
            crlInfo.Issuer = g_tlsCaCertificate->pCertInfo->Subject;
            crlInfo.ThisUpdate = thisUpdate;
            crlInfo.NextUpdate = nextUpdate;
            crlInfo.cCRLEntry = 0;
            crlInfo.rgCRLEntry = nullptr;
            crlInfo.cExtension = 0;
            crlInfo.rgExtension = nullptr;

            DWORD encodedSize = 0;
            if (!CryptSignAndEncodeCertificate(g_tlsCaProvider, AT_SIGNATURE,
                    X509_ASN_ENCODING, X509_CERT_CRL_TO_BE_SIGNED, &crlInfo,
                    &signature, nullptr, nullptr, &encodedSize) || !encodedSize)
            {
                log::Print("[TRUST-CRL] local CRL signing(size) failed error=%lu", GetLastError());
                g_tlsCrlDer.clear();
                return false;
            }

            g_tlsCrlDer.resize(encodedSize);
            if (!CryptSignAndEncodeCertificate(g_tlsCaProvider, AT_SIGNATURE,
                    X509_ASN_ENCODING, X509_CERT_CRL_TO_BE_SIGNED, &crlInfo,
                    &signature, nullptr, g_tlsCrlDer.data(), &encodedSize))
            {
                log::Print("[TRUST-CRL] local CRL signing failed error=%lu", GetLastError());
                g_tlsCrlDer.clear();
                return false;
            }
            g_tlsCrlDer.resize(encodedSize);

            PCCRL_CONTEXT parsed = CertCreateCRLContext(
                X509_ASN_ENCODING, g_tlsCrlDer.data(), static_cast<DWORD>(g_tlsCrlDer.size()));
            if (!parsed)
            {
                log::Print("[TRUST-CRL] signed CRL parse verification failed error=%lu", GetLastError());
                g_tlsCrlDer.clear();
                return false;
            }
            CertFreeCRLContext(parsed);

            log::Print("[TRUST-CRL] local empty CRL ready bytes=%llu url=%ls scope=TLS_REVOCATION_TRUST_ONLY",
                static_cast<unsigned long long>(g_tlsCrlDer.size()), kLocalCrlUrl);
            return true;
        }

        bool CreateAdditionalTlsLeaf(const wchar_t* commonName,
            const wchar_t* const* dnsNames, std::size_t dnsNameCount,
            PCCERT_CONTEXT& outCertificate, const char* logLabel)
        {
            if (!commonName || !*commonName || !dnsNames || !dnsNameCount ||
                !g_tlsCaCertificate || !g_tlsCaProvider || !g_tlsProvider)
                return false;

            auto encodeName = [](const std::wstring& text, std::vector<BYTE>& storage, CERT_NAME_BLOB& blob) -> bool
            {
                DWORD size = 0;
                if (!CertStrToNameW(X509_ASN_ENCODING, text.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &size, nullptr) || !size)
                    return false;
                storage.resize(size);
                if (!CertStrToNameW(X509_ASN_ENCODING, text.c_str(), CERT_X500_NAME_STR, nullptr, storage.data(), &size, nullptr))
                    return false;
                blob.cbData = size;
                blob.pbData = storage.data();
                return true;
            };
            auto encodeObject = [](LPCSTR type, const void* object, std::vector<BYTE>& storage) -> bool
            {
                DWORD size = 0;
                if (!CryptEncodeObjectEx(X509_ASN_ENCODING, type, object, 0, nullptr, nullptr, &size) || !size)
                    return false;
                storage.resize(size);
                return !!CryptEncodeObjectEx(X509_ASN_ENCODING, type, object, 0, nullptr, storage.data(), &size);
            };

            std::vector<BYTE> subjectStorage;
            CERT_NAME_BLOB subject{};
            const std::wstring subjectText = std::wstring(L"CN=") + commonName;
            if (!encodeName(subjectText, subjectStorage, subject))
            {
                log::Print("[TLS443] %s subject encode failed error=%lu", logLabel, GetLastError());
                return false;
            }

            DWORD publicKeyInfoSize = 0;
            if (!CryptExportPublicKeyInfo(g_tlsProvider, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                    nullptr, &publicKeyInfoSize) || !publicKeyInfoSize)
                return false;
            std::vector<BYTE> publicKeyInfoBytes(publicKeyInfoSize);
            auto* publicKeyInfo = reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(publicKeyInfoBytes.data());
            if (!CryptExportPublicKeyInfo(g_tlsProvider, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                    publicKeyInfo, &publicKeyInfoSize))
                return false;

            std::vector<CERT_ALT_NAME_ENTRY> altEntries(dnsNameCount);
            for (std::size_t i = 0; i < dnsNameCount; ++i)
            {
                altEntries[i].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
                altEntries[i].pwszDNSName = const_cast<LPWSTR>(dnsNames[i]);
            }
            CERT_ALT_NAME_INFO altInfo{};
            altInfo.cAltEntry = static_cast<DWORD>(altEntries.size());
            altInfo.rgAltEntry = altEntries.data();
            std::vector<BYTE> altBytes;
            if (!encodeObject(X509_ALTERNATE_NAME, &altInfo, altBytes))
                return false;

            CERT_BASIC_CONSTRAINTS2_INFO constraints{};
            constraints.fCA = FALSE;
            std::vector<BYTE> constraintsBytes;
            if (!encodeObject(X509_BASIC_CONSTRAINTS2, &constraints, constraintsBytes))
                return false;

            BYTE usageByte = static_cast<BYTE>(CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE);
            CRYPT_BIT_BLOB usage{};
            usage.cbData = 1;
            usage.pbData = &usageByte;
            std::vector<BYTE> usageBytes;
            if (!encodeObject(X509_KEY_USAGE, &usage, usageBytes))
                return false;

            LPSTR ekuOid = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
            CERT_ENHKEY_USAGE enhancedUsage{};
            enhancedUsage.cUsageIdentifier = 1;
            enhancedUsage.rgpszUsageIdentifier = &ekuOid;
            std::vector<BYTE> enhancedUsageBytes;
            if (!encodeObject(X509_ENHANCED_KEY_USAGE, &enhancedUsage, enhancedUsageBytes))
                return false;

            if (g_tlsCrlDistributionPointBytes.empty())
            {
                log::Print("[TLS443] %s local CRL distribution point is not ready", logLabel);
                return false;
            }

            CERT_EXTENSION extensions[5]{};
            extensions[0].pszObjId = const_cast<LPSTR>(szOID_SUBJECT_ALT_NAME2);
            extensions[0].Value.cbData = static_cast<DWORD>(altBytes.size());
            extensions[0].Value.pbData = altBytes.data();
            extensions[1].pszObjId = const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2);
            extensions[1].fCritical = TRUE;
            extensions[1].Value.cbData = static_cast<DWORD>(constraintsBytes.size());
            extensions[1].Value.pbData = constraintsBytes.data();
            extensions[2].pszObjId = const_cast<LPSTR>(szOID_KEY_USAGE);
            extensions[2].fCritical = TRUE;
            extensions[2].Value.cbData = static_cast<DWORD>(usageBytes.size());
            extensions[2].Value.pbData = usageBytes.data();
            extensions[3].pszObjId = const_cast<LPSTR>(szOID_ENHANCED_KEY_USAGE);
            extensions[3].fCritical = TRUE;
            extensions[3].Value.cbData = static_cast<DWORD>(enhancedUsageBytes.size());
            extensions[3].Value.pbData = enhancedUsageBytes.data();
            extensions[4].pszObjId = const_cast<LPSTR>(szOID_CRL_DIST_POINTS);
            extensions[4].fCritical = FALSE;
            extensions[4].Value.cbData = static_cast<DWORD>(g_tlsCrlDistributionPointBytes.size());
            extensions[4].Value.pbData = g_tlsCrlDistributionPointBytes.data();

            BYTE serialBytes[16]{};
            if (!CryptGenRandom(g_tlsCaProvider, sizeof(serialBytes), serialBytes))
                return false;
            serialBytes[sizeof(serialBytes) - 1] &= 0x7F;
            if (!serialBytes[sizeof(serialBytes) - 1])
                serialBytes[sizeof(serialBytes) - 1] = 1;

            SYSTEMTIME startSystem{};
            SYSTEMTIME endSystem{};
            FILETIME start{};
            FILETIME end{};
            GetSystemTime(&startSystem);
            endSystem = startSystem;
            endSystem.wYear = static_cast<WORD>(endSystem.wYear + 2);
            if (!SystemTimeToFileTime(&startSystem, &start) || !SystemTimeToFileTime(&endSystem, &end))
                return false;

            CRYPT_ALGORITHM_IDENTIFIER signature{};
            signature.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);
            CERT_INFO info{};
            info.dwVersion = CERT_V3;
            info.SerialNumber.cbData = sizeof(serialBytes);
            info.SerialNumber.pbData = serialBytes;
            info.SignatureAlgorithm = signature;
            info.Issuer = g_tlsCaCertificate->pCertInfo->Subject;
            info.NotBefore = start;
            info.NotAfter = end;
            info.Subject = subject;
            info.SubjectPublicKeyInfo = *publicKeyInfo;
            info.cExtension = 5;
            info.rgExtension = extensions;

            DWORD encodedSize = 0;
            if (!CryptSignAndEncodeCertificate(g_tlsCaProvider, AT_SIGNATURE, X509_ASN_ENCODING,
                    X509_CERT_TO_BE_SIGNED, &info, &signature, nullptr, nullptr, &encodedSize) || !encodedSize)
                return false;
            std::vector<BYTE> encoded(encodedSize);
            if (!CryptSignAndEncodeCertificate(g_tlsCaProvider, AT_SIGNATURE, X509_ASN_ENCODING,
                    X509_CERT_TO_BE_SIGNED, &info, &signature, nullptr, encoded.data(), &encodedSize))
                return false;

            outCertificate = CertCreateCertificateContext(X509_ASN_ENCODING, encoded.data(), encodedSize);
            if (!outCertificate)
                return false;

            CRYPT_KEY_PROV_INFO providerInfo{};
            providerInfo.pwszContainerName = const_cast<LPWSTR>(L"CodRevamped_IW8_1119_TLS_LEAF");
            providerInfo.pwszProvName = const_cast<LPWSTR>(MS_DEF_RSA_SCHANNEL_PROV_W);
            providerInfo.dwProvType = PROV_RSA_SCHANNEL;
            providerInfo.dwKeySpec = AT_KEYEXCHANGE;
            if (!CertSetCertificateContextProperty(outCertificate, CERT_KEY_PROV_INFO_PROP_ID, 0, &providerInfo))
            {
                CertFreeCertificateContext(outCertificate);
                outCertificate = nullptr;
                return false;
            }

            BYTE hash[64]{};
            DWORD hashSize = sizeof(hash);
            if (CertGetCertificateContextProperty(outCertificate, CERT_SHA256_HASH_PROP_ID, hash, &hashSize))
                log::Print("[TLS443] generated SNI leaf identity=%s cn=%ls dnsNames=%llu sha256=%s",
                    logLabel, commonName, static_cast<unsigned long long>(dnsNameCount), HexBytes(hash, hashSize).c_str());
            return true;
        }

        bool BuildTlsCertificate()
        {
            // Correct BGS trust architecture:
            //   local CA (self-signed) -> signs leaf us.actual.battle.net
            //   BGS bundle trusts CA SPKI + embeds CA cert
            //   SChannel presents leaf cert (not the CA itself)
            //   OPTION2 bundle-signing key remains completely separate.
            static wchar_t caContainerName[] = L"CodRevamped_IW8_1119_TLS_CA";
            static wchar_t leafContainerName[] = L"CodRevamped_IW8_1119_TLS_LEAF";

            auto acquireKey = [](HCRYPTPROV& provider, HCRYPTKEY& key,
                                 const wchar_t* container, const wchar_t* providerName,
                                 DWORD providerType, DWORD keySpec, DWORD bits,
                                 const char* label) -> bool
            {
                if (!CryptAcquireContextW(&provider, container, providerName, providerType,
                        CRYPT_NEWKEYSET | CRYPT_SILENT))
                {
                    const DWORD error = GetLastError();
                    if (error != NTE_EXISTS || !CryptAcquireContextW(&provider, container,
                            providerName, providerType, CRYPT_SILENT))
                    {
                        log::Print("[TLS1119] CryptAcquireContext(%s) failed error=%lu", label, GetLastError());
                        return false;
                    }
                }
                if (!CryptGetUserKey(provider, keySpec, &key))
                {
                    if (!CryptGenKey(provider, keySpec, (bits << 16) | CRYPT_EXPORTABLE, &key))
                    {
                        log::Print("[TLS1119] CryptGenKey(%s) failed error=%lu", label, GetLastError());
                        return false;
                    }
                }
                return true;
            };

            if (!acquireKey(g_tlsCaProvider, g_tlsCaKey,
                    caContainerName, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
                    AT_SIGNATURE, 2048, "CA"))
                return false;
            if (!acquireKey(g_tlsProvider, g_tlsKey,
                    leafContainerName, MS_DEF_RSA_SCHANNEL_PROV_W, PROV_RSA_SCHANNEL,
                    AT_KEYEXCHANGE, 2048, "leaf"))
                return false;

            std::string caProviderSpkiSha256;
            if (!ComputeProviderSpkiSha256(g_tlsCaProvider, AT_SIGNATURE, caProviderSpkiSha256))
            {
                log::Print("[TLS1119] local CA provider SPKI SHA256 failed error=%lu", GetLastError());
                return false;
            }

            auto encodeName = [](const wchar_t* text, std::vector<BYTE>& storage, CERT_NAME_BLOB& blob) -> bool
            {
                DWORD size = 0;
                if (!CertStrToNameW(X509_ASN_ENCODING, text, CERT_X500_NAME_STR, nullptr, nullptr, &size, nullptr) || !size)
                    return false;
                storage.resize(size);
                if (!CertStrToNameW(X509_ASN_ENCODING, text, CERT_X500_NAME_STR, nullptr, storage.data(), &size, nullptr))
                    return false;
                blob.cbData = size;
                blob.pbData = storage.data();
                return true;
            };

            auto encodeObject = [](LPCSTR type, const void* object, std::vector<BYTE>& storage) -> bool
            {
                DWORD size = 0;
                if (!CryptEncodeObjectEx(X509_ASN_ENCODING, type, object, 0, nullptr, nullptr, &size) || !size)
                    return false;
                storage.resize(size);
                return !!CryptEncodeObjectEx(X509_ASN_ENCODING, type, object, 0, nullptr, storage.data(), &size);
            };

            CRYPT_ALGORITHM_IDENTIFIER signature{};
            signature.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);

            // ----- Root CA -----
            std::vector<BYTE> caSubjectStorage;
            CERT_NAME_BLOB caSubject{};
            if (!encodeName(L"CN=CodRevamped IW8 Local BGS Root CA", caSubjectStorage, caSubject))
            {
                log::Print("[TLS1119] CA CertStrToName failed error=%lu", GetLastError());
                return false;
            }

            CERT_BASIC_CONSTRAINTS2_INFO caConstraints{};
            caConstraints.fCA = TRUE;
            caConstraints.fPathLenConstraint = FALSE;
            std::vector<BYTE> caConstraintsBytes;
            if (!encodeObject(X509_BASIC_CONSTRAINTS2, &caConstraints, caConstraintsBytes))
            {
                log::Print("[TLS1119] CA BasicConstraints encode failed error=%lu", GetLastError());
                return false;
            }

            BYTE caUsageByte = static_cast<BYTE>(CERT_KEY_CERT_SIGN_KEY_USAGE | CERT_CRL_SIGN_KEY_USAGE);
            CRYPT_BIT_BLOB caUsage{};
            caUsage.cbData = 1;
            caUsage.pbData = &caUsageByte;
            caUsage.cUnusedBits = 0;
            std::vector<BYTE> caUsageBytes;
            if (!encodeObject(X509_KEY_USAGE, &caUsage, caUsageBytes))
            {
                log::Print("[TLS1119] CA KeyUsage encode failed error=%lu", GetLastError());
                return false;
            }

            CERT_EXTENSION caExtensionsArray[2]{};
            caExtensionsArray[0].pszObjId = const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2);
            caExtensionsArray[0].fCritical = TRUE;
            caExtensionsArray[0].Value.cbData = static_cast<DWORD>(caConstraintsBytes.size());
            caExtensionsArray[0].Value.pbData = caConstraintsBytes.data();
            caExtensionsArray[1].pszObjId = const_cast<LPSTR>(szOID_KEY_USAGE);
            caExtensionsArray[1].fCritical = TRUE;
            caExtensionsArray[1].Value.cbData = static_cast<DWORD>(caUsageBytes.size());
            caExtensionsArray[1].Value.pbData = caUsageBytes.data();
            CERT_EXTENSIONS caExtensions{};
            caExtensions.cExtension = 2;
            caExtensions.rgExtension = caExtensionsArray;

            CRYPT_KEY_PROV_INFO caProviderInfo{};
            caProviderInfo.pwszContainerName = caContainerName;
            caProviderInfo.pwszProvName = const_cast<LPWSTR>(MS_ENH_RSA_AES_PROV_W);
            caProviderInfo.dwProvType = PROV_RSA_AES;
            caProviderInfo.dwKeySpec = AT_SIGNATURE;

            SYSTEMTIME caStart{};
            SYSTEMTIME caEnd{};
            GetSystemTime(&caStart);
            caEnd = caStart;
            caEnd.wYear = static_cast<WORD>(caEnd.wYear + 10);

            // Reuse the exact same root certificate across server launches.
            // Windows TLS trust is certificate-based, not merely public-key based,
            // so regenerating a fresh self-signed root on every launch would require
            // the user to trust a new certificate each time.
            const std::wstring persistedCaPath = LocalBgsRootCertificatePath();
            if (!persistedCaPath.empty())
            {
                PCCERT_CONTEXT persisted = LoadDerCertificateFile(persistedCaPath);
                if (persisted)
                {
                    std::string persistedSpki;
                    if (ComputeCertificateSpkiSha256(persisted, persistedSpki) &&
                        _stricmp(persistedSpki.c_str(), caProviderSpkiSha256.c_str()) == 0)
                    {
                        g_tlsCaCertificate = persisted;
                        log::Print("[TLS1119] reusing persisted local BGS root CA certificate");
                    }
                    else
                    {
                        log::Print("[TLS1119] persisted local BGS root CA does not match the current CA key; regenerating it");
                        CertFreeCertificateContext(persisted);
                    }
                }
            }

            if (!g_tlsCaCertificate)
            {
                g_tlsCaCertificate = CertCreateSelfSignCertificate(
                    static_cast<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE>(g_tlsCaProvider), &caSubject, 0,
                    &caProviderInfo, &signature, &caStart, &caEnd, &caExtensions);
                if (!g_tlsCaCertificate)
                {
                    log::Print("[TLS1119] local CA creation failed error=%lu", GetLastError());
                    return false;
                }
            }

            g_tlsSpkiSha256.clear();
            if (!ComputeCertificateSpkiSha256(g_tlsCaCertificate, g_tlsSpkiSha256))
            {
                log::Print("[TLS1119] local CA SPKI SHA256 failed error=%lu", GetLastError());
                return false;
            }
            if (_stricmp(g_tlsSpkiSha256.c_str(), caProviderSpkiSha256.c_str()) != 0)
            {
                log::Print("[TLS1119] local CA certificate/key SPKI mismatch cert=%s key=%s",
                    g_tlsSpkiSha256.c_str(), caProviderSpkiSha256.c_str());
                return false;
            }
            ExportAndReportLocalBgsRootCertificate(g_tlsCaCertificate);

            if (!BuildLocalTlsRevocationArtifacts())
            {
                log::Print("[TRUST-CRL] failed to initialize local revocation infrastructure");
                return false;
            }

            // ----- Server leaf signed by the CA -----
            std::vector<BYTE> leafSubjectStorage;
            CERT_NAME_BLOB leafSubject{};
            if (!encodeName(L"CN=us.actual.battle.net", leafSubjectStorage, leafSubject))
            {
                log::Print("[TLS1119] leaf CertStrToName failed error=%lu", GetLastError());
                return false;
            }

            DWORD publicKeyInfoSize = 0;
            if (!CryptExportPublicKeyInfo(g_tlsProvider, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                    nullptr, &publicKeyInfoSize) || !publicKeyInfoSize)
            {
                log::Print("[TLS1119] CryptExportPublicKeyInfo(size) failed error=%lu", GetLastError());
                return false;
            }
            std::vector<BYTE> publicKeyInfoBytes(publicKeyInfoSize);
            auto* publicKeyInfo = reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(publicKeyInfoBytes.data());
            if (!CryptExportPublicKeyInfo(g_tlsProvider, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                    publicKeyInfo, &publicKeyInfoSize))
            {
                log::Print("[TLS1119] CryptExportPublicKeyInfo failed error=%lu", GetLastError());
                return false;
            }

            // One locally trusted leaf covers the BGS endpoint plus the exact
            // Battle.net web endpoints used by IW8's post-login OAuth/bootstrap.
            // These are protocol hostnames, not executable addresses.
            // Keep all currently observed redirect targets on the local leaf.  The
            // Demonware auth3 endpoint is raw TLS (not WinHTTP), so hostname
            // validation happens before WebAuthService ever sees HTTP bytes.
            // These are wire/service hostnames only; no game RVAs are involved.
            const wchar_t* dnsNames[] = {
                L"us.actual.battle.net",
                L"oauth-us.web.blizzard.net",
                L"us-gateway.integration.blizzard.com",
                L"us.battle.net",
                L"us.api.blizzard.com",
                L"nydus.battle.net",
                L"nydus-qa.web.blizzard.net",
                L"iw8-bnet-auth3.prod.demonware.net",
                L"auth3.prod.demonware.net",
                L"auth3-login.prod.demonware.net",
                L"loginqueue.prod.demonware.net",
                L"prod.umbrella.demonware.net",
                L"*.umbrella.demonware.net",
                L"*.prod.demonware.net",
                L"localhost"
            };
            CERT_ALT_NAME_ENTRY altEntries[_countof(dnsNames) + 1]{};
            for (std::size_t i = 0; i < _countof(dnsNames); ++i)
            {
                altEntries[i].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
                altEntries[i].pwszDNSName = const_cast<LPWSTR>(dnsNames[i]);
            }
            BYTE loopbackBytes[4]{127, 0, 0, 1};
            const std::size_t loopbackAltIndex = _countof(dnsNames);
            altEntries[loopbackAltIndex].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
            altEntries[loopbackAltIndex].IPAddress.cbData = sizeof(loopbackBytes);
            altEntries[loopbackAltIndex].IPAddress.pbData = loopbackBytes;
            CERT_ALT_NAME_INFO altInfo{};
            altInfo.cAltEntry = static_cast<DWORD>(_countof(altEntries));
            altInfo.rgAltEntry = altEntries;
            std::vector<BYTE> altBytes;
            if (!encodeObject(X509_ALTERNATE_NAME, &altInfo, altBytes))
            {
                log::Print("[TLS1119] leaf SAN encode failed error=%lu", GetLastError());
                return false;
            }

            CERT_BASIC_CONSTRAINTS2_INFO leafConstraints{};
            leafConstraints.fCA = FALSE;
            std::vector<BYTE> leafConstraintsBytes;
            if (!encodeObject(X509_BASIC_CONSTRAINTS2, &leafConstraints, leafConstraintsBytes))
            {
                log::Print("[TLS1119] leaf BasicConstraints encode failed error=%lu", GetLastError());
                return false;
            }

            BYTE leafUsageByte = static_cast<BYTE>(CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE);
            CRYPT_BIT_BLOB leafUsage{};
            leafUsage.cbData = 1;
            leafUsage.pbData = &leafUsageByte;
            leafUsage.cUnusedBits = 0;
            std::vector<BYTE> leafUsageBytes;
            if (!encodeObject(X509_KEY_USAGE, &leafUsage, leafUsageBytes))
            {
                log::Print("[TLS1119] leaf KeyUsage encode failed error=%lu", GetLastError());
                return false;
            }

            LPSTR serverAuthOid = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
            CERT_ENHKEY_USAGE enhancedUsage{};
            enhancedUsage.cUsageIdentifier = 1;
            enhancedUsage.rgpszUsageIdentifier = &serverAuthOid;
            std::vector<BYTE> enhancedUsageBytes;
            if (!encodeObject(X509_ENHANCED_KEY_USAGE, &enhancedUsage, enhancedUsageBytes))
            {
                log::Print("[TLS1119] leaf EKU encode failed error=%lu", GetLastError());
                return false;
            }

            CERT_EXTENSION leafExtensions[5]{};
            leafExtensions[0].pszObjId = const_cast<LPSTR>(szOID_SUBJECT_ALT_NAME2);
            leafExtensions[0].fCritical = FALSE;
            leafExtensions[0].Value.cbData = static_cast<DWORD>(altBytes.size());
            leafExtensions[0].Value.pbData = altBytes.data();
            leafExtensions[1].pszObjId = const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2);
            leafExtensions[1].fCritical = TRUE;
            leafExtensions[1].Value.cbData = static_cast<DWORD>(leafConstraintsBytes.size());
            leafExtensions[1].Value.pbData = leafConstraintsBytes.data();
            leafExtensions[2].pszObjId = const_cast<LPSTR>(szOID_KEY_USAGE);
            leafExtensions[2].fCritical = TRUE;
            leafExtensions[2].Value.cbData = static_cast<DWORD>(leafUsageBytes.size());
            leafExtensions[2].Value.pbData = leafUsageBytes.data();
            leafExtensions[3].pszObjId = const_cast<LPSTR>(szOID_ENHANCED_KEY_USAGE);
            leafExtensions[3].fCritical = TRUE;
            leafExtensions[3].Value.cbData = static_cast<DWORD>(enhancedUsageBytes.size());
            leafExtensions[3].Value.pbData = enhancedUsageBytes.data();
            leafExtensions[4].pszObjId = const_cast<LPSTR>(szOID_CRL_DIST_POINTS);
            leafExtensions[4].fCritical = FALSE;
            leafExtensions[4].Value.cbData = static_cast<DWORD>(g_tlsCrlDistributionPointBytes.size());
            leafExtensions[4].Value.pbData = g_tlsCrlDistributionPointBytes.data();

            BYTE serialBytes[16]{};
            if (!CryptGenRandom(g_tlsCaProvider, sizeof(serialBytes), serialBytes))
            {
                log::Print("[TLS1119] leaf serial generation failed error=%lu", GetLastError());
                return false;
            }
            serialBytes[sizeof(serialBytes) - 1] &= 0x7F;
            if (!serialBytes[sizeof(serialBytes) - 1])
                serialBytes[sizeof(serialBytes) - 1] = 1;

            SYSTEMTIME leafStartSystem{};
            SYSTEMTIME leafEndSystem{};
            FILETIME leafStart{};
            FILETIME leafEnd{};
            GetSystemTime(&leafStartSystem);
            leafEndSystem = leafStartSystem;
            leafEndSystem.wYear = static_cast<WORD>(leafEndSystem.wYear + 2);
            if (!SystemTimeToFileTime(&leafStartSystem, &leafStart) ||
                !SystemTimeToFileTime(&leafEndSystem, &leafEnd))
            {
                log::Print("[TLS1119] leaf validity conversion failed error=%lu", GetLastError());
                return false;
            }

            CERT_INFO leafInfo{};
            leafInfo.dwVersion = CERT_V3;
            leafInfo.SerialNumber.cbData = sizeof(serialBytes);
            leafInfo.SerialNumber.pbData = serialBytes;
            leafInfo.SignatureAlgorithm = signature;
            leafInfo.Issuer = g_tlsCaCertificate->pCertInfo->Subject;
            leafInfo.NotBefore = leafStart;
            leafInfo.NotAfter = leafEnd;
            leafInfo.Subject = leafSubject;
            leafInfo.SubjectPublicKeyInfo = *publicKeyInfo;
            leafInfo.cExtension = 5;
            leafInfo.rgExtension = leafExtensions;

            DWORD encodedLeafSize = 0;
            if (!CryptSignAndEncodeCertificate(g_tlsCaProvider, AT_SIGNATURE, X509_ASN_ENCODING,
                    X509_CERT_TO_BE_SIGNED, &leafInfo, &signature, nullptr, nullptr, &encodedLeafSize) ||
                !encodedLeafSize)
            {
                log::Print("[TLS1119] leaf signing(size) failed error=%lu", GetLastError());
                return false;
            }
            std::vector<BYTE> encodedLeaf(encodedLeafSize);
            if (!CryptSignAndEncodeCertificate(g_tlsCaProvider, AT_SIGNATURE, X509_ASN_ENCODING,
                    X509_CERT_TO_BE_SIGNED, &leafInfo, &signature, nullptr,
                    encodedLeaf.data(), &encodedLeafSize))
            {
                log::Print("[TLS1119] leaf signing failed error=%lu", GetLastError());
                return false;
            }

            g_tlsCertificate = CertCreateCertificateContext(X509_ASN_ENCODING,
                encodedLeaf.data(), encodedLeafSize);
            if (!g_tlsCertificate)
            {
                log::Print("[TLS1119] CertCreateCertificateContext(leaf) failed error=%lu", GetLastError());
                return false;
            }

            CRYPT_KEY_PROV_INFO leafProviderInfo{};
            leafProviderInfo.pwszContainerName = leafContainerName;
            leafProviderInfo.pwszProvName = const_cast<LPWSTR>(MS_DEF_RSA_SCHANNEL_PROV_W);
            leafProviderInfo.dwProvType = PROV_RSA_SCHANNEL;
            leafProviderInfo.dwKeySpec = AT_KEYEXCHANGE;
            if (!CertSetCertificateContextProperty(g_tlsCertificate, CERT_KEY_PROV_INFO_PROP_ID,
                    0, &leafProviderInfo))
            {
                log::Print("[TLS1119] CertSetCertificateContextProperty(leaf private key) failed error=%lu", GetLastError());
                return false;
            }

            BYTE caHash[64]{};
            DWORD caHashSize = sizeof(caHash);
            if (CertGetCertificateContextProperty(g_tlsCaCertificate, CERT_SHA256_HASH_PROP_ID, caHash, &caHashSize))
                log::Print("[TLS1119] local BGS root CA sha256=%s", HexBytes(caHash, caHashSize).c_str());

            BYTE leafHash[64]{};
            DWORD leafHashSize = sizeof(leafHash);
            if (CertGetCertificateContextProperty(g_tlsCertificate, CERT_SHA256_HASH_PROP_ID, leafHash, &leafHashSize))
                log::Print("[TLS1119] local leaf certificate subject=us.actual.battle.net sha256=%s", HexBytes(leafHash, leafHashSize).c_str());

            g_tlsLeafSpkiSha256.clear();
            if (ComputeCertificateSpkiSha256(g_tlsCertificate, g_tlsLeafSpkiSha256))
                log::Print("[TLS1119] local trust chain ready caSpki=%s leafSpki=%s leafIssuer=CodRevamped-IW8-CA leafIsCA=no",
                    g_tlsSpkiSha256.c_str(), g_tlsLeafSpkiSha256.c_str());
            else
                log::Print("[TLS1119] WARNING: could not compute local leaf SPKI SHA256 error=%lu", GetLastError());

            log::Print("[TLS443] local leaf SAN coverage ready dnsNames=%llu includes={us.battle.net,iw8-bnet-auth3.prod.demonware.net,prod.umbrella.demonware.net,*.umbrella.demonware.net,*.prod.demonware.net} loopback=yes",
                static_cast<unsigned long long>(_countof(dnsNames)));

            const wchar_t* battleNetDns[] = {
                L"us.battle.net", L"oauth-us.web.blizzard.net", L"us.api.blizzard.com",
                L"us-gateway.integration.blizzard.com"
            };
            if (!CreateAdditionalTlsLeaf(L"us.battle.net", battleNetDns, _countof(battleNetDns),
                    g_tls443BattleNetCertificate, "battle-net-web"))
                log::Print("[TLS443] WARNING: could not create exact-CN us.battle.net leaf; :443 will fall back to the broad BGS leaf");
            g_tls443BattleNetSpkiSha256.clear();
            if (g_tls443BattleNetCertificate &&
                ComputeCertificateSpkiSha256(g_tls443BattleNetCertificate, g_tls443BattleNetSpkiSha256))
            {
                log::Print("[TLS443] exact leaf SPKI identity=battle-net-web spki=%s matchesBroadLeaf=%s",
                    g_tls443BattleNetSpkiSha256.c_str(),
                    g_tls443BattleNetSpkiSha256 == g_tlsLeafSpkiSha256 ? "YES" : "no");
            }

            const wchar_t* demonwareDns[] = {
                L"iw8-bnet-auth3.prod.demonware.net", L"auth3.prod.demonware.net",
                L"auth3-login.prod.demonware.net", L"loginqueue.prod.demonware.net",
                L"prod.umbrella.demonware.net", L"*.umbrella.demonware.net",
                L"*.prod.demonware.net"
            };
            if (!CreateAdditionalTlsLeaf(L"iw8-bnet-auth3.prod.demonware.net", demonwareDns, _countof(demonwareDns),
                    g_tls443DemonwareCertificate, "demonware-auth3"))
                log::Print("[TLS443] WARNING: could not create exact-CN Demonware leaf; :443 will fall back to the broad BGS leaf");
            g_tls443DemonwareSpkiSha256.clear();
            if (g_tls443DemonwareCertificate &&
                ComputeCertificateSpkiSha256(g_tls443DemonwareCertificate, g_tls443DemonwareSpkiSha256))
            {
                log::Print("[TLS443] exact leaf SPKI identity=demonware-auth3 spki=%s matchesBroadLeaf=%s",
                    g_tls443DemonwareSpkiSha256.c_str(),
                    g_tls443DemonwareSpkiSha256 == g_tlsLeafSpkiSha256 ? "YES" : "no");
            }

            ExportLocalTrustSpkiManifest();
            return true;
        }

        void LogWindowsTlsPolicyForHost(const wchar_t* host, PCCERT_CONTEXT certificate = nullptr)
        {
            if (!certificate)
                certificate = g_tlsCertificate;
            if (!host || !*host || !certificate)
                return;

            CERT_CHAIN_PARA chainPara{};
            chainPara.cbSize = sizeof(chainPara);
            PCCERT_CHAIN_CONTEXT chain = nullptr;
            if (!CertGetCertificateChain(nullptr, certificate, nullptr, nullptr,
                    &chainPara, 0, nullptr, &chain) || !chain)
            {
                log::Print("[TLS-POLICY] host=%ls chainBuild=FAILED error=%lu", host, GetLastError());
                return;
            }

            SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslExtra{};
            sslExtra.cbSize = sizeof(sslExtra);
            sslExtra.dwAuthType = AUTHTYPE_SERVER;
            sslExtra.pwszServerName = const_cast<LPWSTR>(host);

            CERT_CHAIN_POLICY_PARA policyPara{};
            policyPara.cbSize = sizeof(policyPara);
            policyPara.pvExtraPolicyPara = &sslExtra;

            CERT_CHAIN_POLICY_STATUS policyStatus{};
            policyStatus.cbSize = sizeof(policyStatus);
            const BOOL verified = CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_SSL, chain, &policyPara, &policyStatus);
            log::Print("[TLS-POLICY] host=%ls windowsPolicy=%s policyError=0x%08lX chainTrust=0x%08lX",
                host,
                verified && policyStatus.dwError == 0 ? "OK" : "FAIL",
                static_cast<unsigned long>(policyStatus.dwError),
                chain->TrustStatus.dwErrorStatus);
            CertFreeCertificateChain(chain);
        }

        bool AcquireTlsCredentialForCertificate(PCCERT_CONTEXT certificate, CredHandle& handle, const char* label)
        {
            if (!certificate)
                return false;
            PCCERT_CONTEXT certificates[1]{certificate};
            SCHANNEL_CRED credential{};
            credential.dwVersion = SCHANNEL_CRED_VERSION;
            credential.cCreds = 1;
            credential.paCred = certificates;
            credential.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
            TimeStamp expiry{};
            const SECURITY_STATUS status = AcquireCredentialsHandleW(nullptr, const_cast<LPWSTR>(UNISP_NAME_W),
                SECPKG_CRED_INBOUND, nullptr, &credential, nullptr, nullptr, &handle, &expiry);
            if (status != SEC_E_OK)
            {
                log::Print("[TLS443] AcquireCredentialsHandle identity=%s failed status=0x%08lX", label,
                    static_cast<unsigned long>(status));
                return false;
            }
            return true;
        }

        bool InitializeTlsCredential()
        {
            if (g_tlsCredentialValid) return true;
            if (g_tlsCredentialAttempted) return false;
            g_tlsCredentialAttempted = true;
            if (!BuildTlsCertificate()) return false;

            if (!AcquireTlsCredentialForCertificate(g_tlsCertificate, g_tlsCredential, "us.actual.battle.net"))
            {
                log::Print("[TLS1119] primary BGS AcquireCredentialsHandle failed");
                return false;
            }
            g_tlsCredentialValid = true;

            if (g_tls443BattleNetCertificate)
                g_tls443BattleNetCredentialValid = AcquireTlsCredentialForCertificate(
                    g_tls443BattleNetCertificate, g_tls443BattleNetCredential, "us.battle.net");
            if (g_tls443DemonwareCertificate)
                g_tls443DemonwareCredentialValid = AcquireTlsCredentialForCertificate(
                    g_tls443DemonwareCertificate, g_tls443DemonwareCredential, "iw8-bnet-auth3.prod.demonware.net");

            log::Print("[TLS1119] SChannel server credential ready; TLS1.2 inbound enabled. Presenting CA-signed us.actual.battle.net leaf; local CA trust comes only from the signed BGS bundle.");
            log::Print("[TLS443] SNI credentials ready battleNet=%s demonware=%s fallback=broad-us.actual.battle.net",
                g_tls443BattleNetCredentialValid ? "yes" : "no",
                g_tls443DemonwareCredentialValid ? "yes" : "no");

            // Verify the generated certificate against the Windows current-user
            // trust store for the two hostnames actually observed in the V27 run.
            // If these report OK while the stock client still closes the raw TLS
            // connection, the remaining blocker is game/Demonware-specific trust
            // or pinning rather than malformed SAN/chain construction.
            LogWindowsTlsPolicyForHost(L"us.battle.net",
                g_tls443BattleNetCertificate ? g_tls443BattleNetCertificate : g_tlsCertificate);
            LogWindowsTlsPolicyForHost(L"iw8-bnet-auth3.prod.demonware.net",
                g_tls443DemonwareCertificate ? g_tls443DemonwareCertificate : g_tlsCertificate);
            LogWindowsTlsPolicyForHost(L"prod.umbrella.demonware.net",
                g_tls443DemonwareCertificate ? g_tls443DemonwareCertificate : g_tlsCertificate);
            return true;
        }

        void ShutdownTlsCredential()
        {
            if (g_tls443BattleNetCredentialValid)
            {
                FreeCredentialsHandle(&g_tls443BattleNetCredential);
                g_tls443BattleNetCredentialValid = false;
            }
            if (g_tls443DemonwareCredentialValid)
            {
                FreeCredentialsHandle(&g_tls443DemonwareCredential);
                g_tls443DemonwareCredentialValid = false;
            }
            if (g_tlsCredentialValid)
            {
                FreeCredentialsHandle(&g_tlsCredential);
                g_tlsCredentialValid = false;
            }
            if (g_tls443BattleNetCertificate)
            {
                CertFreeCertificateContext(g_tls443BattleNetCertificate);
                g_tls443BattleNetCertificate = nullptr;
            }
            if (g_tls443DemonwareCertificate)
            {
                CertFreeCertificateContext(g_tls443DemonwareCertificate);
                g_tls443DemonwareCertificate = nullptr;
            }
            if (g_tlsCertificate)
            {
                CertFreeCertificateContext(g_tlsCertificate);
                g_tlsCertificate = nullptr;
            }
            if (g_tlsCaCertificate)
            {
                CertFreeCertificateContext(g_tlsCaCertificate);
                g_tlsCaCertificate = nullptr;
            }
            if (g_tlsKey)
            {
                CryptDestroyKey(g_tlsKey);
                g_tlsKey = 0;
            }
            if (g_tlsCaKey)
            {
                CryptDestroyKey(g_tlsCaKey);
                g_tlsCaKey = 0;
            }
            if (g_tlsProvider)
            {
                CryptReleaseContext(g_tlsProvider, 0);
                g_tlsProvider = 0;
            }
            if (g_tlsCaProvider)
            {
                CryptReleaseContext(g_tlsCaProvider, 0);
                g_tlsCaProvider = 0;
            }
            g_tlsCredentialAttempted = false;
        }

        void DestroyTlsSession(void*& opaque)
        {
            auto* session = static_cast<TlsSession*>(opaque);
            if (!session) return;
            if (session->contextValid) DeleteSecurityContext(&session->context);
            delete session;
            opaque = nullptr;
        }

        bool SendTlsToken(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer, const void* data, std::size_t size)
        {
            const auto* bytes = static_cast<const char*>(data);
            std::size_t offset = 0;
            while (offset < size)
            {
                const int result = send(socket, bytes + offset,
                    static_cast<int>((std::min)(size - offset, static_cast<std::size_t>(0x7FFFFFFF))), 0);
                if (result == SOCKET_ERROR)
                {
                    log::Print("[TLS%u] id=%llu send server-flight failed WSA=%d after=%llu/%llu",
                        static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), WSAGetLastError(),
                        static_cast<unsigned long long>(offset), static_cast<unsigned long long>(size));
                    return false;
                }
                if (result == 0) return false;
                offset += static_cast<std::size_t>(result);
            }
            log::Payload(id, "TLS-OUT", session.localPort, peer, data, size);
            log::Print("[TLS%u] id=%llu sent SChannel server flight bytes=%llu",
                static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long long>(size));
            return true;
        }


        void ProtoAppendVarint(std::vector<BYTE>& out, std::uint64_t value)
        {
            do
            {
                BYTE b = static_cast<BYTE>(value & 0x7Fu);
                value >>= 7;
                if (value) b |= 0x80u;
                out.push_back(b);
            } while (value);
        }

        void ProtoAppendKey(std::vector<BYTE>& out, std::uint32_t field, std::uint32_t wire)
        {
            ProtoAppendVarint(out, (static_cast<std::uint64_t>(field) << 3) | wire);
        }

        void ProtoAppendVarintField(std::vector<BYTE>& out, std::uint32_t field, std::uint64_t value)
        {
            ProtoAppendKey(out, field, 0);
            ProtoAppendVarint(out, value);
        }

        void ProtoAppendFixed32Field(std::vector<BYTE>& out, std::uint32_t field, std::uint32_t value)
        {
            ProtoAppendKey(out, field, 5);
            out.push_back(static_cast<BYTE>(value & 0xFFu));
            out.push_back(static_cast<BYTE>((value >> 8) & 0xFFu));
            out.push_back(static_cast<BYTE>((value >> 16) & 0xFFu));
            out.push_back(static_cast<BYTE>((value >> 24) & 0xFFu));
        }

        void ProtoAppendFixed64Field(std::vector<BYTE>& out, std::uint32_t field, std::uint64_t value)
        {
            ProtoAppendKey(out, field, 1);
            for (unsigned shift = 0; shift < 64; shift += 8)
                out.push_back(static_cast<BYTE>((value >> shift) & 0xFFu));
        }

        void ProtoAppendBytesField(std::vector<BYTE>& out, std::uint32_t field, const void* data, std::size_t size)
        {
            ProtoAppendKey(out, field, 2);
            ProtoAppendVarint(out, size);
            if (size && data)
            {
                const auto* bytes = static_cast<const BYTE*>(data);
                out.insert(out.end(), bytes, bytes + size);
            }
        }

        void ProtoAppendStringField(std::vector<BYTE>& out, std::uint32_t field, const std::string& value)
        {
            ProtoAppendBytesField(out, field, value.data(), value.size());
        }

        std::vector<BYTE> BuildBgsChallengeExternalFrame(const std::string& webAuthUrl, std::uint32_t token)
        {
            // bgs.protocol.challenge.v1.ChallengeExternalRequest
            //   field 2 = payload_type ("web_auth_url")
            //   field 3 = payload (URL bytes)
            std::vector<BYTE> body;
            ProtoAppendStringField(body, 2, "web_auth_url");
            ProtoAppendBytesField(body, 3, webAuthUrl.data(), webAuthUrl.size());

            // bgs.protocol.Header framing used by Battle.net BGS RPC:
            //   u16be protobuf-header-size | Header | body
            // Header fields are intentionally the minimum request fields:
            //   service_id=0, method_id=3, token=<server request token>, size=body size,
            //   service_hash=ChallengeListener (0xBBDA171F).
            std::vector<BYTE> header;
            ProtoAppendVarintField(header, 1, 0);                  // service_id
            ProtoAppendVarintField(header, 2, 3);                  // method_id: OnExternalChallenge
            ProtoAppendVarintField(header, 3, token);              // server request token
            ProtoAppendVarintField(header, 5, body.size());        // size
            ProtoAppendFixed32Field(header, 11, 0xBBDA171Fu);      // ChallengeListenerHash

            std::vector<BYTE> frame;
            const std::uint16_t headerSize = static_cast<std::uint16_t>(header.size());
            frame.push_back(static_cast<BYTE>((headerSize >> 8) & 0xFFu));
            frame.push_back(static_cast<BYTE>(headerSize & 0xFFu));
            frame.insert(frame.end(), header.begin(), header.end());
            frame.insert(frame.end(), body.begin(), body.end());
            return frame;
        }

        bool SendTlsApplication(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            const void* plaintext, std::size_t plaintextSize, const char* label)
        {
            if (!session.established || !plaintext || !plaintextSize) return false;
            if (!session.streamSizes.cbHeader || !session.streamSizes.cbTrailer || !session.streamSizes.cbMaximumMessage)
            {
                log::Print("[TLS%u] id=%llu cannot send %s: invalid SChannel stream sizes", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), label ? label : "application");
                return false;
            }
            if (plaintextSize > session.streamSizes.cbMaximumMessage)
            {
                log::Print("[TLS%u] id=%llu cannot send %s: plaintext=%llu exceeds maxMessage=%lu",
                    static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), label ? label : "application",
                    static_cast<unsigned long long>(plaintextSize), session.streamSizes.cbMaximumMessage);
                return false;
            }

            std::vector<BYTE> encrypted(session.streamSizes.cbHeader + plaintextSize + session.streamSizes.cbTrailer);
            std::memcpy(encrypted.data() + session.streamSizes.cbHeader, plaintext, plaintextSize);

            SecBuffer buffers[4]{};
            buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
            buffers[0].pvBuffer = encrypted.data();
            buffers[0].cbBuffer = session.streamSizes.cbHeader;
            buffers[1].BufferType = SECBUFFER_DATA;
            buffers[1].pvBuffer = encrypted.data() + session.streamSizes.cbHeader;
            buffers[1].cbBuffer = static_cast<unsigned long>(plaintextSize);
            buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
            buffers[2].pvBuffer = encrypted.data() + session.streamSizes.cbHeader + plaintextSize;
            buffers[2].cbBuffer = session.streamSizes.cbTrailer;
            buffers[3].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc desc{};
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 4;
            desc.pBuffers = buffers;

            const SECURITY_STATUS status = EncryptMessage(&session.context, 0, &desc, 0);
            if (status != SEC_E_OK)
            {
                log::Print("[TLS%u] id=%llu EncryptMessage(%s) failed status=0x%08lX",
                    static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), label ? label : "application", static_cast<unsigned long>(status));
                return false;
            }

            const std::size_t encryptedSize = static_cast<std::size_t>(buffers[0].cbBuffer) +
                static_cast<std::size_t>(buffers[1].cbBuffer) + static_cast<std::size_t>(buffers[2].cbBuffer);
            if (session.localPort == 443)
            {
                // HTTP OAuth bodies can contain bearer material. Never dump web
                // plaintext; the WebAuthService emits only request metadata/keys.
                log::Print("[WEB-AUTH] id=%llu sending %s plaintextBytes=%llu tlsBytes=%llu body=REDACTED",
                    static_cast<unsigned long long>(id), label ? label : "application",
                    static_cast<unsigned long long>(plaintextSize), static_cast<unsigned long long>(encryptedSize));
            }
            else
            {
                log::Payload(id, "TLS-PLAIN-OUT", session.localPort, peer, plaintext, plaintextSize);
                log::Print("[BGS1119] id=%llu sending %s plaintextBytes=%llu tlsBytes=%llu hex=%s",
                    static_cast<unsigned long long>(id), label ? label : "application",
                    static_cast<unsigned long long>(plaintextSize), static_cast<unsigned long long>(encryptedSize),
                    HexPrefix(plaintext, plaintextSize, 256).c_str());
            }
            return SendTlsToken(session, socket, id, peer, encrypted.data(), encryptedSize);
        }

        std::vector<BYTE> BuildWebSocketServerFrame(BYTE opcode, const BYTE* payload, std::size_t payloadSize);

        bool SendBgsWebAuthChallenge(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer)
        {
            // MW2019/BGS 2.2.0 remains idle after ConnectionService.Connect until
            // the server initiates the normal external web-auth challenge. Keep
            // this entirely server-driven: it does not mark login successful.
            // The hostname deliberately matches the CA-signed leaf we already
            // present on :1119, and the DLL redirects :1119 back to localhost.
            static const std::string webAuthUrl = "https://us.actual.battle.net:1119/bnet/login/";
            if (session.webAuthChallengeSent)
                return true;

            const std::uint32_t token = session.bgs.nextServerRequestToken++;
            const std::vector<BYTE> rpcFrame = BuildBgsChallengeExternalFrame(webAuthUrl, token);
            const std::vector<BYTE> wsFrame = BuildWebSocketServerFrame(0x2u, rpcFrame.data(), rpcFrame.size());

            log::Print("[BGS-AUTH] id=%llu server -> client ChallengeListener.OnExternalChallenge token=%u payload_type=web_auth_url url=%s",
                static_cast<unsigned long long>(id), token, webAuthUrl.c_str());
            log::Print("[BGS-AUTH] id=%llu challenge framing rpcBytes=%llu websocketBytes=%llu u16beHeader=%u serviceHash=0xBBDA171F method=3; login is NOT marked successful",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(rpcFrame.size()),
                static_cast<unsigned long long>(wsFrame.size()),
                rpcFrame.size() >= 2 ? static_cast<unsigned>(ReadBe16(rpcFrame.data())) : 0u);

            if (!SendTlsApplication(session, socket, id, peer, wsFrame.data(), wsFrame.size(), "ChallengeListener.OnExternalChallenge websocket frame"))
                return false;

            session.webAuthChallengeSent = true;
            session.webAuthChallengeToken = token;
            log::Print("[BGS-AUTH] id=%llu web-auth challenge SENT; waiting for stock client web-auth/AuthenticationService traffic",
                static_cast<unsigned long long>(id));
            return true;
        }

        std::string TrimAscii(std::string value)
        {
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(value.begin());
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' || value.back() == '\n')) value.pop_back();
            return value;
        }

        bool EqualsAsciiNoCase(const std::string& a, const std::string& b)
        {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i)
            {
                unsigned char ca = static_cast<unsigned char>(a[i]);
                unsigned char cb = static_cast<unsigned char>(b[i]);
                if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                if (ca != cb) return false;
            }
            return true;
        }

        std::string HttpHeaderValue(const std::string& request, const char* wantedName)
        {
            if (!wantedName || !*wantedName) return {};
            std::size_t cursor = 0;
            while (cursor < request.size())
            {
                const std::size_t end = request.find("\r\n", cursor);
                const std::size_t lineEnd = end == std::string::npos ? request.size() : end;
                const std::string line = request.substr(cursor, lineEnd - cursor);
                const std::size_t colon = line.find(':');
                if (colon != std::string::npos)
                {
                    const std::string name = TrimAscii(line.substr(0, colon));
                    if (EqualsAsciiNoCase(name, wantedName))
                        return TrimAscii(line.substr(colon + 1));
                }
                if (end == std::string::npos) break;
                cursor = end + 2;
            }
            return {};
        }

        std::string Base64NoCrLf(const BYTE* data, DWORD size)
        {
            if (!data || !size) return {};
            DWORD chars = 0;
            if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &chars) || !chars)
                return {};
            std::string output(chars, '\0');
            if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &output[0], &chars))
                return {};
            while (!output.empty() && output.back() == '\0') output.pop_back();
            return output;
        }

        std::string BuildWebSocketAccept(const std::string& clientKey)
        {
            static const char kGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            const std::string source = clientKey + kGuid;

            HCRYPTPROV provider = 0;
            HCRYPTHASH hash = 0;
            BYTE digest[20]{};
            DWORD digestSize = sizeof(digest);
            std::string result;

            if (CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT) &&
                CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash) &&
                CryptHashData(hash, reinterpret_cast<const BYTE*>(source.data()), static_cast<DWORD>(source.size()), 0) &&
                CryptGetHashParam(hash, HP_HASHVAL, digest, &digestSize, 0) && digestSize == sizeof(digest))
            {
                result = Base64NoCrLf(digest, digestSize);
            }

            if (hash) CryptDestroyHash(hash);
            if (provider) CryptReleaseContext(provider, 0);
            return result;
        }

        std::vector<BYTE> BuildWebSocketServerFrame(BYTE opcode, const BYTE* payload, std::size_t payloadSize)
        {
            std::vector<BYTE> frame;
            frame.push_back(static_cast<BYTE>(0x80u | (opcode & 0x0Fu))); // FIN + opcode
            if (payloadSize <= 125)
            {
                frame.push_back(static_cast<BYTE>(payloadSize));
            }
            else if (payloadSize <= 0xFFFFu)
            {
                frame.push_back(126);
                frame.push_back(static_cast<BYTE>((payloadSize >> 8) & 0xFFu));
                frame.push_back(static_cast<BYTE>(payloadSize & 0xFFu));
            }
            else
            {
                frame.push_back(127);
                const std::uint64_t length = static_cast<std::uint64_t>(payloadSize);
                for (int shift = 56; shift >= 0; shift -= 8)
                    frame.push_back(static_cast<BYTE>((length >> shift) & 0xFFu));
            }
            if (payload && payloadSize)
                frame.insert(frame.end(), payload, payload + payloadSize);
            return frame;
        }

        void LogBgsRpcWebSocketPayload(std::uint64_t id, std::uint64_t frameNumber, const std::vector<BYTE>& payload)
        {
            if (payload.empty())
            {
                log::Print("[BGS-RPC] id=%llu wsFrame#%llu empty binary payload",
                    static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber));
                return;
            }

            if (payload.size() >= 2)
            {
                const std::uint16_t headerSize = ReadBe16(payload.data());
                if (headerSize <= payload.size() - 2)
                {
                    const std::size_t bodySize = payload.size() - 2 - headerSize;
                    log::Print("[BGS-RPC] id=%llu wsFrame#%llu frameBytes=%llu headerBytes=%u bodyBytes=%llu headerProto=%s",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber),
                        static_cast<unsigned long long>(payload.size()), static_cast<unsigned>(headerSize),
                        static_cast<unsigned long long>(bodySize),
                        DescribeBestProtoCandidate(payload.data() + 2, headerSize).c_str());
                    if (bodySize)
                    {
                        log::Print("[BGS-RPC] id=%llu wsFrame#%llu bodyHex=%s bodyProto=%s",
                            static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber),
                            HexPrefix(payload.data() + 2 + headerSize, bodySize, 256).c_str(),
                            DescribeBestProtoCandidate(payload.data() + 2 + headerSize, bodySize).c_str());
                    }
                    return;
                }
            }

            log::Print("[BGS-RPC] id=%llu wsFrame#%llu unrecognized framing hex=%s",
                static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber),
                HexPrefix(payload.data(), payload.size(), 256).c_str());
        }

        bool HandleBgsRpcWebSocketPayload(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            std::uint64_t frameNumber, const std::vector<BYTE>& payload)
        {
            bgs::RpcEnvelope rpc{};
            if (!bgs::ParseRpcPayload(payload, rpc))
            {
                log::Print("[BGS-RPC] id=%llu wsFrame#%llu header parse failed; server cannot route this frame",
                    static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber));
                return true;
            }

            const auto& header = rpc.header;
            log::Print("[BGS-RPC] id=%llu wsFrame#%llu decoded serviceId=%u method=%u token=%u serviceHash=%s0x%08X service=%s declaredBody=%s%u actualBody=%llu status=%s%u%s%s%s",
                static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber),
                header.serviceId, header.hasMethodId ? header.methodId : 0u, header.token,
                header.hasServiceHash ? "" : "<missing>/", header.serviceHash,
                header.hasServiceHash ? bgs::ServiceName(header.serviceHash) : "<none>",
                header.hasSize ? "" : "<missing>/", header.size,
                static_cast<unsigned long long>(rpc.body.size()),
                header.hasStatus ? "" : "<missing>/", header.status,
                header.hasStatus ? "(" : "", header.hasStatus ? bgs::StatusName(header.status) : "",
                header.hasStatus ? ")" : "");

            if (header.serviceId == 0xFEu)
            {
                // The old generic web-auth challenge is still owned by the TLS
                // bootstrap layer, not the normal BGS service dispatcher.
                if (session.webAuthChallengeSent && header.token == session.webAuthChallengeToken)
                {
                    if (header.hasStatus && header.status == 0x00000BC2u)
                    {
                        session.webAuthChallengeUnsupported = true;
                        log::Print("[BGS-AUTH] id=%llu ChallengeListener response token=%u status=3010 (0x00000BC2 ERROR_RPC_INVALID_SERVICE); challenge retries disabled",
                            static_cast<unsigned long long>(id), header.token);
                    }
                    else
                    {
                        log::Print("[BGS-AUTH] id=%llu ChallengeListener response token=%u status=%s%u (%s)",
                            static_cast<unsigned long long>(id), header.token,
                            header.hasStatus ? "" : "<missing>/", header.status,
                            header.hasStatus ? bgs::StatusName(header.status) : "unknown");
                    }
                    return true;
                }

                return bgs::HandleClientResponse(id, rpc, session.bgs);
            }

            std::vector<bgs::OutgoingRpc> outgoing;
            bgs::RequestContext context{id, rpc, session.bgs, outgoing};
            if (!bgs::DispatchRequest(context))
                return false;

            for (const auto& message : outgoing)
            {
                const std::vector<BYTE> wsResponse = BuildWebSocketServerFrame(
                    0x2u, message.payload.data(), message.payload.size());
                log::Print("[BGS-SEND] id=%llu serviceHash=0x%08X service=%s method=%u token=%u direction=%s rpcBytes=%llu websocketBytes=%llu label=%s",
                    static_cast<unsigned long long>(id), message.serviceHash,
                    bgs::ServiceName(message.serviceHash), message.methodId, message.token,
                    message.serverRequest ? "server->client request" : "server->client response",
                    static_cast<unsigned long long>(message.payload.size()),
                    static_cast<unsigned long long>(wsResponse.size()), message.label.c_str());

                if (!SendTlsApplication(session, socket, id, peer, wsResponse.data(), wsResponse.size(), message.label.c_str()))
                {
                    log::Print("[BGS-SEND] id=%llu SEND FAILED service=%s method=%u token=%u label=%s",
                        static_cast<unsigned long long>(id), bgs::ServiceName(message.serviceHash),
                        message.methodId, message.token, message.label.c_str());
                    return false;
                }
            }

            return true;
        }

        bool PumpWebSocketFrames(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            const BYTE* data, std::size_t size)
        {
            if (data && size)
                session.websocketInput.insert(session.websocketInput.end(), data, data + size);

            while (session.websocketInput.size() >= 2)
            {
                const BYTE b0 = session.websocketInput[0];
                const BYTE b1 = session.websocketInput[1];
                const bool fin = (b0 & 0x80u) != 0;
                const BYTE opcode = static_cast<BYTE>(b0 & 0x0Fu);
                const bool masked = (b1 & 0x80u) != 0;
                std::uint64_t payloadLength = b1 & 0x7Fu;
                std::size_t cursor = 2;

                if (payloadLength == 126)
                {
                    if (session.websocketInput.size() < cursor + 2) return true;
                    payloadLength = ReadBe16(session.websocketInput.data() + cursor);
                    cursor += 2;
                }
                else if (payloadLength == 127)
                {
                    if (session.websocketInput.size() < cursor + 8) return true;
                    payloadLength = 0;
                    for (int i = 0; i < 8; ++i)
                        payloadLength = (payloadLength << 8) | session.websocketInput[cursor + i];
                    cursor += 8;
                }

                BYTE mask[4]{};
                if (masked)
                {
                    if (session.websocketInput.size() < cursor + 4) return true;
                    std::memcpy(mask, session.websocketInput.data() + cursor, 4);
                    cursor += 4;
                }

                if (payloadLength > 16ull * 1024ull * 1024ull)
                {
                    log::Print("[WS1119] id=%llu rejecting absurd websocket payload length=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(payloadLength));
                    return false;
                }
                if (payloadLength > static_cast<std::uint64_t>(session.websocketInput.size() - cursor))
                    return true;

                std::vector<BYTE> payload(static_cast<std::size_t>(payloadLength));
                if (payloadLength)
                    std::memcpy(payload.data(), session.websocketInput.data() + cursor, static_cast<std::size_t>(payloadLength));
                if (masked)
                {
                    for (std::size_t i = 0; i < payload.size(); ++i)
                        payload[i] ^= mask[i & 3u];
                }

                const std::size_t consumed = cursor + static_cast<std::size_t>(payloadLength);
                session.websocketInput.erase(session.websocketInput.begin(), session.websocketInput.begin() + static_cast<std::ptrdiff_t>(consumed));
                ++session.websocketFrameCount;

                log::Print("[WS1119] id=%llu frame#%llu fin=%s opcode=0x%02X masked=%s payloadBytes=%llu",
                    static_cast<unsigned long long>(id), static_cast<unsigned long long>(session.websocketFrameCount),
                    fin ? "yes" : "no", static_cast<unsigned>(opcode), masked ? "yes" : "no",
                    static_cast<unsigned long long>(payload.size()));

                if (opcode == 0x8)
                {
                    log::Print("[WS1119] id=%llu client sent websocket CLOSE codeBytes=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(payload.size()));
                    return false;
                }
                if (opcode == 0x9)
                {
                    const auto pong = BuildWebSocketServerFrame(0xAu, payload.data(), payload.size());
                    if (!SendTlsApplication(session, socket, id, peer, pong.data(), pong.size(), "WebSocket Pong"))
                        return false;
                    log::Print("[WS1119] id=%llu replied to websocket PING with PONG bytes=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(payload.size()));
                    continue;
                }
                if (opcode == 0x2 || opcode == 0x0)
                {
                    LogBgsRpcWebSocketPayload(id, session.websocketFrameCount, payload);
                    if (!HandleBgsRpcWebSocketPayload(session, socket, id, peer, session.websocketFrameCount, payload))
                        return false;
                }
                else if (opcode == 0x1)
                {
                    log::Print("[WS1119] id=%llu text frame ascii=%s",
                        static_cast<unsigned long long>(id), protocol::AsciiPrefix(payload.data(), payload.size(), 512).c_str());
                }
            }
            return true;
        }

        bool HandleBgsPlaintext(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            const void* payload, std::size_t size)
        {
            if (!payload || !size) return true;
            const BYTE* bytes = static_cast<const BYTE*>(payload);

            if (!session.websocketUpgraded)
            {
                if (session.webAuthHttpServed)
                    return true;
                session.websocketInput.insert(session.websocketInput.end(), bytes, bytes + size);
                if (session.websocketInput.size() > 64u * 1024u)
                {
                    log::Print("[WS1119] id=%llu websocket HTTP upgrade header exceeded 64 KiB",
                        static_cast<unsigned long long>(id));
                    return false;
                }

                const std::string bufferedRequest(reinterpret_cast<const char*>(session.websocketInput.data()), session.websocketInput.size());
                const std::size_t headerTerminator = bufferedRequest.find("\r\n\r\n");
                if (headerTerminator == std::string::npos)
                {
                    log::Print("[WS1119] id=%llu websocket HTTP upgrade request is fragmented; bufferedBytes=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(session.websocketInput.size()));
                    return true;
                }
                const std::size_t headerBytes = headerTerminator + 4;
                const std::string request = bufferedRequest.substr(0, headerBytes);
                std::vector<BYTE> trailing;
                if (session.websocketInput.size() > headerBytes)
                    trailing.assign(session.websocketInput.begin() + static_cast<std::ptrdiff_t>(headerBytes), session.websocketInput.end());

                // A second HTTPS connection to this same :1119 listener is used
                // as the local web-auth endpoint advertised by the BGS challenge.
                // Serve a deliberately local/test-only page so we can prove the
                // stock web-auth UI has reached Revamped before implementing ticket
                // issuance. No credentials are accepted or stored in this step.
                if (request.rfind("GET /bnet/login/", 0) == 0 || request.rfind("GET /bnet/login?", 0) == 0)
                {
                    static const char html[] =
                        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                        "<title>Revamped Local Sign In</title><style>body{margin:0;background:#11151b;color:#f4f7fb;font-family:Segoe UI,Arial,sans-serif;display:grid;place-items:center;min-height:100vh}"
                        ".card{width:min(560px,calc(100% - 48px));background:#1a2029;border:1px solid #303a48;border-radius:12px;padding:32px;box-shadow:0 20px 60px #0008}"
                        "h1{font-size:28px;margin:0 0 10px}p{line-height:1.5;color:#b9c4d2}.ok{margin-top:22px;padding:14px 16px;background:#152d22;border:1px solid #2d7652;border-radius:8px;color:#bff3d5}"
                        "code{color:#d7e7ff}</style></head><body><main class=\"card\"><h1>Revamped Local Sign In</h1>"
                        "<p>MW2019 reached the local Battle.net web-auth endpoint successfully.</p>"
                        "<div class=\"ok\">Local web authentication is connected. Account login/create-account ticket exchange is the next emulation step.</div>"
                        "<p>This page does not accept or store Blizzard credentials.</p></main></body></html>";
                    char responseHeader[512]{};
                    const int responseHeaderLength = _snprintf_s(responseHeader, sizeof(responseHeader), _TRUNCATE,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: %llu\r\nConnection: close\r\n\r\n",
                        static_cast<unsigned long long>(sizeof(html) - 1));
                    if (responseHeaderLength <= 0 ||
                        !SendTlsApplication(session, socket, id, peer, responseHeader, static_cast<std::size_t>(responseHeaderLength), "local web-auth HTTP headers") ||
                        !SendTlsApplication(session, socket, id, peer, html, sizeof(html) - 1, "local web-auth HTML"))
                        return false;

                    session.webAuthHttpServed = true;
                    session.websocketInput.clear();
                    log::Print("[WEB-AUTH] id=%llu LOCAL LOGIN PAGE SERVED path=/bnet/login/; no credentials accepted yet; waiting for the next stock auth action",
                        static_cast<unsigned long long>(id));
                    shutdown(socket, SD_SEND);
                    return true;
                }

                if (request.rfind("GET / HTTP/1.1", 0) != 0 || request.find("Upgrade: websocket") == std::string::npos)
                {
                    log::Print("[WS1119] id=%llu plaintext before websocket upgrade is not the expected HTTP websocket request ascii=%s",
                        static_cast<unsigned long long>(id), protocol::AsciiPrefix(request.data(), request.size(), 512).c_str());
                    return false;
                }

                session.websocketUpgradeSeen = true;
                const std::string clientKey = HttpHeaderValue(request, "Sec-WebSocket-Key");
                const std::string requestedProtocol = HttpHeaderValue(request, "Sec-WebSocket-Protocol");
                const std::string accept = BuildWebSocketAccept(clientKey);
                if (clientKey.empty() || accept.empty())
                {
                    log::Print("[WS1119] id=%llu websocket upgrade parse failed key=%s accept=%s",
                        static_cast<unsigned long long>(id), clientKey.empty() ? "missing" : "present", accept.empty() ? "missing" : "present");
                    return false;
                }

                std::ostringstream response;
                response << "HTTP/1.1 101 Switching Protocols\r\n"
                         << "Upgrade: websocket\r\n"
                         << "Connection: Upgrade\r\n"
                         << "Sec-WebSocket-Accept: " << accept << "\r\n";
                if (!requestedProtocol.empty())
                    response << "Sec-WebSocket-Protocol: " << requestedProtocol << "\r\n";
                response << "\r\n";
                const std::string responseText = response.str();

                log::Print("[WS1119] id=%llu websocket upgrade request key=%s protocol=%s",
                    static_cast<unsigned long long>(id), clientKey.c_str(), requestedProtocol.empty() ? "<none>" : requestedProtocol.c_str());
                if (!SendTlsApplication(session, socket, id, peer, responseText.data(), responseText.size(), "WebSocket HTTP 101"))
                    return false;

                session.websocketUpgraded = true;
                session.websocketInput.clear();
                log::Print("[WS1119] id=%llu WEBSOCKET UPGRADE ACCEPTED status=101 protocol=%s accept=%s; waiting for first v1.rpc.battle.net binary frame",
                    static_cast<unsigned long long>(id), requestedProtocol.empty() ? "<none>" : requestedProtocol.c_str(), accept.c_str());
                if (!trailing.empty())
                {
                    log::Print("[WS1119] id=%llu websocket upgrade carried trailing encrypted-application plaintext bytes=%llu; decoding as websocket frames",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(trailing.size()));
                    return PumpWebSocketFrames(session, socket, id, peer, trailing.data(), trailing.size());
                }
                return true;
            }

            return PumpWebSocketFrames(session, socket, id, peer, bytes, size);
        }

        bool HandleWebAuthPlaintext(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            const void* payload, std::size_t size)
        {
            if (!payload || !size) return true;
            const auto* bytes = static_cast<const unsigned char*>(payload);
            session.httpInput.insert(session.httpInput.end(), bytes, bytes + size);
            if (session.httpInput.size() > 1024u * 1024u)
            {
                log::Print("[WEB-AUTH] id=%llu request buffer exceeded 1 MiB; closing", static_cast<unsigned long long>(id));
                return false;
            }

            for (;;)
            {
                web::HttpResult result = web::TryHandleLocalWebRequest(session.httpInput);
                if (!result.complete)
                {
                    log::Print("[WEB-AUTH] id=%llu HTTPS request fragmented; bufferedPlaintextBytes=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(session.httpInput.size()));
                    return true;
                }

                log::Print("[WEB-AUTH] id=%llu request method=%s host=%s path=%s requestBytes=%llu formKeys=%s values=REDACTED",
                    static_cast<unsigned long long>(id),
                    result.method.empty() ? "<unknown>" : result.method.c_str(),
                    result.host.empty() ? "<missing>" : result.host.c_str(),
                    result.path.empty() ? "<missing>" : result.path.c_str(),
                    static_cast<unsigned long long>(result.requestBytes),
                    result.formKeys.empty() ? "<none>" : result.formKeys.c_str());

                if (result.handled)
                    log::Print("[WEB-HANDLED] id=%llu status=%d detail=%s",
                        static_cast<unsigned long long>(id), result.statusCode, result.label.c_str());
                else
                    log::Print("[WEB-MISSING] id=%llu status=%d host=%s path=%s detail=%s",
                        static_cast<unsigned long long>(id), result.statusCode,
                        result.host.empty() ? "<missing>" : result.host.c_str(),
                        result.path.empty() ? "<missing>" : result.path.c_str(), result.label.c_str());

                if (result.response.empty() ||
                    !SendTlsApplication(session, socket, id, peer, result.response.data(), result.response.size(),
                        result.handled ? "local online-services HTTP response" : "local unimplemented HTTP response"))
                    return false;

                // The stock client opens these as short-lived HTTPS requests. Close
                // the send side after one response so retry/next-stage behavior is
                // deterministic and each new dependency gets its own log entry.
                shutdown(socket, SD_SEND);
                session.webAuthHttpServed = true;
                return true;
            }
        }

        void LogTlsAlertIfVisible(std::uint64_t id, std::uint16_t localPort, const std::vector<unsigned char>& input)
        {
            if (input.size() < 7 || input[0] != 0x15) return;
            const std::size_t recordLength = ReadBe16(input.data() + 3);
            if (recordLength < 2 || input.size() < recordLength + 5) return;
            log::Print("[TLS%u] id=%llu TLS alert record level=%u description=%u (plaintext view; encrypted alerts may not decode here)",
                static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), static_cast<unsigned>(input[5]), static_cast<unsigned>(input[6]));
        }

        bool DecryptTlsInput(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer)
        {
            while (!session.input.empty())
            {
                SecBuffer buffers[4]{};
                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = session.input.data();
                buffers[0].cbBuffer = static_cast<unsigned long>(session.input.size());
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;
                SecBufferDesc descriptor{};
                descriptor.ulVersion = SECBUFFER_VERSION;
                descriptor.cBuffers = 4;
                descriptor.pBuffers = buffers;

                const SECURITY_STATUS status = DecryptMessage(&session.context, &descriptor, 0, nullptr);
                if (status == SEC_E_INCOMPLETE_MESSAGE) return true;
                if (status == SEC_I_CONTEXT_EXPIRED)
                {
                    log::Print("[TLS%u] id=%llu peer sent TLS close_notify", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id));
                    if (session.localPort == 1119 && !session.bgsApplicationSeen)
                        log::Print("[BGS1119] id=%llu TLS closed before any decrypted BGS application message was received", static_cast<unsigned long long>(id));
                    return false;
                }
                if (status == SEC_I_RENEGOTIATE)
                {
                    log::Print("[TLS%u] id=%llu TLS renegotiation requested; leaving connection open", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id));
                    return true;
                }
                if (status != SEC_E_OK)
                {
                    log::Print("[TLS%u] id=%llu DecryptMessage failed status=0x%08lX", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(status));
                    LogTlsAlertIfVisible(id, session.localPort, session.input);
                    return false;
                }

                std::size_t extra = 0;
                for (const auto& buffer : buffers)
                {
                    if (buffer.BufferType == SECBUFFER_DATA && buffer.cbBuffer && buffer.pvBuffer)
                    {
                        if (session.localPort == 1119)
                        {
                            LogBgsApplicationPlaintext(session, id, peer, buffer.pvBuffer, buffer.cbBuffer);
                            if (!HandleBgsPlaintext(session, socket, id, peer, buffer.pvBuffer, buffer.cbBuffer))
                                return false;
                        }
                        else if (session.localPort == 443)
                        {
                            if (!HandleWebAuthPlaintext(session, socket, id, peer, buffer.pvBuffer, buffer.cbBuffer))
                                return false;
                        }
                    }
                    else if (buffer.BufferType == SECBUFFER_EXTRA)
                    {
                        extra = buffer.cbBuffer;
                    }
                }

                if (extra && extra <= session.input.size())
                    session.input = std::vector<unsigned char>(session.input.end() - static_cast<std::ptrdiff_t>(extra), session.input.end());
                else
                    session.input.clear();
            }
            return true;
        }

        CredHandle* SelectTlsCredential(TlsSession& session, const char*& identity)
        {
            identity = "us.actual.battle.net";
            if (session.localPort != 443)
                return &g_tlsCredential;

            if (_stricmp(session.sni.c_str(), "us.battle.net") == 0 && g_tls443BattleNetCredentialValid)
            {
                identity = "us.battle.net";
                return &g_tls443BattleNetCredential;
            }
            if (!session.sni.empty() &&
                (_stricmp(session.sni.c_str(), "iw8-bnet-auth3.prod.demonware.net") == 0 ||
                 _stricmp(session.sni.c_str(), "auth3.prod.demonware.net") == 0 ||
                 _stricmp(session.sni.c_str(), "auth3-login.prod.demonware.net") == 0 ||
                 _stricmp(session.sni.c_str(), "loginqueue.prod.demonware.net") == 0 ||
                 _stricmp(session.sni.c_str(), "prod.umbrella.demonware.net") == 0 ||
                 (session.sni.size() > 23 &&
                    _stricmp(session.sni.c_str() + session.sni.size() - 23, ".umbrella.demonware.net") == 0)) &&
                g_tls443DemonwareCredentialValid)
            {
                identity = "iw8-bnet-auth3.prod.demonware.net";
                return &g_tls443DemonwareCredential;
            }
            return &g_tlsCredential;
        }

        bool PumpTls(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer)
        {
            if (!InitializeTlsCredential())
            {
                log::Print("[TLS%u] id=%llu cannot start SChannel because server credential initialization failed", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id));
                return false;
            }

            const char* selectedIdentity = nullptr;
            CredHandle* selectedCredential = SelectTlsCredential(session, selectedIdentity);
            if (!session.credentialLogged)
            {
                session.credentialLogged = true;
                log::Print("[TLS%u] id=%llu selected server identity=%s sni=%s exactSniIdentity=%s",
                    static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id),
                    selectedIdentity ? selectedIdentity : "<none>",
                    session.sni.empty() ? "<none>" : session.sni.c_str(),
                    session.localPort == 443 && selectedIdentity && !session.sni.empty() &&
                        _stricmp(selectedIdentity, session.sni.c_str()) == 0 ? "YES" : "no");
            }

            while (!session.established)
            {
                if (session.input.empty()) return true;
                LogTlsAlertIfVisible(id, session.localPort, session.input);

                SecBuffer inBuffers[2]{};
                inBuffers[0].BufferType = SECBUFFER_TOKEN;
                inBuffers[0].pvBuffer = session.input.data();
                inBuffers[0].cbBuffer = static_cast<unsigned long>(session.input.size());
                inBuffers[1].BufferType = SECBUFFER_EMPTY;
                SecBufferDesc inDescriptor{};
                inDescriptor.ulVersion = SECBUFFER_VERSION;
                inDescriptor.cBuffers = 2;
                inDescriptor.pBuffers = inBuffers;

                SecBuffer outBuffer{};
                outBuffer.BufferType = SECBUFFER_TOKEN;
                SecBufferDesc outDescriptor{};
                outDescriptor.ulVersion = SECBUFFER_VERSION;
                outDescriptor.cBuffers = 1;
                outDescriptor.pBuffers = &outBuffer;

                DWORD attributes = 0;
                TimeStamp expiry{};
                const DWORD requestFlags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                    ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
                const SECURITY_STATUS status = AcceptSecurityContext(selectedCredential,
                    session.contextValid ? &session.context : nullptr, &inDescriptor, requestFlags,
                    SECURITY_NATIVE_DREP, &session.context, &outDescriptor, &attributes, &expiry);

                if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK ||
                    status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE)
                    session.contextValid = true;

                if ((status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) && session.contextValid)
                    CompleteAuthToken(&session.context, &outDescriptor);

                if (outBuffer.pvBuffer && outBuffer.cbBuffer)
                {
                    const bool sent = SendTlsToken(session, socket, id, peer, outBuffer.pvBuffer, outBuffer.cbBuffer);
                    FreeContextBuffer(outBuffer.pvBuffer);
                    outBuffer.pvBuffer = nullptr;
                    if (!sent) return false;
                }

                if (status == SEC_E_INCOMPLETE_MESSAGE)
                    return true;

                std::size_t extra = 0;
                if (inBuffers[1].BufferType == SECBUFFER_EXTRA)
                    extra = inBuffers[1].cbBuffer;
                if (extra && extra <= session.input.size())
                    session.input = std::vector<unsigned char>(session.input.end() - static_cast<std::ptrdiff_t>(extra), session.input.end());
                else
                    session.input.clear();

                log::Print("[TLS%u] id=%llu AcceptSecurityContext status=0x%08lX attrs=0x%08lX extra=%llu",
                    static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(status),
                    static_cast<unsigned long>(attributes), static_cast<unsigned long long>(extra));

                if (status == SEC_E_OK || status == SEC_I_COMPLETE_NEEDED)
                {
                    session.established = true;
                    session.establishedAtMs = GetTickCount64();
                    const SECURITY_STATUS query = QueryContextAttributes(&session.context, SECPKG_ATTR_STREAM_SIZES, &session.streamSizes);
                    log::Print("[TLS%u] id=%llu TLS HANDSHAKE ESTABLISHED queryStreamSizes=0x%08lX header=%lu trailer=%lu maxMessage=%lu",
                        static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(query),
                        session.streamSizes.cbHeader, session.streamSizes.cbTrailer, session.streamSizes.cbMaximumMessage);
                    if (session.localPort == 1119)
                        log::Print("[BGS1119] id=%llu transport is now encrypted/decrypted by SChannel; waiting for the stock client's first BGS application message.",
                            static_cast<unsigned long long>(id));
                    else
                        log::Print("[WEB-AUTH] id=%llu TLS established on :443; waiting for the stock OAuth/online-services HTTP request.",
                            static_cast<unsigned long long>(id));
                    break;
                }

                if (status == SEC_I_CONTINUE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE)
                {
                    if (session.input.empty()) return true;
                    continue;
                }

                if (status == SEC_I_CONTEXT_EXPIRED)
                {
                    log::Print("[TLS%u] id=%llu peer closed TLS before handshake completion status=SEC_I_CONTEXT_EXPIRED(0x%08lX); on :443 this normally means certificate/trust/hostname validation ended the attempt before HTTP",
                        static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(status));
                }
                else
                {
                    log::Print("[TLS%u] id=%llu handshake failed status=0x%08lX. Inspect the preceding SNI/alert before changing application protocol behavior.",
                        static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(status));
                }
                LogTlsAlertIfVisible(id, session.localPort, session.input);
                return false;
            }

            return DecryptTlsInput(session, socket, id, peer);
        }

    }

    bool Server::Start()
    {
        if (running_.exchange(true)) return true;
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        {
            running_ = false;
            return false;
        }
        log::Initialize();
        if (!InitializeBundleSigner())
            log::Print("[TRUST-BOOT] WARNING: local BGS bundle signer setup failed. Start the server beside ModernWarfare.exe and inspect the error before launching the game.");
        if (!web::InitializeLocalAuthSigner())
            log::Print("[AUTH3-TRUST] WARNING: local Auth3 response signer setup failed. Stock Auth3 signature validation cannot complete until this is fixed.");
        if (!InitializeTlsCredential())
            log::Print("[TLS1119] WARNING: TLS credential setup failed. The server will still run, but :1119 cannot complete a TLS handshake until this is fixed.");
        unsigned opened = 0;
        for (const auto port : config_.tcpPorts) opened += CreateTcpListener(port) ? 1u : 0u;
        for (const auto port : config_.udpPorts) opened += CreateUdpListener(port) ? 1u : 0u;
        if (!opened)
        {
            log::Print("No listeners opened; stopping");
            Stop();
            return false;
        }
        log::Print("Revamped IW8 server phase 1 ready; listeners=%u", opened);
        return true;
    }


    void Server::ReadTcp(std::size_t index)
    {
        if (index >= clients_.size()) return;
        Client& client = clients_[index];
        unsigned char buffer[64 * 1024]{};
        const int result = recv(client.socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
        if (result == 0)
        {
            CloseClient(index, "peer-closed");
            return;
        }
        if (result == SOCKET_ERROR)
        {
            const int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK)
            {
                char detail[64]{};
                _snprintf_s(detail, sizeof(detail), _TRUNCATE, "recv-error-wsa=%d", error);
                CloseClient(index, detail);
            }
            return;
        }
        if (config_.dumpPayloads)
            log::Payload(client.id, "IN", client.localPort, client.peer, buffer, static_cast<std::size_t>(result));

        if (client.localPort == 3074u || client.localPort == 3075u)
        {
            if (!HandleLsgTcp(client, buffer, static_cast<std::size_t>(result)))
                CloseClient(index, "lsg-send-failed");
            return;
        }

        if (client.firstPacket)
        {
            client.firstPacket = false;
            if (client.localPort == 1119)
                log::Print("[AUTH] id=%llu first Battle.net client payload captured bytes=%d; attempting real TLS transport only",
                    static_cast<unsigned long long>(client.id), result);
            else if (client.localPort == 443 && result >= 5 && buffer[0] == 0x16 && buffer[1] == 0x03)
                log::Print("[WEB-AUTH] id=%llu HTTPS/TLS ClientHello reached local :443 bytes=%d after BGS challenge; web-login TLS/HTTP emulation is the next layer",
                    static_cast<unsigned long long>(client.id), result);
        }

        if (client.localPort == 1119 || client.localPort == 443)
        {
            auto* session = static_cast<TlsSession*>(client.tlsState);
            if (!session)
            {
                session = new TlsSession();
                session->localPort = client.localPort;
                client.tlsState = session;
            }
            session->input.insert(session->input.end(), buffer, buffer + static_cast<std::size_t>(result));
            if (!session->helloLogged)
            {
                session->helloLogged = LogTlsClientHello(client.id, client.localPort, session->input.data(), session->input.size(), &session->sni);
                if (session->helloLogged)
                    log::Print("[TLS%u] id=%llu ClientHello decoded; replying through SChannel with the local diagnostic certificate",
                        static_cast<unsigned>(client.localPort), static_cast<unsigned long long>(client.id));
            }
            if (!PumpTls(*session, client.socket, client.id, client.peer))
            {
                CloseClient(index, client.localPort == 443 ? "tls443-handshake-or-http-failed" : "tls1119-handshake-or-decrypt-failed");
            }
            return;
        }

        // We now have one decoded, non-auth bootstrap request from the 1.44 client:
        //   GET /pc/0/xpak_ignore.keylist
        // An empty ignore list is a valid local preservation fallback and lets the
        // client continue without inventing any Battle.net/Demonware auth payload.
        if (client.localPort == 80)
        {
            const std::string request(reinterpret_cast<const char*>(buffer), static_cast<std::size_t>(result));

            if (request.rfind("GET /__revamped/iw8.crl ", 0) == 0)
            {
                if (g_tlsCrlDer.empty())
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Length: 0\r\n"
                        "Cache-Control: no-store\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    log::Print("[TRUST-CRL] id=%llu CRL fetch arrived before CRL was ready",
                        static_cast<unsigned long long>(client.id));
                    CloseClient(index, "crl-not-ready-503");
                    return;
                }

                char header[384]{};
                const int headerLength = _snprintf_s(header, sizeof(header), _TRUNCATE,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/pkix-crl\r\n"
                    "Content-Length: %llu\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    static_cast<unsigned long long>(g_tlsCrlDer.size()));
                const bool headerOk = headerLength > 0 &&
                    SendAllNonBlocking(client.socket, header, static_cast<std::size_t>(headerLength));
                const bool bodyOk = headerOk &&
                    SendAllNonBlocking(client.socket, g_tlsCrlDer.data(), g_tlsCrlDer.size());

                if (config_.dumpPayloads && headerOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer,
                        header, static_cast<std::size_t>(headerLength));
                if (config_.dumpPayloads && bodyOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer,
                        g_tlsCrlDer.data(), g_tlsCrlDer.size());

                log::Print("[TRUST-CRL] id=%llu served local empty CRL bytes=%llu result=%s",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(g_tlsCrlDer.size()),
                    bodyOk ? "ok" : "send-failed");
                CloseClient(index, bodyOk ? "crl-200" : "crl-send-failed");
                return;
            }

            // Tiny startup health/prewarm route used by the redirect DLL.  It
            // intentionally carries no auth state; its only purpose is to make
            // the local accept path, trust bootstrap and first socket work happen
            // before the intro starts doing time-sensitive online work.
            if (request.rfind("GET /__revamped/prewarm ", 0) == 0)
            {
                static const char response[] =
                    "HTTP/1.1 204 No Content\r\n"
                    "Content-Length: 0\r\n"
                    "Cache-Control: no-store\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                const bool sent = SendAllNonBlocking(client.socket, response, sizeof(response) - 1);
                log::Print("[PREWARM] id=%llu local backend prewarm request served status=204",
                    static_cast<unsigned long long>(client.id));
                CloseClient(index, sent ? "prewarm-204" : "prewarm-send-failed");
                return;
            }

            if (request.rfind("GET /pc/0/xpak_ignore.keylist ", 0) == 0)
            {
                static const char response[] =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                const int sent = send(client.socket, response, static_cast<int>(sizeof(response) - 1), 0);
                if (sent > 0 && config_.dumpPayloads)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, response, static_cast<std::size_t>(sent));
                if (sent == SOCKET_ERROR)
                {
                    char detail[64]{};
                    _snprintf_s(detail, sizeof(detail), _TRUNCATE, "http-keylist-send-wsa=%d", WSAGetLastError());
                    CloseClient(index, detail);
                }
                else
                {
                    CloseClient(index, "http-keylist-empty-200");
                }
                return;
            }

            if (request.rfind("GET /Bnet/zxx/client/bgs-key-fingerprint ", 0) == 0)
            {
                log::Print("[BGS-BUNDLE] id=%llu stock client requested /Bnet/zxx/client/bgs-key-fingerprint",
                    static_cast<unsigned long long>(client.id));

                const auto stockBundle = LoadStockBgsCertificateBundle();
                if (stockBundle.empty())
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    log::Print("[BGS-BUNDLE] id=%llu stock signed bundle file is not available yet; expected CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock",
                        static_cast<unsigned long long>(client.id));
                    CloseClient(index, "bgs-key-fingerprint-stock-bundle-missing");
                    return;
                }

                std::size_t pinReplacements = 0;
                bool signatureVerified = false;
                const auto bundle = BuildLocalBgsTrustBundle(stockBundle, pinReplacements, signatureVerified);
                log::Print("[BGS-BUNDLE] id=%llu OPTION2 signed local trust bundle trustCert=local-root-ca+ca-signed-leaf caSpki=%s pinReplacements=%llu signatureVerified=%s stockJsonBytes=%llu wireBytes=%llu",
                    static_cast<unsigned long long>(client.id),
                    g_tlsSpkiSha256.empty() ? "<unavailable>" : g_tlsSpkiSha256.c_str(),
                    static_cast<unsigned long long>(pinReplacements),
                    signatureVerified ? "yes" : "no",
                    static_cast<unsigned long long>(stockBundle.size()),
                    static_cast<unsigned long long>(bundle.size()));

                if (bundle.empty() || !signatureVerified)
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    CloseClient(index, "bgs-key-fingerprint-local-signing-failed");
                    return;
                }

                char header[512]{};
                const int headerLength = _snprintf_s(header, sizeof(header), _TRUNCATE,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Content-Length: %llu\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    static_cast<unsigned long long>(bundle.size()));

                const bool headerOk = headerLength > 0 &&
                    SendAllNonBlocking(client.socket, header, static_cast<std::size_t>(headerLength));
                const bool bodyOk = headerOk &&
                    SendAllNonBlocking(client.socket, bundle.data(), bundle.size());

                if (config_.dumpPayloads && headerOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, header, static_cast<std::size_t>(headerLength));
                if (config_.dumpPayloads && bodyOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, bundle.data(), bundle.size());

                if (!bodyOk)
                {
                    const int error = WSAGetLastError();
                    log::Print("[BGS-BUNDLE] id=%llu failed sending stock signed bundle bytes=%llu wsa=%d",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(bundle.size()),
                        error);
                    CloseClient(index, "bgs-key-fingerprint-send-failed");
                }
                else
                {
                    log::Print("[BGS-BUNDLE] id=%llu served OPTION2 signed BGS bundle bytes=%llu format=JSON(local CA trust)+NGIS+RSA2048LE pinReplacements=%llu signatureVerified=yes; login/fence/LUI state remains server-driven",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(bundle.size()),
                        static_cast<unsigned long long>(pinReplacements));
                    CloseClient(index, "bgs-key-fingerprint-option2-signed-200");
                }
                return;
            }
        }

        // Private diagnostic probe only; unknown IW8 binary traffic remains
        // capture-only until its framing/handshake is actually observed.
        static const char probe[] = "CRIW8PNG";
        static const char reply[] = "CRIW8PONG\n";
        if (result >= static_cast<int>(sizeof(probe) - 1) && std::equal(buffer, buffer + sizeof(probe) - 1, reinterpret_cast<const unsigned char*>(probe)))
            send(client.socket, reply, static_cast<int>(sizeof(reply) - 1), 0);
    }


    void Server::CloseClient(std::size_t index, const char* reason)
    {
        if (index >= clients_.size()) return;
        Client& client = clients_[index];
        log::Connection(client.id, client.peer, client.localPort, "closed", reason);
        DestroyTlsSession(client.tlsState);
        closesocket(client.socket);
        clients_.erase(clients_.begin() + static_cast<std::ptrdiff_t>(index));
    }

    void Server::Run()
    {
        while (running_)
        {
            fd_set readSet{};
            FD_ZERO(&readSet);
            SOCKET maximum = 0;
            for (const auto& listener : listeners_)
            {
                FD_SET(listener.socket, &readSet);
                maximum = (std::max)(maximum, listener.socket);
            }
            for (const auto& client : clients_)
            {
                FD_SET(client.socket, &readSet);
                maximum = (std::max)(maximum, client.socket);
            }
            timeval timeout{};
            timeout.tv_sec = 0;
            timeout.tv_usec = 250000;
            const int ready = select(static_cast<int>(maximum + 1), &readSet, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR)
            {
                log::Print("select failed WSA=%d", WSAGetLastError());
                Sleep(100);
                continue;
            }
            for (auto& listener : listeners_)
            {
                if (!FD_ISSET(listener.socket, &readSet)) continue;
                if (listener.udp) ReadUdp(listener); else AcceptTcp(listener);
            }
            for (std::size_t i = clients_.size(); i-- > 0; )
                if (i < clients_.size() && FD_ISSET(clients_[i].socket, &readSet)) ReadTcp(i);

            web::PollAuthPipelineDiagnostics();

            const ULONGLONG now = GetTickCount64();
            for (auto& client : clients_)
            {
                if (client.localPort != 1119) continue;

                if (client.firstPacket && !client.authIdleLogged && client.acceptedAtMs && now - client.acceptedAtMs >= 3000)
                {
                    client.authIdleLogged = true;
                    log::Print("[AUTH] id=%llu :1119 has no TLS client payload after 3s. No guessed bytes sent.",
                        static_cast<unsigned long long>(client.id));
                }

                auto* session = static_cast<TlsSession*>(client.tlsState);
                if (session && session->established && !session->bgsApplicationSeen && !session->serverFirstLogged &&
                    session->establishedAtMs && now - session->establishedAtMs >= 3000)
                {
                    session->serverFirstLogged = true;
                    log::Print("[BGS1119] id=%llu no decrypted application data arrived within 3s of TLS establishment",
                        static_cast<unsigned long long>(client.id));
                    log::Print("[BGS1119] id=%llu documented BGS order is client ConnectionService.Connect -> ConnectResponse -> server ChallengeListener.OnExternalChallenge -> client AuthenticationService.Logon",
                        static_cast<unsigned long long>(client.id));
                    log::Print("[BGS1119] id=%llu MW2019 has not issued ConnectionService.Connect yet; pure emulation will NOT inject a challenge or fake a connection response. Waiting for the client while the DLL scans the Battle.net token/bootstrap gate.",
                        static_cast<unsigned long long>(client.id));
                }
            }
        }
    }

    void Server::Stop()
    {
        if (!running_.exchange(false)) return;
        for (auto& client : clients_)
        {
            DestroyTlsSession(client.tlsState);
            if (client.socket != INVALID_SOCKET) closesocket(client.socket);
        }
        clients_.clear();
        for (auto& listener : listeners_)
            if (listener.socket != INVALID_SOCKET) closesocket(listener.socket);
        listeners_.clear();
        ShutdownTlsCredential();
        ShutdownBundleSigner();
        WSACleanup();
    }

}
