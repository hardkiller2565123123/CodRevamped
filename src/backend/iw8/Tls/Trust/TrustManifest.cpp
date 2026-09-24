#include "TrustManifest.h"

namespace revamped::iw8
{
    namespace
    {
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
    }
}
