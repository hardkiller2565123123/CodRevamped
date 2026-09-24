#include "LeafCertificate.h"

namespace revamped::iw8
{
    namespace
    {
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
    }
}
