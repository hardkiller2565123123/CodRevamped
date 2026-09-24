#include "CertificateAuthority.h"

namespace revamped::iw8
{
    namespace
    {
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
    }
}
