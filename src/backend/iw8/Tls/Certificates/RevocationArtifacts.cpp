#include "RevocationArtifacts.h"

namespace revamped::iw8
{
    namespace
    {
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
    }
}
