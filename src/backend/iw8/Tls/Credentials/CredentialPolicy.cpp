#include "CredentialPolicy.h"

namespace revamped::iw8
{
    namespace
    {
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
    }
}
