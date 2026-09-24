#include "TlsSessionState.h"

namespace revamped::iw8
{
    namespace
    {
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
    }
}
