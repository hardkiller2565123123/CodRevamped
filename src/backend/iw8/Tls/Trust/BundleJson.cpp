#include "BundleJson.h"

namespace revamped::iw8
{
    namespace
    {
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
    }
}
