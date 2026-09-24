#include "AuthSigner.h"

namespace revamped::iw8::web
{
    namespace
    {
        std::vector<std::uint8_t> BuildRsa2048SubjectPublicKeyInfo(
            const std::vector<std::uint8_t>& publicBlob)

        {
            if (publicBlob.size() < sizeof(BCRYPT_RSAKEY_BLOB))
                return {};
            const auto* rsa = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(publicBlob.data());
            if (rsa->Magic != BCRYPT_RSAPUBLIC_MAGIC || rsa->BitLength != 2048u ||
                rsa->cbModulus != 256u || rsa->cbPublicExp != 3u || rsa->cbPrime1 || rsa->cbPrime2)
            {
                return {};
            }
            const std::size_t payloadBytes = sizeof(BCRYPT_RSAKEY_BLOB) +
                static_cast<std::size_t>(rsa->cbPublicExp) + rsa->cbModulus;
            if (payloadBytes > publicBlob.size())
                return {};
            const auto* exponent = publicBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
            const auto* modulus = exponent + rsa->cbPublicExp;
            if (exponent[0] != 0x01u || exponent[1] != 0x00u || exponent[2] != 0x01u)
                return {};

            static constexpr std::uint8_t prefix[] = {
                0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,
                0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,
                0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,
                0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01,0x00
            };
            static constexpr std::uint8_t suffix[] = {0x02,0x03,0x01,0x00,0x01};
            std::vector<std::uint8_t> der;
            der.reserve(sizeof(prefix) + rsa->cbModulus + sizeof(suffix));
            der.insert(der.end(), std::begin(prefix), std::end(prefix));
            der.insert(der.end(), modulus, modulus + rsa->cbModulus);
            der.insert(der.end(), std::begin(suffix), std::end(suffix));
            return der.size() == 294u ? der : std::vector<std::uint8_t>{};
        }

        bool InitializeLocalAuthSignerInternal()
        {
            if (g_auth3SignerReady)
                return true;

            SECURITY_STATUS status = NCryptOpenStorageProvider(
                &g_auth3SignerProvider, MS_KEY_STORAGE_PROVIDER, 0);
            if (status != ERROR_SUCCESS)
            {
                log::Print("[AUTH3-TRUST] NCryptOpenStorageProvider failed status=0x%08lX",
                    static_cast<unsigned long>(status));
                return false;
            }

            static constexpr wchar_t keyName[] = L"CodRevamped_IW8_Auth3_ResponseSigner";
            status = NCryptOpenKey(g_auth3SignerProvider, &g_auth3SignerKey, keyName, 0, NCRYPT_SILENT_FLAG);
            if (status != ERROR_SUCCESS)
            {
                status = NCryptCreatePersistedKey(g_auth3SignerProvider, &g_auth3SignerKey,
                    NCRYPT_RSA_ALGORITHM, keyName, 0, 0);
                DWORD bits = 2048u;
                if (status == ERROR_SUCCESS)
                    status = NCryptSetProperty(g_auth3SignerKey, NCRYPT_LENGTH_PROPERTY,
                        reinterpret_cast<PBYTE>(&bits), sizeof(bits), 0);
                if (status == ERROR_SUCCESS)
                    status = NCryptFinalizeKey(g_auth3SignerKey, NCRYPT_SILENT_FLAG);
            }
            if (status != ERROR_SUCCESS || !g_auth3SignerKey)
            {
                log::Print("[AUTH3-TRUST] persistent RSA key setup failed status=0x%08lX",
                    static_cast<unsigned long>(status));
                return false;
            }

            DWORD publicBytes = 0;
            status = NCryptExportKey(g_auth3SignerKey, 0, BCRYPT_RSAPUBLIC_BLOB,
                nullptr, nullptr, 0, &publicBytes, 0);
            if (status != ERROR_SUCCESS || !publicBytes)
            {
                log::Print("[AUTH3-TRUST] public-key size export failed status=0x%08lX",
                    static_cast<unsigned long>(status));
                return false;
            }
            std::vector<std::uint8_t> publicBlob(publicBytes);
            status = NCryptExportKey(g_auth3SignerKey, 0, BCRYPT_RSAPUBLIC_BLOB,
                nullptr, publicBlob.data(), publicBytes, &publicBytes, 0);
            if (status != ERROR_SUCCESS)
            {
                log::Print("[AUTH3-TRUST] public-key export failed status=0x%08lX",
                    static_cast<unsigned long>(status));
                return false;
            }
            publicBlob.resize(publicBytes);
            const std::vector<std::uint8_t> der = BuildRsa2048SubjectPublicKeyInfo(publicBlob);
            const std::wstring publicPath = ServerSiblingPath(L"auth3-response-signing-public.der");
            if (der.size() != 294u || !WriteBinaryFile(publicPath, der))
            {
                log::Print("[AUTH3-TRUST] failed exporting 294-byte DER public key win32=%lu",
                    GetLastError());
                return false;
            }

            std::array<std::uint8_t, 32> fingerprint{};
            if (!Sha256(der.data(), der.size(), fingerprint))
                return false;
            char prefix[17]{};
            for (std::size_t i = 0; i < 8u; ++i)
                _snprintf_s(prefix + i * 2u, sizeof(prefix) - i * 2u, _TRUNCATE, "%02X", fingerprint[i]);

            g_auth3SignerReady = true;
            log::Print("[AUTH3-TRUST] local RSA-PSS/SHA-256 response signer ready publicDerBytes=%llu sha256Prefix=%s file=auth3-response-signing-public.der",
                static_cast<unsigned long long>(der.size()), prefix);
            return true;
        }

        std::vector<std::uint8_t> SignAuth3Body(const std::string& body)
        {
            if (!InitializeLocalAuthSignerInternal() || body.empty())
                return {};
            std::array<std::uint8_t, 32> digest{};
            if (!Sha256(body.data(), body.size(), digest))
                return {};
            BCRYPT_PSS_PADDING_INFO padding{};
            padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            // IW8's bdRSAKey verifier forwards saltLength=0 to
            // rsa_verify_hash_ex, so the response must use zero-length PSS salt.
            padding.cbSalt = 0;
            DWORD signatureBytes = 0;
            SECURITY_STATUS status = NCryptSignHash(g_auth3SignerKey, &padding,
                digest.data(), static_cast<DWORD>(digest.size()), nullptr, 0,
                &signatureBytes, NCRYPT_PAD_PSS_FLAG);
            if (status != ERROR_SUCCESS || signatureBytes != 256u)
                return {};
            std::vector<std::uint8_t> signature(signatureBytes);
            status = NCryptSignHash(g_auth3SignerKey, &padding,
                digest.data(), static_cast<DWORD>(digest.size()), signature.data(),
                signatureBytes, &signatureBytes, NCRYPT_PAD_PSS_FLAG);
            if (status != ERROR_SUCCESS || signatureBytes != signature.size())
                return {};
            if (NCryptVerifySignature(g_auth3SignerKey, &padding, digest.data(),
                    static_cast<DWORD>(digest.size()), signature.data(), signatureBytes,
                    NCRYPT_PAD_PSS_FLAG) != ERROR_SUCCESS)
            {
                return {};
            }
            return signature;
        }
    }
}
