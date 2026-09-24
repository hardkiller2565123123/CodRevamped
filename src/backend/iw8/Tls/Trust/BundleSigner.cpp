#include "BundleSigner.h"

namespace revamped::iw8
{
    namespace
    {
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
    }
}
