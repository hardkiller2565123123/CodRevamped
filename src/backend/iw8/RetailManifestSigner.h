#pragma once
// IW8 Steam Retail 8.69 native zero-entry patch/comms manifest signing.
// Private RSA key: <server working directory>/ReplayDWData/retail_manifest_key.blob
// Public key shared with local Retail DLL: %LOCALAPPDATA%/CodRevamped/retail_manifest_public.der
// Never embed or transmit the private key to the client. No game-state overrides.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <cstdio>
#include <exception>
#include <string>
#include <system_error>
#include <vector>
#pragma comment(lib, "Bcrypt.lib")

namespace revamped::iw8::localpublisher::retailsigning {
namespace detail {
struct Handle {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    ~Handle() { if (key) BCryptDestroyKey(key); if (algorithm) BCryptCloseAlgorithmProvider(algorithm,0); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle() = default;
};
inline bool Ok(NTSTATUS status) noexcept { return status >= 0; }
inline bool ReadExact(const std::filesystem::path& filename, std::vector<unsigned char>& data, size_t maximum) {
    std::ifstream stream(filename, std::ios::binary | std::ios::ate);
    if (!stream) return false;
    const std::streamoff size = stream.tellg();
    if (size <= 0 || static_cast<std::uint64_t>(size) > maximum) return false;
    data.resize(static_cast<size_t>(size));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return stream.good() || (stream.eof() && stream.gcount() == static_cast<std::streamsize>(data.size()));
}
inline bool WriteNew(const std::filesystem::path& filename, const unsigned char* data, size_t len) {
    // Avoid overwriting an existing private key: silently rotating it would
    // invalidate manifest signatures and client key trust.
    if (std::filesystem::exists(filename)) return false;
    std::ofstream stream(filename, std::ios::binary | std::ios::trunc);
    if (!stream) return false;
    stream.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    stream.flush();
    return stream.good();
}
inline std::filesystem::path PublicFile() {
    wchar_t localAppData[32768]{};
    const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA",localAppData,static_cast<DWORD>(std::size(localAppData)));
    if (!len || len >= std::size(localAppData)) return {};
    return std::filesystem::path(localAppData) / L"CodRevamped" / L"retail_manifest_public.der";
}
// Fingerprint is for log correlation only, never a signature or trust check.
inline std::uint64_t PublicFingerprint(const unsigned char* bytes, size_t len) noexcept {
    std::uint64_t h=14695981039346656037ull;
    for (size_t i=0;i<len;++i) { h^=bytes[i]; h*=1099511628211ull; }
    return h;
}
inline std::filesystem::path GameSiblingPublicFile() {
    std::error_code ec;
    const auto cwd=std::filesystem::current_path(ec);
    if (!ec && std::filesystem::is_regular_file(cwd/L"ModernWarfare.exe",ec))
        return cwd/L"retail_manifest_public.der";
    wchar_t filename[32768]{};
    const DWORD len=GetModuleFileNameW(nullptr,filename,static_cast<DWORD>(std::size(filename)));
    if (len && len<std::size(filename)) {
        const auto exeDir=std::filesystem::path(filename).parent_path();
        ec.clear();
        if (std::filesystem::is_regular_file(exeDir/L"ModernWarfare.exe",ec))
            return exeDir/L"retail_manifest_public.der";
    }
    return {};
}
inline bool WritePublicFile(const std::filesystem::path& path,
                            const std::vector<unsigned char>& publicDer) {
    if (path.empty()) return false;
    std::ofstream output(path,std::ios::binary|std::ios::trunc);
    if (!output) return false;
    output.write(reinterpret_cast<const char*>(publicDer.data()),
                 static_cast<std::streamsize>(publicDer.size()));
    output.flush();
    return output.good();
}
inline bool MakePublicDer(BCRYPT_KEY_HANDLE key, std::vector<unsigned char>& der) {
    ULONG count=0;
    if (!Ok(BCryptExportKey(key,nullptr,BCRYPT_RSAPUBLIC_BLOB,nullptr,0,&count,0)) || count < sizeof(BCRYPT_RSAKEY_BLOB)) return false;
    std::vector<unsigned char> blob(count);
    if (!Ok(BCryptExportKey(key,nullptr,BCRYPT_RSAPUBLIC_BLOB,blob.data(),count,&count,0))) return false;
    BCRYPT_RSAKEY_BLOB info{};
    std::memcpy(&info,blob.data(),sizeof(info));
    if (info.Magic != BCRYPT_RSAPUBLIC_MAGIC || info.BitLength != 2048 ||
        info.cbPublicExp != 3 || info.cbModulus != 256 ||
        sizeof(info)+3u+256u > count) return false;
    const unsigned char* exponent=blob.data()+sizeof(info);
    const unsigned char* modulus=exponent+3;
    if (exponent[0]!=1 || exponent[1]!=0 || exponent[2]!=1 || (modulus[0]&0x80)==0) return false;
    static constexpr unsigned char prefix[]={0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01,0x00};
    static constexpr unsigned char suffix[]={0x02,0x03,0x01,0x00,0x01};
    der.assign(std::begin(prefix),std::end(prefix));
    der.insert(der.end(),modulus,modulus+256);
    der.insert(der.end(),std::begin(suffix),std::end(suffix));
    return der.size()==270;
}
inline bool InitKey(Handle& crypto, std::vector<unsigned char>& publicDer) {
    if (!Ok(BCryptOpenAlgorithmProvider(&crypto.algorithm,BCRYPT_RSA_ALGORITHM,nullptr,0))) return false;
    const std::filesystem::path privatePath=std::filesystem::current_path()/L"ReplayDWData"/L"retail_manifest_key.blob";
    std::error_code error;
    std::filesystem::create_directories(privatePath.parent_path(),error);
    if (error) return false;
    const bool havePrivate=std::filesystem::exists(privatePath,error);
    if (error) return false;
    if (havePrivate) {
        std::vector<unsigned char> blob;
        if (!ReadExact(privatePath,blob,16384) || !Ok(BCryptImportKeyPair(crypto.algorithm,nullptr,
            BCRYPT_RSAPRIVATE_BLOB,&crypto.key,blob.data(),static_cast<ULONG>(blob.size()),0))) return false;
    } else {
        if (!Ok(BCryptGenerateKeyPair(crypto.algorithm,&crypto.key,2048,0)) ||
            !Ok(BCryptFinalizeKeyPair(crypto.key,0))) return false;
        ULONG size=0;
        if (!Ok(BCryptExportKey(crypto.key,nullptr,BCRYPT_RSAPRIVATE_BLOB,nullptr,0,&size,0)) || size>16384) return false;
        std::vector<unsigned char> blob(size);
        if (!Ok(BCryptExportKey(crypto.key,nullptr,BCRYPT_RSAPRIVATE_BLOB,blob.data(),size,&size,0)) ||
            !WriteNew(privatePath,blob.data(),size)) return false;
    }
    if (!MakePublicDer(crypto.key,publicDer)) return false;
    const auto path=PublicFile();
    if (path.empty()) return false;
    std::filesystem::create_directories(path.parent_path(),error);
    if (error) return false;
    // Publish the same key to the existing per-user path and the game folder.
    // A game-root copy avoids stale-key mismatches if the launcher starts the
    // server and game using different Windows user profiles.
    if (!WritePublicFile(path,publicDer)) return false;
    const auto sibling=GameSiblingPublicFile();
    if (!sibling.empty()) {
        if (!WritePublicFile(sibling,publicDer)) {
            std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] WARNING game-root public key could not be written; per-user fallback remains available\n");
        } else {
            std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] game-root public key published fingerprint=0x%016llX\n",
                static_cast<unsigned long long>(PublicFingerprint(publicDer.data(),publicDer.size())));
        }
    } else {
        std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] game-root not located beside server; per-user key only\n");
    }
    std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] public key fingerprint=0x%016llX bytes=%zu\n",
        static_cast<unsigned long long>(PublicFingerprint(publicDer.data(),publicDer.size())),publicDer.size());
    return true;
}
inline std::string Hex(const unsigned char* data,size_t len) {
    static constexpr char digits[]="0123456789abcdef";
    std::string s; s.reserve(len*2);
    for(size_t i=0;i<len;++i){s.push_back(digits[data[i]>>4]);s.push_back(digits[data[i]&15]);}
    return s;
}
inline bool SelfVerifySignature(BCRYPT_ALG_HANDLE algorithm, BCRYPT_KEY_HANDLE key,
    const unsigned char* hash, ULONG hashBytes, const unsigned char* signature, ULONG signatureBytes) {
    // Verify with a freshly imported PUBLIC-only key. This catches persisted-key,
    // export-format and signing mistakes before serving a manifest to Retail.
    ULONG size=0;
    if (!Ok(BCryptExportKey(key,nullptr,BCRYPT_RSAPUBLIC_BLOB,nullptr,0,&size,0)) ||
        size < sizeof(BCRYPT_RSAKEY_BLOB) || size > 4096) return false;
    std::vector<unsigned char> blob(size);
    if (!Ok(BCryptExportKey(key,nullptr,BCRYPT_RSAPUBLIC_BLOB,blob.data(),size,&size,0))) return false;
    BCRYPT_KEY_HANDLE publicKey=nullptr;
    if (!Ok(BCryptImportKeyPair(algorithm,nullptr,BCRYPT_RSAPUBLIC_BLOB,&publicKey,
        blob.data(),size,0))) return false;
    BCRYPT_PSS_PADDING_INFO pss={BCRYPT_SHA256_ALGORITHM,8};
    const bool verified=Ok(BCryptVerifySignature(publicKey,&pss,
        const_cast<PUCHAR>(hash),hashBytes,const_cast<PUCHAR>(signature),signatureBytes,BCRYPT_PAD_PSS));
    BCryptDestroyKey(publicKey);
    return verified;
}
inline bool SignEmpty(BCRYPT_ALG_HANDLE algorithm, BCRYPT_KEY_HANDLE key, std::string& out) {
    // Same zero-entry native buffer as the verified 1.20/Steam Retail parser.
    // Retail's entry processing checks 0x10C1 (4289) at native +0xDC006.
    constexpr size_t signedBytes=0xDC00C;
    std::vector<unsigned char> signedPayload(signedBytes,0);
    signedPayload[0xDC004]=1; // manifestver=1
    signedPayload[0xDC006]=0xC1; signedPayload[0xDC007]=0x10; // dataverff=4289
    BCRYPT_ALG_HANDLE sha=nullptr;
    if (!Ok(BCryptOpenAlgorithmProvider(&sha,BCRYPT_SHA256_ALGORITHM,nullptr,0))) return false;
    std::array<unsigned char,32> hash{};
    const bool hashed=Ok(BCryptHash(sha,nullptr,0,signedPayload.data(),static_cast<ULONG>(signedPayload.size()),
        hash.data(),static_cast<ULONG>(hash.size())));
    BCryptCloseAlgorithmProvider(sha,0);
    if (!hashed) return false;
    BCRYPT_PSS_PADDING_INFO pss={BCRYPT_SHA256_ALGORITHM,8};
    std::array<unsigned char,256> signature{};
    ULONG written=0;
    if (!Ok(BCryptSignHash(key,&pss,hash.data(),static_cast<ULONG>(hash.size()),
        signature.data(),static_cast<ULONG>(signature.size()),&written,BCRYPT_PAD_PSS)) || written!=signature.size()) return false;
    if (!SelfVerifySignature(algorithm,key,hash.data(),static_cast<ULONG>(hash.size()),
        signature.data(),written)) {
        std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] RSA self-verification FAILED; refusing manifest\n");
        return false;
    }
    out="{\"count\":0,\"manifestver\":1,\"dataverff\":4289,\"purgeCache\":0,\"signature\":\"";
    out+=Hex(signature.data(),signature.size());
    out+="\"}\n";
    return true;
}
struct RetailManifests { std::string patch,comms; bool ready=false; };
inline RetailManifests Initialize() {
    RetailManifests result;
    try {
        Handle key; std::vector<unsigned char> publicDer;
        if (!InitKey(key,publicDer)) {
            std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] signing key initialization failed; not advertising unsigned manifests\n");
            return result;
        }
        // Two distinct signed files; metadata is generated from the cached bytes.
        result.ready=SignEmpty(key.algorithm,key.key,result.patch) &&
            SignEmpty(key.algorithm,key.key,result.comms);
        if (result.ready)
            std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] RSA-PSS self-verify=PASS patch=PASS comms=PASS publicDerBytes=%zu\n",
                publicDer.size());
        std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] automatic patch/comms signing %s; native dataverff=4289\n",
            result.ready ? "ready" : "failed");
    } catch (const std::exception& error) {
        std::fprintf(stderr,"[IW8-RETAIL-MANIFEST] startup error: %s\n",error.what());
    }
    return result;
}
} // namespace detail

// Publisher ObjectStore checksums are Base64(SHA1(HTTP content bytes)),
// as established independently by the 1.20 signed manifest's known checksum.
// The objectVersion field is different metadata and may still use the server's
// version digest; do not confuse it with the content checksum.
inline std::string ManifestSha1ChecksumBase64(const std::string& body) {
    BCRYPT_ALG_HANDLE sha=nullptr;
    if (!detail::Ok(BCryptOpenAlgorithmProvider(&sha,BCRYPT_SHA1_ALGORITHM,nullptr,0))) return {};
    std::array<unsigned char,20> digest{};
    const bool ok=detail::Ok(BCryptHash(sha,nullptr,0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(body.data())),
        static_cast<ULONG>(body.size()),digest.data(),static_cast<ULONG>(digest.size())));
    BCryptCloseAlgorithmProvider(sha,0);
    if (!ok) return {};
    static constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output; output.reserve(28);
    for (size_t i=0;i<digest.size();i+=3) {
        const unsigned a=digest[i];
        const unsigned b=i+1<digest.size()?digest[i+1]:0;
        const unsigned c=i+2<digest.size()?digest[i+2]:0;
        output.push_back(alphabet[a>>2]);
        output.push_back(alphabet[((a&3)<<4)|(b>>4)]);
        output.push_back(i+1<digest.size()?alphabet[((b&15)<<2)|(c>>6)]:'=');
        output.push_back(i+2<digest.size()?alphabet[c&63]:'=');
    }
    return output;
}

inline bool LoadAutomaticManifest(const std::string& filename, std::string& output) {
    if (filename!="1_manifest_patch_pc_8.69.txt" && filename!="1_manifest_comms_pc_8.69.txt") return false;
    static const detail::RetailManifests manifests=detail::Initialize();
    if (!manifests.ready) return false;
    output=(filename=="1_manifest_patch_pc_8.69.txt")?manifests.patch:manifests.comms;
    return true;
}
} // namespace revamped::iw8::localpublisher::retailsigning
