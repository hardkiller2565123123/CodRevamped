#include "TrafficSigningKeys.h"

namespace revamped::iw8
{
    namespace
    {
        struct AuthTrafficSigningKeyCandidateV78
        {
            std::uint64_t fileOffset = 0;
            std::array<std::uint8_t, 294> der{};
        };

        std::uint64_t ReadLe64(const std::uint8_t* p)
        {
            std::uint64_t value = 0;
            for (unsigned shift = 0; shift < 64u; shift += 8u)
                value |= static_cast<std::uint64_t>(*p++) << shift;
            return value;
        }

        bool LooksLikeRsaSpki294V78(const std::uint8_t* p, std::size_t available)
        {
            if (!p || available < 294u)
                return false;
            static const std::uint8_t prefix[] =
            {
                0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,
                0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,
                0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,
                0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01
            };
            if (std::memcmp(p, prefix, sizeof(prefix)) != 0)
                return false;
            return p[32] == 0x00u &&
                p[289] == 0x02u && p[290] == 0x03u &&
                p[291] == 0x01u && p[292] == 0x00u && p[293] == 0x01u;
        }

        bool LoadTrafficSigningKeyCandidatePackV78(const wchar_t* path,
            std::vector<AuthTrafficSigningKeyCandidateV78>& out)
        {
            if (!path || !*path)
                return false;

            HANDLE file = CreateFileW(path, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;

            LARGE_INTEGER size{};
            if (!GetFileSizeEx(file, &size) || size.QuadPart < 16 || size.QuadPart > 1024 * 1024)
            {
                CloseHandle(file);
                return false;
            }

            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
            DWORD read = 0;
            const bool readOk = ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) &&
                read == static_cast<DWORD>(bytes.size());
            CloseHandle(file);
            if (!readOk)
                return false;

            static const std::uint8_t magic[8] = {'I','W','8','K','3','V','7','8'};
            if (std::memcmp(bytes.data(), magic, sizeof(magic)) != 0)
                return false;
            const std::uint32_t version = ReadLe32(bytes.data() + 8u);
            const std::uint32_t count = ReadLe32(bytes.data() + 12u);
            if (version != 1u || count > 128u)
                return false;

            constexpr std::size_t recordBytes = 8u + 294u;
            const std::size_t expected = 16u + static_cast<std::size_t>(count) * recordBytes;
            if (bytes.size() != expected)
                return false;

            out.clear();
            out.reserve(count);
            std::size_t offset = 16u;
            for (std::uint32_t i = 0; i < count; ++i)
            {
                AuthTrafficSigningKeyCandidateV78 candidate{};
                candidate.fileOffset = ReadLe64(bytes.data() + offset);
                offset += 8u;
                std::memcpy(candidate.der.data(), bytes.data() + offset, candidate.der.size());
                offset += candidate.der.size();
                if (!LooksLikeRsaSpki294V78(candidate.der.data(), candidate.der.size()))
                    return false;
                out.push_back(candidate);
            }
            return true;
        }

        bool LoadAuthTrafficSigningKeyCandidatesV78(
            std::vector<AuthTrafficSigningKeyCandidateV78>& out, std::wstring* loadedPath)
        {
            const wchar_t fileName[] = L"iw8-auth-traffic-signing-key3-candidates.bin";
            std::vector<std::wstring> paths;

            wchar_t modulePath[32768]{};
            const DWORD chars = GetModuleFileNameW(nullptr, modulePath,
                static_cast<DWORD>(sizeof(modulePath) / sizeof(modulePath[0])));
            if (chars > 0 && chars < (sizeof(modulePath) / sizeof(modulePath[0])))
            {
                std::wstring sibling(modulePath, chars);
                const std::wstring::size_type slash = sibling.find_last_of(L"\\/");
                if (slash != std::wstring::npos)
                    sibling.resize(slash + 1u);
                else
                    sibling.clear();
                paths.push_back(sibling + fileName);
            }
            paths.push_back(fileName);
            paths.push_back(std::wstring(L"server_emu\\") + fileName);

            for (const auto& path : paths)
            {
                std::vector<AuthTrafficSigningKeyCandidateV78> candidates;
                if (!LoadTrafficSigningKeyCandidatePackV78(path.c_str(), candidates))
                    continue;
                out.swap(candidates);
                if (loadedPath)
                    *loadedPath = path;
                return true;
            }
            return false;
        }

        bool EqualBytes(const std::uint8_t* left, const std::uint8_t* right, std::size_t size)
        {
            if (!left || !right) return false;
            std::uint8_t diff = 0;
            for (std::size_t i = 0; i < size; ++i)
                diff |= static_cast<std::uint8_t>(left[i] ^ right[i]);
            return diff == 0;
        }
    }
}
