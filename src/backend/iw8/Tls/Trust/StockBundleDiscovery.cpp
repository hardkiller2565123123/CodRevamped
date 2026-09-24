#include "StockBundleDiscovery.h"

namespace revamped::iw8
{
    namespace
    {
        std::wstring DirectoryOfPath(std::wstring path)
        {
            const std::size_t slash = path.find_last_of(L"\\/");
            if (slash == std::wstring::npos)
                return {};
            path.resize(slash);
            return path;
        }

        void AddUniqueBundleCandidate(std::vector<std::wstring>& candidates, const std::wstring& path)
        {
            if (path.empty())
                return;
            for (const auto& existing : candidates)
            {
                if (_wcsicmp(existing.c_str(), path.c_str()) == 0)
                    return;
            }
            candidates.push_back(path);
        }

        bool WriteSmallUtf8File(const std::wstring& path, const std::string& text)
        {
            if (path.empty() || text.empty())
                return false;
            HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
                return false;
            DWORD written = 0;
            const BOOL ok = WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
            FlushFileBuffers(file);
            CloseHandle(file);
            return ok && written == text.size();
        }

        std::wstring RunningModernWarfareDirectory()
        {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return {};

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            std::wstring result;
            if (Process32FirstW(snapshot, &entry))
            {
                do
                {
                    if (_wcsicmp(entry.szExeFile, L"ModernWarfare.exe") != 0)
                        continue;

                    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                    if (!process)
                        continue;

                    wchar_t imagePath[32768]{};
                    DWORD imageLength = static_cast<DWORD>(sizeof(imagePath) / sizeof(imagePath[0]));
                    if (QueryFullProcessImageNameW(process, 0, imagePath, &imageLength) && imageLength)
                        result = DirectoryOfPath(std::wstring(imagePath, imageLength));
                    CloseHandle(process);
                    if (!result.empty())
                        break;
                } while (Process32NextW(snapshot, &entry));
            }

            CloseHandle(snapshot);
            return result;
        }

        bool TryLoadStockBgsCertificateBundle(const std::wstring& path, std::vector<unsigned char>& bytes)
        {
            bytes.clear();
            FILE* file = nullptr;
            if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || !file)
                return false;

            if (fseek(file, 0, SEEK_END) != 0)
            {
                fclose(file);
                return false;
            }
            const long sizeLong = ftell(file);
            if (sizeLong <= 260 || sizeLong > 1024 * 1024)
            {
                fclose(file);
                return false;
            }
            rewind(file);

            bytes.resize(static_cast<std::size_t>(sizeLong));
            const std::size_t read = fread(bytes.data(), 1, bytes.size(), file);
            fclose(file);
            if (read != bytes.size() || bytes.empty() || bytes[0] != '{')
            {
                bytes.clear();
                return false;
            }

            const std::string json(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            if (json.find("\"Certificates\"") == std::string::npos ||
                json.find("\"PublicKeys\"") == std::string::npos ||
                json.find("\"SigningCertificates\"") == std::string::npos)
            {
                bytes.clear();
                return false;
            }

            std::size_t end = bytes.size();
            while (end && (bytes[end - 1] == '\r' || bytes[end - 1] == '\n' || bytes[end - 1] == ' ' || bytes[end - 1] == '\t'))
                --end;
            if (!end || bytes[end - 1] != '}')
            {
                bytes.clear();
                return false;
            }
            bytes.resize(end);
            return true;
        }

        std::vector<unsigned char> LoadStockBgsCertificateBundle()
        {
            std::vector<std::wstring> candidates;

            wchar_t envPath[32768]{};
            const DWORD envLength = GetEnvironmentVariableW(
                L"REVAMPED_IW8_BGS_BUNDLE",
                envPath,
                static_cast<DWORD>(sizeof(envPath) / sizeof(envPath[0])));
            if (envLength && envLength < (sizeof(envPath) / sizeof(envPath[0])))
                AddUniqueBundleCandidate(candidates, envPath);

            wchar_t serverPath[32768]{};
            const DWORD serverLength = GetModuleFileNameW(
                nullptr,
                serverPath,
                static_cast<DWORD>(sizeof(serverPath) / sizeof(serverPath[0])));
            const std::wstring serverDir =
                (serverLength && serverLength < (sizeof(serverPath) / sizeof(serverPath[0])))
                ? DirectoryOfPath(std::wstring(serverPath, serverLength))
                : std::wstring{};

            if (!serverDir.empty())
            {
                AddUniqueBundleCandidate(candidates, serverDir + L"\\bgs-key-fingerprint.stock");
                AddUniqueBundleCandidate(candidates, serverDir + L"\\CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock");
            }

            wchar_t currentDirectory[32768]{};
            const DWORD currentLength = GetCurrentDirectoryW(
                static_cast<DWORD>(sizeof(currentDirectory) / sizeof(currentDirectory[0])),
                currentDirectory);
            if (currentLength && currentLength < (sizeof(currentDirectory) / sizeof(currentDirectory[0])))
            {
                const std::wstring cwd(currentDirectory, currentLength);
                AddUniqueBundleCandidate(candidates, cwd + L"\\bgs-key-fingerprint.stock");
                AddUniqueBundleCandidate(candidates, cwd + L"\\CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock");
            }

            const std::wstring gameDir = RunningModernWarfareDirectory();
            if (!gameDir.empty())
            {
                AddUniqueBundleCandidate(candidates, gameDir + L"\\bgs-key-fingerprint.stock");
                AddUniqueBundleCandidate(candidates, gameDir + L"\\CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock");
            }

            std::vector<unsigned char> bytes;
            for (const auto& path : candidates)
            {
                if (!TryLoadStockBgsCertificateBundle(path, bytes))
                    continue;

                char utf8[32768]{};
                WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, utf8, static_cast<int>(sizeof(utf8)), nullptr, nullptr);
                log::Print("[BGS-BUNDLE] resolved stock bundle path=%s bytes=%llu",
                    utf8[0] ? utf8 : "<wide-path>",
                    static_cast<unsigned long long>(bytes.size()));
                return bytes;
            }

            log::Print("[BGS-BUNDLE] stock bundle lookup failed candidates=%llu serverDir=%ls gameDir=%ls",
                static_cast<unsigned long long>(candidates.size()),
                serverDir.empty() ? L"<unknown>" : serverDir.c_str(),
                gameDir.empty() ? L"<not-found>" : gameDir.c_str());
            return {};
        }
    }
}
