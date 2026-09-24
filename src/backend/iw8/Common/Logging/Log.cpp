#include "Common/Logging/Log.h"
#include "Common/Protocol/Protocol.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>

namespace revamped::iw8::log
{
    namespace
    {
        wchar_t g_root[MAX_PATH * 4]{};
        SRWLOCK g_lock = SRWLOCK_INIT;

        void Append(const wchar_t* name, const char* text)
        {
            if (!name || !text || !*text) return;
            wchar_t path[MAX_PATH * 4]{};
            _snwprintf_s(path, _countof(path), _TRUNCATE, L"%s\\%s", g_root, name);
            AcquireSRWLockExclusive(&g_lock);
            HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE)
            {
                DWORD written = 0;
                WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
                CloseHandle(file);
            }
            ReleaseSRWLockExclusive(&g_lock);
        }

        void Timestamp(char* out, std::size_t count)
        {
            SYSTEMTIME st{};
            GetLocalTime(&st);
            _snprintf_s(out, count, _TRUNCATE, "%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        }
    }

    bool Initialize()
    {
        wchar_t exe[MAX_PATH * 4]{};
        if (!GetModuleFileNameW(nullptr, exe, _countof(exe))) return false;
        if (wchar_t* slash = wcsrchr(exe, L'\\')) *slash = L'\0';
        wchar_t logs[MAX_PATH * 4]{};
        _snwprintf_s(logs, _countof(logs), _TRUNCATE, L"%s\\logs", exe);
        CreateDirectoryW(logs, nullptr);
        _snwprintf_s(g_root, _countof(g_root), _TRUNCATE, L"%s\\iw8_server", logs);
        CreateDirectoryW(g_root, nullptr);
        return true;
    }

    void Print(const char* format, ...)
    {
        char body[4096]{};
        va_list args;
        va_start(args, format);
        _vsnprintf_s(body, sizeof(body), _TRUNCATE, format, args);
        va_end(args);
        char time[32]{};
        Timestamp(time, sizeof(time));
        char line[4608]{};
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] %s\r\n", time, body);
        std::fputs(line, stdout);
        Append(L"server.log", line);
    }

    void Connection(std::uint64_t id, const std::string& peer, std::uint16_t port, const char* event, const char* detail)
    {
        char line[4096]{};
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[TCP] id=%llu peer=%s localPort=%u event=%s%s%s\r\n",
            static_cast<unsigned long long>(id), peer.c_str(), static_cast<unsigned>(port), event ? event : "?",
            detail ? " detail=" : "", detail ? detail : "");
        Append(L"connections.log", line);
        std::fputs(line, stdout);
    }

    void Payload(std::uint64_t id, const char* direction, std::uint16_t port, const std::string& peer, const void* data, std::size_t size)
    {
        const std::string kind = protocol::Classify(data, size);
        const std::string sni = protocol::TryExtractTlsSni(data, size);
        const std::string hex = protocol::HexPrefix(data, size);
        const std::string ascii = protocol::AsciiPrefix(data, size);
        char line[8192]{};
        _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[TCP-%s] id=%llu peer=%s localPort=%u bytes=%llu type=%s%s%s hex=%s ascii=%s\r\n",
            direction ? direction : "?", static_cast<unsigned long long>(id), peer.c_str(), static_cast<unsigned>(port),
            static_cast<unsigned long long>(size), kind.c_str(), sni.empty() ? "" : " sni=", sni.empty() ? "" : sni.c_str(), hex.c_str(), ascii.c_str());
        Append(L"payloads.log", line);

        wchar_t path[MAX_PATH * 4]{};
        _snwprintf_s(path, _countof(path), _TRUNCATE, L"%s\\tcp_%llu.bin", g_root, static_cast<unsigned long long>(id));
        HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            WriteFile(file, data, static_cast<DWORD>((std::min)(size, static_cast<std::size_t>(0xFFFFFFFFu))), &written, nullptr);
            CloseHandle(file);
        }
    }

    void Udp(std::uint16_t port, const std::string& peer, const void* data, std::size_t size)
    {
        const std::string kind = protocol::Classify(data, size);
        const std::string hex = protocol::HexPrefix(data, size);
        const std::string ascii = protocol::AsciiPrefix(data, size);
        char line[8192]{};
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[UDP] peer=%s localPort=%u bytes=%llu type=%s hex=%s ascii=%s\r\n",
            peer.c_str(), static_cast<unsigned>(port), static_cast<unsigned long long>(size), kind.c_str(), hex.c_str(), ascii.c_str());
        Append(L"udp.log", line);
    }
}
