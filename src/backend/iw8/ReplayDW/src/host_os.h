#pragma once
// The server's small OS boundary. Windows retains its native implementation;
// POSIX preserves byte-oriented files, atomic replacement and socket deadlines.
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <openssl/crypto.h>

using DWORD = uint32_t;
using BOOL = int;
using SOCKET = int;
using HANDLE = void *;
using __time64_t = int64_t;
constexpr int TRUE = 1, FALSE = 0, INVALID_SOCKET = -1, SOCKET_ERROR = -1;
inline const HANDLE INVALID_HANDLE_VALUE = reinterpret_cast<HANDLE>(intptr_t(-1));

inline int host_file_descriptor(HANDLE file)
{
    return static_cast<int>(reinterpret_cast<intptr_t>(file) - 1);
}

constexpr unsigned GENERIC_READ = 1, GENERIC_WRITE = 2;
constexpr unsigned FILE_SHARE_READ = 1, FILE_SHARE_DELETE = 2;
constexpr unsigned OPEN_EXISTING = 1, CREATE_ALWAYS = 2, FILE_ATTRIBUTE_NORMAL = 0;
constexpr unsigned MOVEFILE_REPLACE_EXISTING = 1, MOVEFILE_WRITE_THROUGH = 2;
// Linux bind already excludes a second listener without SO_REUSEPORT.
constexpr int SO_EXCLUSIVEADDRUSE = -100;
constexpr int WSAEMSGSIZE = EMSGSIZE, WSAETIMEDOUT = EAGAIN;
#define WINAPI

struct WSADATA
{
};

struct IN_ADDR
{
    struct
    {
        uint32_t S_addr;
    } S_un;
};

inline int InetPtonA(int family, const char *text, void *out)
{
    return ::inet_pton(family, text, out);
}

struct LARGE_INTEGER
{
    int64_t QuadPart = 0;
};

inline int MAKEWORD(int, int)
{
    return 0;
}

inline int WSAStartup(int, WSADATA *)
{
    return 0;
}

inline void WSACleanup() {}

inline int WSAGetLastError()
{
    return errno;
}

inline int closesocket(int fd)
{
    return ::close(fd);
}

inline void SecureZeroMemory(void *p, size_t size)
{
    OPENSSL_cleanse(p, size);
}

inline int gmtime_s(tm *out, const time_t *value)
{
    return gmtime_r(value, out) ? 0 : errno;
}

inline int _gmtime64_s(tm *out, const int64_t *value)
{
    const time_t seconds = static_cast<time_t>(*value);
    return gmtime_s(out, &seconds);
}

inline HANDLE CreateFileW(
    const char *path, unsigned access, unsigned, void *, unsigned creation, unsigned, void *)
{
    const auto fd = ::open(path,
                           (access == GENERIC_READ ? O_RDONLY : O_WRONLY) |
                               (creation == CREATE_ALWAYS ? O_CREAT | O_TRUNC : 0) | O_CLOEXEC,
                           0600);
    return fd < 0 ? INVALID_HANDLE_VALUE : reinterpret_cast<HANDLE>(intptr_t(fd) + 1);
}

inline BOOL CloseHandle(HANDLE fd)
{
    return ::close(host_file_descriptor(fd)) == 0;
}

inline BOOL GetFileSizeEx(HANDLE fd, LARGE_INTEGER *size)
{
    struct stat status{};
    if (::fstat(host_file_descriptor(fd), &status))
        return FALSE;
    size->QuadPart = status.st_size;
    return TRUE;
}

inline BOOL ReadFile(HANDLE fd, void *data, DWORD size, DWORD *received, void *)
{
    ssize_t n;
    do
    {
        n = ::read(host_file_descriptor(fd), data, size);
    } while (n < 0 && errno == EINTR);
    *received = n < 0 ? 0 : static_cast<DWORD>(n);
    return n >= 0;
}

inline BOOL WriteFile(HANDLE fd, const void *data, DWORD size, DWORD *written, void *)
{
    *written = 0;
    while (*written < size)
    {
        const auto n = ::write(
            host_file_descriptor(fd), static_cast<const char *>(data) + *written, size - *written);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return FALSE;
        *written += static_cast<DWORD>(n);
    }
    return TRUE;
}

inline BOOL FlushFileBuffers(HANDLE fd)
{
    return ::fsync(host_file_descriptor(fd)) == 0;
}

inline BOOL DeleteFileW(const char *path)
{
    return ::unlink(path) == 0;
}

BOOL MoveFileExW(const char *source, const char *target, unsigned flags);
BOOL SetConsoleCtrlHandler(BOOL (*handler)(DWORD), BOOL enabled);

// WinSock accepts millisecond DWORD deadlines and ignores select's first arg.
// Translate those semantics at this boundary, rather than changing wire code.
int host_setsockopt(int socket, int level, int option, const void *value, socklen_t size);

inline int host_select(int, fd_set *read, fd_set *write, fd_set *except, timeval *timeout)
{
    int maximum = -1;
    for (int i = 0; i < FD_SETSIZE; ++i)
        if ((read && FD_ISSET(i, read)) || (write && FD_ISSET(i, write)) ||
            (except && FD_ISSET(i, except)))
            maximum = i;
    return ::select(maximum + 1, read, write, except, timeout);
}

inline int host_getpeername(int socket, sockaddr *address, int *length)
{
    socklen_t size = *length;
    const auto result = ::getpeername(socket, address, &size);
    *length = size;
    return result;
}

inline int host_getsockname(int socket, sockaddr *address, int *length)
{
    socklen_t size = *length;
    const auto result = ::getsockname(socket, address, &size);
    *length = size;
    return result;
}

inline ssize_t host_recvfrom(
    int socket, void *buffer, size_t size, int flags, sockaddr *address, int *length)
{
    socklen_t count = length ? *length : 0;
    const auto result = ::recvfrom(socket, buffer, size, flags, address, length ? &count : nullptr);
    if (length)
        *length = count;
    return result;
}

#define setsockopt host_setsockopt
#define select host_select
#define getpeername host_getpeername
#define getsockname host_getsockname
#define recvfrom host_recvfrom
#endif
