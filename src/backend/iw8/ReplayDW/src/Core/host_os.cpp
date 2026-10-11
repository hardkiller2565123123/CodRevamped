#include "host_os.h"
#ifndef _WIN32
#undef setsockopt
#include <filesystem>
#include <cstdio>

namespace
{
    BOOL (*controlHandler)(DWORD) = nullptr;

    void interrupted(int)
    {
        if (controlHandler)
            controlHandler(0);
    }
} // namespace

BOOL MoveFileExW(const char *source, const char *target, unsigned flags)
{
    // Flush the pending file even for callers using std::ofstream. A rename is
    // atomic within the same filesystem; fsync the parent to persist publication.
    if (flags & MOVEFILE_WRITE_THROUGH)
    {
        const auto fd = ::open(source, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return FALSE;
        const bool flushed = ::fsync(fd) == 0;
        ::close(fd);
        if (!flushed)
            return FALSE;
    }
    if (!(flags & MOVEFILE_REPLACE_EXISTING))
    {
        if (::link(source, target))
            return FALSE;
        if (::unlink(source))
            return FALSE;
    }
    else if (::rename(source, target))
        return FALSE;
    if (flags & MOVEFILE_WRITE_THROUGH)
    {
        auto parent = std::filesystem::path(target).parent_path();
        if (parent.empty())
            parent = ".";
        const auto fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0)
            return FALSE;
        const bool flushed = ::fsync(fd) == 0;
        ::close(fd);
        if (!flushed)
            return FALSE;
    }
    return TRUE;
}

BOOL SetConsoleCtrlHandler(BOOL (*handler)(DWORD), BOOL enabled)
{
    controlHandler = enabled ? handler : nullptr;
    struct sigaction action{};
    action.sa_handler = interrupted;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, nullptr) || sigaction(SIGINT, &action, nullptr))
        return FALSE;
    // A disconnected client must not kill the entire service during send().
    signal(SIGPIPE, SIG_IGN);
    return TRUE;
}

int host_setsockopt(int socket, int level, int option, const void *value, socklen_t size)
{
    if (level == SOL_SOCKET && option == SO_EXCLUSIVEADDRUSE)
    {
        int type = 0;
        socklen_t length = sizeof(type);
        if (::getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &length))
            return -1;
        // TCP needs reuse of TIME_WAIT endpoints after a controlled restart.
        // Without SO_REUSEPORT a second live listener still cannot bind. UDP
        // must keep reuse disabled to retain exclusive datagram ownership.
        const int reuse = type == SOCK_STREAM ? 1 : 0;
        return ::setsockopt(socket, level, SO_REUSEADDR, &reuse, sizeof(reuse));
    }
    if (level == SOL_SOCKET && (option == SO_RCVTIMEO || option == SO_SNDTIMEO) &&
        size == sizeof(DWORD))
    {
        DWORD milliseconds;
        std::memcpy(&milliseconds, value, sizeof(milliseconds));
        timeval timeout{milliseconds / 1000, (milliseconds % 1000) * 1000};
        return ::setsockopt(socket, level, option, &timeout, sizeof(timeout));
    }
    return ::setsockopt(socket, level, option, value, size);
}
#endif
