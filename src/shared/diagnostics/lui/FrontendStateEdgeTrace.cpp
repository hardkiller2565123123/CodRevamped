#include "FrontendStateEdgeTrace.h"
#include "LuaOwnerStateTrace.h"
#include "../../core/Main.hpp"
#include "../../runtime/LogPaths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace frontend_state_edge_trace
{
    namespace
    {
        std::atomic_bool g_running{ false };
        std::atomic_uint g_edges{ 0 };
        std::mutex g_snapshotMutex;

        template <typename T>
        bool SafeRead(
            std::uintptr_t address,
            T& value)
        {
            SIZE_T got = 0;
            return address &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    &value,
                    sizeof(value),
                    &got) &&
                got == sizeof(value);
        }

        bool SafeReadBytes(
            std::uintptr_t address,
            void* output,
            std::size_t size)
        {
            SIZE_T got = 0;
            return address && output && size &&
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(address),
                    output,
                    size,
                    &got) &&
                got == size;
        }

        std::string Sanitize(
            std::string value)
        {
            if (value.empty())
                value = "snapshot";

            for (char& c : value)
            {
                const bool ok =
                    (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '_' ||
                    c == '-';

                if (!ok)
                    c = '_';
            }

            if (value.size() > 80)
                value.resize(80);

            return value;
        }

        bool AddressInMainModule(
            std::uintptr_t address,
            std::uintptr_t& rva)
        {
            rva = 0;

            const auto module =
                reinterpret_cast<std::uintptr_t>(
                    GetModuleHandleW(nullptr));

            if (!module)
                return false;

            IMAGE_DOS_HEADER dos{};
            IMAGE_NT_HEADERS64 nt{};

            if (!SafeRead(module, dos) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE ||
                !SafeRead(
                    module +
                        static_cast<std::uintptr_t>(
                            dos.e_lfanew),
                    nt) ||
                nt.Signature != IMAGE_NT_SIGNATURE)
            {
                return false;
            }

            const auto end =
                module +
                static_cast<std::uintptr_t>(
                    nt.OptionalHeader.SizeOfImage);

            if (address < module ||
                address >= end)
            {
                return false;
            }

            rva = address - module;
            return true;
        }

        const char* ProtectionName(
            DWORD protect)
        {
            const auto p =
                protect & 0xFF;

            switch (p)
            {
            case PAGE_EXECUTE:
                return "X";
            case PAGE_EXECUTE_READ:
                return "XR";
            case PAGE_EXECUTE_READWRITE:
                return "XRW";
            case PAGE_EXECUTE_WRITECOPY:
                return "XWC";
            case PAGE_READONLY:
                return "R";
            case PAGE_READWRITE:
                return "RW";
            case PAGE_WRITECOPY:
                return "WC";
            default:
                return "?";
            }
        }

        void DescribePointer(
            std::ofstream& out,
            const char* field,
            std::uintptr_t value)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            const bool queried =
                value &&
                VirtualQuery(
                    reinterpret_cast<const void*>(
                        value),
                    &mbi,
                    sizeof(mbi));

            std::uintptr_t rva = 0;
            const bool mainModule =
                AddressInMainModule(
                    value,
                    rva);

            out
                << field
                << "=0x"
                << std::hex
                << std::uppercase
                << value
                << std::dec;

            if (mainModule)
            {
                out
                    << " MAIN_EXE_RVA=0x"
                    << std::hex
                    << std::uppercase
                    << rva
                    << std::dec;
            }

            if (queried)
            {
                wchar_t modulePath[MAX_PATH]{};
                HMODULE ownerModule = nullptr;

                if (GetModuleHandleExW(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast<LPCWSTR>(
                            value),
                        &ownerModule) &&
                    ownerModule)
                {
                    GetModuleFileNameW(
                        ownerModule,
                        modulePath,
                        MAX_PATH);
                }

                out
                    << " region=0x"
                    << std::hex
                    << std::uppercase
                    << reinterpret_cast<std::uintptr_t>(
                        mbi.AllocationBase)
                    << " protect="
                    << ProtectionName(
                        mbi.Protect)
                    << std::dec;

                if (modulePath[0])
                {
                    char utf8[MAX_PATH * 3]{};
                    WideCharToMultiByte(
                        CP_UTF8,
                        0,
                        modulePath,
                        -1,
                        utf8,
                        sizeof(utf8),
                        nullptr,
                        nullptr);

                    out
                        << " module="
                        << utf8;
                }
            }

            out << "\n";
        }

        void DumpAddressWindow(
            std::ofstream& out,
            const char* label,
            std::uintptr_t address,
            std::size_t radius)
        {
            if (!address)
                return;

            const auto begin =
                address > radius
                    ? address - radius
                    : address;

            const auto size =
                radius * 2;

            std::vector<unsigned char>
                bytes(size);

            if (!SafeReadBytes(
                    begin,
                    bytes.data(),
                    bytes.size()))
            {
                out
                    << "["
                    << label
                    << "] READ_FAILED @0x"
                    << std::hex
                    << address
                    << std::dec
                    << "\n";
                return;
            }

            out
                << "["
                << label
                << " window]\n"
                << std::hex
                << std::uppercase
                << std::setfill('0');

            for (std::size_t row = 0;
                 row < bytes.size();
                 row += 16)
            {
                out
                    << "0x"
                    << std::setw(16)
                    << (begin + row)
                    << ": ";

                for (std::size_t j = 0;
                     j < 16 &&
                     row + j < bytes.size();
                     ++j)
                {
                    out
                        << std::setw(2)
                        << static_cast<unsigned int>(
                            bytes[row + j])
                        << ' ';
                }

                out << "\n";
            }

            out << std::dec << "\n";
        }

        void DumpLuaRecords(
            std::ofstream& out)
        {
            std::uintptr_t owner = 0;

            if (!lua_owner_state_trace::
                    GetOwnerAddress(owner))
            {
                out
                    << "[LUA RECORDS]\n"
                    << "owner unavailable\n\n";
                return;
            }

            out
                << "[LUA RECORDS]\n"
                << "owner=0x"
                << std::hex
                << std::uppercase
                << owner
                << std::dec
                << "\n"
                << "record_stride=0x48\n\n";

            const auto module =
                reinterpret_cast<std::uintptr_t>(
                    GetModuleHandleW(nullptr));

            for (unsigned int index = 0;
                 index < 4;
                 ++index)
            {
                const auto record =
                    owner +
                    static_cast<std::uintptr_t>(
                        index) *
                        0x48;

                std::uint64_t qwords[9]{};

                if (!SafeReadBytes(
                        record,
                        qwords,
                        sizeof(qwords)))
                {
                    out
                        << "record["
                        << index
                        << "] READ_FAILED\n";
                    continue;
                }

                out
                    << "record["
                    << index
                    << "] address=0x"
                    << std::hex
                    << std::uppercase
                    << record
                    << std::dec
                    << "\n";

                const char* fields[9] =
                {
                    "+00 item",
                    "+08 data",
                    "+10 size_meta",
                    "+18 index_flags",
                    "+20 descriptor_ptr",
                    "+28 hash",
                    "+30 shared_ptr",
                    "+38 layout_meta",
                    "+40 extra"
                };

                for (unsigned int q = 0;
                     q < 9;
                     ++q)
                {
                    DescribePointer(
                        out,
                        fields[q],
                        static_cast<std::uintptr_t>(
                            qwords[q]));
                }

                out << "\n";
            }

            (void)module;
        }

        bool WriteSnapshot(
            const std::string& rawLabel,
            std::string& message)
        {
            std::lock_guard<std::mutex>
                lock(g_snapshotMutex);

            const auto label =
                Sanitize(rawLabel);

            log_paths::EnsureAll();
            CreateDirectoryA(
                "logs\\lui",
                nullptr);
            CreateDirectoryA(
                "logs\\lui\\state_edges",
                nullptr);

            SYSTEMTIME st{};
            GetLocalTime(&st);

            char path[MAX_PATH]{};

            sprintf_s(
                path,
                "logs\\lui\\state_edges\\%02u%02u%02u_%03u_%s.txt",
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds,
                label.c_str());

            std::ofstream out(
                path,
                std::ios::trunc);

            if (!out)
            {
                message =
                    "could not create state-edge snapshot";
                return false;
            }

            std::uint32_t screen = 0;
            std::uint32_t network = 0;
            std::uint32_t session = 0;
            unsigned char inited = 0;

            SafeRead(
                g_Addrs.s_uiScreen,
                screen);
            SafeRead(
                g_Addrs.s_networkMode,
                network);
            SafeRead(
                g_Addrs.sSessionModeState,
                session);
            SafeRead(
                g_Addrs.s_inited,
                inited);

            out
                << "[STATE]\n"
                << "label="
                << label
                << "\n"
                << "screen=0x"
                << std::hex
                << std::uppercase
                << screen
                << "\n"
                << "network=0x"
                << network
                << "\n"
                << "session=0x"
                << session
                << "\n"
                << "inited=0x"
                << static_cast<unsigned int>(
                    inited)
                << std::dec
                << "\n\n";

            DumpLuaRecords(out);

            out << "[GLOBAL WINDOWS]\n\n";

            DumpAddressWindow(
                out,
                "sSessionModeState",
                g_Addrs.sSessionModeState,
                0x200);

            DumpAddressWindow(
                out,
                "s_networkMode",
                g_Addrs.s_networkMode,
                0x200);

            DumpAddressWindow(
                out,
                "s_uiScreen",
                g_Addrs.s_uiScreen,
                0x100);

            std::string luaMarkMessage;
            lua_owner_state_trace::Mark(
                "edge_" + label,
                luaMarkMessage);

            std::ostringstream result;
            result
                << "state-edge snapshot written: "
                << path;

            message = result.str();

            return true;
        }

        const char* EdgeName(
            std::uint32_t from,
            std::uint32_t to)
        {
            if (from == 0x1034 &&
                to == 0x1014)
            {
                return "fresh_to_lan_primed";
            }

            if (from == 0x1014 &&
                to == 0x1020)
            {
                return "lan_primed_to_live_zm";
            }

            if (from == 0x1020 &&
                to == 0x2020)
            {
                return "live_zm_to_online_error";
            }

            if (from == 0x1034 &&
                to == 0x1020)
            {
                return "fresh_to_direct_live_zm";
            }

            return nullptr;
        }

        DWORD WINAPI Worker(
            LPVOID)
        {
            std::uint32_t previousSession = 0;
            std::uint32_t previousScreen = 0;
            std::uint32_t previousNetwork = 0;
            bool havePrevious = false;

            for (;;)
            {
                if (!g_running.load())
                    return 0;

                unsigned char inited = 0;
                std::uint32_t screen = 0;
                std::uint32_t network = 0;
                std::uint32_t session = 0;

                const bool ok =
                    SafeRead(
                        g_Addrs.s_inited,
                        inited) &&
                    SafeRead(
                        g_Addrs.s_uiScreen,
                        screen) &&
                    SafeRead(
                        g_Addrs.s_networkMode,
                        network) &&
                    SafeRead(
                        g_Addrs.sSessionModeState,
                        session);

                if (!ok ||
                    inited == 0)
                {
                    Sleep(5);
                    continue;
                }

                if (!havePrevious)
                {
                    previousSession =
                        session;
                    previousScreen =
                        screen;
                    previousNetwork =
                        network;
                    havePrevious = true;
                    Sleep(5);
                    continue;
                }

                if (session !=
                        previousSession ||
                    screen !=
                        previousScreen ||
                    network !=
                        previousNetwork)
                {
                    const auto edge =
                        EdgeName(
                            previousSession,
                            session);

                    char line[1024]{};

                    sprintf_s(
                        line,
                        "%02u:%02u:%02u session=0x%X->0x%X screen=0x%X->0x%X network=0x%X->0x%X edge=%s\n",
                        0u,
                        0u,
                        0u,
                        previousSession,
                        session,
                        previousScreen,
                        screen,
                        previousNetwork,
                        network,
                        edge ? edge : "other");

                    log_paths::EnsureAll();
                    CreateDirectoryA(
                        "logs\\lui",
                        nullptr);

                    std::ofstream timeline(
                        "logs\\lui\\frontend_state_edges.log",
                        std::ios::app);

                    if (timeline)
                        timeline << line;

                    std::printf(
                        "[STATE-EDGE] %s",
                        line);
                    std::fflush(stdout);

                    if (edge)
                    {
                        ++g_edges;

                        std::string message;
                        WriteSnapshot(
                            std::string("auto_") +
                                edge,
                            message);

                        std::printf(
                            "[STATE-EDGE] %s\n",
                            message.c_str());
                        std::fflush(stdout);
                    }

                    previousSession =
                        session;
                    previousScreen =
                        screen;
                    previousNetwork =
                        network;
                }

                Sleep(5);
            }
        }
    }

    void StartAsync()
    {
        if (g_running.exchange(true))
            return;

        HANDLE thread =
            CreateThread(
                nullptr,
                0,
                Worker,
                nullptr,
                0,
                nullptr);

        if (!thread)
        {
            g_running.store(false);
            return;
        }

        CloseHandle(thread);
    }

    bool IsRunning()
    {
        return g_running.load();
    }

    void PrintStatus()
    {
        std::printf(
            "[STATE-EDGE] running=%s capturedEdges=%u\n",
            g_running.load()
                ? "yes"
                : "no",
            g_edges.load());
        std::fflush(stdout);
    }

    bool SnapshotNow(
        const std::string& label,
        std::string& message)
    {
        return WriteSnapshot(
            label,
            message);
    }
}
