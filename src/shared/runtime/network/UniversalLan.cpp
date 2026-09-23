#include <WinSock2.h>
#include <WS2tcpip.h>

#include "UniversalLan.h"
#include "../LogPaths.h"
#include "../../core/CoreRuntime.h"
#include "../../core/functions.hpp"
#include "../../../clients/coldwar/game/T9Addresses.h"
#include "../../common/utils/MinHook.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>

namespace universal_lan
{
    namespace
    {
        std::mutex g_mutex;
        Status g_status{};

        const char* GameName(games::GameKind game)
        {
            switch (game)
            {
            case games::GameKind::Retail: return "T9 / Black Ops Cold War";
            case games::GameKind::Alpha: return "T9 Alpha/Beta";
            case games::GameKind::S2: return "S2";
            case games::GameKind::IW8: return "IW8 / Modern Warfare 2019";
            case games::GameKind::Beta: return "Unknown T9";
            case games::GameKind::T8: return "T8 / Black Ops 4";
            default: return "Unknown";
            }
        }

        void WriteStatusLog()
        {
            log_paths::EnsureAll();
            CreateDirectoryA("logs\\network", nullptr);
            std::ofstream out("logs\\network\\universal_lan.log", std::ios::app);
            if (!out) return;
            out << "[INIT] game=" << GameName(g_status.game)
                << " defaultGamePort=" << g_status.defaultGamePort
                << " defaultQueryPort=" << g_status.defaultQueryPort
                << " publicBlockerExpected=" << (g_status.publicNetworkBlockerExpected ? 1 : 0)
                << "\n";
        }

        // -----------------------------------------------------------------
        // cw-mod-v2 Cold War Retail bridge
        // -----------------------------------------------------------------
        constexpr std::uintptr_t kDumpImageBase = 0x7FF71CBC0000ull;
        constexpr std::uintptr_t Rva(std::uintptr_t dumpAbsolute)
        {
            return dumpAbsolute - kDumpImageBase;
        }

        // Native descriptor/session path from cw-mod-v2, build 1.34.0.15931218.
        constexpr std::uintptr_t kRvaSessionGetSessionObject = Rva(0x7FF726F82D20ull);
        constexpr std::uintptr_t kRvaClientSessionJoinPendingTarget = Rva(0x7FF727946A30ull);
        constexpr std::uintptr_t kRvaClientJoinCtx = Rva(0x7FF730430DA0ull);
        constexpr std::uintptr_t kRvaPendingAwaiting = Rva(0x7FF730437720ull);
        constexpr std::uintptr_t kRvaPendingNonce = Rva(0x7FF730437724ull);
        constexpr std::uintptr_t kRvaPendingXuid = Rva(0x7FF730437728ull);
        constexpr std::uintptr_t kRvaPendingValid = Rva(0x7FF730437738ull);
        constexpr std::uintptr_t kRvaPendingSessionId = Rva(0x7FF730437748ull);
        constexpr std::uintptr_t kRvaPendingHostName = Rva(0x7FF730437750ull);
        constexpr std::uintptr_t kRvaPendingSlot = Rva(0x7FF730437774ull);
        constexpr std::uintptr_t kRvaPendingSecId = Rva(0x7FF73043778Cull);
        constexpr std::uintptr_t kRvaPendingSecKey = Rva(0x7FF730437794ull);
        constexpr std::uintptr_t kRvaPendingSerializedAdr = Rva(0x7FF7304377A5ull);
        constexpr std::uintptr_t kRvaLobbyLaunchState = Rva(0x7FF73050A740ull);

        // Read-only LAN session diagnostics.
        constexpr std::uintptr_t kRvaNetSessionManager = Rva(0x7FF73753F5C8ull);
        constexpr std::uintptr_t kRvaNetSessionLaunchState = Rva(0x7FF72ADC7CA0ull);
        constexpr std::uintptr_t kRvaHostLaunchPhase = Rva(0x7FF73254F5E8ull);

        // Post-decryption join transcript.
        constexpr std::uintptr_t kRvaNetMsgDispatch = Rva(0x7FF726BF9370ull);
        constexpr std::uintptr_t kRvaNetMsgSendJoinResponse = Rva(0x7FF726BF82C0ull);
        constexpr std::uintptr_t kRvaSessionParseJoinLobbyRequest = Rva(0x7FF726BFB070ull);
        constexpr std::uintptr_t kRvaNetMsgNames = Rva(0x7FF72ADEF4E0ull);
        constexpr std::uintptr_t kRvaJoinResponseCode = Rva(0x7FF730437710ull);
        constexpr std::uintptr_t kRvaExpectedHostAdr = Rva(0x7FF730433E98ull);

        // Session object layout recovered by cw-mod-v2.
        constexpr std::size_t kSessMemberCount = 68;
        constexpr std::size_t kSessHostXuid = 168;
        constexpr std::size_t kSessHostName = 176;
        constexpr std::size_t kSessSerializedAdr = 265;
        constexpr std::size_t kSessSecId = 349;
        constexpr std::size_t kSessSecKey = 357;

        // Native join context / candidate layout.
        constexpr std::size_t kJoinCtxState = 0;
        constexpr std::size_t kJoinCtxActionId = 4;
        constexpr std::size_t kJoinCtxControllerIdx = 16;
        constexpr std::size_t kJoinCtxSrcLobby = 20;
        constexpr std::size_t kJoinCtxDstLobby = 24;
        constexpr std::size_t kJoinCtxCandidates = 40;
        constexpr std::size_t kJoinCtxHostCount = 12440;
        constexpr std::size_t kJoinCtxHostIdx = 12444;
        constexpr std::size_t kJoinCtxCurrentHost = 12456;
        constexpr std::size_t kJoinHostStride = 248;
        constexpr std::size_t kJoinHostMaxCount = 50;
        constexpr std::size_t kJoinHostSessionId = 0;
        constexpr std::size_t kJoinHostName = 8;
        constexpr std::size_t kJoinHostType = 44;
        constexpr std::size_t kJoinHostSerializedAdr = 97;
        constexpr std::size_t kJoinHostSecId = 181;
        constexpr std::size_t kJoinHostSecKey = 189;

        // JoinLobby request / JoinResponse fields used by the optional transcript.
        constexpr std::size_t kNetMsgIdOffset = 64;
        constexpr std::size_t kJoinReqTargetLobby = 0;
        constexpr std::size_t kJoinReqSourceLobby = 4;
        constexpr std::size_t kJoinReqJoinType = 8;
        constexpr std::size_t kJoinReqMemberCount = 44;
        constexpr std::size_t kJoinReqSplitScreen = 4112;
        constexpr std::size_t kJoinReqPlaylistId = 4116;
        constexpr std::size_t kJoinReqPlaylistVer = 4120;
        constexpr std::size_t kJoinReqPlaylistChecksum = 4124;
        constexpr std::size_t kJoinReqTuVersion = 4128;
        constexpr std::size_t kJoinReqFfotdVer = 4132;
        constexpr std::size_t kJoinReqNetworkMode = 4136;
        constexpr std::size_t kJoinReqNetChecksum = 4140;
        constexpr std::size_t kJoinReqProtocol = 4144;
        constexpr std::size_t kJoinReqChangelist = 4148;
        constexpr std::size_t kJoinReqFeatureChecksum = 4200;
        constexpr std::size_t kJoinRespCode = 0;
        constexpr std::size_t kJoinRespName = 4;
        constexpr std::size_t kJoinRespLobbyType = 76;
        constexpr std::size_t kJoinRespNetworkMode = 80;
        constexpr std::size_t kJoinRespMainMode = 84;

        constexpr char kJoinBlobPrefix[] = "CWJOIN1.";
        constexpr std::size_t kJoinBlobBytes = 8 + 1 + 36 + 8 + 16 + 84;
        constexpr std::size_t kJoinBlobHexChars = kJoinBlobBytes * 2;

        using SessionGetSessionObjectFn = std::uint8_t*(__fastcall*)(int, unsigned int);
        using JoinPendingTargetFn = char(__fastcall*)(std::int64_t, int, std::int64_t, int);
        using NetMsgDispatchFn = char(__fastcall*)(unsigned int, void*, void*, void*);
        using NetMsgSendJoinResponseFn = bool(__fastcall*)(int, int, int, void*, void*, void*);
        using ParseJoinLobbyRequestFn = bool(__fastcall*)(void*, void*);

        struct ColdWarBridge
        {
            std::atomic_bool initialized{ false };
            std::atomic_bool commandsRegistered{ false };
            std::uintptr_t base = 0;
            std::uintptr_t imageEnd = 0;
            SessionGetSessionObjectFn getSessionObject = nullptr;
            JoinPendingTargetFn joinPendingTarget = nullptr;
            std::uint8_t* joinCtx = nullptr;
            bool* pendingAwaiting = nullptr;
            int* pendingNonce = nullptr;
            std::int64_t* pendingXuid = nullptr;
            bool* pendingValid = nullptr;
            std::int64_t* pendingSessionId = nullptr;
            char* pendingHostName = nullptr;
            int* pendingSlot = nullptr;
            std::uint8_t* pendingSecId = nullptr;
            std::uint8_t* pendingSecKey = nullptr;
            std::uint8_t* pendingSerializedAdr = nullptr;
            int* lobbyLaunchState = nullptr;
            std::uint8_t** netSessionManager = nullptr;
            int* netSessionLaunchState = nullptr;
            int* hostLaunchPhase = nullptr;
            void** netMsgNames = nullptr;
            int* joinResponseCode = nullptr;
            std::uint8_t* expectedHostAdr = nullptr;
            void* netMsgDispatch = nullptr;
            void* netMsgSendJoinResponse = nullptr;
            void* parseJoinLobbyRequest = nullptr;
        };

        ColdWarBridge g_cw{};
        cmd_function_t g_exportCmd{};
        cmd_function_t g_joinCmd{};
        cmd_function_t g_pendingCmd{};
        cmd_function_t g_joinStateCmd{};
        cmd_function_t g_sessionCmd{};

        std::mutex g_pendingCommandMutex;
        std::string g_pendingJoinBlob;
        int g_pendingJoinType = 4;

        std::mutex g_joinLogMutex;
        std::string g_joinLog;
        std::atomic_bool g_joinWatchRunning{ false };

        NetMsgDispatchFn g_origNetMsgDispatch = nullptr;
        NetMsgSendJoinResponseFn g_origSendJoinResponse = nullptr;
        ParseJoinLobbyRequestFn g_origParseJoinReq = nullptr;
        std::atomic_bool g_netMsgTranscriptOn{ false };

        template <typename T>
        __declspec(noinline) bool SafeRead(const void* address, T& out) noexcept
        {
            if (!address) return false;
            __try
            {
                std::memcpy(&out, address, sizeof(T));
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        __declspec(noinline) bool SafeCopy(void* destination, const void* source, std::size_t bytes) noexcept
        {
            if (!destination || !source || !bytes) return false;
            __try
            {
                std::memcpy(destination, source, bytes);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        __declspec(noinline) bool SafeWrite(void* destination, const void* source, std::size_t bytes) noexcept
        {
            if (!destination || !source || !bytes) return false;
            __try
            {
                std::memcpy(destination, source, bytes);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        __declspec(noinline) std::uint8_t* SafeCallGetSessionObject(
            SessionGetSessionObjectFn function,
            int type,
            unsigned int slot) noexcept
        {
            if (!function) return nullptr;
            __try { return function(type, slot); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
        }

        __declspec(noinline) char SafeCallJoinPendingTarget(
            JoinPendingTargetFn function,
            std::int64_t contextId,
            int controller,
            std::int64_t unused,
            int joinType,
            DWORD& exceptionCode) noexcept
        {
            exceptionCode = 0;
            if (!function) return 0;
            __try { return function(contextId, controller, unused, joinType); }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                exceptionCode = GetExceptionCode();
                return 0;
            }
        }

        bool AddressInImage(std::uintptr_t address, std::size_t bytes = 1)
        {
            if (!g_cw.base || !g_cw.imageEnd || !address || !bytes) return false;
            if (address < g_cw.base || address >= g_cw.imageEnd) return false;
            return bytes <= (g_cw.imageEnd - address);
        }

        bool IsExecutableAddress(std::uintptr_t address)
        {
            if (!AddressInImage(address)) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
            const DWORD p = mbi.Protect & 0xFFu;
            return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsReadableAddress(std::uintptr_t address, std::size_t bytes = 1)
        {
            if (!address || !bytes) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
            const std::uintptr_t end = address + bytes;
            const std::uintptr_t regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            return end >= address && end <= regionEnd;
        }

        bool IsWritableAddress(std::uintptr_t address, std::size_t bytes = 1)
        {
            if (!IsReadableAddress(address, bytes)) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi))) return false;
            const DWORD p = mbi.Protect & 0xFFu;
            return p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
                p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        }

        std::string HexBytes(const std::uint8_t* bytes, std::size_t count)
        {
            std::ostringstream out;
            out << std::uppercase << std::hex << std::setfill('0');
            for (std::size_t i = 0; i < count; ++i)
            {
                if (i) out << ' ';
                out << std::setw(2) << static_cast<unsigned int>(bytes[i]);
            }
            return out.str();
        }

        void HexAppend(std::string& out, const std::uint8_t* bytes, std::size_t count)
        {
            static const char digits[] = "0123456789ABCDEF";
            for (std::size_t i = 0; i < count; ++i)
            {
                out.push_back(digits[bytes[i] >> 4]);
                out.push_back(digits[bytes[i] & 0x0F]);
            }
        }

        bool HexTake(const std::string& text, std::size_t& position, std::uint8_t* out, std::size_t count)
        {
            if (position + count * 2 > text.size()) return false;
            auto nibble = [](char c) -> int
            {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return -1;
            };
            for (std::size_t i = 0; i < count; ++i)
            {
                const int hi = nibble(text[position + i * 2]);
                const int lo = nibble(text[position + i * 2 + 1]);
                if (hi < 0 || lo < 0) return false;
                out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
            }
            position += count * 2;
            return true;
        }

        std::string StripJoinBlob(const std::string& input)
        {
            std::string text;
            text.reserve(input.size());
            for (char c : input)
            {
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n') text.push_back(c);
            }
            const std::size_t prefixLength = sizeof(kJoinBlobPrefix) - 1;
            if (text.size() >= prefixLength && text.compare(0, prefixLength, kJoinBlobPrefix) == 0)
                text.erase(0, prefixLength);
            return text;
        }

        bool ValidateJoinBlob(const std::string& input, std::string& reason)
        {
            reason.clear();
            const std::string text = StripJoinBlob(input);
            if (text.size() != kJoinBlobHexChars)
            {
                std::ostringstream out;
                out << "malformed CWJOIN1 descriptor: expected " << kJoinBlobHexChars
                    << " hex chars after prefix, got " << text.size();
                reason = out.str();
                return false;
            }
            std::array<std::uint8_t, kJoinBlobBytes> bytes{};
            std::size_t pos = 0;
            if (!HexTake(text, pos, bytes.data(), bytes.size()) || pos != text.size())
            {
                reason = "malformed CWJOIN1 descriptor: non-hex character found";
                return false;
            }
            std::int64_t xuid = 0;
            std::memcpy(&xuid, bytes.data(), sizeof(xuid));
            if (!xuid)
            {
                reason = "CWJOIN1 descriptor contains XUID 0; host session was not live when exported";
                return false;
            }
            if (bytes[8] > 2)
            {
                reason = "CWJOIN1 descriptor slot is outside 0..2";
                return false;
            }
            return true;
        }

        std::string BuildJoinDescriptorBlob(
            std::uint64_t xuid,
            int slot,
            const char* name,
            const std::uint8_t* secId,
            const std::uint8_t* secKey,
            const std::uint8_t* serializedAdr)
        {
            std::uint8_t xuidBytes[8]{};
            std::memcpy(xuidBytes, &xuid, sizeof(xuidBytes));
            const std::uint8_t slotByte = static_cast<std::uint8_t>(slot & 0xFF);
            std::uint8_t nameBytes[36]{};
            std::memcpy(nameBytes, name, sizeof(nameBytes));

            std::string result = kJoinBlobPrefix;
            result.reserve((sizeof(kJoinBlobPrefix) - 1) + kJoinBlobHexChars);
            HexAppend(result, xuidBytes, sizeof(xuidBytes));
            HexAppend(result, &slotByte, 1);
            HexAppend(result, nameBytes, sizeof(nameBytes));
            HexAppend(result, secId, 8);
            HexAppend(result, secKey, 16);
            HexAppend(result, serializedAdr, 84);
            return result;
        }

        std::string WallClockNow()
        {
            SYSTEMTIME st{};
            GetLocalTime(&st);
            char buffer[32]{};
            std::snprintf(buffer, sizeof(buffer), "%02u:%02u:%02u.%03u",
                static_cast<unsigned int>(st.wHour), static_cast<unsigned int>(st.wMinute),
                static_cast<unsigned int>(st.wSecond), static_cast<unsigned int>(st.wMilliseconds));
            return buffer;
        }

        void JoinLogAppend(const std::string& line)
        {
            {
                std::lock_guard<std::mutex> lock(g_joinLogMutex);
                g_joinLog += line;
                g_joinLog.push_back('\n');
                if (g_joinLog.size() > 32768)
                    g_joinLog.erase(0, g_joinLog.size() - 32768);
            }
            log_paths::EnsureAll();
            CreateDirectoryA("logs\\network", nullptr);
            std::ofstream file("logs\\network\\cwmod_lan_join.log", std::ios::app);
            if (file) file << line << '\n';
            std::printf("[CWMOD-LAN] %s\n", line.c_str());
            std::fflush(stdout);
        }

        const char* JoinStateLabel(int state)
        {
            switch (state)
            {
            case 0: return "idle";
            case 1: return "pick-candidate";
            case 2: return "send-JoinLobby";
            case 3: return "await-JoinResponse";
            case 4: return "await-agreement";
            case 5: return "next-candidate";
            case 6: return "JOIN COMPLETE";
            case 7: return "teardown";
            default: return "?";
            }
        }

        const char* JoinResponseLabel(int code)
        {
            switch (code)
            {
            case 1: return "ACCEPTED";
            case 9: return "lobby/party-host mismatch";
            case 10: return "candidate roster full";
            case 18: return "host block/ignore gate";
            case 33: return "reservation commit failed";
            case 36: return "networkmode != 1 OR jointype not in {1,4}";
            case 38: return "playlist version higher than host";
            case 39: return "playlist version lower than host";
            case 40: return "playlist checksum mismatch";
            case 42: return "net checksum mismatch";
            case 43: case 44: return "ffotd version mismatch";
            case 45: return "feature checksum mismatch";
            case 47: return "post-accept failed; client retries";
            case 53: case 54: case 55: case 56: return "platform/crossplay refusal";
            case 60: return "crossplay disabled for network mode";
            case 62: return "local-player/splitscreen mismatch";
            default: return "unmapped refusal";
            }
        }

        bool ExactRetailFingerprint(std::uintptr_t base, std::uintptr_t& imageEnd)
        {
            imageEnd = 0;
            if (!base) return false;
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (!IsReadableAddress(base, sizeof(IMAGE_DOS_HEADER)) || dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (!IsReadableAddress(reinterpret_cast<std::uintptr_t>(nt), sizeof(IMAGE_NT_HEADERS64)) ||
                nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            if (nt->FileHeader.TimeDateStamp != t9_addresses::RetailFingerprint.timestamp ||
                nt->OptionalHeader.SizeOfImage != t9_addresses::RetailFingerprint.imageSize)
                return false;
            imageEnd = base + nt->OptionalHeader.SizeOfImage;
            return imageEnd > base;
        }

        template <typename T>
        T ResolveCode(std::uintptr_t rva)
        {
            const std::uintptr_t address = g_cw.base + rva;
            return IsExecutableAddress(address) ? reinterpret_cast<T>(address) : nullptr;
        }

        template <typename T>
        T* ResolveData(std::uintptr_t rva, std::size_t bytes = sizeof(T))
        {
            const std::uintptr_t address = g_cw.base + rva;
            return IsReadableAddress(address, bytes) ? reinterpret_cast<T*>(address) : nullptr;
        }

        template <typename T>
        T* ResolveWritableData(std::uintptr_t rva, std::size_t bytes = sizeof(T))
        {
            const std::uintptr_t address = g_cw.base + rva;
            return IsWritableAddress(address, bytes) ? reinterpret_cast<T*>(address) : nullptr;
        }

        std::string DumpHostDescriptorOnGameThread()
        {
            if (!g_cw.getSessionObject)
                return "host descriptor unavailable: Session_GetSessionObject unresolved";

            std::ostringstream out;
            out << "Session objects (cw-mod-v2 native path). Host through the stock System Link/Create Match path first.\n";
            int live = 0;
            for (int type = 0; type < 2; ++type)
            {
                for (unsigned int slot = 0; slot < 3; ++slot)
                {
                    std::uint8_t* object = SafeCallGetSessionObject(g_cw.getSessionObject, type, slot);
                    if (!object) continue;
                    int members = 0;
                    if (!SafeRead(object + kSessMemberCount, members) || members <= 0) continue;
                    ++live;

                    std::int64_t xuid = 0;
                    char name[37]{};
                    std::uint8_t secId[8]{};
                    std::uint8_t secKey[16]{};
                    std::uint8_t adr[84]{};
                    SafeRead(object + kSessHostXuid, xuid);
                    SafeCopy(name, object + kSessHostName, 36);
                    SafeCopy(secId, object + kSessSecId, sizeof(secId));
                    SafeCopy(secKey, object + kSessSecKey, sizeof(secKey));
                    SafeCopy(adr, object + kSessSerializedAdr, sizeof(adr));
                    name[36] = '\0';

                    out << "[type " << type << " slot " << slot << "] members=" << members
                        << " host='" << name << "' xuid=0x" << std::uppercase << std::hex
                        << static_cast<std::uint64_t>(xuid) << std::dec << "\n"
                        << "secid=" << HexBytes(secId, sizeof(secId)) << "\n"
                        << "serializedAdr[0:32]=" << HexBytes(adr, 32) << "\n"
                        << "CWJOIN1 TOKEN:\n"
                        << BuildJoinDescriptorBlob(static_cast<std::uint64_t>(xuid), static_cast<int>(slot),
                            name, secId, secKey, adr) << "\n";
                }
            }
            if (!live)
                out << "No live session slots. Start/host a System Link lobby or match, then run /lan export again.\n";
            return out.str();
        }

        std::string DumpPendingTargetOnGameThread()
        {
            if (!g_cw.pendingValid) return "pending target unavailable: donor globals unresolved";
            bool awaiting = false;
            bool valid = false;
            int nonce = 0;
            SafeRead(g_cw.pendingAwaiting, awaiting);
            SafeRead(g_cw.pendingValid, valid);
            SafeRead(g_cw.pendingNonce, nonce);
            std::ostringstream out;
            out << "g_pendingJoinTarget awaiting=" << (awaiting ? "yes" : "no")
                << " nonce=" << nonce << " valid=" << (valid ? "YES" : "no") << "\n";
            if (valid)
            {
                char name[37]{};
                std::uint8_t adr[84]{};
                SafeCopy(name, g_cw.pendingHostName, 36);
                SafeCopy(adr, g_cw.pendingSerializedAdr, sizeof(adr));
                out << "host='" << name << "' serializedAdr[0:32]=" << HexBytes(adr, 32) << "\n";
            }
            return out.str();
        }

        std::string DumpJoinStateOnGameThread()
        {
            if (!g_cw.joinCtx) return "g_clientJoinCtx unresolved";
            int state = 0, actionId = 0, controller = 0, src = 0, dst = 0, count = 0, index = 0;
            if (!SafeRead(g_cw.joinCtx + kJoinCtxState, state)) return "g_clientJoinCtx read faulted";
            SafeRead(g_cw.joinCtx + kJoinCtxActionId, actionId);
            SafeRead(g_cw.joinCtx + kJoinCtxControllerIdx, controller);
            SafeRead(g_cw.joinCtx + kJoinCtxSrcLobby, src);
            SafeRead(g_cw.joinCtx + kJoinCtxDstLobby, dst);
            SafeRead(g_cw.joinCtx + kJoinCtxHostCount, count);
            SafeRead(g_cw.joinCtx + kJoinCtxHostIdx, index);
            int launch = -1;
            if (g_cw.lobbyLaunchState) SafeRead(g_cw.lobbyLaunchState, launch);

            std::ostringstream out;
            out << "join state=" << state << " (" << JoinStateLabel(state) << ") actionId=0x"
                << std::hex << actionId << std::dec << " controller=" << controller
                << " srcLobby=" << src << " dstLobby=" << dst
                << " candidates=" << count << " index=" << index
                << " lobbyLaunchState=" << launch << "\n";

            int n = count;
            if (n < 0) n = 0;
            if (n > static_cast<int>(kJoinHostMaxCount)) n = static_cast<int>(kJoinHostMaxCount);
            for (int i = 0; i < n; ++i)
            {
                const std::uint8_t* candidate = g_cw.joinCtx + kJoinCtxCandidates +
                    static_cast<std::size_t>(i) * kJoinHostStride;
                char name[37]{};
                char type[37]{};
                std::uint8_t secId[8]{};
                std::uint8_t secKey[16]{};
                std::uint8_t adr[84]{};
                std::int64_t sessionId = 0;
                SafeCopy(name, candidate + kJoinHostName, 36);
                SafeCopy(type, candidate + kJoinHostType, 36);
                SafeCopy(secId, candidate + kJoinHostSecId, sizeof(secId));
                SafeCopy(secKey, candidate + kJoinHostSecKey, sizeof(secKey));
                SafeCopy(adr, candidate + kJoinHostSerializedAdr, sizeof(adr));
                SafeRead(candidate + kJoinHostSessionId, sessionId);
                out << "host[" << i << "] '" << name << "' type='" << type << "' sessionId=0x"
                    << std::hex << static_cast<std::uint64_t>(sessionId) << std::dec
                    << " secid=" << HexBytes(secId, sizeof(secId))
                    << " adr[0:16]=" << HexBytes(adr, 16) << "\n";
            }
            if (n > 0)
            {
                std::uint8_t current[kJoinHostStride]{};
                if (SafeCopy(current, g_cw.joinCtx + kJoinCtxCurrentHost, sizeof(current)))
                {
                    char name[37]{};
                    SafeCopy(name, current + kJoinHostName, 36);
                    out << "current host='" << name << "'\n";
                }
            }
            return out.str();
        }

        bool VtableInModule(const void* object)
        {
            std::uintptr_t vtable = 0;
            return SafeRead(object, vtable) && AddressInImage(vtable);
        }

        std::string DumpSessionStateOnGameThread()
        {
            std::ostringstream out;
            int phase = -1, launchState = -1;
            if (g_cw.hostLaunchPhase) SafeRead(g_cw.hostLaunchPhase, phase);
            if (g_cw.netSessionLaunchState) SafeRead(g_cw.netSessionLaunchState, launchState);
            out << "g_hostLaunchPhase=" << phase << " g_netSessionLaunchState=" << launchState << "\n";
            if (!g_cw.netSessionManager) return out.str() + "g_netSessionManager unresolved\n";

            std::uint8_t* manager = nullptr;
            if (!SafeRead(g_cw.netSessionManager, manager)) return out.str() + "fault reading *g_netSessionManager\n";
            if (!manager) return out.str() + "NetSession manager=NULL; no active LAN session\n";
            out << "manager=0x" << std::hex << reinterpret_cast<std::uintptr_t>(manager) << std::dec
                << " vtable=" << (VtableInModule(manager) ? "live" : "invalid") << "\n";

            std::uint8_t* session = nullptr;
            if (!SafeRead(manager + 672, session)) return out.str() + "fault reading manager+672 session pointer\n";
            if (!session) return out.str() + "active session=NULL; nothing advertising\n";
            out << "session=0x" << std::hex << reinterpret_cast<std::uintptr_t>(session) << std::dec
                << " vtable=" << (VtableInModule(session) ? "live" : "DANGLING") << "\n";
            if (!VtableInModule(session)) return out.str();

            std::string stateHits;
            for (unsigned int offset = 0x100; offset <= 0x400; offset += 4)
            {
                unsigned int value = 0;
                if (SafeRead(session + offset, value) && (value == 1 || value == 2))
                {
                    char hit[48]{};
                    std::snprintf(hit, sizeof(hit), " +0x%X(=%u)", offset, value);
                    stateHits += hit;
                }
            }
            out << "candidate session state offsets (1/2):" << (stateHits.empty() ? " none" : stateHits) << "\n";
            return out.str();
        }

        std::string JoinDescriptorOnGameThread(const std::string& input, int joinType)
        {
            if (!g_cw.initialized.load()) return "Cold War donor LAN bridge is not initialized";
            if (joinType != 1 && joinType != 4) return "jointype must be 1 or 4 (donor default/preferred = 4)";

            std::string reason;
            if (!ValidateJoinBlob(input, reason)) return reason;
            const std::string text = StripJoinBlob(input);

            std::uint8_t xuidBytes[8]{}, slotByte = 0, name[36]{}, secId[8]{}, secKey[16]{}, adr[84]{};
            std::size_t pos = 0;
            if (!HexTake(text, pos, xuidBytes, sizeof(xuidBytes)) ||
                !HexTake(text, pos, &slotByte, 1) ||
                !HexTake(text, pos, name, sizeof(name)) ||
                !HexTake(text, pos, secId, sizeof(secId)) ||
                !HexTake(text, pos, secKey, sizeof(secKey)) ||
                !HexTake(text, pos, adr, sizeof(adr)) || pos != text.size())
                return "descriptor parse failed after validation";

            std::int64_t xuid = 0;
            std::memcpy(&xuid, xuidBytes, sizeof(xuid));
            int state = 0;
            if (g_cw.joinCtx && SafeRead(g_cw.joinCtx + kJoinCtxState, state) && state != 0)
            {
                std::ostringstream out;
                out << "join refused locally: another join is active, state=" << state
                    << " (" << JoinStateLabel(state) << ")";
                return out.str();
            }

            // This is the donor's proven LAN invariant. Keep public socket/DNS filtering untouched.
            LobbyBase_SetNetworkMode(LOBBY_NETWORKMODE_LAN);
            Com_SessionMode_SetMode(1);
            if (g_Addrs.config[0])
            {
                const unsigned char ready = 1;
                SafeWrite(reinterpret_cast<void*>(g_Addrs.config[0]), &ready, 1);
            }
            if (g_Addrs.config[1])
            {
                const unsigned char ready = 1;
                SafeWrite(reinterpret_cast<void*>(g_Addrs.config[1]), &ready, 1);
            }

            const int slotValue = static_cast<int>(slotByte);
            if (!SafeWrite(g_cw.pendingXuid, &xuid, sizeof(xuid)) ||
                !SafeWrite(g_cw.pendingSessionId, &xuid, sizeof(xuid)) ||
                !SafeWrite(g_cw.pendingSlot, &slotValue, sizeof(slotValue)) ||
                !SafeWrite(g_cw.pendingHostName, name, sizeof(name)) ||
                !SafeWrite(g_cw.pendingSecId, secId, sizeof(secId)) ||
                !SafeWrite(g_cw.pendingSecKey, secKey, sizeof(secKey)) ||
                !SafeWrite(g_cw.pendingSerializedAdr, adr, sizeof(adr)))
                return "descriptor target write faulted; no native join was called";

            if (g_cw.pendingAwaiting)
            {
                const bool awaiting = false;
                SafeWrite(g_cw.pendingAwaiting, &awaiting, sizeof(awaiting));
            }
            const bool valid = true;
            if (!SafeWrite(g_cw.pendingValid, &valid, sizeof(valid)))
                return "descriptor valid-flag write faulted; no native join was called";

            DWORD exceptionCode = 0;
            const char accepted = SafeCallJoinPendingTarget(
                g_cw.joinPendingTarget, 0, 0, 0, joinType, exceptionCode);

            char hostName[37]{};
            std::memcpy(hostName, name, 36);
            std::ostringstream out;
            out << "JoinPendingTarget(ctx=0,pad=0,jointype=" << joinType << ") host='" << hostName
                << "' xuid=0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(xuid) << std::dec;
            if (exceptionCode)
                out << " FAULT exception=0x" << std::hex << exceptionCode << std::dec;
            else
                out << (accepted ? " accepted by local join FSM" : " returned false/refused locally");
            out << "; serializedAdr[0:16]=" << HexBytes(adr, 16);
            return out.str();
        }

        void StartJoinWatchInternal()
        {
            if (!g_cw.joinCtx)
            {
                JoinLogAppend("join-watch unavailable: g_clientJoinCtx unresolved");
                return;
            }
            bool expected = false;
            if (!g_joinWatchRunning.compare_exchange_strong(expected, true))
            {
                JoinLogAppend("join-watch already running");
                return;
            }
            std::thread([]
            {
                const auto started = std::chrono::steady_clock::now();
                int last = -1;
                int highest = 0;
                bool complete = false;
                JoinLogAppend("join-watch armed (2ms sampling, 15s window) at " + WallClockNow());
                while (std::chrono::steady_clock::now() - started < std::chrono::seconds(15))
                {
                    int state = -1, count = -1;
                    SafeRead(g_cw.joinCtx + kJoinCtxState, state);
                    SafeRead(g_cw.joinCtx + kJoinCtxHostCount, count);
                    if (state != last)
                    {
                        const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - started).count();
                        std::ostringstream line;
                        line << "join-watch " << WallClockNow() << " +" << micros << "us state "
                            << last << " -> " << state << " (" << JoinStateLabel(state)
                            << ") candidates=" << count;
                        JoinLogAppend(line.str());
                        if (state == 6) complete = true;
                        if (state > highest && state < 6) highest = state;
                        last = state;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
                int finalState = -1, finalCount = -1;
                SafeRead(g_cw.joinCtx + kJoinCtxState, finalState);
                SafeRead(g_cw.joinCtx + kJoinCtxHostCount, finalCount);
                std::ostringstream end;
                end << "join-watch closed complete=" << (complete ? "YES" : "no")
                    << " highest=" << highest << " (" << JoinStateLabel(highest) << ") final="
                    << finalState << " (" << JoinStateLabel(finalState) << ") candidates=" << finalCount;
                JoinLogAppend(end.str());
                g_joinWatchRunning.store(false);
            }).detach();
        }

        void PrintMultiline(const char* prefix, const std::string& text)
        {
            std::istringstream stream(text);
            std::string line;
            while (std::getline(stream, line))
                std::printf("[%s] %s\n", prefix, line.c_str());
            std::fflush(stdout);
        }

        void EngineCmdExport()
        {
            const std::string result = DumpHostDescriptorOnGameThread();
            PrintMultiline("CWMOD-LAN", result);
            JoinLogAppend("host descriptor export completed on game thread");
        }

        void EngineCmdJoin()
        {
            std::string blob;
            int joinType = 4;
            {
                std::lock_guard<std::mutex> lock(g_pendingCommandMutex);
                blob = g_pendingJoinBlob;
                joinType = g_pendingJoinType;
                g_pendingJoinBlob.clear();
            }
            const std::string result = JoinDescriptorOnGameThread(blob, joinType);
            JoinLogAppend(result);
            if (result.find("accepted by local join FSM") != std::string::npos)
                StartJoinWatchInternal();
        }

        void EngineCmdPending() { PrintMultiline("CWMOD-LAN", DumpPendingTargetOnGameThread()); }
        void EngineCmdJoinState() { PrintMultiline("CWMOD-LAN", DumpJoinStateOnGameThread()); }
        void EngineCmdSession() { PrintMultiline("CWMOD-LAN", DumpSessionStateOnGameThread()); }

        __declspec(noinline) bool RegisterEngineCommandsSeh(DWORD& exceptionCode) noexcept
        {
            exceptionCode = 0;
            __try
            {
                Cmd_AddCommandInternal("cr_cwlan_export", &EngineCmdExport, &g_exportCmd);
                Cmd_AddCommandInternal("cr_cwlan_join", &EngineCmdJoin, &g_joinCmd);
                Cmd_AddCommandInternal("cr_cwlan_pending", &EngineCmdPending, &g_pendingCmd);
                Cmd_AddCommandInternal("cr_cwlan_joinstate", &EngineCmdJoinState, &g_joinStateCmd);
                Cmd_AddCommandInternal("cr_cwlan_session", &EngineCmdSession, &g_sessionCmd);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                exceptionCode = GetExceptionCode();
                return false;
            }
        }

        bool RegisterEngineCommands(std::string& message)
        {
            if (g_cw.commandsRegistered.load())
            {
                message = "cw-mod-v2 engine-thread commands already registered";
                return true;
            }
            if (!g_Addrs.ModuleBase || !IsExecutableAddress(g_Addrs.ModuleBase + t9_addresses::Retail.Cmd_AddCommandInternal))
            {
                message = "Cmd_AddCommandInternal is not ready";
                return false;
            }
            DWORD exceptionCode = 0;
            if (!RegisterEngineCommandsSeh(exceptionCode))
            {
                char buffer[128]{};
                std::snprintf(buffer, sizeof(buffer), "Cmd_AddCommandInternal faulted: 0x%08lX",
                    static_cast<unsigned long>(exceptionCode));
                message = buffer;
                return false;
            }
            g_cw.commandsRegistered.store(true);
            message = "registered cr_cwlan_export/join/pending/joinstate/session on the engine command thread";
            return true;
        }

        bool QueueInternalCommand(const char* command, std::string& message)
        {
            if (!g_cw.commandsRegistered.load())
            {
                message = "cw-mod-v2 engine-thread commands are not registered";
                return false;
            }
            if (!core_runtime::DeveloperCommandReady())
            {
                message = "validated Cbuf_AddText is not ready";
                return false;
            }
            if (!core_runtime::QueueDeveloperCommand(command))
            {
                message = std::string("failed to queue engine command: ") + command;
                return false;
            }
            message = std::string("queued on T9 engine command thread: ") + command;
            return true;
        }

        const char* NetMsgName(int id)
        {
            if (!g_cw.netMsgNames || id < 0 || id >= 35) return "?";
            const char* value = nullptr;
            if (!SafeRead(&g_cw.netMsgNames[id], value) || !value) return "?";
            return IsReadableAddress(reinterpret_cast<std::uintptr_t>(value), 1) ? value : "?";
        }

        bool NetMsgWorthLogging(int id) { return id != 30 && id != 31; }

        char __fastcall HookNetMsgDispatch(unsigned int localClient, void* netadr, void* a3, void* msg)
        {
            int id = -1;
            if (msg) SafeRead(static_cast<std::uint8_t*>(msg) + kNetMsgIdOffset, id);
            const bool log = NetMsgWorthLogging(id);
            std::uint8_t adr[16]{};
            int before = -1;
            if (log)
            {
                SafeCopy(adr, netadr, sizeof(adr));
                if (g_cw.joinCtx) SafeRead(g_cw.joinCtx + kJoinCtxState, before);
            }
            const char result = g_origNetMsgDispatch ? g_origNetMsgDispatch(localClient, netadr, a3, msg) : 0;
            if (log)
            {
                int after = -1;
                if (g_cw.joinCtx) SafeRead(g_cw.joinCtx + kJoinCtxState, after);
                std::ostringstream line;
                line << "netmsg " << WallClockNow() << " recv id=" << id << " " << NetMsgName(id)
                    << " from=" << HexBytes(adr, sizeof(adr)) << " client=" << localClient
                    << " handled=" << (result ? "yes" : "NO");
                if (before != after) line << " joinState " << before << "->" << after << " (" << JoinStateLabel(after) << ")";
                if (id == 17 && g_cw.joinResponseCode)
                {
                    int code = -1;
                    if (SafeRead(g_cw.joinResponseCode, code))
                        line << " verdict=" << code << " (" << JoinResponseLabel(code) << ")";
                }
                JoinLogAppend(line.str());
            }
            return result;
        }

        bool __fastcall HookParseJoinLobbyRequest(void* block, void* msg)
        {
            const bool ok = g_origParseJoinReq ? g_origParseJoinReq(block, msg) : false;
            if (!ok || !block)
            {
                JoinLogAppend("netmsg JoinLobby request parse failed");
                return ok;
            }
            auto i32 = [block](std::size_t offset)
            {
                int value = -1;
                SafeRead(static_cast<std::uint8_t*>(block) + offset, value);
                return value;
            };
            const int joinType = i32(kJoinReqJoinType);
            const int networkMode = i32(kJoinReqNetworkMode);
            std::ostringstream line;
            line << "netmsg " << WallClockNow() << " JoinLobby request"
                << " target=" << i32(kJoinReqTargetLobby)
                << " source=" << i32(kJoinReqSourceLobby)
                << " jointype=" << joinType
                << " members=" << i32(kJoinReqMemberCount)
                << " splitscreen=" << i32(kJoinReqSplitScreen)
                << " networkmode=" << networkMode
                << " playlistid=" << i32(kJoinReqPlaylistId)
                << " playlistver=" << i32(kJoinReqPlaylistVer)
                << " playlistchecksum=" << i32(kJoinReqPlaylistChecksum)
                << " ffotd=" << i32(kJoinReqFfotdVer)
                << " netchecksum=" << i32(kJoinReqNetChecksum)
                << " featurechecksum=" << i32(kJoinReqFeatureChecksum)
                << " tu=" << i32(kJoinReqTuVersion)
                << " protocol=" << i32(kJoinReqProtocol)
                << " changelist=" << i32(kJoinReqChangelist);
            JoinLogAppend(line.str());
            if (networkMode != 1 || (joinType != 1 && joinType != 4))
                JoinLogAppend("netmsg JoinLobby will hit refusal 36: LAN requires networkmode=1 and jointype=1 or 4");
            return ok;
        }

        bool __fastcall HookSendJoinResponse(int a1, int a2, int a3, void* netadr, void* a5, void* response)
        {
            int code = -1, lobbyType = -1, networkMode = -1, mainMode = -1;
            char name[37]{};
            std::uint8_t adr[16]{};
            if (response)
            {
                auto* bytes = static_cast<std::uint8_t*>(response);
                SafeRead(bytes + kJoinRespCode, code);
                SafeCopy(name, bytes + kJoinRespName, 36);
                SafeRead(bytes + kJoinRespLobbyType, lobbyType);
                SafeRead(bytes + kJoinRespNetworkMode, networkMode);
                SafeRead(bytes + kJoinRespMainMode, mainMode);
            }
            SafeCopy(adr, netadr, sizeof(adr));
            std::ostringstream line;
            line << "netmsg " << WallClockNow() << " SEND JoinResponse to=" << HexBytes(adr, sizeof(adr))
                << " verdict=" << code << " (" << JoinResponseLabel(code) << ")"
                << " name='" << name << "' lobbyType=" << lobbyType
                << " networkMode=" << networkMode << " mainMode=" << mainMode;
            JoinLogAppend(line.str());
            return g_origSendJoinResponse ? g_origSendJoinResponse(a1, a2, a3, netadr, a5, response) : false;
        }
    }

    void Initialize(games::GameKind game)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_status.initialized = true;
        g_status.game = game;
        g_status.publicNetworkBlockerExpected = true;
        g_status.defaultGamePort = 3074;
        g_status.defaultQueryPort = 3075;
        WriteStatusLog();
        std::printf("[UNIVERSAL-LAN] %s foundation ready. Private/loopback endpoints allowed; shared public DNS/network blocker remains active.\n", GameName(game));
        std::fflush(stdout);
    }

    Status GetStatus()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_status;
    }

    bool IsPrivateOrLoopbackIPv4(std::uint32_t hostOrderAddress)
    {
        const auto a = static_cast<unsigned int>((hostOrderAddress >> 24) & 0xFF);
        const auto b = static_cast<unsigned int>((hostOrderAddress >> 16) & 0xFF);
        if (a == 127 || a == 10) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        if (a == 169 && b == 254) return true;
        return false;
    }

    bool ParsePrivateEndpoint(const std::string& text, std::string& host, std::uint16_t& port, std::string& error)
    {
        host.clear(); error.clear(); port = 3074;
        if (text.empty()) { error = "empty endpoint"; return false; }
        const auto colon = text.rfind(':');
        if (colon != std::string::npos && text.find(':') == colon)
        {
            host = text.substr(0, colon);
            const auto portText = text.substr(colon + 1);
            char* end = nullptr;
            const auto parsed = std::strtoul(portText.c_str(), &end, 10);
            if (!end || *end || parsed == 0 || parsed > 65535) { error = "invalid port"; return false; }
            port = static_cast<std::uint16_t>(parsed);
        }
        else host = text;
        IN_ADDR address{};
        if (InetPtonA(AF_INET, host.c_str(), &address) != 1)
        {
            error = "endpoint must currently be a literal IPv4 address";
            return false;
        }
        if (!IsPrivateOrLoopbackIPv4(ntohl(address.S_un.S_addr)))
        {
            error = "public IPv4 endpoints are rejected by Universal LAN";
            return false;
        }
        return true;
    }

    void PrintStatus()
    {
        const auto status = GetStatus();
        std::printf("[UNIVERSAL-LAN] initialized=%s game=%s gamePort=%u queryPort=%u publicBlockerExpected=%s\n",
            status.initialized ? "yes" : "no", GameName(status.game),
            static_cast<unsigned int>(status.defaultGamePort), static_cast<unsigned int>(status.defaultQueryPort),
            status.publicNetworkBlockerExpected ? "yes" : "no");
        if (status.game == games::GameKind::Retail)
            std::printf("[UNIVERSAL-LAN] %s\n", ColdWarRetailBridgeStatus().c_str());
        std::fflush(stdout);
    }

    bool InitializeColdWarRetailBridge(std::string& message)
    {
        if (g_cw.initialized.load()) return RegisterEngineCommands(message);
        if (GetStatus().game != games::GameKind::Retail)
        {
            message = "cw-mod-v2 bridge is Retail-only";
            return false;
        }
        const std::uintptr_t base = g_Addrs.ModuleBase;
        std::uintptr_t imageEnd = 0;
        if (!ExactRetailFingerprint(base, imageEnd))
        {
            message = "cw-mod-v2 bridge refused: executable fingerprint is not T9 Retail 1.34.0.15931218";
            return false;
        }
        g_cw.base = base;
        g_cw.imageEnd = imageEnd;
        g_cw.getSessionObject = ResolveCode<SessionGetSessionObjectFn>(kRvaSessionGetSessionObject);
        g_cw.joinPendingTarget = ResolveCode<JoinPendingTargetFn>(kRvaClientSessionJoinPendingTarget);
        g_cw.joinCtx = ResolveData<std::uint8_t>(kRvaClientJoinCtx);
        g_cw.pendingAwaiting = ResolveWritableData<bool>(kRvaPendingAwaiting);
        g_cw.pendingNonce = ResolveData<int>(kRvaPendingNonce);
        g_cw.pendingXuid = ResolveWritableData<std::int64_t>(kRvaPendingXuid);
        g_cw.pendingValid = ResolveWritableData<bool>(kRvaPendingValid);
        g_cw.pendingSessionId = ResolveWritableData<std::int64_t>(kRvaPendingSessionId);
        g_cw.pendingHostName = ResolveWritableData<char>(kRvaPendingHostName, 36);
        g_cw.pendingSlot = ResolveWritableData<int>(kRvaPendingSlot);
        g_cw.pendingSecId = ResolveWritableData<std::uint8_t>(kRvaPendingSecId, 8);
        g_cw.pendingSecKey = ResolveWritableData<std::uint8_t>(kRvaPendingSecKey, 16);
        g_cw.pendingSerializedAdr = ResolveWritableData<std::uint8_t>(kRvaPendingSerializedAdr, 84);
        g_cw.lobbyLaunchState = ResolveData<int>(kRvaLobbyLaunchState);
        g_cw.netSessionManager = ResolveData<std::uint8_t*>(kRvaNetSessionManager);
        g_cw.netSessionLaunchState = ResolveData<int>(kRvaNetSessionLaunchState);
        g_cw.hostLaunchPhase = ResolveData<int>(kRvaHostLaunchPhase);
        g_cw.netMsgDispatch = ResolveCode<void*>(kRvaNetMsgDispatch);
        g_cw.netMsgSendJoinResponse = ResolveCode<void*>(kRvaNetMsgSendJoinResponse);
        g_cw.parseJoinLobbyRequest = ResolveCode<void*>(kRvaSessionParseJoinLobbyRequest);
        g_cw.netMsgNames = ResolveData<void*>(kRvaNetMsgNames, sizeof(void*) * 35);
        g_cw.joinResponseCode = ResolveData<int>(kRvaJoinResponseCode);
        g_cw.expectedHostAdr = ResolveData<std::uint8_t>(kRvaExpectedHostAdr, 16);

        const bool critical = g_cw.getSessionObject && g_cw.joinPendingTarget && g_cw.joinCtx &&
            g_cw.pendingXuid && g_cw.pendingValid && g_cw.pendingSessionId && g_cw.pendingHostName &&
            g_cw.pendingSlot && g_cw.pendingSecId && g_cw.pendingSecKey && g_cw.pendingSerializedAdr;
        if (!critical)
        {
            message = "cw-mod-v2 bridge refused: one or more critical donor anchors are not mapped/readable/executable";
            return false;
        }
        g_cw.initialized.store(true);
        std::string commandMessage;
        const bool commands = RegisterEngineCommands(commandMessage);
        std::ostringstream out;
        out << "cw-mod-v2 native LAN bridge READY; descriptor export/join anchors validated; "
            << commandMessage << "; public network blocker unchanged";
        message = out.str();
        return commands;
    }

    bool ColdWarRetailBridgeReady() { return g_cw.initialized.load() && g_cw.commandsRegistered.load(); }

    std::string ColdWarRetailBridgeStatus()
    {
        std::ostringstream out;
        out << "cw-mod-v2 bridge initialized=" << (g_cw.initialized.load() ? "yes" : "no")
            << " commands=" << (g_cw.commandsRegistered.load() ? "yes" : "no")
            << " descriptorJoin=" << (g_cw.joinPendingTarget ? "ready" : "unresolved")
            << " hostDescriptor=" << (g_cw.getSessionObject ? "ready" : "unresolved")
            << " netmsgTranscript=" << (g_netMsgTranscriptOn.load() ? "ON" : "off")
            << " blocker=ON";
        return out.str();
    }

    bool QueueColdWarHostDescriptor(std::string& message)
    {
        if (!g_cw.commandsRegistered.load() && !InitializeColdWarRetailBridge(message)) return false;
        return QueueInternalCommand("cr_cwlan_export", message);
    }

    bool QueueColdWarDescriptorJoin(const std::string& blob, int joinType, std::string& message)
    {
        if (joinType != 1 && joinType != 4)
        {
            message = "jointype must be 1 or 4; use 4 unless testing playlist-specific join behavior";
            return false;
        }
        std::string validation;
        if (!ValidateJoinBlob(blob, validation)) { message = validation; return false; }
        if (!g_cw.commandsRegistered.load() && !InitializeColdWarRetailBridge(message)) return false;
        {
            std::lock_guard<std::mutex> lock(g_pendingCommandMutex);
            g_pendingJoinBlob = blob;
            g_pendingJoinType = joinType;
        }
        return QueueInternalCommand("cr_cwlan_join", message);
    }

    bool QueueColdWarPendingTargetDump(std::string& message)
    {
        if (!g_cw.commandsRegistered.load() && !InitializeColdWarRetailBridge(message)) return false;
        return QueueInternalCommand("cr_cwlan_pending", message);
    }

    bool QueueColdWarJoinStateDump(std::string& message)
    {
        if (!g_cw.commandsRegistered.load() && !InitializeColdWarRetailBridge(message)) return false;
        return QueueInternalCommand("cr_cwlan_joinstate", message);
    }

    bool QueueColdWarSessionStateDump(std::string& message)
    {
        if (!g_cw.commandsRegistered.load() && !InitializeColdWarRetailBridge(message)) return false;
        return QueueInternalCommand("cr_cwlan_session", message);
    }

    void StartColdWarJoinWatch() { StartJoinWatchInternal(); }

    bool InstallColdWarNetMsgTranscript(std::string& message)
    {
        if (g_netMsgTranscriptOn.load()) { message = "netmsg transcript already ON"; return true; }
        if (!g_cw.commandsRegistered.load() && !InitializeColdWarRetailBridge(message)) return false;
        if (!g_cw.netMsgDispatch || !g_cw.netMsgSendJoinResponse)
        {
            message = "netmsg transcript anchors unresolved";
            return false;
        }
        const MH_STATUS init = MH_Initialize();
        if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
        {
            message = "MinHook initialization failed";
            return false;
        }
        MH_STATUS status = MH_CreateHook(g_cw.netMsgDispatch,
            reinterpret_cast<void*>(&HookNetMsgDispatch), reinterpret_cast<void**>(&g_origNetMsgDispatch));
        if (status != MH_OK)
        {
            message = "failed to create NetMsg_Dispatch hook";
            return false;
        }
        status = MH_EnableHook(g_cw.netMsgDispatch);
        if (status != MH_OK)
        {
            MH_RemoveHook(g_cw.netMsgDispatch);
            g_origNetMsgDispatch = nullptr;
            message = "failed to enable NetMsg_Dispatch hook";
            return false;
        }

        status = MH_CreateHook(g_cw.netMsgSendJoinResponse,
            reinterpret_cast<void*>(&HookSendJoinResponse), reinterpret_cast<void**>(&g_origSendJoinResponse));
        if (status == MH_OK) MH_EnableHook(g_cw.netMsgSendJoinResponse);

        if (g_cw.parseJoinLobbyRequest)
        {
            status = MH_CreateHook(g_cw.parseJoinLobbyRequest,
                reinterpret_cast<void*>(&HookParseJoinLobbyRequest), reinterpret_cast<void**>(&g_origParseJoinReq));
            if (status == MH_OK) MH_EnableHook(g_cw.parseJoinLobbyRequest);
        }
        g_netMsgTranscriptOn.store(true);
        JoinLogAppend("post-decryption netmsg transcript INSTALLED (dispatch + JoinResponse + JoinLobby parser when available)");
        message = "cw-mod-v2 netmsg transcript ON; logs -> logs\\network\\cwmod_lan_join.log";
        return true;
    }

    bool RemoveColdWarNetMsgTranscript(std::string& message)
    {
        if (!g_netMsgTranscriptOn.load()) { message = "netmsg transcript already off"; return true; }
        if (g_cw.netMsgDispatch) { MH_DisableHook(g_cw.netMsgDispatch); MH_RemoveHook(g_cw.netMsgDispatch); }
        if (g_cw.netMsgSendJoinResponse) { MH_DisableHook(g_cw.netMsgSendJoinResponse); MH_RemoveHook(g_cw.netMsgSendJoinResponse); }
        if (g_cw.parseJoinLobbyRequest) { MH_DisableHook(g_cw.parseJoinLobbyRequest); MH_RemoveHook(g_cw.parseJoinLobbyRequest); }
        g_origNetMsgDispatch = nullptr;
        g_origSendJoinResponse = nullptr;
        g_origParseJoinReq = nullptr;
        g_netMsgTranscriptOn.store(false);
        JoinLogAppend("post-decryption netmsg transcript REMOVED; stock handlers restored");
        message = "cw-mod-v2 netmsg transcript off";
        return true;
    }

    bool ColdWarNetMsgTranscriptInstalled() { return g_netMsgTranscriptOn.load(); }

    std::string ColdWarJoinTranscript()
    {
        std::lock_guard<std::mutex> lock(g_joinLogMutex);
        return g_joinLog.empty() ? "(no cw-mod-v2 join events captured yet)" : g_joinLog;
    }
}
