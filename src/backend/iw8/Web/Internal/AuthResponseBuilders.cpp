#include "AuthResponseBuilders.h"

namespace revamped::iw8::web
{
    namespace
    {
        bool LsgForceTestEnabled()
        {
            char value[8]{};
            const DWORD count = GetEnvironmentVariableA("CODREVAMPED_FORCE_LSG_TEST", value, static_cast<DWORD>(sizeof(value)));
            return count != 0 && value[0] == '1';
        }

        enum class LocalIw8Build
        {
            Unknown,
            MW120,
            MW123,
            MW128,
            MW144
        };

        struct LocalIw8BuildProbe
        {
            LocalIw8Build build = LocalIw8Build::Unknown;
            std::uint32_t timestamp = 0;
            std::uint32_t imageSize = 0;
            std::uint32_t entryPoint = 0;
            std::string source;
        };

        LocalIw8Build ClassifyLocalIw8Build(std::uint32_t ts, std::uint32_t image, std::uint32_t ep)
        {
            if (ts == 0x5E9BAF80u && image == 0x1324B000u && ep == 0x021CDC10u)
                return LocalIw8Build::MW120;
            if (ts == 0x5EFCF351u && image == 0x19A42C00u && ep == 0x0493E908u)
                return LocalIw8Build::MW123;
            if (ts == 0x5F8DEF10u && image == 0x1D02BC00u && ep == 0x048D8F78u)
                return LocalIw8Build::MW128;
            if (ts == 0x61671CE8u && image == 0x22C1BA00u)
                return LocalIw8Build::MW144;
            return LocalIw8Build::Unknown;
        }

        bool ReadLocalIw8BuildFromExe(const char* path, LocalIw8BuildProbe& probe)
        {
            if (!path || !*path)
                return false;

            std::FILE* f = nullptr;
#if defined(_WIN32)
            if (fopen_s(&f, path, "rb") != 0 || !f)
                return false;
#else
            f = std::fopen(path, "rb");
            if (!f)
                return false;
#endif

            IMAGE_DOS_HEADER dos{};
            if (std::fread(&dos, 1, sizeof(dos), f) != sizeof(dos) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
            {
                std::fclose(f);
                return false;
            }

            if (std::fseek(f, dos.e_lfanew, SEEK_SET) != 0)
            {
                std::fclose(f);
                return false;
            }

            IMAGE_NT_HEADERS64 nt{};
            const bool ok = std::fread(&nt, 1, sizeof(nt), f) == sizeof(nt);
            std::fclose(f);
            if (!ok || nt.Signature != IMAGE_NT_SIGNATURE ||
                nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                return false;
            }

            const std::uint32_t ts = nt.FileHeader.TimeDateStamp;
            const std::uint32_t image = nt.OptionalHeader.SizeOfImage;
            const std::uint32_t ep = nt.OptionalHeader.AddressOfEntryPoint;
            const LocalIw8Build build = ClassifyLocalIw8Build(ts, image, ep);
            if (build == LocalIw8Build::Unknown)
                return false;

            probe.build = build;
            probe.timestamp = ts;
            probe.imageSize = image;
            probe.entryPoint = ep;
            probe.source = path;
            return true;
        }

        std::string DirectoryOfPath(const char* path)
        {
            if (!path || !*path)
                return {};
            std::string result(path);
            const std::size_t slash = result.find_last_of("\\/");
            if (slash == std::string::npos)
                return {};
            result.resize(slash);
            return result;
        }

        std::string JoinWindowsPath(const std::string& dir, const char* name)
        {
            if (dir.empty())
                return name ? std::string(name) : std::string();
            std::string result = dir;
            if (result.back() != '\\' && result.back() != '/')
                result.push_back('\\');
            if (name)
                result += name;
            return result;
        }

#if defined(_WIN32)
        bool ScanDirectoryForKnownIw8Exe(const std::string& dir, LocalIw8BuildProbe& probe)
        {
            const std::string pattern = JoinWindowsPath(dir, "*.exe");
            WIN32_FIND_DATAA data{};
            HANDLE find = FindFirstFileA(pattern.c_str(), &data);
            if (find == INVALID_HANDLE_VALUE)
                return false;

            bool found = false;
            do
            {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                    continue;
                const std::string candidate = JoinWindowsPath(dir, data.cFileName);
                if (ReadLocalIw8BuildFromExe(candidate.c_str(), probe))
                {
                    found = true;
                    break;
                }
            } while (FindNextFileA(find, &data));

            FindClose(find);
            return found;
        }
#endif

        const LocalIw8BuildProbe& LocalIw8BuildProbeState()
        {
            // Cache after the first Auth3 request.  The server and stock client are
            // normally launched from the same preservation folder, but older IW8
            // builds do not always use ModernWarfare.exe as the image name (1.20
            // is observed here as game_dx12_ship_replay.exe).  Probe the known
            // names first, then shallow-scan the current/server directories by PE
            // fingerprint.  This only chooses protocol semantics; it never writes
            // client state or patches the game.
            static const LocalIw8BuildProbe cached = []() -> LocalIw8BuildProbe
            {
                LocalIw8BuildProbe probe{};

#if defined(_WIN32)
                char overridePath[MAX_PATH * 4]{};
                const DWORD overrideLen = GetEnvironmentVariableA(
                    "CODREVAMPED_IW8_EXE", overridePath, static_cast<DWORD>(sizeof(overridePath)));
                if (overrideLen != 0 && overrideLen < sizeof(overridePath) &&
                    ReadLocalIw8BuildFromExe(overridePath, probe))
                {
                    return probe;
                }
#endif

                static constexpr const char* kKnownNames[] =
                {
                    "game_dx12_ship_replay.exe",
                    "ModernWarfare.exe",
                    "game_dx12_ship.exe"
                };

                for (const char* name : kKnownNames)
                {
                    if (ReadLocalIw8BuildFromExe(name, probe))
                        return probe;
                }

#if defined(_WIN32)
                char currentDir[MAX_PATH * 4]{};
                if (GetCurrentDirectoryA(static_cast<DWORD>(sizeof(currentDir)), currentDir) != 0)
                {
                    const std::string cwd(currentDir);
                    for (const char* name : kKnownNames)
                    {
                        const std::string candidate = JoinWindowsPath(cwd, name);
                        if (ReadLocalIw8BuildFromExe(candidate.c_str(), probe))
                            return probe;
                    }
                    if (ScanDirectoryForKnownIw8Exe(cwd, probe))
                        return probe;
                }

                char serverPath[MAX_PATH * 4]{};
                if (GetModuleFileNameA(nullptr, serverPath, static_cast<DWORD>(sizeof(serverPath))) != 0)
                {
                    const std::string serverDir = DirectoryOfPath(serverPath);
                    if (!serverDir.empty())
                    {
                        for (const char* name : kKnownNames)
                        {
                            const std::string candidate = JoinWindowsPath(serverDir, name);
                            if (ReadLocalIw8BuildFromExe(candidate.c_str(), probe))
                                return probe;
                        }
                        if (ScanDirectoryForKnownIw8Exe(serverDir, probe))
                            return probe;
                    }
                }
#endif

                return probe;
            }();
            return cached;
        }

        LocalIw8Build DetectLocalIw8Build()
        {
            return LocalIw8BuildProbeState().build;
        }

        const char* LocalIw8BuildSource()
        {
            const auto& probe = LocalIw8BuildProbeState();
            return probe.source.empty() ? "<not-found>" : probe.source.c_str();
        }

        const char* LocalIw8BuildName(LocalIw8Build build)
        {
            switch (build)
            {
            case LocalIw8Build::MW120: return "1.20";
            case LocalIw8Build::MW123: return "1.23";
            case LocalIw8Build::MW128: return "1.28";
            case LocalIw8Build::MW144: return "1.44";
            default: return "unknown";
            }
        }

        bool UsesLegacyUmbrellaHandoff(LocalIw8Build build)
        {
            return build == LocalIw8Build::MW120 ||
                   build == LocalIw8Build::MW123 ||
                   build == LocalIw8Build::MW128;
        }

        #pragma pack(push, 1)
        struct DwAuthTicket

        {
            std::uint32_t magicNumber;
            std::uint8_t type;
            std::uint32_t titleId;
            std::uint32_t timeIssued;
            std::uint32_t timeExpires;
            std::uint64_t licenseId;
            std::uint64_t userId;
            char username[64];
            std::uint8_t sessionKey[24];
            std::uint8_t usingHashMagicNumber[3];
            std::uint8_t hash[4];
        };
        #pragma pack(pop)
        static_assert(sizeof(DwAuthTicket) == 128, "Demonware auth ticket must be 128 bytes");

        // V67: /v1.0/tokens/lsg/ is an exchange, not an echo.  The stock
        // client presents Auth3 server_ticket to Umbrella as its request
        // credential.  That server ticket is intentionally opaque (our local
        // form carries the 24-byte Auth3 key at byte 0), so handing it back as
        // the LSG token leaves bdLobby without a structured ticket/session key
        // to consume.  Mint a fresh 128-byte DW ticket for the LSG handoff,
        // preserving the already-proven Auth3 identity fields when available
        // and binding it to the exact same session key used by ServerLsg.
        std::string BuildLocalLsgTokenV67(std::uint32_t titleId)
        {
            DwAuthTicket ticket{};

            // Reuse the accepted Auth3 client-ticket identity payload when it
            // is available.  Do not trust/copy its timing or key material below.
            std::vector<std::uint8_t> auth3ClientRaw;
            if (!g_authPipeline.lastAuth3ClientTicket.empty() &&
                Base64Decode(g_authPipeline.lastAuth3ClientTicket, auth3ClientRaw) &&
                auth3ClientRaw.size() == sizeof(DwAuthTicket) &&
                ReadPackedU32(auth3ClientRaw, 0u) == 0xEFBDADDEu)
            {
                std::memcpy(&ticket, auth3ClientRaw.data(), sizeof(ticket));
            }

            ticket.magicNumber = 0xEFBDADDEu;
            ticket.type = 0;
            ticket.titleId = titleId;
            ticket.timeIssued = static_cast<std::uint32_t>(std::time(nullptr));
            ticket.timeExpires = ticket.timeIssued + 30000u;
            std::memcpy(ticket.sessionKey, kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const auto* bytes = reinterpret_cast<const std::uint8_t*>(&ticket);
            return Base64Encode(std::vector<std::uint8_t>(bytes, bytes + sizeof(ticket)));
        }

        std::string BuildDwBnetAuthResponse(const std::string& requestTask, const std::string& ivSeed,
            std::uint32_t titleId, const std::string& identity, const std::string& serviceLevel,
            const std::string& sessionToken)
        {
            // V72: remember the exact Auth3 IV-seed representation supplied by
            // stock IW8.  It is only used as a bounded candidate source later.
            g_authPipeline.lastAuth3IvSeed = ivSeed;
            // Battle.net-era Auth3 (T8 and later) uses the same 128-byte ticket
            // container but, unlike the older Steam Auth3 path, returns this
            // client ticket as raw bytes encoded with base64. Keep the session key
            // local and deterministic for the next lobby-service correlation step.
            DwAuthTicket ticket{};
            ticket.magicNumber = 0xEFBDADDEu;
            ticket.type = 0;
            ticket.titleId = titleId;
            ticket.timeIssued = static_cast<std::uint32_t>(std::time(nullptr));
            ticket.timeExpires = ticket.timeIssued + 30000u;
            ticket.licenseId = 0;
            ticket.userId = 0;
            const std::size_t usernameBytes = (std::min)(sessionToken.size(), sizeof(ticket.username) - 1u);
            if (usernameBytes != 0)
                std::memcpy(ticket.username, sessionToken.data(), usernameBytes);
            const std::string ticketUsername(ticket.username, usernameBytes);
            std::memcpy(ticket.sessionKey, kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const auto* ticketBytes = reinterpret_cast<const std::uint8_t*>(&ticket);
            std::vector<std::uint8_t> clientTicket(ticketBytes, ticketBytes + sizeof(ticket));
            std::vector<std::uint8_t> serverTicket(128u, 0u);
            std::memcpy(serverTicket.data(), kLocalAuth3SessionKey, sizeof(kLocalAuth3SessionKey));

            const std::string clientB64 = Base64Encode(clientTicket);
            const std::string serverB64 = Base64Encode(serverTicket);
            const std::string extendedB64 = Base64Encode(std::vector<std::uint8_t>{'l','u','l'});
            RememberAuth3Tickets(clientB64, serverB64, titleId);

            unsigned long taskValue = 84u;
            if (!requestTask.empty())
            {
                char* end = nullptr;
                const unsigned long parsed = std::strtoul(requestTask.c_str(), &end, 10);
                if (end && *end == '\0') taskValue = parsed;
            }
            const std::string responseTask = std::to_string(taskValue + 1u);

            std::ostringstream nested;
            nested << "{\"username\":\"" << JsonEscape(ticketUsername)
                   << "\",\"time_to_live\":9999,\"extended_data\":\"" << extendedB64 << "\"}";

            const LocalIw8Build localBuild = DetectLocalIw8Build();
            const bool legacyUmbrellaHandoff = UsesLegacyUmbrellaHandoff(localBuild);
            // Native 1.20/1.23/1.28 state 5 reads loginData+0x68A4 after
            // Auth3 completes: nonzero selects the Umbrella crossplay branch,
            // zero selects legacy login.  Auth3 owns that byte through the
            // crossplay_enabled response field, so enable it for the builds
            // whose native handoff is AUTH3 -> Umbrella -> LSG.
            const bool crossplayEnabled = legacyUmbrellaHandoff || LsgForceTestEnabled();

            std::ostringstream json;
            json << "{\"auth_task\":\"" << responseTask
                 << "\",\"code\":\"700\",\"iv_seed\":\"" << JsonEscape(ivSeed)
                 << "\",\"client_ticket\":\"" << clientB64
                 << "\",\"server_ticket\":\"" << serverB64
                  // ModernWarfare.exe 1.44 carries this exact Auth3 client ID.
                  // A project-name expansion looks plausible but is rejected by
                  // the stock response validator before DW state can advance.
                  << "\",\"client_id\":\"iw-cod-iw8-bnet\""
                 << ",\"account_type\":\"bnet\""
                 << ",\"crossplay_enabled\":" << (crossplayEnabled ? "true" : "false")
                 << ",\"loginqueue_enabled\":false"
                 << ",\"identity\":\"" << JsonEscape(identity) << "\""
                 << ",\"extra_data\":\"" << JsonEscape(nested.str()) << "\""
                 // BNet Auth3 returns the granted service level.  The known T8
                 // implementation returns "paid" even when the incoming request
                 // advertises "free"; IW8 is now probed with that exact behavior.
                 << ",\"service_level\":\"paid\""
                 // 1.20/1.23/1.28 use the older native flow: Auth3 success is
                 // followed by the Umbrella /v1.0/tokens/crossplatform/ exchange,
                 // whose response supplies camelCase lsgEndpoint.  Keep Auth3's
                 // lsg_endpoint null on those builds so the 1.44 direct-endpoint
                 // workaround cannot short-circuit or invalidate that parser path.
                 // Exact 1.44 retains the runtime-proven direct host advertisement.
                 ;
            if (legacyUmbrellaHandoff)
                json << ",\"lsg_endpoint\":null";
            else
                json << ",\"lsg_endpoint\":\"mw-lobby-1.prod.demonware.net\"";
            if (LsgForceTestEnabled())
            {
                // TEST-ONLY compatibility probe for encrypted 1.44: advertise both
                // naming conventions and an explicit port while also enabling the
                // crossplay branch. Unknown JSON fields are intentionally isolated
                // behind /LSG and disappear again with /LSG OFF.
                json << ",\"lsgEndpoint\":\"mw-lobby-1.prod.demonware.net\""
                     << ",\"lsg_port\":3074"
                     << ",\"lsgPort\":3074"
                     << ",\"crossPlatformProgressionEnabled\":true";
            }
            json << "}";
            return json.str();
        }

        std::string BuildResponse(int status, const char* reason, const char* contentType,
            const std::string& body)
        {
            std::ostringstream out;
            out << "HTTP/1.1 " << status << ' ' << (reason ? reason : "") << "\r\n"
                << "Content-Type: " << (contentType ? contentType : "application/octet-stream") << "\r\n"
                << "Cache-Control: no-store\r\n"
                << "Pragma: no-cache\r\n"
                << "Content-Length: " << body.size() << "\r\n"
                << "Connection: close\r\n"
                << "\r\n"
                << body;
            return out.str();
        }

        std::string BuildDwAuthResponse(const std::string& body)
        {
            // Match the Battle.net-era Demonware Auth3 HTTP envelope used by the
            // known working T8 emulator.  Keep this isolated to /auth/ so the
            // rest of the local web endpoints retain the stricter no-store policy.
            char date[64]{};
            const std::time_t now = std::time(nullptr);
            std::tm utc{};
#if defined(_WIN32)
            gmtime_s(&utc, &now);
#else
            gmtime_r(&now, &utc);
#endif
            std::strftime(date, sizeof(date), "%a, %d %b %G %T", &utc);

            const std::vector<std::uint8_t> signature = SignAuth3Body(body);
            const std::string signatureB64 = Base64Encode(signature);

            std::ostringstream out;
            out << "HTTP/1.1 200 OK\r\n"
                << "Server: TornadoServer/4.5.3\r\n"
                << "Content-Type: application/json\r\n"
                << "Date: " << date << " GMT\r\n"
                << "X-Signature: " << signatureB64 << "\r\n"
                << "Content-Length: " << body.size() << "\r\n\r\n"
                << body;
            return out.str();
        }
    }
}
