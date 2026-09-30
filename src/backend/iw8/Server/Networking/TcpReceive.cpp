#include "TcpReceive.h"

#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace
{
    std::wstring KeylistResearchDirectory()
    {
        wchar_t path[32768]{};
        const DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path)));
        if (!length || length >= _countof(path))
            return L"keylist_research";
        wchar_t* slash = wcsrchr(path, L'\\');
        if (slash)
            slash[1] = L'\0';
        std::wstring directory(path);
        directory += L"keylist_research";
        CreateDirectoryW(directory.c_str(), nullptr);
        return directory;
    }

    std::wstring KeylistResearchPath(const wchar_t* name)
    {
        std::wstring path = KeylistResearchDirectory();
        path += L"\\";
        path += name;
        return path;
    }

    struct KeylistFuzzCandidate
    {
        DWORD status;
        const char* reason;
        const char* contentType;
        const unsigned char* body;
        std::size_t bodySize;
        const char* name;
    };

    constexpr unsigned char kKeylistLf[] = {'\n'};
    constexpr unsigned char kKeylistCrlf[] = {'\r', '\n'};
    constexpr unsigned char kKeylistAsciiZero[] = {'0'};
    constexpr unsigned char kKeylistAsciiZeroLf[] = {'0', '\n'};
    constexpr unsigned char kKeylistAsciiZeroCrlf[] = {'0', '\r', '\n'};
    constexpr unsigned char kKeylistJsonArray[] = {'[', ']'};
    constexpr unsigned char kKeylistJsonObject[] = {'{', '}'};
    constexpr unsigned char kKeylistNul1[] = {0x00};
    constexpr unsigned char kKeylistNul2[] = {0x00, 0x00};
    constexpr unsigned char kKeylistNul4[] = {0x00, 0x00, 0x00, 0x00};
    constexpr unsigned char kKeylistNul8[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    constexpr unsigned char kKeylistNul16[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    constexpr unsigned char kKeylistUtf8Bom[] = {0xEF, 0xBB, 0xBF};

    const KeylistFuzzCandidate kKeylistFuzzCandidates[] = {
        {204, "No Content", nullptr, nullptr, 0, "204-empty"},
        {200, "OK", "text/plain", kKeylistLf, sizeof(kKeylistLf), "200-lf"},
        {200, "OK", "text/plain", kKeylistCrlf, sizeof(kKeylistCrlf), "200-crlf"},
        {200, "OK", "text/plain", kKeylistAsciiZero, sizeof(kKeylistAsciiZero), "200-ascii-zero"},
        {200, "OK", "text/plain", kKeylistAsciiZeroLf, sizeof(kKeylistAsciiZeroLf), "200-ascii-zero-lf"},
        {200, "OK", "text/plain", kKeylistAsciiZeroCrlf, sizeof(kKeylistAsciiZeroCrlf), "200-ascii-zero-crlf"},
        {200, "OK", "application/json", kKeylistJsonArray, sizeof(kKeylistJsonArray), "200-json-empty-array"},
        {200, "OK", "application/json", kKeylistJsonObject, sizeof(kKeylistJsonObject), "200-json-empty-object"},
        {200, "OK", "application/octet-stream", kKeylistNul1, sizeof(kKeylistNul1), "200-nul-1"},
        {200, "OK", "application/octet-stream", kKeylistNul2, sizeof(kKeylistNul2), "200-nul-2"},
        {200, "OK", "application/octet-stream", kKeylistNul4, sizeof(kKeylistNul4), "200-le32-zero"},
        {200, "OK", "application/octet-stream", kKeylistNul8, sizeof(kKeylistNul8), "200-le64-zero"},
        {200, "OK", "application/octet-stream", kKeylistNul16, sizeof(kKeylistNul16), "200-zero-16"},
        {200, "OK", "text/plain", kKeylistUtf8Bom, sizeof(kKeylistUtf8Bom), "200-utf8-bom-only"},
    };

    constexpr int kKeylistFuzzCandidateCount = static_cast<int>(sizeof(kKeylistFuzzCandidates) / sizeof(kKeylistFuzzCandidates[0]));
    std::atomic<int> g_lastKeylistFuzzCandidate{0};
    std::atomic<unsigned long long> g_lastKeylistFuzzSequence{0};
    std::atomic_bool g_keylistFuzzProgressLogged{false};

    bool WriteFileBytes(const std::wstring& path, const void* data, std::size_t size)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        bool ok = true;
        const unsigned char* bytes = static_cast<const unsigned char*>(data);
        std::size_t remaining = size;
        while (remaining)
        {
            const DWORD chunk = static_cast<DWORD>((std::min<std::size_t>)(remaining, 1024u * 1024u));
            DWORD written = 0;
            if (!WriteFile(file, bytes, chunk, &written, nullptr) || written != chunk)
            {
                ok = false;
                break;
            }
            bytes += written;
            remaining -= written;
        }
        CloseHandle(file);
        return ok;
    }

    bool ReadFileBytes(const std::wstring& path, std::vector<unsigned char>& out)
    {
        out.clear();
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 8ll * 1024ll * 1024ll)
        {
            CloseHandle(file);
            return false;
        }
        out.resize(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        const bool ok = ReadFile(file, out.data(), static_cast<DWORD>(out.size()), &read, nullptr) && read == out.size();
        CloseHandle(file);
        if (!ok)
            out.clear();
        return ok;
    }

    std::string ReadSmallTextFile(const std::wstring& path)
    {
        std::vector<unsigned char> bytes;
        if (!ReadFileBytes(path, bytes))
            return {};
        return std::string(bytes.begin(), bytes.end());
    }

    int ReadResearchInteger(const wchar_t* name, int fallback)
    {
        const std::string text = ReadSmallTextFile(KeylistResearchPath(name));
        if (text.empty())
            return fallback;
        char* end = nullptr;
        const long value = std::strtol(text.c_str(), &end, 10);
        if (end == text.c_str())
            return fallback;
        return static_cast<int>(value);
    }

    void WriteResearchInteger(const wchar_t* name, int value)
    {
        char text[64]{};
        const int length = _snprintf_s(text, sizeof(text), _TRUNCATE, "%d\r\n", value);
        if (length > 0)
            WriteFileBytes(KeylistResearchPath(name), text, static_cast<std::size_t>(length));
    }

    int SelectKeylistFuzzCandidate(bool& lockedToWinner, unsigned long long& sequence)
    {
        lockedToWinner = false;
        const int winner = ReadResearchInteger(L"keylist_fuzz_winner.txt", 0);
        if (winner >= 1 && winner <= kKeylistFuzzCandidateCount)
        {
            lockedToWinner = true;
            sequence = g_lastKeylistFuzzSequence.fetch_add(1) + 1;
            g_lastKeylistFuzzCandidate.store(winner);
            return winner;
        }

        int next = ReadResearchInteger(L"keylist_fuzz_next.txt", 1);
        if (next < 1 || next > kKeylistFuzzCandidateCount)
            next = 1;

        const int selected = next;
        next = selected == kKeylistFuzzCandidateCount ? 1 : selected + 1;
        WriteResearchInteger(L"keylist_fuzz_next.txt", next);
        sequence = g_lastKeylistFuzzSequence.fetch_add(1) + 1;
        g_lastKeylistFuzzCandidate.store(selected);
        g_keylistFuzzProgressLogged.store(false);
        return selected;
    }

    void SaveKeylistFuzzLast(unsigned long long sequence, int candidateNumber,
        const KeylistFuzzCandidate& candidate, const std::string& request, bool lockedToWinner)
    {
        char summary[2048]{};
        const int summaryLength = _snprintf_s(summary, sizeof(summary), _TRUNCATE,
            "sequence=%llu\r\n"
            "candidate=%d/%d\r\n"
            "name=%s\r\n"
            "status=%lu %s\r\n"
            "content-type=%s\r\n"
            "body-bytes=%llu\r\n"
            "locked-winner=%s\r\n",
            sequence,
            candidateNumber,
            kKeylistFuzzCandidateCount,
            candidate.name,
            static_cast<unsigned long>(candidate.status),
            candidate.reason,
            candidate.contentType ? candidate.contentType : "<none>",
            static_cast<unsigned long long>(candidate.bodySize),
            lockedToWinner ? "yes" : "no");
        if (summaryLength > 0)
            WriteFileBytes(KeylistResearchPath(L"keylist_fuzz_last.txt"), summary, static_cast<std::size_t>(summaryLength));
        WriteFileBytes(KeylistResearchPath(L"keylist_fuzz_last_request.txt"), request.data(), request.size());
        WriteFileBytes(KeylistResearchPath(L"keylist_fuzz_last_body.bin"), candidate.body, candidate.bodySize);
    }

    void NoteKeylistFuzzProgress(std::uint16_t port, std::uint64_t clientId)
    {
        if (port != 1119u && port != 443u)
            return;

        const int candidateNumber = g_lastKeylistFuzzCandidate.load();
        if (candidateNumber < 1 || candidateNumber > kKeylistFuzzCandidateCount)
            return;

        bool expected = false;
        if (!g_keylistFuzzProgressLogged.compare_exchange_strong(expected, true))
            return;

        const KeylistFuzzCandidate& candidate = kKeylistFuzzCandidates[candidateNumber - 1];
        WriteResearchInteger(L"keylist_fuzz_winner.txt", candidateNumber);

        char success[1024]{};
        const int successLength = _snprintf_s(success, sizeof(success), _TRUNCATE,
            "candidate=%d/%d\r\n"
            "name=%s\r\n"
            "progress-port=%u\r\n"
            "client-id=%llu\r\n"
            "result=client-progressed-beyond-keylist\r\n",
            candidateNumber,
            kKeylistFuzzCandidateCount,
            candidate.name,
            static_cast<unsigned>(port),
            static_cast<unsigned long long>(clientId));
        if (successLength > 0)
            WriteFileBytes(KeylistResearchPath(L"keylist_fuzz_success.txt"), success, static_cast<std::size_t>(successLength));

        revamped::iw8::log::Print(
            "[KEYLIST-FUZZ] PASS candidate=%d/%d name=%s progression=tcp:%u winner locked; file=%ls",
            candidateNumber, kKeylistFuzzCandidateCount, candidate.name, static_cast<unsigned>(port),
            KeylistResearchPath(L"keylist_fuzz_success.txt").c_str());
    }

    std::string ExtractHttpHeader(const std::string& request, const char* name)
    {
        if (!name || !*name)
            return {};
        std::string needle(name);
        needle += ':';
        std::size_t line = 0;
        while (line < request.size())
        {
            const std::size_t end = request.find("\r\n", line);
            const std::size_t count = (end == std::string::npos ? request.size() : end) - line;
            const std::string current = request.substr(line, count);
            if (current.size() > needle.size() && _strnicmp(current.c_str(), needle.c_str(), needle.size()) == 0)
            {
                std::size_t value = needle.size();
                while (value < current.size() && (current[value] == ' ' || current[value] == '\t'))
                    ++value;
                return current.substr(value);
            }
            if (end == std::string::npos)
                break;
            line = end + 2;
        }
        return {};
    }

}

namespace revamped::iw8
{
    void Server::ReadTcp(std::size_t index)
    {
        if (index >= clients_.size()) return;
        Client& client = clients_[index];
        unsigned char buffer[64 * 1024]{};
        const int result = recv(client.socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
        if (result == 0)
        {
            CloseClient(index, "peer-closed");
            return;
        }
        if (result == SOCKET_ERROR)
        {
            const int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK)
            {
                char detail[64]{};
                _snprintf_s(detail, sizeof(detail), _TRUNCATE, "recv-error-wsa=%d", error);
                CloseClient(index, detail);
            }
            return;
        }
        if (config_.dumpPayloads)
            log::Payload(client.id, "IN", client.localPort, client.peer, buffer, static_cast<std::size_t>(result));

        if (client.localPort == 3074u || client.localPort == 3075u)
        {
            if (!HandleLsgTcp(client, buffer, static_cast<std::size_t>(result)))
                CloseClient(index, "lsg-send-failed");
            return;
        }

        if (client.firstPacket)
        {
            client.firstPacket = false;
            NoteKeylistFuzzProgress(client.localPort, client.id);
            if (client.localPort == 1119)
                log::Print("[AUTH] id=%llu first Battle.net client payload captured bytes=%d; attempting real TLS transport only",
                    static_cast<unsigned long long>(client.id), result);
            else if (client.localPort == 443 && result >= 5 && buffer[0] == 0x16 && buffer[1] == 0x03)
                log::Print("[WEB-AUTH] id=%llu HTTPS/TLS ClientHello reached local :443 bytes=%d after BGS challenge; web-login TLS/HTTP emulation is the next layer",
                    static_cast<unsigned long long>(client.id), result);
        }

        if (client.localPort == 1119 || client.localPort == 443)
        {
            auto* session = static_cast<TlsSession*>(client.tlsState);
            if (!session)
            {
                session = new TlsSession();
                session->localPort = client.localPort;
                client.tlsState = session;
            }
            session->input.insert(session->input.end(), buffer, buffer + static_cast<std::size_t>(result));
            if (!session->helloLogged)
            {
                session->helloLogged = LogTlsClientHello(client.id, client.localPort, session->input.data(), session->input.size(), &session->sni);
                if (session->helloLogged)
                    log::Print("[TLS%u] id=%llu ClientHello decoded; replying through SChannel with the local diagnostic certificate",
                        static_cast<unsigned>(client.localPort), static_cast<unsigned long long>(client.id));
            }
            if (!PumpTls(*session, client.socket, client.id, client.peer))
            {
                CloseClient(index, client.localPort == 443 ? "tls443-handshake-or-http-failed" : "tls1119-handshake-or-decrypt-failed");
            }
            return;
        }

        // Research target from the stock client:
        //   GET /pc/0/xpak_ignore.keylist
        // The historical CDN object is gone, so this build cycles a small set
        // of deterministic empty-list candidates and watches for native progress
        // to :1119/:443. No game state is patched or forced.
        if (client.localPort == 80)
        {
            const std::string request(reinterpret_cast<const char*>(buffer), static_cast<std::size_t>(result));

            if (request.rfind("GET /__revamped/iw8.crl ", 0) == 0)
            {
                if (g_tlsCrlDer.empty())
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Length: 0\r\n"
                        "Cache-Control: no-store\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    log::Print("[TRUST-CRL] id=%llu CRL fetch arrived before CRL was ready",
                        static_cast<unsigned long long>(client.id));
                    CloseClient(index, "crl-not-ready-503");
                    return;
                }

                char header[384]{};
                const int headerLength = _snprintf_s(header, sizeof(header), _TRUNCATE,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/pkix-crl\r\n"
                    "Content-Length: %llu\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    static_cast<unsigned long long>(g_tlsCrlDer.size()));
                const bool headerOk = headerLength > 0 &&
                    SendAllNonBlocking(client.socket, header, static_cast<std::size_t>(headerLength));
                const bool bodyOk = headerOk &&
                    SendAllNonBlocking(client.socket, g_tlsCrlDer.data(), g_tlsCrlDer.size());

                if (config_.dumpPayloads && headerOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer,
                        header, static_cast<std::size_t>(headerLength));
                if (config_.dumpPayloads && bodyOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer,
                        g_tlsCrlDer.data(), g_tlsCrlDer.size());

                log::Print("[TRUST-CRL] id=%llu served local empty CRL bytes=%llu result=%s",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(g_tlsCrlDer.size()),
                    bodyOk ? "ok" : "send-failed");
                CloseClient(index, bodyOk ? "crl-200" : "crl-send-failed");
                return;
            }

            // Tiny startup health/prewarm route used by the redirect DLL.  It
            // intentionally carries no auth state; its only purpose is to make
            // the local accept path, trust bootstrap and first socket work happen
            // before the intro starts doing time-sensitive online work.
            if (request.rfind("GET /__revamped/prewarm ", 0) == 0)
            {
                static const char response[] =
                    "HTTP/1.1 204 No Content\r\n"
                    "Content-Length: 0\r\n"
                    "Cache-Control: no-store\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                const bool sent = SendAllNonBlocking(client.socket, response, sizeof(response) - 1);
                log::Print("[PREWARM] id=%llu local backend prewarm request served status=204",
                    static_cast<unsigned long long>(client.id));
                CloseClient(index, sent ? "prewarm-204" : "prewarm-send-failed");
                return;
            }

            if (request.rfind("GET /pc/0/xpak_ignore.keylist ", 0) == 0)
            {
                const std::string host = ExtractHttpHeader(request, "Host");
                log::Print("[HTTP80] id=%llu request=\"GET /pc/0/xpak_ignore.keylist HTTP/1.1\" host=%s",
                    static_cast<unsigned long long>(client.id), host.empty() ? "<missing>" : host.c_str());

                WriteFileBytes(KeylistResearchPath(L"xpak_ignore.client_request.txt"), request.data(), request.size());

                // Black-box research result (MW2019 1.44): HTTP 200 with one LF byte
                // is the minimal native empty keylist.  It advances the stock client
                // immediately to Battle.net :1119.  Keep this deterministic now.
                static constexpr unsigned char body[] = {'\n'};
                static constexpr char header[] =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 1\r\n"
                    "Cache-Control: no-store\r\n"
                    "Connection: close\r\n"
                    "\r\n";

                const bool headerOk = SendAllNonBlocking(client.socket, header, sizeof(header) - 1);
                const bool bodyOk = headerOk && SendAllNonBlocking(client.socket, body, sizeof(body));
                WriteFileBytes(KeylistResearchPath(L"xpak_ignore.accepted_body.bin"), body, sizeof(body));

                log::Print(
                    "[KEYLIST] id=%llu status=200 bytes=1 body=LF mode=proven-empty-list result=%s",
                    static_cast<unsigned long long>(client.id), (headerOk && bodyOk) ? "sent" : "send-failed");

                CloseClient(index, (headerOk && bodyOk) ? "http-keylist-200-lf" : "http-keylist-send-failed");
                return;
            }

            if (request.rfind("GET /Bnet/zxx/client/bgs-key-fingerprint ", 0) == 0)
            {
                log::Print("[BGS-BUNDLE] id=%llu stock client requested /Bnet/zxx/client/bgs-key-fingerprint",
                    static_cast<unsigned long long>(client.id));

                const auto stockBundle = LoadStockBgsCertificateBundle();
                if (stockBundle.empty())
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    log::Print("[BGS-BUNDLE] id=%llu stock signed bundle file is not available yet; expected CodRevamped\\MW2019\\server_emu\\bgs-key-fingerprint.stock",
                        static_cast<unsigned long long>(client.id));
                    CloseClient(index, "bgs-key-fingerprint-stock-bundle-missing");
                    return;
                }

                std::size_t pinReplacements = 0;
                bool signatureVerified = false;
                const auto bundle = BuildLocalBgsTrustBundle(stockBundle, pinReplacements, signatureVerified);
                log::Print("[BGS-BUNDLE] id=%llu OPTION2 signed local trust bundle trustCert=local-root-ca+ca-signed-leaf caSpki=%s pinReplacements=%llu signatureVerified=%s stockJsonBytes=%llu wireBytes=%llu",
                    static_cast<unsigned long long>(client.id),
                    g_tlsSpkiSha256.empty() ? "<unavailable>" : g_tlsSpkiSha256.c_str(),
                    static_cast<unsigned long long>(pinReplacements),
                    signatureVerified ? "yes" : "no",
                    static_cast<unsigned long long>(stockBundle.size()),
                    static_cast<unsigned long long>(bundle.size()));

                if (bundle.empty() || !signatureVerified)
                {
                    static const char unavailable[] =
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    SendAllNonBlocking(client.socket, unavailable, sizeof(unavailable) - 1);
                    CloseClient(index, "bgs-key-fingerprint-local-signing-failed");
                    return;
                }

                char header[512]{};
                const int headerLength = _snprintf_s(header, sizeof(header), _TRUNCATE,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Content-Length: %llu\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    static_cast<unsigned long long>(bundle.size()));

                const bool headerOk = headerLength > 0 &&
                    SendAllNonBlocking(client.socket, header, static_cast<std::size_t>(headerLength));
                const bool bodyOk = headerOk &&
                    SendAllNonBlocking(client.socket, bundle.data(), bundle.size());

                if (config_.dumpPayloads && headerOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, header, static_cast<std::size_t>(headerLength));
                if (config_.dumpPayloads && bodyOk)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, bundle.data(), bundle.size());

                if (!bodyOk)
                {
                    const int error = WSAGetLastError();
                    log::Print("[BGS-BUNDLE] id=%llu failed sending stock signed bundle bytes=%llu wsa=%d",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(bundle.size()),
                        error);
                    CloseClient(index, "bgs-key-fingerprint-send-failed");
                }
                else
                {
                    log::Print("[BGS-BUNDLE] id=%llu served OPTION2 signed BGS bundle bytes=%llu format=JSON(local CA trust)+NGIS+RSA2048LE pinReplacements=%llu signatureVerified=yes; login/fence/LUI state remains server-driven",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(bundle.size()),
                        static_cast<unsigned long long>(pinReplacements));
                    CloseClient(index, "bgs-key-fingerprint-option2-signed-200");
                }
                return;
            }
        }

        // Private diagnostic probe only; unknown IW8 binary traffic remains
        // capture-only until its framing/handshake is actually observed.
        static const char probe[] = "CRIW8PNG";
        static const char reply[] = "CRIW8PONG\n";
        if (result >= static_cast<int>(sizeof(probe) - 1) && std::equal(buffer, buffer + sizeof(probe) - 1, reinterpret_cast<const unsigned char*>(probe)))
            send(client.socket, reply, static_cast<int>(sizeof(reply) - 1), 0);
    }
}
