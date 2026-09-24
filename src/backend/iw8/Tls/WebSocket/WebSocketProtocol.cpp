#include "WebSocketProtocol.h"

namespace revamped::iw8
{
    namespace
    {
        std::string TrimAscii(std::string value)
        {
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(value.begin());
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' || value.back() == '\n')) value.pop_back();
            return value;
        }

        bool EqualsAsciiNoCase(const std::string& a, const std::string& b)
        {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i)
            {
                unsigned char ca = static_cast<unsigned char>(a[i]);
                unsigned char cb = static_cast<unsigned char>(b[i]);
                if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                if (ca != cb) return false;
            }
            return true;
        }

        std::string HttpHeaderValue(const std::string& request, const char* wantedName)
        {
            if (!wantedName || !*wantedName) return {};
            std::size_t cursor = 0;
            while (cursor < request.size())
            {
                const std::size_t end = request.find("\r\n", cursor);
                const std::size_t lineEnd = end == std::string::npos ? request.size() : end;
                const std::string line = request.substr(cursor, lineEnd - cursor);
                const std::size_t colon = line.find(':');
                if (colon != std::string::npos)
                {
                    const std::string name = TrimAscii(line.substr(0, colon));
                    if (EqualsAsciiNoCase(name, wantedName))
                        return TrimAscii(line.substr(colon + 1));
                }
                if (end == std::string::npos) break;
                cursor = end + 2;
            }
            return {};
        }

        std::string Base64NoCrLf(const BYTE* data, DWORD size)
        {
            if (!data || !size) return {};
            DWORD chars = 0;
            if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &chars) || !chars)
                return {};
            std::string output(chars, '\0');
            if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &output[0], &chars))
                return {};
            while (!output.empty() && output.back() == '\0') output.pop_back();
            return output;
        }

        std::string BuildWebSocketAccept(const std::string& clientKey)
        {
            static const char kGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            const std::string source = clientKey + kGuid;

            HCRYPTPROV provider = 0;
            HCRYPTHASH hash = 0;
            BYTE digest[20]{};
            DWORD digestSize = sizeof(digest);
            std::string result;

            if (CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT) &&
                CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash) &&
                CryptHashData(hash, reinterpret_cast<const BYTE*>(source.data()), static_cast<DWORD>(source.size()), 0) &&
                CryptGetHashParam(hash, HP_HASHVAL, digest, &digestSize, 0) && digestSize == sizeof(digest))
            {
                result = Base64NoCrLf(digest, digestSize);
            }

            if (hash) CryptDestroyHash(hash);
            if (provider) CryptReleaseContext(provider, 0);
            return result;
        }

        std::vector<BYTE> BuildWebSocketServerFrame(BYTE opcode, const BYTE* payload, std::size_t payloadSize)
        {
            std::vector<BYTE> frame;
            frame.push_back(static_cast<BYTE>(0x80u | (opcode & 0x0Fu))); // FIN + opcode
            if (payloadSize <= 125)
            {
                frame.push_back(static_cast<BYTE>(payloadSize));
            }
            else if (payloadSize <= 0xFFFFu)
            {
                frame.push_back(126);
                frame.push_back(static_cast<BYTE>((payloadSize >> 8) & 0xFFu));
                frame.push_back(static_cast<BYTE>(payloadSize & 0xFFu));
            }
            else
            {
                frame.push_back(127);
                const std::uint64_t length = static_cast<std::uint64_t>(payloadSize);
                for (int shift = 56; shift >= 0; shift -= 8)
                    frame.push_back(static_cast<BYTE>((length >> shift) & 0xFFu));
            }
            if (payload && payloadSize)
                frame.insert(frame.end(), payload, payload + payloadSize);
            return frame;
        }

        void LogBgsRpcWebSocketPayload(std::uint64_t id, std::uint64_t frameNumber, const std::vector<BYTE>& payload)
        {
            if (payload.empty())
            {
                log::Print("[BGS-RPC] id=%llu wsFrame#%llu empty binary payload",
                    static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber));
                return;
            }

            if (payload.size() >= 2)
            {
                const std::uint16_t headerSize = ReadBe16(payload.data());
                if (headerSize <= payload.size() - 2)
                {
                    const std::size_t bodySize = payload.size() - 2 - headerSize;
                    log::Print("[BGS-RPC] id=%llu wsFrame#%llu frameBytes=%llu headerBytes=%u bodyBytes=%llu headerProto=%s",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber),
                        static_cast<unsigned long long>(payload.size()), static_cast<unsigned>(headerSize),
                        static_cast<unsigned long long>(bodySize),
                        DescribeBestProtoCandidate(payload.data() + 2, headerSize).c_str());
                    if (bodySize)
                    {
                        log::Print("[BGS-RPC] id=%llu wsFrame#%llu bodyHex=%s bodyProto=%s",
                            static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber),
                            HexPrefix(payload.data() + 2 + headerSize, bodySize, 256).c_str(),
                            DescribeBestProtoCandidate(payload.data() + 2 + headerSize, bodySize).c_str());
                    }
                    return;
                }
            }

            log::Print("[BGS-RPC] id=%llu wsFrame#%llu unrecognized framing hex=%s",
                static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber),
                HexPrefix(payload.data(), payload.size(), 256).c_str());
        }

        bool HandleBgsRpcWebSocketPayload(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            std::uint64_t frameNumber, const std::vector<BYTE>& payload)
        {
            bgs::RpcEnvelope rpc{};
            if (!bgs::ParseRpcPayload(payload, rpc))
            {
                log::Print("[BGS-RPC] id=%llu wsFrame#%llu header parse failed; server cannot route this frame",
                    static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber));
                return true;
            }

            const auto& header = rpc.header;
            log::Print("[BGS-RPC] id=%llu wsFrame#%llu decoded serviceId=%u method=%u token=%u serviceHash=%s0x%08X service=%s declaredBody=%s%u actualBody=%llu status=%s%u%s%s%s",
                static_cast<unsigned long long>(id), static_cast<unsigned long long>(frameNumber),
                header.serviceId, header.hasMethodId ? header.methodId : 0u, header.token,
                header.hasServiceHash ? "" : "<missing>/", header.serviceHash,
                header.hasServiceHash ? bgs::ServiceName(header.serviceHash) : "<none>",
                header.hasSize ? "" : "<missing>/", header.size,
                static_cast<unsigned long long>(rpc.body.size()),
                header.hasStatus ? "" : "<missing>/", header.status,
                header.hasStatus ? "(" : "", header.hasStatus ? bgs::StatusName(header.status) : "",
                header.hasStatus ? ")" : "");

            if (header.serviceId == 0xFEu)
            {
                // The old generic web-auth challenge is still owned by the TLS
                // bootstrap layer, not the normal BGS service dispatcher.
                if (session.webAuthChallengeSent && header.token == session.webAuthChallengeToken)
                {
                    if (header.hasStatus && header.status == 0x00000BC2u)
                    {
                        session.webAuthChallengeUnsupported = true;
                        log::Print("[BGS-AUTH] id=%llu ChallengeListener response token=%u status=3010 (0x00000BC2 ERROR_RPC_INVALID_SERVICE); challenge retries disabled",
                            static_cast<unsigned long long>(id), header.token);
                    }
                    else
                    {
                        log::Print("[BGS-AUTH] id=%llu ChallengeListener response token=%u status=%s%u (%s)",
                            static_cast<unsigned long long>(id), header.token,
                            header.hasStatus ? "" : "<missing>/", header.status,
                            header.hasStatus ? bgs::StatusName(header.status) : "unknown");
                    }
                    return true;
                }

                return bgs::HandleClientResponse(id, rpc, session.bgs);
            }

            std::vector<bgs::OutgoingRpc> outgoing;
            bgs::RequestContext context{id, rpc, session.bgs, outgoing};
            if (!bgs::DispatchRequest(context))
                return false;

            for (const auto& message : outgoing)
            {
                const std::vector<BYTE> wsResponse = BuildWebSocketServerFrame(
                    0x2u, message.payload.data(), message.payload.size());
                log::Print("[BGS-SEND] id=%llu serviceHash=0x%08X service=%s method=%u token=%u direction=%s rpcBytes=%llu websocketBytes=%llu label=%s",
                    static_cast<unsigned long long>(id), message.serviceHash,
                    bgs::ServiceName(message.serviceHash), message.methodId, message.token,
                    message.serverRequest ? "server->client request" : "server->client response",
                    static_cast<unsigned long long>(message.payload.size()),
                    static_cast<unsigned long long>(wsResponse.size()), message.label.c_str());

                if (!SendTlsApplication(session, socket, id, peer, wsResponse.data(), wsResponse.size(), message.label.c_str()))
                {
                    log::Print("[BGS-SEND] id=%llu SEND FAILED service=%s method=%u token=%u label=%s",
                        static_cast<unsigned long long>(id), bgs::ServiceName(message.serviceHash),
                        message.methodId, message.token, message.label.c_str());
                    return false;
                }
            }

            return true;
        }

        bool PumpWebSocketFrames(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            const BYTE* data, std::size_t size)
        {
            if (data && size)
                session.websocketInput.insert(session.websocketInput.end(), data, data + size);

            while (session.websocketInput.size() >= 2)
            {
                const BYTE b0 = session.websocketInput[0];
                const BYTE b1 = session.websocketInput[1];
                const bool fin = (b0 & 0x80u) != 0;
                const BYTE opcode = static_cast<BYTE>(b0 & 0x0Fu);
                const bool masked = (b1 & 0x80u) != 0;
                std::uint64_t payloadLength = b1 & 0x7Fu;
                std::size_t cursor = 2;

                if (payloadLength == 126)
                {
                    if (session.websocketInput.size() < cursor + 2) return true;
                    payloadLength = ReadBe16(session.websocketInput.data() + cursor);
                    cursor += 2;
                }
                else if (payloadLength == 127)
                {
                    if (session.websocketInput.size() < cursor + 8) return true;
                    payloadLength = 0;
                    for (int i = 0; i < 8; ++i)
                        payloadLength = (payloadLength << 8) | session.websocketInput[cursor + i];
                    cursor += 8;
                }

                BYTE mask[4]{};
                if (masked)
                {
                    if (session.websocketInput.size() < cursor + 4) return true;
                    std::memcpy(mask, session.websocketInput.data() + cursor, 4);
                    cursor += 4;
                }

                if (payloadLength > 16ull * 1024ull * 1024ull)
                {
                    log::Print("[WS1119] id=%llu rejecting absurd websocket payload length=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(payloadLength));
                    return false;
                }
                if (payloadLength > static_cast<std::uint64_t>(session.websocketInput.size() - cursor))
                    return true;

                std::vector<BYTE> payload(static_cast<std::size_t>(payloadLength));
                if (payloadLength)
                    std::memcpy(payload.data(), session.websocketInput.data() + cursor, static_cast<std::size_t>(payloadLength));
                if (masked)
                {
                    for (std::size_t i = 0; i < payload.size(); ++i)
                        payload[i] ^= mask[i & 3u];
                }

                const std::size_t consumed = cursor + static_cast<std::size_t>(payloadLength);
                session.websocketInput.erase(session.websocketInput.begin(), session.websocketInput.begin() + static_cast<std::ptrdiff_t>(consumed));
                ++session.websocketFrameCount;

                log::Print("[WS1119] id=%llu frame#%llu fin=%s opcode=0x%02X masked=%s payloadBytes=%llu",
                    static_cast<unsigned long long>(id), static_cast<unsigned long long>(session.websocketFrameCount),
                    fin ? "yes" : "no", static_cast<unsigned>(opcode), masked ? "yes" : "no",
                    static_cast<unsigned long long>(payload.size()));

                if (opcode == 0x8)
                {
                    log::Print("[WS1119] id=%llu client sent websocket CLOSE codeBytes=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(payload.size()));
                    return false;
                }
                if (opcode == 0x9)
                {
                    const auto pong = BuildWebSocketServerFrame(0xAu, payload.data(), payload.size());
                    if (!SendTlsApplication(session, socket, id, peer, pong.data(), pong.size(), "WebSocket Pong"))
                        return false;
                    log::Print("[WS1119] id=%llu replied to websocket PING with PONG bytes=%llu",
                        static_cast<unsigned long long>(id), static_cast<unsigned long long>(payload.size()));
                    continue;
                }
                if (opcode == 0x2 || opcode == 0x0)
                {
                    LogBgsRpcWebSocketPayload(id, session.websocketFrameCount, payload);
                    if (!HandleBgsRpcWebSocketPayload(session, socket, id, peer, session.websocketFrameCount, payload))
                        return false;
                }
                else if (opcode == 0x1)
                {
                    log::Print("[WS1119] id=%llu text frame ascii=%s",
                        static_cast<unsigned long long>(id), protocol::AsciiPrefix(payload.data(), payload.size(), 512).c_str());
                }
            }
            return true;
        }
    }
}
