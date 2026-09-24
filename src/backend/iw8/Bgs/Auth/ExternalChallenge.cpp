#include "ExternalChallenge.h"

namespace revamped::iw8
{
    namespace
    {
        void ProtoAppendVarint(std::vector<BYTE>& out, std::uint64_t value)
        {
            do
            {
                BYTE b = static_cast<BYTE>(value & 0x7Fu);
                value >>= 7;
                if (value) b |= 0x80u;
                out.push_back(b);
            } while (value);
        }

        void ProtoAppendKey(std::vector<BYTE>& out, std::uint32_t field, std::uint32_t wire)
        {
            ProtoAppendVarint(out, (static_cast<std::uint64_t>(field) << 3) | wire);
        }

        void ProtoAppendVarintField(std::vector<BYTE>& out, std::uint32_t field, std::uint64_t value)
        {
            ProtoAppendKey(out, field, 0);
            ProtoAppendVarint(out, value);
        }

        void ProtoAppendFixed32Field(std::vector<BYTE>& out, std::uint32_t field, std::uint32_t value)
        {
            ProtoAppendKey(out, field, 5);
            out.push_back(static_cast<BYTE>(value & 0xFFu));
            out.push_back(static_cast<BYTE>((value >> 8) & 0xFFu));
            out.push_back(static_cast<BYTE>((value >> 16) & 0xFFu));
            out.push_back(static_cast<BYTE>((value >> 24) & 0xFFu));
        }

        void ProtoAppendFixed64Field(std::vector<BYTE>& out, std::uint32_t field, std::uint64_t value)
        {
            ProtoAppendKey(out, field, 1);
            for (unsigned shift = 0; shift < 64; shift += 8)
                out.push_back(static_cast<BYTE>((value >> shift) & 0xFFu));
        }

        void ProtoAppendBytesField(std::vector<BYTE>& out, std::uint32_t field, const void* data, std::size_t size)
        {
            ProtoAppendKey(out, field, 2);
            ProtoAppendVarint(out, size);
            if (size && data)
            {
                const auto* bytes = static_cast<const BYTE*>(data);
                out.insert(out.end(), bytes, bytes + size);
            }
        }

        void ProtoAppendStringField(std::vector<BYTE>& out, std::uint32_t field, const std::string& value)
        {
            ProtoAppendBytesField(out, field, value.data(), value.size());
        }

        std::vector<BYTE> BuildBgsChallengeExternalFrame(const std::string& webAuthUrl, std::uint32_t token)
        {
            // bgs.protocol.challenge.v1.ChallengeExternalRequest
            //   field 2 = payload_type ("web_auth_url")
            //   field 3 = payload (URL bytes)
            std::vector<BYTE> body;
            ProtoAppendStringField(body, 2, "web_auth_url");
            ProtoAppendBytesField(body, 3, webAuthUrl.data(), webAuthUrl.size());

            // bgs.protocol.Header framing used by Battle.net BGS RPC:
            //   u16be protobuf-header-size | Header | body
            // Header fields are intentionally the minimum request fields:
            //   service_id=0, method_id=3, token=<server request token>, size=body size,
            //   service_hash=ChallengeListener (0xBBDA171F).
            std::vector<BYTE> header;
            ProtoAppendVarintField(header, 1, 0);                  // service_id
            ProtoAppendVarintField(header, 2, 3);                  // method_id: OnExternalChallenge
            ProtoAppendVarintField(header, 3, token);              // server request token
            ProtoAppendVarintField(header, 5, body.size());        // size
            ProtoAppendFixed32Field(header, 11, 0xBBDA171Fu);      // ChallengeListenerHash

            std::vector<BYTE> frame;
            const std::uint16_t headerSize = static_cast<std::uint16_t>(header.size());
            frame.push_back(static_cast<BYTE>((headerSize >> 8) & 0xFFu));
            frame.push_back(static_cast<BYTE>(headerSize & 0xFFu));
            frame.insert(frame.end(), header.begin(), header.end());
            frame.insert(frame.end(), body.begin(), body.end());
            return frame;
        }

        bool SendTlsApplication(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer,
            const void* plaintext, std::size_t plaintextSize, const char* label)
        {
            if (!session.established || !plaintext || !plaintextSize) return false;
            if (!session.streamSizes.cbHeader || !session.streamSizes.cbTrailer || !session.streamSizes.cbMaximumMessage)
            {
                log::Print("[TLS%u] id=%llu cannot send %s: invalid SChannel stream sizes", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), label ? label : "application");
                return false;
            }
            if (plaintextSize > session.streamSizes.cbMaximumMessage)
            {
                log::Print("[TLS%u] id=%llu cannot send %s: plaintext=%llu exceeds maxMessage=%lu",
                    static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), label ? label : "application",
                    static_cast<unsigned long long>(plaintextSize), session.streamSizes.cbMaximumMessage);
                return false;
            }

            std::vector<BYTE> encrypted(session.streamSizes.cbHeader + plaintextSize + session.streamSizes.cbTrailer);
            std::memcpy(encrypted.data() + session.streamSizes.cbHeader, plaintext, plaintextSize);

            SecBuffer buffers[4]{};
            buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
            buffers[0].pvBuffer = encrypted.data();
            buffers[0].cbBuffer = session.streamSizes.cbHeader;
            buffers[1].BufferType = SECBUFFER_DATA;
            buffers[1].pvBuffer = encrypted.data() + session.streamSizes.cbHeader;
            buffers[1].cbBuffer = static_cast<unsigned long>(plaintextSize);
            buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
            buffers[2].pvBuffer = encrypted.data() + session.streamSizes.cbHeader + plaintextSize;
            buffers[2].cbBuffer = session.streamSizes.cbTrailer;
            buffers[3].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc desc{};
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 4;
            desc.pBuffers = buffers;

            const SECURITY_STATUS status = EncryptMessage(&session.context, 0, &desc, 0);
            if (status != SEC_E_OK)
            {
                log::Print("[TLS%u] id=%llu EncryptMessage(%s) failed status=0x%08lX",
                    static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), label ? label : "application", static_cast<unsigned long>(status));
                return false;
            }

            const std::size_t encryptedSize = static_cast<std::size_t>(buffers[0].cbBuffer) +
                static_cast<std::size_t>(buffers[1].cbBuffer) + static_cast<std::size_t>(buffers[2].cbBuffer);
            if (session.localPort == 443)
            {
                // HTTP OAuth bodies can contain bearer material. Never dump web
                // plaintext; the WebAuthService emits only request metadata/keys.
                log::Print("[WEB-AUTH] id=%llu sending %s plaintextBytes=%llu tlsBytes=%llu body=REDACTED",
                    static_cast<unsigned long long>(id), label ? label : "application",
                    static_cast<unsigned long long>(plaintextSize), static_cast<unsigned long long>(encryptedSize));
            }
            else
            {
                log::Payload(id, "TLS-PLAIN-OUT", session.localPort, peer, plaintext, plaintextSize);
                log::Print("[BGS1119] id=%llu sending %s plaintextBytes=%llu tlsBytes=%llu hex=%s",
                    static_cast<unsigned long long>(id), label ? label : "application",
                    static_cast<unsigned long long>(plaintextSize), static_cast<unsigned long long>(encryptedSize),
                    HexPrefix(plaintext, plaintextSize, 256).c_str());
            }
            return SendTlsToken(session, socket, id, peer, encrypted.data(), encryptedSize);
        }

        std::vector<BYTE> BuildWebSocketServerFrame(BYTE opcode, const BYTE* payload, std::size_t payloadSize);

        bool SendBgsWebAuthChallenge(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer)
        {
            // MW2019/BGS 2.2.0 remains idle after ConnectionService.Connect until
            // the server initiates the normal external web-auth challenge. Keep
            // this entirely server-driven: it does not mark login successful.
            // The hostname deliberately matches the CA-signed leaf we already
            // present on :1119, and the DLL redirects :1119 back to localhost.
            static const std::string webAuthUrl = "https://us.actual.battle.net:1119/bnet/login/";
            if (session.webAuthChallengeSent)
                return true;

            const std::uint32_t token = session.bgs.nextServerRequestToken++;
            const std::vector<BYTE> rpcFrame = BuildBgsChallengeExternalFrame(webAuthUrl, token);
            const std::vector<BYTE> wsFrame = BuildWebSocketServerFrame(0x2u, rpcFrame.data(), rpcFrame.size());

            log::Print("[BGS-AUTH] id=%llu server -> client ChallengeListener.OnExternalChallenge token=%u payload_type=web_auth_url url=%s",
                static_cast<unsigned long long>(id), token, webAuthUrl.c_str());
            log::Print("[BGS-AUTH] id=%llu challenge framing rpcBytes=%llu websocketBytes=%llu u16beHeader=%u serviceHash=0xBBDA171F method=3; login is NOT marked successful",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(rpcFrame.size()),
                static_cast<unsigned long long>(wsFrame.size()),
                rpcFrame.size() >= 2 ? static_cast<unsigned>(ReadBe16(rpcFrame.data())) : 0u);

            if (!SendTlsApplication(session, socket, id, peer, wsFrame.data(), wsFrame.size(), "ChallengeListener.OnExternalChallenge websocket frame"))
                return false;

            session.webAuthChallengeSent = true;
            session.webAuthChallengeToken = token;
            log::Print("[BGS-AUTH] id=%llu web-auth challenge SENT; waiting for stock client web-auth/AuthenticationService traffic",
                static_cast<unsigned long long>(id));
            return true;
        }
    }
}
