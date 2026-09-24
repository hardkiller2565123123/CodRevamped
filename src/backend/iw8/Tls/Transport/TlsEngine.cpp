#include "TlsEngine.h"

namespace revamped::iw8
{
    namespace
    {
        void LogTlsAlertIfVisible(std::uint64_t id, std::uint16_t localPort, const std::vector<unsigned char>& input)
        {
            if (input.size() < 7 || input[0] != 0x15) return;
            const std::size_t recordLength = ReadBe16(input.data() + 3);
            if (recordLength < 2 || input.size() < recordLength + 5) return;
            log::Print("[TLS%u] id=%llu TLS alert record level=%u description=%u (plaintext view; encrypted alerts may not decode here)",
                static_cast<unsigned>(localPort), static_cast<unsigned long long>(id), static_cast<unsigned>(input[5]), static_cast<unsigned>(input[6]));
        }

        bool DecryptTlsInput(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer)
        {
            while (!session.input.empty())
            {
                SecBuffer buffers[4]{};
                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = session.input.data();
                buffers[0].cbBuffer = static_cast<unsigned long>(session.input.size());
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;
                SecBufferDesc descriptor{};
                descriptor.ulVersion = SECBUFFER_VERSION;
                descriptor.cBuffers = 4;
                descriptor.pBuffers = buffers;

                const SECURITY_STATUS status = DecryptMessage(&session.context, &descriptor, 0, nullptr);
                if (status == SEC_E_INCOMPLETE_MESSAGE) return true;
                if (status == SEC_I_CONTEXT_EXPIRED)
                {
                    log::Print("[TLS%u] id=%llu peer sent TLS close_notify", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id));
                    if (session.localPort == 1119 && !session.bgsApplicationSeen)
                        log::Print("[BGS1119] id=%llu TLS closed before any decrypted BGS application message was received", static_cast<unsigned long long>(id));
                    return false;
                }
                if (status == SEC_I_RENEGOTIATE)
                {
                    log::Print("[TLS%u] id=%llu TLS renegotiation requested; leaving connection open", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id));
                    return true;
                }
                if (status != SEC_E_OK)
                {
                    log::Print("[TLS%u] id=%llu DecryptMessage failed status=0x%08lX", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(status));
                    LogTlsAlertIfVisible(id, session.localPort, session.input);
                    return false;
                }

                std::size_t extra = 0;
                for (const auto& buffer : buffers)
                {
                    if (buffer.BufferType == SECBUFFER_DATA && buffer.cbBuffer && buffer.pvBuffer)
                    {
                        if (session.localPort == 1119)
                        {
                            LogBgsApplicationPlaintext(session, id, peer, buffer.pvBuffer, buffer.cbBuffer);
                            if (!HandleBgsPlaintext(session, socket, id, peer, buffer.pvBuffer, buffer.cbBuffer))
                                return false;
                        }
                        else if (session.localPort == 443)
                        {
                            if (!HandleWebAuthPlaintext(session, socket, id, peer, buffer.pvBuffer, buffer.cbBuffer))
                                return false;
                        }
                    }
                    else if (buffer.BufferType == SECBUFFER_EXTRA)
                    {
                        extra = buffer.cbBuffer;
                    }
                }

                if (extra && extra <= session.input.size())
                    session.input = std::vector<unsigned char>(session.input.end() - static_cast<std::ptrdiff_t>(extra), session.input.end());
                else
                    session.input.clear();
            }
            return true;
        }

        CredHandle* SelectTlsCredential(TlsSession& session, const char*& identity)
        {
            identity = "us.actual.battle.net";
            if (session.localPort != 443)
                return &g_tlsCredential;

            if (_stricmp(session.sni.c_str(), "us.battle.net") == 0 && g_tls443BattleNetCredentialValid)
            {
                identity = "us.battle.net";
                return &g_tls443BattleNetCredential;
            }
            if (!session.sni.empty() &&
                (_stricmp(session.sni.c_str(), "iw8-bnet-auth3.prod.demonware.net") == 0 ||
                 _stricmp(session.sni.c_str(), "auth3.prod.demonware.net") == 0 ||
                 _stricmp(session.sni.c_str(), "auth3-login.prod.demonware.net") == 0 ||
                 _stricmp(session.sni.c_str(), "loginqueue.prod.demonware.net") == 0 ||
                 _stricmp(session.sni.c_str(), "prod.umbrella.demonware.net") == 0 ||
                 (session.sni.size() > 23 &&
                    _stricmp(session.sni.c_str() + session.sni.size() - 23, ".umbrella.demonware.net") == 0)) &&
                g_tls443DemonwareCredentialValid)
            {
                identity = "iw8-bnet-auth3.prod.demonware.net";
                return &g_tls443DemonwareCredential;
            }
            return &g_tlsCredential;
        }

        bool PumpTls(TlsSession& session, SOCKET socket, std::uint64_t id, const std::string& peer)
        {
            if (!InitializeTlsCredential())
            {
                log::Print("[TLS%u] id=%llu cannot start SChannel because server credential initialization failed", static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id));
                return false;
            }

            const char* selectedIdentity = nullptr;
            CredHandle* selectedCredential = SelectTlsCredential(session, selectedIdentity);
            if (!session.credentialLogged)
            {
                session.credentialLogged = true;
                log::Print("[TLS%u] id=%llu selected server identity=%s sni=%s exactSniIdentity=%s",
                    static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id),
                    selectedIdentity ? selectedIdentity : "<none>",
                    session.sni.empty() ? "<none>" : session.sni.c_str(),
                    session.localPort == 443 && selectedIdentity && !session.sni.empty() &&
                        _stricmp(selectedIdentity, session.sni.c_str()) == 0 ? "YES" : "no");
            }

            while (!session.established)
            {
                if (session.input.empty()) return true;
                LogTlsAlertIfVisible(id, session.localPort, session.input);

                SecBuffer inBuffers[2]{};
                inBuffers[0].BufferType = SECBUFFER_TOKEN;
                inBuffers[0].pvBuffer = session.input.data();
                inBuffers[0].cbBuffer = static_cast<unsigned long>(session.input.size());
                inBuffers[1].BufferType = SECBUFFER_EMPTY;
                SecBufferDesc inDescriptor{};
                inDescriptor.ulVersion = SECBUFFER_VERSION;
                inDescriptor.cBuffers = 2;
                inDescriptor.pBuffers = inBuffers;

                SecBuffer outBuffer{};
                outBuffer.BufferType = SECBUFFER_TOKEN;
                SecBufferDesc outDescriptor{};
                outDescriptor.ulVersion = SECBUFFER_VERSION;
                outDescriptor.cBuffers = 1;
                outDescriptor.pBuffers = &outBuffer;

                DWORD attributes = 0;
                TimeStamp expiry{};
                const DWORD requestFlags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                    ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
                const SECURITY_STATUS status = AcceptSecurityContext(selectedCredential,
                    session.contextValid ? &session.context : nullptr, &inDescriptor, requestFlags,
                    SECURITY_NATIVE_DREP, &session.context, &outDescriptor, &attributes, &expiry);

                if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK ||
                    status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE)
                    session.contextValid = true;

                if ((status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) && session.contextValid)
                    CompleteAuthToken(&session.context, &outDescriptor);

                if (outBuffer.pvBuffer && outBuffer.cbBuffer)
                {
                    const bool sent = SendTlsToken(session, socket, id, peer, outBuffer.pvBuffer, outBuffer.cbBuffer);
                    FreeContextBuffer(outBuffer.pvBuffer);
                    outBuffer.pvBuffer = nullptr;
                    if (!sent) return false;
                }

                if (status == SEC_E_INCOMPLETE_MESSAGE)
                    return true;

                std::size_t extra = 0;
                if (inBuffers[1].BufferType == SECBUFFER_EXTRA)
                    extra = inBuffers[1].cbBuffer;
                if (extra && extra <= session.input.size())
                    session.input = std::vector<unsigned char>(session.input.end() - static_cast<std::ptrdiff_t>(extra), session.input.end());
                else
                    session.input.clear();

                log::Print("[TLS%u] id=%llu AcceptSecurityContext status=0x%08lX attrs=0x%08lX extra=%llu",
                    static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(status),
                    static_cast<unsigned long>(attributes), static_cast<unsigned long long>(extra));

                if (status == SEC_E_OK || status == SEC_I_COMPLETE_NEEDED)
                {
                    session.established = true;
                    session.establishedAtMs = GetTickCount64();
                    const SECURITY_STATUS query = QueryContextAttributes(&session.context, SECPKG_ATTR_STREAM_SIZES, &session.streamSizes);
                    log::Print("[TLS%u] id=%llu TLS HANDSHAKE ESTABLISHED queryStreamSizes=0x%08lX header=%lu trailer=%lu maxMessage=%lu",
                        static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(query),
                        session.streamSizes.cbHeader, session.streamSizes.cbTrailer, session.streamSizes.cbMaximumMessage);
                    if (session.localPort == 1119)
                        log::Print("[BGS1119] id=%llu transport is now encrypted/decrypted by SChannel; waiting for the stock client's first BGS application message.",
                            static_cast<unsigned long long>(id));
                    else
                        log::Print("[WEB-AUTH] id=%llu TLS established on :443; waiting for the stock OAuth/online-services HTTP request.",
                            static_cast<unsigned long long>(id));
                    break;
                }

                if (status == SEC_I_CONTINUE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE)
                {
                    if (session.input.empty()) return true;
                    continue;
                }

                if (status == SEC_I_CONTEXT_EXPIRED)
                {
                    log::Print("[TLS%u] id=%llu peer closed TLS before handshake completion status=SEC_I_CONTEXT_EXPIRED(0x%08lX); on :443 this normally means certificate/trust/hostname validation ended the attempt before HTTP",
                        static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(status));
                }
                else
                {
                    log::Print("[TLS%u] id=%llu handshake failed status=0x%08lX. Inspect the preceding SNI/alert before changing application protocol behavior.",
                        static_cast<unsigned>(session.localPort), static_cast<unsigned long long>(id), static_cast<unsigned long>(status));
                }
                LogTlsAlertIfVisible(id, session.localPort, session.input);
                return false;
            }

            return DecryptTlsInput(session, socket, id, peer);
        }
    }
}
