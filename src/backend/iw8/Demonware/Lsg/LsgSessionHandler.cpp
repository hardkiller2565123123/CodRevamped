#include "LsgSessionHandler.h"

namespace revamped::iw8
{
    bool Server::HandleLsgTcp(Client& client, const std::uint8_t* data, std::size_t size)
    {
        if (!data || !size)
            return true;

        AppendLsgPipelineV63("RX id=%llu port=%u stage=%u bytes=%llu bufferedBefore=%llu",
            static_cast<unsigned long long>(client.id), static_cast<unsigned>(client.localPort),
            static_cast<unsigned>(client.lsgStage), static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(client.lsgInput.size()));
        client.lsgInput.insert(client.lsgInput.end(), data, data + size);
        if (client.lsgInput.size() > 1024u * 1024u)
        {
            log::Print("[LSG] id=%llu port=%u input buffer exceeded 1 MiB; abandoning protocol attribution without touching client state",
                static_cast<unsigned long long>(client.id), static_cast<unsigned>(client.localPort));
            client.lsgInput.clear();
            client.lsgStage = 99;
            return true;
        }

        for (;;)
        {
            if (client.lsgStage == 99)
                return true;

            if (client.lsgStage == 0)
            {
                if (client.lsgInput.size() < 28u)
                    return true;

                const std::uint8_t* hello = client.lsgInput.data();
                const std::uint32_t protocolMinMarker = ReadLe32(hello + 0);
                const std::uint32_t protocolMaxMarker = ReadLe32(hello + 4);
                const std::uint32_t supportedMin = ReadLe32(hello + 8);
                const std::uint32_t supportedMax = ReadLe32(hello + 12);
                const std::uint32_t maxPacket = ReadLe32(hello + 16);
                if (protocolMinMarker != 200u || protocolMaxMarker != 200u ||
                    supportedMin > supportedMax || supportedMin > 220u || supportedMax < 210u ||
                    maxPacket == 0u || maxPacket > 16u * 1024u * 1024u)
                {
                    log::Print("[LSG] id=%llu port=%u first 28 bytes are not the stock bdLobbyConnection hello markers={%u,%u,%u,%u} maxPacket=%u attribution=NO",
                        static_cast<unsigned long long>(client.id), static_cast<unsigned>(client.localPort),
                        protocolMinMarker, protocolMaxMarker, supportedMin, supportedMax, maxPacket);
                    AppendLsgPipelineV63("HELLO_REJECT id=%llu markers={%u,%u,%u,%u} maxPacket=%u",
                        static_cast<unsigned long long>(client.id), protocolMinMarker, protocolMaxMarker, supportedMin, supportedMax, maxPacket);
                    client.lsgStage = 99;
                    return true;
                }

                std::uint64_t auth3Serial = 0;
                std::uint8_t sessionKey[24]{};
                if (!web::GetLatestAuth3SessionKey(sessionKey, &auth3Serial))
                {
                    log::Print("[LSG] id=%llu stock lobby hello arrived before a correlated local Auth3 ticket pair was available; keeping socket open",
                        static_cast<unsigned long long>(client.id));
                    AppendLsgPipelineV63("HELLO_WAIT_AUTH3 id=%llu", static_cast<unsigned long long>(client.id));
                    return true;
                }

                // V69: use the known IW8 Demonware header-ack layout.  The stock
                // hello advertises 210..220, while the reference IW8 handshake
                // selects protocol 210 and sends BOTH 64-bit fields after it:
                //   AB 81 | selectedProto[DWORD] | cypher210ConnID[QWORD] | serverNonce[QWORD]
                // V61-V68 accidentally omitted cypher210ConnID, producing a 14-byte
                // body / 18-byte frame.  The native parser expects a 22-byte body /
                // 26-byte frame, which explains the immediate close before 0x82.
                constexpr std::uint32_t kIw8ReferenceProtocol = 210u;
                constexpr std::uint64_t kIw8ReferenceConnectionId = 0x3713371337133713ull;
                constexpr std::uint64_t kIw8ReferenceServerNonce = 0x3713371337133713ull;

                client.lsgSelectedVersion =
                    (supportedMin <= kIw8ReferenceProtocol && supportedMax >= kIw8ReferenceProtocol)
                    ? kIw8ReferenceProtocol
                    : supportedMin;
                client.lsgMaxPacket = maxPacket;
                std::memcpy(client.lsgClientNonce, hello + 20, 8);
                for (unsigned i = 0; i < 8; ++i)
                    client.lsgServerNonce[i] = static_cast<std::uint8_t>(kIw8ReferenceServerNonce >> (i * 8));

                log::Print("[LSG-V69] HEADER_ACK_LAYOUT id=%llu advertised=%u..%u selected=%u bodyBytes=22 frameBytes=26 connectionId=0x%016llX serverNonce=0x%016llX source=IW8_REFERENCE_LAYOUT stateWrites=off",
                    static_cast<unsigned long long>(client.id), supportedMin, supportedMax,
                    client.lsgSelectedVersion,
                    static_cast<unsigned long long>(kIw8ReferenceConnectionId),
                    static_cast<unsigned long long>(kIw8ReferenceServerNonce));
                AppendLsgPipelineV63(
                    "V69_HEADER_ACK id=%llu advertised=%u..%u selected=%u bodyBytes=22 frameBytes=26 connectionId=0x%016llX next=EXPECT_NATIVE_0x82 clientStateWrites=off",
                    static_cast<unsigned long long>(client.id), supportedMin, supportedMax,
                    client.lsgSelectedVersion,
                    static_cast<unsigned long long>(kIw8ReferenceConnectionId));

                std::vector<std::uint8_t> response;
                response.reserve(26);
                AppendLe32(response, 22u); // AB/81 + DWORD + QWORD connection id + QWORD nonce
                response.push_back(0xAB);
                response.push_back(0x81);
                AppendLe32(response, client.lsgSelectedVersion);
                AppendLe64(response, kIw8ReferenceConnectionId);
                response.insert(response.end(), client.lsgServerNonce, client.lsgServerNonce + 8);

                if (!SendAllNonBlocking(client.socket, response.data(), response.size()))
                    return false;

                if (config_.dumpPayloads)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, response.data(), response.size());

                client.lsgInput.erase(client.lsgInput.begin(), client.lsgInput.begin() + 28);
                client.lsgStage = 1;
                web::NotePostLsgTransport(client.localPort, "TCP_LSG_STOCK_HELLO");
                log::Print("[LSG] id=%llu auth3Serial=%llu HELLO OK clientRange=%u..%u selected=%u maxPacket=%u; sent V69 framed 0x81 header ACK bytes=%llu",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    supportedMin, supportedMax, client.lsgSelectedVersion, client.lsgMaxPacket,
                    static_cast<unsigned long long>(response.size()));
                AppendLsgPipelineV63("HELLO_OK id=%llu auth3Serial=%llu clientRange=%u..%u selected=%u maxPacket=%u responseBytes=%llu layout=DWORD+QWORD+QWORD next=EXPECT_0x82_CLIENTCHAL",
                    static_cast<unsigned long long>(client.id), static_cast<unsigned long long>(auth3Serial),
                    supportedMin, supportedMax, client.lsgSelectedVersion, client.lsgMaxPacket,
                    static_cast<unsigned long long>(response.size()));
                continue;
            }

            if (client.lsgStage == 1)
            {
                if (client.lsgInput.size() < 4u)
                    return true;

                const std::uint32_t bodyBytes = ReadLe32(client.lsgInput.data());
                if (bodyBytes < 10u || bodyBytes > 256u * 1024u)
                {
                    log::Print("[LSG] id=%llu invalid 0x82 outer length=%u; leaving socket passive", static_cast<unsigned long long>(client.id), bodyBytes);
                    client.lsgStage = 99;
                    return true;
                }
                const std::size_t frameBytes = 4u + static_cast<std::size_t>(bodyBytes);
                if (client.lsgInput.size() < frameBytes)
                    return true;

                const std::uint8_t* frame = client.lsgInput.data();
                if (frameBytes < 14u || frame[4] != 0xAB || frame[5] != 0x82)
                {
                    log::Print("[LSG] id=%llu expected framed AB/82 response but got marker=%02X opcode=%02X length=%u; leaving socket passive",
                        static_cast<unsigned long long>(client.id), frameBytes > 4 ? frame[4] : 0u,
                        frameBytes > 5 ? frame[5] : 0u, bodyBytes);
                    client.lsgStage = 99;
                    return true;
                }

                AppendLsgPipelineV63(
                    "NEGOTIATION_ACCEPTED id=%llu selected=%u client82Bytes=%llu milestone=CLIENT_SENT_0x82 clientStateWrites=off",
                    static_cast<unsigned long long>(client.id), client.lsgSelectedVersion,
                    static_cast<unsigned long long>(frameBytes));

                // Stock sub_14232D1B0 hashes the exact connection transcript:
                // 210, 220, maxPacket, client nonce, complete server 0x81 frame,
                // then the client 0x82 frame excluding its final 8-byte proof.
                std::vector<std::uint8_t> transcript;
                transcript.reserve(64u + frameBytes);
                AppendLe32(transcript, 210u);
                AppendLe32(transcript, 220u);
                AppendLe32(transcript, client.lsgMaxPacket);
                transcript.insert(transcript.end(), client.lsgClientNonce, client.lsgClientNonce + 8);
                // Hash the complete V69 server header ACK exactly as it was sent.
                // This mirrors the IW8 reference transcript: 20-byte hello remainder,
                // complete 26-byte server 0x81 frame, then client 0x82 without its
                // trailing 8-byte proof.
                constexpr std::uint64_t kIw8ReferenceConnectionId = 0x3713371337133713ull;
                AppendLe32(transcript, 22u);
                transcript.push_back(0xAB);
                transcript.push_back(0x81);
                AppendLe32(transcript, client.lsgSelectedVersion);
                AppendLe64(transcript, kIw8ReferenceConnectionId);
                transcript.insert(transcript.end(), client.lsgServerNonce, client.lsgServerNonce + 8);
                transcript.insert(transcript.end(), frame, frame + frameBytes - 8u);

                std::uint8_t transcriptHash[20]{};
                if (!BCryptSha1(transcript.data(), transcript.size(), transcriptHash))
                {
                    log::Print("[LSG] id=%llu could not materialize transcript SHA1; no guessed reply sent",
                        static_cast<unsigned long long>(client.id));
                    client.lsgStage = 99;
                    return true;
                }

                // V78: preserve IW8's exact AuthSessionKeyKDF path but remove the
                // V77 runtime KEY_3 extractor. The client bridge scans the game EXE
                // file on disk for all structurally valid 294-byte RSA SPKI values.
                // We try those public DER candidates only against the native 0x82
                // proof. Nothing is accepted unless IW8's first 8 CLIENTCHAL bytes
                // are reproduced exactly.
                constexpr std::size_t kMaxKeySources = 12u;
                std::array<std::uint8_t, kMaxKeySources * 24u> sessionKeys{};
                std::array<std::uint32_t, kMaxKeySources> keyKinds{};
                std::uint64_t auth3Serial = 0;
                const std::size_t keySourceCount = web::GetLsgSessionKeyCandidatesV72(
                    sessionKeys.data(), keyKinds.data(), keyKinds.size(), &auth3Serial);

                const std::uint8_t* auth3ClientTicketSessionKey = nullptr;
                for (std::size_t keyIndex = 0; keyIndex < keySourceCount; ++keyIndex)
                {
                    if (keyKinds[keyIndex] == 2u) // AUTH3_CLIENT_TICKET_SESSIONKEY
                    {
                        auth3ClientTicketSessionKey = sessionKeys.data() + keyIndex * 24u;
                        break;
                    }
                }
                if (!auth3ClientTicketSessionKey)
                {
                    log::Print("[LSG-V78] IW8_KDF_INPUT_MISSING id=%llu auth3Serial=%llu source=AUTH3_CLIENT_TICKET_SESSIONKEY action=NO_0x83",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial));
                    AppendLsgPipelineV63("V78_IW8_KDF_INPUT_MISSING id=%llu auth3Serial=%llu action=NO_0x83",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial));
                    client.lsgStage = 99;
                    return true;
                }

                std::vector<AuthTrafficSigningKeyCandidateV78> key3Candidates;
                std::wstring key3PackPath;
                if (!LoadAuthTrafficSigningKeyCandidatesV78(key3Candidates, &key3PackPath) || key3Candidates.empty())
                {
                    log::Print("[LSG-V78] IW8_KDF_KEY3_CANDIDATES_MISSING id=%llu auth3Serial=%llu expectedFile=iw8-auth-traffic-signing-key3-candidates.bin action=NO_0x83",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial));
                    AppendLsgPipelineV63("V78_IW8_KDF_KEY3_CANDIDATES_MISSING id=%llu auth3Serial=%llu action=NO_0x83",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial));
                    client.lsgStage = 99;
                    return true;
                }

                const char clientChalLabel[] = "CLIENTCHAL";
                const char bdDataLabel[] = "BDDATA";
                const std::uint8_t* clientProof = frame + frameBytes - 8u;
                std::uint8_t chosenPrk[20]{};
                std::uint8_t chosenChallenge[16]{};
                std::size_t matchedCandidate = static_cast<std::size_t>(-1);

                log::Print("[LSG-V78] KEY3_ORACLE_BEGIN id=%llu auth3Serial=%llu candidates=%llu source=ON_DISK_EXE_DER transcriptBytes=%llu clientProof=%02X%02X%02X%02X%02X%02X%02X%02X",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(key3Candidates.size()),
                    static_cast<unsigned long long>(transcript.size()),
                    clientProof[0], clientProof[1], clientProof[2], clientProof[3],
                    clientProof[4], clientProof[5], clientProof[6], clientProof[7]);

                for (std::size_t candidateIndex = 0; candidateIndex < key3Candidates.size(); ++candidateIndex)
                {
                    const auto& candidate = key3Candidates[candidateIndex];
                    std::array<std::uint8_t, 24> trafficSessionKey{};
                    std::uint8_t candidatePrk[20]{};
                    std::uint8_t candidateChallenge[16]{};

                    const bool expanded = HkdfExpandSha1Key(auth3ClientTicketSessionKey, 24u,
                        candidate.der.data(), candidate.der.size(),
                        trafficSessionKey.data(), trafficSessionKey.size());
                    const bool extracted = expanded && BCryptHmacSha1(transcriptHash, sizeof(transcriptHash),
                        trafficSessionKey.data(), trafficSessionKey.size(), candidatePrk);
                    const bool challenged = extracted && HkdfExpandSha1(candidatePrk,
                        reinterpret_cast<const std::uint8_t*>(clientChalLabel), 10u,
                        candidateChallenge, sizeof(candidateChallenge));
                    const bool match = challenged && EqualBytes(candidateChallenge, clientProof, 8u);

                    log::Print("[LSG-V78] KEY3_CANDIDATE id=%llu index=%llu fileOffset=0x%llX derivedProof=%02X%02X%02X%02X%02X%02X%02X%02X valid=%s match=%s",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(candidateIndex),
                        static_cast<unsigned long long>(candidate.fileOffset),
                        candidateChallenge[0], candidateChallenge[1], candidateChallenge[2], candidateChallenge[3],
                        candidateChallenge[4], candidateChallenge[5], candidateChallenge[6], candidateChallenge[7],
                        challenged ? "yes" : "no", match ? "YES" : "no");

                    if (!match)
                        continue;

                    std::memcpy(chosenPrk, candidatePrk, sizeof(chosenPrk));
                    std::memcpy(chosenChallenge, candidateChallenge, sizeof(chosenChallenge));
                    matchedCandidate = candidateIndex;
                    break;
                }

                if (matchedCandidate == static_cast<std::size_t>(-1))
                {
                    log::Print("[LSG-V78] KEY3_ORACLE_NO_MATCH id=%llu auth3Serial=%llu candidates=%llu clientProof=%02X%02X%02X%02X%02X%02X%02X%02X action=NO_0x83 next=VERIFY_OTHER_KDF_INPUTS",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial),
                        static_cast<unsigned long long>(key3Candidates.size()),
                        clientProof[0], clientProof[1], clientProof[2], clientProof[3],
                        clientProof[4], clientProof[5], clientProof[6], clientProof[7]);
                    AppendLsgPipelineV63("V78_KEY3_ORACLE_NO_MATCH id=%llu auth3Serial=%llu candidates=%llu action=NO_0x83 next=VERIFY_OTHER_KDF_INPUTS",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(auth3Serial),
                        static_cast<unsigned long long>(key3Candidates.size()));
                    client.lsgStage = 99;
                    return true;
                }

                std::uint8_t chosenBdData[72]{};
                if (!HkdfExpandSha1(chosenPrk,
                        reinterpret_cast<const std::uint8_t*>(bdDataLabel), 6u,
                        chosenBdData, sizeof(chosenBdData)))
                {
                    log::Print("[LSG-V78] IW8_KDF_BDDATA_FAILED id=%llu action=NO_0x83",
                        static_cast<unsigned long long>(client.id));
                    client.lsgStage = 99;
                    return true;
                }

                client.lsgCryptoVariant = "IW8_AUTHSESSIONKEYKDF_SHA1_V78";
                std::memcpy(client.lsgPrk, chosenPrk, sizeof(client.lsgPrk));
                std::memcpy(client.lsgBdData, chosenBdData, sizeof(client.lsgBdData));

                const auto& matchedKey = key3Candidates[matchedCandidate];
                log::Print("[LSG-V78] IW8_KDF_PROOF_MATCH id=%llu auth3Serial=%llu source=AUTH3_CLIENT_TICKET_SESSIONKEY key3Source=ON_DISK_EXE_DER candidate=%llu fileOffset=0x%llX transcriptBytes=%llu responseId=%02X%02X%02X%02X%02X%02X%02X%02X action=SEND_NATIVE_0x83",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(matchedCandidate),
                    static_cast<unsigned long long>(matchedKey.fileOffset),
                    static_cast<unsigned long long>(transcript.size()),
                    chosenChallenge[8], chosenChallenge[9], chosenChallenge[10], chosenChallenge[11],
                    chosenChallenge[12], chosenChallenge[13], chosenChallenge[14], chosenChallenge[15]);
                AppendLsgPipelineV63("V78_IW8_KDF_PROOF_MATCH id=%llu auth3Serial=%llu candidate=%llu fileOffset=0x%llX next=SEND_0x83_THEN_EXPECT_0x85",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(matchedCandidate),
                    static_cast<unsigned long long>(matchedKey.fileOffset));

                std::vector<std::uint8_t> response;
                response.reserve(14);
                AppendLe32(response, 10u);
                response.push_back(0xAB);
                response.push_back(0x83);
                response.insert(response.end(), chosenChallenge + 8, chosenChallenge + 16);
                if (!SendAllNonBlocking(client.socket, response.data(), response.size()))
                    return false;
                if (config_.dumpPayloads)
                    log::Payload(client.id, "OUT", client.localPort, client.peer, response.data(), response.size());

                client.lsgInput.erase(client.lsgInput.begin(), client.lsgInput.begin() + static_cast<std::ptrdiff_t>(frameBytes));
                client.lsgStage = 2;
                log::Print("[LSG-V78] SERVER_AUTH_DONE id=%llu auth3Serial=%llu sentBytes=%llu opcode=0x83 proofSource=IW8_AUTHSESSIONKEYKDF next=EXPECT_SECURE_0x85",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(response.size()));
                AppendLsgPipelineV63("V78_SERVER_AUTH_DONE id=%llu auth3Serial=%llu sentBytes=%llu next=EXPECT_SECURE_0x85",
                    static_cast<unsigned long long>(client.id),
                    static_cast<unsigned long long>(auth3Serial),
                    static_cast<unsigned long long>(response.size()));
                continue;
            }

            if (client.lsgStage == 2)
            {
                if (client.lsgInput.size() < 4u)
                    return true;
                const std::uint32_t bodyBytes = ReadLe32(client.lsgInput.data());
                // V96: IW8 can emit a four-byte zero-length outer record while an
                // authenticated 2.x lobby connection is idle.  It carries no task
                // payload and must not poison the secure-stream parser.  Consume
                // only the empty record and keep stage 2 so a coalesced/following
                // 0x85 frame is decoded normally.
                if (bodyBytes == 0u)
                {
                    log::Print("[LSG-V96] id=%llu zero-length secure outer frame accepted as no-op/keepalive; stage=2 preserved bufferedBefore=%llu bufferedAfter=%llu",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(client.lsgInput.size()),
                        static_cast<unsigned long long>(client.lsgInput.size() - 4u));
                    AppendLsgPipelineV63(
                        "V96_ZERO_LENGTH_NOOP id=%llu stage=2 bytes=4 bufferedBefore=%llu bufferedAfter=%llu next=EXPECT_SECURE_0x85 stateWrites=off",
                        static_cast<unsigned long long>(client.id),
                        static_cast<unsigned long long>(client.lsgInput.size()),
                        static_cast<unsigned long long>(client.lsgInput.size() - 4u));
                    client.lsgInput.erase(client.lsgInput.begin(), client.lsgInput.begin() + 4);
                    continue;
                }
                if (bodyBytes < 2u || bodyBytes > 1024u * 1024u)
                {
                    log::Print("[LSG] id=%llu secure-stage invalid outer length=%u; retaining connection for diagnostics",
                        static_cast<unsigned long long>(client.id), bodyBytes);
                    client.lsgStage = 99;
                    return true;
                }
                const std::size_t frameBytes = 4u + static_cast<std::size_t>(bodyBytes);
                if (client.lsgInput.size() < frameBytes)
                    return true;

                const std::uint8_t marker = frameBytes > 4u ? client.lsgInput[4] : 0u;
                const std::uint8_t opcode = frameBytes > 5u ? client.lsgInput[5] : 0u;
                if (marker == 0xAB && opcode == 0x85 && frameBytes >= 34u)
                {
                    const std::uint32_t counter = ReadLe32(client.lsgInput.data() + 6);
                    const std::uint8_t* seed = client.lsgInput.data() + 10;
                    const std::size_t encryptedBytes = frameBytes - 34u;
                    const std::uint8_t* encrypted = client.lsgInput.data() + 26;
                    const std::uint8_t* receivedHash = client.lsgInput.data() + frameBytes - 8u;

                    std::uint8_t computedHash[20]{};
                    const bool hashOk = BCryptHmacSha1(client.lsgBdData, 20,
                        client.lsgInput.data(), frameBytes - 8u, computedHash) &&
                        EqualBytes(computedHash, receivedHash, 8u);

                    std::vector<std::uint8_t> plain;
                    const bool decryptOk = hashOk && encryptedBytes && (encryptedBytes & 15u) == 0u &&
                        BCryptAesCbcCrypt(false, client.lsgBdData + 40, seed, encrypted, encryptedBytes, plain);

                    if (!hashOk)
                    {
                        log::Print("[LSG] id=%llu secure 0x85 counter=%u HMAC mismatch; no fake success reply sent",
                            static_cast<unsigned long long>(client.id), counter);
                    }
                    else if (!decryptOk || plain.size() < 8u)
                    {
                        log::Print("[LSG] id=%llu secure 0x85 counter=%u decrypt/shape failed encryptedBytes=%llu; no fake success reply sent",
                            static_cast<unsigned long long>(client.id), counter,
                            static_cast<unsigned long long>(encryptedBytes));
                    }
                    else
                    {
                        const auto taskRequest = demonware::DecodeTaskRequest(plain);
                        const std::string taskDescription = demonware::DescribeTaskRequest(taskRequest);
                        log::Print("[LSG-DECODE] id=%llu secure 0x85 counter=%u %s encryptedBytes=%llu packetMatching=off",
                            static_cast<unsigned long long>(client.id), counter, taskDescription.c_str(),
                            static_cast<unsigned long long>(encryptedBytes));
                        AppendLsgPipelineV63("SECURE_0x85_DECODE id=%llu counter=%u %s encryptedBytes=%llu routing=SEMANTIC",
                            static_cast<unsigned long long>(client.id), counter, taskDescription.c_str(),
                            static_cast<unsigned long long>(encryptedBytes));

                        const demonware::TaskRoute* censusRoute = taskRequest.valid
                            ? demonware::FindTaskRoute(taskRequest.serviceId, taskRequest.taskId) : nullptr;
                        RecordPostLoginTaskCensus(client.id, counter, plain, taskRequest, censusRoute);

                        if (!taskRequest.valid)
                        {
                            log::Print("[LSG-COMPAT] id=%llu secure task decode rejected reason=%s policy=DO_NOT_GUESS_RESPONSE_BYTES",
                                static_cast<unsigned long long>(client.id),
                                taskRequest.error.empty() ? "unknown" : taskRequest.error.c_str());
                        }
                        else if (const demonware::TaskRoute* route = demonware::FindTaskRoute(taskRequest.serviceId, taskRequest.taskId))
                        {
                            if (route->replyPolicy == demonware::ReplyPolicy::None)
                            {
                                log::Print("[LSG-KNOWN-UNIMPLEMENTED] id=%llu service=%u(%s) task=%u(%s) payloadBytes=%llu policy=DO_NOT_GUESS_RESPONSE_BYTES",
                                    static_cast<unsigned long long>(client.id),
                                    static_cast<unsigned>(taskRequest.serviceId), route->serviceName ? route->serviceName : "?",
                                    static_cast<unsigned>(taskRequest.taskId), route->taskName ? route->taskName : "?",
                                    static_cast<unsigned long long>(taskRequest.payloadBytes));
                            }
                            else
                            {
                                const std::uint64_t transactionId = client.lsgTransactionId + 1u;
                                std::vector<std::uint8_t> replyPlain;
                                const std::uint8_t* requestPayload = taskRequest.payloadBytes
                                    ? plain.data() + taskRequest.payloadOffset : nullptr;
                                if (!demonware::BuildTaskReply(*route, taskRequest, requestPayload, taskRequest.payloadBytes,
                                    transactionId, replyPlain))
                                {
                                    if (taskRequest.serviceId == 255u && taskRequest.taskId == 0x0Au)
                                    {
                                        log::Print("[LSG-REST] id=%llu counter=%u REST service/operation not reconstructed; no reply sent",
                                            static_cast<unsigned long long>(client.id), counter);
                                    }
                                    log::Print("[LSG] id=%llu service=%u task=%u route=%s/%s could not serialize semantic reply",
                                        static_cast<unsigned long long>(client.id),
                                        static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId),
                                        route->serviceName ? route->serviceName : "?", route->taskName ? route->taskName : "?");
                                }
                                else
                                {
                                    client.lsgTransactionId = transactionId;
                                    const std::array<std::uint8_t, 16> replySeed{
                                    0x5E,0xED,0x5E,0xED,0x5E,0xED,0x5E,0xED,
                                    0x5E,0xED,0x5E,0xED,0x5E,0xED,0x5E,0xED
                                };
                                std::vector<std::uint8_t> replyEncrypted;
                                if (BCryptAesCbcCrypt(true, client.lsgBdData + 56, replySeed.data(),
                                        replyPlain.data(), replyPlain.size(), replyEncrypted))
                                {
                                    std::vector<std::uint8_t> response;
                                    AppendLe32(response, 30u + static_cast<std::uint32_t>(replyEncrypted.size()));
                                    response.push_back(0xAB);
                                    response.push_back(0x85);
                                    AppendLe32(response, ++client.lsgSendCounter);
                                    response.insert(response.end(), replySeed.begin(), replySeed.end());
                                    response.insert(response.end(), replyEncrypted.begin(), replyEncrypted.end());

                                    std::uint8_t responseHash[20]{};
                                    if (BCryptHmacSha1(client.lsgBdData + 20, 20, response.data(), response.size(), responseHash))
                                    {
                                        response.insert(response.end(), responseHash, responseHash + 8);
                                        if (!SendAllNonBlocking(client.socket, response.data(), response.size()))
                                            return false;
                                        if (config_.dumpPayloads)
                                            log::Payload(client.id, "OUT", client.localPort, client.peer, response.data(), response.size());
                                        log::Print("[LSG-ROUTE] id=%llu service=%u(%s) task=%u(%s) semantic reply sent counter=%u bytes=%llu transaction=%llu",
                                            static_cast<unsigned long long>(client.id),
                                            static_cast<unsigned>(taskRequest.serviceId), route->serviceName ? route->serviceName : "?",
                                            static_cast<unsigned>(taskRequest.taskId), route->taskName ? route->taskName : "?",
                                            client.lsgSendCounter, static_cast<unsigned long long>(response.size()),
                                            static_cast<unsigned long long>(transactionId));
                                        AppendLsgPipelineV63("SEMANTIC_TASK_REPLY_OK id=%llu service=%u task=%u counter=%u bytes=%llu transaction=%llu next=EXPECT_LOGIN_COMPLETE_OR_READY",
                                            static_cast<unsigned long long>(client.id),
                                            static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId),
                                            client.lsgSendCounter, static_cast<unsigned long long>(response.size()),
                                            static_cast<unsigned long long>(transactionId));
                                    }
                                    else
                                    {
                                        log::Print("[LSG] id=%llu semantic task reply HMAC generation failed service=%u task=%u",
                                            static_cast<unsigned long long>(client.id),
                                            static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId));
                                    }
                                }
                                else
                                {
                                    log::Print("[LSG] id=%llu semantic task reply AES encryption failed service=%u task=%u",
                                        static_cast<unsigned long long>(client.id),
                                        static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId));
                                }
                                }
                            }
                        }
                        else
                        {
                            log::Print("[LSG-UNSUPPORTED] id=%llu service=%u task=%u payloadBytes=%llu policy=DO_NOT_GUESS_RESPONSE_BYTES",
                                static_cast<unsigned long long>(client.id),
                                static_cast<unsigned>(taskRequest.serviceId), static_cast<unsigned>(taskRequest.taskId),
                                static_cast<unsigned long long>(taskRequest.payloadBytes));
                        }
                    }
                }
                else
                {
                    log::Print("[LSG] id=%llu post-handshake frame marker=%02X opcode=%02X bytes=%llu",
                        static_cast<unsigned long long>(client.id), marker, opcode,
                        static_cast<unsigned long long>(frameBytes));
                }
                client.lsgInput.erase(client.lsgInput.begin(), client.lsgInput.begin() + static_cast<std::ptrdiff_t>(frameBytes));
                continue;
            }
        }
    }
}
